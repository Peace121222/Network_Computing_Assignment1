"""Bounded threaded TCP sessions and encrypted UDP relay."""

from __future__ import annotations

import argparse
import errno
import logging
import math
import select
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import OrderedDict, deque
from typing import Any

from cryptography.fernet import Fernet

from collab.accounts import Accounts
from collab.server.file_transfers import ServerFileTransfers
from collab.server.routing import RelayRouter
from collab.shared.limits import (
    CONTROL_TIMEOUT,
    FILE_IDLE_TIMEOUT,
    FILE_TRANSFER_TIMEOUT,
    LOGIN_TIMEOUT,
    RETRY_POLL_INTERVAL,
    SERVER_POLL_TIMEOUT,
    SESSION_CHECK_INTERVAL,
    SESSION_EXPIRY,
    SESSION_TIMEOUT,
    SHUTDOWN_TIMEOUT,
    UDP_MTU,
)
from collab.shared.protocol import validate_tcp, validate_udp
from collab.transport.congestion import CubicController
from collab.transport.handshake import server_login
from collab.transport.security import Channel, unseal
from collab.transport.tcp import frame_tcp, send_tcp
from collab.transport.tls import server_context
from collab.transport.udp import encode_udp, udp_frame_size

log = logging.getLogger(__name__)


def retryable(exc, udp=False):
    """Check if an OS error is transient."""
    err = exc.errno
    if udp:
        return err in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK, errno.ECONNRESET, errno.ECONNREFUSED)
    return err in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK)


class Server:
    status: str

    def __init__(
        self,
        host: str = "127.0.0.1",
        tcp_port: int = 9000,
        udp_port: int = 9001,
        *,
        database: str = "accounts.sqlite3",
        certfile: str | None = None,
        keyfile: str | None = None,
        session_expiry: float = SESSION_EXPIRY,
        session_check_interval: float = SESSION_CHECK_INTERVAL,
        max_connections: int = 64,
        max_pending_packets: int = 8192,
        max_pending_per_recipient: int = 1024,
        file_idle_timeout: float = FILE_IDLE_TIMEOUT,
        file_transfer_timeout: float = FILE_TRANSFER_TIMEOUT,
    ) -> None:
        self.host, self.tcp_port, self.udp_port = host, tcp_port, udp_port
        self.session_expiry, self.session_check_interval = session_expiry, session_check_interval
        self.max_connections = max_connections
        self.max_pending_packets = max_pending_packets
        self.max_pending_per_recipient = max_pending_per_recipient
        self.database = database
        self.accounts = None
        self.tls_context = server_context(certfile, keyfile) if certfile and keyfile else None
        
        self.lock = threading.RLock()
        self.status = "stopped"
        self._last_error = None
        
        self.users = {}
        self.connections = set()
        self.running = threading.Event()
        self.presence_dirty = threading.Event()
        self.threads = []
        
        self.pending = {}
        self.chat_records = {}
        self._router = RelayRouter(self)
        self.file_transfers = ServerFileTransfers(self)
        self.revision = 0
        self.tcp = self.udp = None

    @property
    def last_error(self) -> dict[str, Any] | None:
        return self._last_error

    def _start_thread(self, target, args=()):
        """Start a basic daemon thread and track it."""
        thread = threading.Thread(target=target, args=args, daemon=True)
        with self.lock:
            if not self.running.is_set():
                raise RuntimeError("Server is stopping")
            self.threads = [t for t in self.threads if t.is_alive()]
            self.threads.append(thread)
            thread.start()
        return thread

    def start(self) -> None:
        if self.status != "stopped" or any(t.is_alive() for t in self.threads):
            raise RuntimeError("Server is not stopped")
        if self.tls_context is None:
            raise ValueError("TLS certificate and private key are required")
            
        self.accounts = Accounts(self.database)
        self.status = "starting"
        self._last_error = None
        self.running.set()
        self.presence_dirty.clear()
        
        try:
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp.bind((self.host, self.tcp_port))
            self.tcp.listen(64)
            self.tcp.settimeout(SERVER_POLL_TIMEOUT)
            
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind((self.host, self.udp_port))
            self.udp.settimeout(SERVER_POLL_TIMEOUT)
            
            self.tcp_port = self.tcp.getsockname()[1]
            self.udp_port = self.udp.getsockname()[1]
            self.status = "running"
            
            # Start background threads for handling TCP accept, UDP receive, retransmission, session expiry, and presence updates
            for task in (self.accept_loop, self.udp_loop, self.retransmit_loop, self.expiry_loop, self.presence_loop):
                self._start_thread(task)
                
        except BaseException as exc:
            self._last_error = {"message": str(exc)}
            self.close()
            raise

    @staticmethod
    def _close_socket(sock):
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def close(self) -> None:
        self.running.clear()
        self.status = "stopping"
        
        with self.lock:
            connections, sessions = list(self.connections), list(self.users.values())
            self.users.clear()
            self.pending.clear()
            self.chat_records.clear()
            self.file_transfers.records.clear()
            
        sockets = [self.tcp, self.udp] + connections + [u["sock"] for u in sessions]
        for sock in set(sockets):
            if sock:
                self._close_socket(sock)
                
        for user in sessions:
            if "writer_stop" in user:
                user["writer_stop"].set()
                
        self.connections.clear()
        self.tcp = self.udp = None
        self.status = "stopped"

    def _snapshot_locked(self, typ: str = "presence") -> dict[str, Any]:
        return {
            "type": typ,
            "names": sorted(n for n, u in self.users.items() if u["ready"]),
            "revision": self.revision,
        }

    def remove_session(self, name, token, *, notify=True, expired_at=None):
        with self.lock:
            user = self.users.get(name)
            if user is None or user["token"] != token:
                return False
            
            if expired_at is not None and expired_at - user["last_seen"] < self.session_expiry:
                return False
                
            del self.users[name]
            self.file_transfers.remove_session(token, time.monotonic())
            if user["ready"]:
                self.revision += 1
                
            for key, item in list(self.pending.items()):
                if token in (item["source_token"], item["destination_token"]):
                    del self.pending[key]
                    if item["source_token"] != token:
                        self._chat_outcome_locked(item, key[0], "recipient_disconnected")
                        
            for chat_key, record in list(self.chat_records.items()):
                if record["source_token"] == token:
                    del self.chat_records[chat_key]
                    
        if "writer_stop" in user:
            user["writer_stop"].set()
            with user["control_condition"]:
                user["control_condition"].notify_all()
        self._close_socket(user["sock"])
        
        if notify and self.running.is_set():
            self.presence_dirty.set()
        return True

    def expire_sessions(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            expired = [
                (n, u["token"])
                for n, u in self.users.items()
                if now - u["last_seen"] >= self.session_expiry
            ]
        changed = False
        for name, token in expired:
            changed |= self.remove_session(name, token, notify=False, expired_at=now)
        if changed and self.running.is_set():
            self.presence_dirty.set()

    def expiry_loop(self):
        while self.running.is_set():
            time.sleep(self.session_check_interval)
            self.expire_sessions()

    def _send_control(self, user, msg, deadline=None, *, presence=False):
        validate_tcp(msg, from_client=False)
        with user["control_condition"]:
            if user["writer_stop"].is_set():
                return False
            queued = len(user["control"]) + (user["presence"] is not None)
            if presence and user["presence"] is not None:
                if msg["revision"] >= user["presence"]["revision"]:
                    user["presence"] = msg
            elif queued >= 8:
                return False
            elif presence:
                user["presence"] = msg
            else:
                user["control"].append(msg)
            user["control_condition"].notify()
        return True

    def _write_control(self, sock, msg, security=None):
        frame = memoryview(frame_tcp(msg, security))
        deadline = time.monotonic() + CONTROL_TIMEOUT
        while frame:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Control write deadline exceeded")
            if not select.select([], [sock], [], remaining)[1]:
                raise TimeoutError("Control write timeout")
            try:
                count = sock.send(frame)
            except (BlockingIOError, InterruptedError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            if count == 0:
                raise ConnectionError("Control socket closed")
            frame = frame[count:]

    def control_writer(self, name, user):
        chat_streak = 0
        file_turn = True
        try:
            while self.running.is_set() and not user["writer_stop"].is_set():
                with user["control_condition"]:
                    mailbox = user["chat_mailbox"]
                    file_mailbox = user.setdefault("file_mailbox", OrderedDict())

                    def available():
                        return (user["control"] or user["presence"] is not None or 
                                any(v is not None for v in mailbox.values()) or 
                                any(v is not None for v in file_mailbox.values()) or user["writer_stop"].is_set())

                    user["control_condition"].wait_for(available, 0.1)
                    if user["writer_stop"].is_set():
                        return
                        
                    ready = next(((k, v) for k, v in mailbox.items() if v is not None), None)
                    file_ready = next(((k, v) for k, v in file_mailbox.items() if v is not None), None)
                    control_ready = bool(user["control"]) or user["presence"] is not None or file_ready is not None
                    
                    selected_file = selected_key = None
                    
                    if ready is not None and (chat_streak < 3 or not control_ready):
                        selected_key, msg = ready
                        mailbox[selected_key] = None
                        chat_streak += 1
                    elif control_ready:
                        chat_streak = 0
                        if file_ready is not None and (file_turn or not (user["control"] or user["presence"] is not None)):
                            selected_file, msg = file_ready
                            file_mailbox[selected_file] = None
                            file_turn = False
                        else:
                            file_turn = True
                            if user["control"]:
                                msg = user["control"].popleft()
                            else:
                                msg = user["presence"]
                                user["presence"] = None
                    else:
                        continue
                        
                self._write_control(user["sock"], msg, user.get("tcp_security"))
                
                if selected_file is not None and msg.get("state") != "accepted":
                    with user["control_condition"]:
                        file_mailbox.pop(selected_file, None)
                if selected_key is not None:
                    with user["control_condition"]:
                        mailbox.pop(selected_key, None)
                        
        except (OSError, ValueError):
            pass
        finally:
            self.remove_session(name, user["token"])

    def presence_loop(self):
        while self.running.is_set():
            if self.presence_dirty.wait(0.1):
                self.presence_dirty.clear()
                if self.running.is_set():
                    self.publish_presence()

    def publish_presence(self, target=None):
        with self.lock:
            snapshot = self._snapshot_locked()
            targets = [(n, u) for n, u in self.users.items() if u["ready"] and (target is None or n == target)]
            
        raw = snapshot if udp_frame_size(snapshot) <= UDP_MTU else None
        for name, user in targets:
            if raw is not None:
                self._send_session_udp(raw, [(name, user)])
            elif not self._send_control(user, dict(snapshot, type="users"), presence=True):
                self.remove_session(name, user["token"])

    def accept_loop(self):
        while self.running.is_set():
            try:
                conn, _ = self.tcp.accept()
                with self.lock:
                    if len(self.connections) < self.max_connections:
                        self.connections.add(conn)
                        self._start_thread(self.handle_client, (conn,))
                    else:
                        self._close_socket(conn)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.running.is_set():
                    break
                if retryable(exc):
                    time.sleep(0.1)
                    continue
                log.error("TCP accept error: %s", exc)
                break

    def handle_client(self, conn, deadline=None):
        """Own TLS authentication, session service, and cleanup for an accepted socket."""
        name = token = None
        deadline = time.monotonic() + LOGIN_TIMEOUT if deadline is None else deadline
        try:
            conn.settimeout(max(0.001, deadline - time.monotonic()))
            conn = self.tls_context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
            
            conn.setblocking(False)
            while True:
                if not self.running.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError("TLS handshake timeout")
                try:
                    conn.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    select.select([conn], [], [], 0.1)
                except ssl.SSLWantWriteError:
                    select.select([], [conn], [], 0.1)
                    
            conn.settimeout(max(0.001, deadline - time.monotonic()))
            
            # Call server_login to perform the login handshake and get the request and reader
            request, reader = server_login(conn, deadline, threading.Event())
            
            if request["type"] == "register":
                try:
                    self.accounts.register(request["name"], request.pop("password"))
                    send_tcp(conn, dict(type="registered"), deadline)
                except ValueError as exc:
                    send_tcp(conn, dict(type="error", message=str(exc)), deadline)
                return
                
            if not self.accounts.verify(request["name"], request.pop("password")):
                send_tcp(conn, dict(type="error", message="Invalid credentials"), deadline)
                return
                
            name = request["name"]
            with self.lock:
                if name in self.users:
                    send_tcp(conn, dict(type="error", message="User already connected"), deadline, security=reader.security)
                    return
                    
                token = uuid.uuid4().hex
                session_key = Fernet.generate_key()
                user = dict(
                    sock=conn, cipher=Fernet(session_key), congestion=CubicController(),
                    token=token, tcp_addr=conn.getpeername(), udp_addr=None,
                    last_seen=time.monotonic(), ready=False,
                    control_condition=threading.Condition(), control=deque(), presence=None,
                    writer_stop=threading.Event(), chat_mailbox=OrderedDict(),
                    public_id=uuid.uuid4().hex, sequences={}
                )
                self.users[name] = user
                
            send_tcp(conn, dict(type="welcome", token=token, udp_port=self.udp_port, 
                     session=user["public_id"], key=session_key.decode()), 
                     deadline=deadline, security=reader.security)
                     
            user["tcp_security"] = Channel(user["cipher"], user["public_id"], server=True, ordered=True)
            user["udp_security"] = Channel(user["cipher"], user["public_id"], server=True)
            reader.security = user["tcp_security"]
            conn.setblocking(False)
            reader.wait_timeout = SESSION_TIMEOUT
            
            self._start_thread(self.control_writer, (name, user))
            
            with self.lock:
                user["ready"] = True
                self.revision += 1
            self.presence_dirty.set()
            
            while self.running.is_set():
                try:
                    msg = reader.read()
                except socket.timeout:
                    continue
                validate_tcp(msg, from_client=True)
                if msg["type"] == "logout":
                    break
                elif msg["type"] in ("file_receipt", "file_abort"):
                    with self.lock:
                        if msg["type"] == "file_receipt":
                            self.file_transfers.receipt(name, user, msg, time.monotonic())
                        else:
                            self.file_transfers.abort(user, msg["transfer"], time.monotonic())
                elif msg["type"] == "users":
                    with self.lock:
                        snapshot = self._snapshot_locked("users")
                    if not self._send_control(user, snapshot):
                        break
                        
        except Exception as exc:
            log.debug("TCP client error: %s", exc)
        finally:
            if token is not None:
                self.remove_session(name, token)
            self._close_socket(conn)
            with self.lock:
                self.connections.discard(conn)

    def _send_session_udp(self, message, sessions, address=None):
        with self.lock:
            if any(self.users.get(name) is not user for name, user in sessions):
                return False
            destination = sessions[-1][1]
            address = destination["udp_addr"] if address is None else address
            udp = self.udp
            
        if address is None or udp is None:
            return False
            
        raw = encode_udp(message, destination["udp_security"].f, destination["udp_security"])
        try:
            udp.sendto(raw, address)
        except OSError as exc:
            if not self.running.is_set():
                return False
            if retryable(exc, udp=True):
                return False
            log.error("UDP send error: %s", exc)
        return True

    def udp_loop(self):
        while self.running.is_set():
            try:
                raw, addr = self.udp.recvfrom(4096)
                self.handle_udp(raw, addr)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.running.is_set():
                    break
                if retryable(exc, udp=True):
                    time.sleep(0.1)
                    continue
                log.error("UDP receive error: %s", exc)
                break

    def handle_udp(self, raw, addr):
        if len(raw) > UDP_MTU:
            return
        try:
            context = raw[:32].decode("ascii")
            with self.lock:
                candidates = [u["udp_security"].f for u in self.users.values() 
                             if u["public_id"] == context and u["ready"] and "udp_security" in u]
            if not candidates:
                return
            record = unseal(raw, candidates[0])
            msg = record[3]
            validate_udp(msg, from_client=True)
        except (ValueError, UnicodeError):
            return
            
        name, token = msg["from"], msg["token"]
        verified = changed = False
        
        with self.lock:
            user = self.users.get(name)
            if user is None or user["token"] != token or not user["ready"]:
                return
            
            now = time.monotonic()
            if now - user["last_seen"] >= self.session_expiry:
                self.remove_session(name, token, expired_at=now)
                return
                
            # Đã loại bỏ logic Path Challenge cũ kỹ. Khi có gói UDP hợp lệ tới, update luôn địa chỉ!
            if user["udp_addr"] != addr:
                changed = True
                user["udp_addr"] = addr
                
            verified = True
            user["last_seen"] = now
            if msg["type"] == "ack":
                key = (name, msg["id"])
                item = self.pending.get(key)
                if item is not None and item["destination_token"] == token:
                    del self.pending[key]
                    if "congestion" in user:
                        user["congestion"].acknowledge(msg["id"], now)
                    self._chat_outcome_locked(item, name, "delivered")
                    self.file_transfers.acknowledged(item, now)
                        
        if changed:
            self.presence_dirty.set()
        if not verified:
            return
            
        if msg["type"] == "data":
            self.route(msg, addr)
        elif msg["type"] == "heartbeat":
            self.publish_presence(target=name)

    def _chat_support(self, user):
        return self._router._chat_support(user)

    def _chat_outcome_locked(self, item, name, outcome):
        return self._router._chat_outcome_locked(item, name, outcome)

    def route(self, msg, source_addr):
        return self._router.route(msg, source_addr)

    def retransmit_once(self, now=None):
        return self._router.retransmit_once(now)

    def retransmit_loop(self):
        while self.running.is_set():
            self.retransmit_once()
            time.sleep(RETRY_POLL_INTERVAL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=9000)
    parser.add_argument("--udp-port", type=int, default=9001)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--database", default="accounts.sqlite3")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    
    server = None
    try:
        server = Server(
            args.host, args.tcp_port, args.udp_port,
            database=args.database, certfile=args.cert, keyfile=args.key
        )
        server.start()
        print(f"Server started on {args.host}:{args.tcp_port} (TCP), {args.udp_port} (UDP)")
        while server.running.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log.exception("Server error")
        return 1
    finally:
        if server:
            server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())