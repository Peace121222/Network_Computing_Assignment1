"""Client socket engine; no high-level networking libraries."""

from __future__ import annotations

import errno
import logging
import math
import queue
import select
import socket
import ssl
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from collab.accounts import validate_credentials
from collab.client.chat_inbox import ChatInbox
from collab.client.chat_sender import ChatSender
from collab.client.file_transfer import FileTransfers, TransferCapacityError
from collab.shared.limits import (
    CLIENT_LOGIN_TIMEOUT,
    CLIENT_RETRIES,
    CONNECT_TIMEOUT,
    FILE_IDLE_TIMEOUT,
    FILE_TRANSFER_TIMEOUT,
    FILE_WRITE_QUEUE,
    HEARTBEAT_INTERVAL,
    LOGOUT_TIMEOUT,
    RETRY_TIMEOUT,
    SEND_POLL_INTERVAL,
    SEND_WINDOW,
    SESSION_TIMEOUT,
    SHUTDOWN_TIMEOUT,
    UDP_MTU,
    UDP_TIMEOUT,
)
from collab.shared.protocol import data_packet, validate_tcp, validate_udp
from collab.transport.congestion import CubicController
from collab.transport.handshake import client_login
from collab.transport.security import Channel, unseal
from collab.transport.tcp import TCPReader, send_tcp, write_tcp
from collab.transport.tls import client_context
from collab.transport.udp import encode_udp

log = logging.getLogger(__name__)

def retryable(exc, udp=False):
    err = exc.errno
    if udp:
        return err in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK, errno.ECONNRESET, errno.ECONNREFUSED)
    return err in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK)


class Client:
    status: str

    def __init__(
        self,
        name: str,
        host: str = "127.0.0.1",
        port: int = 9000,
        download_dir: str | Path = "downloads",
        *,
        cafile: str | None = None,
        server_name: str | None = None,
        file_idle_timeout: float = FILE_IDLE_TIMEOUT,
        file_transfer_timeout: float = FILE_TRANSFER_TIMEOUT,
    ) -> None:
        self.file_idle_timeout = file_idle_timeout
        self.file_transfer_timeout = file_transfer_timeout
        self.name, self.host, self.port = name, host, port
        self.f = None
        self.cafile, self.server_name = cafile, server_name or host
        
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.events = queue.Queue()
        self.pending = {}
        self.pending_lock = threading.Lock()
        self.messages_seen = OrderedDict()
        self.outgoing_chats = {}
        self._chat_sender = ChatSender(self)
        self.chat_inbox = ChatInbox(self.events.put)
        self.files = {}
        self._file_transfers = FileTransfers(self)
        self.names = []
        self.running = threading.Event()
        self.tcp = self.udp = self.token = self.address = None
        self.threads = []
        
        self._lifecycle_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._session = None
        self.status = "disconnected"
        self.presence_revision = -1

    def _set_status(self, status, reason=None):
        if self.status != status:
            self.status = status
            event = {"type": "connection", "status": status}
            if reason is not None:
                event["reason"] = reason
            self.events.put(event)

    def _open_tls(self, deadline: float | None = None) -> ssl.SSLSocket:
        context = client_context(self.cafile)
        raw = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        try:
            if deadline is not None:
                raw.settimeout(max(0.001, deadline - time.monotonic()))
            return context.wrap_socket(raw, server_hostname=self.server_name)
        except BaseException:
            raw.close()
            raise

    def register(self, password: str, confirmation: str) -> None:
        validate_credentials(self.name, password)
        if password != confirmation:
            raise ValueError("Passwords do not match")
        deadline = time.monotonic() + CLIENT_LOGIN_TIMEOUT
        with self._open_tls(deadline) as sock:
            send_tcp(sock, dict(type="register", name=self.name, password=password), deadline)
            response = TCPReader(sock).read(deadline)
            if response.get("type") != "registered":
                raise RuntimeError(response.get("message", "Registration failed"))

    def connect(self, password: str | None = None) -> None:
        if not self._lifecycle_lock.acquire(blocking=False):
            raise RuntimeError("Client is already connecting or closing")
        try:
            if self.tcp is not None or self.status != "disconnected":
                raise RuntimeError("Client is already connected")
                
            validate_credentials(self.name, password)
            self._reset_session(clear_events=True)
            self._set_status("connecting")
            
            session = {
                "id": object(), "congestion": CubicController(),
                "stop": threading.Event(),
                "finalize_queue": queue.Queue(maxsize=FILE_WRITE_QUEUE),
                "file_resources": {}, "receipts": {},
                "tcp_send_lock": threading.Lock(),
            }
            self._session = session
            try:
                reader = self._establish_session(session, password)
                self._start_session_workers(session, reader)
            except BaseException:
                self._cleanup(logout=False)
                raise
        finally:
            self._lifecycle_lock.release()

    def _establish_session(self, session: dict[str, Any], password: str) -> TCPReader:
        deadline = time.monotonic() + CLIENT_LOGIN_TIMEOUT
        self.tcp = self._open_tls(deadline)
        session["tcp"] = self.tcp
        
        welcome, reader = client_login(self.tcp, self.name, password, deadline)
        self.f = reader.security.f
        session["tcp_security"] = reader.security
        session["udp_security"] = Channel(self.f, welcome["session"])
        self.token = welcome["token"]
        self.address = (self.tcp.getpeername()[0], welcome["udp_port"])
        self.tcp.setblocking(False)
        reader.wait_timeout = SESSION_TIMEOUT
        
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        session["udp"] = self.udp
        self.udp.bind(("0.0.0.0", 0))
        self.udp.settimeout(UDP_TIMEOUT)
        self.send_raw({"type": "heartbeat"})
        return reader

    def _start_session_workers(self, session: dict[str, Any], reader: TCPReader) -> None:
        self.running.set()
        
        def run_worker(target, *args):
            try:
                target(*args)
            except Exception as exc:
                if self._session is session and not session["stop"].is_set():
                    self._request_disconnect(session, f"Worker failed: {exc}")
                    
        self.threads = [
            threading.Thread(target=run_worker, args=(self.listen, session), daemon=True),
            threading.Thread(target=run_worker, args=(self.heartbeats, session), daemon=True),
            threading.Thread(target=run_worker, args=(self.listen_tcp, session, reader), daemon=True),
            threading.Thread(target=run_worker, args=(self.finalize_worker, session), daemon=True),
        ]
        for t in self.threads:
            t.start()
            
        with self._state_lock:
            self._set_status("connected")

    def _reset_session(self, *, clear_events=False):
        self.token = self.f = self.address = None
        self.names = []
        self.presence_revision = -1
        self.messages_seen.clear()
        self.chat_inbox = ChatInbox(self.events.put)
        
        for mid, record in self.outgoing_chats.items():
            if not record["reported"]:
                record["reported"] = True
                self.events.put({"type": "chat_send_failed", "id": mid, "reason": "session_ended"})
            record["done"].set()
            
        self.outgoing_chats.clear()
        self._file_transfers.reset()
        self.files.clear()
        
        with self.pending_lock:
            self.pending.clear()
            
        if clear_events:
            while not self.events.empty():
                try:
                    self.events.get_nowait()
                except queue.Empty:
                    break

    @staticmethod
    def _close_socket(sock):
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _detach_session(self, reason=None):
        session = self._session
        if session is not None:
            session["stop"].set()
            jobs = session.get("finalize_queue")
            if jobs:
                while not jobs.empty():
                    try:
                        jobs.get_nowait()
                        jobs.task_done()
                    except queue.Empty:
                        break
                        
        self.running.clear()
        self._close_socket(self.tcp)
        self._close_socket(self.udp)
        self.tcp = self.udp = self._session = None
        
        self._reset_session()
        self._set_status("disconnected", reason)
        self.events.put({"type": "presence", "names": []})
        if reason:
            self.events.put({"type": "error", "message": reason})

    def _cleanup(self, *, logout):
        with self._state_lock:
            if logout and self.tcp and self.token:
                try:
                    self.send_control({"type": "logout"}, self._session)
                except (OSError, ValueError):
                    pass
            self._detach_session()
            
        current = threading.current_thread()
        for thread in self.threads:
            if thread is not current and thread.is_alive():
                thread.join(timeout=1.0)
        self.threads.clear()

    def _request_disconnect(self, session, reason):
        with self._state_lock:
            if self._session is session and not session["stop"].is_set():
                self._detach_session(reason)

    def close(self) -> None:
        if threading.current_thread() in self.threads:
            with self._state_lock:
                self._detach_session()
            return
            
        if not self._lifecycle_lock.acquire(timeout=SHUTDOWN_TIMEOUT):
            return
        try:
            self._cleanup(logout=True)
        finally:
            self._lifecycle_lock.release()

    def send_control(self, message: dict[str, Any], session: dict[str, Any] | None, *, deadline: float | None = None) -> None:
        validate_tcp(message, from_client=True)
        if session is None:
            raise ConnectionError("Client session ended")
            
        deadline = (time.monotonic() + LOGOUT_TIMEOUT) if deadline is None else deadline
        lock = session["tcp_send_lock"]
        if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("TCP control writer busy")
        try:
            if self._session is not session or session["stop"].is_set():
                raise ConnectionError("Client session ended")
            sock = session["tcp"]
            if hasattr(sock, "fileno"):
                write_tcp(sock, message, deadline, security=session["tcp_security"])
            else:
                send_tcp(sock, message, deadline=deadline, security=session["tcp_security"])
        finally:
            lock.release()

    def send_raw(self, message: dict[str, Any]) -> None:
        with self._state_lock:
            if self.udp is None or self.token is None:
                raise ConnectionError("Client is disconnected")
            packet = dict(message, **{"from": self.name, "token": self.token})
            validate_udp(packet, from_client=True)
            raw = encode_udp(packet, self.f, self._session["udp_security"])
            try:
                self.udp.sendto(raw, self.address)
            except OSError as exc:
                if not retryable(exc, udp=True):
                    raise

    def heartbeats(self, session):
        while self.running.is_set() and not session["stop"].is_set():
            try:
                with self._state_lock:
                    if self._session is not session:
                        return
                    self.send_raw({"type": "heartbeat"})
            except OSError as exc:
                if retryable(exc, udp=True):
                    time.sleep(0.5)
                    continue
                self._request_disconnect(session, str(exc))
                return
            session["stop"].wait(HEARTBEAT_INTERVAL)

    def _apply_presence(self, msg):
        if msg["revision"] >= self.presence_revision:
            self.presence_revision = msg["revision"]
            self.names = list(msg["names"])
            self.chat_inbox.set_peers(self.names)
            self.events.put({"type": "presence", "names": self.names, "revision": self.presence_revision})

    def listen_tcp(self, session, reader):
        try:
            while not session["stop"].is_set():
                try:
                    msg = reader.read()
                except socket.timeout:
                    continue
                validate_tcp(msg, from_client=False)
                with self._state_lock:
                    if self._session is not session:
                        return
                    if msg["type"] == "users":
                        self._apply_presence(msg)
                    elif msg["type"] == "chat_status":
                        self._receive_chat_status(msg, session)
                    elif msg["type"] == "file_status":
                        self._file_transfers.receive_status(msg, session)
                    else:
                        self._file_transfers.cancel(msg, session)
        except (OSError, ValueError) as exc:
            self._request_disconnect(session, f"Server connection lost: {exc}")

    def listen(self, session):
        udp = session["udp"]
        while self.running.is_set() and not session["stop"].is_set():
            with self._state_lock:
                if self._session is not session:
                    return
                self.chat_inbox.flush()
                gap_delay = self.chat_inbox.gap_delay(time.monotonic())
                
            try:
                wait = UDP_TIMEOUT if gap_delay is None else min(UDP_TIMEOUT, gap_delay)
                if not select.select([udp], [], [], wait)[0]:
                    continue
                raw, peer = udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                if retryable(exc, udp=True):
                    time.sleep(0.1)
                    continue
                self._request_disconnect(session, str(exc))
                break
                
            with self._state_lock:
                if self._session is not session:
                    return
                if peer != self.address or len(raw) > UDP_MTU:
                    continue
                try:
                    record = unseal(raw, self.f)
                    msg = record[3]
                    validate_udp(msg, from_client=False)
                except (ValueError, UnicodeError):
                    continue
                    
                try:
                    session["udp_security"].accept(record)
                except ValueError:
                    continue
                    
                typ = msg["type"]
                if typ == "path_challenge":
                    try:
                        self.send_raw({"type": "path_response", "nonce": msg["nonce"]})
                        self.send_raw({"type": "heartbeat"})
                    except OSError:
                        pass
                elif typ == "presence":
                    self._apply_presence(msg)
                elif typ == "ack":
                    with self.pending_lock:
                        event = self.pending.get(msg["id"])
                    if event:
                        event.set()
                    record_chat = self.outgoing_chats.get(msg["id"])
                    if record_chat:
                        self._chat_accepted(msg["id"], record_chat)
                elif typ == "data":
                    mid = msg["id"]
                    if msg["kind"] == "chat":
                        if not self.chat_inbox.accept(msg):
                            continue
                        try:
                            self.send_raw({"type": "ack", "id": mid})
                        except OSError:
                            pass
                        continue
                        
                    try:
                        accepted = self.on_data(msg)
                        if accepted:
                            self.send_raw({"type": "ack", "id": mid})
                    except (ValueError, KeyError, OSError) as exc:
                        self.events.put({"type": "error", "message": str(exc)})

    def validate_transfer_packet(self, msg): return self._file_transfers.validate_transfer_packet(msg)
    def on_data(self, msg): return self._file_transfers.on_data(msg)
    def finish_file(self, key): return self._file_transfers.finish_file(key)
    def finalize_worker(self, session): return self._file_transfers.finalize_worker(session)
    def _finalize_file(self, session, key, f): return self._file_transfers._finalize_file(session, key, f)
    
    def _capture_session(self):
        with self._state_lock:
            if self.status != "connected" or self._session is None:
                raise ConnectionError("Client session ended")
            return self._session

    def send_packets(self, packets, window=SEND_WINDOW, retries=CLIENT_RETRIES, timeout=RETRY_TIMEOUT, *, session=None, file_record=None, deadline=None):
        session = self._capture_session() if session is None else session
        with self._state_lock:
            congestion = session.setdefault("congestion", CubicController())
            
        inflight = {}
        i = 0
        try:
            while i < len(packets) or inflight:
                if file_record is not None:
                    self._file_transfers.check_sending(file_record, deadline)
                    if file_record["result"] is not None:
                        return
                        
                if session is not self._session or self.status != "connected":
                    raise ConnectionError("Session ended")
                    
                while i < len(packets) and len(inflight) < window:
                    p = packets[i]
                    ev = threading.Event()
                    with self.pending_lock:
                        self.pending[p["id"]] = ev
                    inflight[p["id"]] = (p, ev, 0, 0)
                    i += 1
                    
                for mid, (p, ev, tries, last) in list(inflight.items()):
                    if ev.is_set():
                        congestion.acknowledge(mid)
                        del inflight[mid]
                        with self.pending_lock:
                            self.pending.pop(mid, None)
                        continue
                        
                    if tries and not congestion.retry_due(mid, time.monotonic(), timeout):
                        continue
                    if tries >= retries:
                        raise TimeoutError(f"No ACK for packet {mid}")
                    if not congestion.try_send(mid, minimum_retry=timeout):
                        continue
                        
                    try:
                        with self._state_lock:
                            if self._session is not session or self.status != "connected":
                                raise ConnectionError("Session ended")
                            self.send_raw(p)
                    except OSError as exc:
                        if not retryable(exc, udp=True):
                            self._request_disconnect(session, str(exc))
                            raise
                    inflight[mid] = (p, ev, tries + 1, time.monotonic())
                time.sleep(SEND_POLL_INTERVAL)
        finally:
            with self.pending_lock:
                for mid in inflight:
                    self.pending.pop(mid, None)
                    congestion.discard(mid)

    def packet(self, to: str, kind: str, payload: str = "", meta: dict[str, Any] | None = None) -> dict[str, Any]:
        return data_packet(to, kind, payload, meta)

    def _chat_accepted(self, mid, record): return self._chat_sender._chat_accepted(mid, record)
    def _receive_chat_status(self, msg, session): return self._chat_sender._receive_chat_status(msg, session)
    def _preflight_chat(self, packet): return self._chat_sender._preflight_chat(packet)
    def chat(self, recipient: str, text: str) -> None: return self._chat_sender.chat(recipient, text)
    def file(self, recipient: str, path: str | Path) -> None: return self._file_transfers.file(recipient, path)


def main() -> int:
    from collab.client.cli import main as cli_main
    return cli_main()

if __name__ == "__main__":
    raise SystemExit(main())