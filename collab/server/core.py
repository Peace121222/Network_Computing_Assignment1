"""Bounded threaded TCP sessions and encrypted UDP relay."""

from __future__ import annotations
from typing import Any


from collab.shared.limits import (
    SHUTDOWN_TIMEOUT,
    CONTROL_TIMEOUT,
    UDP_PATH_CHALLENGE_TIMEOUT,
    UDP_PATH_CHALLENGE_INTERVAL,
)

import argparse
import errno
from functools import wraps
import sys
from collections import deque, OrderedDict
from contextlib import ExitStack, nullcontext
import logging
import math
import select
import socket
import threading
import time
import uuid
from collab.shared.limits import (
    LOGIN_TIMEOUT,
    SESSION_TIMEOUT,
    SERVER_POLL_TIMEOUT,
    RETRY_POLL_INTERVAL,
    SESSION_EXPIRY,
    SESSION_CHECK_INTERVAL,
)
from collab.transport.udp import cipher, encode_udp
from collab.transport.tcp import send_tcp, frame_tcp
from collab.transport.handshake import server_login
from collab.transport.security import Channel, nonce, unseal
from collab.transport.udp import udp_frame_size
from collab.shared.limits import UDP_MTU
from collab.shared.protocol import validate_tcp, validate_udp

from collab.shared.resilience import Cleanup, RetryDelay, SendBackoff, retryable
from collab.server.routing import RelayRouter
from collab.server.file_transfers import ServerFileTransfers
from collab.shared.limits import FILE_IDLE_TIMEOUT, FILE_TRANSFER_TIMEOUT

log = logging.getLogger(__name__)


class Server:
    """Bounded relay server with session-owned handlers and writers.

    Concurrency: lock protects the registry, revision and routing state. Lifecycle
    ownership serializes start/cleanup; _error_lock protects first-error and stop
    requests. Session udp_lock gates serialize sends/removal; control_condition protects
    each writer mailbox. Workers signal stop without waiting for lifecycle ownership.
    """

    status: str

    def __init__(
        self,
        host: str = "127.0.0.1",
        tcp_port: int = 9000,
        udp_port: int = 9001,
        *,
        session_expiry: float = SESSION_EXPIRY,
        session_check_interval: float = SESSION_CHECK_INTERVAL,
        max_connections: int = 64,
        max_pending_packets: int = 8192,
        max_pending_per_recipient: int = 1024,
        file_idle_timeout: float = FILE_IDLE_TIMEOUT,
        file_transfer_timeout: float = FILE_TRANSFER_TIMEOUT,
    ) -> None:
        for value in (
            session_expiry,
            session_check_interval,
            file_idle_timeout,
            file_transfer_timeout,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("Session timing must be finite and positive")
        for value in (max_connections, max_pending_packets, max_pending_per_recipient):
            if type(value) is not int or value <= 0:
                raise ValueError("Resource limits must be positive integers")
        self.host, self.tcp_port, self.udp_port = host, tcp_port, udp_port
        self.session_expiry, self.session_check_interval = (
            session_expiry,
            session_check_interval,
        )
        self.max_connections = max_connections
        self.max_pending_packets = max_pending_packets
        self.max_pending_per_recipient = max_pending_per_recipient
        self.file_idle_timeout, self.file_transfer_timeout = (
            file_idle_timeout,
            file_transfer_timeout,
        )
        self.f = cipher()
        self._udp_backoff = SendBackoff(log)
        self.lock = threading.RLock()
        self._lifecycle_lock = threading.Lock()
        self.status = "stopped"
        self._error_lock = threading.Lock()
        self._last_error = None
        self._retired_sockets = []
        self._run_id = None
        self._started = threading.Event()
        self._shutdown_requested = threading.Event()
        self._cleanup_active = threading.Event()
        self.users = {}
        self.connections = set()
        self.running = threading.Event()
        self.stopping = threading.Event()
        self.presence_dirty = threading.Event()
        self.threads = []
        self.background_threads = []
        self.handler_threads = set()
        self.writer_threads = set()
        self.pending = {}
        self.chat_records = {}
        self._router = RelayRouter(self)
        self.file_transfers = ServerFileTransfers(self)
        self.revision = 0
        self.tcp = self.udp = None

    @property
    def last_error(self) -> dict[str, Any] | None:
        with self._error_lock:
            return None if self._last_error is None else dict(self._last_error)

    def _request_stop(self, worker=None, error=None, run_id=None):
        """Signal-only worker path: hold _error_lock, never acquire the lifecycle lock or
        join a worker. The first error and run identity prevent stale worker failures
        affecting a later run.
        """
        with self._error_lock:
            if run_id is not None and run_id is not self._run_id:
                return
            if error is not None and self._last_error is None:
                self._last_error = {
                    "worker": worker,
                    "exception": type(error).__name__,
                    "message": str(error),
                }
            self.status = "stopping"
            self.running.clear()
            self.stopping.set()
            self._shutdown_requested.set()
            self.presence_dirty.set()

    def _guard_worker(self, target):
        gate, run_id = self._started, self._run_id

        @wraps(target)
        def run(*args):
            gate.wait()
            if self.stopping.is_set() or self._run_id is not run_id:
                return
            try:
                target(*args)
                if not self.stopping.is_set():
                    raise RuntimeError("Worker returned unexpectedly")
            except BaseException as exc:
                if not self.stopping.is_set():
                    self._request_stop(
                        getattr(target, "__name__", "unknown"), exc, run_id
                    )
                    log.exception(
                        "Critical worker %s failed",
                        getattr(target, "__name__", "unknown"),
                    )

        run.__self__ = self
        return run

    def supervise(self):
        self._started.wait()
        self._shutdown_requested.wait()
        while True:
            # A closer holding the lifecycle lock will join us; never wait on it.
            if self._cleanup_active.is_set():
                return
            if self._lifecycle_lock.acquire(False):
                try:
                    if self.status != "stopped":
                        try:
                            self._stop()
                        except RuntimeError:
                            log.exception("Supervisor cleanup incomplete")
                finally:
                    self._lifecycle_lock.release()
                return
            if self._cleanup_active.wait(0.01):
                return

    def _start_thread(self, target, args=(), group=None, *, critical=False):
        entry = self._guard_worker(target) if critical else target
        thread = threading.Thread(target=entry, args=args, daemon=True)
        with self.lock:
            if self.stopping.is_set():
                raise RuntimeError("Server is stopping")
            self.threads = [t for t in self.threads if t.is_alive()]
            self.handler_threads = {t for t in self.handler_threads if t.is_alive()}
            self.writer_threads = {t for t in self.writer_threads if t.is_alive()}
            self.threads.append(thread)
            if group is not None:
                group.add(thread)
            # Registration and start are atomic with respect to shutdown snapshots.
            try:
                thread.start()
            except BaseException:
                self.threads.remove(thread)
                if group is not None:
                    group.discard(thread)
                raise
        return thread

    def start(self) -> None:
        if not self._lifecycle_lock.acquire(False):
            raise RuntimeError("Server lifecycle operation in progress")
        try:
            if self.status != "stopped" or any(t.is_alive() for t in self.threads):
                raise RuntimeError("Server is not stopped")
            self.status = "starting"
            self._last_error = None
            self._run_id = object()
            self._started = threading.Event()
            self._shutdown_requested.clear()
            self.stopping.clear()
            self._udp_backoff.reset()
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
                self.running.set()
                self.background_threads = [self._start_thread(self.supervise)]
                for task in (
                    self.accept_loop,
                    self.udp_loop,
                    self.retransmit_loop,
                    self.expiry_loop,
                    self.presence_loop,
                ):
                    self.background_threads.append(
                        self._start_thread(task, critical=True)
                    )
                self.status = "running"
            except BaseException as exc:
                self._last_error = {
                    "worker": "startup",
                    "exception": type(exc).__name__,
                    "message": str(exc),
                }
                try:
                    self._stop()
                except Exception:
                    log.exception("Startup rollback incomplete")
                raise
        finally:
            self._lifecycle_lock.release()
            self._started.set()

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
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise

    def _stop(self, deadline=None):
        """Caller owns _lifecycle_lock. _cleanup_active tells the supervisor to exit
        instead of waiting for that owner. Snapshot under the registry lock, then close
        sockets and join outside it; retain unfinished resources.
        """
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        cleanup = Cleanup()
        self._cleanup_active.set()
        self._request_stop()
        self._started.set()
        try:
            connections, sessions = [], []
            locked = self.lock.acquire(timeout=max(0, deadline - time.monotonic()))
            if locked:
                try:
                    connections, sessions = list(self.connections), list(
                        self.users.values()
                    )
                    self.revision += sum(u["ready"] for u in sessions)
                    self.users.clear()
                    self.pending.clear()
                    self.chat_records.clear()
                    self.file_transfers.records.clear()
                finally:
                    self.lock.release()
            else:
                cleanup.errors.append(("registry", RuntimeError("registry lock busy")))
            sockets = (
                [self.tcp, self.udp]
                + connections
                + [u["sock"] for u in sessions]
                + self._retired_sockets
            )
            unique = {id(sock): sock for sock in sockets if sock is not None}
            for sock in unique.values():
                before = len(cleanup.errors)
                cleanup.attempt("socket", self._close_socket, sock)
                if len(cleanup.errors) != before:
                    if sock not in self._retired_sockets:
                        self._retired_sockets.append(sock)
                elif sock in self._retired_sockets:
                    self._retired_sockets.remove(sock)
            for user in sessions:
                if "writer_stop" in user:
                    user["writer_stop"].set()
            current = threading.current_thread()
            for thread in list(self.threads):
                if thread is not current and thread.ident is not None:
                    cleanup.attempt(
                        "worker join", thread.join, max(0, deadline - time.monotonic())
                    )
            # Lifecycle ownership excludes new registration after stopping was set.
            self.threads = [t for t in self.threads if t.is_alive()]
            if any(t is not current for t in self.threads):
                cleanup.errors.append(
                    ("workers", RuntimeError("workers still running"))
                )
            if not cleanup.errors:
                self.connections.clear()
                self.handler_threads.clear()
                self.writer_threads.clear()
                self.background_threads.clear()
                self.tcp = self.udp = None
                self.status = "stopped"
            cleanup.finish("Server shutdown incomplete")
        finally:
            self._cleanup_active.clear()

    def close(self) -> None:
        if threading.current_thread() in self.threads:
            self._request_stop()
            return
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT
        if not self._lifecycle_lock.acquire(
            timeout=max(0, deadline - time.monotonic())
        ):
            raise RuntimeError("Server shutdown incomplete: lifecycle lock busy")
        try:
            self._stop(deadline)
        finally:
            self._lifecycle_lock.release()

    def _snapshot_locked(self, typ: str = "presence") -> dict[str, Any]:
        """Caller must hold self.lock. Return the requested message type, sorted ready
        usernames and current revision; pending logins are never published.
        """
        return {
            "type": typ,
            "names": sorted(n for n, u in self.users.items() if u["ready"]),
            "revision": self.revision,
        }

    def remove_session(self, name, token, *, notify=True, expired_at=None):
        """Look up under self.lock, release it before waiting for the session gate, then
        recheck identity under the registry lock. Never hold the registry lock while
        waiting for a gate or writing sockets.
        """
        with self.lock:
            user = self.users.get(name)
            if user is None or user["token"] != token:
                return False
            gate = user.setdefault("udp_lock", threading.RLock())
        with nullcontext() if self.stopping.is_set() else gate:
            with self.lock:
                if self.users.get(name) is not user:
                    return False
                if (
                    expired_at is not None
                    and expired_at - user["last_seen"] < self.session_expiry
                ):
                    return False
                del self.users[name]
                self.file_transfers.remove_session(token, time.monotonic())
                if user["ready"]:
                    self.revision += 1
                for key, item in list(self.pending.items()):
                    if token in (item["source_token"], item["destination_token"]):
                        del self.pending[key]
                        if item["source_token"] != token:
                            self._chat_outcome_locked(
                                item, key[0], "recipient_disconnected"
                            )
                for chat_key, record in list(self.chat_records.items()):
                    if record["source_token"] == token:
                        del self.chat_records[chat_key]
                for other in self.users.values():
                    for stream_key in list(other.get("sequences", {})):
                        if stream_key[1] == token:
                            del other["sequences"][stream_key]
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
        while not self.stopping.wait(self.session_check_interval):
            self.expire_sessions()

    def _send_control(self, user, msg, deadline=None, *, presence=False):
        validate_tcp(msg, from_client=False)
        condition = user["control_condition"]
        with condition:
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
            condition.notify()
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
            except (BlockingIOError, InterruptedError):
                continue
            if count == 0:
                raise ConnectionError("Control socket closed")
            frame = frame[count:]

    def control_writer(self, name, user):
        """control_condition protects mailbox selection only. Release it before the bounded
        TCP write or session cleanup; no global registry lock is held during socket
        writes.
        """
        chat_streak = 0
        file_turn = True
        try:
            while not self.stopping.is_set() and not user["writer_stop"].is_set():
                with user["control_condition"]:
                    mailbox = user["chat_mailbox"]
                    file_mailbox = user.setdefault("file_mailbox", OrderedDict())

                    def available():
                        return (
                            user["control"]
                            or user["presence"] is not None
                            or any(value is not None for value in mailbox.values())
                            or any(value is not None for value in file_mailbox.values())
                            or user["writer_stop"].is_set()
                        )

                    user["control_condition"].wait_for(available, 0.1)
                    if user["writer_stop"].is_set():
                        return
                    ready = next(
                        (
                            (key, value)
                            for key, value in mailbox.items()
                            if value is not None
                        ),
                        None,
                    )
                    file_ready = next(
                        ((k, v) for k, v in file_mailbox.items() if v is not None), None
                    )
                    control_ready = (
                        bool(user["control"])
                        or user["presence"] is not None
                        or file_ready is not None
                    )
                    selected_file = None
                    selected_key = None
                    if ready is not None and (chat_streak < 3 or not control_ready):
                        selected_key, msg = ready
                        # Keep the reserved slot until the final result is written.
                        mailbox[selected_key] = None
                        chat_streak += 1
                    elif control_ready:
                        chat_streak = 0
                        if file_ready is not None and (
                            file_turn
                            or not (user["control"] or user["presence"] is not None)
                        ):
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
                        if file_mailbox.get(selected_file) is None:
                            file_mailbox.pop(selected_file, None)
                if selected_key is not None:
                    with user["control_condition"]:
                        if mailbox.get(selected_key) is None:
                            mailbox.pop(selected_key, None)
        except (OSError, ValueError):
            pass
        finally:
            self.remove_session(name, user["token"])

    def presence_loop(self):
        while not self.stopping.is_set():
            if self.presence_dirty.wait(0.1):
                self.presence_dirty.clear()
                if not self.stopping.is_set():
                    self.publish_presence()

    def publish_presence(self, target=None):
        """Snapshot ready sessions under self.lock; enqueue controls or send UDP after
        releasing it. TCP writes belong to per-session writers, not this shared loop.
        """
        with self.lock:
            snapshot = self._snapshot_locked()
            targets = [
                (n, u)
                for n, u in self.users.items()
                if u["ready"] and (target is None or n == target)
            ]
        raw = snapshot if udp_frame_size(snapshot) <= UDP_MTU else None
        for name, user in targets:
            if raw is not None:
                self._send_session_udp(raw, [(name, user)])
            elif not self._send_control(
                user, dict(snapshot, type="users"), presence=True
            ):
                self.remove_session(name, user["token"])

    def accept_loop(self):
        delay = RetryDelay(self.stopping, log, "accept")
        while self.running.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self.stopping.is_set():
                    return
                if retryable(exc):
                    delay.wait(exc)
                    continue
                raise
            delay.reset()
            with self.lock:
                accepted = (
                    self.running.is_set()
                    and len(self.connections) < self.max_connections
                )
                if accepted:
                    self.connections.add(conn)
            if not accepted:
                self._close_socket(conn)
                continue
            try:
                self._start_thread(
                    self.handle_client,
                    (conn, time.monotonic() + LOGIN_TIMEOUT),
                    self.handler_threads,
                )
            except RuntimeError:
                self._close_socket(conn)
                with self.lock:
                    self.connections.discard(conn)
                if self.stopping.is_set():
                    break
                log.exception("Could not start connection handler")

    def handle_client(self, conn, deadline=None):
        name = token = None
        deadline = time.monotonic() + LOGIN_TIMEOUT if deadline is None else deadline
        try:
            hello, reader, transcript = server_login(
                conn, self.f, deadline, self.stopping
            )
            try:
                validate_tcp(hello, from_client=True)
                if hello["type"] != "login":
                    raise ValueError("Expected login")
            except ValueError:
                send_tcp(
                    conn,
                    dict(type="error", message="Invalid login", **transcript),
                    deadline=deadline,
                    security=reader.security,
                )
                return
            name = hello["name"]
            with self.lock:
                duplicate = name in self.users
                if not duplicate and self.running.is_set():
                    token = uuid.uuid4().hex
                    user = dict(
                        sock=conn,
                        token=token,
                        tcp_addr=conn.getpeername(),
                        udp_addr=None,
                        last_seen=time.monotonic(),
                        ready=False,
                        send_lock=threading.Lock(),
                        udp_lock=threading.RLock(),
                        control_condition=threading.Condition(),
                        control=deque(),
                        presence=None,
                        writer_stop=threading.Event(),
                        chat_mailbox=OrderedDict(),
                        public_id=uuid.uuid4().hex,
                        sequences={},
                    )
                    self.users[name] = user
            if duplicate:
                send_tcp(
                    conn,
                    dict(type="error", message="User already connected", **transcript),
                    deadline=deadline,
                    security=reader.security,
                )
                return
            if token is None:
                return
            send_tcp(
                conn,
                dict(
                    type="welcome",
                    token=token,
                    udp_port=self.udp_port,
                    session=user["public_id"],
                    **transcript,
                ),
                deadline=deadline,
                security=reader.security,
            )
            user["tcp_security"] = Channel(
                self.f, user["public_id"], server=True, ordered=True
            )
            user["udp_security"] = Channel(self.f, user["public_id"], server=True)
            reader.security = user["tcp_security"]
            conn.setblocking(False)
            reader.wait_timeout = SESSION_TIMEOUT
            self._start_thread(self.control_writer, (name, user), self.writer_threads)
            with self.lock:
                if self.users.get(name) is not user:
                    return
                user["ready"] = True
                self.revision += 1
            self.presence_dirty.set()
            while self.running.is_set():
                try:
                    msg = reader.read()
                except socket.timeout:
                    continue
                validate_tcp(msg, from_client=True)
                if msg["type"] not in {"logout", "users", "file_receipt", "file_abort"}:
                    raise ValueError("Unexpected TCP message after login")
                if msg["type"] == "logout":
                    break
                if msg["type"] in ("file_receipt", "file_abort"):
                    with self.lock:
                        if self.users.get(name) is not user:
                            break
                        if time.monotonic() - user["last_seen"] >= self.session_expiry:
                            break
                        if msg["type"] == "file_receipt":
                            self.file_transfers.receipt(
                                name, user, msg, time.monotonic()
                            )
                        else:
                            self.file_transfers.abort(
                                user, msg["transfer"], time.monotonic()
                            )
                if msg["type"] == "users":
                    with self.lock:
                        snapshot = self._snapshot_locked("users")
                    if not self._send_control(user, snapshot):
                        break
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            log.debug("TCP exit: %s", exc)
        finally:
            if token is not None:
                self.remove_session(name, token)
            self._close_socket(conn)
            with self.lock:
                self.connections.discard(conn)

    def _send_session_udp(self, message, sessions, address=None):
        # Session gates serialize removal with sends; never wait for them under registry lock.
        """Acquire session gates in token order before the brief registry check. Revalidate
        source/destination identity, release the registry lock, then encode/send. A
        retired session cannot send with a replacement session endpoint.
        """
        unique = {user["token"]: (name, user) for name, user in sessions}
        with ExitStack() as stack:
            for _, user in sorted(unique.values(), key=lambda pair: pair[1]["token"]):
                stack.enter_context(user.setdefault("udp_lock", threading.RLock()))
            with self.lock:
                if any(self.users.get(name) is not user for name, user in sessions):
                    return False
                destination = sessions[-1][1]
                address = destination["udp_addr"] if address is None else address
                udp = self.udp
            if address is None or udp is None:
                return False
            if not self._udp_backoff.ready():
                return False
            raw = encode_udp(message, self.f, destination["udp_security"])
            try:
                udp.sendto(raw, address)
            except OSError as exc:
                if self.stopping.is_set():
                    return False
                if retryable(exc, udp=True):
                    self._udp_backoff.failed(exc)
                    return False
                raise
            self._udp_backoff.reset()
        return True

    def udp_loop(self):
        delay = RetryDelay(self.stopping, log, "UDP receive")
        while self.running.is_set():
            try:
                raw, addr = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                if self.stopping.is_set():
                    return
                if retryable(exc, udp=True):
                    delay.wait(exc)
                    continue
                raise
            delay.reset()
            self.handle_udp(raw, addr)

    def handle_udp(self, raw, addr):
        if len(raw) > UDP_MTU:
            return
        try:
            record = unseal(raw, self.f)
            msg = record[3]
            validate_udp(msg, from_client=True)
        except ValueError:
            return
        name, token = msg["from"], msg["token"]
        challenge = None
        verified = False
        changed = False
        with self.lock:
            user = self.users.get(name)
            if user is None or user["token"] != token or not user["ready"]:
                return
            security = user.get("udp_security")
            if security is None:
                return
            try:
                security.accept(record)
            except ValueError:
                return
            now = time.monotonic()
            expired = now - user["last_seen"] >= self.session_expiry
            if not expired:
                candidate = user.get("udp_candidate")
                if msg["type"] == "path_response":
                    if (
                        candidate is not None
                        and candidate["addr"] == addr
                        and now < candidate["deadline"]
                        and msg["nonce"] == candidate["nonce"]
                    ):
                        changed = user["udp_addr"] != addr
                        user["udp_addr"] = addr
                        user.pop("udp_candidate", None)
                    # Path validation alone never extends the session.
                elif user["udp_addr"] != addr:
                    if (
                        now
                        >= user.get("path_issued_at", float("-inf"))
                        + UDP_PATH_CHALLENGE_INTERVAL
                    ):
                        challenge = dict(type="path_challenge", nonce=nonce())
                        user["udp_candidate"] = dict(
                            addr=addr,
                            nonce=challenge["nonce"],
                            deadline=now + UDP_PATH_CHALLENGE_TIMEOUT,
                        )
                        user["path_issued_at"] = now
                else:
                    verified = True
                    user["last_seen"] = now
                    if msg["type"] == "ack":
                        key = (name, msg["id"])
                        item = self.pending.get(key)
                        if item is not None and item["destination_token"] == token:
                            del self.pending[key]
                            self._chat_outcome_locked(item, name, "delivered")
                            self.file_transfers.acknowledged(item, now)
        if expired:
            self.remove_session(name, token, expired_at=now)
            return
        if challenge is not None:
            self._send_session_udp(challenge, [(name, user)], addr)
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
        while not self.stopping.is_set():
            self.retransmit_once()
            self.stopping.wait(RETRY_POLL_INTERVAL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=9000)
    parser.add_argument("--udp-port", type=int, default=9001)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server = None
    result = 0
    try:
        server = Server(args.host, args.tcp_port, args.udp_port)
        server.start()
        server.stopping.wait()
        if server.last_error is not None:
            print("ERROR: " + server.last_error["message"], file=sys.stderr)
            result = 1
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        result = 1
    except Exception:
        log.exception("Server startup failed")
        result = 1
    finally:
        if server is not None:
            try:
                server.close()
            except Exception as exc:
                log.exception("Server cleanup failed")
                print("ERROR: " + str(exc), file=sys.stderr)
                result = 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
