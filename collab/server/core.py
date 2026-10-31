"""Bounded threaded TCP sessions and encrypted UDP relay."""

from __future__ import annotations

import argparse
import errno
import logging
import math
import select
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from collections import OrderedDict, deque
from contextlib import ExitStack, nullcontext
from functools import wraps
from typing import Any

from cryptography.fernet import Fernet

from collab.accounts import Accounts, AuthLimiter
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
    UDP_PATH_CHALLENGE_INTERVAL,
    UDP_PATH_CHALLENGE_TIMEOUT,
)
from collab.shared.protocol import validate_tcp, validate_udp
from collab.shared.resilience import Cleanup, RetryDelay, SendBackoff, retryable
from collab.transport.congestion import CubicController
from collab.transport.handshake import server_login
from collab.transport.security import Channel, nonce, unseal
from collab.transport.tcp import TCPReader, frame_tcp, send_tcp
from collab.transport.tls import server_context
from collab.transport.udp import encode_udp, udp_frame_size

log = logging.getLogger(__name__)


class Server:
    """Own account storage, active sessions, and the TCP/UDP relay workers.

    The registry lock protects sessions and routing state. Lifecycle ownership
    serializes startup/cleanup; worker failures signal shutdown without waiting for
    that ownership. Session gates serialize UDP sends with session removal.

    Attributes:
        host: Address used to bind the TCP and UDP listeners.
        tcp_port: TCP port, updated after an OS-assigned bind when configured as zero.
        udp_port: UDP port, updated after an OS-assigned bind when configured as zero.
        database: SQLite account path used during start().
        users: Username-to-session registry, protected by lock.
        connections: Accepted sockets, including unauthenticated connections.
        status: Current server lifecycle status.
    """

    status: str

    def __init__(
        self,
        host: str = "127.0.0.1",
        tcp_port: int = 9000,
        udp_port: int = 9001,
        *,
        database: str = "accounts.sqlite3",
        auth_limit: int = 10,
        auth_window: float = 60,
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
        for value in (
            session_expiry,
            session_check_interval,
            file_idle_timeout,
            file_transfer_timeout,
            auth_window,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("Session timing must be finite and positive")
        for value in (
            max_connections,
            max_pending_packets,
            max_pending_per_recipient,
            auth_limit,
        ):
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
        self.database = database
        self.accounts = None
        self.auth_limiter = AuthLimiter(limit=auth_limit, window=auth_window)
        self.tls_context = (
            server_context(certfile, keyfile) if certfile and keyfile else None
        )
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
        """Return a copy of the first recorded startup or worker failure.

        Returns:
            Failure details, or None if the current run has not recorded a failure.
        """
        with self._error_lock:
            return None if self._last_error is None else dict(self._last_error)

    def _request_stop(self, worker=None, error=None, run_id=None):
        """Signal shutdown and record the first worker failure for the active run.

        Only the error lock is acquired; this path does not join workers or wait for
        lifecycle ownership. Requests tagged with an older run identity are ignored.

        Args:
            worker: Optional worker name included in failure details.
            error: Optional failure recorded if no earlier error exists.
            run_id: Optional run identity used to reject stale worker callbacks.
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
        """Close resources after a worker failure, unless another closer owns shutdown."""
        self._started.wait()
        self._shutdown_requested.wait()
        if not self._lifecycle_lock.acquire(False):
            return
        try:
            if self.status != "stopped":
                try:
                    self._stop()
                except RuntimeError:
                    log.exception("Server cleanup incomplete")
        finally:
            self._lifecycle_lock.release()

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

            try:
                thread.start()
            except BaseException:
                self.threads.remove(thread)
                if group is not None:
                    group.discard(thread)
                raise
        return thread

    def start(self) -> None:
        """Initialize accounts, bind listeners, and start owned server workers.

        Listeners and workers created during startup are cleaned up if startup fails.
        An existing stopped instance can start again once its workers have exited.

        Raises:
            ValueError: A TLS certificate/private-key context was not configured.
            RuntimeError: A lifecycle operation is active or the server is not fully stopped.
            OSError: Listener creation or binding fails.
        """
        if not self._lifecycle_lock.acquire(False):
            raise RuntimeError("Server lifecycle operation in progress")
        try:
            if self.status != "stopped" or any(t.is_alive() for t in self.threads):
                raise RuntimeError("Server is not stopped")
            if self.tls_context is None:
                raise ValueError("TLS certificate and private key are required")
            self.accounts = Accounts(self.database)
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
        """Release server resources while retaining failures for a cleanup retry.

        The caller owns the lifecycle lock. Registry snapshots are taken under the
        registry lock; sockets are closed and workers joined after releasing it.

        Args:
            deadline: Absolute monotonic deadline in seconds, or None for the default.

        Raises:
            RuntimeError: Registry access, worker termination, or resource cleanup fails.
        """
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        cleanup = Cleanup()
        self._request_stop()
        self._started.set()
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

        self.threads = [t for t in self.threads if t.is_alive()]
        if any(t is not current for t in self.threads):
            cleanup.errors.append(("workers", RuntimeError("workers still running")))
        if not cleanup.errors:
            self.connections.clear()
            self.handler_threads.clear()
            self.writer_threads.clear()
            self.background_threads.clear()
            self.tcp = self.udp = None
            self.status = "stopped"
        cleanup.finish("Server shutdown incomplete")

    def close(self) -> None:
        """Stop listeners and sessions and join workers within the shutdown deadline.

        A server worker only signals shutdown; lifecycle ownership and joining are left
        to the supervisor or an external closer.

        Raises:
            RuntimeError: Lifecycle ownership or resource cleanup cannot complete in time.
        """
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
        """Build an online-user snapshot from ready sessions.

        The caller must hold the registry lock; pending logins are excluded.

        Args:
            typ: Message type to put in the snapshot, normally presence or users.

        Returns:
            A new dictionary containing sorted usernames and the current revision.
        """
        return {
            "type": typ,
            "names": sorted(n for n, u in self.users.items() if u["ready"]),
            "revision": self.revision,
        }

    def remove_session(self, name, token, *, notify=True, expired_at=None):
        """Remove a matching session and retire its pending work and TCP socket.

        The registry lock is released before acquiring the session UDP gate, then identity
        is checked again under the registry lock. During shutdown, the gate is bypassed.
        A replacement login with the same username is left untouched.

        Args:
            name: Username whose active session is being removed.
            token: Token identifying the expected session.
            notify: Whether to request an online-user update while the server is running.
            expired_at: Optional monotonic observation time in seconds; removal is cancelled
                if the latest activity no longer qualifies as expired at that time.

        Returns:
            True if the matching session was removed; False if absent, replaced, or active.
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
        """Remove sessions still expired after rechecking their latest activity.

        Args:
            now: Monotonic observation time in seconds, or None to read the current clock.
        """
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
            except (
                BlockingIOError,
                InterruptedError,
                ssl.SSLWantReadError,
                ssl.SSLWantWriteError,
            ):
                continue
            if count == 0:
                raise ConnectionError("Control socket closed")
            frame = frame[count:]

    def control_writer(self, name, user):
        """Drain one session's bounded control mailboxes and write TCP frames.

        The mailbox condition is released before socket writes or session removal.
        On exit, the matching session is removed without affecting a replacement login.

        Args:
            name: Username owning the writer.
            user: Session record captured when the writer started.
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
        """Send an online-user snapshot to all ready sessions or a selected user.

        The registry is snapshotted under its lock. UDP sends and TCP mailbox updates
        happen afterward; oversized snapshots use the per-session TCP writer. A session
        whose TCP mailbox cannot accept the snapshot is removed.

        Args:
            target: Optional username to receive the update; None selects all ready users.
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

    def _complete_tls_handshake(self, conn: ssl.SSLSocket, deadline: float) -> None:
        """Keep handshake polling interruptible; the handler retains socket ownership."""
        conn.setblocking(False)
        while True:
            if self.stopping.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("TLS handshake deadline exceeded")
            try:
                conn.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select(
                    [conn], [], [], min(0.1, max(0, deadline - time.monotonic()))
                )
            except ssl.SSLWantWriteError:
                select.select(
                    [], [conn], [], min(0.1, max(0, deadline - time.monotonic()))
                )
        conn.settimeout(max(0.001, deadline - time.monotonic()))

    def _authenticate_request(
        self, request: dict[str, Any], conn: socket.socket, deadline: float
    ) -> bool:
        """Consume credentials and send failures; only a valid login returns True."""
        if request["type"] == "register":
            try:
                self.accounts.register(request["name"], request.pop("password"))
                response = dict(type="registered")
            except ValueError as exc:
                response = dict(type="error", message=str(exc))
            send_tcp(conn, response, deadline)
            return False
        authenticated = self.accounts.verify(request["name"], request.pop("password"))
        if not authenticated:
            send_tcp(
                conn,
                dict(type="error", message="Invalid username or password"),
                deadline,
            )
        return authenticated

    def handle_client(self, conn, deadline=None):
        """Own TLS authentication, session service, and cleanup for an accepted socket.

        Registration or authentication failure closes without creating an online session.
        Successful login reserves the username under the registry lock. Expected socket,
        validation, lifecycle, and database errors are logged before cleanup.

        Args:
            conn: Accepted TCP socket transferred to this handler.
            deadline: Absolute monotonic authentication deadline in seconds, or None
                for LOGIN_TIMEOUT seconds from the call.
        """
        name = token = None
        deadline = time.monotonic() + LOGIN_TIMEOUT if deadline is None else deadline
        try:
            original = conn
            conn.settimeout(max(0.001, deadline - time.monotonic()))
            conn = self.tls_context.wrap_socket(
                conn, server_side=True, do_handshake_on_connect=False
            )
            with self.lock:
                self.connections.discard(original)
                self.connections.add(conn)
            self._complete_tls_handshake(conn, deadline)
            if not self.auth_limiter.allow(conn.getpeername()[0]):
                send_tcp(
                    conn,
                    dict(
                        type="error",
                        message="Too many authentication attempts; try later",
                    ),
                    deadline,
                )
                return
            request, reader = server_login(conn, deadline, self.stopping)
            if not self.accounts.slots.acquire(
                timeout=max(0, deadline - time.monotonic())
            ):
                raise TimeoutError("Authentication capacity timeout")
            try:
                authenticated = self._authenticate_request(request, conn, deadline)
            finally:
                self.accounts.slots.release()
            if not authenticated:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("Authentication deadline exceeded")
            try:
                validate_tcp(request, from_client=True)
                if request["type"] != "login":
                    raise ValueError("Expected login")
            except ValueError:
                send_tcp(
                    conn,
                    dict(type="error", message="Invalid login"),
                    deadline=deadline,
                    security=reader.security,
                )
                return
            name = request["name"]
            with self.lock:
                duplicate = name in self.users
                if not duplicate and self.running.is_set():
                    token = uuid.uuid4().hex
                    session_key = Fernet.generate_key()
                    user = dict(
                        sock=conn,
                        cipher=Fernet(session_key),
                        congestion=CubicController(),
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
                    dict(type="error", message="User already connected"),
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
                    key=session_key.decode(),
                ),
                deadline=deadline,
                security=reader.security,
            )
            user["tcp_security"] = Channel(
                user["cipher"], user["public_id"], server=True, ordered=True
            )
            user["udp_security"] = Channel(
                user["cipher"], user["public_id"], server=True
            )
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
            self._serve_session(name, user, reader)
        except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as exc:
            log.debug("TCP exit: %s", exc)
        finally:
            if token is not None:
                self.remove_session(name, token)
            self._close_socket(conn)
            with self.lock:
                self.connections.discard(conn)

    def _serve_session(
        self, name: str, user: dict[str, Any], reader: TCPReader
    ) -> None:
        """Read control messages until logout or loss; the handler owns cleanup."""
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
                        self.file_transfers.receipt(name, user, msg, time.monotonic())
                    else:
                        self.file_transfers.abort(
                            user, msg["transfer"], time.monotonic()
                        )
            if msg["type"] == "users":
                with self.lock:
                    snapshot = self._snapshot_locked("users")
                if not self._send_control(user, snapshot):
                    break

    def _send_session_udp(self, message, sessions, address=None):
        """Send UDP only while all supplied session identities are still current.

        Session gates are acquired in token order before a short registry check. The
        registry lock is released before encryption or socket I/O. Source and destination
        records pin a relay send to the original sessions.

        Args:
            message: Server UDP message dictionary.
            sessions: Ordered username/session pairs, with the destination last.
            address: Optional endpoint override for path challenges; otherwise the
                destination's verified UDP address is used.

        Returns:
            True when sendto() succeeds; False for stale identity, a missing endpoint or
            socket, backoff, a retryable send error, or a socket error during shutdown.

        Raises:
            ValueError: The encoded datagram exceeds the protocol size limit.
            OSError: A non-retryable send error occurs outside shutdown.
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
            raw = encode_udp(
                message, destination["udp_security"].f, destination["udp_security"]
            )
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
        """Validate a datagram before updating endpoint, replay, and relay state.

        The public prefix selects a candidate cipher but is not trusted as authentication.
        Invalid, stale, replayed, and oversize messages are discarded. New endpoints must
        complete an initial path challenge before application traffic can refresh heartbeat state.
        The verified endpoint stays fixed until the client logs in again.

        Args:
            raw: Received datagram bytes, including the public lookup prefix.
            addr: Source IP/port tuple supplied by recvfrom().
        """
        if len(raw) > UDP_MTU:
            return
        try:
            context = raw[:32].decode("ascii")
            with self.lock:
                candidates = [
                    u["udp_security"].f
                    for u in self.users.values()
                    if u["public_id"] == context and u["ready"] and "udp_security" in u
                ]
            if not candidates:
                return
            record = unseal(raw, candidates[0])
            msg = record[3]
            validate_udp(msg, from_client=True)
        except (ValueError, UnicodeError):
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
            if user["udp_addr"] is not None and user["udp_addr"] != addr:
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
                            if "congestion" in user:
                                user["congestion"].acknowledge(msg["id"], now)
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
        """Delegate a validated application packet to the session-bound relay router.

        Args:
            msg: Client data packet with validated sender credentials and schema.
            source_addr: Endpoint used for the ingress ACK after admission.

        Returns:
            True if the packet is accepted; False if identity, capacity, or routing rejects it.
        """
        return self._router.route(msg, source_addr)

    def retransmit_once(self, now=None):
        """Run one relay retry and expiry pass at the supplied monotonic time.

        Args:
            now: Optional monotonic time in seconds; None reads the current clock.
        """
        return self._router.retransmit_once(now)

    def retransmit_loop(self):
        while not self.stopping.is_set():
            self.retransmit_once()
            self.stopping.wait(RETRY_POLL_INTERVAL)


def main() -> int:
    """Run the server until interruption or a supervised worker failure.

    Returns:
        Zero for a normal interrupt; one for a reported startup, worker, or cleanup error.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=9000)
    parser.add_argument("--udp-port", type=int, default=9001)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--database", default="accounts.sqlite3")
    parser.add_argument("--auth-limit", type=int, default=10)
    parser.add_argument("--auth-window", type=float, default=60)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server = None
    result = 0
    try:
        server = Server(
            args.host,
            args.tcp_port,
            args.udp_port,
            database=args.database,
            auth_limit=args.auth_limit,
            auth_window=args.auth_window,
            certfile=args.cert,
            keyfile=args.key,
        )
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
