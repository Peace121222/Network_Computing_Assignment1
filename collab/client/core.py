"""Client socket engine; no high-level networking libraries."""

from __future__ import annotations
from typing import Any


from collab.shared.limits import SHUTDOWN_TIMEOUT

import errno
from functools import wraps
from collections import OrderedDict
import logging
import math
from pathlib import Path
import queue
import select
import socket
import threading
import time
from collab.shared.limits import (
    SEND_WINDOW,
    CLIENT_RETRIES,
    RETRY_TIMEOUT,
    CONNECT_TIMEOUT,
    HEARTBEAT_INTERVAL,
    UDP_TIMEOUT,
    SEND_POLL_INTERVAL,
    CLIENT_LOGIN_TIMEOUT,
    LOGOUT_TIMEOUT,
    SESSION_TIMEOUT,
    UDP_MTU,
)
from collab.transport.udp import encode_udp
from collab.transport.tcp import send_tcp
from collab.shared.protocol import validate_tcp, validate_udp, data_packet
from collab.client.chat_inbox import ChatInbox
from collab.client.file_transfer import FileTransfers, TransferCapacityError
from collab.client.chat_sender import ChatSender
from collab.shared.limits import (
    FILE_IDLE_TIMEOUT,
    FILE_TRANSFER_TIMEOUT,
    FILE_WRITE_QUEUE,
)
from collab.transport.tcp import write_tcp
from collab.transport.handshake import client_login
from collab.transport.tls import client_context
from collab.accounts import validate_credentials
from collab.transport.tcp import send_tcp, TCPReader
from collab.transport.security import Channel, unseal
from collab.shared.resilience import Cleanup, RetryDelay, SendBackoff, retryable

log = logging.getLogger(__name__)


class Client:
    """Socket client with session-owned workers.

    _lifecycle_lock serializes connect/close ownership; _state_lock protects the active
    session and receive/send service state. pending_lock protects hop ACK waiters.
    Worker callbacks must compare session identity and must not wait for lifecycle
    ownership while a closer may be joining them.
    """

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
        for value in (file_idle_timeout, file_transfer_timeout):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("File timeouts must be finite and positive")
        self.file_idle_timeout, self.file_transfer_timeout = (
            file_idle_timeout,
            file_transfer_timeout,
        )
        self.name, self.host, self.port = name, host, port
        self.f = None
        self.cafile, self.server_name = cafile, server_name or host
        self._udp_backoff = SendBackoff(log)
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
        self.tcp = None
        self.udp = None
        self.token = None
        self.address = None
        self.threads = []
        self._retired_sockets = []
        self._lifecycle_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._session = None
        self.status = "disconnected"
        self.presence_revision = -1
        self._operation_context = threading.local()

    def _set_status(self, status, reason=None):
        if self.status != status:
            self.status = status
            event = {"type": "connection", "status": status}
            if reason is not None:
                event["reason"] = reason
            self.events.put(event)

    def _open_tls(self, deadline=None):
        context = client_context(self.cafile)
        raw = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        try:
            if deadline is not None:
                raw.settimeout(max(0.001, deadline - time.monotonic()))
            return context.wrap_socket(raw, server_hostname=self.server_name)
        except BaseException:
            raw.close()
            raise

    def register(self, password, confirmation):
        validate_credentials(self.name, password)
        if password != confirmation:
            raise ValueError("Passwords do not match")
        deadline = time.monotonic() + CLIENT_LOGIN_TIMEOUT
        with self._open_tls(deadline) as sock:
            send_tcp(
                sock, dict(type="register", name=self.name, password=password), deadline
            )
            response = TCPReader(sock).read(deadline)
            if response.get("type") != "registered":
                raise RuntimeError(response.get("message", "Registration failed"))

    def connect(self, password=None) -> None:
        if not self._lifecycle_lock.acquire(blocking=False):
            raise RuntimeError("Client is already connecting or closing")
        try:
            if self.tcp is not None or self.status != "disconnected":
                raise RuntimeError("Client is already connected or still closing")
            self._join_workers()
            if any(t.is_alive() for t in self.threads):
                raise RuntimeError("Previous client workers are still closing")
            validate_credentials(self.name, password)
            self._reset_session(clear_events=True)
            self._udp_backoff.reset()
            self._set_status("connecting")
            session = {
                "id": object(),
                "stop": threading.Event(),
                "finalize_queue": queue.Queue(maxsize=FILE_WRITE_QUEUE),
                "file_resources": {},
                "receipts": {},
                "tcp_send_lock": threading.Lock(),
            }
            self._session = session
            try:
                deadline = time.monotonic() + CLIENT_LOGIN_TIMEOUT
                self.tcp = self._open_tls(deadline)
                session["tcp"] = self.tcp
                hello, reader = client_login(self.tcp, self.name, password, deadline)
                self.f = reader.security.f
                session["tcp_security"] = reader.security
                session["udp_security"] = Channel(self.f, hello["session"])
                self.token = hello["token"]
                self.address = (self.tcp.getpeername()[0], hello["udp_port"])
                self.tcp.setblocking(False)
                reader.wait_timeout = SESSION_TIMEOUT
                self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                session["udp"] = self.udp
                self.udp.bind(("0.0.0.0", 0))
                self.udp.settimeout(UDP_TIMEOUT)
                self.send_raw({"type": "heartbeat"})
                self.threads = [
                    threading.Thread(
                        target=self._guard_worker(self.listen, session),
                        args=(session,),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self._guard_worker(self.heartbeats, session),
                        args=(session,),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self._guard_worker(self.listen_tcp, session),
                        args=(session, reader),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self._guard_worker(self.finalize_worker, session),
                        args=(session,),
                        daemon=True,
                    ),
                ]
                self.running.set()
                # Workers wait until all starts succeed, preventing callbacks during rollback.
                session["started"] = threading.Event()
                for thread in self.threads:
                    thread.start()
                with self._state_lock:
                    self._set_status("connected")
                session["started"].set()
            except BaseException:
                try:
                    self._cleanup(logout=False)
                except Exception:
                    log.exception("Connection rollback incomplete")
                raise
        finally:
            self._lifecycle_lock.release()

    def _reset_session(self, *, clear_events=False):
        self.token = None
        self.f = None
        self.address = None
        self.names = []
        self.presence_revision = -1
        self.messages_seen.clear()
        self.chat_inbox = ChatInbox(self.events.put)
        for mid, record in self.outgoing_chats.items():
            if not record["reported"]:
                record["reported"] = True
                self.events.put(
                    {"type": "chat_send_failed", "id": mid, "reason": "session_ended"}
                )
            record["done"].set()
        self.outgoing_chats.clear()
        self._file_transfers.reset()
        self.files.clear()
        with self.pending_lock:
            self.pending.clear()
        if clear_events:
            while True:
                try:
                    self.events.get_nowait()
                except queue.Empty:
                    break

    @staticmethod
    def _close_socket(sock):
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass
        try:
            sock.close()
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise

    def _join_workers(self, deadline=None):
        """Called by the lifecycle owner outside _state_lock; skip the current and
        unstarted threads and retain live resources for retry.
        """
        current = threading.current_thread()
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        cleanup = Cleanup()
        for thread in self.threads:
            if thread is not current and thread.ident is not None:
                cleanup.attempt(
                    "worker join", thread.join, max(0, deadline - time.monotonic())
                )
        self.threads = [t for t in self.threads if t.is_alive()]
        if any(t is not current for t in self.threads):
            cleanup.errors.append(("workers", RuntimeError("worker still running")))
        else:
            cleanup.attempt("files", self._file_transfers.retry_cleanup)
        for sock in list(self._retired_sockets):
            before = len(cleanup.errors)
            cleanup.attempt("socket", self._close_socket, sock)
            if len(cleanup.errors) == before:
                self._retired_sockets.remove(sock)
        cleanup.finish("Client shutdown incomplete")

    def _detach_session(self, reason=None):
        """Called under state lock; never joins or waits for lifecycle ownership.

        Caller must hold _state_lock. Stop/detach only the current session, preserve
        notification events, and leave joins to the lifecycle owner.
        """
        session = self._session
        if session is not None:
            session["stop"].set()
            jobs = session.get("finalize_queue")
            if jobs is not None:
                while True:
                    try:
                        jobs.get_nowait()
                        jobs.task_done()
                    except queue.Empty:
                        break
            if "started" in session:
                session["started"].set()
        self.running.clear()
        for sock in (self.tcp, self.udp):
            if sock is None:
                continue
            try:
                self._close_socket(sock)
            except Exception as exc:
                if sock not in self._retired_sockets:
                    self._retired_sockets.append(sock)
                self.events.put(
                    {"type": "error", "message": "Socket cleanup failed: " + str(exc)}
                )
        self.tcp = self.udp = None
        self._session = None
        self._reset_session()
        self._set_status("disconnected", reason)
        self.events.put({"type": "presence", "names": []})
        if reason is not None:
            self.events.put({"type": "error", "message": reason})

    def _cleanup(self, *, logout, deadline=None):
        """Caller owns _lifecycle_lock (including failed-connect rollback). Detach under
        _state_lock, release it, then join against the same deadline; workers must not
        acquire lifecycle ownership.
        """
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        cleanup = Cleanup()
        if not self._state_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise RuntimeError("Client shutdown incomplete: state lock busy")
        try:
            if logout and self.tcp is not None and self.token is not None:
                try:
                    self.send_control(
                        {"type": "logout"}, self._session, deadline=deadline
                    )
                except (OSError, ValueError):
                    pass
            cleanup.attempt("session", self._detach_session)
        finally:
            self._state_lock.release()
        cleanup.attempt("workers and files", self._join_workers, deadline)
        cleanup.finish("Client shutdown incomplete")

    def _request_disconnect(self, session, reason):
        """Worker-safe path: acquire _state_lock, compare the captured session, detach
        without joining. Late callbacks from a retired session are ignored.
        """
        with self._state_lock:
            if self._session is session and not session["stop"].is_set():
                self._detach_session(reason)

    def _guard_worker(self, target, session):
        @wraps(target)
        def run(*args):
            if not self._worker_ready(session):
                return
            try:
                target(*args)
                if self._session is session and not session["stop"].is_set():
                    raise RuntimeError("Worker returned unexpectedly")
            except BaseException as exc:
                if self._session is session and not session["stop"].is_set():
                    self._request_disconnect(
                        session, "Client worker failed: " + str(exc)
                    )
                    log.exception(
                        "Client worker %s failed",
                        getattr(target, "__name__", "unknown"),
                    )

        run.__self__ = self
        return run

    def _close_before(self, deadline):
        # A worker must not wait for a lifecycle owner that may be joining it.
        if threading.current_thread() in self.threads:
            with self._state_lock:
                self._detach_session()
            return
        if not self._lifecycle_lock.acquire(
            timeout=max(0, deadline - time.monotonic())
        ):
            raise RuntimeError("Client shutdown incomplete: lifecycle lock busy")
        try:
            self._cleanup(logout=True, deadline=deadline)
        finally:
            self._lifecycle_lock.release()

    def close(self) -> None:
        self._close_before(time.monotonic() + SHUTDOWN_TIMEOUT)

    def send_control(
        self,
        message: dict[str, Any],
        session: dict[str, Any] | None,
        *,
        deadline: float | None = None,
    ) -> None:
        validate_tcp(message, from_client=True)
        if session is None:
            raise ConnectionError("Client session ended")
        deadline = (
            min(time.monotonic() + LOGOUT_TIMEOUT, deadline)
            if deadline is not None
            else time.monotonic() + LOGOUT_TIMEOUT
        )
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
                send_tcp(
                    sock, message, deadline=deadline, security=session["tcp_security"]
                )
        finally:
            lock.release()

    def send_raw(self, message: dict[str, Any]) -> None:
        with self._state_lock:
            if self.udp is None or self.token is None:
                raise ConnectionError("Client is disconnected")
            packet = dict(message, **{"from": self.name, "token": self.token})
            validate_udp(packet, from_client=True)
            raw = encode_udp(packet, self.f, self._session["udp_security"])
            if not self._udp_backoff.ready():
                raise BlockingIOError(errno.EAGAIN, "UDP retry backoff")
            try:
                self.udp.sendto(raw, self.address)
            except OSError as exc:
                if retryable(exc, udp=True):
                    self._udp_backoff.failed(exc)
                raise
            self._udp_backoff.reset()

    def _worker_ready(self, session):
        if session is None:
            return True
        session["started"].wait()
        return not session["stop"].is_set()

    def heartbeats(self, session=None):
        if not self._worker_ready(session):
            return
        delay = RetryDelay(
            session["stop"] if session is not None else threading.Event(),
            log,
            "UDP heartbeat",
            log_errors=False,
        )
        while self.running.is_set() and (
            session is None or not session["stop"].is_set()
        ):
            try:
                with self._state_lock:
                    if session is not None and self._session is not session:
                        return
                    self.send_raw({"type": "heartbeat"})
            except OSError as exc:
                if retryable(exc, udp=True):
                    delay.wait(exc)
                    continue
                if session is not None:
                    self._request_disconnect(session, str(exc))
                return
            delay.reset()
            if session is not None:
                session["stop"].wait(HEARTBEAT_INTERVAL)
            else:
                time.sleep(HEARTBEAT_INTERVAL)

    def _apply_presence(self, msg):
        # Called with state lock by both receiver workers.
        """Caller must hold _state_lock. Both TCP and UDP readers use this path so old
        revisions cannot overwrite newer snapshots.
        """
        if msg["revision"] >= self.presence_revision:
            self.presence_revision = msg["revision"]
            self.names = list(msg["names"])
            self.chat_inbox.set_peers(self.names)
            self.events.put(
                {
                    "type": "presence",
                    "names": self.names,
                    "revision": self.presence_revision,
                }
            )

    def listen_tcp(self, session, reader):
        if not self._worker_ready(session):
            return
        try:
            while not session["stop"].is_set():
                try:
                    msg = reader.read()
                except socket.timeout:
                    continue
                validate_tcp(msg, from_client=False)
                if msg["type"] not in {
                    "users",
                    "chat_status",
                    "file_status",
                    "file_cancel",
                }:
                    raise ValueError("Unexpected TCP control message after login")
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
            self._request_disconnect(session, "Server connection lost: " + str(exc))

    def listen(self, session=None):
        if not self._worker_ready(session):
            return
        udp = self.udp if session is None else session["udp"]
        delay = RetryDelay(
            session["stop"] if session is not None else threading.Event(),
            log,
            "UDP receive",
        )
        while self.running.is_set() and (
            session is None or not session["stop"].is_set()
        ):
            with self._state_lock:
                if session is not None and self._session is not session:
                    return
                self.chat_inbox.flush()
                gap_delay = self.chat_inbox.gap_delay(time.monotonic())
            try:
                if session is not None:
                    wait = (
                        UDP_TIMEOUT
                        if gap_delay is None
                        else min(UDP_TIMEOUT, gap_delay)
                    )
                    if not select.select([udp], [], [], wait)[0]:
                        continue
                raw, peer = udp.recvfrom(4096)
            except socket.timeout:
                continue
            except (OSError, ValueError) as exc:
                if isinstance(exc, OSError) and retryable(exc, udp=True):
                    delay.wait(exc)
                    continue
                if session is not None:
                    self._request_disconnect(session, str(exc))
                break
            delay.reset()
            with self._state_lock:
                if session is not None and self._session is not session:
                    return
                if peer != self.address or len(raw) > UDP_MTU:
                    continue
                try:
                    active = self._session
                    if active is None:
                        continue
                    record = unseal(raw, self.f)
                    msg = record[3]
                    validate_udp(msg, from_client=False)
                    if msg["type"] == "data":
                        if msg["to"] != self.name:
                            raise ValueError("Packet addressed to another client")
                except ValueError as exc:
                    if isinstance(exc, TransferCapacityError):
                        self.events.put({"type": "error", "message": str(exc)})
                    continue
                try:
                    active["udp_security"].accept(record)
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
                    record = self.outgoing_chats.get(msg["id"])
                    if record is not None:
                        self._chat_accepted(msg["id"], record)
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
                    except (ValueError, KeyError, TypeError, OSError) as exc:
                        self.events.put({"type": "error", "message": str(exc)})
                        continue
                    if accepted:
                        try:
                            self.send_raw({"type": "ack", "id": mid})
                        except OSError:
                            pass

    def validate_transfer_packet(self, msg):
        return self._file_transfers.validate_transfer_packet(msg)

    def on_data(self, msg):
        return self._file_transfers.on_data(msg)

    def finish_file(self, key):
        return self._file_transfers.finish_file(key)

    def finalize_worker(self, session):
        return self._file_transfers.finalize_worker(session)

    def _finalize_file(self, session, key, f):
        return self._file_transfers._finalize_file(session, key, f)

    def _capture_session(self):
        with self._state_lock:
            session = self._session
            expected = getattr(self._operation_context, "session", session)
            if self.status != "connected" or session is None or session is not expected:
                raise ConnectionError("Client session ended or changed")
            return session

    def _run_in_session(self, session, fn, *args):
        self._operation_context.session = session
        try:
            self._capture_session()
            return fn(*args)
        finally:
            del self._operation_context.session

    def send_packets(
        self,
        packets,
        window=SEND_WINDOW,
        retries=CLIENT_RETRIES,
        timeout=RETRY_TIMEOUT,
        *,
        session=None,
        file_record=None,
        deadline=None,
    ):
        """Bounded sliding window; only unacknowledged datagrams are retried."""
        session = self._capture_session() if session is None else session
        inflight = {}
        i = 0
        delay = RetryDelay(session["stop"], log, "UDP send", log_errors=False)
        try:
            while i < len(packets) or inflight:
                if file_record is not None:
                    self._file_transfers.check_sending(file_record, deadline)
                    if file_record["result"] is not None:
                        return
                if session is not self._session or self.status != "connected":
                    raise ConnectionError("Session ended while sending")
                while i < len(packets) and len(inflight) < window:
                    p = packets[i]
                    ev = threading.Event()
                    with self.pending_lock:
                        self.pending[p["id"]] = ev
                    inflight[p["id"]] = (p, ev, 0, 0)
                    i += 1
                for mid, (p, ev, tries, last) in list(inflight.items()):
                    if ev.is_set():
                        del inflight[mid]
                        with self.pending_lock:
                            self.pending.pop(mid, None)
                        continue
                    if time.monotonic() - last < timeout:
                        continue
                    if tries >= retries:
                        raise TimeoutError("No ACK for packet " + mid)
                    try:
                        with self._state_lock:
                            if (
                                self._session is not session
                                or self.status != "connected"
                            ):
                                raise ConnectionError("Session ended while sending")
                            self.send_raw(p)
                        delay.reset()
                    except OSError as exc:
                        if not retryable(exc, udp=True):
                            self._request_disconnect(session, str(exc))
                            raise
                        delay.wait(exc)
                    inflight[mid] = (p, ev, tries + 1, time.monotonic())
                time.sleep(SEND_POLL_INTERVAL)
        finally:
            with self.pending_lock:
                for mid in inflight:
                    self.pending.pop(mid, None)

    def packet(
        self, to: str, kind: str, payload: str = "", meta: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return data_packet(to, kind, payload, meta)

    def _chat_accepted(self, mid, record):
        return self._chat_sender._chat_accepted(mid, record)

    def _receive_chat_status(self, msg, session):
        return self._chat_sender._receive_chat_status(msg, session)

    def _preflight_chat(self, packet):
        return self._chat_sender._preflight_chat(packet)

    def chat(self, recipient: str, text: str) -> None:
        return self._chat_sender.chat(recipient, text)

    def file(self, recipient: str, path: str | Path) -> None:
        return self._file_transfers.file(recipient, path)


def main() -> int:
    """Preserve the legacy entry point without importing the CLI during core import."""
    from collab.client.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
