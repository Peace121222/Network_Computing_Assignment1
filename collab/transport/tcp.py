"""Length-prefixed frames with optional authenticated channel and persistent reads."""

from __future__ import annotations
from typing import Any
from collab.transport.security import Channel


import ssl
import json
import select
import socket
import struct
import time
from collab.shared.protocol import _require
from collab.shared.limits import MAX_FRAME, SESSION_TIMEOUT
from collab.transport.security import encrypted_size


def set_deadline_timeout(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TCP handshake deadline exceeded")
    sock.settimeout(remaining)


def frame_tcp(data: Any, security: Channel | None = None) -> bytes:
    _require(isinstance(data, dict), "TCP message must be a JSON object")
    raw = json.dumps(data, separators=(",", ":")).encode()
    _require(1 <= len(raw) <= MAX_FRAME, "Invalid TCP frame length")
    if security is not None:
        raw = security.encode(data)
    return struct.pack("!I", len(raw)) + raw


def send_tcp(
    sock: socket.socket,
    data: Any,
    deadline: float | None = None,
    *,
    security: Channel | None = None,
) -> None:
    frame = frame_tcp(data, security)
    if deadline is not None:
        set_deadline_timeout(sock, deadline)
    sock.sendall(frame)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise ConnectionError("TCP socket closed")
        result.extend(chunk)
    return bytes(result)


class TCPReader:
    """One reader per connection; socket timeouts preserve partial frames."""

    def __init__(self, sock: socket.socket, security: Channel | None = None) -> None:
        self.sock = sock
        self.security = security
        self.header = bytearray()
        self.body = bytearray()
        self.size = None
        self.failed = False
        self.max_frame = MAX_FRAME
        self.wait_timeout = SESSION_TIMEOUT
        self.stop_event = None

    def _fill(self, buffer, size, deadline):
        while len(buffer) < size:
            if self.stop_event is not None and self.stop_event.is_set():
                raise ConnectionError("TCP reader stopped")
            if deadline is not None:
                set_deadline_timeout(self.sock, deadline)
                if self.stop_event is not None:
                    self.sock.settimeout(
                        min(0.1, max(0.001, deadline - time.monotonic()))
                    )
            try:
                chunk = self.sock.recv(size - len(buffer))
            except socket.timeout:
                if (
                    self.stop_event is not None
                    and deadline is not None
                    and time.monotonic() < deadline
                ):
                    continue
                raise
            except (
                BlockingIOError,
                InterruptedError,
                ssl.SSLWantReadError,
                ssl.SSLWantWriteError,
            ):
                remaining = (
                    self.wait_timeout
                    if deadline is None
                    else deadline - time.monotonic()
                )
                if (
                    remaining <= 0
                    or not select.select([self.sock], [], [], remaining)[0]
                ):
                    raise socket.timeout("TCP read timeout")
                continue
            if not chunk:
                raise ConnectionError("TCP socket closed during frame")
            buffer.extend(chunk)

    def read(self, deadline: float | None = None) -> dict[str, Any]:
        if self.failed:
            raise ConnectionError("TCP reader is unusable after a frame error")
        try:
            if self.size is None:
                self._fill(self.header, 4, deadline)
                self.size = struct.unpack("!I", self.header)[0]
                _require(
                    1
                    <= self.size
                    <= (
                        encrypted_size(MAX_FRAME)
                        if self.security is not None
                        else self.max_frame
                    ),
                    "Invalid TCP frame length",
                )
            self._fill(self.body, self.size, deadline)
            if deadline is not None:
                set_deadline_timeout(self.sock, deadline)
            try:
                msg = (
                    self.security.decode(bytes(self.body))
                    if self.security is not None
                    else json.loads(self.body)
                )
                if self.security is not None:
                    _require(
                        len(json.dumps(msg, separators=(",", ":")).encode())
                        <= MAX_FRAME,
                        "Invalid TCP frame length",
                    )
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError("Invalid TCP payload") from exc
            _require(isinstance(msg, dict), "TCP message must be a JSON object")
        except TimeoutError:
            raise
        except (OSError, ValueError):
            self.failed = True
            raise
        self.header.clear()
        self.body.clear()
        self.size = None
        return msg


def recv_tcp(sock: socket.socket, *, security: Channel | None = None) -> dict[str, Any]:
    """Read once; use a persistent TCPReader when resuming after timeout."""
    return TCPReader(sock, security).read()


def write_tcp(
    sock: socket.socket,
    message: dict[str, Any],
    deadline: float,
    *,
    security: Channel | None = None,
) -> None:
    """Write a frame on an already nonblocking socket without changing reader timeouts."""
    frame = memoryview(frame_tcp(message, security))
    while frame:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [sock], [], remaining)[1]:
            raise TimeoutError("TCP control write deadline exceeded")
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
            raise ConnectionError("TCP control socket closed")
        frame = frame[count:]
