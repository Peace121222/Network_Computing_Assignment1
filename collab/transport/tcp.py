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
    """Set the socket timeout to the remaining handshake time.

    Args:
        sock: Socket whose timeout is mutated.
        deadline: Absolute monotonic deadline in seconds.

    Raises:
        TimeoutError: The deadline has already expired.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TCP handshake deadline exceeded")
    sock.settimeout(remaining)


def frame_tcp(data: Any, security: Channel | None = None) -> bytes:
    """Encode a JSON object as a length-prefixed TCP frame.

    Args:
        data: Message dictionary within MAX_FRAME plaintext bytes after encoding.
        security: Optional channel used to encrypt the message and advance its sequence.

    Returns:
        Four-byte big-endian body length followed by the encoded body.

    Raises:
        ValueError: The input is not a dictionary or its encoded size is out of bounds.
    """
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
    """Write one complete length-prefixed frame to a socket.

    Args:
        sock: Socket used for sendall(); ownership stays with the caller.
        data: Message dictionary to encode.
        deadline: Optional absolute monotonic deadline in seconds; sets sock's timeout.
        security: Optional authenticated channel, whose outbound sequence advances.

    Raises:
        ValueError: Frame validation fails.
        TimeoutError: The deadline or socket timeout expires.
        OSError: Socket I/O fails.
    """
    frame = frame_tcp(data, security)
    if deadline is not None:
        set_deadline_timeout(sock, deadline)
    sock.sendall(frame)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly the requested bytes without closing the socket.

    Args:
        sock: Socket to read using its current timeout settings.
        n: Number of bytes requested; nonpositive values return empty bytes.

    Returns:
        Bytes read from the socket.

    Raises:
        ConnectionError: The peer closes before the requested bytes are read.
        OSError: Socket I/O fails, including timeouts.
    """
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise ConnectionError("TCP socket closed")
        result.extend(chunk)
    return bytes(result)


class TCPReader:
    """Read framed messages while preserving partial data across timeouts.

    The caller owns the socket and must use one reader for a resumable connection.
    Invalid frames and non-timeout socket errors mark the reader unusable.

    Attributes:
        security: Optional channel used for decryption and ordered replay validation.
        max_frame: Maximum unencrypted frame size; encrypted frames use MAX_FRAME limits.
        wait_timeout: Readiness wait in seconds when no absolute deadline is supplied.
        stop_event: Optional event that cancels reads when observed by the read loop.
    """

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
        """Read the next complete message and retain partial bytes on timeout.

        Args:
            deadline: Optional absolute monotonic deadline in seconds. With a stop event,
                short socket timeouts permit cancellation checks until the deadline.

        Returns:
            The decoded message dictionary.

        Raises:
            TimeoutError: The read deadline or socket readiness timeout expires.
            ConnectionError: The peer closes, cancellation is observed, or the reader failed.
            ValueError: Frame size, payload, or authenticated-channel validation fails.
            OSError: A non-timeout socket error occurs; the reader becomes unusable.
        """
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
    """Read one framed message using a temporary reader.

    Use TCPReader directly when partial data must survive a timeout.

    Args:
        sock: Socket to read; ownership remains with the caller.
        security: Optional channel used to decode the frame.

    Returns:
        The decoded message dictionary.

    Raises:
        ValueError: Frame or payload validation fails.
        OSError: Socket I/O fails, including closure and timeouts.
    """
    return TCPReader(sock, security).read()


def write_tcp(
    sock: socket.socket,
    message: dict[str, Any],
    deadline: float,
    *,
    security: Channel | None = None,
) -> None:
    """Write a frame on a nonblocking socket without changing its timeout.

    Args:
        sock: Connected nonblocking socket owned by the caller.
        message: Message dictionary to encode.
        deadline: Absolute monotonic write deadline in seconds.
        security: Optional channel, whose outbound sequence advances during encoding.

    Raises:
        ValueError: Frame validation fails.
        TimeoutError: The write cannot finish by the deadline.
        ConnectionError: The socket closes during the write.
        OSError: A socket operation fails.
    """
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
