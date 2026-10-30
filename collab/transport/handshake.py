"""Credential exchange over a verified TLS socket; no shared-key fallback."""

import re
import socket
import threading
from typing import Any
from cryptography.fernet import Fernet
from collab.accounts import validate_credentials
from collab.transport.security import Channel
from collab.transport.tcp import TCPReader, send_tcp
from collab.shared.protocol import validate_tcp


def client_login(
    sock: socket.socket, name: str, password: str, deadline: float
) -> tuple[dict[str, Any], TCPReader]:
    """Exchange credentials and install the session's ordered TCP channel.

    The caller must supply an already verified TLS socket. No TLS negotiation occurs
    here. The received key is removed from the returned welcome dictionary.

    Args:
        sock: Server-verified TLS socket owned by the caller.
        name: Case-sensitive account username.
        password: Account password satisfying the credential policy.
        deadline: Absolute monotonic deadline in seconds for the exchange.

    Returns:
        The validated welcome dictionary and reader configured with the session cipher.

    Raises:
        ValueError: Credentials, welcome fields, or the session key are invalid.
        RuntimeError: The server returns an authentication error.
        OSError: Socket I/O fails, including closure or timeout.
    """
    validate_credentials(name, password)
    send_tcp(sock, dict(type="login", name=name, password=password), deadline)
    reader = TCPReader(sock)
    welcome = reader.read(deadline)
    validate_tcp(welcome, from_client=False)
    if welcome["type"] == "error":
        raise RuntimeError(welcome["message"])
    if (
        welcome["type"] != "welcome"
        or re.fullmatch("[0-9a-f]{32}", welcome.get("session", "")) is None
    ):
        raise ValueError("Invalid welcome")
    key = welcome.pop("key", None)
    if not isinstance(key, str):
        raise ValueError("Invalid session key")
    try:
        session_cipher = Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid session key") from exc
    reader.security = Channel(session_cipher, welcome["session"], ordered=True)
    return welcome, reader


def server_login(
    sock: socket.socket, deadline: float, stop_event: threading.Event
) -> tuple[dict[str, Any], TCPReader]:
    """Read a bounded credential request from an established TLS connection.

    This validates request shape and credential policy only; account lookup, password
    verification, and registration belong to the caller. Invalid credentials produce
    an error response before ValueError is raised.

    Args:
        sock: Accepted TLS socket whose connection is owned by the handler.
        deadline: Absolute monotonic request deadline in seconds.
        stop_event: Event checked to interrupt reads during shutdown.

    Returns:
        The login/register request and its reader. The request contains a plaintext
        password and must not be logged or persisted by the caller.

    Raises:
        ValueError: The frame, request type, or credentials are invalid.
        OSError: Reading or replying fails, including cancellation and timeout.
    """
    reader = TCPReader(sock)
    reader.max_frame = 2048
    reader.stop_event = stop_event
    request = reader.read(deadline)
    if request.get("type") not in ("login", "register"):
        raise ValueError("Expected authentication request")
    try:
        validate_credentials(request.get("name"), request.get("password"))
    except ValueError as exc:
        message = (
            str(exc)
            if request["type"] == "register"
            else "Invalid username or password"
        )
        send_tcp(sock, dict(type="error", message=message), deadline)
        raise ValueError("Invalid credentials") from None
    return request, reader
