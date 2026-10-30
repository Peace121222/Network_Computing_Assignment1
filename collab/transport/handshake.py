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
        f = Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid session key") from exc
    reader.security = Channel(f, welcome["session"], ordered=True)
    return welcome, reader


def server_login(
    sock: socket.socket, deadline: float, stop_event: threading.Event
) -> tuple[dict[str, Any], TCPReader]:
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
