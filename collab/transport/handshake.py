"""Nonce-bound encrypted login; deadlines cover the complete exchange."""

from __future__ import annotations
from typing import Any
import socket
import threading
from cryptography.fernet import Fernet


import re
from collab.transport.security import Channel, ZERO_CONTEXT, nonce
from collab.transport.tcp import TCPReader, send_tcp
from collab.shared.protocol import validate_tcp


def check_transcript(message: dict[str, Any], transcript: dict[str, str]) -> None:
    if any(message.get(key) != value for key, value in transcript.items()):
        raise ValueError("Handshake nonce mismatch")


def client_login(
    sock: socket.socket, name: str, f: Fernet, deadline: float
) -> tuple[dict[str, Any], TCPReader]:
    security = Channel(f, ZERO_CONTEXT, ordered=True)
    reader = TCPReader(sock, security)
    client_nonce = nonce()
    send_tcp(
        sock,
        {"type": "hello", "client_nonce": client_nonce},
        deadline,
        security=security,
    )
    challenge = reader.read(deadline)
    validate_tcp(challenge, from_client=False)
    if (
        challenge["type"] != "challenge"
        or challenge.get("client_nonce") != client_nonce
    ):
        raise ValueError("Expected matching server challenge")
    transcript = dict(client_nonce=client_nonce, server_nonce=challenge["server_nonce"])
    send_tcp(
        sock, dict(type="login", name=name, **transcript), deadline, security=security
    )
    welcome = reader.read(deadline)
    check_transcript(welcome, transcript)
    validate_tcp(welcome, from_client=False)
    if welcome["type"] == "error":
        raise RuntimeError(welcome["message"])
    if welcome["type"] != "welcome":
        raise ValueError("Expected welcome or error during login")
    context = welcome.get("session")
    if not isinstance(context, str) or re.fullmatch("[0-9a-f]{32}", context) is None:
        raise ValueError("Invalid welcome security context")
    reader.security = Channel(f, context, ordered=True)
    return welcome, reader


def server_login(
    sock: socket.socket, f: Fernet, deadline: float, stop_event: threading.Event
) -> tuple[dict[str, Any], TCPReader, dict[str, str]]:
    security = Channel(f, ZERO_CONTEXT, server=True, ordered=True)
    reader = TCPReader(sock, security)
    reader.stop_event = stop_event
    hello = reader.read(deadline)
    validate_tcp(hello, from_client=True)
    if hello["type"] != "hello":
        raise ValueError("Expected client hello")
    transcript = dict(client_nonce=hello["client_nonce"], server_nonce=nonce())
    send_tcp(sock, dict(type="challenge", **transcript), deadline, security=security)
    login = reader.read(deadline)
    check_transcript(login, transcript)
    return login, reader, transcript
