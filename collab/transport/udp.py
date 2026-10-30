"""Session-key encrypted UDP encoding and datagram size checks."""

from __future__ import annotations
from typing import Any
from collab.transport.security import Channel


import json
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from collab.shared.protocol import _require
from collab.shared.limits import UDP_MTU
from collab.transport.security import encrypted_size, seal, unseal


def get_key() -> bytes:
    key = os.getenv("COLLAB_KEY", "")
    if not key:
        raise RuntimeError("Set COLLAB_KEY (generate with python -m collab.keygen)")
    try:
        raw = key.encode("ascii")
        decoded = base64.b64decode(raw, altchars=b"-_", validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded) != raw:
            raise ValueError("Invalid key encoding")
        Fernet(raw)
        return raw
    except (ValueError, UnicodeError) as exc:
        raise ValueError("COLLAB_KEY must be a valid Fernet key") from exc


def cipher() -> Fernet:
    return Fernet(get_key())


def udp_frame_size(msg: dict[str, Any]) -> int:
    """Exact Fernet ciphertext length without encrypting under registry locks."""
    size = len(json.dumps(msg, separators=(",", ":")).encode())
    return 32 + encrypted_size(size)


def encode_udp(msg: Any, f: Fernet, security: Channel | None = None) -> bytes:
    _require(isinstance(msg, dict), "UDP message must be a JSON object")
    raw = (
        (security.context.encode("ascii") + security.encode(msg))
        if security is not None
        else seal(msg, f)
    )
    _require(
        len(raw) <= UDP_MTU,
        "Encrypted UDP frame exceeds 1100 bytes; shorten the message or metadata",
    )
    return raw


def decode_udp(
    raw: bytes, f: Fernet, security: Channel | None = None
) -> dict[str, Any] | None:
    """Inspect an envelope; pass a channel to enforce session and replay checks.

    Network receivers validate the message schema before committing replay state.
    """
    if len(raw) > UDP_MTU:
        return None
    try:
        msg = security.decode(raw) if security is not None else unseal(raw, f)[3]
        return msg if isinstance(msg, dict) else None
    except (InvalidToken, ValueError, UnicodeError):
        return None
