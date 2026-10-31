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
    """Read and validate the legacy COLLAB_KEY environment variable.

    Account-based client and server entry points do not use this helper for login.

    Returns:
        Canonically encoded 32-byte Fernet key material as URL-safe base64 bytes.

    Raises:
        RuntimeError: COLLAB_KEY is missing or empty.
        ValueError: COLLAB_KEY is not a canonical Fernet key.
    """
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
    """Construct a legacy Fernet cipher from COLLAB_KEY.

    Returns:
        A cipher using the key returned by get_key().

    Raises:
        RuntimeError: COLLAB_KEY is missing or empty.
        ValueError: COLLAB_KEY is invalid.
    """
    return Fernet(get_key())


def udp_frame_size(msg: dict[str, Any]) -> int:
    """Calculate session-framed UDP size including the public lookup prefix.

    No encryption is performed, so this estimate can be used during registry updates.
    It includes 32 prefix bytes even when encode_udp() is later used without a channel.

    Args:
        msg: Message dictionary to encode as compact JSON.

    Returns:
        Datagram size in bytes for encoding with a session channel.
    """
    size = len(json.dumps(msg, separators=(",", ":")).encode())
    return 32 + encrypted_size(size)


def validate_udp_size(msg: dict[str, Any]) -> None:
    """Reject messages that exceed the session-framed UDP limit without encryption."""
    _require(
        udp_frame_size(msg) <= UDP_MTU,
        "Encrypted UDP frame exceeds 1100 bytes; shorten the message or metadata",
    )


def encode_udp(msg: Any, f: Fernet, security: Channel | None = None) -> bytes:
    """Encode a message and enforce the encrypted datagram size limit.

    Args:
        msg: Message dictionary to encode.
        f: Fernet cipher used only when security is None.
        security: Optional session channel. When supplied, its public context prefix is
            added and its outbound sequence advances; otherwise seal() is used directly.

    Returns:
        An encoded datagram of at most UDP_MTU bytes.

    Raises:
        ValueError: The message is not a dictionary or the datagram exceeds UDP_MTU.
    """
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
    """Decode a UDP message, returning None for oversize or invalid frames.

    Args:
        raw: Received datagram bytes.
        f: Fernet cipher used only when security is None.
        security: Optional channel that also validates and commits replay state.

    Returns:
        The decrypted dictionary, or None if decoding fails. Message schemas are not
        checked. Without security, session binding and replay state are not enforced.
    """
    if len(raw) > UDP_MTU:
        return None
    try:
        msg = security.decode(raw) if security is not None else unseal(raw, f)[3]
        return msg if isinstance(msg, dict) else None
    except (InvalidToken, ValueError, UnicodeError):
        return None
