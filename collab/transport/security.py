"""Session-bound authenticated envelopes with directional replay protection."""

from __future__ import annotations
from typing import Any
from cryptography.fernet import Fernet


import json
import secrets
import struct
import threading
from cryptography.fernet import InvalidToken

VERSION = 1
C2S, S2C = 1, 2
HEADER = struct.Struct("!B16sBBQ")
MAX_SEQUENCE = (1 << 64) - 1
ZERO_CONTEXT = "0" * 32


def encrypted_size(size: int) -> int:
    """Calculate Fernet token length for a plaintext payload and envelope header."""
    return 4 * ((57 + 16 * ((size + HEADER.size) // 16 + 1) + 2) // 3)


def seal(
    message: Any,
    f: Fernet,
    context: str = ZERO_CONTEXT,
    direction: int = C2S,
    sequence: int = 1,
    transport: int = 2,
) -> bytes:
    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")
    raw = json.dumps(message, separators=(",", ":")).encode()
    return f.encrypt(
        HEADER.pack(VERSION, bytes.fromhex(context), direction, transport, sequence)
        + raw
    )


def unseal(raw: bytes, f: Fernet) -> tuple[str, int, int, dict[str, Any], int]:
    try:
        if len(raw) >= 32 and all(byte in b"0123456789abcdef" for byte in raw[:32]):
            raw = raw[32:]
        plain = f.decrypt(raw)
        version, context, direction, transport, sequence = HEADER.unpack(
            plain[: HEADER.size]
        )
        if (
            version != VERSION
            or direction not in (C2S, S2C)
            or transport not in (1, 2)
            or sequence < 1
        ):
            raise ValueError("Invalid security envelope")
        message = json.loads(plain[HEADER.size :])
        if not isinstance(message, dict):
            raise ValueError("Message must be a JSON object")
        return context.hex(), direction, sequence, message, transport
    except (
        InvalidToken,
        ValueError,
        UnicodeError,
        struct.error,
        RecursionError,
        TypeError,
    ) as exc:
        raise ValueError("Invalid authenticated frame") from exc


class Channel:
    def __init__(
        self, f: Fernet, context: str, *, server: bool = False, ordered: bool = False
    ) -> None:
        self.f, self.context, self.ordered = f, context, ordered
        self.transport = 1 if ordered else 2
        self.outbound = S2C if server else C2S
        self.inbound = C2S if server else S2C
        self.sent = self.highest = 0
        self.lock = threading.Lock()

    def encode(self, message: dict[str, Any]) -> bytes:
        with self.lock:
            if self.sent == MAX_SEQUENCE:
                raise ValueError("Security sequence exhausted")
            self.sent += 1
            return seal(
                message, self.f, self.context, self.outbound, self.sent, self.transport
            )

    def accept(
        self, record: tuple[str, int, int, dict[str, Any], int]
    ) -> dict[str, Any]:
        """Basic Replay Protection: Drop if sequence is older than the highest seen."""
        context, direction, sequence, message, transport = record
        with self.lock:
            if (
                context != self.context
                or direction != self.inbound
                or transport != self.transport
            ):
                raise ValueError("Security context or direction mismatch")
                
            if sequence <= self.highest:
                raise ValueError("Replay attack detected or packet delayed")
                
            self.highest = sequence
            
        return message

    def decode(self, raw: bytes) -> dict[str, Any]:
        return self.accept(unseal(raw, self.f))


