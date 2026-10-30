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
REPLAY_WINDOW = 4096
ZERO_CONTEXT = "0" * 32


def encrypted_size(size: int) -> int:
    """Calculate Fernet token length for a plaintext payload and envelope header.

    Args:
        size: JSON payload length in bytes, before the security header is added.

    Returns:
        Encrypted token length in bytes, excluding TCP framing and the UDP lookup prefix.
    """
    return 4 * ((57 + 16 * ((size + HEADER.size) // 16 + 1) + 2) // 3)


def seal(
    message: Any,
    f: Fernet,
    context: str = ZERO_CONTEXT,
    direction: int = C2S,
    sequence: int = 1,
    transport: int = 2,
) -> bytes:
    """Encrypt a JSON message with a caller-supplied security envelope.

    This low-level helper does not maintain counters or enforce replay policy.

    Args:
        message: Dictionary to serialize as compact JSON.
        f: Fernet cipher used to encrypt the envelope and payload.
        context: Hexadecimal 16-byte session identifier.
        direction: Numeric client-to-server or server-to-client direction.
        sequence: Positive sequence value included in the header.
        transport: Numeric TCP or UDP transport identifier.

    Returns:
        A Fernet token without transport framing or a public lookup prefix.

    Raises:
        ValueError: The message is not a dictionary or the context cannot be decoded.
    """
    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")
    raw = json.dumps(message, separators=(",", ":")).encode()
    return f.encrypt(
        HEADER.pack(VERSION, bytes.fromhex(context), direction, transport, sequence)
        + raw
    )


def unseal(raw: bytes, f: Fernet) -> tuple[str, int, int, dict[str, Any], int]:
    """Decrypt an envelope without committing replay state.

    A leading 32-byte lowercase hexadecimal UDP lookup hint is stripped when present.
    Its value is not trusted here; Channel.accept() checks the encrypted context.

    Args:
        raw: Fernet token, optionally prefixed with a public UDP session lookup hint.
        f: Fernet cipher used to authenticate and decrypt the token.

    Returns:
        Session context as hex, direction, sequence, message dictionary, and transport.

    Raises:
        ValueError: Authentication, envelope fields, or JSON payload validation fails.
    """
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
    """Track directional sequences for one transport and session.

    Ordered channels require the exact next inbound sequence. Unordered channels use
    a bounded replay bitmap. Encoding advances the outbound counter before encryption;
    accepting an invalid or replayed record does not advance inbound replay state.

    Attributes:
        f: Fernet cipher shared by this session's channels.
        context: Hexadecimal session identifier bound into encrypted envelopes.
        ordered: Whether the channel enforces contiguous TCP sequence numbers.
    """

    def __init__(
        self, f: Fernet, context: str, *, server: bool = False, ordered: bool = False
    ) -> None:
        self.f, self.context, self.ordered = f, context, ordered
        self.transport = 1 if ordered else 2
        self.outbound = S2C if server else C2S
        self.inbound = C2S if server else S2C
        self.sent = self.highest = self.bitmap = 0
        self.lock = threading.Lock()

    def encode(self, message: dict[str, Any]) -> bytes:
        """Encrypt a message using the next outbound sequence.

        Args:
            message: Message dictionary to serialize.

        Returns:
            Encrypted envelope without transport framing.

        Raises:
            ValueError: The sequence is exhausted or the message cannot be sealed.
        """
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
        """Validate an envelope and commit its inbound replay state.

        Message-schema validation is separate; callers can validate the decrypted message
        before invoking this method so malformed messages do not consume replay state.

        Args:
            record: Tuple returned by unseal().

        Returns:
            The record's message dictionary without copying it.

        Raises:
            ValueError: Context, direction, transport, order, or replay validation fails.
        """
        context, direction, sequence, message, transport = record
        with self.lock:
            if (
                context != self.context
                or direction != self.inbound
                or transport != self.transport
            ):
                raise ValueError("Security context or direction mismatch")
            if self.ordered:
                if sequence != self.highest + 1:
                    raise ValueError("Invalid TCP security sequence")
                self.highest = sequence
            elif sequence > self.highest:
                shift = sequence - self.highest
                self.bitmap = (
                    1
                    if shift >= REPLAY_WINDOW
                    else ((self.bitmap << shift) | 1) & ((1 << REPLAY_WINDOW) - 1)
                )
                self.highest = sequence
            else:
                distance = self.highest - sequence
                if distance >= REPLAY_WINDOW or self.bitmap & (1 << distance):
                    raise ValueError("Replayed UDP frame")
                self.bitmap |= 1 << distance
        return message

    def decode(self, raw: bytes) -> dict[str, Any]:
        """Decrypt an envelope and commit its inbound replay state.

        Args:
            raw: Encrypted envelope, optionally carrying a UDP lookup prefix.

        Returns:
            The decrypted message dictionary; message-schema validation is not performed.

        Raises:
            ValueError: Decryption, envelope validation, or replay validation fails.
        """
        return self.accept(unseal(raw, self.f))


def nonce() -> str:
    return secrets.token_hex(32)
