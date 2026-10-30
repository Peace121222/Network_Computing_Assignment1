"""Message schemas, validation and payload encoding; no socket operations."""

from __future__ import annotations
from typing import Any


import base64
import re
from collab.shared.limits import FILE_FAILURE_REASONS
from collab.shared.limits import (
    CHUNK,
    MAX_FILE_SIZE,
    MAX_CHUNKS,
    MAX_USERNAME,
    MAX_PACKET_ID,
    MAX_FILENAME,
    MAX_CHAT_CHARS,
    MAX_ERROR_CHARS,
    CHAT_FAILURE_REASONS,
    TCP_TYPES,
    CLIENT_UDP_TYPES,
    SERVER_UDP_TYPES,
    DATA_KINDS,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def valid_name(name: Any) -> bool:
    """Check the existing case-sensitive username syntax.

    Args:
        name: Untrusted value to check without normalization.

    Returns:
        True for 1 to MAX_USERNAME Unicode letters/digits/underscores with at least one
        letter or digit; False otherwise.
    """
    return (
        isinstance(name, str)
        and 1 <= len(name) <= MAX_USERNAME
        and name.replace("_", "").isalnum()
    )


def _text(value, limit):
    return isinstance(value, str) and 1 <= len(value) <= limit


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _hex(value, size):
    return (
        isinstance(value, str)
        and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None
    )


def _names(value):
    return (
        isinstance(value, list)
        and all(valid_name(n) for n in value)
        and len(value) == len(set(value))
    )


def validate_tcp(msg: Any, *, from_client: bool) -> dict[str, Any]:
    """Validate a TCP control message for its wire direction.

    Args:
        msg: Untrusted decoded message.
        from_client: Whether the message travels from client to server.

    Returns:
        The original dictionary, without copying or mutation.

    Raises:
        ValueError: The message type, direction, or required fields are invalid.
    """
    _require(isinstance(msg, dict), "TCP message must be a JSON object")
    typ = msg.get("type")
    allowed = (
        {"hello", "login", "logout", "users", "file_receipt", "file_abort"}
        if from_client
        else {
            "challenge",
            "welcome",
            "error",
            "users",
            "chat_status",
            "file_status",
            "file_cancel",
        }
    )
    _require(
        isinstance(typ, str) and typ in TCP_TYPES and typ in allowed,
        "Invalid TCP message type or direction",
    )
    if typ in {"hello", "challenge"}:
        _require(_hex(msg.get("client_nonce"), 64), "Invalid client nonce")
        if typ == "challenge":
            _require(_hex(msg.get("server_nonce"), 64), "Invalid server nonce")
    elif typ == "login":
        _require(valid_name(msg.get("name")), "Invalid user name")
    elif typ == "welcome":
        _require(_hex(msg.get("token"), 32), "Invalid session token")
        _require(_integer(msg.get("udp_port"), 1, 65535), "Invalid UDP port")
    elif typ == "error":
        _require(_text(msg.get("message"), MAX_ERROR_CHARS), "Invalid error message")
    elif typ in {"file_status", "file_receipt", "file_abort", "file_cancel"}:
        _require(_hex(msg.get("transfer"), 32), "Invalid file transfer ID")
        if typ in {"file_receipt", "file_cancel"}:
            _require(_hex(msg.get("sender_session"), 32), "Invalid sender session")
        if typ == "file_receipt":
            _require(
                msg.get("state") in ("delivered", "failed"), "Invalid file receipt"
            )
            if msg["state"] == "failed":
                _require(
                    isinstance(msg.get("reason"), str)
                    and msg.get("reason") in FILE_FAILURE_REASONS,
                    "Invalid file failure",
                )
        elif typ == "file_cancel":
            _require(
                isinstance(msg.get("reason"), str)
                and msg.get("reason") in FILE_FAILURE_REASONS,
                "Invalid cancellation",
            )
        elif typ == "file_status":
            state = msg.get("state")
            _require(
                state in ("accepted", "delivered", "failed", "rejected"),
                "Invalid file state",
            )
            recipients, delivered, failures = (
                msg.get("recipients"),
                msg.get("delivered"),
                msg.get("failures"),
            )
            _require(
                _names(recipients) and _names(delivered) and isinstance(failures, list),
                "Invalid file result",
            )
            failed = []
            for failure in failures:
                _require(
                    isinstance(failure, dict) and valid_name(failure.get("name")),
                    "Invalid failed recipient",
                )
                _require(
                    isinstance(failure.get("reason"), str)
                    and failure.get("reason") in FILE_FAILURE_REASONS,
                    "Invalid file failure",
                )
                failed.append(failure["name"])
            _require(
                len(failed) == len(set(failed)) and not (set(failed) & set(delivered)),
                "Conflicting file result",
            )
            if state == "accepted":
                _require(
                    bool(recipients) and not delivered and not failures,
                    "Invalid file acceptance",
                )
            elif state == "rejected":
                _require(
                    not recipients and not delivered and len(failures) == 1,
                    "Invalid file rejection",
                )
            else:
                _require(
                    bool(recipients)
                    and set(recipients) == set(delivered) | set(failed),
                    "Incomplete file result",
                )
                _require(
                    (state == "delivered") == (not failures), "Invalid final file state"
                )
    elif typ == "chat_status":
        _require(_text(msg.get("id"), MAX_PACKET_ID), "Invalid chat ID")
        state = msg.get("state")
        _require(
            isinstance(state, str) and state in {"delivered", "failed", "rejected"},
            "Invalid chat state",
        )
        recipients, delivered, failures = (
            msg.get("recipients"),
            msg.get("delivered"),
            msg.get("failures"),
        )
        _require(_names(recipients) and _names(delivered), "Invalid chat recipients")
        _require(isinstance(failures, list), "Invalid chat failures")
        failed = []
        for failure in failures:
            _require(
                isinstance(failure, dict) and valid_name(failure.get("name")),
                "Invalid failed recipient",
            )
            reason = failure.get("reason")
            _require(
                isinstance(reason, str) and reason in CHAT_FAILURE_REASONS,
                "Invalid chat failure reason",
            )
            failed.append(failure["name"])
        _require(
            len(failed) == len(set(failed)) and not (set(failed) & set(delivered)),
            "Conflicting chat result",
        )
        if state == "rejected":
            _require(
                not delivered and not recipients and len(failures) == 1,
                "Invalid rejection",
            )
        else:
            _require(
                set(recipients) == set(delivered) | set(failed),
                "Incomplete chat result",
            )
            _require(
                bool(recipients) and ((state == "delivered") == (not failures)),
                "Invalid final state",
            )
    elif typ == "users" and not from_client:
        _require(_names(msg.get("names")), "Invalid user list")
        _require(
            type(msg.get("revision")) is int and msg["revision"] >= 0,
            "Invalid presence revision",
        )
    return msg


def validate_udp(msg: Any, *, from_client: bool) -> dict[str, Any]:
    """Validate decrypted UDP structure before endpoint updates or packet ACKs.

    Hop ACKs do not establish application-level file completion. Transfer lifecycle
    checks belong to the receiver, beyond this wire schema.

    Args:
        msg: Untrusted decoded message.
        from_client: Whether the message travels from client to server.

    Returns:
        The original dictionary, without copying or mutation.

    Raises:
        ValueError: The message schema, payload, or metadata is invalid.
    """
    _require(isinstance(msg, dict), "UDP message must be a JSON object")
    typ = msg.get("type")
    allowed = CLIENT_UDP_TYPES if from_client else SERVER_UDP_TYPES
    _require(
        isinstance(typ, str) and typ in allowed, "Invalid UDP message type or direction"
    )
    if from_client:
        _require(valid_name(msg.get("from")), "Invalid sender")
        _require(_hex(msg.get("token"), 32), "Invalid session token")
    else:
        _require("token" not in msg, "Server packets must not expose session tokens")
    if typ in {"path_challenge", "path_response"}:
        _require(_hex(msg.get("nonce"), 64), "Invalid path nonce")
    if typ == "presence":
        _require(_names(msg.get("names")), "Invalid user list")
        _require(
            type(msg.get("revision")) is int and msg["revision"] >= 0,
            "Invalid presence revision",
        )
    if typ in {"ack", "data"}:
        _require(_text(msg.get("id"), MAX_PACKET_ID), "Invalid packet ID")
    if typ != "data":
        return msg
    _require(valid_name(msg.get("from")), "Invalid sender")
    recipient = msg.get("to")
    _require(
        valid_name(recipient) or (from_client and recipient == "*"), "Invalid recipient"
    )
    kind, payload, meta = msg.get("kind"), msg.get("payload"), msg.get("meta")
    _require(isinstance(kind, str) and kind in DATA_KINDS, "Invalid data kind")
    _require(isinstance(payload, str), "Payload must be a string")
    _require(isinstance(meta, dict), "Metadata must be an object")
    if kind == "chat":
        _require(_text(payload, MAX_CHAT_CHARS), "Message must be 1-1000 characters")
        if from_client:
            _require(not meta, "Client chat metadata must be empty")
        else:
            _require(_hex(meta.get("sender_session"), 32), "Invalid sender session")
            _require(
                valid_name(meta.get("channel")) or meta.get("channel") == "*",
                "Invalid chat channel",
            )
            _require(
                type(meta.get("sequence")) is int and meta["sequence"] > 0,
                "Invalid chat sequence",
            )
        return msg
    _require(_hex(meta.get("transfer"), 32), "Invalid transfer ID")
    if not from_client:
        _require(_hex(meta.get("sender_session"), 32), "Invalid sender session")
    else:
        _require("sender_session" not in meta, "Client cannot choose sender session")
    if kind == "file_start":
        filename, size, count = (
            meta.get("filename"),
            meta.get("size"),
            meta.get("count"),
        )
        _require(
            _text(filename, MAX_FILENAME)
            and filename not in {".", ".."}
            and not any(c in filename for c in ("/", "\\", "\x00")),
            "Invalid filename",
        )
        _require(_integer(size, 0, MAX_FILE_SIZE), "Invalid file size (maximum 25 MiB)")
        _require(
            _integer(count, 0, MAX_CHUNKS) and count == (size + CHUNK - 1) // CHUNK,
            "Chunk count does not match file size",
        )
        _require(_hex(meta.get("sha256"), 64), "Invalid SHA-256")
    elif kind == "file_chunk":
        _require(_integer(meta.get("index"), 0, MAX_CHUNKS - 1), "Invalid chunk index")
        _require(
            0 < len(payload) <= 4 * ((CHUNK + 2) // 3), "Invalid encoded chunk size"
        )
        try:
            block = unb64(payload)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid base64 chunk") from exc
        _require(0 < len(block) <= CHUNK, "Invalid chunk size")
    if kind != "file_chunk":
        _require(payload == "", "Control payload must be empty")
    return msg


def data_packet(
    to: str, kind: str, payload: str = "", meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Create a data packet with a random application-level ID.

    Args:
        to: Recipient username, or * for broadcast.
        kind: Data kind to place in the packet; validation is deferred to callers.
        payload: Chat text or encoded file chunk, or empty for file control messages.
        meta: Metadata dictionary retained by reference, or None for a fresh empty one.

    Returns:
        A packet dictionary without sender credentials or a security envelope.
    """
    import uuid

    return {
        "type": "data",
        "id": uuid.uuid4().hex,
        "to": to,
        "kind": kind,
        "payload": payload,
        "meta": {} if meta is None else meta,
    }


def b64(raw: bytes) -> str:
    """Encode bytes as an ASCII base64 string."""
    return base64.b64encode(raw).decode("ascii")


def unb64(value: str) -> bytes:
    """Decode base64 with strict alphabet and padding validation.

    Args:
        value: ASCII base64 payload.

    Returns:
        The decoded bytes, including empty bytes for an empty payload.

    Raises:
        ValueError: The payload is not valid base64 or cannot be used as ASCII input.
    """
    return base64.b64decode(value, validate=True)
