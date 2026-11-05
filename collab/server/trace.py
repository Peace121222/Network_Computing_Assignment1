"""Allowlisted, server-side protocol evidence; never captures payloads or secrets."""

REQUIREMENTS = {
    "1": "Protocol / serialization",
    "2": "TCP handshake",
    "3": "Authentication / user state",
    "4": "Concurrent sessions",
    "5": "Unicast / broadcast routing",
    "6": "UDP file transfer",
    "7": "Resilience / ACK / retry",
    "8": "Encryption / TLS",
    "9": "Client HTTP UI (observe in client)",
    "10": "Testing / code quality (separate checks)",
    "flow": "Sequence / sliding window / CUBIC",
}


def classify(event, details):
    """Map observed events to rubric topics, without asserting rubric completion."""
    tags = set()
    message = details.get("message", "")
    if event.startswith("tcp."):
        tags.add("1")
        if event in {"tcp.accepted", "tcp.listening"} or message == "welcome":
            tags.add("2")
    if event.startswith("tls.") or details.get("encrypted"):
        tags.add("8")
    if event.startswith(("login.", "account.", "auth.", "session.")):
        tags.add("3")
    if event in {"login.succeeded", "session.closed"}:
        tags.add("4")
    if event.startswith("chat.") or message == "chat":
        tags.add("5")
    if event.startswith("file.") or message.startswith("file_"):
        tags.add("6")
    if event.startswith("udp."):
        tags.add("1")
        if details.get("encrypted"):
            tags.add("8")
    if message in {"heartbeat", "presence", "users", "path_challenge", "path_response"}:
        tags.add("3")
    if message == "ack" or event == "udp.ack_matched" or event in {"udp.retry", "udp.retry_exhausted", "udp.dropped", "connection.ended"}:
        tags.add("7")
    if "sequence" in details or "cwnd" in details:
        tags.add("flow")
    if details.get("reason") == "expired":
        tags.add("7")
    return sorted(tags)


def endpoint(address):
    """Format real socket endpoints, retaining ports and IPv6 brackets."""
    host, port = address[:2]
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


def packet_metadata(message):
    """Extract only public protocol fields; never copy an entire message/meta."""
    meta = message.get("meta", {})
    fields = {"message": message.get("kind", message.get("type", "unknown"))}
    if "name" in message:
        fields["user"] = message["name"]
    elif "from" in message:
        fields["user"] = message["from"]
    for name in ("id", "transfer", "state"):
        if name in message:
            fields[name] = message[name]
    for name in ("transfer", "index", "count", "size", "sequence", "sha256"):
        if name in meta:
            fields[{"size": "file_bytes", "sequence": "stream_sequence"}.get(name, name)] = meta[name]
    if message.get("type") == "data":
        fields["recipient"] = message.get("to", "")
        fields["mode"] = "broadcast" if meta.get("channel", message.get("to")) == "*" else "unicast"
    if message.get("type") == "file_receipt":
        fields["verification"] = "receiver_confirmed_sha256_and_save" if message.get("state") == "delivered" else message.get("reason", "failed")
    if message.get("type") in {"presence", "users"}:
        fields["users"] = message.get("users", [])
    return fields


def ciphertext_metadata(raw):
    """Preview actual AES ciphertext in a session-framed Fernet UDP datagram.

    Base64 decoding is not decryption. Skip the public 32-byte lookup prefix,
    then the Fernet version/timestamp/IV (25 bytes) and trailing HMAC (32 bytes).
    The caller authenticates received datagrams before requesting this preview.
    No key, plaintext or session authentication token is logged. The wire prefix
    includes public Fernet framing such as the timestamp and IV.
    """
    import base64
    import binascii

    try:
        token = raw[32:]
        decoded = base64.b64decode(token, altchars=b"-_", validate=True)
        ciphertext = decoded[25:-32]
        if decoded[0] != 0x80 or not ciphertext or len(ciphertext) % 16:
            return {}
        return {
            "encryption": "Fernet: AES-128-CBC + HMAC-SHA256",
            "ciphertext_bytes": len(ciphertext),
            "ciphertext_hex": ciphertext[:32].hex(),
            "fernet_wire_prefix": token[:64].decode("ascii"),
        }
    except (ValueError, IndexError, UnicodeError, binascii.Error):
        return {}


def redacted_packet(message):
    """Show the real logical packet shape, never credentials or message content."""
    safe = {name: message[name] for name in ("type", "id", "from", "to", "kind")
            if name in message}
    if "payload" in message:
        safe["payload"] = "[content redacted]"
    meta = message.get("meta", {})
    safe["meta"] = {name: meta[name] for name in
                    ("transfer", "index", "count", "size", "sequence", "channel", "sha256")
                    if name in meta}
    return safe


def is_activity_event(event):
    """Keep demo milestones, excluding high-volume per-packet diagnostics."""
    return (not event.startswith(("tcp.", "udp.", "tls.")) or event in
            {"tcp.accepted", "tls.established", "udp.retry_exhausted"})
