"""Scripted sockets for framing and authenticated-client setup tests."""

import json
import struct

from cryptography.fernet import Fernet


def frame(msg):
    raw = json.dumps(msg).encode()
    return struct.pack("!I", len(raw)) + raw


class Stream:
    """Simulate fragmented socket reads, timeouts, EOF, and recorded writes."""

    def __init__(self, parts):
        self.parts = list(parts)
        self.closed = False
        self.timeouts = []
        self.sent = []

    def recv(self, size):
        if not self.parts:
            return b""
        part = self.parts.pop(0)
        if isinstance(part, BaseException):
            raise part
        self.parts.insert(0, part[size:]) if len(part) > size else None
        return part[:size]

    def getpeername(self):
        return ("127.0.0.1", 9000)

    def setblocking(self, blocking):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, raw):
        self.sent.append(raw)

    def close(self):
        self.closed = True


class LoginStream(Stream):
    """Simulate login responses at the already-verified TLS transport boundary.

    A scripted welcome gains a session ID and generated key. Credentials and replies
    use framed JSON here; this helper does not implement TLS or nonce negotiation.
    """

    def sendall(self, raw):
        self.sent.append(raw)
        try:
            message = json.loads(raw[4:])
        except (ValueError, UnicodeError):
            return
        if (
            message.get("type") == "login"
            and self.parts
            and isinstance(self.parts[0], bytes)
        ):
            response = json.loads(b"".join(self.parts)[4:])
            if isinstance(response, dict) and response.get("type") == "welcome":
                response["session"] = "e" * 32
                response["key"] = Fernet.generate_key().decode()
            self.parts = [frame(response)]
