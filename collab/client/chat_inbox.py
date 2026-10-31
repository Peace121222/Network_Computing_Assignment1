"""Bounded chat reordering and replay memory, local to one receiving session."""

from collections import OrderedDict
import time
from collab.shared.limits import (
    CHAT_GAP_TIMEOUT,
    CHAT_STREAM_WINDOW,
    CHAT_STREAM_LIMIT,
    CHAT_CACHE_TTL,
    MAX_SEEN_PACKETS,
)


class ChatInbox:
    """Buffer validated chat packets for bounded ordering within a receive session.

    Accepted messages and gap notifications are emitted through the supplied callback.
    Callers serialize state access; this class does not acquire a client state lock.
    """

    def __init__(self, emit):
        self.emit = emit
        self.streams = {}
        self.seen = OrderedDict()
        self.fingerprints = {}
        self.peers = None

    def _prune(self, now):
        while self.seen and next(iter(self.seen.values())) <= now:
            key, _ = self.seen.popitem(last=False)
            self.fingerprints.pop(key, None)


        for key, stream in list(self.streams.items()):
            if stream.get("retired") and not stream["buffer"]:
                del self.streams[key]

    def set_peers(self, names):
        """Retire departed peer streams and prune replay state using the current clock.

        Args:
            names: Latest online usernames, converted to a set without mutating the input.
        """
        names = set(names)
        departed = (self.peers or set()) - names
        for key, stream in self.streams.items():
            if key[0] in departed:
                stream["retired"] = True
        self.peers = names
        self._prune(time.monotonic())

    def gap_delay(self, now):
        """Calculate the wait until the earliest buffered stream gap expires.

        Args:
            now: Monotonic observation time in seconds.

        Returns:
            Nonnegative seconds until the next gap deadline, or None if no gaps exist.
        """
        deadlines = [
            s["gap_since"] + CHAT_GAP_TIMEOUT
            for s in self.streams.values()
            if s["gap_since"] is not None
        ]
        return max(0, min(deadlines) - now) if deadlines else None

    def _drain(self, stream):
        while stream["next"] in stream["buffer"]:
            msg, _ = stream["buffer"].pop(stream["next"])
            self.emit(
                {
                    "type": "chat",
                    "id": msg["id"],
                    "from": msg["from"],
                    "text": msg["payload"],
                    **msg["meta"],
                }
            )
            stream["next"] += 1
        stream["gap_since"] = min(
            (arrived for _, arrived in stream["buffer"].values()), default=None
        )

    def flush(self, now=None):
        """Emit ready gap notifications, drain buffered chats, and prune expired state.

        Args:
            now: Monotonic observation time in seconds, or None for the current clock.
        """
        now = time.monotonic() if now is None else now
        for key, stream in self.streams.items():
            if (
                stream["gap_since"] is not None
                and now - stream["gap_since"] >= CHAT_GAP_TIMEOUT
            ):
                next_available = (
                    min(stream["buffer"])
                    if stream["buffer"]
                    else stream.pop("gap_target")
                )
                self.emit(
                    {
                        "type": "chat_gap",
                        "from": key[0],
                        "sender_session": key[1],
                        "channel": key[2],
                        "missing_from": stream["next"],
                        "missing_to": next_available - 1,
                    }
                )
                stream["next"] = next_available
                self._drain(stream)
        self._prune(now)

    def accept(self, msg, now=None):
        """Admit a forwarded chat into bounded ordering and replay state.

        The caller supplies a validated packet and serializes access to this inbox.
        Admission can emit chats or gap events through the callback.

        Args:
            msg: Server-forwarded chat with sender-session, channel, and sequence metadata.
            now: Monotonic arrival time in seconds, or None for the current clock.

        Returns:
            True if retained, already handled, or an identical cached duplicate; False
            for conflicting data, exhausted capacity, or an out-of-window sequence.
        """
        now = time.monotonic() if now is None else now
        self.flush(now)
        meta = msg["meta"]
        key = (msg["from"], meta["sender_session"], meta["channel"])
        message_key = (meta["sender_session"], msg["id"])
        fingerprint = (msg["from"], msg["payload"], meta["channel"], meta["sequence"])
        cached = self.seen.get(message_key)
        if cached is not None:

            return self.fingerprints[message_key] == fingerprint
        stream = self.streams.get(key)
        if stream is None:

            for old_key, old in list(self.streams.items()):
                if old_key[0] == key[0] and old_key[1] != key[1] and not old["buffer"]:
                    del self.streams[old_key]
            if len(self.streams) >= CHAT_STREAM_LIMIT:
                return False
            stream = {"next": 1, "buffer": {}, "gap_since": None, "last_seen": now}
            self.streams[key] = stream
        seq = meta["sequence"]
        if seq < stream["next"]:
            return True
        if seq >= stream["next"] + CHAT_STREAM_WINDOW:


            if not stream["buffer"]:
                if stream["gap_since"] is None:
                    stream["gap_since"] = now
                stream["gap_target"] = min(stream.get("gap_target", seq), seq)
            return False
        if seq in stream["buffer"]:
            return False
        if len(self.seen) >= MAX_SEEN_PACKETS:
            return False
        self.seen[message_key] = now + CHAT_CACHE_TTL
        self.fingerprints[message_key] = fingerprint
        stream.pop("gap_target", None)
        stream["last_seen"] = now
        stream["buffer"][seq] = (msg, now)
        self._drain(stream)
        return True
