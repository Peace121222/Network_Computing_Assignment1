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
        # Keep sequence watermarks for live peers even when replay entries expire.
        # Resetting next=1 after an idle minute would strand higher sequence numbers.
        for key, stream in list(self.streams.items()):
            if stream.get("retired") and not stream["buffer"]:
                del self.streams[key]

    def set_peers(self, names):
        names = set(names)
        departed = (self.peers or set()) - names
        for key, stream in self.streams.items():
            if key[0] in departed:
                stream["retired"] = True
        self.peers = names
        self._prune(time.monotonic())

    def gap_delay(self, now):
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
        now = time.monotonic() if now is None else now
        self.flush(now)
        meta = msg["meta"]
        key = (msg["from"], meta["sender_session"], meta["channel"])
        message_key = (meta["sender_session"], msg["id"])
        fingerprint = (msg["from"], msg["payload"], meta["channel"], meta["sequence"])
        cached = self.seen.get(message_key)
        if cached is not None:
            # Expiry is stored separately; a duplicate cannot change original contents.
            return self.fingerprints[message_key] == fingerprint
        stream = self.streams.get(key)
        if stream is None:
            # A server-assigned epoch change supersedes an old, empty stream.
            for old_key, old in list(self.streams.items()):
                if old_key[0] == key[0] and old_key[1] != key[1] and not old["buffer"]:
                    del self.streams[old_key]
            if len(self.streams) >= CHAT_STREAM_LIMIT:
                return False
            stream = {"next": 1, "buffer": {}, "gap_since": None, "last_seen": now}
            self.streams[key] = stream
        seq = meta["sequence"]
        if seq < stream["next"]:
            return True  # Already displayed or deliberately skipped.
        if seq >= stream["next"] + CHAT_STREAM_WINDOW:
            # Do not retain or ACK an out-of-window payload. Remember only a bounded
            # sequence hint so a long run of missing packets cannot strand the stream.
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
