"""Session-bound chat/file routing, delivery results and retry scheduling."""

from collections import OrderedDict
import json
import threading
import time
import uuid
from collab.shared.limits import (
    CHAT_OUTGOING_LIMIT,
    CHAT_CACHE_TTL,
    CHAT_CACHE_LIMIT,
    CHAT_SERVER_TIMEOUT,
    UDP_MTU,
    SERVER_RETRIES,
    RETRY_TIMEOUT,
)
from collab.transport.udp import udp_frame_size

RETRANSMIT_BATCH = 128


class RelayRouter:
    """Manage session-bound relay admission, outcomes, and retransmission state.

    Routing mutations run under server.lock. Actual sends use session gates after the
    registry lock is released; stored tokens pin each retry to its original sessions.
    """

    def __init__(self, server):
        self.server = server

    def _chat_support(self, user):
        user.setdefault("public_id", uuid.uuid4().hex)
        user.setdefault("sequences", {})
        user.setdefault("chat_mailbox", OrderedDict())
        user.setdefault("control_condition", threading.Condition())

    def _chat_slot(self, source, key):
        self._chat_support(source)
        with source["control_condition"]:
            mailbox = source["chat_mailbox"]
            if key not in mailbox:
                if len(mailbox) >= CHAT_OUTGOING_LIMIT:
                    return False
                mailbox[key] = None
            return True

    def _publish_chat_result_locked(self, record):
        """Publish a completed chat result to the matching source session's mailbox.

        The caller holds server.lock. The source condition protects its mailbox; the TCP
        writer performs I/O only after both locks are released.
        """
        server = self.server
        if record.get("result") is None:
            states = record["states"]
            if any(state is None for state in states.values()):
                return
            delivered = sorted(n for n, state in states.items() if state == "delivered")
            failures = [
                {"name": n, "reason": state}
                for n, state in sorted(states.items())
                if state != "delivered"
            ]
            record["result"] = {
                "type": "chat_status",
                "id": record["id"],
                "state": "failed" if failures else "delivered",
                "recipients": sorted(states),
                "delivered": delivered,
                "failures": failures,
            }
        source = server.users.get(record["source"])
        if source is None or source["token"] != record["source_token"]:
            return
        key = (record["source_token"], record["id"])
        if not self._chat_slot(source, key):
            return
        with source["control_condition"]:
            source["chat_mailbox"][key] = record["result"]
            source["control_condition"].notify()

    def _chat_outcome_locked(self, item, name, outcome):
        """Set a pinned recipient outcome and publish when the chat is complete.

        The caller holds server.lock. Only still-pending outcomes are changed.
        """
        server = self.server
        key = item.get("chat_key")
        record = server.chat_records.get(key)
        if record is not None and record["states"].get(name, "unknown") is None:
            record["states"][name] = outcome
            self._publish_chat_result_locked(record)

    def _expire_chats_locked(self, now):
        """Expire chat records and pending work without socket I/O.

        The caller must hold server.lock; now is a monotonic timestamp in seconds.
        """
        server = self.server
        for key, record in list(server.chat_records.items()):
            if record["result"] is None and now >= record["deadline"]:
                for name, state in record["states"].items():
                    if state is None:
                        record["states"][name] = "delivery_timeout"
                for pending_key, item in list(server.pending.items()):
                    if item.get("chat_key") == key:
                        del server.pending[pending_key]
                self._publish_chat_result_locked(record)
            if now - record["created"] >= CHAT_CACHE_TTL:
                del server.chat_records[key]

    def _admission_locked(self, additions, is_chat):
        """Check pending-packet capacity while preserving reserved chat headroom.

        The caller holds server.lock through this check and any subsequent admission,
        so global and per-recipient counts cannot change between those operations.

        Returns:
            True if the proposed additions fit the applicable limits; False otherwise.
        """
        server = self.server
        if len(server.pending) + len(additions) > server.max_pending_packets:
            return False
        counts, files = {}, {}
        for key, item in server.pending.items():
            name = key[0]
            counts[name] = counts.get(name, 0) + 1
            if item["packet"]["kind"] != "chat":
                files[name] = files.get(name, 0) + 1
        if any(
            counts.get(n, 0) + 1 > server.max_pending_per_recipient
            for n, _ in additions
        ):
            return False
        if not is_chat:
            reserve = min(512, max(1, server.max_pending_packets // 8))
            per_reserve = min(64, max(1, server.max_pending_per_recipient // 8))
            if (
                sum(files.values()) + len(additions)
                > server.max_pending_packets - reserve
            ):
                return False
            if any(
                files.get(n, 0) + 1 > server.max_pending_per_recipient - per_reserve
                for n, _ in additions
            ):
                return False
        return True

    def _route_chat_locked(self, msg, source, now):
        """Pin a chat's content and recipients before scheduling relay packets.

        The caller holds server.lock. Identical retries reuse the original recipient set
        and sequence allocation; conflicting retries are rejected.

        Returns:
            True if admitted or an accepted duplicate; False if rejected or at capacity.
        """
        server = self.server
        self._expire_chats_locked(now)
        key = (source["token"], msg["id"])
        fingerprint = (
            msg["to"],
            msg["payload"],
            json.dumps(msg["meta"], sort_keys=True),
        )
        record = server.chat_records.get(key)
        if record is not None:
            if record["fingerprint"] != fingerprint:
                return False
            if record["result"] is not None:
                self._publish_chat_result_locked(record)
            return record["result"] is None or record["result"]["state"] != "rejected"
        if len(server.chat_records) >= CHAT_CACHE_LIMIT:
            return False
        targets = list(server.users) if msg["to"] == "*" else [msg["to"]]
        recipients = [
            (n, server.users[n])
            for n in targets
            if n in server.users and server.users[n]["ready"] and n != msg["from"]
        ]
        reason = None
        if msg["to"] == msg["from"]:
            reason = "self_recipient"
        elif not recipients:
            reason = "no_recipients" if msg["to"] == "*" else "recipient_offline"
        if not self._admission_locked(recipients, True):
            return False
        if not self._chat_slot(source, key):
            return False
        record = dict(
            id=msg["id"],
            source=msg["from"],
            source_token=source["token"],
            fingerprint=fingerprint,
            created=now,
            deadline=now + CHAT_SERVER_TIMEOUT,
            states={n: None for n, _ in recipients},
            destinations={n: u["token"] for n, u in recipients},
            result=None,
        )
        if reason is not None:
            # No recipient accepted; keep a negative result for idempotent retries.
            failure_name = msg["to"] if msg["to"] != "*" else msg["from"]
            record["result"] = {
                "type": "chat_status",
                "id": msg["id"],
                "state": "rejected",
                "recipients": [],
                "delivered": [],
                "failures": [{"name": failure_name, "reason": reason}],
            }
            server.chat_records[key] = record
            self._publish_chat_result_locked(record)
            return False
        # Relay IDs are hop-local: two senders may safely choose the same original ID.
        relay_id = uuid.uuid4().hex
        plans = []
        self._chat_support(source)
        for name, user in recipients:
            stream_key = (msg["to"], user["token"])
            sequence = source["sequences"].get(stream_key, 0) + 1
            packet = {
                "type": "data",
                "id": relay_id,
                "kind": "chat",
                "from": msg["from"],
                "to": name,
                "payload": msg["payload"],
                "meta": {
                    "sender_session": source["public_id"],
                    "channel": msg["to"],
                    "sequence": sequence,
                },
            }
            if udp_frame_size(packet) > UDP_MTU:
                # Reject packets that cannot fit after adding relay metadata and framing.
                with source["control_condition"]:
                    source["chat_mailbox"].pop(key, None)
                return False
            plans.append((name, user, stream_key, sequence, packet))
        server.chat_records[key] = record
        for name, user, stream_key, sequence, packet in plans:
            source["sequences"][stream_key] = sequence
            server.pending[(name, relay_id)] = dict(
                packet=packet,
                attempts=0,
                retry_time=0,
                source_token=source["token"],
                destination_token=user["token"],
                chat_key=key,
            )
        return True

    def route(self, msg, source_addr):
        """Admit an application packet and ACK accepted ingress outside the registry lock.

        Args:
            msg: Validated client data packet with sender identity and token.
            source_addr: Source endpoint to receive the hop ACK.

        Returns:
            True for an accepted packet; False for stale identity or rejected admission.
        """
        server = self.server
        with server.lock:
            source = server.users.get(msg["from"])
            if source is None or source["token"] != msg["token"]:
                return False
            if msg["kind"] == "chat":
                accepted = self._route_chat_locked(msg, source, time.monotonic())
            else:
                accepted = server.file_transfers.route(msg, source, time.monotonic())
        if accepted:
            raw = {"type": "ack", "id": msg["id"]}
            server._send_session_udp(raw, [(msg["from"], source)], source_addr)
        return accepted

    def retransmit_once(self, now=None):
        """Expire stale work and send one bounded relay retry batch.

        A batch is selected under server.lock, then session identities are revalidated
        by session-gated sends outside that lock. Selected queue entries rotate to the end.

        Args:
            now: Monotonic observation time in seconds, or None for the current clock.
        """
        server = self.server
        now = time.monotonic() if now is None else now
        plans = []
        with server.lock:
            self._expire_chats_locked(now)
            server.file_transfers.expire(now)
            chats, files = [], []
            for key, item in list(server.pending.items()):
                if server.pending.get(key) is not item:
                    continue
                source = server.users.get(item["packet"]["from"])
                destination = server.users.get(key[0])
                if (
                    source is None
                    or source["token"] != item["source_token"]
                    or destination is None
                    or destination["token"] != item["destination_token"]
                ):
                    del server.pending[key]
                    self._chat_outcome_locked(item, key[0], "recipient_disconnected")
                    server.file_transfers.pending_outcome(
                        item, key[0], "recipient_disconnected", now
                    )
                    continue
                if item["retry_time"] > now:
                    continue
                if item["attempts"] >= SERVER_RETRIES:
                    del server.pending[key]
                    self._chat_outcome_locked(item, key[0], "delivery_timeout")
                    server.file_transfers.pending_outcome(
                        item, key[0], "delivery_timeout", now
                    )
                    continue
                if destination["udp_addr"] is not None and server._udp_backoff.ready():
                    (chats if item["packet"]["kind"] == "chat" else files).append(
                        (key, item, source, destination)
                    )
            selected = chats[:96] + files[:32]
            spare = RETRANSMIT_BATCH - len(selected)
            selected += (chats[96:] + files[32:])[:spare]
            for key, item, source, destination in selected:
                if server.pending.get(key) is not item:
                    continue
                server.pending.pop(key)
                server.pending[key] = item
                item["retry_time"] = now + RETRY_TIMEOUT
                item["attempts"] += 1
                plans.append((key, item, source, destination))
        for key, item, source, destination in plans:
            raw = item["packet"]
            server._send_session_udp(
                raw,
                [(item["packet"]["from"], source), (item["packet"]["to"], destination)],
            )
