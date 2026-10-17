"""Bounded, session-bound file routing and end-to-end delivery results.

All methods run under the server registry lock. Only bounded mailbox and pending
mutations happen here; TCP writes and UDP encoding/sends belong to the workers.
"""

from collections import OrderedDict
import hashlib
import json
import time
import uuid

from collab.shared.limits import (
    CHUNK,
    FILE_ACTIVE_LIMIT,
    FILE_CACHE_LIMIT,
    FILE_MAILBOX_LIMIT,
    FILE_OUTGOING_LIMIT,
    FILE_RESULT_TTL,
    UDP_MTU,
    FILE_HASH_BUDGET,
    FILE_HASH_ENTRY_BYTES,
)
from collab.transport.udp import udp_frame_size


class ServerFileTransfers:
    """Caller holds server.lock for state methods. Mailbox updates briefly acquire the
    recipient condition in that order; writers release conditions before I/O or registry
    cleanup. Stored source/destination tokens pin work to the original sessions.
    """

    def __init__(self, server):
        self.server = server
        self.records = OrderedDict()

    def queue(self, user, key, message):
        condition = user["control_condition"]
        with condition:
            mailbox = user.setdefault("file_mailbox", OrderedDict())
            if key not in mailbox and len(mailbox) >= FILE_MAILBOX_LIMIT:
                user["writer_stop"].set()
                condition.notify_all()
                return False
            mailbox[key] = message
            condition.notify()
            return True

    def status(self, record, state=None):
        if record["result"] is not None:
            return record["result"]
        return {
            "type": "file_status",
            "transfer": record["transfer"],
            "state": state or "accepted",
            "recipients": sorted(record["destinations"]),
            "delivered": [],
            "failures": [],
        }

    def publish(self, record):
        """Caller holds server.lock; enqueue only for the original source session, without
        writing TCP.
        """
        source = self.server.users.get(record["source"])
        if source is not None and source["token"] == record["source_token"]:
            self.queue(source, ("source", record["transfer"]), self.status(record))

    def cancel_recipient(self, record, name, reason):
        user = self.server.users.get(name)
        if user is not None and user["token"] == record["destinations"][name]:
            self.queue(
                user,
                ("cancel", record["sender_session"], record["transfer"]),
                {
                    "type": "file_cancel",
                    "transfer": record["transfer"],
                    "sender_session": record["sender_session"],
                    "reason": reason,
                },
            )

    def finish(self, record, now):
        """Caller holds server.lock; finalize a record once and remove its pending packets
        before publishing the final result.
        """
        if record["result"] is not None or any(
            v is None for v in record["states"].values()
        ):
            return
        states = record["states"]
        record["result"] = {
            "type": "file_status",
            "transfer": record["transfer"],
            "state": (
                "failed"
                if any(v != "delivered" for v in states.values())
                else "delivered"
            ),
            "recipients": sorted(states),
            "delivered": sorted(n for n, v in states.items() if v == "delivered"),
            "failures": [
                {"name": n, "reason": v}
                for n, v in sorted(states.items())
                if v != "delivered"
            ],
        }
        record["finished"] = now
        # Completed records retain only bounded retry identities, not packet payloads.
        for key, item in list(self.server.pending.items()):
            if item.get("file_key") == record["key"]:
                del self.server.pending[key]
        self.publish(record)

    def outcome(self, record, name, reason, now):
        if (
            record["result"] is not None
            or record["states"].get(name, "unknown") is not None
        ):
            return
        record["states"][name] = reason
        for key, item in list(self.server.pending.items()):
            if item.get("file_key") == record["key"] and key[0] == name:
                del self.server.pending[key]
        if reason != "delivered":
            self.cancel_recipient(record, name, reason)
        self.finish(record, now)

    def pending_outcome(self, item, name, reason, now=None):
        record = self.records.get(item.get("file_key"))
        if record is not None:
            self.outcome(record, name, reason, time.monotonic() if now is None else now)

    def acknowledged(self, item, now):
        record = self.records.get(item.get("file_key"))
        if record is not None and record["result"] is None:
            record["progress"] = now

    def expire(self, now):
        for key, record in list(self.records.items()):
            if record["result"] is None and (
                now >= record["deadline"]
                or now - record["progress"] >= self.server.file_idle_timeout
            ):
                for name in record["states"]:
                    self.outcome(record, name, "delivery_timeout", now)
            if (
                record["result"] is not None
                and now - record["finished"] >= FILE_RESULT_TTL
            ):
                del self.records[key]

    def remove_session(self, token, now):
        """Caller holds server.lock; cancel only records pinned to the departing token, not
        a replacement login.
        """
        for key, record in list(self.records.items()):
            if record["source_token"] == token:
                for name in record["states"]:
                    if record["states"][name] is None:
                        self.cancel_recipient(record, name, "source_disconnected")
                del self.records[key]
            elif record["result"] is None:
                for name, destination in record["destinations"].items():
                    if destination == token:
                        self.outcome(record, name, "recipient_disconnected", now)

    def receipt(self, name, user, msg, now):
        record = next(
            (
                r
                for r in self.records.values()
                if r["sender_session"] == msg["sender_session"]
                and r["transfer"] == msg["transfer"]
            ),
            None,
        )
        if record is None or record["destinations"].get(name) != user["token"]:
            return
        if msg["state"] == "delivered":
            if ("file_end", -1) not in record["packets"] or record["chunks"] != record[
                "meta"
            ]["count"]:
                return
            reason = "delivered"
        else:
            reason = msg["reason"]
        self.outcome(record, name, reason, now)

    def abort(self, user, transfer, now):
        record = self.records.get((user["token"], transfer))
        if record is not None:
            for name in record["states"]:
                self.outcome(record, name, "source_aborted", now)

    def route(self, msg, source, now):
        self.expire(now)
        server = self.server
        transfer = msg["meta"]["transfer"]
        key = (source["token"], transfer)
        record = self.records.get(key)
        if record is None:
            if msg["kind"] != "file_start":
                return False
            active = [r for r in self.records.values() if r["result"] is None]
            if (
                sum(
                    r["meta"]["count"] * FILE_HASH_ENTRY_BYTES
                    for r in self.records.values()
                )
                + msg["meta"]["count"] * FILE_HASH_ENTRY_BYTES
                > FILE_HASH_BUDGET
            ):
                return False
            if (
                len(self.records) >= FILE_CACHE_LIMIT
                or len(active) >= FILE_ACTIVE_LIMIT
                or sum(r["source_token"] == source["token"] for r in active)
                >= FILE_OUTGOING_LIMIT
            ):
                return False
            targets = list(server.users) if msg["to"] == "*" else [msg["to"]]
            recipients = [
                (n, server.users[n])
                for n in targets
                if n in server.users and server.users[n]["ready"] and n != msg["from"]
            ]
            reason = (
                "self_recipient"
                if msg["to"] == msg["from"]
                else (
                    ("no_recipients" if msg["to"] == "*" else "recipient_offline")
                    if not recipients
                    else None
                )
            )
            if not server._router._admission_locked(recipients, False):
                return False
            record = dict(
                key=key,
                transfer=transfer,
                source=msg["from"],
                source_token=source["token"],
                sender_session=source.setdefault("public_id", uuid.uuid4().hex),
                channel=msg["to"],
                meta=dict(msg["meta"]),
                destinations={n: u["token"] for n, u in recipients},
                states={n: None for n, _ in recipients},
                packets={},
                chunks=0,
                created=now,
                progress=now,
                deadline=now + server.file_transfer_timeout,
                result=None,
                finished=None,
            )
            if reason is not None:
                record["destinations"] = {}
                record["states"] = {}
                record["result"] = {
                    "type": "file_status",
                    "transfer": transfer,
                    "state": "rejected",
                    "recipients": [],
                    "delivered": [],
                    "failures": [
                        {
                            "name": msg["to"] if msg["to"] != "*" else msg["from"],
                            "reason": reason,
                        }
                    ],
                }
                record["finished"] = now
            if not self.queue(source, ("source", transfer), self.status(record)):
                return False
            self.records[key] = record
        if msg["to"] != record["channel"]:
            return False
        if record["result"] is not None:
            slot = (msg["kind"], msg["meta"].get("index", -1))
            digest = hashlib.sha256(
                json.dumps([msg["meta"], msg["payload"]], sort_keys=True).encode()
            ).digest()
            previous = record["packets"].get(slot)
            if (msg["kind"] == "file_start" and msg["meta"] != record["meta"]) or (
                previous is not None and previous != digest
            ):
                return False
            self.publish(record)
            return True
        kind = msg["kind"]
        slot = (kind, msg["meta"].get("index", -1))
        fingerprint = hashlib.sha256(
            json.dumps([msg["meta"], msg["payload"]], sort_keys=True).encode()
        ).digest()
        previous = record["packets"].get(slot)
        if previous is not None:
            if previous != fingerprint:
                for name in record["states"]:
                    self.outcome(
                        record,
                        name,
                        (
                            "chunk_conflict"
                            if kind == "file_chunk"
                            else "metadata_conflict"
                        ),
                        now,
                    )
                return False
            return True
        if kind == "file_chunk":
            index = msg["meta"]["index"]
            from collab.shared.protocol import unb64

            if index >= record["meta"]["count"] or len(unb64(msg["payload"])) != min(
                CHUNK, record["meta"]["size"] - index * CHUNK
            ):
                return False
        recipients = [
            (n, server.users[n])
            for n, token in record["destinations"].items()
            if record["states"][n] is None
            and n in server.users
            and server.users[n]["token"] == token
        ]
        if not server._router._admission_locked(recipients, False):
            return False
        relay_id = uuid.uuid4().hex
        plans = []
        for name, user in recipients:
            packet = {
                "type": "data",
                "id": relay_id,
                "kind": kind,
                "from": msg["from"],
                "to": name,
                "payload": msg["payload"],
                "meta": dict(msg["meta"], sender_session=record["sender_session"]),
            }
            if udp_frame_size(packet) > UDP_MTU:
                for recipient in record["states"]:
                    self.outcome(record, recipient, "metadata_conflict", now)
                return False
            plans.append((name, user, packet))
        record["packets"][slot] = fingerprint
        record["chunks"] += kind == "file_chunk"
        record["progress"] = now
        for name, user, packet in plans:
            server.pending[(name, relay_id)] = dict(
                packet=packet,
                attempts=0,
                retry_time=0,
                source_token=source["token"],
                destination_token=user["token"],
                file_key=key,
            )
        return True
