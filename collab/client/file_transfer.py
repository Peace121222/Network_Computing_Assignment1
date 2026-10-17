"""Bounded streaming file sender and asynchronous, session-bound disk receiver."""

from collections import OrderedDict
from collab.shared.limits import FILE_PROGRESS_INTERVAL

import hashlib
import os
from pathlib import Path
import queue
import tempfile
import threading
import time
import uuid

from collab.shared.limits import (
    CHUNK,
    MAX_FILE_SIZE,
    SEND_WINDOW,
    FILE_OUTGOING_LIMIT,
    FILE_RESULT_TTL,
    FILE_CACHE_LIMIT,
    FILE_HASH_BUDGET,
    FILE_HASH_ENTRY_BYTES,
    FILE_MAILBOX_LIMIT,
)
from collab.shared.protocol import b64, unb64, validate_udp
from collab.transport.udp import encode_udp

MAX_INCOMING_TRANSFERS = 2
MAX_INCOMING_BYTES = 50 * 1024 * 1024


class TransferCapacityError(ValueError):
    pass


class FileTransfers:
    def __init__(self, client):
        self.client = client
        self.outgoing = {}
        self.completed = OrderedDict()
        self.orphans = {}

    def reset(self):
        for f in self.client.files.values():
            f["cancelled"] = True
        for record in self.outgoing.values():
            record["done"].set()
        self.outgoing.clear()
        self.completed.clear()

    @staticmethod
    def identity(msg):
        return msg["meta"].get("sender_session", ""), msg["meta"]["transfer"]

    def validate_transfer_packet(self, msg):
        if msg["kind"] == "chat":
            return
        client, meta = self.client, msg["meta"]
        f = client.files.get((msg["from"], meta["transfer"]))
        if msg["kind"] == "file_start":
            if f is None and (
                len(client.files) >= MAX_INCOMING_TRANSFERS
                or sum(item["size"] for item in client.files.values()) + meta["size"]
                > MAX_INCOMING_BYTES
            ):
                raise TransferCapacityError("Incoming file transfer capacity exceeded")
        if msg["kind"] == "file_chunk" and f is not None:
            index = meta["index"]
            if index >= f["total"]:
                raise ValueError("Chunk index exceeds declared file size")
            if len(unb64(msg["payload"])) != min(CHUNK, f["size"] - index * CHUNK):
                raise ValueError("Chunk length does not match declared file size")

    def receipt(self, session, epoch, transfer, state, reason=None):
        message = {
            "type": "file_receipt",
            "sender_session": epoch,
            "transfer": transfer,
            "state": state,
        }
        if reason is not None:
            message["reason"] = reason
        key = (epoch, transfer)
        if (
            key not in session["receipts"]
            and len(session["receipts"]) >= FILE_MAILBOX_LIMIT
        ):
            session["receipt_overflow"] = True
            return
        session["receipts"][key] = message

    def fail(self, key, f, reason):
        client = self.client
        if f.get("cancelled"):
            return
        f["cancelled"] = True
        if client.files.get(key) is f:
            del client.files[key]
        self.remember(f, "failed", reason)
        self.receipt(f["session"], f["epoch"], key[1], "failed", reason)
        client.events.put(
            {
                "type": "error",
                "message": "File transfer failed: " + reason,
                "transfer": key[1],
                "sender_session": f["epoch"],
                "from": key[0],
                "filename": f["name"],
            }
        )

    def remember(self, f, state, reason=None):
        self.completed[(f["epoch"], f["transfer"])] = {
            "expires": time.monotonic() + FILE_RESULT_TTL,
            "state": state,
            "reason": reason,
            "sender": f["sender"],
            "meta": f["meta"],
            "chunks": f["chunks"],
            "ended": f["ended"],
        }

    def on_data(self, msg):
        """Called under the state lock. True means retained, and may be ACKed."""
        client = self.client
        if msg["kind"] == "chat":
            client.events.put(
                {"type": "chat", "from": msg["from"], "text": msg["payload"]}
            )
            return True
        session = client._session
        if session is None or session["stop"].is_set():
            return False
        kind, meta = msg["kind"], msg["meta"]
        epoch, transfer = self.identity(msg)
        completed = self.completed.get((epoch, transfer))
        if completed is not None:
            valid = completed["sender"] == msg["from"] and (
                kind != "file_start" or completed["meta"] == meta
            )
            if kind == "file_chunk":
                valid = (
                    valid
                    and completed["chunks"].get(meta["index"])
                    == hashlib.sha256(unb64(msg["payload"])).digest()
                )
            if valid:
                self.receipt(
                    session, epoch, transfer, completed["state"], completed["reason"]
                )
            return valid
        key = (msg["from"], transfer)
        f = client.files.get(key)
        if f is not None and f["epoch"] != epoch:
            return False
        if kind == "file_start":
            if f is not None:
                if f["meta"] != meta:
                    self.fail(key, f, "metadata_conflict")
                    return False
                return True
            reserved = sum(
                f["total"] * FILE_HASH_ENTRY_BYTES for f in client.files.values()
            )
            reserved += sum(
                f["meta"]["count"] * FILE_HASH_ENTRY_BYTES
                for f in self.completed.values()
            )
            if reserved + meta["count"] * FILE_HASH_ENTRY_BYTES > FILE_HASH_BUDGET:
                self.receipt(session, epoch, transfer, "failed", "capacity_exceeded")
                return False
            if len(self.completed) + len(client.files) >= FILE_CACHE_LIMIT:
                return False
            try:
                self.validate_transfer_packet(msg)
            except TransferCapacityError:
                self.receipt(session, epoch, transfer, "failed", "capacity_exceeded")
                client.events.put(
                    {
                        "type": "error",
                        "message": "Incoming file transfer capacity exceeded",
                    }
                )
                return False
            if session["finalize_queue"].full():
                return False
            now = time.monotonic()
            f = {
                "name": Path(meta["filename"]).name,
                "total": meta["count"],
                "sha256": meta["sha256"],
                "size": meta["size"],
                "meta": dict(meta),
                "chunks": {},
                "written": set(),
                "ended": False,
                "finalizing": False,
                "cancelled": False,
                "stream": None,
                "temporary": None,
                "created": now,
                "progress": now,
                "epoch": epoch,
                "sender": msg["from"],
                "transfer": transfer,
                "session": session,
            }
            client.files[key] = f
            session["file_resources"][id(f)] = f
            session["finalize_queue"].put_nowait(("start", key, f))
            return True
        if f is None or f["cancelled"]:
            return False  # Unknown transfer: do not ACK or poison duplicate memory.
        if kind == "file_chunk":
            self.validate_transfer_packet(msg)
            index = meta["index"]
            block = unb64(msg["payload"])
            digest = hashlib.sha256(block).digest()
            if index in f["chunks"]:
                if f["chunks"][index] != digest:
                    self.fail(key, f, "chunk_conflict")
                    return False
                return True
            try:
                session["finalize_queue"].put_nowait(("chunk", key, f, index, block))
            except queue.Full:
                return False
            f["chunks"][index] = digest
            f["progress"] = time.monotonic()
            return True
        if kind == "file_end":
            if not f["ended"]:
                f["ended"] = True
                f["progress"] = time.monotonic()
            self.finish_file(key)
            return True
        return False

    def finish_file(self, key):
        f = self.client.files.get(key)
        if (
            not f
            or f["cancelled"]
            or f["finalizing"]
            or not f["ended"]
            or len(f["written"]) != f["total"]
        ):
            return
        try:
            f["session"]["finalize_queue"].put_nowait(("finish", key, f))
        except queue.Full:
            return
        f["finalizing"] = True

    def dispose(self, f):
        try:
            if f["stream"] is not None:
                f["stream"].close()
                f["stream"] = None
            if f["temporary"] is not None:
                f["temporary"].unlink(missing_ok=True)
                f["temporary"] = None
            self.orphans.pop(id(f), None)
        except OSError:
            self.orphans[id(f)] = f
            self.client.events.put(
                {"type": "error", "message": "File cleanup incomplete"}
            )

    def retry_cleanup(self):
        for f in list(self.orphans.values()):
            self.dispose(f)
        if self.orphans:
            raise RuntimeError("Client shutdown incomplete: file cleanup failed")

    def maintenance(self, session, now=None):
        """State only; disk and TCP work is performed outside the state lock."""
        now = time.monotonic() if now is None else now
        for key, f in list(self.client.files.items()):
            if (
                now - f["progress"] >= self.client.file_idle_timeout
                or now - f["created"] >= self.client.file_transfer_timeout
            ):
                self.fail(key, f, "delivery_timeout")
        for key, result in list(self.completed.items()):
            if result["expires"] <= now:
                del self.completed[key]
        for key in list(self.client.files):
            self.finish_file(key)
        receipts = list(session["receipts"].values())
        session["receipts"].clear()
        return receipts

    def finalize_worker(self, session):
        client = self.client
        if not client._worker_ready(session):
            return
        jobs = session["finalize_queue"]
        try:
            while not session["stop"].is_set():
                with client._state_lock:
                    if client._session is not session:
                        return
                    if session.get("receipt_overflow"):
                        raise ConnectionError("File receipt mailbox full")
                    receipts = self.maintenance(session)
                    garbage = [
                        f for f in session["file_resources"].values() if f["cancelled"]
                    ]
                for f in garbage:
                    self.dispose(f)
                    with client._state_lock:
                        session["file_resources"].pop(id(f), None)
                for message in receipts:
                    client.send_control(message, session)
                try:
                    job = jobs.get(timeout=0.05)
                except queue.Empty:
                    continue
                kind, key, f, *args = job
                try:
                    if f["cancelled"] or session["stop"].is_set():
                        continue
                    if kind == "start":
                        stream = tempfile.NamedTemporaryFile(
                            dir=client.download_dir, prefix=".collab_", delete=False
                        )
                        f["stream"], f["temporary"] = stream, Path(stream.name)
                        with client._state_lock:
                            if (
                                client._session is session
                                and client.files.get(key) is f
                                and not f["cancelled"]
                            ):
                                client.events.put(
                                    {
                                        "type": "file_receiving",
                                        "transfer": key[1],
                                        "sender_session": f["epoch"],
                                        "from": key[0],
                                        "filename": f["name"],
                                        "total": f["total"],
                                    }
                                )
                    elif kind == "chunk":
                        index, block = args
                        f["stream"].seek(index * CHUNK)
                        f["stream"].write(block)
                        with client._state_lock:
                            if (
                                client._session is session
                                and client.files.get(key) is f
                                and not f["cancelled"]
                            ):
                                f["written"].add(index)
                                now = time.monotonic()
                                # UI samples progress; chunk reliability remains independent.
                                if (
                                    now - f.get("ui_progress_at", float("-inf"))
                                    >= FILE_PROGRESS_INTERVAL
                                    or len(f["written"]) == f["total"]
                                ):
                                    f["ui_progress_at"] = now
                                    client.events.put(
                                        {
                                            "type": "file_progress",
                                            "from": key[0],
                                            "filename": f["name"],
                                            "transfer": key[1],
                                            "sender_session": f["epoch"],
                                            "received": len(f["written"]),
                                            "total": f["total"],
                                        }
                                    )
                                self.finish_file(key)
                    else:
                        client._finalize_file(session, key, f)
                except OSError:
                    with client._state_lock:
                        if client._session is session:
                            self.fail(key, f, "disk_error")
                finally:
                    jobs.task_done()
        except (OSError, ValueError) as exc:
            client._request_disconnect(session, "File control failed: " + str(exc))
        finally:
            # This worker exclusively owns file descriptors, including after detach.
            for f in list(session["file_resources"].values()):
                self.dispose(f)
            session["file_resources"].clear()

    def _finalize_file(self, session, key, f):
        client = self.client
        try:
            stream = f["stream"]
            stream.flush()
            stream.seek(0)
            digest = hashlib.sha256()
            size = 0
            while not session["stop"].is_set() and not f["cancelled"]:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                digest.update(block)
            if session["stop"].is_set() or f["cancelled"]:
                return
            if size != f["size"] or digest.hexdigest() != f["sha256"]:
                with client._state_lock:
                    if client._session is session:
                        self.fail(key, f, "hash_mismatch")
                return
            stream.close()
            f["stream"] = None
            destination = client.download_dir / (uuid.uuid4().hex[:8] + "_" + f["name"])
            with client._state_lock:
                if (
                    client._session is not session
                    or session["stop"].is_set()
                    or f["cancelled"]
                ):
                    return
                f["temporary"].replace(destination)
                f["temporary"] = None
                self.remember(f, "delivered")
                self.receipt(session, f["epoch"], key[1], "delivered")
                client.files.pop(key, None)
                session["file_resources"].pop(id(f), None)
                client.events.put(
                    {
                        "type": "file_complete",
                        "from": key[0],
                        "filename": f["name"],
                        "path": str(destination),
                        "size": size,
                        "transfer": key[1],
                        "sender_session": f["epoch"],
                    }
                )
        except OSError:
            with client._state_lock:
                if client._session is session:
                    self.fail(key, f, "disk_error")

    def cancel(self, msg, session):
        if self.client._session is not session:
            return
        for key, f in list(self.client.files.items()):
            if (f["epoch"], key[1]) == (msg["sender_session"], msg["transfer"]):
                self.fail(key, f, msg["reason"])

    def receive_status(self, msg, session):
        record = self.outgoing.get(msg["transfer"])
        if (
            record is None
            or record["session"] is not session
            or record["result"] is not None
        ):
            return
        if msg["state"] == "accepted":
            if not record["accepted"].is_set():
                self.client.events.put(dict(msg, type="file_accepted"))
            record["accepted"].set()
        else:
            record["result"] = msg
            record["accepted"].set()
            record["done"].set()

    def check_sending(self, record, deadline):
        if (
            self.client._session is not record["session"]
            or record["session"]["stop"].is_set()
        ):
            raise ConnectionError("Session ended while sending file")
        if time.monotonic() >= deadline:
            raise TimeoutError("File delivery is unconfirmed")
        result = record["result"]
        if result is not None and result["state"] != "delivered":
            raise RuntimeError(
                "File delivery failed: "
                + ", ".join(
                    item["name"] + ": " + item["reason"] for item in result["failures"]
                )
            )

    def file(self, recipient, path):
        client = self.client
        session = client._capture_session()
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError("File size limit: 25 MiB")
        transfer = uuid.uuid4().hex
        with client._state_lock:
            if client._session is not session:
                raise ConnectionError("Session ended before sending file")
            if len(self.outgoing) >= FILE_OUTGOING_LIMIT:
                raise RuntimeError("Too many outgoing file transfers")
            record = {
                "session": session,
                "accepted": threading.Event(),
                "done": threading.Event(),
                "result": None,
            }
            self.outgoing[transfer] = record
            deadline = time.monotonic() + client.file_transfer_timeout
            client.events.put(
                {
                    "type": "file_sending",
                    "transfer": transfer,
                    "to": recipient,
                    "filename": path.name,
                }
            )
        try:
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if before.st_size > MAX_FILE_SIZE:
                    raise ValueError("File size limit: 25 MiB")
                digest = hashlib.sha256()
                hashed_size = 0
                while True:
                    self.check_sending(record, deadline)
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    hashed_size += len(block)
                    if hashed_size > before.st_size:
                        raise RuntimeError("Source file changed while hashing")
                    digest.update(block)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise RuntimeError("Source file changed while hashing")
                meta = {
                    "transfer": transfer,
                    "filename": path.name,
                    "count": (before.st_size + CHUNK - 1) // CHUNK,
                    "size": before.st_size,
                    "sha256": digest.hexdigest(),
                }
                start = client.packet(recipient, "file_start", "", meta)
                validate_udp(
                    dict(start, **{"from": client.name, "token": client.token}),
                    from_client=True,
                )
                encode_udp(
                    dict(start, **{"from": client.name, "token": client.token}),
                    client.f,
                )
                encode_udp(
                    dict(
                        start,
                        **{
                            "from": client.name,
                            "to": "x" * 24,
                            "meta": dict(meta, sender_session="0" * 32),
                        },
                    ),
                    client.f,
                )
                client.send_packets(
                    [start], session=session, file_record=record, deadline=deadline
                )
                self.check_sending(record, deadline)
                stream.seek(0)
                index = 0
                ui_progress_at = float("-inf")
                while index < meta["count"]:
                    self.check_sending(record, deadline)
                    batch = []
                    for _ in range(min(SEND_WINDOW, meta["count"] - index)):
                        block = stream.read(CHUNK)
                        if len(block) != min(CHUNK, meta["size"] - index * CHUNK):
                            raise RuntimeError("Source file changed while sending")
                        batch.append(
                            client.packet(
                                recipient,
                                "file_chunk",
                                b64(block),
                                {"transfer": transfer, "index": index},
                            )
                        )
                        index += 1
                    client.send_packets(
                        batch, session=session, file_record=record, deadline=deadline
                    )
                    now = time.monotonic()
                    if (
                        now - ui_progress_at >= FILE_PROGRESS_INTERVAL
                        or index == meta["count"]
                    ):
                        with client._state_lock:
                            self.check_sending(record, deadline)
                            client.events.put(
                                {
                                    "type": "file_send_progress",
                                    "transfer": transfer,
                                    "to": recipient,
                                    "filename": path.name,
                                    "sent": index,
                                    "total": meta["count"],
                                }
                            )
                        ui_progress_at = now
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise RuntimeError("Source file changed while sending")
                client.send_packets(
                    [client.packet(recipient, "file_end", "", {"transfer": transfer})],
                    session=session,
                    file_record=record,
                    deadline=deadline,
                )
            waiting_since = time.monotonic()
            while not record["done"].wait(0.05):
                self.check_sending(record, deadline)
                if time.monotonic() - waiting_since >= client.file_idle_timeout:
                    raise TimeoutError("File delivery is unconfirmed")
            self.check_sending(record, deadline)
            with client._state_lock:
                self.check_sending(record, deadline)
                client.events.put(dict(record["result"], type="file_delivered"))
                client.events.put(
                    {
                        "type": "file_sent",
                        "transfer": transfer,
                        "filename": path.name,
                        "to": recipient,
                        "size": meta["size"],
                    }
                )
        except (OSError, RuntimeError, ValueError) as exc:
            if client._session is session and record["result"] is None:
                try:
                    client.send_control(
                        {"type": "file_abort", "transfer": transfer}, session
                    )
                except (OSError, ValueError):
                    pass
            with client._state_lock:
                if client._session is session or client._session is None:
                    client.events.put(
                        {
                            "type": "file_send_failed",
                            "transfer": transfer,
                            "to": recipient,
                            "reason": str(exc),
                            "result": record["result"],
                        }
                    )
                    client.events.put({"type": "error", "message": str(exc)})
            raise
        finally:
            with client._state_lock:
                if self.outgoing.get(transfer) is record:
                    del self.outgoing[transfer]
