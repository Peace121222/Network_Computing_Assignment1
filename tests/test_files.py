"""File transaction routing, admission, reordering, disk errors and receipts."""

from collections import deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import os
from pathlib import Path
import queue
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from cryptography.fernet import Fernet

from collab.client import Client
from collab.server import Server
from collab.transport.security import Channel
from collab.shared.protocol import b64, validate_tcp, validate_udp
from collab.shared.limits import CHUNK
from collab.transport.udp import decode_udp


def wait(test, predicate, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        threading.Event().wait(0.01)
    test.fail("Timed out waiting for file state")


def metadata(content=b"abc", transfer="d" * 32):
    return {
        "transfer": transfer,
        "filename": "sample.bin",
        "size": len(content),
        "count": (len(content) + CHUNK - 1) // CHUNK,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


class FileRoutingTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.server = Server(file_idle_timeout=30, file_transfer_timeout=90)
        self.server.udp = Mock()
        self.clock = patch(
            "collab.server.file_transfers.time.monotonic", return_value=100
        )
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.a, self.b = self.user("a"), self.user("b")
        self.server.users = {"alice": self.a, "bob": self.b}

    def user(self, letter):
        return dict(
            udp_security=Channel(self.server.f, letter * 32, server=True),
            token=letter * 32,
            public_id=(letter.upper().lower()) * 32,
            ready=True,
            udp_addr=("127.0.0.1", 1234),
            sock=Mock(),
            last_seen=100,
            control_condition=threading.Condition(),
            writer_stop=threading.Event(),
            control=deque(),
            presence=None,
            chat_mailbox=OrderedDict(),
        )

    def packet(self, kind="file_start", to="bob", **fields):
        packet = {
            "type": "data",
            "from": "alice",
            "token": self.a["token"],
            "to": to,
            "kind": kind,
            "id": kind,
            "meta": metadata(),
            "payload": "",
        }
        packet.update(fields)
        return packet

    def route(self, packet):
        return self.server.route(packet, self.a["udp_addr"])

    def record(self):
        return self.server.file_transfers.records[(self.a["token"], "d" * 32)]

    def test_start_retry_does_not_relay_twice_and_metadata_conflict_fails(self):
        start = self.packet()
        self.assertTrue(self.route(start))
        keys = set(self.server.pending)
        self.assertTrue(self.route(start))
        self.assertEqual(keys, set(self.server.pending))
        changed = copy.deepcopy(start)
        changed["meta"]["filename"] = "changed.bin"
        self.assertFalse(self.route(changed))
        self.assertEqual(self.record()["states"], {"bob": "metadata_conflict"})

    def test_broadcast_freezes_recipient_sessions(self):
        self.assertTrue(self.route(self.packet(to="*")))
        self.server.users["carol"] = self.user("c")
        chunk = self.packet(
            "file_chunk",
            to="*",
            meta={"transfer": "d" * 32, "index": 0},
            payload=b64(b"abc"),
        )
        self.assertTrue(self.route(chunk))
        self.assertTrue(all(name == "bob" for name, _ in self.server.pending))
        self.server.remove_session("bob", self.b["token"])
        self.server.users["bob"] = self.user("e")
        self.route(self.packet(to="*"))
        self.assertEqual(self.record()["states"], {"bob": "recipient_disconnected"})
        self.assertEqual(self.server.pending, {})

    def test_unknown_transfer_is_not_acked(self):
        self.assertFalse(
            self.route(self.packet("file_end", meta={"transfer": "d" * 32}))
        )
        self.server.udp.sendto.assert_not_called()

    def test_rejections_and_cached_final_result(self):
        for target, reason in [
            ("alice", "self_recipient"),
            ("offline", "recipient_offline"),
            ("*", "no_recipients"),
        ]:
            with self.subTest(target=target):
                self.server.file_transfers.records.clear()
                self.server.users = {"alice": self.a}
                start = self.packet(to=target)
                self.assertTrue(self.route(start))
                self.assertEqual(
                    self.record()["result"]["failures"][0]["reason"], reason
                )
                self.assertTrue(self.route(start))
                self.assertEqual(self.server.pending, {})

    def test_ack_is_not_delivery_and_receipt_requires_current_session_and_complete_ingress(
        self,
    ):
        self.route(self.packet())
        receipt = {
            "type": "file_receipt",
            "transfer": "d" * 32,
            "sender_session": self.a["public_id"],
            "state": "delivered",
        }
        manager = self.server.file_transfers
        manager.receipt("bob", self.b, receipt, 101)
        self.assertIsNone(self.record()["result"])
        self.route(
            self.packet(
                "file_chunk",
                meta={"transfer": "d" * 32, "index": 0},
                payload=b64(b"abc"),
            )
        )
        self.route(self.packet("file_end", meta={"transfer": "d" * 32}))
        manager.receipt("bob", self.user("e"), receipt, 102)
        self.assertIsNone(self.record()["result"])
        manager.receipt("bob", self.b, receipt, 102)
        self.assertEqual(self.record()["result"]["state"], "delivered")
        self.assertFalse(self.server.pending)
        self.assertTrue(self.route(self.packet()))
        self.assertFalse(self.server.pending)

    def test_idle_boundary_and_duplicate_does_not_extend_deadline(self):
        self.route(self.packet())
        self.server.file_transfers.expire(129.99)
        self.assertIsNone(self.record()["result"])
        self.route(self.packet())
        self.assertEqual(self.record()["progress"], 100)
        self.server.file_transfers.expire(130)
        self.assertEqual(self.record()["states"]["bob"], "delivery_timeout")
        self.server.file_transfers.expire(190)
        self.assertFalse(self.server.file_transfers.records)

    def test_partial_failure_and_source_cleanup(self):
        c = self.user("c")
        self.server.users["carol"] = c
        self.route(self.packet(to="*"))
        self.server.file_transfers.outcome(self.record(), "bob", "disk_error", 101)
        self.assertIsNone(self.record()["result"])
        self.server.file_transfers.outcome(self.record(), "carol", "delivered", 102)
        result = self.record()["result"]
        self.assertEqual(result["delivered"], ["carol"])
        self.assertEqual(result["state"], "failed")
        self.server.remove_session("alice", self.a["token"])
        self.assertFalse(self.server.file_transfers.records)

    def test_hash_memory_budget_and_active_limit(self):
        with patch("collab.server.file_transfers.FILE_HASH_BUDGET", 1):
            self.assertFalse(self.route(self.packet()))
        with patch("collab.server.file_transfers.FILE_ACTIVE_LIMIT", 0):
            self.assertFalse(self.route(self.packet()))
        self.assertFalse(self.server.pending)

    def test_total_deadline_applies_despite_recent_progress(self):
        self.route(self.packet())
        self.record()["progress"] = 189.99
        self.server.file_transfers.expire(190)
        self.assertEqual(self.record()["states"], {"bob": "delivery_timeout"})

    def test_exhausted_retry_fails_transfer_and_removes_its_other_packets(self):
        self.route(self.packet())
        self.route(
            self.packet(
                "file_chunk",
                meta={"transfer": "d" * 32, "index": 0},
                payload=b64(b"abc"),
            )
        )
        next(iter(self.server.pending.values()))["attempts"] = 12
        self.server.retransmit_once(now=101)
        self.assertFalse(self.server.pending)
        self.assertEqual(self.record()["states"], {"bob": "delivery_timeout"})

    def test_result_cache_retry_rejects_changed_contents(self):
        start = self.packet()
        self.route(start)
        self.server.file_transfers.outcome(self.record(), "bob", "disk_error", 101)
        changed = copy.deepcopy(start)
        changed["meta"]["filename"] = "changed.bin"
        self.assertFalse(self.route(changed))
        self.assertTrue(self.route(start))
        self.assertFalse(self.server.pending)

    def test_mailbox_capacity_is_bounded_and_stops_slow_session(self):
        self.a["file_mailbox"] = OrderedDict((i, None) for i in range(32))
        self.assertFalse(self.route(self.packet()))
        self.assertTrue(self.a["writer_stop"].is_set())
        self.assertFalse(self.server.file_transfers.records)

    def test_invalid_timeout_configuration(self):
        for value in (True, 0, -1, float("nan"), float("inf"), "30"):
            for field in ("file_idle_timeout", "file_transfer_timeout"):
                with (
                    self.subTest(value=value, field=field),
                    self.assertRaises(ValueError),
                ):
                    Server(**{field: value})
                with (
                    self.subTest(value=value, field=field),
                    self.assertRaises(ValueError),
                ):
                    Client("alice", **{field: value})


class FileReceiverTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.client = Client("bob", download_dir=self.temp.name)
        self.session = {
            "stop": threading.Event(),
            "started": threading.Event(),
            "finalize_queue": queue.Queue(4),
            "file_resources": {},
            "receipts": {},
        }
        self.client._session = self.session
        self.client.status = "connected"
        self.addCleanup(self.client.close)

    def packet(self, kind, content=b"abc", index=0):
        meta = metadata(content)
        payload = ""
        if kind != "file_start":
            meta = {"transfer": "d" * 32}
        if kind == "file_chunk":
            meta["index"] = index
            payload = b64(content)
        meta["sender_session"] = "a" * 32
        return {
            "type": "data",
            "id": kind,
            "kind": kind,
            "from": "alice",
            "to": "bob",
            "meta": meta,
            "payload": payload,
        }

    def test_chunk_and_end_before_start_are_not_accepted_or_remembered(self):
        for kind in ("file_chunk", "file_end"):
            self.assertFalse(self.client.on_data(self.packet(kind)))
        self.assertFalse(self.client.messages_seen)
        self.assertTrue(self.client.on_data(self.packet("file_start")))
        self.assertTrue(self.client.on_data(self.packet("file_chunk")))
        self.assertTrue(self.client.on_data(self.packet("file_end")))
        f = next(iter(self.client.files.values()))
        self.assertEqual(len(f["chunks"]), 1)
        self.assertTrue(f["ended"])

    def test_full_queue_does_not_accept_chunk_then_retry_can_succeed(self):
        self.client.on_data(self.packet("file_start"))
        jobs = self.session["finalize_queue"]
        while not jobs.full():
            jobs.put_nowait(("placeholder",))
        chunk = self.packet("file_chunk")
        self.assertFalse(self.client.on_data(chunk))
        self.assertFalse(next(iter(self.client.files.values()))["chunks"])
        jobs.get_nowait()
        jobs.task_done()
        self.assertTrue(self.client.on_data(chunk))
        size = jobs.qsize()
        self.assertTrue(self.client.on_data(chunk))
        self.assertEqual(jobs.qsize(), size)

    def test_conflicting_chunk_fails_transfer_and_reports_reason(self):
        self.client.on_data(self.packet("file_start"))
        self.client.on_data(self.packet("file_chunk"))
        self.assertFalse(self.client.on_data(self.packet("file_chunk", b"bad")))
        self.assertFalse(self.client.files)
        self.assertEqual(
            next(iter(self.session["receipts"].values()))["reason"], "chunk_conflict"
        )

    def test_idle_expiry_returns_capacity(self):
        self.client.on_data(self.packet("file_start"))
        f = next(iter(self.client.files.values()))
        receipts = self.client._file_transfers.maintenance(
            self.session, f["progress"] + 30
        )
        self.assertFalse(self.client.files)
        self.assertEqual(receipts[0]["reason"], "delivery_timeout")

    def test_validation_rejects_bad_control_messages_and_missing_epoch(self):
        status = {
            "type": "file_status",
            "transfer": "d" * 32,
            "state": "delivered",
            "recipients": ["bob"],
            "delivered": ["bob"],
            "failures": [],
        }
        validate_tcp(status, from_client=False)
        for changed in (
            {"state": "accepted"},
            {"delivered": []},
            {"transfer": "bad"},
            {"state": []},
        ):
            with self.assertRaises(ValueError):
                validate_tcp(dict(status, **changed), from_client=False)
        chunk = self.packet("file_chunk")
        del chunk["meta"]["sender_session"]
        with self.assertRaises(ValueError):
            validate_udp(chunk, from_client=False)

    def test_conflicting_start_does_not_replace_original_metadata(self):
        start = self.packet("file_start")
        self.client.on_data(start)
        changed = copy.deepcopy(start)
        changed["meta"]["size"] = 2
        self.assertFalse(self.client.on_data(changed))
        self.assertEqual(
            self.client._file_transfers.completed[("a" * 32, "d" * 32)]["meta"],
            start["meta"],
        )

    def test_failed_temp_cleanup_blocks_connect_until_retry_succeeds(self):
        self.client.on_data(self.packet("file_start"))
        f = next(iter(self.client.files.values()))
        temporary = Path(self.temp.name) / ".leftover"
        temporary.write_bytes(b"partial")
        f["temporary"] = temporary
        f["cancelled"] = True
        with patch.object(Path, "unlink", side_effect=OSError("busy")):
            self.client._file_transfers.dispose(f)
            with self.assertRaisesRegex(RuntimeError, "file cleanup failed"):
                self.client.close()
            with self.assertRaisesRegex(RuntimeError, "file cleanup failed"):
                self.client.connect()
        self.client.close()
        self.assertFalse(temporary.exists())
        self.assertFalse(self.client._file_transfers.orphans)

    def test_old_session_cancellation_cannot_cancel_current_transfer(self):
        self.client.on_data(self.packet("file_start"))
        key = ("alice", "d" * 32)
        message = {
            "type": "file_cancel",
            "sender_session": "a" * 32,
            "transfer": "d" * 32,
            "reason": "source_aborted",
        }
        self.client._file_transfers.cancel(message, {"stop": threading.Event()})
        self.assertIn(key, self.client.files)
        self.assertFalse(self.client.files[key]["cancelled"])
        self.client._file_transfers.cancel(message, self.session)
        self.assertNotIn(key, self.client.files)

    def test_completed_retry_is_idempotent_and_repeats_receipt(self):
        start = self.packet("file_start")
        self.client.on_data(start)
        f = next(iter(self.client.files.values()))
        self.client._file_transfers.remember(f, "delivered")
        self.client.files.clear()
        self.assertTrue(self.client.on_data(start))
        self.assertFalse(self.client.files)
        self.assertEqual(
            next(iter(self.session["receipts"].values()))["state"], "delivered"
        )


class FileNetworkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.server = Server(tcp_port=0, udp_port=0)
        self.server.start()
        self.clients = []
        self.source = Path(self.temp.name) / "source.bin"
        self.source.write_bytes(os.urandom(4 * CHUNK + 1))

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.server.close()
        self.temp.cleanup()
        self.env.stop()

    def client(self, name):
        c = Client(
            name, port=self.server.tcp_port, download_dir=Path(self.temp.name) / name
        )
        self.clients.append(c)
        c.connect()
        wait(
            self, lambda: name in self.server.users and self.server.users[name]["ready"]
        )
        return c

    def pair(self):
        a, b = self.client("alice"), self.client("bob")
        wait(self, lambda: len(a.names) == len(b.names) == 2)
        return a, b

    def test_success_waits_for_disk_completion_and_reports_once(self):
        a, b = self.pair()
        entered, release = threading.Event(), threading.Event()
        original = b._finalize_file

        def slow(*args):
            entered.set()
            release.wait(3)
            return original(*args)

        try:
            with (
                patch.object(b, "_finalize_file", side_effect=slow),
                ThreadPoolExecutor(1) as pool,
            ):
                future = pool.submit(a.file, "bob", self.source)
                try:
                    self.assertTrue(entered.wait(2))
                    self.assertFalse(future.done())
                    a.chat("bob", "while hashing")
                finally:
                    release.set()
                future.result(3)
        finally:
            release.set()
        events = list(a.events.queue)
        self.assertEqual(sum(e["type"] == "file_sent" for e in events), 1)
        files = list(b.download_dir.iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), self.source.read_bytes())

    def test_unknown_start_order_and_lost_ack_recover_without_duplicate_file(self):
        a, b = self.pair()
        send = self.server._send_session_udp
        counts = {"start": 0, "source_ack": 0}

        def reorder(raw, sessions, address=None):
            msg = raw
            if msg["type"] == "data" and msg["kind"] == "file_start":
                counts["start"] += 1
                if counts["start"] == 1:
                    return False
            if msg["type"] == "ack":
                counts["source_ack"] += 1
                return False  # Final status must also supersede missing end ACK.
            return send(raw, sessions, address)

        # Drop only the end ingress ACK; earlier packet ACKs must advance sender.
        def selective(raw, sessions, address=None):
            msg = raw
            if msg["type"] == "ack":
                is_end = any(
                    r["packets"].get(("file_end", -1))
                    for r in self.server.file_transfers.records.values()
                )
                if not is_end:
                    return send(raw, sessions, address)
            return reorder(raw, sessions, address)

        with patch.object(self.server, "_send_session_udp", side_effect=selective):
            a.file("bob", self.source)
        self.assertGreaterEqual(counts["start"], 2)
        self.assertEqual(len(list(b.download_dir.iterdir())), 1)

    def test_lost_start_ingress_ack_and_chunk_recipient_ack_are_idempotent(self):
        a, b = self.pair()
        transfer = "e" * 32
        start = a.packet("bob", "file_start", "", metadata(b"abc", transfer))
        forward = self.server._send_session_udp
        ack = b.send_raw
        state = {
            "ingress_dropped": False,
            "recipient_dropped": False,
            "starts": 0,
            "chunks": 0,
        }

        def server_send(raw, sessions, address=None):
            msg = raw
            if (
                msg["type"] == "ack"
                and msg["id"] == start["id"]
                and not state["ingress_dropped"]
            ):
                state["ingress_dropped"] = True
                return False
            if msg["type"] == "data":
                if msg["kind"] == "file_start":
                    state["starts"] += 1
                if msg["kind"] == "file_chunk":
                    state["chunks"] += 1
            return forward(raw, sessions, address)

        def recipient_send(msg):
            if msg["type"] == "ack":
                item = self.server.pending.get(("bob", msg["id"]))
                if (
                    item
                    and item["packet"]["kind"] == "file_chunk"
                    and not state["recipient_dropped"]
                ):
                    state["recipient_dropped"] = True
                    return
            return ack(msg)

        with (
            patch.object(self.server, "_send_session_udp", side_effect=server_send),
            patch.object(b, "send_raw", side_effect=recipient_send),
        ):
            a.send_packets([start])
            self.assertEqual(state["starts"], 1)
            a.send_packets(
                [
                    a.packet(
                        "bob",
                        "file_chunk",
                        b64(b"abc"),
                        {"transfer": transfer, "index": 0},
                    )
                ]
            )
            wait(self, lambda: state["chunks"] >= 2 and not self.server.pending)
            a.send_packets([a.packet("bob", "file_end", "", {"transfer": transfer})])
            wait(
                self,
                lambda: any(e["type"] == "file_complete" for e in list(b.events.queue)),
            )
        self.assertEqual(sum(e["type"] == "file_progress" for e in b.events.queue), 1)
        self.assertEqual(len(list(b.download_dir.iterdir())), 1)

    def test_disk_error_is_returned_to_sender(self):
        a, b = self.pair()
        with patch(
            "collab.client.file_transfer.tempfile.NamedTemporaryFile",
            side_effect=OSError("disk unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "disk_error"):
                a.file("bob", self.source)
        wait(self, lambda: not b.files and not list(b.download_dir.iterdir()))
        self.assertFalse(any(e["type"] == "file_sent" for e in a.events.queue))

    def test_bad_hash_is_reported_and_temp_file_removed(self):
        a, b = self.pair()
        original = a.packet

        def packet(*args, **kwargs):
            p = original(*args, **kwargs)
            if p["kind"] == "file_start":
                p["meta"]["sha256"] = "0" * 64
            return p

        with patch.object(a, "packet", side_effect=packet):
            with self.assertRaisesRegex(RuntimeError, "hash_mismatch"):
                a.file("bob", self.source)
        wait(self, lambda: not list(b.download_dir.iterdir()))

    def test_offline_self_and_empty_broadcast_are_explicit_failures(self):
        a = self.client("alice")
        for target, reason in [
            ("bob", "recipient_offline"),
            ("alice", "self_recipient"),
            ("*", "no_recipients"),
        ]:
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(RuntimeError, reason),
            ):
                a.file(target, self.source)
        self.assertFalse(any(e["type"] == "file_sent" for e in a.events.queue))

    def test_broadcast_partial_failure_contains_successful_recipient(self):
        a, b = self.pair()
        c = self.client("carol")
        wait(self, lambda: len(a.names) == 3)

        def reject(session, key, f):
            with b._state_lock:
                b._file_transfers.fail(key, f, "disk_error")

        with patch.object(b, "_finalize_file", side_effect=reject):
            with self.assertRaisesRegex(RuntimeError, "disk_error"):
                a.file("*", self.source)
        result = next(
            e["result"] for e in a.events.queue if e["type"] == "file_send_failed"
        )
        self.assertEqual(result["delivered"], ["carol"])
        self.assertEqual(len(list(c.download_dir.iterdir())), 1)

    def test_sender_registration_limit_and_session_change(self):
        a, b = self.pair()
        with a._state_lock:
            a._file_transfers.outgoing = {str(i): {} for i in range(2)}
        try:
            with self.assertRaisesRegex(RuntimeError, "Too many"):
                a.file("bob", self.source)
        finally:
            a._file_transfers.outgoing.clear()

    def test_twenty_clients_transfer_concurrently(self):
        clients = [self.client("user" + str(i)) for i in range(20)]
        wait(self, lambda: all(len(c.names) == 20 for c in clients))
        barrier = threading.Barrier(20)

        def send(index):
            barrier.wait(3)
            clients[index].file(clients[(index + 1) % 20].name, self.source)

        with ThreadPoolExecutor(20) as pool:
            results = [pool.submit(send, i) for i in range(20)]
            for result in results:
                result.result(10)
        for c in clients:
            files = list(c.download_dir.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), self.source.read_bytes())
            self.assertEqual(sum(e["type"] == "file_sent" for e in c.events.queue), 1)
        wait(self, lambda: not self.server.pending)

    def test_end_before_chunks_and_duplicate_recipient_ack(self):
        a, b = self.pair()
        transfer = "f" * 32
        content = b"z" * (CHUNK + 1)
        meta = metadata(content, transfer)
        start = a.packet("bob", "file_start", "", meta)
        a.send_packets([start])
        wait(self, lambda: ("alice", transfer) in b.files)
        a.send_packets([a.packet("bob", "file_end", "", {"transfer": transfer})])
        original = b.send_raw
        dropped = threading.Event()

        def ack(message):
            if message["type"] == "ack" and not dropped.is_set():
                dropped.set()
                return
            return original(message)

        chunks = [
            a.packet(
                "bob",
                "file_chunk",
                b64(content[CHUNK:]),
                {"transfer": transfer, "index": 1},
            ),
            a.packet(
                "bob",
                "file_chunk",
                b64(content[:CHUNK]),
                {"transfer": transfer, "index": 0},
            ),
        ]
        with patch.object(b, "send_raw", side_effect=ack):
            a.send_packets(chunks)
            wait(
                self,
                lambda: any(e["type"] == "file_complete" for e in list(b.events.queue)),
            )
        event = next(e for e in list(b.events.queue) if e["type"] == "file_complete")
        self.assertEqual(Path(event["path"]).read_bytes(), content)
        self.assertEqual(sum(e["type"] == "file_complete" for e in b.events.queue), 1)

    def test_disconnect_cancels_sender_and_retry_uses_new_session(self):
        a, b = self.pair()
        entered, release = threading.Event(), threading.Event()
        original = b._finalize_file

        def slow(*args):
            entered.set()
            release.wait(3)
            return original(*args)

        try:
            with (
                patch.object(b, "_finalize_file", side_effect=slow),
                ThreadPoolExecutor(1) as pool,
            ):
                future = pool.submit(a.file, "bob", self.source)
                try:
                    self.assertTrue(entered.wait(2))
                    a.close()
                    with self.assertRaises(ConnectionError):
                        future.result(2)
                finally:
                    release.set()
            wait(self, lambda: not b.files and not list(b.download_dir.iterdir()))
            a.connect()
            a.file("bob", self.source)
            self.assertEqual(len(list(b.download_dir.iterdir())), 1)
        finally:
            release.set()

    def test_receiver_silence_times_out_and_cleans_both_sides(self):
        a, b = self.pair()
        self.server.file_idle_timeout = 0.15
        original = self.server._send_session_udp

        def drop_data(raw, sessions, address=None):
            msg = raw
            if msg["type"] == "data" and msg["kind"].startswith("file_"):
                return False
            return original(raw, sessions, address)

        with patch.object(self.server, "_send_session_udp", side_effect=drop_data):
            with self.assertRaisesRegex(RuntimeError, "delivery_timeout"):
                a.file("bob", self.source)
        self.assertFalse(self.server.pending)
        self.assertFalse(b.files)


class FileStreamingTests(unittest.TestCase):
    def test_near_25_mib_streams_in_bounded_windows_with_exact_content(self):
        from collab.shared.limits import MAX_FILE_SIZE, SEND_WINDOW
        from collab.shared.protocol import unb64

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}),
        ):
            source = Path(directory) / "large.bin"
            size = MAX_FILE_SIZE - 1
            with source.open("wb") as stream:
                stream.truncate(size)
            client = Client("alice", download_dir=Path(directory) / "received")
            session = {"stop": threading.Event()}
            client._session = session
            client.status = "connected"
            client.token = "a" * 32
            digest = hashlib.sha256()
            observed = {"size": 0, "chunks": 0, "max_batch": 0}

            def transport(packets, **kwargs):
                observed["max_batch"] = max(observed["max_batch"], len(packets))
                for p in packets:
                    validate_udp(
                        dict(p, **{"from": "alice", "token": client.token}),
                        from_client=True,
                    )
                    if p["kind"] == "file_start":
                        observed["meta"] = dict(p["meta"])
                    elif p["kind"] == "file_chunk":
                        self.assertEqual(p["meta"]["index"], observed["chunks"])
                        block = unb64(p["payload"])
                        digest.update(block)
                        observed["size"] += len(block)
                        observed["chunks"] += 1
                    else:
                        client._file_transfers.receive_status(
                            {
                                "type": "file_status",
                                "transfer": p["meta"]["transfer"],
                                "state": "delivered",
                                "recipients": ["bob"],
                                "delivered": ["bob"],
                                "failures": [],
                            },
                            session,
                        )

            with patch.object(client, "send_packets", side_effect=transport):
                client.file("bob", source)
            self.assertLessEqual(observed["max_batch"], SEND_WINDOW)
            self.assertEqual(observed["size"], size)
            self.assertEqual(observed["meta"]["sha256"], digest.hexdigest())
            self.assertEqual(observed["meta"]["count"], observed["chunks"])
            client._session = None
            client.status = "disconnected"
            client.close()


if __name__ == "__main__":
    unittest.main()
