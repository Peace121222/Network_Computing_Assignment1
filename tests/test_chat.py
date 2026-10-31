"""End-to-end chat results, immutable routing, replay and bounded ordering."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import copy
import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from collab.client.chat_inbox import ChatInbox
from tests.auth_support import Client
from collab.transport.udp import encode_udp, decode_udp
from collab.shared.protocol import validate_tcp, validate_udp
from collab.transport.security import Channel
from tests.auth_support import Server


def incoming(seq=1, mid=None, sender="alice", epoch="a" * 32, channel="bob"):
    return {
        "type": "data",
        "id": mid or "message-" + str(seq),
        "from": sender,
        "to": "bob",
        "kind": "chat",
        "payload": "text-" + str(seq),
        "meta": {"sender_session": epoch, "channel": channel, "sequence": seq},
    }


def wait_for(test, predicate, timeout=4):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    test.fail("Chat state did not converge")


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.inbox = ChatInbox(self.events.append)

    def test_reorders_two_before_one_and_duplicates(self):
        self.assertTrue(self.inbox.accept(incoming(2), now=0))
        self.assertEqual(self.events, [])
        self.assertTrue(self.inbox.accept(incoming(1), now=0.5))
        self.assertEqual([e["text"] for e in self.events], ["text-1", "text-2"])
        self.assertTrue(self.inbox.accept(incoming(2), now=0.6))
        self.assertEqual(len(self.events), 2)
        changed = incoming(2)
        changed["payload"] = "changed"
        self.assertFalse(self.inbox.accept(changed, now=0.7))

    def test_gap_deadline_and_late_message(self):
        self.inbox.accept(incoming(2), now=0)
        self.inbox.flush(now=0.99)
        self.assertEqual(self.events, [])
        self.inbox.flush(now=1)
        self.assertEqual([e["type"] for e in self.events], ["chat_gap", "chat"])
        self.assertEqual(self.events[0]["missing_from"], 1)
        self.assertEqual(self.events[0]["missing_to"], 1)
        self.assertTrue(self.inbox.accept(incoming(1), now=1.1))
        self.assertEqual(len(self.events), 2)

    def test_other_stream_is_not_blocked_and_ids_are_scoped(self):
        self.inbox.accept(incoming(2, mid="same"), now=0)
        self.inbox.accept(
            incoming(1, mid="same", sender="carol", epoch="c" * 32), now=0.1
        )
        self.assertEqual([e["from"] for e in self.events], ["carol"])
        self.inbox.flush(now=1)
        self.assertEqual(self.events[-1]["from"], "alice")

    def test_gap_flushes_while_other_messages_keep_arriving(self):
        self.inbox.accept(incoming(3), now=0)
        for index in range(1, 11):
            self.inbox.accept(
                incoming(index, sender="carol", epoch="c" * 32), now=index / 10
            )
        self.assertTrue(any(e["type"] == "chat_gap" for e in self.events))
        self.assertTrue(
            any(e.get("text") == "text-3" and e["from"] == "alice" for e in self.events)
        )

    def test_window_stream_cache_limits_and_expiry(self):
        self.assertFalse(self.inbox.accept(incoming(65), now=0))
        for index in range(2, 65):
            self.assertTrue(self.inbox.accept(incoming(index), now=0))
        self.assertEqual(len(next(iter(self.inbox.streams.values()))["buffer"]), 63)
        self.inbox.flush(now=1)
        self.assertTrue(self.inbox.accept(incoming(65), now=1))
        self.inbox.flush(now=62)
        self.assertEqual(self.inbox.seen, {})
        self.assertEqual(self.inbox.fingerprints, {})
        self.inbox = ChatInbox(self.events.append)
        with patch("collab.client.chat_inbox.CHAT_STREAM_LIMIT", 1):
            self.assertTrue(self.inbox.accept(incoming(1), now=63))
            self.assertFalse(
                self.inbox.accept(incoming(1, sender="carol", epoch="b" * 32), now=63)
            )
        with patch("collab.client.chat_inbox.MAX_SEEN_PACKETS", 1):
            self.assertFalse(self.inbox.accept(incoming(2), now=63))

    def test_watermark_survives_replay_cache_expiry(self):
        for seq in range(1, 81):
            self.inbox.accept(incoming(seq), now=seq / 100)
        self.inbox.flush(now=62)
        self.assertEqual(self.inbox.seen, {})
        self.assertTrue(self.inbox.accept(incoming(81), now=63))
        self.assertEqual(self.events[-1]["text"], "text-81")
        self.assertFalse(any(e["type"] == "chat_gap" for e in self.events))

    def test_unknown_peer_presence_does_not_reset_new_stream(self):
        self.inbox.set_peers(["bob"])
        self.inbox.accept(incoming(1), now=100)
        self.inbox.flush(now=100.1)
        self.inbox.accept(incoming(2), now=100.2)
        self.assertEqual([e["text"] for e in self.events], ["text-1", "text-2"])

    def test_far_ahead_packet_is_not_acked_but_can_recover_after_gap(self):
        self.assertFalse(self.inbox.accept(incoming(100), now=0))
        self.assertEqual(len(self.inbox.seen), 0)
        self.inbox.flush(now=1)
        self.assertEqual(self.events[0]["missing_to"], 99)
        self.assertTrue(self.inbox.accept(incoming(100), now=1.1))
        self.assertEqual(self.events[-1]["text"], "text-100")

    def test_ciphertext_size_estimate_matches_actual_fernet_padding(self):
        from collab.transport.udp import udp_frame_size

        cipher = Fernet(Fernet.generate_key())
        for count in range(100):
            msg = {"text": "界" * count}
            actual = encode_udp(msg, cipher, Channel(cipher, "a" * 32))
            self.assertEqual(udp_frame_size(msg), len(actual))

    def test_invalid_forwarded_chat_metadata_is_rejected(self):
        for field, value in (
            ("sender_session", "bad"),
            ("sequence", True),
            ("sequence", 0),
            ("channel", []),
        ):
            msg = incoming()
            msg["meta"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_udp(msg, from_client=False)

    def test_status_schema_rejects_conflicting_or_incomplete_results(self):
        valid = {
            "type": "chat_status",
            "id": "message",
            "state": "delivered",
            "recipients": ["bob"],
            "delivered": ["bob"],
            "failures": [],
        }
        validate_tcp(valid, from_client=False)
        for change in (
            {"state": []},
            {"delivered": []},
            {"recipients": []},
            {"failures": [{"name": "bob", "reason": "delivery_timeout"}]},
            {"state": "failed", "failures": [{"name": "bob", "reason": "bad"}]},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_tcp(dict(valid, **change), from_client=False)
        with self.assertRaises(ValueError):
            validate_tcp(valid, from_client=True)


class ChatServerTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.clock = patch("collab.server.core.time.monotonic", return_value=100)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.server = Server()
        self.server.udp = Mock()
        self.a, self.b = self.user("a" * 32), self.user("b" * 32)
        self.server.users = {"alice": self.a, "bob": self.b}

    def user(self, token):
        return dict(
            udp_security=Channel(self.server.f, token, server=True),
            test_sender=Channel(self.server.f, token),
            token=token,
            ready=True,
            udp_addr=("127.0.0.1", 1001),
            last_seen=100,
            sock=Mock(),
            udp_lock=threading.RLock(),
            control_condition=threading.Condition(),
            control=deque(),
            presence=None,
            writer_stop=threading.Event(),
        )

    def msg(self, mid="original", to="bob", sender="alice"):
        return {
            "type": "data",
            "id": mid,
            "from": sender,
            "token": self.server.users[sender]["token"],
            "to": to,
            "kind": "chat",
            "payload": "hello",
            "meta": {},
        }

    def route(self, msg=None):
        return self.server.route(msg or self.msg(), ("127.0.0.1", 1001))

    def ack(self, key):
        name, relay_id = key
        user = self.server.users[name]
        self.server.handle_udp(
            encode_udp(
                {"type": "ack", "from": name, "token": user["token"], "id": relay_id},
                self.server.f,
                user["test_sender"],
            ),
            user["udp_addr"],
        )

    def record(self, mid="original", sender="alice"):
        return self.server.chat_records[(self.server.users[sender]["token"], mid)]

    def test_duplicate_after_delivery_does_not_requeue_or_change_sequence(self):
        self.assertTrue(self.route())
        first_key = next(iter(self.server.pending))
        self.assertEqual(
            self.server.pending[first_key]["packet"]["meta"]["sequence"], 1
        )
        self.ack(first_key)
        self.assertEqual(self.record()["result"]["state"], "delivered")
        self.assertTrue(self.route())
        self.assertEqual(self.server.pending, {})
        self.assertEqual(list(self.a["sequences"].values()), [1])
        changed = self.msg()
        changed["payload"] = "different"
        self.assertFalse(self.route(changed))
        self.assertEqual(self.record()["fingerprint"][1], "hello")

    def test_same_original_id_from_two_sources_has_independent_ack(self):
        self.server.users["carol"] = self.user("c" * 32)
        self.route()
        self.route(self.msg(sender="carol"))
        self.assertEqual(len(self.server.pending), 2)
        alice_key = next(
            k
            for k, item in self.server.pending.items()
            if item["packet"]["from"] == "alice"
        )
        self.ack(alice_key)
        self.assertEqual(self.record()["result"]["state"], "delivered")
        self.assertIsNone(self.record(sender="carol")["result"])

    def test_broadcast_freezes_sessions_and_new_recipient_starts_own_stream(self):
        self.route(self.msg(to="*"))
        original_key = next(iter(self.server.pending))
        self.server.users["carol"] = self.user("c" * 32)
        self.assertTrue(self.route(self.msg(to="*")))
        self.assertEqual(set(self.server.pending), {original_key})
        self.assertEqual(self.record()["states"], {"bob": None})
        self.ack(original_key)
        self.route(self.msg(mid="next", to="*"))
        sequences = {
            item["packet"]["to"]: item["packet"]["meta"]["sequence"]
            for item in self.server.pending.values()
        }
        self.assertEqual(sequences, {"bob": 2, "carol": 1})

    def test_partial_broadcast_failure_and_relogin_not_included(self):
        self.server.users["carol"] = self.user("c" * 32)
        self.route(self.msg(to="*"))
        self.ack(next(k for k in self.server.pending if k[0] == "bob"))
        self.server.remove_session("carol", "c" * 32)
        result = self.record()["result"]
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["delivered"], ["bob"])
        self.assertEqual(
            result["failures"], [{"name": "carol", "reason": "recipient_disconnected"}]
        )
        self.server.users["carol"] = self.user("d" * 32)
        self.route(self.msg(to="*"))
        self.assertEqual(self.server.pending, {})

    def test_rejections_are_cached_and_no_success_ack(self):
        for index, (to, reason) in enumerate(
            (("missing", "recipient_offline"), ("alice", "self_recipient"))
        ):
            msg = self.msg(mid=str(index), to=to)
            self.server.udp.reset_mock()
            self.assertFalse(self.route(msg))
            self.server.udp.sendto.assert_not_called()
            self.assertEqual(
                self.record(str(index))["result"]["failures"][0]["reason"], reason
            )
        self.server.users.pop("bob")
        self.route(self.msg(mid="empty", to="*"))
        self.assertEqual(
            self.record("empty")["result"]["failures"][0]["reason"], "no_recipients"
        )

    def test_deadline_includes_recipient_without_udp_endpoint(self):
        self.b["udp_addr"] = None
        self.route()
        self.server.retransmit_once(now=104.99)
        self.assertIsNone(self.record()["result"])
        self.server.retransmit_once(now=105)
        self.assertEqual(
            self.record()["result"]["failures"][0]["reason"], "delivery_timeout"
        )
        self.assertEqual(self.server.pending, {})

    def test_retry_exhaustion_reports_failure_and_source_cleanup_cancels(self):
        self.route()
        next(iter(self.server.pending.values()))["attempts"] = 12
        self.server.retransmit_once(now=101)
        self.assertEqual(self.record()["result"]["state"], "failed")
        self.server.remove_session("alice", self.a["token"])
        self.assertEqual(self.server.chat_records, {})
        self.assertEqual(self.server.pending, {})

    def test_cache_and_mailbox_are_bounded_and_expire(self):
        with patch("collab.server.routing.CHAT_CACHE_LIMIT", 1):
            self.assertTrue(self.route())
            self.assertFalse(self.route(self.msg(mid="new")))
            self.server.retransmit_once(now=160)
            self.assertEqual(self.server.chat_records, {})
        with patch("collab.server.routing.CHAT_OUTGOING_LIMIT", 1):
            self.a["chat_mailbox"].clear()
            self.assertTrue(self.route(self.msg(mid="another")))
            self.assertFalse(self.route(self.msg(mid="full")))

    def test_status_writer_yields_to_control_after_three_results(self):
        self.server._chat_support(self.a)
        status = {
            "type": "chat_status",
            "id": "x",
            "state": "delivered",
            "recipients": ["bob"],
            "delivered": ["bob"],
            "failures": [],
        }
        for index in range(5):
            self.a["chat_mailbox"][("a" * 32, str(index))] = dict(status, id=str(index))
        self.a["control"].append(
            {"type": "users", "names": ["alice", "bob"], "revision": 1}
        )
        writes = []

        def write(sock, msg, security=None):
            writes.append(msg["type"])
            if len(writes) == 5:
                self.a["writer_stop"].set()

        with patch.object(self.server, "_write_control", side_effect=write):
            self.server.control_writer("alice", self.a)
        self.assertEqual(
            writes,
            ["chat_status", "chat_status", "chat_status", "users", "chat_status"],
        )
        self.assertEqual(len(self.a["chat_mailbox"]), 1)

    def test_reserved_capacity_keeps_chat_admissible_when_files_fill_quota(self):
        self.server.max_pending_packets = self.server.max_pending_per_recipient = 8
        from collab.shared.limits import CHUNK
        from collab.shared.protocol import b64

        start = dict(
            self.msg(mid="file-start"),
            kind="file_start",
            payload="",
            meta={
                "transfer": "d" * 32,
                "filename": "file.bin",
                "size": CHUNK * 8,
                "count": 8,
                "sha256": "0" * 64,
            },
        )
        self.assertTrue(self.route(start))
        for index in range(6):
            msg = dict(
                self.msg(mid="file" + str(index)),
                kind="file_chunk",
                payload=b64(b"x" * CHUNK),
                meta={"transfer": "d" * 32, "index": index},
            )
            self.assertTrue(self.route(msg))
        msg = dict(msg, id="extra-file", meta={"transfer": "d" * 32, "index": 6})
        self.assertFalse(self.route(msg))
        self.assertTrue(self.route())
        self.assertEqual(len(self.server.pending), 8)

    def test_weighted_schedule_uses_96_chat_and_32_file_slots(self):

        from collab.transport.congestion import CubicController

        congestion = CubicController(max_window=512, clock=lambda: 100)
        congestion.cwnd = congestion._tokens = 512
        self.server.users["bob"]["congestion"] = congestion
        for index in range(140):
            for kind in ("chat", "file_end"):
                mid = kind + str(index)
                self.server.pending[("bob", mid)] = dict(
                    packet={
                        "type": "data",
                        "id": mid,
                        "from": "alice",
                        "to": "bob",
                        "kind": kind,
                        "payload": "hello" if kind == "chat" else "",
                        "meta": (
                            incoming()["meta"]
                            if kind == "chat"
                            else {"transfer": "d" * 32}
                        ),
                    },
                    source_token=self.a["token"],
                    destination_token=self.b["token"],
                    attempts=0,
                    retry_time=0,
                )
        self.server.retransmit_once(now=100)
        sent = [
            item["packet"]["kind"]
            for item in self.server.pending.values()
            if item["attempts"]
        ]
        self.assertEqual(sent.count("chat"), 96)
        self.assertEqual(sent.count("file_end"), 32)
        for _ in range(3):
            self.server.retransmit_once(now=100)
        self.assertTrue(
            all(item["attempts"] == 1 for item in self.server.pending.values())
        )


class ChatNetworkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.server = Server("127.0.0.1", 0, 0)
        self.server.start()
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.close()
        self.temp.cleanup()
        self.env.stop()

    def client(self, name):
        client = Client(
            name, port=self.server.tcp_port, download_dir=Path(self.temp.name) / name
        )
        self.clients.append(client)
        client.connect()
        return client

    def pair(self):
        a, b = self.client("alice"), self.client("bob")
        wait_for(self, lambda: a.names == b.names == ["alice", "bob"])
        return a, b

    def events(self, client):
        result = []
        while not client.events.empty():
            result.append(client.events.get_nowait())
        return result

    def test_end_to_end_success_and_rejected_offline_self_empty(self):
        a, b = self.pair()
        a.chat("bob", "confirmed")
        types = [e["type"] for e in self.events(a)]
        self.assertLess(types.index("chat_sending"), types.index("chat_accepted"))
        self.assertLess(types.index("chat_accepted"), types.index("chat_delivered"))
        self.assertEqual(types.count("sent"), 1)
        self.assertEqual(
            [e["text"] for e in self.events(b) if e["type"] == "chat"], ["confirmed"]
        )
        for recipient, reason in (
            ("missing", "recipient_offline"),
            ("alice", "self_recipient"),
        ):
            with self.assertRaisesRegex(RuntimeError, reason):
                a.chat(recipient, "rejected")
            self.assertFalse(any(e["type"] == "sent" for e in self.events(a)))
        b.close()
        wait_for(self, lambda: "bob" not in self.server.users)
        with self.assertRaisesRegex(RuntimeError, "no_recipients"):
            a.chat("*", "empty")

    def test_final_tcp_status_supersedes_lost_ingress_ack(self):
        a, b = self.pair()
        original = self.server._send_session_udp

        def drop_ack(raw, sessions, address=None):
            if raw.get("type") == "ack":
                return True
            return original(raw, sessions, address)

        with patch.object(self.server, "_send_session_udp", side_effect=drop_ack):
            a.chat("bob", "TCP final before UDP ACK")
        self.assertEqual(len(self.server.chat_records), 1)
        self.assertEqual(len([e for e in self.events(b) if e["type"] == "chat"]), 1)
        self.assertEqual(len([e for e in self.events(a) if e["type"] == "sent"]), 1)

    def test_lost_recipient_ack_causes_retry_without_duplicate_display(self):
        a, b = self.pair()
        original = b.send_raw
        dropped = threading.Event()

        def send(msg):
            if msg["type"] == "ack" and not dropped.is_set():
                dropped.set()
                return
            original(msg)

        with patch.object(b, "send_raw", side_effect=send):
            a.chat("bob", "retry once")
        self.assertTrue(dropped.is_set())
        self.assertEqual(len([e for e in self.events(b) if e["type"] == "chat"]), 1)

    def test_partial_broadcast_failure_is_returned_to_sender(self):
        a, b = self.pair()
        c = self.client("carol")
        wait_for(self, lambda: len(a.names) == 3)
        original = self.server._send_session_udp
        blocked = threading.Event()

        def drop_carol(raw, sessions, address=None):
            msg = raw
            if msg.get("kind") == "chat" and msg.get("to") == "carol":
                blocked.set()
                return True
            return original(raw, sessions, address)

        with (
            patch.object(self.server, "_send_session_udp", side_effect=drop_carol),
            ThreadPoolExecutor(1) as pool,
        ):
            future = pool.submit(a.chat, "*", "partial")
            self.assertTrue(blocked.wait(2))
            wait_for(
                self, lambda: any(e["type"] == "chat" for e in list(b.events.queue))
            )
            self.server.remove_session("carol", c.token)
            with self.assertRaisesRegex(RuntimeError, "recipient_disconnected"):
                future.result(3)
        failure = next(e for e in self.events(a) if e["type"] == "chat_send_failed")
        self.assertEqual(failure["result"]["delivered"], ["bob"])
        self.assertEqual(failure["result"]["failures"][0]["name"], "carol")

    def test_receiver_reorders_over_network_and_reports_gap(self):
        a, b = self.pair()
        original = self.server._send_session_udp
        held = []

        def reorder(raw, sessions, address=None):
            msg = raw
            if msg.get("kind") == "chat" and msg["meta"]["sequence"] == 1:
                if not held:
                    held.append((raw, sessions, address))
                return True
            return original(raw, sessions, address)

        with (
            patch.object(self.server, "_send_session_udp", side_effect=reorder),
            ThreadPoolExecutor(2) as pool,
        ):
            first = pool.submit(a.chat, "bob", "first")
            wait_for(self, lambda: bool(held))
            second = pool.submit(a.chat, "bob", "second")
            second.result(2)
            original(*held[0])
            first.result(2)
        wait_for(
            self,
            lambda: len([e for e in list(b.events.queue) if e["type"] == "chat"]) == 2,
        )
        self.assertEqual(
            [e["text"] for e in self.events(b) if e["type"] == "chat"],
            ["first", "second"],
        )

    def test_recipient_without_endpoint_times_out_without_sent_event(self):
        a, b = self.pair()
        original = self.server._send_session_udp

        def drop_chat(raw, sessions, address=None):
            if raw.get("kind") == "chat":
                return True
            return original(raw, sessions, address)

        with (
            patch("collab.server.routing.CHAT_SERVER_TIMEOUT", 0.2),
            patch.object(self.server, "_send_session_udp", side_effect=drop_chat),
        ):
            with self.assertRaisesRegex(RuntimeError, "delivery_timeout"):
                a.chat("bob", "lost")
        self.assertFalse(any(e["type"] == "sent" for e in self.events(a)))

    def test_client_timeout_and_disconnect_wake_pending_chat(self):
        a, b = self.pair()
        with (
            patch.object(a, "send_packets"),
            patch("collab.client.chat_sender.CHAT_CONFIRM_TIMEOUT", 0.05),
        ):
            with self.assertRaises(TimeoutError):
                a.chat("bob", "unconfirmed")
        self.assertEqual(a.outgoing_chats, {})
        with patch.object(a, "send_packets"), ThreadPoolExecutor(1) as pool:
            future = pool.submit(a.chat, "bob", "disconnect")
            wait_for(self, lambda: bool(a.outgoing_chats))
            a.close()
            with self.assertRaises(ConnectionError):
                future.result(2)

    def test_chat_is_confirmed_during_concurrent_file_transfer(self):
        a, b = self.pair()
        source = Path(self.temp.name) / "payload.bin"
        content = os.urandom(150_000)
        source.write_bytes(content)
        original = a.send_packets
        chunks_started = threading.Event()

        def send(packets, *args, **kwargs):
            if packets and packets[0]["kind"] == "file_chunk":
                chunks_started.set()
            return original(packets, *args, **kwargs)

        with (
            patch.object(a, "send_packets", side_effect=send),
            ThreadPoolExecutor(2) as pool,
        ):
            file_future = pool.submit(a.file, "bob", source)
            self.assertTrue(chunks_started.wait(2))
            pool.submit(a.chat, "bob", "chat during file").result(4)
            file_future.result(12)
        wait_for(
            self,
            lambda: any(e["type"] == "file_complete" for e in list(b.events.queue)),
            timeout=8,
        )
        events = self.events(b)
        self.assertEqual(
            len([e for e in events if e.get("text") == "chat during file"]), 1
        )
        received = next(e for e in events if e["type"] == "file_complete")
        self.assertEqual(Path(received["path"]).read_bytes(), content)

    def test_client_outgoing_limit(self):
        a, b = self.pair()
        with a._state_lock:
            for index in range(32):
                a.outgoing_chats[str(index)] = {
                    "reported": True,
                    "done": threading.Event(),
                }
        with self.assertRaisesRegex(RuntimeError, "Too many"):
            a.chat("bob", "busy")
        with a._state_lock:
            a.outgoing_chats.clear()


if __name__ == "__main__":
    unittest.main()
