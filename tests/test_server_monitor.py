"""Operational event privacy, bounded state and loopback HTTP behavior."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from collab.server.monitor import EventJournal, LogConsole


class MonitorTests(unittest.TestCase):
    def test_concurrent_events_are_ordered_bounded_and_exclude_secrets(self):
        journal = EventJournal(capacity=20)
        with ThreadPoolExecutor(4) as pool:
            list(pool.map(lambda i: journal.emit("chat.result", user="alice", state="delivered",
                                                password="SECRET", payload="PRIVATE", key="KEY"), range(100)))
        snapshot = journal.snapshot()
        self.assertEqual(snapshot["latest"], 100)
        self.assertEqual([e["id"] for e in snapshot["events"]], list(range(81, 101)))
        self.assertNotIn("SECRET", json.dumps(snapshot))
        self.assertNotIn("PRIVATE", json.dumps(snapshot))
        self.assertNotIn("KEY", json.dumps(snapshot))

    def test_activity_survives_packet_trace_eviction(self):
        journal = EventJournal(capacity=3)
        journal.emit("login.succeeded", user="alice")
        for _ in range(10):
            journal.emit("udp.received", message="heartbeat")
        snapshot = journal.snapshot()
        self.assertEqual(len(snapshot["events"]), 3)
        self.assertEqual([e["event"] for e in snapshot["activity"]], ["login.succeeded"])
        self.assertEqual(snapshot["activity_evicted"], 0)
        for _ in range(4):
            journal.emit("chat.result", user="alice", state="delivered")
        snapshot = journal.snapshot()
        self.assertEqual(len(snapshot["activity"]), 3)
        self.assertEqual(snapshot["activity_evicted"], 2)

    def test_each_run_creates_its_own_file_without_appending_existing_logs(self):
        from datetime import datetime, timezone
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as root:
            template = Path(root) / "server.jsonl"
            template.write_text("previous log\n")
            paths = []
            with patch("collab.server.monitor.datetime") as clock:
                clock.now.return_value = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
                for user in ("alice", "bob"):
                    journal = EventJournal()
                    path = journal.start_file(template)
                    journal.emit("login.succeeded", user=user)
                    journal.close()
                    paths.append(path)
            self.assertNotEqual(paths[0], paths[1])
            self.assertEqual(template.read_text(), "previous log\n")
            for path, user in zip(paths, ("alice", "bob")):
                self.assertTrue(path.name.startswith("server-20261103T120000.000000Z-"))
                self.assertEqual(path.suffix, ".jsonl")
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual([row["details"]["user"] for row in rows], [user])

    def test_file_flush_rotation_and_json_lines(self):
        with tempfile.TemporaryDirectory() as root:
            journal = EventJournal()
            journal.start_file(Path(root) / "nested" / "server.jsonl")
            journal._handler.maxBytes = 350
            for _ in range(8):
                journal.emit("login.succeeded", user="alice")
            journal.close()
            files = list((Path(root) / "nested").iterdir())
            self.assertGreater(len(files), 1)
            self.assertLessEqual(len(files), 4)
            for path in files:
                for line in path.read_text().splitlines():
                    self.assertEqual(json.loads(line)["event"], "login.succeeded")
            self.assertEqual(journal.snapshot()["write_errors"], 0)

    def test_file_write_failure_keeps_events_available(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as root:
            journal = EventJournal()
            journal.start_file(Path(root) / "server.jsonl")
            with patch.object(journal._handler.stream, "write", side_effect=OSError("disk full")):
                journal.emit("login.succeeded", user="alice")
                journal.close()
            snapshot = journal.snapshot()
            self.assertEqual(snapshot["write_errors"], 1)
            self.assertEqual(snapshot["events"][0]["event"], "login.succeeded")

    def test_real_chat_file_events_once_and_no_contents(self):
        from tests.auth_support import Server, Client
        import time

        with tempfile.TemporaryDirectory() as root:
            server = Server(tcp_port=0, udp_port=0, trace_network=True)
            self.addCleanup(server.close)
            server.start()
            alice = Client("alice", port=server.tcp_port, download_dir=Path(root) / "a")
            bob = Client("bob", port=server.tcp_port, download_dir=Path(root) / "b")
            self.addCleanup(alice.close)
            self.addCleanup(bob.close)
            alice.connect()
            bob.connect()
            deadline = time.monotonic() + 3
            while len(alice.names) != 2 or len(bob.names) != 2:
                if time.monotonic() > deadline:
                    self.fail("Presence was not ready")
                server.stopping.wait(0.01)
            # Simulate one dropped relay datagram below the routing boundary.
            # No udp.sent event is invented for the skipped send.
            from unittest.mock import patch
            original_send = server._send_session_udp
            dropped = []

            def drop_once(message, sessions, address=None):
                if message.get("kind") == "chat" and not dropped:
                    dropped.append(message["id"])
                    return True
                return original_send(message, sessions, address)

            with patch.object(server, "_send_session_udp", side_effect=drop_once):
                alice.chat("bob", "PRIVATE MESSAGE CONTENT")
            source = Path(root) / "source.txt"
            source.write_text("PRIVATE FILE CONTENT")
            alice.file("bob", source)
            snapshot = server.events.snapshot()
            events = snapshot["events"]
            self.assertEqual(sum(e["event"] == "chat.result" for e in events), 1)
            self.assertEqual(sum(e["event"] == "file.started" for e in events), 1)
            self.assertEqual(sum(e["event"] == "file.result" for e in events), 1)
            names = {e["event"] for e in events}
            self.assertTrue({"tcp.accepted", "tls.established", "tcp.received", "tcp.sent",
                             "udp.received", "udp.sent", "udp.ack_matched", "udp.window_send"} <= names)
            self.assertTrue(any(e["event"] == "udp.retry" and e["details"]["attempt"] >= 2
                                for e in events))
            udp = [e for e in events if e["event"] in {"udp.sent", "udp.received"}]
            self.assertTrue(all(0 < e["details"]["bytes"] <= 1100 for e in udp))
            self.assertTrue(all(len(e["details"]["ciphertext_hex"]) == 64 for e in udp))
            self.assertTrue(all(":" in e["details"]["source"] for e in udp))
            self.assertTrue(any(e["details"].get("verification") == "receiver_confirmed_sha256_and_save" for e in events))
            for tag in ("1", "2", "3", "4", "5", "6", "7", "8", "flow"):
                self.assertGreater(snapshot["evidence_counts"].get(tag, 0), 0, tag)
            self.assertEqual(snapshot["evidence_counts"].get("9", 0), 0)
            self.assertEqual(snapshot["evidence_counts"].get("10", 0), 0)
            self.assertNotIn("PRIVATE", json.dumps(snapshot))
            self.assertNotIn(alice.token, json.dumps(snapshot))
            self.assertNotIn("test password 123", json.dumps(snapshot))
            for entry in events:
                if entry["event"] in ("chat.result", "file.result"):
                    self.assertEqual(entry["details"]["state"], "delivered")
            alice.close()
            self.assertTrue(any(e["event"] == "session.closed" for e in server.events.snapshot()["events"]))

    def test_default_ui_has_handshake_ciphertext_and_sampled_file_milestones(self):
        from tests.auth_support import Server, Client
        import time

        with tempfile.TemporaryDirectory() as root:
            server = Server(tcp_port=0, udp_port=0)
            self.addCleanup(server.close)
            server.start()
            alice = Client("alice", port=server.tcp_port, download_dir=Path(root) / "a")
            bob = Client("bob", port=server.tcp_port, download_dir=Path(root) / "b")
            self.addCleanup(alice.close)
            self.addCleanup(bob.close)
            alice.connect()
            bob.connect()
            deadline = time.monotonic() + 3
            while len(alice.names) != 2 or len(bob.names) != 2:
                if time.monotonic() > deadline:
                    self.fail("Presence was not ready")
                server.stopping.wait(0.01)
            alice.chat("bob", "PRIVATE DEMO CONTENT")
            source = Path(root) / "file.bin"
            source.write_bytes(b"x" * 640 + b"y")
            alice.file("bob", source)
            activity = server.events.snapshot()["activity"]
            names = {e["event"] for e in activity}
            self.assertTrue({"tcp.accepted", "tls.established", "connection.welcome_sent",
                             "security.encrypted", "file.chunk_received", "file.end_received",
                             "file.result"} <= names)
            chunks = [e["details"]["index"] for e in activity if e["event"] == "file.chunk_received"]
            self.assertEqual(chunks, [0, 2])
            samples = [e["details"] for e in activity if e["event"] == "security.encrypted"]
            self.assertEqual(len(samples), 4)  # chat + start + first chunk + end
            self.assertTrue(all(len(d["ciphertext_hex"]) == 64 for d in samples))
            self.assertTrue(all(d["packet_example"]["payload"] == "[content redacted]" for d in samples))
            self.assertNotIn(alice.token, json.dumps(activity))
            self.assertNotIn("PRIVATE DEMO CONTENT", json.dumps(activity))
            self.assertNotIn("test password 123", json.dumps(activity))
            self.assertFalse(any(e["event"] in {"udp.sent", "udp.received"} for e in activity))

    def test_trace_reports_rejected_datagrams_without_raw_contents(self):
        from collab.server import Server

        server = Server(trace_network=True)
        address = ("127.0.0.1", 12345)
        server.handle_udp(b"x" * 1101, address)
        server.handle_udp(b"unknown session", address)
        server.handle_udp(b"\xff" * 32, address)
        events = server.events.snapshot()["events"]
        self.assertEqual([e["details"]["reason"] for e in events],
                         ["oversize", "unknown_session", "invalid_datagram"])
        self.assertTrue(all(e["details"]["source"] == "127.0.0.1:12345" for e in events))
        self.assertNotIn("unknown session", json.dumps(events))

    def test_ciphertext_preview_matches_actual_encrypted_datagram(self):
        import base64
        from cryptography.fernet import Fernet, InvalidToken
        from collab.transport.security import Channel
        from collab.transport.udp import encode_udp
        from collab.server.trace import ciphertext_metadata

        cipher = Fernet(Fernet.generate_key())
        channel = Channel(cipher, "a" * 32)
        plaintext = "TEACHER_DEMO_MESSAGE_123"
        message = {"type": "data", "payload": plaintext}
        raw = encode_udp(message, cipher, channel)
        meta = ciphertext_metadata(raw)
        decoded = base64.urlsafe_b64decode(raw[32:])
        self.assertEqual(meta["ciphertext_hex"], decoded[25:-32][:32].hex())
        self.assertEqual(meta["ciphertext_bytes"], len(decoded[25:-32]))
        self.assertEqual(meta["fernet_wire_prefix"], raw[32:96].decode())
        self.assertNotIn(plaintext.encode(), raw)
        self.assertNotIn(plaintext, json.dumps(meta))
        self.assertIn(plaintext.encode(), cipher.decrypt(raw[32:]))
        with self.assertRaises(InvalidToken):
            Fernet(Fernet.generate_key()).decrypt(raw[32:])
        damaged = bytearray(decoded)
        damaged[25] ^= 1
        with self.assertRaises(InvalidToken):
            cipher.decrypt(base64.urlsafe_b64encode(damaged))
        another = encode_udp(message, cipher, channel)
        self.assertNotEqual(meta["ciphertext_hex"], ciphertext_metadata(another)["ciphertext_hex"])
        self.assertEqual(ciphertext_metadata(b"invalid"), {})

    def test_trace_metadata_excludes_secrets_and_classifies_accurately(self):
        from collab.server.trace import packet_metadata, classify

        meta = packet_metadata({"type": "welcome", "key": "SECRET", "token": "TOKEN",
                                "password": "PASSWORD", "payload": "PRIVATE"})
        self.assertEqual(meta, {"message": "welcome"})
        self.assertEqual(classify("tcp.sent", meta), ["1", "2"])
        self.assertNotIn("2", classify("tcp.sent", {"message": "file_status"}))
        journal = EventJournal()
        journal.emit("udp.retry", protocol="UDP", message="file_chunk", attempt=2, cwnd=1)
        tags = journal.snapshot()["events"][0]["requirements"]
        self.assertTrue({"1", "6", "7", "flow"} <= set(tags))

    def test_local_console_snapshot_is_non_consuming_and_safe(self):
        journal = EventJournal()
        journal.emit("account.registered", user="alice")
        console = LogConsole(journal, 0)
        self.addCleanup(console.close)
        self.assertEqual(console.http.server_address[0], "127.0.0.1")
        for _ in range(2):
            with urlopen(console.url + "/api/events", timeout=2) as response:
                self.assertEqual(json.load(response)["events"][0]["details"]["user"], "alice")
        journal.emit("udp.received", message="heartbeat", ciphertext_hex="ABCD")
        with urlopen(console.url + "/api/activity", timeout=2) as response:
            activity = json.load(response)
            self.assertEqual(len(activity["activity"]), 1)
            self.assertNotIn("ABCD", json.dumps(activity))
            self.assertNotIn("events", activity)
        with urlopen(console.url, timeout=2) as response:
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertIn(b"Server log", response.read())
        for path in ("/logs.js", "/logs.css"):
            with urlopen(console.url + path, timeout=2) as response:
                self.assertEqual(response.status, 200)
        for request in (Request(console.url, headers={"Host": "evil.example"}),
                        Request(console.url, headers={"Origin": "http://evil.example"})):
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            urlopen(console.url + "/../accounts.sqlite3", timeout=2)
        self.assertEqual(error.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
