"""Localhost integration tests using real encrypted TCP and UDP sockets."""

import hashlib
import os
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from tests.auth_support import Client
from tests.auth_support import Server
from collab.shared.protocol import validate_udp
from collab.transport.udp import encode_udp


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        environment = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        environment.start()
        cls.addClassCleanup(environment.stop)
        cls.server = Server("127.0.0.1", 0, 0)
        cls.addClassCleanup(cls.server.close)
        cls.server.start()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.a = Client("alice", port=self.server.tcp_port, download_dir=root / "alice")
        self.b = Client("bob", port=self.server.tcp_port, download_dir=root / "bob")
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.a.connect()
        self.b.connect()
        self.wait(lambda: "bob" in self.a.names and "alice" in self.b.names)

    def wait(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.04)
        self.fail("Timed out waiting for expected state")

    def get_event(self, client, event_type, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = client.events.get(timeout=0.1)
            except queue.Empty:
                continue
            if event["type"] == event_type:
                return event
        self.fail("No event " + event_type)

    def test_01_login_presence_private_and_broadcast(self):
        self.a.chat("bob", "private hello")
        self.assertEqual(self.get_event(self.b, "chat")["text"], "private hello")
        self.a.chat("*", "broadcast hello")
        self.assertEqual(self.get_event(self.b, "chat")["text"], "broadcast hello")

    def test_02_binary_file_and_sha256(self):
        original = os.urandom(125000)
        source = Path(self.temp.name) / "sample.bin"
        source.write_bytes(original)
        self.a.file("bob", source)
        event = self.get_event(self.b, "file_complete", timeout=18)
        received_digest = hashlib.sha256(Path(event["path"]).read_bytes()).digest()
        self.assertEqual(received_digest, hashlib.sha256(original).digest())

    def test_03_empty_file(self):
        source = Path(self.temp.name) / "empty.bin"
        source.write_bytes(b"")
        self.a.file("bob", source)
        event = self.get_event(self.b, "file_complete")
        self.assertEqual(Path(event["path"]).read_bytes(), b"")

    def test_04_duplicate_user_rejected(self):
        duplicate = Client(
            "alice",
            port=self.server.tcp_port,
            download_dir=Path(self.temp.name) / "duplicate",
        )
        self.addCleanup(duplicate.close)
        with self.assertRaises(RuntimeError):
            duplicate.connect()

    def test_05_disconnect_cleanup(self):
        self.b.close()
        self.wait(lambda: "bob" not in self.server.users)

    def test_06_malformed_udp_has_no_ack_and_server_keeps_working(self):
        before = self.server.users["alice"]["udp_addr"]
        invalid = [
            {"type": "heartbeat", "from": [], "token": self.a.token},
            {"type": "ack", "from": "alice", "token": self.a.token, "id": []},
            {
                "type": "data",
                "from": "alice",
                "token": self.a.token,
                "id": "bad",
                "to": {},
                "kind": "chat",
                "payload": "bad",
                "meta": {},
            },
            {
                "type": "data",
                "from": "alice",
                "token": self.a.token,
                "id": "badmeta",
                "to": "bob",
                "kind": "file_start",
                "payload": "",
                "meta": [],
            },
        ]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
            attacker.bind(("127.0.0.1", 0))
            attacker.settimeout(0.15)
            for message in invalid:
                rejected_by_schema = threading.Event()

                def observe_validation(packet, *, from_client):
                    try:
                        return validate_udp(packet, from_client=from_client)
                    except ValueError:
                        if packet == message and from_client:
                            rejected_by_schema.set()
                        raise

                # Keep the authenticated envelope valid so rejection must reach
                # schema validation, rather than merely rejecting an old format.
                raw = encode_udp(message, self.a.f, self.a._session["udp_security"])
                with (
                    self.subTest(message=message),
                    patch(
                        "collab.server.core.validate_udp",
                        side_effect=observe_validation,
                    ),
                ):
                    attacker.sendto(raw, ("127.0.0.1", self.server.udp_port))
                    self.assertTrue(
                        rejected_by_schema.wait(2),
                        "Malformed payload did not reach schema validation",
                    )
                    with self.assertRaises(socket.timeout):
                        attacker.recvfrom(4096)
        self.assertEqual(self.server.users["alice"]["udp_addr"], before)
        self.a.chat("bob", "still working after malformed packets")
        self.assertEqual(
            self.get_event(self.b, "chat")["text"],
            "still working after malformed packets",
        )

    def test_07_oversize_chat_fails_without_poisoning_sender(self):
        for text in ("a" * 1000, "界" * 500):
            with self.assertRaisesRegex(ValueError, "1100 bytes"):
                self.a.chat("bob", text)
            self.assertEqual(self.a.pending, {})
        self.a.chat("bob", "short message")
        self.assertEqual(self.get_event(self.b, "chat")["text"], "short message")


if __name__ == "__main__":
    unittest.main()
