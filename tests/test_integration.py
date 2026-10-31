"""End-to-end messaging, file delivery, production-scale clients, and data-hop loss."""

from pathlib import Path
from unittest.mock import patch
import concurrent.futures
import hashlib
import os
import queue
import socket
import tempfile
import threading
import time
import unittest

from cryptography.fernet import Fernet

from collab.client import Client as ProductionClient
from collab.server import Server as ProductionServer
from collab.shared.protocol import validate_udp
from collab.transport.udp import encode_udp
from tests.auth_support import Client, PASSWORD, ROOT, Server


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


class ProductionScaleTests(unittest.TestCase):
    def test_twenty_real_clients_share_an_explicit_same_ip_auth_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = ProductionServer(
                tcp_port=0,
                udp_port=0,
                database=str(root / "accounts.db"),
                certfile=str(ROOT / "server.crt"),
                keyfile=str(ROOT / "server.key"),
                auth_limit=60,
            )
            clients = []
            server.start()
            try:
                self.assertEqual(server.auth_limiter.limit, 60)
                for i in range(20):
                    clients.append(
                        ProductionClient(
                            f"prod{i}",
                            port=server.tcp_port,
                            cafile=str(ROOT / "ca.crt"),
                            download_dir=root / f"user{i}",
                        )
                    )
                with concurrent.futures.ThreadPoolExecutor(4) as pool:
                    list(pool.map(lambda c: c.register(PASSWORD, PASSWORD), clients))
                barrier = threading.Barrier(20)

                def connect(client):
                    barrier.wait(5)
                    client.connect(PASSWORD)

                with concurrent.futures.ThreadPoolExecutor(20) as pool:
                    list(pool.map(connect, clients))
                deadline = time.monotonic() + 8
                while not all(len(c.names) == 20 for c in clients):
                    self.assertLess(time.monotonic(), deadline)
                    threading.Event().wait(0.01)
                source = root / "binary.bin"
                data = bytes(range(256)) * 24
                source.write_bytes(data)

                def send(i):
                    clients[i].chat(clients[(i + 1) % 20].name, f"private {i}")
                    clients[i].file(clients[(i + 1) % 20].name, source)

                with concurrent.futures.ThreadPoolExecutor(20) as pool:
                    list(pool.map(send, range(20)))
                for client in clients:
                    received = list(client.download_dir.iterdir())
                    self.assertEqual(len(received), 1)
                    self.assertEqual(
                        hashlib.sha256(received[0].read_bytes()).digest(),
                        hashlib.sha256(data).digest(),
                    )
                    self.assertGreater(
                        client._session["congestion"].snapshot()["acked"], 0
                    )
                    self.assertGreater(
                        server.users[client.name]["congestion"].snapshot()["acked"], 0
                    )
                self.assertEqual(len(server.users), 20)
            finally:
                for client in clients:
                    client.close()
                server.close()
            self.assertFalse(server.users)
            self.assertFalse(server.connections)

    def test_authentication_configuration_keeps_secure_defaults(self):
        server = ProductionServer()
        self.assertEqual(server.auth_limiter.limit, 10)
        self.assertEqual(server.auth_limiter.window, 60)
        for kwargs in (
            {"auth_limit": 0},
            {"auth_limit": True},
            {"auth_window": 0},
            {"auth_window": float("nan")},
        ):
            with self.assertRaises(ValueError):
                ProductionServer(**kwargs)

    def test_loss_on_each_data_hop_reduces_and_recovers_its_controller(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = ProductionServer(
                tcp_port=0,
                udp_port=0,
                database=str(root / "accounts.db"),
                certfile=str(ROOT / "server.crt"),
                keyfile=str(ROOT / "server.key"),
            )
            clients = [
                ProductionClient(
                    name, port=0, cafile=str(ROOT / "ca.crt"), download_dir=root / name
                )
                for name in ("alice", "bob")
            ]
            server.start()
            try:
                for client in clients:
                    client.port = server.tcp_port
                    client.register(PASSWORD, PASSWORD)
                    client.connect(PASSWORD)
                a, b = clients
                deadline = time.monotonic() + 5
                while b.name not in a.names:
                    self.assertLess(time.monotonic(), deadline)
                    threading.Event().wait(0.01)
                dropped = {"ingress": False, "relay": False}
                send_client = a.send_raw
                send_server = server._send_session_udp

                def client_send(message):
                    if message.get("kind") == "file_chunk" and not dropped["ingress"]:
                        dropped["ingress"] = True
                        return
                    return send_client(message)

                def relay_send(message, sessions, address=None):
                    if message.get("kind") == "file_chunk" and not dropped["relay"]:
                        dropped["relay"] = True
                        return True
                    return send_server(message, sessions, address)

                source = root / "loss.bin"
                payload = bytes(range(256)) * 48
                source.write_bytes(payload)
                with (
                    patch.object(a, "send_raw", side_effect=client_send),
                    patch.object(server, "_send_session_udp", side_effect=relay_send),
                ):
                    a.file("bob", source)
                self.assertTrue(all(dropped.values()))
                self.assertEqual(next(b.download_dir.iterdir()).read_bytes(), payload)
                for controller in (
                    a._session["congestion"],
                    server.users["bob"]["congestion"],
                ):
                    stats = controller.snapshot()
                    self.assertGreater(stats["loss_events"], 0)
                    self.assertGreater(stats["retransmissions"], 0)
                    self.assertEqual(stats["inflight"], 0)
            finally:
                for client in clients:
                    client.close()
                server.close()


if __name__ == "__main__":
    unittest.main()
