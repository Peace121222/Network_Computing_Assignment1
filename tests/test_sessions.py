"""Session authentication, presence convergence and session isolation."""

import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from tests.auth_support import Client
from tests.auth_support import Server
from collab.transport.udp import encode_udp
from collab.transport.tcp import send_tcp, recv_tcp
from collab.shared.protocol import validate_tcp, validate_udp
from collab.transport.security import Channel
from tests.auth_support import client_login, tls_connection


class SessionUnitTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.server = Server(session_expiry=10)
        self.server.udp = Mock()
        self.a = self.user("a" * 32, ("127.0.0.1", 1001))
        self.b = self.user("b" * 32, ("127.0.0.1", 1002))
        self.server.users = {"alice": self.a, "bob": self.b}

    def user(self, token, address):
        return dict(
            udp_security=Channel(self.server.f, token, server=True),
            test_sender=Channel(self.server.f, token),
            sock=Mock(),
            token=token,
            tcp_addr=address,
            udp_addr=address,
            last_seen=100.0,
            ready=True,
            send_lock=threading.Lock(),
        )

    def packet(self, typ="heartbeat", **fields):
        return dict({"type": typ, "from": "alice", "token": self.a["token"]}, **fields)

    def receive(self, msg, now=105, address=None):
        with patch("collab.server.core.time.monotonic", return_value=now):
            user = self.server.users.get(
                msg.get("from") if isinstance(msg.get("from"), str) else "", self.a
            )
            self.server.handle_udp(
                encode_udp(msg, self.server.f, user["test_sender"]),
                address or user["udp_addr"],
            )

    def queue_packet(self):
        msg = self.packet(
            "data",
            id="packet",
            to="bob",
            kind="file_end",
            payload="",
            meta={"transfer": "d" * 32},
        )
        self.server.pending[("bob", "packet")] = dict(
            packet={k: v for k, v in msg.items() if k != "token"},
            source_token=self.a["token"],
            destination_token=self.b["token"],
            attempts=0,
            retry_time=0,
        )
        return self.server.pending[("bob", "packet")]

    def test_invalid_session_configuration(self):
        for value in (True, 0, -1, float("inf"), float("nan"), "10"):
            for field in ("session_expiry", "session_check_interval"):
                with (
                    self.subTest(value=value, field=field),
                    self.assertRaises(ValueError),
                ):
                    Server(**{field: value})

    def test_endpoint_change_requires_a_new_login(self):
        old = self.a["udp_addr"]
        new = ("127.0.0.1", 2000)
        self.receive(self.packet(), address=new)
        self.assertEqual(self.a["udp_addr"], old)
        self.assertEqual(self.a["last_seen"], 100)
        self.assertNotIn("udp_candidate", self.a)
        self.assertEqual(self.a["udp_security"].highest, 0)
        self.server.udp.sendto.assert_not_called()
        self.receive(self.packet(), address=old)
        self.assertEqual(self.a["last_seen"], 105)

    def test_invalid_or_old_token_and_malformed_packet_change_nothing(self):
        for msg in (
            self.packet(token="c" * 32),
            self.packet(token="bad"),
            self.packet(**{"from": []}),
            self.packet("ack", id=[]),
        ):
            self.receive(msg)
        self.assertEqual(self.a["last_seen"], 100)
        self.assertEqual(self.a["udp_addr"], ("127.0.0.1", 1001))
        self.server.udp.sendto.assert_not_called()

    def test_valid_data_and_ack_refresh_activity(self):
        self.receive(
            self.packet("data", id="chat", to="bob", kind="chat", payload="hi", meta={})
        )
        self.assertEqual(self.a["last_seen"], 105)
        self.receive(self.packet("ack", id="other"), now=108)
        self.assertEqual(self.a["last_seen"], 108)

    def test_expiry_boundary_and_no_late_revival(self):
        self.server.expire_sessions(now=109.99)
        self.assertEqual(len(self.server.users), 2)
        self.receive(self.packet(), now=110)
        self.assertNotIn("alice", self.server.users)
        self.assertEqual(self.server.revision, 1)
        self.a["sock"].shutdown.assert_called_once()
        self.a["sock"].close.assert_called_once()

    def test_activity_extends_expiry_and_expiry_rechecks_latest_activity(self):
        self.receive(self.packet(), now=109)
        self.server.expire_sessions(now=115)
        self.assertIn("alice", self.server.users)
        self.assertFalse(
            self.server.remove_session("alice", self.a["token"], expired_at=115)
        )
        self.server.expire_sessions(now=119)
        self.assertNotIn("alice", self.server.users)

    def test_cleanup_old_session_cannot_remove_replacement(self):
        old_token = self.a["token"]
        replacement = self.user("c" * 32, ("127.0.0.1", 3000))
        self.server.users["alice"] = replacement
        self.assertFalse(self.server.remove_session("alice", old_token))
        self.assertIs(self.server.users["alice"], replacement)
        replacement["sock"].close.assert_not_called()

    def test_cleanup_drops_pending_in_both_directions(self):
        for name in ("alice", "bob"):
            with self.subTest(name=name):
                self.server.users = {"alice": self.a, "bob": self.b}
                self.queue_packet()
                self.assertTrue(
                    self.server.remove_session(name, self.server.users[name]["token"])
                )
                self.assertEqual(self.server.pending, {})
                self.assertFalse(self.server.remove_session(name, "expired"))

    def test_retransmit_rejects_replaced_source_or_destination(self):
        for name in ("alice", "bob"):
            with self.subTest(name=name):
                self.server.users = {"alice": self.a, "bob": self.b}
                self.queue_packet()
                self.server.users[name] = self.user("c" * 32, ("127.0.0.1", 3000))
                self.server.udp.reset_mock()
                self.server.retransmit_once(now=105)
                self.assertEqual(self.server.pending, {})
                self.server.udp.sendto.assert_not_called()

    def test_ack_requires_current_destination_session(self):
        self.queue_packet()
        ack = {"type": "ack", "from": "bob", "token": "c" * 32, "id": "packet"}
        self.receive(ack)
        self.assertIn(("bob", "packet"), self.server.pending)
        ack["token"] = self.b["token"]
        self.receive(ack)
        self.assertEqual(self.server.pending, {})

    def test_current_ack_cannot_remove_pending_for_previous_destination(self):
        item = self.queue_packet()
        item["destination_token"] = "c" * 32
        self.receive(
            {"type": "ack", "from": "bob", "token": self.b["token"], "id": "packet"}
        )
        self.assertIn(("bob", "packet"), self.server.pending)
        self.server.retransmit_once(now=105)
        self.assertEqual(self.server.pending, {})

    def test_presence_contains_only_ready_sessions_and_sorted_names(self):
        self.server.users = {
            "bob": self.b,
            "alice": self.a,
            "hidden": dict(self.a, ready=False),
        }
        self.server.revision = 8
        self.assertEqual(
            self.server._snapshot_locked(),
            {"type": "presence", "names": ["alice", "bob"], "revision": 8},
        )

    def test_revision_is_required_and_integer(self):
        for revision in (None, True, -1, "1"):
            for typ in ("presence", "users"):
                msg = {"type": typ, "names": [], "revision": revision}
                with (
                    self.subTest(typ=typ, revision=revision),
                    self.assertRaises(ValueError),
                ):
                    (validate_udp if typ == "presence" else validate_tcp)(
                        msg, from_client=False
                    )

    def test_client_ignores_old_presence_and_old_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Client("alice", download_dir=directory)
            with client._state_lock:
                client._apply_presence({"names": ["alice", "bob"], "revision": 3})
                client._apply_presence({"names": ["alice"], "revision": 2})
            self.assertEqual(client.names, ["alice", "bob"])
            current = {"stop": threading.Event()}
            client._session = current
            client.status = "connected"
            client._request_disconnect({"stop": threading.Event()}, "old callback")
            self.assertIs(client._session, current)
            self.assertEqual(client.status, "connected")
            client.close()

    def test_disconnected_client_rejects_chat_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Client("alice", download_dir=directory)
            with self.assertRaises(ConnectionError):
                client.chat("*", "hi")
            with self.assertRaises(ConnectionError):
                client.file("*", Path(directory) / "missing")
            client.close()


class SessionNetworkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.server = Server(
            "127.0.0.1", 0, 0, session_expiry=5, session_check_interval=0.03
        )
        self.server.start()
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.close()
        self.temp.cleanup()
        self.env.stop()

    def wait(self, pred, timeout=4):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return
            time.sleep(0.01)
        self.fail("Session state did not converge")

    def client(self, name, *, heartbeat=True):
        client = Client(
            name, port=self.server.tcp_port, download_dir=Path(self.temp.name) / name
        )
        if not heartbeat:
            client.heartbeats = lambda session: session["stop"].wait()
        self.clients.append(client)
        client.connect()
        return client

    def events(self, client):
        events = []
        while not client.events.empty():
            events.append(client.events.get_nowait())
        return events

    def test_endpoints_immediate_join_logout_and_no_false_error(self):
        a = self.client("alice")
        b = self.client("bob")
        self.wait(lambda: a.names == b.names == ["alice", "bob"])
        user = self.server.users["alice"]
        self.assertEqual(user["tcp_addr"], a.tcp.getsockname())
        self.assertEqual(user["udp_addr"][1], a.udp.getsockname()[1])
        self.events(b)
        b.close()
        self.wait(lambda: a.names == ["alice"])
        self.assertEqual(b.status, "disconnected")
        self.assertFalse(any(e["type"] == "error" for e in self.events(b)))

    def test_udp_expiry_disconnects_client_even_with_tcp_open(self):
        self.server.session_expiry = 0.4
        client = self.client("quiet", heartbeat=False)
        tcp = client.tcp
        self.assertGreaterEqual(tcp.fileno(), 0)
        self.wait(lambda: client.status == "disconnected")
        self.assertNotIn("quiet", self.server.users)
        self.assertIsNone(client.token)
        self.assertIsNone(client.tcp)
        self.assertEqual(client.names, [])
        self.assertTrue(any(e["type"] == "error" for e in self.events(client)))
        self.wait(lambda: all(not t.is_alive() for t in client.threads))

    def test_login_without_udp_registration_expires(self):
        self.server.session_expiry = 0.2
        with tls_connection(("127.0.0.1", self.server.tcp_port), timeout=1) as sock:
            welcome, _ = client_login(
                sock, "no_udp", self.server.f, time.monotonic() + 1
            )
            self.assertEqual(welcome["type"], "welcome")
            self.wait(lambda: "no_udp" not in self.server.users)
            self.assertEqual(sock.recv(1), b"")

    def test_shutdown_detected_and_disconnect_event_preserved(self):
        client = self.client("alice")
        self.wait(lambda: client.names == ["alice"])
        self.events(client)
        self.server.close()
        self.wait(lambda: client.status == "disconnected")
        events = self.events(client)
        self.assertTrue(
            any(
                e["type"] == "connection" and e["status"] == "disconnected"
                for e in events
            )
        )
        self.assertTrue(any(e["type"] == "presence" and not e["names"] for e in events))
        self.assertTrue(any(e["type"] == "error" for e in events))

    def test_reconnect_uses_new_token_and_old_token_cannot_move_endpoint(self):
        client = self.client("alice")
        self.wait(lambda: client.names == ["alice"])
        old_token = client.token
        old_session = client._session
        client.close()
        self.wait(lambda: "alice" not in self.server.users)
        client.connect()
        self.wait(lambda: client.names == ["alice"])
        self.assertNotEqual(client.token, old_token)
        before = self.server.users["alice"]["udp_addr"]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.sendto(
                encode_udp(
                    {"type": "heartbeat", "from": "alice", "token": old_token},
                    self.server.f,
                ),
                ("127.0.0.1", self.server.udp_port),
            )
        client._request_disconnect(old_session, "late worker")
        time.sleep(0.05)
        self.assertEqual(client.status, "connected")
        self.assertEqual(self.server.users["alice"]["udp_addr"], before)

    def test_changed_udp_endpoint_is_rejected_until_a_new_login(self):
        client = self.client("alice", heartbeat=False)
        self.wait(lambda: client.names == ["alice"])
        revision = self.server.revision
        old_endpoint = self.server.users["alice"]["udp_addr"]
        old_token = client.token
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(0.15)
            packet = {"type": "heartbeat", "from": "alice", "token": client.token}
            sock.sendto(
                encode_udp(packet, client.f, client._session["udp_security"]),
                ("127.0.0.1", self.server.udp_port),
            )
            with self.assertRaises(socket.timeout):
                sock.recvfrom(4096)
        self.assertEqual(self.server.users["alice"]["udp_addr"], old_endpoint)
        self.assertEqual(self.server.revision, revision)

        client.names = []
        client.send_raw({"type": "heartbeat"})
        self.wait(lambda: client.names == ["alice"])
        client.close()
        self.wait(lambda: "alice" not in self.server.users)
        client.connect()
        self.wait(lambda: client.names == ["alice"])
        self.assertNotEqual(client.token, old_token)
        self.assertEqual(
            self.server.users["alice"]["udp_addr"][1], client.udp.getsockname()[1]
        )

    def test_heartbeat_recovers_lost_presence_notification(self):
        client = self.client("alice", heartbeat=False)
        self.wait(lambda: client.names == ["alice"])
        client.names = []
        client.send_raw({"type": "heartbeat"})
        self.wait(lambda: client.names == ["alice"])

    def test_twenty_clients_and_oversized_snapshot_falls_back_to_tcp(self):

        names = ["界" * 21 + str(i) for i in range(20)]
        clients = [self.client(name) for name in names]
        expected = sorted(names)
        self.wait(lambda: all(c.names == expected for c in clients), timeout=8)
        self.assertEqual(len(self.server.users), 20)
        with self.assertRaises(ValueError):
            encode_udp(self.server._snapshot_locked(), self.server.f)
        self.assertTrue(all(c.status == "connected" for c in clients))
        clients[0].chat("*", "twenty-client broadcast")
        received = set()

        def broadcast_received():
            for index, client in enumerate(clients[1:], 1):
                for event in self.events(client):
                    if event.get("text") == "twenty-client broadcast":
                        received.add(index)
            return len(received) == 19

        self.wait(broadcast_received)
        clients[-1].close()
        self.wait(
            lambda: all(c.names == sorted(names[:-1]) for c in clients[:-1]), timeout=8
        )

    def test_repeated_close_reconnect_has_no_live_old_workers(self):
        client = self.client("cycle")
        for _ in range(4):
            self.wait(lambda: client.names == ["cycle"])
            workers = list(client.threads)
            client.close()
            self.assertFalse(any(t.is_alive() for t in workers))
            self.wait(lambda: "cycle" not in self.server.users)
            client.connect()
            self.assertEqual(client.status, "connected")

    def test_tcp_worker_start_failure_rolls_back(self):
        client = Client(
            "failed", port=self.server.tcp_port, download_dir=self.temp.name
        )
        self.clients.append(client)
        original = threading.Thread.start
        count = 0


        def start(thread):
            nonlocal count
            target = getattr(thread, "_target", None)
            if getattr(target, "__self__", None) is client:
                count += 1
                if count == 3:
                    raise RuntimeError("TCP worker failed")
            original(thread)

        with patch("threading.Thread.start", new=start):
            with self.assertRaisesRegex(RuntimeError, "TCP worker failed"):
                client.connect()
        self.assertEqual(client.status, "disconnected")
        self.assertIsNone(client.tcp)
        self.assertEqual(client.threads, [])
        self.wait(lambda: "failed" not in self.server.users)


if __name__ == "__main__":
    unittest.main()
