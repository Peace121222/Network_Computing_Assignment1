"""Deterministic concurrency, bounded admission and shutdown checks."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import hashlib
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
from collab.client import Client, TransferCapacityError
from collab.common import b64, encode_udp, recv_tcp, send_tcp
from collab.shared.concurrency import BoundedExecutor
from collab.server import Server
from collab.transport.security import Channel
from collab.transport.handshake import client_login


def wait_for(test, predicate, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    test.fail("Concurrent state did not converge")


class PoolTests(unittest.TestCase):
    def test_capacity_reservations_cancellation_and_cleanup(self):
        pool = BoundedExecutor(2, 4)
        entered = threading.Barrier(3)
        release = threading.Event()
        cleaned = []

        def blocked():
            entered.wait(2)
            release.wait(3)

        try:
            for i in range(2):
                lease = pool.reserve()
                pool.submit(lease, blocked, lambda i=i: cleaned.append(i))
            entered.wait(2)
            for i in range(2, 6):
                lease = pool.reserve()
                pool.submit(lease, lambda: None, lambda i=i: cleaned.append(i))
            self.assertIsNone(pool.reserve())
            self.assertEqual(len(pool.waiting), 4)
            pool.stop()
            self.assertFalse(pool.waiting)
            self.assertEqual(set(cleaned), set())
            release.set()
            pool.close()
            self.assertEqual(set(cleaned), set(range(6)))
            self.assertEqual(pool.admitted, 0)
            self.assertFalse(any(t.is_alive() for t in pool.threads))
        finally:
            release.set()
            pool.close()

    def test_pool_start_failure_rolls_back(self):
        original = threading.Thread.start
        threads = []

        def start(thread):
            threads.append(thread)
            if len(threads) == 2:
                raise RuntimeError("pool start failed")
            original(thread)

        with patch("threading.Thread.start", new=start):
            with self.assertRaises(RuntimeError):
                BoundedExecutor(2, 4)
        self.assertFalse(any(t.is_alive() for t in threads))


class ConcurrencyNetworkTests(unittest.TestCase):
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

    def test_twenty_simultaneous_logins_unicast_broadcast_and_close(self):
        clients = [
            Client(
                "u" + str(i),
                port=self.server.tcp_port,
                download_dir=Path(self.temp.name) / str(i),
            )
            for i in range(20)
        ]
        self.clients.extend(clients)
        barrier = threading.Barrier(20)

        def connect(client):
            barrier.wait(5)
            client.connect()

        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(connect, clients))
        wait_for(self, lambda: all(len(c.names) == 20 for c in clients))
        barrier = threading.Barrier(20)

        def send(index):
            barrier.wait(5)
            clients[index].chat("*", "broadcast-" + str(index))
            clients[index].chat(clients[(index + 1) % 20].name, "private-" + str(index))

        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(send, range(20)))
        received = [[] for _ in clients]

        def complete():
            for index, client in enumerate(clients):
                while not client.events.empty():
                    event = client.events.get_nowait()
                    if event["type"] == "chat":
                        received[index].append(event["text"])
            return all(len(messages) == 20 for messages in received)

        wait_for(self, complete, 8)
        for index, messages in enumerate(received):
            expected = {"broadcast-" + str(i) for i in range(20) if i != index}
            expected.add("private-" + str((index - 1) % 20))
            self.assertEqual(set(messages), expected)
            self.assertEqual(len(messages), len(expected))
        workers = [t for client in clients for t in client.threads]
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda c: c.close(), clients))
        wait_for(
            self,
            lambda: not self.server.connections
            and not self.server.users
            and not self.server.pending,
        )
        self.assertFalse(any(t.is_alive() for t in workers))

    def test_simultaneous_duplicate_name_has_one_winner(self):
        clients = [
            Client("same", port=self.server.tcp_port, download_dir=self.temp.name)
            for _ in range(10)
        ]
        self.clients.extend(clients)
        barrier = threading.Barrier(10)

        def attempt(client):
            barrier.wait(3)
            try:
                client.connect()
                return True
            except RuntimeError:
                return False

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(attempt, clients))
        self.assertEqual(sum(results), 1)
        self.assertEqual(list(self.server.users), ["same"])

    def test_shutdown_closes_prelogin_and_partial_frame_and_restarts(self):
        sockets = [
            socket.create_connection(("127.0.0.1", self.server.tcp_port), timeout=1)
            for _ in range(3)
        ]
        try:
            sockets[1].sendall(b"\x00\x00")
            sockets[2].sendall(b"\x00\x00\x00\x20{")
            wait_for(self, lambda: len(self.server.connections) == 3)
            workers = list(self.server.threads)
            with ThreadPoolExecutor(2) as pool:
                list(pool.map(lambda _: self.server.close(), range(2)))
            self.assertEqual(self.server.status, "stopped")
            self.assertEqual(self.server.connections, set())
            self.assertFalse(any(t.is_alive() for t in workers))
            for sock in sockets:
                try:
                    self.assertEqual(sock.recv(1), b"")
                except ConnectionResetError:
                    pass
            for _ in range(2):
                self.server.start()
                with self.assertRaises(RuntimeError):
                    self.server.start()
                self.server.close()
            self.server.start()
        finally:
            for sock in sockets:
                sock.close()

    def test_connection_limit_includes_prelogin(self):
        self.server.max_connections = 2
        sockets = [
            socket.create_connection(("127.0.0.1", self.server.tcp_port), timeout=1)
            for _ in range(2)
        ]
        try:
            wait_for(self, lambda: len(self.server.connections) == 2)
            with socket.create_connection(
                ("127.0.0.1", self.server.tcp_port), timeout=1
            ) as excess:
                self.assertEqual(excess.recv(1), b"")
            sockets[0].close()
            wait_for(self, lambda: len(self.server.connections) == 1)
            client = self.client("accepted")
            self.assertEqual(client.status, "connected")
        finally:
            for sock in sockets:
                sock.close()

    def test_bind_and_background_start_failure_roll_back(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            server = Server("127.0.0.1", 0, occupied.getsockname()[1])
            with self.assertRaises(OSError):
                server.start()
            self.assertEqual(server.status, "stopped")
            self.assertIsNone(server.tcp)
        server = Server("127.0.0.1", 0, 0)
        original = threading.Thread.start
        seen = []

        def start(thread):
            seen.append(thread)
            if len(seen) == 2:
                raise RuntimeError("worker failed")
            original(thread)

        with patch("threading.Thread.start", new=start):
            with self.assertRaises(RuntimeError):
                server.start()
        self.assertEqual(server.status, "stopped")
        self.assertFalse(any(t.is_alive() for t in seen))
        server.start()
        server.close()

    def test_handler_and_writer_start_failures_leave_accept_loop_alive(self):
        original = threading.Thread.start
        for target_name in ("handle_client", "control_writer"):
            failed = threading.Event()

            def start(thread):
                if (
                    getattr(getattr(thread, "_target", None), "__name__", "")
                    == target_name
                    and not failed.is_set()
                ):
                    failed.set()
                    raise RuntimeError("injected thread failure")
                original(thread)

            with (
                patch("threading.Thread.start", new=start),
                self.assertLogs("collab.server", level="DEBUG"),
            ):
                with socket.create_connection(
                    ("127.0.0.1", self.server.tcp_port), timeout=1
                ) as sock:
                    if target_name == "control_writer":
                        client_login(
                            sock, "writer_fail", self.server.f, time.monotonic() + 1
                        )
                    self.assertEqual(sock.recv(1), b"")
            wait_for(
                self, lambda: not self.server.connections and not self.server.users
            )
            client = self.client("ok_" + target_name)
            self.assertEqual(client.status, "connected")
            client.close()
            wait_for(self, lambda: not self.server.users)

    def test_slow_control_writer_does_not_block_other_clients(self):
        a = self.client("alice")
        b = self.client("bob")
        wait_for(self, lambda: len(a.names) == len(b.names) == 2)
        entered, release = threading.Event(), threading.Event()
        original = self.server._write_control
        slow_socket = self.server.users["alice"]["sock"]

        def slow(sock, msg, security=None):
            if sock is slow_socket:
                entered.set()
                release.wait(3)
                raise TimeoutError("slow control peer")
            original(sock, msg, security)

        try:
            with patch.object(self.server, "_write_control", side_effect=slow):
                user = self.server.users["alice"]
                self.server._send_control(
                    user,
                    {
                        "type": "users",
                        "names": a.names,
                        "revision": self.server.revision,
                    },
                )
                self.assertTrue(entered.wait(1))
                c = self.client("carol")
                wait_for(self, lambda: "carol" in b.names)
                b.chat("carol", "while alice is slow")
                wait_for(
                    self,
                    lambda: any(
                        e.get("text") == "while alice is slow"
                        for e in list(c.events.queue)
                    ),
                )
                self.assertEqual(b.status, "connected")
                release.set()
                wait_for(self, lambda: "alice" not in self.server.users)
        finally:
            release.set()

    def test_slow_finalize_does_not_block_udp_or_publish_after_disconnect(self):
        a = self.client("alice")
        b = self.client("bob")
        wait_for(self, lambda: len(a.names) == len(b.names) == 2)
        entered, release = threading.Event(), threading.Event()
        original = b._finalize_file

        def slow(session, key, f):
            entered.set()
            release.wait(5)
            original(session, key, f)

        source = Path(self.temp.name) / "sample.bin"
        source.write_bytes(b"content")
        try:
            with (
                patch.object(b, "_finalize_file", side_effect=slow),
                ThreadPoolExecutor(1) as pool,
            ):
                sending = pool.submit(a.file, "bob", source)
                self.assertTrue(entered.wait(2))
                a.chat("bob", "during disk work")
                wait_for(
                    self,
                    lambda: any(
                        e.get("text") == "during disk work"
                        for e in list(b.events.queue)
                    ),
                )
                # Server-side removal stops the session without waiting for disk work.
                self.server.remove_session("bob", b.token)
                wait_for(self, lambda: b.status == "disconnected")
                with patch("collab.client.core.SHUTDOWN_TIMEOUT", 0.05):
                    with self.assertRaisesRegex(RuntimeError, "shutdown incomplete"):
                        b.close()
                    with self.assertRaises(RuntimeError):
                        b.connect()
                release.set()
                wait_for(self, lambda: all(not t.is_alive() for t in b.threads))
                b.close()
                self.assertEqual(list(b.download_dir.iterdir()), [])
                self.assertFalse(
                    any(e.get("type") == "file_complete" for e in list(b.events.queue))
                )
                with self.assertRaises((RuntimeError, ConnectionError)):
                    sending.result(3)
        finally:
            release.set()

    def test_shutdown_timeout_reports_worker_and_blocks_restart(self):
        release = threading.Event()
        worker = self.server._start_thread(lambda: release.wait(5))
        try:
            with patch("collab.server.core.SHUTDOWN_TIMEOUT", 0.05):
                with self.assertRaisesRegex(RuntimeError, "shutdown incomplete"):
                    self.server.close()
            self.assertEqual(self.server.status, "stopping")
            self.assertIn(worker, self.server.threads)
            with self.assertRaises(RuntimeError):
                self.server.start()
        finally:
            release.set()
            self.server.close()
        self.assertEqual(self.server.status, "stopped")

    def test_finalization_write_error_cleans_transfer_without_blocking_chat(self):
        a = self.client("alice")
        b = self.client("bob")
        wait_for(self, lambda: len(a.names) == len(b.names) == 2)
        source = Path(self.temp.name) / "sample.bin"
        source.write_bytes(b"content")
        with patch(
            "collab.client.file_transfer.tempfile.NamedTemporaryFile",
            side_effect=OSError("disk unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "disk_error"):
                a.file("bob", source)
            wait_for(
                self,
                lambda: any(
                    "disk_error" in e.get("message", "") for e in list(b.events.queue)
                ),
            )
        self.assertEqual(b.files, {})
        self.assertEqual(list(b.download_dir.iterdir()), [])
        a.chat("bob", "after disk failure")
        wait_for(
            self,
            lambda: any(
                e.get("text") == "after disk failure" for e in list(b.events.queue)
            ),
        )

    def test_incoming_transfer_limit_rejects_before_ack(self):
        a = self.client("alice")
        b = self.client("bob")
        wait_for(self, lambda: len(a.names) == len(b.names) == 2)
        c = self.client("carol")
        for index in range(3):
            sender = c if index == 2 else a
            packet = sender.packet(
                "bob",
                "file_start",
                meta={
                    "transfer": f"{index:032x}",
                    "filename": "x.bin",
                    "count": 1,
                    "size": 1,
                    "sha256": hashlib.sha256(b"x").hexdigest(),
                },
            )
            sender.send_packets([packet])
            if index < 2:
                wait_for(self, lambda: len(b.files) == index + 1)
        wait_for(
            self,
            lambda: any(
                "capacity" in e.get("message", "") for e in list(b.events.queue)
            ),
        )
        self.assertEqual(len(b.files), 2)
        wait_for(
            self,
            lambda: any(
                r["states"].get("bob") == "capacity_exceeded"
                for r in self.server.file_transfers.records.values()
            ),
        )


class AdmissionUnitTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.server = Server(max_pending_packets=2, max_pending_per_recipient=1)
        self.server.udp = Mock()
        self.server.users = {
            name: dict(
                udp_security=Channel(self.server.f, str(i) * 32, server=True),
                token=str(i) * 32,
                ready=True,
                udp_addr=("127.0.0.1", i + 1000),
                sock=Mock(),
                udp_lock=threading.RLock(),
            )
            for i, name in enumerate(("alice", "bob", "carol"), 1)
        }

    def msg(self, mid, recipient="*"):
        return {
            "type": "data",
            "id": mid,
            "from": "alice",
            "token": "1" * 32,
            "to": recipient,
            "kind": "chat",
            "payload": "hello",
            "meta": {},
        }

    def test_atomic_broadcast_admission_and_no_ack_when_full(self):
        self.assertTrue(
            self.server.route(self.msg("first", "bob"), ("127.0.0.1", 1001))
        )
        self.server.udp.reset_mock()
        self.assertFalse(self.server.route(self.msg("second"), ("127.0.0.1", 1001)))
        self.assertEqual(len(self.server.pending), 1)
        self.assertEqual(next(iter(self.server.pending))[0], "bob")
        self.server.udp.sendto.assert_not_called()
        self.server.pending.clear()
        self.assertTrue(self.server.route(self.msg("second"), ("127.0.0.1", 1001)))
        self.assertEqual(len(self.server.pending), 2)

    def test_retransmission_batch_is_fair_and_send_does_not_hold_registry(self):
        self.server.max_pending_packets = self.server.max_pending_per_recipient = 300
        for index in range(260):
            msg = dict(
                self.msg(str(index), "bob"),
                kind="file_end",
                payload="",
                meta={"transfer": "a" * 32},
            )
            self.server.pending[("bob", msg["id"])] = dict(
                packet={k: v for k, v in msg.items() if k != "token"},
                source_token=self.server.users["alice"]["token"],
                destination_token=self.server.users["bob"]["token"],
                attempts=0,
                retry_time=0,
            )
        before = len(self.server.pending)
        lock_available = []

        def send(raw, address):
            acquired = threading.Event()

            def probe():
                with self.server.lock:
                    acquired.set()

            thread = threading.Thread(target=probe)
            thread.start()
            lock_available.append(acquired.wait(1))
            thread.join(1)

        self.server.udp.sendto.side_effect = send
        self.server.retransmit_once(now=1)
        self.assertEqual(
            sum(item["attempts"] for item in self.server.pending.values()), 128
        )
        self.server.retransmit_once(now=1)
        self.server.retransmit_once(now=1)
        self.assertEqual(
            sum(item["attempts"] for item in self.server.pending.values()), before
        )
        self.assertTrue(all(lock_available))

    def test_control_queue_and_presence_coalescing(self):
        user = dict(
            control_condition=threading.Condition(),
            control=deque(),
            presence=None,
            writer_stop=threading.Event(),
        )
        for revision in range(20):
            self.assertTrue(
                self.server._send_control(
                    user,
                    {"type": "users", "names": [], "revision": revision},
                    presence=True,
                )
            )
        self.assertEqual(user["presence"]["revision"], 19)
        for _ in range(7):
            self.assertTrue(
                self.server._send_control(
                    user, {"type": "users", "names": [], "revision": 20}
                )
            )
        self.assertFalse(
            self.server._send_control(
                user, {"type": "users", "names": [], "revision": 20}
            )
        )

    def test_nonblocking_control_write_enforces_deadline_without_changing_reader_timeout(
        self,
    ):
        writer, reader = socket.socketpair()
        with writer, reader:
            writer.setblocking(False)
            writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
            start = time.monotonic()
            with patch("collab.server.core.CONTROL_TIMEOUT", 0.05):
                with self.assertRaises(TimeoutError):
                    self.server._write_control(writer, {"payload": "x" * 200_000})
            self.assertLess(time.monotonic() - start, 0.5)
            self.assertEqual(writer.gettimeout(), 0)

    def test_resource_limits_reject_boolean_zero_and_noninteger(self):
        for key in (
            "max_connections",
            "max_pending_packets",
            "max_pending_per_recipient",
        ):
            for value in (True, 0, -1, 1.5):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    Server(**{key: value})


if __name__ == "__main__":
    unittest.main()
