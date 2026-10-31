"""Account persistence, TLS authentication, handshake deadlines, and client setup."""

from pathlib import Path
from unittest.mock import Mock, patch
import concurrent.futures
import json
import os
import queue
import socket
import sqlite3
import ssl
import struct
import tempfile
import threading
import time
import unittest

from cryptography.fernet import Fernet

from collab.accounts import Accounts, AuthLimiter
from collab.client.core import Client as ProductionClient
from collab.transport.tcp import TCPReader, recv_tcp, send_tcp
from collab.transport.security import Channel, HEADER, VERSION, ZERO_CONTEXT
from collab.transport.tcp import frame_tcp
from tests.auth_support import (
    Client,
    PASSWORD,
    ROOT,
    Server,
    client_login,
    tls_connection,
)
from tests.stream_support import LoginStream, Stream, frame


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "accounts.db"
        self.accounts = Accounts(self.path)

    def test_registration_persistence_hash_and_credentials(self):
        self.accounts.register("Alice", PASSWORD)
        reopened = Accounts(self.path)
        self.assertTrue(reopened.verify("Alice", PASSWORD))
        self.assertFalse(reopened.verify("alice", PASSWORD))
        self.assertFalse(reopened.verify("missing", PASSWORD))
        self.assertFalse(reopened.verify("Alice", "wrong password"))
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT id, username, password_hash, created_at FROM accounts"
            ).fetchone()
        self.assertTrue(row[2].startswith("$argon2id$"))
        self.assertNotIn(PASSWORD, row[2])
        self.assertTrue(row[3])
        with self.assertRaisesRegex(ValueError, "already registered"):
            reopened.register("Alice", PASSWORD)

    def test_invalid_inputs(self):
        for username, password in [
            ("", PASSWORD),
            ("bad name", PASSWORD),
            ("a" * 100, PASSWORD),
            ("ok", ""),
            ("ok", "short"),
            ("ok", "a" * 129),
            ([], PASSWORD),
            ("ok", None),
        ]:
            with self.subTest(username=username), self.assertRaises(ValueError):
                self.accounts.register(username, password)

    def test_concurrent_registration(self):
        def register(_):
            try:
                self.accounts.register("race", PASSWORD)
                return True
            except ValueError:
                return False

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(register, range(2))), [False, True])

    def test_limiter_expiry_and_memory(self):
        now = [0]
        limiter = AuthLimiter(limit=2, window=5, clock=lambda: now[0])
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        now[0] = 5
        self.assertTrue(limiter.allow("a"))
        for i in range(10):
            limiter.allow(str(i))
        now[0] = 10
        limiter.allow("fresh")
        self.assertEqual(set(limiter.entries), {"fresh"})


class AuthenticationNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = Server(tcp_port=0, udp_port=0)
        self.server.start()
        self.addCleanup(self.server.close)

    def client(self, name="alice", **kwargs):
        kwargs.setdefault("cafile", str(ROOT / "ca.crt"))
        c = ProductionClient(
            name, port=self.server.tcp_port, download_dir=self.temp.name, **kwargs
        )
        self.addCleanup(c.close)
        return c

    def wait_removed(self):
        deadline = time.monotonic() + 2
        while self.server.users and time.monotonic() < deadline:
            self.server.presence_dirty.wait(0.01)
        self.assertFalse(self.server.users)

    def test_register_login_new_keys_and_old_packet(self):
        a = self.client()
        with self.assertRaises(ValueError):
            a.register(PASSWORD, "different")
        a.register(PASSWORD, PASSWORD)
        a.connect(PASSWORD)
        old = a._session["udp_security"].encode(
            {"type": "heartbeat", "from": "alice", "token": a.token}
        )
        old_key, old_token = a.f, a.token
        a.close()
        self.assertIsNone(a.f)
        self.wait_removed()
        a.connect(PASSWORD)
        self.assertNotEqual(a.token, old_token)
        self.assertNotEqual(a.f.encrypt(b"x"), old_key.encrypt(b"x"))
        with self.assertRaises(ValueError):
            a._session["udp_security"].decode(old)
        with self.assertRaises(Exception):
            old_key.decrypt(a.f.encrypt(b"new session"))

    def test_wrong_password_online_check_and_concurrent_login(self):
        self.server.accounts.register("alice", PASSWORD)
        bad = self.client()
        with self.assertRaisesRegex(RuntimeError, "Invalid username or password"):
            bad.connect("wrong password")
        with self.assertRaisesRegex(RuntimeError, "Invalid username or password"):
            self.client("missing").connect(PASSWORD)
        clients = [self.client(), self.client()]

        def connect(c):
            try:
                c.connect(PASSWORD)
                return True
            except RuntimeError:
                return False

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(connect, clients)), [False, True])
        with self.assertRaisesRegex(RuntimeError, "Invalid username or password"):
            bad.connect("wrong password")
        self.assertEqual(len(self.server.users), 1)

    def test_untrusted_and_hostname_mismatch_rejected(self):
        for options in ({"cafile": None}, {"server_name": "wrong.example"}):
            with (
                self.subTest(options=options),
                self.assertRaises(ssl.SSLCertVerificationError),
            ):
                self.client(**options).connect(PASSWORD)
        self.wait_removed()

    def test_restart_preserves_account(self):
        a = self.client()
        a.register(PASSWORD, PASSWORD)
        database = self.server.database
        self.server.close()
        self.server = Server(tcp_port=0, udp_port=0, database=database)
        self.server.start()
        self.addCleanup(self.server.close)
        self.client().connect(PASSWORD)

    def test_server_throttles_then_accepts_after_expiry(self):
        now = [0]
        self.server.auth_limiter = AuthLimiter(limit=2, window=5, clock=lambda: now[0])
        self.server.accounts.register("alice", PASSWORD)
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "Invalid username or password"):
                self.client().connect("wrong password")
        with self.assertRaisesRegex(RuntimeError, "Too many authentication attempts"):
            self.client().connect(PASSWORD)
        self.assertFalse(self.server.users)
        now[0] = 5
        self.client().connect(PASSWORD)

    def test_two_clients_have_independent_keys(self):
        a, b = self.client(), self.client("bob")
        for c in (a, b):
            c.register(PASSWORD, PASSWORD)
            c.connect(PASSWORD)
        from cryptography.fernet import InvalidToken

        with self.assertRaises(InvalidToken):
            a.f.decrypt(b.f.encrypt(b"different account"))

    def test_bad_authentication_frames_leave_no_session(self):
        import threading
        import struct
        from tests.auth_support import tls_connection
        from collab.transport.tcp import send_tcp, TCPReader

        for request in (
            {"type": "login", "name": "alice", "password": ""},
            {"type": "login", "name": "bad name", "password": PASSWORD},
        ):
            with tls_connection(("127.0.0.1", self.server.tcp_port)) as sock:
                send_tcp(sock, request)
                self.assertEqual(
                    TCPReader(sock).read()["message"], "Invalid username or password"
                )
        with tls_connection(("127.0.0.1", self.server.tcp_port)) as sock:
            sock.sendall(struct.pack("!I", 2049))
            self.assertEqual(sock.recv(1), b"")
        deadline = time.monotonic() + 2
        while self.server.connections and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        self.assertFalse(self.server.connections)
        self.assertFalse(self.server.users)


class TerminalAuthenticationTests(unittest.TestCase):
    def test_register_returns_to_menu_then_login_uses_same_core(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from collab.client.terminal_auth import authenticate

        opts = SimpleNamespace(
            name="alice",
            host="localhost",
            port=9000,
            downloads="downloads",
            ca="ca.crt",
            server_name=None,
        )
        registration, login = Mock(), Mock()
        registration.status = "disconnected"
        login.status = "connected"
        with (
            patch(
                "collab.client.terminal_auth.Client", side_effect=[registration, login]
            ),
            patch("builtins.input", side_effect=["2", "", "1", ""]),
            patch("collab.client.terminal_auth.getpass", side_effect=[PASSWORD] * 3),
            patch("builtins.print"),
        ):
            self.assertIs(authenticate(opts), login)
        registration.register.assert_called_once_with(PASSWORD, PASSWORD)
        registration.close.assert_called_once()
        login.connect.assert_called_once_with(PASSWORD)

    def test_failed_authentication_closes_core_before_exit(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from collab.client.terminal_auth import authenticate

        opts = SimpleNamespace(
            name="alice",
            host="localhost",
            port=9000,
            downloads="downloads",
            ca="ca.crt",
            server_name=None,
        )
        client = Mock(status="disconnected")
        client.connect.side_effect = ConnectionRefusedError("offline")
        with (
            patch("collab.client.terminal_auth.Client", return_value=client),
            patch("builtins.input", side_effect=["1", "", "3"]),
            patch("collab.client.terminal_auth.getpass", return_value=PASSWORD),
            patch("builtins.print"),
        ):
            self.assertIsNone(authenticate(opts))
        client.close.assert_called_once()

    def test_web_opens_http_only_after_terminal_authentication(self):
        from unittest.mock import Mock, patch
        from collab.web import cli

        client = Mock(name="alice")
        order = []

        def authenticate(opts):
            order.append("authenticated")
            return client

        http = Mock()

        def open_http(*args):
            order.append("http")
            return http

        with (
            patch.object(cli, "authenticate", side_effect=authenticate),
            patch.object(cli, "BoundedHTTPServer", side_effect=open_http),
            patch("sys.argv", ["web", "--ca", "ca.crt"]),
            patch("builtins.print"),
        ):
            self.assertEqual(cli.main(), 0)
        self.assertEqual(order, ["authenticated", "http"])
        http.server_close.assert_called_once()


class AuthLimiterCompatibilityTests(unittest.TestCase):
    def test_denied_attempts_do_not_extend_the_original_window(self):
        now = [0.0]
        limiter = AuthLimiter(limit=1, window=5, clock=lambda: now[0])
        self.assertTrue(limiter.allow("client"))
        now[0] = 4
        self.assertFalse(limiter.allow("client"))
        now[0] = 5
        self.assertTrue(limiter.allow("client"))

    def test_activity_on_other_ips_does_not_reset_a_limit(self):
        limiter = AuthLimiter(limit=2, clock=lambda: 0)
        self.assertTrue(limiter.allow("alice"))
        self.assertTrue(limiter.allow("alice"))
        for i in range(10):
            self.assertTrue(limiter.allow(str(i)))
        self.assertFalse(limiter.allow("alice"))


class ReaderTests(unittest.TestCase):
    def test_timeout_in_header_and_body_preserves_following_frame(self):
        first, second = frame({"type": "users"}), frame({"type": "logout"})
        stream = Stream(
            [
                first[:2],
                socket.timeout(),
                first[2:7],
                socket.timeout(),
                first[7:] + second,
            ]
        )
        reader = TCPReader(stream)
        for _ in range(2):
            with self.assertRaises(TimeoutError):
                reader.read()
        self.assertEqual(reader.read(), {"type": "users"})
        self.assertEqual(reader.read(), {"type": "logout"})

    def test_deadline_is_not_extended_by_partial_reads(self):
        stream = Stream([b"\x00", b"\x00", b"\x00", b"\x02", b"{}"])
        with patch(
            "collab.transport.tcp.time.monotonic", side_effect=[10, 10.4, 10.8, 11.2]
        ):
            with self.assertRaises(TimeoutError):
                TCPReader(stream).read(deadline=11)
        self.assertEqual(len(stream.timeouts), 3)
        self.assertAlmostEqual(stream.timeouts[-1], 0.2)

    def test_eof_and_bad_frames_make_reader_unusable(self):
        for raw in (
            b"\x00\x00",
            struct.pack("!I", 5) + b"{}",
            struct.pack("!I", 0),
            struct.pack("!I", 2_000_001),
            struct.pack("!I", 1) + b"{",
            frame([]),
            struct.pack("!I", 1) + b"\xff",
        ):
            with self.subTest(raw=raw[:12]):
                reader = TCPReader(Stream([raw]))
                with self.assertRaises((ValueError, ConnectionError)):
                    reader.read()
                with self.assertRaises(ConnectionError):
                    reader.read()

    def test_send_uses_remaining_deadline(self):
        stream = Stream([])
        with patch("collab.transport.tcp.time.monotonic", return_value=10):
            send_tcp(stream, {"type": "logout"}, deadline=10.5)
            self.assertEqual(stream.timeouts, [0.5])
            with self.assertRaises(TimeoutError):
                send_tcp(stream, {}, deadline=10)
        self.assertEqual(len(stream.sent), 1)


class ClientLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.client = Client("alice", download_dir=self.temp.name)
        self.tcp = LoginStream(
            [frame({"type": "welcome", "token": "a" * 32, "udp_port": 9001})]
        )
        self.udp = Mock()
        self.udp.recvfrom.side_effect = OSError("closed")
        self.connection = patch(
            "collab.client.core.Client._open_tls", return_value=self.tcp
        )
        self.udp_factory = patch(
            "collab.client.core.socket.socket", return_value=self.udp
        )
        self.worker_patches = [
            patch.object(
                self.client,
                method,
                side_effect=lambda session, *args: session["stop"].wait(),
            )
            for method in ("listen", "heartbeats", "listen_tcp")
        ]
        for worker_patch in self.worker_patches:
            worker_patch.start()
        self.connection.start()
        self.udp_factory.start()

    def tearDown(self):
        self.client.close()
        for worker_patch in self.worker_patches:
            worker_patch.stop()
        self.udp_factory.stop()
        self.connection.stop()
        self.temp.cleanup()
        self.env.stop()

    def assert_clean(self):
        self.assertIsNone(self.client.tcp)
        self.assertIsNone(self.client.udp)
        self.assertIsNone(self.client.token)
        self.assertIsNone(self.client.address)
        self.assertFalse(self.client.running.is_set())
        self.assertEqual(self.client.threads, [])

    def test_close_before_connect_and_repeatedly(self):
        for _ in range(3):
            self.client.close()
        self.assert_clean()

    def test_invalid_name_opens_no_socket(self):
        self.client.name = []
        with self.assertRaises(ValueError):
            self.client.connect()
        self.assertFalse(self.tcp.closed)
        self.assert_clean()

    def test_bad_welcome_eof_timeout_and_refusal_cleanup(self):
        cases = [
            ({"type": "users", "names": []}, ValueError),
            ({"type": "welcome", "token": "bad", "udp_port": 9001}, ValueError),
            ({"type": "welcome", "token": "a" * 32, "udp_port": True}, ValueError),
            ({"type": "error", "message": "User already connected"}, RuntimeError),
            ([], ValueError),
        ]
        for reply, error in cases:
            with self.subTest(reply=reply):
                self.tcp.parts = [frame(reply)]
                with self.assertRaises(error):
                    self.client.connect()
                self.assertTrue(self.tcp.closed)
                self.assert_clean()
        for parts, error in (([], ConnectionError), ([socket.timeout()], TimeoutError)):
            self.tcp.parts = parts
            with self.assertRaises(error):
                self.client.connect()
            self.assert_clean()
        self.udp.bind.assert_not_called()

    def test_udp_creation_bind_and_initial_heartbeat_failures(self):
        for target in ("create", "bind", "send"):
            with self.subTest(target=target):
                self.tcp.parts = [
                    frame({"type": "welcome", "token": "a" * 32, "udp_port": 9001})
                ]
                self.udp.reset_mock(side_effect=True)
                self.udp.recvfrom.side_effect = OSError("closed")
                if target == "create":
                    context = patch(
                        "collab.client.core.socket.socket",
                        side_effect=OSError("create"),
                    )
                else:
                    context = patch.object(
                        self.udp,
                        "bind" if target == "bind" else "sendto",
                        side_effect=OSError(target),
                    )
                with context, self.assertRaises(OSError):
                    self.client.connect()
                self.assertTrue(self.tcp.closed)
                if target != "create":
                    self.udp.close.assert_called_once()
                self.assert_clean()

    def test_worker_start_failure_stops_started_worker(self):
        original = threading.Thread.start
        workers = []

        def start(thread):
            workers.append(thread)
            if len(workers) == 2:
                raise RuntimeError("start failed")
            original(thread)

        with patch("collab.client.core.threading.Thread.start", new=start):
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                self.client.connect()
        self.assertFalse(any(t.is_alive() for t in workers))
        self.assert_clean()

    def test_connected_guard_and_reconnect_reset_old_state(self):
        self.client.connect()
        with self.assertRaises(RuntimeError):
            self.client.connect()
        self.client.close()
        self.client.names = ["old"]
        self.client.messages_seen["old"] = 100
        self.client.files["old"] = {}
        self.client.events.put({"old": True})
        self.tcp.parts = [
            frame({"type": "welcome", "token": "b" * 32, "udp_port": 9001})
        ]
        self.client.connect()
        self.assertEqual(self.client.names, [])
        self.assertEqual(self.client.messages_seen, {})
        self.assertEqual(self.client.files, {})
        events = []
        while not self.client.events.empty():
            events.append(self.client.events.get_nowait())
        self.assertTrue(events)
        self.assertTrue(all(e["type"] == "connection" for e in events))
        self.client.close()
        self.assert_clean()

    def test_connecting_guard(self):
        self.client._lifecycle_lock.acquire()
        try:
            with self.assertRaises(RuntimeError):
                self.client.connect()
        finally:
            self.client._lifecycle_lock.release()

    def test_logout_failure_does_not_prevent_cleanup(self):
        self.client.connect()
        self.tcp.sendall = Mock(side_effect=socket.timeout())
        self.client.close()
        self.assertLessEqual(self.tcp.timeouts[-1], 0.5)
        self.assertTrue(self.tcp.closed)
        self.udp.close.assert_called_once()
        self.assert_clean()

    def test_close_from_worker_does_not_join_itself_or_unstarted_thread(self):
        errors = []

        def shutdown():
            try:
                self.client.close()
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=shutdown)
        self.client.threads = [worker, threading.Thread(target=lambda: None)]
        worker.start()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.client.close()
        self.assert_clean()

    def test_connection_failure_can_be_retried(self):
        with patch(
            "collab.client.core.Client._open_tls",
            side_effect=ConnectionRefusedError(),
        ):
            with self.assertRaises(ConnectionRefusedError):
                self.client.connect()
        self.assert_clean()
        self.client.connect()
        self.assertTrue(self.client.running.is_set())


class HandshakeNetworkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.login_timeout = patch("collab.server.core.LOGIN_TIMEOUT", 0.25)
        self.session_timeout = patch("collab.server.core.SESSION_TIMEOUT", 0.05)
        self.login_timeout.start()
        self.session_timeout.start()
        self.server = Server("127.0.0.1", 0, 0)
        self.server.start()

    def tearDown(self):
        self.server.close()
        self.session_timeout.stop()
        self.login_timeout.stop()
        self.env.stop()

    def connect(self):
        return tls_connection(("127.0.0.1", self.server.tcp_port), timeout=1)

    def wait_removed(self, name):
        until = time.monotonic() + 2
        while time.monotonic() < until and name in self.server.users:
            time.sleep(0.01)
        self.assertNotIn(name, self.server.users)

    def test_session_resumes_partial_header_and_body_across_timeouts(self):
        with self.connect() as sock:
            welcome, reader = client_login(
                sock, "partial", self.server.f, time.monotonic() + 1
            )
            security = reader.security
            request = frame_tcp({"type": "users"}, security)
            sock.sendall(request[:2])
            time.sleep(0.12)
            sock.sendall(request[2:7])
            time.sleep(0.12)
            sock.sendall(request[7:] + frame_tcp({"type": "users"}, security))
            self.assertEqual(reader.read()["names"], ["partial"])
            self.assertEqual(reader.read()["names"], ["partial"])
            send_tcp(sock, {"type": "logout"}, security=security)
        self.wait_removed("partial")

    def test_silent_and_drip_login_expire(self):
        for drip in (False, True):
            with (
                self.subTest(drip=drip),
                socket.create_connection(
                    ("127.0.0.1", self.server.tcp_port), timeout=1
                ) as sock,
            ):
                start = time.monotonic()
                if drip:
                    for byte in frame({"type": "login", "name": "slow"})[:4]:
                        try:
                            sock.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(0.09)
                try:
                    result = sock.recv(1024)
                except ConnectionResetError:
                    result = b""
                self.assertEqual(result, b"")
                self.assertLess(time.monotonic() - start, 0.9)
        self.assertEqual(self.server.users, {})

    def test_invalid_login_does_not_affect_existing_session(self):
        with self.connect() as original:
            _, reader = client_login(
                original, "alice", self.server.f, time.monotonic() + 1
            )
            for name in ("bad name", "alice"):
                with self.connect() as sock:
                    with self.assertRaises((ValueError, RuntimeError)):
                        client_login(sock, name, self.server.f, time.monotonic() + 1)
                    sock.close()
            send_tcp(original, {"type": "users"}, security=reader.security)
            self.assertEqual(reader.read()["names"], ["alice"])
        self.wait_removed("alice")

    def test_eof_mid_session_removes_user(self):
        with self.connect() as sock:
            _, reader = client_login(sock, "eof", self.server.f, time.monotonic() + 1)
            sock.sendall(frame_tcp({"type": "users"}, reader.security)[:6])
        self.wait_removed("eof")

    def test_fragmented_login_and_invalid_json(self):
        class Fragmented:
            def __init__(self, sock):
                self.sock = sock

            def sendall(self, raw):
                self.sock.sendall(raw[:2])
                self.sock.sendall(raw[2:8])
                self.sock.sendall(raw[8:])

            def __getattr__(self, key):
                return getattr(self.sock, key)

        with self.connect() as sock:
            welcome, _ = client_login(
                Fragmented(sock), "fragment", self.server.f, time.monotonic() + 1
            )
            self.assertEqual(welcome["type"], "welcome")
        self.wait_removed("fragment")
        with self.connect() as sock:
            sock.sendall(struct.pack("!I", 1) + b"{")
            self.assertEqual(sock.recv(1), b"")

    def test_failed_udp_setup_removes_real_server_session_and_allows_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Client("retry", port=self.server.tcp_port, download_dir=directory)
            try:
                with patch.object(
                    client, "send_raw", side_effect=OSError("heartbeat failed")
                ):
                    with self.assertRaises(OSError):
                        client.connect()
                self.assertIsNone(client.tcp)
                self.assertIsNone(client.udp)
                self.assertEqual(client.threads, [])
                self.wait_removed("retry")
                client.connect()
                self.assertIn("retry", self.server.users)
            finally:
                client.close()
            self.wait_removed("retry")

    def test_client_login_timeout_against_silent_server(self):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as directory:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(1)
            done = threading.Event()

            def silent():
                with listener.accept()[0] as conn:
                    done.wait(1)

            thread = threading.Thread(target=silent)
            thread.start()
            client = Client(
                "alice", port=listener.getsockname()[1], download_dir=directory
            )
            try:
                with patch("collab.client.core.CLIENT_LOGIN_TIMEOUT", 0.15):
                    with self.assertRaises(TimeoutError):
                        client.connect()
                self.assertIsNone(client.tcp)
                self.assertFalse(client.running.is_set())
            finally:
                done.set()
                thread.join(1)
                client.close()


if __name__ == "__main__":
    unittest.main()
