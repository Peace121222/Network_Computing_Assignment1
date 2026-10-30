"""Account persistence, races, throttling and verified TLS authentication."""

import concurrent.futures
import sqlite3
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from collab.accounts import Accounts, AuthLimiter
from collab.client.core import Client
from tests.auth_support import Server, ROOT, PASSWORD


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
        limiter = AuthLimiter(limit=2, window=5, capacity=3, clock=lambda: now[0])
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        now[0] = 5
        self.assertTrue(limiter.allow("a"))
        for i in range(10):
            limiter.allow(str(i))
        self.assertLessEqual(len(limiter.entries), 3)


class AuthenticationNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = Server(tcp_port=0, udp_port=0)
        self.server.start()
        self.addCleanup(self.server.close)

    def client(self, name="alice", **kwargs):
        kwargs.setdefault("cafile", str(ROOT / "ca.crt"))
        c = Client(
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

    def test_recently_used_entries_are_retained_at_capacity(self):
        limiter = AuthLimiter(limit=2, capacity=2, clock=lambda: 0)
        self.assertTrue(limiter.allow("alice"))
        self.assertTrue(limiter.allow("bob"))
        self.assertTrue(limiter.allow("alice"))
        self.assertTrue(limiter.allow("carol"))
        self.assertFalse(limiter.allow("alice"))
        self.assertTrue(limiter.allow("bob"))
