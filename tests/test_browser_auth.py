"""Real TLS accounts through the loopback browser login/signup interface."""

from http.client import HTTPConnection
from pathlib import Path
import json
import tempfile
import threading
import unittest

from collab.client import Client
from collab.web.auth import BrowserAuth
from collab.web.handlers import handler_factory
from collab.web.runtime import BoundedHTTPServer
from tests.auth_support import ROOT, Server, PASSWORD


class BrowserAccountTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.server = Server(tcp_port=0, udp_port=0)
        self.server.start()
        self.addCleanup(self.server.close)
        self.client = Client("", port=self.server.tcp_port, cafile=str(ROOT / "ca.crt"),
                             download_dir=Path(root.name) / "received")
        self.auth = BrowserAuth(self.client, "alice")
        self.http = BoundedHTTPServer(("127.0.0.1", 0), handler_factory(self.client, auth=self.auth))
        self.thread = threading.Thread(target=self.http.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)
        self.cookie = ""

    def stop(self):
        self.http.server_close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def request(self, path, data=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.http.server_port, timeout=8)
        supplied = {"Cookie": self.cookie}
        if headers:
            supplied.update(headers)
        body = None
        if data is not None:
            body = json.dumps(data)
            supplied["Content-Type"] = "application/json"
        try:
            connection.request("POST" if data is not None else "GET", path, body, supplied)
            response = connection.getresponse()
            status, response_headers, raw = response.status, dict(response.getheaders()), response.read()
            if "Set-Cookie" in response_headers:
                self.cookie = response_headers["Set-Cookie"].split(";")[0]
            return status, response_headers, raw
        finally:
            connection.close()

    def signup(self, name="alice"):
        return self.request("/auth/signup", {"username": name, "password": PASSWORD,
                                             "confirmation": PASSWORD})

    def login(self, name="alice", password=PASSWORD):
        return self.request("/auth/login", {"username": name, "password": password})

    def test_separate_pages_and_private_api_requires_cookie(self):
        status, headers, _ = self.request("/")
        self.assertEqual((status, headers["Location"]), (303, "/login"))
        for path in ("/login", "/signup"):
            status, _, raw = self.request(path)
            self.assertEqual(status, 200)
            self.assertIn(b'id="password"', raw)
            self.assertNotIn(b"<header", raw)
        self.assertEqual(self.request("/events")[0], 401)
        self.assertEqual(self.request("/chat", {"to": "*", "text": "no"})[0], 401)
        self.assertEqual(self.request("/session", headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.request("/session", headers={"Host": "evil.example"})[0], 403)

    def test_signup_login_logout_and_cookie_isolation(self):
        self.assertEqual(self.signup()[0], 201)
        self.assertNotIn("alice", self.server.users)
        self.assertEqual(self.signup()[0], 409)
        self.assertEqual(self.login(password="incorrect password")[0], 401)
        self.assertFalse(self.auth.authorized(self.cookie, self.http.server_port))
        status, headers, _ = self.login()
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertFalse(self.auth.authorized(self.cookie, self.http.server_port + 1))
        self.assertEqual(self.request("/")[0], 200)
        self.assertEqual(json.loads(self.request("/events")[2])["self"], "alice")
        old_cookie = self.cookie
        self.assertEqual(self.request("/auth/logout", {})[0], 200)
        self.assertEqual(self.request("/events", headers={"Cookie": old_cookie})[0], 401)
        self.assertEqual(self.client.status, "disconnected")
        self.client.events.put({"type": "chat", "text": "OLD ACCOUNT CONTENT"})
        self.assertEqual(self.signup("bob")[0], 201)
        self.assertEqual(self.login("bob")[0], 200)
        self.assertNotIn(b"OLD ACCOUNT CONTENT", self.request("/events")[2])
        self.assertEqual(self.request("/events", headers={"Cookie": old_cookie})[0], 401)

    def test_bad_signup_does_not_create_account_and_server_failure_keeps_login_page(self):
        status, _, _ = self.request("/auth/signup", {"username": "alice", "password": PASSWORD,
                                                     "confirmation": "mismatch"})
        self.assertEqual(status, 400)
        self.assertFalse(self.server.accounts.verify("alice", PASSWORD))
        self.server.close()
        self.assertEqual(self.login()[0], 503)
        self.assertEqual(self.request("/login")[0], 200)

    def test_shutdown_rejects_new_login_and_registration(self):
        self.auth.closing.set()
        self.assertEqual(self.login()[0], 409)
        self.assertEqual(self.signup()[0], 409)
        self.assertEqual(self.client.status, "disconnected")
        self.assertIsNone(self.auth.token)

    def test_another_tab_without_cookie_cannot_replace_active_account(self):
        self.assertEqual(self.signup()[0], 201)
        self.assertEqual(self.login()[0], 200)
        self.cookie = ""
        self.assertEqual(self.login()[0], 409)
        self.assertEqual(self.client.name, "alice")
        self.assertEqual(self.client.status, "connected")
