"""HTTP admission, upload ownership and shutdown without UI changes."""

import base64
import http.client
import json
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
from collab.web.handlers import BoundedHTTPServer, handler_factory


def wait_for(test, predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    test.fail("HTTP state did not converge")


class HTTPConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.client = Client("alice", download_dir=self.temp.name)
        self.client.status = "connected"
        self.client._session = {"stop": threading.Event()}
        self.client.chat = Mock()
        self.client.file = Mock()
        self.handler = handler_factory(self.client)
        self.http = BoundedHTTPServer(("127.0.0.1", 0), self.handler)
        self.server_thread = threading.Thread(target=self.http.serve_forever)
        self.server_thread.start()
        wait_for(self, self.http._serving.is_set)
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        self.http.server_close()
        self.server_thread.join(2)
        self.temp.cleanup()
        self.env.stop()

    def request(self, path, data, *, raw=False):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.http.server_port, timeout=2
        )
        body = data if raw else json.dumps(data)
        try:
            connection.request("POST", path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def fill_active_senders(self):
        entered = threading.Barrier(3)

        def slow(*args):
            entered.wait(2)
            self.release.wait(5)

        self.client.chat.side_effect = slow
        for _ in range(2):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "blocking"})[0], 202
            )
        entered.wait(2)
        return self.client._session

    def test_send_pool_returns_503_when_full_and_releases_slots(self):
        self.fill_active_senders()
        for _ in range(4):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "queued"})[0], 202
            )
        self.assertEqual(self.request("/chat", {"to": "*", "text": "excess"})[0], 503)
        self.assertEqual(self.handler.runtime.tasks.admitted, 6)
        self.assertEqual(len(self.handler.runtime.tasks.threads), 2)
        # Avoid the barrier on later calls after releasing the initial two senders.
        self.client.chat.side_effect = None
        self.release.set()
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)

    def test_two_upload_slots_include_running_and_queued_and_cleanup(self):
        self.fill_active_senders()
        paths = []
        self.client.file.side_effect = lambda to, path: paths.append(path)
        payload = {
            "to": "*",
            "filename": "file.bin",
            "data": base64.b64encode(b"data").decode(),
        }
        created = []
        original = tempfile.mkdtemp

        def temporary(*args, **kwargs):
            path = original(*args, **kwargs)
            created.append(Path(path))
            return path

        try:
            with patch("collab.web.handlers.tempfile.mkdtemp", side_effect=temporary):
                self.assertEqual(self.request("/file", payload)[0], 202)
                self.assertEqual(self.request("/file", payload)[0], 202)
                self.assertEqual(self.request("/file", payload)[0], 503)
            self.assertEqual(len(created), 2)
            self.client.chat.side_effect = None
            self.release.set()
            wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(not directory.exists() for directory in created))
            self.assertTrue(self.handler.runtime.uploads.acquire(False))
            self.assertTrue(self.handler.runtime.uploads.acquire(False))
            self.handler.runtime.uploads.release()
            self.handler.runtime.uploads.release()
        finally:
            self.release.set()
            for directory in created:
                for path in directory.glob("*"):
                    path.unlink(missing_ok=True)
                if directory.exists():
                    directory.rmdir()

    def test_invalid_upload_and_failed_send_return_reservations_and_error(self):
        self.assertEqual(
            self.request("/file", {"to": "*", "filename": "../bad", "data": ""})[0], 400
        )
        self.assertEqual(
            self.request("/file", {"to": "*", "filename": "x", "data": "!!!!"})[0], 400
        )
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.client.chat.side_effect = ValueError("send failed")
        self.assertEqual(self.request("/chat", {"to": "*", "text": "hi"})[0], 202)
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
        self.assertTrue(
            any(
                e.get("message") == "send failed"
                for e in list(self.client.events.queue)
            )
        )

    def test_chat_body_limit_before_admission(self):
        self.assertEqual(self.request("/chat", "x" * (16 * 1024 + 1), raw=True)[0], 400)
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.client.chat.assert_not_called()

    def test_queued_job_cannot_run_in_replacement_session(self):
        self.fill_active_senders()
        self.assertEqual(
            self.request("/chat", {"to": "*", "text": "old session"})[0], 202
        )
        with self.client._state_lock:
            self.client._session = {"stop": threading.Event()}
        self.client.chat.side_effect = None
        self.release.set()
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
        texts = [call.args[1] for call in self.client.chat.call_args_list]
        self.assertNotIn("old session", texts)
        self.assertTrue(
            any(
                "session" in e.get("message", "")
                for e in list(self.client.events.queue)
            )
        )

    def test_http_handler_limit_has_eight_workers_and_sixteen_connections(self):
        sockets = []
        try:
            # Incomplete headers occupy handlers and the bounded waiting slots.
            for _ in range(16):
                sock = socket.create_connection(
                    ("127.0.0.1", self.http.server_port), timeout=1
                )
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
                sockets.append(sock)
            wait_for(self, lambda: self.http.handlers.admitted == 16)
            self.assertEqual(len(self.http.handlers.threads), 8)
            with socket.create_connection(
                ("127.0.0.1", self.http.server_port), timeout=1
            ) as excess:
                self.assertEqual(excess.recv(1), b"")
        finally:
            for sock in sockets:
                sock.close()
        wait_for(self, lambda: self.http.handlers.admitted == 0)

    def test_shutdown_cancels_queued_upload_and_closes_all_owned_workers(self):
        entered = threading.Barrier(3)

        def until_closed(*args):
            entered.wait(2)
            self.client._session["stop"].wait(3)

        self.client.chat.side_effect = until_closed
        for _ in range(2):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "active"})[0], 202
            )
        entered.wait(2)
        directories = []
        original = tempfile.mkdtemp

        def temporary(*args, **kwargs):
            directory = original(*args, **kwargs)
            directories.append(Path(directory))
            return directory

        with patch("collab.web.handlers.tempfile.mkdtemp", side_effect=temporary):
            self.assertEqual(
                self.request(
                    "/file",
                    {
                        "to": "*",
                        "filename": "pending.bin",
                        "data": base64.b64encode(b"data").decode(),
                    },
                )[0],
                202,
            )
        workers = list(self.http.handlers.threads) + list(
            self.handler.runtime.tasks.threads
        )
        self.http.server_close()
        self.server_thread.join(1)
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.assertFalse(any(t.is_alive() for t in workers))
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(self.client.status, "disconnected")


if __name__ == "__main__":
    unittest.main()
