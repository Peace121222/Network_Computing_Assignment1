"""Failure isolation, worker supervision, CLI continuity and bounded cleanup."""

from concurrent.futures import ThreadPoolExecutor
import contextlib
import errno
import io
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from cryptography.fernet import Fernet

from tests.auth_support import Client, ROOT, PASSWORD
from collab.client import core as client_core
from collab.client import cli as client_cli
from tests.auth_support import Server
from collab.server import core as server_core
from collab.shared.resilience import RetryDelay, SendBackoff, retryable
from collab.shared.concurrency import BoundedExecutor
from collab.transport.tcp import TCPReader, write_tcp
from collab.web.runtime import BoundedHTTPServer
from collab.web.handlers import handler_factory
from collab.web import cli as web_cli


def wait(test, predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.005)
    test.fail("Resilience state did not converge")


class RetryTests(unittest.TestCase):
    def test_classification_is_transport_specific(self):
        for code in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK):
            self.assertTrue(retryable(OSError(code, "retry")))
        for code in (errno.ECONNRESET, errno.ECONNREFUSED, 10054, 10061):
            self.assertTrue(retryable(OSError(code, "peer"), udp=True))
            self.assertFalse(retryable(OSError(code, "peer")))
        self.assertFalse(retryable(OSError(errno.EBADF, "closed"), udp=True))

    def test_backoff_cap_reset_rate_limit_and_stop(self):
        stop, logger = Mock(), Mock()
        stop.wait.return_value = False
        delay = RetryDelay(stop, logger, "receive")
        error = OSError(errno.ECONNRESET, "peer")
        with patch(
            "collab.shared.resilience.time.monotonic",
            side_effect=[0, 0.1, 0.2, 0.3, 0.4, 0.5, 1, 1.1],
        ):
            for _ in range(7):
                delay.wait(error)
            delay.reset()
            stop.wait.return_value = True
            self.assertTrue(delay.wait(error))
        self.assertEqual(
            [c.args[0] for c in stop.wait.call_args_list],
            [0.05, 0.1, 0.2, 0.4, 0.8, 1, 1, 0.05],
        )
        self.assertEqual(logger.warning.call_count, 2)

    def test_backoff_is_interruptible(self):
        stop = threading.Event()
        delay = RetryDelay(stop, Mock(), "receive")
        delay.delay = 1
        stop.set()
        before = time.monotonic()
        self.assertTrue(delay.wait(OSError(errno.EAGAIN, "retry")))
        self.assertLess(time.monotonic() - before, 0.1)

    def test_send_backoff_throttles_without_blocking_and_resets_on_success(self):
        logger = Mock()
        retry = SendBackoff(logger)
        error = OSError(errno.ECONNREFUSED, "peer")
        with patch("collab.shared.resilience.time.monotonic", return_value=10):
            self.assertTrue(retry.ready())
            retry.failed(error)
            self.assertFalse(retry.ready())
            for _ in range(8):
                retry.failed(error)
            self.assertEqual(retry.delay, 1)
            self.assertEqual(logger.warning.call_count, 1)
            retry.reset()
            self.assertTrue(retry.ready())
            self.assertEqual(retry.delay, 0.05)


class CLITests(unittest.TestCase):
    def client(self):
        client = Mock()
        client.status = "connected"
        client.names = ["alice", "bob"]
        client.running = threading.Event()
        client.events = queue.Queue()
        return client

    def invoke(self, client, commands):
        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(client_cli, "authenticate", return_value=client),
            patch("sys.argv", ["client", "--name", "alice", "--ca", "fixture-ca"]),
            patch("builtins.input", side_effect=commands),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = client_cli.main()
        return code, out.getvalue(), err.getvalue()

    def test_invalid_commands_and_missing_file_preserve_connection(self):
        client = self.client()
        client.file.side_effect = FileNotFoundError("missing.bin")
        code, out, err = self.invoke(
            client,
            ["/msg bob", "/file bob", "/file bob missing.bin", "/users", "/quit"],
        )
        self.assertEqual(code, 0)
        self.assertIn("bob", out)
        self.assertEqual(err.count("ERROR:"), 3)
        self.assertNotIn("Traceback", err)
        client._close_before.assert_called_once()

    def test_rejection_and_timeout_continue_to_next_command(self):
        client = self.client()
        client.chat.side_effect = [
            RuntimeError("recipient_offline"),
            TimeoutError("unconfirmed"),
            None,
        ]
        code, _, err = self.invoke(
            client, ["/msg bob first", "/all second", "/all third", "/quit"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(client.chat.call_count, 3)
        self.assertIn("recipient_offline", err)
        self.assertIn("unconfirmed", err)

    def test_lost_session_exits_with_error(self):
        client = self.client()

        def lose(*args):
            client.status = "disconnected"
            raise ConnectionResetError("lost peer")

        client.chat.side_effect = lose
        code, _, err = self.invoke(client, ["/all hello"])
        self.assertEqual(code, 1)
        self.assertIn("lost peer", err)
        client._close_before.assert_called_once()

    def test_eof_and_interrupt_are_successful_exits(self):
        for error in (EOFError(), KeyboardInterrupt()):
            client = self.client()
            code, _, _ = self.invoke(client, error)
            self.assertEqual(code, 0)
            client._close_before.assert_called_once()

    def test_startup_failure_is_reported(self):
        with (
            patch.object(
                client_cli,
                "authenticate",
                side_effect=ConnectionRefusedError("connect rejected"),
            ),
            patch("sys.argv", ["client", "--ca", "fixture-ca"]),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(client_cli.main(), 1)
        self.assertIn("connect rejected", err.getvalue())

    def test_server_cli_stops_on_fatal_worker(self):
        server = Mock()
        server.last_error = {"worker": "udp_loop", "message": "fatal UDP"}
        with (
            patch.object(server_core, "Server", return_value=server),
            patch(
                "sys.argv", ["server", "--cert", "fixture-cert", "--key", "fixture-key"]
            ),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(server_core.main(), 1)
        server.stopping.wait.assert_called_once()
        server.close.assert_called_once()
        self.assertIn("fatal UDP", err.getvalue())

    def test_web_auth_failure_does_not_open_http(self):
        with (
            patch.object(
                web_cli, "authenticate", side_effect=ConnectionRefusedError("no server")
            ),
            patch.object(web_cli, "BoundedHTTPServer") as http,
            patch("sys.argv", ["web", "--ca", "fixture-ca"]),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(web_cli.main(), 1)
        http.assert_not_called()


class NetworkResilienceTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.server = Server(tcp_port=0, udp_port=0)
        self.server.start()
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.close()
        self.temp.cleanup()
        self.env.stop()

    def client(self, name):
        c = Client(
            name, port=self.server.tcp_port, download_dir=Path(self.temp.name) / name
        )
        self.clients.append(c)
        c.connect()
        return c

    def test_each_critical_worker_failure_stops_server_and_restart_is_clean(self):
        for name in (
            "accept_loop",
            "udp_loop",
            "retransmit_loop",
            "expiry_loop",
            "presence_loop",
        ):
            with self.subTest(worker=name):
                server = Server(tcp_port=0, udp_port=0)

                def fail(owner):
                    raise RuntimeError("injected " + name)

                fail.__name__ = name
                with (
                    patch.object(Server, name, fail),
                    self.assertLogs("collab.server", level="ERROR"),
                ):
                    server.start()
                    wait(
                        self,
                        lambda: server.status == "stopped"
                        and not any(t.is_alive() for t in server.threads),
                    )
                self.assertEqual(server.last_error["worker"], name)
                self.assertEqual(server.last_error["exception"], "RuntimeError")
                copy = server.last_error
                copy["message"] = "changed"
                self.assertNotEqual(copy, server.last_error)
                self.assertFalse(server.running.is_set())
                self.assertIsNone(server.tcp)
                self.assertIsNone(server.udp)
                server.start()
                self.assertIsNone(server.last_error)
                server.close()

    def test_system_exit_in_critical_worker_is_not_a_silent_exit(self):
        server = Server(tcp_port=0, udp_port=0)

        def udp_loop(owner):
            raise SystemExit("worker exit")

        with (
            patch.object(Server, "udp_loop", udp_loop),
            self.assertLogs("collab.server", level="ERROR"),
        ):
            server.start()
            wait(self, lambda: server.status == "stopped")
        self.assertEqual(server.last_error["exception"], "SystemExit")
        server.close()

    def test_unexpected_worker_return_is_a_failure(self):
        server = Server(tcp_port=0, udp_port=0)

        def udp_loop(owner):
            return

        with (
            patch.object(Server, "udp_loop", udp_loop),
            self.assertLogs("collab.server", level="ERROR"),
        ):
            server.start()
            wait(self, lambda: server.status == "stopped")
        self.assertIn("returned unexpectedly", server.last_error["message"])
        server.close()

    def test_fatal_udp_error_closes_sessions_partial_handshake_and_pending(self):
        a, b = self.client("alice"), self.client("bob")
        raw = socket.create_connection(("127.0.0.1", self.server.tcp_port), timeout=1)
        try:
            raw.sendall(b"\x00\x00")
            wait(self, lambda: len(self.server.connections) == 3)
            with (
                patch.object(
                    self.server,
                    "handle_udp",
                    side_effect=OSError(errno.EIO, "broken UDP"),
                ),
                self.assertLogs("collab.server", level="ERROR"),
            ):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as trigger:
                    trigger.sendto(b"fault", ("127.0.0.1", self.server.udp_port))
                wait(self, lambda: self.server.status == "stopped")
            wait(self, lambda: a.status == b.status == "disconnected")
            self.assertFalse(self.server.users)
            self.assertFalse(self.server.connections)
            self.assertFalse(self.server.pending)
            self.assertFalse(self.server.file_transfers.records)
            self.assertEqual(raw.recv(1), b"")
        finally:
            raw.close()

    def test_concurrent_close_with_worker_failure_does_not_deadlock(self):
        entered, release = threading.Event(), threading.Event()
        server = Server(tcp_port=0, udp_port=0)

        def udp_loop(owner):
            entered.set()
            release.wait(2)
            raise OSError(errno.EIO, "late fault")

        with patch.object(Server, "udp_loop", udp_loop):
            server.start()
            self.assertTrue(entered.wait(1))
            with ThreadPoolExecutor(3) as pool:
                futures = [pool.submit(server.close) for _ in range(3)]
                release.set()
                for future in futures:
                    future.result(4)
        self.assertEqual(server.status, "stopped")
        self.assertFalse(any(t.is_alive() for t in server.threads))

    def test_each_client_worker_exception_detaches_session(self):
        for name in ("listen", "heartbeats", "listen_tcp", "finalize_worker"):
            with self.subTest(worker=name):
                client = Client(
                    "fail_" + name,
                    port=self.server.tcp_port,
                    download_dir=self.temp.name,
                )

                def fail(*args):
                    raise RuntimeError("injected client worker")

                fail.__name__ = name
                with (
                    patch.object(client, name, fail),
                    self.assertLogs("collab.client", level="ERROR"),
                ):
                    client.connect()
                    wait(self, lambda: client.status == "disconnected")
                client.close()
                self.assertFalse(any(t.is_alive() for t in client.threads))
                self.assertTrue(
                    any(
                        e["type"] == "connection" and e["status"] == "disconnected"
                        for e in client.events.queue
                    )
                )

    def test_old_client_worker_error_cannot_disconnect_new_session(self):
        client = self.client("alice")
        current = client._session
        stale = {"stop": threading.Event(), "started": threading.Event()}
        stale["started"].set()

        def fail():
            raise RuntimeError("old worker")

        client._guard_worker(fail, stale)()
        self.assertIs(client._session, current)
        self.assertEqual(client.status, "connected")

    def test_udp_peer_errors_retry_and_success_resets_backoff(self):
        server = Server()
        server.udp = Mock()
        server.running.set()
        server.udp.recvfrom.side_effect = [
            ConnectionResetError(errno.ECONNRESET, "peer"),
            (b"ok", ("127.0.0.1", 1)),
            ConnectionRefusedError(errno.ECONNREFUSED, "peer"),
        ]
        calls = []

        def pause(error):
            calls.append(error.errno)
            if len(calls) == 2:
                server.running.clear()
            return False

        with patch("collab.server.core.RetryDelay.wait", side_effect=pause):
            server.udp_loop()
        self.assertEqual(calls, [errno.ECONNRESET, errno.ECONNREFUSED])
        self.assertIsNone(server.last_error)

    def test_tcp_reset_affects_only_one_session(self):
        a, b, c = self.client("alice"), self.client("bob"), self.client("carol")
        victim = self.server.users["alice"]
        original = self.server._write_control

        def write(sock, message, security=None):
            if sock is victim["sock"]:
                raise BrokenPipeError(errno.EPIPE, "reset peer")
            return original(sock, message, security)

        with patch.object(self.server, "_write_control", side_effect=write):
            self.server._send_control(
                victim,
                {"type": "users", "names": ["alice", "bob", "carol"], "revision": 100},
            )
            wait(self, lambda: a.status == "disconnected")
        wait(self, lambda: len(b.names) == len(c.names) == 2)
        b.chat("carol", "still healthy")
        self.assertEqual(self.server.status, "running")
        self.assertIsNone(self.server.last_error)

    def test_killed_client_process_is_cleaned_without_stopping_healthy_clients(self):
        healthy = self.client("healthy")
        script = """
import sys, threading
from collab.client import Client
c=Client('victim',port=int(sys.argv[1]),download_dir=sys.argv[2],cafile=sys.argv[3]); c.connect(sys.argv[4])
import hashlib
meta={'transfer':'d'*32,'filename':'partial.bin','size':1,'count':1,'sha256':hashlib.sha256(b'x').hexdigest()}
c.send_packets([c.packet('healthy','file_start','',meta)])
print('ready',flush=True)
threading.Event().wait()
"""
        self.server.accounts.register("victim", PASSWORD)
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(self.server.tcp_port),
                self.temp.name,
                str(ROOT / "ca.crt"),
                PASSWORD,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = process.stdout.readline().strip()
            self.assertEqual(line, "ready", process.stderr.read() if not line else "")
            wait(
                self,
                lambda: "victim" in self.server.users
                and bool(healthy.files)
                and bool(self.server.file_transfers.records),
            )
            process.kill()
            process.wait(3)
            wait(
                self,
                lambda: "victim" not in self.server.users
                and not healthy.files
                and not self.server.file_transfers.records
                and not self.server.pending,
            )
            self.assertEqual(healthy.status, "connected")
            self.assertEqual(self.server.status, "running")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)

    def test_tcp_read_reset_and_control_broken_pipe_are_transport_errors(self):
        stream = Mock()
        stream.recv.side_effect = ConnectionResetError(errno.ECONNRESET, "reset")
        with self.assertRaises(ConnectionResetError):
            TCPReader(stream).read()
        stream.send.side_effect = BrokenPipeError(errno.EPIPE, "broken pipe")
        with patch(
            "collab.transport.tcp.select.select", return_value=([], [stream], [])
        ):
            with self.assertRaises(BrokenPipeError):
                write_tcp(stream, {"type": "logout"}, time.monotonic() + 1)

    def test_client_send_peer_error_retries_without_detaching(self):
        a, b = self.client("alice"), self.client("bob")
        wait(self, lambda: len(a.names) == len(b.names) == 2)
        original = a.send_raw
        failed = threading.Event()

        def send(message):
            if message["type"] == "data" and not failed.is_set():
                failed.set()
                raise ConnectionRefusedError(errno.ECONNREFUSED, "UDP peer")
            return original(message)

        with patch.object(a, "send_raw", side_effect=send):
            a.chat("bob", "retry then success")
        self.assertTrue(failed.is_set())
        self.assertEqual(a.status, "connected")

    def test_client_fatal_send_detaches_session(self):
        a, b = self.client("alice"), self.client("bob")
        wait(self, lambda: len(a.names) == len(b.names) == 2)
        with patch.object(
            a, "send_raw", side_effect=OSError(errno.EBADF, "closed socket")
        ):
            with self.assertRaises(OSError):
                a.chat("bob", "cannot send")
        self.assertEqual(a.status, "disconnected")
        self.assertEqual(b.status, "connected")

    def test_file_control_broken_pipe_only_disconnects_its_source(self):
        a, b = self.client("alice"), self.client("bob")
        wait(self, lambda: len(a.names) == len(b.names) == 2)
        source = Path(self.temp.name) / "payload.bin"
        source.write_bytes(b"payload")
        victim = self.server.users["alice"]["sock"]
        original = self.server._write_control

        def write(sock, message, security=None):
            if sock is victim and message["type"] == "file_status":
                raise BrokenPipeError(errno.EPIPE, "file control broken")
            return original(sock, message, security)

        with patch.object(self.server, "_write_control", side_effect=write):
            with self.assertRaises((ConnectionError, RuntimeError)):
                a.file("bob", source)
            wait(self, lambda: a.status == "disconnected")
        wait(
            self,
            lambda: not b.files
            and not self.server.file_transfers.records
            and not self.server.pending,
        )
        self.assertEqual(b.status, "connected")
        self.assertIsNone(self.server.last_error)
        self.assertEqual(self.server.status, "running")

    def test_supervisor_failure_records_only_first_error(self):
        identity = self.server._run_id
        with self.server._error_lock:
            self.server._last_error = {
                "worker": "first",
                "exception": "OSError",
                "message": "first cause",
            }
        self.server._request_stop("second", RuntimeError("second cause"), identity)
        wait(self, lambda: self.server.status == "stopped")
        self.assertEqual(self.server.last_error["worker"], "first")


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def http(self):
        client = Client("alice", download_dir=self.temp.name)
        http = BoundedHTTPServer(("127.0.0.1", 0), handler_factory(client))
        self.addCleanup(http.server_close)
        return http, client

    def test_client_cleanup_failure_does_not_skip_pool_joins(self):
        http, client = self.http()
        with (
            patch.object(
                client, "_close_before", side_effect=RuntimeError("blocked client")
            ),
            patch.object(http.handlers, "close", wraps=http.handlers.close) as handlers,
            patch.object(
                http.runtime.tasks, "close", wraps=http.runtime.tasks.close
            ) as senders,
            self.assertLogs("collab.shared.resilience", level="ERROR"),
        ):
            with self.assertRaisesRegex(RuntimeError, "blocked client"):
                http.server_close()
        self.assertEqual(handlers.call_count, 1)
        self.assertEqual(senders.call_count, 1)
        self.assertEqual(handlers.call_args.args[0], senders.call_args.args[0])
        self.assertFalse(
            any(
                t.is_alive() for t in http.handlers.threads + http.runtime.tasks.threads
            )
        )

    def test_handler_pool_failure_does_not_skip_send_pool_cleanup(self):
        http, client = self.http()
        with (
            patch.object(
                http.handlers, "close", side_effect=RuntimeError("blocked handlers")
            ),
            patch.object(
                http.runtime.tasks, "close", wraps=http.runtime.tasks.close
            ) as senders,
            self.assertLogs("collab.shared.resilience", level="ERROR"),
        ):
            with self.assertRaisesRegex(RuntimeError, "blocked handlers"):
                http.server_close()
        self.assertEqual(senders.call_count, 1)
        self.assertEqual(client.status, "disconnected")

    def test_close_lock_wait_uses_remaining_deadline(self):
        client = Client("alice", download_dir=self.temp.name)
        client._lifecycle_lock.acquire()
        try:
            before = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "lifecycle lock busy"):
                client._close_before(before + 0.03)
            self.assertLess(time.monotonic() - before, 0.2)
        finally:
            client._lifecycle_lock.release()
            client.close()

    def test_server_socket_failure_still_closes_other_sockets_and_is_retryable(self):
        server = Server(tcp_port=0, udp_port=0)
        server.start()
        udp = server.udp
        original = server._close_socket

        def close(sock):
            if sock is udp:
                raise OSError(errno.EIO, "cannot close UDP")
            return original(sock)

        with (
            patch.object(server, "_close_socket", side_effect=close),
            self.assertLogs("collab.shared.resilience", level="ERROR"),
        ):
            with self.assertRaises(RuntimeError):
                server.close()
        self.assertEqual(server.status, "stopping")
        self.assertIs(server.udp, udp)
        server.close()
        self.assertEqual(server.status, "stopped")

    def test_registry_lock_wait_is_bounded_and_cleanup_can_be_retried(self):
        server = Server()
        entered, release = threading.Event(), threading.Event()

        def hold():
            with server.lock:
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            with patch("collab.server.core.SHUTDOWN_TIMEOUT", 0.03):
                before = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "registry lock busy"):
                    server.close()
                self.assertLess(time.monotonic() - before, 0.2)
                self.assertEqual(server.status, "stopping")
        finally:
            release.set()
            thread.join(1)
            server.close()

    def test_cancelled_cleanup_io_does_not_block_close_past_deadline(self):
        pool = BoundedExecutor(1, 1)
        active, release_active, cleanup_entered, release_cleanup = [
            threading.Event() for _ in range(4)
        ]

        def run():
            active.set()
            release_active.wait(2)

        def cleanup():
            cleanup_entered.set()
            release_cleanup.wait(2)

        pool.submit(pool.reserve(), run)
        self.assertTrue(active.wait(1))
        never_run = Mock()
        pool.submit(pool.reserve(), never_run, cleanup)
        pool.stop()
        release_active.set()
        self.assertTrue(cleanup_entered.wait(1))
        try:
            before = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "shutdown incomplete"):
                pool.close(before + 0.03)
            self.assertLess(time.monotonic() - before, 0.2)
            self.assertTrue(any(t.is_alive() for t in pool.threads))
            never_run.assert_not_called()
        finally:
            release_cleanup.set()
            pool.close()
        self.assertEqual(pool.admitted, 0)

    def test_failed_cancelled_cleanup_is_retained_and_retried_once(self):
        pool = BoundedExecutor(1, 1)
        entered, release, failed = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )

        def active():
            entered.set()
            release.wait(2)

        attempts = []

        def cleanup():
            attempts.append(1)
            if len(attempts) == 1:
                failed.set()
                raise OSError("disk busy")

        pool.submit(pool.reserve(), active)
        self.assertTrue(entered.wait(1))
        lease = pool.reserve()
        never_run = Mock()
        pool.submit(lease, never_run, cleanup)
        with self.assertLogs("collab.shared.concurrency", level="ERROR"):
            pool.stop()
            release.set()
            self.assertTrue(failed.wait(1))
            wait(self, lambda: bool(pool.failed_cleanup))
        pool.close()
        self.assertEqual(len(attempts), 2)
        self.assertTrue(lease.released)
        self.assertEqual(pool.admitted, 0)
        never_run.assert_not_called()
        self.assertFalse(any(t.is_alive() for t in pool.threads))

    def test_http_serving_wait_cannot_exceed_deadline(self):
        http, client = self.http()
        http._serve_done.clear()
        before = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "serving still running"):
                http._stop_serving(before + 0.03)
            self.assertLess(time.monotonic() - before, 0.2)
        finally:
            http._serve_done.set()

    def test_client_join_error_does_not_skip_other_joins_or_file_cleanup(self):
        client = Client("alice", download_dir=self.temp.name)
        first, second = Mock(), Mock()
        for thread in (first, second):
            thread.ident = 1
            thread.is_alive.return_value = False
        first.join.side_effect = RuntimeError("join failed")
        client.threads = [first, second]
        with (
            patch.object(client._file_transfers, "retry_cleanup") as files,
            self.assertLogs("collab.shared.resilience", level="ERROR"),
        ):
            with self.assertRaisesRegex(RuntimeError, "join failed"):
                client._join_workers()
        second.join.assert_called_once()
        files.assert_called_once()
        client.close()

    def test_client_failed_socket_close_is_retained_and_other_socket_is_closed(self):
        client = Client("alice", download_dir=self.temp.name)
        tcp, udp = Mock(), Mock()
        tcp.close.side_effect = OSError(errno.EIO, "close failed")
        client.tcp, client.udp = tcp, udp
        client.status = "connected"
        with self.assertLogs("collab.shared.resilience", level="ERROR"):
            with self.assertRaisesRegex(RuntimeError, "close failed"):
                client.close()
        self.assertEqual(client.status, "disconnected")
        udp.close.assert_called_once()
        self.assertIn(tcp, client._retired_sockets)
        tcp.close.side_effect = None
        client.close()
        self.assertFalse(client._retired_sockets)


if __name__ == "__main__":
    unittest.main()
