"""Bounded HTTP handlers, send jobs and coordinated backend shutdown."""

from collab.shared.limits import SHUTDOWN_TIMEOUT, HTTP_REQUEST_TIMEOUT

import threading
import select
import time
from http.server import HTTPServer
from collab.client.core import Client
from collab.shared.concurrency import BoundedExecutor
from collab.shared.resilience import Cleanup


class WebRuntime:
    """Own the bounded send-job pool and upload capacity for one HTTP backend.

    Attributes:
        client: Client core shared by HTTP handlers and queued send jobs.
        tasks: Executor started during runtime construction.
        uploads: Semaphore limiting concurrent upload processing.
    """

    def __init__(self, client):
        self.client = client
        self.tasks = BoundedExecutor(2, 4, name="collab-send")
        self.uploads = threading.BoundedSemaphore(2)

    def submit(self, lease, session, fn, args, cleanup):
        """Submit work bound to the captured client session and transfer its cleanup.

        Background failures become client error events. The task's cleanup remains owned
        by the executor after submission, including cancellation during shutdown.

        Args:
            lease: Unsubmitted reservation from this runtime's task executor.
            session: Client session captured when the HTTP request was admitted.
            fn: Client operation to invoke only while that session remains current.
            args: Positional arguments passed to fn.
            cleanup: Zero-argument cleanup callable owned by the submitted job.

        Raises:
            RuntimeError: The reservation is invalid or task admission has stopped.
        """

        def run():
            try:
                self.client._run_in_session(session, fn, *args)
            except Exception as exc:
                self.client.events.put({"type": "error", "message": str(exc)})

        self.tasks.submit(lease, run, cleanup)


class BoundedHTTPServer(HTTPServer):
    """Serve HTTP using bounded handlers and coordinated client cleanup.

    Construction binds the supplied address and starts handler workers. The Web entry
    point supplies a loopback address; this class does not enforce loopback itself.

    Attributes:
        runtime: Send runtime supplied by the handler class.
        handlers: Owned request executor, or None before successful initialization.
    """

    def __init__(self, address, handler):
        self.runtime = handler.runtime
        self.handlers = None
        self._requests_lock = threading.Lock()
        self._requests = set()
        self._close_lock = threading.Lock()
        self._serving = threading.Event()
        self._serving_thread = None
        self._serve_stop = threading.Event()
        self._serve_done = threading.Event()
        self._serve_done.set()
        self._closing = False
        try:
            super().__init__(address, handler)
            self.handlers = BoundedExecutor(8, 8, name="collab-http")
        except BaseException:
            cleanup = Cleanup()
            cleanup.attempt("HTTP startup rollback", self.server_close)
            raise

    def serve_forever(self, poll_interval=0.1):
        """Serve requests until shutdown is signalled or the backend is closing.

        Args:
            poll_interval: Requested listener readiness wait in seconds, capped at 0.1.
        """
        with self._requests_lock:
            if self._closing:
                return
            self._serving_thread = threading.current_thread()
            self._serve_done.clear()
            self._serving.set()
        try:
            while not self._serve_stop.is_set():
                try:
                    ready = select.select(
                        [self.socket], [], [], min(0.1, poll_interval)
                    )[0]
                except (OSError, ValueError):
                    if self._serve_stop.is_set():
                        break
                    raise
                if ready and not self._serve_stop.is_set():
                    self._handle_request_noblock()
        finally:
            self._serving.clear()
            self._serve_done.set()

    def _stop_serving(self, deadline):
        self._serve_stop.set()
        if threading.current_thread() is not self._serving_thread:
            if not self._serve_done.wait(max(0, deadline - time.monotonic())):
                raise RuntimeError("HTTP shutdown incomplete: serving still running")

    def shutdown(self):
        """Stop HTTP serving within the shutdown timeout without closing all resources.

        The serving thread does not wait for itself. Other callers wait for the serve loop;
        server_close() remains responsible for sockets, client state, and worker pools.

        Raises:
            RuntimeError: The serve loop does not finish before the shutdown deadline.
        """
        self._stop_serving(time.monotonic() + SHUTDOWN_TIMEOUT)

    def process_request(self, request, address):
        lease = self.handlers.reserve()
        if lease is None:
            self.shutdown_request(request)
            return
        with self._requests_lock:
            if self._closing:
                lease.release()
                self.shutdown_request(request)
                return
            self._requests.add(request)

        def cleanup():
            try:
                self.shutdown_request(request)
            finally:
                with self._requests_lock:
                    self._requests.discard(request)

        def run():
            request.settimeout(HTTP_REQUEST_TIMEOUT)
            try:
                self.finish_request(request, address)
            except (OSError, ValueError):
                pass

        try:
            self.handlers.submit(lease, run, cleanup)
        except RuntimeError:
            cleanup()
            lease.release()

    def server_close(self):
        """Close HTTP sockets, client state, and both worker pools within one deadline.

        Cleanup steps continue after individual failures, which are reported together.

        Raises:
            RuntimeError: Close ownership, serving, worker joins, or cleanup is incomplete.
        """
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT
        if not self._close_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise RuntimeError("HTTP shutdown incomplete: close lock busy")
        cleanup = Cleanup()
        try:
            self._closing = True
            cleanup.attempt("HTTP serving", self._stop_serving, deadline)
            cleanup.attempt("HTTP listener", super().server_close)
            if self._requests_lock.acquire(timeout=max(0, deadline - time.monotonic())):
                try:
                    requests = list(self._requests)
                finally:
                    self._requests_lock.release()
            else:
                requests = []
                cleanup.errors.append(("requests", RuntimeError("request lock busy")))
            for request in requests:
                cleanup.attempt("HTTP request socket", Client._close_socket, request)
            if self.handlers is not None:
                cleanup.attempt("HTTP pool stop", self.handlers.stop, deadline)
            cleanup.attempt("send pool stop", self.runtime.tasks.stop, deadline)
            cleanup.attempt("client", self.runtime.client._close_before, deadline)
            if self.handlers is not None:
                cleanup.attempt("HTTP pool join", self.handlers.close, deadline)
            cleanup.attempt("send pool join", self.runtime.tasks.close, deadline)
            cleanup.finish("HTTP shutdown incomplete")
        finally:
            self._close_lock.release()
