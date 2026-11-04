"""Bounded operational events and a read-only loopback HTTP console.

Only explicitly selected metadata is recorded. Network workers never write log files.
"""

from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlsplit
import json
import logging
import os
import tempfile
import queue
import threading
from collab.server.trace import classify, REQUIREMENTS, is_activity_event


class EventJournal:
    """Keep the latest events; optionally persist JSON lines via a bounded queue."""

    FIELDS = {
        "user", "peer", "recipient", "id", "transfer", "state", "bytes", "reason",
        "protocol", "direction", "source", "destination", "message", "sequence",
        "stream_sequence", "index", "count", "file_bytes", "mode", "encrypted",
        "tls_version", "cipher", "app_frame_bytes", "attempt", "cwnd", "inflight",
        "rto", "rtt", "loss_events", "online", "users", "verified", "window",
        "sha256", "verification", "encryption", "ciphertext_bytes",
        "ciphertext_hex", "fernet_wire_prefix", "packet_example",
    }

    def __init__(self, capacity=1000):
        self._events = deque(maxlen=capacity)
        self._activity = deque(maxlen=capacity)
        self._activity_total = 0
        self._lock = threading.Lock()
        self._sequence = 0
        self._evidence_counts = {}
        self._queue = queue.Queue(maxsize=2048)
        self._stop = threading.Event()
        self._thread = None
        self._handler = None
        self.dropped = 0
        self.write_errors = 0

    def start_file(self, path):
        """Create a unique UTC-stamped log per run, with three rotating backups.

        The supplied path is a filename template, not a file to append to. Exclusive
        creation keeps simultaneous starts separate even when their timestamps match.
        Returns the actual path for the startup message.
        """
        if self._handler is not None:
            raise RuntimeError("Log writer has already been started")
        template = Path(path)
        template.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        fd, filename = tempfile.mkstemp(
            prefix=f"{template.stem}-{stamp}-",
            suffix=template.suffix or ".jsonl",
            dir=template.parent,
        )
        os.close(fd)
        actual = Path(filename).resolve()
        self._handler = RotatingFileHandler(
            actual, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        self._thread = threading.Thread(target=self._write, name="collab-log", daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._handler.close()
            raise
        return actual

    def emit(self, event, level="INFO", **fields):
        with self._lock:
            self._sequence += 1
            entry = dict(
                id=self._sequence,
                time=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                level=level,
                event=event,
                details={k: v for k, v in fields.items() if k in self.FIELDS},
            )
            entry["requirements"] = classify(event, entry["details"])
            for tag in entry["requirements"]:
                self._evidence_counts[tag] = self._evidence_counts.get(tag, 0) + 1
            self._events.append(entry)
            if is_activity_event(event):
                self._activity.append(entry)
                self._activity_total += 1
            if self._handler is not None:
                try:
                    self._queue.put_nowait(entry)
                except queue.Full:
                    self.dropped += 1
        return entry

    def snapshot(self):
        with self._lock:
            return dict(events=list(self._events), latest=self._sequence,
                        activity=list(self._activity),
                        activity_evicted=max(0, self._activity_total - self._activity.maxlen),
                        dropped=self.dropped, write_errors=self.write_errors,
                        evicted=max(0, self._sequence - self._events.maxlen),
                        requirements=REQUIREMENTS, evidence_counts=dict(self._evidence_counts))

    def _write(self):
        while not self._stop.is_set() or not self._queue.empty():
            try:
                entry = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                # Call file operations directly so write failures are observable.
                record = logging.LogRecord("collab.events", logging.INFO, "", 0,
                                           json.dumps(entry, ensure_ascii=True), (), None)
                if self._handler.shouldRollover(record):
                    self._handler.doRollover()
                self._handler.stream.write(self._handler.format(record) + "\n")
                self._handler.flush()
            except (OSError, ValueError):
                with self._lock:
                    self.write_errors += 1
            finally:
                self._queue.task_done()

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(3)
            if self._thread.is_alive():
                raise TimeoutError("Log writer did not stop within 3 seconds")
        if self._handler is not None:
            self._handler.close()


class LogConsole:
    """Read-only local console; no account, payload or key inspection endpoints."""

    def __init__(self, journal, port, users_snapshot=None):
        static = Path(__file__).with_name("static")

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(0.5)
                super().setup()

            def log_message(self, *args):
                pass

            def do_GET(self):
                allowed = {f"127.0.0.1:{self.server.server_port}",
                           f"localhost:{self.server.server_port}"}
                if self.headers.get("Host") not in allowed:
                    self.send_error(403)
                    return
                origin = self.headers.get("Origin")
                if origin and origin not in {"http://" + h for h in allowed}:
                    self.send_error(403)
                    return
                path = urlsplit(self.path).path
                files = {"/": ("logs.html", "text/html"),
                         "/logs.css": ("logs.css", "text/css"),
                         "/logs.js": ("logs.js", "text/javascript")}
                if path in {"/api/events", "/api/activity"}:
                    snapshot = journal.snapshot()
                    if path == "/api/activity":
                        snapshot = {key: snapshot[key] for key in
                                    ("activity", "activity_evicted", "dropped", "write_errors")}
                    body = json.dumps(snapshot).encode()
                    content_type = "application/json"
                elif path == "/api/users":
                    snapshot = users_snapshot() if users_snapshot else dict(users=[], count=0)
                    body = json.dumps(snapshot).encode()
                    content_type = "application/json"
                elif path in files:
                    name, content_type = files[path]
                    body = (static / name).read_bytes()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type + "; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; frame-ancestors 'none'; object-src 'none'")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.http = HTTPServer(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever,
                                       kwargs={"poll_interval": 0.1}, daemon=True,
                                       name="collab-log-http")
        try:
            self.thread.start()
        except BaseException:
            self.http.server_close()
            raise

    @property
    def url(self):
        return f"http://127.0.0.1:{self.http.server_port}"

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)
