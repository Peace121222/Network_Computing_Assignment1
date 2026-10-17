"""Bounded localhost HTTP bridge; networking remains raw TCP/UDP sockets."""

import base64
import json
from pathlib import Path
import queue
import tempfile
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse
from collab.shared.limits import MAX_FILE_SIZE
from collab.web.runtime import WebRuntime, BoundedHTTPServer


STATIC_DIR = Path(__file__).resolve().parent / "static"


def _load_static(name: str) -> str:
    """Load fixed package resources at import; no request path reaches the filesystem."""
    try:
        return (STATIC_DIR / name).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"Cannot load web static resource: {name}") from exc


PAGE = _load_static("index.html")
_STATIC = {
    "/": (PAGE.encode("utf-8"), "text/html; charset=utf-8"),
    "/static/style.css": (
        _load_static("style.css").encode("utf-8"),
        "text/css; charset=utf-8",
    ),
    "/static/app.js": (
        _load_static("app.js").encode("utf-8"),
        "text/javascript; charset=utf-8",
    ),
}


def handler_factory(client):
    runtime = WebRuntime(client)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def output(self, status, payload):
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            resource = _STATIC.get(urlparse(self.path).path)
            if resource is not None:
                raw, content_type = resource
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif self.path == "/events":
                events = []
                for _ in range(100):
                    try:
                        event = client.events.get_nowait()
                    except queue.Empty:
                        break
                    if event.get("type") != "presence":
                        events.append(event)
                with client._state_lock:
                    names, status = list(client.names), client.status
                self.output(
                    200,
                    {
                        "self": client.name,
                        "names": names,
                        "status": status,
                        "events": events,
                    },
                )
            else:
                self.output(404, {"error": "Not found"})

        def do_POST(self):
            lease = None
            upload = False
            path = tmpdir = None
            submitted = False

            def cleanup():
                nonlocal upload
                try:
                    if path is not None:
                        path.unlink(missing_ok=True)
                    if tmpdir is not None:
                        tmpdir.rmdir()
                finally:
                    if upload:
                        upload = False
                        runtime.uploads.release()

            try:
                if self.path not in ("/chat", "/file"):
                    return self.output(404, {"error": "Not found"})
                if (
                    self.headers.get("Content-Type", "").split(";")[0]
                    != "application/json"
                ):
                    raise ValueError("Expected application/json")
                size = int(self.headers.get("Content-Length", "0"))
                limit = 16 * 1024 if self.path == "/chat" else 37 * 1024 * 1024 - 1
                if not 0 < size <= limit:
                    raise ValueError("Invalid request length")
                lease = runtime.tasks.reserve()
                if lease is None:
                    return self.output(503, {"error": "Send queue is full"})
                if self.path == "/file":
                    upload = runtime.uploads.acquire(False)
                    if not upload:
                        return self.output(503, {"error": "Upload capacity exceeded"})
                session = client._capture_session()
                raw_body = self.rfile.read(size)
                if len(raw_body) != size:
                    raise ValueError("Incomplete request body")
                data = json.loads(raw_body)
                if not isinstance(data, dict):
                    raise ValueError("Expected JSON object")
                if self.path == "/chat":
                    fn, args = client.chat, (data["to"], data["text"])
                else:
                    name = data["filename"]
                    if (
                        not isinstance(name, str)
                        or not name
                        or name in (".", "..")
                        or "/" in name
                        or "\\" in name
                        or "\x00" in name
                    ):
                        raise ValueError("Invalid filename")
                    raw = base64.b64decode(data["data"], validate=True)
                    if len(raw) > MAX_FILE_SIZE:
                        raise ValueError("File too large")
                    tmpdir = Path(tempfile.mkdtemp(prefix="collab_upload_"))
                    path = tmpdir / name
                    path.write_bytes(raw)
                    fn, args = client.file, (data["to"], path)
                runtime.submit(lease, session, fn, args, cleanup)
                submitted = True
                self.output(202, {"accepted": True})
            except (ValueError, KeyError, TypeError) as exc:
                self.output(400, {"error": str(exc)})
            except (OSError, RuntimeError) as exc:
                self.output(503, {"error": str(exc)})
            finally:
                if not submitted:
                    cleanup()
                    if lease is not None:
                        lease.release()

    Handler.runtime = runtime
    return Handler
