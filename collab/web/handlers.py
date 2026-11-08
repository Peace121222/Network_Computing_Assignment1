"""Bounded localhost HTTP bridge; networking remains raw TCP/UDP sockets."""

import base64
from contextlib import nullcontext
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
    """Read a fixed package resource and fail early if it is unavailable.

    Args:
        name: Package-controlled resource name, never an untrusted HTTP request path.

    Returns:
        UTF-8 resource contents.

    Raises:
        RuntimeError: Reading or UTF-8 decoding fails.
    """
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

for route, filename in (("/login", "login.html"), ("/signup", "signup.html"),
                        ("/static/auth.js", "auth.js")):
    _STATIC[route] = (_load_static(filename).encode("utf-8"),
                      "text/javascript; charset=utf-8" if filename.endswith(".js")
                      else "text/html; charset=utf-8")


def handler_factory(client, *, auth=None):
    """Create HTTP handlers and a bounded send runtime for one client.

    The returned class exposes its runtime to BoundedHTTPServer for coordinated
    shutdown. Calling this factory starts send-pool workers; it does not bind HTTP.

    Args:
        client: Client core used directly for event polling, chat, and file operations.

    Returns:
        A BaseHTTPRequestHandler subclass with the attached runtime.
    """
    runtime = WebRuntime(client)
    runtime.auth = auth

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def trusted_origin(self):
            if auth is None:
                return True
            allowed = {f"127.0.0.1:{self.server.server_port}",
                       f"localhost:{self.server.server_port}"}
            return (self.headers.get("Host") in allowed and
                    (not self.headers.get("Origin") or
                     self.headers.get("Origin") in {"http://" + x for x in allowed}))

        def signed_in(self):
            return auth is None or auth.authorized(self.headers.get("Cookie"), self.server.server_port)

        def redirect(self, path):
            self.send_response(303)
            self.send_header("Location", path)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def output(self, status, payload, cookie=None):
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if not self.trusted_origin():
                return self.output(403, {"error": "Local same-origin access only"})
            path = urlparse(self.path).path
            if auth is not None:
                with auth.lock:
                    if path == "/session":
                        return self.output(200, {"authenticated": self.signed_in(),
                                                 "prefill": auth.prefill,
                                                 "host": client.host, "port": client.port})
                    if path == "/" and not self.signed_in():
                        return self.redirect("/login")
                    if path in ("/login", "/signup") and self.signed_in() and client.status == "connected":
                        return self.redirect("/")
            resource = _STATIC.get(urlparse(self.path).path)
            if resource is not None:
                raw, content_type = resource
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'")
                self.end_headers()
                self.wfile.write(raw)
            elif self.path == "/events":
                with auth.lock if auth is not None else nullcontext():
                    if not self.signed_in():
                        return self.output(401, {"error": "Log in to continue"})
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

        def account_action(self):
            try:
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("Expected application/json")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError("Invalid request length")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("Incomplete request body")
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError("Expected JSON object")
                if self.path == "/auth/logout":
                    cookie = auth.logout(self.headers.get("Cookie"), self.server.server_port)
                    return self.output(200, {"redirect": "/login"}, cookie)
                username, password = data.get("username"), data.get("password")
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValueError("Enter a username and password")
                if self.path == "/auth/signup":
                    auth.register(username, password, data.get("confirmation"))
                    return self.output(201, {"redirect": "/login?registered=1"})
                cookie = auth.login(username, password, self.headers.get("Cookie"), self.server.server_port)
                return self.output(200, {"redirect": "/"}, cookie)
            except PermissionError as exc:
                self.output(401, {"error": str(exc)})
            except (ValueError, TypeError, KeyError) as exc:
                self.output(400, {"error": str(exc)})
            except OSError as exc:
                self.output(503, {"error": str(exc)})
            except RuntimeError as exc:
                status = 401 if str(exc) == "Invalid username or password" else 409
                self.output(status, {"error": str(exc)})

        def do_POST(self):
            if not self.trusted_origin():
                return self.output(403, {"error": "Local same-origin access only"})
            if auth is not None and self.path in ("/auth/login", "/auth/signup", "/auth/logout"):
                return self.account_action()
            if not self.signed_in():
                return self.output(401, {"error": "Log in to continue"})
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
                with auth.lock if auth is not None else nullcontext():
                    if not self.signed_in():
                        return self.output(401, {"error": "Log in to continue"})
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
