"""One browser-owned account session per loopback Web backend."""

from http.cookies import SimpleCookie, CookieError
import secrets
import queue
import threading


class BrowserAuth:
    """Serialize account transitions; the existing client owns TLS and workers."""

    def __init__(self, client, prefill=""):
        self.client = client
        self.prefill = prefill or ""
        self.lock = threading.RLock()
        self.token = None
        self.closing = threading.Event()

    @staticmethod
    def cookie_name(port):
        # Cookies do not isolate ports. Give each local user backend its own name.
        return f"collab_session_{port}"

    def authorized(self, header, port):
        try:
            cookies = SimpleCookie()
            cookies.load(header or "")
            value = cookies.get(self.cookie_name(port))
            return bool(self.token and value and secrets.compare_digest(value.value, self.token))
        except (CookieError, TypeError):
            return False

    def login(self, username, password, header, port):
        if not self.lock.acquire(blocking=False):
            raise RuntimeError("An account operation is already in progress")
        try:
            if self.closing.is_set():
                raise RuntimeError("Web backend is stopping")
            if self.client.status == "connected" and not self.authorized(header, port):
                raise RuntimeError("This backend already has an active account")
            self.token = None
            self.client.close()
            self.client.name = username
            self.client.connect(password)
            if self.closing.is_set():
                self.client.close()
                raise RuntimeError("Web backend is stopping")
            # Previous account events must never appear in a new account's page.
            while True:
                try:
                    self.client.events.get_nowait()
                except queue.Empty:
                    break
            self.token = secrets.token_urlsafe(32)
            return f"{self.cookie_name(port)}={self.token}; HttpOnly; SameSite=Strict; Path=/"
        finally:
            try:
                if self.closing.is_set():
                    self.token = None
                    self.client.close()
            finally:
                self.lock.release()

    def register(self, username, password, confirmation):
        if not self.lock.acquire(blocking=False):
            raise RuntimeError("An account operation is already in progress")
        try:
            if self.closing.is_set():
                raise RuntimeError("Web backend is stopping")
            if self.client.status == "connected":
                raise RuntimeError("Log out before creating another account")
            self.client.close()
            self.client.name = username
            self.client.register(password, confirmation)
        finally:
            self.lock.release()

    def logout(self, header, port):
        with self.lock:
            if not self.authorized(header, port):
                raise PermissionError("Log in to continue")
            self.token = None
            self.client.close()
        return f"{self.cookie_name(port)}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"
