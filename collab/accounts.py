"""Persistent accounts and bounded, expiring authentication throttling."""

from contextlib import closing
import sqlite3
import threading
import time
from collections import OrderedDict
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError
from collab.shared.protocol import valid_name


def validate_credentials(username, password):
    if not valid_name(username):
        raise ValueError("Invalid username")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        raise ValueError("Password must contain 8 to 128 characters")


class Accounts:
    def __init__(self, path):
        self.path = str(path)
        self.hasher = PasswordHasher(
            time_cost=2, memory_cost=19456, parallelism=1, type=Type.ID
        )
        self.slots = threading.BoundedSemaphore(4)
        self.dummy = self.hasher.hash("dummy authentication password")
        with self.connection() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def connection(self):
        # Explicitly close connections: sqlite context managers only commit/rollback.
        return closing(sqlite3.connect(self.path, timeout=1))

    def register(self, username, password):
        validate_credentials(username, password)
        encoded = self.hasher.hash(password)
        try:
            with self.connection() as db:
                with db:
                    db.execute(
                        "INSERT INTO accounts(username,password_hash) VALUES (?,?)",
                        (username, encoded),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already registered") from exc

    def verify(self, username, password):
        validate_credentials(username, password)
        with self.connection() as db:
            row = db.execute(
                "SELECT password_hash FROM accounts WHERE username=?", (username,)
            ).fetchone()
        try:
            valid = self.hasher.verify(row[0] if row else self.dummy, password)
        except VerificationError:
            return False
        return bool(row) and valid


class AuthLimiter:
    """Per-IP fixed window, bounded LRU state; includes registration attempts."""

    def __init__(self, limit=10, window=60, capacity=4096, clock=time.monotonic):
        self.limit, self.window, self.capacity, self.clock = (
            limit,
            window,
            capacity,
            clock,
        )
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key):
        with self.lock:
            now = self.clock()
            for old in list(self.entries):
                if now - self.entries[old][0] >= self.window:
                    del self.entries[old]
            start, count = self.entries.pop(key, (now, 0))
            self.entries[key] = (start, count + 1)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return count < self.limit
