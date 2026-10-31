"""Persistent accounts and fixed-window authentication throttling."""

from __future__ import annotations

from collections.abc import Callable, Hashable
from contextlib import closing
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError
from collab.shared.protocol import valid_name


def validate_credentials(username: Any, password: Any) -> None:
    """Validate credentials without trimming passwords or normalizing usernames.

    Args:
        username: Case-sensitive name containing 1 to 24 Unicode letters, digits,
            or underscores, with at least one letter or digit.
        password: Password containing 8 to 128 characters.

    Raises:
        ValueError: The username or password violates the input policy.
    """
    if not valid_name(username):
        raise ValueError("Invalid username")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        raise ValueError("Password must contain 8 to 128 characters")


class Accounts:
    """Store persistent accounts using short-lived SQLite connections.

    Each operation closes its own connection. SQLite enforces username uniqueness,
    including concurrent registration attempts. Network callers acquire slots before
    password-hashing work; register() and verify() do not acquire it themselves.

    Attributes:
        path: Database path, resolved relative to the process working directory.
        hasher: Argon2id password hasher with library-managed random salts.
        slots: Semaphore used by the server to bound concurrent authentication work.
        dummy: Hash verified for unknown usernames to reduce timing differences.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self.hasher = PasswordHasher(
            time_cost=2, memory_cost=19456, parallelism=1, type=Type.ID
        )
        self.slots = threading.BoundedSemaphore(4)
        self.dummy = self.hasher.hash("dummy authentication password")
        with self.connection() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS accounts ("
                "id INTEGER PRIMARY KEY, "
                "username TEXT UNIQUE NOT NULL, "
                "password_hash TEXT NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def connection(self) -> closing[sqlite3.Connection]:
        """Create a context manager that closes its SQLite connection on exit.

        The connection has a one-second database lock timeout. The caller must commit
        writes explicitly or use the connection's transaction context manager.

        Returns:
            A closing context manager for a newly opened database connection.
        """
        return closing(sqlite3.connect(self.path, timeout=1))

    def register(self, username: str, password: str) -> None:
        """Persist a new account with an Argon2id password hash.

        Args:
            username: Case-sensitive username satisfying validate_credentials().
            password: Password satisfying validate_credentials(); never stored as plaintext.

        Raises:
            ValueError: Credentials are invalid or the username is already registered.
        """
        validate_credentials(username, password)
        password_hash = self.hasher.hash(password)
        try:
            with self.connection() as db:
                with db:
                    db.execute(
                        "INSERT INTO accounts(username,password_hash) VALUES (?,?)",
                        (username, password_hash),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already registered") from exc

    def verify(self, username: str, password: str) -> bool:
        """Verify a password without creating or modifying an account.

        Unknown usernames still perform a password-hash verification. Plaintext passwords
        are not stored in account state or the database.

        Args:
            username: Case-sensitive username satisfying validate_credentials().
            password: Password satisfying validate_credentials().

        Returns:
            True for matching credentials; False for an unknown account or wrong password.

        Raises:
            ValueError: The credentials violate the input policy.
        """
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
    """Track expiring authentication windows by source IP.

    The server keys attempts by source IP and counts registration and login attempts,
    including successes. Expired entries are removed on the next authentication attempt.

    Attributes:
        limit: Number of allowed attempts within a window.
        window: Window duration in seconds.
        clock: Monotonic clock returning seconds.
    """

    def __init__(
        self,
        limit: int = 10,
        window: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit, self.window, self.clock = limit, window, clock
        self.entries: dict[Hashable, tuple[float, int]] = {}
        self.lock = threading.Lock()

    def allow(self, key: Hashable) -> bool:
        """Count an attempt and check its fixed-window allowance.

        Denied attempts do not extend the fixed window.

        Args:
            key: Hashable client identity, normally a source IP address.

        Returns:
            True if this attempt is within the configured limit; False otherwise.
        """
        with self.lock:
            now = self.clock()
            for previous_key, (window_started_at, _) in list(self.entries.items()):
                if now - window_started_at >= self.window:
                    del self.entries[previous_key]
            window_started_at, attempts = self.entries.get(key, (now, 0))
            self.entries[key] = (window_started_at, attempts + 1)
            return attempts < self.limit
