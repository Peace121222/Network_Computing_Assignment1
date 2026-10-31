"""Simple SQLite accounts storage with PBKDF2 hashing."""

import hashlib
import os
import sqlite3
import threading

class Accounts:
    def __init__(self, db_path: str = "accounts.sqlite3"):
        self.db_path = db_path
        self.lock = threading.Lock()
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        salt BLOB NOT NULL,
                        hash BLOB NOT NULL
                    )
                    """
                )
                conn.commit()
                
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    def register(self, username: str, password: str) -> None:
        if not (3 <= len(username) <= 32 and username.isalnum()):
            raise ValueError("Username must be 3-32 alphanumeric characters")
        if not (8 <= len(password) <= 128):
            raise ValueError("Password must be 8-128 characters")
            
        salt = os.urandom(16)
        pwd_hash = self._hash_password(password, salt)
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                try:
                    conn.execute("INSERT INTO users (username, salt, hash) VALUES (?, ?, ?)", 
                                 (username, salt, pwd_hash))
                    conn.commit()
                except sqlite3.IntegrityError:
                    raise ValueError("Username already exists")

    def verify(self, username: str, password: str) -> bool:
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT salt, hash FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                
        if row is None:
            return False
            
        salt, stored_hash = row
        return self._hash_password(password, salt) == stored_hash
