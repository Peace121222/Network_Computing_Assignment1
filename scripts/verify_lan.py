"""Verify chat and file receipts against an already running TLS server.

Run from the repository root with --host, --port and --ca. This creates two
throwaway demo accounts on that server; their passwords/keys are never printed.
The server operator should use a disposable database for demonstrations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collab.client import Client  # noqa: E402


def verify(host: str, port: int, ca: str) -> dict:
    """Create disposable users, exchange data, and return non-secret evidence."""
    with tempfile.TemporaryDirectory() as directory:
        prefix = "demo_" + secrets.token_hex(3)
        password = secrets.token_urlsafe(24)
        clients = [
            Client(prefix + suffix, host, port, Path(directory) / suffix, cafile=ca)
            for suffix in ("_alice", "_bob")
        ]
        start = time.monotonic()
        try:
            for client in clients:
                client.register(password, password)
                client.connect(password)
            deadline = time.monotonic() + 8
            while not all(
                len(c.names) >= 2 and all(peer.name in c.names for peer in clients)
                for c in clients
            ):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Demo presence did not converge")
                threading.Event().wait(0.01)
            a, b = clients
            a.chat(b.name, "private demo")
            b.chat("*", "broadcast demo")
            payload = bytes(range(256)) * 64
            source = Path(directory) / "demo.bin"
            source.write_bytes(payload)
            a.file(b.name, source)
            files = list(b.download_dir.iterdir())
            if len(files) != 1 or files[0].read_bytes() != payload:
                raise RuntimeError("Saved file does not match the source")
            events_a = list(a.events.queue)
            events_b = list(b.events.queue)
            if not any(
                e.get("text") == "private demo" and e.get("type") == "chat"
                for e in events_b
            ):
                raise RuntimeError("Private chat missing")
            if not any(
                e.get("text") == "broadcast demo" and e.get("type") == "chat"
                for e in events_a
            ):
                raise RuntimeError("Broadcast chat missing")
            return dict(
                host=host,
                port=port,
                users=2,
                private_chat=True,
                broadcast=True,
                saved_file_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                client_congestion=a._session["congestion"].snapshot(),
                elapsed_seconds=round(time.monotonic() - start, 3),
                scope="Same-host interface unless run from a second physical client machine",
            )
        finally:
            for client in clients:
                client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--ca", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.host, args.port, args.ca), indent=2))


if __name__ == "__main__":
    main()
