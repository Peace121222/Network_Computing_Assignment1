"""Live 20-client evidence run against Collab LAN's already running server."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
DEMO_PASSWORD = "demo1234"
sys.path.insert(0, str(PROJECT))
from collab.client import Client  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default="load")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--ca", default=str(PROJECT / "certs/ca.crt"))
    args = parser.parse_args()

    names = [f"{args.prefix}{i:02d}" for i in range(20)]
    clients = [
        Client(name, host=args.host, port=args.port, cafile=args.ca,
               download_dir=PROJECT / "downloads" / name)
        for name in names
    ]
    try:
        for client in clients:
            try:
                client.register(DEMO_PASSWORD, DEMO_PASSWORD)
            except RuntimeError as exc:
                if str(exc) != "Username already registered":
                    raise
                print(f"Account {client.name} already exists; logging in.", flush=True)
            else:
                print(f"Registered {client.name}", flush=True)

        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda client: client.connect(DEMO_PASSWORD), clients))
        deadline = time.monotonic() + 15
        while not all(len(client.names) == 20 for client in clients):
            if time.monotonic() > deadline:
                raise TimeoutError("Not all clients see 20 online users")
            time.sleep(0.1)
        print("20/20 clients connected and see 20 online users.", flush=True)

        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda item: item[1].chat(names[(item[0] + 1) % 20],
                                                   f"LIVE20-{item[0]:02d}"),
                          enumerate(clients)))
        print("20 private messages sent to the next client.", flush=True)
        input("Capture server page (20 connected) and log, then press Enter to close... ")
    finally:
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda client: client.close(), clients))
        print("All test clients closed.", flush=True)


if __name__ == "__main__":
    main()
