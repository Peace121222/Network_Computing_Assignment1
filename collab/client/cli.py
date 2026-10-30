"""Terminal interface and process cleanup for the socket client."""

import argparse
import json
import logging
import queue
import sys
import threading
import time

from collab.client.terminal_auth import authenticate
from collab.shared.limits import SHUTDOWN_TIMEOUT

log = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--downloads", default="downloads")
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    client = None
    printer_thread = None
    result = 0
    try:
        client = authenticate(args)
        if client is None:
            return 0
        print(
            "Commands: /users, /msg USER MESSAGE, /all MESSAGE, /file USER PATH, /quit"
        )

        def printer():
            while client.running.is_set():
                try:
                    event = client.events.get(timeout=0.3)
                    if event["type"] != "presence":
                        print("\nEVENT", json.dumps(event, ensure_ascii=False))
                except queue.Empty:
                    pass

        printer_thread = threading.Thread(target=printer, daemon=True)
        printer_thread.start()
        while client.status == "connected":
            line = input("> ").strip()
            if line == "/quit":
                break
            try:
                if line == "/users":
                    print(client.names)
                elif line.startswith("/all "):
                    client.chat("*", line[5:])
                elif line.startswith("/msg ") or line.startswith("/file "):
                    parts = line.split(" ", 2)
                    if len(parts) != 3 or not parts[1] or not parts[2].strip():
                        raise ValueError("Expected recipient and message or file path")
                    command, recipient, content = parts
                    if command == "/msg":
                        client.chat(recipient, content)
                    else:
                        client.file(recipient, content)
                else:
                    raise ValueError("Invalid command")
            except (OSError, ValueError, RuntimeError, TypeError) as exc:
                print("ERROR: " + str(exc), file=sys.stderr)
                if client.status != "connected":
                    result = 1
                    break
        if client.status != "connected":
            result = 1
    except (KeyboardInterrupt, EOFError):
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        result = 1
    except Exception:
        log.exception("Client failed")
        result = 1
    finally:
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT
        if client is not None:
            try:
                client._close_before(deadline)
            except Exception as exc:
                log.exception("Client cleanup failed")
                print("ERROR: " + str(exc), file=sys.stderr)
                result = 1
        if printer_thread is not None:
            printer_thread.join(max(0, deadline - time.monotonic()))
            if printer_thread.is_alive():
                print("ERROR: Client printer shutdown incomplete", file=sys.stderr)
                result = 1
    return result
