"""Terminal interface and process cleanup for the socket client."""

import argparse
import json
import logging
import queue
import sys
import threading
import time

from collab.client.core import Client
from collab.client.terminal_auth import add_connection_arguments, authenticate
from collab.shared.limits import SHUTDOWN_TIMEOUT

log = logging.getLogger(__name__)


def _print_events(client: Client) -> None:
    while client.running.is_set():
        try:
            event = client.events.get(timeout=0.3)
        except queue.Empty:
            continue
        if event["type"] != "presence":
            print("\nEVENT", json.dumps(event, ensure_ascii=False))


def _execute_command(client: Client, line: str) -> None:
    """Dispatch one command; /quit is handled by the owning input loop."""
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


def _run_commands(client: Client) -> int:
    """Keep command errors recoverable while the session remains connected."""
    while client.status == "connected":
        line = input("> ").strip()
        if line == "/quit":
            break
        try:
            _execute_command(client, line)
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            print("ERROR: " + str(exc), file=sys.stderr)
            if client.status != "connected":
                return 1
    return 0 if client.status == "connected" else 1


def main() -> int:
    """Run terminal authentication, command input, event output, and cleanup.

    Returns:
        Zero for a normal exit, EOF, or interrupt; one for a reported startup,
        disconnection, or cleanup failure.
    """
    parser = argparse.ArgumentParser()
    add_connection_arguments(parser)
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

        printer_thread = threading.Thread(
            target=_print_events, args=(client,), daemon=True
        )
        printer_thread.start()
        result = _run_commands(client)
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
