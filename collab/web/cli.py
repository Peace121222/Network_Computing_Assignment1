"""Command-line startup for the local browser interface."""

import argparse
import logging
import sys

from collab.client.terminal_auth import add_connection_arguments
from collab.client import Client
from .auth import BrowserAuth
from .handlers import handler_factory
from .runtime import BoundedHTTPServer

log = logging.getLogger(__name__)


def main() -> int:
    """Open a loopback browser login page; CLI authentication stays terminal-only."""
    parser = argparse.ArgumentParser()
    add_connection_arguments(parser)
    parser.add_argument("--web-port", type=int, default=8080)
    args = parser.parse_args()
    client = http = None
    result = 0
    try:
        client = Client(args.name or "", args.host, args.port, args.downloads,
                        cafile=args.ca, server_name=args.server_name)
        auth = BrowserAuth(client, args.name)
        http = BoundedHTTPServer(("127.0.0.1", args.web_port), handler_factory(client, auth=auth))
        print(
            f"Open http://127.0.0.1:{http.server_port}/login to sign in", flush=True
        )
        http.serve_forever()
    except (KeyboardInterrupt, EOFError):
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        result = 1
    except Exception:
        log.exception("HTTP backend failed")
        result = 1
    finally:
        try:
            if http is not None:
                http.server_close()
            elif client is not None:
                client.close()
        except Exception as exc:
            log.exception("HTTP cleanup failed")
            print("ERROR: " + str(exc), file=sys.stderr)
            result = 1
    return result
