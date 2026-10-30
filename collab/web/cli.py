"""Command-line startup for the local browser interface."""

import argparse
import logging
import sys

from collab.client.terminal_auth import add_connection_arguments, authenticate
from .handlers import handler_factory
from .runtime import BoundedHTTPServer

log = logging.getLogger(__name__)


def main() -> int:
    """Authenticate in the terminal and serve the local browser interface.

    The HTTP listener opens only after login. Shutdown closes the HTTP runtime and
    its client, or closes the client directly if HTTP startup did not finish.

    Returns:
        Zero for a normal exit, EOF, or interrupt; one for a reported backend or
        cleanup failure.
    """
    parser = argparse.ArgumentParser()
    add_connection_arguments(parser)
    parser.add_argument("--web-port", type=int, default=8080)
    args = parser.parse_args()
    client = http = None
    result = 0
    try:
        client = authenticate(args)
        if client is None:
            return 0
        http = BoundedHTTPServer(("127.0.0.1", args.web_port), handler_factory(client))
        print(
            f"Open http://127.0.0.1:{args.web_port} for user {client.name}", flush=True
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
