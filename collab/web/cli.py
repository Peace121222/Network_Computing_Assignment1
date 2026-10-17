"""Command-line startup for the local browser interface."""

import argparse
import logging
import sys
from collab.client import Client
from .handlers import handler_factory
from .runtime import BoundedHTTPServer


def main() -> int:
    a = argparse.ArgumentParser()
    a.add_argument("--name", required=True)
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=9000)
    a.add_argument("--web-port", type=int, default=8080)
    a.add_argument("--downloads", default="downloads")
    opts = a.parse_args()
    client = http = None
    result = 0
    try:
        client = Client(opts.name, opts.host, opts.port, opts.downloads)
        client.connect()
        http = BoundedHTTPServer(("127.0.0.1", opts.web_port), handler_factory(client))
        print(f"Open http://127.0.0.1:{opts.web_port} for user {opts.name}", flush=True)
        http.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        result = 1
    except Exception:
        logging.getLogger(__name__).exception("HTTP backend failed")
        result = 1
    finally:
        try:
            if http is not None:
                http.server_close()
            elif client is not None:
                client.close()
        except Exception as exc:
            logging.getLogger(__name__).exception("HTTP cleanup failed")
            print("ERROR: " + str(exc), file=sys.stderr)
            result = 1
    return result
