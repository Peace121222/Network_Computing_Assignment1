"""Compatibility entry point for python -m collab.webui."""

from .web.cli import main
from .web.handlers import PAGE, handler_factory
from .web.runtime import BoundedHTTPServer, WebRuntime

__all__ = ["main", "PAGE", "handler_factory", "BoundedHTTPServer", "WebRuntime"]

if __name__ == "__main__":
    raise SystemExit(main())
