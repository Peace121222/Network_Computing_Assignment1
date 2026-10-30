"""Terminal-only authentication shared by both application entry points."""

from argparse import ArgumentParser, Namespace
from getpass import getpass
from collab.client.core import Client


def add_connection_arguments(parser: ArgumentParser) -> None:
    """Add the connection options shared by both terminal entry points.

    Args:
        parser: Argument parser to mutate with the existing flags and defaults.
    """
    parser.add_argument("--name")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--downloads", default="downloads")
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name")


def authenticate(opts: Namespace) -> Client | None:
    """Run the terminal account menu and return a connected client.

    Passwords are read with getpass. Registration returns to the menu; rejected or
    failed attempts close their client. The caller owns a successfully returned client.

    Args:
        opts: Parsed connection options: name, host, port, downloads, ca, and server_name.

    Returns:
        A connected client after login, or None when the user chooses Exit.

    Raises:
        EOFError: Terminal input ends; any active attempt is cleaned up first.
        KeyboardInterrupt: The user interrupts input; attempt cleanup runs first.
    """
    while True:
        print("1. Log in\n2. Register\n3. Exit")
        choice = input("> ").strip()
        if choice == "3":
            return None
        if choice not in ("1", "2"):
            continue
        username = input(f"Username [{opts.name or ''}]: ").strip() or opts.name or ""
        client = Client(
            username,
            opts.host,
            opts.port,
            opts.downloads,
            cafile=opts.ca,
            server_name=opts.server_name,
        )
        try:
            password = getpass("Password: ")
            if choice == "2":
                client.register(password, getpass("Confirm password: "))
                print("Registration successful. Please log in.")
            else:
                client.connect(password)
                return client
        except (OSError, ValueError, RuntimeError) as exc:
            print("ERROR: " + str(exc))
        finally:
            password = None
            if client.status != "connected":
                client.close()
