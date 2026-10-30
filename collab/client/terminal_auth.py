"""Terminal-only authentication shared by both application entry points."""

from getpass import getpass
from collab.client.core import Client


def authenticate(opts):
    while True:
        print("1. Log in\n2. Register\n3. Exit")
        choice = input("> ").strip()
        if choice == "3":
            return None
        if choice not in ("1", "2"):
            continue
        name = input(f"Username [{opts.name or ''}]: ").strip() or opts.name or ""
        client = Client(
            name,
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
