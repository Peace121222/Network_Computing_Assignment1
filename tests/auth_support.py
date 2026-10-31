"""Provide disposable account and TLS fixtures for network regression tests.

Import creates a temporary CA directory and certificate files for test clients.
Server/database directories are retained until process cleanup. Production client
and server behavior is exercised after test-only account provisioning.
"""

import tempfile
import atexit
from collab.client import TransferCapacityError
from pathlib import Path
from collab.certgen import generate
from collab.client.core import Client as RealClient
from collab.server.core import Server as RealServer

PASSWORD = "test password 123"
_resources = tempfile.TemporaryDirectory()
ROOT = Path(_resources.name)
generate(ROOT, ["localhost", "127.0.0.1"])
SERVERS = {}
atexit.register(_resources.cleanup)


class Server(RealServer):
    """Supply disposable databases and certificates for production-server tests.

    Tests may inject synthetic session dictionaries; handle_udp() adds their lookup
    identities before delegating. Authentication-specific tests restore their own
    limiter settings when exercising the production rate policy.
    """

    def __init__(self, *args, **kwargs):
        self._test_directory = tempfile.TemporaryDirectory()
        kwargs.setdefault(
            "database", str(Path(self._test_directory.name) / "accounts.db")
        )
        kwargs.setdefault("certfile", str(ROOT / "server.crt"))
        kwargs.setdefault("keyfile", str(ROOT / "server.key"))
        atexit.register(self._test_directory.cleanup)
        super().__init__(*args, **kwargs)
        from cryptography.fernet import Fernet

        self.f = Fernet(Fernet.generate_key())
        self.auth_limiter.limit = 10000

    def handle_udp(self, raw, addr):
        with self.lock:
            for user in self.users.values():
                if "udp_security" in user:
                    user.setdefault("public_id", user["udp_security"].context)
        return super().handle_udp(raw, addr)

    def start(self):
        super().start()
        SERVERS[self.tcp_port] = self


class Client(RealClient):
    """Provision test accounts before connecting through the production client.

    Unconnected unit fixtures also receive a synthetic cipher for packet tests. These
    default credentials and provisioning behavior exist only in the test subclass.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("cafile", str(ROOT / "ca.crt"))
        super().__init__(*args, **kwargs)

        from cryptography.fernet import Fernet

        self.f = Fernet(Fernet.generate_key())

    def connect(self, password=PASSWORD):
        server = SERVERS.get(self.port)
        if server is not None:
            try:
                server.accounts.register(self.name, PASSWORD)
            except ValueError:
                pass
        return super().connect(password)


def tls_connection(address, timeout=1):
    import socket
    from collab.transport.tls import client_context

    raw = socket.create_connection(address, timeout=timeout)
    try:
        return client_context(str(ROOT / "ca.crt")).wrap_socket(
            raw, server_hostname="localhost"
        )
    except BaseException:
        raw.close()
        raise


def client_login(sock, name, unused, deadline):
    from collab.transport.handshake import client_login as login

    server = SERVERS.get(sock.getpeername()[1])
    if server is not None and isinstance(name, str):
        try:
            server.accounts.register(name, PASSWORD)
        except ValueError:
            pass
    return login(sock, name, PASSWORD, deadline)
