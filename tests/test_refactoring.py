"""Compatibility boundaries for CLI extraction, static resources and annotations."""

import ast
import importlib.util
import inspect
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import typing
import unittest
from unittest.mock import patch

from collab import common
from collab.client import cli, core
from collab.shared import limits, protocol
from collab.transport import handshake, security, tcp, udp
from collab.web import handlers

ROOT = Path(__file__).resolve().parents[1]


class RefactoringTests(unittest.TestCase):
    def test_legacy_core_main_delegates_without_new_arguments(self):
        with patch.object(cli, "main", return_value=17) as entry:
            self.assertEqual(core.main(), 17)
        entry.assert_called_once_with()
        self.assertEqual(list(inspect.signature(core.main).parameters), [])

    def test_cli_and_core_import_in_either_order(self):
        for order in (("cli", "core"), ("core", "cli")):
            with self.subTest(order=order):
                code = "; ".join(f"import collab.client.{module}" for module in order)
                result = subprocess.run(
                    [sys.executable, "-c", code],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_limits_keep_existing_values_and_patchable_imports(self):
        from collab.server import core as server_core
        from collab.web import runtime
        from collab.shared import concurrency

        expected = {
            "SHUTDOWN_TIMEOUT": 3,
            "CONTROL_TIMEOUT": 0.5,
            "UDP_PATH_CHALLENGE_TIMEOUT": 2,
            "UDP_PATH_CHALLENGE_INTERVAL": 0.5,
            "HTTP_REQUEST_TIMEOUT": 2,
            "FILE_PROGRESS_INTERVAL": 0.1,
        }
        for name, value in expected.items():
            self.assertEqual(getattr(limits, name), value)
        for module in (common, core, server_core, runtime, concurrency, cli):
            self.assertEqual(module.SHUTDOWN_TIMEOUT, 3)
        self.assertEqual(common.CONTROL_TIMEOUT, server_core.CONTROL_TIMEOUT)
        with patch.object(core, "SHUTDOWN_TIMEOUT", 0.01):
            self.assertEqual(core.SHUTDOWN_TIMEOUT, 0.01)
            self.assertEqual(limits.SHUTDOWN_TIMEOUT, 3)

    def test_public_annotations_resolve_without_import_cycles(self):
        functions = [
            protocol.valid_name,
            protocol.validate_tcp,
            protocol.validate_udp,
            protocol.data_packet,
            protocol.b64,
            protocol.unb64,
            tcp.send_tcp,
            tcp.frame_tcp,
            tcp.recv_tcp,
            tcp.write_tcp,
            tcp.TCPReader.__init__,
            tcp.TCPReader.read,
            udp.get_key,
            udp.cipher,
            udp.encode_udp,
            udp.decode_udp,
            security.Channel.__init__,
            security.Channel.encode,
            security.Channel.decode,
            handshake.client_login,
            handshake.server_login,
            core.Client.__init__,
            core.Client.connect,
            core.Client.close,
            core.Client.chat,
            core.Client.file,
            cli.main,
        ]
        from collab.server.core import Server

        self.assertEqual(typing.get_type_hints(Server)["status"], str)
        functions += [
            Server.__init__,
            Server.start,
            Server.close,
            Server.last_error.fget,
        ]
        for function in functions:
            with self.subTest(function=function.__qualname__):
                hints = typing.get_type_hints(function)
                self.assertIn("return", hints)
        self.assertEqual(typing.get_type_hints(core.Client)["status"], str)

    def test_signatures_and_validator_results_keep_their_contract(self):
        signature = inspect.signature(tcp.send_tcp)
        self.assertEqual(
            list(signature.parameters), ["sock", "data", "deadline", "security"]
        )
        self.assertIsNone(signature.parameters["deadline"].default)
        self.assertEqual(
            signature.parameters["security"].kind, inspect.Parameter.KEYWORD_ONLY
        )
        self.assertIsNone(
            inspect.signature(udp.encode_udp).parameters["security"].default
        )
        message = {"type": "login", "name": "alice"}
        self.assertIs(protocol.validate_tcp(message, from_client=True), message)
        self.assertEqual(
            typing.get_type_hints(protocol.validate_tcp)["msg"], typing.Any
        )
        for value in (None, [], 42):
            with self.assertRaises(ValueError):
                protocol.validate_tcp(value, from_client=True)

    def test_static_resources_are_independent_of_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from collab.web.handlers import PAGE, STATIC_DIR; "
                    "from collab.webui import PAGE as LEGACY; "
                    "assert PAGE == LEGACY; "
                    "assert '/static/app.js' in PAGE; "
                    "assert (STATIC_DIR / 'style.css').is_file()",
                ],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_invalid_static_resource_fails_during_import(self):
        for error in (FileNotFoundError("missing"), UnicodeError("bad encoding")):
            spec = importlib.util.spec_from_file_location(
                "static_import_probe", handlers.__file__
            )
            module = importlib.util.module_from_spec(spec)
            with patch.object(Path, "read_text", side_effect=error):
                with self.assertRaisesRegex(
                    RuntimeError, "static resource: index.html"
                ):
                    spec.loader.exec_module(module)

    def test_source_remains_parseable_with_python_310_grammar(self):
        for path in (ROOT / "collab").rglob("*.py"):
            with self.subTest(path=path.relative_to(ROOT)):
                ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 10))


class StartupCompatibilityTests(unittest.TestCase):
    def test_client_entry_points_preserve_connection_defaults_and_overrides(self):
        from collab.web import cli as web_cli

        for entry, executable in ((cli, "client"), (web_cli, "web")):
            cases = (
                (
                    ["--ca", "demo-ca.crt"],
                    {
                        "name": None,
                        "host": "127.0.0.1",
                        "port": 9000,
                        "downloads": "downloads",
                        "ca": "demo-ca.crt",
                        "server_name": None,
                    },
                ),
                (
                    [
                        "--ca",
                        "custom-ca.crt",
                        "--name",
                        "Alice",
                        "--host",
                        "192.0.2.1",
                        "--port",
                        "9100",
                        "--downloads",
                        "received files",
                        "--server-name",
                        "demo.local",
                    ],
                    {
                        "name": "Alice",
                        "host": "192.0.2.1",
                        "port": 9100,
                        "downloads": "received files",
                        "ca": "custom-ca.crt",
                        "server_name": "demo.local",
                    },
                ),
            )
            for arguments, expected in cases:
                with self.subTest(entry=executable, arguments=arguments):
                    with (
                        patch("sys.argv", [executable, *arguments]),
                        patch.object(
                            entry, "authenticate", return_value=None
                        ) as authenticate,
                    ):
                        self.assertEqual(entry.main(), 0)
                    parsed = authenticate.call_args.args[0]
                    self.assertEqual(
                        {name: getattr(parsed, name) for name in expected}, expected
                    )
                    if executable == "web":
                        self.assertEqual(parsed.web_port, 8080)

    def test_cli_preserves_message_and_file_contents(self):
        from unittest.mock import Mock

        client = Mock(status="connected")
        commands = [
            "/msg bob hello  with spaces",
            "/file bob folder/my file.txt",
            "/all broadcast  text",
            "/quit",
        ]
        with patch("builtins.input", side_effect=commands), patch("builtins.print"):
            self.assertEqual(cli._run_commands(client), 0)
        client.chat.assert_any_call("bob", "hello  with spaces")
        client.chat.assert_any_call("*", "broadcast  text")
        client.file.assert_called_once_with("bob", "folder/my file.txt")

    def test_certificate_generation_preserves_trust_names_and_private_keys(self):
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from collab.certgen import generate

        with tempfile.TemporaryDirectory() as directory:
            generate(directory, ["localhost", "127.0.0.1", "192.0.2.1"])
            root = Path(directory)
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {"ca.key", "ca.crt", "server.key", "server.crt"},
            )
            ca = x509.load_pem_x509_certificate((root / "ca.crt").read_bytes())
            server = x509.load_pem_x509_certificate((root / "server.crt").read_bytes())
            ca.public_key().verify(
                server.signature,
                server.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server.signature_hash_algorithm,
            )
            self.assertEqual(server.issuer, ca.subject)
            self.assertTrue(
                ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            )
            self.assertFalse(
                server.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value.ca
            )
            sans = server.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertEqual(sans.get_values_for_type(x509.DNSName), ["localhost"])
            self.assertEqual(
                sans.get_values_for_type(x509.IPAddress),
                [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("192.0.2.1")],
            )
            self.assertEqual(
                server.not_valid_after_utc - server.not_valid_before_utc,
                datetime.timedelta(days=90, minutes=5),
            )
            for stem, certificate in (("ca", ca), ("server", server)):
                path = root / f"{stem}.key"
                private_key = serialization.load_pem_private_key(
                    path.read_bytes(), password=None
                )
                self.assertEqual(
                    private_key.public_key().public_numbers(),
                    certificate.public_key().public_numbers(),
                )
                if os.name == "posix":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_certificate_generation_does_not_overwrite_existing_outputs(self):
        from collab.certgen import generate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "server.crt"
            existing.write_bytes(b"existing certificate")
            with self.assertRaisesRegex(ValueError, "already exist"):
                generate(directory, ["localhost"])
            self.assertEqual(existing.read_bytes(), b"existing certificate")
            self.assertEqual(list(root.iterdir()), [existing])
