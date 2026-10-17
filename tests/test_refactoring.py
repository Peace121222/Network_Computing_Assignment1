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
