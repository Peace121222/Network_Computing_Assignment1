"""Wire-format boundaries and rejection of malformed protocol messages."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from collab import common
from collab.transport.security import Channel
from tests.auth_support import Client


class BufferSocket:
    def __init__(self, raw=b"", fragment=2):
        self.stream = io.BytesIO(raw)
        self.fragment = fragment
        self.sent = b""

    def recv(self, size):
        return self.stream.read(min(size, self.fragment))

    def sendall(self, raw):
        self.sent += raw


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.f = Fernet(Fernet.generate_key())
        self.packet = common.data_packet("bob", "chat", "hello")
        self.packet.update({"from": "alice", "token": "a" * 32})
        self.start = common.data_packet(
            "bob",
            "file_start",
            meta={
                "transfer": "b" * 32,
                "filename": "sample.bin",
                "size": 321,
                "count": 2,
                "sha256": hashlib.sha256(b"x" * 321).hexdigest(),
            },
        )
        self.start.update({"from": "alice", "token": "a" * 32})

    def test_tcp_fragmented_frame_and_following_frame(self):
        sock = BufferSocket()
        common.send_tcp(sock, {"type": "login", "name": "alice"})
        common.send_tcp(sock, {"type": "logout"})
        reader = BufferSocket(sock.sent, fragment=1)
        self.assertEqual(common.recv_tcp(reader), {"type": "login", "name": "alice"})
        self.assertEqual(common.recv_tcp(reader), {"type": "logout"})

    def test_tcp_rejects_invalid_length_json_and_non_objects(self):
        for size in (0, common.MAX_FRAME + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                common.recv_tcp(BufferSocket(struct.pack("!I", size)))
        for raw in (b"[]", b"null", b"1", b'"hello"', b"{", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                common.recv_tcp(BufferSocket(struct.pack("!I", len(raw)) + raw))
        with self.assertRaises(ConnectionError):
            common.recv_tcp(BufferSocket(struct.pack("!I", 10) + b"{}"))
        with self.assertRaises(ValueError):
            common.send_tcp(BufferSocket(), [])

    def test_tcp_direction_and_welcome_fields(self):
        common.validate_tcp({"type": "login", "name": "alice"}, from_client=True)
        common.validate_tcp(
            {"type": "welcome", "token": "a" * 32, "udp_port": 9001}, from_client=False
        )
        for msg in (
            {"type": []},
            {"type": "welcome", "token": "x", "udp_port": 9001},
            {"type": "welcome", "token": "a" * 32, "udp_port": True},
            {"type": "welcome", "token": "a" * 32, "udp_port": 65536},
            {"type": "users", "names": ["alice", []]},
            {"type": "login", "name": "alice"},
        ):
            with self.subTest(msg=msg), self.assertRaises(ValueError):
                common.validate_tcp(msg, from_client=False)
        for name in ("", "a" * 25, [], "bad name"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                common.validate_tcp({"type": "login", "name": name}, from_client=True)

    def test_udp_valid_directions_and_encryption(self):
        common.validate_udp(self.packet, from_client=True)
        encoded = common.encode_udp(self.packet, self.f)
        self.assertNotIn(b"hello", encoded)
        self.assertEqual(common.decode_udp(encoded, self.f), self.packet)
        server_packet = {k: v for k, v in self.packet.items() if k != "token"}
        server_packet["meta"] = {
            "sender_session": "c" * 32,
            "channel": "bob",
            "sequence": 1,
        }
        common.validate_udp(server_packet, from_client=False)
        common.validate_udp(
            {"type": "presence", "names": ["alice", "bob"], "revision": 0},
            from_client=False,
        )
        common.validate_udp({"type": "ack", "id": "packet"}, from_client=False)
        with self.assertRaises(ValueError):
            common.validate_udp(self.packet, from_client=False)

    def test_udp_rejects_bad_fields_without_type_errors(self):
        for key, value in (
            ("from", []),
            ("to", {}),
            ("id", []),
            ("id", ""),
            ("id", "x" * 81),
            ("token", None),
            ("type", []),
            ("kind", []),
            ("kind", "file_complete"),
            ("meta", []),
            ("payload", 1),
            ("payload", ""),
        ):
            msg = dict(self.packet, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                common.validate_udp(msg, from_client=True)
        for msg in (None, [], {"type": "presence", "names": []}):
            with self.subTest(msg=msg), self.assertRaises(ValueError):
                common.validate_udp(msg, from_client=True)

    def test_encrypted_size_boundary_and_unicode(self):
        fits, too_large = [], []
        for count in range(1, 1001):
            msg = dict(self.packet, payload="a" * count)
            try:
                common.encode_udp(msg, self.f)
                fits.append(count)
            except ValueError:
                too_large.append(count)
        self.assertTrue(fits)
        self.assertEqual(min(too_large), max(fits) + 1)
        common.encode_udp(dict(self.packet, payload="a" * max(fits)), self.f)
        for text in ("a" * 1000, "界" * 500):
            with self.assertRaisesRegex(ValueError, "1100 bytes"):
                common.encode_udp(dict(self.packet, payload=text), self.f)

    def test_decode_rejects_oversize_invalid_cipher_and_non_objects(self):
        for raw in (
            b"x" * (common.UDP_MTU + 1),
            b"bad cipher",
            self.f.encrypt(b"[]"),
            self.f.encrypt(b"{"),
            self.f.encrypt(b"\xff"),
        ):
            self.assertIsNone(common.decode_udp(raw, self.f))

    def test_file_metadata_boundaries(self):
        common.validate_udp(self.start, from_client=True)
        for size in (0, 1, common.CHUNK, common.CHUNK + 1, common.MAX_FILE_SIZE):
            msg = copy.deepcopy(self.start)
            msg["meta"].update(
                size=size, count=(size + common.CHUNK - 1) // common.CHUNK
            )
            common.validate_udp(msg, from_client=True)
        for field, value in (
            ("size", True),
            ("size", -1),
            ("size", common.MAX_FILE_SIZE + 1),
            ("count", True),
            ("count", 1),
            ("filename", "../x"),
            ("filename", "a\\b"),
            ("filename", "a\x00b"),
            ("filename", "x" * 256),
            ("sha256", "x" * 64),
            ("transfer", []),
        ):
            msg = copy.deepcopy(self.start)
            msg["meta"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                common.validate_udp(msg, from_client=True)
        msg = copy.deepcopy(self.start)
        del msg["meta"]["size"]
        with self.assertRaises(ValueError):
            common.validate_udp(msg, from_client=True)

    def test_chunk_encoding_size_and_index(self):
        chunk = dict(
            self.packet,
            kind="file_chunk",
            payload=common.b64(b"x" * common.CHUNK),
            meta={"transfer": "b" * 32, "index": 0},
        )
        common.validate_udp(chunk, from_client=True)
        for payload in ("", "!!!!", common.b64(b"x" * (common.CHUNK + 1)), "界"):
            with self.subTest(payload=payload[:12]), self.assertRaises(ValueError):
                common.validate_udp(dict(chunk, payload=payload), from_client=True)
        for index in (True, -1, common.MAX_CHUNKS, "0"):
            msg = copy.deepcopy(chunk)
            msg["meta"]["index"] = index
            with self.subTest(index=index), self.assertRaises(ValueError):
                common.validate_udp(msg, from_client=True)

    def test_client_discards_invalid_packets_before_ack_then_accepts_chat(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}),
        ):
            client = Client("bob", download_dir=directory)
            client.token = "b" * 32
            client.address = ("127.0.0.1", 9001)
            valid = {k: v for k, v in self.packet.items() if k != "token"}
            valid["meta"] = {
                "sender_session": "c" * 32,
                "channel": "bob",
                "sequence": 1,
            }
            invalid = dict(valid, id="bad", meta=[])
            wrong_recipient = dict(valid, id="wrong", to="carol")
            sender = Channel(client.f, "a" * 32, server=True)
            client._session = {"udp_security": Channel(client.f, "a" * 32)}
            packets = [
                common.encode_udp(m, client.f, sender)
                for m in (invalid, wrong_recipient, valid)
            ]

            class FakeUDP:
                def __init__(self):
                    self.sent = []

                def recvfrom(self, size):
                    if packets:
                        return packets.pop(0), client.address
                    raise OSError("finished")

                def sendto(self, raw, address):
                    self.sent.append(raw)

            client.udp = FakeUDP()
            client.running.set()
            client.listen()
            client.running.clear()
            acks = [common.decode_udp(raw, client.f) for raw in client.udp.sent]
            self.assertEqual([ack["id"] for ack in acks], [valid["id"]])
            self.assertEqual(client.events.get_nowait()["text"], "hello")
            self.assertNotIn("bad", client.messages_seen)

    def test_receiver_checks_chunk_against_declared_size(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}),
        ):
            client = Client("bob", download_dir=directory)
            client.files[("alice", "b" * 32)] = {"total": 2, "size": 321}
            chunk = dict(
                self.packet,
                kind="file_chunk",
                payload=common.b64(b"x"),
                meta={"transfer": "b" * 32, "index": 1},
            )
            client.validate_transfer_packet(chunk)
            chunk["payload"] = common.b64(b"xx")
            with self.assertRaises(ValueError):
                client.validate_transfer_packet(chunk)
            chunk["meta"]["index"] = 2
            with self.assertRaises(ValueError):
                client.validate_transfer_packet(chunk)

    def test_file_limit_checked_before_reading(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}),
        ):
            client = Client("alice", download_dir=directory)
            client.status = "connected"
            client._session = {"stop": __import__("threading").Event()}
            source = Path(directory) / "large.bin"
            with source.open("wb") as stream:
                stream.truncate(common.MAX_FILE_SIZE + 1)
            with self.assertRaisesRegex(ValueError, "25 MiB"):
                client.file("*", source)
            self.assertEqual(list(client.pending), [])


if __name__ == "__main__":
    unittest.main()
