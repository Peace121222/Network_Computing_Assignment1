"""Authenticated transport, replay windows, handshake and UDP path validation."""

import base64
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from tests.auth_support import Client
from tests.auth_support import Server
from collab.transport.security import (
    Channel,
    HEADER,
    VERSION,
    ZERO_CONTEXT,
    C2S,
    S2C,
    REPLAY_WINDOW,
    MAX_SEQUENCE,
    seal,
    unseal,
)
from collab.transport.tcp import TCPReader, frame_tcp, send_tcp
from collab.transport.udp import cipher, encode_udp, decode_udp, udp_frame_size
from collab.transport.handshake import client_login
from tests.auth_support import tls_connection, PASSWORD, client_login as fixture_login
from tests.stream_support import Stream, LoginStream, frame


def wait(test, predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        threading.Event().wait(0.005)
    test.fail("Security state did not converge")


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.f = Fernet(Fernet.generate_key())
        self.sender = Channel(self.f, "a" * 32)
        self.receiver = Channel(self.f, "a" * 32, server=True)

    def test_udp_replay_and_out_of_order(self):
        packets = [self.sender.encode({"n": n}) for n in range(4)]
        for n in (3, 1, 0, 2):
            self.assertEqual(self.receiver.decode(packets[n]), {"n": n})
        for raw in packets:
            with self.assertRaises(ValueError):
                self.receiver.decode(raw)

    def test_window_boundary_and_memory_bound(self):
        old = self.sender.encode({"n": 1})
        self.sender.sent = REPLAY_WINDOW
        latest = self.sender.encode({"n": REPLAY_WINDOW + 1})
        self.receiver.decode(latest)
        with self.assertRaises(ValueError):
            self.receiver.decode(old)
        self.assertLessEqual(self.receiver.bitmap.bit_length(), REPLAY_WINDOW)
        boundary = seal({"n": 2}, self.f, "a" * 32, C2S, 2)
        self.assertEqual(self.receiver.decode(boundary), {"n": 2})
        self.assertEqual(self.receiver.bitmap.bit_length(), REPLAY_WINDOW)

    def test_wrong_session_direction_and_transport_do_not_advance_window(self):
        for source in (
            Channel(self.f, "b" * 32),
            Channel(self.f, "a" * 32, server=True),
            Channel(self.f, "a" * 32, ordered=True),
        ):
            with self.assertRaises(ValueError):
                self.receiver.decode(source.encode({"type": "heartbeat"}))
        self.assertEqual(self.receiver.highest, 0)
        self.receiver.decode(self.sender.encode({"type": "heartbeat"}))

    def test_tcp_requires_exact_sequence(self):
        sender = Channel(self.f, "a" * 32, ordered=True)
        receiver = Channel(self.f, "a" * 32, server=True, ordered=True)
        first, second = sender.encode({}), sender.encode({})
        with self.assertRaises(ValueError):
            receiver.decode(second)
        self.assertEqual(receiver.highest, 0)
        receiver.decode(first)
        with self.assertRaises(ValueError):
            receiver.decode(first)
        receiver.decode(second)

    def test_tampering_wrong_key_and_bad_envelopes(self):
        good = self.sender.encode({"type": "heartbeat"})
        binary = bytearray(base64.urlsafe_b64decode(good))
        binary[-1] ^= 1
        malformed = [
            base64.urlsafe_b64encode(binary),
            Fernet(Fernet.generate_key()).encrypt(b"bad"),
            self.f.encrypt(b"{}"),
            b"not-fernet",
        ]
        for version, direction, transport, sequence in (
            (2, C2S, 2, 1),
            (VERSION, 3, 2, 1),
            (VERSION, C2S, 0, 1),
            (VERSION, C2S, 2, 0),
        ):
            malformed.append(
                self.f.encrypt(
                    HEADER.pack(
                        version, bytes.fromhex("a" * 32), direction, transport, sequence
                    )
                    + b"{}"
                )
            )
        for raw in malformed:
            with self.assertRaises(ValueError):
                self.receiver.decode(raw)
        self.assertEqual(self.receiver.highest, 0)

    def test_retry_has_new_security_sequence_same_application_id(self):
        message = {"type": "ack", "id": "original"}
        first, retry = self.sender.encode(message), self.sender.encode(message)
        self.assertNotEqual(first, retry)
        self.assertEqual(unseal(first, self.f)[2], 1)
        self.assertEqual(unseal(retry, self.f)[2], 2)
        self.assertEqual(self.receiver.decode(first), self.receiver.decode(retry))

    def test_sequence_exhaustion_is_explicit(self):
        self.sender.sent = MAX_SEQUENCE
        with self.assertRaisesRegex(ValueError, "exhausted"):
            self.sender.encode({})

    def test_ciphertext_size_estimate_includes_security_header(self):
        for size in range(700):
            message = {"payload": "界" * (size // 3)}
            try:
                raw = encode_udp(message, self.f, self.sender)
            except ValueError:
                self.assertGreater(udp_frame_size(message), 1100)
            else:
                self.assertEqual(udp_frame_size(message), len(raw))
                self.assertLessEqual(len(raw), 1100)

    def test_tcp_ciphertext_hides_fields_and_resumes_fragmented_frames(self):
        sender = Channel(self.f, "a" * 32, server=True, ordered=True)
        receiver = Channel(self.f, "a" * 32, ordered=True)
        message = {
            "type": "welcome",
            "token": "secret-session-token",
            "name": "private-nickname",
        }
        first, second = frame_tcp(message, sender), frame_tcp({"type": "users"}, sender)
        self.assertNotIn(b"secret-session-token", first)
        self.assertNotIn(b"private-nickname", first)
        reader = TCPReader(
            Stream(
                [
                    first[:2],
                    socket.timeout(),
                    first[2:9],
                    socket.timeout(),
                    first[9:] + second,
                ]
            ),
            receiver,
        )
        for _ in range(2):
            with self.assertRaises(TimeoutError):
                reader.read()
        self.assertEqual(reader.read(), message)
        self.assertEqual(reader.read(), {"type": "users"})

    def test_tcp_rejects_plaintext_and_excessive_encrypted_length(self):
        for raw in (frame({"type": "hello"}), struct.pack("!I", 3_000_000)):
            reader = TCPReader(
                Stream([raw]), Channel(self.f, ZERO_CONTEXT, server=True, ordered=True)
            )
            with self.assertRaises(ValueError):
                reader.read()
            with self.assertRaises(ConnectionError):
                reader.read()

    def test_encrypted_handshake_keeps_one_total_deadline(self):
        with patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}):
            stream = LoginStream(
                [frame(dict(type="welcome", token="a" * 32, udp_port=9001))]
            )
            ticks = iter(10 + n / 10 for n in range(30))
            with patch(
                "collab.transport.tcp.time.monotonic", side_effect=lambda: next(ticks)
            ):
                with self.assertRaises(TimeoutError):
                    client_login(stream, "alice", PASSWORD, 10.15)
            self.assertTrue(stream.timeouts)
            self.assertTrue(
                all(a >= b for a, b in zip(stream.timeouts, stream.timeouts[1:]))
            )

    def test_legacy_group_key_is_not_an_authentication_requirement(self):
        for value in ("", "invalid", Fernet.generate_key().decode()):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"COLLAB_KEY": value}),
            ):
                client = Client("alice")
                self.assertEqual(client.status, "disconnected")
                client.close()
                server = Server()
                self.assertFalse(server.users)
                server.close()


class PathTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.server = Server()
        self.server.udp = Mock()
        self.sender = Channel(self.server.f, "a" * 32)
        self.user = dict(
            token="b" * 32,
            udp_security=Channel(self.server.f, "a" * 32, server=True),
            ready=True,
            udp_addr=("127.0.0.1", 1000),
            last_seen=100,
            sock=Mock(),
            udp_lock=threading.RLock(),
        )
        self.server.users["alice"] = self.user
        self.packet = dict(type="heartbeat", **{"from": "alice", "token": "b" * 32})
        self.old, self.new = self.user["udp_addr"], ("127.0.0.1", 2000)

    def receive(self, message=None, *, now=101, address=None, raw=None):
        if raw is None:
            raw = encode_udp(message or self.packet, self.server.f, self.sender)
        with patch("collab.server.core.time.monotonic", return_value=now):
            self.server.handle_udp(raw, address or self.old)
        return raw

    def test_replayed_heartbeat_cannot_move_endpoint_or_extend_liveness(self):
        raw = self.receive()
        self.receive(raw=raw, now=105, address=self.new)
        self.assertEqual(self.user["last_seen"], 101)
        self.assertEqual(self.user["udp_addr"], self.old)
        self.assertNotIn("udp_candidate", self.user)

    def test_ack_replay_does_not_remove_pending_or_refresh_session(self):
        message = dict(self.packet, type="ack", id="relay")
        raw = self.receive(message)
        key = ("alice", "relay")
        self.server.pending[key] = dict(destination_token=self.user["token"])
        self.receive(raw=raw, now=105)
        self.assertIn(key, self.server.pending)
        self.assertEqual(self.user["last_seen"], 101)
        self.receive(message, now=106)
        self.assertNotIn(key, self.server.pending)
        self.assertEqual(self.user["last_seen"], 106)

    def test_candidate_does_not_disrupt_current_path_or_ack_candidate_data(self):
        self.receive(address=self.new)
        self.receive(now=102)
        self.assertEqual(self.user["last_seen"], 102)
        self.assertEqual(self.user["udp_addr"], self.old)
        self.server.udp.reset_mock()
        message = dict(
            self.packet,
            type="data",
            id="chat",
            to="bob",
            kind="chat",
            payload="hello",
            meta={},
        )
        self.receive(message, address=self.new, now=102.1)
        self.assertEqual(self.server.pending, {})
        self.assertEqual(self.server.chat_records, {})
        sent = [
            decode_udp(call.args[0], self.server.f)
            for call in self.server.udp.sendto.call_args_list
        ]
        self.assertFalse(any(msg["type"] == "ack" for msg in sent))
        self.assertEqual(self.user["last_seen"], 102)

    def test_malformed_schema_does_not_consume_replay_sequence(self):
        raw = seal(dict(self.packet, token="invalid"), self.server.f, "a" * 32, C2S, 1)
        self.receive(raw=raw)
        self.assertEqual(self.user["udp_security"].highest, 0)
        self.receive()
        self.assertEqual(self.user["last_seen"], 101)

    def test_wrong_context_token_and_ciphertext_have_no_effect(self):
        packets = [
            encode_udp(dict(self.packet, token="c" * 32), self.server.f, self.sender),
            Channel(self.server.f, "c" * 32).encode(self.packet),
            b"invalid",
            b"x" * 1101,
        ]
        for raw in packets:
            self.receive(raw=raw, address=self.new)
        self.assertEqual(self.user["last_seen"], 100)
        self.assertEqual(self.user["udp_security"].highest, 0)
        self.server.udp.sendto.assert_not_called()

    def test_endpoint_requires_response_and_does_not_refresh_activity(self):
        self.receive(address=self.new)
        challenge = decode_udp(self.server.udp.sendto.call_args.args[0], self.server.f)
        self.assertEqual(challenge["type"], "path_challenge")
        self.assertEqual(self.user["udp_addr"], self.old)
        response = dict(self.packet, type="path_response", nonce=challenge["nonce"])
        self.receive(response, address=self.new, now=102)
        self.assertEqual(self.user["udp_addr"], self.new)
        self.assertEqual(self.user["last_seen"], 100)
        self.receive(now=103, address=self.new)
        self.assertEqual(self.user["last_seen"], 103)
        self.assertEqual(self.server.revision, 0)

    def test_wrong_expired_and_replayed_response_cannot_rebind(self):
        self.receive(address=self.new)
        response = dict(
            self.packet, type="path_response", nonce=self.user["udp_candidate"]["nonce"]
        )
        self.receive(dict(response, nonce="f" * 64), address=self.new)
        self.receive(response, address=self.old)
        self.receive(response, address=self.new, now=103)
        self.assertEqual(self.user["udp_addr"], self.old)
        self.receive(address=self.new, now=104)
        response["nonce"] = self.user["udp_candidate"]["nonce"]
        raw = self.receive(response, address=self.new, now=104.1)
        self.receive(raw=raw, address=self.old, now=104.2)
        self.assertEqual(self.user["udp_addr"], self.new)
        self.assertEqual(self.user["last_seen"], 100)

    def test_challenge_rate_limit_recovery_and_single_candidate(self):
        self.receive(address=self.new)
        first = self.user["udp_candidate"]["nonce"]
        self.receive(address=("127.0.0.1", 3000), now=101.49)
        self.assertEqual(self.server.udp.sendto.call_count, 1)
        self.assertEqual(self.user["udp_candidate"]["addr"], self.new)
        self.receive(address=self.new, now=101.5)
        self.assertEqual(self.server.udp.sendto.call_count, 2)
        self.assertNotEqual(self.user["udp_candidate"]["nonce"], first)
        self.assertEqual(self.user["last_seen"], 100)

    def test_path_messages_cannot_revive_expired_session(self):
        self.receive(address=self.new)
        response = dict(
            self.packet, type="path_response", nonce=self.user["udp_candidate"]["nonce"]
        )
        self.receive(response, address=self.new, now=110)
        self.assertNotIn("alice", self.server.users)
        self.user["sock"].close.assert_called_once()

    def test_broadcast_envelopes_are_bound_to_each_recipient(self):
        other = dict(
            self.user,
            token="c" * 32,
            udp_security=Channel(self.server.f, "c" * 32, server=True),
            udp_addr=("127.0.0.1", 3000),
            udp_lock=threading.RLock(),
        )
        self.server.users["bob"] = other
        message = dict(type="presence", names=["alice", "bob"], revision=1)
        self.server._send_session_udp(message, [("alice", self.user)])
        self.server._send_session_udp(message, [("bob", other)])
        raw_a, raw_b = [call.args[0] for call in self.server.udp.sendto.call_args_list]
        self.assertEqual(unseal(raw_a, self.server.f)[0], "a" * 32)
        self.assertEqual(unseal(raw_b, self.server.f)[0], "c" * 32)
        with self.assertRaises(ValueError):
            Channel(self.server.f, "a" * 32).decode(raw_b)


class SecurityNetworkTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.server = Server("127.0.0.1", 0, 0)
        self.server.start()
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.close()
        self.temp.cleanup()
        self.env.stop()

    def client(self, name):
        client = Client(
            name, port=self.server.tcp_port, download_dir=Path(self.temp.name) / name
        )
        self.clients.append(client)
        client.connect()
        wait(
            self,
            lambda: name in self.server.users
            and self.server.users[name]["udp_addr"] is not None,
        )
        return client

    def test_plaintext_and_wrong_key_cannot_register_user(self):
        for raw in (
            frame({"type": "login", "name": "intruder"}),
            frame_tcp(
                {"type": "hello", "client_nonce": "a" * 64},
                Channel(Fernet(Fernet.generate_key()), ZERO_CONTEXT, ordered=True),
            ),
        ):
            with socket.create_connection(
                ("127.0.0.1", self.server.tcp_port), timeout=1
            ) as sock:
                sock.sendall(raw)
                self.assertEqual(sock.recv(1), b"")
        self.assertEqual(self.server.users, {})
        self.assertEqual(self.server.status, "running")

    def test_old_tcp_envelope_fails_fresh_authenticated_session(self):
        client = self.client("alice")
        old = frame_tcp({"type": "users"}, client._session["tcp_security"])
        client.close()
        wait(self, lambda: not self.server.users)
        client.connect()
        with client._session["tcp_send_lock"]:
            client.tcp.sendall(old)
        wait(self, lambda: client.status == "disconnected")
        wait(self, lambda: not self.server.users and not self.server.connections)

    def test_duplicate_tcp_control_closes_only_corresponding_session(self):
        a, b = self.client("alice"), self.client("bob")
        channel = a._session["tcp_security"]
        with a._session["tcp_send_lock"]:
            raw = frame_tcp({"type": "users"}, channel)
            a.tcp.sendall(raw + raw)
        wait(self, lambda: a.status == "disconnected")
        self.assertEqual(b.status, "connected")
        self.assertEqual(self.server.status, "running")

    def test_wrong_udp_peer_and_presence_replay_are_ignored(self):
        client = self.client("alice")
        wait(self, lambda: client.names == ["alice"])
        user = self.server.users["alice"]
        spoof = dict(type="presence", names=["ghost"], revision=1_000_000)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
            raw = encode_udp(spoof, self.server.f, user["udp_security"])
            attacker.sendto(raw, ("127.0.0.1", client.udp.getsockname()[1]))
        client.send_raw({"type": "heartbeat"})
        wait(
            self,
            lambda: client._session["udp_security"].highest > unseal(raw, client.f)[2],
        )
        self.assertEqual(client.names, ["alice"])
        self.assertLess(client.presence_revision, 1_000_000)
        # Deliver an authentic snapshot, then replay it after a newer one.
        old = encode_udp(dict(spoof, revision=100), self.server.f, user["udp_security"])
        self.server.udp.sendto(old, user["udp_addr"])
        wait(self, lambda: client.presence_revision == 100)
        before = sum(e.get("revision") == 100 for e in list(client.events.queue))
        self.server.udp.sendto(old, user["udp_addr"])
        self.server._send_session_udp(
            dict(type="ack", id="replay-barrier"), [("alice", user)]
        )
        sequence = user["udp_security"].sent
        wait(self, lambda: client._session["udp_security"].highest >= sequence)
        self.assertEqual(
            sum(e.get("revision") == 100 for e in list(client.events.queue)), before
        )
        self.server._send_session_udp(
            dict(type="presence", names=["alice"], revision=101), [("alice", user)]
        )
        wait(self, lambda: client.presence_revision == 101)
        self.server.udp.sendto(old, user["udp_addr"])
        client.send_raw({"type": "heartbeat"})
        self.assertEqual(client.names, ["alice"])

    def test_oversize_authenticated_udp_is_ignored_by_client(self):
        client = self.client("alice")
        wait(self, lambda: client.names == ["alice"])
        user = self.server.users["alice"]
        raw = user["udp_security"].encode(
            dict(
                type="presence", names=["u" + str(i) for i in range(200)], revision=9999
            )
        )
        self.assertGreater(len(raw), 1100)
        self.assertLess(len(raw), 4096)
        self.server.udp.sendto(raw, user["udp_addr"])
        self.server._send_session_udp(dict(type="ack", id="barrier"), [("alice", user)])
        sequence = user["udp_security"].sent
        wait(self, lambda: client._session["udp_security"].highest >= sequence)
        self.assertEqual(client.names, ["alice"])
        self.assertLess(client.presence_revision, 9999)

    def test_handshake_message_after_login_closes_only_that_session(self):
        healthy = self.client("healthy")
        with tls_connection(("127.0.0.1", self.server.tcp_port), timeout=1) as sock:
            _, reader = fixture_login(
                sock, "invalid_phase", self.server.f, time.monotonic() + 1
            )
            send_tcp(
                sock,
                dict(type="hello", client_nonce="a" * 64),
                security=reader.security,
            )
            self.assertEqual(sock.recv(1), b"")
        wait(self, lambda: "invalid_phase" not in self.server.users)
        self.assertEqual(healthy.status, "connected")
        self.assertEqual(self.server.status, "running")

    def test_old_session_ciphertext_cannot_change_reconnected_session(self):
        client = self.client("alice")
        old_context = client._session["udp_security"].context
        raw = encode_udp(
            dict(type="heartbeat", **{"from": "alice", "token": client.token}),
            self.server.f,
            client._session["udp_security"],
        )
        client.close()
        wait(self, lambda: "alice" not in self.server.users)
        client.connect()
        wait(
            self, lambda: self.server.users.get("alice", {}).get("udp_addr") is not None
        )
        self.assertNotEqual(client._session["udp_security"].context, old_context)
        user = self.server.users["alice"]
        before = user["last_seen"]
        self.server.handle_udp(raw, ("127.0.0.1", 1234))
        self.assertEqual(user["last_seen"], before)
        self.assertEqual(client.status, "connected")

    def test_connection_with_wrong_password_rolls_back_resources(self):
        client = Client(
            "wrong",
            port=self.server.tcp_port,
            download_dir=Path(self.temp.name) / "wrong",
        )
        self.clients.append(client)
        client.f = Fernet(Fernet.generate_key())
        with self.assertRaisesRegex(RuntimeError, "Invalid username or password"):
            client.connect("wrong password")
        self.assertEqual(client.status, "disconnected")
        self.assertIsNone(client.token)
        self.assertIsNone(client.tcp)
        self.assertIsNone(client.udp)
        self.assertFalse(any(t.is_alive() for t in client.threads))
        wait(self, lambda: not self.server.connections and not self.server.users)

    def test_welcome_without_session_key_cannot_complete_handshake(self):
        stream = Stream(
            [
                frame(
                    dict(
                        type="welcome", token="a" * 32, udp_port=9001, session="b" * 32
                    )
                )
            ]
        )
        with self.assertRaises(ValueError):
            client_login(stream, "alice", PASSWORD, time.monotonic() + 1)


if __name__ == "__main__":
    unittest.main()
