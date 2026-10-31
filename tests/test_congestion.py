"""Deterministic CUBIC windows, RTT sampling, recovery, and framing boundaries."""

import unittest
from types import SimpleNamespace
from cryptography.fernet import Fernet
from collab.transport.congestion import CubicController
from collab.client.chat_sender import ChatSender
from collab.shared.protocol import data_packet
from collab.transport.security import Channel
from collab.transport.udp import encode_udp, udp_frame_size, validate_udp_size


class CubicTests(unittest.TestCase):
    def setUp(self):
        self.now = [0.0]
        self.cc = CubicController(clock=lambda: self.now[0])

    def test_initial_window_and_ack_growth(self):
        self.assertTrue(self.cc.try_send("a"))
        self.assertTrue(self.cc.try_send("b"))
        self.assertFalse(self.cc.try_send("c"))
        self.now[0] = 0.05
        self.assertTrue(self.cc.acknowledge("a"))
        self.assertEqual(self.cc.cwnd, 3)
        self.assertTrue(self.cc.try_send("c"))
        self.assertFalse(self.cc.acknowledge("unknown"))
        self.assertFalse(self.cc.acknowledge("a"))
        self.assertEqual(self.cc.acked, 1)

    def test_timeout_restarts_and_uses_karn_rtt_rule(self):
        self.cc.try_send("a")
        self.now[0] = 0.24
        self.assertFalse(self.cc.try_send("a"))
        self.now[0] = 0.25
        self.assertTrue(self.cc.try_send("a"))
        self.assertEqual(self.cc.cwnd, 1)
        self.assertEqual(self.cc.ssthresh, 2)
        self.assertEqual(self.cc.timeouts, 1)
        self.now[0] = 0.30
        self.cc.acknowledge("a")
        self.assertIsNone(self.cc.srtt)
        self.assertEqual(self.cc.retransmissions, 1)

    def test_three_later_acks_reduce_window_once(self):
        self.cc.cwnd = self.cc._tokens = 8
        for i in range(5):
            self.assertTrue(self.cc.try_send(str(i)))
        self.now[0] = 0.05
        for i in range(1, 4):
            self.cc.acknowledge(str(i))
        self.assertEqual(self.cc.loss_events, 1)
        self.assertAlmostEqual(self.cc.cwnd, self.cc.ssthresh)
        self.assertTrue(self.cc.retry_due("0", 0.05))
        self.assertTrue(self.cc.try_send("0"))
        self.assertEqual(self.cc.timeouts, 0)

    def test_cubic_epoch_growth_and_window_cap(self):
        self.cc.cwnd = self.cc.ssthresh = 10
        self.cc.w_max = 10
        for i in range(300):
            self.now[0] += 0.1
            self.assertTrue(self.cc.try_send(str(i)))
            self.now[0] += 0.01
            self.cc.acknowledge(str(i))
        self.assertGreater(self.cc.cwnd, 10)
        self.assertLessEqual(self.cc.cwnd, self.cc.max_window)
        self.assertIsNotNone(self.cc.epoch)
        self.assertGreater(self.cc.srtt, 0)

    def test_idle_time_does_not_grow_cubic_epoch(self):
        self.cc.cwnd = self.cc.ssthresh = self.cc.w_max = 10
        self.cc.try_send("a")
        self.now[0] = 0.01
        self.cc.acknowledge("a")
        before = self.cc.cwnd
        self.now[0] = 100
        self.cc.retain([])
        self.cc.try_send("b")
        self.now[0] += 0.01
        self.cc.acknowledge("b")
        self.assertLess(self.cc.cwnd, before + 1)

    def test_cancelled_flights_release_capacity_without_ack_growth(self):
        self.cc.try_send("a")
        self.cc.try_send("b")
        self.cc.retain(["b"])
        self.cc.discard("b")
        self.assertEqual(self.cc.snapshot()["inflight"], 0)
        self.assertEqual(self.cc.acked, 0)
        self.assertEqual(self.cc.cwnd, 2)

    def test_invalid_window_configuration(self):
        for value in (0, 1, -1, True, 2.5):
            with self.assertRaises(ValueError):
                CubicController(max_window=value)

    def test_cubic_curve_can_outgrow_the_reno_estimate(self):
        self.cc.cwnd = self.cc.ssthresh = self.cc.w_max = 10
        self.cc.w_est = 10
        self.cc.cwnd_prior = 10
        self.cc.epoch = 0
        self.cc.try_send("curve")
        self.now[0] = 2
        self.cc.acknowledge("curve")
        self.assertAlmostEqual(self.cc.cwnd, 10.5)
        self.assertGreater(self.cc.cwnd, self.cc.w_est)

    def test_fast_convergence_remembers_a_lower_saturation_point(self):
        self.cc.w_max = 20
        self.cc.cwnd = 10
        with self.cc.lock:
            self.cc._loss(0, timeout=False)
        self.assertAlmostEqual(self.cc.w_max, 8.5)
        self.assertAlmostEqual(self.cc.cwnd, 7)


class FramingRegressionTests(unittest.TestCase):
    def test_chat_boundary_accounts_for_session_prefix_before_sending(self):
        cipher = Fernet(Fernet.generate_key())
        client = SimpleNamespace(
            name="alice", token="a" * 32, names=["alice", "bob"], f=cipher
        )
        packet = data_packet("bob", "chat", "x" * 511)
        with self.assertRaisesRegex(ValueError, "1100 bytes"):
            ChatSender(client)._preflight_chat(packet)
        sender = ChatSender(client)
        sender._preflight_chat(data_packet("bob", "chat", "short message"))

    def test_size_validation_matches_actual_channel_encoding(self):
        cipher = Fernet(Fernet.generate_key())
        for count in range(450, 650):
            message = {"type": "data", "payload": "x" * count, "meta": {}}
            channel = Channel(cipher, "a" * 32)
            if udp_frame_size(message) > 1100:
                with self.assertRaises(ValueError):
                    validate_udp_size(message)
            else:
                validate_udp_size(message)
                self.assertEqual(
                    udp_frame_size(message), len(encode_udp(message, cipher, channel))
                )


class RelayCongestionTests(unittest.TestCase):
    def server(self):
        import threading
        from unittest.mock import Mock
        from collab.server.routing import RelayRouter

        users = {
            name: dict(
                token=name,
                udp_addr=("127.0.0.1", 1000 + i),
                congestion=CubicController(clock=lambda: 0),
            )
            for i, name in enumerate(("alice", "bob", "carol"))
        }
        server = SimpleNamespace(
            lock=threading.RLock(),
            users=users,
            pending={},
            chat_records={},
            file_transfers=Mock(),
            _udp_backoff=Mock(),
            _send_session_udp=Mock(return_value=True),
            _chat_outcome_locked=Mock(),
        )
        server._udp_backoff.ready.return_value = True
        return server, RelayRouter(server)

    def add(
        self, server, identity, destination="bob", kind="chat", attempts=0, retry_time=0
    ):
        server.pending[(destination, identity)] = dict(
            packet={
                "type": "data",
                "id": identity,
                "from": "alice",
                "to": destination,
                "kind": kind,
            },
            source_token="alice",
            destination_token=destination,
            attempts=attempts,
            retry_time=retry_time,
        )

    def test_a_blocked_path_does_not_hide_other_paths_beyond_the_batch_front(self):
        server, router = self.server()
        cc = server.users["bob"]["congestion"]
        for identity in ("held1", "held2"):
            self.assertTrue(cc.try_send(identity, 0))
            self.add(server, identity, attempts=1, retry_time=100)
        for i in range(140):
            self.add(server, f"blocked{i}")
        self.add(server, "other-path", "carol")
        router.retransmit_once(now=0.01)
        self.assertEqual(server.pending[("carol", "other-path")]["attempts"], 1)
        self.assertTrue(
            all(
                server.pending[("bob", f"blocked{i}")]["attempts"] == 0
                for i in range(140)
            )
        )
        self.assertEqual(server._send_session_udp.call_count, 1)

    def test_files_progress_across_small_window_scheduler_passes(self):
        server, router = self.server()
        for i in range(12):
            self.add(server, f"chat{i}")
            self.add(server, f"file{i}", kind="file_end")
        router.retransmit_once(now=0)
        first = [key for key, item in server.pending.items() if item["attempts"]]
        self.assertEqual(len(first), 2)
        for key in first:
            server.users["bob"]["congestion"].acknowledge(key[1], now=0.01)
            del server.pending[key]
        router.retransmit_once(now=0.1)
        self.assertTrue(
            any(
                item["attempts"] and item["packet"]["kind"] == "file_end"
                for item in server.pending.values()
            )
        )
