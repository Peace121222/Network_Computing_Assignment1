"""CUBIC congestion control for reliable application datagrams on one UDP path.

The window follows RFC 9438 with C=0.4, beta=0.7, Reno-friendly growth, fast
convergence, Reno slow start, and timeout restart. Datagram ACKs replace TCP ACKs;
ECN, TCP recovery, HyStart++, and spurious-loss undo are not implemented. A bounded
token bucket smooths sends, allowing at most one congestion window per burst.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import threading
import time
from collections.abc import Callable, Iterable


@dataclass
class _Flight:
    serial: int
    sent_at: float
    attempts: int = 1
    later_acks: int = 0
    lost: bool = False


class CubicController:
    """Own bounded congestion and RTT state shared by data senders on one path.

    Args:
        max_window: Hard datagram flight limit, independent of application queues.
        clock: Monotonic clock in seconds; injectable for deterministic tests.

    Control ACKs, path checks, and heartbeats bypass this data controller. Packet
    identities must be unique within the active path/session. Methods serialize
    state access internally; they never sleep or acquire application locks.
    """

    C = 0.4
    BETA = 0.7
    ALPHA = 3 * (1 - BETA) / (1 + BETA)

    def __init__(
        self, max_window: int = 128, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if type(max_window) is not int or max_window < 2:
            raise ValueError("Congestion window limit must be an integer of at least 2")
        self.max_window = max_window
        self.clock = clock
        self.lock = threading.RLock()
        self.cwnd = 2.0
        self.ssthresh = float(max_window)
        self.w_max = 0.0
        self.cwnd_prior = self.cwnd
        self.w_est = self.cwnd
        self.epoch = None
        self.epoch_window = self.cwnd
        self.k = 0.0
        self.srtt = None
        self.rttvar = None
        self.rto = 0.25
        self._serial = 0
        self._flights: dict[str, _Flight] = {}
        self._tokens = self.cwnd
        self._refilled = clock()
        self._idle_since = self._refilled
        self._recovery_until = float("-inf")
        self.sent = 0
        self.acked = 0
        self.loss_events = 0
        self.timeouts = 0
        self.retransmissions = 0
        self.peak_inflight = 0

    def _refill(self, now):
        interval = max(self.srtt or 0.01, 0.001)
        self._tokens = min(
            self.cwnd,
            self._tokens + max(0, now - self._refilled) * self.cwnd / interval,
        )
        self._refilled = now

    def _loss(self, now, timeout):
        prior = self.cwnd
        self.cwnd_prior = prior
        self.w_max = prior * (1 + self.BETA) / 2 if prior < self.w_max else prior
        self.ssthresh = max(2.0, prior * self.BETA)
        self.cwnd = 1.0 if timeout else self.ssthresh
        self.w_est = self.cwnd
        self.epoch = None
        self._tokens = min(self._tokens, self.cwnd)
        self.loss_events += 1
        self._recovery_until = now + max(
            self.srtt or 0.01, self.rto if timeout else 0.0
        )
        if timeout:
            self.timeouts += 1
            self.rto = min(2.0, self.rto * 2)

    def is_lost(self, packet_id: str) -> bool:
        """Report whether later ACKs have marked a flight for fast retransmission."""
        with self.lock:
            flight = self._flights.get(packet_id)
            return flight is not None and flight.lost

    def retry_due(self, packet_id: str, now: float, minimum: float = 0.25) -> bool:
        """Check whether a flight is fast-loss-marked or its retry timer expired."""
        with self.lock:
            flight = self._flights.get(packet_id)
            return (
                flight is None
                or flight.lost
                or now - flight.sent_at >= max(minimum, self.rto)
            )

    def try_send(
        self, packet_id: str, now: float | None = None, minimum_retry: float = 0.25
    ) -> bool:
        """Reserve flight and pacing capacity before a datagram is sent.

        Returns:
            True if reserved; False when the congestion window, retry timer, or
            pacing budget requires the caller to try again later without sleeping.
        """
        now = self.clock() if now is None else now
        with self.lock:
            self._refill(now)
            flight = self._flights.get(packet_id)
            if flight is not None:
                if not flight.lost and now - flight.sent_at < max(
                    minimum_retry, self.rto
                ):
                    return False
                if not flight.lost and now >= self._recovery_until:
                    self._loss(now, timeout=True)
            elif len(self._flights) >= max(1, math.floor(self.cwnd)):
                return False
            if self._tokens < 1:
                return False
            if not self._flights:
                if self.epoch is not None:
                    self.epoch += max(0, now - self._idle_since)
            self._tokens -= 1
            self.sent += 1
            if flight is None:
                self._serial += 1
                self._flights[packet_id] = _Flight(self._serial, now)
            else:
                flight.sent_at = now
                flight.attempts += 1
                flight.lost = False
                flight.later_acks = 0
                self.retransmissions += 1
            self.peak_inflight = max(self.peak_inflight, len(self._flights))
            return True

    def acknowledge(self, packet_id: str, now: float | None = None) -> bool:
        """Release one flight, update RTT for first sends, and grow the window.

        Duplicate/unknown ACKs have no effect. Retransmitted packets do not supply
        RTT samples (Karn's rule). Three later ACKs mark an earlier flight lost.
        """
        now = self.clock() if now is None else now
        with self.lock:
            self._refill(now)
            flight = self._flights.pop(packet_id, None)
            if flight is None:
                return False
            self.acked += 1
            if flight.attempts == 1:
                sample = max(0.001, now - flight.sent_at)
                if self.srtt is None:
                    self.srtt, self.rttvar = sample, sample / 2
                else:
                    self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                    self.srtt = 0.875 * self.srtt + 0.125 * sample
                self.rto = min(2.0, max(0.05, self.srtt + 4 * self.rttvar))
            for older in self._flights.values():
                if older.serial < flight.serial and not older.lost:
                    older.later_acks += 1
                    if older.later_acks >= 3:
                        older.lost = True
                        if now >= self._recovery_until:
                            self._loss(now, timeout=False)
            if now >= self._recovery_until:
                if self.cwnd < self.ssthresh:
                    self.cwnd += 1
                else:
                    if self.epoch is None:
                        self.epoch = now
                        self.epoch_window = self.cwnd
                        if self.w_max == 0:
                            self.w_max = self.cwnd
                            self.cwnd_prior = self.cwnd
                        self.w_est = self.cwnd
                        self.k = (max(0, self.w_max - self.cwnd) / self.C) ** (1 / 3)
                    elapsed = max(0, now - self.epoch)
                    target = (
                        self.C * (elapsed + (self.srtt or 0.01) - self.k) ** 3
                        + self.w_max
                    )
                    target = min(1.5 * self.cwnd, max(self.cwnd, target))
                    alpha = 1.0 if self.w_est >= self.cwnd_prior else self.ALPHA
                    self.w_est += alpha / self.cwnd
                    self.cwnd = max(
                        self.w_est, self.cwnd + (target - self.cwnd) / self.cwnd
                    )
                self.cwnd = min(float(self.max_window), self.cwnd)
            if not self._flights:
                self._idle_since = now
            return True

    def discard(self, packet_id: str) -> None:
        """Release cancelled work without treating cancellation as a successful ACK."""
        with self.lock:
            had_flights = bool(self._flights)
            self._flights.pop(packet_id, None)
            if had_flights and not self._flights:
                self._idle_since = self.clock()

    def retain(self, packet_ids: Iterable[str]) -> None:
        """Drop flight references for work cancelled by the owning application's queue."""
        with self.lock:
            had_flights = bool(self._flights)
            allowed = set(packet_ids)
            for packet_id in list(self._flights):
                if packet_id not in allowed:
                    del self._flights[packet_id]
            if had_flights and not self._flights:
                self._idle_since = self.clock()

    def snapshot(self) -> dict[str, float | int | None]:
        """Return non-secret diagnostic counters without exposing packet payloads."""
        with self.lock:
            return dict(
                cwnd=self.cwnd,
                ssthresh=self.ssthresh,
                rtt=self.srtt,
                rto=self.rto,
                inflight=len(self._flights),
                peak_inflight=self.peak_inflight,
                sent=self.sent,
                acked=self.acked,
                loss_events=self.loss_events,
                timeouts=self.timeouts,
                retransmissions=self.retransmissions,
            )
