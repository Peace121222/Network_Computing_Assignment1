"""Simplified Application-level CUBIC Congestion Control over UDP."""

import math
import time
from collections import OrderedDict
from typing import Any

# CUBIC Constants
CUBIC_C = 0.4
CUBIC_BETA = 0.7
MIN_WINDOW = 2
MAX_WINDOW = 128
INITIAL_RTO = 1.0
MIN_RTO = 0.2
MAX_RTO = 10.0

class CubicController:
    """Manages UDP packet pacing using simplified CUBIC and RTT tracking."""
    
    def __init__(self) -> None:
        self.cwnd = float(MIN_WINDOW)
        self.ssthresh = float(MAX_WINDOW)
        self.w_max = 0.0
        self.epoch_start = 0.0
        self.origin_point = 0.0
        self.d_min = 0.0
        
        self.srtt = 0.0
        self.rttvar = 0.0
        self.rto = INITIAL_RTO
        
        self.inflight = OrderedDict()
        
    def _update_cubic(self, now: float) -> None:
        """Update cwnd using CUBIC growth function."""
        if self.epoch_start == 0:
            self.epoch_start = now
            if self.cwnd < self.w_max:
                self.origin_point = self.w_max
                self.d_min = (self.w_max - self.cwnd) / CUBIC_C
                self.d_min = math.pow(self.d_min, 1.0/3.0)
            else:
                self.origin_point = self.cwnd
                self.d_min = 0.0
                
        t = now - self.epoch_start
        target = self.origin_point + CUBIC_C * math.pow(t - self.d_min, 3.0)
        
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0 # Slow start (Reno-style)
        else:
            self.cwnd += (target - self.cwnd) / self.cwnd # CUBIC growth
            
        self.cwnd = max(MIN_WINDOW, min(self.cwnd, MAX_WINDOW))

    def acknowledge(self, packet_id: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        if packet_id in self.inflight:
            sent_time = self.inflight.pop(packet_id)
            rtt = now - sent_time
            if rtt > 0:
                if self.srtt == 0:
                    self.srtt = rtt
                    self.rttvar = rtt / 2
                else:
                    self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - rtt)
                    self.srtt = 0.875 * self.srtt + 0.125 * rtt
                self.rto = max(MIN_RTO, min(self.srtt + max(0.01, 4 * self.rttvar), MAX_RTO))
            
            self._update_cubic(now)

    def try_send(self, packet_id: str, minimum_retry: float | None = None) -> bool:
        """Check if cwnd allows sending another packet."""
        now = time.monotonic()
        if len(self.inflight) >= int(self.cwnd):
            return False
            
        self.inflight[packet_id] = now
        return True

    def retry_due(self, packet_id: str, now: float, minimum_retry: float | None = None) -> bool:
        """Check if a packet needs retransmission based on RTO."""
        sent_time = self.inflight.get(packet_id)
        if sent_time is None:
            return True
        timeout = self.rto if minimum_retry is None else max(self.rto, minimum_retry)
        if now - sent_time >= timeout:
            self.inflight.pop(packet_id, None)
            # Packet loss detected: reduce window
            self.epoch_start = 0
            self.w_max = self.cwnd
            self.ssthresh = max(MIN_WINDOW, self.cwnd * CUBIC_BETA)
            self.cwnd = self.ssthresh
            return True
        return False

    def discard(self, packet_id: str) -> None:
        self.inflight.pop(packet_id, None)