"""Interruptible retry delays and best-effort cleanup with collected errors."""

import errno
import logging
import time

RETRYABLE = frozenset({errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK})
UDP_PEER_ERRORS = frozenset({errno.ECONNRESET, errno.ECONNREFUSED, 10054, 10061})


def retryable(error, *, udp=False):
    code = error.errno if error.errno is not None else getattr(error, "winerror", None)
    return code in RETRYABLE or (udp and code in UDP_PEER_ERRORS)


class RetryDelay:
    def __init__(self, stop, logger, operation, *, log_errors=True):
        self.stop, self.logger, self.operation = stop, logger, operation
        self.delay = 0.05
        self.log_errors = log_errors
        self.logged = {}

    def reset(self):
        self.delay = 0.05

    def wait(self, error):
        now = time.monotonic()
        key = (type(error).__name__, error.errno)
        if self.log_errors and now - self.logged.get(key, float("-inf")) >= 1:
            self.logger.warning("%s: %s; retrying", self.operation, error)
            self.logged[key] = now
        stopped = self.stop.wait(self.delay)
        self.delay = min(1, self.delay * 2)
        return stopped


class Cleanup:
    def __init__(self):
        self.errors = []

    def attempt(self, label, action, *args, **kwargs):
        try:
            return action(*args, **kwargs)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "Cleanup %s failed: %s", label, exc, exc_info=True
            )
            self.errors.append((label, exc))

    def finish(self, message):
        if self.errors:
            detail = "; ".join(f"{label}: {error}" for label, error in self.errors)
            raise RuntimeError(message + ": " + detail) from self.errors[0][1]


class SendBackoff:
    """Rate-limit a shared UDP socket without sleeping under session/state locks."""

    def __init__(self, logger):
        import threading

        self.lock = threading.Lock()
        self.logger = logger
        self.until = 0
        self.delay = 0.05
        self.logged = {}

    def ready(self):
        with self.lock:
            return time.monotonic() >= self.until

    def reset(self):
        with self.lock:
            self.until = 0
            self.delay = 0.05

    def failed(self, error):
        with self.lock:
            now = time.monotonic()
            self.until = now + self.delay
            self.delay = min(1, self.delay * 2)
            key = (type(error).__name__, error.errno)
            if now - self.logged.get(key, float("-inf")) >= 1:
                self.logger.warning("UDP send: %s; retrying", error)
                self.logged[key] = now
