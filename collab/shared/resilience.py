"""Interruptible retry delays and best-effort cleanup with collected errors."""

import errno
import logging
import time

RETRYABLE = frozenset({errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK})
UDP_PEER_ERRORS = frozenset({errno.ECONNRESET, errno.ECONNREFUSED, 10054, 10061})


def retryable(error, *, udp=False):
    """Classify socket errors eligible for the existing retry policy.

    Args:
        error: Socket error exposing errno and optionally a Windows error code.
        udp: Whether UDP-specific peer reset/refusal errors may also be retried.

    Returns:
        True for a retryable error code; False otherwise.
    """
    code = error.errno if error.errno is not None else getattr(error, "winerror", None)
    return code in RETRYABLE or (udp and code in UDP_PEER_ERRORS)


class RetryDelay:
    """Track interruptible exponential retry delays and rate-limited warnings."""

    def __init__(self, stop, logger, operation, *, log_errors=True):
        self.stop, self.logger, self.operation = stop, logger, operation
        self.delay = 0.05
        self.log_errors = log_errors
        self.logged = {}

    def reset(self):
        self.delay = 0.05

    def wait(self, error):
        """Wait for the current retry delay, stopping early if cancellation is signalled.

        Args:
            error: Socket error used to group and rate-limit warnings.

        Returns:
            The stop event's wait result. The next delay doubles, capped at one second.
        """
        now = time.monotonic()
        key = (type(error).__name__, error.errno)
        if self.log_errors and now - self.logged.get(key, float("-inf")) >= 1:
            self.logger.warning("%s: %s; retrying", self.operation, error)
            self.logged[key] = now
        stopped = self.stop.wait(self.delay)
        self.delay = min(1, self.delay * 2)
        return stopped


class Cleanup:
    """Collect cleanup failures so later resource-release steps still run.

    Attributes:
        errors: Ordered list of labels and exceptions caught by attempt().
    """

    def __init__(self):
        self.errors = []

    def attempt(self, label, action, *args, **kwargs):
        """Run one cleanup action and collect ordinary exceptions instead of raising.

        Args:
            label: Resource label used in logs and the collected error list.
            action: Callable invoked for this cleanup step.
            *args: Positional arguments passed to action.
            **kwargs: Keyword arguments passed to action.

        Returns:
            The action's result, or None when an Exception is caught and logged.
        """
        try:
            return action(*args, **kwargs)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "Cleanup %s failed: %s", label, exc, exc_info=True
            )
            self.errors.append((label, exc))

    def finish(self, message):
        """Raise a combined failure if any earlier cleanup action failed.

        Args:
            message: Prefix for the combined error message.

        Raises:
            RuntimeError: Collected cleanup errors exist; the first is chained as the cause.
        """
        if self.errors:
            detail = "; ".join(f"{label}: {error}" for label, error in self.errors)
            raise RuntimeError(message + ": " + detail) from self.errors[0][1]


class SendBackoff:
    """Track UDP send readiness without sleeping under session or state locks."""

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
        """Defer UDP sends using capped exponential backoff and rate-limited warnings."""
        with self.lock:
            now = time.monotonic()
            self.until = now + self.delay
            self.delay = min(1, self.delay * 2)
            key = (type(error).__name__, error.errno)
            if now - self.logged.get(key, float("-inf")) >= 1:
                self.logger.warning("UDP send: %s; retrying", error)
                self.logged[key] = now
