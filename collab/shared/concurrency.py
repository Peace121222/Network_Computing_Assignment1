"""Bounded FIFO workers with cancellation and one cleanup attempt per job."""

from collections import deque
import logging
import threading
import time

from collab.shared.limits import SHUTDOWN_TIMEOUT

log = logging.getLogger(__name__)


class Reservation:
    """Reserve capacity before a request allocates upload resources."""

    def __init__(self, owner):
        self.owner = owner
        self.released = False
        self.submitted = False

    def release(self):
        with self.owner.condition:
            if not self.released:
                self.released = True
                self.owner.admitted -= 1
                self.owner.condition.notify_all()


class BoundedExecutor:
    """Run bounded jobs on fixed daemon workers.

    Pending jobs are skipped on stop, but their cleanup still runs on a worker.
    Cleanup is attempted once. Failures stop admission and are reported by close().
    """

    def __init__(self, workers, waiting, *, name="collab-worker"):
        self.condition = threading.Condition()
        self.capacity = workers + waiting
        self.admitted = 0
        self.jobs = deque()
        self.stopping = False
        self.errors = []
        self.threads = []
        try:
            for index in range(workers):
                thread = threading.Thread(
                    target=self._worker, daemon=True, name=f"{name}-{index}"
                )
                self.threads.append(thread)
                thread.start()
        except BaseException:
            self.close()
            raise

    def reserve(self):
        with self.condition:
            if self.stopping or self.admitted >= self.capacity:
                return None
            self.admitted += 1
            return Reservation(self)

    def submit(self, reservation, fn, cleanup=lambda: None):
        with self.condition:
            if (
                reservation.owner is not self
                or reservation.released
                or reservation.submitted
                or self.stopping
            ):
                raise RuntimeError("Task reservation is no longer valid")
            reservation.submitted = True
            self.jobs.append((fn, cleanup, reservation))
            self.condition.notify()

    def _worker(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.jobs or self.stopping)
                if not self.jobs:
                    return
                fn, cleanup, reservation = self.jobs.popleft()
                cancelled = self.stopping
            try:
                if not cancelled:
                    fn()
            except BaseException:
                log.exception("Background task failed")
            finally:
                try:
                    cleanup()
                except Exception as exc:
                    log.exception("Task cleanup failed")
                    with self.condition:
                        self.errors.append(exc)
                        self.stopping = True
                        self.condition.notify_all()
                finally:
                    reservation.release()

    def stop(self, deadline=None):
        """Stop admission and let workers clean up queued jobs without running them."""
        acquired = (
            self.condition.acquire()
            if deadline is None
            else self.condition.acquire(timeout=max(0, deadline - time.monotonic()))
        )
        if not acquired:
            raise RuntimeError("Worker pool shutdown incomplete: condition lock busy")
        try:
            self.stopping = True
            self.condition.notify_all()
        finally:
            self.condition.release()

    def close(self, deadline=None):
        """Stop and join workers; report incomplete work or a cleanup failure."""
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        self.stop(deadline)
        current = threading.current_thread()
        for thread in self.threads:
            if thread is not current and thread.ident is not None:
                thread.join(max(0, deadline - time.monotonic()))
        if any(t.is_alive() and t is not current for t in self.threads) or self.errors:
            raise RuntimeError("Worker pool shutdown incomplete")
