"""Small bounded worker pool with explicit admission reservations."""

from collections import deque
from collab.shared.limits import SHUTDOWN_TIMEOUT

import logging
import threading
import time

log = logging.getLogger(__name__)


class Reservation:
    """Represent one worker-pool admission slot.

    Attributes:
        owner: Executor whose admission count includes this reservation.
        released: Whether release() has returned the slot.
        submitted: Whether a job has been submitted using the slot.
    """

    def __init__(self, owner):
        self.owner = owner
        self.released = False
        self.submitted = False

    def release(self):
        """Return the admission slot once and notify waiting pool workers."""
        with self.owner.condition:
            if not self.released:
                self.released = True
                self.owner.admitted -= 1
                self.owner.condition.notify_all()


class BoundedExecutor:
    """Run tasks with bounded admission and worker-owned cleanup.

    Construction starts daemon workers. Each accepted job owns its reservation until
    cleanup completes or fails. Failed cleanup is retained for retry during close().

    Attributes:
        capacity: Total number of admitted running and waiting jobs.
        admitted: Number of reservations not yet released.
        threads: Worker threads owned by this executor.
    """

    def __init__(self, workers, waiting, *, name="collab-worker"):
        self.condition = threading.Condition()
        self.capacity = workers + waiting
        self.admitted = 0
        self.waiting = deque()
        self.cancelled = deque()
        self.failed_cleanup = []
        self.mailboxes = [None] * workers
        self.busy = [False] * workers
        self.stopping = False
        self.threads = []
        try:
            for index in range(workers):
                thread = threading.Thread(
                    target=self._worker,
                    args=(index,),
                    daemon=True,
                    name=f"{name}-{index}",
                )
                self.threads.append(thread)
                thread.start()
        except BaseException:
            self.close()
            raise

    def reserve(self):
        """Reserve admission capacity without blocking for a free slot.

        Returns:
            A reservation owned by this executor, or None if stopping or at capacity.
        """
        with self.condition:
            if self.stopping or self.admitted >= self.capacity:
                return None
            self.admitted += 1
            return Reservation(self)

    def submit(self, reservation, fn, cleanup=lambda: None):
        """Transfer a valid reservation and task cleanup to the worker pool.

        Args:
            reservation: Unreleased, unsubmitted reservation returned by reserve().
            fn: Zero-argument job callable. Worker failures are logged.
            cleanup: Zero-argument callable run after execution or cancellation.

        Raises:
            RuntimeError: The reservation is invalid or the executor is stopping.
        """
        with self.condition:
            if (
                reservation.owner is not self
                or reservation.released
                or reservation.submitted
                or self.stopping
            ):
                raise RuntimeError("Task reservation is no longer valid")
            job = (fn, cleanup, reservation)
            reservation.submitted = True
            for index, busy in enumerate(self.busy):
                if not busy:
                    self.busy[index] = True
                    self.mailboxes[index] = job
                    break
            else:
                self.waiting.append(job)
            self.condition.notify_all()

    @staticmethod
    def _finish(job):
        try:
            job[1]()
        finally:
            job[2].release()

    def _worker(self, index):
        while True:
            with self.condition:
                self.condition.wait_for(
                    lambda: self.mailboxes[index] is not None
                    or self.cancelled
                    or (self.stopping and not self.failed_cleanup)
                )
                job = self.mailboxes[index]
                self.mailboxes[index] = None
                cleanup_only = False
                if job is None and self.cancelled:
                    job = self.cancelled.popleft()
                    cleanup_only = True
                if job is None:
                    return
            try:
                if not cleanup_only:
                    job[0]()
            except BaseException:
                log.exception("Background task failed")
            finally:
                try:
                    self._finish(job)
                except Exception:
                    log.exception("Task cleanup failed")
                    with self.condition:
                        self.failed_cleanup.append(job)
                    self.stop()
                with self.condition:
                    if self.waiting and not self.stopping:
                        self.mailboxes[index] = self.waiting.popleft()
                    else:
                        self.busy[index] = False
                    self.condition.notify_all()

    def stop(self, deadline=None, *, retry_cleanup=False):
        """Stop admission and schedule pending jobs for cleanup without executing them.

        Active jobs are not interrupted. Cleanup remains worker-owned and is not executed
        inline by this method.

        Args:
            deadline: Absolute monotonic lock-acquisition deadline in seconds, or None
                to acquire the condition lock without a timeout.
            retry_cleanup: Whether to requeue jobs whose earlier cleanup failed.

        Raises:
            RuntimeError: The condition lock cannot be acquired before the deadline.
        """
        if deadline is None:
            acquired = self.condition.acquire()
        else:
            acquired = self.condition.acquire(
                timeout=max(0, deadline - time.monotonic())
            )
        if not acquired:
            raise RuntimeError("Worker pool shutdown incomplete: condition lock busy")
        try:
            self.stopping = True
            self.cancelled.extend(self.waiting)
            self.waiting.clear()
            for index, job in enumerate(self.mailboxes):
                if job is not None:
                    self.cancelled.append(job)
                    self.mailboxes[index] = None
                    self.busy[index] = False
            if retry_cleanup:
                self.cancelled.extend(self.failed_cleanup)
                self.failed_cleanup.clear()
            self.condition.notify_all()
        finally:
            self.condition.release()

    def close(self, deadline=None):
        """Stop admission, retry deferred cleanup, and join owned workers.

        The current worker and unstarted threads are not joined.

        Args:
            deadline: Absolute monotonic deadline in seconds, or None for the default
                shutdown timeout.

        Raises:
            RuntimeError: Lock acquisition, worker termination, or cleanup is incomplete.
        """
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT if deadline is None else deadline
        self.stop(deadline, retry_cleanup=True)
        current = threading.current_thread()
        for thread in self.threads:
            if thread is not current and thread.ident is not None:
                thread.join(max(0, deadline - time.monotonic()))
        if (
            any(t.is_alive() and t is not current for t in self.threads)
            or self.failed_cleanup
        ):
            raise RuntimeError("Worker pool shutdown incomplete")
