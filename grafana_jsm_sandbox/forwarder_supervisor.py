"""Bounded local supervision for the private Forwarder control listener.

This module owns the lifecycle between a :class:`PrivateControlListener` and a
single :class:`ForwarderControl`.  It intentionally has no launcher, provider,
or deployment responsibilities.
"""

from __future__ import annotations

import math
import socket
import threading
import time
from dataclasses import dataclass

from .forwarder_control import ForwarderControl
from .forwarder_listener import ListenerCloseout, ListenerError, PrivateControlListener

MAX_HANDLERS = 4
ACCEPT_TIMEOUT = 0.1
MAX_STOP_TIMEOUT = 10.0


class ServiceError(ValueError):
    """A fixed service lifecycle or configuration rejection."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ServiceCloseout:
    """A non-diagnostic closeout: state is completion, reason is its trigger."""

    state: str
    reason: str
    listener_state: str
    threads_alive: int


@dataclass
class _Worker:
    sock: socket.socket
    published: threading.Event
    thread: threading.Thread | None = None
    start_complete: bool = False


class ControlService:
    """Own one unopened listener and unused controller for one terminal run."""

    def __init__(self, listener: PrivateControlListener, control: ForwarderControl):
        if not isinstance(listener, PrivateControlListener):
            raise ServiceError("invalid_listener")
        if not isinstance(control, ForwarderControl):
            raise ServiceError("invalid_control")
        # Unused and exclusive ownership are caller preconditions.  These cheap
        # fail-closed checks only reject objects already visibly terminal.
        if getattr(listener, "_opened", True) or getattr(listener, "_closed", True):
            raise ServiceError("listener_not_fresh")
        if getattr(control, "_closed", True):
            raise ServiceError("control_not_fresh")
        self._listener = listener
        self._control = control
        self._lock = threading.RLock()
        self._phase = "new"  # new, starting, running, stopping
        self._opening = False
        self._accept_thread: threading.Thread | None = None
        self._accept_starting = False
        self._accept_published = threading.Event()
        self._workers: list[_Worker] = []
        self._pending: socket.socket | None = None
        self._listener_closeout: ListenerCloseout | None = None
        self._listener_cleanup_attempted = False
        self._reason = "stopped"
        self._fatal = False
        self._cleanup_in_progress = False
        self._cleanup_done = threading.Event()
        self._cleanup_done.set()
        self._control_shutdown_attempted = False

    @property
    def endpoint(self) -> str:
        with self._lock:
            if self._phase != "running":
                raise ServiceError("not_running")
        try:
            return self._listener.endpoint
        except ListenerError:
            # Do not let filesystem details or an implementation-specific listener
            # code become a service diagnostic.
            raise ServiceError("not_running") from None

    def start(self) -> ControlService:
        """Open the listener and publish one accept loop exactly once."""
        with self._lock:
            if self._phase != "new":
                raise ServiceError("invalid_lifecycle")
            self._phase = "starting"
            self._opening = True
        try:
            self._listener.open()
        except BaseException:  # noqa: BLE001 - terminal cleanup must be fail-closed.
            with self._lock:
                self._opening = False
            self._initiate_shutdown("start_failed")
            raise ServiceError("start_failed") from None
        with self._lock:
            self._opening = False

        with self._lock:
            if self._phase != "starting":
                interrupted = True
            else:
                interrupted = False
                try:
                    thread = threading.Thread(
                        target=self._accept_loop, name="forwarder-control-accept", daemon=True
                    )
                    self._accept_thread = thread
                    self._accept_starting = True
                except BaseException:  # noqa: BLE001 - a failed factory is terminal.
                    thread = None
                    self._reason = "start_failed"
        if interrupted:
            self._initiate_shutdown("stopped")
            raise ServiceError("start_failed")
        if thread is None:
            self._initiate_shutdown("start_failed")
            raise ServiceError("start_failed")
        try:
            thread.start()
        except BaseException:  # noqa: BLE001 - ambiguous starts remain owned.
            self._initiate_shutdown("start_failed")
            raise ServiceError("start_failed") from None
        finally:
            with self._lock:
                self._accept_starting = False
        with self._lock:
            if self._phase == "starting":
                self._phase = "running"
                self._accept_published.set()
                return self
        self._initiate_shutdown("stopped")
        raise ServiceError("start_failed")

    def stop(self, *, timeout: float = 2.0) -> ServiceCloseout:
        """Permanently hold control authority and observe owned thread completion."""
        seconds = self._stop_timeout(timeout)
        deadline = time.monotonic() + seconds
        self._initiate_shutdown("stopped", deadline)
        self._wait_cleanup(deadline)
        return self._observe(deadline)

    def _accept_loop(self) -> None:
        try:
            self._accept_published.wait()
            while self._is_running():
                try:
                    accepted = self._listener.accept(timeout=ACCEPT_TIMEOUT)
                except ListenerError:
                    if self._is_stopping():
                        return
                    self._fatal_shutdown()
                    return
                if accepted is not None:
                    self._dispatch(accepted)
        except BaseException:  # noqa: BLE001 - orchestration failure is fatal.
            self._fatal_shutdown()

    def _dispatch(self, sock: socket.socket) -> None:
        """Transfer one accepted descriptor to a published worker or close it."""
        worker: _Worker | None = None
        reject = False
        try:
            with self._lock:
                # Publish before reaping, so an exceptional bookkeeping path
                # cannot leave the just-accepted descriptor ownerless.
                self._pending = sock
                self._reap_locked()
                if self._phase != "running" or len(self._workers) >= MAX_HANDLERS:
                    reject = True
                else:
                    worker = _Worker(sock=sock, published=threading.Event())
                    self._workers.append(worker)
                    self._pending = None
        except BaseException:  # noqa: BLE001 - accepted descriptor must be recovered.
            self._close_socket(sock)
            with self._lock:
                if self._pending is sock:
                    self._pending = None
            self._fatal_shutdown()
            return
        if reject:
            closed = self._close_socket(sock)
            with self._lock:
                if self._pending is sock:
                    self._pending = None
            if not closed:
                self._fatal_shutdown()
            return
        assert worker is not None
        try:
            thread = threading.Thread(
                target=self._worker_loop, args=(worker,), name="forwarder-control-handler", daemon=True
            )
            worker.thread = thread
        except BaseException:  # noqa: BLE001 - reservation construction is fatal.
            self._discard_unstarted(worker)
            self._fatal_shutdown()
            return
        try:
            thread.start()
        except BaseException:  # noqa: BLE001 - ambiguous starts remain tracked.
            # If an unusual Thread implementation has started it despite raising,
            # it remains owned and receives the publication release below.
            if thread.is_alive():
                worker.start_complete = True
                worker.published.set()
            else:
                self._discard_unstarted(worker)
            self._fatal_shutdown()
            return
        worker.start_complete = True
        worker.published.set()

    def _worker_loop(self, worker: _Worker) -> None:
        try:
            worker.published.wait()
            self._control.serve_connection(worker.sock)
        except BaseException:  # noqa: BLE001 - workers must trigger a fatal hold.
            self._fatal_shutdown()
        finally:
            if not self._close_socket(worker.sock):
                self._fatal_shutdown()

    def _fatal_shutdown(self) -> None:
        self._initiate_shutdown("fatal_failure")

    def _initiate_shutdown(self, reason: str, deadline: float | None = None) -> None:
        """Perform non-blocking terminal cleanup without holding the state lock."""
        with self._lock:
            if self._phase != "stopping":
                self._phase = "stopping"
                self._reason = reason
            if reason == "fatal_failure":
                self._fatal = True
                self._reason = "fatal_failure"
            if self._cleanup_in_progress:
                return
            self._cleanup_in_progress = True
            self._cleanup_done.clear()
            pending = self._pending
            sockets = tuple(worker.sock for worker in self._workers)
            workers = tuple(self._workers)
            opening = self._opening
            close_listener = not self._listener_cleanup_attempted and not opening
            if close_listener:
                self._listener_cleanup_attempted = True
            shutdown_control = not self._control_shutdown_attempted
            if shutdown_control:
                self._control_shutdown_attempted = True

        failed = False
        # Holding authority comes first; every other cleanup action is attempted
        # even if this call or a socket close fails.
        if shutdown_control:
            try:
                self._control.shutdown()
            except BaseException:  # noqa: BLE001 - continue mandatory cleanup.
                failed = True
        if pending is not None:
            if self._close_socket(pending):
                with self._lock:
                    if self._pending is pending:
                        self._pending = None
            else:
                failed = True
        for sock in sockets:
            if not self._close_socket(sock):
                failed = True
        for worker in workers:
            worker.published.set()
        self._accept_published.set()
        if close_listener:
            try:
                closeout = self._listener.close()
            except BaseException:  # noqa: BLE001 - preserve unknown closeout.
                closeout = None
                failed = True
            with self._lock:
                if self._listener_closeout is None and closeout is not None:
                    self._listener_closeout = closeout
        if failed:
            with self._lock:
                self._fatal = True
                if self._reason == "stopped":
                    self._reason = "shutdown_failure"
        with self._lock:
            self._cleanup_in_progress = False
            self._cleanup_done.set()
            retry_listener_cleanup = (
                not self._listener_cleanup_attempted and not self._opening
            )
        if retry_listener_cleanup:
            self._initiate_shutdown(self._reason, deadline)

    def _observe(self, deadline: float) -> ServiceCloseout:
        with self._lock:
            accept = self._accept_thread
        self._join(accept, deadline)
        with self._lock:
            workers = tuple(self._workers)
        for worker in workers:
            self._join(worker.thread, deadline)
        with self._lock:
            self._reap_locked()
            threads = tuple(
                thread for thread in (self._accept_thread, *(w.thread for w in self._workers))
                if thread is not None
            )
            alive = sum(thread.is_alive() for thread in threads)
            inflight = sum(not worker.start_complete for worker in self._workers)
            listener_state = (
                self._listener_closeout.state if self._listener_closeout is not None else "unknown"
            )
            clean_listener = listener_state == "removed" or (
                listener_state == "not_open" and self._accept_thread is None
            )
            state = "stopped" if (
                alive == 0 and inflight == 0 and self._pending is None
                and not self._accept_starting and not self._cleanup_in_progress
                and clean_listener and not self._fatal
            ) else "unknown"
            return ServiceCloseout(state, self._reason, listener_state, alive)

    def _wait_cleanup(self, deadline: float) -> None:
        with self._lock:
            pending = self._cleanup_in_progress
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining > 0:
            self._cleanup_done.wait(remaining)

    def _join(self, thread: threading.Thread | None, deadline: float) -> None:
        if thread is None or thread is threading.current_thread() or not thread.is_alive():
            return
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                thread.join(remaining)
            except (RuntimeError, OSError):
                # The final liveness observation determines the closeout.
                pass

    def _discard_unstarted(self, worker: _Worker) -> None:
        # Retain the reservation until its descriptor is closed; otherwise a
        # concurrent observer could mistake an in-flight close for completion.
        worker.published.set()
        closed = self._close_socket(worker.sock)
        with self._lock:
            try:
                self._workers.remove(worker)
            except ValueError:
                pass
        if not closed:
            self._fatal_shutdown()

    def _reap_locked(self) -> None:
        self._workers[:] = [
            worker for worker in self._workers
            if not worker.start_complete or worker.thread is None or worker.thread.is_alive()
        ]

    def _is_running(self) -> bool:
        with self._lock:
            return self._phase == "running"

    def _is_stopping(self) -> bool:
        with self._lock:
            return self._phase == "stopping"

    @staticmethod
    def _close_socket(sock: socket.socket) -> bool:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except BaseException:  # noqa: BLE001, S110 - best-effort descriptor close.
            pass
        try:
            sock.close()
        except BaseException:  # noqa: BLE001 - best-effort descriptor close.
            return False
        try:
            return sock.fileno() == -1
        except BaseException:  # noqa: BLE001 - unobservable close is unknown.
            return False

    @staticmethod
    def _stop_timeout(timeout: object) -> float:
        if type(timeout) not in (int, float):
            raise ServiceError("invalid_timeout")
        try:
            seconds = float(timeout)
        except OverflowError:
            raise ServiceError("invalid_timeout") from None
        if not math.isfinite(seconds) or not 0 < seconds <= MAX_STOP_TIMEOUT:
            raise ServiceError("invalid_timeout")
        return seconds
