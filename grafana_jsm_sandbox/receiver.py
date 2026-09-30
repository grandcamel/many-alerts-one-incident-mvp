"""The Receiver: the HTTP endpoint that accepts Notifications and starts Runs."""

from __future__ import annotations

import logging
import queue
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from grafana_jsm_sandbox.notification import (
    NOTIFICATION_FILENAME,
    InvalidNotification,
    validate_notification,
)

logger = logging.getLogger(__name__)

SHUTDOWN_POLL_INTERVAL = 0.05
"""How long `stop` may wait for the serving loop to notice it. The module's own default
of half a second is time a container spends on the way down, and time a test suite pays
for every server it starts."""

TRANSCRIPT_FILENAME = "transcript.jsonl"
"""What a Run's raw stream-json is teed to, beside its Notification. In the container that is
the runs tmpfs, so it lasts until the container stops or is recreated and no longer."""

REJECTED_PATH_LENGTH = 200
"""How much of a path a rejected POST named reaches the log. Anyone who can reach the port
chooses it, so it is also logged quoted and escaped, never raw to a terminal."""


@dataclass(frozen=True)
class Run:
    """One headless Claude invocation, started for exactly one Notification."""

    run_id: str
    working_directory: Path

    @property
    def notification_path(self) -> Path:
        return self.working_directory / NOTIFICATION_FILENAME

    @property
    def transcript_path(self) -> Path:
        return self.working_directory / TRANSCRIPT_FILENAME


@dataclass(frozen=True)
class RunOutcome:
    """How a Run ended: its exit status, and why it failed when it did.

    The exit status alone cannot say. A Run the API refused (out of usage credits,
    an expired token) reports its failure only inside its Transcript and still exits
    0, so the spawner reads the stream and hands the reason back with the status.
    """

    exit_status: int
    failure: str | None = None

    @classmethod
    def of(cls, ended: RunOutcome | int) -> RunOutcome:
        """The outcome a spawner returned, or the one a bare exit status implies.

        A spawner that knows only how the process exited, a test's fake among
        them, may return just that; any status but 0 is then the reason.
        """
        if isinstance(ended, RunOutcome):
            return ended
        return cls(ended, None if ended == 0 else f"exit status {ended}")


class Receiver:
    """Accepts Grafana Notifications over HTTP and starts one Run for each.

    Runs are executed one at a time in arrival order by a single worker, so two
    Firings of the same Alert can never race. `spawn_run` is injected so that
    tests can substitute a fake: it is called with a Run and returns a
    `RunOutcome`, or just the Run's exit status.
    """

    def __init__(
        self,
        spawn_run,
        runs_directory: Path,
        host: str = "127.0.0.1",
        port: int = 0,
        settle_seconds: float = 0.0,
    ):
        self._spawn_run = spawn_run
        self._settle_seconds = settle_seconds
        self._last_ended_at: float | None = None
        self._runs_directory = Path(runs_directory)
        self._host = host
        self._queue: queue.Queue = queue.Queue()
        self._backlog = 0
        self._backlog_lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), _build_handler(self))
        self._http_thread: threading.Thread | None = None
        self._worker_thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        """Where the Receiver is actually listening, once an ephemeral port is bound."""
        port = self._server.server_address[1]
        return f"http://{self._host}:{port}"

    def start(self) -> None:
        self._worker_thread = threading.Thread(target=self._work, name="receiver-runs", daemon=True)
        self._worker_thread.start()
        self._http_thread = threading.Thread(
            target=self._server.serve_forever,
            args=(SHUTDOWN_POLL_INTERVAL,),
            name="receiver-http",
            daemon=True,
        )
        self._http_thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._http_thread is not None:
            self._http_thread.join(timeout=5)
        self._queue.put(None)
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5)

    def accept(self, body: bytes) -> Run:
        """Record a Notification as a new Run and queue it. Returns before it starts.

        Raises InvalidNotification if the body is not a Grafana Notification.
        """
        notification = validate_notification(body)
        run = self._prepare_run(body)
        with self._backlog_lock:
            ahead = self._backlog
            self._backlog += 1
        # Logged before it is queued, so this line always comes before the Run's own.
        alerts = len(notification["alerts"])
        logger.info(
            "notification accepted: %d alert%s, run %s queued, %d ahead",
            alerts,
            "" if alerts == 1 else "s",
            run.run_id,
            ahead,
        )
        self._queue.put(run)
        return run

    def _prepare_run(self, body: bytes) -> Run:
        run_id = f"{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
        working_directory = self._runs_directory / run_id
        working_directory.mkdir(parents=True)
        run = Run(run_id, working_directory)
        run.notification_path.write_bytes(body)
        return run

    def _work(self) -> None:
        while True:
            run = self._queue.get()
            if run is None:
                return
            self._execute(run)

    def _execute(self, run: Run) -> None:
        """Run one Run to completion. A Run that blows up must not stall the queue.

        A failed Run ends on a `run <id> FAILED: <reason>` line at ERROR, so one
        search of the log finds every Run that did not do its job, whatever the
        reason and whatever its exit status said.
        """
        if self._last_ended_at is not None:
            remaining = self._settle_seconds - (time.monotonic() - self._last_ended_at)
            if remaining > 0:
                logger.info(
                    "run %s waits %.2fs for Jira's search index before starting",
                    run.run_id,
                    remaining,
                )
                time.sleep(remaining)
        logger.info("run %s started in %s", run.run_id, run.working_directory)
        started_at = time.monotonic()
        try:
            try:
                ended = self._spawn_run(run)
            finally:
                self._last_ended_at = time.monotonic()
                # Out of the count before anything says the Run ended, so a Notification
                # accepted after that line is never told this Run is still ahead of it.
                with self._backlog_lock:
                    self._backlog -= 1
            outcome = RunOutcome.of(ended)
        except Exception:
            duration = time.monotonic() - started_at
            logger.exception("run %s FAILED after %.2fs: the spawner raised", run.run_id, duration)
            return
        duration = time.monotonic() - started_at
        logger.info(
            "run %s finished with exit status %s in %.2fs",
            run.run_id,
            outcome.exit_status,
            duration,
        )
        if outcome.failure is not None:
            logger.error("run %s FAILED: %s", run.run_id, outcome.failure)


def _build_handler(receiver: Receiver):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path == "/health":
                self._respond(200, b"ok")
            else:
                self._respond(404, b"not found")

        def do_POST(self):
            if self.path != "/notification":
                logger.warning(
                    "rejected a POST to %r from %s: not found",
                    self.path[:REJECTED_PATH_LENGTH],
                    self.client_address[0],
                )
                self._respond(404, b"not found")
                return
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                receiver.accept(body)
            except InvalidNotification as error:
                logger.warning("rejected a Notification from %s: %s", self.client_address[0], error)
                self._respond(400, str(error).encode())
                return
            except Exception:
                logger.exception("could not record a Notification as a Run")
                self._respond(500, b"could not record the notification")
                return
            self._respond(202, b"accepted")

        def _respond(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            """Silence BaseHTTPRequestHandler's stderr access log; the Receiver logs Runs."""

    return Handler
