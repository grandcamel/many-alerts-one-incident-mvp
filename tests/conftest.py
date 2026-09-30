"""Shared fixtures for the tests that drive a real server over real HTTP.

Every test here drives a real Receiver or a real Forwarder over real HTTP on an
ephemeral port. Nothing in the HTTP layer is mocked; the substitutions are the
Run spawner, which is injected into the Receiver at construction, and the
Forwarder's upstream, which is a fake Atlassian site on another ephemeral port.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from grafana_jsm_sandbox.forwarder import Forwarder, JiraCredential
from grafana_jsm_sandbox.receiver import Receiver, Run, RunOutcome
from tests.upstream import FakeUpstream

REPOSITORY = Path(__file__).resolve().parent.parent
"""The git working tree, the build context, and where compose is run from."""

FIXTURES = REPOSITORY / "fixtures"

CONTAINER_VARIABLE = "DEMO_CONTAINER"
"""Set it to anything and the checks that need `docker compose up -d` done run too."""

needs_the_stack_up = pytest.mark.skipif(
    not os.environ.get(CONTAINER_VARIABLE),
    reason=f"needs the stack up; set {CONTAINER_VARIABLE}=1 after docker compose up -d",
)
"""The opt-in for anything that asks the running containers a question."""

TESTS = REPOSITORY / "tests"

BASIC_DEMO_OPTION = "--basic-demo"

BASIC_DEMO_TESTS = frozenset(
    {
        "test_alert_rules.py",
        "test_basic_demo.py",
        "test_configure.py",
        "test_container.py",
        "test_demo_config.py",
        "test_docs.py",
        "test_doctor.py",
        "test_end_to_end.py",
        "test_fake_jira.py",
        "test_fixtures.py",
        "test_forwarder.py",
        "test_grafana.py",
        "test_group_notifications.py",
        "test_log_formatter.py",
        "test_notification_fixtures.py",
        "test_receiver.py",
        "test_replay.py",
        "test_reset.py",
        "test_run_command.py",
        "test_run_costs.py",
        "test_run_spawner.py",
        "test_setup_skill.py",
        "test_skill_template.py",
        "test_startup.py",
        "test_verify.py",
        "test_verify_mvp.py",
    }
)
"""The test files the basic demo needs, and the only ones `--basic-demo` collects on its own.

The basic demo is chapter one: the Receiver, the Forwarder, the Run and the helpers around
them. Every other file tests chapter two, the mediated Forwarder chain (`forwarder_*`) and the
`prototype/` work, which the basic demo never runs. An engineer checking their host before a
demo should not need chapter two's code to import on their Python, so `--basic-demo` passes over
those files before they are imported. The list is spelled out rather than matched, so a file
joins it by decision; `tests/test_basic_demo.py` holds every file to the one rule that decides
its side. A file named on the command line is still collected: pytest never asks this hook about
the paths it was given, and whoever names a file asked for it.
"""


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        BASIC_DEMO_OPTION,
        action="store_true",
        help="collect only the basic demo's test files; chapter two's are never imported",
    )


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Under `--basic-demo`, pass over every test file not in the list, before it is imported.

    Returning None rather than False for a listed file leaves pytest's own `--ignore` and
    `norecursedirs` in charge of it. Without the option nothing changes.
    """
    if not config.getoption(BASIC_DEMO_OPTION):
        return None
    if collection_path.is_dir() or not collection_path.name.startswith("test_"):
        return None
    if collection_path.resolve().parent == TESTS and collection_path.name in BASIC_DEMO_TESTS:
        return None
    return True


def compose(*arguments: str) -> subprocess.CompletedProcess:
    """One `docker compose` command against this repo's stack, whatever it answers."""
    return subprocess.run(
        ["docker", "compose", *arguments],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=False,
    )


REAL_EMAIL = "ops@example.invalid"
REAL_TOKEN = "real-jira-token-that-must-never-be-logged"
"""The credential the Forwarder holds. No Run and no log line may ever contain it."""


def firing_notification() -> dict:
    """The canned firing Notification, as Grafana's webhook contact point sends it."""
    return json.loads((FIXTURES / "notification-firing.json").read_text())


@dataclass
class SpawnedRun:
    """One recorded invocation of the injected spawner.

    The Notification is read when the spawn happens, not later, so a test that
    asserts on it is asserting the file was already there when the Run started.
    """

    run_id: str
    working_directory: Path
    notification: dict

    @classmethod
    def record(cls, run: Run) -> SpawnedRun:
        return cls(
            run.run_id,
            run.working_directory,
            json.loads(run.notification_path.read_text()),
        )


@dataclass
class RecordingSpawner:
    """A fake Run spawner that records what the Receiver asked it to start.

    It returns `outcome` when a test sets one, as the real spawner does, and the bare
    `exit_status` otherwise.
    """

    exit_status: int = 0
    outcome: RunOutcome | None = None
    spawned: list[SpawnedRun] = field(default_factory=list)
    _progress: threading.Condition = field(default_factory=threading.Condition)
    _release: threading.Event | None = None
    _fail_next: BaseException | None = None

    def block_until_released(self) -> threading.Event:
        """Make the next spawn hang until the returned event is set."""
        self._release = threading.Event()
        return self._release

    def fail_next(self, error: BaseException) -> None:
        """Make the next spawn — and only the next — blow up."""
        self._fail_next = error

    def wait_for_spawns(self, count: int, timeout: float = 5.0) -> None:
        with self._progress:
            reached = self._progress.wait_for(lambda: len(self.spawned) >= count, timeout)
        assert reached, f"expected {count} spawns, saw {len(self.spawned)}"

    def __call__(self, run) -> RunOutcome | int:
        with self._progress:
            self.spawned.append(SpawnedRun.record(run))
            error, self._fail_next = self._fail_next, None
            self._progress.notify_all()
        if self._release is not None:
            release, self._release = self._release, None
            assert release.wait(5.0), "blocked spawn was never released"
        if error is not None:
            raise error
        return self.exit_status if self.outcome is None else self.outcome


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


def post_notification(receiver: Receiver, body) -> Response:
    """POST a Notification body. `body` may be bytes, str or a JSON-serialisable object."""
    if isinstance(body, (bytes, bytearray)):
        data = bytes(body)
    elif isinstance(body, str):
        data = body.encode()
    else:
        data = json.dumps(body).encode()
    return http_request(
        receiver.url + "/notification", method="POST", data=data, content_type="application/json"
    )


def get_health(receiver: Receiver) -> Response:
    return http_request(receiver.url + "/health")


def basic_auth_header(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def http_request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
) -> Response:
    """One real HTTP request. A 4xx or 5xx comes back as a Response, not an exception."""
    sent = dict(headers or {})
    if content_type:
        sent["Content-Type"] = content_type
    if basic_auth is not None:
        sent["Authorization"] = basic_auth_header(*basic_auth)
    request = urllib.request.Request(url, data=data, headers=sent, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return Response(response.status, response.read(), dict(response.headers))
    except urllib.error.HTTPError as error:
        return Response(error.code, error.read(), dict(error.headers))


@pytest.fixture
def upstream():
    upstream = FakeUpstream()
    upstream.start()
    try:
        yield upstream
    finally:
        upstream.stop()


@pytest.fixture
def forwarder(upstream):
    forwarder = Forwarder(
        JiraCredential(site_url=upstream.url, email=REAL_EMAIL, api_token=REAL_TOKEN)
    )
    forwarder.start()
    try:
        yield forwarder
    finally:
        forwarder.stop()


@pytest.fixture
def spawner() -> RecordingSpawner:
    return RecordingSpawner()


@pytest.fixture
def receiver(spawner, tmp_path):
    receiver = Receiver(spawn_run=spawner, runs_directory=tmp_path / "runs")
    receiver.start()
    try:
        yield receiver
    finally:
        receiver.stop()


def wait_for_log(caplog, substring: str, count: int = 1, timeout: float = 5.0) -> str:
    """Wait until `substring` has been logged `count` times; return the log text."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = caplog.text
        if text.count(substring) >= count:
            return text
        time.sleep(0.01)
    raise AssertionError(
        f"expected {count} log lines containing {substring!r}; log was:\n{caplog.text}"
    )
