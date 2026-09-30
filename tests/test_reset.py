"""Resetting the demo's project and the traffic before a demo, so the Incidents queue starts empty.

The reset talks to Jira through `jira-as` and to the stack through `docker
compose`, both injected, so these tests drive it against a fake OPS whose
workflow is the real one's (ADR 0004): `Resolve` is the only transition that
takes a resolution, `Canceled` has no way out, and an Incident without a
resolution stays in the Incidents queue. The last tests start a real `jira-as`
stand-in, to show what the reset hands it comes from `.env` and not the shell.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from grafana_jsm_sandbox.demo_config import PROXY_VARIABLES, DemoProject
from grafana_jsm_sandbox.reset import (
    CLOSE_FAILED_COMMENT,
    NO_ROAD,
    NO_ROAD_BACK,
    NOT_A_RUNS,
    OPEN_INCIDENTS,
    RESET_COMMENT,
    RESOLUTION,
    STUCK_INCIDENTS,
    UNRESOLVED,
    UNRESOLVED_COMPLETED,
    main,
    reset,
)
from grafana_jsm_sandbox.run_spawner import TRUST_STORE_VARIABLES

KEY = "OPS"
"""The project the fake answers for, whose workflow ticket 04 read."""

WORKFLOW = {
    "Open": {"11": "Work in progress", "21": "Completed", "31": "Canceled"},
    "Work in progress": {"21": "Completed", "31": "Canceled"},
    "Pending": {"31": "Canceled"},
    "Completed": {"41": "Closed", "51": "Open"},
    "Canceled": {"41": "Closed"},
    "Closed": {},
}
"""The OPS Incident workflow as ticket 04 read it off real issues: transition id to
the status it lands on. `Pending` is the one open status with no road to Completed."""

DONE = {"Completed", "Canceled", "Closed"}

PAGE = 50
"""What one `search jql` answers at most, as jira-as 2.0.0 asks Jira by default."""


@dataclass
class FakeIncident:
    status: str
    labels: list[str]
    resolution: str | None = None
    comments: list[str] = field(default_factory=list)


@dataclass
class FakeOps:
    """A stand-in for `jira-as` against OPS: answers the queries the reset makes and
    moves Incidents the way the real workflow would.

    Its searches page the way `search jql` does, `PAGE` issues and a `nextPageToken` at
    a time, the token being an offset into the matches as they stand when each page is
    asked for. A caller that moves issues between pages therefore misses some, as it
    would against Jira."""

    incidents: dict[str, FakeIncident]
    key: str = KEY
    calls: list[tuple[str, ...]] = field(default_factory=list)
    workflow: dict[str, dict[str, str]] = field(default_factory=lambda: WORKFLOW)
    resolve_screen_lacks_resolution: bool = False
    """The site's Resolve screen has no Resolution field. jira-as 2.0.0 then retries the
    transition without it and only warns, so the Incident lands on Completed unresolved."""
    status_open: str = "Open"
    status_done: str = "Completed"
    done_statuses: set[str] = field(default_factory=lambda: set(DONE))
    close_refused: str | None = None
    """When set, `jira-as` fails the Close transition with this message."""

    def __call__(self, *arguments: str) -> str:
        self.calls.append(arguments)
        searches = {
            OPEN_INCIDENTS.format(key=self.key): self._open,
            UNRESOLVED_COMPLETED.replace('"Completed"', json.dumps(self.status_done)).format(
                key=self.key
            ): self._unresolved_completed,
            STUCK_INCIDENTS.replace('"Completed"', json.dumps(self.status_done)).format(
                key=self.key
            ): self._stuck,
        }
        match arguments:
            case ("search", "jql", jql, *rest):
                assert jql in searches, jql
                keys = searches[jql]()
                start = int(rest[rest.index("--page-token") + 1]) if "--page-token" in rest else 0
                page = {"issues": [self._issue(key) for key in keys[start : start + PAGE]]}
                if start + PAGE < len(keys):
                    page |= {"nextPageToken": str(start + PAGE), "isLast": False}
                else:
                    page |= {"isLast": True}
                return json.dumps(page)
            case ("issue", "get", key, "--fields", "resolution", *_):
                resolution = self.incidents[key].resolution
                return json.dumps(
                    {"key": key, "fields": {"resolution": resolution and {"name": resolution}}}
                )
            case ("lifecycle", "transitions", key, *_):
                return json.dumps(
                    [
                        {"id": id, "name": f"to {status}", "to": {"name": status}}
                        for id, status in self.workflow[self.incidents[key].status].items()
                    ]
                )
            case ("lifecycle", "transition", key, "--id", id, *rest):
                incident = self.incidents[key]
                assert id in self.workflow[incident.status], f"{id} is not a transition from {key}"
                target = self.workflow[incident.status][id]
                if target == "Closed" and self.close_refused is not None:
                    raise RuntimeError(self.close_refused)
                incident.status = target
                if target == self.status_open:
                    incident.resolution = None
                if rest:
                    assert rest[0] == "--resolution" and target == self.status_done, (
                        "only Resolve takes one"
                    )
                    if not self.resolve_screen_lacks_resolution:
                        incident.resolution = rest[1]
                return ""
            case ("collaborate", "comment", "add", key, "-b", body, *_):
                self.incidents[key].comments.append(body)
                return ""
        raise AssertionError(f"the fake does not answer {arguments}")

    def _open(self) -> list[str]:
        return [
            key
            for key, incident in self.incidents.items()
            if incident.status not in self.done_statuses
        ]

    def _unresolved_completed(self) -> list[str]:
        """Completed without a resolution: in the queue, but with the road back to Open."""
        return [
            key
            for key, incident in self.incidents.items()
            if incident.status == self.status_done and incident.resolution is None
        ]

    def _stuck(self) -> list[str]:
        """Done by status, unresolved by resolution, and no road back: in the queue for good."""
        return [
            key
            for key, incident in self.incidents.items()
            if incident.status in self.done_statuses - {self.status_done}
            and incident.resolution is None
        ]

    def _issue(self, key: str) -> dict:
        incident = self.incidents[key]
        return {
            "key": key,
            "fields": {"status": {"name": incident.status}, "labels": incident.labels},
        }


@dataclass
class FakeCompose:
    calls: list[tuple[str, ...]] = field(default_factory=list)
    failure: BaseException | None = None
    """What `docker compose` raises instead of starting anything, when set."""

    def __call__(self, *arguments: str) -> None:
        self.calls.append(arguments)
        if self.failure is not None:
            raise self.failure


@pytest.fixture
def compose() -> FakeCompose:
    return FakeCompose()


def test_open_incidents_with_a_fingerprint_label_leave_the_queue_completed_and_closed(compose):
    ops = FakeOps(
        {
            "OPS-20": FakeIncident("Open", ["fp-87e2f184874a3b71"]),
            "OPS-21": FakeIncident("Work in progress", ["fp-deadbeef00000000"]),
        }
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == ["OPS-20", "OPS-21"]
    assert outcome.left == {}
    for key in ("OPS-20", "OPS-21"):
        assert ops.incidents[key].status == "Closed"
        assert ops.incidents[key].resolution == RESOLUTION, f"{key} would sit in the queue"


def test_each_closed_incident_says_it_was_a_rehearsal_leftover(compose):
    ops = FakeOps({"OPS-20": FakeIncident("Open", ["fp-87e2f184874a3b71"])})

    reset(KEY, jira_as=ops, compose=compose)

    assert len(ops.incidents["OPS-20"].comments) == 1
    assert "reset" in ops.incidents["OPS-20"].comments[0].lower()


def test_an_open_incident_without_a_fingerprint_label_is_a_humans_and_is_left_alone(compose):
    ops = FakeOps(
        {
            "OPS-22": FakeIncident("Open", ["customer-reported"]),
            "OPS-23": FakeIncident("Open", []),
        }
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == []
    assert outcome.skipped == ["OPS-22", "OPS-23"]
    assert ops.incidents["OPS-22"].status == "Open"
    assert ops.incidents["OPS-23"].status == "Open"
    assert not any(call[:2] == ("lifecycle", "transition") for call in ops.calls)


def test_an_incident_with_no_road_to_completed_is_reported_and_not_forced(compose):
    ops = FakeOps({"OPS-24": FakeIncident("Pending", ["fp-87e2f184874a3b71"])})

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == []
    assert outcome.left == {"OPS-24": NO_ROAD}
    assert ops.incidents["OPS-24"].status == "Pending", "Canceled would park it in the queue"


def test_incidents_already_out_of_the_queue_are_not_asked_about(compose):
    ops = FakeOps(
        {
            "OPS-13": FakeIncident("Completed", ["fp-87e2f184874a3b71"], resolution="Done"),
            "OPS-12": FakeIncident("Closed", ["fp-87e2f184874a3b71"], resolution="Done"),
        }
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == outcome.skipped == outcome.stuck == []
    assert outcome.left == {}
    assert outcome.queue_is_empty
    assert all(call[:2] == ("search", "jql") for call in ops.calls)


def test_a_done_incident_without_a_resolution_is_reported_as_stuck_in_the_queue(compose):
    ops = FakeOps(
        {
            "OPS-6": FakeIncident("Canceled", ["fp-87e2f184874a3b71"]),
            "OPS-1": FakeIncident("Closed", []),
            "OPS-13": FakeIncident("Completed", ["fp-87e2f184874a3b71"], resolution="Done"),
        }
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.stuck == ["OPS-6", "OPS-1"], "both sit in the queue and nothing can move them"
    assert not outcome.queue_is_empty
    assert not any(call[:2] == ("lifecycle", "transition") for call in ops.calls)


def test_traffic_is_started_after_the_queue_is_cleared_and_even_when_it_already_was(compose):
    ops = FakeOps({})

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert compose.calls == [("start", "traffic")]
    assert outcome.traffic_started


def test_the_queue_is_cleared_before_the_traffic_moves():
    order: list[str] = []
    ops = FakeOps({"OPS-20": FakeIncident("Open", ["fp-87e2f184874a3b71"])})
    inner = ops.__call__

    def jira_as(*arguments: str) -> str:
        order.append("jira")
        return inner(*arguments)

    def compose(*arguments: str) -> None:
        order.append("compose")

    reset(KEY, jira_as=jira_as, compose=compose)

    assert order[-1] == "compose" and order.count("compose") == 1


# --- A reset that cannot strand an Incident (step 04 of demo-onboarding) ---


def transitions_of(ops: FakeOps, key: str) -> list[str]:
    """The transition ids the reset took on `key`, in order."""
    return [call[4] for call in ops.calls if call[:3] == ("lifecycle", "transition", key)]


def test_an_incident_completed_without_a_resolution_is_not_closed_and_is_left_with_why(compose):
    ops = FakeOps(
        {"OPS-30": FakeIncident("Open", ["fp-87e2f184874a3b71"])},
        resolve_screen_lacks_resolution=True,
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == []
    assert outcome.left == {"OPS-30": UNRESOLVED}
    assert "Resolution on the Resolve screen" in UNRESOLVED
    assert ops.incidents["OPS-30"].status == "Completed", "Closed would strand it in the queue"
    assert transitions_of(ops, "OPS-30") == ["21"]
    assert ops.incidents["OPS-30"].comments == [], "the comment says it was closed"
    assert outcome.stuck == [], "reported once, as left, not again as stuck"
    assert not outcome.queue_is_empty


def test_the_resolution_is_read_back_after_the_move_and_before_the_close(compose):
    ops = FakeOps({"OPS-20": FakeIncident("Open", ["fp-87e2f184874a3b71"])})

    reset(KEY, jira_as=ops, compose=compose)

    asked = [call[:3] for call in ops.calls if call[0] in ("issue", "lifecycle")]
    resolve = asked.index(("lifecycle", "transition", "OPS-20"))
    assert asked[resolve + 1] == ("issue", "get", "OPS-20")
    assert asked[-1] == ("lifecycle", "transition", "OPS-20")


def test_a_close_jira_refuses_leaves_the_incident_for_a_human_and_the_reset_goes_on(compose):
    ops = FakeOps(
        {
            "OPS-31": FakeIncident("Open", ["fp-87e2f184874a3b71"]),
            "OPS-32": FakeIncident("Open", ["fp-deadbeef00000000"]),
        },
        close_refused="jira-as lifecycle transition OPS-31 --id 41 failed: HTTP 400",
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.closed == []
    assert set(outcome.left) == {"OPS-31", "OPS-32"}
    assert "not closed" in outcome.left["OPS-31"]
    assert "HTTP 400" in outcome.left["OPS-31"]
    assert ops.incidents["OPS-31"].resolution == RESOLUTION
    assert ops.incidents["OPS-31"].comments == [RESET_COMMENT, CLOSE_FAILED_COMMENT], (
        "its history must not end on a close that never happened"
    )
    assert outcome.queue_is_empty, "resolved with Done, so out of the queue already"
    assert not outcome.finished
    assert outcome.traffic_started


def test_an_incident_with_no_road_from_completed_to_closed_is_left(compose):
    workflow = {**WORKFLOW, "Completed": {"51": "Open"}}
    ops = FakeOps({"OPS-33": FakeIncident("Open", ["fp-87e2f184874a3b71"])}, workflow=workflow)

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert list(outcome.left) == ["OPS-33"]
    assert "no transition to Closed" in outcome.left["OPS-33"]
    assert ops.incidents["OPS-33"].status == "Completed"
    assert ops.incidents["OPS-33"].comments == [RESET_COMMENT, CLOSE_FAILED_COMMENT]


def test_a_failed_close_ends_the_report_with_an_empty_queue_and_a_close_left_to_do(
    tmp_path, capsys
):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps(
        {"SANDBOX-34": FakeIncident("Open", ["fp-87e2f184874a3b71"])},
        key="SANDBOX",
        close_refused="jira-as lifecycle transition SANDBOX-34 --id 41 failed: HTTP 400",
    )

    assert main([], env_file=env_file, compose=FakeCompose(), jira_as=ops) == 1

    said = capsys.readouterr().out.splitlines()
    assert said[-1] == "queue is empty; 1 left for a human to close"


def test_a_rerun_after_the_admin_fix_reopens_and_closes_what_the_first_run_left(tmp_path, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps(
        {"SANDBOX-30": FakeIncident("Open", ["fp-87e2f184874a3b71"])},
        key="SANDBOX",
        resolve_screen_lacks_resolution=True,
    )
    assert main([], env_file=env_file, compose=FakeCompose(), jira_as=ops) == 1
    capsys.readouterr()

    ops.resolve_screen_lacks_resolution = False  # the Jira admin put Resolution on the screen
    ops.calls.clear()
    assert main([], env_file=env_file, compose=FakeCompose(), jira_as=ops) == 0

    said = capsys.readouterr().out
    assert "deleteIssue" not in said, "a recoverable Incident must never be offered for deletion"
    assert "SANDBOX-30: completed with resolution Done and closed" in said
    assert transitions_of(ops, "SANDBOX-30") == ["51", "21", "41"], "Reopen, Resolve, Close"
    assert ops.incidents["SANDBOX-30"].status == "Closed"
    assert ops.incidents["SANDBOX-30"].resolution == RESOLUTION


def test_a_rerun_before_the_admin_fix_leaves_it_completed_again_and_says_why(compose):
    ops = FakeOps(
        {"OPS-30": FakeIncident("Completed", ["fp-87e2f184874a3b71"])},
        resolve_screen_lacks_resolution=True,
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.left == {"OPS-30": UNRESOLVED}
    assert outcome.stuck == []
    assert ops.incidents["OPS-30"].status == "Completed", "never Closed without a resolution"
    assert ops.incidents["OPS-30"].comments == []


def test_an_unresolved_completed_incident_with_no_road_back_is_left_and_not_deleted(compose):
    workflow = {**WORKFLOW, "Completed": {"41": "Closed"}}
    ops = FakeOps({"OPS-35": FakeIncident("Completed", ["fp-87e2f184874a3b71"])}, workflow=workflow)

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.left == {"OPS-35": NO_ROAD_BACK}
    assert outcome.stuck == []
    assert ops.incidents["OPS-35"].status == "Completed", "Closed would strand it for good"


def test_an_unresolved_completed_incident_that_is_not_a_runs_is_left_alone(compose):
    ops = FakeOps({"OPS-36": FakeIncident("Completed", ["customer-reported"])})

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert outcome.left == {"OPS-36": NOT_A_RUNS}
    assert outcome.stuck == []
    assert not any(call[:2] == ("lifecycle", "transition") for call in ops.calls)


def test_every_page_of_open_incidents_is_read_before_any_is_moved(compose):
    ops = FakeOps(
        {f"OPS-{n}": FakeIncident("Open", ["fp-87e2f184874a3b71"]) for n in range(1, 131)}
    )

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert len(outcome.closed) == 130, "a search walked while moving issues skips some"
    assert all(incident.status == "Closed" for incident in ops.incidents.values())
    open_search = ops.calls[:3]
    assert all(call[:2] == ("search", "jql") for call in open_search)
    assert [call[-1] for call in open_search[1:]] == ["50", "100"], "each page by its token"


def test_every_page_of_stuck_incidents_is_reported(compose):
    ops = FakeOps({f"OPS-{n}": FakeIncident("Canceled", []) for n in range(1, 76)})

    outcome = reset(KEY, jira_as=ops, compose=compose)

    assert len(outcome.stuck) == 75


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, ["docker", "compose", "start", "traffic"]),
        FileNotFoundError(2, "No such file or directory", "docker"),
        subprocess.TimeoutExpired(["docker", "compose", "start", "traffic"], 120),
    ],
    ids=["compose-exits-non-zero", "no-docker", "compose-hangs"],
)
def test_a_compose_failure_still_reports_the_jira_changes_and_says_how_to_start_traffic(
    tmp_path, failure, capsys
):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps({"SANDBOX-3": FakeIncident("Open", ["fp-87e2f184874a3b71"])}, key="SANDBOX")

    assert main([], env_file=env_file, compose=FakeCompose(failure=failure), jira_as=ops) == 1

    said = capsys.readouterr().out
    assert "SANDBOX-3: completed with resolution Done and closed" in said
    assert "traffic NOT started" in said
    assert "start the traffic with `docker compose start traffic`" in said
    assert said.rstrip().endswith("queue is empty"), "the queue did empty; only traffic failed"
    assert ops.incidents["SANDBOX-3"].status == "Closed"


def test_the_delete_hint_actually_deletes_and_warns_that_it_is_permanent(tmp_path, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps({"SANDBOX-6": FakeIncident("Canceled", ["fp-87e2f184874a3b71"])}, key="SANDBOX")

    assert main([], env_file=env_file, compose=FakeCompose(), jira_as=ops) == 1

    line = next(line for line in capsys.readouterr().out.splitlines() if "SANDBOX-6" in line)
    assert "`jira-as api call deleteIssue --issueIdOrKey SANDBOX-6 --confirm`" in line
    assert "permanent" in line


def test_the_report_names_why_each_incident_was_left(tmp_path, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps(
        {
            "SANDBOX-7": FakeIncident("Open", ["fp-87e2f184874a3b71"]),
            "SANDBOX-8": FakeIncident("Pending", ["fp-deadbeef00000000"]),
        },
        key="SANDBOX",
        resolve_screen_lacks_resolution=True,
    )

    assert main([], env_file=env_file, compose=FakeCompose(), jira_as=ops) == 1

    said = capsys.readouterr().out.splitlines()
    assert f"SANDBOX-7: {UNRESOLVED}" in said
    assert f"SANDBOX-8: {NO_ROAD}" in said
    assert said[-1] == "queue is NOT empty"


def test_a_dry_run_reads_everything_and_changes_nothing(compose):
    ops = FakeOps(
        {
            "OPS-20": FakeIncident("Open", ["fp-87e2f184874a3b71"]),
            "OPS-24": FakeIncident("Pending", ["fp-deadbeef00000000"]),
            "OPS-22": FakeIncident("Open", ["customer-reported"]),
            "OPS-6": FakeIncident("Canceled", ["fp-87e2f184874a3b71"]),
            "OPS-30": FakeIncident("Completed", ["fp-87e2f184874a3b71"]),
        }
    )

    outcome = reset(KEY, jira_as=ops, compose=compose, dry_run=True)

    assert outcome.dry_run
    assert outcome.closed == ["OPS-20", "OPS-30"], "a road to Completed, or back to Open"
    assert outcome.left == {"OPS-24": NO_ROAD}
    assert outcome.skipped == ["OPS-22"]
    assert outcome.stuck == ["OPS-6"]
    assert not outcome.traffic_started
    assert compose.calls == []
    asked = {call[:2] for call in ops.calls}
    assert asked <= {("search", "jql"), ("lifecycle", "transitions")}, asked
    assert [incident.status for incident in ops.incidents.values()] == [
        "Open",
        "Pending",
        "Open",
        "Canceled",
        "Completed",
    ]
    assert all(incident.comments == [] for incident in ops.incidents.values())


def test_a_dry_run_prints_what_would_change_and_says_nothing_did(tmp_path, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)
    ops = FakeOps({"SANDBOX-3": FakeIncident("Open", ["fp-87e2f184874a3b71"])}, key="SANDBOX")
    compose = FakeCompose()

    assert main(["--dry-run"], env_file=env_file, compose=compose, jira_as=ops) == 0

    said = capsys.readouterr().out.splitlines()
    assert "SANDBOX-3: would be completed with resolution Done and closed" in said
    assert "traffic would be started" in said
    assert "dry run: nothing was changed" in said
    assert any("shows only in a real run" in line for line in said), "it cannot foresee that"
    assert said[-1] == "queue would be empty"
    assert ops.incidents["SANDBOX-3"].status == "Open"
    assert compose.calls == []


# --- The project and the credential come from .env (step 02 of demo-onboarding) ---


def test_the_reset_searches_the_project_it_is_given_and_no_other(compose):
    ops = FakeOps({"SANDBOX-3": FakeIncident("Open", ["fp-87e2f184874a3b71"])}, key="SANDBOX")

    outcome = reset("SANDBOX", jira_as=ops, compose=compose)

    assert outcome.closed == ["SANDBOX-3"]
    searched = [call[2] for call in ops.calls if call[:2] == ("search", "jql")]
    assert searched and all(jql.startswith('project = "SANDBOX" AND ') for jql in searched)


RECORDING_JIRA_AS = """\
#!{python}
import json, os, pathlib, sys
with pathlib.Path({record!r}).open("a") as record:
    record.write(json.dumps({{"argv": sys.argv[1:], "environment": dict(os.environ)}}) + "\\n")
print(json.dumps({{"issues": []}}))
"""
"""A stand-in for `jira-as` on PATH that records how it was started and finds nothing open.
The record's path is written into it, because its environment is not the test's to extend."""

ENV_FILE = """\
JIRA_SITE_URL=https://demo-site.atlassian.net
JIRA_EMAIL=demo@example.invalid
JIRA_API_TOKEN=the-token-in-dot-env
CLAUDE_CODE_OAUTH_TOKEN=an-anthropic-oauth-token
DEMO_PROJECT_KEY=SANDBOX
"""

PLATFORM_ADDITIONS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
"""What macOS adds to every child process; the laptop helpers run there."""


@pytest.fixture
def jira_as_on_path(tmp_path, monkeypatch) -> Path:
    """Put the stand-in first on this shell's PATH, in a shell configured for production."""
    record = tmp_path / "jira-as-calls.jsonl"
    stand_in = tmp_path / "bin" / "jira-as"
    stand_in.parent.mkdir()
    stand_in.write_text(RECORDING_JIRA_AS.format(python=sys.executable, record=str(record)))
    stand_in.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stand_in.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("JIRA_SITE_URL", "https://production.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "the-token-for-production")
    monkeypatch.setenv("JIRA_ALLOWED_PROJECTS", "PROD")
    monkeypatch.setenv("JIRA_AS_TRANSPORT", "simulation")
    return record


def calls_to(record: Path) -> list[dict]:
    if not record.exists():
        return []
    return [json.loads(line) for line in record.read_text().splitlines()]


def test_jira_as_is_started_with_env_s_credential_and_project_and_nothing_of_the_shell(
    tmp_path, jira_as_on_path, compose, capsys, monkeypatch
):
    # The trust store and the explicit proxy are the shell's to pass on by design; a shell
    # that has them set must not decide this test.
    for variable in (*TRUST_STORE_VARIABLES, *PROXY_VARIABLES):
        monkeypatch.delenv(variable, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE)

    assert main([], env_file=env_file, compose=compose) == 0

    calls = calls_to(jira_as_on_path)
    assert [call["argv"][:2] for call in calls] == [["search", "jql"]] * 3
    for call in calls:
        environment = call["environment"]
        assert set(environment) - PLATFORM_ADDITIONS == {
            "PATH",
            "HOME",
            "JIRA_SITE_URL",
            "JIRA_EMAIL",
            "JIRA_API_TOKEN",
            "JIRA_ALLOWED_PROJECTS",
            "JIRA_ALLOW_SITE_OPERATIONS",
        }
        assert environment["JIRA_SITE_URL"] == "https://demo-site.atlassian.net"
        assert environment["JIRA_API_TOKEN"] == "the-token-in-dot-env"
        assert environment["JIRA_ALLOWED_PROJECTS"] == "SANDBOX"
        assert environment["JIRA_ALLOW_SITE_OPERATIONS"] == "true"
    assert compose.calls == [("start", "traffic")]
    said = capsys.readouterr()
    assert "production.atlassian.net" in said.err, "the shell's other site is said out loud"
    assert "the-token" not in said.out + said.err


def test_without_an_env_file_the_reset_says_how_to_make_one_and_touches_nothing(
    tmp_path, jira_as_on_path, compose, capsys
):
    assert main([], env_file=tmp_path / ".env", compose=compose) == 1

    assert "cp .env.example .env" in capsys.readouterr().err
    assert calls_to(jira_as_on_path) == []
    assert compose.calls == []


def test_an_env_file_without_a_project_key_is_refused_before_jira_is_asked_anything(
    tmp_path, jira_as_on_path, compose, capsys
):
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FILE.replace("DEMO_PROJECT_KEY=SANDBOX", "DEMO_PROJECT_KEY="))

    assert main([], env_file=env_file, compose=compose) == 1

    said = capsys.readouterr().err
    assert "DEMO_PROJECT_KEY" in said
    assert "the-token" not in said
    assert calls_to(jira_as_on_path) == []
    assert compose.calls == []


@pytest.mark.parametrize("initial", ["New", "In Progress", "Resolved"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_custom_workflow_reset_resolves_and_skips_close(
    tmp_path, compose, capsys, initial, dry_run
):
    project = DemoProject(
        "SANDBOX",
        status_open="New",
        status_in_progress="In Progress",
        status_done="Resolved",
        status_closed="",
    )
    workflow = {
        name: {"to-open": "New", "to-done": "Resolved"}
        for name in ("New", "In Progress", "Resolved")
    }
    ops = FakeOps(
        {"SANDBOX-1": FakeIncident(initial, ["fp-example"])},
        key=project.key,
        workflow=workflow,
        status_open=project.status_open,
        status_done=project.status_done,
        done_statuses={"Resolved", "Canceled"},
    )
    path = tmp_path / ".env"
    path.write_text(
        ENV_FILE
        + "DEMO_STATUS_OPEN=New\nDEMO_STATUS_IN_PROGRESS=In Progress\nDEMO_STATUS_DONE=Resolved\nDEMO_STATUS_CLOSED=\n"
    )

    assert main(["--dry-run"] if dry_run else [], env_file=path, jira_as=ops, compose=compose) == 0

    out = capsys.readouterr().out
    assert "left in Resolved; no close step in this workflow" in out
    assert not any(
        "Closed" in argument or "Completed" in argument for call in ops.calls for argument in call
    )
    transitions = [call for call in ops.calls if call[:2] == ("lifecycle", "transition")]
    if dry_run:
        assert not transitions
        assert ops.incidents["SANDBOX-1"].status == initial
        assert not compose.calls
    else:
        assert transitions[-1] == (
            "lifecycle",
            "transition",
            "SANDBOX-1",
            "--id",
            "to-done",
            "--resolution",
            "Done",
        )
        if initial == "Resolved":
            assert transitions[0][-1] == "to-open"
        assert ops.incidents["SANDBOX-1"].status == "Resolved"
        assert ops.incidents["SANDBOX-1"].resolution == "Done"
        assert "no close step in this workflow" in ops.incidents["SANDBOX-1"].comments[-1]
        assert compose.calls == [("start", "traffic")]
