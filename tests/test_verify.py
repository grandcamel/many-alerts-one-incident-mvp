"""`verify`: one Incident's lifecycle watched stage by stage, with the whole demo faked.

The fake is one small simulation on a fake clock, so a six-minute watch takes no time:
`docker compose stop traffic` makes Grafana's rule Pending and then Firing on the
rehearsal's timings, Firing sends a Notification and repeats it every seventy seconds,
starting the traffic brings the rule back to Normal and sends the Resolved, and each
Notification is a Run that, thirty seconds after the one before it finished, changes
the fake project the way the Skill says: create with an opening comment, a trend comment
and Work in progress on the first repeat, a closing comment and Completed with Done on
the Resolved. jira-as is that project answering the read-only calls `verify` makes, and
fails the test on any other. Each failure a test needs is a switch on the simulation.
A few tests use real HTTP instead: posting at a real Receiver, and asking a fake
Grafana on an ephemeral port.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from grafana_jsm_sandbox import replay, verify
from grafana_jsm_sandbox.doctor import GrafanaUnanswered
from grafana_jsm_sandbox.replay import FIXTURES, SEQUENCE
from grafana_jsm_sandbox.verify import (
    LABELLED,
    MATCH,
    POLL,
    RECENT,
    RUN_MARGIN,
    Timeouts,
    World,
    grafana_state_at,
    main,
    run_compose,
)
from tests.conftest import REPOSITORY
from tests.test_configure import older_python
from tests.test_doctor import FakeGrafana
from tests.test_end_to_end import verify_arguments

KEY = "SANDBOX"
SITE = "https://sandbox.example.invalid"
TOKEN = "the-token-in-dot-env-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
OAUTH_TOKEN = "sk-ant-oat01-an-anthropic-oauth-token-that-must-never-be-printed"

FINGERPRINT = json.loads((FIXTURES / SEQUENCE[0]).read_text())["alerts"][0]["fingerprint"]
LABEL = f"fp-{FINGERPRINT}"

RECEIVER = "http://127.0.0.1:18080"
"""Where the fake Receiver is said to be; the simulation never opens it."""

LINE = re.compile(
    r"^\[\+\d+s\] (WAIT|OK|WARN|FAIL|NOTE) "
    r"(preflight|traffic stopped|firing|posted|created|commented|work in progress"
    r"|traffic started|normal|completed|cleanup) — [^\n]+$"
)
END = re.compile(
    r"^(VERIFIED: [A-Z][A-Z0-9_]+-\d+ Open → Work in progress → Completed with resolution \S+ "
    r"in \d+s|NOT VERIFIED: [a-z ]+ — .+)$"
)
"""The documented output, which the setup skill parses."""

ASK = re.compile(r"docs/admin-requests\.md#([a-z0-9-]+)")

PENDING_AFTER = 30.0
FIRING_AFTER = 60.0
GROUP_WAIT = 8.0
REPEAT_EVERY = 70.0
NORMAL_AFTER = 15.0
RUN_SECONDS = 30.0
"""The rehearsal's timings, rounded (the runbook's record)."""

DONE = {"Completed", "Closed", "Canceled"}


class FakeClock:
    """Monotonic seconds that pass only when `verify` sleeps."""

    def __init__(self, start: float = 1000.0):
        self.time = start
        self.interrupt_at: float | None = None

    def now(self) -> float:
        return self.time

    def sleep(self, seconds: float) -> None:
        self.time += seconds
        if self.interrupt_at is not None and self.time >= self.interrupt_at:
            raise KeyboardInterrupt


@dataclass
class FakeIncident:
    status: str
    labels: list[str]
    resolution: str | None = None
    comments: int = 0
    created: float = 0.0


@dataclass
class Demo:
    """The demo, from the traffic to the project, on a fake clock. Every switch is a failure."""

    clock: FakeClock = field(default_factory=FakeClock)
    incidents: dict[str, FakeIncident] = field(default_factory=dict)
    next_number: int = 1

    # Grafana
    rule_before: str | None = "inactive"
    """What Grafana says before the traffic is touched."""
    never_fires: bool = False
    stays_firing: bool = False
    grafana_down: bool = False

    # compose
    stop_fails: bool = False
    start_fails: bool = False
    compose_calls: list[tuple[str, ...]] = field(default_factory=list)

    # the Receiver
    receiver_down: bool = False
    receiver_status: int = 202
    posted: list[str] = field(default_factory=list)

    # the Runs
    failing_runs: set[str] = field(default_factory=set)
    """The Notifications whose Run does nothing: `firing`, `repeat`, `resolved`."""
    label_created: str = LABEL
    """The label the Firing's Run gives the Incident: another when the live Fingerprint differs."""
    no_opening_comment: bool = False
    resolve_screen_drops_resolution: bool = False
    repeat_lands_on: str = "Work in progress"
    duplicate_create: bool = False
    no_closing_comment: bool = False

    # jira-as
    jira_as_fails: int = 0
    """How many jira-as calls, from the next one, fail."""
    jira_as_failure: str = "jira-as failed: HTTP 503"
    jira_calls: list[tuple[str, ...]] = field(default_factory=list)

    stopped_at: float | None = None
    started_at: float | None = None
    replayed: list[tuple[float, str]] = field(default_factory=list)
    _runs_done: int = 0
    _run_ends: list[float] = field(default_factory=list)

    # --- the world as verify sees it ---

    def world(self, out: list[str]) -> World:
        return World(
            jira_as=self.jira_as,
            compose=self.compose,
            post=self.post,
            grafana_state=self.grafana_state,
            now=self.clock.now,
            sleep=self.clock.sleep,
            out=out.append,
        )

    def compose(self, *arguments: str) -> None:
        self.compose_calls.append(arguments)
        if arguments == ("stop", "traffic"):
            if self.stop_fails:
                raise verify.ComposeFailed(1, ["docker", "compose", *arguments], "", "no stack")
            self.stopped_at = self.clock.now()
        elif arguments == ("start", "traffic"):
            if self.start_fails:
                raise verify.ComposeFailed(1, ["docker", "compose", *arguments], "", "no stack")
            self.started_at = self.clock.now()
        else:
            raise AssertionError(f"verify asked compose for {arguments}")

    def post(self, url: str, notification: bytes) -> int:
        assert url == RECEIVER + "/notification"
        if self.receiver_down:
            raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
        # The repeat is the Firing sent again, byte for byte, so the order tells them apart.
        if json.loads(notification)["status"] == "resolved":
            kind = "resolved"
        else:
            kind = "repeat" if any(k == "firing" for _, k in self.replayed) else "firing"
        self.posted.append(SEQUENCE[("firing", "repeat", "resolved").index(kind)])
        if self.receiver_status == 202:
            self.replayed.append((self.clock.now(), kind))
        return self.receiver_status

    def grafana_state(self) -> str | None:
        if self.grafana_down:
            raise GrafanaUnanswered("nothing answered at http://127.0.0.1:3000 (refused)")
        now = self.clock.now()
        if self.stopped_at is None:
            return self.rule_before
        normal = self._normal_at()
        firing = self._firing_at()
        if normal is not None and now >= normal:
            return "inactive"
        if firing is not None and now >= firing:
            return "firing"
        if now >= self.stopped_at + PENDING_AFTER:
            return "pending"
        return "inactive"

    def jira_as(self, *arguments: str) -> str:
        self.jira_calls.append(arguments)
        if self.jira_as_fails:
            self.jira_as_fails -= 1
            raise RuntimeError(self.jira_as_failure)
        self._catch_up()
        match arguments:
            case ("search", "jql", jql, "--fields", "key,status,labels", "-o", "json"):
                return json.dumps({"issues": self._search(jql), "isLast": True})
            case ("issue", "get", key, "--fields", "status,resolution", "-o", "json"):
                incident = self.incidents[key]
                resolution = incident.resolution and {"name": incident.resolution}
                return json.dumps(
                    {
                        "key": key,
                        "fields": {"status": {"name": incident.status}, "resolution": resolution},
                    }
                )
            case ("collaborate", "comment", "list", key, "-o", "json"):
                return json.dumps({"total": self.incidents[key].comments, "comments": []})
        raise AssertionError(f"verify only reads, and asked jira-as for {arguments}")

    # --- the simulation ---

    def add(self, status: str, labels: list[str], resolution: str | None = None) -> str:
        key = f"{KEY}-{self.next_number}"
        self.next_number += 1
        self.incidents[key] = FakeIncident(status, labels, resolution, comments=1)
        return key

    def _firing_at(self) -> float | None:
        if self.stopped_at is None or self.never_fires:
            return None
        return self.stopped_at + FIRING_AFTER

    def _normal_at(self) -> float | None:
        if self.started_at is None or self.stays_firing:
            return None
        return self.started_at + NORMAL_AFTER

    def _notifications(self) -> list[tuple[float, str]]:
        """What reached the Receiver by now: the replay's posts, or Grafana's own."""
        now = self.clock.now()
        sent = [(when, kind) for when, kind in self.replayed if when <= now]
        firing = self._firing_at()
        if firing is None:
            return sent
        normal = self._normal_at()
        when, kind = firing + GROUP_WAIT, "firing"
        while when <= now and (normal is None or when < normal):
            sent.append((when, kind))
            when, kind = when + REPEAT_EVERY, "repeat"
        if normal is not None and normal <= now:
            sent.append((normal + 4, "resolved"))
        return sorted(sent)

    def _catch_up(self) -> None:
        """Finish every Run that would have finished by now, one at a time, in order."""
        notifications = self._notifications()
        while self._runs_done < len(notifications):
            when, kind = notifications[self._runs_done]
            previous = self._run_ends[-1] if self._run_ends else when
            end = max(when, previous) + RUN_SECONDS
            if end > self.clock.now():
                return
            self._run_ends.append(end)
            self._runs_done += 1
            if kind not in self.failing_runs:
                self._run(kind, end)

    def _run(self, kind: str, when: float) -> None:
        match = [
            key
            for key, incident in self.incidents.items()
            if self.label_created in incident.labels and incident.status not in DONE
        ]
        if kind in ("firing", "repeat") and not match:
            key = self.add("Open", [self.label_created])
            self.incidents[key].comments = 0 if self.no_opening_comment else 1
            self.incidents[key].created = when
            if self.duplicate_create:
                self.add("Open", [self.label_created])
            return
        if not match:
            return
        incident = self.incidents[match[0]]
        if kind in ("firing", "repeat"):
            incident.comments += 1
            if incident.status == "Open":
                incident.status = self.repeat_lands_on
        elif kind == "resolved":
            incident.comments += 0 if self.no_closing_comment else 1
            incident.status = "Completed"
            if not self.resolve_screen_drops_resolution:
                incident.resolution = "Done"

    def _search(self, jql: str) -> list[dict]:
        labelled = re.search(r'labels = "([^"]+)"', jql)
        recent = re.search(r'created >= "-(\d+)m"', jql)
        assert jql.startswith(f'project = "{KEY}" AND issuetype = Incident'), jql
        found = []
        for key, incident in self.incidents.items():
            if labelled and labelled[1] not in incident.labels:
                continue
            if "statusCategory != Done" in jql and incident.status in DONE:
                continue
            if recent and incident.created < self.clock.now() - 60 * int(recent[1]):
                continue
            found.append(
                {
                    "key": key,
                    "fields": {"status": {"name": incident.status}, "labels": incident.labels},
                }
            )
        assert labelled or recent, jql
        return found


def run(demo: Demo, mode: str = verify.REPLAY, **options) -> tuple[int, list[str]]:
    out: list[str] = []
    status = verify.verify(
        mode, KEY, demo.world(out), receiver=RECEIVER, timeouts=options.pop("timeouts", None)
    )
    assert not options
    return status, out


def stages(out: list[str]) -> list[tuple[str, str]]:
    """(level, stage) of each stage line, in order."""
    return [
        (found[1], found[2])
        for text in out
        if (found := re.match(r"^\[\+\d+s\] (\w+) ([a-z ]+) — ", text))
    ]


def line(out: list[str], level: str, stage: str) -> str:
    matching = [text for text in out if re.match(rf"^\[\+\d+s\] {level} {stage} — ", text)]
    assert len(matching) == 1, (level, stage, out)
    return matching[0]


def elapsed(text: str) -> int:
    return int(re.match(r"^\[\+(\d+)s\]", text)[1])


def assert_documented(out: list[str]) -> None:
    for text in out[:-1]:
        assert LINE.match(text), text
    assert END.match(out[-1]), out[-1]
    assert sum(1 for text in out if text.startswith(("VERIFIED", "NOT VERIFIED"))) == 1


def assert_read_only(demo: Demo) -> None:
    for call in demo.jira_calls:
        assert call[:2] in {("search", "jql"), ("issue", "get")} or call[:3] == (
            "collaborate",
            "comment",
            "list",
        ), call


@pytest.fixture
def demo() -> Demo:
    return Demo()


# --- The replay ---


def test_a_replay_watches_one_incident_through_every_stage_and_is_verified(demo):
    status, out = run(demo)

    assert status == 0
    assert out[-1].startswith(
        f"VERIFIED: {KEY}-1 Open → Work in progress → Completed with resolution Done in "
    )
    assert [stage for level, stage in stages(out) if level == "OK"] == [
        "preflight",
        "posted",
        "created",
        "commented",
        "posted",
        "work in progress",
        "posted",
        "completed",
    ]
    assert demo.posted == list(SEQUENCE)
    assert demo.compose_calls == [], "a replay leaves the traffic alone"
    assert_documented(out)
    assert_read_only(demo)


def test_each_notification_is_posted_only_once_the_incident_answered_the_one_before(demo):
    status, out = run(demo)

    assert status == 0
    posts = [text for text in out if " OK posted — " in text]
    assert elapsed(posts[1]) >= elapsed(line(out, "OK", "commented"))
    assert elapsed(posts[2]) >= elapsed(line(out, "OK", "work in progress"))


def test_every_stage_says_how_long_it_took(demo):
    status, out = run(demo)

    assert status == 0
    created = line(out, "OK", "created")
    assert f"{KEY}-1 (Open), 30s after posting the Firing" in created
    assert elapsed(created) == 30
    assert "after posting the repeat" in line(out, "OK", "work in progress")
    assert "after posting the Resolved" in line(out, "OK", "completed")


def test_a_leftover_incident_with_the_label_is_not_taken_for_this_run_s(demo):
    """A rehearsal's Completed Incident carries the same label; the watch waits for a new one."""
    old = demo.add("Completed", [LABEL], resolution="Done")

    status, out = run(demo)

    assert status == 0
    assert f"1 earlier one(s) ({old}) are not this run's" in line(out, "OK", "preflight")
    assert out[-1].startswith(f"VERIFIED: {KEY}-2 ")
    assert elapsed(line(out, "OK", "created")) == 30, "not the leftover, found at once"


def test_an_open_match_stops_it_before_anything_is_posted(demo):
    leftover = demo.add("Work in progress", [LABEL])

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "preflight")
    assert f"{leftover} is open and already carries {LABEL}" in failed
    assert "python3 -m grafana_jsm_sandbox.reset" in failed
    assert demo.posted == []
    assert out[-1].startswith("NOT VERIFIED: preflight — ")
    assert not any(" NOTE cleanup — " in text for text in out), "it had not begun"
    assert_documented(out)


def test_a_replay_refuses_while_grafana_is_firing(demo):
    demo.rule_before = "firing"

    status, out = run(demo)

    assert status == 1
    assert "is firing, not Normal" in line(out, "FAIL", "preflight")
    assert demo.posted == []


def test_a_replay_goes_on_without_grafana_and_says_so(demo):
    """Grafana being down is one of the reasons to replay at all."""
    demo.grafana_down = True

    status, out = run(demo)

    assert status == 0
    assert "Grafana did not answer" in line(out, "WARN", "preflight")


def test_a_receiver_that_is_not_there_is_named(demo):
    demo.receiver_down = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "posted")
    assert f"nothing answered at {RECEIVER}" in failed
    assert "docker compose ps" in failed
    assert_documented(out)


def test_a_receiver_that_refuses_the_notification_is_named(demo):
    demo.receiver_status = 400

    status, out = run(demo)

    assert status == 1
    assert "answered notification-firing.json with 400, not 202" in line(out, "FAIL", "posted")


# --- Stages that do not come ---


def test_no_incident_names_the_stage_the_wait_and_where_to_look(demo):
    demo.failing_runs = {"firing"}

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "created")
    run_timeout = Timeouts().run
    assert (
        f"no Incident within {run_timeout:.0f}s of posting the Firing: check `docker compose "
        "logs demo` for [FAILED]"
    ) in failed
    assert elapsed(failed) == run_timeout
    assert out[-1] == f"NOT VERIFIED: created — {failed.split(' — ', 1)[1]}"
    assert demo.posted == [SEQUENCE[0]], "nothing more is posted after a failed stage"
    assert_documented(out)


def test_an_incident_under_another_fingerprint_is_pointed_out(demo):
    demo.label_created = "fp-0123456789abcdef"

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "created")
    assert f"{KEY}-1 was created meanwhile with fp-0123456789abcdef instead" in failed
    assert "run again with --fingerprint 0123456789abcdef" in failed


def test_an_incident_without_its_opening_comment_fails_the_comment_stage(demo):
    demo.no_opening_comment = True

    status, out = run(demo)

    assert status == 1
    assert "OK created" in " ".join(out)
    assert f"{KEY}-1 has no comment" in line(out, "FAIL", "commented")


def test_a_repeat_whose_run_fails_times_out_at_work_in_progress(demo):
    demo.failing_runs = {"repeat"}

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "work in progress")
    assert f"{KEY}-1 is still Open with 1 comment(s)" in failed
    assert "[FAILED]" in failed


def test_an_incident_taken_off_the_path_fails_at_once(demo):
    demo.repeat_lands_on = "Canceled"

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "work in progress")
    assert "went to Canceled instead of Work in progress" in failed
    assert elapsed(failed) < 30 + 30 + Timeouts().run, "no waiting out the whole stage"


def test_completed_without_a_resolution_names_the_resolve_screen_request(demo):
    demo.resolve_screen_drops_resolution = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "completed")
    assert f"{KEY}-1 is Completed without a resolution" in failed
    assert ASK.findall(failed) == ["jira-admin-resolution-screen"]
    assert "Completed without a resolution" in out[-1]
    assert f"{KEY}-1 is left Completed: `python3 -m grafana_jsm_sandbox.reset`" in line(
        out, "NOTE", "cleanup"
    )
    assert_documented(out)


def test_a_resolved_run_that_never_completes_times_out_at_completed(demo):
    demo.failing_runs = {"resolved"}

    status, out = run(demo)

    assert status == 1
    assert "is still Work in progress" in line(out, "FAIL", "completed")


def test_a_missing_closing_comment_is_a_warning_not_a_failure(demo):
    demo.no_closing_comment = True

    status, out = run(demo)

    assert status == 0
    assert "without its closing comment" in line(out, "WARN", "completed")


def test_a_second_incident_for_one_firing_is_warned_about_and_the_first_watched(demo):
    demo.duplicate_create = True

    status, out = run(demo)

    assert status == 0
    assert f"{KEY}-1, {KEY}-2 all carry {LABEL}" in line(out, "WARN", "created")
    assert out[-1].startswith(f"VERIFIED: {KEY}-1 ")


# --- jira-as ---


def test_a_passing_jira_as_failure_is_ridden_out(demo):
    """Two failures in a row, just after the preflight's two searches, are a blip."""
    original = demo.jira_as
    seen = {"calls": 0}

    def flaky(*arguments):
        seen["calls"] += 1
        if seen["calls"] in (3, 4):
            raise RuntimeError("jira-as failed: HTTP 503")
        return original(*arguments)

    demo.jira_as = flaky
    status, out = run(demo)

    assert status == 0, out


def test_an_answer_that_is_not_json_is_ridden_out_like_a_failure(demo):
    original = demo.jira_as
    seen = {"calls": 0}

    def garbled(*arguments):
        seen["calls"] += 1
        answer = original(*arguments)
        return "<html>gateway timeout</html>" if seen["calls"] == 3 else answer

    demo.jira_as = garbled
    status, out = run(demo)

    assert status == 0, out


def test_jira_as_failing_again_and_again_ends_the_stage_without_a_secret(demo):
    demo.jira_as_failure = (
        f"jira-as search failed: 401 Unauthorized, Authorization: Basic {TOKEN} was refused"
    )
    original = demo.jira_as
    seen = {"calls": 0}

    def failing_after_preflight(*arguments):
        seen["calls"] += 1
        if seen["calls"] > 2:
            raise RuntimeError(demo.jira_as_failure)
        return original(*arguments)

    demo.jira_as = failing_after_preflight
    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "created")
    assert "jira-as failed 3 times in a row" in failed
    assert "--only env,jira" in failed
    assert TOKEN not in "\n".join(out)


def test_jira_as_refusing_the_first_search_fails_the_preflight(demo):
    demo.jira_as_fails = 1

    status, out = run(demo)

    assert status == 1
    assert f"jira-as could not search {KEY}" in line(out, "FAIL", "preflight")
    assert demo.posted == []


def timing_out_after(demo: Demo, calls: int, times: int | None = None):
    """jira-as as `reset.jira_as_with` fails when a slow site outlasts its timeout: from call
    `calls + 1`, `times` times (for ever when None)."""
    original = demo.jira_as
    seen = {"calls": 0}

    def slow(*arguments):
        seen["calls"] += 1
        if seen["calls"] > calls and (times is None or seen["calls"] <= calls + times):
            raise subprocess.TimeoutExpired(["jira-as", *arguments], 120)
        return original(*arguments)

    return slow


def test_a_jira_as_call_that_times_out_once_is_ridden_out(demo):
    demo.jira_as = timing_out_after(demo, calls=2, times=1)

    status, out = run(demo)

    assert status == 0, out


def test_jira_as_timing_out_again_and_again_ends_the_stage_in_a_line(demo):
    demo.jira_as = timing_out_after(demo, calls=2)

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "created")
    assert "jira-as failed 3 times in a row, last: no answer within 120s" in failed
    assert "--only env,jira" in failed
    assert out[-1].startswith("NOT VERIFIED: created — jira-as failed 3 times")
    assert_documented(out)


def test_jira_as_timing_out_live_still_starts_the_traffic_and_ends_in_a_verdict(demo):
    demo.jira_as = timing_out_after(demo, calls=2)

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "no answer within 120s" in line(out, "FAIL", "created")
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert line(out, "OK", "traffic started")
    assert_documented(out)


def test_no_jira_as_on_path_fails_the_preflight_and_names_the_host_check(demo):
    def missing(*arguments):
        raise FileNotFoundError(2, "No such file or directory", "jira-as")

    demo.jira_as = missing

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "preflight")
    assert "jira-as is not on PATH" in failed
    assert "`python3 -m grafana_jsm_sandbox.doctor --only host`" in failed
    assert demo.posted == []
    assert_documented(out)


def test_jira_as_gone_mid_watch_fails_at_once_rather_than_waiting(demo):
    original = demo.jira_as
    seen = {"calls": 0}

    def vanishing(*arguments):
        seen["calls"] += 1
        if seen["calls"] > 2:
            raise FileNotFoundError(2, "No such file or directory", "jira-as")
        return original(*arguments)

    demo.jira_as = vanishing

    status, out = run(demo)

    assert status == 1
    assert "jira-as is not on PATH" in line(out, "FAIL", "created")
    assert seen["calls"] == 3, "one look, not three"


def test_an_answer_of_another_shape_is_ridden_out_like_a_failure(demo):
    original = demo.jira_as
    shaped = {"once": False}

    def reshaped(*arguments):
        answer = original(*arguments)
        if arguments[:2] == ("issue", "get") and not shaped["once"]:
            shaped["once"] = True
            return json.dumps({"key": arguments[2], "errorMessages": ["try again"]})
        return answer

    demo.jira_as = reshaped
    status, out = run(demo)

    assert status == 0, out
    assert shaped["once"]


def test_an_answer_of_another_shape_every_time_ends_in_a_line(demo):
    original = demo.jira_as

    def reshaped(*arguments):
        answer = original(*arguments)
        if arguments[:2] == ("issue", "get"):
            return json.dumps(["not", "an", "issue"])
        return answer

    demo.jira_as = reshaped
    status, out = run(demo)

    assert status == 1
    assert f"jira-as answered {KEY}-1 in an unexpected shape" in line(out, "FAIL", "created")
    assert_documented(out)


# --- Live ---


def test_live_stops_the_traffic_watches_the_alert_and_starts_it_again(demo):
    status, out = run(demo, verify.LIVE)

    assert status == 0, out
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert [stage for level, stage in stages(out) if level == "OK"] == [
        "preflight",
        "traffic stopped",
        "firing",
        "created",
        "commented",
        "work in progress",
        "traffic started",
        "normal",
        "completed",
    ]
    assert demo.posted == [], "live posts nothing; Grafana does"
    assert_documented(out)
    assert_read_only(demo)


def test_live_times_come_from_the_rehearsal(demo):
    status, out = run(demo, verify.LIVE)

    assert status == 0
    firing = line(out, "OK", "firing")
    assert elapsed(firing) == FIRING_AFTER
    assert "60s after the stop" in firing
    # Firing, then the group wait, then a thirty-second Run.
    assert "40s after the Firing" in line(out, "OK", "created")
    # The traffic is started only once the repeat has moved the Incident on.
    assert elapsed(line(out, "OK", "traffic started")) >= elapsed(
        line(out, "OK", "work in progress")
    )
    assert "15s after the start" in line(out, "OK", "normal")


def test_live_needs_the_rule_normal_before_it_stops_anything(demo):
    demo.rule_before = "pending"

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "is pending, not Normal" in line(out, "FAIL", "preflight")
    assert demo.compose_calls == []


def test_live_needs_grafana_and_suggests_the_replay(demo):
    demo.grafana_down = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "verify with --replay" in line(out, "FAIL", "preflight")
    assert demo.compose_calls == []


def test_live_needs_the_rule_evaluated_once(demo):
    demo.rule_before = None

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "has not evaluated" in line(out, "FAIL", "preflight")


def test_a_rule_that_never_fires_is_named_and_the_traffic_started_again(demo):
    demo.never_fires = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    failed = line(out, "FAIL", "firing")
    assert "is still pending 180s after the traffic stopped" in failed
    assert "--only grafana" in failed
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert stages(out)[-2:] == [("OK", "traffic started"), ("NOTE", "cleanup")]
    assert_documented(out)


def test_no_incident_after_a_live_firing_names_the_example_cause(demo):
    demo.failing_runs = {"firing", "repeat"}

    status, out = run(demo, verify.LIVE)

    assert status == 1
    run_timeout = Timeouts().run
    assert (
        f"no Incident within {run_timeout:.0f}s of the Firing: check `docker compose logs demo` "
        "for [FAILED]"
    ) in line(out, "FAIL", "created")
    assert demo.compose_calls[-1] == ("start", "traffic")
    assert "no Incident of this run was seen" in line(out, "NOTE", "cleanup")


def test_a_repeat_that_never_moves_it_on_live_names_grafana_and_the_log(demo):
    demo.failing_runs = {"repeat"}

    status, out = run(demo, verify.LIVE)

    assert status == 1
    failed = line(out, "FAIL", "work in progress")
    assert "Grafana repeats a Firing every minute" in failed
    assert "[FAILED]" in failed
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert f"{KEY}-1 is left Open" in line(out, "NOTE", "cleanup")


def test_a_rule_that_stays_firing_after_the_start_fails_at_normal(demo):
    demo.stays_firing = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "is still firing 120s after the traffic started" in line(out, "FAIL", "normal")
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")], "started once"


def test_an_interruption_still_starts_the_traffic_and_says_so(demo):
    demo.clock.interrupt_at = demo.clock.time + 100

    status, out = run(demo, verify.LIVE)

    assert status == 130
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert out[-1].startswith("NOT VERIFIED: interrupted — ")
    assert line(out, "OK", "traffic started")
    assert_documented(out)


def test_an_interruption_before_the_stop_returns_still_starts_the_traffic(demo):
    def interrupted(*arguments):
        demo.compose_calls.append(arguments)
        if arguments[0] == "stop":
            raise KeyboardInterrupt

    demo.compose = interrupted

    status, _ = run(demo, verify.LIVE)

    assert status == 130
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_a_failed_stop_is_named_and_the_start_still_tried(demo):
    demo.stop_fails = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "`docker compose stop traffic` failed: exit 1: no stack" in line(
        out, "FAIL", "traffic stopped"
    )
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_a_failed_start_says_how_to_start_it_by_hand(demo):
    demo.start_fails = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    failed = line(out, "FAIL", "traffic started")
    assert "start it with `docker compose start traffic`" in failed
    assert out[-1] == "NOT VERIFIED: " + failed.split(" FAIL ", 1)[1], "the FAIL's own words"
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")], "tried once"
    assert_documented(out)


def test_after_a_failure_the_way_to_start_the_traffic_by_hand_is_said_before_trying(demo):
    demo.never_fires = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    levels = [level for level, stage in stages(out) if stage == "traffic started"]
    assert levels == ["WAIT", "OK"]
    assert "start it with `docker compose start traffic`" in line(out, "WAIT", "traffic started")
    assert out[-1].startswith("NOT VERIFIED: firing — "), "the first FAIL is the verdict"
    assert_documented(out)


def test_a_failed_start_on_the_way_out_does_not_take_the_verdict(demo):
    demo.never_fires = True
    demo.start_fails = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert [level for level, _ in stages(out) if level == "FAIL"] == ["FAIL", "FAIL"]
    assert line(out, "FAIL", "traffic started")
    assert out[-1].startswith("NOT VERIFIED: firing — ")
    assert_documented(out)


def test_timeouts_are_the_callers_to_set(demo):
    demo.never_fires = True

    status, out = run(demo, verify.LIVE, timeouts=Timeouts(firing=45))

    assert status == 1
    assert "45s after the traffic stopped" in line(out, "FAIL", "firing")


# --- The cleanup note ---


def test_it_leaves_the_completed_incident_as_it_is_and_says_so(demo):
    status, out = run(demo)

    assert status == 0
    note = line(out, "NOTE", "cleanup")
    assert (
        f"{KEY}-1 is left Completed with resolution Done, already out of the Incidents queue"
        in (note)
    )
    assert "closes and deletes nothing" in note
    assert demo.incidents[f"{KEY}-1"].status == "Completed"


def test_a_failed_run_leaves_its_incident_to_reset(demo):
    demo.failing_runs = {"resolved"}

    status, out = run(demo)

    assert status == 1
    note = line(out, "NOTE", "cleanup")
    assert f"{KEY}-1 is left Work in progress: `python3 -m grafana_jsm_sandbox.reset`" in note
    assert "may still complete it" not in note, "a replay sends no Resolved of its own"


def test_live_warns_that_the_resolved_may_still_complete_what_it_left(demo):
    demo.stays_firing = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    note = line(out, "NOTE", "cleanup")
    assert f"{KEY}-1 is left Work in progress" in note
    assert "the Resolved's Run may still complete it" in note
    assert "`python3 -m grafana_jsm_sandbox.reset --dry-run` shows what is left" in note


# --- The command ---


def env_text(**overrides: str) -> str:
    values = {
        "JIRA_SITE_URL": SITE,
        "JIRA_EMAIL": "ops@example.invalid",
        "JIRA_API_TOKEN": TOKEN,
        "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN,
        "DEMO_PROJECT_KEY": KEY,
        **overrides,
    }
    return "".join(f"{name}={value}\n" for name, value in values.items() if value is not None)


@pytest.fixture
def env_file(tmp_path, monkeypatch) -> Path:
    for name in ("BIND_ADDRESS", "RECEIVER_HOST_PORT", "GRAFANA_HOST_PORT"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".env"
    path.write_text(env_text())
    return path


def command(demo: Demo, argv: list[str], env_file: Path, capsys) -> tuple[int, list[str], str]:
    out: list[str] = []
    status = main(argv, env_file=env_file, world=demo.world(out))
    captured = capsys.readouterr()
    return status, out, captured.out + captured.err


def test_the_command_replays_by_default_at_the_published_receiver(demo, env_file, capsys):
    env_file.write_text(env_text(RECEIVER_HOST_PORT="18080"))

    status, out, _ = command(demo, [], env_file, capsys)

    assert status == 0, out
    assert demo.posted == list(SEQUENCE)


def test_the_command_runs_live_when_asked(demo, env_file, capsys):
    status, out, _ = command(demo, ["--live"], env_file, capsys)

    assert status == 0, out
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_the_run_timeout_is_the_receiver_s_own_plus_a_margin(demo, env_file, capsys):
    env_file.write_text(env_text(RUN_TIMEOUT="120"))
    demo.failing_runs = {"firing"}

    status, out, _ = command(demo, ["--receiver", RECEIVER], env_file, capsys)

    assert status == 1
    assert f"no Incident within {120 + RUN_MARGIN:.0f}s" in line(out, "FAIL", "created")


def test_the_run_timeout_flag_wins(demo, env_file, capsys):
    env_file.write_text(env_text(RUN_TIMEOUT="120"))
    demo.failing_runs = {"firing"}

    status, out, _ = command(
        demo, ["--receiver", RECEIVER, "--run-timeout", "90"], env_file, capsys
    )

    assert status == 1
    assert "no Incident within 90s" in line(out, "FAIL", "created")


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("--firing-timeout", "FIRING_TIMEOUT"),
        ("--repeat-timeout", "REPEAT_TIMEOUT"),
        ("--resolved-timeout", "RESOLVED_TIMEOUT"),
    ],
)
def test_each_grafana_wait_has_a_flag_with_the_documented_default(flag, expected, capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert f"{flag} S" in help_text
    assert f"(default {getattr(verify, expected):.0f})" in help_text


def test_the_fingerprint_flag_names_the_label_watched(demo, env_file, capsys):
    demo.label_created = "fp-0123456789abcdef"

    status, out, _ = command(
        demo, ["--receiver", RECEIVER, "--fingerprint", "0123456789abcdef"], env_file, capsys
    )

    assert status == 0, out
    assert "carries fp-0123456789abcdef" in line(out, "OK", "preflight")


@pytest.mark.parametrize(
    "argv",
    [
        ["--replay", "--live"],
        ["--run-timeout", "0"],
        ["--run-timeout", "soon"],
        ["--fingerprint", "not hex"],
        ["--live", "--receiver", RECEIVER],
    ],
)
def test_bad_arguments_are_a_usage_error(demo, env_file, capsys, argv):
    with pytest.raises(SystemExit) as exit:
        main(argv, env_file=env_file, world=demo.world([]))

    assert exit.value.code == 2
    assert demo.jira_calls == []


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (None, "does not exist"),
        (env_text(DEMO_PROJECT_KEY=""), "DEMO_PROJECT_KEY is not set"),
        (env_text(RUN_TIMEOUT="soon"), "RUN_TIMEOUT in .env is not a number of seconds"),
        (env_text(DEMO_SESSION_ID="Take One"), "DEMO_SESSION_ID is not a session id"),
    ],
)
def test_a_configuration_error_is_exit_2_before_anything_is_asked(
    demo, env_file, capsys, text, said
):
    if text is None:
        env_file.unlink()
    else:
        env_file.write_text(text)

    status, out, printed = command(demo, [], env_file, capsys)

    assert status == 2
    assert said in printed
    assert out == []
    assert demo.jira_calls == demo.compose_calls == demo.posted == []
    assert TOKEN not in printed


def test_a_ctrl_c_before_the_watch_is_a_verdict_not_a_traceback(
    demo, env_file, capsys, monkeypatch
):
    def interrupted(path):
        raise KeyboardInterrupt

    monkeypatch.setattr(verify, "read_env_file", interrupted)

    status, _, printed = command(demo, [], env_file, capsys)

    assert status == 130
    assert printed.strip() == (
        "NOT VERIFIED: interrupted — stopped by the user before anything was asked"
    )
    assert END.match(printed.strip())
    assert demo.jira_calls == demo.compose_calls == demo.posted == []


def test_nothing_it_prints_holds_a_secret(demo, env_file, capsys):
    demo.failing_runs = {"resolved"}

    _, out, printed = command(demo, ["--live"], env_file, capsys)

    for secret in (TOKEN, OAUTH_TOKEN):
        assert secret not in "\n".join(out) + printed


# --- The real world, where it can be had offline ---


def test_the_replay_posts_reach_a_real_receiver(receiver, spawner, demo):
    """The Notifications go over real HTTP, and the Receiver starts a Run for each."""
    posts: list[int] = []

    def through_the_receiver(url: str, notification: bytes) -> int:
        status = replay.post(url, notification)
        posts.append(status)
        demo.post(RECEIVER + "/notification", notification)
        return status

    out: list[str] = []
    world = demo.world(out)
    world.post = through_the_receiver

    status = verify.verify(verify.REPLAY, KEY, world, receiver=receiver.url)

    assert status == 0, out
    assert posts == [202, 202, 202]
    spawner.wait_for_spawns(3)
    assert [run.notification["status"] for run in spawner.spawned] == [
        "firing",
        "firing",
        "resolved",
    ]


@pytest.fixture
def fake_grafana():
    grafana = FakeGrafana()
    grafana.start()
    try:
        yield grafana
    finally:
        grafana.stop()


RULES = "/api/prometheus/grafana/api/v1/rules"


def test_the_rule_state_is_asked_of_grafana_over_http(fake_grafana):
    state = grafana_state_at(f"http://127.0.0.1:{fake_grafana.port}")

    assert state() == "inactive"
    fake_grafana.answers[RULES]["data"]["groups"][0]["rules"][0]["state"] = "firing"
    assert state() == "firing"
    del fake_grafana.answers[RULES]["data"]["groups"][0]["rules"][0]["state"]
    assert state() is None, "a rule listed without a state is not evaluated yet, not 'None'"
    fake_grafana.answers[RULES]["data"]["groups"][0]["rules"] = []
    assert state() is None, "not evaluated yet"


def test_a_grafana_that_is_not_there_is_unanswered(fake_grafana):
    port = fake_grafana.port
    fake_grafana.stop()

    with pytest.raises(GrafanaUnanswered):
        grafana_state_at(f"http://127.0.0.1:{port}")()


def test_compose_is_run_from_the_repo_and_its_complaint_kept(tmp_path, monkeypatch):
    docker = tmp_path / "docker"
    docker.write_text(
        '#!/bin/sh\necho "$(pwd -P) $*" > "$(dirname "$0")/asked"\n'
        'echo "no such service: traffic" >&2\nexit 1\n'
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    with pytest.raises(subprocess.CalledProcessError) as failure:
        run_compose("stop", "traffic")

    assert str(failure.value) == "exit 1: no such service: traffic"
    assert (tmp_path / "asked").read_text().split() == [
        str(REPOSITORY.resolve()),
        "compose",
        "stop",
        "traffic",
    ]


def test_the_jql_is_the_match_a_run_uses():
    assert MATCH == LABELLED + " AND statusCategory != Done"
    assert MATCH.format(key=KEY, label=LABEL) == (
        f'project = "{KEY}" AND issuetype = Incident AND labels = "{LABEL}"'
        " AND statusCategory != Done"
    )
    assert RECENT.format(key=KEY, minutes=3).endswith('created >= "-3m"')


def test_it_polls_no_faster_than_every_five_seconds():
    assert POLL >= 5


# --- The end-to-end check, which is this command run as a test ---


@pytest.mark.parametrize(
    ("environment", "arguments"),
    [
        ({"DEMO_END_TO_END": "1"}, ["--replay"]),
        ({"DEMO_END_TO_END": "live"}, ["--live"]),
        (
            {
                "DEMO_END_TO_END": "1",
                "DEMO_RECEIVER_URL": "http://demo.example.invalid:8080",
                "DEMO_END_TO_END_RUN_TIMEOUT": "600",
            },
            ["--replay", "--receiver", "http://demo.example.invalid:8080", "--run-timeout", "600"],
        ),
        (
            {"DEMO_END_TO_END": "live", "DEMO_RECEIVER_URL": "http://demo.example.invalid:8080"},
            ["--live"],
        ),
    ],
)
def test_the_end_to_end_check_runs_verify(environment, arguments):
    assert verify_arguments(environment) == arguments


def test_an_older_python_is_told_so_in_a_sentence_and_not_a_traceback():
    python = older_python()
    if python is None:
        pytest.skip("no python3 older than 3.11 here")

    answer = subprocess.run(
        [python, "-m", "grafana_jsm_sandbox.verify", "--live"],
        cwd=REPOSITORY,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert answer.returncode == 2
    assert "needs Python 3.11 or newer" in answer.stderr
    assert "Traceback" not in answer.stderr
    assert answer.stdout == ""


def test_it_is_a_module_the_setup_skill_can_run():
    answer = subprocess.run(
        [sys.executable, "-m", "grafana_jsm_sandbox.verify", "--help"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=False,
    )

    assert answer.returncode == 0
    assert "--replay" in answer.stdout and "--live" in answer.stdout
