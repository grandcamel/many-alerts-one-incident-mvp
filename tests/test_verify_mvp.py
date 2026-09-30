"""`verify --mvp`: one Incident for a group of related Alerts, watched with the demo faked.

The fake is `tests/test_verify.py`'s idea on group semantics, on a fake clock: stopping the
traffic makes Grafana's rules fire, Grafana sends the group's Alerts in one Notification,
a related Alert joins the group later and the Firing repeats, and each Notification is a
Run that changes the fake project the way Skill v2 says: create one Incident with the
group, session and `fp-` labels, add labels and a comment on an update, complete on the
Resolved. jira-as is that project answering the read-only calls `verify` makes. Each
failure a test needs is a switch on the simulation: a Run that creates a second Incident,
one that comments without adding the label, one that never comes.
"""

from __future__ import annotations

import json
import re
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from grafana_jsm_sandbox import replay, verify, verify_mvp
from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.doctor import GrafanaUnanswered
from grafana_jsm_sandbox.notification import validate_notification
from grafana_jsm_sandbox.replay import FIXTURES
from grafana_jsm_sandbox.verify import Timeouts, World, main
from grafana_jsm_sandbox.verify_mvp import (
    GROUP_LABELLED,
    GROUP_MATCH,
    MVP_SEQUENCE,
    GroupIncident,
    group_label,
    session_from,
    session_label,
)
from tests.test_verify import KEY, OAUTH_TOKEN, RECEIVER, TOKEN, FakeClock, elapsed, line, stages

GROUP = "checkout-outage"
SESSION = "rehearsal1"
GRP = group_label(GROUP)
SES = session_label(SESSION)


def fixture(filename: str) -> dict:
    return validate_notification((FIXTURES / filename).read_bytes())


def labels_in(filename: str) -> list[str]:
    return [f"fp-{alert['fingerprint']}" for alert in fixture(filename)["alerts"]]


FIRING, REPEAT, RELATED, RESOLVED = MVP_SEQUENCE
GROUP_LABELS = labels_in(FIRING)
ALL_LABELS = labels_in(RELATED)
RELATED_LABEL = (set(ALL_LABELS) - set(GROUP_LABELS)).pop()

LINE = re.compile(
    r"^\[\+\d+s\] (WAIT|OK|WARN|FAIL|NOTE) "
    r"(preflight|traffic stopped|firing|posted|created|grouped|updated|related|one incident"
    r"|traffic started|normal|completed|cleanup) — [^\n]+$"
)
END = re.compile(
    r"^(VERIFIED: [A-Z][A-Z0-9_]+-\d+ created with \d+ fp- labels → updated → "
    r"fp-[0-9a-f]+(, fp-[0-9a-f]+)* added → Completed with resolution \S+ in \d+s"
    r"|NOT VERIFIED: [a-z ]+ — .+)$"
)
"""The documented output, in `verify`'s form with the scenario's stages and verdict."""

ASK = re.compile(r"docs/admin-requests\.md#([a-z0-9-]+)")

PENDING_AFTER = 30.0
FIRING_AFTER = 65.0
GROUP_WAIT = 10.0
RELATED_AFTER = 120.0
"""Seconds after the group's first Notification that the sustained-outage Alert joins it."""
REPEAT_EVERY = 180.0
"""The policy's repeat interval (spec: 3m)."""
NORMAL_AFTER = 15.0
RUN_SECONDS = 30.0

DONE = {"Completed", "Closed", "Canceled"}


@dataclass
class FakeIncident:
    status: str
    labels: list[str]
    resolution: str | None = None
    comments: int = 0
    bodies: list[str] = field(default_factory=list)
    created: float = 0.0


@dataclass
class GroupDemo:
    """The MVP's demo, from the traffic to the project, on a fake clock."""

    clock: FakeClock = field(default_factory=FakeClock)
    incidents: dict[str, FakeIncident] = field(default_factory=dict)
    next_number: int = 1

    project: DemoProject = field(default_factory=lambda: DemoProject(KEY))

    # Grafana
    rule_before: str | None = "inactive"
    never_fires: bool = False
    stays_firing: bool = False
    grafana_down: bool = False
    related_never_fires: bool = False
    related_after: float = RELATED_AFTER
    """When the sustained-outage Alert joins the group, after the group's first Notification."""

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
    """The Notifications whose Run does nothing: `firing`, `repeat`, `related`, `resolved`."""
    session_created: str = SES
    """The session label the Run gives the Incident: another when `.env` and `--session` differ."""
    creates_with_one_label: bool = False
    duplicate_create: bool = False
    misses_match_on_update: bool = False
    no_update_comment: bool = False
    opening_delay: float = 5.0
    no_opening_comment: bool = False
    probe_update: bool = True
    alertmanager_down: bool = False
    no_related_label: bool = False
    update_lands_on: str = "Work in progress"
    resolve_screen_drops_resolution: bool = False
    no_closing_comment: bool = False

    # jira-as
    jira_as_fails: int = 0
    jira_calls: list[tuple[str, ...]] = field(default_factory=list)

    stopped_at: float | None = None
    started_at: float | None = None
    replayed: list[tuple[float, str, list[str]]] = field(default_factory=list)
    _runs_done: int = 0
    _run_ends: list[float] = field(default_factory=list)

    @property
    def done_statuses(self) -> set[str]:
        return {self.project.status_done, self.project.status_closed, "Canceled", "Declined"}

    # --- the world as verify sees it ---

    def world(self, out: list[str]) -> World:
        return World(
            jira_as=self.jira_as,
            compose=self.compose,
            post=self.post,
            grafana_state=self.grafana_state,
            grafana_alerts=self.grafana_alerts,
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
        parsed = json.loads(notification)
        labels = [f"fp-{alert['fingerprint']}" for alert in parsed["alerts"]]
        if parsed["status"] == "resolved":
            kind = "resolved"
        elif set(labels) > set(GROUP_LABELS):
            kind = "related"
        else:
            # The repeat is the Firing sent again, byte for byte, so the order tells them apart.
            kind = "repeat" if any(k == "firing" for _, k, _ in self.replayed) else "firing"
        self.posted.append(MVP_SEQUENCE[("firing", "repeat", "related", "resolved").index(kind)])
        if self.receiver_status == 202:
            self.replayed.append((self.clock.now(), kind, labels))
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

    def grafana_alerts(self) -> list[dict]:
        if self.alertmanager_down:
            raise GrafanaUnanswered("Alertmanager answered 503")
        if self.stopped_at is None or self.related_never_fires:
            return []
        if self.clock.now() < self.stopped_at + FIRING_AFTER + GROUP_WAIT + self.related_after:
            return []
        return [
            {
                "labels": {"alertname": verify_mvp.SUSTAINED_TITLE, "incident_group": GROUP},
                "fingerprint": RELATED_LABEL.removeprefix("fp-"),
            }
        ]

    def jira_as(self, *arguments: str) -> str:
        self.jira_calls.append(arguments)
        if self.jira_as_fails:
            self.jira_as_fails -= 1
            raise RuntimeError("jira-as failed: HTTP 503")
        self._catch_up()
        match arguments:
            case ("search", "jql", jql, "--fields", "key,status,labels", "-o", "json"):
                return json.dumps({"issues": self._search(jql), "isLast": True})
            case ("issue", "get", key, "--fields", "status,resolution,labels", "-o", "json"):
                incident = self.incidents[key]
                resolution = incident.resolution and {"name": incident.resolution}
                return json.dumps(
                    {
                        "key": key,
                        "fields": {
                            "status": {
                                "name": incident.status,
                                "statusCategory": {
                                    "key": "done"
                                    if incident.status in self.done_statuses
                                    else "new"
                                },
                            },
                            "resolution": resolution,
                            "labels": list(incident.labels),
                        },
                    }
                )
            case ("collaborate", "comment", "list", key, "-o", "json"):
                return json.dumps(
                    {
                        "total": self.incidents[key].comments,
                        "comments": [{"body": body} for body in self.incidents[key].bodies],
                    }
                )
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

    def _notifications(self) -> list[tuple[float, str, list[str]]]:
        """What reached the Receiver by now: the replay's posts, or Grafana's own."""
        now = self.clock.now()
        sent = [(when, kind, labels) for when, kind, labels in self.replayed if when <= now]
        firing = self._firing_at()
        if firing is None:
            return sorted(sent)
        normal = self._normal_at()
        first = firing + GROUP_WAIT
        # Three rules fire within the group wait; the sustained-outage one joins later, on a
        # group interval; the Firing repeats on the repeat interval, all Alerts included.
        planned: list[tuple[float, str, list[str]]] = [(first, "firing", list(GROUP_LABELS[:2]))]
        if self.probe_update:
            planned.append((first + 60, "probe", list(GROUP_LABELS)))
        labels = list(GROUP_LABELS)
        if not self.related_never_fires:
            planned.append((first + self.related_after, "related", list(ALL_LABELS)))
            labels = list(ALL_LABELS)
        when = first + REPEAT_EVERY
        while when <= now + REPEAT_EVERY:
            planned.append(
                (
                    when,
                    "repeat",
                    labels if when > first + self.related_after else list(GROUP_LABELS),
                )
            )
            when += REPEAT_EVERY
        for when, kind, labels in sorted(planned):
            if when <= now and (normal is None or when < normal):
                sent.append((when, kind, labels))
        if normal is not None and normal <= now:
            sent.append((normal + 4, "resolved", labels))
        return sorted(sent)

    def _catch_up(self) -> None:
        """Finish every Run that would have finished by now, one at a time, in order."""
        for incident in self.incidents.values():
            if (
                not self.no_opening_comment
                and incident.comments == 0
                and self.clock.now() >= incident.created + self.opening_delay
            ):
                incident.comments = 1
                incident.bodies.append("Opened from firing Alerts.")
        notifications = self._notifications()
        while self._runs_done < len(notifications):
            when, kind, labels = notifications[self._runs_done]
            previous = self._run_ends[-1] if self._run_ends else when
            end = max(when, previous) + RUN_SECONDS
            if end > self.clock.now():
                return
            self._run_ends.append(end)
            self._runs_done += 1
            if kind not in self.failing_runs:
                self._run(kind, labels, end)

    def _run(self, kind: str, labels: list[str], when: float) -> None:
        match = [
            key
            for key, incident in self.incidents.items()
            if GRP in incident.labels
            and self.session_created in incident.labels
            and incident.status not in self.done_statuses
        ]
        if kind == "resolved":
            if match:
                incident = self.incidents[match[0]]
                incident.comments += 0 if self.no_closing_comment else 1
                incident.status = self.project.status_done
                if not self.resolve_screen_drops_resolution:
                    incident.resolution = "Done"
            return
        if not match or (self.misses_match_on_update and kind != "firing"):
            created = labels[:1] if self.creates_with_one_label else labels
            key = self.add(self.project.status_open, [GRP, self.session_created, *created])
            self.incidents[key].comments = 0
            self.incidents[key].created = when
            if self.duplicate_create:
                self.add(self.project.status_open, [GRP, self.session_created, *created])
            return
        incident = self.incidents[match[0]]
        new = set(labels) - set(incident.labels)
        if not self.no_related_label:
            incident.labels += [label for label in labels if label not in incident.labels]
        incident.comments += 0 if self.no_update_comment else 1
        if not self.no_update_comment:
            incident.bodies.append(
                f"Update: {len(labels)} firing. New: {', '.join(sorted(new)) or 'none'}. "
                "Repeat: existing alerts. Resolved: none. Open for 1m."
            )
        if incident.status == self.project.status_open:
            incident.status = self.update_lands_on

    def _search(self, jql: str) -> list[dict]:
        labelled = re.findall(r'labels = "([^"]+)"', jql)
        recent = re.search(r'created >= "-(\d+)m"', jql)
        assert jql.startswith(f'project = "{KEY}" AND issuetype = Incident'), jql
        assert labelled or recent, jql
        found = []
        for key, incident in self.incidents.items():
            if any(label not in incident.labels for label in labelled):
                continue
            if "statusCategory != Done" in jql and incident.status in self.done_statuses:
                continue
            if recent and incident.created < self.clock.now() - 60 * int(recent[1]):
                continue
            found.append(
                {
                    "key": key,
                    "fields": {
                        "status": {
                            "name": incident.status,
                            "statusCategory": {
                                "key": "done" if incident.status in self.done_statuses else "new"
                            },
                        },
                        "labels": incident.labels,
                    },
                }
            )
        return found


def run(demo: GroupDemo, mode: str = verify.REPLAY, **options) -> tuple[int, list[str]]:
    out: list[str] = []
    status = verify_mvp.verify_mvp(
        mode,
        KEY,
        SESSION,
        demo.world(out),
        receiver=RECEIVER,
        timeouts=options.pop("timeouts", None),
        project=demo.project,
    )
    assert not options
    return status, out


def assert_documented(out: list[str]) -> None:
    for text in out[:-1]:
        assert LINE.match(text), text
    assert END.match(out[-1]), out[-1]
    assert sum(1 for text in out if text.startswith(("VERIFIED", "NOT VERIFIED"))) == 1


def assert_read_only(demo: GroupDemo) -> None:
    for call in demo.jira_calls:
        assert call[:2] in {("search", "jql"), ("issue", "get")} or call[:3] == (
            "collaborate",
            "comment",
            "list",
        ), call


def ok_stages(out: list[str]) -> list[str]:
    return [stage for level, stage in stages(out) if level == "OK"]


@pytest.fixture
def demo() -> GroupDemo:
    return GroupDemo()


# --- The fixtures the replay posts ---


@pytest.mark.parametrize("filename", MVP_SEQUENCE)
def test_each_grouped_fixture_is_a_notification_the_receiver_accepts(filename):
    notification = fixture(filename)
    assert len(notification["alerts"]) >= 3, "a group, not one Alert"
    assert json.loads((FIXTURES / filename).read_text()) == notification


@pytest.mark.parametrize("filename", MVP_SEQUENCE)
def test_every_grouped_alert_carries_the_group_label_and_what_the_field_mapping_reads(filename):
    notification = fixture(filename)
    assert notification["groupLabels"] == {"incident_group": GROUP}
    for alert in notification["alerts"]:
        assert alert["labels"]["incident_group"] == GROUP
        assert set(alert["labels"]) >= {"alertname", "instance", "service", "severity"}
        assert set(alert["annotations"]) >= {"summary", "description"}
        assert {"generatorURL", "dashboardURL", "panelURL"} <= set(alert)


def test_the_grouped_sequence_is_three_firing_the_same_again_one_more_then_all_resolved():
    assert len(set(GROUP_LABELS)) == len(GROUP_LABELS) == 3, "three Alerts, three Fingerprints"
    assert (FIXTURES / REPEAT).read_bytes() == (FIXTURES / FIRING).read_bytes()
    assert ALL_LABELS[:3] == GROUP_LABELS
    assert len(ALL_LABELS) == 4
    resolved = fixture(RESOLVED)
    assert resolved["status"] == "resolved"
    assert labels_in(RESOLVED) == ALL_LABELS
    assert all(alert["status"] == "resolved" for alert in resolved["alerts"])
    assert all(alert["status"] == "firing" for alert in fixture(RELATED)["alerts"])


def test_the_sustained_outage_alert_starts_later_than_the_group_and_all_end_when_resolved():
    related = {alert["fingerprint"]: alert for alert in fixture(RELATED)["alerts"]}
    starts = {fingerprint: alert["startsAt"] for fingerprint, alert in related.items()}
    sustained = RELATED_LABEL.removeprefix("fp-")
    assert all(starts[sustained] > starts[other] for other in starts if other != sustained)
    for alert in fixture(RESOLVED)["alerts"]:
        assert alert["endsAt"] > alert["startsAt"]
        assert alert["startsAt"] == starts[alert["fingerprint"]], "a resolve does not restart"


def test_the_canned_alert_is_the_group_s_first():
    canned = json.loads((FIXTURES / replay.SEQUENCE[0]).read_text())["alerts"][0]
    assert GROUP_LABELS[0] == f"fp-{canned['fingerprint']}", "chapter one's Alert leads the group"


# --- The replay ---


def test_a_replay_watches_one_incident_through_every_stage_and_is_verified(demo):
    status, out = run(demo)

    assert status == 0, out
    assert out[-1].startswith(
        f"VERIFIED: {KEY}-1 created with 3 fp- labels → updated → {RELATED_LABEL} added → "
        "Completed with resolution Done in "
    )
    assert ok_stages(out) == [
        "preflight",
        "posted",
        "created",
        "grouped",
        "posted",
        "updated",
        "posted",
        "related",
        "posted",
        "completed",
    ]
    assert demo.posted == list(MVP_SEQUENCE)
    assert demo.compose_calls == [], "a replay leaves the traffic alone"
    assert set(demo.incidents[f"{KEY}-1"].labels) == {GRP, SES, *ALL_LABELS}
    assert len(demo.incidents) == 1
    assert_documented(out)
    assert_read_only(demo)


def test_each_notification_is_posted_only_once_the_incident_answered_the_one_before(demo):
    status, out = run(demo)

    assert status == 0
    posts = [text for text in out if " OK posted — " in text]
    assert elapsed(posts[1]) >= elapsed(line(out, "OK", "grouped"))
    assert elapsed(posts[2]) >= elapsed(line(out, "OK", "updated"))
    assert elapsed(posts[3]) >= elapsed(line(out, "OK", "related"))


def test_every_stage_says_what_it_saw_and_how_long_it_took(demo):
    status, out = run(demo)

    assert status == 0
    created = line(out, "OK", "created")
    assert f"{KEY}-1 (Open) carries {GRP} and {SES}, 30s after posting the grouped Firing" in (
        created
    )
    grouped = line(out, "OK", "grouped")
    assert f"{KEY}-1 carries 3 fp- labels ({', '.join(sorted(GROUP_LABELS))})" in grouped
    updated = line(out, "OK", "updated")
    assert f"{KEY}-1 has a new comment (2 now) and is Work in progress" in updated
    assert "after posting the repeat; still the one Incident" in updated
    related = line(out, "OK", "related")
    assert f"{KEY}-1 gained {RELATED_LABEL} with a comment" in related
    assert "after posting the related Alert" in related
    assert "after posting the Resolved" in line(out, "OK", "completed")


def test_a_preflight_names_both_labels_and_the_earlier_incidents_of_the_session(demo):
    old = demo.add("Completed", [GRP, SES, *GROUP_LABELS], resolution="Done")

    status, out = run(demo)

    assert status == 0, out
    preflight = line(out, "OK", "preflight")
    assert f"no open Incident in {KEY} carries {GRP} and {SES}" in preflight
    assert f"1 earlier one(s) ({old}) are not this run's" in preflight
    assert out[-1].startswith(f"VERIFIED: {KEY}-2 ")
    assert elapsed(line(out, "OK", "created")) == 30, "not the leftover, found at once"


def test_an_open_match_stops_it_before_anything_is_posted(demo):
    leftover = demo.add("Work in progress", [GRP, SES, *GROUP_LABELS])

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "preflight")
    assert f"{leftover} is open and already carries {GRP} and {SES}" in failed
    assert "python3 -m grafana_jsm_sandbox.reset" in failed
    assert demo.posted == []
    assert out[-1].startswith("NOT VERIFIED: preflight — ")
    assert_documented(out)


def test_another_session_s_open_incident_is_not_a_match(demo):
    """A rehearsal under another session id is left where it is, and never counted."""
    other = demo.add("Open", [GRP, "ses-other-take", *GROUP_LABELS])

    status, out = run(demo)

    assert status == 0, out
    assert out[-1].startswith(f"VERIFIED: {KEY}-2 ")
    assert other not in " ".join(out)


# --- The Proof, and each way it fails ---


def test_a_run_that_creates_with_one_label_fails_grouped(demo):
    demo.creates_with_one_label = True

    status, out = run(demo)

    assert status == 1
    assert "OK created" in " ".join(out)
    failed = line(out, "FAIL", "grouped")
    assert f"{KEY}-1 carries 1 fp- label(s) ({GROUP_LABELS[0]}), not the 3 fp- labels" in failed
    assert f"the Run left off {', '.join(sorted(GROUP_LABELS[1:]))}" in failed
    assert "[FAILED]" in failed
    assert demo.posted == [FIRING], "nothing more is posted after a failed stage"
    assert_documented(out)


def test_a_second_incident_on_create_is_a_failure_not_a_warning(demo):
    demo.duplicate_create = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "one incident")
    assert f"{KEY}-1, {KEY}-2 are all open with {GRP} and {SES} during created" in failed
    assert "a Run missed the Match and created a second Incident" in failed
    assert out[-1].startswith("NOT VERIFIED: one incident — ")
    assert demo.posted == [FIRING]
    assert_documented(out)


def test_a_repeat_whose_run_creates_instead_of_updating_fails_one_incident(demo):
    demo.misses_match_on_update = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "one incident")
    assert f"{KEY}-1, {KEY}-2 are all open with {GRP} and {SES} during updated" in failed
    assert demo.posted == [FIRING, REPEAT]
    assert f"{KEY}-1 is left Open" in line(out, "NOTE", "cleanup")


def test_a_repeat_without_a_comment_times_out_at_updated(demo):
    demo.no_update_comment = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "updated")
    assert f"{KEY}-1 still has 1 comment(s), none since posting the repeat" in failed
    assert "created instead of updating" in failed
    assert "[FAILED]" in failed
    assert elapsed(failed) == elapsed(line(out, "OK", "grouped")) + Timeouts().run
    assert out[-1] == f"NOT VERIFIED: updated — {failed.split(' — ', 1)[1]}"
    assert_documented(out)


def test_a_repeat_whose_run_never_runs_times_out_at_updated(demo):
    demo.failing_runs = {"repeat"}

    status, out = run(demo)

    assert status == 1
    assert "none since posting the repeat" in line(out, "FAIL", "updated")


def test_a_related_alert_whose_label_is_not_added_fails_related(demo):
    demo.no_related_label = True

    status, out = run(demo)

    assert status == 1
    assert "OK updated" in " ".join(out), "the repeat's comment came"
    failed = line(out, "FAIL", "related")
    assert f"{KEY}-1 still carries only {', '.join(sorted(GROUP_LABELS))}, no new fp- label" in (
        failed
    )
    assert "updated without adding the label" in failed
    assert demo.posted == [FIRING, REPEAT, RELATED]
    assert_documented(out)


def test_a_related_alert_whose_run_never_runs_fails_related(demo):
    demo.failing_runs = {"related"}

    status, out = run(demo)

    assert status == 1
    assert "no new fp- label with a comment" in line(out, "FAIL", "related")


def test_an_update_that_leaves_it_open_is_a_warning(demo):
    demo.update_lands_on = "Open"

    status, out = run(demo)

    assert status == 0, out
    assert f"{KEY}-1 is still Open, not Work in progress" in line(out, "WARN", "updated")


def test_an_update_that_takes_it_off_the_path_fails_at_once(demo):
    demo.update_lands_on = "Canceled"

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "updated")
    assert f"{KEY}-1 went to Canceled instead of staying open" in failed
    assert elapsed(failed) < elapsed(line(out, "OK", "grouped")) + Timeouts().run


def test_a_resolved_run_that_never_completes_times_out_at_completed(demo):
    demo.failing_runs = {"resolved"}

    status, out = run(demo)

    assert status == 1
    assert "is still Work in progress" in line(out, "FAIL", "completed")
    assert f"{KEY}-1 is left Work in progress: `python3 -m grafana_jsm_sandbox.reset`" in line(
        out, "NOTE", "cleanup"
    )


def test_completed_without_a_resolution_names_the_resolve_screen_request(demo):
    demo.resolve_screen_drops_resolution = True

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "completed")
    assert f"{KEY}-1 is Completed without a resolution" in failed
    assert ASK.findall(failed) == ["jira-admin-resolution-screen"]
    assert_documented(out)


def test_a_missing_closing_comment_is_a_warning_not_a_failure(demo):
    demo.no_closing_comment = True

    status, out = run(demo)

    assert status == 0
    assert f"{KEY}-1 has no closing comment" in line(out, "WARN", "completed")


def test_an_incident_created_under_another_session_label_is_pointed_out(demo):
    demo.session_created = "ses-take2"

    status, out = run(demo)

    assert status == 1
    failed = line(out, "FAIL", "created")
    assert f"no Incident within {Timeouts().run:.0f}s of posting the grouped Firing" in failed
    assert f"{KEY}-1 was created meanwhile with ses-take2 instead of {SES}" in failed
    assert "run again with --session take2, or set DEMO_SESSION_ID in .env" in failed


def test_a_receiver_that_refuses_the_notification_is_named(demo):
    demo.receiver_status = 400

    status, out = run(demo)

    assert status == 1
    assert f"answered {FIRING} with 400, not 202" in line(out, "FAIL", "posted")


def test_jira_as_refusing_the_first_search_fails_the_preflight(demo):
    demo.jira_as_fails = 1

    status, out = run(demo)

    assert status == 1
    assert f"jira-as could not search {KEY}" in line(out, "FAIL", "preflight")
    assert demo.posted == []


# --- Live ---


def test_live_stops_the_traffic_watches_the_group_and_starts_it_again(demo):
    status, out = run(demo, verify.LIVE)

    assert status == 0, out
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert ok_stages(out) == [
        "preflight",
        "traffic stopped",
        "firing",
        "created",
        "grouped",
        "related",
        "updated",
        "traffic started",
        "normal",
        "completed",
    ]
    assert demo.posted == [], "live posts nothing; Grafana does"
    assert len(demo.incidents) == 1
    assert_documented(out)
    assert_read_only(demo)


def test_live_waits_for_both_updates_and_takes_them_in_either_order(demo):
    """The sustained-outage Alert may reach the Incident before or after the repeat."""
    status, out = run(demo, verify.LIVE)
    assert status == 0, out
    assert elapsed(line(out, "OK", "related")) <= elapsed(line(out, "OK", "updated"))

    later = GroupDemo(related_after=REPEAT_EVERY + 60)
    status, out = run(later, verify.LIVE)
    assert status == 0, out
    assert elapsed(line(out, "OK", "updated")) < elapsed(line(out, "OK", "related"))
    assert [stage for level, stage in stages(out) if level == "WAIT"][3:5] == [
        "updated",
        "related",
    ], "both waits are announced before either lands"


def test_a_related_alert_that_never_fires_fails_related_after_the_repeat_came(demo):
    demo.related_never_fires = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert line(out, "OK", "updated")
    failed = line(out, "FAIL", "related")
    assert "no new fp- label with a comment" in failed
    assert "--only grafana" in failed
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert stages(out)[-2:] == [("OK", "traffic started"), ("NOTE", "cleanup")]
    assert_documented(out)


def test_a_second_open_incident_live_fails_one_incident_and_starts_the_traffic(demo):
    demo.misses_match_on_update = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert line(out, "FAIL", "one incident")
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert out[-1].startswith("NOT VERIFIED: one incident — ")


def test_a_rule_that_never_fires_is_named_and_the_traffic_started_again(demo):
    demo.never_fires = True

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "is still pending 180s after the traffic stopped" in line(out, "FAIL", "firing")
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_an_interruption_still_starts_the_traffic_and_says_so(demo):
    demo.clock.interrupt_at = demo.clock.time + 100

    status, out = run(demo, verify.LIVE)

    assert status == 130
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]
    assert out[-1].startswith("NOT VERIFIED: interrupted — ")
    assert_documented(out)


def test_live_needs_the_rule_normal_before_it_stops_anything(demo):
    demo.rule_before = "firing"

    status, out = run(demo, verify.LIVE)

    assert status == 1
    assert "is firing, not Normal" in line(out, "FAIL", "preflight")
    assert demo.compose_calls == []


def test_timeouts_are_the_callers_to_set(demo):
    demo.related_never_fires = True

    status, out = run(demo, verify.LIVE, timeouts=Timeouts(repeat=30, run=60))

    assert status == 1
    assert "up to 90s for the sustained-outage Alert's Run" in line(out, "WAIT", "related")


# --- The Match ---


def test_the_jql_is_the_match_a_run_uses():
    assert GROUP_MATCH == GROUP_LABELLED + " AND statusCategory != Done"
    assert GROUP_MATCH.format(key=KEY, group=GRP, session=SES) == (
        f'project = "{KEY}" AND issuetype = Incident AND labels = "{GRP}" AND labels = "{SES}"'
        " AND statusCategory != Done"
    )


def test_the_group_is_prefixed_once_but_the_session_id_is_literal():
    assert group_label("checkout-outage") == group_label("grp-checkout-outage") == GRP
    assert session_label("rehearsal1") == SES
    assert session_label("ses-rehearsal1") == "ses-ses-rehearsal1"
    assert re.fullmatch(r"grp-[a-z0-9-]+", GRP) and re.fullmatch(r"ses-[a-z0-9-]{1,32}", SES)


def test_a_group_incident_knows_its_fingerprint_labels():
    incident = GroupIncident("X-1", "Open", None, 0, frozenset({GRP, SES, *GROUP_LABELS}))
    assert incident.fingerprints == frozenset(GROUP_LABELS)


@pytest.mark.parametrize(
    ("values", "flag", "expected"),
    [
        ({"DEMO_SESSION_ID": "rehearsal1"}, None, "rehearsal1"),
        ({"DEMO_SESSION_ID": " rehearsal1 "}, None, "rehearsal1"),
        ({"DEMO_SESSION_ID": "rehearsal1"}, "take2", "take2"),
        ({}, "ses-take2", "ses-take2"),
    ],
)
def test_the_session_comes_from_the_flag_or_dot_env(values, flag, expected):
    assert session_from(values, flag) == expected


@pytest.mark.parametrize(
    ("values", "flag", "said"),
    [
        ({}, None, "DEMO_SESSION_ID is not set"),
        ({"DEMO_SESSION_ID": ""}, None, "DEMO_SESSION_ID is not set"),
        ({"DEMO_SESSION_ID": "Rehearsal 1"}, None, "DEMO_SESSION_ID in .env is not a session id"),
        ({}, "a" * 33, "--session is not a session id"),
        ({}, "", "DEMO_SESSION_ID is not set"),
    ],
)
def test_a_missing_or_malformed_session_is_a_configuration_error(values, flag, said):
    with pytest.raises(verify.ConfigurationError) as failure:
        session_from(values, flag)

    assert said in str(failure.value)


# --- The command ---


def env_text(**overrides: str | None) -> str:
    values = {
        "JIRA_SITE_URL": "https://sandbox.example.invalid",
        "JIRA_EMAIL": "ops@example.invalid",
        "JIRA_API_TOKEN": TOKEN,
        "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN,
        "DEMO_PROJECT_KEY": KEY,
        "DEMO_SESSION_ID": SESSION,
        "RECEIVER_HOST_PORT": "18080",
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


def command(demo: GroupDemo, argv: list[str], env_file: Path, capsys) -> tuple[int, list[str], str]:
    out: list[str] = []
    status = main(argv, env_file=env_file, world=demo.world(out))
    captured = capsys.readouterr()
    return status, out, captured.out + captured.err


def test_the_command_reads_the_session_from_dot_env_and_replays_by_default(demo, env_file, capsys):
    status, out, _ = command(demo, ["--mvp"], env_file, capsys)

    assert status == 0, out
    assert demo.posted == list(MVP_SEQUENCE)
    assert f"carries {GRP} and {SES}" in line(out, "OK", "preflight")


def test_the_session_flag_wins_over_dot_env(demo, env_file, capsys):
    demo.session_created = "ses-take2"

    status, out, _ = command(demo, ["--mvp", "--session", "take2"], env_file, capsys)

    assert status == 0, out
    assert f"carries {GRP} and ses-take2" in line(out, "OK", "preflight")


def test_the_group_flag_names_the_group_label_watched(demo, env_file, capsys):
    status, out, _ = command(demo, ["--mvp", "--group", "checkout-outage"], env_file, capsys)

    assert status == 0, out
    assert f"carries {GRP} and {SES}" in line(out, "OK", "preflight")


def test_the_command_runs_the_mvp_live_when_asked(demo, env_file, capsys):
    status, out, _ = command(demo, ["--mvp", "--live"], env_file, capsys)

    assert status == 0, out
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_without_mvp_the_command_is_chapter_one_s(demo, env_file, capsys):
    """The chapter-one watch on the group demo: its Runs create nothing under one fp- label."""
    demo.failing_runs = {"firing"}

    status, out, _ = command(demo, ["--run-timeout", "10"], env_file, capsys)

    assert status == 1
    assert f"carries fp-{GROUP_LABELS[0].removeprefix('fp-')}" in line(out, "OK", "preflight")
    assert [labels for _, _, labels in demo.replayed] == [[GROUP_LABELS[0]]], "one Alert posted"


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (env_text(DEMO_SESSION_ID=None), "DEMO_SESSION_ID is not set"),
        (env_text(DEMO_SESSION_ID=""), "DEMO_SESSION_ID is not set"),
        # A malformed one is refused as the project is read, the same refusal that keeps the
        # Receiver from starting, so the fix is `.env`'s rather than a `--session`.
        (env_text(DEMO_SESSION_ID="Rehearsal 1"), "DEMO_SESSION_ID is not a session id"),
    ],
)
def test_a_session_the_env_lacks_is_exit_2_before_anything_is_asked(
    demo, env_file, capsys, text, said
):
    env_file.write_text(text)

    status, out, printed = command(demo, ["--mvp"], env_file, capsys)

    assert status == 2
    assert said in printed
    assert "--session" in printed or "is not a session id" in printed
    assert out == []
    assert demo.jira_calls == demo.compose_calls == demo.posted == []
    assert TOKEN not in printed


@pytest.mark.parametrize(
    "argv",
    [
        ["--session", "take2"],
        ["--group", "another"],
        ["--mvp", "--live", "--receiver", RECEIVER],
        ["--mvp", "--replay", "--live"],
    ],
)
def test_bad_arguments_are_a_usage_error(demo, env_file, capsys, argv):
    with pytest.raises(SystemExit) as exit:
        main(argv, env_file=env_file, world=demo.world([]))

    assert exit.value.code == 2
    assert demo.jira_calls == []


def test_the_flags_are_in_the_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--mvp" in help_text
    assert "--session ID" in help_text
    assert "--group NAME" in help_text
    assert "DEMO_SESSION_ID" in help_text


def test_nothing_it_prints_holds_a_secret(demo, env_file, capsys):
    demo.failing_runs = {"resolved"}

    _, out, printed = command(demo, ["--mvp", "--live"], env_file, capsys)

    for secret in (TOKEN, OAUTH_TOKEN):
        assert secret not in "\n".join(out) + printed


# --- The real Receiver, on loopback ---


def test_the_grouped_posts_reach_a_real_receiver(receiver, spawner, demo):
    """The four Notifications go over real HTTP, and the Receiver starts a Run for each."""
    posts: list[int] = []

    def through_the_receiver(url: str, notification: bytes) -> int:
        status = replay.post(url, notification)
        posts.append(status)
        demo.post(RECEIVER + "/notification", notification)
        return status

    out: list[str] = []
    world = demo.world(out)
    world.post = through_the_receiver

    status = verify_mvp.verify_mvp(verify.REPLAY, KEY, SESSION, world, receiver=receiver.url)

    assert status == 0, out
    assert posts == [202, 202, 202, 202]
    spawner.wait_for_spawns(4)
    assert [run.notification["status"] for run in spawner.spawned] == [
        "firing",
        "firing",
        "firing",
        "resolved",
    ]
    assert [len(run.notification["alerts"]) for run in spawner.spawned] == [3, 3, 4, 4]


def test_custom_workflow_replay_is_verified_end_to_end(env_file, capsys):
    project = DemoProject(
        KEY,
        status_open="New",
        status_in_progress="In Progress",
        status_done="Resolved",
        status_closed="",
    )
    demo = GroupDemo(project=project, update_lands_on="In Progress")
    env_file.write_text(
        env_text(
            DEMO_STATUS_OPEN="New",
            DEMO_STATUS_IN_PROGRESS="In Progress",
            DEMO_STATUS_DONE="Resolved",
            DEMO_STATUS_CLOSED="",
        )
    )

    status, out, _ = command(demo, ["--mvp", "--replay"], env_file, capsys)

    assert status == 0, out
    assert "(New)" in line(out, "OK", "created")
    assert "is In Progress" in line(out, "OK", "updated")
    assert "is Resolved with resolution Done" in line(out, "OK", "completed")
    assert "→ Resolved with resolution Done" in out[-1]
    assert out[-1].startswith("VERIFIED:")
    assert len(demo.incidents) == 1
    assert_read_only(demo)


@pytest.mark.parametrize("status", ["Canceled", "Declined"])
def test_custom_workflow_other_done_statuses_are_off_the_path(status):
    project = DemoProject(
        KEY,
        status_open="New",
        status_in_progress="In Progress",
        status_done="Resolved",
        status_closed="",
    )
    demo = GroupDemo(project=project, update_lands_on=status)

    code, out = run(demo)

    assert code == 1
    assert f"went to {status}" in out[-1]
    assert "a Run took it off the demo's path" in out[-1]


def test_custom_workflow_done_without_resolution_still_fails():
    project = DemoProject(
        KEY,
        status_open="New",
        status_in_progress="In Progress",
        status_done="Resolved",
        status_closed="",
    )
    demo = GroupDemo(
        project=project, update_lands_on="In Progress", resolve_screen_drops_resolution=True
    )

    code, out = run(demo)

    assert code == 1
    assert "Resolved without a resolution" in out[-1]


def test_replay_baseline_waits_for_the_opening_comment(demo):
    demo.failing_runs = {"repeat"}
    demo.opening_delay = 10
    status, out = run(demo)
    assert status == 1
    assert elapsed(line(out, "OK", "created")) == RUN_SECONDS
    assert elapsed(line(out, "OK", "grouped")) == RUN_SECONDS + 10
    assert len(demo.posted) == 2
    assert line(out, "FAIL", "updated")
    assert demo.incidents[f"{KEY}-1"].comments == 1


def test_missing_opening_comment_never_posts_the_repeat(demo):
    demo.no_opening_comment = True
    status, out = run(demo, timeouts=Timeouts(run=60))
    assert status == 1
    assert demo.posted == [FIRING]
    assert "opening comment (0 comments)" in line(out, "FAIL", "grouped")


def test_probe_update_cannot_pass_repeat_or_related(demo):
    demo.related_never_fires = True
    demo.failing_runs = {"repeat"}
    status, out = run(demo, verify.LIVE)
    assert status == 1
    assert "updated" not in ok_stages(out)
    assert "related" not in ok_stages(out)
    assert demo.incidents[f"{KEY}-1"].comments == 2


def test_probe_and_sustained_updates_still_need_a_repeat(demo):
    demo.failing_runs = {"repeat"}
    status, out = run(demo, verify.LIVE)
    assert status == 1
    assert "related" in ok_stages(out)
    assert "updated" not in ok_stages(out)
    assert demo.incidents[f"{KEY}-1"].comments == 3


def test_live_restarts_only_after_both_updates(demo):
    status, out = run(demo, verify.LIVE)
    assert status == 0
    assert elapsed(line(out, "OK", "traffic started")) >= max(
        elapsed(line(out, "OK", "updated")), elapsed(line(out, "OK", "related"))
    )
    assert demo.incidents[f"{KEY}-1"].comments >= 4


def test_unreadable_alertmanager_fails_related_and_restores_traffic(demo):
    demo.alertmanager_down = True
    status, out = run(demo, verify.LIVE)
    assert status == 1
    assert "Alertmanager answered 503" in line(out, "FAIL", "related")
    assert demo.compose_calls == [("stop", "traffic"), ("start", "traffic")]


def test_prefixed_session_matches_the_rendered_skill_and_jql(demo, env_file, capsys):
    from grafana_jsm_sandbox.skill_template import render

    values = {"DEMO_PROJECT_KEY": KEY, "DEMO_SESSION_ID": "ses-x"}
    project = DemoProject.from_environment(values)
    template = (Path(__file__).resolve().parents[1] / "skill/incident-sync/SKILL.md").read_text()
    rendered = render(template, project)
    demo.session_created = "ses-ses-x"
    env_file.write_text(env_text(DEMO_SESSION_ID="ses-x"))
    status, out, _ = command(demo, ["--mvp"], env_file, capsys)
    assert status == 0, out
    assert 'labels = "ses-ses-x"' in rendered
    assert any(
        'labels = "ses-ses-x"' in call[2]
        for call in demo.jira_calls
        if call[:2] == ("search", "jql")
    )


def test_repeat_comment_reads_plain_text_and_adf():
    text = "Update: 4 firing. New: none. Repeat: alerts. Resolved: none. Open for 1m."
    adf = {
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": text[:30]},
                    {"type": "text", "text": text[30:]},
                ],
            }
        ],
    }
    assert verify_mvp.is_repeat_comment(text)
    assert verify_mvp.is_repeat_comment(adf)
    assert not verify_mvp.is_repeat_comment(text.replace("New: none", "New: probe"))
    assert not verify_mvp.is_repeat_comment("Opened from 4 firing Alerts.")


def test_sustained_title_matches_the_provisioned_rule():
    import yaml

    path = Path(__file__).resolve().parents[1] / "grafana/provisioning/alerting/alert-rule.yaml"
    rules = yaml.safe_load(path.read_text())["groups"][0]["rules"]
    rule = next(rule for rule in rules if rule["uid"] == "rolldice-outage-sustained")
    assert verify_mvp.SUSTAINED_TITLE == rule["title"]


def test_alertmanager_adapter_uses_the_verify_base_and_exact_endpoint(monkeypatch):
    calls = []
    monkeypatch.setattr(verify, "ask_grafana", lambda base, path: calls.append((base, path)) or [])
    assert verify.grafana_alerts_at("http://127.0.0.1:13000")() == []
    assert calls == [("http://127.0.0.1:13000", "/api/alertmanager/grafana/api/v2/alerts")]


def test_sustained_label_waits_for_its_own_comment_even_after_a_repeat(demo):
    baseline = GroupIncident("X-1", "Open", None, 1, frozenset(GROUP_LABELS[:2]))
    watch = verify_mvp.GroupWatch(demo.world([]), KEY, GROUP, SESSION, Timeouts())
    watch.one_open = lambda stage: []
    watch.world.grafana_alerts = lambda: [
        {
            "labels": {"alertname": verify_mvp.SUSTAINED_TITLE, "incident_group": GROUP},
            "fingerprint": RELATED_LABEL.removeprefix("fp-"),
        }
    ]
    probe = frozenset(GROUP_LABELS) - baseline.fingerprints
    reads = iter(
        [
            GroupIncident("X-1", "Open", None, 2, frozenset(GROUP_LABELS), 0, probe),
            GroupIncident("X-1", "Open", None, 3, frozenset(GROUP_LABELS), 1, probe),
            GroupIncident("X-1", "Open", None, 3, frozenset(ALL_LABELS), 1, probe),
            GroupIncident(
                "X-1", "Open", None, 4, frozenset(ALL_LABELS), 1, probe | {RELATED_LABEL}
            ),
        ]
    )

    def read(key):
        watch.incident = next(reads)
        return watch.incident

    watch.read = read
    incident = verify_mvp.updated(
        watch,
        baseline,
        demo.clock.now(),
        60,
        "creation",
        "no update",
        ("updated", "related"),
        live=True,
    )
    assert incident.comments == 4
    assert demo.clock.time == 1010


@pytest.mark.parametrize("answer", [None, {}, [{"labels": "malformed"}]])
def test_malformed_alertmanager_answers_fail_related(demo, answer):
    watch = verify_mvp.GroupWatch(demo.world([]), KEY, GROUP, SESSION, Timeouts())
    watch.world.grafana_alerts = lambda: answer
    with pytest.raises(verify.NotVerified, match="related"):
        verify_mvp.sustained_label(watch)


def test_sustained_fingerprint_is_from_alertmanager_and_not_a_fixture(demo):
    watch = verify_mvp.GroupWatch(demo.world([]), KEY, GROUP, SESSION, Timeouts())
    watch.world.grafana_alerts = lambda: [
        {
            "labels": {"alertname": "rolldice health probe is failing", "incident_group": GROUP},
            "fingerprint": "1111",
        },
        {
            "labels": {"alertname": verify_mvp.SUSTAINED_TITLE, "incident_group": "other"},
            "fingerprint": "2222",
        },
        {
            "labels": {"alertname": verify_mvp.SUSTAINED_TITLE, "incident_group": GROUP},
            "fingerprint": "abc123",
        },
    ]
    assert verify_mvp.sustained_label(watch) == "fp-abc123"


def test_a_reworded_update_comment_still_counts():
    """A Run that words the Skill's template differently is still read as the repeat, and its
    fp- labels as named: the labels on the Incident are the proof, not the comment's wording."""
    from grafana_jsm_sandbox.verify_mvp import is_repeat_comment, new_fingerprints

    assert is_repeat_comment("update - 3 firing; new: none; repeats: rate zero value=0")
    assert is_repeat_comment("Update: 3 firing. New: none. Repeat: a value=0.")
    assert not is_repeat_comment("Update: 4 firing. New: sustained (fp-5a0f3e) value=0.")
    assert new_fingerprints("Added the sustained outage alert fp-5a0f3e to this Incident.") == {
        "fp-5a0f3e"
    }
