"""The MVP's Notification sequence: one group of related Alerts, seen four times.

`docs/mvp-spec.md` promises one Incident for a fault that fires several
related Alerts. These four fixtures are that fault as Grafana posts it with
`group_by: [incident_group]`: three Alerts firing together, the same three
repeated, a fourth related Alert joining them, and every one of them resolved.
They are written to the spec, not recorded: the traffic-absence Alert keeps the
real Fingerprint chapter one recorded, the others' are made up but distinct.

What is asserted is the sequence, because the fixtures only mean anything
together, and then what a Run does with each of them: the decision table in the
rendered Skill sends that Notification to that step, and `incident-payload`, run
on it in a Run's working directory with the Match the step before would have
left, prints the `jira-as` commands for it, each on one line. The real jira-as
carries those commands out against the fake Jira in `test_fake_jira.py`.
"""

from __future__ import annotations

import json
import re
import shlex

import pytest
import yaml

from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.incident_payload import printed
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME, validate_notification
from grafana_jsm_sandbox.run_command import RENDERED_SKILL, SKILL_FILE
from grafana_jsm_sandbox.skill_template import materialize, render
from tests.conftest import FIXTURES, REPOSITORY

GROUP = "checkout-outage"
"""The demo's `incident_group`, which every related alert rule carries (the spec)."""

GROUP_LABEL = f"grp-{GROUP}"
"""The group's Jira label, as the spec spells it."""

SESSION_LABEL = "ses-rehearsal1"
"""One session's label, as the Receiver renders it from `DEMO_SESSION_ID`."""

FIRING = "notification-group-firing.json"
REPEAT = "notification-group-repeat.json"
RELATED = "notification-group-related.json"
RESOLVED = "notification-group-resolved.json"

GROUP_SEQUENCE = (FIRING, REPEAT, RELATED, RESOLVED)
"""The canned group Notifications, in the order the MVP demo replays them."""

TRAFFIC_ABSENCE_FINGERPRINT = "87e2f184874a3b71"
"""The real Fingerprint of chapter one's Alert (`fixtures/notification-firing.json`), which is
the first rule of the group."""

TEMPLATE = (REPOSITORY / "skill" / SKILL_FILE).read_text(encoding="utf-8")

PROJECT = DemoProject(key="SANDBOX", session_id="rehearsal1")

SKILL = render(TEMPLATE, PROJECT)
"""The Skill as a Run reads it for a project called SANDBOX in one rehearsal session."""

COMMANDS = [
    line for line in SKILL.splitlines() if line.startswith(("jira-as ", "incident-payload "))
]
"""Every invocation the Skill spells out, each one line."""


def canned(filename: str) -> dict:
    """One canned Notification, validated the way the Receiver validates it."""
    return validate_notification((FIXTURES / filename).read_bytes())


def alerts(filename: str) -> list[dict]:
    return canned(filename)["alerts"]


def fingerprints(filename: str) -> list[str]:
    return [alert["fingerprint"] for alert in alerts(filename)]


def commands_starting(*prefixes: str) -> list[str]:
    """The Skill's command lines that start with each prefix, one per prefix, in order."""
    found = []
    for prefix in prefixes:
        matching = [command for command in COMMANDS if command.startswith(prefix)]
        assert matching, f"the Skill spells out no command starting {prefix!r}"
        found.append(matching[0])
    return found


def table_row(notification: str, match: str) -> str:
    """The decision table's row for a Notification status and a Match status."""
    [row] = [
        line for line in SKILL.splitlines() if line.startswith(f"| `{notification}` | {match} |")
    ]
    return row


# --- The fixtures are a sequence ---


@pytest.mark.parametrize("filename", GROUP_SEQUENCE)
def test_each_fixture_is_a_notification_the_receiver_accepts(filename):
    notification = canned(filename)
    assert notification["alerts"]

    # The bytes on disk are what Grafana would post, formatting included.
    raw = (FIXTURES / filename).read_text()
    assert json.loads(raw) == notification


@pytest.mark.parametrize("filename", GROUP_SEQUENCE)
def test_every_alert_is_in_the_group_and_the_group_is_what_grafana_grouped_by(filename):
    notification = canned(filename)

    assert notification["groupLabels"] == {"incident_group": GROUP}
    assert notification["commonLabels"]["incident_group"] == GROUP
    for alert in notification["alerts"]:
        assert alert["labels"]["incident_group"] == GROUP


def test_the_group_label_is_the_spec_s_shape():
    assert re.fullmatch(r"grp-[a-z0-9-]+", GROUP_LABEL)
    assert GROUP_LABEL == "grp-" + canned(FIRING)["groupLabels"]["incident_group"]


def test_the_sequence_is_three_firing_then_a_repeat_then_a_related_then_all_resolved():
    assert [canned(filename)["status"] for filename in GROUP_SEQUENCE] == [
        "firing",
        "firing",
        "firing",
        "resolved",
    ]
    assert [len(alerts(filename)) for filename in GROUP_SEQUENCE] == [3, 3, 4, 4]


def test_the_first_notification_carries_three_distinct_firing_alerts():
    firing = alerts(FIRING)

    assert [alert["status"] for alert in firing] == ["firing"] * 3
    assert len(set(fingerprints(FIRING))) == 3
    assert TRAFFIC_ABSENCE_FINGERPRINT in fingerprints(FIRING), "chapter one's Alert leads"


def test_a_repeat_is_the_same_notification_sent_again():
    """Grafana repeats a Firing verbatim, values included; the update comment says `repeat`."""
    assert canned(REPEAT) == canned(FIRING)


def test_the_related_alert_joins_the_same_three_and_adds_one_fingerprint():
    related = alerts(RELATED)

    assert related[:3] == alerts(FIRING)
    assert [alert["status"] for alert in related] == ["firing"] * 4
    joined = related[3]
    assert joined["fingerprint"] not in fingerprints(FIRING)
    assert joined["labels"]["alertname"] == "rolldice outage is sustained"
    assert joined["startsAt"] > max(alert["startsAt"] for alert in alerts(FIRING)), (
        "the sustained-outage rule has the longer pending period, so it fires later"
    )


def test_the_resolved_notification_resolves_every_alert_the_group_ever_had():
    resolved = alerts(RESOLVED)

    assert [alert["status"] for alert in resolved] == ["resolved"] * 4
    assert fingerprints(RESOLVED) == fingerprints(RELATED)
    for alert in resolved:
        assert alert["endsAt"] > alert["startsAt"]


def test_every_fingerprint_is_hex_and_every_alert_keeps_its_own_across_the_sequence():
    by_name: dict[str, set[str]] = {}
    for filename in GROUP_SEQUENCE:
        for alert in alerts(filename):
            assert re.fullmatch(r"[0-9a-f]{16}", alert["fingerprint"])
            by_name.setdefault(alert["labels"]["alertname"], set()).add(alert["fingerprint"])
    assert all(len(seen) == 1 for seen in by_name.values()), by_name
    assert len(by_name) == 4


@pytest.mark.parametrize("filename", GROUP_SEQUENCE)
def test_every_alert_carries_what_the_field_mapping_reads(filename):
    for alert in alerts(filename):
        assert set(alert["labels"]) >= {"alertname", "instance", "service", "severity"}
        assert set(alert["annotations"]) >= {"summary", "description"}
        assert {"generatorURL", "dashboardURL", "panelURL", "startsAt"} <= set(alert)
        assert "A" in alert["values"]


def test_the_group_shares_one_service_so_the_summary_and_component_name_it():
    for filename in GROUP_SEQUENCE:
        assert {alert["labels"]["service"] for alert in alerts(filename)} == {"rolldice"}


@pytest.mark.parametrize("filename", GROUP_SEQUENCE)
@pytest.mark.parametrize("directory", [FIXTURES, FIXTURES / "mvp"], ids=["root", "mvp"])
def test_group_annotations_and_message_match_the_real_alert_rules(directory, filename):
    rules = yaml.safe_load(
        (REPOSITORY / "grafana/provisioning/alerting/alert-rule.yaml").read_text()
    )["groups"][0]["rules"]
    annotations = {rule["title"]: rule["annotations"] for rule in rules}
    notification = validate_notification((directory / filename).read_bytes())

    for alert in notification["alerts"]:
        expected = annotations[alert["labels"]["alertname"]]
        for name in ("summary", "description"):
            assert alert["annotations"][name] == expected[name]
            assert f" - {name} = {expected[name]}\n" in notification["message"]


# --- What a Run does with each of them ---

MATCH = "incident-payload match"
CREATE = "incident-payload create --component '<service>'"
UPDATE = "incident-payload update --key <key> --labels "
CLOSE = "incident-payload close --key <key> --labels "
SERVER_TIME = "jira-as -o json api call getServerInfo"
COMMENTS = "jira-as collaborate comment list <key> --order asc --limit 200 -o json"
TRANSITIONS = "jira-as lifecycle transitions <key> -o json"
TRANSITION = "jira-as lifecycle transition <key> --id <id>"
COMPLETE = "jira-as lifecycle transition <key> --id <id> --resolution Done"
CHECK = "jira-as issue get <key> --fields status,resolution -o json"

KEY = "SANDBOX-1"
CREATED = "2026-09-25T14:02:30.000+0000"
NOW = "2026-09-25T14:06:00.000+0000"
"""The Incident the first Run would have created, and Jira's clock at a later Run."""

AFTER_CREATE = [GROUP_LABEL, SESSION_LABEL, *(f"fp-{fp}" for fp in fingerprints(FIRING))]
"""The Match's labels once the first Notification's Run created it."""


def run_on(tmp_path, filename: str, *argv: str) -> list[str]:
    """What `incident-payload` prints for one canned Notification, in a Run's directory."""
    runs = tmp_path / "runs"
    if not (runs / RENDERED_SKILL).exists():
        materialize(REPOSITORY / "skill", runs / RENDERED_SKILL, PROJECT)
    working = runs / filename.replace(".json", "")
    working.mkdir(parents=True, exist_ok=True)
    (working / NOTIFICATION_FILENAME).write_bytes((FIXTURES / filename).read_bytes())
    return printed(list(argv), working)


def against_match(*step: str, labels: list[str]) -> list[str]:
    return [
        *step,
        "--key",
        KEY,
        "--labels",
        ",".join(labels),
        "--created",
        CREATED,
        "--server-time",
        NOW,
    ]


def run_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if not line.startswith("#")]


def test_the_first_firing_finds_no_match_and_creates_the_one_incident(tmp_path):
    """Three Alerts, one create, one opening comment: no per-Alert Incident."""
    commands_starting(MATCH, CREATE)
    [search] = run_lines(run_on(tmp_path, FIRING, "match"))
    dry_run, create, opened = run_lines(
        run_on(tmp_path, FIRING, "create", "--component", "rolldice")
    )

    assert f'labels = "{SESSION_LABEL}"' in search and f'labels = "{GROUP_LABEL}"' in search
    assert "fp-" not in search, "the Match is the group's and the session's, not one Alert's"
    assert "[Create]" in table_row("firing", "none")
    assert f"--labels '{','.join(AFTER_CREATE)}'" in create
    assert dry_run == create.replace(" -o json", " --dry-run -o json")
    assert "-s 'checkout-outage: 3 alerts firing on rolldice'" in create
    assert "Opened from 3 firing Alerts in checkout-outage: " in opened


def test_the_repeat_finds_the_open_incident_and_updates_it_without_creating(tmp_path):
    """Every Alert repeats: no label to add, one comment naming them as repeats, then
    `Open` moves to `Work in progress`, which the first update and only the first does."""
    commands_starting(MATCH, SERVER_TIME, UPDATE, TRANSITIONS, TRANSITION)
    lines = run_on(tmp_path, REPEAT, *against_match("update", labels=AFTER_CREATE))

    [comment] = run_lines(lines)
    assert "[Update]" in table_row("firing", "`Open`")
    assert "move it to `Work in progress`" in table_row("firing", "`Open`")
    assert lines[0].startswith("# No label to add")
    assert comment.startswith(f"jira-as collaborate comment add {KEY} -b 'Update: 3 firing. ")
    assert "New: none. Repeat: rolldice request rate is zero value=0; " in comment
    assert "Open for 3m30s.'" in comment


def test_the_related_alert_adds_its_label_and_a_comment_and_nothing_else(tmp_path):
    """The Incident is in `Work in progress` by now: add the one new `fp-` label, comment,
    and leave the status alone."""
    joined = alerts(RELATED)[3]["fingerprint"]

    add, comment = run_lines(
        run_on(tmp_path, RELATED, *against_match("update", labels=AFTER_CREATE))
    )

    assert add == (
        f"jira-as api call editIssue --issue-id-or-key {KEY} "
        f'--field \'update.labels=[{{"add":"fp-{joined}"}}]\''
    )
    assert f"New: rolldice outage is sustained (fp-{joined}) value=" in comment
    assert "[Update]" in table_row("firing", "`Work in progress`")
    assert "nothing else" in table_row("firing", "`Work in progress`")
    assert "Never use\n`jira-as issue update --labels`" in SKILL, (
        "jira-as 2.0.0's `issue update --labels` replaces the whole set"
    )
    assert not any(command.startswith("jira-as issue update") for command in COMMANDS)


def test_all_resolved_closes_the_incident_with_a_resolution_and_checks_it(tmp_path):
    commands_starting(MATCH, SERVER_TIME, COMMENTS, CLOSE, COMPLETE, CHECK)
    every = [*AFTER_CREATE, f"fp-{alerts(RELATED)[3]['fingerprint']}"]

    [comment] = run_lines(
        run_on(tmp_path, RESOLVED, *against_match("close", "--runs", "3", labels=every))
    )

    assert "[Close]" in table_row("resolved", "`Open` or `Work in progress`")
    assert COMMANDS.count(COMPLETE) == 1
    assert comment == (
        f"jira-as collaborate comment add {KEY} -b 'Resolved after 3m30s: every Alert in "
        "checkout-outage is resolved (4 Alerts, 4 Runs). Completed automatically from the "
        "Grafana Notification.'"
    )


def test_a_resolved_notification_with_no_open_incident_is_skipped_and_said_so():
    row = table_row("resolved", "none")

    assert "Do nothing" in row
    assert "skipped" in row


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_the_skill_spells_out_is_one_line_the_allow_list_matches(command):
    """One line of plain single quotes, or the permission boundary denies it whole (README)."""
    assert command.startswith(("jira-as ", "incident-payload "))
    assert "$'" not in command and "\\" not in command and "\n" not in command
    assert command.count("'") % 2 == 0, "an unbalanced quote would run on to the next line"


@pytest.mark.parametrize("enabled", [False, True])
def test_opening_and_investigation_then_close_counts_two_lifecycle_runs(tmp_path, enabled):
    from grafana_jsm_sandbox.investigation_contract import is_investigation

    skill = render(TEMPLATE, PROJECT, investigation_enabled=enabled)
    assert COMMENTS in skill
    _, _, opening = run_lines(run_on(tmp_path, FIRING, "create"))
    bodies = [shlex.split(opening)[-1], "[grafana-investigation] New: none; fp-deadbeef"]
    assert len(bodies) == 2
    prior_lifecycle = sum(not is_investigation(body) for body in bodies)
    *_, closing = run_lines(run_on(tmp_path, RESOLVED,
                                *against_match("close", "--runs", str(prior_lifecycle),
                                               labels=AFTER_CREATE)))
    assert "2 Runs" in closing
