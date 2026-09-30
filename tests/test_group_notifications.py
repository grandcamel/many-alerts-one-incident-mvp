"""The MVP's Notification sequence: one group of related Alerts, seen four times.

`docs/mvp-spec.md` promises one Incident for a fault that fires several
related Alerts. These four fixtures are that fault as Grafana posts it with
`group_by: [incident_group]`: three Alerts firing together, the same three
repeated, a fourth related Alert joining them, and every one of them resolved.
They are written to the spec, not recorded: the traffic-absence Alert keeps the
real Fingerprint chapter one recorded, the others' are made up but distinct.

What is asserted is the sequence, because the fixtures only mean anything
together, and then what the Skill does with each of them: the `jira-as`
commands the Skill prescribes for that step, in order. The repo has no harness
that runs the Skill against a fake Jira, so the expected sequence is checked
against the Skill's own text: every command the step calls for is a command the
rendered Skill spells out, on one line, and the decision table sends that
Notification to that step.
"""

from __future__ import annotations

import json
import re

import pytest
import yaml

from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.notification import validate_notification
from grafana_jsm_sandbox.run_command import SKILL_FILE
from grafana_jsm_sandbox.skill_template import render
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

SKILL = render(TEMPLATE, DemoProject(key="SANDBOX", session_id="rehearsal1"))
"""The Skill as a Run reads it for a project called SANDBOX in one rehearsal session."""

COMMANDS = [line for line in SKILL.splitlines() if line.startswith("jira-as ")]
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


# --- What the Skill does with each of them ---

MATCH_SEARCH = "jira-as search jql 'project = SANDBOX AND issuetype = Incident AND labels = "
CREATE = "jira-as issue create -p SANDBOX -t Incident "
OPENING_COMMENT = "jira-as collaborate comment add <key> -b 'Opened from "
ADD_LABELS = "jira-as api call editIssue --issue-id-or-key <key> --field 'update.labels=["
SERVER_TIME = "jira-as -o json api call getServerInfo"
ISSUE_GET = "jira-as issue get <key> -o json"
UPDATE_COMMENT = "jira-as collaborate comment add <key> -b 'Update: "
TRANSITIONS = "jira-as lifecycle transitions <key> -o json"
TRANSITION = "jira-as lifecycle transition <key> --id <id>"
CLOSING_COMMENT = "jira-as collaborate comment add <key> -b 'Resolved after "
COMPLETE = "jira-as lifecycle transition <key> --id <id> --resolution Done"


def test_the_first_firing_finds_no_match_and_creates_the_one_incident():
    """Three Alerts, one create, one opening comment: no per-Alert Incident."""
    search, create, opened = commands_starting(MATCH_SEARCH, CREATE, OPENING_COMMENT)

    assert f'labels = "{SESSION_LABEL}"' in search and 'labels = "grp-' in search
    assert "fp-" not in search, "the Match is the group's and the session's, not one Alert's"
    assert "[Create]" in table_row("firing", "none")
    assert f"--labels 'grp-<incident_group>,{SESSION_LABEL},fp-<fingerprint>" in create
    assert COMMANDS.count(create) == 1
    assert "<n> firing Alerts in <incident_group>" in opened


def test_the_repeat_finds_the_open_incident_and_updates_it_without_creating():
    """Every Alert repeats: no label to add, one comment naming them as repeats, then
    `Open` moves to `Work in progress`, which the first update and only the first does."""
    commands_starting(MATCH_SEARCH, SERVER_TIME, ISSUE_GET, UPDATE_COMMENT, TRANSITIONS, TRANSITION)

    assert "[Update]" in table_row("firing", "`Open`")
    assert "move it to `Work in progress`" in table_row("firing", "`Open`")
    assert "Skip this command entirely when no Alert is new" in SKILL
    [comment] = commands_starting(UPDATE_COMMENT)
    assert "Repeat: <alertname> value=<current>" in comment
    assert "New: <alertname> (fp-<fingerprint>) value=<current>" in comment


def test_the_related_alert_adds_its_label_and_a_comment_and_nothing_else():
    """The Incident is in `Work in progress` by now: add the one new `fp-` label, comment,
    and leave the status alone."""
    [add_labels] = commands_starting(ADD_LABELS)

    assert '{"add":"fp-<fingerprint>"}' in add_labels
    assert "[Update]" in table_row("firing", "`Work in progress`")
    assert "nothing else" in table_row("firing", "`Work in progress`")
    assert "Never use\n`jira-as issue update --labels`" in SKILL, (
        "jira-as 2.0.0's `issue update --labels` replaces the whole set"
    )
    assert not any(command.startswith("jira-as issue update") for command in COMMANDS)


def test_all_resolved_closes_the_incident_with_a_resolution():
    commands_starting(MATCH_SEARCH, CLOSING_COMMENT, COMPLETE)

    assert "[Close]" in table_row("resolved", "`Open` or `Work in progress`")
    assert "--resolution Done" in COMPLETE
    assert COMMANDS.count(COMPLETE) == 1


def test_a_resolved_notification_with_no_open_incident_is_skipped_and_said_so():
    row = table_row("resolved", "none")

    assert "Do nothing" in row
    assert "skipped" in row


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_the_skill_spells_out_is_one_line_the_allow_list_matches(command):
    """One line of plain single quotes, or the permission boundary denies it whole (README)."""
    assert command.startswith("jira-as ")
    assert "$'" not in command and "\\" not in command and "\n" not in command
    assert command.count("'") % 2 == 0, "an unbalanced quote would run on to the next line"
