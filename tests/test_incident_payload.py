"""`incident-payload`: the jira-as lines a Run runs instead of building payloads by hand.

The 2026-10-01 rehearsals showed what a cheaper model does with a Skill that asks it
to write ADF inside a shell argument: six malformed creates and an Incident whose
Description was `Test`. The tool takes that work, so these tests hold it to what the
Run and verification rely on: the summary, the labels, the fields, the Description's
ADF, the comment text, the sort of each Alert into new, repeat or resolved, the
duration, and refusals that are one line. Every printed command must be one line the
permission boundary admits, whatever the Alert text holds, and the printed create
must be one the real jira-as accepts: it is run through jira-as's offline
`--dry-run`, which sends nothing anywhere.
"""

from __future__ import annotations

import ast
import importlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from grafana_jsm_sandbox import demo_config, incident_payload
from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.incident_payload import (
    FACTS_FILE,
    PayloadError,
    main,
    plain,
    printed,
    read_group,
)
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.run_command import RENDERED_SKILL
from grafana_jsm_sandbox.skill_template import FIELDS, materialize
from tests.conftest import FIXTURES, REPOSITORY

SKILL_TEMPLATE = REPOSITORY / "skill"

CONFIGURED = DemoProject(
    key="SANDBOX",
    severity_field="customfield_20001",
    urgency_field="customfield_20002",
    source_field="customfield_20003",
    major_incident_field="customfield_20004",
    session_id="rehearsal1",
)
"""A project with every field, under ids that are nobody's real site's."""

BARE = DemoProject(key="SANDBOX", session_id="rehearsal1")
"""A project that lacks every optional field."""

SESSION = "ses-rehearsal1"
GROUP_LABEL = "grp-checkout-outage"

FIRING = "mvp/notification-group-firing.json"
REPEAT = "mvp/notification-group-repeat.json"
RELATED = "mvp/notification-group-related.json"
RESOLVED = "mvp/notification-group-resolved.json"

FIRST_THREE = ("87e2f184874a3b71", "3c1d9a7e5b2f8046", "a94f0c2e7d13b58c")
"""The three Alerts of the first Notification, in its order."""

CREATED = "2026-10-01T14:02:10.123+0000"
SERVER_TIME = "2026-10-01T14:06:40.456+0000"
"""A Match's `created` and Jira's `serverTime` four and a half minutes later, as Jira writes
them."""


def canned(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def run_directory(tmp_path: Path, notification: dict, project: DemoProject = CONFIGURED) -> Path:
    """A Run's working directory, laid out as the Receiver lays it out.

    The Skill is rendered from the real template into `<runs>/.skill`, which puts the
    project's facts beside it, and the Notification is the Run's own.
    """
    runs = tmp_path / "runs"
    if not (runs / RENDERED_SKILL).exists():
        materialize(SKILL_TEMPLATE, runs / RENDERED_SKILL, project)
    working = runs / "20261001T140210-abc123"
    working.mkdir(parents=True, exist_ok=True)
    (working / NOTIFICATION_FILENAME).write_text(json.dumps(notification), encoding="utf-8")
    return working


def commands(lines: list[str]) -> list[str]:
    """The printed lines a Run runs: everything that is not a `#` line."""
    return [line for line in lines if not line.startswith("#")]


def argument(command: str, flag: str) -> str:
    """The value one flag of a printed command takes, as the shell would hand it over."""
    words = shlex.split(command)
    return words[words.index(flag) + 1]


def labels_of(match_labels: list[str]) -> str:
    return ",".join(match_labels)


def update_argv(labels: list[str], *more: str) -> list[str]:
    return [
        "update",
        "--key",
        "SANDBOX-7",
        "--labels",
        labels_of(labels),
        "--created",
        CREATED,
        "--server-time",
        SERVER_TIME,
        *more,
    ]


def close_argv(labels: list[str], runs: int = 3, *more: str) -> list[str]:
    return [
        "close",
        "--key",
        "SANDBOX-7",
        "--labels",
        labels_of(labels),
        "--created",
        CREATED,
        "--server-time",
        SERVER_TIME,
        "--runs",
        str(runs),
        *more,
    ]


def alert(
    fingerprint: str,
    status: str = "firing",
    severity: str = "critical",
    service: str = "rolldice",
    **overrides: object,
) -> dict:
    """One Grafana Alert, shaped like the fixtures' and as plain as one can be."""
    made = {
        "status": status,
        "labels": {
            "alertname": f"alert {fingerprint}",
            "incident_group": "checkout-outage",
            "instance": "rolldice:8082",
            "service": service,
            "severity": severity,
        },
        "annotations": {"summary": "something is wrong"},
        "startsAt": "2026-09-25T14:02:10Z",
        "generatorURL": f"http://localhost:3000/alerting/grafana/{fingerprint}/view?orgId=1",
        "fingerprint": fingerprint,
        "values": {"A": 0},
    }
    made.update(overrides)
    return made


def notification_of(*alerts: dict) -> dict:
    status = "firing" if any(a["status"] == "firing" for a in alerts) else "resolved"
    return {
        "status": status,
        "alerts": list(alerts),
        "groupLabels": {"incident_group": "checkout-outage"},
    }


HOSTILE_SUMMARY = (
    "it's \"down\" (again)\nsee C:\\logs\\app.log; cost `$5` & $'x' — naïve 日本 🚨\t\u2028end\x07"
)
"""Everything an annotation could hold that a shell argument or a JSON string would choke on."""

HOSTILE_URL = "http://grafana.example.invalid/d/abc?orgId=1&var-q=(a%20b)&from=now-1h"


def hostile() -> dict:
    return notification_of(
        alert(
            "0a1b2c3d4e5f6071",
            annotations={"summary": HOSTILE_SUMMARY},
            generatorURL=HOSTILE_URL,
            labels={
                "alertname": "O'Brien's \"probe\"",
                "incident_group": "checkout-outage",
                "instance": "host (eu-1)",
                "service": "rolldice",
                "severity": "critical",
            },
        ),
        alert("1b2c3d4e5f607182"),
    )


# --- The Match search ---


def test_the_match_search_names_the_project_the_group_and_the_session(tmp_path):
    lines = printed(["match"], run_directory(tmp_path, canned(FIRING)))

    [search] = commands(lines)
    assert search == (
        "jira-as search jql 'project = SANDBOX AND issuetype = Incident AND labels = "
        f'"{GROUP_LABEL}" AND labels = "{SESSION}" AND statusCategory != Done\' '
        "--fields key,status,labels,created -o json"
    )


def test_the_group_label_is_lower_case_and_a_z_0_9_and_hyphens_only(tmp_path):
    notification = canned(FIRING)
    notification["groupLabels"]["incident_group"] = "Checkout_Outage EU"

    [search] = commands(printed(["match"], run_directory(tmp_path, notification)))

    assert 'labels = "grp-checkout-outage-eu"' in search


# --- Create ---


def created(tmp_path, notification: dict, project=CONFIGURED, *more: str) -> list[str]:
    return commands(printed(["create", *more], run_directory(tmp_path, notification, project)))


def test_create_prints_the_dry_run_then_the_create_then_the_opening_comment(tmp_path):
    dry_run, create, comment = created(tmp_path, canned(FIRING))

    assert dry_run == f"{create.removesuffix(' -o json')} --dry-run -o json"
    assert create.startswith("jira-as issue create -p SANDBOX -t Incident ")
    assert comment.startswith("jira-as collaborate comment add <key> -b '")


def test_the_summary_names_the_group_the_firing_count_and_the_shared_service(tmp_path):
    [_, create, _] = created(tmp_path, canned(FIRING))

    assert argument(create, "-s") == "checkout-outage: 3 alerts firing on rolldice"


def test_the_summary_names_no_service_when_the_firing_alerts_differ(tmp_path):
    notification = notification_of(alert("aa01", service="rolldice"), alert("aa02", service="db"))

    [_, create, _] = created(tmp_path, notification)

    assert argument(create, "-s") == "checkout-outage: 2 alerts firing"


def test_the_summary_counts_only_firing_alerts(tmp_path):
    notification = notification_of(alert("aa01"), alert("aa02", status="resolved"))

    [_, create, _] = created(tmp_path, notification)

    assert argument(create, "-s") == "checkout-outage: 1 alerts firing on rolldice"


def test_the_labels_are_the_group_the_session_and_every_alert_resolved_ones_included(tmp_path):
    notification = notification_of(alert("aa01"), alert("aa02", status="resolved"), alert("aa01"))

    [_, create, _] = created(tmp_path, notification)

    assert argument(create, "--labels").split(",") == [GROUP_LABEL, SESSION, "fp-aa01", "fp-aa02"]


def test_the_labels_of_the_first_notification(tmp_path):
    [_, create, _] = created(tmp_path, canned(FIRING))

    assert argument(create, "--labels").split(",") == [
        GROUP_LABEL,
        SESSION,
        *(f"fp-{fingerprint}" for fingerprint in FIRST_THREE),
    ]


@pytest.mark.parametrize(
    ("severities", "severity", "urgency"),
    [
        (["critical"], "Sev-1", "Critical"),
        (["warning", "critical", "info"], "Sev-1", "Critical"),
        (["Critical"], "Sev-1", "Critical"),
        (["warning", "info"], "Sev-2", "High"),
        (["info"], "Sev-3", "Medium"),
        ([""], "Sev-3", "Medium"),
    ],
)
def test_severity_is_the_worst_firing_alert_s_and_urgency_follows(
    tmp_path, severities, severity, urgency
):
    notification = notification_of(
        *(alert(f"bb{index:02d}", severity=label) for index, label in enumerate(severities))
    )

    [_, create, _] = created(tmp_path, notification)

    assert json.loads(argument(create, "--custom-fields")) == {
        "customfield_20001": {"value": severity},
        "customfield_20002": {"value": urgency},
        "customfield_20003": {"value": "Monitoring systems"},
    }


def test_a_resolved_alert_s_severity_does_not_count(tmp_path):
    notification = notification_of(
        alert("cc01", severity="warning"), alert("cc02", status="resolved", severity="critical")
    )

    [_, create, _] = created(tmp_path, notification)

    assert json.loads(argument(create, "--custom-fields"))["customfield_20001"] == {
        "value": "Sev-2"
    }


def test_only_the_project_s_own_fields_are_set_and_the_description_is_not_one(tmp_path):
    project = replace(CONFIGURED, urgency_field=None)

    [_, create, _] = created(tmp_path, canned(FIRING), project)

    fields = json.loads(argument(create, "--custom-fields"))
    assert set(fields) == {"customfield_20001", "customfield_20003"}
    assert all(name.startswith("customfield_") for name in fields)


def test_a_project_with_no_optional_field_gets_no_custom_fields_at_all(tmp_path):
    [_, create, _] = created(tmp_path, canned(FIRING), BARE)

    assert "--custom-fields" not in shlex.split(create)
    assert "customfield_" not in create


def test_the_values_written_are_the_values_the_skill_names():
    """The Skill's facts table says which values each field takes; the tool writes only those."""
    named = {field.name: field.values for field in FIELDS}
    for _, severity in (*incident_payload.SEVERITIES, (None, incident_payload.LOWEST_SEVERITY)):
        assert f"`{severity}`" in named["Severity"]
        assert f"`{incident_payload.URGENCY[severity]}`" in named["Urgency"]
    assert f"`{incident_payload.SOURCE}`" in named["Source"]


def test_the_description_is_adf_a_heading_and_one_bullet_per_firing_alert_in_order(tmp_path):
    notification = canned(FIRING)
    notification["alerts"].insert(1, alert("dd01", status="resolved"))

    [_, create, _] = created(tmp_path, notification)

    document = json.loads(argument(create, "--description"))
    assert document["type"] == "doc" and document["version"] == 1
    heading, bullets = document["content"]
    assert heading == {
        "type": "paragraph",
        "content": [
            {"type": "text", "text": "Partial Report: 3 alerts firing in group checkout-outage."}
        ],
    }
    assert bullets["type"] == "bulletList"
    texts = []
    for item in bullets["content"]:
        assert item["type"] == "listItem"
        [paragraph] = item["content"]
        assert paragraph["type"] == "paragraph"
        [text] = paragraph["content"]
        assert text["type"] == "text"
        texts.append(text["text"])
    assert texts == [
        (
            "rolldice request rate is zero on rolldice:8082: rolldice is receiving no traffic. "
            "value=0, since 2026-09-25T14:02:10Z. "
            "http://localhost:3000/alerting/grafana/rolldice-rate-zero/view?orgId=1"
        ),
        (
            "rolldice successful responses have dropped on rolldice:8082: rolldice successful "
            "responses have dropped. value=0, since 2026-09-25T14:02:10Z. "
            "http://localhost:3000/alerting/grafana/rolldice-2xx-drop/view?orgId=1"
        ),
        (
            "rolldice health probe is failing on rolldice:8082: the rolldice health probe is "
            "failing. value=1, since 2026-09-25T14:02:10Z. "
            "http://localhost:3000/alerting/grafana/rolldice-probe-failing/view?orgId=1"
        ),
    ]


def test_a_bullet_does_without_what_the_alert_lacks(tmp_path):
    bare = alert("ee01", annotations={"description": "only a description."}, values=None)
    del bare["labels"]["instance"], bare["generatorURL"]

    [_, create, _] = created(tmp_path, notification_of(bare))

    [bullet] = json.loads(argument(create, "--description"))["content"][1]["content"]
    assert bullet["content"][0]["content"][0]["text"] == (
        "alert ee01: only a description. value=unknown, since 2026-09-25T14:02:10Z."
    )


def test_the_opening_comment_names_each_firing_alert_and_its_value(tmp_path):
    [_, _, comment] = created(tmp_path, canned(FIRING))

    assert argument(comment, "-b") == (
        "Opened from 3 firing Alerts in checkout-outage: rolldice request rate is zero value=0; "
        "rolldice successful responses have dropped value=0; "
        "rolldice health probe is failing value=1."
    )


def test_a_component_is_named_only_when_it_is_the_firing_alerts_shared_service(tmp_path):
    [_, create, _] = created(tmp_path, canned(FIRING), CONFIGURED, "--component", "rolldice")

    assert argument(create, "--components") == "rolldice"
    [_, without, _] = created(tmp_path, canned(FIRING))
    assert "--components" not in shlex.split(without)


@pytest.mark.parametrize(
    "notification",
    [
        notification_of(alert("ff01", service="rolldice")),
        notification_of(alert("ff01", service="rolldice"), alert("ff02", service="db")),
    ],
    ids=["another service", "no shared service"],
)
def test_a_component_that_is_not_the_shared_service_is_refused(tmp_path, notification):
    with pytest.raises(PayloadError, match="--component 'db'|leave --component off"):
        printed(["create", "--component", "db"], run_directory(tmp_path, notification))


def test_a_notification_with_nothing_firing_is_never_created(tmp_path):
    with pytest.raises(PayloadError, match="skipped, never created"):
        printed(["create"], run_directory(tmp_path, canned(RESOLVED)))


# --- Update ---


def updated(tmp_path, notification: dict, labels: list[str]) -> list[str]:
    return printed(update_argv(labels), run_directory(tmp_path, notification))


AFTER_CREATE = [GROUP_LABEL, SESSION, *(f"fp-{fingerprint}" for fingerprint in FIRST_THREE)]
"""The Match's labels once the first Notification created it."""


def test_a_repeat_adds_no_label_and_comments_that_every_alert_repeats(tmp_path):
    lines = updated(tmp_path, canned(REPEAT), AFTER_CREATE)

    [comment] = commands(lines)
    assert "# No label to add" in lines[0]
    assert argument(comment, "-b") == (
        "Update: 3 firing. New: none. Repeat: rolldice request rate is zero value=0; "
        "rolldice successful responses have dropped value=0; "
        "rolldice health probe is failing value=1. Resolved: none. Open for 4m30s."
    )
    assert comment.startswith("jira-as collaborate comment add SANDBOX-7 -b '")
    assert lines[-3:] == [f"# fp-{fingerprint} repeat" for fingerprint in FIRST_THREE]


def test_the_related_alert_is_new_and_only_its_label_is_added(tmp_path):
    joined = canned(RELATED)["alerts"][3]["fingerprint"]

    lines = updated(tmp_path, canned(RELATED), AFTER_CREATE)

    add, comment = commands(lines)
    assert add == (
        "jira-as api call editIssue --issue-id-or-key SANDBOX-7 --field "
        f'\'update.labels=[{{"add":"fp-{joined}"}}]\''
    )
    text = argument(comment, "-b")
    assert f"New: rolldice outage is sustained (fp-{joined}) value=" in text
    assert text.startswith("Update: 4 firing. ")
    assert "# For the Finish: 1 label added. The Alerts:" in lines
    assert f"# fp-{joined} new" in lines


def test_a_resolved_alert_in_a_firing_notification_is_listed_and_keeps_its_label(tmp_path):
    notification = notification_of(alert("aa01"), alert("aa02", status="resolved"))

    lines = updated(tmp_path, notification, [GROUP_LABEL, SESSION, "fp-aa01"])

    add, comment = commands(lines)
    assert '{"add":"fp-aa02"}' in add
    assert argument(comment, "-b") == (
        "Update: 1 firing. New: none. Repeat: alert aa01 value=0. Resolved: alert aa02. "
        "Open for 4m30s."
    )
    assert lines[-2:] == ["# fp-aa01 repeat", "# fp-aa02 resolved"]


def test_the_match_s_labels_may_be_the_json_list_jira_as_printed(tmp_path):
    working = run_directory(tmp_path, canned(REPEAT))
    argv = update_argv([])
    argv[argv.index("--labels") + 1] = json.dumps(AFTER_CREATE)

    assert printed(argv, working) == updated(tmp_path, canned(REPEAT), AFTER_CREATE)


def test_an_update_with_nothing_firing_is_refused_as_a_close(tmp_path):
    with pytest.raises(PayloadError, match="that is a close"):
        updated(tmp_path, canned(RESOLVED), AFTER_CREATE)


@pytest.mark.parametrize("missing", [GROUP_LABEL, SESSION])
def test_labels_that_are_not_this_group_s_match_s_are_refused(tmp_path, missing):
    labels = [label for label in AFTER_CREATE if label != missing]

    with pytest.raises(PayloadError, match=f"--labels lacks {missing}"):
        updated(tmp_path, canned(REPEAT), labels)


@pytest.mark.parametrize("key", ["OTHER-7", "SANDBOX", "SANDBOX-0", "sandbox-7", "SANDBOX-7 x"])
def test_a_key_that_is_not_an_issue_of_the_project_is_refused(tmp_path, key):
    argv = update_argv(AFTER_CREATE)
    argv[argv.index("--key") + 1] = key

    with pytest.raises(PayloadError, match="--key"):
        printed(argv, run_directory(tmp_path, canned(REPEAT)))


# --- Durations ---


@pytest.mark.parametrize(
    ("created", "server_time", "said"),
    [
        (CREATED, SERVER_TIME, "4m30s"),
        ("2026-10-01T14:02:10.000+0000", "2026-10-01T14:02:55.999+0000", "45s"),
        ("2026-10-01T14:02:10.000+0000", "2026-10-01T14:02:10.000+0000", "0s"),
        ("2026-10-01T14:02:10.000+0000", "2026-10-01T15:04:13.000+0000", "1h2m3s"),
        ("2026-10-01T14:02:10Z", "2026-10-01T14:07:10Z", "5m0s"),
        ("2026-10-01T14:02:10.123+00:00", "2026-10-01T16:06:40.123+02:00", "4m30s"),
        ("2026-10-01T14:02:10.123456789+0000", "2026-10-01T14:06:40.123456789+0000", "4m30s"),
    ],
)
def test_the_duration_is_jira_s_clock_minus_created(created, server_time, said):
    assert incident_payload.duration(created, server_time) == said


@pytest.mark.parametrize(
    ("created", "server_time", "refusal"),
    [
        (SERVER_TIME, CREATED, "before --created"),
        ("2026-10-01 14:02:10", SERVER_TIME, "--created is not a Jira timestamp"),
        ("2026-10-01T14:02:10.123", SERVER_TIME, "--created is not a Jira timestamp"),
        (CREATED, "now", "--server-time is not a Jira timestamp"),
        ("2026-13-01T14:02:10.123+0000", SERVER_TIME, "not a time there ever was"),
    ],
)
def test_a_duration_that_cannot_be_worked_out_is_refused(created, server_time, refusal):
    with pytest.raises(PayloadError, match=refusal):
        incident_payload.duration(created, server_time)


# --- Close ---


EVERY_LABEL = [*AFTER_CREATE, "fp-" + canned(RELATED)["alerts"][3]["fingerprint"]]
"""The Match's labels once the related Alert joined: all four Alerts."""


def test_the_closing_comment_counts_the_alerts_and_the_runs_this_one_included(tmp_path):
    lines = printed(close_argv(EVERY_LABEL, runs=3), run_directory(tmp_path, canned(RESOLVED)))

    [comment] = commands(lines)
    assert "# No label to add" in lines[0]
    assert argument(comment, "-b") == (
        "Resolved after 4m30s: every Alert in checkout-outage is resolved (4 Alerts, 4 Runs). "
        "Completed automatically from the Grafana Notification."
    )
    assert lines[-4:] == [f"# {label} resolved" for label in EVERY_LABEL[2:]]


def test_a_close_adds_the_label_of_an_alert_the_incident_never_saw_and_counts_it(tmp_path):
    lines = printed(close_argv(AFTER_CREATE, runs=2), run_directory(tmp_path, canned(RESOLVED)))

    add, comment = commands(lines)
    assert add.endswith(f'\'update.labels=[{{"add":"{EVERY_LABEL[-1]}"}}]\'')
    assert "(4 Alerts, 3 Runs)" in argument(comment, "-b")


def test_the_closing_comment_names_the_project_s_own_done_status(tmp_path):
    project = replace(CONFIGURED, status_done="Resolved")

    lines = printed(
        close_argv(EVERY_LABEL), run_directory(tmp_path, canned(RESOLVED), project=project)
    )

    assert argument(commands(lines)[0], "-b").endswith(
        "Resolved automatically from the Grafana Notification."
    )


def test_a_human_owned_match_is_told_its_status_was_left_to_the_human(tmp_path):
    lines = printed(
        close_argv(EVERY_LABEL, 3, "--leave-status"), run_directory(tmp_path, canned(RESOLVED))
    )

    [comment] = commands(lines)
    assert argument(comment, "-b") == (
        "Resolved after 4m30s: every Alert in checkout-outage is resolved (4 Alerts, 4 Runs). "
        "The status was left to the human."
    )


def test_a_close_while_an_alert_still_fires_is_refused_as_an_update(tmp_path):
    with pytest.raises(PayloadError, match="that is an update"):
        printed(close_argv(AFTER_CREATE), run_directory(tmp_path, canned(RELATED)))


@pytest.mark.parametrize("runs", ["-1", "three", ""])
def test_a_run_count_that_is_not_one_is_refused(tmp_path, runs):
    argv = close_argv(EVERY_LABEL)
    argv[argv.index("--runs") + 1] = runs

    with pytest.raises(PayloadError, match="--runs"):
        printed(argv, run_directory(tmp_path, canned(RESOLVED)))


# --- Every printed command is one line the permission boundary admits ---


def every_step(tmp_path, notification: dict) -> list[str]:
    """Every line every step prints for one Notification, as far as each step accepts it."""
    working = run_directory(tmp_path, notification)
    lines = []
    for argv in (
        ["match"],
        ["create"],
        update_argv([GROUP_LABEL, SESSION]),
        close_argv([GROUP_LABEL, SESSION]),
    ):
        try:
            lines += printed(argv, working)
        except PayloadError:
            continue
    return lines


@pytest.mark.parametrize(
    "notification",
    [canned(FIRING), canned(RELATED), canned(RESOLVED), hostile()],
    ids=["firing", "related", "resolved", "hostile"],
)
def test_every_printed_command_is_one_line_with_no_escape_the_boundary_refuses(
    tmp_path, notification
):
    lines = every_step(tmp_path, notification)

    assert commands(lines)
    for line in lines:
        assert "\n" not in line and "\r" not in line
        if line.startswith("#"):
            continue
        assert line.startswith("jira-as ")
        assert "'\\''" not in line and "$'" not in line and "\\" not in line
        assert line.count("'") % 2 == 0, "an unbalanced quote would run on to the next line"
        assert shlex.split(line)[0] == "jira-as"


def test_alert_text_reaches_jira_as_look_alikes_rather_than_escapes(tmp_path):
    [_, create, comment] = created(tmp_path, hostile())

    [first, _] = json.loads(argument(create, "--description"))["content"][1]["content"]
    text = first["content"][0]["content"][0]["text"]
    assert text.startswith("O’Brien’s ”probe” on host (eu-1): it’s ”down” (again) see C:⧵logs")
    assert "cost ˋ＄5ˋ & ＄’x’ — naïve 日本 🚨 end." in text
    assert text.endswith(HOSTILE_URL)
    assert "O’Brien’s ”probe” value=0" in argument(comment, "-b")


PLAIN_CASES = [
    ("it's", "it’s"),
    ('say "x"', "say ”x”"),
    ("a\\b", "a⧵b"),
    ("`id` $HOME $'x'", "ˋidˋ ＄HOME ＄’x’"),
    ("one\ntwo\r\nthree\tfour", "one two three four"),
    ("left\u2028right\u2029end", "left right end"),
    ("bell\x07 null\x00 del\x7f", "bell null del"),
    ("\u202eevil", "evil"),
    ("lone \ud800 surrogate", "lone \ufffd surrogate"),
    ("  padded  ", "padded"),
    ("(a)?&=b 日本 🚨", "(a)?&=b 日本 🚨"),
]
"""Text as an Alert can hold it, and what `plain` makes of it."""


@pytest.mark.parametrize(("raw", "safe"), PLAIN_CASES)
def test_plain_text_needs_no_escape_in_single_quotes_or_json(raw, safe):
    made = plain(raw)

    assert made == safe
    assert json.dumps(made, ensure_ascii=False) == f'"{made}"'


@pytest.mark.parametrize("raw", [raw for raw, _ in PLAIN_CASES])
def test_plain_is_idempotent_so_verification_may_apply_it_to_text_that_already_went_through(raw):
    assert plain(plain(raw)) == plain(raw)


def test_the_look_alike_table_is_the_content_contract_verification_reads():
    """`verify_content` compares an Alert's text with `plain(text)` and spells this table for
    it, so the five pairs may not change without it. A `"` in an alertname becomes `”` in the
    Description, and a check that looks for the `"` would call a correct Incident missing it."""
    table = {chr(code): look_alike for code, look_alike in incident_payload.LOOK_ALIKES.items()}

    assert table == {
        "'": "\u2019",
        '"': "\u201d",
        "\\": "\u29f5",
        "`": "\u02cb",
        "$": "\uff04",
    }
    assert plain('Disk "data" full') == "Disk \u201ddata\u201d full"


# --- What it reads, and how it refuses ---


@pytest.mark.parametrize(
    "notification",
    [canned(FIRING), canned(RELATED), hostile()],
    ids=["firing", "related", "hostile"],
)
def test_a_notification_from_the_receiver_reads_back_as_the_same_group(tmp_path, notification):
    working = run_directory(tmp_path, notification)

    group = read_group(working / NOTIFICATION_FILENAME)

    assert [alert.fingerprint for alert in group.alerts] == [
        alert["fingerprint"] for alert in notification["alerts"]
    ]


def test_the_facts_are_read_from_the_skill_the_receiver_rendered(tmp_path):
    working = run_directory(tmp_path, canned(FIRING), replace(CONFIGURED, key="OTHER"))

    [search] = commands(printed(["match"], working))

    assert (working.parent / RENDERED_SKILL / FACTS_FILE).is_file()
    assert search.startswith("jira-as search jql 'project = OTHER AND ")


def refusal(capsys, argv: list[str], working: Path) -> str:
    """The one line `main` refuses with, after checking it said nothing else."""
    assert main(argv, working) == 2
    out, err = capsys.readouterr()
    assert out == ""
    [line] = err.splitlines()
    assert line.startswith("incident-payload: error: ")
    return line


def test_a_run_directory_without_a_notification_is_refused_in_one_line(tmp_path, capsys):
    working = run_directory(tmp_path, canned(FIRING))
    (working / NOTIFICATION_FILENAME).unlink()

    assert f"no {NOTIFICATION_FILENAME}" in refusal(capsys, ["create"], working)


def test_a_directory_with_no_rendered_skill_beside_it_is_refused_in_one_line(tmp_path, capsys):
    working = tmp_path / "somewhere"
    working.mkdir()
    (working / NOTIFICATION_FILENAME).write_text(json.dumps(canned(FIRING)))

    assert "no project facts" in refusal(capsys, ["match"], working)


@pytest.mark.parametrize(
    ("body", "said"),
    [
        ("{not json", "cannot be read as JSON"),
        ("[]", "is not a JSON object"),
        ('{"alerts": []}', "has no alerts"),
        ('{"alerts": ["x"]}', "alert 0 is not a JSON object"),
        (json.dumps(notification_of(alert("NOT-HEX"))), "fingerprint is not lower-case hex"),
        (json.dumps(notification_of(alert("aa01", status="pending"))), "neither firing"),
        (json.dumps({"alerts": [alert("aa01")]}), "no groupLabels.incident_group"),
        (
            json.dumps({**notification_of(alert("aa01")), "groupLabels": {"incident_group": "!"}}),
            "leaves nothing for the grp- label",
        ),
    ],
)
def test_a_notification_a_payload_does_not_fit_is_refused_in_one_line(tmp_path, capsys, body, said):
    working = run_directory(tmp_path, canned(FIRING))
    (working / NOTIFICATION_FILENAME).write_text(body)

    assert said in refusal(capsys, ["create"], working)


@pytest.mark.parametrize(
    ("facts", "said"),
    [
        ("not json", "not JSON"),
        ('{"project": "sandbox"}', "project is not one"),
        (
            (
                '{"project": "SANDBOX", "session_label": "ses-x", "severity_field": "Severity", '
                '"status_done": "Completed"}'
            ),
            "severity_field is not a custom field id",
        ),
        ('{"project": "SANDBOX", "session_label": "ses-x"}', "status_done is not a status"),
    ],
)
def test_facts_that_are_not_the_receiver_s_are_refused_in_one_line(tmp_path, capsys, facts, said):
    working = tmp_path / "runs" / "r1"
    working.mkdir(parents=True)
    (working / NOTIFICATION_FILENAME).write_text(json.dumps(canned(FIRING)))
    (tmp_path / "runs" / RENDERED_SKILL).mkdir()
    (tmp_path / "runs" / RENDERED_SKILL / FACTS_FILE).write_text(facts)

    assert said in refusal(capsys, ["match"], working)


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        ([], "required"),
        (["delete"], "invalid choice"),
        (["create", "/etc/passwd"], "unrecognized arguments"),
        (["update", "--key", "SANDBOX-7"], "required"),
        (["create", "--description", "Test"], "unrecognized arguments"),
    ],
)
def test_a_bad_argument_is_refused_in_one_line_and_no_path_is_ever_read(
    tmp_path, capsys, argv, said
):
    working = run_directory(tmp_path, canned(FIRING))

    assert said in refusal(capsys, argv, working)


def test_help_reads_no_file_and_names_every_step(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exited:
        main(["--help"])

    assert exited.value.code == 0
    out = capsys.readouterr().out
    for step in ("match", "create", "update", "close"):
        assert step in out


def test_main_prints_the_lines_and_succeeds(tmp_path, capsys):
    working = run_directory(tmp_path, canned(FIRING))

    assert main(["match"], working) == 0

    assert capsys.readouterr().out.splitlines() == printed(["match"], working)


def test_the_shapes_it_checks_are_the_ones_demo_config_holds_the_env_to():
    """It cannot import `demo_config`, which imports the Forwarder and the spawner and would put
    both inside every Run's tool, so its copies are pinned equal here. A shape the two disagree
    on would let `materialize` write a `project.json` every Run's `incident-payload` refuses."""
    assert incident_payload.PROJECT_KEY.pattern == demo_config.PROJECT_KEY.pattern
    assert incident_payload.FIELD_ID.pattern == demo_config.FIELD_ID.pattern
    assert incident_payload.SESSION_LABEL.pattern == (
        demo_config.SESSION_LABEL_PREFIX + demo_config.SESSION_ID.pattern
    )


def test_it_imports_nothing_that_could_reach_out():
    """Pure and local: no socket, no process, no environment, no file written. Its imports are
    the standard library's parsing and data modules and two of this package's constants."""
    tree = ast.parse(Path(incident_payload.__file__).read_text())
    imported = set()
    named = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
        elif isinstance(node, ast.Attribute):
            named.add(node.attr)
        elif isinstance(node, ast.Name):
            named.add(node.id)

    assert imported == {
        "__future__",
        "argparse",
        "json",
        "decimal",
        "urllib.parse",
        "grafana_jsm_sandbox.investigation_contract",
        "grafana_jsm_sandbox.loki_evidence",
        "grafana_jsm_sandbox.tempo_evidence",
        "re",
        "shlex",
        "sys",
        "unicodedata",
        "collections.abc",
        "dataclasses",
        "datetime",
        "pathlib",
        "grafana_jsm_sandbox.notification",
        "grafana_jsm_sandbox.run_command",
    }
    reaching = {"open", "write_text", "write_bytes", "mkdir", "unlink", "environ", "getenv"}
    assert named & reaching == set()


# --- The printed create, through the real jira-as's offline dry run ---


def jira_as() -> str:
    """The real CLI beside this Python, or on PATH, or a skip that says how to get it."""
    beside = Path(sys.executable).parent / "jira-as"
    found = str(beside) if beside.is_file() else shutil.which("jira-as")
    if found is None:
        pytest.skip("jira-as is not on PATH (pip install jira-as==2.0.0); no dry run was made")
    return found


def dry_run(command: str, home: Path) -> dict:
    """The printed dry run, run as printed, with an environment that reaches no site.

    `--dry-run` builds the payload and prints it without sending anything; the site is
    `example.invalid` all the same, and the project allow list is the demo's.
    """
    executable = jira_as()
    words = shlex.split(command)
    assert words[0] == "jira-as" and words[-3:] == ["--dry-run", "-o", "json"]
    answer = subprocess.run(
        [executable, *words[1:]],
        env={
            "HOME": str(home),
            "JIRA_ALLOWED_PROJECTS": "SANDBOX",
            "JIRA_SITE_URL": "https://example.invalid",
            "PATH": f"{Path(executable).parent}{os.pathsep}/usr/bin{os.pathsep}/bin",
        },
        cwd=home,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert answer.returncode == 0, answer.stderr
    payload = json.loads(answer.stdout)
    assert payload["dry_run"] is True
    return payload["fields"]


@pytest.mark.parametrize("project", [CONFIGURED, BARE], ids=["every field", "no field"])
@pytest.mark.parametrize(
    "notification",
    [canned(FIRING), canned(RELATED), hostile()],
    ids=["firing", "related", "hostile"],
)
def test_the_printed_create_is_the_payload_jira_as_would_send(tmp_path, project, notification):
    """The exact printed line, through jira-as 2.0.0's own parsing of every argument."""
    working = run_directory(tmp_path, notification, project)
    [dry, create, _] = commands(printed(["create", "--component", "rolldice"], working))
    home = tmp_path / "home"
    home.mkdir()

    fields = dry_run(dry, home)

    group = read_group(working / NOTIFICATION_FILENAME)
    assert fields["description"] == incident_payload.description(group)
    assert fields["summary"] == argument(create, "-s")
    assert fields["labels"] == argument(create, "--labels").split(",")
    assert fields["components"] == [{"name": "rolldice"}]
    assert fields["project"] == {"key": "SANDBOX"} and fields["issuetype"] == {"name": "Incident"}
    custom = {name: value for name, value in fields.items() if name.startswith("customfield_")}
    assert set(fields) - set(custom) == {
        "project",
        "issuetype",
        "summary",
        "description",
        "labels",
        "components",
    }
    configured = {project.severity_field, project.urgency_field, project.source_field} - {None}
    assert set(custom) == configured


@pytest.mark.parametrize(
    "notification",
    [canned(FIRING), canned(RELATED), hostile()],
    ids=["firing", "related", "hostile"],
)
def test_the_printed_create_carries_the_content_the_forwarder_asks_of_a_first_create(
    tmp_path, notification, monkeypatch
):
    """The Forwarder forwards a Run's one create only if its judged fields equal the registered
    content (ADR 0002, 2026-10-01). The body is what jira-as's dry run prints
    as `fields`, so a tool that stopped printing a create the Forwarder admits fails here, on
    the tree that holds both. A tree without the Forwarder's check has nothing to compare."""
    forwarder = importlib.import_module("grafana_jsm_sandbox.forwarder")
    missing = getattr(forwarder, "missing_from_incident", None)
    if missing is None:
        pytest.skip("the Forwarder in this tree does not read a create's content")
    [dry, _, _] = commands(printed(["create"], run_directory(tmp_path, notification)))
    home = tmp_path / "home"
    home.mkdir()

    fields = dry_run(dry, home)

    expected = incident_payload.create_fields(
        incident_payload.group_from_notification(notification),
        incident_payload.read_facts(tmp_path / "runs" / RENDERED_SKILL / FACTS_FILE),
    )
    body = json.dumps({"fields": fields}).encode()
    assert missing(body, expected) is None
    monkeypatch.setattr(forwarder, "ThreadingHTTPServer", lambda *args: None)
    gate = forwarder.Forwarder(forwarder.JiraCredential("https://example.invalid", "run", "token"))
    sent = []
    monkeypatch.setattr(gate, "_send_upstream", lambda *args: (sent.append(args) or (201, {}, b"{}")))
    gate.set_sentinel("sentinel", expected)
    from email.message import Message

    from tests.conftest import basic_auth_header
    headers = Message()
    headers["Authorization"] = basic_auth_header("run", "sentinel")
    assert gate.handle("POST", "/rest/api/3/issue", headers, body)[0] == 201
    assert sent[0][3] == body
    assert gate.handle("POST", "/rest/api/3/issue", headers, body)[0] == 409
    assert len(sent) == 1


# --- Investigation evidence is mechanical, judgments stay with the Run ---


def evidence_record(command="range", status="ok", value="0", error=None, query=None):
    from urllib.parse import quote

    if query is None:
        query = r'''sum(rate(metric_count{service_name="rolldice",path=~"a\\b.*",tag="$'`{}"}[5m]))'''
    start, end = "2026-10-01T14:00:00.000Z", "2026-10-01T14:10:00.000Z"
    if command == "instant":
        end = start
    panes = {"A": {"datasource": "prometheus", "queries": [{"refId": "A", "expr": query,
             "instant": command == "instant", "range": command == "range"}],
             "range": {"from": "1790863200000", "to": "1790863800000"}}}
    return {
        "schema_version": 1, "command": command,
        "query": None if command == "get" else query, "datasource": "prometheus",
        "path": {"get": "/api/v1/labels", "instant": "/api/v1/query",
                 "range": "/api/v1/query_range"}[command],
        "parameters": ([["match[]", query]] if command == "get" else
                       [["query", query], ["time", "1790863200"]] if command == "instant" else
                       [["query", query], ["start", "1790863200"], ["end", "1790863800"],
                        ["step", "10"]]),
        "window": {"start": None if command == "get" else start,
                   "end": None if command == "get" else end,
                   "step_seconds": 10 if command == "range" else None},
        "retrieved_at": end, "status": status, "error": error,
        "sample_summary": {
            "result_type": None if status == "unavailable" else "vector",
            "series_count": 1 if status == "ok" else 0,
            "sample_count": 1 if status == "ok" else 0,
            "unmodelled_count": 0, "discovery_items": None,
            "series": [{"labels": {"service_name": "rolldice"}, "count": 1,
                        "latest": {"timestamp": 1790863800, "value": value},
                        "min": value if value == "0" or value == "2" else None,
                        "max": value if value == "0" or value == "2" else None}] if status == "ok" else [],
        },
        "presenter_link": "http://localhost:3000/explore?schemaVersion=1&panes=" + quote(
            json.dumps(panes, separators=(",", ":")), safe=""),
        "response": None if status == "unavailable" else {
            "status": "success", "data": {"resultType": "vector", "result": [
                {"metric": {"service_name": "rolldice"}, "value": [1790863800, value]}
            ] if status == "ok" else []}},
    }


def investigation_argv():
    return ["investigate", "--key", "SANDBOX-7", "--observation", "zero 'requests'\nseen",
            "--interpretation", 'uncertain "$why"', "--unknown", "check `traffic`\\source"]


def investigate_on(tmp_path, records):
    from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME

    working = run_directory(tmp_path, canned(FIRING))
    if records is not None:
        (working / EVIDENCE_FILENAME).write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    [command] = printed(investigation_argv(), working)
    return command, working


def investigation_body(command):
    adf = json.loads(argument(command, "-b"))
    return "".join(node["text"] for node in adf["content"][0]["content"])


@pytest.mark.parametrize("query", [
    'http_server_duration_milliseconds_count{service_name="rolldice"}',
    r'''sum(rate(metric_count{service_name="rolldice",path=~"a\\b.*",tag="$'`{}"}[5m]))''',
])
def test_investigation_punctuation_link_and_real_jira_conversion(tmp_path, query):
    from urllib.parse import parse_qs, urlsplit

    jira_as = pytest.importorskip("jira_as")
    from as_engine.index import ProductIndexes
    from as_engine.surface import Surface
    from as_engine.transport import Response
    from jira_as.compat.client import GenericClient
    from jira_as.compat.implementations import _add_comment_impl
    from jira_as.compat.richtext import richtext

    from grafana_jsm_sandbox.investigation_contract import INVESTIGATION_MARKER

    record = evidence_record(query=query)
    command, working = investigate_on(tmp_path, [record])
    assert "\\" not in command and "\n" not in command and "$'" not in command
    assert shlex.split(command)[:5] == ["jira-as", "collaborate", "comment", "add", "SANDBOX-7"]
    assert argument(command, "--format") == "adf"
    body = argument(command, "-b")
    assert body == json.dumps(json.loads(body), ensure_ascii=False, separators=(",", ":"))
    converted = richtext(body, "adf")
    captured = []

    class Capture:
        def call(self, operation, parameters, payload, **options):
            assert operation.operationId == "addComment"
            assert parameters["issueIdOrKey"] == "SANDBOX-7"
            captured.append(payload["body"])
            return Response(201, {"id": "1", "body": payload["body"]})

        def close(self):
            pass

    surface = Surface(ProductIndexes(Path(jira_as.__file__).parent / "_generated"),
                      lambda document, index: Capture())
    surface.scope_allowlist = ("SANDBOX",)
    client = GenericClient(surface=surface)
    _add_comment_impl("SANDBOX-7", body, body_format=argument(command, "--format"), client=client)
    [adf] = captured
    assert adf == converted
    assert adf["type"] == "doc" and adf["version"] == 1
    assert len(adf["content"]) == 1 and adf["content"][0]["type"] == "paragraph"
    nodes = adf["content"][0]["content"]
    assert nodes[0] == {"type": "text", "text": INVESTIGATION_MARKER}
    assert [node["text"] for node in nodes if node.get("marks") == [{"type": "strong"}]] == [
        "Observation:", "Interpretation:", "Unknown / next check:", "Evidence:"]
    assert [node["text"] for node in nodes if node.get("marks") == [{"type": "code"}]] == [
        plain(query)]
    rendered = "".join(node["text"] for node in nodes)
    assert rendered == (
        "[grafana-investigation] Observation: zero ’requests’ seen | Interpretation: "
        "uncertain ”＄why” | Unknown / next check: check ˋtrafficˋ⧵source | Evidence: "
        f"{plain(query)} (prometheus, 2026-10-01T14:00:00.000Z..2026-10-01T14:10:00.000Z, "
        "step 10s; retrieved 2026-10-01T14:10:00.000Z): observed zero Open in Grafana")
    links = [mark["attrs"]["href"] for node in nodes for mark in node.get("marks", [])
             if mark["type"] == "link"]
    assert links == [record["presenter_link"]]
    assert [node["text"] for node in nodes if any(
        mark["type"] == "link" for mark in node.get("marks", []))] == ["Open in Grafana"]
    panes = json.loads(parse_qs(urlsplit(links[0]).query)["panes"][0])
    assert panes["A"]["queries"][0]["expr"] == record["query"]
    assert json.loads((working / "grafana-evidence.jsonl").read_text()) == record


@pytest.mark.parametrize("status, expected", [("empty", "no data"), ("ok", "observed zero")])
def test_investigation_includes_success_and_failures_in_append_order(tmp_path, status, expected):
    failure = evidence_record(status="unavailable", error={
        "kind": "token_rejected", "message": "token rejected", "http_status": 401})
    success = evidence_record(status=status)
    command, _ = investigate_on(tmp_path, [failure, success])
    body = investigation_body(command)
    assert "Observation: zero ’requests’ seen" in body
    assert body.index("unavailable: token rejected") < body.index(expected)
    assert " ; " in body and body.count("Open in Grafana") == 2


@pytest.mark.parametrize("records, reason", [
    (None, "no query evidence recorded"), ([], "no query evidence recorded"),
    ([{"schema_version": 1}], "evidence file unreadable"),
    ([evidence_record(), {"schema_version": 2}], "evidence file unreadable"),
])
def test_missing_empty_or_invalid_evidence_overrides_judgments(tmp_path, records, reason):
    command, _ = investigate_on(tmp_path, records)
    from jira_as.compat.richtext import richtext

    adf = richtext(argument(command, "-b"), "adf")
    nodes = adf["content"][0]["content"]
    assert nodes[0] == {"type": "text", "text": "[grafana-investigation] "}
    assert [node["text"] for node in nodes if node.get("marks") == [{"type": "strong"}]] == [
        "Observation:", "Interpretation:", "Unknown / next check:", "Evidence:"]
    assert all(mark["type"] == "strong" for node in nodes for mark in node.get("marks", []))
    assert investigation_body(command) == (
        "[grafana-investigation] Observation: Evidence unavailable | Interpretation: "
        "No conclusion from Grafana | Unknown / next check: check ˋtrafficˋ⧵source | "
        f"Evidence: unavailable: {reason}")


def test_all_failed_evidence_deduplicates_reasons_in_first_seen_order(tmp_path):
    records = [evidence_record(status="unavailable", error={
        "kind": "unreachable", "message": message, "http_status": None})
        for message in ["unreachable", "token rejected", "unreachable"]]
    command, _ = investigate_on(tmp_path, records)
    assert investigation_body(command).endswith("Evidence: unavailable: unreachable; token rejected")
    assert "observed zero" not in command


@pytest.mark.parametrize("raw", [b'{bad json}\n', b'\xff', b'\n', b'null\n'])
def test_unreadable_jsonl_is_unavailable_and_exits_zero(tmp_path, raw, capsys):
    from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME

    _, working = investigate_on(tmp_path, None)
    (working / EVIDENCE_FILENAME).write_bytes(raw)
    assert main(investigation_argv(), working) == 0
    output = capsys.readouterr()
    assert output.err == "" and output.out.count("\n") == 1
    assert "evidence file unreadable" in output.out


def test_unreadable_evidence_path_is_unavailable(tmp_path):
    _, working = investigate_on(tmp_path, None)
    (working / "grafana-evidence.jsonl").mkdir()
    assert "evidence file unreadable" in printed(investigation_argv(), working)[0]


@pytest.mark.parametrize("command", ["instant", "get"])
def test_investigation_instant_and_discovery_wording(tmp_path, command):
    record = evidence_record(command=command)
    if command == "get":
        record["sample_summary"].update(result_type="discovery", series_count=0,
                                        sample_count=0, series=[], discovery_items=3)
    line, _ = investigate_on(tmp_path, [record])
    body = investigation_body(line)
    assert "step " not in body
    if command == "instant":
        assert "at 2026-10-01T14:00:00.000Z; retrieved" in body
    else:
        assert "GET /api/v1/labels?match%5B%5D=" in body
        assert "discovery: 3 items" in body
        assert "prometheus; retrieved" in body


@pytest.mark.parametrize("value", ["2", "NaN", "+Inf"])
def test_nonzero_and_nonfinite_data_never_become_observed_zero(tmp_path, value):
    record = evidence_record(value=value)
    if value != "2":
        record["sample_summary"]["series"][0].update(min=None, max=None)
    record["presenter_link"] = None
    command, _ = investigate_on(tmp_path, [record])
    assert "observed zero" not in command
    assert f"latest {value} at " in command and "no link" in command
    from jira_as.compat.richtext import richtext

    nodes = richtext(argument(command, "-b"), "adf")["content"][0]["content"]
    assert nodes[-1] == {"type": "text", "text": "no link"}
    assert not any(mark["type"] == "link" for node in nodes for mark in node.get("marks", []))


def test_unmodelled_data_is_not_zero_or_absent(tmp_path):
    record = evidence_record()
    record["sample_summary"].update(unmodelled_count=1)
    command, _ = investigate_on(tmp_path, [record])
    assert "observed zero" not in command and "unmodelled samples=1" in command


@pytest.mark.parametrize("flag", ["--key", "--observation", "--interpretation", "--unknown"])
def test_investigation_requires_all_four_flags(tmp_path, flag, capsys):
    _, working = investigate_on(tmp_path, None)
    argv = investigation_argv()
    index = argv.index(flag)
    del argv[index:index + 2]
    assert main(argv, working) == 2
    assert capsys.readouterr().err.startswith("incident-payload: error:")


def test_investigation_rejects_wrong_project_key(tmp_path, capsys):
    _, working = investigate_on(tmp_path, None)
    argv = investigation_argv()
    argv[2] = "OTHER-7"
    assert main(argv, working) == 2
    assert "not an issue of SANDBOX" in capsys.readouterr().err


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("command", "write"),
    ("query", None), ("datasource", 3), ("parameters", [["a"]]),
    ("window", {"start": None, "end": None, "step_seconds": None}),
    ("retrieved_at", "not a time"), ("status", "zero"),
    ("error", {"kind": "timeout", "message": "timeout after 10s", "http_status": None}),
    ("sample_summary", {"series": []}), ("presenter_link", "https://example.test/a b"),
])
def test_invalid_schema_invalidates_even_an_earlier_success(tmp_path, field, value):
    invalid = evidence_record()
    invalid[field] = value
    line, _ = investigate_on(tmp_path, [evidence_record(), invalid])
    assert "Evidence unavailable" in line and "evidence file unreadable" in line
    assert "observed zero" not in line


def test_mixed_nonfinite_and_zero_bounds_never_report_observed_zero(tmp_path):
    record = evidence_record()
    record["response"]["data"].update(resultType="matrix", result=[
        {"metric": {}, "values": [[1, "NaN"], [2, "0"]]}])
    record["sample_summary"].update(sample_count=2, result_type="matrix")
    record["sample_summary"]["series"][0]["count"] = 2
    line, _ = investigate_on(tmp_path, [record])
    assert "observed zero" not in line and "2 samples" in line


@pytest.mark.parametrize("kind", ["scalar", "string"])
def test_a_scalar_zero_is_an_observed_sample(tmp_path, kind):
    record = evidence_record()
    record["response"]["data"].update(resultType=kind, result=[1790863800, "0"])
    record["sample_summary"]["result_type"] = kind
    line, _ = investigate_on(tmp_path, [record])
    assert "observed zero" in line


def test_all_series_contribute_to_zero_classification_and_first_series_display(tmp_path):
    record = evidence_record(value="2")
    summary = record["sample_summary"]
    summary.update(series_count=2, sample_count=2)
    summary["series"].append({"labels": {}, "count": 1, "latest": {"timestamp": 1, "value": "0"},
                              "min": "0", "max": "0"})
    record["response"]["data"]["result"].append({"metric": {}, "value": [1, "0"]})
    line, _ = investigate_on(tmp_path, [record])
    assert "2 series, 2 samples; latest 2 at " in line
    assert "; min 2, max 2; +1 more series" in line and "observed zero" not in line


def test_investigation_still_validates_notification_and_facts(tmp_path, capsys):
    _, working = investigate_on(tmp_path, None)
    (working / NOTIFICATION_FILENAME).write_text('{}')
    assert main(investigation_argv(), working) == 2
    assert "has no alerts" in capsys.readouterr().err
    (working / NOTIFICATION_FILENAME).write_text(json.dumps(canned(FIRING)))
    facts_path = working.parent / RENDERED_SKILL / FACTS_FILE
    facts_path.chmod(0o600)
    facts_path.write_text('{}')
    assert main(investigation_argv(), working) == 2
    assert "project facts" in capsys.readouterr().err


def test_close_help_names_prior_lifecycle_comments(capsys):
    with pytest.raises(SystemExit) as exit:
        main(["close", "--help"])
    assert exit.value.code == 0
    assert "prior lifecycle comments" in capsys.readouterr().out
