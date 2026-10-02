"""`incident-payload`: the Jira commands a Run would otherwise build by hand.

A Run keeps every judgment the Skill asks of it: whether the Notification has a
Match, and whether to create, update, close or skip. This command does the
mechanical part of each step, the part a cheaper model got wrong in the
2026-10-01 rehearsals, where Haiku wrote six malformed creates and left an
Incident whose Description was `Test`: the summary, the labels, the fields, the
ADF Description, the comment text, which Alerts are new, repeat or resolved, and
how long the Incident has been open. It prints `jira-as` command lines, and the
Run runs them as printed.

    incident-payload investigate --key KEY --observation TEXT --interpretation TEXT --unknown TEXT
    incident-payload match
    incident-payload create [--component NAME]
    incident-payload update --key KEY --labels LABELS --created TIME --server-time TIME
    incident-payload close --key KEY --labels LABELS --created TIME --server-time TIME
        --runs N [--leave-status]

Investigation also reads `grafana-evidence.jsonl` in the working directory and adds
readable ADF evidence with presenter links to three judgments supplied by the Run.

It is local. Lifecycle steps read two files at fixed places, and no path named on its
command line: `notification.json` in the working directory, which is the Run's
Notification, and `project.json` in the Skill the Receiver rendered for this
start, `<runs directory>/.skill`, which is the working directory's parent's. That
file holds the project facts the Skill already shows a Run: the key, the session
label, the field ids and the done status (`skill_template.materialize` writes it).
It opens no socket, starts no process and reads no environment variable, so it
holds nothing a Run does not and cannot reach Jira. Lifecycle steps write no
files. Investigation publishes one private ADF artifact under the Run's working
directory, accepting no output path, then prints a short Jira body-file command.

Every command it prints is one line. Lifecycle text arguments use plain single
quotes and contain no backslashes. Investigation commands contain a safe basename;
the UTF-8 JSON artifact preserves evidence punctuation and line breaks. Hidden
controls and literal Unicode escape notation have disclosed printable displays;
the original evidence file stays unchanged.
Alert text is made safe first (`plain`). Lines that
start with `#` say what the next command does and are not commands; a literal
`<key>` stands where the Incident's key is not known yet.

`plain` is part of what verification reads. Every Alert name, instance, summary and URL
reaches the Incident as `plain(text)`, so anything that looks for an Alert's text in the
Incident compares with `plain(text)`, not `text` (`LOOK_ALIKES` is the whole table):

    '  ->  ’ (U+2019)        "  ->  ” (U+201D)        \\  ->  ⧵ (U+29F5)
    `  ->  ˋ (U+02CB)        $  ->  ＄ (U+FF04)

and every run of whitespace, a line break included, is one space, and a control or format
character is a space. `plain` is idempotent, so applying it to text that already went
through it changes nothing.

Bad input prints one line, `incident-payload: error: <why>`, and exits 2. The Skill
treats a lifecycle error as the end of the Run: it finishes `failed`, and never
builds the command by hand instead. An investigation error leaves a successful
lifecycle successful, with investigation unavailable in the Finish.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from grafana_jsm_sandbox.investigation_artifact import ArtifactError, publish_comment
from grafana_jsm_sandbox.investigation_contract import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    INVESTIGATION_MARKER,
)
from grafana_jsm_sandbox.loki_evidence import summarize_logs
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.run_command import RENDERED_SKILL
from grafana_jsm_sandbox.tempo_evidence import normalize_trace_id, summarize_search, summarize_trace

PROGRAM = "incident-payload"
"""The command's name on a Run's PATH, and the start of every line it prints on a failure."""

FACTS_FILE = "project.json"
"""Where in the rendered Skill directory the project's facts are, as `skill_template` writes
them for every start."""

EXIT_ERROR = 2
"""The exit status of any refusal: bad input, a missing file, an argument that is not one."""

ISSUE_TYPE = "Incident"

SOURCE = "Monitoring systems"
"""The one value the Source field takes for an Incident a Run creates."""

SEVERITIES = (("critical", "Sev-1"), ("warning", "Sev-2"))
"""The worst firing Alert's `severity` label, mapped to Severity; anything else is `Sev-3`."""

LOWEST_SEVERITY = "Sev-3"

URGENCY = {"Sev-1": "Critical", "Sev-2": "High", "Sev-3": "Medium"}
"""Urgency follows Severity."""

GROUP_PREFIX = "grp-"
FINGERPRINT_PREFIX = "fp-"
"""The labels an Incident is keyed by, beside the session's (ADR 0004 and the MVP spec)."""

FINGERPRINT = re.compile(r"[0-9a-f]{1,64}")
"""Grafana's Fingerprint: lower-case hex. Anything else would make an `fp-` label Jira or the
Match search could refuse."""

PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
SESSION_LABEL = re.compile(r"ses-[a-z0-9-]{1,32}")
FIELD_ID = re.compile(r"customfield_[0-9]+")
"""The shapes `demo_config` already holds `.env` to. They are checked again here because each
is written unquoted into a command line or a JQL clause."""

NOT_IN_A_GROUP_LABEL = re.compile(r"[^a-z0-9-]+")
"""What the group label leaves out of `incident_group`: it is lower case and `[a-z0-9-]` only,
so every other run of characters becomes one `-`."""

JIRA_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})")
"""A Jira timestamp, `2026-10-01T14:02:10.123+0000`, as `created` and `serverTime` give it,
or the same with `Z` or `+00:00`. It must say its offset: Jira's always do."""

LOOK_ALIKES = str.maketrans({"'": "’", '"': "”", "\\": "⧵", "`": "ˋ", "$": "＄"})
"""What a character the permission boundary or the JSON would need escaped becomes in Alert
text. A `'` would end the single-quoted argument and a `"` or `\\` would need a backslash in
the JSON; a backtick or `$` is harmless in single quotes but is the kind of thing a command
check reads as a substitution, so it goes too.

The table is part of the content contract. `verify_content` in the verification lane
compares an Alert's text with `plain(text)` and spells this table for it, and a test there
pins the two equal once they are on one tree; the test of this module pins the table."""

SUMMARY_LIMIT = 255
"""Jira's longest summary."""


class PayloadError(ValueError):
    """The input cannot become a payload, and says why in one line."""


@dataclass(frozen=True)
class Facts:
    """The project's facts a payload needs, as the Receiver renders them beside the Skill.

    A field id that is None is a field the project lacks, which a create leaves off.
    """

    project: str
    session_label: str
    severity_field: str | None
    urgency_field: str | None
    source_field: str | None
    status_done: str

    def as_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Facts:
        """The facts in `text`, or a PayloadError naming what is wrong with them."""
        try:
            raw = json.loads(text)
        except ValueError as failure:
            raise PayloadError(f"the project facts are not JSON: {failure}") from None
        if not isinstance(raw, dict):
            raise PayloadError("the project facts are not a JSON object")
        values = {}
        for name, shape in (("project", PROJECT_KEY), ("session_label", SESSION_LABEL)):
            value = raw.get(name)
            if not isinstance(value, str) or not shape.fullmatch(value):
                raise PayloadError(f"the project facts' {name} is not one: {value!r}")
            values[name] = value
        for name in ("severity_field", "urgency_field", "source_field"):
            value = raw.get(name)
            if value is not None and (not isinstance(value, str) or not FIELD_ID.fullmatch(value)):
                raise PayloadError(f"the project facts' {name} is not a custom field id: {value!r}")
            values[name] = value
        status_done = raw.get("status_done")
        if not isinstance(status_done, str) or not plain(status_done):
            raise PayloadError(f"the project facts' status_done is not a status: {status_done!r}")
        return cls(**values, status_done=plain(status_done))


@dataclass(frozen=True)
class Alert:
    """One Alert of the Notification, as much of it as a payload says."""

    fingerprint: str
    firing: bool
    name: str
    instance: str
    summary: str
    value: str
    starts_at: str
    generator_url: str
    service: str
    severity: str

    @property
    def label(self) -> str:
        return f"{FINGERPRINT_PREFIX}{self.fingerprint}"

    def bullet(self) -> str:
        """The Description's line for this Alert."""
        where = f"{self.name} on {self.instance}" if self.instance else self.name
        what = f"{where}: {self.summary.rstrip('.')}." if self.summary else f"{where}."
        since = f", since {self.starts_at}" if self.starts_at else ""
        source = f" {self.generator_url}" if self.generator_url else ""
        return f"{what} value={self.value}{since}.{source}"


@dataclass(frozen=True)
class Group:
    """The Notification: one group of related Alerts, in the order Grafana listed them."""

    name: str
    alerts: tuple[Alert, ...]

    @property
    def label(self) -> str:
        slug = NOT_IN_A_GROUP_LABEL.sub("-", self.name.lower()).strip("-")
        return f"{GROUP_PREFIX}{slug}"

    @property
    def firing(self) -> tuple[Alert, ...]:
        return tuple(alert for alert in self.alerts if alert.firing)

    @property
    def fingerprint_labels(self) -> list[str]:
        """One `fp-` label per Alert, resolved ones included, each once."""
        return list(dict.fromkeys(alert.label for alert in self.alerts))

    @property
    def service(self) -> str:
        """The `service` label every firing Alert carries, or empty when they differ."""
        services = {alert.service for alert in self.firing}
        return services.pop() if len(services) == 1 else ""


def plain(text: str) -> str:
    """`text` as one line that is safe inside a single-quoted argument and a JSON string.

    Every run of whitespace, line breaks included, becomes one space; a control or
    format character becomes a space too; and the characters `LOOK_ALIKES` names
    become their look-alikes. Nothing that is left needs escaping in either.
    """
    kept = []
    for character in text:
        category = unicodedata.category(character)
        if category == "Cs":
            kept.append("\N{REPLACEMENT CHARACTER}")
        elif category in ("Cc", "Cf", "Zl", "Zp"):
            kept.append(" ")
        else:
            kept.append(character)
    return " ".join("".join(kept).split()).translate(LOOK_ALIKES)


def quoted(text: str) -> str:
    """One argument in plain single quotes, which `plain` has already made safe."""
    if "'" in text or "\\" in text or "\n" in text:
        raise PayloadError(f"internal: {text[:40]!r}… is not safe in single quotes")
    return f"'{text}'"


def value_of(alert: dict) -> str:
    """The Alert's `values.A`, as Grafana wrote it, or `unknown` when it has none."""
    values = alert.get("values")
    value = values.get("A") if isinstance(values, dict) else None
    if value is None:
        return "unknown"
    if isinstance(value, str):
        return plain(value) or "unknown"
    return plain(json.dumps(value))


def text_at(mapping: object, name: str) -> str:
    value = mapping.get(name) if isinstance(mapping, dict) else None
    return plain(value) if isinstance(value, str) else ""


def read_group(path: Path) -> Group:
    """The Notification at `path`, or a PayloadError saying why it is not one a payload fits."""
    try:
        notification = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PayloadError(
            f"there is no {NOTIFICATION_FILENAME} in {path.parent}: run {PROGRAM} in the "
            "Run's working directory"
        ) from None
    except (OSError, UnicodeDecodeError, ValueError) as failure:
        raise PayloadError(f"{NOTIFICATION_FILENAME} cannot be read as JSON: {failure}") from None
    return group_from_notification(notification)


def group_from_notification(notification: object) -> Group:
    """The payload facts of a Notification, without reading a file."""
    if not isinstance(notification, dict):
        raise PayloadError(f"{NOTIFICATION_FILENAME} is not a JSON object")
    raw_alerts = notification.get("alerts")
    if not isinstance(raw_alerts, list) or not raw_alerts:
        raise PayloadError(f"{NOTIFICATION_FILENAME} has no alerts")
    alerts = []
    for index, raw in enumerate(raw_alerts):
        if not isinstance(raw, dict):
            raise PayloadError(f"alert {index} is not a JSON object")
        fingerprint = raw.get("fingerprint")
        if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
            raise PayloadError(
                f"alert {index}'s fingerprint is not lower-case hex: {fingerprint!r}"
            )
        status = raw.get("status")
        if status not in ("firing", "resolved"):
            raise PayloadError(f"alert {index}'s status is neither firing nor resolved: {status!r}")
        labels = raw.get("labels")
        annotations = raw.get("annotations")
        alerts.append(
            Alert(
                fingerprint=fingerprint,
                firing=status == "firing",
                name=text_at(labels, "alertname") or f"{FINGERPRINT_PREFIX}{fingerprint}",
                instance=text_at(labels, "instance"),
                summary=text_at(annotations, "summary") or text_at(annotations, "description"),
                value=value_of(raw),
                starts_at=text_at(raw, "startsAt"),
                generator_url=text_at(raw, "generatorURL"),
                service=text_at(labels, "service"),
                severity=text_at(labels, "severity").lower(),
            )
        )
    name = text_at(notification.get("groupLabels"), "incident_group")
    if not name:
        raise PayloadError(f"{NOTIFICATION_FILENAME} has no groupLabels.incident_group")
    group = Group(name, tuple(alerts))
    if group.label == GROUP_PREFIX:
        raise PayloadError(f"the incident_group {name!r} leaves nothing for the grp- label")
    return group


def read_facts(path: Path) -> Facts:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PayloadError(
            f"there are no project facts at {path}: the Receiver renders them beside the Skill "
            f"at every start, and {PROGRAM} reads them from a Run's working directory"
        ) from None
    except (OSError, UnicodeDecodeError) as failure:
        raise PayloadError(f"the project facts at {path} cannot be read: {failure}") from None
    return Facts.from_json(text)


def jira_time(text: str, flag: str) -> datetime:
    """A Jira timestamp given as `flag`, or a PayloadError saying it is not one."""
    found = JIRA_TIME.fullmatch(text.strip())
    if found is None:
        raise PayloadError(
            f"{flag} is not a Jira timestamp like 2026-10-01T14:02:10.123+0000: {text!r}"
        )
    moment, fraction, offset = found.groups()
    fraction = f".{fraction[:6]:0<6}" if fraction else ""
    offset = "+00:00" if offset == "Z" else f"{offset[:3]}:{offset[-2:]}"
    try:
        return datetime.fromisoformat(moment + fraction + offset)
    except ValueError as failure:
        raise PayloadError(f"{flag} is not a time there ever was: {text!r} ({failure})") from None


def duration(created: str, server_time: str) -> str:
    """Jira's clock now minus the Incident's `created`, written like `4m30s`."""
    seconds = int(
        (jira_time(server_time, "--server-time") - jira_time(created, "--created")).total_seconds()
    )
    if seconds < 0:
        raise PayloadError(
            "--server-time is before --created: pass getServerInfo's serverTime and the "
            "Match's fields.created"
        )
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes}m{seconds}s"
    if minutes:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


def match_labels(text: str) -> list[str]:
    """The Match's labels, given comma-separated or as the JSON list jira-as printed."""
    text = text.strip()
    if text.startswith("["):
        try:
            labels = json.loads(text)
        except ValueError:
            raise PayloadError(f"--labels is not a JSON list of labels: {text!r}") from None
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
            raise PayloadError(f"--labels is not a list of labels: {text!r}")
    else:
        labels = text.split(",")
    return [label.strip().strip("\"'") for label in labels if label.strip().strip("\"'")]


# --- the commands ---


def match(group: Group, facts: Facts) -> list[str]:
    jql = (
        f"project = {facts.project} AND issuetype = {ISSUE_TYPE} AND "
        f'labels = "{group.label}" AND labels = "{facts.session_label}" '
        "AND statusCategory != Done"
    )
    return [
        "# The Match: the open Incident with this group's and this session's labels.",
        f"jira-as search jql {quoted(jql)} --fields key,status,labels,created -o json",
    ]


def description(group: Group) -> dict:
    """The Description, as ADF: a heading paragraph and one bullet per firing Alert."""
    firing = group.firing

    def paragraph(text: str) -> dict:
        return {"type": "paragraph", "content": [{"type": "text", "text": text}]}

    return {
        "type": "doc",
        "version": 1,
        "content": [
            paragraph(f"Partial Report: {len(firing)} alerts firing in group {group.name}."),
            {
                "type": "bulletList",
                "content": [
                    {"type": "listItem", "content": [paragraph(alert.bullet())]} for alert in firing
                ],
            },
        ],
    }


def summary(group: Group) -> str:
    text = f"{group.name}: {len(group.firing)} alerts firing"
    if group.service:
        text += f" on {group.service}"
    return text if len(text) <= SUMMARY_LIMIT else text[: SUMMARY_LIMIT - 1] + "…"


def severity(group: Group) -> str:
    """The worst firing Alert's: any `critical` is Sev-1, otherwise any `warning` Sev-2."""
    seen = {alert.severity for alert in group.firing}
    return next((sev for label, sev in SEVERITIES if label in seen), LOWEST_SEVERITY)


def custom_fields(group: Group, facts: Facts) -> dict:
    """Severity, Urgency and Source, each only where the project has the field."""
    chosen = severity(group)
    values = (
        (facts.severity_field, chosen),
        (facts.urgency_field, URGENCY[chosen]),
        (facts.source_field, SOURCE),
    )
    return {field: {"value": value} for field, value in values if field}


def compact(value: object) -> str:
    """JSON on one line, Unicode as itself, which `plain` text leaves needing no escape."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def create_fields(group: Group, facts: Facts) -> dict:
    """The create fields shared by the printed command and the Forwarder gate."""
    firing = group.firing
    if not firing:
        raise PayloadError(
            "no Alert in the Notification is firing: a resolved Notification with no Match is "
            "skipped, never created"
        )
    return {
        "summary": summary(group),
        "labels": [group.label, facts.session_label, *group.fingerprint_labels],
        "description": description(group),
    }


def create(group: Group, facts: Facts, component: str | None) -> list[str]:
    content = create_fields(group, facts)
    firing = group.firing
    if component is not None and (not group.service or component != group.service):
        raise PayloadError(
            f"--component {component!r} is not the service label every firing Alert carries "
            f"({group.service or 'they carry none in common'}): leave --component off"
        )
    words = [
        f"jira-as issue create -p {facts.project} -t {ISSUE_TYPE}",
        f"-s {quoted(content['summary'])}",
        f"--labels {quoted(','.join(content['labels']))}",
        f"--description {quoted(compact(content['description']))}",
    ]
    fields = custom_fields(group, facts)
    if fields:
        words.append(f"--custom-fields {quoted(compact(fields))}")
    if component is not None:
        words.append(f"--components {quoted(component)}")
    issue = " ".join(words)
    opened = "; ".join(f"{alert.name} value={alert.value}" for alert in firing)
    comment = f"Opened from {len(firing)} firing Alerts in {group.name}: {opened}."
    return [
        "# 1. The dry run: it sends nothing to Jira and prints the payload.",
        f"{issue} --dry-run -o json",
        "# 2. The create. Run it once; if it fails, finish failed and never run it again.",
        f"{issue} -o json",
        "# 3. The opening comment, with the new Incident's key in place of <key>.",
        f"jira-as collaborate comment add <key> -b {quoted(comment)}",
    ]


def labels_to_add(group: Group, key: str, labels: list[str]) -> tuple[list[str], list[str]]:
    """The `fp-` labels the Match lacks, and the lines that add them, or say none is needed."""
    missing = [label for label in group.fingerprint_labels if label not in labels]
    if not missing:
        return missing, ["# No label to add: the Incident carries every Alert's fp- label already."]
    adds = "update.labels=" + compact([{"add": label} for label in missing])
    return missing, [
        (
            f"# Add the {len(missing)} fp- label{'' if len(missing) == 1 else 's'} the Incident "
            "lacks. It prints null on success; do not re-check or retry it."
        ),
        f"jira-as api call editIssue --issue-id-or-key {key} --field {quoted(adds)}",
    ]


def sorted_alerts(group: Group, labels: list[str]) -> list[tuple[Alert, str]]:
    """Each Alert and what it is to the Match: `new`, `repeat` or `resolved`."""
    return [
        (
            alert,
            "resolved" if not alert.firing else "repeat" if alert.label in labels else "new",
        )
        for alert in group.alerts
    ]


def finish_lines(sorted_: list[tuple[Alert, str]], added: list[str]) -> list[str]:
    """What the Finish says this Run did: the labels it added, then each Alert and its kind."""
    return [
        f"# For the Finish: {len(added)} label{'' if len(added) == 1 else 's'} added. The Alerts:",
        *(f"# {alert.label} {kind}" for alert, kind in sorted_),
    ]


def update(group: Group, key: str, labels: list[str], open_for: str) -> list[str]:
    if not group.firing:
        raise PayloadError(
            "every Alert in the Notification is resolved: that is a close, not an update"
        )
    added, add_lines = labels_to_add(group, key, labels)
    sorted_ = sorted_alerts(group, labels)

    def listed(kind: str, with_label: bool = False, with_value: bool = True) -> str:
        named = [
            alert.name
            + (f" ({alert.label})" if with_label else "")
            + (f" value={alert.value}" if with_value else "")
            for alert, sorted_kind in sorted_
            if sorted_kind == kind
        ]
        return "; ".join(named) or "none"

    comment = (
        f"Update: {len(group.firing)} firing. New: {listed('new', with_label=True)}. "
        f"Repeat: {listed('repeat')}. Resolved: {listed('resolved', with_value=False)}. "
        f"Open for {open_for}."
    )
    return [
        *add_lines,
        "# The one update comment.",
        f"jira-as collaborate comment add {key} -b {quoted(comment)}",
        *finish_lines(sorted_, added),
    ]


def close(
    group: Group,
    facts: Facts,
    key: str,
    labels: list[str],
    open_for: str,
    runs: int,
    leave_status: bool,
) -> list[str]:
    if group.firing:
        raise PayloadError(
            f"{len(group.firing)} Alert{'' if len(group.firing) == 1 else 's'} in the "
            "Notification still fire: that is an update, not a close"
        )
    added, add_lines = labels_to_add(group, key, labels)
    seen = {label for label in labels if label.startswith(FINGERPRINT_PREFIX)} | set(added)
    ending = (
        "The status was left to the human."
        if leave_status
        else f"{facts.status_done} automatically from the Grafana Notification."
    )
    comment = (
        f"Resolved after {open_for}: every Alert in {group.name} is resolved "
        f"({len(seen)} Alerts, {runs + 1} Runs). {ending}"
    )
    return [
        *add_lines,
        "# The comment; then leave the status." if leave_status else "# The closing comment.",
        f"jira-as collaborate comment add {key} -b {quoted(comment)}",
        *finish_lines(sorted_alerts(group, labels), added),
    ]


# --- investigation evidence ---


def _evidence_record(record: object) -> dict:
    """Check schema v1 before any record contributes to a comment.

    A corrupt record invalidates the whole file, including an earlier success.
    These checks are format checks, not a query policy or a response-size cap.
    """
    def fields(value, shape):
        if not isinstance(value, dict):
            raise TypeError("not an object")
        for name, kinds in shape.items():
            if name not in value or type(value[name]) not in kinds:
                raise ValueError("missing or invalid field")
        return value

    string = (str,)
    nullable_string = (str, type(None))
    number = (int, float, Decimal)
    nullable_number = (*number, type(None))
    record = fields(record, {
        "schema_version": (int,), "command": string, "query": nullable_string,
        "datasource": string, "path": string, "parameters": (list,), "window": (dict,),
        "retrieved_at": string, "status": string, "error": (dict, type(None)),
        "sample_summary": (dict,), "presenter_link": nullable_string,
        "response": (dict, list, str, *number, bool, type(None)),
    })
    if (record["schema_version"] != EVIDENCE_SCHEMA_VERSION
            or record["command"] not in ("instant", "range", "get", "logs", "traces", "trace")
            or record["status"] not in ("ok", "empty", "unavailable")):
        raise ValueError("unknown schema, command or status")
    if (record["query"] is None) != (record["command"] == "get"):
        raise ValueError("query does not match command")
    for pair in record["parameters"]:
        if (not isinstance(pair, list) or len(pair) != 2
                or not all(isinstance(item, str) for item in pair)):
            raise ValueError("invalid parameter")
    window = fields(record["window"], {
        "start": nullable_string, "end": nullable_string, "step_seconds": nullable_number,
    })
    for value in (record["retrieved_at"], window["start"], window["end"]):
        if value is not None:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
                raise ValueError("invalid evidence time")
            datetime.fromisoformat(value)
    step = window["step_seconds"]
    if step is not None and (not Decimal(step).is_finite() or step <= 0):
        raise ValueError("invalid step")
    if record["command"] in ("instant", "range", "logs", "traces") and (
        window["start"] is None or window["end"] is None
    ):
        raise ValueError("query window missing")
    if record["command"] == "range" and step is None:
        raise ValueError("range step missing")
    error = record["error"]
    if (error is not None) != (record["status"] == "unavailable"):
        raise ValueError("error does not match status")
    if error is not None:
        fields(error, {"kind": string, "message": string, "http_status": (int, type(None))})
        if error["kind"] not in (
            "token_rejected", "http_error", "query_error", "timeout", "unreachable",
            "malformed_response",
        ):
            raise ValueError("unknown error kind")
    summary = fields(record["sample_summary"], {
        "result_type": nullable_string, "series_count": (int,), "sample_count": (int,),
        "unmodelled_count": (int,), "discovery_items": (int, type(None)), "series": (list,),
    })
    for name in ("series_count", "sample_count", "unmodelled_count", "discovery_items"):
        if summary[name] is not None and summary[name] < 0:
            raise ValueError("negative count")
    if summary["series_count"] != len(summary["series"]):
        raise ValueError("series count mismatch")
    if summary["result_type"] == "discovery" and summary["discovery_items"] is None:
        raise ValueError("discovery count missing")
    for series in summary["series"]:
        fields(series, {"labels": (dict,), "count": (int,), "latest": (dict, type(None)),
                        "min": nullable_string, "max": nullable_string})
        if series["count"] < 0 or not all(
            isinstance(value, str) for value in series["labels"].values()
        ):
            raise ValueError("invalid series")
        if series["latest"] is not None:
            fields(series["latest"], {"timestamp": number, "value": string})
            datetime.fromtimestamp(float(series["latest"]["timestamp"]), UTC)
    if record["command"] == "logs":
        fields(record, {"log_summary": (dict, type(None))})
        parameters = dict(record["parameters"])
        if (len(record["parameters"]) != 5
                or set(parameters) != {"query", "start", "end", "limit", "direction"}
                or parameters["query"] != record["query"]
                or parameters["start"] != window["start"]
                or parameters["end"] != window["end"]
                or parameters["direction"] not in ("forward", "backward")
                or not re.fullmatch(r"[0-9]+", parameters["limit"])
                or int(parameters["limit"]) <= 0
                or record["path"] != "/loki/api/v1/query_range"
                or step is not None
                or window["start"] > window["end"]):
            raise ValueError("inconsistent logs command or parameters")
        expected_sample = {"result_type": None if record["status"] == "unavailable" else "streams",
                           "series_count": 0, "sample_count": 0, "unmodelled_count": 0,
                           "discovery_items": None, "series": []}
        if summary != expected_sample:
            raise ValueError("logs must have an empty sample summary")
        if record["status"] == "unavailable":
            if record["log_summary"] is not None:
                raise ValueError("failed logs have a summary")
        else:
            log_summary = fields(record["log_summary"], {
                "stream_count": (int,), "entry_count": (int,), "limit_reached": (bool,),
                "excerpts": (list,),
            })
            for excerpt in log_summary["excerpts"]:
                fields(excerpt, {"timestamp_ns": string, "labels": (dict,), "metadata": (dict,),
                                 "line": string, "truncated": (bool,)})
            limit = int(parameters["limit"])
            expected = summarize_logs(record["response"], limit)
            if record["log_summary"] != expected:
                raise ValueError("log summary differs from response")
            if record["status"] != ("ok" if expected["entry_count"] else "empty"):
                raise ValueError("log status differs from returned entries")
    if record["command"] in ("traces", "trace"):
        fields(record, {"trace_summary": (dict, type(None))})
        if step is not None:
            raise ValueError("trace evidence has a step")
        if record["command"] == "traces":
            parameters = dict(record["parameters"])
            if (len(record["parameters"]) != 4
                    or set(parameters) != {"q", "start", "end", "limit"}
                    or parameters["q"] != record["query"]
                    or record["path"] != "/api/search"
                    or any(not re.fullmatch(r"[0-9]+", parameters[name])
                           for name in ("start", "end", "limit"))
                    or int(parameters["limit"]) <= 0):
                raise ValueError("inconsistent trace search command or parameters")
            start, end = int(parameters["start"]), int(parameters["end"])
            if not 0 <= start <= end < 2 ** 32:
                raise ValueError("invalid trace search bounds")
            for name, seconds in (("start", start), ("end", end)):
                expected_time = datetime.fromtimestamp(seconds, UTC).isoformat(
                    timespec="milliseconds").replace("+00:00", "Z")
                if window[name] != expected_time:
                    raise ValueError("trace search window differs from parameters")
        elif (normalize_trace_id(record["query"]) != record["query"]
              or record["path"] != "/api/v2/traces/" + record["query"]
              or record["parameters"] or window["start"] is not None
              or window["end"] is not None):
            raise ValueError("inconsistent trace ID lookup")
        expected_sample = {"result_type": (None if record["status"] == "unavailable"
                                           else record["command"]),
                           "series_count": 0, "sample_count": 0, "unmodelled_count": 0,
                           "discovery_items": None, "series": []}
        if summary != expected_sample:
            raise ValueError("traces must have an empty sample summary")
        if record["status"] == "unavailable":
            if record["trace_summary"] is not None:
                raise ValueError("failed traces have a summary")
        else:
            trace_summary = record["trace_summary"]
            if record["command"] == "traces":
                fields(trace_summary, {"kind": string, "trace_count": (int,),
                       "limit_reached": (bool,), "completed_jobs": (int, type(None)),
                       "total_jobs": (int, type(None)), "excerpts": (list,)})
                for excerpt in trace_summary["excerpts"]:
                    fields(excerpt, {"trace_id": string, "root_service": nullable_string,
                           "root_name": nullable_string, "start_time_ns": nullable_string,
                           "duration_ms": (int,)})
                expected = summarize_search(record["response"], int(parameters["limit"]))
                count = expected["trace_count"]
            else:
                fields(trace_summary, {"kind": string, "trace_id": string,
                       "backend_status": string, "backend_message": nullable_string,
                       "span_count": (int,), "services": (list,), "root_span_count": (int,),
                       "missing_parent_count": (int,), "start_time_ns": nullable_string,
                       "end_time_ns": nullable_string, "duration_ns": nullable_string,
                       "spans": (list,)})
                if not all(isinstance(service, str) for service in trace_summary["services"]):
                    raise ValueError("invalid trace services")
                for span in trace_summary["spans"]:
                    fields(span, {"span_id": string, "parent_span_id": nullable_string,
                           "service": nullable_string, "name": string, "kind": string,
                           "status": string, "start_time_ns": string, "end_time_ns": string,
                           "duration_ns": string})
                expected = summarize_trace(record["response"], record["query"])
                count = expected["span_count"]
            if trace_summary != expected:
                raise ValueError("trace summary differs from response")
            if record["status"] != ("ok" if count else "empty"):
                raise ValueError("trace status differs from returned evidence")
    link = record["presenter_link"]
    if link is not None:
        parsed = urlsplit(link)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or any(character in link for character in "'\\\n\r\t ()<>\"`$")):
            raise ValueError("invalid encoded presenter link")
    return record


def read_evidence(path: Path) -> tuple[list[dict], str | None]:
    """Every evidence record in append order, or the unavailable reason for the whole file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], "no query evidence recorded"
    except (OSError, UnicodeDecodeError):
        return [], "evidence file unreadable"
    if not text:
        return [], "no query evidence recorded"
    try:
        records = [_evidence_record(json.loads(line, parse_float=Decimal)) for line in text.splitlines()]
    except (ValueError, TypeError, OverflowError, OSError):
        return [], "evidence file unreadable"
    return records, None


def evidence_result(record: dict) -> str:
    """The summary in words, keeping unavailable, empty, zero and unmodelled data distinct."""
    if record["status"] == "unavailable":
        return "unavailable: " + plain(record["error"]["message"])
    if record["command"] == "logs":
        summary = record["log_summary"]
        words = f"{summary['entry_count']} returned log entries in {summary['stream_count']} streams"
        if summary["limit_reached"]:
            words += "; limit reached: possibly incomplete"
        if not summary["entry_count"]:
            words += "; no data returned"
        return words
    if record["command"] == "traces":
        trace = record["trace_summary"]
        words = f"{trace['trace_count']} returned traces"
        if trace["limit_reached"]:
            words += "; limit reached: possibly incomplete"
        if not trace["trace_count"]:
            words += "; no data returned"
        completed = trace["completed_jobs"] if trace["completed_jobs"] is not None else "unknown"
        total = trace["total_jobs"] if trace["total_jobs"] is not None else "unknown"
        return words + f"; jobs completed={completed} total={total}; telemetry completeness unknown"
    if record["command"] == "trace":
        trace = record["trace_summary"]
        words = (f"{trace['span_count']} observed spans; backend {trace['backend_status']}; "
                 f"{trace['root_span_count']} roots; {trace['missing_parent_count']} missing parents")
        if trace["duration_ns"] is not None:
            words += f"; observed envelope_ns={trace['duration_ns']} (max(end)-min(start))"
        else:
            words += "; no returned spans"
        return words
    if record["status"] == "empty":
        return "no data"
    summary = record["sample_summary"]
    if summary["result_type"] == "discovery":
        return f"discovery: {summary['discovery_items']} items"
    series = summary["series"]
    if _observed_zero(record):
        return "observed zero"
    words = f"{summary['series_count']} series, {summary['sample_count']} samples"
    if series:
        first = series[0]
        latest = first["latest"]
        if latest is not None:
            time = datetime.fromtimestamp(float(latest["timestamp"]), UTC).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")
            words += f"; latest {plain(latest['value'])} at {time}"
        words += f"; min {plain(first['min'] or 'none')}, max {plain(first['max'] or 'none')}"
        if len(series) > 1:
            words += f"; +{len(series) - 1} more series"
    if summary["unmodelled_count"]:
        words += f"; unmodelled samples={summary['unmodelled_count']}"
    return words


def _observed_zero(record: dict) -> bool:
    """Check actual samples: finite zero bounds alone can hide a nonfinite sample."""
    summary = record["sample_summary"]
    if summary["sample_count"] == 0 or summary["unmodelled_count"]:
        return False
    response = record["response"]
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, dict):
        return False
    result, kind = data.get("result"), data.get("resultType")
    samples = []
    if kind in ("scalar", "string"):
        samples = [result]
    elif kind in ("vector", "matrix") and isinstance(result, list):
        for series in result:
            if not isinstance(series, dict):
                return False
            if kind == "vector":
                samples.append(series.get("value"))
            else:
                values = series.get("values", [])
                if not isinstance(values, list):
                    return False
                samples.extend(values)
    if len(samples) != summary["sample_count"]:
        return False
    for sample in samples:
        if (not isinstance(sample, list) or len(sample) != 2
                or not isinstance(sample[1], str)):
            return False
        try:
            number = Decimal(sample[1])
            if not number.is_finite() or number != 0:
                return False
        except InvalidOperation:
            return False
    return bool(samples)


_UNICODE_ESCAPE_NOTATION = re.compile(r"\\u[0-9a-fA-F]{4}")


def _display_evidence_text(text: str) -> str:
    """Show controls, separators and Unicode-escape backslashes as [U+XXXX].

    JSON escaping alone is insufficient: an observed wire-to-tool-input
    normalization expanded escaped ESC before command validation. Printable
    notation has no escape sequence for that stage to expand. LF remains an
    ordinary evidence line break, preserved by the JSON argument.
    Conservatively show the backslash of literal Unicode escape notation too:
    its expansion under this replay is unsafe, although live normalization of
    double-escaped literals has not been confirmed. Other backslashes stay literal.
    """
    text = _UNICODE_ESCAPE_NOTATION.sub(lambda match: "[U+005C]" + match[0][1:], text)
    return "".join(
        f"[U+{ord(character):04X}]"
        if unicodedata.category(character) in ("Cc", "Zl", "Zp") and character != "\n"
        else character
        for character in text
    )


def _display_evidence_notices(*texts: str) -> list[dict]:
    """Disclose hidden-character display separately from printable escape notation."""
    notices = []
    if any(unicodedata.category(character) in ("Cc", "Zl", "Zp") and character != "\n"
           for text in texts for character in text):
        notices.append({"type": "text", "text": " [control characters shown as U+XXXX]"})
    if any(_UNICODE_ESCAPE_NOTATION.search(text) for text in texts):
        notices.append({"type": "text", "text": " [Unicode escape notation shown with U+005C]"})
    return notices


def evidence_display(record: dict) -> list[dict]:
    """ADF keeps log punctuation, discloses hidden controls and links to exact evidence."""
    query = record["query"]
    if query is None:
        parameters = urlencode([tuple(pair) for pair in record["parameters"]])
        query = f"GET {record['path']}" + (f"?{parameters}" if parameters else "")
    window = record["window"]
    context = plain(record["datasource"])
    if record["command"] == "instant":
        context += f", at {window['start']}"
    elif record["command"] == "trace":
        context += ", lookup by ID (no API time window)"
    elif window["start"] is not None or window["end"] is not None:
        context += f", {window['start'] or 'none'}..{window['end'] or 'none'}"
    if record["command"] == "range":
        context += f", step {Decimal(window['step_seconds']):g}s"
    context += f"; retrieved {record['retrieved_at']}"
    link = record["presenter_link"]
    destination = {"type": "text", "text": "no link"} if link is None else {
        "type": "text", "text": "Open in Grafana",
        "marks": [{"type": "link", "attrs": {"href": link}}],
    }
    display_query = _display_evidence_text(query)
    nodes = [
        {"type": "text", "text": display_query,
         "marks": [{"type": "code"}]},
        {"type": "text", "text": f" ({plain(context)}): {plain(evidence_result(record))} "},
        destination,
    ]
    if display_query != query:
        nodes[1:1] = _display_evidence_notices(query)
    if record["command"] == "logs" and record["log_summary"] is not None:
        for excerpt in record["log_summary"]["excerpts"]:
            line = _display_evidence_text(excerpt["line"])
            time = (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
                milliseconds=int(excerpt["timestamp_ns"]) // 1_000_000,
            )).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            labels = excerpt["labels"]
            severity = labels.get("severity_text", labels.get("detected_level", "").upper())
            display_severity = _display_evidence_text(severity)
            nodes.extend([
                {"type": "text", "text": f" | {time} "
                 + (f"{display_severity} " if display_severity else "")},
                ({"type": "text", "text": line, "marks": [{"type": "code"}]}
                 if line else {"type": "text", "text": "[empty log line]"}),
            ])
            if line != excerpt["line"] or display_severity != severity:
                nodes.extend(_display_evidence_notices(excerpt["line"], severity))
            if excerpt["truncated"]:
                nodes.append({"type": "text", "text": " [truncated to 600 characters]"})
    if record["command"] in ("traces", "trace") and record["trace_summary"] is not None:
        trace = record["trace_summary"]

        def literal_detail(text):
            displayed = _display_evidence_text(text)
            nodes.append({"type": "text", "text": displayed, "marks": [{"type": "code"}]})
            if displayed != text:
                nodes.extend(_display_evidence_notices(text))

        if record["command"] == "traces":
            for excerpt in trace["excerpts"]:
                literal_detail(
                    f" | trace_id={excerpt['trace_id']} "
                    f"root_service={excerpt['root_service'] if excerpt['root_service'] is not None else 'unknown'} "
                    f"root_name={excerpt['root_name'] if excerpt['root_name'] is not None else 'unknown'} "
                    f"start_time_ns={excerpt['start_time_ns'] or 'unknown'} "
                    f"duration_ms={excerpt['duration_ms']}")
        else:
            services = [_display_evidence_text(service) for service in trace["services"]]
            literal_detail(f" | trace_id={trace['trace_id']} services={compact(services)} "
                           f"start_time_ns={trace['start_time_ns'] or 'unknown'} "
                           f"end_time_ns={trace['end_time_ns'] or 'unknown'}")
            if services != trace["services"]:
                nodes.extend(_display_evidence_notices(*trace["services"]))
            if trace["backend_message"] is not None:
                literal_detail(f" | backend_message={trace['backend_message']}")
            for span in trace["spans"]:
                literal_detail(
                    f" | span_id={span['span_id']} parent_span_id={span['parent_span_id'] or 'root'} "
                    f"service={span['service'] if span['service'] is not None else 'unknown'} "
                    f"name={span['name']} kind={span['kind']} status={span['status']} "
                    f"start_time_ns={span['start_time_ns']} end_time_ns={span['end_time_ns']} "
                    f"duration_ns={span['duration_ns']}")
    return nodes


def investigate(key: str, observation: str, interpretation: str, unknown: str, path: Path) -> list[str]:
    records, reason = read_evidence(path)
    evidence = []
    if any(record["status"] in ("ok", "empty") for record in records):
        for record in records:
            if evidence:
                evidence.append({"type": "text", "text": " ; "})
            evidence.extend(evidence_display(record))
    else:
        observation, interpretation = "Evidence unavailable", "No conclusion from Grafana"
        reasons = dict.fromkeys(plain(record["error"]["message"]) for record in records)
        evidence = [{"type": "text", "text": "unavailable: " + (reason or "; ".join(reasons))}]
    nodes = [{"type": "text", "text": INVESTIGATION_MARKER}]
    for label, judgment in (
        ("Observation:", observation), ("Interpretation:", interpretation),
        ("Unknown / next check:", unknown),
    ):
        nodes.extend([
            {"type": "text", "text": label, "marks": [{"type": "strong"}]},
            {"type": "text", "text": f" {plain(judgment)} | "},
        ])
    nodes.extend([
        {"type": "text", "text": "Evidence:", "marks": [{"type": "strong"}]},
        {"type": "text", "text": " "},
        *evidence,
    ])
    comment = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": nodes}]}
    try:
        body = json.dumps(comment, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        name = publish_comment(body, path.parent)
    except (ArtifactError, UnicodeError) as failure:
        raise PayloadError(str(failure)) from None
    return [f"jira-as collaborate comment add {key} --body-file {name} --format adf"]


# --- the command line ---


class _Parser(argparse.ArgumentParser):
    """argparse, refusing in the one line every other refusal is, rather than with a usage."""

    def error(self, message: str):
        raise PayloadError(message)


def parser() -> argparse.ArgumentParser:
    commands = _Parser(
        prog=PROGRAM,
        description=(
            "Print the jira-as command lines for one step of the Skill, built from "
            f"{NOTIFICATION_FILENAME} in this directory and the project's facts. Run each "
            "printed line as written; lines starting # are not commands."
        ),
    )
    steps = commands.add_subparsers(dest="step", required=True, metavar="STEP")
    steps.add_parser("match", help="the Match search")
    creating = steps.add_parser(
        "create", help="the dry run, the one create and the opening comment"
    )
    creating.add_argument(
        "--component",
        help="the service label every firing Alert carries, only when a component of that "
        "exact name exists on the project",
    )
    for name, does in (
        ("update", "the label add and the one update comment"),
        ("close", "the label add and the closing comment"),
    ):
        step = steps.add_parser(name, help=does)
        step.add_argument("--key", required=True, help="the Match's key")
        step.add_argument(
            "--labels", required=True, help="the Match's fields.labels, comma-separated"
        )
        step.add_argument("--created", required=True, help="the Match's fields.created")
        step.add_argument("--server-time", required=True, help="getServerInfo's serverTime")
        if name == "close":
            step.add_argument(
                "--runs",
                required=True,
                type=int,
                help="prior lifecycle comments, the opening one included; the "
                "closing comment counts this Run as one more",
            )
            step.add_argument(
                "--leave-status",
                action="store_true",
                help="the Match is in a status a human owns: comment, and do not complete it",
            )
    investigation = steps.add_parser("investigate", help="one evidence-grounded investigation comment")
    for flag in ("key", "observation", "interpretation", "unknown"):
        investigation.add_argument(f"--{flag}", required=True)
    return commands


def printed(argv: Sequence[str], working_directory: Path) -> list[str]:
    """The lines `incident-payload <argv>` prints in `working_directory`, or a PayloadError."""
    arguments = parser().parse_args(list(argv))
    facts = read_facts(working_directory.parent / RENDERED_SKILL / FACTS_FILE)
    group = read_group(working_directory / NOTIFICATION_FILENAME)
    if arguments.step == "match":
        return match(group, facts)
    if arguments.step == "create":
        return create(group, facts, arguments.component)
    key = arguments.key.strip()
    if not re.fullmatch(rf"{facts.project}-[1-9][0-9]*", key):
        raise PayloadError(f"--key {key!r} is not an issue of {facts.project}")
    if arguments.step == "investigate":
        return investigate(key, arguments.observation, arguments.interpretation, arguments.unknown,
                           working_directory / EVIDENCE_FILENAME)
    labels = match_labels(arguments.labels)
    for needed in (group.label, facts.session_label):
        if needed not in labels:
            raise PayloadError(
                f"--labels lacks {needed}, so they are not this group's Match's labels: pass "
                "the Match's fields.labels as the search printed them"
            )
    open_for = duration(arguments.created, arguments.server_time)
    if arguments.step == "update":
        return update(group, key, labels, open_for)
    if arguments.runs < 0:
        raise PayloadError(f"--runs is a count of comments, not {arguments.runs}")
    return close(group, facts, key, labels, open_for, arguments.runs, arguments.leave_status)


def main(argv: Sequence[str] | None = None, working_directory: Path | None = None) -> int:
    """Print one step's commands, or one `incident-payload: error:` line and exit 2."""
    argv = sys.argv[1:] if argv is None else argv
    working_directory = Path.cwd() if working_directory is None else working_directory
    try:
        lines = printed(argv, working_directory)
    except PayloadError as failure:
        print(f"{PROGRAM}: error: {failure}", file=sys.stderr)
        return EXIT_ERROR
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
