"""`incident-payload`: the Jira commands a Run would otherwise build by hand.

A Run keeps every judgment the Skill asks of it: whether the Notification has a
Match, and whether to create, update, close or skip. This command does the
mechanical part of each step, the part a cheaper model got wrong in the
2026-10-01 rehearsals, where Haiku wrote six malformed creates and left an
Incident whose Description was `Test`: the summary, the labels, the fields, the
ADF Description, the comment text, which Alerts are new, repeat or resolved, and
how long the Incident has been open. It prints `jira-as` command lines, and the
Run runs them as printed.

    incident-payload match
    incident-payload create [--component NAME]
    incident-payload update --key KEY --labels LABELS --created TIME --server-time TIME
    incident-payload close --key KEY --labels LABELS --created TIME --server-time TIME
        --runs N [--leave-status]

It is pure and local. It reads two files at fixed places, and no path named on its
command line: `notification.json` in the working directory, which is the Run's
Notification, and `project.json` in the Skill the Receiver rendered for this
start, `<runs directory>/.skill`, which is the working directory's parent's. That
file holds the project facts the Skill already shows a Run: the key, the session
label, the field ids and the done status (`skill_template.materialize` writes it).
It opens no socket, starts no process, writes no file and reads no environment
variable, so it holds nothing a Run does not, and it cannot reach Jira.

Every command it prints is one line the Run's permission boundary admits: no
newline, no backslash, no `'\\''` and no `$'…'`, every argument that holds text in
plain single quotes. Alert text is made safe for that first (`plain`). Lines that
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
treats that as the end of the Run: it finishes `failed`, and never builds the
command by hand instead.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.run_command import RENDERED_SKILL

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


def create(group: Group, facts: Facts, component: str | None) -> list[str]:
    firing = group.firing
    if not firing:
        raise PayloadError(
            "no Alert in the Notification is firing: a resolved Notification with no Match is "
            "skipped, never created"
        )
    if component is not None and (not group.service or component != group.service):
        raise PayloadError(
            f"--component {component!r} is not the service label every firing Alert carries "
            f"({group.service or 'they carry none in common'}): leave --component off"
        )
    labels = [group.label, facts.session_label, *group.fingerprint_labels]
    words = [
        f"jira-as issue create -p {facts.project} -t {ISSUE_TYPE}",
        f"-s {quoted(summary(group))}",
        f"--labels {quoted(','.join(labels))}",
        f"--description {quoted(compact(description(group)))}",
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
                help="how many comments the Incident has now, the opening one included; the "
                "closing comment counts this Run as one more",
            )
            step.add_argument(
                "--leave-status",
                action="store_true",
                help="the Match is in a status a human owns: comment, and do not complete it",
            )
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
