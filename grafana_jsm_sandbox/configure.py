"""Reading the dedicated project's site facts off Jira, and writing them to `.env`.

    python3 -m grafana_jsm_sandbox.configure [--write]

The Skill a Run follows names the project's own Severity, Urgency, Source and
Major incident field ids, and the presenter's screen shows its Incidents queue.
Those differ on every site, and the site-wide field list cannot tell a
project's Severity from another project's field of the same name (the
2026-09-23 audit, F3). So this asks the project itself, through `jira-as` with
the environment `demo_config` builds from `.env`: its create metadata for the
Incident issue type, which gives each field's id and the values it offers, the
statuses and the resolution a reset and a Run move Incidents through, the
service desk's queues, the permissions the account in `.env` holds there, the
optional `rolldice` component, and whether the project holds open Incidents
that are not a Run's.

It only reads. It never creates, edits or transitions anything in Jira: where
a fix is the engineer's to make, such as adding the optional component, it
prints the `jira-as` command instead of running it, and where the fix is an
admin's it names the request in `docs/admin-requests.md`. The option values and
resolution are checked, not written. Status roles are configurable: this proposes
names from the Incident workflow and writes them with the field ids.

By default it prints the `.env` changes it would make. `--write` makes them in
place: an existing line keeps its place, its `export ` and its inline comment,
a key `.env` lacks is appended under a marked block, and no other line is
touched, the credential lines among them. A field it cannot pin down, because
the project lacks it, two fields share its name, or it does not offer a value
the Skill writes, is written empty, so a Run leaves it off rather than guess.
That is a WARN, not a FAIL: the demo still runs, its Incidents only lack the
field, and the line names the request that would add it.

Every line it prints is one of these, for a person at a terminal and for the
setup skill to parse:

    OK   <check>: <what it found>
    WARN <check>: <what is off, what it costs>[; ask: docs/admin-requests.md#<anchor> ...]
    FAIL <check>: <what stops the demo>[; ask: docs/admin-requests.md#<anchor> ...]
    .env: not checked: <NAME>, ...; left as .env has them
    .env: up to date | .env: <n> change(s) planned; ... | .env: <n> change(s) written; ...
    - <NAME>=<value .env has now>
    + <NAME>=<value configure found>
    READY | NOT READY: <the first FAIL's check>: <what it said>

Each line is one line: whatever Jira or jira-as said is folded onto it. The
`not checked` line comes first, and only when the check behind a key could not
be made, so `.env` could not be compared there; `up to date` is printed only
when every key was compared and none differs. A FAIL names the admin request
that fixes it, and so does the WARN for a Severity, Urgency or Source the Skill
leaves off, where the request is optional; always as
`docs/admin-requests.md#<anchor>`.

READY and NOT READY are about the project, not about `.env`: whether `.env`
already holds what the project said is the `.env:` line's to say, and a READY
run without `--write` that plans changes has not made them. The exit status is
0 when it ends READY; 1 when it ends NOT READY, because something needs an
admin or Jira could not be asked; and 2 for a usage or configuration error
before Jira was asked anything (bad arguments, no `.env`, no credential or
project key in it, no `jira-as` on PATH, a Python older than 3.11).
"""

from __future__ import annotations

import sys

# Checked before anything else is imported, so an older python3 gets a sentence rather than a
# traceback from some later syntax. Everything below this line is only compiled on it.
if sys.version_info < (3, 11):  # noqa: UP036 - pyproject's floor is what this enforces
    sys.stderr.write(
        "python3 -m grafana_jsm_sandbox.configure needs Python 3.11 or newer, and this is "
        + sys.version.split()[0]
        + ": run it with a newer python3 (README, What you need)\n"
    )
    raise SystemExit(2)

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from grafana_jsm_sandbox.demo_config import (
    ALLOWED_PROJECTS_VARIABLE,
    CONFIGURE,
    DOUBLE_QUOTED,
    ENV_FILE,
    FIELD_ID,
    FIELD_VARIABLES,
    INLINE_COMMENT,
    QUEUE_URL_VARIABLE,
    SITE_URL_VARIABLE,
    STATUS_DEFAULTS,
    STATUS_VARIABLES,
    ConfigurationError,
    DemoProject,
    jira_as_environment,
    read_env_file,
)
from grafana_jsm_sandbox.forwarder import DIAGNOSED_BODY_BYTES, IP_ALLOWLIST
from grafana_jsm_sandbox.log_formatter import redact
from grafana_jsm_sandbox.reset import (
    FINGERPRINT_PREFIX,
    OPEN_INCIDENTS,
    RESOLUTION,
    JiraAs,
    is_a_runs,
    jira_as_with,
    search,
)

COMMAND = CONFIGURE

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
"""A check's level. Only FAIL stops the demo. A FAIL names the admin request that fixes it; a
WARN names one only for a field the Skill leaves off, which an admin could add."""

ADMIN_REQUESTS = "docs/admin-requests.md"
"""Where every request an engineer forwards to an admin is written out, ready to paste."""

CREATE_PROJECT = "jira-admin-create-project"
INCIDENT_FIELDS = "jira-admin-incident-fields"
RESOLUTION_SCREEN = "jira-admin-resolution-screen"
WORKFLOW_STATUSES = "jira-admin-workflow-statuses"
PERMISSIONS = "jira-admin-permissions"
AGENT_LICENCE = "atlassian-org-admin-agent-licence"
API_TOKENS = "atlassian-org-admin-api-tokens"
IP_ALLOWLIST_REQUEST = "atlassian-org-admin-ip-allowlist"
"""The anchors in `docs/admin-requests.md` this command can name, one per request."""

INCIDENT = "Incident"
"""The issue type a Run creates, which the ITSM template brings."""

SERVICE_DESK = "service_desk"
"""`projectTypeKey` of a Jira Service Management project."""

COMPANY_MANAGED = "classic"
"""`style` of a company-managed project, the kind the demo was built and rehearsed on."""

WORK_IN_PROGRESS = "Work in progress"

WORKFLOW = {
    "status_open": False,
    "status_in_progress": False,
    "status_done": True,
    "status_closed": True,
}
"""The status roles and whether each must be Done: open and in progress must not be Done.
Discovery prefers To Do for open and In Progress for in progress."""

STATUS_CANDIDATES = {
    "status_open": ("Open", "New", "To Do"),
    "status_in_progress": ("Work in progress", "In Progress"),
    "status_done": ("Completed", "Resolved", "Done"),
    "status_closed": ("Closed",),
}
"""Names proposed in order within the role's category; human-owned done names are never proposed."""


REQUIRED_PERMISSIONS = (
    "BROWSE_PROJECTS",
    "CREATE_ISSUES",
    "EDIT_ISSUES",
    "TRANSITION_ISSUES",
    "RESOLVE_ISSUES",
    "CLOSE_ISSUES",
    "ADD_COMMENTS",
)
"""What a Run and the reset do on the project with the account in `.env`."""

OPTIONAL_PERMISSIONS = {
    "ADMINISTER_PROJECTS": "adding the optional component yourself",
    "DELETE_ISSUES": "deleting an Incident stuck in the queue, which only a human does",
}
"""Worth holding, and what each is for; the demo runs without them."""

QUEUE = "Incidents"
"""The ITSM template's queue of open Incidents, the one the presenter projects."""

UNRESOLVED = re.compile(r"(?i)\bresolution\s*(?:=|\bis\b)\s*(?:unresolved|empty|null)\b")
"""What a queue's JQL must say for a completed Incident to leave it (ADR 0004): JQL spells
the unresolved `resolution = Unresolved`, `resolution is EMPTY` or `resolution = EMPTY`."""

COMPONENT = "rolldice"
"""The Alert's `service` label (grafana/provisioning/alerting/alert-rule.yaml), which a Run sets
as the Component only when the project has one of that exact name."""

FILLED_BY_A_RUN = frozenset(
    {"project", "issuetype", "summary", "reporter", "labels", "description"}
)
"""The create fields a Run always sets, or Jira fills for it: the reporter is the caller."""

GATEWAY_HOST = "api.atlassian.com"
"""The host of a scoped token's `JIRA_SITE_URL`, which is no address a browser opens."""

UNREACHABLE = "HTTP transport failed"
"""How jira-as 2.0.0 words a site it could not connect to, which it reports as a 503."""

JIRA_AS_FAILED = "Failed to "
"""How jira-as 2.0.0 starts the message for an error status: `Failed to <operation>: <body>`
(`error_handler.handle_jira_error`)."""

PAGE_SIZE = 50
"""What each page of a paged answer is asked for. Jira may answer fewer, so pages are followed."""

SHOWN = 5
"""How many issue keys a line names before it says how many more there are."""

SAID_LIMIT = 300
"""How much of one thing Jira or jira-as said a line carries: an IP allowlist's HTML page or
a traceback would otherwise drown the line it explains."""

SITE_FACTS_MARKER = f"# --- site facts written by configure ({COMMAND} --write) ---"
"""The comment the keys `.env` lacked are appended under, and found under again next time."""


@dataclass(frozen=True)
class SiteField:
    """A custom field the Skill names, and the values a Run writes into it."""

    variable: str
    name: str
    """The field's exact name on the Incident create screen."""
    options: tuple[str, ...]
    """Every value the Skill may write; empty for the field a Run never touches."""

    @property
    def check(self) -> str:
        return self.name.lower()


SITE_FIELDS = (
    SiteField(FIELD_VARIABLES["severity_field"], "Severity", ("Sev-1", "Sev-2", "Sev-3")),
    SiteField(FIELD_VARIABLES["urgency_field"], "Urgency", ("Critical", "High", "Medium")),
    SiteField(FIELD_VARIABLES["source_field"], "Source", ("Monitoring systems",)),
    SiteField(FIELD_VARIABLES["major_incident_field"], "Major incident", ()),
)
"""The fields `configure` writes the ids of, in `.env`'s order. The values are the Skill's
(`skill_template.FIELDS`), and a test holds the two to each other."""

FACT_VARIABLES = (
    *(site_field.variable for site_field in SITE_FIELDS),
    QUEUE_URL_VARIABLE,
    *STATUS_VARIABLES.values(),
)
"""Every `.env` key `configure` may write, and the only ones it ever touches."""


@dataclass(frozen=True)
class Check:
    """One printed line: what was checked, how it came out, and whom to ask when it failed."""

    level: str
    name: str
    message: str
    ask: tuple[str, ...] = ()

    @property
    def line(self) -> str:
        line = f"{self.level:<4} {self.name}: {one_line(self.message)}"
        if self.ask:
            line += "; ask: " + " ".join(f"{ADMIN_REQUESTS}#{anchor}" for anchor in self.ask)
        return line


@dataclass
class Discovery:
    """What the project answered: a line per check, and the `.env` values it pins down.

    A key is in `facts` only when the project answered for it, so a check that could not
    be made changes nothing in `.env`, where a check that found nothing writes it empty.
    """

    checks: list[Check] = field(default_factory=list)
    facts: dict[str, str] = field(default_factory=dict)

    def add(self, level: str, name: str, message: str, *ask: str) -> None:
        self.checks.append(Check(level, name, message, ask))

    @property
    def unchecked(self) -> list[str]:
        """The `.env` keys the project did not answer for, which `.env` cannot be held to."""
        return [name for name in FACT_VARIABLES if name not in self.facts]

    @property
    def blocker(self) -> Check | None:
        return next((check for check in self.checks if check.level == FAIL), None)


class JiraRefused(Exception):
    """A `jira-as` call that did not answer: Jira's status when it had one, and its messages.

    jira-as 2.0.0's `api call` writes a failure as one JSON object on stderr,
    `{"status": 404, "messages": [...], ...}`, with `status` null for its own refusals and
    503 for a site it could not reach. The messages are redacted before they are kept, and
    folded onto one short line, since they end up on a check's line.

    Whether they are an IP allowlist's refusal is decided first, on what was said in
    full: jira-as puts the whole response body after `Failed to <operation>: `, and an
    allowlist's HTML page says so well past what a line keeps. The body is searched as
    far as the Forwarder's `diagnose` searches one, so the laptop and the container
    read the same page the same way.
    """

    def __init__(self, status: int | None, messages: list[str]):
        self.status = status
        self.ip_allowlist = any(IP_ALLOWLIST.search(body_of(message)) for message in messages)
        self.messages = [clipped(redact(message)) for message in messages]
        super().__init__("; ".join(self.messages) or "no message")


def body_of(message: str) -> str:
    """The start of the response body a jira-as message quotes, as much as `diagnose` searches."""
    if message.startswith(JIRA_AS_FAILED):
        message = message.partition(": ")[2]
    return message[:DIAGNOSED_BODY_BYTES]


def one_line(text: str) -> str:
    """`text` with every run of whitespace, line breaks among them, made one space."""
    return " ".join(text.split())


def clipped(text: str) -> str:
    """`text` on one line and at most `SAID_LIMIT` characters, marked where it was cut."""
    text = one_line(text)
    return text if len(text) <= SAID_LIMIT else text[: SAID_LIMIT - 3].rstrip() + "..."


@dataclass(frozen=True)
class Change:
    """One `.env` key and the value `configure` would give it."""

    name: str
    before: str | None
    """What `.env` holds now; None when it has no such key."""
    after: str


def discover(
    project_key: str, site_url: str, jira_as: JiraAs, project: DemoProject | None = None
) -> Discovery:
    """Ask the project everything the demo relies on, and nothing that changes it.

    The project comes first: when Jira cannot find it, or refuses the credential,
    nothing else it could say would help. Every later check stands alone, so one
    that fails still leaves the others to be read.
    """
    found = Discovery()
    project_id = check_project(found, jira_as, project_key)
    if project_id is None:
        return found
    attempt(found, "permissions", check_permissions, jira_as, project_key)
    component = attempt(found, "component", find_component, jira_as, project_key, site_url)
    incident = attempt(found, "issue type", check_issue_type, jira_as, project_key)
    if incident is not None:
        has_component = component is not None and component[1]
        attempt(found, "create screen", check_fields, jira_as, project_key, incident, has_component)
    attempt(found, "statuses", check_statuses, jira_as, project_key, incident, project)
    attempt(found, "resolution", check_resolution, jira_as)
    attempt(found, "service desk", check_queue, jira_as, project_key, project_id, site_url)
    if component is not None:
        found.checks.append(component[0])
    attempt(found, "dedicated", check_dedicated, jira_as, project_key)
    return found


def attempt(found: Discovery, name: str, check: Callable, *arguments):
    """Run one check; a call Jira refused becomes that check's FAIL, and the rest go on."""
    try:
        return check(found, *arguments)
    except JiraRefused as failure:
        found.checks.append(refused(name, failure))
        return None


def refused(name: str, failure: JiraRefused) -> Check:
    """The line for a call Jira refused, naming whom to ask where the status says who."""
    said = str(failure)
    if failure.status == 401:
        return Check(
            FAIL,
            name,
            "Jira refused the credential in .env (401): check JIRA_EMAIL and JIRA_API_TOKEN, "
            "and whether your account may use API tokens",
            (API_TOKENS,),
        )
    if failure.status == 403 and failure.ip_allowlist:
        return Check(
            FAIL,
            name,
            f"the site's IP allowlist refused this address (403): {said}",
            (IP_ALLOWLIST_REQUEST,),
        )
    if failure.status == 403:
        return Check(
            FAIL,
            name,
            f"Jira refused the account in .env (403): {said}",
            (PERMISSIONS, AGENT_LICENCE),
        )
    if failure.status is None:
        return Check(
            FAIL,
            name,
            f"jira-as refused the call: {said}; check that `jira-as --version` is 2.0.x and "
            "that .env's DEMO_PROJECT_KEY is the project you mean (README, What you need)",
        )
    if failure.status == 503 and UNREACHABLE in said:
        return Check(
            FAIL,
            name,
            f"jira-as could not reach {SITE_URL_VARIABLE} ({said}): check the address in .env, "
            "the network, and any proxy or VPN the site needs",
        )
    return Check(FAIL, name, f"Jira answered {failure.status}: {said}")


def check_project(found: Discovery, jira_as: JiraAs, key: str) -> str | None:
    """The project's id when the key names a Jira Service Management project the account in
    `.env` can see, else None; the id finds its service desk when the key does not."""
    try:
        project = as_dict(call(jira_as, "getProject", "--project-id-or-key", key))
    except JiraRefused as failure:
        if failure.status == 404:
            found.add(
                FAIL,
                "project",
                f"Jira has no project {key}, or the account in .env cannot see it",
                CREATE_PROJECT,
                PERMISSIONS,
            )
        else:
            found.checks.append(refused("project", failure))
        return None
    kind = project.get("projectTypeKey")
    if kind != SERVICE_DESK:
        found.add(
            FAIL,
            "project",
            f"{key} is a {kind or 'untyped'} project, not a Jira Service Management one "
            "made from the IT service management template",
            CREATE_PROJECT,
        )
        return None
    name = project.get("name") or key
    if project.get("style") == COMPANY_MANAGED:
        found.add(OK, "project", f"{key} ({name}) is a company-managed service project")
    else:
        found.add(
            WARN,
            "project",
            f"{key} ({name}) is a team-managed service project; the demo was built on a "
            "company-managed one, and its workflow and screens may differ",
        )
    return str(project.get("id") or "")


def check_permissions(found: Discovery, jira_as: JiraAs, key: str) -> None:
    """Whether the account in `.env` may do on the project what a Run and the reset do."""
    asked = (*REQUIRED_PERMISSIONS, *OPTIONAL_PERMISSIONS)
    answer = as_dict(
        call(
            jira_as,
            "getMyPermissions",
            "--project-key",
            key,
            "--permissions",
            ",".join(asked),
        )
    )
    held = {
        name
        for name, permission in as_dict(answer.get("permissions")).items()
        if as_dict(permission).get("havePermission") is True
    }
    missing = [name for name in REQUIRED_PERMISSIONS if name not in held]
    if missing:
        found.add(
            FAIL,
            "permissions",
            f"the account in .env lacks {', '.join(missing)} on {key}; without a Jira Service "
            "Management agent licence it lacks them whatever role it has",
            PERMISSIONS,
            AGENT_LICENCE,
        )
    else:
        found.add(OK, "permissions", f"the account in .env holds {', '.join(REQUIRED_PERMISSIONS)}")
    for name, use in OPTIONAL_PERMISSIONS.items():
        if name not in held:
            found.add(WARN, "permissions", f"no {name} on {key}, which is only for {use}")


def find_component(
    found: Discovery, jira_as: JiraAs, key: str, site_url: str
) -> tuple[Check, bool]:
    """Whether the project has the component a Run would set, and the line saying so.

    The line is printed after the others, and the answer is needed before them: a
    create screen that requires a component is filled only when this one exists. Adding
    one is optional and is the project admin's write, so the line carries the command
    for the engineer to run, pointed at the demo's site, and nothing here runs it.
    """
    components = as_list(call(jira_as, "getProjectComponents", "--project-id-or-key", key))
    if COMPONENT in {as_dict(component).get("name") for component in components}:
        return Check(OK, "component", f"{COMPONENT} exists, so a Run sets it"), True
    return Check(
        OK,
        "component",
        f"no {COMPONENT} component, so a Run creates Incidents without one; to add it (optional, "
        f"as the project's administrator), add it under the project's settings, Components, or "
        f"run: {create_component_command(key, site_url)}",
    ), False


def create_component_command(key: str, site_url: str) -> str:
    """The command that adds the optional component, for the engineer to run themselves.

    It runs with the engineer's own jira-as credential, from their shell, keychain or
    settings file, which may well be a production site's. So it names `.env`'s site and
    key on the command line: jira-as 2.0.0 takes each of the site, email and token from
    the environment before anything else (jira_as/config_manager.py:96-111), so the
    write can only land on the demo's site, and the allow list confines it to the
    demo's project there. Neither is a secret; the email and token stay out of it.

    `createComponent` scopes itself by the body's `project`, and jira-as 2.0.0 then
    wants the same key as `--project` too before it sends anything.
    """
    return (
        f"{SITE_URL_VARIABLE}={shlex.quote(site_url)} {ALLOWED_PROJECTS_VARIABLE}={key} "
        f"jira-as api call createComponent --project {key} "
        f"--field name={COMPONENT} --field project={key}"
    )


def check_issue_type(found: Discovery, jira_as: JiraAs, key: str) -> dict | None:
    """The Incident issue type as the project's create metadata names it, or None."""
    types = every_page(
        jira_as,
        "getCreateIssueMetaIssueTypes",
        ("--project-id-or-key", key),
        ("issueTypes",),
        "--start-at",
        "--max-results",
    )
    incidents = [kind for kind in types if as_dict(kind).get("name") == INCIDENT]
    if not incidents:
        offered = ", ".join(str(as_dict(kind).get("name")) for kind in types) or "none"
        found.add(
            FAIL,
            "issue type",
            f"{key} offers no {INCIDENT} issue type to create (it offers: {offered})",
            CREATE_PROJECT,
        )
        return None
    incident = as_dict(incidents[0])
    found.add(OK, "issue type", f"{INCIDENT} is issue type {incident.get('id')}")
    return incident


def check_fields(
    found: Discovery, jira_as: JiraAs, key: str, incident: dict, has_component: bool
) -> None:
    """Read each field's id and offered values off the Incident create screen, by exact name.

    Only the project's own create metadata is asked, never the site's field list: two
    projects on one site can each have a Severity, and only this one's is the one a
    create on this project takes. The create screen as a whole is checked last, since a
    required field no Run fills would refuse every create.
    """
    fields = [
        as_dict(item)
        for item in every_page(
            jira_as,
            "getCreateIssueMetaIssueTypeId",
            ("--project-id-or-key", key, "--issue-type-id", str(incident.get("id"))),
            ("fields", "results"),
            "--start-at",
            "--max-results",
        )
    ]
    filled = set(FILLED_BY_A_RUN)
    if has_component:
        filled.add("components")
    for site_field in SITE_FIELDS:
        field_id = match_field(found, site_field, fields)
        found.facts[site_field.variable] = field_id
        if field_id and site_field.options:
            filled.add(field_id)
    present = {item.get("fieldId") for item in fields}
    problems = [
        f"it lacks {name}, which {why}"
        for system, name, why in (
            ("labels", "Labels", "a Run keys every Incident by"),
            ("description", "Description", "every create sets"),
        )
        if system not in present
    ]
    unfilled = [
        f"{item.get('name')} ({item.get('fieldId')})"
        for item in fields
        if item.get("required") is True
        and not item.get("hasDefaultValue")
        and item.get("fieldId") not in filled
    ]
    if unfilled:
        problems.append(f"it requires {', '.join(unfilled)}, which no Run fills")
    if problems:
        found.add(
            FAIL,
            "create screen",
            f"the {INCIDENT} create screen: {'; '.join(problems)}",
            INCIDENT_FIELDS,
        )
    else:
        found.add(
            OK,
            "create screen",
            "Labels and Description are on it, and a Run fills every field it requires",
        )


def match_field(found: Discovery, site_field: SiteField, fields: list[dict]) -> str:
    """The field's id when exactly one field has its name and offers every value; else empty.

    Empty is what the Skill reads as "this project lacks it", so a Run leaves the field off
    instead of writing a value the create would refuse, or into the wrong field. That
    costs the Incident the field and nothing else, so it is a WARN naming the optional
    request. A create screen that requires the field is `check_fields`'s FAIL.
    """
    named = [item for item in fields if item.get("name") == site_field.name]
    left = f"so {site_field.variable} is left empty and a Run leaves {site_field.name} off"
    if not site_field.options:
        return match_untouched(found, site_field, named)
    if not named:
        found.add(
            WARN,
            site_field.check,
            f"no field named {site_field.name} on the {INCIDENT} create screen, {left}",
            INCIDENT_FIELDS,
        )
        return ""
    if len(named) > 1:
        ids = ", ".join(str(item.get("fieldId")) for item in named)
        found.add(
            WARN,
            site_field.check,
            f"{len(named)} fields are named {site_field.name} on the {INCIDENT} create screen "
            f"({ids}), and which one is meant cannot be told, {left}",
            INCIDENT_FIELDS,
        )
        return ""
    field_id = str(named[0].get("fieldId") or "")
    if not FIELD_ID.fullmatch(field_id):
        found.add(
            WARN,
            site_field.check,
            f"{site_field.name} on the {INCIDENT} create screen is {field_id or 'unnamed'}, "
            f"not a custom field, {left}",
            INCIDENT_FIELDS,
        )
        return ""
    offered = {
        as_dict(value).get("value")
        for value in as_list(named[0].get("allowedValues"))
        if not as_dict(value).get("disabled")
    }
    lacking = [option for option in site_field.options if option not in offered]
    if lacking:
        found.add(
            WARN,
            site_field.check,
            f"{site_field.name} ({field_id}) does not offer {', '.join(lacking)}, {left}",
            INCIDENT_FIELDS,
        )
        return ""
    found.add(OK, site_field.check, f"{field_id}, offering {', '.join(site_field.options)}")
    return field_id


def match_untouched(found: Discovery, site_field: SiteField, named: list[dict]) -> str:
    """The id of the field a Run is told never to touch, when one field unambiguously has it.

    The Skill names it by name either way, so not finding it costs only the id in brackets.
    """
    field_ids = [str(item.get("fieldId") or "") for item in named]
    if len(field_ids) == 1 and FIELD_ID.fullmatch(field_ids[0]):
        found.add(OK, site_field.check, f"{field_ids[0]}, which a Run is told never to touch")
        return field_ids[0]
    if not field_ids:
        found.add(
            OK,
            site_field.check,
            f"none on the {INCIDENT} create screen; the Skill still tells a Run never to "
            f"touch {site_field.name}",
        )
    else:
        found.add(
            WARN,
            site_field.check,
            f"{', '.join(field_ids)} cannot be told apart, so {site_field.variable} is left "
            f"empty; the Skill still tells a Run never to touch {site_field.name}",
        )
    return ""


def check_statuses(
    found: Discovery,
    jira_as: JiraAs,
    key: str,
    incident: dict | None,
    project: DemoProject | None = None,
    propose: bool = True,
) -> None:
    """Whether the Incident workflow has the statuses a Run and the reset move through."""
    kinds = [
        as_dict(kind)
        for kind in as_list(call(jira_as, "getAllStatuses", "--project-id-or-key", key))
    ]
    wanted = None if incident is None else incident.get("id")
    kind = next((kind for kind in kinds if wanted and kind.get("id") == wanted), None) or next(
        (kind for kind in kinds if kind.get("name") == INCIDENT), None
    )
    if kind is None:
        found.add(FAIL, "statuses", f"{key} has no {INCIDENT} workflow", WORKFLOW_STATUSES)
        return
    categories = {
        as_dict(status).get("name"): as_dict(as_dict(status).get("statusCategory")).get("key")
        for status in as_list(kind.get("statuses"))
    }
    project = DemoProject(key) if project is None else project
    problems = []
    proposals = []
    kept = []
    listed = ", ".join(f"{name} ({category})" for name, category in categories.items()) or "none"
    for role, done in WORKFLOW.items():
        variable = STATUS_VARIABLES[role]
        name = getattr(project, role)
        valid = (role == "status_closed" and not name) or (
            name in categories and (categories[name] == "done") == done
        )
        if valid:
            found.facts[variable] = name
            kept.append(name or "no close step")
            continue
        why = (
            f"{name} is {'not ' if done else ''}in the Done category"
            if name in categories
            else f"it lacks {name or 'a status name'}"
        )
        if not propose:
            problems.append(f"{role}: {variable}={name}: {why}; set {variable} by hand")
            continue
        category = "done" if done else "new" if role == "status_open" else "indeterminate"
        offered = [name for name, actual in categories.items() if actual == category]
        proposal = next((name for name in STATUS_CANDIDATES[role] if name in offered), None)
        if role == "status_in_progress" and len(offered) == 1:
            proposal = offered[0]
        if role == "status_closed" and proposal is None:
            proposal = ""
        if proposal is None:
            problems.append(f"{role}: {variable}: {why}; set {variable} by hand")
        else:
            found.facts[variable] = proposal
            proposals.append(f"{variable}={proposal or '(empty, no close step)'}")
    if problems:
        found.add(
            FAIL,
            "statuses",
            f"the {INCIDENT} workflow: {'; '.join(problems)}; statuses: {listed}",
            WORKFLOW_STATUSES,
        )
    elif proposals:
        found.add(WARN, "statuses", f"the {INCIDENT} workflow: proposed {', '.join(proposals)}")
    else:
        found.add(OK, "statuses", f"the {INCIDENT} workflow has {', '.join(kept)}")


def check_resolution(found: Discovery, jira_as: JiraAs) -> None:
    """Whether the resolution a Run and the reset complete an Incident with exists.

    Whether the Resolve screen takes it shows only when an Incident is resolved, which
    this never does: the reset and `verify` read it back after the move.
    """
    names = {
        as_dict(resolution).get("name")
        for resolution in every_page(
            jira_as, "searchResolutions", (), ("values",), "--start-at", "--max-results"
        )
    }
    if RESOLUTION not in names:
        found.add(
            FAIL,
            "resolution",
            f"the site has no resolution named {RESOLUTION}, which completes an Incident",
            RESOLUTION_SCREEN,
        )
    else:
        found.add(
            OK,
            "resolution",
            f"{RESOLUTION} exists; whether the Resolve screen takes it shows the first time "
            "an Incident is completed",
        )


def check_queue(
    found: Discovery, jira_as: JiraAs, key: str, project_id: str, site_url: str
) -> None:
    """The service desk behind the project, and the address of its Incidents queue.

    The address is the one a browser shows for the queue, built from the queue's id as
    the service desk API gives it. That the API's id is the address bar's is what the
    audit could not verify offline; a queue that opens elsewhere is fixed by hand.
    """
    desk = find_service_desk(jira_as, key, project_id)
    if desk is None:
        found.add(
            FAIL,
            "service desk",
            f"{key} is not a service desk the account in .env can see",
            CREATE_PROJECT,
            AGENT_LICENCE,
        )
        return
    desk_id = str(desk.get("id") or "")
    found.add(OK, "service desk", f"{key} is service desk {desk_id}")
    queues = [
        as_dict(queue)
        for queue in every_page(
            jira_as, "getQueues", ("--service-desk-id", desk_id), ("values",), "--start", "--limit"
        )
    ]
    named = [queue for queue in queues if queue.get("name") == QUEUE]
    if len(named) != 1:
        found.add(
            WARN,
            "queue",
            f"{len(named) or 'no'} queue(s) named {QUEUE} on {key}, so {QUEUE_URL_VARIABLE} is "
            "left as it is; open the queue that shows open Incidents and copy its address there",
        )
        return
    try:
        site = browser_site(jira_as, site_url)
    except JiraRefused as failure:
        site, why = "", str(failure)
    else:
        why = "the site named no base URL"
    if not site:
        found.add(
            WARN,
            "queue",
            f"the site's address could not be read ({why}), so {QUEUE_URL_VARIABLE} is left as "
            "it is; open the queue and copy its address there",
        )
        return
    url = f"{site}/jira/servicedesk/projects/{key}/queues/custom/{named[0].get('id')}"
    found.facts[QUEUE_URL_VARIABLE] = url
    jql = str(named[0].get("jql") or "")
    if UNRESOLVED.search(jql):
        found.add(OK, "queue", url)
    else:
        found.add(
            WARN,
            "queue",
            f"{url} does not filter on resolution = Unresolved, so a completed Incident stays "
            f"in it: {clipped(jql)}",
        )


def find_service_desk(jira_as: JiraAs, key: str, project_id: str) -> dict | None:
    """The service desk behind the project, or None when the account can see none.

    The service desk API documents that its id "can alternatively be a project
    identifier", which a key is on the sites the demo was built on, but no offline
    check can promise every site takes one. So a 404 or 400 for the key is not taken
    as the answer: the desks the account can see are paged through for the one whose
    project is this key, or this project's id.
    """
    try:
        return as_dict(call(jira_as, "getServiceDeskById", "--service-desk-id", key))
    except JiraRefused as failure:
        if failure.status not in (400, 404):
            raise
    desks = every_page(jira_as, "getServiceDesks", (), ("values",), "--start", "--limit")
    return next(
        (
            as_dict(desk)
            for desk in desks
            if as_dict(desk).get("projectKey") == key
            or (project_id and str(as_dict(desk).get("projectId")) == project_id)
        ),
        None,
    )


def browser_site(jira_as: JiraAs, site_url: str) -> str:
    """The site's address as a browser opens it: `.env`'s, unless that is the API gateway.

    A scoped token reaches Jira through `api.atlassian.com/ex/jira/<cloudId>`, which is no
    page anyone can open, so then the site's own base URL is asked for.
    """
    parts = urlsplit(site_url)
    if (parts.hostname or "").lower() != GATEWAY_HOST:
        return f"{parts.scheme}://{parts.netloc}"
    return str(as_dict(call(jira_as, "getServerInfo")).get("baseUrl") or "").rstrip("/")


def check_dedicated(found: Discovery, jira_as: JiraAs, key: str) -> None:
    """Whether every open Incident on the project is a Run's, as on a project the demo owns.

    One without a Fingerprint label is somebody's real Incident: the reset leaves it
    alone, so the queue will not start empty, and a Run's Match search sits beside it.
    """
    try:
        issues = search(jira_as, OPEN_INCIDENTS.format(key=key))
        others = [str(issue.get("key")) for issue in issues if not is_a_runs(issue)]
    except (RuntimeError, subprocess.TimeoutExpired) as failure:
        raise refusal(failure) from None
    except (ValueError, KeyError, TypeError, AttributeError):
        raise JiraRefused(
            None, ["search jql answered something other than the expected JSON"]
        ) from None
    if not others:
        found.add(OK, "dedicated", f"no open {INCIDENT} on {key} but a Run's")
        return
    named = ", ".join(others[:SHOWN]) + (
        f" and {len(others) - SHOWN} more" if len(others) > SHOWN else ""
    )
    found.add(
        WARN,
        "dedicated",
        f"{key} doesn't look dedicated to the demo: {len(others)} open {INCIDENT}(s) carry no "
        f"{FINGERPRINT_PREFIX} label ({named}); the reset leaves them alone, so the queue "
        "will not start empty",
    )


def call(jira_as: JiraAs, operation: str, *arguments: str) -> object:
    """One `jira-as api call`, its JSON answer decoded; a refusal raises `JiraRefused`."""
    try:
        answer = jira_as("api", "call", operation, *arguments)
    except (RuntimeError, subprocess.TimeoutExpired) as failure:
        raise refusal(failure) from None
    try:
        return json.loads(answer)
    except ValueError:
        raise JiraRefused(None, [f"{operation} answered something other than JSON"]) from None


def every_page(
    jira_as: JiraAs,
    operation: str,
    arguments: tuple[str, ...],
    items: tuple[str, ...],
    start: str,
    size: str,
) -> list:
    """Every item of an offset-paged answer, page after page.

    Jira caps a page below what was asked for when it likes, so the next page starts
    where the items so far end, until a page is empty, says it is the last, or the
    total is reached. `items` names where the list is, first match wins, because
    createmeta's field pages are documented under two names.
    """
    found: list = []
    while True:
        page = as_dict(
            call(jira_as, operation, *arguments, start, str(len(found)), size, str(PAGE_SIZE))
        )
        batch = next((page[name] for name in items if isinstance(page.get(name), list)), [])
        found += batch
        total = page.get("total")
        if (
            not batch
            or page.get("isLast") is True
            or page.get("isLastPage") is True
            or (isinstance(total, int) and len(found) >= total)
        ):
            return found


def refusal(failure: BaseException) -> JiraRefused:
    """What a failed `jira-as` said, read from the JSON error object its stderr carries."""
    if isinstance(failure, subprocess.TimeoutExpired):
        return JiraRefused(None, [f"jira-as had no answer in {failure.timeout:g} s"])
    text = str(failure)
    start = text.find('{"status"')
    if start >= 0:
        try:
            said, _ = json.JSONDecoder().raw_decode(text, start)
        except ValueError:
            said = None
        if isinstance(said, dict):
            status = said.get("status")
            messages = [str(message) for message in as_list(said.get("messages"))]
            return JiraRefused(status if isinstance(status, int) else None, messages)
    return JiraRefused(None, [text])


def as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def planned(current: Mapping[str, str], facts: Mapping[str, str]) -> list[Change]:
    """The keys whose value in `.env` differs from what the project said, in `.env`'s order."""
    defaults = {variable: STATUS_DEFAULTS[role] for role, variable in STATUS_VARIABLES.items()}
    return [
        Change(name, current.get(name), facts[name])
        for name in FACT_VARIABLES
        if name in facts and current.get(name, defaults.get(name)) != facts[name]
    ]


def rewritten(text: str, changes: list[Change]) -> str:
    """`.env`'s text with the changes made and every other byte as it was.

    A key already there is set where it stands, every time it appears, keeping its
    indentation, `export ` and inline comment. A key not there goes under
    `SITE_FACTS_MARKER`, which is added at the end the first time.
    """
    values = {change.name: change.after for change in changes}
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    seen = set()
    for number, line in enumerate(lines):
        name = assigned(line)
        if name in values:
            lines[number] = assignment(line, name, values[name])
            seen.add(name)
    appended = [f"{name}={value}{newline}" for name, value in values.items() if name not in seen]
    if not appended:
        return "".join(lines)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += newline
    marker = next(
        (number for number, line in enumerate(lines) if line.strip() == SITE_FACTS_MARKER), None
    )
    if marker is None:
        if lines and lines[-1].strip():
            lines.append(newline)
        return "".join([*lines, SITE_FACTS_MARKER + newline, *appended])
    end = marker + 1
    while end < len(lines) and lines[end].strip():
        end += 1
    return "".join([*lines[:end], *appended, *lines[end:]])


def assigned(line: str) -> str | None:
    """The name a line of `.env` sets, read as `demo_config.read_env_file` reads it."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    name, equals, _ = stripped.partition("=")
    return name.strip() if equals else None


def assignment(line: str, name: str, value: str) -> str:
    """`line` setting `name` to `value` instead, with its layout and inline comment kept."""
    body = line.rstrip("\r\n")
    ending = line[len(body) :]
    indent = body[: len(body) - len(body.lstrip())]
    rest = body.lstrip()
    export = "export " if rest.startswith("export ") else ""
    raw = rest.partition("=")[2].strip()
    return f"{indent}{export}{name}={value}{inline_comment(raw)}{ending}"


def inline_comment(raw: str) -> str:
    """The comment after a value, with the space before it, or nothing."""
    tail = ""
    if raw.startswith("'"):
        end = raw.find("'", 1)
        tail = raw[end + 1 :] if end > 0 else ""
    elif raw.startswith('"'):
        quoted = DOUBLE_QUOTED.match(raw)
        tail = raw[quoted.end() :] if quoted else ""
    else:
        comment = INLINE_COMMENT.search(raw)
        tail = raw[comment.start() :] if comment else ""
    tail = tail.strip()
    return f" {tail}" if tail.startswith("#") else ""


def write(path: Path, changes: list[Change]) -> None:
    """Make the changes to `.env` in place, all at once, keeping its permissions.

    The new text goes to a file beside it that is then renamed over it, so an
    interrupted write leaves the old `.env` whole: it holds the credentials.
    """
    target = path.resolve()
    with open(target, encoding="utf-8", newline="") as current:
        text = current.read()
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".env.", suffix=".new")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as new:
            new.write(rewritten(text, changes))
        shutil.copymode(target, temporary)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def unchecked(values: Mapping[str, str]) -> dict[str, str]:
    """`.env`'s values without the ones `configure` writes, which it is here to correct."""
    return {name: value for name, value in values.items() if name not in FACT_VARIABLES}


def main(
    argv: list[str] | None = None,
    env_file: Path = ENV_FILE,
    jira_as: JiraAs | None = None,
) -> int:
    """Discover, print a line per check and the `.env` diff, and write it with `--write`.

    `jira_as` replaces the real one built from `.env`, which is read and checked all the same.
    """
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        description=__doc__.splitlines()[0],
        epilog=(
            "exit status: 0 READY; 1 NOT READY, because something needs an admin or Jira could "
            "not be asked; 2 a usage or configuration error before Jira was asked anything. "
            "READY is about the project: the .env line says whether .env holds what it said"
        ),
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="make the planned changes to .env in place; without it, only print them",
    )
    arguments = parser.parse_args(argv)
    try:
        values = read_env_file(env_file)
        environment = jira_as_environment(unchecked(values))
        project = DemoProject.from_environment(
            {
                **unchecked(values),
                **{name: values[name] for name in STATUS_VARIABLES.values() if name in values},
            }
        )
    except ConfigurationError as failure:
        print(failure, file=sys.stderr)
        return 2
    jira_as = jira_as_with(environment) if jira_as is None else jira_as
    try:
        found = discover(project.key, environment[SITE_URL_VARIABLE], jira_as, project)
    except FileNotFoundError:
        print(
            "jira-as is not on PATH: install the Jira Assistant CLI 2.x (README, What you need)",
            file=sys.stderr,
        )
        return 2
    for check in found.checks:
        print(check.line)
    changes = planned(values, found.facts)
    if arguments.write and changes:
        write(env_file, changes)
    report(changes, written=arguments.write, unchecked=found.unchecked)
    if found.blocker is None:
        print("READY")
        return 0
    print(f"NOT READY: {found.blocker.name}: {one_line(found.blocker.message)}")
    return 1


def report(changes: list[Change], written: bool, unchecked: list[str]) -> None:
    """The `.env` lines, then the diff: what is there now, and what the project said.

    A key whose check could not be made was compared with nothing, so it is named
    as not checked rather than folded into an "up to date" it was never held to.
    """
    if unchecked:
        print(f".env: not checked: {', '.join(unchecked)}; left as .env has them")
    if not changes:
        if not unchecked:
            print(".env: up to date")
        return
    if written:
        print(
            f".env: {len(changes)} change(s) written; recreate the demo container with "
            "`docker compose up -d demo` so the Run's Skill is rendered from them"
        )
    else:
        print(f".env: {len(changes)} change(s) planned; run again with --write to make them")
    for change in changes:
        if change.before is not None:
            print(f"- {change.name}={redact(change.before)}")
        print(f"+ {change.name}={change.after}")


if __name__ == "__main__":
    raise SystemExit(main())
