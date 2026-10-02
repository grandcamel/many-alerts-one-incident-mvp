"""Reading the dedicated project's site facts off Jira, and writing them to `.env`.

`configure` talks to Jira only through an injected `jira-as`, as the reset does, so
these tests drive it against a fake that answers from sanitized fixtures under
`fixtures/jira/`: a company-managed ITSM project `SANDBOX` on a made-up site, with
the template's Incident fields, workflow, resolutions and queues. The fake pages
every paged answer two items at a time, whatever it is asked for, as Jira may,
and refuses anything that is not a read. A few tests start a real `jira-as`
stand-in, or ask the real `jira-as` to describe the operations offline, or run
the module on an older Python.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from grafana_jsm_sandbox import skill_template
from grafana_jsm_sandbox.configure import (
    ADMIN_REQUESTS,
    COMPONENT,
    FACT_VARIABLES,
    SITE_FACTS_MARKER,
    SITE_FIELDS,
    create_component_command,
    main,
)
from grafana_jsm_sandbox.demo_config import read_env_file
from tests.conftest import FIXTURES, REPOSITORY

JIRA_FIXTURES = FIXTURES / "jira"

KEY = "SANDBOX"
SITE = "https://sandbox.example.invalid"

TOKEN = "the-token-in-dot-env-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
OAUTH_TOKEN = "sk-ant-oat01-an-anthropic-oauth-token-that-must-never-be-printed"

ENV_FILE = f"""\
# The real Jira credential.
JIRA_SITE_URL={SITE}
JIRA_EMAIL=ops@example.invalid
JIRA_API_TOKEN={TOKEN}
CLAUDE_CODE_OAUTH_TOKEN={OAUTH_TOKEN}

# The dedicated project.
DEMO_PROJECT_KEY={KEY}

# Its field ids and queue, which configure reads off it.
DEMO_SEVERITY_FIELD=
DEMO_URGENCY_FIELD=
DEMO_SOURCE_FIELD=
DEMO_MAJOR_INCIDENT_FIELD=
DEMO_QUEUE_URL=
"""
"""A `.env` as an engineer has it after `cp .env.example .env` and filling in the top."""

FOUND = {
    "DEMO_SEVERITY_FIELD": "customfield_10040",
    "DEMO_URGENCY_FIELD": "customfield_10041",
    "DEMO_SOURCE_FIELD": "customfield_10042",
    "DEMO_MAJOR_INCIDENT_FIELD": "customfield_10044",
    "DEMO_QUEUE_URL": f"{SITE}/jira/servicedesk/projects/{KEY}/queues/custom/32",
}
"""What the fixtures' project says, as `.env` values."""

ANSWERS = {
    "getProject": "project.json",
    "getMyPermissions": "permissions.json",
    "getProjectComponents": "components.json",
    "getCreateIssueMetaIssueTypes": "createmeta-issuetypes.json",
    "getCreateIssueMetaIssueTypeId": "createmeta-incident-fields.json",
    "getAllStatuses": "statuses.json",
    "searchResolutions": "resolutions.json",
    "getServiceDeskById": "servicedesk.json",
    "getServiceDesks": "servicedesks.json",
    "getQueues": "queues.json",
}
"""Each read `configure` makes, and the fixture that answers it."""

READS = {*ANSWERS, "getServerInfo"}
"""Every operation the fake answers. Anything else, a write above all, fails the test."""

STEP_11_ANCHORS = {
    "jira-admin-create-project",
    "jira-admin-incident-fields",
    "jira-admin-resolution-screen",
    "jira-admin-workflow-statuses",
    "jira-admin-permissions",
    "atlassian-org-admin-agent-licence",
    "atlassian-org-admin-api-tokens",
    "atlassian-org-admin-ip-allowlist",
    "claude-org-owner",
    "docker-admin",
}
"""The headings step 11 writes `docs/admin-requests.md` with. A request named here must be one."""

CHECK_LINE = re.compile(r"^(OK|WARN|FAIL) +([a-z ]+): (.+)$")
ENV_LINE = re.compile(
    r"^\.env: (up to date|\d+ change\(s\) (planned|written); .+"
    r"|not checked: [A-Z_]+(, [A-Z_]+)*; left as \.env has them)$"
)
DIFF_LINE = re.compile(r"^[-+] DEMO_[A-Z_]+=.*$")
END_LINE = re.compile(r"^(READY|NOT READY: [a-z ]+: .+)$")
ASK = re.compile(rf"{re.escape(ADMIN_REQUESTS)}#([a-z0-9-]+)")
"""The documented line format, which the setup skill parses."""


@dataclass(frozen=True)
class Paging:
    """How one paged operation pages: where its items are, and its start and size flags."""

    items: str
    start: str
    size: str
    last: str | None = None

    def page(self, body: dict, flags: dict[str, str], cap: int) -> dict:
        assert self.start in flags and self.size in flags, f"not paged: {flags}"
        start = int(flags[self.start])
        size = min(int(flags[self.size]), cap)
        every = body[self.items]
        page = {**body, self.items: every[start : start + size]}
        if self.last is None:
            page |= {"startAt": start, "maxResults": size, "total": len(every)}
        else:
            page[self.last] = start + size >= len(every)
            page.pop("total", None)
        return page


PAGED = {
    "getCreateIssueMetaIssueTypes": Paging("issueTypes", "--start-at", "--max-results"),
    "getCreateIssueMetaIssueTypeId": Paging("fields", "--start-at", "--max-results"),
    "searchResolutions": Paging("values", "--start-at", "--max-results", "isLast"),
    "getServiceDesks": Paging("values", "--start", "--limit", "isLastPage"),
    "getQueues": Paging("values", "--start", "--limit", "isLastPage"),
}
"""The fixtures' paged answers, and how the real API pages each: createmeta by `total`,
resolutions by `isLast`, the service desk's queues by `isLastPage`."""


@dataclass
class Refusal:
    """A call jira-as fails, as it does: one JSON object on stderr and a non-zero exit."""

    status: int | None
    messages: list[str]

    def raise_for(self, arguments: tuple[str, ...]) -> None:
        said = {"status": self.status, "messages": self.messages, "operation": arguments[2]}
        # The reset's `jira_as_with` words a failure this way, stderr and all.
        raise RuntimeError(f"jira-as {' '.join(arguments)} failed: {json.dumps(said)}")


def fixture_answers() -> dict[str, object]:
    return {
        operation: json.loads((JIRA_FIXTURES / name).read_text())
        for operation, name in ANSWERS.items()
    }


@dataclass
class FakeJira:
    """A stand-in for `jira-as` against the fixtures' project that only ever reads."""

    answers: dict[str, object] = field(default_factory=fixture_answers)
    open_incidents: list[dict] = field(default_factory=list)
    page_cap: int = 2
    paging: dict[str, Paging] = field(default_factory=lambda: dict(PAGED))
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(self, *arguments: str) -> str:
        self.calls.append(arguments)
        if arguments[:2] == ("search", "jql"):
            assert arguments[2].startswith(f'project = "{KEY}" AND issuetype = Incident')
            return json.dumps({"issues": self.open_incidents, "isLast": True})
        assert arguments[:2] == ("api", "call"), f"the fake does not answer {arguments}"
        operation = arguments[2]
        assert operation in READS, f"configure asked {operation}, which is not one of its reads"
        flags = dict(zip(arguments[3::2], arguments[4::2]))
        answer = self.answers[operation]
        if isinstance(answer, Refusal):
            answer.raise_for(arguments)
        if operation in self.paging:
            answer = self.paging[operation].page(answer, flags, self.page_cap)
        return json.dumps(answer)

    def asked(self, operation: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:3] == ("api", "call", operation)]

    def fields(self) -> list[dict]:
        return self.answers["getCreateIssueMetaIssueTypeId"]["fields"]

    def named(self, name: str) -> dict:
        return next(item for item in self.fields() if item["name"] == name)


@dataclass
class Said:
    """What one `configure` printed and how it exited."""

    code: int
    out: str
    err: str

    @property
    def lines(self) -> list[str]:
        return self.out.splitlines()

    def check(self, name: str) -> list[str]:
        """Every check line for `name`."""
        return [line for line in self.lines if (m := CHECK_LINE.match(line)) and m[2] == name]

    def level(self, name: str) -> str:
        levels = {CHECK_LINE.match(line)[1] for line in self.check(name)}
        assert len(levels) == 1, f"{name}: {self.check(name)}"
        return levels.pop()

    def asks(self) -> set[str]:
        return set(ASK.findall(self.out))


@pytest.fixture
def env_file(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv("JIRA_SITE_URL", raising=False)
    path = tmp_path / ".env"
    path.write_text(ENV_FILE)
    return path


@pytest.fixture
def configure(env_file, capsys):
    """Run `configure` against a fake, and read back what it printed."""

    def run(jira: FakeJira, *argv: str, path: Path = env_file) -> Said:
        code = main(list(argv), env_file=path, jira_as=jira)
        out, err = capsys.readouterr()
        return Said(code, out, err)

    return run


# --- A project that has everything ---


def test_a_project_with_everything_is_ready_and_says_so_check_by_check(configure, env_file):
    said = configure(FakeJira())

    assert said.code == 0, said.out
    assert said.lines[-1] == "READY"
    for name in (
        "project",
        "permissions",
        "issue type",
        "severity",
        "urgency",
        "source",
        "major incident",
        "create screen",
        "statuses",
        "resolution",
        "service desk",
        "queue",
        "component",
        "dedicated",
    ):
        assert said.level(name) == "OK", said.check(name)
    assert said.asks() == set()


def test_every_line_is_in_the_documented_format(configure):
    for jira in (
        FakeJira(),
        FakeJira(answers={**fixture_answers(), "searchResolutions": {"values": []}}),
        FakeJira(open_incidents=[{"key": "SANDBOX-1", "fields": {"labels": []}}]),
    ):
        said = configure(jira)
        for line in said.lines[:-1]:
            assert CHECK_LINE.match(line) or ENV_LINE.match(line) or DIFF_LINE.match(line), line
        assert END_LINE.match(said.lines[-1]), said.lines[-1]


def test_the_lines_of_a_queue_that_is_listed_or_checked_are_in_the_documented_format(
    configure, env_file
):
    ambiguous = FakeJira()
    rename_incidents(ambiguous)
    queue_named(ambiguous, "Problems")["jql"] = queue_named(ambiguous, "Open incidents")["jql"]
    none = FakeJira()
    rename_incidents(none, jql="assignee = currentUser()")
    for jira, hand_set in ((ambiguous, ""), (none, ""), (none, queue_address("99", key="OTHER"))):
        env_file.write_text(ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={hand_set}"))
        said = configure(jira)
        for line in said.lines[:-1]:
            assert CHECK_LINE.match(line) or ENV_LINE.match(line) or DIFF_LINE.match(line), line
        assert END_LINE.match(said.lines[-1]), said.lines[-1]


def test_by_default_it_prints_the_planned_diff_and_leaves_env_as_it_was(configure, env_file):
    before = env_file.read_bytes()

    said = configure(FakeJira())

    assert env_file.read_bytes() == before
    assert ".env: 5 change(s) planned; run again with --write to make them" in said.lines
    for name, value in FOUND.items():
        assert f"- {name}=" in said.lines
        assert f"+ {name}={value}" in said.lines


def test_with_write_env_holds_what_the_project_said(configure, env_file):
    said = configure(FakeJira(), "--write")

    assert said.code == 0
    assert any(line.startswith(".env: 5 change(s) written;") for line in said.lines)
    assert "docker compose up -d demo" in said.out
    values = read_env_file(env_file)
    assert {name: values[name] for name in FOUND} == FOUND


def test_a_second_run_after_write_finds_env_up_to_date(configure, env_file):
    configure(FakeJira(), "--write")
    written = env_file.read_bytes()

    said = configure(FakeJira(), "--write")

    assert ".env: up to date" in said.lines
    assert env_file.read_bytes() == written


# --- Field ids and their values, from the project's createmeta alone ---


def test_field_ids_come_from_the_project_s_create_metadata_and_never_the_site_s_fields(
    configure,
):
    jira = FakeJira()

    configure(jira)

    operations = {call[2] for call in jira.calls if call[:2] == ("api", "call")}
    assert "getFields" not in operations
    types_asked = jira.asked("getCreateIssueMetaIssueTypes")
    assert types_asked and all(call[3:5] == ("--project-id-or-key", KEY) for call in types_asked)
    fields_asked = jira.asked("getCreateIssueMetaIssueTypeId")
    assert fields_asked and all(
        call[3:7] == ("--project-id-or-key", KEY, "--issue-type-id", "10101")
        for call in fields_asked
    ), "the Incident type's own create screen, by the id the project gave"


def test_every_page_of_the_create_screen_is_read(configure):
    jira = FakeJira(page_cap=2)
    fields = jira.fields()
    assert [item["name"] for item in fields].index("Severity") >= 2, "Severity is past page one"

    said = configure(jira)

    assert len(jira.asked("getCreateIssueMetaIssueTypeId")) == -(-len(fields) // 2)
    assert said.check("severity") == [
        "OK   severity: customfield_10040, offering Sev-1, Sev-2, Sev-3"
    ]


def test_createmeta_pages_documented_as_results_are_read_too(configure):
    jira = FakeJira()
    body = jira.answers["getCreateIssueMetaIssueTypeId"]
    body["results"] = body.pop("fields")
    jira.paging["getCreateIssueMetaIssueTypeId"] = Paging("results", "--start-at", "--max-results")

    said = configure(jira)

    assert said.level("severity") == "OK"


def test_an_ambiguous_field_name_is_left_empty_and_warns_naming_the_admin_request(
    configure, env_file
):
    jira = FakeJira()
    twin = copy.deepcopy(jira.named("Severity")) | {
        "fieldId": "customfield_10099",
        "key": "customfield_10099",
    }
    jira.fields().append(twin)
    env_file.write_text(
        ENV_FILE.replace("DEMO_SEVERITY_FIELD=", "DEMO_SEVERITY_FIELD=customfield_10040")
    )

    said = configure(jira, "--write")

    (line,) = said.check("severity")
    assert line.startswith("WARN severity: 2 fields are named Severity")
    assert "customfield_10040, customfield_10099" in line
    assert line.endswith("; ask: docs/admin-requests.md#jira-admin-incident-fields")
    assert read_env_file(env_file)["DEMO_SEVERITY_FIELD"] == ""
    assert said.code == 0, "the demo runs, its Incidents only lack the field"
    assert said.lines[-1] == "READY"


def test_a_missing_option_value_is_left_empty_and_warns_naming_the_admin_request(
    configure, env_file
):
    jira = FakeJira()
    urgency = jira.named("Urgency")
    urgency["allowedValues"] = [v for v in urgency["allowedValues"] if v["value"] != "Medium"]

    said = configure(jira, "--write")

    (line,) = said.check("urgency")
    assert line.startswith("WARN urgency: Urgency (customfield_10041) does not offer Medium")
    assert "DEMO_URGENCY_FIELD is left empty and a Run leaves Urgency off" in line
    assert "jira-admin-incident-fields" in said.asks()
    assert read_env_file(env_file)["DEMO_URGENCY_FIELD"] == ""
    assert read_env_file(env_file)["DEMO_SEVERITY_FIELD"] == "customfield_10040", "the rest stand"
    assert said.code == 0


def test_a_disabled_option_is_not_offered(configure):
    jira = FakeJira()
    for value in jira.named("Source")["allowedValues"]:
        if value["value"] == "Monitoring systems":
            value["disabled"] = True

    said = configure(jira)

    assert said.level("source") == "WARN"
    assert "does not offer Monitoring systems" in said.check("source")[0]


def test_a_field_the_project_lacks_is_empty_so_a_run_leaves_it_off(configure, env_file):
    jira = FakeJira()
    jira.fields().remove(jira.named("Source"))
    env_file.write_text(
        ENV_FILE.replace("DEMO_SOURCE_FIELD=", "DEMO_SOURCE_FIELD=customfield_10042")
    )

    said = configure(jira, "--write")

    (line,) = said.check("source")
    assert line.startswith("WARN source: no field named Source on the Incident create screen")
    assert "a Run leaves Source off" in line
    assert line.endswith("; ask: docs/admin-requests.md#jira-admin-incident-fields")
    assert said.code == 0 and said.lines[-1] == "READY"
    assert "- DEMO_SOURCE_FIELD=customfield_10042" in said.lines
    assert "+ DEMO_SOURCE_FIELD=" in said.lines
    assert read_env_file(env_file)["DEMO_SOURCE_FIELD"] == ""


def test_matching_is_by_exact_name(configure):
    jira = FakeJira()
    jira.named("Severity")["name"] = "severity"

    said = configure(jira)

    assert said.level("severity") == "WARN"


def test_a_field_named_like_ours_that_is_not_a_custom_field_is_not_taken(configure):
    jira = FakeJira()
    jira.named("Severity")["fieldId"] = "priority"

    said = configure(jira)

    assert "is priority, not a custom field" in said.check("severity")[0]


def test_no_major_incident_field_is_fine_because_a_run_never_touches_it(configure, env_file):
    jira = FakeJira()
    jira.fields().remove(jira.named("Major incident"))

    said = configure(jira, "--write")

    assert said.level("major incident") == "OK"
    assert said.code == 0
    assert read_env_file(env_file)["DEMO_MAJOR_INCIDENT_FIELD"] == ""


def test_two_major_incident_fields_leave_it_empty_with_a_warning_and_no_request(
    configure, env_file
):
    jira = FakeJira()
    jira.fields().append(
        copy.deepcopy(jira.named("Major incident")) | {"fieldId": "customfield_10098"}
    )
    env_file.write_text(
        ENV_FILE.replace(
            "DEMO_MAJOR_INCIDENT_FIELD=", "DEMO_MAJOR_INCIDENT_FIELD=customfield_10044"
        )
    )

    said = configure(jira)

    assert said.level("major incident") == "WARN"
    assert "+ DEMO_MAJOR_INCIDENT_FIELD=" in said.lines
    assert said.asks() == set()
    assert said.code == 0


def test_the_values_checked_are_the_values_the_skill_writes():
    for site_field in SITE_FIELDS:
        if not site_field.options:
            continue
        (rendered,) = [f for f in skill_template.FIELDS if f.name == site_field.name]
        assert rendered.example in site_field.options
        for option in site_field.options:
            assert f"`{option}`" in rendered.values, (site_field.name, option)
    assert {f.name for f in skill_template.FIELDS} <= {f.name for f in SITE_FIELDS}


# --- The create screen as a whole ---


@pytest.mark.parametrize(
    ("field_id", "said_lacking"),
    [("labels", "it lacks Labels"), ("description", "it lacks Description")],
)
def test_a_create_screen_without_labels_or_description_stops_every_create(
    configure, field_id, said_lacking
):
    jira = FakeJira()
    jira.answers["getCreateIssueMetaIssueTypeId"]["fields"] = [
        item for item in jira.fields() if item["fieldId"] != field_id
    ]

    said = configure(jira)

    (line,) = said.check("create screen")
    assert line.startswith("FAIL create screen:") and said_lacking in line
    assert line.endswith("#jira-admin-incident-fields")
    assert said.code == 1


def test_a_required_field_no_run_fills_stops_every_create(configure):
    jira = FakeJira()
    jira.named("Impact")["required"] = True

    said = configure(jira)

    assert (
        "it requires Impact (customfield_10043), which no Run fills"
        in said.check("create screen")[0]
    )
    assert said.code == 1


def test_a_required_field_with_a_default_or_a_run_fills_is_fine(configure):
    jira = FakeJira()
    jira.named("Impact").update(required=True, hasDefaultValue=True)
    jira.named("Severity")["required"] = True

    said = configure(jira)

    assert said.level("create screen") == "OK"


def test_a_required_component_is_filled_only_when_the_run_s_component_exists(configure):
    jira = FakeJira()
    jira.named("Components")["required"] = True
    assert configure(jira).level("create screen") == "FAIL"

    jira = FakeJira()
    jira.named("Components")["required"] = True
    jira.answers["getProjectComponents"] = [{"id": "10500", "name": COMPONENT}]
    assert configure(jira).level("create screen") == "OK"


def test_a_required_field_whose_option_is_missing_stops_every_create(configure):
    """Left empty, a required Severity would be left off by a Run, and the create refused."""
    jira = FakeJira()
    severity = jira.named("Severity")
    severity["required"] = True
    severity["allowedValues"] = severity["allowedValues"][:1]

    said = configure(jira)

    assert "it requires Severity (customfield_10040)" in said.check("create screen")[0]


# --- The project, the account, and what they allow ---


def test_a_project_jira_does_not_have_names_the_create_project_request_and_stops_there(
    configure, env_file
):
    jira = FakeJira()
    jira.answers["getProject"] = Refusal(404, ["No project could be found with key 'SANDBOX'."])
    before = env_file.read_bytes()

    said = configure(jira, "--write")

    (line,) = said.check("project")
    assert line.startswith(
        f"FAIL project: Jira has no project {KEY}, or the account in .env cannot"
    )
    assert said.asks() == {"jira-admin-create-project", "jira-admin-permissions"}
    assert [call[2] for call in jira.calls] == ["getProject"], "nothing else could help"
    assert ".env: up to date" not in said.lines, "nothing was compared"
    assert f".env: not checked: {', '.join(FACT_VARIABLES)}; left as .env has them" in said.lines
    assert env_file.read_bytes() == before
    assert said.code == 1
    assert said.lines[-1].startswith("NOT READY: project: Jira has no project")


def test_a_project_that_is_not_a_service_desk_is_refused(configure):
    jira = FakeJira()
    jira.answers["getProject"]["projectTypeKey"] = "software"

    said = configure(jira)

    assert said.check("project")[0].startswith(
        "FAIL project: SANDBOX is a software project, not a Jira Service Management one"
    )
    assert said.asks() == {"jira-admin-create-project"}
    assert said.code == 1


def test_a_team_managed_project_is_a_warning(configure):
    jira = FakeJira()
    jira.answers["getProject"]["style"] = "next-gen"

    said = configure(jira)

    assert said.level("project") == "WARN"
    assert said.code == 0


@pytest.mark.parametrize(
    ("refusal", "asked", "words"),
    [
        (
            Refusal(401, ["Unauthorized"]),
            {"atlassian-org-admin-api-tokens"},
            "refused the credential",
        ),
        (
            Refusal(403, ["The IP address has been rejected by the site's IP allowlist"]),
            {"atlassian-org-admin-ip-allowlist"},
            "IP allowlist refused this address",
        ),
        (
            Refusal(403, ["You do not have permission"]),
            {"jira-admin-permissions", "atlassian-org-admin-agent-licence"},
            "refused the account in .env",
        ),
        (
            Refusal(503, ["HTTP transport failed: ConnectionError"]),
            set(),
            "could not reach JIRA_SITE_URL",
        ),
    ],
)
def test_a_refused_first_call_is_classified_and_stops_there(configure, refusal, asked, words):
    jira = FakeJira()
    jira.answers["getProject"] = refusal

    said = configure(jira)

    (line,) = said.check("project")
    assert line.startswith("FAIL project:") and words in line
    assert said.asks() == asked
    assert len(jira.calls) == 1
    assert said.code == 1


def test_missing_permissions_name_the_permissions_and_licence_requests(configure):
    jira = FakeJira()
    for name in ("TRANSITION_ISSUES", "RESOLVE_ISSUES"):
        jira.answers["getMyPermissions"]["permissions"][name]["havePermission"] = False
    del jira.answers["getMyPermissions"]["permissions"]["ADD_COMMENTS"]

    said = configure(jira)

    (line,) = said.check("permissions")
    assert "lacks TRANSITION_ISSUES, RESOLVE_ISSUES, ADD_COMMENTS on SANDBOX" in line
    assert said.asks() == {"jira-admin-permissions", "atlassian-org-admin-agent-licence"}
    assert said.code == 1


def test_permissions_are_asked_for_the_project_by_key(configure):
    jira = FakeJira()

    configure(jira)

    ((*_, key_flag, key, permissions_flag, permissions),) = jira.asked("getMyPermissions")
    assert (key_flag, key, permissions_flag) == ("--project-key", KEY, "--permissions")
    assert set(permissions.split(",")) >= {
        "BROWSE_PROJECTS",
        "CREATE_ISSUES",
        "EDIT_ISSUES",
        "TRANSITION_ISSUES",
        "RESOLVE_ISSUES",
        "CLOSE_ISSUES",
        "ADD_COMMENTS",
    }


def test_optional_permissions_only_warn(configure):
    jira = FakeJira()
    for name in ("ADMINISTER_PROJECTS", "DELETE_ISSUES"):
        jira.answers["getMyPermissions"]["permissions"][name]["havePermission"] = False

    said = configure(jira)

    lines = said.check("permissions")
    assert lines[0].startswith("OK   permissions:")
    assert [line.split(":")[0] for line in lines[1:]] == ["WARN permissions"] * 2
    assert said.code == 0


def test_a_project_without_an_incident_issue_type_names_the_create_project_request(configure):
    jira = FakeJira()
    body = jira.answers["getCreateIssueMetaIssueTypes"]
    body["issueTypes"] = [kind for kind in body["issueTypes"] if kind["name"] != "Incident"]
    body["total"] = len(body["issueTypes"])

    said = configure(jira)

    (line,) = said.check("issue type")
    assert line.startswith("FAIL issue type: SANDBOX offers no Incident issue type")
    assert "Service request" in line
    assert jira.asked("getCreateIssueMetaIssueTypeId") == []
    assert said.code == 1


# --- The workflow, the resolution, the queue ---


def incident_statuses(jira: FakeJira) -> list[dict]:
    return next(kind for kind in jira.answers["getAllStatuses"] if kind["name"] == "Incident")[
        "statuses"
    ]


def test_a_workflow_without_a_status_a_run_uses_names_the_workflow_request(configure):
    jira = FakeJira()
    statuses = incident_statuses(jira)
    statuses[:] = [
        status for status in statuses if status["statusCategory"]["key"] != "indeterminate"
    ]

    said = configure(jira)

    (line,) = said.check("statuses")
    assert line.startswith("FAIL statuses:") and "it lacks Work in progress" in line
    assert said.asks() == {"jira-admin-workflow-statuses"}


def test_completed_outside_the_done_category_is_a_workflow_problem(configure):
    jira = FakeJira()
    completed = next(status for status in incident_statuses(jira) if status["name"] == "Completed")
    completed["statusCategory"] = {"key": "indeterminate"}

    said = configure(jira)

    assert "Completed is not in the Done category" in said.check("statuses")[0]


def test_the_statuses_are_the_incident_type_s_not_another_s(configure):
    jira = FakeJira()
    request = next(
        kind for kind in jira.answers["getAllStatuses"] if kind["name"] == "Service request"
    )
    request["statuses"] = incident_statuses(jira)
    incident_statuses(jira).clear()

    said = configure(jira)

    assert said.level("statuses") == "FAIL"


def test_a_site_without_the_done_resolution_names_the_resolution_request(configure):
    jira = FakeJira()
    body = jira.answers["searchResolutions"]
    body["values"] = [value for value in body["values"] if value["name"] != "Done"]

    said = configure(jira)

    (line,) = said.check("resolution")
    assert line.startswith("FAIL resolution: the site has no resolution named Done")
    assert said.asks() == {"jira-admin-resolution-screen"}


def test_the_done_resolution_on_a_later_page_is_found(configure):
    jira = FakeJira(page_cap=1)
    body = jira.answers["searchResolutions"]
    body["values"].append(body["values"].pop(0))

    said = configure(jira)

    assert said.level("resolution") == "OK"
    assert len(jira.asked("searchResolutions")) == len(body["values"])


def test_the_queue_url_is_the_site_the_key_and_the_incidents_queue_s_id(configure):
    jira = FakeJira(page_cap=2)

    said = configure(jira)

    assert said.check("queue") == [f"OK   queue: {FOUND['DEMO_QUEUE_URL']}"]
    assert said.check("service desk") == ["OK   service desk: SANDBOX is service desk 7"]
    (desk,) = jira.asked("getServiceDeskById")
    assert desk[3:] == ("--service-desk-id", KEY)
    assert all(call[3:5] == ("--service-desk-id", "7") for call in jira.asked("getQueues"))
    assert len(jira.asked("getQueues")) == 3, "every page, two queues at a time"


def test_a_site_url_with_a_path_or_a_trailing_slash_still_gives_the_queue_s_address(
    configure, env_file
):
    env_file.write_text(ENV_FILE.replace(f"JIRA_SITE_URL={SITE}", f"JIRA_SITE_URL={SITE}/"))

    said = configure(FakeJira())

    assert f"+ DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}" in said.lines


def test_through_the_api_gateway_the_queue_s_address_is_the_site_s_own(configure, env_file):
    gateway = "https://api.atlassian.com/ex/jira/00000000-0000-0000-0000-000000000000"
    env_file.write_text(ENV_FILE.replace(f"JIRA_SITE_URL={SITE}", f"JIRA_SITE_URL={gateway}"))
    jira = FakeJira()
    jira.answers["getServerInfo"] = {"baseUrl": SITE + "/"}

    said = configure(jira)

    assert said.check("queue") == [f"OK   queue: {FOUND['DEMO_QUEUE_URL']}"]


def queue_named(jira: FakeJira, name: str) -> dict:
    """The fixture's queue with this name."""
    return next(queue for queue in jira.answers["getQueues"]["values"] if queue["name"] == name)


def rename_incidents(jira: FakeJira, name: str = "Open incidents", jql: str | None = None) -> dict:
    """The Incidents queue under another name, and with another JQL when one is given."""
    queue = queue_named(jira, "Incidents")
    queue["name"] = name
    if jql is not None:
        queue["jql"] = jql
    return queue


def queue_address(queue_id: str, key: str = KEY, site: str = SITE) -> str:
    return f"{site}/jira/servicedesk/projects/{key}/queues/custom/{queue_id}"


def test_a_queue_with_another_name_that_shows_the_open_incidents_is_chosen(configure, env_file):
    jira = FakeJira()
    rename_incidents(jira)

    said = configure(jira, "--write")

    (line,) = said.check("queue")
    assert line.startswith(f"OK   queue: {FOUND['DEMO_QUEUE_URL']} (")
    assert 'the queue "Open incidents"' in line and "no queue is named Incidents" in line
    assert "the only one whose JQL shows SANDBOX's open Incidents" in line
    assert f"+ DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}" in said.lines
    assert read_env_file(env_file)["DEMO_QUEUE_URL"] == FOUND["DEMO_QUEUE_URL"]
    assert said.code == 0


@pytest.mark.parametrize(
    "jql",
    [
        'project = "SANDBOX" AND issuetype = "Incident" AND resolution = Unresolved',
        "project in (SANDBOX) and type = Incident and resolution is EMPTY order by created desc",
        "project = 10042 AND issuetype = Incident AND resolution = Unresolved",
        "issuetype in (Incident) && resolution = EMPTY && project = SANDBOX ORDER BY rank",
        "project = SANDBOX AND issuetype = Incident AND resolution = Unresolved",
    ],
)
def test_every_way_jql_says_the_open_incidents_is_a_queue_that_is_chosen(configure, jql):
    jira = FakeJira()
    rename_incidents(jira, jql=jql)

    said = configure(jira)

    assert said.level("queue") == "OK"
    assert f"+ DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}" in said.lines


def test_a_queue_of_every_open_issue_is_not_taken_for_the_incidents_queue(configure):
    """The fixture's `All open` names the project and the resolution, and shows Service
    requests too: only the one that also names Incident is the choice."""
    jira = FakeJira()
    rename_incidents(jira)

    configure(jira)

    all_open = queue_named(jira, "All open")
    assert "issuetype" not in all_open["jql"] and "resolution = Unresolved" in all_open["jql"]
    assert f"+ DEMO_QUEUE_URL={queue_address('30')}" not in configure(jira).lines


OPEN_INCIDENTS = "project = SANDBOX AND issuetype = Incident AND resolution = Unresolved"


@pytest.mark.parametrize(
    "jql",
    [
        f"{OPEN_INCIDENTS} AND assignee = currentUser()",
        f"{OPEN_INCIDENTS} AND status != Closed",
        "project = SANDBOX AND (issuetype = Incident OR issuetype = Problem) AND resolution = Unresolved",
        "project = SANDBOX AND issuetype = Incident OR resolution = Unresolved",
        "project = OTHER AND issuetype = Incident AND resolution = Unresolved",
        "project = SANDBOX AND issuetype = Incident",
        "issuetype = Incident AND resolution = Unresolved",
    ],
)
def test_jql_that_is_not_exactly_the_open_incidents_is_not_chosen(configure, jql):
    jira = FakeJira()
    rename_incidents(jira, jql=jql)

    said = configure(jira)

    assert said.level("queue") == "WARN"
    assert not any("DEMO_QUEUE_URL" in line for line in said.lines if DIFF_LINE.match(line))
    assert said.check("queue")[0].startswith("WARN queue: no queue is named Incidents on SANDBOX")


def test_two_queues_that_show_the_open_incidents_are_listed_and_none_is_chosen(configure):
    jira = FakeJira()
    rename_incidents(jira)
    queue_named(jira, "Problems")["jql"] = (
        'project = "SANDBOX" AND issuetype = Incident AND resolution = Unresolved'
    )

    said = configure(jira, "--write")

    summary, *candidates = said.check("queue")
    assert summary.startswith(
        "WARN queue: no queue is named Incidents on SANDBOX, and 2 queues have JQL that shows "
        "its open Incidents, so DEMO_QUEUE_URL is left as it is; "
    )
    assert "to choose one, set DEMO_QUEUE_URL in .env to its address (listed below)" in summary
    assert "run python3 -m grafana_jsm_sandbox.configure again to check it" in summary
    listed = {
        line.split('"')[1]: line for line in candidates if line.startswith("WARN queue: candidate ")
    }
    assert set(listed) == {"Open incidents", "Problems", "All open"}
    assert (
        f"(id 32): {queue_address('32')}; JQL: project = SANDBOX AND issuetype"
        in (listed["Open incidents"])
    )
    assert f"(id 34): {queue_address('34')};" in listed["Problems"]
    assert "Assigned to me" not in said.out and "Service requests" not in said.out
    assert not any("DEMO_QUEUE_URL" in line for line in said.lines if DIFF_LINE.match(line))
    assert ".env: not checked: DEMO_QUEUE_URL" in said.out
    assert said.code == 0


def test_a_queue_that_could_show_the_incidents_is_a_candidate_though_none_is_chosen(configure):
    jira = FakeJira()
    rename_incidents(jira, jql="project = SANDBOX AND issuetype = Incident ORDER BY created")

    said = configure(jira)

    summary, *candidates = said.check("queue")
    assert "none has JQL that shows exactly its open Incidents" in summary
    assert "issuetype = Incident and resolution = Unresolved" in summary
    assert [line.split('"')[1] for line in candidates] == ["All open", "Open incidents"]


def test_no_queue_that_could_show_the_incidents_says_how_to_make_one(configure):
    jira = FakeJira()
    rename_incidents(jira, jql="assignee = currentUser()")
    for queue in jira.answers["getQueues"]["values"]:
        queue["jql"] = queue["jql"].replace("resolution = Unresolved", "assignee = currentUser()")

    said = configure(jira)

    (line,) = said.check("queue")
    assert line.startswith("WARN queue: no queue is named Incidents on SANDBOX, and none has JQL")
    assert "open SANDBOX's Queues, click the one that shows its open Incidents" in line
    assert "or make a queue with the JQL: project = SANDBOX AND issuetype = Incident AND" in line
    assert "resolution = Unresolved ORDER BY created DESC" in line


def test_two_queues_named_incidents_are_chosen_between_by_their_jql(configure):
    jira = FakeJira()
    jira.answers["getQueues"]["values"].append(
        {**queue_named(jira, "Incidents"), "id": "35", "jql": "project = SANDBOX"}
    )

    said = configure(jira)

    (line,) = said.check("queue")
    assert line == (
        f'OK   queue: {FOUND["DEMO_QUEUE_URL"]} (the queue "Incidents": 2 queues are named '
        "Incidents, and it is the only one of them whose JQL shows SANDBOX's open Incidents)"
    )
    assert "no queue is named" not in line, "two queues are named Incidents"


def test_a_queue_chosen_when_none_is_named_incidents_says_so(configure):
    jira = FakeJira()
    rename_incidents(jira)

    said = configure(jira)

    (line,) = said.check("queue")
    assert line == (
        f'OK   queue: {FOUND["DEMO_QUEUE_URL"]} (the queue "Open incidents": no queue is named '
        "Incidents, and it is the only one whose JQL shows SANDBOX's open Incidents)"
    )


def test_two_queues_named_incidents_that_both_show_them_are_listed(configure):
    jira = FakeJira()
    jira.answers["getQueues"]["values"].append({**queue_named(jira, "Incidents"), "id": "35"})

    said = configure(jira)

    summary, *candidates = said.check("queue")
    assert summary.startswith("WARN queue: 2 queues are named Incidents on SANDBOX, and 2 of them")
    assert len(candidates) == 2 and all("candidate" in line for line in candidates)
    assert not any("DEMO_QUEUE_URL" in line for line in said.lines if DIFF_LINE.match(line))


def test_the_candidates_carry_ids_when_the_site_s_address_cannot_be_read(configure, env_file):
    gateway = "https://api.atlassian.com/ex/jira/00000000-0000-0000-0000-000000000000"
    env_file.write_text(ENV_FILE.replace(f"JIRA_SITE_URL={SITE}", f"JIRA_SITE_URL={gateway}"))
    jira = FakeJira()
    rename_incidents(jira)
    queue_named(jira, "Problems")["jql"] = queue_named(jira, "Open incidents")["jql"]
    jira.answers["getServerInfo"] = Refusal(500, ["Internal server error"])

    said = configure(jira)

    candidate = next(line for line in said.check("queue") if '"Problems"' in line)
    assert "queue 34 (the site's address could not be read: Internal server error)" in candidate


def test_a_hand_set_queue_of_the_project_that_empties_is_all_the_demo_needs(configure, env_file):
    jira = FakeJira()
    rename_incidents(jira, jql="project = SANDBOX AND issuetype = Incident")
    env_file.write_text(
        ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={queue_address('30')}")
    )

    said = configure(jira, "--write")

    (line,) = said.check("queue")
    assert line == (
        'OK   queue: DEMO_QUEUE_URL is the queue "All open" of SANDBOX\'s service desk, and it '
        "filters on resolution = Unresolved"
    )
    assert read_env_file(env_file)["DEMO_QUEUE_URL"] == queue_address("30")
    assert not [line for line in said.lines if line.startswith(".env: not checked")], (
        "the queue check just said it is the project's own queue"
    )
    assert said.code == 0


def test_a_hand_set_queue_that_keeps_resolved_incidents_is_a_warning_with_the_candidates(
    configure, env_file
):
    jira = FakeJira()
    rename_incidents(jira, jql="project = SANDBOX AND issuetype = Incident")
    env_file.write_text(
        ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={queue_address('32')}")
    )

    said = configure(jira)

    first, summary, *_ = said.check("queue")
    assert first.startswith(f"WARN queue: {queue_address('32')} does not filter on resolution")
    assert (
        "so a completed Incident stays in it: project = SANDBOX AND issuetype = Incident" in first
    )
    assert summary.startswith("WARN queue: no queue is named Incidents")
    assert said.code == 0


@pytest.mark.parametrize(
    ("address", "said"),
    [
        (queue_address("32", key="OTHER"), "is a queue of project OTHER, not of SANDBOX"),
        (queue_address("32", key="sandbox2"), "is a queue of project sandbox2, not of SANDBOX"),
        (queue_address("99"), "names queue 99, which SANDBOX's service desk does not have"),
        (
            queue_address("32", site="https://work.example.invalid"),
            "is on work.example.invalid, not on the demo's site sandbox.example.invalid",
        ),
    ],
)
def test_a_hand_set_queue_that_is_not_the_project_s_fails_validation(
    configure, env_file, address, said
):
    jira = FakeJira()
    rename_incidents(jira, jql="assignee = currentUser()")
    env_file.write_text(ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={address}"))

    out = configure(jira, "--write")

    (line, *_) = out.check("queue")
    assert line.startswith("FAIL queue: DEMO_QUEUE_URL ") and said in line
    assert out.lines[-1].startswith("NOT READY: queue: ") and out.code == 1
    assert read_env_file(env_file)["DEMO_QUEUE_URL"] == address, (
        "a wrong address is left, not guessed"
    )


def test_a_hand_set_address_that_is_no_queue_s_is_not_checked_and_only_warns(configure, env_file):
    jira = FakeJira()
    rename_incidents(jira, jql="assignee = currentUser()")
    env_file.write_text(
        ENV_FILE.replace(
            "DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={SITE}/jira/servicedesk/projects/{KEY}"
        )
    )

    said = configure(jira)

    (line, *_) = said.check("queue")
    assert line.startswith("WARN queue: DEMO_QUEUE_URL is not shaped like <site>/jira/servicedesk/")
    assert "so it was not checked against SANDBOX's queues" in line and said.code == 0


def test_a_wrong_hand_set_queue_is_only_a_warning_when_this_run_replaces_it(configure, env_file):
    other = queue_address("32", key="OTHER")
    env_file.write_text(ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={other}"))

    said = configure(FakeJira(), "--write")

    wrong, chosen = said.check("queue")
    assert wrong.startswith(
        "WARN queue: DEMO_QUEUE_URL is a queue of project OTHER, not of SANDBOX"
    )
    assert wrong.endswith(f"configure --write replaces it with {FOUND['DEMO_QUEUE_URL']}")
    assert chosen == f"OK   queue: {FOUND['DEMO_QUEUE_URL']}"
    assert read_env_file(env_file)["DEMO_QUEUE_URL"] == FOUND["DEMO_QUEUE_URL"]
    assert said.code == 0


def test_a_valid_hand_set_queue_that_the_run_replaces_adds_no_line_of_its_own(configure, env_file):
    env_file.write_text(
        ENV_FILE.replace("DEMO_QUEUE_URL=", f"DEMO_QUEUE_URL={queue_address('30')}")
    )

    said = configure(FakeJira())

    assert said.check("queue") == [f"OK   queue: {FOUND['DEMO_QUEUE_URL']}"]
    assert f"- DEMO_QUEUE_URL={queue_address('30')}" in said.lines


def test_a_queue_that_does_not_filter_on_resolution_is_a_warning(configure):
    jira = FakeJira()
    for queue in jira.answers["getQueues"]["values"]:
        if queue["name"] == "Incidents":
            queue["jql"] = "project = SANDBOX AND issuetype = Incident"

    said = configure(jira)

    (line,) = said.check("queue")
    assert line.startswith("WARN queue:") and "resolution = Unresolved" in line
    assert f"+ DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}" in said.lines


@pytest.mark.parametrize(
    "filtered",
    [
        "resolution = Unresolved",
        "RESOLUTION=unresolved",
        "resolution is EMPTY",
        "resolution = EMPTY",
        "resolution IS null",
    ],
)
def test_every_way_jql_says_unresolved_is_a_queue_that_empties(configure, filtered):
    jira = FakeJira()
    for queue in jira.answers["getQueues"]["values"]:
        if queue["name"] == "Incidents":
            queue["jql"] = f"project = SANDBOX AND issuetype = Incident AND {filtered}"

    assert configure(jira).level("queue") == "OK"


@pytest.mark.parametrize("filtered", ["resolution is not EMPTY", "resolution != Unresolved"])
def test_a_queue_of_resolved_incidents_is_still_a_warning(configure, filtered):
    jira = FakeJira()
    for queue in jira.answers["getQueues"]["values"]:
        if queue["name"] == "Incidents":
            queue["jql"] = f"project = SANDBOX AND issuetype = Incident AND\n{filtered}"

    said = configure(jira)

    (line,) = said.check("queue")
    assert line.startswith("WARN queue:") and line.endswith(f"AND {filtered}")


def test_a_project_that_is_no_service_desk_to_the_account_names_the_request(configure):
    jira = FakeJira()
    jira.answers["getServiceDeskById"] = Refusal(404, ["Service Desk does not exist"])
    desks = jira.answers["getServiceDesks"]
    desks["values"] = [desk for desk in desks["values"] if desk["projectKey"] != KEY]

    said = configure(jira)

    (line,) = said.check("service desk")
    assert line.startswith("FAIL service desk: SANDBOX is not a service desk")
    assert {"jira-admin-create-project", "atlassian-org-admin-agent-licence"} <= said.asks()
    assert jira.asked("getServiceDesks"), "the desks the account sees were looked through first"
    assert jira.asked("getQueues") == []


@pytest.mark.parametrize("status", [404, 400])
@pytest.mark.parametrize("by", ["projectKey", "projectId"])
def test_a_site_that_takes_no_key_for_a_service_desk_id_finds_the_desk_in_the_list(
    configure, status, by
):
    jira = FakeJira(page_cap=1)
    jira.answers["getServiceDeskById"] = Refusal(status, ["Service Desk does not exist"])
    if by == "projectId":
        for desk in jira.answers["getServiceDesks"]["values"]:
            desk["projectKey"] = "ELSE"

    said = configure(jira)

    assert said.check("service desk") == ["OK   service desk: SANDBOX is service desk 7"]
    assert len(jira.asked("getServiceDesks")) == 3, "every page, one desk at a time"
    assert said.check("queue") == [f"OK   queue: {FOUND['DEMO_QUEUE_URL']}"]
    assert said.code == 0


def test_a_check_jira_refuses_fails_alone_and_the_rest_go_on(configure, env_file):
    jira = FakeJira()
    jira.answers["getAllStatuses"] = Refusal(500, ["Internal server error"])

    said = configure(jira, "--write")

    assert said.check("statuses") == ["FAIL statuses: Jira answered 500: Internal server error"]
    assert said.level("queue") == "OK"
    assert read_env_file(env_file)["DEMO_SEVERITY_FIELD"] == "customfield_10040"
    assert said.code == 1


def test_a_create_screen_jira_refuses_leaves_the_field_ids_as_they_are(configure, env_file):
    env_file.write_text(
        ENV_FILE.replace("DEMO_SEVERITY_FIELD=", "DEMO_SEVERITY_FIELD=customfield_1")
    )
    jira = FakeJira()
    jira.answers["getCreateIssueMetaIssueTypeId"] = Refusal(500, ["Internal server error"])

    said = configure(jira, "--write")

    assert said.level("create screen") == "FAIL"
    assert read_env_file(env_file)["DEMO_SEVERITY_FIELD"] == "customfield_1", "unknown is not empty"
    fields = ", ".join(site_field.variable for site_field in SITE_FIELDS)
    assert f".env: not checked: {fields}; left as .env has them" in said.lines
    assert ".env: 1 change(s) written;" in said.out, "the queue, which was checked, is written"


def test_a_multi_line_refusal_still_prints_one_line_per_check(configure):
    """A traceback, a usage error or an allowlist's HTML page is folded onto the line."""
    jira = FakeJira()
    jira.answers["getProject"] = Refusal(
        403,
        ["<html>\n<body>\n<p>Your IP address is not on the IP allowlist</p>\n" + "x" * 900],
    )

    said = configure(jira)

    assert len(said.lines) == 3, said.lines
    (line,) = said.check("project")
    assert "IP allowlist refused this address" in line and len(line) < 600
    assert line.endswith("...; ask: docs/admin-requests.md#atlassian-org-admin-ip-allowlist")
    assert END_LINE.match(said.lines[-1])


def test_an_allowlist_page_is_read_in_full_before_the_line_is_cut(configure):
    """Its words can sit well past what a line keeps, behind a page's head and style."""
    jira = FakeJira()
    head = "<html><head><style>" + "body { margin: 0; padding: 0 } " * 20 + "</style></head>"
    jira.answers["getProject"] = Refusal(
        403, [f"Failed to getProject: {head}<body>Your IP address has been rejected</body>"]
    )

    said = configure(jira)

    assert len(head) > 300
    (line,) = said.check("project")
    assert line.endswith("; ask: docs/admin-requests.md#atlassian-org-admin-ip-allowlist"), line


def test_a_refusal_with_no_json_is_folded_onto_one_line_with_a_next_step(configure):
    """A jira-as that crashed, or no longer knows a flag, says so in no JSON at all."""
    jira = FakeJira()

    def crashing(*arguments: str) -> str:
        if arguments[:3] == ("api", "call", "getAllStatuses"):
            raise RuntimeError(
                f"jira-as {' '.join(arguments)} failed: Traceback (most recent call last):\n"
                "  File \"x\", line 1\nKeyError: 'statuses'"
            )
        return jira(*arguments)

    said = configure(crashing)

    (line,) = said.check("statuses")
    assert line.startswith("FAIL statuses: jira-as refused the call: jira-as api call")
    assert 'Traceback (most recent call last): File "x", line 1 KeyError' in line
    assert line.endswith(
        "check that `jira-as --version` is 2.0.x and that .env's DEMO_PROJECT_KEY is the "
        "project you mean (README, What you need)"
    )
    for text in said.lines[:-1]:
        assert CHECK_LINE.match(text) or ENV_LINE.match(text) or DIFF_LINE.match(text), text
    assert said.lines[-1].startswith("NOT READY: statuses: jira-as refused the call")
    assert END_LINE.match(said.lines[-1])


# --- The optional component, and whether the project is the demo's alone ---


def test_no_component_prints_the_command_and_runs_nothing(configure):
    jira = FakeJira()

    said = configure(jira)

    (line,) = said.check("component")
    assert line.startswith("OK   component: no rolldice component")
    assert "project's settings, Components" in line
    assert line.endswith(create_component_command(KEY, SITE))
    assert create_component_command(KEY, SITE) == (
        f"JIRA_SITE_URL={SITE} JIRA_ALLOWED_PROJECTS=SANDBOX jira-as api call createComponent "
        "--project SANDBOX --field name=rolldice --field project=SANDBOX"
    ), "pinned to .env's site and key, whatever the engineer's own jira-as points at"
    assert "JIRA_EMAIL" not in line and "JIRA_API_TOKEN" not in line and TOKEN not in line
    assert not any("createComponent" in " ".join(call) for call in jira.calls)
    assert said.code == 0


def test_an_existing_component_is_ok(configure):
    jira = FakeJira()
    jira.answers["getProjectComponents"] = [{"id": "10500", "name": COMPONENT}]

    said = configure(jira)

    assert said.check("component") == ["OK   component: rolldice exists, so a Run sets it"]


def test_open_incidents_without_a_fingerprint_label_say_the_project_is_not_dedicated(configure):
    jira = FakeJira()
    jira.open_incidents = [
        {"key": f"SANDBOX-{n}", "fields": {"labels": ["customer-reported"]}} for n in range(1, 8)
    ] + [{"key": "SANDBOX-20", "fields": {"labels": ["fp-87e2f184874a3b71"]}}]

    said = configure(jira)

    (line,) = said.check("dedicated")
    assert line.startswith("WARN dedicated: SANDBOX doesn't look dedicated to the demo")
    assert "7 open Incident(s) carry no fp- label" in line
    assert "SANDBOX-1, SANDBOX-2, SANDBOX-3, SANDBOX-4, SANDBOX-5 and 2 more" in line
    assert "SANDBOX-20" not in line
    assert said.code == 0


def test_only_a_run_s_open_incidents_is_dedicated(configure):
    jira = FakeJira()
    jira.open_incidents = [{"key": "SANDBOX-20", "fields": {"labels": ["fp-87e2f184874a3b71"]}}]

    assert configure(jira).level("dedicated") == "OK"


@pytest.mark.parametrize(
    "answer", ["not json", json.dumps({"issues": [{"key": "SANDBOX-1"}], "isLast": True})]
)
def test_a_search_answer_it_cannot_read_is_a_fail_line_not_a_traceback(configure, answer):
    jira = FakeJira()

    def searching(*arguments: str) -> str:
        return answer if arguments[:2] == ("search", "jql") else jira(*arguments)

    said = configure(searching)

    (line,) = said.check("dedicated")
    assert line.startswith("FAIL dedicated: jira-as refused the call: search jql answered")
    assert said.code == 1


# --- It only reads ---


def test_it_never_asks_jira_anything_but_its_reads(configure):
    """The fake refuses any operation outside `READS`; this runs every path to its end."""
    jira = FakeJira()
    jira.open_incidents = [{"key": "SANDBOX-1", "fields": {"labels": []}}]

    configure(jira, "--write")

    for call in jira.calls:
        assert call[:2] in {("api", "call"), ("search", "jql")}, call
        assert "--confirm" not in call


@pytest.fixture
def real_jira_as() -> str:
    found = shutil.which("jira-as")
    if found is None:
        pytest.skip("jira-as is not on PATH")
    return found


def test_every_operation_it_calls_is_a_safe_get_jira_as_describes_with_those_flags(
    configure, env_file, real_jira_as, tmp_path
):
    """Offline: `jira-as api describe` reads the operation index it ships, and needs no site."""
    env_file.write_text(
        ENV_FILE.replace(
            f"JIRA_SITE_URL={SITE}", "JIRA_SITE_URL=https://api.atlassian.com/ex/jira/x"
        )
    )
    jira = FakeJira()
    jira.answers["getServerInfo"] = {"baseUrl": SITE}
    jira.answers["getServiceDeskById"] = Refusal(404, ["asked, then looked up in the list"])
    configure(jira)
    used: dict[str, set[str]] = {}
    for call in jira.calls:
        if call[:2] == ("api", "call"):
            used.setdefault(call[2], set()).update(a for a in call[3:] if a.startswith("--"))
    assert set(used) == READS

    for operation, flags in used.items():
        described = subprocess.run(
            [real_jira_as, "api", "describe", operation],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert f"# {operation}\n" in described
        assert re.search(r"^GET `", described, re.MULTILINE), f"{operation} is not a GET"
        assert "- Risk: safe." in described, operation
        for flag in flags:
            assert f"`{flag}`" in described, f"{operation} has no {flag}"


# --- .env, edited in place ---


def test_write_changes_only_its_own_lines_and_keeps_every_other_byte(configure, env_file):
    text = (
        "# A comment an engineer wrote\n"
        f"JIRA_SITE_URL={SITE}\n"
        "JIRA_EMAIL=ops@example.invalid\n"
        f"JIRA_API_TOKEN='{TOKEN}'  # pasted from id.atlassian.com\n"
        f'CLAUDE_CODE_OAUTH_TOKEN="{OAUTH_TOKEN}"\n'
        "\n"
        "DEMO_PROJECT_KEY=SANDBOX\n"
        "  export DEMO_SEVERITY_FIELD=customfield_1 # was the old site's\n"
        "DEMO_URGENCY_FIELD='customfield_2' # quoted\n"
        "# DEMO_SOURCE_FIELD=customfield_3\n"
        "RUN_MODEL=claude-opus-5\n"
    )
    env_file.write_text(text)
    env_file.chmod(0o600)

    configure(FakeJira(), "--write")

    lines = env_file.read_text().splitlines()
    before = text.splitlines()
    assert lines[:7] == before[:7], "the credential lines are untouched"
    assert lines[7] == "  export DEMO_SEVERITY_FIELD=customfield_10040 # was the old site's"
    assert lines[8] == "DEMO_URGENCY_FIELD=customfield_10041 # quoted"
    assert lines[9:11] == before[9:11], "a commented-out key is not a key"
    assert lines[11:] == [
        "",
        SITE_FACTS_MARKER,
        "DEMO_SOURCE_FIELD=customfield_10042",
        "DEMO_MAJOR_INCIDENT_FIELD=customfield_10044",
        f"DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}",
    ]
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert {name: read_env_file(env_file)[name] for name in FOUND} == FOUND
    assert [path.name for path in env_file.parent.iterdir()] == [".env"], "no temporary file left"


def test_a_key_missing_later_goes_into_the_block_it_went_into_before(configure, env_file):
    env_file.write_text(
        ENV_FILE.replace("DEMO_SOURCE_FIELD=\n", "").replace("DEMO_QUEUE_URL=\n", "")
    )
    configure(FakeJira(), "--write")
    queue_line = f"DEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}\n"
    first = env_file.read_text()
    assert first.endswith(
        f"\n\n{SITE_FACTS_MARKER}\nDEMO_SOURCE_FIELD=customfield_10042\n{queue_line}"
    )
    env_file.write_text(first.replace(queue_line, "") + "\n# mine\nMINE=1\n")

    configure(FakeJira(), "--write")

    text = env_file.read_text()
    assert text.count(SITE_FACTS_MARKER) == 1
    assert text.endswith(
        f"{SITE_FACTS_MARKER}\nDEMO_SOURCE_FIELD=customfield_10042\n{queue_line}\n# mine\nMINE=1\n"
    )


def test_crlf_line_endings_and_a_last_line_without_one_are_kept(configure, env_file):
    text = ENV_FILE.replace("DEMO_QUEUE_URL=\n", "").replace("\n", "\r\n").rstrip("\r\n")
    env_file.write_bytes(text.encode())

    configure(FakeJira(), "--write")

    written = env_file.read_bytes().decode()
    assert "\n" not in written.replace("\r\n", "")
    assert "DEMO_SEVERITY_FIELD=customfield_10040\r\n" in written
    assert written.endswith(f"{SITE_FACTS_MARKER}\r\nDEMO_QUEUE_URL={FOUND['DEMO_QUEUE_URL']}\r\n")


def test_a_key_set_twice_is_set_everywhere(configure, env_file):
    env_file.write_text(ENV_FILE + "DEMO_SEVERITY_FIELD=customfield_1\n")

    configure(FakeJira(), "--write")

    assert env_file.read_text().count("DEMO_SEVERITY_FIELD=customfield_10040\n") == 2


def test_write_refuses_without_an_env_file_and_says_how_to_make_one(configure, tmp_path):
    missing = tmp_path / "elsewhere" / ".env"
    jira = FakeJira()

    said = configure(jira, "--write", path=missing)

    assert said.code == 2
    assert "cp .env.example .env" in said.err
    assert not missing.exists()
    assert jira.calls == []


def test_a_malformed_old_field_id_does_not_stop_the_command_that_fixes_it(configure, env_file):
    env_file.write_text(ENV_FILE.replace("DEMO_SEVERITY_FIELD=", "DEMO_SEVERITY_FIELD=Severity"))

    said = configure(FakeJira(), "--write")

    assert said.code == 0
    assert "- DEMO_SEVERITY_FIELD=Severity" in said.lines
    assert read_env_file(env_file)["DEMO_SEVERITY_FIELD"] == "customfield_10040"


def test_a_missing_key_or_credential_is_a_configuration_error_before_jira_is_asked(
    configure, env_file
):
    for broken in (
        ENV_FILE.replace(f"DEMO_PROJECT_KEY={KEY}", "DEMO_PROJECT_KEY="),
        ENV_FILE.replace(f"JIRA_API_TOKEN={TOKEN}", "JIRA_API_TOKEN="),
    ):
        env_file.write_text(broken)
        jira = FakeJira()

        said = configure(jira, "--write")

        assert said.code == 2
        assert jira.calls == []
        assert env_file.read_text() == broken


def test_an_unknown_argument_is_a_usage_error(configure):
    with pytest.raises(SystemExit) as exit:
        configure(FakeJira(), "--yes")

    assert exit.value.code == 2


def test_help_documents_the_exit_statuses(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    said = " ".join(capsys.readouterr().out.split())
    assert (
        "0 READY" in said and "1 NOT READY" in said and "2 a usage or configuration error" in said
    )
    assert "READY is about the project: the .env line says whether .env holds what it said" in said


def test_ready_is_about_the_project_and_the_env_line_about_env(configure, env_file):
    """Without --write a ready project still ends READY; the .env line says .env lags it."""
    said = configure(FakeJira())

    assert said.code == 0 and said.lines[-1] == "READY"
    assert ".env: 5 change(s) planned; run again with --write to make them" in said.lines


# --- Never a secret ---


def test_no_secret_is_ever_printed(configure, env_file):
    jira = FakeJira()
    jira.answers["getAllStatuses"] = Refusal(
        500, [f"echoed Authorization: Basic {TOKEN}", f"token {OAUTH_TOKEN}"]
    )
    env_file.write_text(ENV_FILE.replace("DEMO_URGENCY_FIELD=", f"DEMO_URGENCY_FIELD={TOKEN}"))

    said = configure(jira, "--write")

    for secret in (TOKEN, OAUTH_TOKEN):
        assert secret not in said.out + said.err
    assert "<redacted>" in said.out
    assert f"JIRA_API_TOKEN={TOKEN}" in env_file.read_text(), "and the credential stays put"


# --- The real jira-as, and the real python3 ---

STAND_IN = """\
#!{python}
import json, os, pathlib, sys
with pathlib.Path({record!r}).open("a") as record:
    record.write(json.dumps({{"argv": sys.argv[1:], "environment": dict(os.environ)}}) + "\\n")
sys.stderr.write(json.dumps({{"status": 404, "messages": ["No project could be found"]}}) + "\\n")
sys.exit(5)
"""
"""A `jira-as` on PATH that records how it was started and answers as 2.0.0 does for a key
the site does not have: the JSON error object on stderr, and exit 5."""


def test_the_real_jira_as_is_started_from_env_and_its_refusal_is_read(
    env_file, tmp_path, monkeypatch, capsys
):
    record = tmp_path / "calls.jsonl"
    stand_in = tmp_path / "bin" / "jira-as"
    stand_in.parent.mkdir()
    stand_in.write_text(STAND_IN.format(python=sys.executable, record=str(record)))
    stand_in.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stand_in.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("JIRA_API_TOKEN", "the-token-for-production")
    monkeypatch.setenv("JIRA_ALLOWED_PROJECTS", "PROD")

    assert main([], env_file=env_file) == 1

    (call,) = [json.loads(line) for line in record.read_text().splitlines()]
    assert call["argv"] == ["api", "call", "getProject", "--project-id-or-key", KEY]
    assert call["environment"]["JIRA_SITE_URL"] == SITE
    assert call["environment"]["JIRA_API_TOKEN"] == TOKEN
    assert call["environment"]["JIRA_ALLOWED_PROJECTS"] == KEY
    assert call["environment"]["JIRA_ALLOW_SITE_OPERATIONS"] == "true"
    said = capsys.readouterr()
    assert "FAIL project: Jira has no project SANDBOX" in said.out
    assert TOKEN not in said.out + said.err


def test_a_session_id_the_label_could_not_carry_is_a_configuration_error(env_file, capsys):
    """Held to the same shape the Receiver holds it to, before Jira is asked anything."""
    env_file.write_text(ENV_FILE + "DEMO_SESSION_ID=Take One\n")

    assert main([], env_file=env_file, jira_as=FakeJira()) == 2

    assert "DEMO_SESSION_ID is not a session id" in capsys.readouterr().err


def test_no_jira_as_on_path_is_a_configuration_error(env_file, tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    assert main([], env_file=env_file) == 2

    assert "jira-as is not on PATH" in capsys.readouterr().err


def older_python() -> str | None:
    """A python3 older than 3.11 on this machine, such as macOS's own, or None."""
    for candidate in ("python3.10", "python3.9", "python3.8", "/usr/bin/python3"):
        path = shutil.which(candidate)
        if path is None:
            continue
        answer = subprocess.run(
            [path, "-c", "import sys; print(sys.version_info < (3, 11))"],
            capture_output=True,
            text=True,
            check=False,
        )
        if answer.stdout.strip() == "True":
            return path
    return None


def test_an_older_python_is_told_so_in_a_sentence_and_not_a_traceback():
    python = older_python()
    if python is None:
        pytest.skip("no python3 older than 3.11 here")

    answer = subprocess.run(
        [python, "-m", "grafana_jsm_sandbox.configure", "--write"],
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


# --- The fixtures and the requests it names ---


def test_every_admin_request_it_can_name_is_one_step_11_writes():
    source = (REPOSITORY / "grafana_jsm_sandbox" / "configure.py").read_text()
    named = set(
        re.findall(
            r'^[A-Z_]+ = "((?:jira-admin|atlassian-org-admin)[a-z-]+)"$', source, re.MULTILINE
        )
    )

    assert named and named <= STEP_11_ANCHORS


def test_the_jira_fixtures_carry_nothing_of_a_real_site():
    for path in sorted(JIRA_FIXTURES.glob("*.json")):
        text = path.read_text()
        json.loads(text)
        assert "atlassian.net" not in text, path.name
        assert "accountId" not in text, path.name
        assert all(
            address.endswith("@example.invalid")
            for address in re.findall(r"[\w.+-]*@[\w.-]+", text)
        )
        hosts = set(re.findall(r"https?://([^/\"]+)", text))
        assert hosts <= {"sandbox.example.invalid"}, (path.name, hosts)


def test_configure_writes_only_the_keys_it_documents():
    assert set(FACT_VARIABLES) == set(FOUND) | set(CUSTOM_ROLES)


CUSTOM_STATUSES = {
    "New": "new",
    "In Progress": "indeterminate",
    "Waiting for customer": "new",
    "Pending": "new",
    "Resolved": "done",
    "Canceled": "done",
}
"""A generic Incident workflow with global transitions and no close step."""

CUSTOM_ROLES = {
    "DEMO_STATUS_OPEN": "New",
    "DEMO_STATUS_IN_PROGRESS": "In Progress",
    "DEMO_STATUS_DONE": "Resolved",
    "DEMO_STATUS_CLOSED": "",
}
"""The roles configure should discover on that workflow."""


def custom_workflow(jira: FakeJira) -> None:
    incident_statuses(jira)[:] = [
        {"name": name, "statusCategory": {"key": category}}
        for name, category in CUSTOM_STATUSES.items()
    ]


def test_configure_plans_and_writes_the_custom_workflow(configure, env_file):
    jira = FakeJira()
    custom_workflow(jira)
    before = env_file.read_bytes()

    said = configure(jira)

    assert said.code == 0
    assert said.level("statuses") == "WARN"
    for name, value in CUSTOM_ROLES.items():
        assert f"+ {name}={value}" in said.lines
    assert env_file.read_bytes() == before

    said = configure(jira, "--write")

    assert said.code == 0
    assert {name: read_env_file(env_file)[name] for name in CUSTOM_ROLES} == CUSTOM_ROLES
    assert ".env: 9 change(s) written" in said.out
    assert ".env: up to date" in configure(jira).lines


def test_stock_workflow_keeps_default_roles_without_planning_changes(configure):
    said = configure(FakeJira())

    assert said.level("statuses") == "OK"
    assert not any(line.startswith("+ DEMO_STATUS_") for line in said.lines)


def test_configure_keeps_explicit_names_in_the_right_categories(configure, env_file):
    jira = FakeJira()
    custom_workflow(jira)
    roles = {**CUSTOM_ROLES, "DEMO_STATUS_OPEN": "Pending"}
    env_file.write_text(ENV_FILE + "".join(f"{name}={value}\n" for name, value in roles.items()))

    said = configure(jira)

    assert said.level("statuses") == "OK"
    assert not any(line.startswith("+ DEMO_STATUS_") for line in said.lines)


@pytest.mark.parametrize("name", ["Canceled", "Cancelled", "Declined", "Won't Do"])
def test_configure_fails_when_done_has_only_a_human_owned_status(configure, name):
    jira = FakeJira()
    custom_workflow(jira)
    statuses = incident_statuses(jira)
    statuses[:] = [status for status in statuses if status["statusCategory"]["key"] != "done"]
    statuses.append({"name": name, "statusCategory": {"key": "done"}})

    said = configure(jira)

    assert said.code == 1
    assert said.level("statuses") == "FAIL"
    assert "status_done: DEMO_STATUS_DONE" in said.out
    assert f"{name} (done)" in said.out
    assert "New (new)" in said.out
    assert "+ DEMO_STATUS_DONE=" not in said.out


def test_in_progress_discovery_uses_the_only_status_or_the_preferred_name(configure):
    jira = FakeJira()
    custom_workflow(jira)
    statuses = incident_statuses(jira)
    next(status for status in statuses if status["name"] == "In Progress")["name"] = "Investigating"
    assert "+ DEMO_STATUS_IN_PROGRESS=Investigating" in configure(jira).lines

    statuses.append({"name": "In Progress", "statusCategory": {"key": "indeterminate"}})
    assert "+ DEMO_STATUS_IN_PROGRESS=In Progress" in configure(jira).lines

    statuses[-1]["name"] = "Reviewing"
    said = configure(jira)
    assert said.code == 1
    assert "DEMO_STATUS_IN_PROGRESS" in said.check("statuses")[0]
