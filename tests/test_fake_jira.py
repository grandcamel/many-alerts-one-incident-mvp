"""The fake Jira: what it answers, and the real `jira-as` 2.0.0 driven against it.

The first part drives `FakeJira.handle` in-process: the JQL subset, create, the label
add, comments, the two workflows' transitions, the `custom` workflow's resolution
rejection and post-function, authentication, the state dump and the request log.

The second part starts the fake on a free localhost port and runs the real `jira-as`
CLI against it: every `jira-as` command line in the Skill as `skill_template.render`
renders it for each workflow, with the placeholders the Skill leaves to the Run filled
in, and every line `incident-payload` prints for the MVP's four Notifications, as
printed, through the whole create → add labels → comment → move → resolve sequence; then
`configure` against the fake, whose `.env` `verify --mvp --replay` then reads to watch a
scripted Run take the fake project through the MVP's lifecycle. Without `jira-as` on
PATH that part is skipped, with the reason, never failed.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest

from grafana_jsm_sandbox import configure, fake_jira, incident_payload, skill_template, verify
from grafana_jsm_sandbox.demo_config import (
    FIELD_VARIABLES,
    STATUS_VARIABLES,
    DemoProject,
    jira_as_environment,
    read_env_file,
)
from grafana_jsm_sandbox.fake_jira import (
    CUSTOM,
    ITSM,
    JIRA_TIME,
    SCREEN_REJECTION,
    WORKFLOWS,
    FakeJira,
    Server,
    Workflow,
)
from grafana_jsm_sandbox.investigation_contract import is_investigation
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.reset import jira_as_with
from grafana_jsm_sandbox.run_command import RENDERED_SKILL, SKILL_FILE
from grafana_jsm_sandbox.verify import World
from grafana_jsm_sandbox.verify_mvp import MVP_SEQUENCE, comment_text
from tests.conftest import FIXTURES, REPOSITORY
from tests.test_verify import FakeClock
from tests.test_verify_mvp import closing_of, description_of, opening_of, summary_of, update_of

KEY = "FAKE"
EMAIL = "rehearsal@example.invalid"
TOKEN = "not-a-real-token"
SESSION = "fake1"
GROUP = "checkout-outage"

TEMPLATE = (REPOSITORY / "skill" / SKILL_FILE).read_text(encoding="utf-8")

ADF = {
    "type": "doc",
    "version": 1,
    "content": [{"type": "paragraph", "content": [{"type": "text", "text": "hello"}]}],
}

SEARCH = "/rest/api/3/search/jql?jql="


def basic(email: str = EMAIL, token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()}


def match_jql(*labels: str, open_only: bool = True) -> str:
    """The Skill's Match search, for the labels given."""
    clauses = [
        f"project = {KEY}",
        "issuetype = Incident",
        *(f'labels = "{label}"' for label in labels),
    ]
    if open_only:
        clauses.append("statusCategory != Done")
    return " AND ".join(clauses)


class Client:
    """`FakeJira.handle` as a client would use it: one call per request, no socket."""

    def __init__(self, fake: FakeJira):
        self.fake = fake

    def __call__(self, method: str, path: str, body: object = None, headers: dict | None = None):
        headers = dict(basic()) if headers is None else dict(headers)
        data = b""
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        return self.fake.handle(method, path, headers, data)

    def ok(self, method: str, path: str, body: object = None):
        status, answer = self(method, path, body)
        assert status < 300, (method, path, status, answer)
        return answer

    def refused(self, method: str, path: str, body: object = None, status: int = 400) -> dict:
        got, answer = self(method, path, body)
        assert got == status, (method, path, got, answer)
        return answer

    def search(self, jql: str, **params: str) -> dict:
        query = "&".join(
            [f"jql={quote(jql)}", *(f"{name}={quote(value)}" for name, value in params.items())]
        )
        return self.ok("GET", f"/rest/api/3/search/jql?{query}")

    def keys(self, jql: str) -> list[str]:
        return [issue["key"] for issue in self.search(jql)["issues"]]

    def create(
        self, labels: list[str] | None = None, summary: str = "an incident", **fields
    ) -> str:
        body = {
            "fields": {
                "project": {"key": KEY},
                "issuetype": {"name": "Incident"},
                "summary": summary,
                "labels": labels or [],
                "description": ADF,
                **fields,
            }
        }
        return self.ok("POST", "/rest/api/3/issue", body)["key"]

    def issue(self, key: str, fields: str | None = None) -> dict:
        tail = f"?fields={fields}" if fields else ""
        return self.ok("GET", f"/rest/api/3/issue/{key}{tail}")["fields"]

    def transitions(self, key: str) -> dict[str, str]:
        """Transition id by the status it lands on."""
        answer = self.ok("GET", f"/rest/api/3/issue/{key}/transitions")["transitions"]
        return {transition["to"]["name"]: transition["id"] for transition in answer}

    def move(self, key: str, to: str, resolution: str | None = None) -> tuple[int, object]:
        body: dict = {"transition": {"id": self.transitions(key)[to]}}
        if resolution is not None:
            body["fields"] = {"resolution": {"name": resolution}}
        return self("POST", f"/rest/api/3/issue/{key}/transitions", body)

    def comment(self, key: str, text: str) -> dict:
        body = {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
        }
        return self.ok("POST", f"/rest/api/3/issue/{key}/comment", {"body": body})

    def state(self, key: str) -> dict:
        return next(issue for issue in self.fake.state()["issues"] if issue["key"] == key)


@pytest.fixture(params=[ITSM, CUSTOM], ids=lambda workflow: workflow.name)
def workflow(request) -> Workflow:
    return request.param


@pytest.fixture
def client(workflow: Workflow) -> Client:
    return Client(FakeJira(workflow))


@pytest.fixture
def itsm() -> Client:
    return Client(FakeJira(ITSM))


@pytest.fixture
def custom() -> Client:
    return Client(FakeJira(CUSTOM))


# --- authentication ---


def test_any_non_empty_email_and_token_are_accepted_and_nothing_else_is(client):
    assert client("GET", "/rest/api/3/myself")[0] == 200
    assert (
        client("GET", "/rest/api/3/myself", headers=basic("someone@example.invalid", "x"))[0] == 200
    )
    assert client("GET", "/rest/api/3/myself", headers={})[0] == 401
    assert client("GET", "/rest/api/3/myself", headers={"Authorization": "Bearer abc"})[0] == 401
    assert client("GET", "/rest/api/3/myself", headers=basic("", TOKEN))[0] == 401
    assert client("GET", "/rest/api/3/myself", headers=basic(EMAIL, ""))[0] == 401
    assert (
        client("GET", "/rest/api/3/myself", headers={"Authorization": "Basic not-base64!"})[0]
        == 401
    )


def test_the_evidence_endpoints_need_no_credential(client):
    assert client("GET", "/__fake__/state", headers={})[0] == 200
    assert client("POST", "/__fake__/reset", headers={})[0] == 200


def test_an_unknown_path_is_a_404_and_a_wrong_method_a_405(client):
    status, answer = client("GET", "/rest/api/3/dashboard")
    assert (
        status == 404 and "does not answer GET /rest/api/3/dashboard" in answer["errorMessages"][0]
    )
    assert client("DELETE", "/rest/api/3/serverInfo")[0] == 405


# --- create ---


def test_create_needs_only_summary_issue_type_and_project(client, workflow):
    key = client.ok(
        "POST",
        "/rest/api/3/issue",
        {"fields": {"project": {"key": KEY}, "issuetype": {"name": "Incident"}, "summary": "bare"}},
    )["key"]

    fields = client.issue(key)
    assert key == f"{KEY}-1"
    assert fields["status"]["name"] == workflow.initial.name
    assert fields["labels"] == [] and fields["resolution"] is None
    assert fields["issuetype"]["name"] == "Incident" and fields["project"]["key"] == KEY
    assert datetime.strptime(fields["created"], JIRA_TIME).replace(tzinfo=UTC)


def test_a_create_missing_a_required_field_or_naming_another_project_is_refused(client):
    errors = client.refused(
        "POST",
        "/rest/api/3/issue",
        {"fields": {"project": {"key": "OTHER"}, "issuetype": {"name": "Bug"}}},
    )["errors"]

    assert set(errors) == {"project", "issuetype", "summary"}
    assert client.fake.state()["issues"] == []


def test_labels_with_a_space_and_a_description_that_is_not_adf_are_refused(client):
    errors = client.refused(
        "POST",
        "/rest/api/3/issue",
        {
            "fields": {
                "project": {"key": KEY},
                "issuetype": {"name": "Incident"},
                "summary": "x",
                "labels": ["fine", "not fine"],
                "description": "plain text",
            }
        },
    )["errors"]

    assert "not fine" in errors["labels"] and "Atlassian Document" in errors["description"]


def test_the_itsm_create_screen_takes_the_four_custom_fields_by_their_offered_values(itsm):
    key = itsm.create(
        ["grp-x"],
        customfield_10101={"value": "Sev-1"},
        customfield_10102={"value": "Critical"},
        customfield_10103={"value": "Monitoring systems"},
        components=[{"name": "rolldice"}],
    )

    fields = itsm.issue(key)
    assert fields["customfield_10101"]["value"] == "Sev-1"
    assert [component["name"] for component in fields["components"]] == ["rolldice"]
    errors = itsm.refused(
        "POST",
        "/rest/api/3/issue",
        {
            "fields": {
                "project": {"key": KEY},
                "issuetype": {"name": "Incident"},
                "summary": "x",
                "customfield_10101": {"value": "Sev-9"},
                "components": [{"name": "checkout"}],
            }
        },
    )["errors"]
    assert "Sev-9" in errors["customfield_10101"] and "checkout" in errors["components"]


def test_the_custom_create_screen_has_no_custom_field_and_no_component(custom):
    errors = custom.refused(
        "POST",
        "/rest/api/3/issue",
        {
            "fields": {
                "project": {"key": KEY},
                "issuetype": {"name": "Incident"},
                "summary": "x",
                "customfield_10101": {"value": "Sev-1"},
                "components": [{"name": "rolldice"}],
            }
        },
    )["errors"]

    assert errors["customfield_10101"] == SCREEN_REJECTION.format(field="customfield_10101")
    assert "rolldice" in errors["components"]
    assert custom.ok("GET", f"/rest/api/3/project/{KEY}/components") == []


# --- the label add, and the update the Skill warns against ---


def test_edit_issue_with_update_labels_add_adds_and_keeps_the_rest(client):
    key = client.create(["grp-x", "ses-y", "fp-1"])

    status, _ = client(
        "PUT",
        f"/rest/api/3/issue/{key}",
        {"update": {"labels": [{"add": "fp-2"}, {"add": "fp-3"}, {"add": "fp-1"}]}},
    )

    assert status == 204
    assert client.issue(key)["labels"] == ["grp-x", "ses-y", "fp-1", "fp-2", "fp-3"]


def test_setting_fields_labels_replaces_the_whole_set_as_jira_does(client):
    """Which is why the Skill says never to use `issue update --labels` for the add."""
    key = client.create(["grp-x", "ses-y", "fp-1"])

    client.ok("PUT", f"/rest/api/3/issue/{key}?notifyUsers=true", {"fields": {"labels": ["fp-2"]}})

    assert client.issue(key)["labels"] == ["fp-2"]


def test_an_edit_of_a_field_off_the_screen_is_refused_and_recorded(client):
    key = client.create()

    errors = client.refused(
        "PUT", f"/rest/api/3/issue/{key}", {"fields": {"customfield_99999": {"value": "x"}}}
    )["errors"]

    assert errors == {"customfield_99999": SCREEN_REJECTION.format(field="customfield_99999")}
    assert client.state(key)["refusals"][0]["errors"] == errors


# --- comments ---


def test_comments_are_added_listed_in_order_and_counted(client):
    key = client.create()
    first = client.comment(key, "Opened from 3 firing Alerts")
    client.comment(key, "Update: 3 firing")

    listed = client.ok("GET", f"/rest/api/3/issue/{key}/comment")
    newest_first = client.ok(
        "GET", f"/rest/api/3/issue/{key}/comment?orderBy=-created&maxResults=50&startAt=0"
    )

    assert listed["total"] == 2 and listed["comments"][0]["id"] == first["id"]
    assert (
        newest_first["comments"][0]["body"]["content"][0]["content"][0]["text"]
        == "Update: 3 firing"
    )
    assert [c["text"] for c in client.state(key)["comments"]] == [
        "Opened from 3 firing Alerts",
        "Update: 3 firing",
    ]
    assert client.refused("POST", f"/rest/api/3/issue/{key}/comment", {"body": "text"})["errors"][
        "comment"
    ]


# --- the itsm workflow ---


def test_itsm_offers_the_stock_path_and_only_resolve_takes_a_resolution(itsm):
    key = itsm.create()
    assert itsm.transitions(key) == {
        "Work in progress": "11",
        "Pending": "21",
        "Completed": "31",
        "Canceled": "41",
    }

    refused = itsm.move(key, "Work in progress", resolution="Done")
    assert refused[0] == 400 and refused[1]["errors"] == {
        "resolution": SCREEN_REJECTION.format(field="resolution")
    }
    assert itsm.issue(key)["status"]["name"] == "Open"

    assert itsm.move(key, "Work in progress")[0] == 204
    assert itsm.transitions(key) == {"Pending": "21", "Completed": "31", "Canceled": "41"}
    assert itsm.move(key, "Completed", resolution="Done")[0] == 204
    fields = itsm.issue(key)
    assert fields["status"]["name"] == "Completed" and fields["resolution"]["name"] == "Done"
    assert fields["status"]["statusCategory"]["key"] == "done" and fields["resolutiondate"]
    assert itsm.transitions(key) == {"Closed": "51", "Open": "61"}
    assert itsm.move(key, "Closed")[0] == 204
    assert itsm.transitions(key) == {}
    assert [entry["to"] for entry in itsm.state(key)["history"]] == [
        "Open",
        "Work in progress",
        "Completed",
        "Closed",
    ]
    assert itsm.state(key)["refusals"][0]["errors"]["resolution"].startswith(
        "Field 'resolution' cannot be set"
    )


def test_itsm_completed_without_a_resolution_can_be_reopened_and_canceled_cannot_be_completed(itsm):
    """The reset's two edge cases: the road back from Completed, and Canceled's lack of one."""
    key = itsm.create()
    assert itsm.move(key, "Completed")[0] == 204
    assert itsm.issue(key)["resolution"] is None
    assert itsm.move(key, "Open")[0] == 204
    assert itsm.move(key, "Completed", resolution="Done")[0] == 204
    assert itsm.issue(key)["resolution"]["name"] == "Done"

    other = itsm.create()
    assert itsm.move(other, "Canceled")[0] == 204
    assert "Completed" not in itsm.transitions(other)
    assert itsm.keys(
        f'project = "{KEY}" AND issuetype = Incident AND statusCategory = Done AND status != "Completed" AND resolution = Unresolved'
    ) == [other]


def test_a_transition_that_is_not_offered_is_refused(itsm):
    key = itsm.create()

    answer = itsm.refused(
        "POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": "51"}}
    )

    assert "not valid" in answer["errorMessages"][0]
    assert itsm.issue(key)["status"]["name"] == "Open"


# --- the custom workflow ---


def test_custom_transitions_are_global_named_after_their_target_and_there_is_no_closed(custom):
    key = custom.create()

    offered = custom.ok("GET", f"/rest/api/3/issue/{key}/transitions")["transitions"]

    assert [t["name"] for t in offered] == [t["to"]["name"] for t in offered]
    assert [t["to"]["name"] for t in offered] == [
        "In Progress",
        "Waiting for customer",
        "Pending",
        "Resolved",
        "Canceled",
    ]
    assert all(t["isGlobal"] and not t["hasScreen"] for t in offered)
    statuses = {
        status["name"]: status["statusCategory"]["name"]
        for status in custom.ok("GET", f"/rest/api/3/project/{KEY}/statuses")[0]["statuses"]
    }
    assert statuses == {
        "New": "To Do",
        "In Progress": "In Progress",
        "Waiting for customer": "To Do",
        "Pending": "To Do",
        "Resolved": "Done",
        "Canceled": "Done",
    }


def test_custom_rejects_a_resolution_on_every_transition_with_jira_s_own_400(custom):
    key = custom.create()

    for target in ("In Progress", "Waiting for customer", "Pending", "Resolved", "Canceled"):
        status, answer = custom.move(key, target, resolution="Done")
        assert status == 400, target
        assert answer == {
            "errorMessages": [],
            "errors": {
                "resolution": "Field 'resolution' cannot be set. It is not on the appropriate screen, or unknown."
            },
        }
    assert custom.issue(key)["status"]["name"] == "New"
    assert len(custom.state(key)["refusals"]) == 5


def test_custom_moving_to_resolved_sets_resolution_done_itself_and_moving_back_clears_it(custom):
    key = custom.create()
    assert custom.move(key, "In Progress")[0] == 204

    assert custom.move(key, "Resolved")[0] == 204

    fields = custom.issue(key)
    assert fields["status"]["name"] == "Resolved" and fields["resolution"]["name"] == "Done"
    assert custom.keys(match_jql()) == []
    assert custom.move(key, "New")[0] == 204
    assert custom.issue(key)["resolution"] is None
    assert custom.move(key, "Canceled")[0] == 204
    assert custom.issue(key)["resolution"] is None
    history = custom.state(key)["history"]
    assert [(entry["to"], entry.get("resolution")) for entry in history] == [
        ("New", None),
        ("In Progress", None),
        ("Resolved", "Done"),
        ("New", None),
        ("Canceled", None),
    ]


# --- the JQL subset ---


def test_the_match_search_finds_the_open_incident_with_both_labels_and_not_a_done_one(
    client, workflow
):
    done = "Completed" if workflow is ITSM else "Resolved"
    first = client.create(["grp-x", "ses-a", "fp-1"])
    client.create(["grp-x", "ses-b", "fp-1"])
    client.create(["grp-y", "ses-a", "fp-2"])
    completed = client.create(["grp-x", "ses-a", "fp-3"])
    assert client.move(completed, done, resolution="Done" if workflow is ITSM else None)[0] == 204

    assert client.keys(match_jql("grp-x", "ses-a")) == [first]
    assert client.keys(match_jql("grp-x", "ses-a", open_only=False)) == [first, completed]
    assert client.keys(f'project = "{KEY}" AND issuetype = Incident AND statusCategory = Done') == [
        completed
    ]


def test_status_resolution_and_created_clauses_as_the_reset_and_verify_write_them(itsm):
    now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    itsm.fake._now = lambda: now
    old = itsm.create(["fp-1"])
    itsm.fake._now = lambda: now + timedelta(minutes=30)
    new = itsm.create(["fp-2"])
    itsm.move(old, "Completed")

    assert itsm.keys(
        f'project = "{KEY}" AND issuetype = Incident AND status = "Completed" AND resolution = Unresolved'
    ) == [old]
    assert itsm.keys(f'project = "{KEY}" AND issuetype = Incident AND resolution is EMPTY') == [
        old,
        new,
    ]
    assert itsm.keys(f"project = {KEY} AND resolution = Done") == []
    assert itsm.keys(f'project = "{KEY}" AND issuetype = Incident AND created >= "-5m"') == [new]
    assert itsm.keys(f'project = "{KEY}" AND created >= "-1h" ORDER BY created DESC') == [new, old]
    assert itsm.keys(f"project = {KEY} AND statusCategory != Done") == [new]
    assert itsm.keys(f'project = {KEY} AND status != "Completed"') == [new]
    assert itsm.keys(f'project = {KEY} AND statusCategory = "To Do"') == [new]


@pytest.mark.parametrize(
    "jql, clause",
    [
        (f"project = {KEY} AND assignee = currentUser()", "assignee = currentUser()"),
        (f"project = {KEY} OR labels = x", f"project = {KEY} OR labels = x"),
        (f"project = {KEY} AND labels in (a, b)", "labels in (a, b)"),
        (f"project = {KEY} AND created >= 2026-01-01", "created >= 2026-01-01"),
        (f"project = {KEY} AND summary ~ outage", "summary ~ outage"),
        (f"project = {KEY} AND status is EMPTY", "status is EMPTY"),
    ],
)
def test_a_clause_outside_the_subset_is_refused_with_a_400_that_names_it(client, jql, clause):
    status, answer = client("GET", SEARCH + quote(jql))

    assert status == 400
    assert answer["errorMessages"] == [f"The fake Jira does not understand the clause '{clause}'"]


def test_ordering_by_an_unknown_field_and_another_project_are_refused_too(client):
    assert client("GET", SEARCH + quote(f"project = {KEY} ORDER BY priority DESC"))[0] == 400
    status, answer = client("GET", SEARCH + quote("project = OTHER AND issuetype = Incident"))
    assert status == 400 and "OTHER" in answer["errorMessages"][0]


def test_search_pages_with_a_next_page_token_and_answers_only_the_fields_asked_for(client):
    for n in range(7):
        client.create([f"fp-{n}"])

    page = client.search(f"project = {KEY}", maxResults="3", fields="key,status,labels")
    second = client.search(f"project = {KEY}", maxResults="3", nextPageToken=page["nextPageToken"])
    last = client.search(f"project = {KEY}", maxResults="3", nextPageToken=second["nextPageToken"])

    assert [i["key"] for i in page["issues"]] == [f"{KEY}-1", f"{KEY}-2", f"{KEY}-3"] and page[
        "isLast"
    ] is False
    assert set(page["issues"][0]["fields"]) == {"status", "labels"}
    assert (
        [i["key"] for i in last["issues"]] == [f"{KEY}-7"]
        and last["isLast"] is True
        and "nextPageToken" not in last
    )
    repeated = client.ok(
        "GET", SEARCH + quote(f"project = {KEY}") + "&fields=key&fields=status&fields=labels"
    )
    assert set(repeated["issues"][0]["fields"]) == {"status", "labels"}


# --- the project's facts, as configure and doctor read them ---


def test_the_project_facts_describe_each_workflow_as_the_brief_says(client, workflow):
    project = client.ok("GET", f"/rest/api/3/project/{KEY}")
    assert project["projectTypeKey"] == "service_desk" and project["style"] == "classic"
    types = client.ok(
        "GET", f"/rest/api/3/issue/createmeta/{KEY}/issuetypes?startAt=0&maxResults=50"
    )["issueTypes"]
    incident = next(kind for kind in types if kind["name"] == "Incident")
    fields = client.ok(
        "GET",
        f"/rest/api/3/issue/createmeta/{KEY}/issuetypes/{incident['id']}?startAt=0&maxResults=50",
    )["fields"]
    required = {f["fieldId"] for f in fields if f["required"] and not f["hasDefaultValue"]}
    custom = {f["name"]: f["fieldId"] for f in fields if f["fieldId"].startswith("customfield_")}
    statuses = {
        kind["name"]: [s["name"] for s in kind["statuses"]]
        for kind in client.ok("GET", f"/rest/api/3/project/{KEY}/statuses")
    }
    resolutions = client.ok("GET", "/rest/api/3/resolution/search?startAt=0&maxResults=50")
    permissions = client.ok(
        "GET",
        f"/rest/api/3/mypermissions?projectKey={KEY}&permissions=CREATE_ISSUES,ADMINISTER_PROJECTS,SYSTEM_ADMIN",
    )["permissions"]
    desk = client.ok("GET", f"/rest/servicedeskapi/servicedesk/{KEY}")
    queues = client.ok(
        "GET", f"/rest/servicedeskapi/servicedesk/{desk['id']}/queue?start=0&limit=50"
    )["values"]
    info = client.ok("GET", "/rest/api/3/serverInfo")

    assert required == {"summary", "issuetype", "project"}
    assert {"labels", "description"} <= {f["fieldId"] for f in fields}
    if workflow is ITSM:
        assert set(custom) == {"Severity", "Urgency", "Source", "Major incident"}
        assert statuses["Incident"] == [
            "Open",
            "Work in progress",
            "Pending",
            "Completed",
            "Canceled",
            "Closed",
        ]
        assert {"Sev-1", "Sev-2", "Sev-3"} <= {
            v["value"] for v in next(f for f in fields if f["name"] == "Severity")["allowedValues"]
        }
    else:
        assert custom == {}
        assert statuses["Incident"] == [
            "New",
            "In Progress",
            "Waiting for customer",
            "Pending",
            "Resolved",
            "Canceled",
        ]
    assert "Done" in {r["name"] for r in resolutions["values"]} and resolutions["isLast"] is True
    assert permissions["CREATE_ISSUES"]["havePermission"] is True
    assert permissions["SYSTEM_ADMIN"]["havePermission"] is False
    assert desk["projectKey"] == KEY
    incidents = next(queue for queue in queues if queue["name"] == "Incidents")
    assert configure.UNRESOLVED.search(incidents["jql"])
    assert info["deploymentType"] == "Cloud" and datetime.strptime(
        info["serverTime"], JIRA_TIME
    ).replace(tzinfo=UTC)
    assert client.ok("GET", "/rest/api/3/myself")["active"] is True
    assert client("GET", "/rest/api/3/project/OTHER")[0] == 404
    assert client("GET", "/rest/servicedeskapi/servicedesk/OTHER")[0] == 404


# --- the state dump, the reset and the log ---


def test_the_state_dump_carries_issues_labels_comments_and_the_status_path_and_reset_empties_it(
    itsm,
):
    key = itsm.create(["grp-x", "ses-y", "fp-1"], summary="checkout-outage: 3 alerts firing")
    itsm.comment(key, "Opened from 3 firing Alerts")
    itsm.ok("PUT", f"/rest/api/3/issue/{key}", {"update": {"labels": [{"add": "fp-2"}]}})
    itsm.move(key, "Work in progress")
    itsm.move(key, "Completed", resolution="Done")

    state = itsm.fake.state()
    [issue] = state["issues"]
    assert state["workflow"] == "itsm" and state["project"] == KEY
    assert issue["key"] == key and issue["summary"] == "checkout-outage: 3 alerts firing"
    assert issue["labels"] == ["grp-x", "ses-y", "fp-1", "fp-2"]
    assert [c["text"] for c in issue["comments"]] == ["Opened from 3 firing Alerts"]
    assert [(h["from"], h["to"], h.get("resolution")) for h in issue["history"]] == [
        (None, "Open", None),
        ("Open", "Work in progress", None),
        ("Work in progress", "Completed", "Done"),
    ]
    assert issue["description"] == "hello"
    json.dumps(state)

    assert itsm("POST", "/__fake__/reset") == (200, {"reset": True})
    assert itsm.fake.state()["issues"] == []
    assert itsm.create() == f"{KEY}-2", "the numbering goes on, as a project's does"


def test_delete_issue_removes_it_as_the_reset_s_hint_would(itsm):
    key = itsm.create(["fp-1"])

    assert itsm("DELETE", f"/rest/api/3/issue/{key}")[0] == 204

    assert itsm.keys(f"project = {KEY}") == []
    assert itsm("GET", f"/rest/api/3/issue/{key}")[0] == 404


def test_over_http_each_request_logs_its_method_path_and_status_and_nothing_else(caplog):
    fake = FakeJira(ITSM)
    secret = "a-token-that-must-not-be-logged"
    with Server(fake) as server, caplog.at_level(logging.INFO, logger="fake_jira"):
        request = urllib.request.Request(
            server.url + "/rest/api/3/issue",
            data=json.dumps(
                {
                    "fields": {
                        "project": {"key": KEY},
                        "issuetype": {"name": "Incident"},
                        "summary": "the summary text",
                    }
                }
            ).encode(),
            headers={**basic(EMAIL, secret), "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            assert response.status == 201
        with urllib.request.urlopen(
            urllib.request.Request(
                server.url + SEARCH + quote(f'project = {KEY} AND labels = "secret-label"'),
                headers=basic(EMAIL, secret),
            )
        ) as response:
            assert response.status == 200
        try:
            urllib.request.urlopen(server.url + "/rest/api/3/myself")
        except urllib.error.HTTPError as refused:
            assert refused.code == 401 and refused.headers["WWW-Authenticate"].startswith("Basic")

    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "POST /rest/api/3/issue 201",
        "GET /rest/api/3/search/jql 200",
        "GET /rest/api/3/myself 401",
    ]
    assert (
        secret not in caplog.text
        and "summary text" not in caplog.text
        and "secret-label" not in caplog.text
    )


def test_the_module_runs_from_the_command_line_with_a_workflow_and_a_port():
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "grafana_jsm_sandbox.fake_jira",
            "--workflow",
            "custom",
            "--port",
            "0",
        ],
        cwd=REPOSITORY,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        first = process.stdout.readline()
        url = re.search(r"listening on (http://\S+):", first)
        assert url, first
        with urllib.request.urlopen(url[1] + "/__fake__/state") as response:
            state = json.load(response)
        assert state == {"workflow": "custom", "project": KEY, "issues": []}
        second = process.stdout.readline()
        assert second.rstrip().endswith("GET /__fake__/state 200")
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_workflows_are_the_two_the_brief_names():
    assert set(WORKFLOWS) == {"itsm", "custom"}
    assert "Closed" not in {status.name for status in CUSTOM.statuses}
    assert [field.name for field in ITSM.custom_fields] == [
        "Severity",
        "Urgency",
        "Source",
        "Major incident",
    ]
    assert CUSTOM.custom_fields == () and CUSTOM.components == ()
    assert fake_jira.DEFAULT_PORT == 8090 and fake_jira.DEFAULT_PROJECT_KEY == KEY


# --- the real jira-as, against the fake on a socket ---


@pytest.fixture(scope="module")
def jira_as_cli() -> str:
    """The real CLI, or a skip that says how to get it."""
    found = shutil.which("jira-as")
    if found is None:
        pytest.skip(
            "jira-as is not on PATH (pip install jira-as==2.0.0); the fake was not driven by the real CLI"
        )
    try:
        version = subprocess.run(
            [found, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as failure:
        pytest.skip(f"jira-as --version did not answer ({failure!r})")
    said = (version.stdout + version.stderr).strip()
    if version.returncode != 0 or not re.search(r"\b2\.\d+\.\d+\b", said):
        pytest.skip(f"jira-as --version said {said!r}, not a 2.x the Skill was written against")
    return found


@pytest.fixture
def served(workflow: Workflow) -> Server:
    with Server(FakeJira(workflow)) as server:
        yield server


def env_values(server: Server, **more: str) -> dict[str, str]:
    return {
        "JIRA_SITE_URL": server.url,
        "JIRA_EMAIL": EMAIL,
        "JIRA_API_TOKEN": TOKEN,
        "DEMO_PROJECT_KEY": KEY,
        "DEMO_SESSION_ID": SESSION,
        **more,
    }


def cli_for(server: Server, monkeypatch):
    """The real `jira-as` started as the laptop helpers start it, pointed at the fake."""
    monkeypatch.delenv("JIRA_SITE_URL", raising=False)
    environment = jira_as_environment(env_values(server), warn=lambda message: None)
    return jira_as_with(environment)


def project_for(workflow: Workflow, fake: FakeJira) -> DemoProject:
    """The project as `configure --write` would leave it in `.env` for this workflow."""
    fields = {field.name: field.id for field in fake.workflow.custom_fields}
    roles = (
        {
            "status_open": "Open",
            "status_in_progress": "Work in progress",
            "status_done": "Completed",
            "status_closed": "Closed",
        }
        if workflow is ITSM
        else {
            "status_open": "New",
            "status_in_progress": "In Progress",
            "status_done": "Resolved",
            "status_closed": "",
        }
    )
    return DemoProject(
        key=KEY,
        severity_field=fields.get("Severity"),
        urgency_field=fields.get("Urgency"),
        source_field=fields.get("Source"),
        major_incident_field=fields.get("Major incident"),
        session_id=SESSION,
        **roles,
    )


PLACEHOLDER = re.compile(r"<([a-zA-Z_ ]+)>")


def skill_commands(rendered: str) -> list[str]:
    """Every `jira-as` command line the rendered Skill holds, fenced or in prose."""
    lines = []
    for block in re.finditer(r"```bash\n(.*?)```", rendered, re.DOTALL):
        lines += [line for line in block.group(1).splitlines() if line.startswith("jira-as")]
    fenced = list(lines)
    prose = re.sub(r"```.*?```", "", rendered, flags=re.DOTALL)
    # The one command the prose quotes to forbid, `issue update --labels`, is not one to run,
    # and a prose mention that is only the start of a fenced command (`jira-as api call
    # editIssue` prints null) names that command rather than being another one.
    lines += [
        line
        for line in re.findall(r"`(jira-as [^`]+)`", prose)
        if "never" not in prose.split(line)[0][-80:].lower()
        and not any(command != line and command.startswith(line) for command in fenced)
    ]
    return lines


def fill(line: str, values: dict[str, object]) -> str:
    """The placeholders the Skill leaves to the Run, filled: a list is consumed in order."""
    counters: dict[str, int] = {}

    def replace(match: re.Match) -> str:
        name = match[1]
        assert name in values, f"the Skill's placeholder <{name}> has no value in this test"
        value = values[name]
        if isinstance(value, list):
            index = counters.get(name, 0)
            counters[name] = index + 1
            return str(value[min(index, len(value) - 1)])
        return str(value)

    filled = PLACEHOLDER.sub(replace, line)
    assert "<" not in filled or ">" not in filled.split("<", 1)[1], filled
    return filled


def shape(line: str) -> str:
    """Which of the Skill's commands a line is, by what is fixed in it."""
    words = shlex.split(
        fill(
            line,
            {
                name: "x"
                for name in (
                    "key",
                    "id",
                    "fingerprint",
                    "incident_group",
                    "summary",
                    "n",
                    "m",
                    "alertname",
                    "current",
                    "duration",
                    "description",
                    "service",
                    "total",
                )
            },
        )
    )
    if words[1:4] == ["collaborate", "comment", "add"]:
        return "comment " + words[-1].split(":")[0].split(" ")[0].lower()
    if words[1:3] == ["lifecycle", "transition"]:
        return "resolve" if "--resolution" in words else "move"
    if "api" in words and "call" in words:
        return words[words.index("call") + 1]
    return " ".join(words[1:3])


@pytest.mark.usefixtures("jira_as_cli")
def test_the_real_jira_as_carries_out_every_command_line_of_the_rendered_skill(
    served, workflow, monkeypatch, tmp_path
):
    """The MVP's four Notifications, one Run each, on each workflow, with the CLI the Runs use:
    the Skill's own lines with the Run's placeholders filled, and every line `incident-payload`
    prints, run exactly as printed. One create, and the Incident ends done with a resolution."""
    jira_as = cli_for(served, monkeypatch)
    project = project_for(workflow, served.fake)
    rendered = skill_template.render(TEMPLATE, project)
    commands = {
        "collaborate comment larger" if "<total>" in line else shape(line): line
        for line in skill_commands(rendered)
    }
    assert set(commands) == {
        "search jql",
        "getProjectComponents",
        "getServerInfo",
        "collaborate comment",
        "collaborate comment larger",
        "lifecycle transitions",
        "move",
        "resolve",
        "issue get",
    }, "a command line joined or left the Skill; teach this test its shape"
    covered = set()
    runs = tmp_path / "runs"
    skill_template.materialize(REPOSITORY / "skill", runs / RENDERED_SKILL, project)
    firing, repeat, related, resolved = MVP_SEQUENCE

    def run(name: str, **values: object) -> str:
        covered.add(name)
        return jira_as(*shlex.split(fill(commands[name], values))[1:])

    def payload(notification: str, *argv: str) -> list[str]:
        """What `incident-payload` prints, less its `#` lines, in this Notification's Run."""
        working = runs / Path(notification).stem
        working.mkdir(exist_ok=True)
        (working / NOTIFICATION_FILENAME).write_bytes((FIXTURES / notification).read_bytes())
        lines = incident_payload.printed(list(argv), working)
        return [line for line in lines if not line.startswith("#")]

    def as_printed(line: str, key: str | None = None) -> str:
        """One printed line, run as written but for the Incident's key in place of `<key>`."""
        if key is not None:
            line = line.replace("<key>", key)
        assert "<key>" not in line
        return jira_as(*shlex.split(line)[1:])

    def against(match: dict, notification: str, step: str, *more: str) -> list[str]:
        server_time = json.loads(run("getServerInfo"))["serverTime"]
        return payload(
            notification,
            step,
            "--key",
            match["key"],
            "--labels",
            ",".join(match["fields"]["labels"]),
            "--created",
            match["fields"]["created"],
            "--server-time",
            server_time,
            *more,
        )

    def the_match() -> dict:
        [search] = payload(firing, "match")
        assert search == fill(commands["search jql"], {"incident_group": GROUP})
        covered.add("search jql")
        [match] = json.loads(as_printed(search))["issues"]
        return match

    # Run 1: three Alerts firing and no Match, so the one create.
    [search] = payload(firing, "match")
    assert json.loads(as_printed(search))["issues"] == []
    components = {component["name"] for component in json.loads(run("getProjectComponents"))}
    component = ["--component", "rolldice"] if "rolldice" in components else []
    dry_run, create, opened = payload(firing, "create", *component)
    assert json.loads(as_printed(dry_run))["dry_run"] is True
    assert served.fake.state()["issues"] == [], "the dry run sent nothing"
    key = re.search(rf"\b({KEY}-\d+)\b", as_printed(create))[1]
    as_printed(opened, key)

    match = the_match()
    assert match["key"] == key and match["fields"]["status"]["name"] == project.status_open
    fingerprints = ["87e2f184874a3b71", "3c1d9a7e5b2f8046", "a94f0c2e7d13b58c"]
    assert match["fields"]["labels"] == [
        f"grp-{GROUP}",
        f"ses-{SESSION}",
        *(f"fp-{fp}" for fp in fingerprints),
    ]

    # Run 2: the same three again, so no label and one comment; Open moves on.
    [comment] = against(match, repeat, "update")
    as_printed(comment)
    created_at = datetime.strptime(match["fields"]["created"], JIRA_TIME).replace(tzinfo=UTC)
    server_time = datetime.strptime(
        json.loads(run("getServerInfo"))["serverTime"], JIRA_TIME
    ).replace(tzinfo=UTC)
    assert timedelta(0) <= server_time - created_at < timedelta(minutes=5)
    transitions = {
        t["to"]["name"]: t["id"] for t in json.loads(run("lifecycle transitions", key=key))
    }
    run("move", key=key, id=transitions[project.status_in_progress])

    # Run 3: the sustained-outage Alert joins: its label, then one comment.
    match = the_match()
    assert match["fields"]["status"]["name"] == project.status_in_progress
    add, comment = against(match, related, "update")
    assert as_printed(add).strip() in ("", "null")
    as_printed(comment)

    # Run 4: every Alert resolved, so the close.
    match = the_match()
    listed = json.loads(run("collaborate comment", key=key))
    assert "--order asc --limit 200" in commands["collaborate comment"]
    assert len(listed["comments"]) == listed["total"], "count only a complete list"
    # Exercise the larger-page command too, with Jira's total as its limit.
    larger = json.loads(run("collaborate comment larger", key=key, total=listed["total"]))
    assert len(larger["comments"]) == larger["total"]
    assert larger["comments"] == listed["comments"]
    count = sum(
        not is_investigation(comment_text(comment["body"])) for comment in listed["comments"]
    )
    assert count == 3, "step 2c counts prior lifecycle comments"
    [comment] = against(match, resolved, "close", "--runs", str(count))
    as_printed(comment)
    transitions = {
        t["to"]["name"]: t["id"] for t in json.loads(run("lifecycle transitions", key=key))
    }
    run("resolve", key=key, id=transitions[project.status_done])
    fields = json.loads(run("issue get", key=key))["fields"]
    assert set(fields) == {"status", "resolution"}, "the check reads two fields and no more"
    assert (
        fields["status"]["name"] == project.status_done and fields["resolution"]["name"] == "Done"
    )
    assert json.loads(as_printed(search))["issues"] == []

    assert covered == set(commands)
    assert [issue["key"] for issue in served.fake.state()["issues"]] == [key], "one create"
    state = Client(served.fake).state(key)
    joined = "fp-" + json.loads((FIXTURES / related).read_text())["alerts"][3]["fingerprint"]
    assert state["labels"] == [
        f"grp-{GROUP}",
        f"ses-{SESSION}",
        *(f"fp-{fp}" for fp in fingerprints),
        joined,
    ]
    assert state["summary"] == f"{GROUP}: 3 alerts firing on rolldice"
    description = state["description"].splitlines()
    assert description[0] == f"Partial Report: 3 alerts firing in group {GROUP}."
    assert len(description) == 4 and all("value=" in line for line in description[1:])
    texts = [c["text"] for c in state["comments"]]
    assert [text.split(":")[0].split(" ")[0] for text in texts] == [
        "Opened",
        "Update",
        "Update",
        "Resolved",
    ]
    assert "New: none." in texts[1] and f"({joined})" in texts[2]
    assert f"(4 Alerts, 4 Runs). {project.status_done} automatically" in texts[3]
    assert [h["to"] for h in state["history"]] == [
        project.status_open,
        project.status_in_progress,
        project.status_done,
    ]
    if workflow is ITSM:
        assert state["refusals"] == []
        assert state["history"][-1]["resolution_requested"] == "Done"
        assert set(state["custom_fields"].values()) == {"Sev-1", "Critical", "Monitoring systems"}
        assert state["components"] == ["rolldice"]
    else:
        assert [refusal["errors"] for refusal in state["refusals"]] == [
            {"resolution": SCREEN_REJECTION.format(field="resolution")}
        ]
        assert state["history"][-1]["resolution_requested"] is None, "jira-as retried without it"
        assert state["custom_fields"] == {} and state["components"] == []


@pytest.fixture
def env_file(tmp_path: Path, served: Server, monkeypatch) -> Path:
    monkeypatch.delenv("JIRA_SITE_URL", raising=False)
    path = tmp_path / ".env"
    path.write_text("".join(f"{name}={value}\n" for name, value in env_values(served).items()))
    return path


@pytest.mark.usefixtures("jira_as_cli")
def test_configure_reads_each_workflow_off_the_fake_and_writes_its_facts(
    served, workflow, env_file, capsys
):
    planned = configure.main([], env_file=env_file)
    said = capsys.readouterr().out.splitlines()

    assert planned == 0, said
    assert said[-1] == "READY"
    checks = {}
    for line in said:
        matched = re.match(r"^(OK|WARN|FAIL) +([a-z ]+): (.+)$", line)
        if matched:
            checks[matched[2]] = (matched[1], matched[3])
    statuses = f"{checks['statuses'][0]} statuses: {checks['statuses'][1]}"
    levels = {name: checks[name][0] for name in ("severity", "urgency", "source", "major incident")}
    if workflow is ITSM:
        assert (
            statuses
            == "OK statuses: the Incident workflow has Open, Work in progress, Completed, Closed"
        )
        assert levels == {"severity": "OK", "urgency": "OK", "source": "OK", "major incident": "OK"}
    else:
        assert statuses == (
            "WARN statuses: the Incident workflow: proposed DEMO_STATUS_OPEN=New, "
            "DEMO_STATUS_IN_PROGRESS=In Progress, DEMO_STATUS_DONE=Resolved, "
            "DEMO_STATUS_CLOSED=(empty, no close step)"
        )
        assert levels == {
            "severity": "WARN",
            "urgency": "WARN",
            "source": "WARN",
            "major incident": "OK",
        }
    assert checks["dedicated"][0] == "OK" and checks["create screen"][0] == "OK"
    assert checks["resolution"][0] == "OK" and checks["queue"][0] == "OK"

    written = configure.main(["--write"], env_file=env_file)
    assert written == 0
    values = read_env_file(env_file)
    project = DemoProject.from_environment(values)
    expected = project_for(workflow, served.fake)
    assert (
        project.status_open,
        project.status_in_progress,
        project.status_done,
        project.status_closed,
    ) == (
        expected.status_open,
        expected.status_in_progress,
        expected.status_done,
        expected.status_closed,
    )
    assert (
        project.severity_field == expected.severity_field
        and project.source_field == expected.source_field
    )
    assert (
        values["DEMO_QUEUE_URL"]
        == f"{served.url}/jira/servicedesk/projects/{KEY}/queues/custom/{served.fake.queue_id}"
    )
    assert served.fake.state()["issues"] == [], "configure only reads"
    assert set(values) >= set(FIELD_VARIABLES.values())
    if workflow is ITSM:
        assert not set(values) & set(STATUS_VARIABLES.values()), (
            "the stock roles are the defaults, so none is written"
        )
    else:
        assert set(values) >= set(STATUS_VARIABLES.values())


class ScriptedRun:
    """A Run that follows Skill v2 to the letter, standing in for the Receiver's real one.

    `verify` posts a Notification and this acts on the fake project at once, through
    `FakeJira.handle`, the way a real Run would through jira-as: search the Match, create
    with its Report, comment, move on the first update, resolve on the Resolved. What it writes
    is the Skill's templates filled in from the Alerts, which `verify --mvp` holds it to.
    """

    def __init__(self, fake: FakeJira, project: DemoProject, description: dict | None = None):
        self.client = Client(fake)
        self.project = project
        self.description = description
        """What it writes as the Description in place of the Report, when it is given one."""
        self.posted: list[str] = []

    def post(self, url: str, notification: bytes) -> int:
        parsed = json.loads(notification)
        self.posted.append(parsed["status"])
        group = f"grp-{parsed['groupLabels']['incident_group']}"
        session = self.project.session_label
        labels = [f"fp-{alert['fingerprint']}" for alert in parsed["alerts"]]
        matches = self.client.search(match_jql(group, session))["issues"]
        if parsed["status"] == "resolved":
            if matches:
                key = matches[0]["key"]
                comments = self.client.issue(key, "comment")["comment"]
                assert len(comments["comments"]) == comments["total"]
                prior = sum(
                    not is_investigation(comment_text(comment["body"]))
                    for comment in comments["comments"]
                )
                self.client.comment(key, closing_of(len(labels), prior + 1))
                status, _ = self.client.move(key, self.project.status_done, resolution="Done")
                if status == 400:
                    assert self.client.move(key, self.project.status_done)[0] == 204
            return 202
        if not matches:
            key = self.client.create(
                [group, session, *labels],
                summary=summary_of(labels),
                description=self.description or description_of(labels),
            )
            self.client.comment(key, opening_of(labels))
            return 202
        key = matches[0]["key"]
        seen = matches[0]["fields"]["labels"]
        new = [label for label in labels if label not in seen]
        if new:
            self.client.ok(
                "PUT",
                f"/rest/api/3/issue/{key}",
                {"update": {"labels": [{"add": label} for label in new]}},
            )
        self.client.comment(key, update_of(labels, seen))
        if matches[0]["fields"]["status"]["name"] == self.project.status_open:
            assert self.client.move(key, self.project.status_in_progress)[0] == 204
        return 202


@pytest.mark.usefixtures("jira_as_cli")
def test_verify_mvp_replay_watches_a_scripted_run_through_the_fake_end_to_end(
    served, workflow, env_file, monkeypatch, capsys
):
    """`verify --mvp --replay`'s own logic, its reads through the real jira-as against the
    fake, on the `.env` `configure --write` leaves: the World stands in for the Receiver,
    compose, Grafana and the clock, and nothing of `verify` is doubled."""
    assert configure.main(["--write"], env_file=env_file) == 0
    capsys.readouterr()
    values = read_env_file(env_file)
    project = DemoProject.from_environment(values)
    run = ScriptedRun(served.fake, project)
    clock = FakeClock()
    out: list[str] = []
    world = World(
        jira_as=jira_as_with(jira_as_environment(values, warn=lambda message: None)),
        compose=lambda *arguments: pytest.fail(f"--replay asked compose for {arguments}"),
        post=run.post,
        grafana_state=lambda: "inactive",
        now=clock.now,
        sleep=clock.sleep,
        out=out.append,
    )

    status = verify.main(
        ["--mvp", "--replay", "--receiver", "http://127.0.0.1:9"], env_file=env_file, world=world
    )

    assert status == 0, "\n".join(out)
    assert run.posted == ["firing", "firing", "firing", "resolved"]
    related = json.loads((FIXTURES / MVP_SEQUENCE[2]).read_text())["alerts"][-1]["fingerprint"]
    assert re.fullmatch(
        rf"VERIFIED: {KEY}-1 created with 3 fp- labels → updated → fp-{related} added → "
        rf"{re.escape(project.status_done)} with resolution Done in \d+s",
        out[-1],
    ), out[-1]
    stages = [line.split(" ")[1:3] for line in out[:-1]]
    assert (
        ["OK", "created"] in stages and ["OK", "grouped"] in stages and ["OK", "updated"] in stages
    )
    assert ["OK", "related"] in stages and ["OK", "completed"] in stages
    assert not any(level == "WARN" for level, _ in stages), out
    [issue] = served.fake.state()["issues"]
    assert issue["status"] == project.status_done and issue["resolution"] == "Done"
    assert len([label for label in issue["labels"] if label.startswith("fp-")]) == 4
    assert len(issue["comments"]) == 4


@pytest.mark.usefixtures("jira_as_cli")
def test_verify_mvp_replay_names_a_placeholder_description_through_the_real_jira_as(
    served, env_file, capsys
):
    """The lifecycle is complete and the Description is `Test`: the Description is read back
    through the real jira-as from the fake, and `verify` names it."""
    assert configure.main(["--write"], env_file=env_file) == 0
    capsys.readouterr()
    values = read_env_file(env_file)
    placeholder = {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Test"}]}],
    }
    run = ScriptedRun(served.fake, DemoProject.from_environment(values), placeholder)
    clock = FakeClock()
    out: list[str] = []
    world = World(
        jira_as=jira_as_with(jira_as_environment(values, warn=lambda message: None)),
        compose=lambda *arguments: pytest.fail(f"--replay asked compose for {arguments}"),
        post=run.post,
        grafana_state=lambda: "inactive",
        now=clock.now,
        sleep=clock.sleep,
        out=out.append,
    )

    status = verify.main(
        ["--mvp", "--replay", "--receiver", "http://127.0.0.1:9"], env_file=env_file, world=world
    )

    assert status == 1, "\n".join(out)
    assert run.posted == ["firing"], "nothing more is posted after the failed stage"
    assert out[-1].startswith(f"NOT VERIFIED: created — {KEY}-1's Description 'Test' is missing: ")
    [issue] = served.fake.state()["issues"]
    assert issue["description"] == "Test"
    assert len([label for label in issue["labels"] if label.startswith("fp-")]) == 3
