"""A fake Jira Cloud, in memory, for rehearsing the MVP with a real model and no real site.

    python3 -m grafana_jsm_sandbox.fake_jira --workflow itsm|custom [--port 8090] [--host 127.0.0.1]

It answers the REST calls jira-as 2.0.0 makes for the Run's Skill
(`skill/incident-sync/SKILL.md`) and for the laptop helpers (`configure`, `doctor`,
`verify`, `reset`), and nothing else: an unknown path is a 404, a JQL clause outside
the subset those callers write is a 400 that names the clause. The calls were read off
jira-as's own source and off the wire, not guessed; `tests/test_fake_jira.py` drives the
real CLI against it for every command line in the rendered Skill.

One project, `FAKE` by default, with one issue type a Run creates, `Incident`, on one of
two workflows:

- `itsm`, the stock Jira Service Management ITSM Incident workflow: Open (To Do), Work in
  progress (In Progress), Pending (To Do), Completed, Canceled and Closed (Done). The
  Resolve transition's screen takes `resolution`; no other transition's does. Severity,
  Urgency, Source and Major incident are on the create screen, and a `rolldice`
  component exists.
- `custom`, a workflow unlike the stock one: New (To Do), In Progress (In Progress),
  Waiting for customer (To Do), Pending (To Do), Resolved (Done), Canceled (Done), and no
  Closed. Every transition is global and named after its target. No transition screen
  takes `resolution`: setting one is refused with the 400 Jira sends ("Field
  'resolution' cannot be set. It is not on the appropriate screen, or unknown."), and
  moving to Resolved sets resolution Done itself, as a post-function would. No custom
  field is on the create screen and there is no component.

Authentication is HTTP Basic with any non-empty email and token, and 401 otherwise. The
Forwarder injects whatever credential `.env` holds, which for a rehearsal is a made-up
word: nothing here can reach a real site, and no real site's name, id or field is here.

Evidence: `GET /__fake__/state` is a JSON dump of every issue with its labels, comments and
status history, and `POST /__fake__/reset` empties the project. Every request is logged
as one line, the method, the path and the status, and never a body, a query or a header.

Standard library only, so the demo image carries it as it is.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger("fake_jira")

DEFAULT_PROJECT_KEY = "FAKE"
DEFAULT_PORT = 8090
DEFAULT_HOST = "127.0.0.1"

INCIDENT = "Incident"
SERVICE_REQUEST = "Service request"
"""The two issue types. Only the Incident is ever created; the other shows the callers
picking the right workflow out of several."""

DONE_RESOLUTION = "Done"

SCREEN_REJECTION = "Field '{field}' cannot be set. It is not on the appropriate screen, or unknown."
"""Jira's own wording for a field a transition or create screen does not carry, which
jira-as 2.0.0 reads to retry a transition without `--resolution`."""

CATEGORIES = {
    "new": {"id": 2, "key": "new", "name": "To Do", "colorName": "blue-gray"},
    "indeterminate": {
        "id": 4,
        "key": "indeterminate",
        "name": "In Progress",
        "colorName": "yellow",
    },
    "done": {"id": 3, "key": "done", "name": "Done", "colorName": "green"},
}
"""Jira's three status categories, by key."""

JIRA_TIME = "%Y-%m-%dT%H:%M:%S.000+0000"
"""How Jira Cloud writes a timestamp, which the Skill subtracts `created` from `serverTime` in."""

LABEL = re.compile(r"[^\s]+")
"""A label: Jira refuses one with a space in it."""

RELATIVE = re.compile(r"-?(\d+)([mhdw])")
"""`-5m`, `-2h`, `-1d`, `-1w`: the relative times the callers' JQL compares `created` with."""

PRIORITIES = ("Highest", "High", "Medium", "Low", "Lowest")


@dataclass(frozen=True)
class Status:
    id: str
    name: str
    category: str
    """A key of `CATEGORIES`."""

    def as_json(self) -> dict:
        return {
            "self": f"status/{self.id}",
            "id": self.id,
            "name": self.name,
            "description": "",
            "statusCategory": dict(CATEGORIES[self.category]),
        }


@dataclass(frozen=True)
class Transition:
    id: str
    name: str
    to: str
    """The status name it lands on."""
    from_statuses: tuple[str, ...] | None = None
    """Where it is offered from; None is a global transition, offered from every other status."""
    takes_resolution: bool = False
    """Whether its screen carries the Resolution field."""
    sets_resolution: str | None = None
    """A resolution its post-function sets whatever the screen took."""


@dataclass(frozen=True)
class CustomField:
    id: str
    name: str
    options: tuple[str, ...]

    def createmeta(self) -> dict:
        return {
            "fieldId": self.id,
            "key": self.id,
            "name": self.name,
            "required": False,
            "hasDefaultValue": False,
            "operations": ["set"],
            "schema": {
                "type": "option",
                "custom": "com.atlassian.jira.plugin.system.customfieldtypes:select",
                "customId": int(self.id.rpartition("_")[2]),
            },
            "allowedValues": [
                {"self": f"customFieldOption/{self.id}-{n}", "value": option, "id": f"{n}"}
                for n, option in enumerate(self.options, start=1)
            ],
        }


@dataclass(frozen=True)
class Workflow:
    name: str
    statuses: tuple[Status, ...]
    transitions: tuple[Transition, ...]
    custom_fields: tuple[CustomField, ...] = ()
    components: tuple[str, ...] = ()

    @property
    def initial(self) -> Status:
        return self.statuses[0]

    def status(self, name: str) -> Status:
        return next(status for status in self.statuses if status.name == name)

    def available(self, current: str) -> list[Transition]:
        """The transitions offered from `current`, in the order the workflow lists them."""
        return [
            transition
            for transition in self.transitions
            if (
                transition.to != current
                if transition.from_statuses is None
                else current in transition.from_statuses
            )
        ]

    def custom_field(self, field_id: str) -> CustomField | None:
        return next((item for item in self.custom_fields if item.id == field_id), None)


ITSM = Workflow(
    "itsm",
    statuses=(
        Status("1", "Open", "new"),
        Status("2", "Work in progress", "indeterminate"),
        Status("3", "Pending", "new"),
        Status("4", "Completed", "done"),
        Status("5", "Canceled", "done"),
        Status("6", "Closed", "done"),
    ),
    transitions=(
        Transition("11", "Start work", "Work in progress", ("Open", "Pending")),
        Transition("21", "Pend", "Pending", ("Open", "Work in progress")),
        Transition(
            "31",
            "Resolve",
            "Completed",
            ("Open", "Work in progress", "Pending"),
            takes_resolution=True,
        ),
        Transition("41", "Cancel", "Canceled", ("Open", "Work in progress", "Pending")),
        Transition("51", "Close", "Closed", ("Completed", "Canceled")),
        Transition("61", "Reopen", "Open", ("Completed", "Canceled")),
    ),
    custom_fields=(
        CustomField("customfield_10101", "Severity", ("Sev-0", "Sev-1", "Sev-2", "Sev-3")),
        CustomField("customfield_10102", "Urgency", ("Critical", "High", "Medium", "Low")),
        CustomField("customfield_10103", "Source", ("Monitoring systems", "Phone", "Email")),
        CustomField("customfield_10104", "Major incident", ("Major incident",)),
    ),
    components=("rolldice",),
)
"""The stock ITSM Incident workflow as the demo was built on it: the reset's route out is
Resolve with a resolution, then Close, and Canceled has no road to Completed."""

CUSTOM = Workflow(
    "custom",
    statuses=(
        Status("101", "New", "new"),
        Status("102", "In Progress", "indeterminate"),
        Status("103", "Waiting for customer", "new"),
        Status("104", "Pending", "new"),
        Status("105", "Resolved", "done"),
        Status("106", "Canceled", "done"),
    ),
    transitions=(
        Transition("201", "New", "New"),
        Transition("202", "In Progress", "In Progress"),
        Transition("203", "Waiting for customer", "Waiting for customer"),
        Transition("204", "Pending", "Pending"),
        Transition("205", "Resolved", "Resolved", sets_resolution=DONE_RESOLUTION),
        Transition("206", "Canceled", "Canceled"),
    ),
)
"""A workflow unlike the stock one: global transitions, no Closed, no Resolve screen, a
post-function that resolves."""

WORKFLOWS = {ITSM.name: ITSM, CUSTOM.name: CUSTOM}

RESOLUTIONS = (
    {"id": "1", "name": "Done", "description": "Work has been completed on this issue."},
    {"id": "2", "name": "Won't Do", "description": "This issue won't be actioned."},
    {
        "id": "3",
        "name": "Duplicate",
        "description": "The problem is a duplicate of an existing issue.",
    },
    {"id": "4", "name": "Declined", "description": "This issue won't be actioned."},
)

PERMISSIONS = (
    "BROWSE_PROJECTS",
    "CREATE_ISSUES",
    "EDIT_ISSUES",
    "TRANSITION_ISSUES",
    "RESOLVE_ISSUES",
    "CLOSE_ISSUES",
    "ADD_COMMENTS",
    "ADMINISTER_PROJECTS",
    "DELETE_ISSUES",
)
"""What the one account holds on the project: everything a Run, the reset and the
engineer need, and nothing an org admin gives out."""

ACCOUNT = {
    "self": "user?accountId=fake-account",
    "accountId": "fake-account",
    "accountType": "atlassian",
    "emailAddress": "rehearsal@example.invalid",
    "displayName": "Fake Jira rehearsal account",
    "active": True,
    "timeZone": "UTC",
    "locale": "en_US",
}

INCIDENTS_QUEUE_JQL = 'project = {key} AND issuetype = Incident AND resolution = Unresolved ORDER BY "Time to resolution" ASC'


class Refused(Exception):
    """An answer other than success, in Jira's error shape."""

    def __init__(self, status: int, messages: list[str] | None = None, errors: dict | None = None):
        super().__init__(status, messages, errors)
        self.status = status
        self.messages = messages or []
        self.errors = errors or {}

    @property
    def body(self) -> dict:
        return {"errorMessages": self.messages, "errors": self.errors}


@dataclass
class Comment:
    id: str
    body: dict
    created: str

    @property
    def text(self) -> str:
        return adf_text(self.body)


@dataclass
class Issue:
    id: str
    key: str
    issuetype: str
    summary: str
    status: str
    created: str
    updated: str
    description: dict | None = None
    labels: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    priority: str = "Medium"
    resolution: str | None = None
    resolutiondate: str | None = None
    custom_fields: dict[str, str] = field(default_factory=dict)
    comments: list[Comment] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    refusals: list[dict] = field(default_factory=list)
    """Every write on this issue the fake refused with a 400, and why: on the `custom`
    workflow the Run's `--resolution Done` shows up here once, before jira-as retries
    without it."""


class FakeJira:
    """The project's state and the answers to every request, thread-safe.

    `handle` is the whole server without the socket: a test can drive it in-process, and
    `Handler` hands it what arrived on the wire.
    """

    def __init__(
        self,
        workflow: Workflow = ITSM,
        project_key: str = DEFAULT_PROJECT_KEY,
        base_url: str = "",
        now: Callable[[], datetime] | None = None,
    ):
        self.workflow = workflow
        self.project_key = project_key
        self.project_id = "10000"
        self.project_name = f"{project_key} rehearsal incidents"
        self.service_desk_id = "1"
        self.queue_id = "20"
        self.base_url = base_url
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._issues: dict[str, Issue] = {}
        self._next_number = 1
        self._next_id = 10000
        self._next_comment = 100

    # --- the wire ---

    def handle(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, object]:
        """Answer one request: the status, and the JSON body or None for an empty one."""
        parts = urlsplit(target)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query, keep_blank_values=True)
        try:
            if path.startswith("/__fake__/"):
                return self._evidence(method, path)
            self._authenticate(headers)
            payload = self._payload(body)
            with self._lock:
                return self._dispatch(method, path, query, payload)
        except Refused as refusal:
            return refusal.status, refusal.body

    def _authenticate(self, headers: dict[str, str]) -> None:
        authorization = next(
            (value for name, value in headers.items() if name.lower() == "authorization"), ""
        )
        scheme, _, encoded = authorization.partition(" ")
        if scheme.lower() != "basic":
            raise Refused(401, ["Basic authentication with an email and an API token is required"])
        try:
            email, colon, token = (
                base64.b64decode(encoded.strip(), validate=True).decode().partition(":")
            )
        except (ValueError, UnicodeDecodeError):
            raise Refused(
                401, ["The Authorization header is not Basic base64(email:token)"]
            ) from None
        if not (colon and email and token):
            raise Refused(401, ["Basic authentication needs a non-empty email and API token"])

    @staticmethod
    def _payload(body: bytes) -> object:
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            raise Refused(400, ["The request body is not JSON"]) from None

    def _dispatch(self, method: str, path: str, query: dict, payload: object) -> tuple[int, object]:
        for pattern, verb, answer in self._routes():
            matched = pattern.fullmatch(path)
            if matched is None:
                continue
            if verb != method:
                continue
            return answer(query, payload, *matched.groups())
        if any(pattern.fullmatch(path) for pattern, _, _ in self._routes()):
            raise Refused(405, [f"{method} is not supported on {path}"])
        raise Refused(404, [f"The fake Jira does not answer {method} {path}"])

    def _routes(self):
        api = r"/rest/api/3"
        desk = r"/rest/servicedeskapi"
        return (
            (re.compile(rf"{api}/search/jql"), "GET", self._search),
            (re.compile(rf"{api}/issue"), "POST", self._create),
            (re.compile(rf"{api}/issue/([^/]+)"), "GET", self._get_issue),
            (re.compile(rf"{api}/issue/([^/]+)"), "PUT", self._edit_issue),
            (re.compile(rf"{api}/issue/([^/]+)"), "DELETE", self._delete_issue),
            (re.compile(rf"{api}/issue/([^/]+)/comment"), "POST", self._add_comment),
            (re.compile(rf"{api}/issue/([^/]+)/comment"), "GET", self._comments),
            (re.compile(rf"{api}/issue/([^/]+)/transitions"), "GET", self._transitions),
            (re.compile(rf"{api}/issue/([^/]+)/transitions"), "POST", self._transition),
            (
                re.compile(rf"{api}/issue/createmeta/([^/]+)/issuetypes"),
                "GET",
                self._createmeta_types,
            ),
            (
                re.compile(rf"{api}/issue/createmeta/([^/]+)/issuetypes/([^/]+)"),
                "GET",
                self._createmeta_fields,
            ),
            (re.compile(rf"{api}/project/([^/]+)"), "GET", self._project),
            (re.compile(rf"{api}/project/([^/]+)/components"), "GET", self._components),
            (re.compile(rf"{api}/project/([^/]+)/statuses"), "GET", self._statuses),
            (re.compile(rf"{api}/resolution/search"), "GET", self._resolutions),
            (re.compile(rf"{api}/myself"), "GET", self._myself),
            (re.compile(rf"{api}/mypermissions"), "GET", self._permissions),
            (re.compile(rf"{api}/serverInfo"), "GET", self._server_info),
            (re.compile(rf"{api}/field"), "GET", self._fields),
            (re.compile(rf"{desk}/servicedesk"), "GET", self._service_desks),
            (re.compile(rf"{desk}/servicedesk/([^/]+)"), "GET", self._service_desk),
            (re.compile(rf"{desk}/servicedesk/([^/]+)/queue"), "GET", self._queues),
        )

    # --- evidence ---

    def _evidence(self, method: str, path: str) -> tuple[int, object]:
        if path == "/__fake__/state" and method == "GET":
            return 200, self.state()
        if path == "/__fake__/reset" and method == "POST":
            self.reset()
            return 200, {"reset": True}
        raise Refused(404, [f"The fake Jira does not answer {method} {path}"])

    def state(self) -> dict:
        """Every issue, with its labels, comments and status history, as JSON."""
        with self._lock:
            return {
                "workflow": self.workflow.name,
                "project": self.project_key,
                "issues": [
                    {
                        "key": issue.key,
                        "id": issue.id,
                        "issuetype": issue.issuetype,
                        "summary": issue.summary,
                        "status": issue.status,
                        "resolution": issue.resolution,
                        "labels": list(issue.labels),
                        "components": list(issue.components),
                        "priority": issue.priority,
                        "custom_fields": dict(issue.custom_fields),
                        "description": adf_text(issue.description) if issue.description else None,
                        "created": issue.created,
                        "updated": issue.updated,
                        "comments": [
                            {"id": comment.id, "created": comment.created, "text": comment.text}
                            for comment in issue.comments
                        ],
                        "history": [dict(entry) for entry in issue.history],
                        "refusals": [dict(entry) for entry in issue.refusals],
                    }
                    for issue in self._issues.values()
                ],
            }

    def reset(self) -> None:
        with self._lock:
            self._issues.clear()

    def issues(self) -> list[Issue]:
        with self._lock:
            return list(self._issues.values())

    # --- issues ---

    def _issue(self, key_or_id: str) -> Issue:
        issue = self._issues.get(key_or_id.upper()) or next(
            (issue for issue in self._issues.values() if issue.id == key_or_id), None
        )
        if issue is None:
            raise Refused(404, ["Issue does not exist or you do not have permission to see it."])
        return issue

    def _timestamp(self) -> str:
        return self._now().strftime(JIRA_TIME)

    def _create(self, query: dict, payload: object, *_) -> tuple[int, object]:
        fields = as_dict(as_dict(payload).get("fields"))
        errors: dict[str, str] = {}
        project = as_dict(fields.get("project"))
        if project.get("key") != self.project_key and project.get("id") != self.project_id:
            errors["project"] = (
                "Specified project does not exist or you do not have permission to view it."
            )
        issuetype = as_dict(fields.get("issuetype"))
        types = self._issue_types()
        kind = next(
            (
                t
                for t in types
                if issuetype.get("name") == t["name"] or issuetype.get("id") == t["id"]
            ),
            None,
        )
        if kind is None:
            errors["issuetype"] = "Specify a valid issue type"
        summary = fields.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            errors["summary"] = "You must specify a summary of the issue."
        labels = self._labels(fields.get("labels", []), errors)
        components = self._components_named(fields.get("components", []), errors)
        description = fields.get("description")
        if description is not None and not is_adf(description):
            errors["description"] = (
                "Operation value must be an Atlassian Document (see the Atlassian Document Format)"
            )
        priority = as_dict(fields.get("priority")).get("name", "Medium")
        if priority not in PRIORITIES:
            errors["priority"] = f"Priority name '{priority}' is not valid"
        custom = {}
        for name, value in fields.items():
            if name in {
                "project",
                "issuetype",
                "summary",
                "labels",
                "components",
                "description",
                "priority",
                "reporter",
            }:
                continue
            if name.startswith("customfield_") and self.workflow.custom_field(name) is not None:
                option = self.workflow.custom_field(name)
                chosen = as_dict(value).get("value") if isinstance(value, dict) else value
                if chosen not in option.options:
                    errors[name] = f"Option value '{chosen}' is not valid"
                else:
                    custom[name] = chosen
            else:
                errors[name] = SCREEN_REJECTION.format(field=name)
        if errors:
            raise Refused(400, [], errors)
        now = self._timestamp()
        issue = Issue(
            id=str(self._next_id),
            key=f"{self.project_key}-{self._next_number}",
            issuetype=kind["name"],
            summary=summary.strip(),
            status=self.workflow.initial.name,
            created=now,
            updated=now,
            description=description,
            labels=labels,
            components=components,
            priority=priority,
            custom_fields=custom,
        )
        issue.history.append({"at": now, "from": None, "to": issue.status, "transition": "Create"})
        self._next_id += 1
        self._next_number += 1
        self._issues[issue.key] = issue
        return 201, {"id": issue.id, "key": issue.key, "self": self._self(f"issue/{issue.id}")}

    def _labels(self, value: object, errors: dict) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(label, str) for label in value):
            errors["labels"] = "Labels must be a list of strings"
            return []
        bad = [label for label in value if not LABEL.fullmatch(label)]
        if bad:
            errors["labels"] = f"The label '{bad[0]}' contains spaces which is invalid."
        return list(dict.fromkeys(value))

    def _components_named(self, value: object, errors: dict) -> list[str]:
        if not isinstance(value, list):
            errors["components"] = "Components must be a list"
            return []
        names = []
        by_id = {str(n): name for n, name in enumerate(self.workflow.components, start=1)}
        for item in value:
            item = as_dict(item)
            name = item.get("name", by_id.get(str(item.get("id"))))
            if name not in self.workflow.components:
                errors["components"] = (
                    f"Component name '{item.get('name', item.get('id'))}' is not valid"
                )
            else:
                names.append(name)
        return names

    def _get_issue(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        return 200, self._issue_json(self._issue(key), requested_fields(query))

    def _edit_issue(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        payload = as_dict(payload)
        errors: dict[str, str] = {}
        labels = list(issue.labels)
        for name, operations in as_dict(payload.get("update")).items():
            if name != "labels":
                errors[name] = SCREEN_REJECTION.format(field=name)
                continue
            for operation in as_list(operations):
                operation = as_dict(operation)
                if "add" in operation:
                    added = self._labels([operation["add"]], errors)
                    labels += [label for label in added if label not in labels]
                elif "remove" in operation:
                    labels = [label for label in labels if label != operation["remove"]]
                elif "set" in operation:
                    labels = self._labels(operation["set"], errors)
                else:
                    errors["labels"] = f"Unknown operation {sorted(operation)} on labels"
        fields = as_dict(payload.get("fields"))
        summary = issue.summary
        description = issue.description
        components = list(issue.components)
        custom = dict(issue.custom_fields)
        for name, value in fields.items():
            if name == "labels":
                labels = self._labels(value, errors)
            elif name == "summary":
                if not isinstance(value, str) or not value.strip():
                    errors["summary"] = "You must specify a summary of the issue."
                else:
                    summary = value.strip()
            elif name == "description":
                if not is_adf(value):
                    errors["description"] = (
                        "Operation value must be an Atlassian Document (see the Atlassian Document Format)"
                    )
                else:
                    description = value
            elif name == "components":
                components = self._components_named(value, errors)
            elif name.startswith("customfield_") and self.workflow.custom_field(name) is not None:
                chosen = as_dict(value).get("value") if isinstance(value, dict) else value
                if chosen not in self.workflow.custom_field(name).options:
                    errors[name] = f"Option value '{chosen}' is not valid"
                else:
                    custom[name] = chosen
            else:
                errors[name] = SCREEN_REJECTION.format(field=name)
        if errors:
            issue.refusals.append(
                {"at": self._timestamp(), "request": "edit", "errors": dict(errors)}
            )
            raise Refused(400, [], errors)
        issue.labels, issue.summary, issue.description = labels, summary, description
        issue.components, issue.custom_fields = components, custom
        issue.updated = self._timestamp()
        return 204, None

    def _delete_issue(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        del self._issues[issue.key]
        return 204, None

    def _add_comment(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        body = as_dict(payload).get("body")
        if not is_adf(body):
            raise Refused(
                400,
                [],
                {
                    "comment": "Operation value must be an Atlassian Document (see the Atlassian Document Format)"
                },
            )
        comment = self._comment(issue, body)
        return 201, self._comment_json(comment)

    def _comment(self, issue: Issue, body: dict) -> Comment:
        comment = Comment(str(self._next_comment), body, self._timestamp())
        self._next_comment += 1
        issue.comments.append(comment)
        issue.updated = comment.created
        return comment

    def _comment_json(self, comment: Comment) -> dict:
        return {
            "self": self._self(f"comment/{comment.id}"),
            "id": comment.id,
            "author": dict(ACCOUNT),
            "body": comment.body,
            "created": comment.created,
            "updated": comment.created,
            "jsdPublic": True,
        }

    def _comments(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        start = int(first(query, "startAt", "0"))
        size = int(first(query, "maxResults", "100"))
        order = first(query, "orderBy", "created")
        comments = list(issue.comments)
        if order.startswith("-"):
            comments.reverse()
        return 200, {
            "startAt": start,
            "maxResults": size,
            "total": len(comments),
            "comments": [self._comment_json(c) for c in comments[start : start + size]],
        }

    def _transitions(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        return 200, {
            "expand": "transitions",
            "transitions": [
                self._transition_json(transition)
                for transition in self.workflow.available(issue.status)
            ],
        }

    def _transition_json(self, transition: Transition) -> dict:
        fields = {}
        if transition.takes_resolution:
            fields["resolution"] = {
                "required": False,
                "schema": {"type": "resolution", "system": "resolution"},
                "name": "Resolution",
                "key": "resolution",
                "operations": ["set"],
                "allowedValues": [dict(resolution) for resolution in RESOLUTIONS],
            }
        return {
            "id": transition.id,
            "name": transition.name,
            "to": self.workflow.status(transition.to).as_json(),
            "hasScreen": transition.takes_resolution,
            "isGlobal": transition.from_statuses is None,
            "isInitial": False,
            "isAvailable": True,
            "isConditional": False,
            "fields": fields,
        }

    def _transition(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        issue = self._issue(key)
        payload = as_dict(payload)
        wanted = str(as_dict(payload.get("transition")).get("id", ""))
        transition = next(
            (t for t in self.workflow.available(issue.status) if t.id == wanted), None
        )
        if transition is None:
            raise Refused(
                400,
                [f"Transition id '{wanted or '?'}' is not valid for this issue."],
            )
        fields = as_dict(payload.get("fields"))
        errors: dict[str, str] = {}
        resolution = None
        comment_body = None
        for name, value in fields.items():
            if name == "resolution":
                if not transition.takes_resolution:
                    errors[name] = SCREEN_REJECTION.format(field=name)
                    continue
                chosen = as_dict(value).get("name") or as_dict(value).get("id")
                named = next((r for r in RESOLUTIONS if chosen in (r["name"], r["id"])), None)
                if named is None:
                    errors[name] = f"Resolution name '{chosen}' is not valid"
                else:
                    resolution = named["name"]
            elif name == "comment":
                body = value if is_adf(value) else as_dict(value).get("body")
                if not is_adf(body):
                    errors[name] = (
                        "Operation value must be an Atlassian Document (see the Atlassian Document Format)"
                    )
                else:
                    comment_body = body
            else:
                errors[name] = SCREEN_REJECTION.format(field=name)
        update = as_dict(payload.get("update"))
        for name, operations in update.items():
            if name != "comment":
                errors[name] = SCREEN_REJECTION.format(field=name)
                continue
            for operation in as_list(operations):
                body = as_dict(as_dict(operation).get("add")).get("body")
                if not is_adf(body):
                    errors[name] = (
                        "Operation value must be an Atlassian Document (see the Atlassian Document Format)"
                    )
                else:
                    comment_body = body
        if errors:
            issue.refusals.append(
                {
                    "at": self._timestamp(),
                    "request": f"transition {transition.name} to {transition.to}",
                    "errors": dict(errors),
                }
            )
            raise Refused(400, [], errors)
        now = self._timestamp()
        before = issue.status
        target = self.workflow.status(transition.to)
        if transition.sets_resolution:
            resolution = transition.sets_resolution
        if target.category == "done":
            if resolution is not None:
                issue.resolution, issue.resolutiondate = resolution, now
        else:
            issue.resolution, issue.resolutiondate = None, None
        issue.status = target.name
        issue.updated = now
        issue.history.append(
            {
                "at": now,
                "from": before,
                "to": target.name,
                "transition": transition.name,
                "resolution": issue.resolution,
                "resolution_requested": as_dict(fields.get("resolution")).get("name")
                if "resolution" in fields
                else None,
            }
        )
        if comment_body is not None:
            self._comment(issue, comment_body)
        return 204, None

    def _issue_json(self, issue: Issue, wanted: set[str] | None) -> dict:
        status = self.workflow.status(issue.status)
        resolution = next((r for r in RESOLUTIONS if r["name"] == issue.resolution), None)
        kind = next(t for t in self._issue_types() if t["name"] == issue.issuetype)
        fields = {
            "summary": issue.summary,
            "description": issue.description,
            "labels": list(issue.labels),
            "status": status.as_json(),
            "resolution": {**resolution, "self": self._self(f"resolution/{resolution['id']}")}
            if resolution
            else None,
            "resolutiondate": issue.resolutiondate,
            "issuetype": kind,
            "project": self._project_json(),
            "priority": {"name": issue.priority, "id": str(PRIORITIES.index(issue.priority) + 1)},
            "components": [self._component_json(name) for name in issue.components],
            "created": issue.created,
            "updated": issue.updated,
            "reporter": dict(ACCOUNT),
            "assignee": None,
            "comment": {
                "comments": [self._comment_json(c) for c in issue.comments],
                "total": len(issue.comments),
                "startAt": 0,
                "maxResults": len(issue.comments),
            },
        }
        for custom in self.workflow.custom_fields:
            chosen = issue.custom_fields.get(custom.id)
            fields[custom.id] = (
                {"value": chosen, "id": str(custom.options.index(chosen) + 1)} if chosen else None
            )
        if wanted is not None:
            fields = {name: value for name, value in fields.items() if name in wanted}
        return {
            "expand": "",
            "id": issue.id,
            "self": self._self(f"issue/{issue.id}"),
            "key": issue.key,
            "fields": fields,
        }

    # --- search ---

    def _search(self, query: dict, payload: object, *_) -> tuple[int, object]:
        jql = first(query, "jql", "")
        clauses, order = parse_jql(jql)
        for clause in clauses:
            if (
                clause.field == "project"
                and clause.value.upper() != self.project_key
                and clause.operator == "="
            ):
                raise Refused(
                    400,
                    [f"The value '{clause.value}' does not exist for the field 'project'."],
                )
        now = self._now()
        found = [issue for issue in self._issues.values() if self._matches(issue, clauses, now)]
        found.sort(key=lambda issue: int(issue.key.rpartition("-")[2]))
        if order is not None:
            attribute, descending = order
            found.sort(
                key=lambda issue: (
                    getattr(issue, attribute)
                    if attribute != "key"
                    else int(issue.key.rpartition("-")[2])
                ),
                reverse=descending,
            )
        size = min(int(first(query, "maxResults", "50")), 100)
        start = int(first(query, "nextPageToken", "0") or 0)
        page = found[start : start + size]
        wanted = requested_fields(query)
        answer: dict = {
            "issues": [self._issue_json(issue, wanted) for issue in page],
            "isLast": start + size >= len(found),
        }
        if not answer["isLast"]:
            answer["nextPageToken"] = str(start + size)
        return 200, answer

    def _matches(self, issue: Issue, clauses: list[Clause], now: datetime) -> bool:
        for clause in clauses:
            if not self._matches_one(issue, clause, now):
                return False
        return True

    def _matches_one(self, issue: Issue, clause: Clause, now: datetime) -> bool:
        field_name, operator, value = clause.field, clause.operator, clause.value
        status = self.workflow.status(issue.status)
        if field_name == "project":
            actual = issue.key.rpartition("-")[0].upper() == value.upper()
        elif field_name == "issuetype":
            actual = issue.issuetype.lower() == value.lower()
        elif field_name == "labels":
            actual = value in issue.labels
        elif field_name == "status":
            actual = issue.status.lower() == value.lower()
        elif field_name == "statuscategory":
            category = CATEGORIES[status.category]
            actual = value.lower() in (
                category["name"].lower(),
                category["key"],
                str(category["id"]),
            )
        elif field_name == "resolution":
            if value.lower() in ("unresolved", "empty", "null"):
                actual = issue.resolution is None
            else:
                actual = (issue.resolution or "").lower() == value.lower()
        elif field_name == "key":
            actual = issue.key.upper() == value.upper()
        elif field_name == "created":
            created = datetime.strptime(issue.created, JIRA_TIME).replace(tzinfo=UTC)
            threshold = now - relative(value, clause.text)
            if operator in (">=", ">"):
                return created >= threshold
            return created <= threshold
        else:  # pragma: no cover - parse_jql refuses these first
            raise Refused(400, [f"The fake Jira does not understand the clause '{clause.text}'"])
        return actual if operator in ("=", "is") else not actual

    # --- the project's facts ---

    def _issue_types(self) -> list[dict]:
        return [
            {
                "self": self._self("issuetype/1"),
                "id": "1",
                "name": INCIDENT,
                "description": "",
                "subtask": False,
            },
            {
                "self": self._self("issuetype/2"),
                "id": "2",
                "name": SERVICE_REQUEST,
                "description": "",
                "subtask": False,
            },
        ]

    def _project_json(self) -> dict:
        return {
            "self": self._self(f"project/{self.project_id}"),
            "id": self.project_id,
            "key": self.project_key,
            "name": self.project_name,
            "projectTypeKey": "service_desk",
            "simplified": False,
            "style": "classic",
            "isPrivate": False,
        }

    def _known_project(self, key_or_id: str) -> None:
        if key_or_id.upper() != self.project_key and key_or_id != self.project_id:
            raise Refused(404, [f"No project could be found with key '{key_or_id}'."])

    def _project(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        self._known_project(key)
        return 200, self._project_json()

    def _component_json(self, name: str) -> dict:
        number = self.workflow.components.index(name) + 1
        return {
            "self": self._self(f"component/{number}"),
            "id": str(number),
            "name": name,
            "description": "",
            "project": self.project_key,
            "projectId": int(self.project_id),
        }

    def _components(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        self._known_project(key)
        return 200, [self._component_json(name) for name in self.workflow.components]

    def _statuses(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        self._known_project(key)
        incident, request = self._issue_types()
        return 200, [
            {**incident, "statuses": [status.as_json() for status in self.workflow.statuses]},
            {
                **request,
                "statuses": [
                    Status("901", "Waiting for support", "new").as_json(),
                    Status("902", "In progress", "indeterminate").as_json(),
                    Status("903", "Resolved", "done").as_json(),
                ],
            },
        ]

    def _createmeta_types(self, query: dict, payload: object, key: str) -> tuple[int, object]:
        self._known_project(key)
        return 200, offset_page(self._issue_types(), "issueTypes", query)

    def _createmeta_fields(
        self, query: dict, payload: object, key: str, type_id: str
    ) -> tuple[int, object]:
        self._known_project(key)
        kind = next((t for t in self._issue_types() if t["id"] == type_id), None)
        if kind is None:
            raise Refused(
                404, ["The issue type does not exist or you do not have permission to view it."]
            )
        fields = [
            system_field(
                "summary", "Summary", {"type": "string", "system": "summary"}, required=True
            ),
            system_field(
                "issuetype",
                "Issue Type",
                {"type": "issuetype", "system": "issuetype"},
                required=True,
            ),
            system_field(
                "project", "Project", {"type": "project", "system": "project"}, required=True
            ),
            system_field(
                "reporter",
                "Reporter",
                {"type": "user", "system": "reporter"},
                required=True,
                default=True,
            ),
            system_field("description", "Description", {"type": "string", "system": "description"}),
            system_field(
                "labels",
                "Labels",
                {"type": "array", "items": "string", "system": "labels"},
                operations=["add", "set", "remove"],
            ),
            {
                **system_field(
                    "priority", "Priority", {"type": "priority", "system": "priority"}, default=True
                ),
                "allowedValues": [
                    {"name": name, "id": str(n)} for n, name in enumerate(PRIORITIES, start=1)
                ],
            },
        ]
        if self.workflow.components:
            fields.append(
                {
                    **system_field(
                        "components",
                        "Components",
                        {"type": "array", "items": "component", "system": "components"},
                        operations=["add", "set", "remove"],
                    ),
                    "allowedValues": [
                        self._component_json(name) for name in self.workflow.components
                    ],
                }
            )
        if kind["name"] == INCIDENT:
            fields += [custom.createmeta() for custom in self.workflow.custom_fields]
        return 200, offset_page(fields, "fields", query)

    def _resolutions(self, query: dict, payload: object, *_) -> tuple[int, object]:
        values = [
            {**r, "self": self._self(f"resolution/{r['id']}"), "isDefault": False}
            for r in RESOLUTIONS
        ]
        page = offset_page(values, "values", query)
        page["isLast"] = page["startAt"] + page["maxResults"] >= page["total"]
        return 200, page

    def _myself(self, query: dict, payload: object, *_) -> tuple[int, object]:
        return 200, {**ACCOUNT, "self": self._self(ACCOUNT["self"])}

    def _permissions(self, query: dict, payload: object, *_) -> tuple[int, object]:
        project = first(query, "projectKey", "") or first(query, "projectId", "")
        if project and project.upper() != self.project_key and project != self.project_id:
            raise Refused(404, [f"No project could be found with key '{project}'."])
        asked = [name for name in first(query, "permissions", "").split(",") if name]
        if not asked:
            raise Refused(400, ["The 'permissions' query parameter is required"])
        return 200, {
            "permissions": {
                name: {
                    "id": str(n),
                    "key": name,
                    "name": name.replace("_", " ").title(),
                    "type": "PROJECT",
                    "havePermission": name in PERMISSIONS,
                }
                for n, name in enumerate(asked, start=1)
            }
        }

    def _server_info(self, query: dict, payload: object, *_) -> tuple[int, object]:
        now = self._now()
        return 200, {
            "baseUrl": self.base_url,
            "version": "1001.0.0-SNAPSHOT",
            "versionNumbers": [1001, 0, 0],
            "deploymentType": "Cloud",
            "buildNumber": 100000,
            "buildDate": "2026-01-01T00:00:00.000+0000",
            "serverTime": now.strftime(JIRA_TIME),
            "scmInfo": "fake",
            "serverTitle": f"Fake Jira ({self.workflow.name} workflow)",
            "defaultLocale": {"locale": "en_US"},
        }

    def _fields(self, query: dict, payload: object, *_) -> tuple[int, object]:
        fields = [
            {"id": name, "key": name, "name": label, "custom": False, "schema": schema}
            for name, label, schema in (
                ("summary", "Summary", {"type": "string", "system": "summary"}),
                ("description", "Description", {"type": "string", "system": "description"}),
                ("labels", "Labels", {"type": "array", "items": "string", "system": "labels"}),
                ("status", "Status", {"type": "status", "system": "status"}),
                ("resolution", "Resolution", {"type": "resolution", "system": "resolution"}),
                (
                    "components",
                    "Components",
                    {"type": "array", "items": "component", "system": "components"},
                ),
                ("created", "Created", {"type": "datetime", "system": "created"}),
            )
        ]
        fields += [
            {
                "id": custom.id,
                "key": custom.id,
                "name": custom.name,
                "custom": True,
                "schema": custom.createmeta()["schema"],
            }
            for custom in self.workflow.custom_fields
        ]
        return 200, fields

    def _service_desk_json(self) -> dict:
        return {
            "id": self.service_desk_id,
            "projectId": self.project_id,
            "projectName": self.project_name,
            "projectKey": self.project_key,
            "_links": {"self": self._self(f"servicedesk/{self.service_desk_id}", desk=True)},
        }

    def _service_desks(self, query: dict, payload: object, *_) -> tuple[int, object]:
        return 200, desk_page([self._service_desk_json()], query)

    def _service_desk(self, query: dict, payload: object, desk_id: str) -> tuple[int, object]:
        if desk_id not in (self.service_desk_id, self.project_key, self.project_id):
            raise Refused(
                404, ["Service Desk does not exist or you do not have permission to see it."]
            )
        return 200, self._service_desk_json()

    def _queues(self, query: dict, payload: object, desk_id: str) -> tuple[int, object]:
        if desk_id != self.service_desk_id:
            raise Refused(
                404, ["Service Desk does not exist or you do not have permission to see it."]
            )
        queues = [
            {
                "id": "19",
                "name": "All open",
                "jql": f"project = {self.project_key} AND resolution = Unresolved ORDER BY created DESC",
                "fields": ["issuetype", "issuekey", "summary", "status"],
            },
            {
                "id": self.queue_id,
                "name": "Incidents",
                "jql": INCIDENTS_QUEUE_JQL.format(key=self.project_key),
                "fields": ["issuetype", "issuekey", "summary", "status"],
            },
        ]
        return 200, desk_page(queues, query)

    def _self(self, tail: str, desk: bool = False) -> str:
        root = "/rest/servicedeskapi" if desk else "/rest/api/3"
        return f"{self.base_url}{root}/{tail}"


# --- JQL ---


@dataclass(frozen=True)
class Clause:
    field: str
    """Lower-cased."""
    operator: str
    value: str
    text: str
    """The clause as written, for an error that names it."""


ORDER_BY = re.compile(r"\s+ORDER\s+BY\s+(\w+)(?:\s+(ASC|DESC))?\s*$", re.IGNORECASE)
AND = re.compile(r"\s+AND\s+", re.IGNORECASE)
CLAUSE = re.compile(
    r"""^\s*(\w+)\s*(!=|>=|<=|=|>|<|\bIS\s+NOT\b|\bIS\b)\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']+)\s*$""",
    re.IGNORECASE,
)
FIELDS = {
    "project",
    "issuetype",
    "labels",
    "statuscategory",
    "status",
    "resolution",
    "created",
    "key",
}
"""The JQL fields the Skill, `configure`, `verify`, `verify_mvp` and `reset` write. Nothing
else is understood, and refusing it is the point: a Run that wrote a clause outside the
subset would be told so in the rehearsal, rather than found out on a real site."""

ORDERABLE = {"created": "created", "key": "key", "updated": "updated"}


def parse_jql(jql: str) -> tuple[list[Clause], tuple[str, bool] | None]:
    """The clauses of `jql`, and its ORDER BY, or a 400 naming the first clause outside
    the subset."""
    text = jql.strip()
    if not text:
        raise Refused(400, ["A JQL query is required."])
    order = None
    matched = ORDER_BY.search(text)
    if matched:
        attribute = matched[1].lower()
        if attribute not in ORDERABLE:
            raise Refused(400, [f"The fake Jira does not order by '{matched[1]}'"])
        order = (ORDERABLE[attribute], (matched[2] or "ASC").upper() == "DESC")
        text = text[: matched.start()]
    clauses = []
    for piece in AND.split(text):
        clause = CLAUSE.match(piece)
        if clause is None:
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        name, operator, raw = clause[1].lower(), " ".join(clause[2].lower().split()), clause[3]
        if name not in FIELDS:
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        value = raw[1:-1] if raw[:1] in "\"'" else raw
        if operator in ("is", "is not") and value.lower() not in ("empty", "null"):
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        if name == "created" and (
            operator not in (">=", ">", "<=", "<") or RELATIVE.fullmatch(value.strip()) is None
        ):
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        if name != "created" and operator not in ("=", "!=", "is", "is not"):
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        if operator in ("is", "is not") and name != "resolution":
            raise Refused(400, [f"The fake Jira does not understand the clause '{piece.strip()}'"])
        clauses.append(
            Clause(name, {"is": "=", "is not": "!="}.get(operator, operator), value, piece.strip())
        )
    return clauses, order


def relative(value: str, clause: str) -> timedelta:
    matched = RELATIVE.fullmatch(value.strip())
    if matched is None:
        raise Refused(400, [f"The fake Jira does not understand the clause '{clause}'"])
    amount = int(matched[1])
    return {
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
    }[matched[2]]


# --- helpers ---


def as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def first(query: dict, name: str, default: str) -> str:
    values = query.get(name) or []
    return values[0] if values else default


def requested_fields(query: dict) -> set[str] | None:
    """The `fields` a request names, whether repeated or comma-joined; None for all."""
    named = [name for value in query.get("fields", []) for name in value.split(",") if name]
    if not named or "*all" in named:
        return None
    return set(named)


def is_adf(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("type") == "doc"
        and isinstance(value.get("content"), list)
    )


def adf_text(node: object) -> str:
    """The text of an ADF document, paragraphs and list items on separate lines."""
    if isinstance(node, dict):
        if node.get("type") == "text":
            return str(node.get("text", ""))
        parts = [adf_text(child) for child in node.get("content", [])]
        if node.get("type") in ("paragraph", "listItem", "heading"):
            return "".join(parts)
        return "\n".join(part for part in parts if part)
    if isinstance(node, list):
        return "\n".join(adf_text(child) for child in node)
    return ""


def system_field(
    field_id: str,
    name: str,
    schema: dict,
    required: bool = False,
    default: bool = False,
    operations: list[str] | None = None,
) -> dict:
    return {
        "fieldId": field_id,
        "key": field_id,
        "name": name,
        "required": required,
        "hasDefaultValue": default,
        "operations": operations or ["set"],
        "schema": schema,
    }


def offset_page(items: list, name: str, query: dict) -> dict:
    start = int(first(query, "startAt", "0"))
    size = int(first(query, "maxResults", "50"))
    return {
        "startAt": start,
        "maxResults": size,
        "total": len(items),
        name: items[start : start + size],
    }


def desk_page(items: list, query: dict) -> dict:
    start = int(first(query, "start", "0"))
    size = int(first(query, "limit", "50"))
    page = items[start : start + size]
    return {
        "size": len(page),
        "start": start,
        "limit": size,
        "isLastPage": start + size >= len(items),
        "values": page,
    }


# --- the server ---


def build_handler(fake: FakeJira):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            status, answer = fake.handle(self.command, self.path, dict(self.headers.items()), body)
            data = b"" if answer is None else json.dumps(answer).encode("utf-8")
            # Logged before the answer leaves, so the line is there by the time a client reads it.
            logger.info("%s %s %s", self.command, urlsplit(self.path).path, status)
            self.send_response(status)
            if answer is not None:
                self.send_header("Content-Type", "application/json;charset=UTF-8")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="fake-jira"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _serve

        def log_message(self, format, *args):
            """Silenced: `_serve` logs the method, the path and the status, and nothing else."""

    return Handler


class Server:
    """The fake on a socket, in a thread; `url` is where, once bound."""

    def __init__(self, fake: FakeJira, host: str = DEFAULT_HOST, port: int = 0):
        self.fake = fake
        self._server = ThreadingHTTPServer((host, port), build_handler(fake))
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None
        shown = f"[{host}]" if ":" in host else host
        if host in ("0.0.0.0", "::"):
            shown = "localhost"
        self.url = f"http://{shown}:{self._server.server_address[1]}"
        if not fake.base_url:
            fake.base_url = self.url

    def start(self) -> Server:
        self._thread = threading.Thread(
            target=self._server.serve_forever, args=(0.05,), daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._server.server_close()

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m grafana_jsm_sandbox.fake_jira", description=__doc__.splitlines()[0]
    )
    parser.add_argument(
        "--workflow",
        choices=sorted(WORKFLOWS),
        default=ITSM.name,
        help="the Incident workflow the fake project runs (default itsm)",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"default {DEFAULT_PORT}")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"default {DEFAULT_HOST}")
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT_KEY,
        help=f"the project key (default {DEFAULT_PROJECT_KEY})",
    )
    arguments = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(message)s", stream=sys.stdout
    )
    fake = FakeJira(WORKFLOWS[arguments.workflow], arguments.project)
    server = Server(fake, arguments.host, arguments.port)
    logger.info(
        "fake Jira listening on %s: project %s, %s workflow; state at /__fake__/state",
        server.url,
        arguments.project,
        arguments.workflow,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
