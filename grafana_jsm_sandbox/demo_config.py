"""One configuration for the demo: the `.env` at the repo root, and nothing else.

Compose hands `.env` to the demo container as its environment. The laptop helpers,
the reset, the replay and the end-to-end check, read the same file through this
module, so the demo is described once. They never rely on whatever `jira-as`
happens to be configured with in the engineer's own shell: someone who uses it
every day probably has their production site there, reached through the
environment, the keychain or a settings file, and the demo must never write to
it by accident (the 2026-09-23 audit, F10).

The demo's configuration lives here:

- `read_env_file`, which reads the file the way compose does, closely enough for
  the values it holds;
- `DemoProject`, the dedicated Jira project the demo writes to, which has no
  default: a default key would point Runs at whichever project on the site
  happens to have it;
- `InvestigationSettings`, the opt-in Grafana URLs and Viewer token, read from
  the Receiver's environment and passed to a Run only when enabled;
- `jira_as_environment`, the whole environment a laptop helper starts `jira-as`
  with, built from `.env` rather than inherited.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from grafana_jsm_sandbox.forwarder import (
    ENVIRONMENT_VARIABLES,
    IncompleteJiraCredential,
    JiraCredential,
)
from grafana_jsm_sandbox.run_spawner import (
    ALLOWED_PROJECTS_VARIABLE,
    SITE_OPERATIONS_VARIABLE,
    trust_store_from_environment,
)

REPOSITORY = Path(__file__).resolve().parent.parent
"""Where compose is run from, and so where it looks for `.env`."""

ENV_FILE = REPOSITORY / ".env"
"""The single source: what compose hands the container and what the laptop helpers read."""

PROJECT_KEY_VARIABLE = "DEMO_PROJECT_KEY"
"""The key of the dedicated project. Required, with no default."""

FIELD_VARIABLES = {
    "severity_field": "DEMO_SEVERITY_FIELD",
    "urgency_field": "DEMO_URGENCY_FIELD",
    "source_field": "DEMO_SOURCE_FIELD",
    "major_incident_field": "DEMO_MAJOR_INCIDENT_FIELD",
}
"""The project's own custom field ids, which differ on every site. Empty means the project
lacks the field and a Run leaves it off."""

STATUS_VARIABLES = {
    "status_open": "DEMO_STATUS_OPEN",
    "status_in_progress": "DEMO_STATUS_IN_PROGRESS",
    "status_done": "DEMO_STATUS_DONE",
    "status_closed": "DEMO_STATUS_CLOSED",
}
"""The workflow's four roles. An empty closed role means there is no close step."""

STATUS_DEFAULTS = {
    "status_open": "Open",
    "status_in_progress": "Work in progress",
    "status_done": "Completed",
    "status_closed": "Closed",
}
"""Chapter one's ITSM names, used only when the variable is absent."""

QUEUE_URL_VARIABLE = "DEMO_QUEUE_URL"
"""The project's Incidents queue, for the presenter's screen."""

SESSION_ID_VARIABLE = "DEMO_SESSION_ID"
"""Which take this is. Every Incident a Run creates carries `ses-<id>`, and a Run matches only
open Incidents with this take's label, so a rehearsal's leftovers never match the real demo's
alerts. Set per take; `DEFAULT_SESSION_ID` when a `.env` from before it says nothing."""

DEFAULT_SESSION_ID = "demo"

SESSION_ID = re.compile(r"[a-z0-9-]{1,32}")
"""A session id as the spec allows one: lower case, digits and hyphens, so `ses-<id>` is a Jira
label a JQL clause can name without quoting trouble, and short enough to read on a card."""

SESSION_LABEL_PREFIX = "ses-"
"""What the session id becomes on an Incident: the label the Skill searches by and writes."""

JQL_ISSUE_KEY = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*)-[0-9]+\b")
"""What jira-as 2.0.0's project guard reads as an issue key in any JQL it is given
(`jira_as/project_guard.py`, `ISSUE_KEY`), refusing the search when its project is not the
demo's. A session label of that shape, such as `ses-local-1` (`LOCAL-1`) or `ses-2026` (`SES-2026`),
would make every Match search fail, the Run's and `verify`'s alike."""

PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
"""A Jira project key as a Jira admin can create one: a capital, then capitals, digits or
underscores, two to ten in all. Lower case is refused rather than upper-cased, so that the key
in `.env` is the key the queue URL and the Incidents carry."""

FIELD_ID = re.compile(r"customfield_[0-9]+")
"""A custom field's id as createmeta names it, and never its display name."""

CONFIGURE = "python3 -m grafana_jsm_sandbox.configure"
"""The command that reads a project's field ids and queue off Jira and writes them to `.env`."""

SHELL_VARIABLES = ("PATH", "HOME")
"""What a laptop helper's `jira-as` takes from the shell besides the trust store: where to find
`jira-as`, and where its field cache lives."""

PROXY_VARIABLES = tuple(
    spelling
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
    for spelling in (name, name.lower())
)
"""The laptop's explicit proxy, in both spellings `requests` reads. A helper holds the real
token and talks to the real site itself, as the engineer's own `jira-as` does, so reaching it
the way the laptop reaches everything else widens nothing. A Run is another matter, and still
gets none of them: without loopback in `NO_PROXY`, its proxy would carry the sentinel to the
Forwarder (the 2026-09-23 audit, F21)."""

SITE_URL_VARIABLE = ENVIRONMENT_VARIABLES["site_url"]

DOUBLE_QUOTED = re.compile(r'"((?:\\.|[^"\\])*)"')
"""A double-quoted value up to its first unescaped closing quote."""

INLINE_COMMENT = re.compile(r" #")
"""Where an unquoted value ends, when a comment follows it on the same line. Only a space
starts one: compose keeps a `#` after a tab as part of the value."""


class ConfigurationError(ValueError):
    """`.env` does not describe a demo that could work, and says how, without any value in it."""


class IncompleteDemoProject(ConfigurationError):
    """No dedicated project named, or one named in a shape Jira would not have."""


class InvalidSessionId(IncompleteDemoProject):
    """A session id set in a shape the `ses-` label could not carry."""


@dataclass(frozen=True)
class InvestigationSettings:
    """Opt-in Grafana investigation: internal queries and links for the presenter.

    A Run holds the Viewer token only when investigation is enabled. Validation
    names variables rather than values, and does not try the token against Grafana.
    """

    enabled: bool = False
    url: str = "http://localhost:3000"
    presenter_url: str = "http://localhost:3000"
    viewer_token: str = field(default="", repr=False)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> InvestigationSettings:
        """Read the settings, collecting enabled configuration errors without their values."""
        environment = os.environ if environment is None else environment
        flag = environment.get("DEMO_INVESTIGATION_ENABLED", "").strip().lower()
        if flag not in {"", "false", "0", "true", "1"}:
            raise ConfigurationError("DEMO_INVESTIGATION_ENABLED must be true, false, 1 or 0")
        if flag in {"", "false", "0"}:
            return cls()

        failures: list[str] = []
        url = _investigation_url(
            environment, "DEMO_GRAFANA_URL", "http://localhost:3000", failures
        )
        presenter_default = "http://localhost:3000"
        if "DEMO_GRAFANA_PRESENTER_URL" not in environment:
            try:
                port = int(environment.get("GRAFANA_HOST_PORT", "3000"))
                if not 1 <= port <= 65535:
                    raise ValueError
                presenter_default = f"http://localhost:{port}"
            except ValueError:
                failures.append("GRAFANA_HOST_PORT must be an integer from 1 to 65535")
        presenter_url = _investigation_url(
            environment, "DEMO_GRAFANA_PRESENTER_URL", presenter_default, failures
        )
        raw_token = environment.get("DEMO_GRAFANA_VIEWER_TOKEN", "")
        token = raw_token.strip()
        if not token or "\r" in raw_token or "\n" in raw_token:
            failures.append("DEMO_GRAFANA_VIEWER_TOKEN must be nonblank and contain no CR/LF")
        if failures:
            raise ConfigurationError("\n".join(failures))
        return cls(enabled=True, url=url, presenter_url=presenter_url, viewer_token=token)

    def run_environment(self) -> dict[str, str]:
        """Exactly the four normalized investigation variables, or none when disabled."""
        if not self.enabled:
            return {}
        return {
            "DEMO_INVESTIGATION_ENABLED": "true",
            "DEMO_GRAFANA_URL": self.url,
            "DEMO_GRAFANA_PRESENTER_URL": self.presenter_url,
            "DEMO_GRAFANA_VIEWER_TOKEN": self.viewer_token,
        }


def _investigation_url(
    environment: Mapping[str, str], variable: str, default: str, failures: list[str]
) -> str:
    """A Grafana base URL, or a failure naming only the variable."""
    value = environment.get(variable, default).strip()
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme in {"http", "https"}
            and parts.hostname
            and parts.port != 0
            and parts.username is None
            and parts.password is None
            and "?" not in value
            and "#" not in value
            and not any(character.isspace() or ord(character) < 32 for character in value)
        )
    except ValueError:
        valid = False
    if not valid:
        failures.append(f"{variable} must be an absolute http/https base URL")
    return value.rstrip("/")


def session_id_from_environment(environment: Mapping[str, str] | None = None) -> str:
    """This take's session id: `DEMO_SESSION_ID`, or the default when it is not set."""
    environment = os.environ if environment is None else environment
    value = environment.get(SESSION_ID_VARIABLE, "").strip()
    if not value:
        return DEFAULT_SESSION_ID
    problem = session_id_problem(value)
    if problem:
        raise InvalidSessionId(f"{SESSION_ID_VARIABLE} {problem}")
    return value


def session_id_problem(value: str) -> str | None:
    """Why `value` cannot be a session id, worded to follow its variable's name; None if it can."""
    if not SESSION_ID.fullmatch(value):
        return (
            f"is not a session id: {value!r} (1 to 32 of a-z, 0-9 and -, which becomes the "
            f"{SESSION_LABEL_PREFIX}<id> label on every Incident)"
        )
    looks_like_a_key = JQL_ISSUE_KEY.search(session_label(value))
    if looks_like_a_key:
        return (
            f"is not a session id: {value!r} makes the label {session_label(value)}, in which "
            f"jira-as reads {looks_like_a_key[0]} as an issue key and refuses every search; "
            "start it with a letter and put no hyphen before a digit, as in local1 or reh2"
        )
    return None


def session_label(session_id: str) -> str:
    """The Jira label a take's Incidents carry."""
    return f"{SESSION_LABEL_PREFIX}{session_id}"


def read_env_file(path: Path = ENV_FILE) -> dict[str, str]:
    """The variables in an env file, read the way compose reads it.

    Compose's rules, as `docker compose config` shows them: blank lines and
    `#` lines are skipped, an `export ` prefix is allowed, whitespace around the
    name and the value goes, a value in single quotes is taken literally, one in
    double quotes loses its quotes and the backslash in `\\"` and `\\\\`, and an
    unquoted value ends at a `#` that follows a space. A line with no `=` is
    skipped: compose would pass that name through from its own shell, which is
    nothing this file says. A quote that never closes is refused, as compose
    refuses it, naming the line and never its value.

    It is close enough rather than exact, for values like the demo's, which
    hold no `$` and no backslash. Compose also interpolates `$VAR` and `${VAR}`
    in unquoted and double-quoted values, and expands escapes such as `\\n` and
    `\\t` inside double quotes; this reader leaves both as written, so a value
    that used them would reach the container and a laptop helper differently.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigurationError(
            f"{path} does not exist: `cp .env.example .env` at the repo root, then fill it in"
        ) from None
    variables = {}
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, equals, value = line.partition("=")
        if not equals:
            continue
        name = name.strip()
        variables[name] = _value(value.strip(), f"{path}:{number}: {name}")
    return variables


def compose_environment(
    path: Path = ENV_FILE, shell: Mapping[str, str] | None = None
) -> dict[str, str]:
    """What compose interpolates `docker-compose.yml`'s `${...}` from: `.env`, the shell over it.

    That precedence is compose's own, so a helper that works out where compose
    published something, such as the replay's default Receiver, reads it from
    here and lands where compose did. Without a `.env` it is the shell alone,
    because compose would not get as far as publishing anything.
    """
    shell = os.environ if shell is None else shell
    from_file = read_env_file(path) if path.exists() else {}
    return {**from_file, **shell}


@dataclass(frozen=True)
class DemoProject:
    """The dedicated Jira Service Management project the demo writes to, and its site facts.

    The key is what Runs, the reset and the end-to-end check are confined to.
    The field ids are the project's own, read off it by `configure`; one that is
    empty is a field the project lacks, which a Run then leaves off. The session
    id is this take's, and rides along because it is rendered into the Skill
    beside the project's facts. Status roles name this workflow's path; an empty
    closed role leaves the Incident in done after reset.
    """

    key: str
    severity_field: str | None = None
    urgency_field: str | None = None
    source_field: str | None = None
    major_incident_field: str | None = None
    queue_url: str | None = None
    session_id: str = DEFAULT_SESSION_ID
    status_open: str = STATUS_DEFAULTS["status_open"]
    status_in_progress: str = STATUS_DEFAULTS["status_in_progress"]
    status_done: str = STATUS_DEFAULTS["status_done"]
    status_closed: str = STATUS_DEFAULTS["status_closed"]

    @property
    def session_label(self) -> str:
        """The `ses-<id>` label every Incident of this take carries."""
        return session_label(self.session_id)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> DemoProject:
        """Read the project, or raise one error naming every value that is missing or malformed.

        Every failure is collected, as the Receiver's own configuration does, so a
        half-filled `.env` is fixed in one pass.
        """
        environment = os.environ if environment is None else environment
        failures = []
        session_id = DEFAULT_SESSION_ID
        try:
            session_id = session_id_from_environment(environment)
        except InvalidSessionId as failure:
            failures.append(str(failure))
        key = environment.get(PROJECT_KEY_VARIABLE, "").strip()
        if not key:
            failures.append(
                f"{PROJECT_KEY_VARIABLE} is not set: name the demo's dedicated Jira project in "
                f".env, then `{CONFIGURE}` fills in its field ids"
            )
        elif not PROJECT_KEY.fullmatch(key):
            failures.append(
                f"{PROJECT_KEY_VARIABLE} is not a Jira project key: {key!r} "
                "(a capital letter, then 1 to 9 capitals, digits or underscores)"
            )
        fields = {}
        for attribute, variable in FIELD_VARIABLES.items():
            value = environment.get(variable, "").strip()
            if value and not FIELD_ID.fullmatch(value):
                failures.append(
                    f"{variable} is not a custom field id like customfield_10085: {value!r}; "
                    f"`{CONFIGURE}` reads the right one off the project"
                )
            fields[attribute] = value or None
        if failures:
            raise IncompleteDemoProject("\n".join(failures))
        return cls(
            key=key,
            queue_url=environment.get(QUEUE_URL_VARIABLE, "").strip() or None,
            session_id=session_id,
            **fields,
            **{
                attribute: environment.get(variable, STATUS_DEFAULTS[attribute]).strip()
                for attribute, variable in STATUS_VARIABLES.items()
            },
        )


def jira_as_environment(
    values: Mapping[str, str],
    shell: Mapping[str, str] | None = None,
    warn: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """The whole environment a laptop helper starts `jira-as` with, from `.env`'s `values`.

    It is built rather than inherited, like a Run's (ADR 0002), so nothing in the
    shell can send the helper somewhere else. jira-as reads the site, email and
    token from the environment first and asks the keychain and its settings
    files only when one of the three is missing (jira_as/config_manager.py:96-120
    in 2.0.0), so all three come from `.env`. Its other knobs stay behind too:
    a `JIRA_AS_TRANSPORT` left in the shell would answer from a simulation.

    `JIRA_ALLOWED_PROJECTS` confines every call to the demo's project, and
    `JIRA_ALLOW_SITE_OPERATIONS` lets through the site-scoped calls the allow list
    otherwise refuses, such as reading the site's fields or its server info. Both
    variables win over a `.claude/settings.json`: jira-as reads its settings file
    from the first `.claude` directory above its working directory, which in this
    repo is the committed one, but consults the file's `allowed_projects` and
    `allow_site_operations` only when the variable is absent
    (jira_as/config_manager.py:211-216 and 233-238). The committed file names no
    project key at all (its jira block only allows site operations, and its
    permission rules deny a Claude session Read and Edit of `./.env`), and even a
    settings file that did name one could not veto a key set here. So the
    children run wherever the helper was started rather than from a directory
    outside the repo.

    PATH and HOME come from the shell, which is where `jira-as` and its cache
    are, and so do the trust-store variables, for a laptop behind an
    intercepting proxy, and the explicit proxy variables, for one that reaches
    the site only through a named proxy. A shell whose own `JIRA_SITE_URL` names
    another site is said out loud through `warn`, because the engineer may think
    they are working on it.
    """
    shell = os.environ if shell is None else shell
    warn = _to_stderr if warn is None else warn
    failures = []
    credential = project = None
    try:
        credential = JiraCredential.from_environment(values)
    except IncompleteJiraCredential as failure:
        failures.append(str(failure))
    try:
        project = DemoProject.from_environment(values)
    except IncompleteDemoProject as failure:
        failures.append(str(failure))
    if failures or credential is None or project is None:
        raise ConfigurationError("\n".join(failures))
    theirs = _host(shell.get(SITE_URL_VARIABLE, ""))
    ours = _host(credential.site_url)
    if theirs and theirs != ours:
        warn(
            f"this shell's {SITE_URL_VARIABLE} is {theirs}, but .env names {ours}; "
            f"jira-as is given .env's"
        )
    return {
        **{name: shell[name] for name in (*SHELL_VARIABLES, *PROXY_VARIABLES) if name in shell},
        **trust_store_from_environment(shell),
        SITE_URL_VARIABLE: credential.site_url,
        ENVIRONMENT_VARIABLES["email"]: credential.email,
        ENVIRONMENT_VARIABLES["api_token"]: credential.api_token,
        ALLOWED_PROJECTS_VARIABLE: project.key,
        SITE_OPERATIONS_VARIABLE: "true",
    }


def _value(raw: str, where: str) -> str:
    """One value as compose takes it; `where` names the line, never the value, in an error."""
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end < 0:
            raise ConfigurationError(f"{where} opens a quote it never closes")
        return raw[1:end]
    if raw.startswith('"'):
        quoted = DOUBLE_QUOTED.match(raw)
        if quoted is None:
            raise ConfigurationError(f"{where} opens a quote it never closes")
        return re.sub(r'\\(["\\])', r"\1", quoted[1])
    return INLINE_COMMENT.split(raw, maxsplit=1)[0].rstrip()


def _host(url: str) -> str:
    """The host a site URL names, lower case, with or without a scheme; empty for none."""
    url = url.strip()
    if not url:
        return ""
    return (urlsplit(url if "//" in url else f"//{url}").hostname or "").lower()


def _to_stderr(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)
