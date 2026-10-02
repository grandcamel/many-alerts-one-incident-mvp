"""Checking, layer by layer, that the demo will work, before an audience finds out it won't.

    python3 -m grafana_jsm_sandbox.doctor [--only LAYER[,LAYER...]] [--with-model]

It runs these layers in order and stops at the first one that fails, because
each later layer asks questions an earlier failure has already answered: no Jira
check passes with a placeholder token, and no Grafana check means anything with
the stack down.

    host     Docker and Compose, this Python, jira-as 2.x, whether the images compose
             pulls are here, and the laptop ports compose publishes Grafana and the
             Receiver on
    env      `.env`: that it is there, that no placeholder of `.env.example` is left,
             that JIRA_SITE_URL is a site's address or the API gateway's, that exactly
             one model credential is set and which kind, the project key, the session
             id, and whether the Receiver would start on it
    jira     through jira-as with `.env`, as `configure` asks: who the credential is,
             the site, the project and the permissions the account holds on it
    facts    the field ids in `.env` against the project's own create screen and the
             values the Skill writes, the Incident workflow and the resolution Done,
             and the Incidents queue: whether `configure` can find it, and whether
             the address in `.env` is one of the project's queues
    stack    `docker compose ps`, the demo container's health, and this command again
             inside the container (`--in-container`, below)
    grafana  what the running Grafana took from the provisioning files, asked of its
             HTTP API on the laptop port compose published it on: the contact point, the
             incident_group policy with one-minute updates and three-minute repeats,
             every MVP rule, a series for each rule's query, and whether each is Normal

`--only` names the layers to run, comma-separated, still in that order.
`--with-model` adds one short, real Run to the stack layer; it is off by default
because it costs a little of the Claude account's usage.

Inside the container (the stack layer runs it with `docker compose exec -T demo`):

    python3 -m grafana_jsm_sandbox.doctor --in-container [--with-model]

it checks what only the container can: that it can make itself non-dumpable, that
the Receiver's `/proc/1/environ` is unreadable to the Runs' uid, that the Skill
rendered into the runs directory names the project, and that Jira answers
`/rest/api/3/myself` for the container's credential, through a Forwarder the way a
Run's call goes, from the container's own network address. Of Jira's answer it
prints the status and what the status means, never the account.

Docker hands every process it execs into the container the container's whole
environment, the real Jira token included, as the Runs' own uid, and dumpable
(ADR 0002's amendment). So this process makes itself non-dumpable before it reads
its environment or does anything else, before even its own imports, with a module
that imports nothing of the package. The window that is left runs from the exec to
that call, the interpreter's own start-up, during which a Run working at the same
moment could read the token from this process's `/proc/<pid>/environ` through one
of jira-as's file-reading paths.
Nothing it starts afterwards gets the token: the Forwarder is a thread of this
process, and the one child, `--with-model`'s Run, gets a Run's environment.

`--with-model` asks one Run, started with exactly the flags an Alert's Run gets
(`run_command.build_run_command`, the allow list included) and by the Run spawner
itself, to run `jira-as --version` and read its rendered Skill, and nothing else.
Its Jira is an address where nothing listens, so whatever it does it cannot reach
the site, and its token is a throwaway sentinel. It says which model it asked for
(`RUN_MODEL`) and which one the seat really ran, read from the Run's Transcript:
the same model, or an alias resolved to its full name, is OK, and any other model
is a WARN. The Receiver's startup does not check that the seat can run the model,
so this is where that shows. It says whether the Run failed and why, in the words
of the log's `[FAILED]` and `[hint]` lines, and whether either allowed call was
denied, which would mean the organisation's managed permission rules override the
Run's own. Its working directory, and so its Transcript, stay under the runs
directory, as a Run's do.

Every line it prints is one of these, for a person at a terminal and for the
setup skill to parse:

    [<layer>] OK <check> — <what it found>
    [<layer>] WARN <check> — <what is off, what it costs, the fix>[; ask: ...]
    [<layer>] FAIL <check> — <what stops the demo, and the fix>[; ask: docs/admin-requests.md#<anchor> ...]
    not checked: <layer>, ...; an earlier layer failed
    READY | NOT READY: [<layer>] <check> — <what the first FAIL said>

The layers inside the container are `container` and `model`, and the stack layer
passes their lines on as they are. A FAIL names the admin request that fixes it,
and so does a WARN whose cost an admin can take away (images not pulled yet, a
field the Skill leaves off), always as `docs/admin-requests.md#<anchor>`.
Each line is one line: whatever a tool said is folded onto it, redacted, and cut
short. The exit status is 0 when it ends READY, 1 when it ends NOT READY, and 2
for bad arguments or a Python older than 3.11.
"""

from __future__ import annotations

import sys

# Checked before anything else is imported, so an older python3 gets a sentence rather than a
# traceback from an import that needs a newer one. The whole file is still compiled first,
# so it must keep to syntax an older python3 can read; what follows only runs on 3.11.
if sys.version_info < (3, 11):  # noqa: UP036 - pyproject's floor is what this enforces
    sys.stderr.write(
        "python3 -m grafana_jsm_sandbox.doctor needs Python 3.11 or newer, and this is "
        + sys.version.split()[0]
        + ": run it with a newer python3 (README, What you need)\n"
    )
    raise SystemExit(2)

_REFUSED_FIRST: bool | OSError | None = None
"""What making this process non-dumpable came to, when `--in-container` did it before the
imports below; None when it was not done here."""

# Inside the container this process was exec'd with the real Jira token in its environment,
# readable to the Runs' uid until it is non-dumpable. The imports below take the better part
# of a second where every module compiles from source, so it closes itself before them, with
# a module that imports nothing of the package. A failure is kept for `in_container` to report.
if __name__ == "__main__" and "--in-container" in sys.argv[1:]:
    from grafana_jsm_sandbox.nondumpable import refuse_to_be_read as _refuse_first

    try:
        _REFUSED_FIRST = _refuse_first()
    except OSError as _failure:
        _REFUSED_FIRST = _failure

import argparse
import base64
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast
from urllib.parse import urlencode, urlsplit

from grafana_jsm_sandbox.__main__ import IncompleteConfiguration, Settings
from grafana_jsm_sandbox.configure import (
    ADMIN_REQUESTS,
    AGENT_LICENCE,
    FAIL,
    GATEWAY_HOST,
    IP_ALLOWLIST_REQUEST,
    OK,
    PERMISSIONS,
    SITE_FIELDS,
    UNREACHABLE,
    WARN,
    Check,
    Discovery,
    JiraRefused,
    as_dict,
    as_list,
    attempt,
    call,
    check_fields,
    check_issue_type,
    check_permissions,
    check_project,
    check_queue,
    check_resolution,
    check_statuses,
    clipped,
    find_component,
    one_line,
    refused,
)
from grafana_jsm_sandbox.demo_config import (
    CONFIGURE,
    DEFAULT_SESSION_ID,
    ENV_FILE,
    PROJECT_KEY_VARIABLE,
    QUEUE_URL_VARIABLE,
    REPOSITORY,
    SESSION_ID_VARIABLE,
    SITE_URL_VARIABLE,
    ConfigurationError,
    DemoProject,
    IncompleteDemoProject,
    InvalidSessionId,
    compose_environment,
    jira_as_environment,
    read_env_file,
    session_id_from_environment,
    session_label,
)
from grafana_jsm_sandbox.forwarder import (
    ENVIRONMENT_VARIABLES,
    UNREACHABLE_BODY,
    UNSEARCHED_403_DIAGNOSIS,
    UPSTREAM_TIMEOUT,
    Forwarder,
    IncompleteJiraCredential,
    JiraCredential,
    diagnose,
)
from grafana_jsm_sandbox.log_formatter import (
    HINT,
    HINT_CREDITS,
    HINT_MODEL,
    format_event,
    redact,
    run_failure,
)
from grafana_jsm_sandbox.nondumpable import refuse_to_be_read
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.receiver import Run, RunOutcome
from grafana_jsm_sandbox.replay import (
    BIND_ADDRESS_VARIABLE,
    DEFAULT_BIND_ADDRESS,
    DEFAULT_RECEIVER_HOST_PORT,
    RECEIVER_HOST_PORT_VARIABLE,
    laptop_url,
)
from grafana_jsm_sandbox.reset import JiraAs, jira_as_with
from grafana_jsm_sandbox.run_command import (
    SKILL_FILE,
    build_run_command,
    rendered_skill_directory,
)
from grafana_jsm_sandbox.run_spawner import (
    API_KEY_VARIABLE,
    CREDENTIAL_KINDS,
    MODEL_CREDENTIAL_VARIABLES,
    OAUTH_TOKEN_VARIABLE,
    SENTINEL_BYTES,
    MissingModelCredential,
    RunSpawner,
    model_credential_from_environment,
    trust_store_from_environment,
)

COMMAND = "python3 -m grafana_jsm_sandbox.doctor"

HOST = "host"
ENV = "env"
JIRA = "jira"
FACTS = "facts"
STACK = "stack"
GRAFANA = "grafana"
LAYERS = (HOST, ENV, JIRA, FACTS, STACK, GRAFANA)
"""The laptop's layers, in the order they run. Each stands on the ones before it."""

CONTAINER = "container"
MODEL = "model"
"""The layers checked inside the demo container, which the stack layer passes on."""

CLAUDE_ORG_OWNER = "claude-org-owner"
DOCKER_ADMIN = "docker-admin"
"""The requests only `doctor` names; `configure` names the Jira and Atlassian ones it shares."""

ENV_EXAMPLE = REPOSITORY / ".env.example"
"""Whose placeholder values must not be left in `.env`."""

ENGINEERS_OWN = (
    *ENVIRONMENT_VARIABLES.values(),
    *MODEL_CREDENTIAL_VARIABLES,
    PROJECT_KEY_VARIABLE,
)
"""The variables only the engineer can fill in, so whatever `.env.example` holds for them is a
placeholder. Its other values may be real defaults, which `.env` is free to keep."""

COMPOSE_FILE = REPOSITORY / "docker-compose.yml"
"""Where the images compose pulls are named."""

BUILT_HERE = "grafana-jsm-sandbox"
"""The prefix of the images compose builds from this repo rather than pulls."""

SERVICES = ("lgtm", "demo", "rolldice", "traffic")
"""The stack's services, each of which must be running for the demo, traffic until it is
stopped on purpose."""

TRAFFIC = "traffic"
DEMO = "demo"
LGTM = "lgtm"

GRAFANA_HOST_PORT_VARIABLE = "GRAFANA_HOST_PORT"
DEFAULT_GRAFANA_HOST_PORT = 3000

COMPOSE_CPUS = (2, 17)
COMPOSE_PIDS_LIMIT = (2, 2)
"""The Compose releases that first apply `cpus` and `pids_limit`; an older one leaves them off."""

TOOL_TIMEOUT = 30.0
"""Seconds a `docker` or `jira-as` question may take before it counts as no answer."""

IN_CONTAINER_TIMEOUT = 90.0
"""Seconds `doctor --in-container` may take without a model Run: a Jira call and file reads."""

MODEL_TIMEOUT = 180.0
"""Seconds `--with-model`'s Run may take: two tool calls, well inside a real Run's timeout."""

GRAFANA_TIMEOUT = 10.0

MYSELF = "/rest/api/3/myself"
"""Who the credential is: the one Jira call made from inside the container."""

NOT_A_SITE = (
    f"JIRA_SITE_URL answered 404 for {MYSELF}, so it is not a Jira Cloud site's address: check it "
    f"in .env (with a scoped token it is https://{GATEWAY_HOST}/ex/jira/<cloudId>)"
)
"""What a 404 means for the question every Jira site answers."""

GATEWAY_PATH = re.compile(r"/ex/jira/([0-9A-Fa-f-]{36})")
"""The only path a scoped token's `JIRA_SITE_URL` has: the site's cloud id on the gateway."""

RECEIVER_ENVIRON = Path("/proc/1/environ")
"""The Receiver's environment in the container, where the real Jira token is."""

SKILL_PROJECT_ROW = "| Project | `{key}` |"
"""The row of the rendered Skill's facts table that names the project a Run writes to."""

RECEIVER_ON_THE_NETWORK = "http://demo:8080/notification"
"""The Receiver as Grafana's contact point must name it: by compose service name."""

RULE_UID = "rolldice-rate-zero"
"""The primary Alert rule, also watched by chapter-one verify."""

EXPECTED_RULES = {
    RULE_UID: "30s",
    "rolldice-2xx-drop": "30s",
    "rolldice-probe-failing": "20s",
    "rolldice-outage-sustained": "2m",
}
"""The MVP's provisioned Alert rules and their pending periods."""

EVALUATION_INTERVAL = 10
GROUP_BY = ["incident_group"]
GROUP_INTERVAL = "1m"
INCIDENT_GROUP = "checkout-outage"
REPEAT_INTERVAL = "3m"
LONGEST_GROUP_WAIT = 30
RULE_SERVICE = "rolldice"
"""What the provisioning files say and what the live Alert depends on, as the opt-in
`tests/test_grafana.py` checks them."""

FIELD_MAPPING_LABELS = ("severity", "service")
"""The rule's labels the Skill's field mapping reads: `severity` becomes the Severity and
Urgency, `service` the Component. Without one, every Incident lacks what it maps to."""

PROMETHEUS = "prometheus"
"""The datasource uid the rule's query runs against."""

NOWHERE = "http://127.0.0.1:9"
"""Where `--with-model`'s Run finds Jira: the discard port on loopback, where nothing listens."""

MODEL_PROMPT = (
    "This Run is doctor's preflight check, not a Notification: there is no "
    f"{NOTIFICATION_FILENAME} and no Incident to handle, so do not follow the skill. Do exactly "
    "three things and nothing else. First, run `jira-as --version` with Bash. Second, run "
    "`incident-payload --help` with Bash. Third, Read {skill}. Then reply with one line: what "
    "jira-as printed, and the skill's first heading."
)
"""What `--with-model`'s Run is asked: one call each of the three its allow list has, all
harmless, so a denial of any can only come from rules above the Run's own."""

HINT_REQUESTS = {
    HINT_CREDITS: CLAUDE_ORG_OWNER,
    HINT_MODEL: CLAUDE_ORG_OWNER,
}
"""The failed-Run hints whose fix is the Claude organisation's: its usage, and the models it
allows. A refused credential is the engineer's own to replace, with a new API key or another
`claude setup-token`; only an organisation that gives out neither needs asking, which the env
layer names when there is no credential at all."""

LINE = re.compile(
    r"^\[(?P<layer>[a-z]+)\] (?P<level>OK|WARN|FAIL) (?P<check>[^—]+?) — (?P<message>.*?)"
    rf"(?:; ask: (?P<ask>(?:{re.escape(ADMIN_REQUESTS)}#[a-z0-9-]+ ?)+))?$"
)
"""One check line, as `Line.text` writes it: how the stack layer reads the container's."""


@dataclass(frozen=True)
class Line:
    """One printed check: its layer, how it came out, and whom to ask when it failed."""

    layer: str
    level: str
    check: str
    message: str
    ask: tuple[str, ...] = ()

    @classmethod
    def of(cls, layer: str, check: Check) -> Line:
        """A `configure` check, printed in this layer."""
        return cls(layer, check.level, check.name, check.message, check.ask)

    @classmethod
    def parse(cls, text: str) -> Line | None:
        found = LINE.match(text)
        if found is None:
            return None
        asks = (found["ask"] or "").split()
        return cls(
            found["layer"],
            found["level"],
            found["check"],
            found["message"],
            tuple(ask.removeprefix(f"{ADMIN_REQUESTS}#") for ask in asks),
        )

    @property
    def summary(self) -> str:
        """The line without its level or requests, as NOT READY names the first blocker."""
        return f"[{self.layer}] {self.check} — {one_line(self.message)}"

    @property
    def text(self) -> str:
        text = f"[{self.layer}] {self.level} {self.check} — {one_line(self.message)}"
        if self.ask:
            text += "; ask: " + " ".join(f"{ADMIN_REQUESTS}#{anchor}" for anchor in self.ask)
        return text


@dataclass(frozen=True)
class Answer:
    """What one command said and how it exited."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], float], Answer]
"""`run(argv, timeout) -> Answer`, from the repo root. A missing executable raises
`FileNotFoundError`, and no answer in time `subprocess.TimeoutExpired`."""


def run_here(argv: Sequence[str], timeout: float) -> Answer:
    """One command, from where compose finds this repo's stack."""
    done = subprocess.run(
        list(argv),
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return Answer(done.returncode, done.stdout, done.stderr)


def port_is_free(address: str, port: int) -> bool:
    """Whether compose could publish on `address:port`: nothing else may hold it.

    Bound without `SO_REUSEADDR`, so a port held on the wildcard address counts as
    held on loopback too, as it does when Docker then tries to publish there.
    """
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((address, port))
        except OSError:
            return False
    return True


def said(text: str) -> str:
    """What a tool said, fit for a line: redacted, on one line, and cut short."""
    return clipped(redact(text.strip())) or "nothing"


@dataclass
class Laptop:
    """Everything the laptop's layers ask of the world, each replaceable in a test."""

    env_file: Path = ENV_FILE
    run: Runner = run_here
    port_free: Callable[[str, int], bool] = port_is_free
    jira_as: JiraAs | None = None
    """Replaces the real `jira-as`, which is otherwise built from `.env` as `configure`'s is."""
    shell: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    with_model: bool = False
    example_file: Path = ENV_EXAMPLE
    compose_file: Path = COMPOSE_FILE
    _jira: tuple[DemoProject, str, JiraAs] | None = field(default=None, init=False, repr=False)

    def values(self) -> dict[str, str]:
        """`.env`'s variables; a file that cannot be read is a `ConfigurationError` like any."""
        try:
            return read_env_file(self.env_file)
        except (OSError, UnicodeDecodeError) as failure:
            raise ConfigurationError(
                f"{self.env_file} could not be read ({failure.__class__.__name__}): make it a "
                "UTF-8 text file you can read"
            ) from None

    def published(self) -> dict[str, str]:
        """What compose interpolates the published ports and images from, `.env` or no `.env`."""
        try:
            return compose_environment(self.env_file, self.shell)
        except (ConfigurationError, OSError, UnicodeDecodeError):
            return dict(self.shell)

    def jira(self) -> tuple[DemoProject, str, JiraAs]:
        """The project, the site and the `jira-as` the jira and facts layers ask, built once,
        so a shell that names another site is warned about once."""
        if self._jira is None:
            values = self.values()
            environment = jira_as_environment(values, self.shell)
            project = DemoProject.from_environment(values)
            jira_as = jira_as_with(environment) if self.jira_as is None else self.jira_as
            self._jira = (project, environment[SITE_URL_VARIABLE], jira_as)
        return self._jira


# --- host ---


def host(laptop: Laptop) -> list[Line]:
    """What the laptop needs installed and free before compose or jira-as can do anything."""
    lines = [Line(HOST, OK, "python", f"{platform.python_version()} ({sys.executable})")]
    docker = docker_line(laptop)
    lines.append(docker)
    if docker.level != FAIL:
        lines.append(compose_line(laptop))
    lines.append(jira_as_line(laptop))
    if docker.level != FAIL:
        lines += image_lines(laptop)
    lines += port_lines(laptop, docker_works=docker.level != FAIL)
    return lines


def asked(laptop: Laptop, argv: Sequence[str], timeout: float = TOOL_TIMEOUT) -> Answer | str:
    """A command's answer, or a sentence saying why there was none."""
    try:
        return laptop.run(argv, timeout)
    except FileNotFoundError:
        return f"{argv[0]} is not on PATH"
    except subprocess.TimeoutExpired:
        return f"`{' '.join(argv[:3])}` had no answer in {timeout:g} s"


def docker_line(laptop: Laptop) -> Line:
    answer = asked(laptop, ["docker", "version", "--format", "{{.Server.Version}}"])
    if isinstance(answer, str):
        return Line(
            HOST,
            FAIL,
            "docker",
            f"{answer}: install Docker Desktop, or Docker Engine with the Compose plugin "
            "(README, What you need)",
        )
    if answer.returncode != 0 or not answer.stdout.strip():
        return Line(
            HOST,
            FAIL,
            "docker",
            f"the Docker daemon did not answer ({said(answer.stderr)}): start Docker Desktop, "
            "or the docker service",
        )
    return Line(HOST, OK, "docker", f"Docker Engine {answer.stdout.strip()}")


def version_of(text: str) -> tuple[int, ...] | None:
    """The first dotted version in `text`, as numbers."""
    found = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    return None if found is None else tuple(int(part) for part in found.groups() if part)


def dotted(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def compose_line(laptop: Laptop) -> Line:
    """Compose v2, new enough to apply the demo container's limits.

    An older Compose starts the stack all the same and silently leaves `cpus` (before
    2.17) or `pids_limit` (before 2.2) off, so it is a warning, not a stop.
    """
    answer = asked(laptop, ["docker", "compose", "version", "--short"])
    if isinstance(answer, str) or answer.returncode != 0:
        return Line(
            HOST,
            FAIL,
            "compose",
            "`docker compose` does not answer here: install the Compose v2 plugin "
            "(docker-compose v1 will not do)",
        )
    version = version_of(answer.stdout)
    if version is None:
        return Line(
            HOST, WARN, "compose", f"Compose's version could not be read: {said(answer.stdout)}"
        )
    if version < COMPOSE_CPUS:
        missing = "cpus and pids_limit" if version < COMPOSE_PIDS_LIMIT else "cpus"
        return Line(
            HOST,
            WARN,
            "compose",
            f"Compose {dotted(version)} leaves the demo container's {missing} off, so a runaway "
            f"Run is not held to them: update Docker to Compose {dotted(COMPOSE_CPUS)} or newer",
        )
    return Line(HOST, OK, "compose", f"Compose {dotted(version)}")


def jira_as_line(laptop: Laptop) -> Line:
    """jira-as 2.x on the laptop, which `configure`, the reset and this command run."""
    answer = asked(laptop, ["jira-as", "--version"])
    fix = "install the Jira Assistant CLI 2.x (README, What you need)"
    if isinstance(answer, str):
        return Line(HOST, FAIL, "jira-as", f"{answer}: {fix}")
    version = version_of(answer.stdout)
    if answer.returncode != 0 or version is None:
        return Line(
            HOST,
            FAIL,
            "jira-as",
            f"`jira-as --version` did not say a version ({said(answer.stderr or answer.stdout)}): "
            f"{fix}",
        )
    if version[0] < 2:
        return Line(
            HOST,
            FAIL,
            "jira-as",
            f"jira-as {dotted(version)} is older than the 2.0 the reset, configure and the Skill "
            f"are written against: {fix}",
        )
    if version[0] > 2:
        return Line(
            HOST,
            WARN,
            "jira-as",
            f"jira-as {dotted(version)} is newer than the 2.x the demo was verified against; "
            "the image carries its own 2.0.0 for Runs",
        )
    return Line(HOST, OK, "jira-as", f"jira-as {dotted(version)}")


def pulled_images(compose_file: Path, environment: Mapping[str, str]) -> list[str]:
    """The images compose pulls rather than builds, as `environment` interpolates them."""

    def interpolated(found: re.Match) -> str:
        return environment.get(found[1], "").strip() or found[2]

    images = []
    for match in re.finditer(r"(?m)^\s*image:\s*(\S+)\s*$", compose_file.read_text()):
        image = re.sub(r"\$\{(\w+):-([^}]*)\}", interpolated, match[1])
        if not image.startswith(BUILT_HERE):
            images.append(image)
    return images


def image_lines(laptop: Laptop) -> list[Line]:
    """Whether the images compose would pull are already here.

    Not a stop: `docker compose up` pulls them. But a laptop whose registry access is
    refused finds out only then, so the line says whom to ask now.
    """
    try:
        images = pulled_images(laptop.compose_file, laptop.published())
    except OSError as failure:
        return [Line(HOST, WARN, "images", f"docker-compose.yml could not be read: {failure}")]
    missing = []
    for image in images:
        answer = asked(laptop, ["docker", "image", "inspect", "--format", "{{.Id}}", image])
        if isinstance(answer, str) or answer.returncode != 0:
            missing.append(image)
    if not missing:
        return [Line(HOST, OK, "images", f"{', '.join(images)} already here")]
    return [
        Line(
            HOST,
            WARN,
            "images",
            f"not pulled yet: {', '.join(missing)}; `docker compose up` pulls them from Docker "
            "Hub, and where that is refused a mirror named in LGTM_IMAGE can stand in",
            (DOCKER_ADMIN,),
        )
    ]


def port_lines(laptop: Laptop, docker_works: bool) -> list[Line]:
    """Whether compose can publish Grafana and the Receiver where `.env` says it will.

    A port held by this very stack, already up, is as it should be; compose says which
    service publishes what, when Docker answers at all.
    """
    environment = laptop.published()
    address = environment.get(BIND_ADDRESS_VARIABLE, "").strip() or DEFAULT_BIND_ADDRESS
    lines = []
    if not is_loopback(address):
        lines.append(
            Line(
                HOST,
                WARN,
                "bind address",
                f"{BIND_ADDRESS_VARIABLE}={address} publishes Grafana, whose anonymous user is an "
                "Admin, and the Receiver, which starts paid Runs, beyond this laptop",
            )
        )
    services: list[dict] | None = None
    for variable, default, service, what in (
        (GRAFANA_HOST_PORT_VARIABLE, DEFAULT_GRAFANA_HOST_PORT, LGTM, "Grafana"),
        (RECEIVER_HOST_PORT_VARIABLE, DEFAULT_RECEIVER_HOST_PORT, DEMO, "the Receiver"),
    ):
        check = f"{service} port"
        raw = environment.get(variable, "").strip() or str(default)
        if not raw.isdigit() or not 0 < int(raw) < 65536:
            lines.append(Line(HOST, FAIL, check, f"{variable} is not a port number: {raw!r}"))
            continue
        port = int(raw)
        if laptop.port_free(address, port):
            lines.append(Line(HOST, OK, check, f"{address}:{port} is free for {what}"))
            continue
        if services is None:
            services = compose_services(laptop) if docker_works else []
            services = services if isinstance(services, list) else []
        if publishes(services, service, port):
            lines.append(
                Line(HOST, OK, check, f"{address}:{port} is {what}'s, published by this stack")
            )
            continue
        lines.append(
            Line(
                HOST,
                FAIL,
                check,
                f"{address}:{port} is taken by another program, so compose cannot publish {what} "
                f"there: stop it, or set {variable} in .env to a free port",
            )
        )
    return lines


def is_loopback(address: str) -> bool:
    if address == "localhost":
        return True
    try:
        return ipaddress.ip_address(address.strip("[]")).is_loopback
    except ValueError:
        return False


def publishes(services: list[dict], service: str, port: int) -> bool:
    """Whether `service`, in `docker compose ps`'s answer, publishes `port` on the laptop."""
    return any(
        entry.get("Service") == service
        and any(
            as_dict(published).get("PublishedPort") == port
            for published in as_list(entry.get("Publishers"))
        )
        for entry in services
    )


def compose_services(laptop: Laptop) -> list[dict] | str:
    """Every container of this repo's stack as `docker compose ps` describes it, or why not.

    Compose has printed this as one JSON array, and since 2.21 as one object per line;
    both are read.
    """
    answer = asked(laptop, ["docker", "compose", "ps", "--all", "--format", "json"])
    if isinstance(answer, str):
        return answer
    if answer.returncode != 0:
        return f"`docker compose ps` failed: {said(answer.stderr)}"
    text = answer.stdout.strip()
    try:
        if text.startswith("["):
            entries = json.loads(text)
        else:
            entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    except ValueError:
        return f"`docker compose ps` answered something other than JSON: {said(text)}"
    return [entry for entry in as_list(entries) if isinstance(entry, dict)]


# --- env ---


def env(laptop: Laptop) -> list[Line]:
    """Whether `.env` describes a demo that could work, without printing anything secret in it."""
    try:
        values = laptop.values()
    except ConfigurationError as failure:
        return [Line(ENV, FAIL, ".env", str(failure))]
    lines = [Line(ENV, OK, ".env", f"{laptop.env_file} is readable")]
    lines.append(placeholder_line(values, laptop.example_file))
    try:
        credential = JiraCredential.from_environment(values)
    except IncompleteJiraCredential as failure:
        lines.append(Line(ENV, FAIL, "jira credential", str(failure)))
    else:
        lines.append(site_line(credential.site_url))
    lines.append(model_credential_line(values))
    try:
        # The session has a line of its own, below, so here it is held to nothing: a
        # session id in the wrong shape is that line's fault to name, not the key's.
        project = DemoProject.from_environment({**values, SESSION_ID_VARIABLE: ""})
    except IncompleteDemoProject as failure:
        lines.append(Line(ENV, FAIL, "project key", "; ".join(str(failure).splitlines())))
    else:
        lines.append(Line(ENV, OK, "project key", f"DEMO_PROJECT_KEY={project.key}"))
    lines.append(session_line(values))
    if not any(line.level == FAIL for line in lines):
        lines.append(receiver_line(values))
    return lines


def placeholder_line(values: Mapping[str, str], example_file: Path) -> Line:
    """Whether a value only the engineer can give is still what `.env.example` says."""
    try:
        example = read_env_file(example_file)
    except (ConfigurationError, OSError, UnicodeDecodeError) as failure:
        return Line(ENV, WARN, "placeholders", f"the example could not be read: {failure}")
    left = [
        name
        for name in ENGINEERS_OWN
        if example.get(name, "").strip() and values.get(name, "").strip() == example[name].strip()
    ]
    if left:
        return Line(
            ENV,
            FAIL,
            "placeholders",
            f"{', '.join(left)} still hold .env.example's placeholder: paste your own into .env",
        )
    return Line(ENV, OK, "placeholders", "none of .env.example's placeholders is left")


def site_line(url: str) -> Line:
    """Whether `JIRA_SITE_URL` is an address jira-as and the Forwarder can put an API path after.

    A site's own address has no path; a scoped token's is the API gateway's, with the
    site's cloud id and nothing else. Anything more would be doubled up by the API
    path both append.
    """
    parts = urlsplit(url)
    site = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    if parts.scheme != "https":
        return Line(
            ENV,
            FAIL,
            "site url",
            f"{SITE_URL_VARIABLE} must be an https:// address, not {parts.scheme}://: Jira Cloud "
            "answers only over TLS",
        )
    if parts.query or parts.fragment:
        return Line(ENV, FAIL, "site url", f"{SITE_URL_VARIABLE} must carry no query or fragment")
    if site == GATEWAY_HOST:
        cloud = GATEWAY_PATH.fullmatch(path)
        if cloud is None:
            return Line(
                ENV,
                FAIL,
                "site url",
                f"{SITE_URL_VARIABLE} on {GATEWAY_HOST} must be https://{GATEWAY_HOST}/ex/jira/"
                f"<cloudId>, not {path or '/'}: the cloud id is at "
                "https://<site>.atlassian.net/_edge/tenant_info",
            )
        return Line(
            ENV, OK, "site url", f"the API gateway for cloud id {cloud[1]}, for a scoped token"
        )
    if site.endswith(".atlassian.net"):
        if path:
            return Line(
                ENV,
                FAIL,
                "site url",
                f"{SITE_URL_VARIABLE} must be the site's address alone, https://{site}, without "
                f"{path}: jira-as and the Forwarder add the API's path themselves",
            )
        return Line(ENV, OK, "site url", f"https://{site}")
    return Line(
        ENV,
        WARN,
        "site url",
        f"{site or url!r} is neither an atlassian.net site nor the API gateway: fine for a "
        "custom domain, which the demo has not been tried on",
    )


CREDENTIAL_PREFIXES = {
    API_KEY_VARIABLE: "sk-ant-api",
    OAUTH_TOKEN_VARIABLE: "sk-ant-oat",
}
"""How each kind of model credential announces itself. A value with the other kind's prefix is
in the wrong variable: the Claude CLI would take it, and the API would then refuse the Run."""


def model_credential_line(values: Mapping[str, str]) -> Line:
    """Whether exactly one model credential is there, and which kind; never its value.

    Either kind is taken: a work API key is the MVP's, a `claude setup-token` token
    still works. What is refused is none, both, or one in the other's variable.
    """
    check = "model credential"
    try:
        credential = model_credential_from_environment(values)
    except MissingModelCredential as failure:
        if all(values.get(variable, "").strip() for variable in MODEL_CREDENTIAL_VARIABLES):
            return Line(ENV, FAIL, check, str(failure))
        return Line(
            ENV,
            FAIL,
            check,
            f"{failure}: paste a work API key ({CREDENTIAL_PREFIXES[API_KEY_VARIABLE]}...) into "
            f"{API_KEY_VARIABLE}, or what `claude setup-token` prints into "
            f"{OAUTH_TOKEN_VARIABLE}; where the organisation gives out neither",
            (CLAUDE_ORG_OWNER,),
        )
    (other,) = set(MODEL_CREDENTIAL_VARIABLES) - {credential.variable}
    if credential.value.startswith(CREDENTIAL_PREFIXES[other]):
        return Line(
            ENV,
            FAIL,
            check,
            f"{credential.variable} holds {CREDENTIAL_KINDS[other]}, not {credential.kind}: put "
            f"it in {other} instead, and leave {credential.variable} unset",
        )
    if not credential.value.startswith(CREDENTIAL_PREFIXES[credential.variable]):
        return Line(
            ENV,
            WARN,
            check,
            f"{credential.variable} does not look like {credential.kind} "
            f"({CREDENTIAL_PREFIXES[credential.variable]}...); `--with-model` shows whether "
            "Claude takes it",
        )
    return Line(ENV, OK, check, f"{credential.kind} ({credential.variable}), and only it")


def session_line(values: Mapping[str, str]) -> Line:
    """Which take this is, as the `ses-` label on its Incidents will say.

    Unset is not a stop, so a `.env` from before the session id still runs, but it
    is worth a warning: every take then shares one label, and a rehearsal's leftover
    Incident is what the real demo's alerts would match.
    """
    try:
        session_id = session_id_from_environment(values)
    except InvalidSessionId as failure:
        return Line(ENV, FAIL, "session", str(failure))
    if not values.get(SESSION_ID_VARIABLE, "").strip():
        return Line(
            ENV,
            WARN,
            "session",
            f"{SESSION_ID_VARIABLE} is not set, so every take's Incidents carry "
            f"{session_label(DEFAULT_SESSION_ID)}: set one per rehearsal in .env, so a rehearsal's "
            "leftovers never match the real demo's alerts",
        )
    return Line(
        ENV,
        OK,
        "session",
        f"{SESSION_ID_VARIABLE}={session_id}, so this take's Incidents carry "
        f"{session_label(session_id)}",
    )


def receiver_line(values: Mapping[str, str]) -> Line:
    """Whether the Receiver would start on this `.env`, as the container will read it."""
    try:
        settings = Settings.from_environment(values)
    except IncompleteConfiguration as failure:
        return Line(
            ENV,
            FAIL,
            "receiver",
            f"the Receiver would refuse this .env: {'; '.join(str(failure).splitlines())}",
        )
    budget = (
        "no spending cap"
        if settings.run_budget_usd is None
        else f"at most ${settings.run_budget_usd:g} a Run"
    )
    return Line(
        ENV,
        OK,
        "receiver",
        f"the Receiver would start: Runs ask for {settings.run_model}, {budget}",
    )


# --- jira and facts ---


def refusal_line(
    layer: str, check: str, failure: JiraRefused, not_found: str | None = None
) -> Line:
    """What a refused Jira call means, the same from the laptop and from inside the container.

    Both reduce Jira's answer to a status and words and hand them to `configure`'s
    classifier, which reads an IP allowlist's refusal with the Forwarder's own pattern:
    the laptop's words are what jira-as reported, the container's are what the
    Forwarder's `diagnose` made of the body. A 404 means what the question makes it mean.
    """
    if failure.status == 404 and not_found is not None:
        return Line(layer, FAIL, check, not_found)
    if failure.status == 403 and str(failure) == UNSEARCHED_403_DIAGNOSIS:
        return Line(
            layer,
            FAIL,
            check,
            f"Jira refused the account in .env (403): {UNSEARCHED_403_DIAGNOSIS}",
            (PERMISSIONS, IP_ALLOWLIST_REQUEST),
        )
    return Line.of(layer, refused(check, failure))


def jira(laptop: Laptop) -> list[Line]:
    """Who the credential in `.env` is, on which site, and what it may do on the project."""
    try:
        project, _, jira_as = laptop.jira()
    except ConfigurationError as failure:
        return [Line(JIRA, FAIL, ".env", "; ".join(str(failure).splitlines()))]
    try:
        return jira_checks(jira_as, project.key)
    except FileNotFoundError:
        return [
            Line(
                JIRA,
                FAIL,
                "jira-as",
                "jira-as is not on PATH: install the Jira Assistant CLI 2.x (README, What you need)",
            )
        ]


def jira_checks(jira_as: JiraAs, key: str) -> list[Line]:
    """The first call is who the credential is: when Jira refuses that, nothing else would pass."""
    try:
        me = as_dict(call(jira_as, "getCurrentUser"))
    except JiraRefused as failure:
        return [refusal_line(JIRA, "whoami", failure, NOT_A_SITE)]
    lines = [whoami_line(me)]
    try:
        lines.append(server_line(as_dict(call(jira_as, "getServerInfo"))))
    except JiraRefused as failure:
        lines.append(refusal_line(JIRA, "server", failure))
    found = Discovery()
    if check_project(found, jira_as, key) is not None:
        attempt(found, "permissions", check_permissions, jira_as, key)
    return lines + [Line.of(JIRA, check) for check in found.checks]


def whoami_line(me: dict) -> Line:
    if me.get("active") is False:
        return Line(
            JIRA,
            FAIL,
            "whoami",
            "the account in .env is deactivated: ask for it back, or use another",
            (AGENT_LICENCE,),
        )
    kind = " (a service account)" if me.get("accountType") == "app" else ""
    return Line(
        JIRA,
        OK,
        "whoami",
        f"Jira accepts the credential in .env, as {me.get('displayName') or 'an unnamed account'}"
        f"{kind}",
    )


def server_line(info: dict) -> Line:
    kind = info.get("deploymentType")
    if kind and kind != "Cloud":
        return Line(JIRA, FAIL, "server", f"the site is Jira {kind}, and the demo needs Jira Cloud")
    return Line(JIRA, OK, "server", f"Jira Cloud at {info.get('baseUrl') or 'an unnamed site'}")


def facts(laptop: Laptop) -> list[Line]:
    """The project's own facts, as `configure` reads them, held against what `.env` says."""
    try:
        values = laptop.values()
        project, site, jira_as = laptop.jira()
    except ConfigurationError as failure:
        return [Line(FACTS, FAIL, ".env", "; ".join(str(failure).splitlines()))]
    key = project.key
    found = Discovery()
    try:
        component = attempt(found, "component", find_component, jira_as, key, site)
        incident = attempt(found, "issue type", check_issue_type, jira_as, key)
        if incident is not None:
            has_component = component is not None and component[1]
            attempt(found, "create screen", check_fields, jira_as, key, incident, has_component)
        attempt(found, "statuses", check_statuses, jira_as, key, incident, project, False)
        attempt(found, "resolution", check_resolution, jira_as)
        attempt(
            found,
            "service desk",
            check_queue,
            jira_as,
            key,
            project_id_of(jira_as, key),
            site,
            project.queue_url or "",
        )
    except FileNotFoundError:
        return [
            Line(
                FACTS,
                FAIL,
                "jira-as",
                "jira-as is not on PATH: install the Jira Assistant CLI 2.x (README, What you need)",
            )
        ]
    lines = [Line.of(FACTS, check) for check in found.checks]
    lines += held_to_env(values, found.facts)
    lines.append(queue_url_line(project.queue_url, QUEUE_URL_VARIABLE in found.facts))
    return lines


def project_id_of(jira_as: JiraAs, key: str) -> str:
    """The project's id, as `configure` reads it, or empty when Jira would not say.

    A queue's JQL may name the project by id as well as by key, and `check_queue` accepts
    both only when it is given the id, so `doctor` and `configure` must give it the same.
    """
    try:
        return str(as_dict(call(jira_as, "getProject", "--project-id-or-key", key)).get("id") or "")
    except JiraRefused:
        return ""


def queue_url_line(queue_url: str | None, discoverable: bool) -> Line:
    """Whether `.env` has the queue's address, and how to get it there when it has not.

    `configure --write` is advised only when `configure` found the queue, which is what
    `discoverable` says. When it found none, or Jira would not say, running it again
    writes nothing, so the address is the engineer's to copy from the queue itself.
    """
    if queue_url:
        return Line(FACTS, OK, "queue url", f"{QUEUE_URL_VARIABLE} is set")
    empty = f"{QUEUE_URL_VARIABLE} is empty, so the runbook and verify have no queue to open"
    if discoverable:
        return Line(FACTS, WARN, "queue url", f"{empty}: `{CONFIGURE} --write`")
    return Line(
        FACTS,
        WARN,
        "queue url",
        f"{empty}, and `{CONFIGURE}` cannot find it for you: set it by hand, from the project's "
        "Queues, by clicking the one that shows its open Incidents and copying its address "
        f"into {QUEUE_URL_VARIABLE} in .env (the `queue` lines above list the candidates); "
        f"`{CONFIGURE}` then checks it",
    )


def held_to_env(values: Mapping[str, str], found: Mapping[str, str]) -> list[Line]:
    """Each field id in `.env` against the one the project's create screen gives.

    A Run writes what `.env` said when its container was created, so an id the project
    no longer has is a create the project refuses. An empty one only costs the field.
    Major incident is a field a Run never touches, so any difference there is a warning.
    """
    fix = f"`{CONFIGURE} --write`, then `docker compose up -d demo`"
    lines = []
    for site_field in SITE_FIELDS:
        if site_field.variable not in found:
            continue
        check = f"{site_field.check} in .env"
        ours = values.get(site_field.variable, "").strip()
        theirs = found[site_field.variable]
        stop = FAIL if site_field.options else WARN
        if ours == theirs:
            message = (
                f"{site_field.variable}={ours}, the project's own"
                if ours
                else f"{site_field.variable} is empty, as the project has no usable "
                f"{site_field.name}, so a Run leaves it off"
            )
            lines.append(Line(FACTS, OK, check, message))
        elif not ours:
            lines.append(
                Line(
                    FACTS,
                    WARN,
                    check,
                    f"{site_field.variable} is empty, but the project's {site_field.name} is "
                    f"{theirs}, so a Run leaves it off: {fix}",
                )
            )
        elif not theirs:
            lines.append(
                Line(
                    FACTS,
                    stop,
                    check,
                    f"{site_field.variable}={ours}, but the project has no usable "
                    f"{site_field.name}, so a Run would set a field the create refuses: {fix}",
                )
            )
        else:
            lines.append(
                Line(
                    FACTS,
                    stop,
                    check,
                    f"{site_field.variable}={ours}, but the project's {site_field.name} is "
                    f"{theirs}: {fix}",
                )
            )
    return lines


# --- stack ---


def stack(laptop: Laptop) -> list[Line]:
    """Whether the stack is up and healthy, and what the demo container says of itself."""
    services = compose_services(laptop)
    if isinstance(services, str):
        return [Line(STACK, FAIL, "compose", f"{services}: is the stack's .env in place?")]
    if not services:
        return [
            Line(
                STACK,
                FAIL,
                "stack",
                "nothing is up: `docker compose up -d --build`, then `docker compose logs -f demo`",
            )
        ]
    by_name = {str(entry.get("Service")): entry for entry in services}
    lines = [service_line(name, by_name.get(name)) for name in SERVICES]
    demo = by_name.get(DEMO)
    if demo is not None and demo.get("State") == "running":
        lines += in_container_lines(laptop)
    return lines


def service_line(name: str, entry: dict | None) -> Line:
    if entry is None:
        level = WARN if name == TRAFFIC else FAIL
        return Line(STACK, level, name, f"{name} has no container: `docker compose up -d`")
    state = str(entry.get("State") or "unknown")
    if state != "running":
        if name == TRAFFIC:
            return Line(
                STACK,
                WARN,
                name,
                f"{name} is {state}, so the Alert fires within a minute: "
                f"`docker compose start {TRAFFIC}` before the demo",
            )
        why = " (a half-filled .env is named there)" if name == DEMO else ""
        return Line(
            STACK,
            FAIL,
            name,
            f"{name} is {state}: `docker compose logs {name}` says why{why}, and "
            f"`docker compose up -d {name}` starts it",
        )
    health = str(entry.get("Health") or "")
    if health == "unhealthy":
        return Line(
            STACK,
            FAIL,
            name,
            f"{name} is running but unhealthy: `docker compose logs {name}` says why",
        )
    if health == "starting":
        return Line(
            STACK,
            WARN,
            name,
            f"{name} is running and its healthcheck has not passed yet: run doctor again in a "
            "few seconds",
        )
    return Line(STACK, OK, name, f"running{', healthy' if health == 'healthy' else ''}")


def in_container_lines(laptop: Laptop) -> list[Line]:
    """This command inside the demo container, its lines passed on as it printed them.

    The non-secret project key and session `.env` holds now go with it, so a container
    created for another project or rehearsal is caught here.
    """
    argv = [
        "docker",
        "compose",
        "exec",
        "-T",
        DEMO,
        "python3",
        "-m",
        "grafana_jsm_sandbox.doctor",
        "--in-container",
    ]
    try:
        project = DemoProject.from_environment(laptop.values())
        argv += ["--project-key", project.key, "--session-id", project.session_id]
    except ConfigurationError:
        pass
    timeout = IN_CONTAINER_TIMEOUT
    if laptop.with_model:
        argv.append("--with-model")
        timeout += MODEL_TIMEOUT
    answer = asked(laptop, argv, timeout)
    if isinstance(answer, str):
        return [
            Line(
                STACK,
                FAIL,
                "in-container",
                f"{answer}: `docker compose logs demo` says whether the container is stuck, and "
                "`docker compose restart demo` restarts it",
            )
        ]
    lines = [
        line
        for line in map(Line.parse, answer.stdout.splitlines())
        if line is not None and line.layer in (CONTAINER, MODEL)
    ]
    # 0 is READY and 1 NOT READY; anything else is the check itself falling over,
    # after whatever lines it managed to print.
    if lines and answer.returncode in (0, 1):
        return lines
    text = f"{answer.stderr}\n{answer.stdout}"
    missing_doctor = "No module named grafana_jsm_sandbox.doctor" in text
    missing_session_check = "unrecognized arguments: --session-id" in text
    if missing_doctor or missing_session_check:
        return [
            Line(
                STACK,
                FAIL,
                "in-container",
                "the demo image predates "
                f"{'doctor' if missing_doctor else 'the session check'}: rebuild it with "
                "`docker compose up -d --build demo`",
            )
        ]
    last = (answer.stderr.strip() or answer.stdout.strip()).splitlines()[-1:] or [""]
    return [
        *lines,
        Line(
            STACK,
            FAIL,
            "in-container",
            f"`doctor --in-container` exited {answer.returncode}: {said(last[0])}",
        ),
    ]


# --- grafana ---


class GrafanaUnanswered(Exception):
    """Grafana gave no answer this command could read, and why."""


GRAFANA_FIX = (
    f"`docker compose logs {LGTM}` says why, and `docker compose restart {LGTM}` restarts it"
)
"""What to do when Grafana's API answers a check with an error."""


_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))
"""For Grafana on the laptop: never through a proxy."""


def ask_grafana(base: str, path: str, form: Mapping[str, str] | None = None) -> object:
    """One question for Grafana's HTTP API, as its anonymous Admin; a POST when `form` is given."""
    request = urllib.request.Request(
        base + path,
        data=None if form is None else urlencode(form).encode(),
        headers={"Accept": "application/json"},
        method="GET" if form is None else "POST",
    )
    if form is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with _LOCAL.open(request, timeout=GRAFANA_TIMEOUT) as answer:
            body = answer.read()
    except urllib.error.HTTPError as error:
        raise GrafanaUnanswered(f"{path} answered {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        reason = getattr(error, "reason", error)
        raise GrafanaUnanswered(f"nothing answered at {base} ({reason})") from None
    try:
        return json.loads(body)
    except ValueError:
        raise GrafanaUnanswered(f"{path} answered something other than JSON") from None


def seconds(duration: object) -> int | None:
    """A Grafana duration such as `10s`, `1m` or `1m30s`, in seconds; None when it is not one."""
    text = str(duration)
    parts = re.findall(r"(\d+)([smh])", text)
    if not parts or "".join(f"{number}{unit}" for number, unit in parts) != text:
        return None
    return sum(int(number) * {"s": 1, "m": 60, "h": 3600}[unit] for number, unit in parts)


def grafana(laptop: Laptop) -> list[Line]:
    """What the running Grafana took from provisioning, and whether the MVP rules can fire.

    A typo in a provisioning file makes Grafana skip it and say so only in its own log,
    so the files are never read back: Grafana is asked what it actually holds.
    """
    base = laptop_url(GRAFANA_HOST_PORT_VARIABLE, DEFAULT_GRAFANA_HOST_PORT, laptop.published())
    try:
        points = ask_grafana(base, "/api/v1/provisioning/contact-points")
    except GrafanaUnanswered as failure:
        return [
            Line(
                GRAFANA,
                FAIL,
                "grafana",
                f"{failure}: is lgtm up? `docker compose up -d {LGTM}`",
            )
        ]
    lines = []
    point_line, point = contact_point_line(points)
    lines.append(point_line)
    lines.append(checked("policy", policy_line, base, point))
    for uid, pending_period in EXPECTED_RULES.items():
        rule_line, rule = rule_check(base, uid, pending_period)
        lines.append(rule_line)
        if rule is not None:
            lines.append(checked("series", series_line, base, rule))
            lines.append(checked("state", state_line, base, rule))
    return lines


def checked(name: str, check: Callable[..., Line], *arguments) -> Line:
    try:
        return check(*arguments)
    except GrafanaUnanswered as failure:
        return Line(GRAFANA, FAIL, name, f"{failure}: {GRAFANA_FIX}")


def contact_point_line(points: object) -> tuple[Line, str | None]:
    aimed = [
        as_dict(point)
        for point in as_list(points)
        if as_dict(point).get("uid")
        and as_dict(point).get("type") == "webhook"
        and as_dict(as_dict(point).get("settings")).get("url") == RECEIVER_ON_THE_NETWORK
    ]
    if not aimed:
        return Line(
            GRAFANA,
            FAIL,
            "contact point",
            f"no provisioned webhook aims at {RECEIVER_ON_THE_NETWORK}: Grafana did not take "
            "grafana/provisioning/alerting/contact-point.yaml; `docker compose logs lgtm` names "
            "a file it skipped, and `docker compose restart lgtm` reads them again",
        ), None
    point = aimed[0]
    name = str(point.get("name"))
    if point.get("disableResolveMessage"):
        return Line(
            GRAFANA,
            FAIL,
            "contact point",
            f"{name} sends no Resolved, so no Incident is ever Completed",
        ), name
    return Line(
        GRAFANA, OK, "contact point", f"{name}, a webhook at {RECEIVER_ON_THE_NETWORK}"
    ), name


def policy_line(base: str, point: str | None) -> Line:
    policy = as_dict(ask_grafana(base, "/api/v1/provisioning/policies"))
    problems = []
    if point is not None and policy.get("receiver") != point:
        problems.append(f"it sends to {policy.get('receiver')}, not {point}")
    if policy.get("routes"):
        problems.append("it has child routes, which may send the Alert elsewhere")
    if policy.get("group_by") != GROUP_BY:
        problems.append(f"its group_by is {policy.get('group_by')}, not {GROUP_BY}")
    if seconds(policy.get("group_interval")) != seconds(GROUP_INTERVAL):
        problems.append(
            f"its group_interval is {policy.get('group_interval')}, not {GROUP_INTERVAL}, so "
            "related Alerts would not join on the demo's update timing"
        )
    if policy.get("repeat_interval") != REPEAT_INTERVAL:
        problems.append(
            f"it repeats every {policy.get('repeat_interval')}, not every {REPEAT_INTERVAL}, so "
            "the repeat Firings that add trend comments would not come during the demo"
        )
    wait = seconds(policy.get("group_wait"))
    if wait is None or wait > LONGEST_GROUP_WAIT:
        problems.append(
            f"its group wait, {policy.get('group_wait')}, holds the first Notification back "
            f"longer than {LONGEST_GROUP_WAIT}s"
        )
    if problems:
        return Line(
            GRAFANA,
            FAIL,
            "policy",
            f"the notification policy: {'; '.join(problems)}; `docker compose restart lgtm` "
            "reads grafana/provisioning/alerting again",
        )
    return Line(
        GRAFANA,
        OK,
        "policy",
        f"everything to {point}, grouped by incident_group, updated every {GROUP_INTERVAL}, "
        f"repeated every {REPEAT_INTERVAL}",
    )


def rule_check(base: str, uid: str, pending_period: str) -> tuple[Line, dict | None]:
    try:
        rules = as_list(ask_grafana(base, "/api/v1/provisioning/alert-rules"))
        rule = next((as_dict(r) for r in rules if as_dict(r).get("uid") == uid), None)
        if rule is None:
            return Line(
                GRAFANA,
                FAIL,
                "rule",
                f"Grafana has no rule {uid}: it did not take "
                "grafana/provisioning/alerting/alert-rule.yaml; `docker compose logs lgtm` says why",
            ), None
        group = as_dict(
            ask_grafana(
                base,
                f"/api/v1/provisioning/folder/{rule.get('folderUID')}"
                f"/rule-groups/{rule.get('ruleGroup')}",
            )
        )
    except GrafanaUnanswered as failure:
        return Line(GRAFANA, FAIL, "rule", f"{uid}: {failure}: {GRAFANA_FIX}"), None
    problems = []
    if group.get("interval") != EVALUATION_INTERVAL:
        problems.append(f"it is evaluated every {group.get('interval')}s, not every 10s")
    if rule.get("for") != pending_period:
        problems.append(f"it fires after {rule.get('for')}, not {pending_period}")
    labels = as_dict(rule.get("labels"))
    missing = [label for label in FIELD_MAPPING_LABELS if not labels.get(label)]
    if missing:
        problems.append(
            f"it has no {' or '.join(missing)} label, which the Skill's field mapping reads"
        )
    elif labels.get("service") != RULE_SERVICE:
        problems.append(f"its service label is not {RULE_SERVICE}, which the Skill reads")
    if labels.get("incident_group") != INCIDENT_GROUP:
        problems.append(f"its incident_group label is not {INCIDENT_GROUP}")
    if problems:
        return Line(
            GRAFANA,
            FAIL,
            "rule",
            f"{uid}: {'; '.join(problems)}; `docker compose restart lgtm` reads "
            "grafana/provisioning/alerting again",
        ), rule
    return Line(
        GRAFANA,
        OK,
        "rule",
        f"{uid}: {rule.get('title')}, evaluated every {EVALUATION_INTERVAL}s, "
        f"firing after {pending_period}",
    ), rule


def series_line(base: str, rule: dict) -> Line:
    """The rule's own query, run against the Prometheus it reads.

    With no series the rule reads NoData, which the rule keeps Normal on purpose: the
    Alert would then never fire, and nothing but this would say so.
    """
    query = next(
        (
            as_dict(q)
            for q in as_list(rule.get("data"))
            if as_dict(q).get("datasourceUid") == PROMETHEUS
        ),
        None,
    )
    expr = as_dict(as_dict(query).get("model")).get("expr")
    if not expr:
        return Line(
            GRAFANA,
            FAIL,
            "series",
            f"{rule.get('uid')} has no {PROMETHEUS} query: `docker compose restart lgtm` reads "
            "grafana/provisioning/alerting again",
        )
    answer = as_dict(
        ask_grafana(
            base,
            f"/api/datasources/proxy/uid/{PROMETHEUS}/api/v1/query",
            {"query": str(expr)},
        )
    )
    series = as_list(as_dict(answer.get("data")).get("result"))
    if not series:
        return Line(
            GRAFANA,
            FAIL,
            "series",
            f"{rule.get('uid')}: the rule's query matches no series, so the rule reads NoData, "
            "stays Normal and "
            "never fires: rolldice may not have exported yet (wait a minute after `up`, and see "
            "`docker compose ps rolldice`), or the metric's name moved with the image",
        )
    return Line(
        GRAFANA, OK, "series", f"{rule.get('uid')}: the rule's query matches {len(series)} series"
    )


def rule_states(base: str, uid: object) -> list[str]:
    """What Grafana last evaluated rule `uid` to, one state per rule with that uid (normally
    one): `inactive` (Normal), `pending` or `firing`. Empty before its first evaluation, and a
    rule listed without a state counts as not evaluated. `verify` watches the same."""
    groups = as_list(
        as_dict(as_dict(ask_grafana(base, "/api/prometheus/grafana/api/v1/rules")).get("data")).get(
            "groups"
        )
    )
    return [
        str(as_dict(evaluated)["state"])
        for group in groups
        for evaluated in as_list(as_dict(group).get("rules"))
        if as_dict(evaluated).get("uid") == uid and as_dict(evaluated).get("state") is not None
    ]


def state_line(base: str, rule: dict) -> Line:
    uid = rule.get("uid")
    states = rule_states(base, uid)
    if states == ["inactive"]:
        return Line(GRAFANA, OK, "state", f"{uid}: the rule is Normal")
    if not states:
        return Line(GRAFANA, WARN, "state", f"{uid}: Grafana has not evaluated the rule yet")
    return Line(
        GRAFANA,
        WARN,
        "state",
        f"{uid}: the rule is {', '.join(str(state) for state in states)}, not Normal: with "
        f"`docker compose start {TRAFFIC}` it goes Normal within a minute",
    )


# --- inside the container ---


def refused_first() -> bool:
    """Whether this process is non-dumpable, as the refusal before the imports found.

    Its failure is raised again here, for `in_container` to report. When nothing was
    done before the imports, as when `main` is called rather than run, it is done now.
    """
    if _REFUSED_FIRST is None:
        return refuse_to_be_read()
    if isinstance(_REFUSED_FIRST, OSError):
        raise _REFUSED_FIRST
    return _REFUSED_FIRST


def in_container(
    with_model: bool,
    expected_key: str | None = None,
    *,
    expected_session: str | None = None,
    refuse: Callable[[], bool] = refused_first,
    environment: Mapping[str, str] | None = None,
    receiver_environ: Path = RECEIVER_ENVIRON,
) -> list[Line]:
    """The container's checks, the first of them before this process reads its environment.

    `refuse`, `environment` and `receiver_environ` are there for the tests.
    """
    try:
        unreadable = refuse()
    except OSError as failure:
        return [
            Line(
                CONTAINER,
                FAIL,
                "non-dumpable",
                f"this check could not make itself non-dumpable ({failure}), so it stops before "
                "reading the Jira token it was started with",
            )
        ]
    environment = os.environ if environment is None else environment
    lines = [
        Line(CONTAINER, OK, "non-dumpable", "this check's own environment is root's from here on")
        if unreadable
        else Line(CONTAINER, WARN, "non-dumpable", "not Linux, so there is no /proc to close")
    ]
    lines.append(receiver_environ_line(receiver_environ))
    try:
        settings = Settings.from_environment(environment)
    except IncompleteConfiguration as failure:
        lines.append(
            Line(
                CONTAINER,
                FAIL,
                "settings",
                f"the container's environment is incomplete: {'; '.join(str(failure).splitlines())}; "
                "fix .env, then `docker compose up -d demo`",
            )
        )
        return lines
    if expected_key is not None and expected_key != settings.project.key:
        lines.append(
            Line(
                CONTAINER,
                FAIL,
                "project key",
                f"the container was created with DEMO_PROJECT_KEY={settings.project.key}, and .env "
                f"now names {expected_key}: recreate it with `docker compose up -d demo` "
                "(a restart keeps the environment it was created with)",
            )
        )
    if expected_session is not None and expected_session != settings.project.session_id:
        lines.append(
            Line(
                CONTAINER,
                FAIL,
                "session",
                f"the container was created with {SESSION_ID_VARIABLE}="
                f"{settings.project.session_id}, and .env now names {expected_session}: "
                "recreate it with `docker compose up -d demo` "
                "(a restart keeps the environment it was created with)",
            )
        )
    lines.append(skill_line(settings))
    lines.append(myself_line(settings.credential))
    if with_model and not any(line.level == FAIL for line in lines):
        lines += model_lines(settings, environment)
    return lines


def receiver_environ_line(path: Path) -> Line:
    """Whether the Receiver's environment, the real token in it, is closed to the Runs' uid."""
    try:
        with open(path, "rb") as environ:
            environ.read(1)
    except PermissionError:
        return Line(CONTAINER, OK, "receiver environ", f"{path} is unreadable to the Runs' uid")
    except FileNotFoundError:
        return Line(CONTAINER, WARN, "receiver environ", f"there is no {path} here to check")
    except OSError as failure:
        return Line(CONTAINER, WARN, "receiver environ", f"{path} could not be checked: {failure}")
    if os.geteuid() == 0:
        return Line(
            CONTAINER,
            WARN,
            "receiver environ",
            f"this check runs as root, which reads {path} whatever the Receiver does; "
            "run it as the image's own user",
        )
    return Line(
        CONTAINER,
        FAIL,
        "receiver environ",
        f"{path}, which holds the real Jira token, is readable to the Runs' uid: the image "
        "predates the non-dumpable Receiver; rebuild it with `docker compose up -d --build demo`",
    )


def skill_line(settings: Settings) -> Line:
    """Whether the Skill rendered for this start names the project the container was given."""
    path = rendered_skill_directory(settings.runs_directory) / SKILL_FILE
    key = settings.project.key
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as failure:
        return Line(
            CONTAINER,
            FAIL,
            "skill",
            f"no rendered Skill at {path} ({failure.__class__.__name__}): the Receiver renders it "
            "at startup, and `docker compose logs demo` says why it did not",
        )
    if "{{" in text or SKILL_PROJECT_ROW.format(key=key) not in text:
        return Line(
            CONTAINER,
            FAIL,
            "skill",
            f"the Skill at {path} was not rendered for {key}: recreate the container with "
            "`docker compose up -d demo`",
        )
    return Line(CONTAINER, OK, "skill", f"rendered for {key} at {path}")


def myself_line(credential: JiraCredential) -> Line:
    """Jira's answer to `/rest/api/3/myself`, asked the way a Run asks, from the container.

    Through a Forwarder of its own with a sentinel, so the request leaves the container
    exactly as a Run's does: the container's egress address, its trust store, the real
    credential attached by the Forwarder. Only the status is kept; the body names the
    account, and is read only for what the Forwarder's diagnosis makes of a refusal.
    """
    forwarder = Forwarder(credential)
    sentinel = secrets.token_urlsafe(SENTINEL_BYTES)
    forwarder.set_sentinel(sentinel)
    forwarder.start()
    try:
        status, headers, body = through(forwarder.url + MYSELF, credential.email, sentinel)
    finally:
        forwarder.clear_sentinel()
        forwarder.stop()
    if status == 200:
        return Line(
            CONTAINER,
            OK,
            "whoami",
            f"Jira answered 200 to {MYSELF} for the container's credential, through a Forwarder",
        )
    if 300 <= status < 400:
        return Line(
            CONTAINER,
            FAIL,
            "whoami",
            f"JIRA_SITE_URL redirects ({status}), and a Run's calls are never followed past the "
            "site: put the address it redirects to in .env, then `docker compose up -d demo`",
        )
    if status == 502 and body == UNREACHABLE_BODY:
        failure = JiraRefused(503, [f"{UNREACHABLE}: nothing answered the container"])
    else:
        diagnosis = diagnose(status, headers, body)
        failure = JiraRefused(status, [diagnosis] if diagnosis else [])
    return refusal_line(CONTAINER, "whoami", failure, NOT_A_SITE)


def through(url: str, email: str, sentinel: str) -> tuple[int, dict[str, str], bytes]:
    """One GET at the Forwarder, as jira-as would send it with the sentinel for a token."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    encoded = base64.b64encode(f"{email}:{sentinel}".encode()).decode()
    request.add_header("Authorization", f"Basic {encoded}")
    try:
        with _TO_THE_FORWARDER.open(request, timeout=UPSTREAM_TIMEOUT + 5) as answer:
            return answer.status, dict(answer.headers), answer.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


class _Unfollowed(urllib.request.HTTPRedirectHandler):
    """Takes a 3xx the Forwarder hands back as Jira's answer, rather than following it.

    The Forwarder never follows one itself; following it here would send the account's
    email to whatever host the redirect names, past the Forwarder, and read that host's
    answer as Jira's.
    """

    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


_TO_THE_FORWARDER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _Unfollowed)
"""For the Forwarder on loopback: never through a proxy, and never past a redirect."""


class _Nowhere:
    """The Forwarder `--with-model`'s Run is given: one that forwards nothing.

    The Run spawner registers a sentinel with its Forwarder and points the Run's
    jira-as at it. This one holds no credential and its address is a port where
    nothing listens, so the Run's environment is a Run's in every variable, and yet
    no call it makes reaches Jira.
    """

    url = NOWHERE

    def set_sentinel(self, sentinel: str, create_fields: dict | None = None) -> None:
        pass

    def clear_sentinel(self) -> None:
        pass


def model_lines(
    settings: Settings, environment: Mapping[str, str], timeout: float = MODEL_TIMEOUT
) -> list[Line]:
    """One real Run with the real flags, asked for jira-as's version and its Skill, and judged."""
    runs = settings.runs_directory.resolve()
    run_id = f"doctor-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
    run = Run(run_id, runs / run_id)
    skill = rendered_skill_directory(runs) / SKILL_FILE
    try:
        run.working_directory.mkdir(parents=True)
    except OSError as failure:
        return [Line(MODEL, FAIL, "run", f"no working directory under {runs}: {failure}")]
    spawn = RunSpawner(
        command=build_run_command(
            runs,
            settings.project.key,
            model=settings.run_model,
            budget_usd=settings.run_budget_usd,
            prompt=MODEL_PROMPT.format(skill=skill),
        ),
        forwarder=cast("Forwarder", _Nowhere()),
        model_credential=settings.model_credential,
        jira_email=settings.credential.email,
        project_key=settings.project.key,
        timeout=timeout,
        path=environment.get("PATH", os.defpath),
        trust_store=trust_store_from_environment(environment),
    )
    try:
        outcome = spawn.run_diagnostic(run)
    except OSError as failure:
        return [
            Line(
                MODEL,
                FAIL,
                "run",
                f"claude could not be started ({failure}): the image carries it; rebuild with "
                "`docker compose up -d --build demo`",
            )
        ]
    return judged(transcript_events(run.transcript_path), outcome, settings.run_model, skill, run)


def transcript_events(path: Path) -> list[dict]:
    """Every Run event in a Transcript, skipping lines that are not one."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


SYNTHETIC = "<synthetic>"
"""The model Claude Code names on a message it wrote itself, a refusal's among them."""

DATED = re.compile(r"-\d{8}")
"""How a full model name ends when it is pinned to a release: `claude-haiku-4-5-20251001`."""


def models_that_answered(events: Iterable[dict]) -> list[str]:
    """The models the Transcript's assistant messages name, in the order each first spoke.

    That is what the API served, where the init event only says what Claude Code started
    with. A message Claude Code wrote itself, such as a refusal, names no model.
    """
    answered: list[str] = []
    for event in events:
        if event.get("type") != "assistant":
            continue
        name = as_dict(event.get("message")).get("model")
        if isinstance(name, str) and name and name != SYNTHETIC and name not in answered:
            answered.append(name)
    return answered


def spelled(model: str) -> str:
    """A model name as Claude Code resolves it: lower case, with a hyphen for each dot and
    without a context-window suffix such as `[1m]`."""
    return model.partition("[")[0].strip().lower().replace(".", "-")


def same_model(requested: str, ran: str) -> bool:
    """Whether `ran` is `requested` under another spelling: the dotted form of the name, the
    name pinned to a release, or an alias (`opus`) resolved to a full name."""
    asked, got = spelled(requested), spelled(ran)
    return (
        asked == got
        or (got.startswith(f"{asked}-") and DATED.fullmatch(got[len(asked) :]) is not None)
        or ("-" not in asked and asked in got.split("-"))
    )


def model_line(requested: str, reported: str, answered: Sequence[str]) -> Line:
    """The model the Run asked for, beside the one that ran, and what any difference means.

    `answered` is what the Transcript's messages name: the model the API served. When none
    names one, `reported`, what Claude Code says it started with, is all there is. The same
    name is OK. So is an alias that resolved, or a name that was spelled another way: the
    line gives the full name, so `RUN_MODEL` can pin it. Any other model is the seat
    choosing for the Run, or a name that is not quite a model's, and is a WARN.
    """
    ran = list(answered) or [reported]
    shown = ", ".join(ran)
    verb = "ran" if answered else "Claude Code reports"
    if any(not same_model(requested, model) for model in ran):
        return Line(
            MODEL,
            WARN,
            "model",
            f"requested {requested}, but {verb} {shown}: that is not the same model, so the seat "
            f"chose for the Run, or {requested} is misspelled; set RUN_MODEL in .env to a model "
            "the seat can run, then `docker compose up -d demo`",
        )
    if not answered:
        return Line(
            MODEL,
            WARN,
            "model",
            f"requested {requested}; no model answered the Run, so which one ran is not known "
            f"(Claude Code reports {reported}, which is what it started with)",
        )
    if all(model == requested for model in ran):
        return Line(MODEL, OK, "model", f"requested {requested}, {verb} {shown}")
    # A context window the presenter asked for, `[1m]`, is not part of the name the Run reports,
    # and `RUN_MODEL` without it would run the model with a smaller one.
    window = requested[requested.index("[") :] if "[" in requested else ""
    return Line(
        MODEL,
        OK,
        "model",
        f"requested {requested}, {verb} {shown}: the same model, as Claude Code names it; "
        f"RUN_MODEL={ran[0]}{window} pins it",
    )


def blocks(events: Iterable[dict], kind: str, block: str) -> list[dict]:
    """The content blocks of one kind in every event of one type."""
    return [
        item
        for event in events
        if event.get("type") == kind
        for item in as_list(as_dict(event.get("message")).get("content"))
        if isinstance(item, dict) and item.get("type") == block
    ]


def text_of(content: object) -> str:
    if isinstance(content, str):
        return content
    return "\n".join(
        str(as_dict(item).get("text", ""))
        for item in as_list(content)
        if as_dict(item).get("type") == "text"
    )


def judged(
    events: list[dict], outcome: RunOutcome, requested: str, skill: Path, run: Run
) -> list[Line]:
    """What the Run's Transcript shows: the model, each allowed call, and how it ended.

    The ending is read as the log reads it, through `log_formatter.run_failure` and its
    hints, so `doctor` and the Receiver never disagree about a Run.
    """
    lines = []
    init = next(
        (e for e in events if e.get("type") == "system" and e.get("subtype") == "init"), None
    )
    result = next((e for e in reversed(events) if e.get("type") == "result"), None)
    if init is not None:
        lines.append(
            model_line(requested, str(init.get("model") or "unknown"), models_that_answered(events))
        )
    denied = {
        str(as_dict(denial).get("tool_use_id"))
        for denial in as_list(as_dict(result).get("permission_denials"))
    } | {
        str(e.get("tool_use_id"))
        for e in events
        if e.get("type") == "system" and e.get("subtype") == "permission_denied"
    }
    answers = {str(item.get("tool_use_id")): item for item in blocks(events, "user", "tool_result")}
    calls = blocks(events, "assistant", "tool_use")
    jira_calls = [
        call
        for call in calls
        if call.get("name") == "Bash"
        and str(as_dict(call.get("input")).get("command", "")).lstrip().startswith("jira-as")
    ]
    payload_calls = [
        call
        for call in calls
        if call.get("name") == "Bash"
        and str(as_dict(call.get("input")).get("command", ""))
        .lstrip()
        .startswith("incident-payload")
    ]
    skill_reads = [
        call
        for call in calls
        if call.get("name") == "Read"
        and str(as_dict(call.get("input")).get("file_path", "")).startswith(
            str(skill.parent.parent)
        )
    ]
    failure = outcome.failure

    def asked_jira(call: dict) -> bool:
        return str(as_dict(call.get("input")).get("command", "")).strip() == "jira-as --version"

    def asked_payload(call: dict) -> bool:
        return (
            str(as_dict(call.get("input")).get("command", "")).strip() == "incident-payload --help"
        )

    def asked_read(call: dict) -> bool:
        return str(as_dict(call.get("input")).get("file_path", "")) == str(skill)

    lines.append(
        allowed_call_line(
            "jira-as", "Bash(jira-as *)", jira_calls, asked_jira, denied, answers, failure
        )
    )
    lines.append(
        allowed_call_line(
            "incident-payload",
            "Bash(incident-payload *)",
            payload_calls,
            asked_payload,
            denied,
            answers,
            failure,
        )
    )
    lines.append(
        allowed_call_line(
            "skill read", f"Read of {skill}", skill_reads, asked_read, denied, answers, failure
        )
    )
    if failure is None:
        cost = as_dict(result).get("total_cost_usd")
        spent = f", ${cost:.4f}" if isinstance(cost, (int, float)) else ""
        lines.append(
            Line(MODEL, OK, "run", f"finished{spent}; its Transcript is {run.transcript_path}")
        )
    else:
        hint = hint_of(result)
        lines.append(
            Line(
                MODEL,
                FAIL,
                "run",
                f"{failure}{f'; {hint}' if hint else ''}; its Transcript is {run.transcript_path}",
                (HINT_REQUESTS[hint],) if hint in HINT_REQUESTS else (),
            )
        )
    return [line for line in lines if line is not None]


def allowed_call_line(
    check: str,
    rule: str,
    made: list[dict],
    asked: Callable[[dict], bool],
    denied: set[str],
    answers: Mapping[str, dict],
    failure: str | None,
) -> Line | None:
    """Whether a call the Run's own allow list admits went through.

    Denied, the very call the Run was asked for can only be refused by rules above
    the Run's: an organisation's managed settings deny it, or allow only their own
    rules. A call the model wrote otherwise, a compound command or another path, the
    Run's own allow list may deny, so that is only a warning. Never made, there is
    nothing to say beyond what the Run's failure says already.
    """
    refused = [call for call in made if str(call.get("id")) in denied]
    if any(asked(call) for call in refused):
        return Line(
            MODEL,
            FAIL,
            check,
            f"the Run's allow list admits {rule} and it was denied: the organisation's managed "
            "permission rules override the Run's own",
            (CLAUDE_ORG_OWNER,),
        )
    ran = [
        answers[str(call.get("id"))]
        for call in made
        if str(call.get("id")) in answers and call not in refused
    ]
    if ran:
        first = next(
            (line for line in text_of(ran[0].get("content")).splitlines() if line.strip()), ""
        )
        if ran[0].get("is_error"):
            return Line(MODEL, WARN, check, f"{rule} was allowed, and failed: {said(first)}")
        return Line(MODEL, OK, check, f"{rule} was allowed{f': {said(first)}' if first else ''}")
    if refused:
        return Line(
            MODEL,
            WARN,
            check,
            f"the Run made a call other than the one it was asked for, and it was denied: "
            f"{said(json.dumps(as_dict(refused[0].get('input'))))}; whether {rule} is allowed was "
            "not shown, so run `--with-model` again",
        )
    if failure is not None:
        return None
    return Line(
        MODEL,
        WARN,
        check,
        f"the Run never made the {rule} call it was asked for, so whether it may was not shown",
    )


def hint_of(result: dict | None) -> str | None:
    """The `[hint]` the log prints under a failed result, as its bare text."""
    if result is None or run_failure(result) is None:
        return None
    return next(
        (line[len(HINT) :].strip() for line in format_event(result) if line.startswith(HINT)), None
    )


# --- the command ---


def diagnose_laptop(laptop: Laptop, layers: Sequence[str], out=print) -> Line | None:
    """Run the layers in order, printing each line as it comes; the first FAIL, or None."""
    checks = {
        HOST: host,
        ENV: env,
        JIRA: jira,
        FACTS: facts,
        STACK: stack,
        GRAFANA: grafana,
    }
    blocker = None
    skipped = []
    for layer in layers:
        if blocker is not None:
            skipped.append(layer)
            continue
        for line in checks[layer](laptop):
            out(line.text)
            if blocker is None and line.level == FAIL:
                blocker = line
    if skipped:
        out(f"not checked: {', '.join(skipped)}; an earlier layer failed")
    return blocker


def verdict(blocker: Line | None) -> int:
    if blocker is None:
        print("READY", flush=True)
        return 0
    print(f"NOT READY: {blocker.summary}", flush=True)
    return 1


def selected(only: list[str] | None, parser: argparse.ArgumentParser) -> list[str]:
    if not only:
        return list(LAYERS)
    named = {name.strip() for names in only for name in names.split(",") if name.strip()}
    unknown = sorted(named - set(LAYERS))
    if unknown:
        parser.error(f"--only: no layer {', '.join(unknown)}; the layers are {', '.join(LAYERS)}")
    return [layer for layer in LAYERS if layer in named]


def main(
    argv: list[str] | None = None,
    laptop: Laptop | None = None,
    inside: Mapping[str, object] | None = None,
) -> int:
    """Check each layer and end READY or NOT READY. `laptop` and `inside` replace the world."""
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        description=__doc__.splitlines()[0],
        epilog=(
            f"layers, in order: {', '.join(LAYERS)}. exit status: 0 READY; 1 NOT READY; "
            "2 bad arguments or a Python older than 3.11"
        ),
    )
    parser.add_argument(
        "--only",
        action="append",
        metavar="LAYER[,LAYER...]",
        help="run only these layers, still in order",
    )
    parser.add_argument(
        "--with-model",
        action="store_true",
        help="also start one short, real Run inside the container (costs a little usage)",
    )
    parser.add_argument(
        "--in-container",
        action="store_true",
        help="the container's own checks; the stack layer runs this with docker compose exec",
    )
    parser.add_argument("--project-key", help=argparse.SUPPRESS)
    parser.add_argument("--session-id", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.in_container:
        if arguments.only:
            parser.error("--only names the laptop's layers, not the container's")
        # The Forwarder and the Run spawner log for the Receiver's log; here they
        # would only print past the lines the stack layer reads.
        logging.getLogger("grafana_jsm_sandbox").addHandler(logging.NullHandler())
        # Nothing before this reads the environment. Run as a command, the process
        # made itself non-dumpable before its imports; `in_container` says how that
        # went before it reads anything.
        lines = in_container(
            arguments.with_model,
            arguments.project_key,
            expected_session=arguments.session_id,
            **dict(inside or {}),
        )
        blocker = None
        for line in lines:
            print(line.text, flush=True)
            if blocker is None and line.level == FAIL:
                blocker = line
        return verdict(blocker)
    layers = selected(arguments.only, parser)
    if arguments.with_model and STACK not in layers:
        parser.error(f"--with-model runs in the {STACK} layer, which --only leaves out")
    laptop = Laptop(with_model=arguments.with_model) if laptop is None else laptop
    laptop.with_model = laptop.with_model or arguments.with_model
    blocker = diagnose_laptop(laptop, layers, lambda text: print(text, flush=True))
    return verdict(blocker)


if __name__ == "__main__":
    raise SystemExit(main())
