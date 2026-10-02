"""`doctor`: the ordered preflight, layer by layer, with every part of the world faked.

Docker and compose are an injected runner that answers each command from a table,
jira-as is the same kind of fake `configure`'s tests drive (answering from the
sanitized fixtures under `fixtures/jira/`), Grafana is a small HTTP server on an
ephemeral port answering its provisioning API, Jira seen from inside the container
is the tests' fake Atlassian site behind a real Forwarder, and the Claude CLI is a
stand-in script on PATH that prints a canned stream-json Transcript. Nothing here
reaches Jira, Grafana, Docker or a model.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import yaml

from grafana_jsm_sandbox import doctor, skill_template
from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.doctor import (
    CLAUDE_ORG_OWNER,
    DOCKER_ADMIN,
    LAYERS,
    MODEL_PROMPT,
    NOT_A_SITE,
    NOWHERE,
    SKILL_PROJECT_ROW,
    Answer,
    Laptop,
    Line,
    in_container,
    main,
    port_is_free,
)
from grafana_jsm_sandbox.forwarder import SHUTDOWN_POLL_INTERVAL
from grafana_jsm_sandbox.log_formatter import HINT_CREDITS, HINT_TOKEN
from grafana_jsm_sandbox.run_command import (
    PROMPT,
    SKILL_FILE,
    build_run_command,
    rendered_skill_directory,
)
from tests.conftest import FIXTURES, REAL_EMAIL, REAL_TOKEN, REPOSITORY
from tests.test_configure import (
    CUSTOM_ROLES,
    FOUND,
    KEY,
    STEP_11_ANCHORS,
    FakeJira,
    Refusal,
    custom_workflow,
    fixture_answers,
    queue_address,
    queue_named,
    rename_incidents,
)
from tests.upstream import FakeUpstream

SITE = "https://sandbox-0000.atlassian.net"
"""A made-up site, shaped like a real one so the env layer's shape check passes."""

OAUTH_TOKEN = "sk-ant-oat01-an-anthropic-oauth-token-that-must-never-be-printed"
JIRA_TOKEN = "the-jira-token-in-dot-env-9f8e7d6c5b4a39281706f5e4d3c2b1a0"

SECRETS = (OAUTH_TOKEN, JIRA_TOKEN, REAL_TOKEN)

LINE = re.compile(
    r"^\[(host|env|jira|facts|stack|grafana|container|model)\] (OK|WARN|FAIL) [^—]+ — .+$"
)
NOT_CHECKED = re.compile(r"^not checked: [a-z]+(, [a-z]+)*; an earlier layer failed$")
END = re.compile(r"^(READY|NOT READY: \[[a-z]+\] [^—]+ — .+)$")
ASK = re.compile(r"docs/admin-requests\.md#([a-z0-9-]+)")
"""The documented output, which the setup skill parses."""


API_KEY = "sk-ant-api03-a-work-api-key-that-must-never-be-printed"
"""The MVP's model credential, which stands in the OAuth token's place, never beside it."""


def env_text(**overrides: str | None) -> str:
    """A filled-in `.env`; an override of None leaves its line out."""
    values = {
        "JIRA_SITE_URL": SITE,
        "JIRA_EMAIL": "ops@example.invalid",
        "JIRA_API_TOKEN": JIRA_TOKEN,
        "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN,
        "DEMO_PROJECT_KEY": KEY,
        "DEMO_SESSION_ID": "rehearsal1",
        **FOUND,
        "DEMO_QUEUE_URL": queue_address("32", site=SITE),
        **overrides,
    }
    return "".join(f"{name}={value}\n" for name, value in values.items() if value is not None)


@pytest.fixture
def env_file(tmp_path) -> Path:
    path = tmp_path / ".env"
    path.write_text(env_text())
    return path


# --- The world, faked ---


@dataclass
class FakeRunner:
    """`docker`, `docker compose` and `jira-as`, answering each command from a table.

    A key is the start of an argv; the longest key that matches answers. An answer is
    an `Answer`, or an exception to raise, as a missing executable raises one.
    """

    answers: dict[tuple[str, ...], Answer | BaseException] = field(default_factory=dict)
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append((argv, timeout))
        keys = [key for key in self.answers if argv[: len(key)] == key]
        assert keys, f"the fake runner does not answer {argv}"
        answer = self.answers[max(keys, key=len)]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def asked(self, *start: str) -> list[tuple[str, ...]]:
        return [argv for argv, _ in self.calls if argv[: len(start)] == start]


def ok(stdout: str = "") -> Answer:
    return Answer(0, stdout, "")


def ps(*entries: dict, lines: bool = True) -> Answer:
    """`docker compose ps --format json`, one object per line (2.21+) or one array (older)."""
    if lines:
        return ok("\n".join(json.dumps(entry) for entry in entries) + "\n")
    return ok(json.dumps(list(entries)))


def service(name: str, state: str = "running", health: str = "", *published: int) -> dict:
    return {
        "Service": name,
        "State": state,
        "Health": health,
        "Publishers": [
            {"URL": "127.0.0.1", "TargetPort": port, "PublishedPort": port, "Protocol": "tcp"}
            for port in published
        ],
    }


UP = (
    service("lgtm", "running", "", 3000),
    service("demo", "running", "healthy", 8080),
    service("rolldice"),
    service("traffic"),
)
"""The whole stack up, as `docker compose ps` describes it."""

IN_CONTAINER_READY = (
    "\n".join(
        line.text
        for line in (
            Line("container", "OK", "non-dumpable", "this check's own environment is root's"),
            Line("container", "OK", "receiver environ", "/proc/1/environ is unreadable"),
            Line("container", "OK", "skill", f"rendered for {KEY} at /app/runs/.skill"),
            Line("container", "OK", "whoami", "Jira answered 200"),
        )
    )
    + "\nREADY\n"
)


def healthy_runner(overrides: dict | None = None) -> FakeRunner:
    answers = {
        ("docker", "version"): ok("29.8.0\n"),
        ("docker", "compose", "version"): ok("5.5.1\n"),
        ("jira-as", "--version"): ok("jira-as, version 2.0.0 (build sha256-e937)\n"),
        ("docker", "image", "inspect"): ok("sha256:0123\n"),
        ("docker", "compose", "ps"): ps(*UP),
        ("docker", "compose", "exec"): ok(IN_CONTAINER_READY),
    }
    answers.update(overrides or {})
    return FakeRunner(answers)


class DoctorJira(FakeJira):
    """`configure`'s fake project, which also answers who the credential is and the site."""

    def __init__(self, me: object = None, server: object = None, **kwargs):
        super().__init__(**kwargs)
        self.me = me if me is not None else {"displayName": "Sandbox Robot", "active": True}
        self.server = server if server is not None else {"baseUrl": SITE, "deploymentType": "Cloud"}

    def __call__(self, *arguments: str) -> str:
        if arguments[:3] == ("api", "call", "getCurrentUser"):
            self.calls.append(arguments)
            return self._answer(self.me, arguments)
        if arguments[:3] == ("api", "call", "getServerInfo"):
            self.calls.append(arguments)
            return self._answer(self.server, arguments)
        return super().__call__(*arguments)

    @staticmethod
    def _answer(answer: object, arguments: tuple[str, ...]) -> str:
        if isinstance(answer, Refusal):
            answer.raise_for(arguments)
        return json.dumps(answer)


class FakeGrafana:
    """Grafana's HTTP API as the provisioning files leave it, on an ephemeral port."""

    def __init__(self):
        self.answers: dict[str, object] = healthy_grafana()
        self.statuses: dict[str, int] = {}
        self.posted: list[tuple[str, dict]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, args=(SHUTDOWN_POLL_INTERVAL,), daemon=True
        )

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def _handler(self):
        grafana = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, form: dict | None) -> None:
                if form is not None:
                    grafana.posted.append((self.path, form))
                status = grafana.statuses.get(self.path, 200)
                body = json.dumps(grafana.answers.get(self.path, {"message": "Not found"}))
                if self.path not in grafana.answers:
                    status = 404
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._answer(None)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self._answer(parse_qs(self.rfile.read(length).decode()))

            def log_message(self, format, *args):
                """Silent; the tests read `posted`."""

        return Handler

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


PROVISIONING = REPOSITORY / "grafana" / "provisioning" / "alerting"


def healthy_grafana() -> dict[str, object]:
    """What Grafana answers once it has taken this repo's provisioning files."""
    point = yaml.safe_load((PROVISIONING / "contact-point.yaml").read_text())["contactPoints"][0]
    receiver = point["receivers"][0]
    policy = yaml.safe_load((PROVISIONING / "notification-policy.yaml").read_text())["policies"][0]
    group = yaml.safe_load((PROVISIONING / "alert-rule.yaml").read_text())["groups"][0]
    rule = group["rules"][0]
    return {
        "/api/v1/provisioning/contact-points": [
            {"uid": "", "name": "email receiver", "type": "email", "settings": {}},
            {
                "uid": receiver["uid"],
                "name": point["name"],
                "type": receiver["type"],
                "settings": receiver["settings"],
                "disableResolveMessage": receiver["disableResolveMessage"],
            },
        ],
        "/api/v1/provisioning/policies": {
            "receiver": policy["receiver"],
            "group_by": policy["group_by"],
            "group_wait": policy["group_wait"],
            "group_interval": policy["group_interval"],
            "repeat_interval": policy["repeat_interval"],
        },
        "/api/v1/provisioning/alert-rules": [
            {
                "uid": rule["uid"],
                "title": rule["title"],
                "folderUID": "demo-folder",
                "ruleGroup": group["name"],
                "for": rule["for"],
                "labels": rule["labels"],
                "data": rule["data"],
            }
        ],
        f"/api/v1/provisioning/folder/demo-folder/rule-groups/{group['name']}": {
            "title": group["name"],
            "interval": int(group["interval"].rstrip("s")),
        },
        "/api/datasources/proxy/uid/prometheus/api/v1/query": {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {"instance": "rolldice:8082"}, "value": [0, "1.0"]}],
            },
        },
        "/api/prometheus/grafana/api/v1/rules": {
            "data": {"groups": [{"rules": [{"uid": rule["uid"], "state": "inactive"}]}]}
        },
    }


@pytest.fixture
def fake_grafana():
    grafana = FakeGrafana()
    grafana.start()
    try:
        yield grafana
    finally:
        grafana.stop()


@pytest.fixture
def upstream():
    upstream = FakeUpstream()
    upstream.start()
    try:
        yield upstream
    finally:
        upstream.stop()


def laptop(env_file: Path, **kwargs) -> Laptop:
    """A laptop whose every tool is faked, and whose shell says nothing of its own."""
    kwargs.setdefault("run", healthy_runner())
    kwargs.setdefault("port_free", lambda address, port: True)
    kwargs.setdefault("jira_as", DoctorJira())
    kwargs.setdefault("shell", {"PATH": os.environ.get("PATH", "")})
    return Laptop(env_file=env_file, **kwargs)


def lines_of(lines: list[Line], check: str) -> list[Line]:
    return [line for line in lines if line.check == check]


def only(lines: list[Line], check: str) -> Line:
    (line,) = lines_of(lines, check)
    return line


@dataclass
class Printed:
    code: int
    out: str
    err: str

    @property
    def lines(self) -> list[str]:
        return self.out.splitlines()

    def asks(self) -> set[str]:
        return set(ASK.findall(self.out))


@pytest.fixture
def run_doctor(capsys):
    def run(*argv: str, **kwargs) -> Printed:
        code = main(list(argv), **kwargs)
        out, err = capsys.readouterr()
        return Printed(code, out, err)

    return run


# --- The line format ---


def test_every_line_reads_back_as_the_line_it_was():
    for line in (
        Line("host", "OK", "docker", "Docker Engine 29.8.0"),
        Line(
            "jira", "FAIL", "whoami", "refused (401): check it", ("atlassian-org-admin-api-tokens",)
        ),
        Line("model", "FAIL", "run", "a; b: c", (CLAUDE_ORG_OWNER,)),
        Line("facts", "WARN", "severity in .env", "x — y"),
    ):
        assert LINE.match(line.text), line.text
        assert Line.parse(line.text) == line


def test_a_line_is_one_line_whatever_it_carries():
    line = Line("stack", "FAIL", "in-container", "one\ntwo\n\tthree")

    assert line.text == "[stack] FAIL in-container — one two three"


# --- host ---


def test_a_healthy_host_is_ok_check_by_check(env_file):
    lines = doctor.host(laptop(env_file))

    assert {line.check: line.level for line in lines} == {
        "python": "OK",
        "docker": "OK",
        "compose": "OK",
        "jira-as": "OK",
        "images": "OK",
        "lgtm port": "OK",
        "demo port": "OK",
    }
    assert "Docker Engine 29.8.0" in only(lines, "docker").message
    assert "Compose 5.5.1" in only(lines, "compose").message
    assert "jira-as 2.0.0" in only(lines, "jira-as").message


def test_no_docker_is_a_stop_and_compose_is_not_asked(env_file):
    runner = healthy_runner({("docker", "version"): FileNotFoundError("docker")})

    lines = doctor.host(laptop(env_file, run=runner))

    assert only(lines, "docker").level == "FAIL"
    assert "docker is not on PATH" in only(lines, "docker").message
    assert not runner.asked("docker", "compose")
    assert not runner.asked("docker", "image")


def test_a_daemon_that_does_not_answer_says_so_and_how_to_start_it(env_file):
    runner = healthy_runner(
        {("docker", "version"): Answer(1, "", "Cannot connect to the Docker daemon")}
    )

    line = only(doctor.host(laptop(env_file, run=runner)), "docker")

    assert line.level == "FAIL"
    assert "Cannot connect to the Docker daemon" in line.message
    assert "start Docker Desktop" in line.message


def test_no_compose_plugin_is_a_stop(env_file):
    runner = healthy_runner(
        {("docker", "compose", "version"): Answer(1, "", "'compose' is not a docker command")}
    )

    line = only(doctor.host(laptop(env_file, run=runner)), "compose")

    assert line.level == "FAIL" and "Compose v2" in line.message


@pytest.mark.parametrize(
    ("version", "words"),
    [("v2.16.0", "cpus off"), ("2.1.1", "cpus and pids_limit off")],
)
def test_an_old_compose_warns_which_limit_it_leaves_off(env_file, version, words):
    runner = healthy_runner({("docker", "compose", "version"): ok(version)})

    line = only(doctor.host(laptop(env_file, run=runner)), "compose")

    assert line.level == "WARN" and words in line.message


@pytest.mark.parametrize(
    ("answer", "level", "words"),
    [
        (FileNotFoundError("jira-as"), "FAIL", "jira-as is not on PATH"),
        (ok("jira-as, version 1.9.4\n"), "FAIL", "older than the 2.0"),
        (ok("jira-as, version 3.0.0\n"), "WARN", "newer than the 2.x"),
        (Answer(2, "", "Traceback: boom"), "FAIL", "did not say a version"),
    ],
)
def test_jira_as_must_be_2_x(env_file, answer, level, words):
    runner = healthy_runner({("jira-as", "--version"): answer})

    line = only(doctor.host(laptop(env_file, run=runner)), "jira-as")

    assert line.level == level and words in line.message


def test_images_not_pulled_yet_warn_and_name_the_docker_admin_request(env_file):
    runner = healthy_runner({("docker", "image", "inspect"): Answer(1, "", "No such image")})

    line = only(doctor.host(laptop(env_file, run=runner)), "images")

    assert line.level == "WARN"
    assert line.ask == (DOCKER_ADMIN,)
    assert "grafana/otel-lgtm:0.33.0@sha256:" in line.message
    assert "alpine:3.20" in line.message
    assert "grafana-jsm-sandbox" not in line.message, "built here, never pulled"


def test_the_images_inspected_follow_lgtm_image_as_compose_would(env_file):
    env_file.write_text(env_text(LGTM_IMAGE="mirror.example.invalid/otel-lgtm:0.33.0"))
    runner = healthy_runner()

    doctor.host(laptop(env_file, run=runner))

    inspected = [argv[-1] for argv in runner.asked("docker", "image", "inspect")]
    assert inspected == ["mirror.example.invalid/otel-lgtm:0.33.0", "alpine:3.20"]


def test_a_port_another_program_holds_is_a_stop_naming_the_variable_that_moves_it(env_file):
    lines = doctor.host(
        laptop(
            env_file,
            port_free=lambda address, port: port != 3000,
            run=healthy_runner({("docker", "compose", "ps"): ps()}),
        )
    )

    line = only(lines, "lgtm port")
    assert line.level == "FAIL"
    assert "127.0.0.1:3000 is taken by another program" in line.message
    assert "GRAFANA_HOST_PORT" in line.message
    assert only(lines, "demo port").level == "OK"


@pytest.mark.parametrize("per_line", [True, False], ids=["ndjson", "array"])
def test_a_port_this_stack_publishes_is_as_it_should_be(env_file, per_line):
    runner = healthy_runner({("docker", "compose", "ps"): ps(*UP, lines=per_line)})

    lines = doctor.host(laptop(env_file, run=runner, port_free=lambda address, port: False))

    assert "is Grafana's, published by this stack" in only(lines, "lgtm port").message
    assert "is the Receiver's, published by this stack" in only(lines, "demo port").message


def test_the_ports_follow_env_and_the_shell_over_it(env_file):
    env_file.write_text(env_text(GRAFANA_HOST_PORT="3300", RECEIVER_HOST_PORT="8880"))
    asked = []

    doctor.host(
        laptop(
            env_file,
            shell={"RECEIVER_HOST_PORT": "8990"},
            port_free=lambda address, port: asked.append((address, port)) or True,
        )
    )

    assert asked == [("127.0.0.1", 3300), ("127.0.0.1", 8990)]


def test_a_port_that_is_no_number_is_a_stop(env_file):
    env_file.write_text(env_text(GRAFANA_HOST_PORT="three thousand"))

    line = only(doctor.host(laptop(env_file)), "lgtm port")

    assert line.level == "FAIL" and "GRAFANA_HOST_PORT is not a port number" in line.message


def test_publishing_beyond_loopback_warns(env_file):
    env_file.write_text(env_text(BIND_ADDRESS="0.0.0.0"))

    line = only(doctor.host(laptop(env_file)), "bind address")

    assert line.level == "WARN" and "anonymous user is an Admin" in line.message


def test_the_port_probe_sees_a_listening_socket():
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        port = held.getsockname()[1]
        assert not port_is_free("127.0.0.1", port)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    assert port_is_free("127.0.0.1", free)


# --- env ---


def test_a_filled_in_env_is_ok_check_by_check(env_file):
    lines = doctor.env(laptop(env_file))

    assert {line.check: line.level for line in lines} == {
        ".env": "OK",
        "placeholders": "OK",
        "site url": "OK",
        "model credential": "OK",
        "project key": "OK",
        "session": "OK",
        "receiver": "OK",
    }
    assert "Runs ask for claude-opus-5, no spending cap" in only(lines, "receiver").message


def test_no_env_says_how_to_make_one(tmp_path):
    (line,) = doctor.env(laptop(tmp_path / ".env"))

    assert line.level == "FAIL" and "cp .env.example .env" in line.message


def test_example_placeholders_left_in_env_are_named(env_file):
    example = doctor.read_env_file(doctor.ENV_EXAMPLE)
    env_file.write_text(
        env_text(
            JIRA_API_TOKEN=example["JIRA_API_TOKEN"],
            ANTHROPIC_API_KEY=None,
            CLAUDE_CODE_OAUTH_TOKEN=None,
        )
    )

    line = only(doctor.env(laptop(env_file)), "placeholders")

    assert line.level == "FAIL"
    assert "JIRA_API_TOKEN still hold .env.example's placeholder" in line.message


def test_the_oauth_token_s_placeholder_is_one_too_when_it_is_uncommented_and_left(
    env_file, tmp_path
):
    """An older example with a credential placeholder still detects it when left unchanged."""
    example = tmp_path / "example"
    example.write_text("CLAUDE_CODE_OAUTH_TOKEN=paste-your-claude-code-oauth-token-here\n")
    env_file.write_text(env_text(CLAUDE_CODE_OAUTH_TOKEN="paste-your-claude-code-oauth-token-here"))

    line = only(doctor.env(laptop(env_file, example_file=example)), "placeholders")

    assert line.level == "FAIL" and "CLAUDE_CODE_OAUTH_TOKEN" in line.message


def test_a_default_the_example_gives_is_no_placeholder(env_file, tmp_path):
    """Only what the engineer alone can give is a placeholder; a real default may be kept."""
    example = tmp_path / "example"
    example.write_text(
        "JIRA_API_TOKEN=paste-your-atlassian-api-token-here\n"
        "RUN_MODEL=claude-opus-5\nBIND_ADDRESS=127.0.0.1\n"
    )
    env_file.write_text(env_text(RUN_MODEL="claude-opus-5", BIND_ADDRESS="127.0.0.1"))

    line = only(doctor.env(laptop(env_file, example_file=example)), "placeholders")

    assert line.level == "OK", line.text


@pytest.mark.parametrize(
    ("url", "level", "words"),
    [
        ("https://sandbox-0000.atlassian.net", "OK", "https://sandbox-0000.atlassian.net"),
        ("https://sandbox-0000.atlassian.net/", "OK", "https://sandbox-0000.atlassian.net"),
        ("https://sandbox-0000.atlassian.net/jira/your-work", "FAIL", "without /jira/your-work"),
        ("http://sandbox-0000.atlassian.net", "FAIL", "must be an https:// address"),
        (
            "https://api.atlassian.com/ex/jira/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "OK",
            "the API gateway for cloud id 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        ),
        (
            "https://api.atlassian.com/ex/jira/",
            "FAIL",
            "must be https://api.atlassian.com/ex/jira/",
        ),
        ("https://api.atlassian.com", "FAIL", "/ex/jira/<cloudId>"),
        ("https://jira.example.invalid", "WARN", "custom domain"),
        ("https://sandbox-0000.atlassian.net?x=1", "FAIL", "no query"),
    ],
)
def test_the_site_url_is_a_site_s_address_or_the_gateway_s(url, level, words):
    line = doctor.site_line(url)

    assert (line.level, line.check) == (level, "site url")
    assert words in line.message


@pytest.mark.parametrize(
    ("api_key", "oauth_token", "level", "words", "ask"),
    [
        pytest.param(
            API_KEY,
            None,
            "OK",
            "an Anthropic API key (ANTHROPIC_API_KEY), and only it",
            (),
            id="api-key",
        ),
        pytest.param(
            None,
            OAUTH_TOKEN,
            "OK",
            "a Claude Code OAuth token (CLAUDE_CODE_OAUTH_TOKEN), and only it",
            (),
            id="oauth-token",
        ),
        pytest.param(
            None,
            None,
            "FAIL",
            "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set",
            (CLAUDE_ORG_OWNER,),
            id="neither",
        ),
        pytest.param(
            "",
            "",
            "FAIL",
            "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set",
            (CLAUDE_ORG_OWNER,),
            id="both-empty",
        ),
        pytest.param(
            API_KEY,
            OAUTH_TOKEN,
            "FAIL",
            "both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set: set exactly one",
            (),
            id="both",
        ),
        pytest.param(
            None,
            "sk-ant-api03-an-api-key-not-an-oauth-token",
            "FAIL",
            "CLAUDE_CODE_OAUTH_TOKEN holds an Anthropic API key, not a Claude Code OAuth token: "
            "put it in ANTHROPIC_API_KEY instead",
            (),
            id="api-key-in-the-oauth-variable",
        ),
        pytest.param(
            "sk-ant-oat01-an-oauth-token-not-an-api-key",
            None,
            "FAIL",
            "ANTHROPIC_API_KEY holds a Claude Code OAuth token, not an Anthropic API key: put it "
            "in CLAUDE_CODE_OAUTH_TOKEN instead",
            (),
            id="oauth-token-in-the-api-key-variable",
        ),
        pytest.param(
            None,
            "something-else-entirely",
            "WARN",
            "CLAUDE_CODE_OAUTH_TOKEN does not look like a Claude Code OAuth token (sk-ant-oat...)",
            (),
            id="oauth-token-of-another-shape",
        ),
        pytest.param(
            "something-else-entirely",
            None,
            "WARN",
            "ANTHROPIC_API_KEY does not look like an Anthropic API key (sk-ant-api...)",
            (),
            id="api-key-of-another-shape",
        ),
    ],
)
def test_exactly_one_model_credential_of_either_kind_is_taken_and_named_by_kind(
    env_file, api_key, oauth_token, level, words, ask
):
    """Neither, both, and one in the other's variable are stops; a value is never printed."""
    env_file.write_text(env_text(ANTHROPIC_API_KEY=api_key, CLAUDE_CODE_OAUTH_TOKEN=oauth_token))

    lines = doctor.env(laptop(env_file))
    line = only(lines, "model credential")

    assert (line.level, line.ask) == (level, ask)
    assert words in line.message, line.message
    for value in (api_key, oauth_token):
        assert not value or all(value not in text.text for text in lines)


def test_no_model_credential_says_where_each_kind_comes_from(env_file):
    env_file.write_text(env_text(CLAUDE_CODE_OAUTH_TOKEN=None))

    line = only(doctor.env(laptop(env_file)), "model credential")

    assert "paste a work API key (sk-ant-api...) into ANTHROPIC_API_KEY" in line.message
    assert "`claude setup-token` prints into CLAUDE_CODE_OAUTH_TOKEN" in line.message


def test_a_work_api_key_alone_is_a_env_the_receiver_would_start_on(env_file):
    env_file.write_text(env_text(ANTHROPIC_API_KEY=API_KEY, CLAUDE_CODE_OAUTH_TOKEN=None))

    lines = doctor.env(laptop(env_file))

    assert only(lines, "receiver").level == "OK"
    assert all(API_KEY not in line.text for line in lines)


# --- env: the session ---


def test_the_session_line_names_the_label_this_take_s_incidents_carry(env_file):
    env_file.write_text(env_text(DEMO_SESSION_ID="take3"))

    line = only(doctor.env(laptop(env_file)), "session")

    assert line.level == "OK"
    assert line.message == "DEMO_SESSION_ID=take3, so this take's Incidents carry ses-take3"


def test_no_session_id_is_a_warning_naming_the_shared_label(env_file):
    """A `.env` from before the session id still runs; every take then shares one label."""
    env_file.write_text(env_text(DEMO_SESSION_ID=None))

    lines = doctor.env(laptop(env_file))
    line = only(lines, "session")

    assert line.level == "WARN"
    assert "DEMO_SESSION_ID is not set" in line.message and "ses-demo" in line.message
    assert only(lines, "receiver").level == "OK", "not a stop"


@pytest.mark.parametrize("session_id", ["Take One", "take_1", "TAKE", "a" * 33, "ses-1!"])
def test_a_session_id_the_label_could_not_carry_is_a_stop_of_its_own(env_file, session_id):
    """Named on the session line, and not laid at the project key's door."""
    env_file.write_text(env_text(DEMO_SESSION_ID=session_id))

    lines = doctor.env(laptop(env_file))

    line = only(lines, "session")
    assert line.level == "FAIL" and "DEMO_SESSION_ID is not a session id" in line.message
    assert only(lines, "project key").level == "OK"
    assert not lines_of(lines, "receiver"), "said once, not again by the Receiver's reading"


def test_no_project_key_is_a_stop_naming_configure(env_file):
    env_file.write_text(env_text(DEMO_PROJECT_KEY=""))

    lines = doctor.env(laptop(env_file))

    line = only(lines, "project key")
    assert line.level == "FAIL" and "DEMO_PROJECT_KEY is not set" in line.message
    assert not lines_of(lines, "receiver"), "said once, not again by the Receiver's reading"


def test_a_knob_the_receiver_would_refuse_is_a_stop(env_file):
    env_file.write_text(env_text(RUN_BUDGET_USD="lots"))

    line = only(doctor.env(laptop(env_file)), "receiver")

    assert line.level == "FAIL"
    assert "RUN_BUDGET_USD is not a positive number of dollars" in line.message


def test_the_receiver_line_names_the_model_and_the_cap(env_file):
    env_file.write_text(env_text(RUN_MODEL="claude-haiku-5", RUN_BUDGET_USD="2"))

    line = only(doctor.env(laptop(env_file)), "receiver")

    assert "Runs ask for claude-haiku-5, at most $2 a Run" in line.message


# --- jira ---


def test_a_credential_jira_accepts_on_the_right_project_is_ok(env_file):
    jira = DoctorJira()

    lines = doctor.jira(laptop(env_file, jira_as=jira))

    assert [(line.check, line.level) for line in lines] == [
        ("whoami", "OK"),
        ("server", "OK"),
        ("project", "OK"),
        ("permissions", "OK"),
    ]
    assert "as Sandbox Robot" in only(lines, "whoami").message
    assert f"Jira Cloud at {SITE}" in only(lines, "server").message
    assert jira.calls[0] == ("api", "call", "getCurrentUser")


@pytest.mark.parametrize(
    ("refusal", "asked", "words"),
    [
        (
            Refusal(401, ["Client must be authenticated"]),
            {"atlassian-org-admin-api-tokens"},
            "refused the credential",
        ),
        (
            Refusal(403, ["<p>Your IP address has been rejected by the IP allowlist</p>"]),
            {"atlassian-org-admin-ip-allowlist"},
            "IP allowlist refused this address",
        ),
        (
            Refusal(403, ["You do not have permission"]),
            {"jira-admin-permissions", "atlassian-org-admin-agent-licence"},
            "refused the account in .env",
        ),
        (Refusal(404, ["Not Found"]), set(), NOT_A_SITE),
        (Refusal(503, ["HTTP transport failed: ConnectionError"]), set(), "could not reach"),
    ],
)
def test_a_refused_whoami_is_classified_and_stops_the_layer(env_file, refusal, asked, words):
    jira = DoctorJira(me=refusal)

    (line,) = doctor.jira(laptop(env_file, jira_as=jira))

    assert (line.check, line.level) == ("whoami", "FAIL")
    assert words in line.message
    assert set(line.ask) == asked
    assert len(jira.calls) == 1


def test_a_project_jira_does_not_have_names_the_create_project_request(env_file):
    jira = DoctorJira()
    jira.answers["getProject"] = Refusal(404, ["No project could be found"])

    line = only(doctor.jira(laptop(env_file, jira_as=jira)), "project")

    assert line.level == "FAIL"
    assert set(line.ask) == {"jira-admin-create-project", "jira-admin-permissions"}


def test_a_deactivated_account_or_a_server_jira_is_a_stop(env_file):
    lines = doctor.jira(
        laptop(
            env_file,
            jira_as=DoctorJira(me={"active": False}, server={"deploymentType": "Server"}),
        )
    )

    assert only(lines, "whoami").level == "FAIL"
    assert "deactivated" in only(lines, "whoami").message
    assert only(lines, "server").level == "FAIL"


def test_missing_permissions_are_a_stop_naming_the_requests(env_file):
    jira = DoctorJira()
    jira.answers["getMyPermissions"] = {
        "permissions": {"BROWSE_PROJECTS": {"havePermission": True}}
    }

    line = next(
        line
        for line in doctor.jira(laptop(env_file, jira_as=jira))
        if line.check == "permissions" and line.level == "FAIL"
    )

    assert set(line.ask) == {"jira-admin-permissions", "atlassian-org-admin-agent-licence"}


# --- facts ---


def test_field_ids_in_env_that_are_the_project_s_own_are_ok(env_file):
    lines = doctor.facts(laptop(env_file))

    assert not [line for line in lines if line.level == "FAIL"], [l.text for l in lines]
    for name in ("severity", "urgency", "source", "major incident"):
        assert only(lines, f"{name} in .env").level == "OK"
    assert only(lines, "statuses").level == "OK"
    assert only(lines, "resolution").level == "OK"
    assert only(lines, "queue url").level == "OK"


def test_an_empty_id_the_project_has_warns_that_a_run_leaves_it_off(env_file):
    env_file.write_text(env_text(DEMO_SEVERITY_FIELD=""))

    line = only(doctor.facts(laptop(env_file)), "severity in .env")

    assert line.level == "WARN"
    assert "the project's Severity is customfield_10040, so a Run leaves it off" in line.message
    assert "configure --write" in line.message


def test_an_id_the_project_no_longer_has_is_a_stop(env_file):
    env_file.write_text(env_text(DEMO_URGENCY_FIELD="customfield_19999"))

    line = only(doctor.facts(laptop(env_file)), "urgency in .env")

    assert line.level == "FAIL"
    assert "DEMO_URGENCY_FIELD=customfield_19999, but the project's Urgency is" in line.message


def test_an_id_for_a_field_the_project_lacks_is_a_stop(env_file):
    jira = DoctorJira()
    jira.answers["getCreateIssueMetaIssueTypeId"] = {
        **jira.answers["getCreateIssueMetaIssueTypeId"],
        "fields": [item for item in jira.fields() if item["name"] != "Source"],
    }

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert only(lines, "source").ask == ("jira-admin-incident-fields",)
    line = only(lines, "source in .env")
    assert line.level == "FAIL" and "a field the create refuses" in line.message


def test_a_field_the_project_lacks_and_env_leaves_empty_only_warns(env_file):
    """As `configure` says it: the demo runs, and a Run leaves the field off."""
    jira = DoctorJira()
    jira.answers["getCreateIssueMetaIssueTypeId"] = {
        **jira.answers["getCreateIssueMetaIssueTypeId"],
        "fields": [item for item in jira.fields() if item["name"] != "Source"],
    }
    env_file.write_text(env_text(DEMO_SOURCE_FIELD=""))

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert not [line for line in lines if line.level == "FAIL"], [l.text for l in lines]
    source = only(lines, "source")
    assert source.level == "WARN" and source.ask == ("jira-admin-incident-fields",)
    assert only(lines, "source in .env").level == "OK"


def test_a_major_incident_id_that_differs_only_warns(env_file):
    env_file.write_text(env_text(DEMO_MAJOR_INCIDENT_FIELD="customfield_19998"))

    line = only(doctor.facts(laptop(env_file)), "major incident in .env")

    assert line.level == "WARN"


def test_the_workflow_and_resolution_are_checked_as_configure_checks_them(env_file):
    jira = DoctorJira(answers={**fixture_answers(), "searchResolutions": {"values": []}})

    line = only(doctor.facts(laptop(env_file, jira_as=jira)), "resolution")

    assert line.level == "FAIL" and line.ask == ("jira-admin-resolution-screen",)


def test_no_queue_url_warns(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))

    assert only(doctor.facts(laptop(env_file)), "queue url").level == "WARN"


def test_no_queue_url_the_project_gives_is_fixed_by_configure(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))

    line = only(doctor.facts(laptop(env_file)), "queue url")

    assert line.level == "WARN"
    assert "DEMO_QUEUE_URL is empty" in line.message
    assert "`python3 -m grafana_jsm_sandbox.configure --write`" in line.message
    assert "by hand" not in line.message


def test_a_queue_with_another_name_that_configure_would_take_is_fixed_by_configure(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))
    jira = DoctorJira()
    rename_incidents(jira)

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert "configure --write" in only(lines, "queue url").message
    assert queue_address("32", site=SITE) in only(lines, "queue").message


def ambiguous_queues(jira: FakeJira) -> None:
    """Two queues that both show the open Incidents, so `configure` takes neither."""
    rename_incidents(jira)
    queue_named(jira, "Problems")["jql"] = queue_named(jira, "Open incidents")["jql"]


def test_no_queue_url_configure_cannot_find_is_set_by_hand_and_never_by_configure_write(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))
    jira = DoctorJira()
    ambiguous_queues(jira)

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    line = only(lines, "queue url")
    assert line.level == "WARN"
    assert "--write" not in line.message
    assert "`python3 -m grafana_jsm_sandbox.configure` cannot find it for you" in line.message
    assert (
        "set it by hand" in line.message
        and "copying its address into DEMO_QUEUE_URL" in line.message
    )
    assert "the `queue` lines above list the candidates" in line.message
    candidates = [line for line in lines_of(lines, "queue") if "candidate" in line.message]
    assert len(candidates) == 3, "the three queues that could show the Incidents are listed"


def test_no_queue_url_when_jira_would_not_list_the_queues_is_set_by_hand(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))
    jira = DoctorJira()
    jira.answers["getQueues"] = Refusal(500, ["Internal server error"])

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert "Jira answered 500" in lines_of(lines, "service desk")[-1].message
    line = only(lines, "queue url")
    assert "set it by hand" in line.message and "--write" not in line.message


def test_a_queue_whose_jql_names_the_project_by_id_is_found_as_configure_finds_it(env_file):
    """`configure` reads the project's id and `check_queue` takes a JQL that names it; `doctor`
    gave it none, so it advised setting the address by hand for a queue `--write` would write."""
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))
    jira = DoctorJira()
    rename_incidents(
        jira, jql="project = 10042 AND issuetype = Incident AND resolution = Unresolved"
    )

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    line = only(lines, "queue url")
    assert "configure --write" in line.message and "by hand" not in line.message
    assert queue_address("32", site=SITE) in only(lines, "queue").message
    assert ("api", "call", "getProject", "--project-id-or-key", KEY) in jira.calls


def test_a_project_jira_will_not_describe_costs_only_the_queues_named_by_id(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=""))
    jira = DoctorJira()
    jira.answers["getProject"] = Refusal(500, ["Internal server error"])
    rename_incidents(jira)

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert "configure --write" in only(lines, "queue url").message, "the JQL names the key"


def test_a_queue_url_that_is_set_by_hand_and_the_project_s_own_is_ok(env_file):
    env_file.write_text(env_text(DEMO_QUEUE_URL=queue_address("30", site=SITE)))
    jira = DoctorJira()
    ambiguous_queues(jira)

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    assert only(lines, "queue url").level == "OK"
    assert only(lines, "queue").level == "OK"
    assert not [line for line in lines if line.level == "FAIL"], [l.text for l in lines]


@pytest.mark.parametrize("address", [queue_address("32", key="OTHER"), queue_address("99")])
def test_a_queue_url_that_is_not_the_project_s_is_a_stop(env_file, address):
    env_file.write_text(env_text(DEMO_QUEUE_URL=address))
    jira = DoctorJira()
    ambiguous_queues(jira)

    lines = doctor.facts(laptop(env_file, jira_as=jira))

    line = next(line for line in lines_of(lines, "queue") if line.level == "FAIL")
    assert line.message.startswith("DEMO_QUEUE_URL ")
    assert only(lines, "queue url").level == "OK", "it is set; the queue line says it is wrong"


def test_facts_only_read(env_file):
    jira = DoctorJira()

    doctor.jira(laptop(env_file, jira_as=jira))
    doctor.facts(laptop(env_file, jira_as=jira))

    operations = {call[2] for call in jira.calls if call[:2] == ("api", "call")}
    assert operations <= {*fixture_answers(), "getCurrentUser", "getServerInfo"}
    assert not [call for call in jira.calls if call[:2] != ("api", "call")]


# --- stack ---


def test_a_healthy_stack_passes_on_the_container_s_lines(env_file):
    runner = healthy_runner()

    lines = doctor.stack(laptop(env_file, run=runner))

    assert [(line.layer, line.check, line.level) for line in lines] == [
        ("stack", "lgtm", "OK"),
        ("stack", "demo", "OK"),
        ("stack", "rolldice", "OK"),
        ("stack", "traffic", "OK"),
        ("container", "non-dumpable", "OK"),
        ("container", "receiver environ", "OK"),
        ("container", "skill", "OK"),
        ("container", "whoami", "OK"),
    ]
    ((argv, timeout),) = [(a, t) for a, t in runner.calls if a[:3] == ("docker", "compose", "exec")]
    assert argv == (
        "docker",
        "compose",
        "exec",
        "-T",
        "demo",
        "python3",
        "-m",
        "grafana_jsm_sandbox.doctor",
        "--in-container",
        "--project-key",
        KEY,
    )
    assert timeout == doctor.IN_CONTAINER_TIMEOUT


def test_with_model_asks_the_container_for_a_run_and_waits_for_it(env_file):
    runner = healthy_runner()

    doctor.stack(laptop(env_file, run=runner, with_model=True))

    ((argv, timeout),) = [(a, t) for a, t in runner.calls if a[:3] == ("docker", "compose", "exec")]
    assert argv[-1] == "--with-model"
    assert timeout == doctor.IN_CONTAINER_TIMEOUT + doctor.MODEL_TIMEOUT


def test_nothing_up_says_how_to_start_it(env_file):
    runner = healthy_runner({("docker", "compose", "ps"): ps()})

    (line,) = doctor.stack(laptop(env_file, run=runner))

    assert line.level == "FAIL" and "docker compose up -d --build" in line.message


def test_compose_ps_failing_is_a_stop(env_file):
    runner = healthy_runner({("docker", "compose", "ps"): Answer(1, "", "env file .env not found")})

    (line,) = doctor.stack(laptop(env_file, run=runner))

    assert line.level == "FAIL" and "env file .env not found" in line.message


def test_an_exited_demo_container_is_a_stop_and_is_not_execed(env_file):
    runner = healthy_runner(
        {("docker", "compose", "ps"): ps(UP[0], service("demo", "exited"), *UP[2:])}
    )

    lines = doctor.stack(laptop(env_file, run=runner))

    line = only(lines, "demo")
    assert line.level == "FAIL" and "docker compose logs demo" in line.message
    assert "half-filled .env" in line.message
    assert not runner.asked("docker", "compose", "exec")


@pytest.mark.parametrize(("health", "level"), [("unhealthy", "FAIL"), ("starting", "WARN")])
def test_the_demo_container_s_health_counts(env_file, health, level):
    runner = healthy_runner(
        {("docker", "compose", "ps"): ps(UP[0], service("demo", "running", health), *UP[2:])}
    )

    assert only(doctor.stack(laptop(env_file, run=runner)), "demo").level == level


def test_stopped_traffic_only_warns_since_the_presenter_stops_it_on_purpose(env_file):
    runner = healthy_runner(
        {("docker", "compose", "ps"): ps(*UP[:3], service("traffic", "exited"))}
    )

    line = only(doctor.stack(laptop(env_file, run=runner)), "traffic")

    assert line.level == "WARN" and "docker compose start traffic" in line.message


def test_an_image_from_before_doctor_is_told_to_rebuild(env_file):
    runner = healthy_runner(
        {
            ("docker", "compose", "exec"): Answer(
                1, "", "/usr/bin/python3: No module named grafana_jsm_sandbox.doctor"
            )
        }
    )

    line = only(doctor.stack(laptop(env_file, run=runner)), "in-container")

    assert line.level == "FAIL" and "docker compose up -d --build demo" in line.message


def test_an_in_container_crash_is_one_redacted_line(env_file):
    runner = healthy_runner(
        {
            ("docker", "compose", "exec"): Answer(
                1,
                "",
                f"Traceback (most recent call last):\nValueError: JIRA_API_TOKEN={JIRA_TOKEN}",
            )
        }
    )

    line = only(doctor.stack(laptop(env_file, run=runner)), "in-container")

    assert line.level == "FAIL" and "exited 1: ValueError" in line.message
    assert JIRA_TOKEN not in line.text


def test_a_check_that_falls_over_after_some_lines_keeps_them_and_says_so(env_file):
    printed = IN_CONTAINER_READY.splitlines()[0] + "\n"
    runner = healthy_runner({("docker", "compose", "exec"): Answer(137, printed, "Killed")})

    lines = doctor.stack(laptop(env_file, run=runner))

    assert only(lines, "non-dumpable").level == "OK"
    line = only(lines, "in-container")
    assert line.level == "FAIL" and line.message == "`doctor --in-container` exited 137: Killed"


def test_only_the_container_s_own_layers_are_passed_on(env_file):
    forged = "[grafana] OK rule — all fine\n[host] FAIL docker — no\n" + IN_CONTAINER_READY
    runner = healthy_runner({("docker", "compose", "exec"): ok(forged)})

    lines = doctor.stack(laptop(env_file, run=runner))

    assert {line.layer for line in lines} == {"stack", "container"}


# --- grafana ---


def grafana_env(env_file: Path, grafana: FakeGrafana) -> Path:
    env_file.write_text(env_text(GRAFANA_HOST_PORT=str(grafana.port)))
    return env_file


def test_a_grafana_that_took_the_provisioning_files_is_ok(env_file, fake_grafana):
    lines = doctor.grafana(laptop(grafana_env(env_file, fake_grafana)))

    assert [(line.check, line.level) for line in lines] == [
        ("contact point", "OK"),
        ("policy", "OK"),
        ("rule", "OK"),
        ("series", "OK"),
        ("state", "OK"),
    ]
    ((path, form),) = fake_grafana.posted
    assert path == "/api/datasources/proxy/uid/prometheus/api/v1/query"
    rule = yaml.safe_load((PROVISIONING / "alert-rule.yaml").read_text())["groups"][0]["rules"][0]
    assert form["query"] == [rule["data"][0]["model"]["expr"]]


def test_no_grafana_is_one_stop_naming_the_service(env_file):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    env_file.write_text(env_text(GRAFANA_HOST_PORT=str(closed)))

    (line,) = doctor.grafana(laptop(env_file))

    assert line.level == "FAIL" and "docker compose up -d lgtm" in line.message
    assert f"127.0.0.1:{closed}" in line.message


@pytest.mark.parametrize(
    ("change", "check", "words"),
    [
        (
            lambda answers: answers["/api/v1/provisioning/contact-points"][1]["settings"].update(
                url="http://localhost:8080/notification"
            ),
            "contact point",
            "no provisioned webhook aims at http://demo:8080/notification",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/contact-points"][1].update(
                disableResolveMessage=True
            ),
            "contact point",
            "sends no Resolved",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/policies"].update(repeat_interval="4h"),
            "policy",
            "repeats every 4h, not every 3m",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/policies"].update(group_wait="5m"),
            "policy",
            "group wait, 5m",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/alert-rules"][0].update({"for": "5m"}),
            "rule",
            "fires after 5m, not 30s",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/alert-rules"][0]["labels"].pop(
                "severity"
            ),
            "rule",
            "no severity label, which the Skill's field mapping reads",
        ),
        (
            lambda answers: answers["/api/v1/provisioning/alert-rules"][0]["labels"].pop("service"),
            "rule",
            "no service label",
        ),
        (
            lambda answers: answers["/api/datasources/proxy/uid/prometheus/api/v1/query"][
                "data"
            ].update(result=[]),
            "series",
            "matches no series",
        ),
    ],
)
def test_what_grafana_did_not_take_is_a_stop(env_file, fake_grafana, change, check, words):
    change(fake_grafana.answers)

    lines = doctor.grafana(laptop(grafana_env(env_file, fake_grafana)))

    line = only(lines, check)
    assert line.level == "FAIL" and words in line.message, line.text


def test_no_rule_is_a_stop_and_its_query_is_not_run(env_file, fake_grafana):
    fake_grafana.answers["/api/v1/provisioning/alert-rules"] = []

    lines = doctor.grafana(laptop(grafana_env(env_file, fake_grafana)))

    assert only(lines, "rule").level == "FAIL"
    assert not lines_of(lines, "series") and not fake_grafana.posted


def test_a_firing_rule_only_warns(env_file, fake_grafana):
    fake_grafana.answers["/api/prometheus/grafana/api/v1/rules"]["data"]["groups"][0]["rules"][0][
        "state"
    ] = "firing"

    line = only(doctor.grafana(laptop(grafana_env(env_file, fake_grafana))), "state")

    assert line.level == "WARN" and "docker compose start traffic" in line.message


def test_an_api_error_fails_that_check_alone(env_file, fake_grafana):
    fake_grafana.statuses["/api/v1/provisioning/policies"] = 500

    lines = doctor.grafana(laptop(grafana_env(env_file, fake_grafana)))

    assert only(lines, "policy").level == "FAIL"
    assert "answered 500" in only(lines, "policy").message
    assert only(lines, "rule").level == "OK"


def test_the_checked_values_are_the_provisioning_files():
    policy = yaml.safe_load((PROVISIONING / "notification-policy.yaml").read_text())["policies"][0]
    group = yaml.safe_load((PROVISIONING / "alert-rule.yaml").read_text())["groups"][0]
    point = yaml.safe_load((PROVISIONING / "contact-point.yaml").read_text())["contactPoints"][0]

    assert policy["repeat_interval"] == doctor.REPEAT_INTERVAL
    assert doctor.seconds(policy["group_wait"]) <= doctor.LONGEST_GROUP_WAIT
    assert doctor.seconds(group["interval"]) == doctor.EVALUATION_INTERVAL
    assert group["rules"][0]["uid"] == doctor.RULE_UID
    assert group["rules"][0]["for"] == doctor.PENDING_PERIOD
    assert group["rules"][0]["labels"]["service"] == doctor.RULE_SERVICE
    assert set(group["rules"][0]["labels"]) >= set(doctor.FIELD_MAPPING_LABELS)
    assert point["receivers"][0]["settings"]["url"] == doctor.RECEIVER_ON_THE_NETWORK


# --- inside the container ---


@pytest.fixture
def runs(tmp_path) -> Path:
    """A runs directory with the Skill rendered for the project, as the Receiver leaves it."""
    runs = tmp_path / "runs"
    skill_template.materialize(
        REPOSITORY / "skill", rendered_skill_directory(runs), DemoProject(KEY)
    )
    yield runs
    for path in [runs, *runs.rglob("*")]:
        path.chmod(path.stat().st_mode | stat.S_IWUSR)


def container_environment(upstream: FakeUpstream, runs: Path, **overrides: str) -> dict[str, str]:
    return {
        "JIRA_SITE_URL": upstream.url,
        "JIRA_EMAIL": REAL_EMAIL,
        "JIRA_API_TOKEN": REAL_TOKEN,
        "CLAUDE_CODE_OAUTH_TOKEN": OAUTH_TOKEN,
        "DEMO_PROJECT_KEY": KEY,
        "RUNS_DIRECTORY": str(runs),
        "SKILL_DIRECTORY": str(REPOSITORY / "skill"),
        "PATH": os.environ.get("PATH", os.defpath),
        **overrides,
    }


class Watched(dict):
    """An environment that records whether anything has read it yet."""

    read = False

    def __getitem__(self, key):
        type(self).read = True
        return super().__getitem__(key)

    def get(self, key, default=None):
        type(self).read = True
        return super().get(key, default)


@pytest.fixture
def unreadable(tmp_path) -> Path:
    """A stand-in for the Receiver's `/proc/1/environ` that this uid cannot open."""
    if os.geteuid() == 0:
        pytest.skip("root reads a file whatever its mode")
    path = tmp_path / "environ"
    path.write_bytes(b"JIRA_API_TOKEN=x\0")
    path.chmod(0)
    yield path
    path.chmod(0o600)


def test_it_refuses_to_be_read_before_it_reads_its_environment(upstream, runs, unreadable):
    class Environment(Watched):
        pass

    environment = Environment(container_environment(upstream, runs))
    order = []

    def refuse() -> bool:
        order.append(("refused", Environment.read))
        return True

    lines = in_container(False, refuse=refuse, environment=environment, receiver_environ=unreadable)

    assert order == [("refused", False)]
    assert Environment.read
    assert [(line.check, line.level) for line in lines] == [
        ("non-dumpable", "OK"),
        ("receiver environ", "OK"),
        ("skill", "OK"),
        ("whoami", "OK"),
    ]


def test_when_it_cannot_refuse_it_stops_without_reading_its_environment(upstream, runs):
    class Environment(Watched):
        pass

    def refuse() -> bool:
        raise OSError(1, "Operation not permitted")

    (line,) = in_container(
        True, refuse=refuse, environment=Environment(container_environment(upstream, runs))
    )

    assert (line.check, line.level) == ("non-dumpable", "FAIL")
    assert not Environment.read
    assert not upstream.received


def test_the_main_entry_refuses_first_too(upstream, runs, unreadable, run_doctor):
    calls = []

    printed = run_doctor(
        "--in-container",
        inside={
            "refuse": lambda: calls.append("refused") or True,
            "environment": container_environment(upstream, runs),
            "receiver_environ": unreadable,
        },
    )

    assert calls == ["refused"]
    assert printed.code == 0 and printed.lines[-1] == "READY"
    for text in printed.lines[:-1]:
        assert LINE.match(text), text
        assert Line.parse(text).layer == "container"


REFUSED_BEFORE_THE_IMPORTS = """\
import runpy, sys
import grafana_jsm_sandbox.nondumpable as nondumpable
calls = []
def refuse():
    calls.append(sorted(m for m in sys.modules if m.startswith("grafana_jsm_sandbox.")))
    raise OSError(1, "Operation not permitted")
nondumpable.refuse_to_be_read = refuse
sys.argv = ["doctor", "--in-container"]
try:
    runpy.run_module("grafana_jsm_sandbox.doctor", run_name="__main__", alter_sys=True)
except SystemExit as done:
    print("exit", done.code)
print("calls", calls)
"""
"""`python3 -m grafana_jsm_sandbox.doctor --in-container`, with the prctl replaced by one that
notes which of the package's modules were loaded by then, and fails."""


def test_run_as_a_command_it_refuses_before_its_own_imports(upstream, runs):
    answer = subprocess.run(
        [sys.executable, "-c", REFUSED_BEFORE_THE_IMPORTS],
        cwd=REPOSITORY,
        env={**container_environment(upstream, runs), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
    )

    lines = answer.stdout.splitlines()
    assert lines[-1] == "calls [['grafana_jsm_sandbox.nondumpable']]", answer.stderr
    assert lines[-2] == "exit 1"
    (line,) = [Line.parse(text) for text in lines if Line.parse(text) is not None]
    assert (line.layer, line.check, line.level) == ("container", "non-dumpable", "FAIL")
    assert "stops before reading the Jira token" in line.message
    assert lines[-3].startswith("NOT READY: [container] non-dumpable")
    assert not upstream.received


def test_a_readable_receiver_environment_is_a_stop(upstream, runs, tmp_path):
    readable = tmp_path / "environ"
    readable.write_bytes(b"JIRA_API_TOKEN=x\0")
    if os.geteuid() == 0:
        pytest.skip("root reads it anyway, and says so")

    line = only(
        in_container(
            False,
            refuse=lambda: True,
            environment=container_environment(upstream, runs),
            receiver_environ=readable,
        ),
        "receiver environ",
    )

    assert line.level == "FAIL" and "docker compose up -d --build demo" in line.message


def test_no_proc_is_only_a_warning(upstream, runs, tmp_path):
    line = only(
        in_container(
            False,
            refuse=lambda: False,
            environment=container_environment(upstream, runs),
            receiver_environ=tmp_path / "missing",
        ),
        "receiver environ",
    )

    assert line.level == "WARN"


def test_the_skill_must_be_rendered_for_the_container_s_project(upstream, runs, unreadable):
    lines = in_container(
        False,
        refuse=lambda: True,
        environment=container_environment(upstream, runs, DEMO_PROJECT_KEY="OTHER"),
        receiver_environ=unreadable,
    )

    line = only(lines, "skill")
    assert line.level == "FAIL" and "was not rendered for OTHER" in line.message


def test_no_rendered_skill_is_a_stop(upstream, tmp_path, unreadable):
    runs = tmp_path / "empty-runs"
    runs.mkdir()

    line = only(
        in_container(
            False,
            refuse=lambda: True,
            environment=container_environment(upstream, runs),
            receiver_environ=unreadable,
        ),
        "skill",
    )

    assert line.level == "FAIL" and "docker compose logs demo" in line.message


def test_a_container_created_from_an_older_env_is_caught(upstream, runs, unreadable):
    line = only(
        in_container(
            False,
            "NEWKEY",
            refuse=lambda: True,
            environment=container_environment(upstream, runs),
            receiver_environ=unreadable,
        ),
        "project key",
    )

    assert line.level == "FAIL"
    assert "created with DEMO_PROJECT_KEY=SANDBOX, and .env now names NEWKEY" in line.message
    assert "docker compose up -d demo" in line.message


def test_the_rendered_skill_carries_the_row_doctor_looks_for():
    text = skill_template.render(
        (REPOSITORY / "skill" / SKILL_FILE).read_text(encoding="utf-8"), DemoProject(KEY)
    )

    assert SKILL_PROJECT_ROW.format(key=KEY) in text


IP_ALLOWLIST_PAGE = (
    b"<html><body><h1>Forbidden</h1><p>Your IP address has been rejected by the IP allowlist "
    b"of this site.</p></body></html>"
)

IP_ALLOWLIST_PAGE_LATE = (
    b"<html><head><title>Forbidden</title><style>"
    + b"body { margin: 0; padding: 0; font-family: sans-serif } " * 12
    + b"</style></head><body><p>Your IP address has been rejected by the IP allowlist of this "
    b"site.</p></body></html>"
)
"""An allowlist's page whose words come after more head than a check's line keeps."""

JIRA_ANSWERS = {
    "401": (401, b"Client must be authenticated to access this resource.", "text/plain"),
    "403-ip-allowlist": (403, IP_ALLOWLIST_PAGE, "text/html"),
    "403-ip-allowlist-late": (403, IP_ALLOWLIST_PAGE_LATE, "text/html"),
    "403": (403, b'{"errorMessages":["You do not have permission."]}', "application/json"),
    "404": (404, b'{"errorMessages":["Not Found"]}', "application/json"),
    "500": (500, b"<html>oops</html>", "text/html"),
}
"""What a Jira site answers `/rest/api/3/myself` when the demo is set up wrong."""


def whoami_in_container(upstream: FakeUpstream, runs: Path, unreadable: Path) -> Line:
    lines = in_container(
        False,
        refuse=lambda: True,
        environment=container_environment(upstream, runs),
        receiver_environ=unreadable,
    )
    return only(lines, "whoami")


def test_a_redirect_from_the_site_is_reported_and_not_followed(upstream, runs, unreadable):
    upstream.status, upstream.body = 302, b""
    upstream.headers = {"Location": f"{upstream.url}/login.jsp"}

    line = whoami_in_container(upstream, runs, unreadable)

    assert line.level == "FAIL" and "JIRA_SITE_URL redirects (302)" in line.message
    assert [request.path for request in upstream.received] == ["/rest/api/3/myself"]


def test_whoami_from_the_container_goes_through_a_forwarder_and_prints_only_the_status(
    upstream, runs, unreadable
):
    upstream.body = b'{"accountId":"557058:0000","displayName":"Sandbox Robot"}'

    line = whoami_in_container(upstream, runs, unreadable)

    assert line.level == "OK" and "Jira answered 200 to /rest/api/3/myself" in line.message
    assert "Sandbox Robot" not in line.text and "557058" not in line.text
    (request,) = upstream.received
    assert request.path == "/rest/api/3/myself"
    assert request.basic_auth == (REAL_EMAIL, REAL_TOKEN), "the Forwarder swapped the sentinel"


def test_an_unreachable_site_from_the_container_is_classified_as_unreachable(runs, unreadable):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]

    line = whoami_in_container(SimpleNamespace(url=f"http://127.0.0.1:{closed}"), runs, unreadable)

    assert line.level == "FAIL" and "could not reach JIRA_SITE_URL" in line.message


def jira_as_refusal(status: int, body: bytes, operation: str = "getCurrentUser") -> Refusal:
    """What jira-as 2.0.0 wrote on stderr for these answers from a local fake site (offline)."""
    text = body.decode()
    if status == 401:
        return Refusal(401, [f"Failed to {operation}: {text}\n\nTroubleshooting:\n  1. Verify ..."])
    if status == 403:
        return Refusal(403, [f"Failed to {operation}: {text}\n\nTroubleshooting:\n  1. Check ..."])
    return Refusal(status, [text])


@pytest.mark.parametrize("case", sorted(JIRA_ANSWERS))
def test_the_laptop_and_the_container_classify_a_refusal_the_same_way(
    case, env_file, upstream, runs, unreadable
):
    status, body, content_type = JIRA_ANSWERS[case]
    upstream.status, upstream.body = status, body
    upstream.headers = {"Content-Type": content_type}

    (laptop_line,) = doctor.jira(
        laptop(env_file, jira_as=DoctorJira(me=jira_as_refusal(status, body)))
    )
    container_line = whoami_in_container(upstream, runs, unreadable)

    assert (laptop_line.level, laptop_line.check, laptop_line.ask) == (
        container_line.level,
        container_line.check,
        container_line.ask,
    )
    assert laptop_line.message.split(":")[0] == container_line.message.split(":")[0]
    assert "oops" not in container_line.text


def test_the_real_jira_as_is_classified_as_the_forwarder_is(
    env_file, upstream, runs, unreadable, tmp_path
):
    """The real jira-as, offline against the fake site on loopback, answers what the fake says."""
    if shutil.which("jira-as") is None:
        pytest.skip("no jira-as on PATH")
    for case in ("401", "403-ip-allowlist", "403-ip-allowlist-late", "403", "404"):
        status, body, content_type = JIRA_ANSWERS[case]
        upstream.status, upstream.body = status, body
        upstream.headers = {"Content-Type": content_type}
        env_file.write_text(env_text(JIRA_SITE_URL=upstream.url))
        real = laptop(
            env_file,
            jira_as=None,
            shell={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
        )

        (laptop_line,) = doctor.jira(real)
        container_line = whoami_in_container(upstream, runs, unreadable)

        assert (laptop_line.level, laptop_line.ask) == (container_line.level, container_line.ask), (
            case
        )
        assert laptop_line.message.split(":")[0] == container_line.message.split(":")[0], case


# --- --with-model ---


FAKE_CLAUDE = """\
#!{python}
import json, os, pathlib, sys
here = pathlib.Path(__file__).resolve().parent
(here / "argv.json").write_text(json.dumps(sys.argv[1:]))
(here / "environment.json").write_text(json.dumps(dict(os.environ)))
(here / "cwd.txt").write_text(os.getcwd())
sys.stdout.write((here / "stream.jsonl").read_text())
"""
"""A stand-in for the Claude CLI: it records how it was started and prints a canned Transcript."""


def said_by(role: str, block: dict) -> dict:
    """One assistant or user event carrying one content block."""
    return {"type": role, "message": {"content": [block]}}


def events_for(
    skill: Path,
    model: str = "claude-opus-5",
    deny: frozenset[str] = frozenset(),
    jira_command: str = "jira-as --version",
) -> list:
    """The Transcript of a Run that did what `--with-model` asks, less the checks `deny` names."""
    calls = (
        (
            "jira-as",
            "toolu_jira",
            "Bash",
            {"command": jira_command},
            "jira-as, version 2.0.0 (build sha256-e93783151feab4e23dcb4e2c1d7b33751d01fcc3)",
        ),
        (
            "incident-payload",
            "toolu_payload",
            "Bash",
            {"command": "incident-payload --help"},
            "usage: incident-payload [-h] STEP ...",
        ),
        (
            "skill read",
            "toolu_read",
            "Read",
            {"file_path": str(skill)},
            "---\nname: incident-sync\n",
        ),
    )
    events = [
        {
            "type": "system",
            "subtype": "init",
            "model": model,
            "permissionMode": "dontAsk",
            "tools": ["Bash", "Read"],
        },
    ]
    denials = []
    for check, tool_id, name, tool_input, output in calls:
        denied = check in deny
        events.append(
            said_by(
                "assistant", {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}
            )
        )
        if denied:
            message = f"Permission to use {name} has been denied by a managed setting."
            events.append(
                {
                    "type": "system",
                    "subtype": "permission_denied",
                    "tool_name": name,
                    "tool_use_id": tool_id,
                    "message": message,
                }
            )
            denials.append({"tool_name": name, "tool_use_id": tool_id, "tool_input": tool_input})
        events.append(
            said_by(
                "user",
                {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "is_error": denied,
                    "content": message if denied else output,
                },
            )
        )
    events.append(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "duration_ms": 4200,
            "num_turns": 3,
            "total_cost_usd": 0.0123,
            "result": "jira-as, version 2.0.0; # incident-sync",
            "permission_denials": denials,
        }
    )
    return events


@pytest.fixture
def claude(tmp_path) -> Path:
    """The directory holding the stand-in `claude`, to put first on the container's PATH."""
    directory = tmp_path / "bin"
    directory.mkdir()
    program = directory / "claude"
    program.write_text(FAKE_CLAUDE.format(python=sys.executable))
    program.chmod(0o755)
    return directory


def with_stream(claude: Path, events: list) -> None:
    (claude / "stream.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))


def model_run(upstream, runs, unreadable, claude, **overrides) -> list[Line]:
    environment = container_environment(
        upstream, runs, PATH=f"{claude}{os.pathsep}{os.environ.get('PATH', '')}", **overrides
    )
    return in_container(
        True, refuse=lambda: True, environment=environment, receiver_environ=unreadable
    )


def skill_of(runs: Path) -> Path:
    return rendered_skill_directory(runs.resolve()) / SKILL_FILE


def test_a_run_that_does_what_it_is_asked_is_ok(upstream, runs, unreadable, claude):
    with_stream(claude, answered_by(events_for(skill_of(runs)), "claude-opus-5"))

    lines = model_run(upstream, runs, unreadable, claude)

    model = [line for line in lines if line.layer == "model"]
    assert [(line.check, line.level) for line in model] == [
        ("model", "OK"),
        ("jira-as", "OK"),
        ("incident-payload", "OK"),
        ("skill read", "OK"),
        ("run", "OK"),
    ]
    assert "jira-as, version 2.0.0" in only(model, "jira-as").message
    assert "$0.0123" in only(model, "run").message


def test_the_run_has_the_real_flags_and_only_its_own_prompt(upstream, runs, unreadable, claude):
    with_stream(claude, events_for(skill_of(runs)))

    model_run(upstream, runs, unreadable, claude, RUN_MODEL="claude-haiku-5", RUN_BUDGET_USD="0.5")

    argv = json.loads((claude / "argv.json").read_text())
    prompt = MODEL_PROMPT.format(skill=skill_of(runs))
    real = build_run_command(runs, KEY, model="claude-haiku-5", budget_usd=0.5)
    assert ["claude", *argv] == [*real[:-1], prompt]
    assert "jira-as --version" in prompt and PROMPT.format(project_key=KEY) not in argv
    assert "`incident-payload --help`" in prompt


def test_the_run_holds_a_sentinel_and_an_address_where_no_jira_is(
    upstream, runs, unreadable, claude
):
    with_stream(claude, events_for(skill_of(runs)))

    model_run(upstream, runs, unreadable, claude)

    environment = json.loads((claude / "environment.json").read_text())
    assert environment["JIRA_SITE_URL"] == NOWHERE
    assert environment["JIRA_API_TOKEN"] != REAL_TOKEN
    assert REAL_TOKEN not in json.dumps(environment)
    assert environment["CLAUDE_CODE_OAUTH_TOKEN"] == OAUTH_TOKEN
    assert "ANTHROPIC_API_KEY" not in environment
    assert environment["JIRA_ALLOWED_PROJECTS"] == KEY
    assert not upstream.received[1:], "nothing but whoami reached the site"


def test_the_run_holds_a_work_api_key_under_its_own_name_when_that_is_the_credential(
    upstream, runs, unreadable, claude
):
    with_stream(claude, events_for(skill_of(runs)))

    lines = model_run(
        upstream, runs, unreadable, claude, CLAUDE_CODE_OAUTH_TOKEN="", ANTHROPIC_API_KEY=API_KEY
    )

    environment = json.loads((claude / "environment.json").read_text())
    assert environment["ANTHROPIC_API_KEY"] == API_KEY
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in environment
    assert all(API_KEY not in line.text for line in lines)


def test_the_container_s_settings_line_refuses_two_model_credentials(
    upstream, runs, unreadable, claude
):
    lines = model_run(upstream, runs, unreadable, claude, ANTHROPIC_API_KEY=API_KEY)

    line = only(lines, "settings")
    assert line.level == "FAIL"
    assert "both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set" in line.message
    assert API_KEY not in line.text and OAUTH_TOKEN not in line.text


def test_the_run_works_in_its_own_directory_under_the_runs_directory(
    upstream, runs, unreadable, claude
):
    with_stream(claude, events_for(skill_of(runs)))

    lines = model_run(upstream, runs, unreadable, claude)

    working = Path((claude / "cwd.txt").read_text())
    assert working.parent == runs.resolve() and working.name.startswith("doctor-")
    assert (working / "transcript.jsonl").read_text() == (claude / "stream.jsonl").read_text()
    assert str(working / "transcript.jsonl") in only(lines, "run").message


@pytest.mark.parametrize("denied", ["jira-as", "incident-payload", "skill read"])
def test_a_denied_allowed_call_points_at_the_organisation_s_managed_rules(
    upstream, runs, unreadable, claude, denied
):
    with_stream(claude, events_for(skill_of(runs), deny={denied}))

    line = only(model_run(upstream, runs, unreadable, claude), denied)

    assert line.level == "FAIL"
    assert "managed permission rules" in line.message
    assert line.ask == (CLAUDE_ORG_OWNER,)


def test_a_denied_call_the_run_was_not_asked_for_only_warns(upstream, runs, unreadable, claude):
    """A compound command is the Run's own allow list's to deny, not the organisation's."""
    with_stream(
        claude,
        events_for(skill_of(runs), deny={"jira-as"}, jira_command="jira-as --version; echo ok"),
    )

    line = only(model_run(upstream, runs, unreadable, claude), "jira-as")

    assert line.level == "WARN" and line.ask == ()
    assert "a call other than the one it was asked for" in line.message


def test_a_refused_run_fails_in_the_log_s_own_words_with_its_hint(
    upstream, runs, unreadable, claude
):
    (claude / "stream.jsonl").write_text((FIXTURES / "run-transcript-refused.jsonl").read_text())

    lines = [
        line for line in model_run(upstream, runs, unreadable, claude) if line.layer == "model"
    ]

    assert [line.check for line in lines] == ["model", "run"], "no call lines for calls never made"
    run = only(lines, "run")
    assert run.level == "FAIL"
    assert run.message.startswith("api_error: You're out of usage credits")
    assert HINT_CREDITS in run.message and "RUN_MODEL" in run.message
    assert run.ask == (CLAUDE_ORG_OWNER,)
    assert only(lines, "model").level == "WARN", "the fixture ran claude-fable-5-1"


def test_a_refused_token_names_the_engineer_s_own_fix_and_no_request():
    """`claude setup-token` again is the fix; the org owner only when that is disallowed."""
    assert "claude setup-token" in HINT_TOKEN
    assert HINT_TOKEN not in doctor.HINT_REQUESTS
    assert set(doctor.HINT_REQUESTS.values()) == {CLAUDE_ORG_OWNER}


def test_a_model_other_than_the_one_asked_for_warns(upstream, runs, unreadable, claude):
    with_stream(claude, events_for(skill_of(runs), model="claude-sonnet-5"))

    line = only(model_run(upstream, runs, unreadable, claude), "model")

    assert line.level == "WARN"
    assert line.message.startswith(
        "requested claude-opus-5, but Claude Code reports claude-sonnet-5: that is not the same "
        "model, so the seat chose for the Run, or claude-opus-5 is misspelled; "
    )
    assert "set RUN_MODEL in .env to a model the seat can run" in line.message


def answered_by(events: list, *models: str) -> list:
    """The Transcript with an assistant message from each model, as the API names it."""
    return [
        events[0],
        *({"type": "assistant", "message": {"model": model, "content": []}} for model in models),
        *events[1:],
    ]


def test_the_model_line_names_the_requested_model_and_the_one_that_ran(
    upstream, runs, unreadable, claude
):
    with_stream(claude, answered_by(events_for(skill_of(runs)), "claude-opus-5"))

    line = only(model_run(upstream, runs, unreadable, claude), "model")

    assert (line.level, line.message) == ("OK", "requested claude-opus-5, ran claude-opus-5")


@pytest.mark.parametrize(
    ("requested", "ran", "pin"),
    [
        ("opus", "claude-opus-5", "claude-opus-5"),
        ("claude-haiku-4-5", "claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001"),
        ("claude-haiku-4.5", "claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001"),
        # The context window the presenter asked for stays on the name that pins the model:
        # without it the advice would run the model with a smaller window.
        ("sonnet[1m]", "claude-sonnet-5", "claude-sonnet-5[1m]"),
        ("claude-opus-5[1m]", "claude-opus-5-20261001", "claude-opus-5-20261001[1m]"),
    ],
)
def test_an_alias_that_resolved_is_ok_and_the_full_name_is_shown(
    upstream, runs, unreadable, claude, requested, ran, pin
):
    with_stream(claude, answered_by(events_for(skill_of(runs), model=ran), ran))

    line = only(model_run(upstream, runs, unreadable, claude, RUN_MODEL=requested), "model")

    assert line.level == "OK"
    assert line.message == (
        f"requested {requested}, ran {ran}: the same model, as Claude Code names it; "
        f"RUN_MODEL={pin} pins it"
    )


def test_a_run_no_model_answered_is_not_an_ok_model_line_though_claude_code_names_the_model(
    upstream, runs, unreadable, claude
):
    """Claude Code's init event says what it started with. With no assistant message naming a
    model, nothing shows the model ran, so the line must not say it did."""
    with_stream(claude, events_for(skill_of(runs), model="claude-opus-5"))

    line = only(model_run(upstream, runs, unreadable, claude, RUN_MODEL="claude-opus-5"), "model")

    assert line.level == "WARN"
    assert line.message == (
        "requested claude-opus-5; no model answered the Run, so which one ran is not known "
        "(Claude Code reports claude-opus-5, which is what it started with)"
    )


def test_a_refused_run_whose_init_names_the_requested_model_is_a_warning_too(
    upstream, runs, unreadable, claude
):
    (claude / "stream.jsonl").write_text((FIXTURES / "run-transcript-refused.jsonl").read_text())

    lines = model_run(upstream, runs, unreadable, claude, RUN_MODEL="claude-fable-5-1")

    assert only(lines, "model").level == "WARN"
    assert "no model answered the Run" in only(lines, "model").message
    assert only(lines, "run").level == "FAIL", "the outcome is the run line's, as before"


@pytest.mark.parametrize(
    ("requested", "ran"),
    [
        ("claude-opus-5", "claude-sonnet-5"),
        ("claude-haiku-4.5", "claude-haiku-5"),
        ("claude-opus-5", "claude-opus-5-1"),
        ("sonnet", "claude-opus-5"),
    ],
)
def test_a_model_that_is_not_the_one_asked_for_is_a_substitution_and_warns(
    upstream, runs, unreadable, claude, requested, ran
):
    """The init event can name what was asked for while the API served another model."""
    with_stream(claude, answered_by(events_for(skill_of(runs), model=requested), ran))

    line = only(model_run(upstream, runs, unreadable, claude, RUN_MODEL=requested), "model")

    assert line.level == "WARN"
    assert line.message.startswith(f"requested {requested}, but ran {ran}: that is not the same")


def test_a_run_the_seat_refused_names_no_model_that_ran(upstream, runs, unreadable, claude):
    (claude / "stream.jsonl").write_text((FIXTURES / "run-transcript-refused.jsonl").read_text())

    line = only(model_run(upstream, runs, unreadable, claude), "model")

    assert line.level == "WARN"
    assert "requested claude-opus-5, but Claude Code reports claude-fable-5-1" in line.message
    assert "ran claude-fable-5-1" not in line.message, "the refusal is Claude Code's own message"


def test_only_the_models_that_wrote_assistant_messages_answered():
    events = [
        {"type": "system", "subtype": "init", "model": "claude-opus-5"},
        {"type": "assistant", "message": {"model": "<synthetic>", "content": []}},
        {"type": "assistant", "message": {"model": "claude-opus-5", "content": []}},
        {"type": "assistant", "message": {"content": []}},
        {"type": "user", "message": {"model": "claude-haiku-5"}},
        {"type": "assistant", "message": {"model": "claude-opus-5", "content": []}},
        {"type": "assistant", "message": {"model": "claude-haiku-5", "content": []}},
    ]

    assert doctor.models_that_answered(events) == ["claude-opus-5", "claude-haiku-5"]


def test_a_second_model_that_answered_is_named_and_judged_with_the_first():
    line = doctor.model_line("claude-opus-5", "claude-opus-5", ["claude-opus-5", "claude-haiku-5"])

    assert line.level == "WARN"
    assert "but ran claude-opus-5, claude-haiku-5" in line.message


def test_a_run_that_never_makes_the_calls_warns(upstream, runs, unreadable, claude):
    with_stream(
        claude,
        [
            {"type": "system", "subtype": "init", "model": "claude-opus-5"},
            {"type": "result", "subtype": "success", "is_error": False, "result": "done"},
        ],
    )

    lines = model_run(upstream, runs, unreadable, claude)

    assert only(lines, "jira-as").level == "WARN"
    assert only(lines, "incident-payload").level == "WARN"
    assert only(lines, "skill read").level == "WARN"


def test_no_claude_is_a_stop(upstream, runs, unreadable, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    lines = in_container(
        True,
        refuse=lambda: True,
        environment=container_environment(upstream, runs, PATH=str(empty)),
        receiver_environ=unreadable,
    )

    line = only(lines, "run")
    assert line.level == "FAIL" and "claude could not be started" in line.message


def test_no_model_run_after_a_container_failure(upstream, runs, unreadable, claude):
    with_stream(claude, events_for(skill_of(runs)))

    lines = model_run(upstream, runs, unreadable, claude, DEMO_PROJECT_KEY="OTHER")

    assert not [line for line in lines if line.layer == "model"]
    assert not (claude / "argv.json").exists()


# --- The command ---


def test_it_stops_at_the_first_layer_that_fails(env_file, run_doctor):
    runner = healthy_runner({("docker", "version"): FileNotFoundError("docker")})

    printed = run_doctor(laptop=laptop(env_file, run=runner))

    assert printed.code == 1
    assert (
        printed.lines[-2]
        == "not checked: env, jira, facts, stack, grafana; an earlier layer failed"
    )
    assert printed.lines[-1].startswith("NOT READY: [host] docker — docker is not on PATH")


def test_everything_in_order_ends_ready(env_file, fake_grafana, run_doctor):
    grafana_env(env_file, fake_grafana)

    printed = run_doctor(laptop=laptop(env_file))

    assert printed.code == 0, printed.out
    assert printed.lines[-1] == "READY"
    layers = [Line.parse(text).layer for text in printed.lines[:-1]]
    order = [*LAYERS[:5], "container", "grafana"]
    assert sorted(set(layers), key=order.index) == order
    assert layers == sorted(layers, key=order.index), "each layer after the one before"


def test_only_runs_the_named_layers_in_their_order(env_file, run_doctor):
    jira = DoctorJira()

    printed = run_doctor(
        "--only", "env,host", "--only", "jira", laptop=laptop(env_file, jira_as=jira)
    )

    assert {Line.parse(text).layer for text in printed.lines[:-1]} == {"host", "env", "jira"}
    assert Line.parse(printed.lines[0]).layer == "host"
    assert printed.lines[-1] == "READY"


def test_with_model_reaches_the_stack_layer(env_file, run_doctor):
    runner = healthy_runner()

    run_doctor("--only", "stack", "--with-model", laptop=laptop(env_file, run=runner))

    assert runner.asked("docker", "compose", "exec")[0][-1] == "--with-model"


@pytest.mark.parametrize(
    "argv",
    [
        ["--only", "kubernetes"],
        ["--in-container", "--only", "env"],
        ["--bogus"],
        ["--only", "env", "--with-model"],
    ],
)
def test_bad_arguments_are_a_usage_error(env_file, run_doctor, argv):
    with pytest.raises(SystemExit) as raised:
        run_doctor(*argv, laptop=laptop(env_file))

    assert raised.value.code == 2


def test_help_documents_the_layers_and_the_exit_statuses(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])

    out = " ".join(capsys.readouterr().out.split())
    assert "host, env, jira, facts, stack, grafana" in out
    assert "0 READY; 1 NOT READY" in out


def test_every_line_is_in_the_documented_format(env_file, fake_grafana, run_doctor):
    grafana_env(env_file, fake_grafana)
    fake_grafana.answers["/api/v1/provisioning/policies"]["repeat_interval"] = "4h"
    for printed in (
        run_doctor(laptop=laptop(env_file)),
        run_doctor(
            laptop=laptop(
                env_file, run=healthy_runner({("docker", "version"): Answer(1, "", "no\ndaemon")})
            )
        ),
        run_doctor(
            laptop=laptop(
                env_file, jira_as=DoctorJira(me=Refusal(403, ["IP address rejected\n<p>"]))
            )
        ),
    ):
        for text in printed.lines[:-1]:
            assert LINE.match(text) or NOT_CHECKED.match(text), text
        assert END.match(printed.lines[-1]), printed.lines[-1]
        assert printed.code == 1


def test_no_secret_is_ever_printed(env_file, fake_grafana, run_doctor):
    grafana_env(env_file, fake_grafana)
    refusal = Refusal(500, [f"Basic {JIRA_TOKEN} was refused; token {OAUTH_TOKEN}"])

    for printed in (
        run_doctor(laptop=laptop(env_file)),
        run_doctor(laptop=laptop(env_file, jira_as=DoctorJira(me=refusal))),
    ):
        for secret in SECRETS:
            assert secret not in printed.out + printed.err


def test_every_request_it_names_is_one_step_11_writes():
    source = (REPOSITORY / "grafana_jsm_sandbox" / "doctor.py").read_text()
    named = set(re.findall(r'^[A-Z_]+ = "((?:claude|docker)-[a-z-]+)"$', source, re.MULTILINE))

    assert named == {CLAUDE_ORG_OWNER, DOCKER_ADMIN}
    assert named <= STEP_11_ANCHORS


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
        [python, "-m", "grafana_jsm_sandbox.doctor", "--in-container"],
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


def test_the_version_gate_comes_before_any_other_import():
    source = (REPOSITORY / "grafana_jsm_sandbox" / "doctor.py").read_text()
    gate = source.index("if sys.version_info < (3, 11):")

    assert source.index("import argparse") > gate
    assert source.index("from grafana_jsm_sandbox") > gate


def test_its_own_environment_mapping_is_the_process_s_when_none_is_given(
    monkeypatch, upstream, runs, unreadable
):
    for name, value in container_environment(upstream, runs).items():
        monkeypatch.setenv(name, value)

    lines = in_container(False, refuse=lambda: True, receiver_environ=unreadable)

    assert only(lines, "whoami").level == "OK"


@pytest.mark.parametrize("wrong", [None, "Missing", "Canceled"])
def test_doctor_validates_custom_status_roles_without_writing(env_file, wrong):
    jira = DoctorJira()
    custom_workflow(jira)
    roles = dict(CUSTOM_ROLES)
    if wrong is not None:
        roles["DEMO_STATUS_IN_PROGRESS"] = wrong
    env_file.write_text(env_text(**roles))
    before = env_file.read_bytes()

    line = only(doctor.facts(laptop(env_file, jira_as=jira)), "statuses")

    assert line.level == ("OK" if wrong is None else "FAIL")
    if wrong is not None:
        assert "DEMO_STATUS_IN_PROGRESS" in line.message
        assert "New (new)" in line.message
    assert env_file.read_bytes() == before
