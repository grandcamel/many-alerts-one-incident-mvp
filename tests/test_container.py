"""The committed container and compose, checked against the process they must start.

Nothing here builds an image. These drive the three committed files — the
Dockerfile, `docker-compose.yml` and `.env.example` — against the code and the
rules they exist to satisfy: the configuration reader that refuses to start
without a credential, git's own ignore rules, and the redaction the log
formatter applies to anything credential-shaped.

The checks that need a container actually running are opt-in, like the
end-to-end check, because they cost a build and a demo:

    DEMO_CONTAINER=1 python3 -m pytest tests/test_container.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.request
from collections.abc import Mapping
from fnmatch import fnmatch
from pathlib import Path

import pytest
import yaml

from grafana_jsm_sandbox.__main__ import (
    HOST_VARIABLE,
    PORT_VARIABLE,
    RUN_BUDGET_VARIABLE,
    RUN_MODEL_VARIABLE,
    RUN_TIMEOUT_VARIABLE,
    RUNS_DIRECTORY_VARIABLE,
    SKILL_DIRECTORY_VARIABLE,
    IncompleteConfiguration,
    Settings,
)
from grafana_jsm_sandbox.demo_config import (
    FIELD_VARIABLES,
    PROJECT_KEY_VARIABLE,
    QUEUE_URL_VARIABLE,
    SESSION_ID_VARIABLE,
    DemoProject,
    read_env_file,
)
from grafana_jsm_sandbox.forwarder import ENVIRONMENT_VARIABLES
from grafana_jsm_sandbox.log_formatter import redact
from grafana_jsm_sandbox.replay import (
    BIND_ADDRESS_VARIABLE,
    DEFAULT_BIND_ADDRESS,
    RECEIVER_HOST_PORT_VARIABLE,
    default_receiver,
)
from grafana_jsm_sandbox.run_command import SKILL_FILE, rendered_skill_directory
from grafana_jsm_sandbox.run_spawner import (
    API_KEY_VARIABLE,
    MODEL_CREDENTIAL_VARIABLES,
    OAUTH_TOKEN_VARIABLE,
    TRUST_STORE_VARIABLES,
)
from tests.conftest import REPOSITORY, compose, needs_the_stack_up

COMPOSE_FILE = REPOSITORY / "docker-compose.yml"
DOCKERFILE = REPOSITORY / "Dockerfile"
DOCKER_IGNORE = REPOSITORY / ".dockerignore"
ENV_EXAMPLE = REPOSITORY / ".env.example"
"""The four committed files that describe the container, all read as text."""

ENV_FILE = ".env"
"""What compose reads the demo's credentials from, and what git must never take."""

RUNS_PATTERN = "runs/"
"""What must stay ignored: each Run's working directory, and the Notification in it."""

DEMO_SERVICE = "demo"
"""The container the Run happens in. Grafana's contact point will name it."""

LGTM_SERVICE = "lgtm"
"""The published Grafana stack the Alert fires from."""

TRAFFIC_SERVICE = "traffic"
"""The synthetic traffic. Stopping it fires the Alert; starting it resolves it (story 55)."""

FAKE_JIRA_SERVICE = "fakejira"
"""The fake Jira for rehearsing with no real site (lane 5). Under a profile, so a plain
`docker compose up` never starts it."""

FAKE_JIRA_PROFILE = "fake-jira"

FAKE_JIRA_PORT = 8090
"""The fake's port, the same in the container and on the laptop, so that one `JIRA_SITE_URL`
names it from both sides."""

PROVISIONING = REPOSITORY / "grafana" / "provisioning" / "alerting"
"""The contact point, the notification policy and the alert rule, in this repo (story 53)."""

GRAFANA_ALERTING_PROVISIONING = "/otel-lgtm/grafana/conf/provisioning/alerting"
"""Where Grafana in the published image reads alerting provisioning from."""

GRAFANA_PORT = 3000
"""Grafana's port in its container, and on the laptop unless GRAFANA_HOST_PORT moves it."""

RECEIVER_PORT = 8080
"""The Receiver's port in its container, which the contact point names; on the laptop unless
RECEIVER_HOST_PORT moves it."""

GRAFANA_HOST_PORT_VARIABLE = "GRAFANA_HOST_PORT"
"""The presenter's knob for a laptop whose 3000 is taken."""

CREDENTIALS = (*ENVIRONMENT_VARIABLES.values(), API_KEY_VARIABLE)
"""Every variable the process refuses to start without, as the example sets them: the Jira
credential, and the API key as the one model credential it sets (the OAuth token is the other
name, named but left unset, since exactly one of the two may be)."""

SETTINGS_VARIABLES = (
    *CREDENTIALS,
    OAUTH_TOKEN_VARIABLE,
    PROJECT_KEY_VARIABLE,
    SESSION_ID_VARIABLE,
    *FIELD_VARIABLES.values(),
    QUEUE_URL_VARIABLE,
    HOST_VARIABLE,
    PORT_VARIABLE,
    RUNS_DIRECTORY_VARIABLE,
    SKILL_DIRECTORY_VARIABLE,
    RUN_TIMEOUT_VARIABLE,
    RUN_MODEL_VARIABLE,
    RUN_BUDGET_VARIABLE,
)
"""Every variable the process reads at all, which is what the example must list."""

LGTM_IMAGE_VARIABLE = "LGTM_IMAGE"
"""Compose's knob for pulling the pinned Grafana stack from somewhere else, such as a mirror."""

LGTM_REPOSITORY = "grafana/otel-lgtm"
LGTM_TAG = "0.33.0"
LGTM_INDEX_DIGEST = "sha256:475319e883b66594d1a2f22ef168c2459802bb94548e6f25d9782bd5f5c19a3a"
"""What the laptop's `latest` was on 2026-09-23, not a release the demo is recorded as
rehearsed on: its multi-platform index (linux/amd64, linux/arm64) is, by `docker buildx
imagetools inspect`, the one tagged 0.33.0, and it carries Grafana 13.2.1 (step 06 of
demo-onboarding)."""

PINNED_REFERENCE = re.compile(
    r"(?P<name>[^\s@]+?):(?P<tag>\w[\w.-]{0,127})(?:@sha256:[0-9a-f]{64})?"
)
"""An image reference with an explicit tag, and optionally a digest after it. The name may
carry a registry's port, so the tag is the last colon's, not the first's."""


def env_example() -> dict[str, str]:
    """The committed example read the way compose reads an env file, by the demo's own reader."""
    return read_env_file(ENV_EXAMPLE)


COMPOSE = yaml.safe_load(COMPOSE_FILE.read_text())
"""The committed compose file, read once."""


def service(name: str) -> dict:
    return COMPOSE["services"][name]


INTERPOLATION = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}")
"""`${NAME}` or `${NAME:-default}`, the two forms of compose interpolation this file uses."""


def interpolated(value: str, environment: Mapping[str, str]) -> str:
    """A compose value as compose resolves it: `:-` takes the default for empty or unset."""
    return INTERPOLATION.sub(lambda match: environment.get(match[1]) or (match[2] or ""), value)


def publications(name: str, environment: Mapping[str, str] | None = None) -> set[tuple]:
    """What a service publishes to the laptop: address, laptop port, container port.

    Compose's short form is `"[address:]host:container"`, here with the address and
    the laptop port interpolated from the presenter's environment, empty by default.
    A bare `"container"` publishes nothing to the laptop and so counts for nothing.
    """
    found = set()
    for mapping in service(name).get("ports", []):
        parts = interpolated(str(mapping), environment or {}).rsplit(":", 2)
        if len(parts) == 3:
            found.add((parts[0], int(parts[1]), int(parts[2])))
        elif len(parts) == 2:
            found.add(("", int(parts[0]), int(parts[1])))
    return found


def published_ports(name: str, environment: Mapping[str, str] | None = None) -> set[int]:
    """The container ports a service publishes to the laptop at all."""
    return {container for _, _, container in publications(name, environment)}


def git_ignores(path: str) -> bool:
    """By this repo's own rules: another engineer's clone has none of this laptop's global ones."""
    return (
        subprocess.run(
            ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "-q", path],
            cwd=REPOSITORY,
            check=False,
        ).returncode
        == 0
    )


def test_the_committed_example_leaves_the_project_key_for_the_engineer_to_choose():
    """Copied as it is, the Receiver names both missing choices: model credential and project."""
    assert env_example()[PROJECT_KEY_VARIABLE] == ""

    with pytest.raises(IncompleteConfiguration) as refusal:
        Settings.from_environment(env_example())

    assert f"{PROJECT_KEY_VARIABLE} is not set" in str(refusal.value)
    assert "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set" in str(refusal.value)


@pytest.mark.parametrize("credential", MODEL_CREDENTIAL_VARIABLES)
def test_the_committed_example_with_a_key_and_one_model_credential_would_start(credential):
    """Either model method works once the engineer supplies the project and one credential."""
    settings = Settings.from_environment(
        {**env_example(), PROJECT_KEY_VARIABLE: "SANDBOX", credential: "test-only-model-credential"}
    )

    assert settings.credential.site_url.startswith("https://")
    assert settings.credential.email
    assert settings.credential.api_token
    assert settings.model_credential.variable == credential
    assert settings.project.key == "SANDBOX"


def test_the_example_names_both_model_credentials_empty_and_commented():
    example = env_example()
    for name in MODEL_CREDENTIAL_VARIABLES:
        assert name not in example
        assert f"# {name}=\n" in ENV_EXAMPLE.read_text()


def test_the_example_sets_a_session_id_the_label_can_carry():
    """A working value rather than a placeholder: a rehearsal's, to change before the demo."""
    session_id = env_example()[SESSION_ID_VARIABLE]
    assert session_id and re.fullmatch(r"[a-z0-9-]{1,32}", session_id)
    assert DemoProject.from_environment({**env_example(), PROJECT_KEY_VARIABLE: "SANDBOX"}) == (
        DemoProject(key="SANDBOX", session_id=session_id)
    )


@pytest.mark.parametrize("variable", CREDENTIALS)
def test_the_example_names_every_credential_the_demo_needs(variable):
    assert re.search(rf"^#? ?{variable}=", ENV_EXAMPLE.read_text(), re.MULTILINE)


@pytest.mark.parametrize("variable", SETTINGS_VARIABLES)
def test_the_example_names_every_variable_the_process_reads(variable):
    """Named, not necessarily set: the ones with a working default are commented out."""
    assert variable in ENV_EXAMPLE.read_text()


def test_the_example_carries_placeholders_rather_than_anyone_s_credential():
    """Nothing in it is credential-shaped, by the same rule that keeps the log clean."""
    for name, value in env_example().items():
        assert redact(value) == value, f"{name} looks like a real credential"


def test_git_never_takes_the_env_file_compose_reads():
    assert git_ignores(ENV_FILE)


def test_git_never_takes_a_run_s_working_directory():
    assert git_ignores(RUNS_PATTERN)


def test_the_build_context_carries_neither_the_env_file_nor_a_past_run():
    ignored = DOCKER_IGNORE.read_text().split()

    assert ENV_FILE in ignored
    assert RUNS_PATTERN in ignored


LOCAL_ONLY = (".claude/", "**/__pycache__/", ".scratch/", "prototype/")
"""What a laptop keeps beside the code and an image must not carry: Claude Code's local
settings, byte code from any depth, the working notes, and the chapter-two prototype."""


def test_git_never_takes_claude_code_s_local_settings():
    """Where a laptop's own permissions go, and never a commit (audit F24)."""
    assert git_ignores(".claude/settings.local.json")
    assert not git_ignores(".claude/settings.json"), "the shared settings are committed"


@pytest.mark.parametrize("pattern", LOCAL_ONLY)
def test_the_build_context_refuses_what_is_only_the_laptop_s(pattern):
    assert pattern in DOCKER_IGNORE.read_text().split()


def copied_sources() -> list[str]:
    """Every path either Dockerfile copies from the build context, which both build from the
    repository root through the one .dockerignore, the CA argument as its default."""
    sources = []
    instructions = [line for file in BOTH_DOCKERFILES for line in dockerfile_instructions(file)]
    for instruction in instructions:
        if instruction.startswith("COPY "):
            words = [word for word in instruction.split()[1:] if not word.startswith("--")]
            sources += [
                word.replace(f"${{{EXTRA_CA_ARGUMENT}}}", PLACEHOLDER) for word in words[:-1]
            ]
    return sources


def test_the_build_context_still_carries_everything_the_image_copies():
    """Checked against every ignore pattern, and against each directory above each source."""
    patterns = [
        line.strip().rstrip("/")
        for line in DOCKER_IGNORE.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert copied_sources(), "the Dockerfile copies nothing; the check reads nothing"
    for source in copied_sources():
        path = source.rstrip("/")
        prefixes = [path] + [
            "/".join(path.split("/")[:end]) for end in range(1, path.count("/") + 1)
        ]
        for pattern in patterns:
            for prefix in prefixes:
                assert not fnmatch(prefix, pattern), f"{pattern} keeps {source} out of the image"


def test_the_demo_takes_its_credentials_from_the_ignored_env_file():
    demo = service(DEMO_SERVICE)

    assert ENV_FILE in _as_list(demo["env_file"])
    assert not set(demo.get("environment", {})) & set(CREDENTIALS)


def test_a_misconfigured_demo_is_not_restarted_into_a_crash_loop():
    """The Receiver refuses to start and names the missing variable. Once (story 47)."""
    assert "restart" not in service(DEMO_SERVICE)


def test_no_service_is_handed_the_docker_socket():
    for name, definition in COMPOSE["services"].items():
        for volume in definition.get("volumes", []):
            assert "docker.sock" not in str(volume), f"{name} mounts the docker socket"
        assert not definition.get("privileged"), f"{name} is privileged"


def test_grafana_and_the_receiver_answer_the_laptop():
    assert GRAFANA_PORT in published_ports(LGTM_SERVICE)
    assert RECEIVER_PORT in published_ports(DEMO_SERVICE)


def started_by_default() -> list[str]:
    """The services a plain `docker compose up` starts: every one without a profile."""
    return [
        name for name, definition in COMPOSE["services"].items() if not definition.get("profiles")
    ]


def test_grafana_and_the_receiver_are_all_that_is_published():
    """OTLP stays on the compose network, where rolldice exports to it (audit F11)."""
    published = {(name, port) for name in started_by_default() for port in published_ports(name)}

    assert published == {(LGTM_SERVICE, GRAFANA_PORT), (DEMO_SERVICE, RECEIVER_PORT)}


def test_the_fake_jira_is_under_a_profile_and_publishes_one_port_under_one_name():
    """A plain `docker compose up` never starts the fake, and the demo service is not
    changed for it: the only way anything reaches it is a `.env` whose JIRA_SITE_URL names
    `http://fakejira:8090`, which the container resolves on the network and the laptop
    through /etc/hosts, so the port must be the same on both sides."""
    fake = service(FAKE_JIRA_SERVICE)

    assert fake["profiles"] == [FAKE_JIRA_PROFILE]
    assert FAKE_JIRA_SERVICE not in started_by_default()
    assert publications(FAKE_JIRA_SERVICE) == {
        (DEFAULT_BIND_ADDRESS, FAKE_JIRA_PORT, FAKE_JIRA_PORT)
    }
    assert publications(FAKE_JIRA_SERVICE, {"FAKE_JIRA_PORT": "18090"}) == {
        (DEFAULT_BIND_ADDRESS, 18090, 18090)
    }
    assert "--port" in fake["command"] and "--host" in fake["command"]
    assert fake["build"] == service(DEMO_SERVICE)["build"]
    assert fake["image"] == service(DEMO_SERVICE)["image"]
    assert "env_file" not in fake and "environment" not in fake
    assert "extra_hosts" not in service(DEMO_SERVICE)
    assert "restart" not in fake


def test_by_default_nothing_is_published_beyond_the_laptop_s_loopback():
    """Grafana has anonymous Admin and a POST to the Receiver starts a paid Run that writes to
    Jira; on 0.0.0.0 both were anyone's on the office Wi-Fi (audit F11)."""
    for name in COMPOSE["services"]:
        for address, laptop, container in publications(name):
            assert address == DEFAULT_BIND_ADDRESS == "127.0.0.1", f"{name} is on {address!r}"
            assert laptop == container, f"{name} moved {container} to {laptop} by default"


def test_the_presenter_moves_the_laptop_side_and_never_the_container_side():
    """A taken 3000 or 8080 is fixed in the environment; the contact point still names
    `demo:8080` and the healthcheck still asks the container's own 8080 (audit F22)."""
    moved = {
        BIND_ADDRESS_VARIABLE: "192.0.2.10",
        GRAFANA_HOST_PORT_VARIABLE: "13000",
        RECEIVER_HOST_PORT_VARIABLE: "18080",
    }

    assert publications(LGTM_SERVICE, moved) == {("192.0.2.10", 13000, GRAFANA_PORT)}
    assert publications(DEMO_SERVICE, moved) == {("192.0.2.10", 18080, RECEIVER_PORT)}
    contact_point = yaml.safe_load((PROVISIONING / "contact-point.yaml").read_text())
    [receiver] = contact_point["contactPoints"][0]["receivers"]
    assert receiver["settings"]["url"] == f"http://{DEMO_SERVICE}:{RECEIVER_PORT}/notification"


@pytest.mark.parametrize(
    "environment",
    [{}, {RECEIVER_HOST_PORT_VARIABLE: "18080"}, {BIND_ADDRESS_VARIABLE: "192.0.2.10"}],
    ids=["default", "moved-port", "moved-address"],
)
def test_the_replay_script_posts_where_compose_publishes_the_receiver(environment):
    [(address, laptop, _)] = publications(DEMO_SERVICE, environment)

    assert default_receiver(environment) == f"http://{address}:{laptop}"


def test_the_receiver_listens_where_the_published_port_leads():
    """The port compose publishes is the port the process is told to bind."""
    settings = Settings.from_environment(
        {**env_example(), PROJECT_KEY_VARIABLE: "SANDBOX", API_KEY_VARIABLE: "test-only-api-key"}
    )

    assert settings.port == RECEIVER_PORT
    assert PORT_VARIABLE not in service(DEMO_SERVICE).get("environment", {})


def test_every_service_shares_the_one_network():
    """The contact point names `demo`, traffic names `rolldice`, rolldice names `lgtm`."""
    networks = COMPOSE["networks"]
    assert len(networks) == 1

    only = next(iter(networks))
    for name, definition in COMPOSE["services"].items():
        assert _as_list(definition.get("networks", [])) == [only], f"{name} is off the network"


def test_grafana_reads_its_alerting_provisioning_from_this_repo():
    """Story 53: `grafana/docker-otel-lgtm` is a reference; this repo mounts its own files over the sample."""
    mounts = [str(volume).split(":") for volume in service(LGTM_SERVICE).get("volumes", [])]
    alerting = [parts for parts in mounts if parts[1] == GRAFANA_ALERTING_PROVISIONING]

    assert len(alerting) == 1, f"{LGTM_SERVICE} mounts {mounts}"
    source, _, *options = alerting[0]
    assert (REPOSITORY / source).resolve() == PROVISIONING
    assert options == ["ro"], "Grafana reads the files; it does not get to change them"
    assert {path.name for path in PROVISIONING.glob("*.yaml")} == {
        "contact-point.yaml",
        "notification-policy.yaml",
        "alert-rule.yaml",
    }


def test_stopped_traffic_stays_stopped():
    """The presenter's one action is `docker compose stop traffic`; nothing may undo it."""
    assert "restart" not in service(TRAFFIC_SERVICE)


def test_the_container_ends_as_a_user_who_is_not_root():
    """Read off the Dockerfile, so the default run says it even with no stack up.

    `TestAStackThatIsUp` asks the running container the same question properly.
    """
    assert run_user() != "root"


def test_the_image_is_built_holding_no_credential():
    """No credential variable is so much as named in the build, let alone given a value."""
    for line in DOCKERFILE.read_text().splitlines():
        for variable in CREDENTIALS:
            assert variable not in line, f"{variable} is named in the Dockerfile"


@needs_the_stack_up
class TestAStackThatIsUp:
    """With `docker compose up -d` already done, the two things the demo depends on."""

    def test_the_health_endpoint_answers_the_laptop(self):
        assert _get(f"{default_receiver()}/health") == 200

    def test_the_health_endpoint_answers_from_inside_the_network(self):
        """What Grafana's contact point will do, from the container that will do it."""
        answered = compose(
            "exec",
            "-T",
            LGTM_SERVICE,
            "curl",
            "-fsS",
            f"http://{DEMO_SERVICE}:{RECEIVER_PORT}/health",
        )

        assert answered.returncode == 0, answered.stderr

    def test_the_healthcheck_itself_passes_and_holds_no_environment(self):
        """The compose healthcheck's own command, run the way Docker runs it, and the same
        probe asked what environment it holds."""
        check = service(DEMO_SERVICE)["healthcheck"]["test"]
        passed = compose("exec", "-T", DEMO_SERVICE, *check[1:])
        environ = compose(
            "exec",
            "-T",
            DEMO_SERVICE,
            *HEALTHCHECK_PROBE,
            "-c",
            "import sys; sys.stdout.write(repr(open('/proc/self/environ', 'rb').read()))",
        )

        assert passed.returncode == 0, passed.stderr
        assert environ.returncode == 0, environ.stderr
        assert environ.stdout == "b''", "the probe was handed an environment"

    def test_the_receiver_runs_as_a_user_who_is_not_root(self):
        who = compose("exec", "-T", DEMO_SERVICE, "id", "-u")

        assert who.stdout.strip() != "0"

    @pytest.mark.parametrize("path", ["/proc/1/environ", "/proc/1/task/1/environ"])
    def test_no_run_can_read_the_receiver_s_environment(self, path):
        """The Receiver, PID 1, holds the real Jira token in its environment and is
        non-dumpable, so its /proc is root's; `exec` runs as the Run user, with no capability."""
        read = compose("exec", "-T", DEMO_SERVICE, "cat", path)

        assert read.returncode != 0, "the Receiver's environment is readable by the Run user"
        assert "Permission denied" in read.stderr
        assert not read.stdout

    def test_the_run_s_skill_is_rendered_for_the_configured_project(self):
        """What a Run reads, rendered from .env at this start (step 03 of demo-onboarding)."""
        key = compose("exec", "-T", DEMO_SERVICE, "printenv", PROJECT_KEY_VARIABLE).stdout.strip()
        skill = rendered_skill_directory(runs_directory()) / SKILL_FILE
        read = compose("exec", "-T", DEMO_SERVICE, "cat", str(skill))

        assert read.returncode == 0, read.stderr
        assert f"project = {key} AND issuetype = Incident" in read.stdout
        assert "{{" not in read.stdout

    def test_a_run_would_find_the_tools_it_is_allowed_to_use(self):
        for tool in ("claude", "jira-as", "incident-payload", "grafana-query"):
            found = compose("exec", "-T", DEMO_SERVICE, "sh", "-c", f"command -v {tool}")
            assert found.returncode == 0, f"{tool} is not on the Run's PATH"

    def test_the_installed_grafana_query_can_load_its_module(self):
        helped = compose("exec", "-T", DEMO_SERVICE, "grafana-query", "--help")

        assert helped.returncode == 0, helped.stderr
        assert helped.stdout.startswith("usage: grafana-query")


def _as_list(value) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def _get(url: str) -> int:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status


# --- The image carries only what a Run needs (ticket 01 of hardened-demo-image) ---


def dockerfile_instructions(dockerfile: Path = DOCKERFILE) -> list[str]:
    """A Dockerfile's instructions, continuation lines joined and comments dropped."""
    instructions: list[str] = []
    for raw in dockerfile.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if instructions and instructions[-1].endswith("\\"):
            instructions[-1] = instructions[-1][:-1] + " " + line
        else:
            instructions.append(line)
    return instructions


def build_argument_default(name: str, dockerfile: Path = DOCKERFILE) -> str:
    """What `ARG <name>=<default>` in a Dockerfile falls back to when compose passes nothing."""
    for instruction in dockerfile_instructions(dockerfile):
        if instruction.startswith(f"ARG {name}="):
            return instruction.partition("=")[2].strip()
    raise AssertionError(f"{dockerfile.name} declares no ARG {name}")


def test_the_image_is_built_from_the_slim_official_node_image_at_a_pinned_tag():
    """A build on another laptop must produce the image that was rehearsed (story 24)."""
    base = build_argument_default("BASE_IMAGE")
    repository, _, tag = base.partition(":")

    assert repository == "node", f"the base is {base}, not the official Node image"
    assert re.fullmatch(r"\d+\.\d+\.\d+-\w+-slim", tag), f"{tag} is not a pinned slim tag"
    assert "FROM ${BASE_IMAGE}" in dockerfile_instructions(), "the build argument is not used"


ESCALATION_TOOLS = ("sudo", "docker", "docker.io", "docker-ce", "gh", "git", "curl", "jq")
"""What the old base image carried and a Run must not find (stories 9 and 14)."""

PACKAGES_A_RUN_NEEDS = {"ca-certificates", "python3", "python3-venv"}
"""Everything the distribution may add to the base image: TLS roots, and a Python to run
the Receiver and hold jira-as."""


def run_instructions(dockerfile: Path = DOCKERFILE) -> list[str]:
    return [line for line in dockerfile_instructions(dockerfile) if line.startswith("RUN ")]


def run_commands(dockerfile: Path = DOCKERFILE) -> list[list[str]]:
    """Every shell command the RUN instructions chain, each as its words."""
    return [
        command.split()
        for instruction in run_instructions(dockerfile)
        for command in re.split(r"&&|;", instruction[len("RUN ") :])
    ]


def apt_packages() -> set[str]:
    """Every package name an `apt-get install` in the Dockerfile asks for."""
    packages: set[str] = set()
    for words in run_commands():
        if words[:2] == ["apt-get", "install"]:
            packages |= {word for word in words[2:] if not word.startswith("-")}
    return packages


def run_user() -> str:
    """The account the Dockerfile's last USER names: the Receiver's, and so every Run's."""
    users = [
        line.split(maxsplit=1)[1] for line in dockerfile_instructions() if line.startswith("USER ")
    ]
    assert users, "the Dockerfile never switches user"
    return users[-1]


def useradd_arguments() -> list[str]:
    """What the Dockerfile's useradd was given for the user the container ends as."""
    for words in run_commands():
        if words[:1] == ["useradd"] and words[-1] == run_user():
            return words[1:]
    raise AssertionError(f"{run_user()} is not created by a useradd in the Dockerfile")


def test_no_line_of_the_build_installs_an_escalation_tool():
    """The default run says it with no stack up; `TestAStackThatIsUp` asks the container."""
    for instruction in run_instructions():
        words = set(re.split(r"[\s=\"']+", instruction))
        assert not words & set(ESCALATION_TOOLS), f"an escalation tool is installed: {instruction}"


def test_the_distribution_adds_nothing_but_tls_roots_and_a_python():
    assert apt_packages() <= PACKAGES_A_RUN_NEEDS, f"{apt_packages() - PACKAGES_A_RUN_NEEDS} too"


def test_claude_code_and_jira_as_are_pinned():
    """A rebuild on demo day must not ship a Transcript shape nothing has ever seen."""
    for argument in ("CLAUDE_CODE_VERSION", "JIRA_AS_VERSION"):
        assert re.fullmatch(r"\d+\.\d+\.\d+", build_argument_default(argument)), argument


def test_the_user_the_container_ends_as_was_created_by_this_dockerfile():
    """Not inherited from a base image whose groups and sudoers nobody here wrote (story 14)."""
    assert run_user() in useradd_arguments()


INCIDENT_PAYLOAD_LAUNCHER = REPOSITORY / "docker" / "incident-payload"
"""The local payload command, as the image puts it on the PATH (ADR 0003's
2026-10-01 amendment)."""


def test_incident_payload_is_on_the_path_beside_jira_as():
    """A launcher for the package's own module, which the image copies to /app."""
    assert (
        "COPY --chmod=0755 docker/incident-payload /usr/local/bin/incident-payload"
        in dockerfile_instructions()
    ), "the image sets the mode itself, so a checkout that lost the executable bit still works"
    assert INCIDENT_PAYLOAD_LAUNCHER.read_text().splitlines()[0] == "#!/usr/bin/python3 -I"


def test_the_launcher_runs_the_package_s_incident_payload_in_isolated_mode(tmp_path):
    """Run as the image runs it, with this checkout standing where the image has /app."""
    launcher = INCIDENT_PAYLOAD_LAUNCHER.read_text()
    assert 'sys.path.insert(0, "/app")' in launcher
    script = tmp_path / "incident-payload"
    script.write_text(launcher.replace('"/app"', repr(str(REPOSITORY))))

    ran = subprocess.run(
        [sys.executable, "-I", str(script), "--help"],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert ran.returncode == 0, ran.stderr
    assert ran.stdout.startswith("usage: incident-payload")


GRAFANA_QUERY_LAUNCHER = REPOSITORY / "docker" / "grafana-query"
INVESTIGATION_VARIABLES = (
    "DEMO_INVESTIGATION_ENABLED",
    "DEMO_GRAFANA_URL",
    "DEMO_GRAFANA_PRESENTER_URL",
    "DEMO_GRAFANA_VIEWER_TOKEN",
)


def test_grafana_query_is_installed_in_isolated_mode_beside_incident_payload():
    assert (
        "COPY --chmod=0755 docker/grafana-query /usr/local/bin/grafana-query"
        in dockerfile_instructions()
    )
    launcher = GRAFANA_QUERY_LAUNCHER.read_text()
    assert launcher.splitlines()[0] == "#!/usr/bin/python3 -I"
    assert 'sys.path.insert(0, "/app")' in launcher
    assert "from grafana_jsm_sandbox.grafana_query import main" in launcher
    assert "raise SystemExit(main())" in launcher


def test_the_grafana_launcher_runs_the_query_cli_from_the_image_package(tmp_path):
    """Needs lane A's module; a missing dependency is not an installed-command pass."""
    launcher = GRAFANA_QUERY_LAUNCHER.read_text()
    if not (REPOSITORY / "grafana_jsm_sandbox" / "grafana_query.py").is_file():
        pytest.skip("lane A's grafana_query module has not been composed into this worktree")
    script = tmp_path / "grafana-query"
    script.write_text(launcher.replace('"/app"', repr(str(REPOSITORY))))
    ran = subprocess.run(
        [sys.executable, "-I", str(script), "--help"],
        cwd=tmp_path,
        env={},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert ran.returncode == 0, ran.stderr
    assert ran.stdout.startswith("usage: grafana-query")
    assert all(command in ran.stdout for command in ("instant", "range", "get"))


def test_the_image_defaults_to_internal_grafana_without_enabling_investigation():
    variables = environment_set_by(DOCKERFILE)
    assert variables["DEMO_GRAFANA_URL"][1] == "http://lgtm:3000"
    assert "DEMO_INVESTIGATION_ENABLED" not in variables
    assert "DEMO_GRAFANA_VIEWER_TOKEN" not in variables
    assert "DEMO_GRAFANA_PRESENTER_URL" not in variables


@pytest.mark.parametrize("port", [None, "", "13000"])
def test_compose_hands_the_resolved_grafana_port_to_the_receiver(port):
    environment = {} if port is None else {GRAFANA_HOST_PORT_VARIABLE: port}
    declared = service(DEMO_SERVICE)["environment"][GRAFANA_HOST_PORT_VARIABLE]
    assert declared == "${GRAFANA_HOST_PORT:-3000}"
    resolved = int(interpolated(declared, environment))
    [(_, published, _)] = publications(LGTM_SERVICE, environment)
    assert resolved == published


def test_the_example_leaves_all_four_investigation_variables_commented_and_token_empty():
    example = ENV_EXAMPLE.read_text()
    assert not set(INVESTIGATION_VARIABLES) & env_example().keys()
    for variable in INVESTIGATION_VARIABLES:
        assert re.search(rf"^# {variable}=.*$", example, re.MULTILINE)
    assert "# DEMO_INVESTIGATION_ENABLED=false\n" in example
    assert "# DEMO_GRAFANA_URL=http://lgtm:3000\n" in example
    assert "# DEMO_GRAFANA_VIEWER_TOKEN=\n" in example


ENTRYPOINT = REPOSITORY / "docker" / "entrypoint.sh"
"""What the container starts: onboarding pre-accepted, then the command it was given."""

TOOLS_THE_IMAGE_CARRIES = ("sh", "mkdir", "chmod", "python3")
"""All the entrypoint may call. The slim image has no jq (story 21), so the test's PATH has none."""

ONBOARDING_FLAG = "hasCompletedOnboarding"


def start_container_with(tmp_path, *command: str, existing: dict | None = None) -> tuple:
    """Run the real entrypoint as the container would, on a PATH of only what the image carries.

    Returns the pre-accepted onboarding file's contents and the command's output.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in TOOLS_THE_IMAGE_CARRIES:
        found = shutil.which(tool)
        assert found, f"{tool} is not on this machine"
        (bin_dir / tool).symlink_to(found)
    config_dir = tmp_path / "claude"
    if existing is not None:
        config_dir.mkdir()
        (config_dir / ".claude.json").write_text(json.dumps(existing))

    started = subprocess.run(
        ["sh", str(ENTRYPOINT), *command],
        env={"PATH": str(bin_dir), "CLAUDE_CONFIG_DIR": str(config_dir), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert started.returncode == 0, started.stderr
    onboarding = config_dir / ".claude.json"
    assert oct(onboarding.stat().st_mode)[-3:] == "600"
    return json.loads(onboarding.read_text()), started.stdout


def test_the_entrypoint_pre_accepts_onboarding_and_becomes_the_command_it_was_given(tmp_path):
    """A fresh container: no config yet, and the one flag headless Claude needs is written."""
    onboarding, output = start_container_with(tmp_path, "sh", "-c", "echo became the command")

    assert onboarding == {ONBOARDING_FLAG: True}
    assert output.strip() == "became the command"


def test_the_entrypoint_keeps_whatever_claude_code_already_wrote(tmp_path):
    """A restart: Claude Code's own configuration is there, and only the flag is added to it."""
    onboarding, _ = start_container_with(
        tmp_path, "sh", "-c", "true", existing={"numStartups": 3, ONBOARDING_FLAG: False}
    )

    assert onboarding == {"numStartups": 3, ONBOARDING_FLAG: True}


HEALTHCHECK_PROBE = ("env", "-i", "/usr/bin/python3")
"""How the healthcheck starts: `env -i` with no environment, then Python by its full path,
since nothing is left to search a PATH with. Both are in the image: `command -v env python3`
in a throwaway container of it answers `/usr/bin/env` and `/usr/bin/python3` (step 06)."""


def test_the_healthcheck_needs_nothing_the_image_does_not_carry():
    """Compose must report the container healthy for the right reason (story 21): the slim
    image has no curl, so the check is Python's standard library asking the health endpoint."""
    check = service(DEMO_SERVICE)["healthcheck"]["test"]

    assert check[0] == "CMD"
    assert Path(check[3]).name in TOOLS_THE_IMAGE_CARRIES, f"{check[3]} is not in the image"
    assert "curl" not in " ".join(check)
    assert f"http://localhost:{RECEIVER_PORT}/health" in " ".join(check)


def test_the_healthcheck_starts_with_an_empty_environment():
    """Docker hands every process it execs into the container the whole container
    environment, the real Jira token included, as the Runs' uid and dumpable; the
    healthcheck is one every ten seconds. Through `env -i`, its Python holds nothing
    in /proc/<pid>/environ (ADR 0002's amendment)."""
    check = service(DEMO_SERVICE)["healthcheck"]["test"]

    assert tuple(check[1:4]) == HEALTHCHECK_PROBE
    assert check[4] == "-c"
    assert len(check) == 6, "the probe is one Python statement and nothing after it"


# --- The images compose pulls are pinned (step 06 of demo-onboarding) ---


def pulled_images(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Every service's image that compose pulls rather than builds, as compose resolves it.

    A service with `build:` names the image it builds on this laptop, and its tag is
    only that local name: nothing is pulled by it."""
    return {
        name: interpolated(definition["image"], environment or {})
        for name, definition in COMPOSE["services"].items()
        if "build" not in definition
    }


def test_the_grafana_stack_is_pinned_by_tag_and_index_digest():
    """`latest` moved weekly, and with the rule's noDataState at OK a drifted metric would
    leave the Alert silently never firing (audit F12)."""
    assert pulled_images()[LGTM_SERVICE] == f"{LGTM_REPOSITORY}:{LGTM_TAG}@{LGTM_INDEX_DIGEST}"


def test_a_mirror_can_stand_in_for_the_pinned_grafana_stack():
    mirror = f"registry.example.invalid/{LGTM_REPOSITORY}:{LGTM_TAG}@{LGTM_INDEX_DIGEST}"

    assert pulled_images({LGTM_IMAGE_VARIABLE: mirror})[LGTM_SERVICE] == mirror
    assert LGTM_IMAGE_VARIABLE in ENV_EXAMPLE.read_text()


@pytest.mark.parametrize("name", sorted(pulled_images()))
def test_no_pulled_image_is_latest_or_untagged(name):
    """An untagged reference is `latest` by another name."""
    reference = pulled_images()[name]

    assert ":latest" not in reference
    matched = PINNED_REFERENCE.fullmatch(reference)
    assert matched, f"{name} pulls {reference!r}, which names no tag"
    assert matched["tag"] != "latest"


def test_no_pulled_image_anywhere_in_the_compose_file_is_latest():
    """Read as text too, so an image added under a new key is not missed by the parse."""
    for line in COMPOSE_FILE.read_text().splitlines():
        if line.strip().startswith("image:") and ":latest" in line:
            image = line.split("image:", 1)[1].strip()
            assert any(
                definition.get("image") == image and "build" in definition
                for definition in COMPOSE["services"].values()
            ), f"{image} is pulled as latest"


# The image, asked directly (opt-in, like the rest of TestAStackThatIsUp).

NODE_READS_THE_OS_TRUST_STORE = (22, 15)
"""The first Node on which Claude Code reads the operating system trust store."""


@needs_the_stack_up
class TestTheImageCarriesOnlyWhatARunNeeds:
    """With `docker compose up -d` done, the claims the default run reads off the Dockerfile."""

    @pytest.mark.parametrize("tool", ESCALATION_TOOLS)
    def test_no_escalation_tool_is_on_a_runs_path(self, tool):
        found = compose("exec", "-T", DEMO_SERVICE, "sh", "-c", f"command -v {tool}")

        assert found.returncode != 0, f"{tool} is in the container at {found.stdout.strip()}"

    def test_there_is_no_docker_group_to_be_in(self):
        group = compose("exec", "-T", DEMO_SERVICE, "getent", "group", "docker")

        assert group.returncode != 0, group.stdout

    def test_node_is_new_enough_to_read_the_os_trust_store(self):
        version = compose("exec", "-T", DEMO_SERVICE, "node", "--version").stdout.strip()

        assert (
            tuple(int(part) for part in version.lstrip("v").split("."))
            >= NODE_READS_THE_OS_TRUST_STORE
        ), version


# --- A corporate CA is trusted through the build and every Run (ticket 02) ---

ROLLDICE_DOCKERFILE = REPOSITORY / "docker" / "rolldice" / "Dockerfile"
"""The other image this repo builds. Its build reaches PyPI through the same proxy."""

BOTH_DOCKERFILES = (DOCKERFILE, ROLLDICE_DOCKERFILE)

ROLLDICE_SERVICE = "rolldice"

EXTRA_CA_ARGUMENT = "EXTRA_CA_CERT"
"""The build argument naming a PEM file in the build context; the presenter's shell sets it."""

CERTIFICATES_DIRECTORY = "certs"
"""Where the presenter puts the corporate CA. Git takes nothing from it but the placeholder."""

PLACEHOLDER = f"{CERTIFICATES_DIRECTORY}/NO_EXTRA_CERTS"
"""The committed, intentionally empty file the argument defaults to (story 8)."""

SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
"""Where update-ca-certificates writes, and so where every trust-store variable points."""

INSTALLED_CERTIFICATES = "/usr/local/share/ca-certificates"
"""Where a certificate must be put for update-ca-certificates to add it to the bundle.
Empty after a build with the placeholder."""

PACKAGE_INSTALLS = ("npm install", "pip install", "opentelemetry-bootstrap")
"""Every command in either build that reaches a registry over TLS (story 16)."""


def instruction_index(dockerfile: Path, *fragments: str) -> int:
    """Where the first instruction holding every fragment is, in build order."""
    for index, instruction in enumerate(dockerfile_instructions(dockerfile)):
        if all(fragment in instruction for fragment in fragments):
            return index
    raise AssertionError(f"{dockerfile.name} has no instruction holding {fragments}")


def environment_set_by(dockerfile: Path) -> dict[str, tuple[int, str]]:
    """Every `ENV name=value` in a Dockerfile: the variable, where it is set, and its value."""
    variables: dict[str, tuple[int, str]] = {}
    for index, instruction in enumerate(dockerfile_instructions(dockerfile)):
        if instruction.startswith("ENV "):
            for pair in instruction[len("ENV ") :].split():
                name, _, value = pair.partition("=")
                variables[name] = (index, value)
    return variables


def package_install_indexes(dockerfile: Path) -> list[int]:
    return [
        index
        for index, instruction in enumerate(dockerfile_instructions(dockerfile))
        if instruction.startswith("RUN ") and any(c in instruction for c in PACKAGE_INSTALLS)
    ]


@pytest.mark.parametrize("dockerfile", BOTH_DOCKERFILES, ids=lambda path: path.parent.name)
def test_both_builds_take_a_corporate_ca_and_default_to_the_committed_placeholder(dockerfile):
    """A build with no certificate named behaves exactly as before (story 8)."""
    assert build_argument_default(EXTRA_CA_ARGUMENT, dockerfile) == PLACEHOLDER
    assert f"COPY ${{{EXTRA_CA_ARGUMENT}}} " in " ".join(dockerfile_instructions(dockerfile))


def test_the_placeholder_is_committed_and_intentionally_empty():
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", PLACEHOLDER], cwd=REPOSITORY, check=False
    )

    assert tracked.returncode == 0, f"{PLACEHOLDER} is not in git"
    assert (REPOSITORY / PLACEHOLDER).stat().st_size == 0


@pytest.mark.parametrize("dockerfile", BOTH_DOCKERFILES, ids=lambda path: path.parent.name)
def test_the_certificate_is_trusted_before_anything_reaches_npm_or_pypi(dockerfile):
    """The build itself must work behind the intercepting proxy, not only the runtime (story 16)."""
    copied = instruction_index(dockerfile, "COPY", f"${{{EXTRA_CA_ARGUMENT}}}")
    installed = instruction_index(dockerfile, "RUN", "update-ca-certificates")
    installs = package_install_indexes(dockerfile)

    assert installs, f"{dockerfile.name} installs nothing over TLS; the check reads nothing"
    assert copied < installed < min(installs), dockerfile_instructions(dockerfile)


def test_the_demo_image_points_every_tls_client_at_the_system_bundle():
    """Set once, image-wide, before the installs that need them (story 17): Python's ssl
    module and the Forwarder's urllib, jira-as's requests, pip, and Claude Code."""
    variables = environment_set_by(DOCKERFILE)

    for name in TRUST_STORE_VARIABLES:
        assert name in variables, f"{name} is not set in the Dockerfile"
        index, value = variables[name]
        assert value == SYSTEM_BUNDLE, f"{name} is {value}"
        assert index < min(package_install_indexes(DOCKERFILE)), f"{name} is set after an install"


def test_the_rolldice_build_points_pip_at_the_system_bundle():
    """Its build's only TLS clients are pip and the bootstrap that runs pip."""
    index, value = environment_set_by(ROLLDICE_DOCKERFILE)["PIP_CERT"]

    assert value == SYSTEM_BUNDLE
    assert index < min(package_install_indexes(ROLLDICE_DOCKERFILE))


@pytest.mark.parametrize("name", (DEMO_SERVICE, ROLLDICE_SERVICE))
def test_compose_hands_the_presenters_certificate_to_both_builds(name):
    """From the shell, with the placeholder as the default, so the build command is the same
    on both laptops; and from the repo root, so the same path means the same file in both."""
    build = service(name)["build"]

    assert build["args"][EXTRA_CA_ARGUMENT] == f"${{{EXTRA_CA_ARGUMENT}:-{PLACEHOLDER}}}"
    assert (REPOSITORY / build["context"]).resolve() == REPOSITORY


def test_git_never_takes_a_certificate_but_does_take_the_placeholder():
    """A corporate artifact must not end up in a public repository (story 6)."""
    assert git_ignores(f"{CERTIFICATES_DIRECTORY}/corporate-root.crt")
    assert git_ignores(f"{CERTIFICATES_DIRECTORY}/anything-else-at-all")
    assert not git_ignores(PLACEHOLDER)


def test_the_build_context_admits_the_certificate_directory():
    for pattern in DOCKER_IGNORE.read_text().split():
        assert not pattern.lstrip("/").startswith(CERTIFICATES_DIRECTORY), pattern


# The trust store, asked directly (opt-in, like the rest of TestAStackThatIsUp).

READ_THE_TRUST_STORE = f"""\
import hashlib, json, os, re, ssl
pem = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
def fingerprints(text):
    return sorted(hashlib.sha256(ssl.PEM_cert_to_DER_cert(c)).hexdigest() for c in pem.findall(text))
print(json.dumps({{
    "environment": {{name: os.environ.get(name) for name in {TRUST_STORE_VARIABLES!r}}},
    "bundle": fingerprints(open(os.environ["SSL_CERT_FILE"]).read()),
    "loaded": sorted(hashlib.sha256(der).hexdigest()
                     for der in ssl.create_default_context().get_ca_certs(binary_form=True)),
    "installed": sorted(os.listdir({INSTALLED_CERTIFICATES!r})),
}}))
"""
"""What the running container says about its trust store: the variables, the SHA-256
fingerprints in the bundle they name, the ones Python's default SSL context really loaded
from it, and whatever the build put where update-ca-certificates reads extras from."""


def named_certificate() -> Path | None:
    """The certificate the presenter's shell names for the build, or None for the placeholder.

    The same variable compose reads, so the check and the build cannot disagree.
    """
    named = os.environ.get(EXTRA_CA_ARGUMENT, "") or PLACEHOLDER
    return None if named == PLACEHOLDER else REPOSITORY / named


def fingerprints_of(certificate: Path) -> set[str]:
    """SHA-256 over the DER form of every certificate in a PEM file, as `openssl x509
    -fingerprint -sha256` would print them, without the colons."""
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        certificate.read_text(),
        re.DOTALL,
    )
    return {hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest() for block in blocks}


@pytest.fixture(scope="module")
def trust_store() -> dict:
    """The running container's answer, read once for the class below."""
    read = compose("exec", "-T", DEMO_SERVICE, "python3", "-c", READ_THE_TRUST_STORE)
    assert read.returncode == 0, read.stderr
    return json.loads(read.stdout)


@needs_the_stack_up
class TestTheTrustStoreOfAStackThatIsUp:
    """With `docker compose up -d` done: what the build put in the bundle, and whether the
    Python every Jira call and the healthcheck run on loads it (story 23)."""

    def test_every_tls_client_in_the_container_is_pointed_at_the_bundle(self, trust_store):
        assert trust_store["environment"] == dict.fromkeys(TRUST_STORE_VARIABLES, SYSTEM_BUNDLE)

    def test_python_loads_the_whole_bundle_the_variables_name(self, trust_store):
        assert trust_store["bundle"], "the bundle is empty"
        assert trust_store["loaded"] == trust_store["bundle"]

    def test_the_named_certificate_is_in_the_bundle_and_python_loads_it(self, trust_store):
        certificate = named_certificate()
        if certificate is None:
            pytest.skip(f"{EXTRA_CA_ARGUMENT} names no certificate; the placeholder was built")

        expected = fingerprints_of(certificate)
        assert expected, f"{certificate} holds no PEM certificate"
        assert expected <= set(trust_store["bundle"]), "the build did not install it"
        assert expected <= set(trust_store["loaded"]), "Python's default context did not load it"
        assert trust_store["installed"] == ["extra-ca.crt"]

    def test_a_build_with_the_placeholder_added_nothing(self, trust_store):
        if named_certificate() is not None:
            pytest.skip(f"{EXTRA_CA_ARGUMENT} names a certificate; it should be in the bundle")

        assert trust_store["installed"] == []


# --- The demo container runs the way Anthropic's deployment guide describes (ticket 03) ---

TEMP_DIRECTORY = "/tmp"
"""Where Claude Code keeps a Run's sockets and task files, and Python its temporary files."""

NO_NEW_PRIVILEGES = "no-new-privileges:true"
"""The security option under which no process in the container gains a privilege at exec."""

CAPABILITY_SETS = ("CapInh", "CapPrm", "CapEff", "CapBnd")
"""Four of the five masks /proc/self/status prints (the ambient set is empty whenever the
permitted set is); the bounding set is the one nothing can grow back."""

NO_CAPABILITIES = "0000000000000000"
"""An empty capability mask, as /proc/self/status prints one."""

APPLICATION_DIRECTORY = "/app"
"""The Run user's own directory in the image. Only a read-only root can refuse it a write."""


def run_user_id() -> int:
    """The uid the Dockerfile gives the account, which the tmpfs the user owns must name too."""
    arguments = useradd_arguments()
    return int(arguments[arguments.index("--uid") + 1])


def run_user_home() -> str:
    """HOME for the Receiver and, through the account, for a Run that is handed no HOME: the
    entrypoint writes the onboarding flag there, Claude Code its configuration and Transcripts."""
    arguments = useradd_arguments()
    assert "--create-home" in arguments, "the home is not made by useradd"
    assert not {"--home-dir", "-d"} & set(arguments), "the home is not useradd's default"
    return f"/home/{run_user()}"


def runs_directory() -> str:
    """The parent of every Run's working directory, as the image tells the Receiver."""
    return environment_set_by(DOCKERFILE)[RUNS_DIRECTORY_VARIABLE][1]


def scratch_directories() -> tuple[str, str, str]:
    """Everything a container writes across three Runs, as `docker diff` lists it (story 19)."""
    return (TEMP_DIRECTORY, runs_directory(), run_user_home())


def tmpfs_mounts(name: str) -> dict[str, dict[str, str]]:
    """A service's tmpfs mounts: each path, with its mount options as a dict."""
    mounts: dict[str, dict[str, str]] = {}
    for entry in _as_list(service(name).get("tmpfs", [])):
        path, _, options = str(entry).partition(":")
        mounts[path] = {}
        for option in filter(None, options.split(",")):
            key, _, value = option.partition("=")
            mounts[path][key] = value
    return mounts


def memory_in_bytes(limit) -> int:
    """A compose memory limit (`2g`, `512m`, `1024`) in bytes, binary multiples as compose reads it."""
    if isinstance(limit, int):
        return limit
    match = re.fullmatch(r"(\d+)([bkmg]?)b?", str(limit).lower())
    assert match, f"{limit!r} is not a memory limit"
    return int(match[1]) * 1024 ** "bkmg".index(match[2] or "b")


def test_the_demo_drops_every_capability():
    """The guide's first flag (story 10). The Receiver binds an unprivileged port and needs none."""
    assert _as_list(service(DEMO_SERVICE)["cap_drop"]) == ["ALL"]


def test_no_process_in_the_demo_gains_a_privilege_at_exec():
    assert NO_NEW_PRIVILEGES in _as_list(service(DEMO_SERVICE)["security_opt"])


def test_the_demo_s_root_filesystem_is_read_only():
    assert service(DEMO_SERVICE)["read_only"] is True


def test_exactly_the_three_scratch_directories_are_writable_and_none_outlives_the_container():
    """The temp directory, the runs directory and the Run user's home, on tmpfs and nowhere
    else (story 19). No volume either, so a restart starts clean."""
    assert set(tmpfs_mounts(DEMO_SERVICE)) == set(scratch_directories())
    assert "volumes" not in service(DEMO_SERVICE)


def test_the_run_s_skill_is_rendered_onto_a_tmpfs_from_a_template_on_the_read_only_root():
    """The template is baked into the image; what a Run reads is rendered from .env at every
    start into the runs directory, which no restart keeps (step 03 of demo-onboarding)."""
    mounts = [Path(mount) for mount in tmpfs_mounts(DEMO_SERVICE)]
    rendered = rendered_skill_directory(runs_directory())
    template = Path(environment_set_by(DOCKERFILE)[SKILL_DIRECTORY_VARIABLE][1])

    assert any(rendered.is_relative_to(mount) for mount in mounts)
    assert not any(template.is_relative_to(mount) for mount in mounts)


def test_the_runs_directory_and_the_home_belong_to_the_run_user():
    """A tmpfs is root's and world-writable unless told otherwise; these two are the user's own,
    with the uid the Dockerfile gave the account and the group `--user-group` made for it."""
    uid = str(run_user_id())
    for directory in (runs_directory(), run_user_home()):
        options = tmpfs_mounts(DEMO_SERVICE)[directory]
        assert options.get("uid") == uid, f"{directory} is not the user's: {options}"
        assert options.get("gid") == uid, f"{directory} is not the user's group's: {options}"
        assert options.get("mode") == "0700", f"{directory} is not private: {options}"


def test_every_scratch_directory_is_sized():
    """A tmpfs is memory; unsized, each may grow to half the machine's (story 20)."""
    for directory, options in tmpfs_mounts(DEMO_SERVICE).items():
        assert re.fullmatch(r"\d+[kmg]", options.get("size", "")), f"{directory} is unsized"


PEAK_TASKS_IN_A_LIFECYCLE = 24
"""The most tasks (processes and threads) the container's cgroup held at any sample across the
three Runs of the end-to-end check, run under the limits and sampled every 0.7s (ticket 03)."""

PEAK_MEMORY_IN_A_LIFECYCLE = 227 * 1024**2
"""The cgroup's peak memory across the same three Runs, as the kernel reported it."""


def test_a_runaway_run_is_bounded_in_processes_memory_and_cpu():
    """Sized for three Runs in a row on a laptop (story 20): the process and memory limits have
    headroom over the measured peak, the CPU limit is a share of the laptop rather than a peak,
    and `TestTheBoundaryOfAStackThatIsUp` reads what the kernel then enforces."""
    demo = service(DEMO_SERVICE)

    assert isinstance(demo["pids_limit"], int)
    assert demo["pids_limit"] >= 4 * PEAK_TASKS_IN_A_LIFECYCLE
    assert memory_in_bytes(demo["mem_limit"]) >= 4 * PEAK_MEMORY_IN_A_LIFECYCLE
    assert float(demo["cpus"]) > 0


# The kernel, asked directly (opt-in, like the rest of TestAStackThatIsUp).

PROBED_DIRECTORIES = (APPLICATION_DIRECTORY, *scratch_directories())
"""One the user owns on the root filesystem, and the three scratch directories."""

ASK_THE_KERNEL = f"""\
import json, os
def probe(directory):
    path = os.path.join(directory, "write-probe-%d" % os.getpid())
    try:
        open(path, "w").close()
        os.remove(path)
        return "accepted"
    except OSError as error:
        return error.strerror
def first(*paths):
    for path in paths:
        try:
            return open(path).read().strip()
        except OSError:
            continue
status = {{}}
for line in open("/proc/self/status"):
    name, separator, value = line.partition(":")
    if separator:
        status[name] = value.strip()
quota = first("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
period = first("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
print(json.dumps({{
    "capabilities": {{name: status[name] for name in {CAPABILITY_SETS!r}}},
    "no_new_privs": status.get("NoNewPrivs"),
    "writes": {{directory: probe(directory) for directory in {PROBED_DIRECTORIES!r}}},
    "pids_max": first("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"),
    "memory_max": first("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    "cpu_max": first("/sys/fs/cgroup/cpu.max") or (quota and period and quota + " " + period),
}}))
"""
"""What the running container's kernel says: the process's four capability masks, whether it can gain a privilege at exec, which directories accept a write, and the process,
memory and CPU limits its cgroup enforces (cgroup v2 first, v1 where that is what there is)."""

UNLIMITED = "max"
"""What cgroup v2 prints for a limit that is not set; v1 prints -1 or a number near 2**63."""


def enforced_processes(kernel: dict) -> int | None:
    """The cgroup's process limit, or None where there is none."""
    value = kernel["pids_max"]
    return None if value in (None, UNLIMITED) else int(value)


def enforced_memory(kernel: dict) -> int | None:
    """The cgroup's memory limit in bytes, or None where there is none."""
    value = kernel["memory_max"]
    return None if value in (None, UNLIMITED) or int(value) >= 2**62 else int(value)


def enforced_cpus(kernel: dict) -> float | None:
    """The cgroup's CPU limit as a count of CPUs, or None where there is none."""
    if not kernel["cpu_max"]:
        return None
    quota, period = kernel["cpu_max"].split()
    return None if quota == UNLIMITED or int(quota) < 0 else int(quota) / int(period)


def not_applied(control: str, enforced) -> str:
    """Why a declared limit is not the enforced one: this Compose is too old to have applied it.

    Compose 2.2 is the first to apply `pids_limit` and 2.17 the first to apply `cpus`; a
    current Docker Desktop applies both. Until then the runbook's pre-demo check names the
    `docker update` that applies them to the running container.
    """
    version = compose("version", "--short").stdout.strip()
    return f"{control} is declared but the kernel enforces {enforced!r}: Compose {version} did not apply it"


@pytest.fixture(scope="module")
def kernel() -> dict:
    """The running container's kernel's answer, read once for the class below."""
    asked = compose("exec", "-T", DEMO_SERVICE, "python3", "-c", ASK_THE_KERNEL)
    assert asked.returncode == 0, asked.stderr
    return json.loads(asked.stdout)


@needs_the_stack_up
class TestTheBoundaryOfAStackThatIsUp:
    """With `docker compose up -d` done: the controls the default run reads off the compose
    file, as the kernel of the machine giving the demo actually enforces them (story 23)."""

    def test_the_root_filesystem_refuses_a_write_even_where_the_user_owns_it(self, kernel):
        """/app is the Run user's own; only a read-only root can refuse it a write there."""
        assert kernel["writes"][APPLICATION_DIRECTORY] == "Read-only file system"

    @pytest.mark.parametrize("directory", scratch_directories())
    def test_each_scratch_directory_accepts_a_write(self, kernel, directory):
        assert kernel["writes"][directory] == "accepted"

    def test_no_capability_is_left_not_even_in_the_bounding_set(self, kernel):
        assert kernel["capabilities"] == dict.fromkeys(CAPABILITY_SETS, NO_CAPABILITIES)

    def test_no_process_can_gain_a_privilege_at_exec(self, kernel):
        assert kernel["no_new_privs"] == "1"

    def test_the_process_limit_is_the_one_compose_declares(self, kernel):
        declared = service(DEMO_SERVICE)["pids_limit"]

        assert enforced_processes(kernel) == declared, not_applied("pids_limit", kernel["pids_max"])

    def test_the_memory_limit_is_the_one_compose_declares(self, kernel):
        declared = memory_in_bytes(service(DEMO_SERVICE)["mem_limit"])

        assert enforced_memory(kernel) == declared, not_applied("mem_limit", kernel["memory_max"])

    def test_the_cpu_limit_is_the_one_compose_declares(self, kernel):
        declared = float(service(DEMO_SERVICE)["cpus"])

        assert enforced_cpus(kernel) == declared, not_applied("cpus", kernel["cpu_max"])
