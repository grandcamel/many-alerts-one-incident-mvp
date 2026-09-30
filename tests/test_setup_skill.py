"""The engineer's setup skill names only commands, flags, services and requests that exist.

`.claude/skills/demo-setup/` tells an agent on the engineer's laptop which commands to run,
in order, and which admin request to show when one names it. A flag renamed in a command, a
heading renamed in `docs/admin-requests.md`, or a service renamed in compose would leave the
agent running something that fails, or showing the engineer the top of a page, with no error
anywhere until an engineer met it. So the skill is read here the way the agent reads it.
"""

from __future__ import annotations

import functools
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from grafana_jsm_sandbox import doctor
from tests.test_docs import ADMIN_REQUESTS, REQUEST_PREFIXES, anchors, links, prose

REPOSITORY = Path(__file__).resolve().parent.parent
SKILL_DIRECTORY = REPOSITORY / ".claude" / "skills" / "demo-setup"
SKILL = SKILL_DIRECTORY / "SKILL.md"
DOCUMENTS = sorted(SKILL_DIRECTORY.glob("*.md"))
"""SKILL.md and the reference files beside it, all of which the agent may read."""

PACKAGE = "grafana_jsm_sandbox"

MODULE_COMMAND = re.compile(r"-m grafana_jsm_sandbox\.(\w+)([^`\n]*)")
"""A command as the skill spells it in full, `python3 -m grafana_jsm_sandbox.doctor --only
host`, and the rest of its line, where its flags are."""

SHORT_COMMAND = re.compile(r"`(configure|doctor|verify|reset)((?: --[a-z][a-z-]*)+)")
"""A command as prose names it, `configure --write` or `doctor --with-model`."""

FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z-]*)")

ONLY = re.compile(r"--only ([a-z]+(?:,[a-z]+)*)")

DOCUMENT_REFERENCE = re.compile(r"((?:docs/[\w/.-]+|README)\.md)#([\w-]+)")
"""A heading in a repo document, as the skill names it: `docs/admin-requests.md#docker-admin`."""

PREREQUISITES = {
    "jira-admin-create-project",
    "atlassian-org-admin-agent-licence",
    "atlassian-org-admin-api-tokens",
    "atlassian-org-admin-ip-allowlist",
    "claude-org-owner",
    "docker-admin",
    "network",
}
"""The requests the admin-prerequisites stage asks the engineer about, one per item. The
project's fields, screens, workflow and permissions are left to `configure` to find."""

REPOSITORY_PATH = re.compile(r"`((?:\.?[\w-]+/)+[\w.-]+\.(?:md|py|json|yml))`")

COMPOSE = re.compile(r"docker compose (logs|start|stop|restart|exec|up|ps)\b([^`\n]*)")

COMPOSE_VALUED_FLAGS = {"--tail", "--since", "-n"}
"""Flags of the compose verbs above that take a value, so the value is not read as a service."""

ALLOWED_ENV_COMMANDS = {"ls .env", "cp .env.example .env"}
"""The only commands of the skill's that name `.env`, which holds the engineer's real tokens:
one says whether it exists, the other makes it from the example."""

ENV_FILE = re.compile(r"(?<![\w./-])\.env(?![\w.])")


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def every_text() -> str:
    return "\n".join(text(document) for document in DOCUMENTS)


def bash_commands(path: Path) -> list[str]:
    """Every line of every fenced bash block: the commands the agent is told to run."""
    commands, fenced = [], False
    for line in text(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = stripped == "```bash" if not fenced else False
            continue
        if fenced and stripped:
            commands.append(stripped)
    return commands


def frontmatter() -> dict:
    opening, matter, _body = text(SKILL).split("---\n", 2)
    assert opening == "", "SKILL.md must open with its frontmatter"
    return yaml.safe_load(matter)


@functools.cache
def help_text(module: str) -> str:
    finished = subprocess.run(
        [sys.executable, "-m", f"{PACKAGE}.{module}", "--help"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, (module, finished.stderr)
    return finished.stdout


def named_commands() -> dict[str, set[str]]:
    """Each module the skill runs, with every flag it gives it anywhere."""
    named: dict[str, set[str]] = {}
    body = every_text()
    for module, rest in MODULE_COMMAND.findall(body):
        named.setdefault(module, set()).update(FLAG.findall(rest))
    for module, flags in SHORT_COMMAND.findall(body):
        named.setdefault(module, set()).update(FLAG.findall(flags))
    return named


def test_the_skill_and_its_references_are_there():
    assert SKILL.is_file()
    assert [path.name for path in DOCUMENTS] == ["READING-OUTPUT.md", "SKILL.md"]


def test_the_frontmatter_parses_and_the_name_is_the_directory_s():
    matter = frontmatter()

    assert set(matter) == {"name", "description"}
    assert matter["name"] == SKILL_DIRECTORY.name
    assert re.fullmatch(r"[a-z0-9-]{1,64}", matter["name"])
    assert isinstance(matter["description"], str)
    assert 0 < len(matter["description"]) <= 1024


def test_the_description_triggers_on_the_setup_and_sets_it_apart_from_the_run_s_skill():
    description = frontmatter()["description"].lower()

    for trigger in ("set up the demo", "run or rehearse the demo", "demo on my jira"):
        assert trigger in description, trigger
    assert "skill/incident-sync/skill.md" in description


def test_the_search_finds_the_commands_the_stages_run():
    """So the checks below cannot pass by finding nothing."""
    named = named_commands()

    assert {"doctor", "configure", "verify", "reset", "log_formatter"} <= set(named)
    assert {"--only", "--with-model"} <= named["doctor"]
    assert "--write" in named["configure"]
    assert {"--replay", "--live"} <= named["verify"]
    assert "--dry-run" in named["reset"]


@pytest.mark.parametrize("module", sorted(named_commands()))
def test_every_command_it_runs_is_a_module_of_the_package(module):
    assert importlib.util.find_spec(f"{PACKAGE}.{module}") is not None


@pytest.mark.parametrize(
    ("module", "flag"),
    sorted((module, flag) for module, flags in named_commands().items() for flag in flags),
)
def test_every_flag_it_gives_a_command_is_in_that_command_s_help(module, flag):
    assert re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text(module)), (module, flag)


def test_every_layer_it_names_to_doctor_exists():
    named = {layer for layers in ONLY.findall(every_text()) for layer in layers.split(",")}

    assert named
    assert named <= set(doctor.LAYERS), sorted(named - set(doctor.LAYERS))


def test_every_admin_request_it_names_is_a_heading_there():
    body = every_text()
    named = {
        anchor
        for path, anchor in DOCUMENT_REFERENCE.findall(body)
        if path == "docs/admin-requests.md"
    }
    named |= {
        bare for bare in re.findall(r"`([a-z0-9-]+)`", body) if bare.startswith(REQUEST_PREFIXES)
    }

    assert PREREQUISITES <= named, sorted(PREREQUISITES - named)
    assert named <= anchors(ADMIN_REQUESTS), sorted(named - anchors(ADMIN_REQUESTS))


def test_every_document_heading_it_names_lands():
    missing = [
        f"{path}#{anchor}"
        for path, anchor in DOCUMENT_REFERENCE.findall(every_text())
        if anchor not in anchors(REPOSITORY / path)
    ]

    assert not missing, missing


@pytest.mark.parametrize("document", DOCUMENTS, ids=lambda path: path.name)
def test_every_path_and_link_it_names_exists(document):
    missing = []
    for target in REPOSITORY_PATH.findall(text(document)):
        if not (REPOSITORY / target).exists():
            missing.append(target)
    for target in links(document):
        if re.match(r"[a-z]+:", target):
            continue
        path, _, fragment = target.partition("#")
        landed = (document.parent / path).resolve()
        if not landed.exists() or (fragment and fragment not in anchors(landed)):
            missing.append(target)

    assert not missing, missing


def test_every_compose_service_it_names_exists():
    services = set(yaml.safe_load(text(REPOSITORY / "docker-compose.yml"))["services"])
    named = set()
    for _verb, rest in COMPOSE.findall(every_text()):
        words = iter(rest.split())
        for word in words:
            if word in COMPOSE_VALUED_FLAGS:
                next(words, None)
            elif not word.startswith("-"):
                named.add(word.strip("`.,;:"))
                break

    assert {"demo", "traffic"} <= named
    assert named <= services, sorted(named - services)


@pytest.mark.parametrize("document", DOCUMENTS, ids=lambda path: path.name)
def test_no_command_it_runs_reads_or_writes_env_beyond_making_it(document):
    naming = [command for command in bash_commands(document) if ENV_FILE.search(command)]

    assert set(naming) <= ALLOWED_ENV_COMMANDS, naming


@pytest.mark.parametrize("document", DOCUMENTS, ids=lambda path: path.name)
def test_no_command_its_prose_names_reads_or_writes_env_either(document):
    """A command in running prose, "then `cat .env`", is followed as readily as a fenced one.
    A span that starts with `.env` is the file's name or a `configure` line quoted, not a
    command."""
    unfenced = re.sub(r"```.*?```", "", text(document), flags=re.DOTALL)
    naming = [
        span
        for span in re.findall(r"`([^`\n]+)`", unfenced)
        if ENV_FILE.search(span) and not span.startswith(".env")
    ]

    assert set(naming) <= ALLOWED_ENV_COMMANDS, naming


def test_every_model_preflight_it_asks_for_reaches_the_stack_layer():
    """`--with-model` runs inside the container, which only the `stack` layer reaches: an
    `--only` without it is a usage error, exit 2."""
    uses = re.findall(r"(?:grafana_jsm_sandbox\.|`)doctor([^`\n]*)", every_text())
    with_model = [rest for rest in uses if "--with-model" in rest]

    assert with_model
    for rest in with_model:
        for layers in ONLY.findall(rest):
            assert "stack" in layers.split(","), rest


def test_it_leaves_the_run_s_skill_to_the_receiver():
    """Nothing the skill runs touches the Run's Skill template; it only names it, to set
    itself apart."""
    for document in DOCUMENTS:
        for command in bash_commands(document):
            assert "skill/incident-sync" not in command, command
    assert any("skill/incident-sync/SKILL.md" in line for line in prose(SKILL))
