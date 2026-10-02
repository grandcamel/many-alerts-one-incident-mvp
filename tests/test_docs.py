"""The engineer-facing docs hold together: every admin request a command or a doc names is a
heading in `docs/admin-requests.md`, and every relative link in them lands.

`configure`, `doctor` and `verify` end a line with `; ask: docs/admin-requests.md#<anchor>`,
and the setup skill and a person both follow that anchor to the request they forward. A
heading renamed, or an anchor misspelt in the code, would send them to the top of the page
with no error anywhere, so the anchors are resolved here the way GitHub resolves them.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from grafana_jsm_sandbox import configure, doctor
from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME, INVESTIGATION_MARKER

REPOSITORY = Path(__file__).resolve().parent.parent
ADMIN_REQUESTS = REPOSITORY / "docs" / "admin-requests.md"
PACKAGE = REPOSITORY / "grafana_jsm_sandbox"

REFERENCE = re.compile(r"docs/admin-requests\.md#([a-z0-9-]+)")
"""A request as the commands print it and the docs cite it. `#<anchor>` is a placeholder, not a
reference, and this does not match it."""

REQUEST_PREFIXES = ("jira-admin-", "atlassian-org-admin-", "claude-org-owner", "docker-admin")
"""How every request's anchor starts, so an anchor the code holds as a bare constant is found."""

REQUIRED = {
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
"""The requests the demo-onboarding spec (step 11) asks `docs/admin-requests.md` to carry."""

LINKED = (
    REPOSITORY / "README.md",
    *sorted((REPOSITORY / "docs").glob("*.md")),
    *sorted((REPOSITORY / "docs" / "adr").glob("000[1-5]-*.md")),
    REPOSITORY / "CLAUDE.md",
)
"""The engineer-facing docs whose relative links must land: the README, the docs, chapter one's
ADRs (0001 to 0005, which this onboarding amends) and the agents' CLAUDE.md."""

FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")


def prose(path: Path) -> list[str]:
    """The file's lines outside fenced code blocks, where a `#` is no heading."""
    lines, fenced = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return lines


def slug(heading: str) -> str:
    """A heading's anchor as GitHub makes it: the text lower-cased, markup and punctuation
    dropped except `-` and `_`, and each space a `-`."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    """Every heading anchor in a Markdown file, a repeated one numbered as GitHub numbers it."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    for line in prose(path):
        heading = HEADING.match(line)
        if heading is None:
            continue
        base = slug(heading[2])
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def referenced() -> dict[str, set[str]]:
    """Every request anchor named anywhere, and where: the package's source (as a printed
    reference or as a bare constant), the README, `.env.example` and the docs."""
    where: dict[str, set[str]] = {}

    def note(anchor: str, place: Path) -> None:
        where.setdefault(anchor, set()).add(str(place.relative_to(REPOSITORY)))

    for source in sorted(PACKAGE.glob("*.py")):
        text = source.read_text(encoding="utf-8")
        for anchor in REFERENCE.findall(text):
            note(anchor, source)
        for node in ast.walk(ast.parse(text)):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith(REQUEST_PREFIXES)
                and re.fullmatch(r"[a-z0-9-]+", node.value)
            ):
                note(node.value, source)
    for document in (
        REPOSITORY / "README.md",
        REPOSITORY / ".env.example",
        *sorted((REPOSITORY / "docs").rglob("*.md")),
    ):
        for anchor in REFERENCE.findall(document.read_text(encoding="utf-8")):
            note(anchor, document)
    return where


def test_the_admin_requests_carry_every_request_the_spec_asks_for():
    assert REQUIRED <= anchors(ADMIN_REQUESTS), sorted(REQUIRED - anchors(ADMIN_REQUESTS))


def test_every_admin_request_named_anywhere_is_a_heading_there():
    where = referenced()
    missing = {anchor: sorted(places) for anchor, places in where.items()}
    for anchor in anchors(ADMIN_REQUESTS):
        missing.pop(anchor, None)

    assert not missing, missing


def test_the_search_finds_what_the_commands_name():
    """So the test above cannot pass by finding nothing."""
    named = {
        configure.CREATE_PROJECT,
        configure.INCIDENT_FIELDS,
        configure.RESOLUTION_SCREEN,
        configure.WORKFLOW_STATUSES,
        configure.PERMISSIONS,
        configure.AGENT_LICENCE,
        configure.API_TOKENS,
        configure.IP_ALLOWLIST_REQUEST,
        doctor.CLAUDE_ORG_OWNER,
        doctor.DOCKER_ADMIN,
    }

    assert named <= set(referenced())


def test_the_anchor_rules_are_github_s():
    assert slug("Jira admin: create project") == "jira-admin-create-project"
    assert slug("Atlassian org admin: API tokens") == "atlassian-org-admin-api-tokens"
    assert (
        slug("Reset: between takes, or after a bad one") == "reset-between-takes-or-after-a-bad-one"
    )
    assert slug("The setup commands: configure, doctor, verify") == (
        "the-setup-commands-configure-doctor-verify"
    )
    assert slug("`--basic-demo`, and why") == "--basic-demo-and-why"


def links(path: Path) -> list[str]:
    """Every link target outside code blocks, link text that wraps a line included."""
    return LINK.findall("\n".join(prose(path)))


@pytest.mark.parametrize("document", LINKED, ids=lambda path: str(path.relative_to(REPOSITORY)))
def test_every_relative_link_lands(document):
    broken = []
    for target in links(document):
        if re.match(r"[a-z]+:", target):
            continue
        path, _, fragment = target.partition("#")
        landed = (document.parent / path).resolve() if path else document
        if not landed.exists():
            broken.append(f"{target}: no such file")
        elif fragment and landed.suffix == ".md" and fragment not in anchors(landed):
            broken.append(f"{target}: no such heading")

    assert not broken, broken


RUNBOOK = REPOSITORY / "docs" / "mvp-runbook.md"
SETUP_SKILL = REPOSITORY / ".claude" / "skills" / "demo-setup" / "SKILL.md"


@pytest.mark.parametrize("document", [RUNBOOK, SETUP_SKILL], ids=lambda path: path.name)
def test_investigation_setup_keeps_the_viewer_token_manual_and_private(document):
    body = " ".join(document.read_text().split())
    for required in (
        "service account with role Viewer",
        "presenter's Admin access",
        "mode-0600",
        "DEMO_INVESTIGATION_ENABLED=true",
        "DEMO_GRAFANA_VIEWER_TOKEN",
        "docker compose up -d --force-recreate demo",
        "/data/grafana",
        "token rejected",
    ):
        assert required in body, required
    assert "after `lgtm` is recreated" in body


@pytest.mark.parametrize("document", [RUNBOOK, REPOSITORY / "README.md"])
def test_investigation_docs_distinguish_evidence_and_presenter_access(document):
    body = " ".join(document.read_text().split())
    for required in (
        "These queries authenticate with a Viewer token",
        "anonymous Admin",
        # The 2026-10-02 rehearsal: anonymous Admin also answers a wrong or missing token.
        "wrong or missing token",
        "bypasses the Jira Forwarder",
        "presenter's browser",
        "zero, no data and unavailable",
        "not an independent reachability check",
        "current system",
        "DEMO_INVESTIGATION_ENABLED=false",
    ):
        assert required in body, required


@pytest.mark.parametrize("number", ["0002", "0003"])
def test_the_access_adrs_describe_the_opt_in_grafana_credential(number):
    [document] = (REPOSITORY / "docs" / "adr").glob(f"{number}-*.md")
    body = " ".join(document.read_text().split())
    for required in ("model credential", "Grafana Viewer credential", "Jira", "sentinel"):
        assert required in body, required
    assert "bypasses the Jira Forwarder" in body


def test_the_runbook_uses_the_shared_evidence_name_and_exact_comment_marker():
    body = RUNBOOK.read_text()
    assert f"`{EVIDENCE_FILENAME}`" in body
    assert f"`{INVESTIGATION_MARKER}`" in body


def test_the_runbook_query_examples_use_only_frozen_subcommands_and_flags():
    examples = re.findall(r"`(grafana-query (?:instant|range|get|logs|traces|trace)\b[^`]+)`", RUNBOOK.read_text())
    required = {
        "instant": "--query", "range": "--query", "get": "--path",
        "logs": "--query", "traces": "--query", "trace": "--id",
    }
    found = set()
    for example in examples:
        words = example.split()
        command = words[1]
        found.add(command)
        # Values follow `=`, so an expression starting with `-` is not read as a flag.
        assert len(words) == 3 and words[:2] == ["grafana-query", command]
        assert words[2].startswith(required[command] + "=") and words[2] != required[command] + "="
    assert found == set(required)


@pytest.mark.parametrize(
    "document", [REPOSITORY / "README.md", REPOSITORY / "docs/demo-runbook.md", SETUP_SKILL]
)
def test_presenters_use_grouped_verification_and_name_the_incompatible_replay(document):
    body = " ".join(document.read_text().split())
    for required in (
        "mvp-runbook.md", "verify --mvp --live", "verify --mvp --replay",
        "groupLabels.incident_group", "PayloadError", "no create is registered",
        "replay` has no option for grouped fixtures",
    ):
        assert required in body, required


def test_reset_guidance_names_its_immediate_writes_scope_and_fault_recovery():
    body = " ".join(RUNBOOK.read_text().split()).split("## 8. Reset and teardown", 1)[1]
    for required in (
        "It does not ask: it changes Jira at once",
        "python3 -m grafana_jsm_sandbox.reset --dry-run",
        "python3 -m grafana_jsm_sandbox.reset",
        "`fp-` label, from any session",
        "when the workflow has a close step",
        "does not undo an injected `ROLLDICE_SIDES` or `ROLLDICE_SLOW_MS`",
        "first recreate traffic", "docker compose down",
    ):
        assert required in body, required


def test_create_timing_includes_the_investigation_qualification():
    body = " ".join(RUNBOOK.read_text().split())
    assert "typically within a minute of the Notification (longer with investigation on a slower model)" in body


def test_readme_runnable_verification_examples_use_the_grouped_mvp():
    body = (REPOSITORY / "README.md").read_text()
    examples = re.findall(r"```bash\n(.*?)```", body, re.DOTALL)
    commands = [
        line.strip()
        for example in examples
        for line in example.splitlines()
        if "-m grafana_jsm_sandbox.verify" in line
    ]
    assert commands
    for command in commands:
        assert "--mvp" in command, command
        assert "--replay" in command or "--live" in command, command
    assert not any("-m grafana_jsm_sandbox.replay" in example for example in examples)
    assert "This wrapper does not work with the MVP Run" in " ".join(body.split())
    assert "`claude setup-token`" in body
    assert not re.search(r"`claude setup-[\s\n]+token`", body)


def test_chapter_one_output_reference_is_explicitly_historical_and_incompatible():
    body = " ".join((SETUP_SKILL.parent / "READING-OUTPUT.md").read_text().split())
    for required in (
        "Chapter-one verify (historical output only)",
        "do not work with the MVP Run", "groupLabels.incident_group",
        "PayloadError", "no create is registered",
        "Use `verify --mvp --replay` or `verify --mvp --live` for the current demo",
    ):
        assert required in body, required


def test_presenter_narration_qualifies_investigation_permissions_and_file_output():
    body = " ".join((REPOSITORY / "docs/demo-runbook.md").read_text().split())
    for required in (
        "With investigation disabled, its allow list has three rules",
        "With investigation enabled, `run_command.py` adds `Bash(grafana-query *)` as a fourth rule",
        "`investigate` subcommand also writes one ADF body file in the Run's directory",
        "--body-file", "three-rule allow list when investigation is disabled (four rules when enabled)",
    ):
        assert required in body, required
    assert "only prints" not in body


def test_chapter_one_reset_guidance_also_recovers_injected_traffic_settings():
    body = " ".join((REPOSITORY / "docs/demo-runbook.md").read_text().split())
    for required in (
        "`reset.py` only starts the existing container",
        "recreate traffic with the defaults", "ROLLDICE_SIDES=6", "ROLLDICE_SLOW_MS=0",
        "loki-investigation.md#optional-malformed-input-fault",
        "slow-response-investigation.md#inject-inspect-recover",
    ):
        assert required in body, required
    assert "the one thing the reset cannot fix" not in body
