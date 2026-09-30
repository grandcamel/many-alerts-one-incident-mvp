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
