"""The committed fixtures are fit for a stranger to clone.

A recorded Transcript is the real thing: whatever the Run read, said and was
told comes back in it verbatim, including the Jira account it acted as and the
directory it ran in. Those were fine on one laptop and are a decision when the
tree is public. These checks read every fixture git tracks and refuse three
things a re-recorded Transcript would otherwise carry straight back in: an
address that is not the documentation placeholder, that address hidden in a
Gravatar URL as its hash, and a path on the recording machine rather than in
the container.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, REPOSITORY

PLACEHOLDER_ADDRESS = "ops@example.invalid"
"""The one address a fixture may carry: the account the tests' Forwarder acts as."""

PLACEHOLDER_DOMAIN = PLACEHOLDER_ADDRESS.partition("@")[2]
"""The one domain an `@` in a fixture may be followed by."""

RECORDING_MACHINE_PATHS = ("/Users/", "/private/", "/home/")
"""Where a Run's working directory lands when it is recorded on a laptop, not in the container."""

CONTAINER_HOME = "/home/demo"
"""The one `/home` a Run in the container writes under; a Transcript may name it."""


def committed_fixtures() -> list[Path]:
    """Every file under `fixtures/` that git tracks — the ones a clone gets.

    A tree unpacked from an archive has no git to ask; there, every file present
    is what shipped, and the check reads them all.
    """
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--", str(FIXTURES.relative_to(REPOSITORY))],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
            check=True,
        )
        paths = [REPOSITORY / line for line in listed.stdout.splitlines() if line]
    except (FileNotFoundError, subprocess.CalledProcessError):
        paths = sorted(path for path in FIXTURES.iterdir() if path.is_file())
    assert paths, "no fixture is committed at all"
    return paths


every_committed_fixture = pytest.mark.parametrize(
    "fixture", committed_fixtures(), ids=lambda path: path.name
)


def addresses_off_the_placeholder_domain(text: str) -> list[str]:
    """Every `@`, with what is around it, unless the placeholder domain follows it."""
    return [
        match.group(0)
        for match in re.finditer(r"[\w.+-]*@[\w.-]*", text)
        if not match.group(0).endswith("@" + PLACEHOLDER_DOMAIN)
    ]


def gravatar_hashes(text: str) -> set[str]:
    """Every hash in a Gravatar URL, which is an address run through MD5."""
    return set(re.findall(r"gravatar\.com/avatar/([0-9a-f]{32})", text))


def recording_machine_paths(text: str) -> list[str]:
    """Every path into a laptop's filesystem, with the container's own home excused."""
    found = []
    for prefix in RECORDING_MACHINE_PATHS:
        for match in re.finditer(re.escape(prefix) + r"[\w./-]*", text):
            if match.group(0).startswith(CONTAINER_HOME):
                continue
            found.append(match.group(0))
    return found


@every_committed_fixture
def test_no_committed_fixture_carries_an_address_outside_the_placeholder_domain(fixture):
    """An `@` in a fixture is followed by `example.invalid` or it is somebody's."""
    found = addresses_off_the_placeholder_domain(fixture.read_text())

    assert not found, f"{fixture.name} carries {sorted(set(found))}"


@every_committed_fixture
def test_no_committed_fixture_carries_an_address_hashed_into_a_gravatar_url(fixture):
    """The MD5 of a guessable address is the address; only the placeholder's may appear."""
    allowed = hashlib.md5(PLACEHOLDER_ADDRESS.encode()).hexdigest()
    found = gravatar_hashes(fixture.read_text()) - {allowed}

    assert not found, f"{fixture.name} carries a Gravatar hash of some other address: {found}"


@every_committed_fixture
def test_no_committed_fixture_carries_a_path_on_the_recording_machine(fixture):
    """A Run's paths in a fixture are the container's, not the laptop's it was recorded on."""
    found = recording_machine_paths(fixture.read_text())

    assert not found, f"{fixture.name} carries {sorted(set(found))[:5]}"
