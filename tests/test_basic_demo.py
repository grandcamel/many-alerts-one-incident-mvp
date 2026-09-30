"""`--basic-demo` runs chapter one's tests and never imports chapter two.

An engineer who is about to run the basic demo checks their host with
`python3 -m pytest --basic-demo`. Chapter two's code, the mediated Forwarder chain and the
`prototype/` work, is not part of that demo, and a file of its tests that fails to import on
their Python must not stand between them and a green check. So the option passes over every
test file not in `BASIC_DEMO_TESTS` before it is imported.

The list is only as good as the rule behind it: a test file is chapter one's exactly when it
imports nothing from chapter two. These checks hold every file to that rule, then run the real
collection in a child pytest and look at what it collected and what it loaded.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.conftest import BASIC_DEMO_OPTION, BASIC_DEMO_TESTS, REPOSITORY, TESTS
from tests.conftest import pytest_ignore_collect as ignore_collect

EVERY_TEST_FILE = sorted(TESTS.glob("test_*.py"))


def is_chapter_two(module: str) -> bool:
    """Whether importing `module` would bring chapter two's code with it.

    `grafana_jsm_sandbox.forwarder` is chapter one's Forwarder; its `forwarder_*` siblings are
    the mediated chain. A test module outside the list counts too, because importing one runs
    its own imports.
    """
    if module == "prototype" or module.startswith("prototype."):
        return True
    if module.startswith("grafana_jsm_sandbox.forwarder_"):
        return True
    package, _, name = module.partition(".")
    return (
        package == "tests"
        and name.startswith("test_")
        and (f"{name.partition('.')[0]}.py" not in BASIC_DEMO_TESTS)
    )


def chapter_two_imports(path: Path) -> list[str]:
    """The chapter-two modules a test file imports by name, `from x import y` included."""
    imported = set()
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
    return sorted(module for module in imported if is_chapter_two(module))


def test_every_listed_file_is_there():
    assert sorted(BASIC_DEMO_TESTS - {path.name for path in EVERY_TEST_FILE}) == []


@pytest.mark.parametrize("path", EVERY_TEST_FILE, ids=lambda path: path.name)
def test_a_file_is_on_the_list_exactly_when_it_imports_nothing_from_chapter_two(path):
    imports = chapter_two_imports(path)
    if path.name in BASIC_DEMO_TESTS:
        assert imports == [], f"{path.name} is on the basic-demo list but imports {imports}"
    else:
        assert imports, (
            f"{path.name} imports nothing from chapter two: add it to BASIC_DEMO_TESTS "
            "in tests/conftest.py"
        )


def test_the_rule_knows_chapter_one_s_forwarder_from_chapter_two_s():
    assert not is_chapter_two("grafana_jsm_sandbox.forwarder")
    assert is_chapter_two("grafana_jsm_sandbox.forwarder_upstream")
    assert is_chapter_two("prototype.run_timing.executor")
    assert not is_chapter_two("tests.test_replay")
    assert is_chapter_two("tests.test_forwarder_upstream")


# --- The hook itself ---


@dataclass
class Options:
    """The one thing the hook asks of pytest's config."""

    basic_demo: bool

    def getoption(self, name: str) -> bool:
        assert name == BASIC_DEMO_OPTION
        return self.basic_demo


def test_without_the_option_the_hook_leaves_every_file_to_pytest():
    for path in EVERY_TEST_FILE:
        assert ignore_collect(path, Options(basic_demo=False)) is None, path.name


def test_with_the_option_only_the_listed_files_are_kept():
    options = Options(basic_demo=True)
    kept = {path.name for path in EVERY_TEST_FILE if not ignore_collect(path, options)}
    assert kept == BASIC_DEMO_TESTS


def test_the_option_passes_over_nothing_but_test_files():
    for path in (TESTS, TESTS / "conftest.py", TESTS / "upstream.py", TESTS / "__init__.py"):
        assert ignore_collect(path, Options(basic_demo=True)) is None, path.name


def test_a_listed_name_outside_the_tests_directory_is_still_passed_over(tmp_path):
    stray = tmp_path / "test_replay.py"
    stray.write_text("")
    assert ignore_collect(stray, Options(basic_demo=True)) is True


# --- The real collection, in a child pytest ---

CENSUS = """
import json, sys
import pytest

class Census:
    def __init__(self):
        self.files = set()

    def pytest_collection_modifyitems(self, items):
        self.files.update(item.path.name for item in items)

census = Census()
status = int(pytest.main(sys.argv[1:], plugins=[census]))
files, modules = sorted(census.files), sorted(sys.modules)
print(json.dumps({"status": status, "files": files, "modules": modules}))
"""
"""Collects as pytest would from the repo root, then reports the files and every loaded module."""


@pytest.fixture(scope="module")
def basic_demo_collection() -> dict:
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            CENSUS,
            BASIC_DEMO_OPTION,
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    lines = child.stdout.strip().splitlines()
    assert lines, f"the child pytest printed nothing; stderr:\n{child.stderr}"
    census = json.loads(lines[-1])
    assert census["status"] == 0, child.stdout + child.stderr
    return census


def test_the_option_collects_exactly_the_listed_files(basic_demo_collection):
    assert set(basic_demo_collection["files"]) == BASIC_DEMO_TESTS


def test_the_option_loads_no_chapter_two_module(basic_demo_collection):
    assert [m for m in basic_demo_collection["modules"] if is_chapter_two(m)] == []
