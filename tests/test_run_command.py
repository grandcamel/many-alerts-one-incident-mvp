"""The command line that starts one Run.

The flags here are the demo's permission boundary (ADR 0003): a Run is started
in a mode where anything outside the allow list is denied without a prompt, and
the allow list is jira-as and reading under one absolute directory. These tests
are what stops a later change from quietly widening that, which no other test in
this repo would notice.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.run_command import (
    DEFAULT_MODEL,
    SKILL_FILE,
    build_run_command,
    main,
    rendered_skill_directory,
)

RUNS_DIRECTORY = Path("/srv/runs")
RENDERED_SKILL_DIRECTORY = Path("/srv/runs/.skill")
"""Where the Receiver renders the Skill at startup: inside the runs directory."""
PROJECT_KEY = "SANDBOX"


@pytest.fixture
def command() -> list[str]:
    return build_run_command(RUNS_DIRECTORY, PROJECT_KEY)


def value_of(command: list[str], flag: str) -> str:
    """The single value given to `flag`."""
    assert flag in command, f"{flag} is not on the command line"
    return command[command.index(flag) + 1]


def values_of(command: list[str], flag: str) -> list[str]:
    """Every value given to a flag that takes a list, up to the next flag."""
    assert flag in command, f"{flag} is not on the command line"
    rest = command[command.index(flag) + 1 :]
    taken = []
    for argument in rest:
        if argument.startswith("--"):
            break
        taken.append(argument)
    return taken


def test_the_run_is_a_headless_claude_invocation(command):
    assert command[0] == "claude"
    assert "--print" in command


def test_anything_outside_the_allow_list_is_denied_without_a_prompt(command):
    assert value_of(command, "--permission-mode") == "dontAsk"


def test_the_run_may_execute_jira_as_and_read_the_runs_directory_and_nothing_else(command):
    """One Read rule: the runs directory holds the Notification and the rendered Skill both."""
    assert values_of(command, "--allowedTools") == [
        "Bash(jira-as *)",
        "Read(//srv/runs/**)",
    ]
    assert "--dangerously-skip-permissions" not in command
    assert "--allow-dangerously-skip-permissions" not in command
    assert "--disallowedTools" not in command


def test_every_run_names_its_model_and_by_default_it_is_opus_5(command):
    """Named rather than left to Claude Code, whose default follows the account and release."""
    assert DEFAULT_MODEL == "claude-opus-5"
    assert value_of(command, "--model") == "claude-opus-5"


def test_the_model_is_the_one_the_receiver_was_given():
    command = build_run_command(RUNS_DIRECTORY, PROJECT_KEY, model="claude-haiku-4-5")

    assert value_of(command, "--model") == "claude-haiku-4-5"
    assert command.count("--model") == 1


def test_without_a_budget_there_is_no_spending_cap_flag(command):
    assert "--max-budget-usd" not in command


@pytest.mark.parametrize(("budget", "passed"), [(2.0, "2.0"), (0.75, "0.75"), (10, "10")])
def test_a_budget_is_claude_code_s_own_cap_on_one_run(budget, passed):
    """`--max-budget-usd` works only with `--print`, which every Run has."""
    command = build_run_command(RUNS_DIRECTORY, PROJECT_KEY, budget_usd=budget)

    assert value_of(command, "--max-budget-usd") == passed
    assert "--print" in command


def test_the_model_and_the_budget_leave_the_allow_list_and_the_prompt_as_they_were(command):
    """The new flags sit before the allow list, so neither can be read as one of its tools."""
    knobs = build_run_command(RUNS_DIRECTORY, PROJECT_KEY, model="opus", budget_usd=1.5)

    assert values_of(knobs, "--allowedTools") == values_of(command, "--allowedTools")
    assert knobs[-1] == command[-1]
    assert [a for a in knobs if a not in ("--max-budget-usd", "1.5", "opus")] == [
        a for a in command if a != DEFAULT_MODEL
    ]


def test_the_transcript_is_stream_json_one_run_event_per_line(command):
    assert value_of(command, "--output-format") == "stream-json"
    assert "--verbose" in command, "stream-json in print mode needs --verbose"


def test_the_rendered_skill_is_inside_the_runs_directory():
    assert rendered_skill_directory(RUNS_DIRECTORY) == RENDERED_SKILL_DIRECTORY


def test_the_run_can_reach_the_rendered_skill_and_not_the_template(command):
    """The template in the repo still carries `{{PROJECT_KEY}}`; a Run is given the rendering."""
    assert value_of(command, "--add-dir") == str(RENDERED_SKILL_DIRECTORY)
    assert all("/skill" not in tool for tool in values_of(command, "--allowedTools"))


def test_the_rendered_skill_is_under_the_one_read_rule(command):
    [rule] = [tool for tool in values_of(command, "--allowedTools") if tool.startswith("Read")]
    assert f"Read(/{RENDERED_SKILL_DIRECTORY.parent}/**)" == rule


def test_the_system_prompt_appendix_names_the_notification_and_the_skill(command):
    appendix = value_of(command, "--append-system-prompt")
    assert NOTIFICATION_FILENAME in appendix
    assert str(RENDERED_SKILL_DIRECTORY / SKILL_FILE) in appendix


def test_the_run_is_told_the_same_allow_list_that_is_enforced_on_it(command):
    """A Run that knows what it may do stops reaching for what it may not."""
    appendix = value_of(command, "--append-system-prompt")
    for tool in values_of(command, "--allowedTools"):
        assert tool in appendix


def test_the_prompt_is_the_last_argument_and_is_not_a_flag(command):
    prompt = command[-1]
    assert not prompt.startswith("-")
    assert NOTIFICATION_FILENAME in prompt


def test_the_prompt_names_the_demo_s_project_and_not_ops(command):
    prompt = command[-1]
    assert PROJECT_KEY in prompt
    assert "OPS" not in prompt


def test_another_prompt_changes_the_prompt_and_nothing_else(command):
    """`doctor --with-model` asks a Run with the real flags to do something harmless."""
    probe = build_run_command(RUNS_DIRECTORY, PROJECT_KEY, prompt="run `jira-as --version`")

    assert probe[:-1] == command[:-1]
    assert probe[-1] == "run `jira-as --version`"


def test_a_relative_runs_directory_puts_the_rendered_skill_at_an_absolute_path(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    command = build_run_command(Path("runs"), PROJECT_KEY)
    assert value_of(command, "--add-dir") == str(tmp_path.resolve() / "runs" / ".skill")


def test_every_read_rule_names_an_absolute_path(command):
    """A bare `Read` handed a Run the real token from /proc/1/task/1/environ (the
    2026-09-23 probe). `//` is Claude Code's prefix for an absolute path, and only a
    rule scoped that way denied the token and every alias of it."""
    for tool in values_of(command, "--allowedTools"):
        if tool.startswith("Read"):
            assert tool.startswith("Read(//") and tool.endswith("/**)"), tool
    assert "Read" not in values_of(command, "--allowedTools")


def test_a_relative_runs_directory_is_made_absolute_in_its_read_rule(tmp_path, monkeypatch):
    """The Receiver's default runs directory is relative to where it was started."""
    monkeypatch.chdir(tmp_path)
    command = build_run_command(Path("runs"), PROJECT_KEY)
    assert f"Read(/{tmp_path.resolve()}/runs/**)" in values_of(command, "--allowedTools")


def test_printed_by_hand_it_needs_the_runs_directory_and_the_project(capsys):
    assert main(["/srv/runs"]) == 2
    assert "<project-key>" in capsys.readouterr().err
    assert main(["/srv/skill", "/srv/runs", "SANDBOX"]) == 2
    assert "<runs-directory>" in capsys.readouterr().err

    assert main(["/srv/runs", "SANDBOX"]) == 0
    printed = capsys.readouterr().out
    assert "'Read(//srv/runs/**)'" in printed
    assert f"--model {DEFAULT_MODEL}" in printed
    assert "/srv/runs/.skill" in printed
    assert "SANDBOX" in printed
