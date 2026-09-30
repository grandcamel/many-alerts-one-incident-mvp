"""The command line that starts one Run.

A Run is headless Claude, started in print mode for exactly one Notification,
in a mode where any tool call outside the allow list is denied without a prompt
(ADR 0003). The allow list is jira-as and reading the runs directory, which
holds each Run's working directory and the Skill the Receiver rendered for this
start, so a Run can talk to Jira and nothing else, and the denials show up in
its Transcript where an audience can read them.

The Receiver builds this command line for each Run in ticket 05. Print it to
run one by hand, naming the runs directory and the demo's project key; the Run
reads its Skill from `<runs directory>/.skill`, so use a runs directory a
Receiver has started with, such as laptop mode's `runs`:

    python3 -m grafana_jsm_sandbox.run_command runs <KEY>

Printed by hand, it names the default model and no budget, whatever `.env` sets;
the Receiver passes `RUN_MODEL` and `RUN_BUDGET_USD` through its settings.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME

CLAUDE = "claude"
"""The Claude Code executable, on PATH on the laptop and in the container."""

SKILL_FILE = "incident-sync/SKILL.md"
"""The skill a Run follows, relative to the skill directory."""

RENDERED_SKILL = ".skill"
"""Where in the runs directory the Receiver renders the Skill at startup. Run ids are
timestamps, so no Run's working directory can take the name."""

PERMISSION_MODE = "dontAsk"
"""Anything not on the allow list is denied, without a prompt a Run could hang on."""

JIRA_AS = "Bash(jira-as *)"
"""Talking to Jira: the one command a Run may execute."""

OUTPUT_FORMAT = "stream-json"
"""The Transcript: one Run event per line, rendered into the log as it arrives."""

DEFAULT_MODEL = "claude-opus-5"
"""The model a Run asks for unless `RUN_MODEL` names another. Named on every command line
rather than left to Claude Code, whose own default follows the account and the release, so
the Run an audience watches is the model the presenter chose and the log said at startup."""

SYSTEM_PROMPT_APPENDIX = """\
You are a Run: one headless invocation handling exactly one Grafana Notification.

The Notification is the file {notification} in your working directory.
Your instructions are the skill at {skill}. Read it first and follow it exactly.

Your tools are exactly these: {tools}. Every other tool call will be denied, so do
not reach for one — the skill never needs one."""

PROMPT = (
    f"Read the skill, then handle every Alert in {NOTIFICATION_FILENAME} as it says. "
    "Finish with one line per Alert saying what changed in {project_key}."
)
"""What a Run is asked to do, naming the demo's project, which is `DEMO_PROJECT_KEY`."""


def rendered_skill_directory(runs_directory: Path | str) -> Path:
    """The skill directory a Run reads, rendered for this start inside the runs directory."""
    return Path(runs_directory) / RENDERED_SKILL


def allowed_tools(runs_directory: Path) -> tuple[str, ...]:
    """Everything a Run may do: talk to Jira, and read under one absolute directory.

    A bare `Read` would let a Run read any file its uid can, and the container's
    main process runs as that uid with the real Jira token in its initial
    environment. A live Run asked for it got the token back from
    `/proc/1/task/1/environ` (the 2026-09-23 probe, ADR 0003's amendment). A rule
    scoped to absolute paths denies that and every alias of it: `//` is Claude
    Code's prefix for an absolute path, which a directory's own leading `/` supplies.

    The runs directory holds each Run's working directory and so its Notification,
    and the rendered Skill, so one rule covers both.
    """
    return (JIRA_AS, read_rule(runs_directory))


def read_rule(directory: Path) -> str:
    """A Read rule for everything under one absolute directory."""
    return f"Read(/{directory}/**)"


def build_run_command(
    runs_directory: Path | str,
    project_key: str,
    model: str = DEFAULT_MODEL,
    budget_usd: float | None = None,
    prompt: str | None = None,
) -> list[str]:
    """The argv that starts one Run, to be executed in the Run's working directory.

    `runs_directory` is the parent of every Run's working directory, and holds the
    Skill the Receiver rendered into it (`RENDERED_SKILL`). It is made absolute,
    because a Run's working directory is not this process's, `--add-dir` is
    resolved from the Run's, and a Read rule names an absolute path. `project_key`
    is the demo's project, which the prompt names.

    `model` is always passed. `budget_usd`, when given, is Claude Code's own cap on
    what one Run may spend (`--max-budget-usd`, print mode only): a Run that reaches
    it stops with `error_max_budget_usd`, which the log formatter's hint names. With
    none, a Run is bounded only by its timeout.

    `prompt` replaces the one a Notification's Run is given, and nothing else: `doctor
    --with-model` asks a Run with these very flags to do something harmless, so what it
    finds out about the seat and the allow list holds for the Runs an Alert starts.
    """
    runs_directory = Path(runs_directory).resolve()
    skill_directory = rendered_skill_directory(runs_directory)
    tools = allowed_tools(runs_directory)
    budget = [] if budget_usd is None else ["--max-budget-usd", str(budget_usd)]
    return [
        CLAUDE,
        "--print",
        "--model",
        model,
        *budget,
        "--permission-mode",
        PERMISSION_MODE,
        "--allowedTools",
        *tools,
        "--output-format",
        OUTPUT_FORMAT,
        "--verbose",
        "--add-dir",
        str(skill_directory),
        "--append-system-prompt",
        SYSTEM_PROMPT_APPENDIX.format(
            notification=NOTIFICATION_FILENAME,
            skill=skill_directory / SKILL_FILE,
            tools=", ".join(tools),
        ),
        PROMPT.format(project_key=project_key) if prompt is None else prompt,
    ]


def main(argv: list[str] | None = None) -> int:
    """Print the command line, ready to paste into a Run's working directory."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(
            "usage: python3 -m grafana_jsm_sandbox.run_command <runs-directory> <project-key>",
            file=sys.stderr,
        )
        return 2
    print(shlex.join(build_run_command(argv[0], argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
