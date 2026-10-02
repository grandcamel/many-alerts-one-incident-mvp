"""The container's main process: the Receiver, the Forwarder it owns, and real Runs.

Everything the demo needs in one process (ADR 0001). The Forwarder is a thread
inside it holding the real Jira credential; the Receiver listens for Grafana's
Notifications; each Notification becomes a child process started by the spawner
with a sentinel where that credential would be.

    python3 -m grafana_jsm_sandbox

It reads its whole configuration from the environment, which compose fills from
`.env`, and refuses to start without a Jira credential, exactly one model
credential (an Anthropic API key or a Claude Code OAuth token) and the demo's
project key, naming everything that is missing at once, because a
container that starts and quietly does nothing is only found out when an Alert
fires in front of an audience.

At every start it renders the Skill a Run follows from the template in this
repo, filling in the project's key and field ids, into the runs directory, which
is a tmpfs in the container. A Run reads that rendering and nothing else, so the
Skill always describes the project `.env` names now, and nobody edits a tracked
file or rebuilds the image to point the demo at their own site.

On Linux it first marks itself non-dumpable. The real Jira token is in this
process's initial environment, and every Run is a child running as the same
uid, so without that a Run could read the token back out of `/proc/1`. It does
this itself, rather than trusting each Run's Read rule, because jira-as opens
local files too (an attachment upload, a template, a batch file) and Claude's
permission rules never see those reads (ADR 0002's amendment).
"""

from __future__ import annotations

import logging
import math
import os
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from grafana_jsm_sandbox.demo_config import DemoProject, IncompleteDemoProject
from grafana_jsm_sandbox.forwarder import Forwarder, IncompleteJiraCredential, JiraCredential
from grafana_jsm_sandbox.nondumpable import refuse_to_be_read
from grafana_jsm_sandbox.receiver import Receiver
from grafana_jsm_sandbox.run_command import (
    DEFAULT_MODEL,
    build_run_command,
    rendered_skill_directory,
)
from grafana_jsm_sandbox.run_spawner import (
    RUN_TIMEOUT,
    MissingModelCredential,
    ModelCredential,
    RunSpawner,
    model_credential_from_environment,
)
from grafana_jsm_sandbox.skill_template import SkillTemplateError, materialize

logger = logging.getLogger(__name__)

Number = TypeVar("Number", int, float)

HOST_VARIABLE = "RECEIVER_HOST"
PORT_VARIABLE = "RECEIVER_PORT"
RUNS_DIRECTORY_VARIABLE = "RUNS_DIRECTORY"
SKILL_DIRECTORY_VARIABLE = "SKILL_DIRECTORY"
RUN_TIMEOUT_VARIABLE = "RUN_TIMEOUT"
RUN_SETTLE_VARIABLE = "RUN_SETTLE_SECONDS"
"""What the container sets to place the demo; the credential variables are the Forwarder's
and the spawner's, and the project's, which have no default, are `demo_config`'s. Every one of
these has a default that works on a laptop."""

RUN_MODEL_VARIABLE = "RUN_MODEL"
"""The model every Run asks for, `run_command.DEFAULT_MODEL` unless `.env` names another: an
alias Claude Code knows or a model's full name. A seat that may not use it fails each Run with
a hint that names this variable."""

MODEL_PREFLIGHT = "python3 -m grafana_jsm_sandbox.doctor --only stack --with-model"
"""The command that asks the seat for one short Run on `RUN_MODEL` and reports the model it
asked for beside the one that ran. Startup does not do that, so the log names it."""

RUN_BUDGET_VARIABLE = "RUN_BUDGET_USD"
"""The most one Run may spend, in dollars, passed as Claude Code's `--max-budget-usd`. Unset
means no cap beyond the Run's timeout. Claude Code checks it against its own estimate of what
the Run has spent, so it is not a limit the API or the bill enforces (ADR 0013)."""

DEFAULT_HOST = "0.0.0.0"
"""Grafana reaches the Receiver from another container; the Forwarder is the loopback one."""

DEFAULT_PORT = 8080
"""What the contact point URL names, so compose publishes one well-known port."""

DEFAULT_RUN_SETTLE_SECONDS = 30.0
"""Time after a Run ends for Jira's search index to reflect its newly created Incident."""

DEFAULT_RUNS_DIRECTORY = Path("runs")
"""Where each Run's working directory goes, relative to wherever this was started."""

DEFAULT_SKILL_DIRECTORY = Path(__file__).resolve().parent.parent / "skill"
"""The Skill's template in this repo, which the image copies in and the Receiver renders from.
A Run never reads it: it reads the rendering in the runs directory."""

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
"""Every line the process logs carries when it was said and how much it matters. A failed Run,
a Jira refusal and a rejected Notification are WARNING or ERROR, so they can be found without
reading every Run. The level is padded so a Transcript's labels still line up."""

LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
"""To the second, with no zone: `docker compose logs` has no time of its own unless asked
(`-t`), and a presenter reads these against a wall clock."""


class IncompleteConfiguration(ValueError):
    """The environment does not describe a demo that could work, and says how."""


@dataclass(frozen=True)
class Settings:
    """Everything the process needs, read from the environment in one place."""

    credential: JiraCredential
    model_credential: ModelCredential
    project: DemoProject
    host: str
    port: int
    runs_directory: Path
    skill_directory: Path
    run_timeout: float
    run_model: str = DEFAULT_MODEL
    run_budget_usd: float | None = None
    run_settle_seconds: float = DEFAULT_RUN_SETTLE_SECONDS

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> Settings:
        """Read the whole configuration, or raise naming every part of it that is wrong.

        Every failure is collected rather than raised at the first one, so a
        half-filled env file is fixed in one pass instead of three restarts.
        """
        environment = os.environ if environment is None else environment
        failures: list[str] = []
        credential = model_credential = project = None
        try:
            credential = JiraCredential.from_environment(environment)
        except IncompleteJiraCredential as failure:
            failures.append(str(failure))
        try:
            model_credential = model_credential_from_environment(environment)
        except MissingModelCredential as failure:
            failures.append(str(failure))
        try:
            project = DemoProject.from_environment(environment)
        except IncompleteDemoProject as failure:
            failures.append(str(failure))
        port = _number(environment, PORT_VARIABLE, DEFAULT_PORT, int, failures)
        run_timeout = _number(environment, RUN_TIMEOUT_VARIABLE, RUN_TIMEOUT, float, failures)
        run_settle_seconds = _number(
            environment, RUN_SETTLE_VARIABLE, DEFAULT_RUN_SETTLE_SECONDS, float, failures
        )
        run_model = _model(environment, failures)
        run_budget_usd = _budget(environment, failures)
        if failures or credential is None or model_credential is None or project is None:
            raise IncompleteConfiguration("\n".join(failures))
        return cls(
            credential=credential,
            model_credential=model_credential,
            project=project,
            host=environment.get(HOST_VARIABLE, "").strip() or DEFAULT_HOST,
            port=port,
            runs_directory=_directory(environment, RUNS_DIRECTORY_VARIABLE, DEFAULT_RUNS_DIRECTORY),
            skill_directory=_directory(
                environment, SKILL_DIRECTORY_VARIABLE, DEFAULT_SKILL_DIRECTORY
            ),
            run_timeout=run_timeout,
            run_model=run_model,
            run_budget_usd=run_budget_usd,
            run_settle_seconds=run_settle_seconds,
        )


def render_skill(settings: Settings) -> Path:
    """Render the Skill for this start where every Run will read it, and say where.

    Done at every start, before anything listens, so the first Run already reads
    the Skill for the project `.env` names now.
    """
    rendered = materialize(
        settings.skill_directory,
        rendered_skill_directory(settings.runs_directory),
        settings.project,
    )
    logger.info(
        "skill rendered for project %s, session label %s, at %s",
        settings.project.key,
        settings.project.session_label,
        rendered,
    )
    return rendered


def log_run_knobs(settings: Settings) -> None:
    """Say what every Run authenticates with, which model it asks for, and what it may spend.

    Said once at startup, before any Alert, so a presenter reading the log can tell
    a model the seat cannot use, or a missing cap, from the Run that then fails.
    The credential is named by kind and variable, never by value. The model is only
    named, not tried: whether the seat can run it is what `MODEL_PREFLIGHT` finds out.
    """
    logger.info(
        "runs authenticate with %s (%s)",
        settings.model_credential.kind,
        settings.model_credential.variable,
    )
    logger.info("runs use model %s (%s)", settings.run_model, RUN_MODEL_VARIABLE)
    logger.info(
        "startup does not check that the Claude seat can run %s; before a demo on a model not "
        "tried yet, run `%s` on the laptop, which says which model ran",
        settings.run_model,
        MODEL_PREFLIGHT,
    )
    logger.info("runs time out after %ss (%s)", settings.run_timeout, RUN_TIMEOUT_VARIABLE)
    logger.info(
        "runs settle for %ss after the previous run (%s)",
        settings.run_settle_seconds,
        RUN_SETTLE_VARIABLE,
    )
    if settings.run_budget_usd is None:
        logger.info("runs have no spending cap (%s is not set)", RUN_BUDGET_VARIABLE)
    else:
        logger.info(
            "each run may spend at most $%s (%s)", settings.run_budget_usd, RUN_BUDGET_VARIABLE
        )


def serve(settings: Settings) -> int:
    """Render the Skill, start the Forwarder and the Receiver, and serve until interrupted."""
    try:
        render_skill(settings)
    except (SkillTemplateError, OSError) as failure:
        # Refused rather than served: without a Skill every Run would fail, and only
        # once an Alert fired would anyone see why.
        print(f"cannot render the Run's Skill: {failure}", file=sys.stderr)
        return 1
    forwarder = Forwarder(settings.credential)
    forwarder.start()
    receiver = Receiver(
        spawn_run=RunSpawner(
            command=build_run_command(
                settings.runs_directory,
                settings.project.key,
                model=settings.run_model,
                budget_usd=settings.run_budget_usd,
            ),
            forwarder=forwarder,
            model_credential=settings.model_credential,
            # The email, and only the email. The spawner is handed the one part of
            # the credential a Run is allowed to hold, rather than the credential
            # it would then have to be trusted not to pass on (ADR 0002).
            jira_email=settings.credential.email,
            project_key=settings.project.key,
            timeout=settings.run_timeout,
        ),
        runs_directory=settings.runs_directory,
        host=settings.host,
        port=settings.port,
        settle_seconds=settings.run_settle_seconds,
    )
    receiver.start()
    logger.info("receiver listening on %s", receiver.url)
    logger.info(
        "runs reach %s as %s through the Forwarder, holding a sentinel",
        settings.credential.site_url,
        settings.credential.email,
    )
    logger.info(
        "jira-as in each run is confined to project %s (JIRA_ALLOWED_PROJECTS)",
        settings.project.key,
    )
    log_run_knobs(settings)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        receiver.stop()
        forwarder.stop()
    return 0


def main(argv: list[str] | None = None, environment: Mapping[str, str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: python3 -m grafana_jsm_sandbox", file=sys.stderr)
        return 2
    try:
        settings = Settings.from_environment(environment)
    except IncompleteConfiguration as failure:
        print(failure, file=sys.stderr)
        return 1
    try:
        unreadable = refuse_to_be_read()
    except OSError as failure:
        # Refused rather than served: a Receiver whose environment a Run can read
        # would hand every Run the real token the Forwarder exists to keep from it.
        print(f"cannot keep the Jira token from Runs: {failure}", file=sys.stderr)
        return 1
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_TIME_FORMAT)
    if unreadable:
        logger.info("receiver is non-dumpable: no Run can read its environment")
    return serve(settings)


def _number(
    environment: Mapping[str, str],
    variable: str,
    default: Number,
    read: Callable[[str], Number],
    failures: list[str],
) -> Number:
    """A number read from the environment, or the default, or one more failure to report."""
    value = environment.get(variable, "").strip()
    if not value:
        return default
    try:
        return read(value)
    except ValueError:
        failures.append(f"{variable} is not a number: {value!r}")
        return default


def _model(environment: Mapping[str, str], failures: list[str]) -> str:
    """The model a Run asks for, or the default, or one more failure to report.

    A name with whitespace in it is no model, and one starting `-` would be read
    by Claude Code as a flag rather than as the value of `--model`.
    """
    value = environment.get(RUN_MODEL_VARIABLE, "").strip()
    if not value:
        return DEFAULT_MODEL
    if value.startswith("-") or any(character.isspace() for character in value):
        failures.append(f"{RUN_MODEL_VARIABLE} is not a model name: {value!r}")
    return value


def _budget(environment: Mapping[str, str], failures: list[str]) -> float | None:
    """The most one Run may spend, None for no cap, or one more failure to report."""
    value = environment.get(RUN_BUDGET_VARIABLE, "").strip()
    if not value:
        return None
    try:
        budget = float(value)
    except ValueError:
        budget = math.nan
    if not (math.isfinite(budget) and budget > 0):
        failures.append(f"{RUN_BUDGET_VARIABLE} is not a positive number of dollars: {value!r}")
        return None
    return budget


def _directory(environment: Mapping[str, str], variable: str, default: Path) -> Path:
    return Path(environment.get(variable, "").strip() or default)


if __name__ == "__main__":
    raise SystemExit(main())
