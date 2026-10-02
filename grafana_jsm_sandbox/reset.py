"""Resetting the demo's project and the traffic before a demo, so the Incidents queue starts empty.

Rehearsals leave Incidents behind. This takes every *open* Incident in the
demo's project that a Run created — the ones carrying a Fingerprint label — out
of the Incidents queue, and starts the synthetic traffic so that Grafana's rule
is Normal when the audience arrives:

    python3 -m grafana_jsm_sandbox.reset [--dry-run]

`--dry-run` reads the same issues and prints what the reset would do, and
changes nothing in Jira or the stack.

It runs on the laptop, like the end-to-end check, and never through a Run. The
project and the Jira credential come from `.env`, the file compose hands the
container, and `jira-as` is started with an environment built from it alone
(`demo_config`), so a shell configured for another site or project changes
nothing. It moves an Incident to the configured done status with a resolution,
then to the configured closed status when there is a close step. The defaults
are Completed and Closed (ADR 0004). The queue is `resolution = Unresolved`,
so reaching done without a resolution does not empty it. An open Incident with
no road to done from where it is, or without a Fingerprint label at all, is a
human's and is reported rather than touched. One left in done without a
resolution is reopened to the configured open status on the next reset and
resolved again, once the Jira admin has fixed the screen or post-function.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from grafana_jsm_sandbox.demo_config import (
    ENV_FILE,
    ConfigurationError,
    DemoProject,
    jira_as_environment,
    read_env_file,
)

OPEN_INCIDENTS = 'project = "{key}" AND issuetype = Incident AND statusCategory != Done'
"""Everything a Run could still act on, whoever opened it. The key is quoted so that one
which is also a JQL word still reads as a key."""

STUCK_INCIDENTS = (
    'project = "{key}" AND issuetype = Incident AND statusCategory = Done'
    ' AND status != "Completed" AND resolution = Unresolved'
)
"""Done by status but still in the Incidents queue, which filters on resolution, with no
transition left that could set one (ADR 0004): Canceled, or Closed without a resolution.
Only deleting them empties the queue."""

UNRESOLVED_COMPLETED = (
    'project = "{key}" AND issuetype = Incident AND status = "Completed"'
    " AND resolution = Unresolved"
)
"""Done by status and still in the queue, but not for good: what a Resolve screen without
the Resolution field leaves behind. Completed has a road back to Open, so these are not
stuck, and telling anyone to delete one would destroy an Incident that can be recovered."""

FINGERPRINT_PREFIX = "fp-"
"""What marks an Incident as a Run's: the label a Run keys it by (ADR 0004)."""

OPEN = "Open"
"""Where `Reopen` lands from Completed, and `Resolve` can leave again."""

COMPLETED = "Completed"
CLOSED = "Closed"
RESOLUTION = "Done"
"""The way out: `Resolve` with this resolution, then `Close`. Never `Cancel`."""

RESET_COMMENT = (
    "Reset before the demo: a rehearsal left this open. Completed and closed by the reset."
)

CLOSE_FAILED_COMMENT = (
    f"The reset could not close this after all: it is {COMPLETED} with resolution"
    f" {RESOLUTION}, and a human has to close it."
)
"""Posted when the Close fails, so the Incident's history does not keep claiming it was
closed. `RESET_COMMENT` comes first because a Closed Incident may take no comment."""

NO_ROAD = f"a Run's, but has no transition to {COMPLETED} from where it is; finish it by hand"
UNRESOLVED = (
    "completed without a resolution: ask your Jira admin to put Resolution on the Resolve screen"
)
NO_ROAD_BACK = (
    f"completed without a resolution, with no transition back to {OPEN};"
    f" reopen it and resolve it with {RESOLUTION} by hand"
)
NOT_CLOSED = f"completed with resolution {RESOLUTION} but not closed ({{why}}); close it by hand"
NOT_A_RUNS = (
    f"completed without a resolution, but without a {FINGERPRINT_PREFIX} label, so not a Run's;"
    f" reopen it and resolve it with {RESOLUTION} by hand"
)
"""Why the reset left an Incident for a human, one sentence per road it could not take."""

TRAFFIC_SERVICE = "traffic"
"""The compose service whose absence fires the Alert. Started last, so the rule goes Normal."""

REPOSITORY = Path(__file__).resolve().parent.parent
"""Where `docker compose` must be run from to find this repo's stack."""

JIRA_AS = "jira-as"

JiraAs = Callable[..., str]
"""`jira_as(*arguments) -> stdout`, with `-o json` passed where a JSON answer is read.
A command jira-as refuses raises `RuntimeError`."""

Compose = Callable[..., None]
"""`compose(*arguments)` runs one `docker compose` command against this repo's stack."""

COMPOSE_FAILURES = (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired)
"""How `docker compose` fails: a non-zero exit, no `docker` on PATH, or no answer in time."""


class _JiraFailure(Exception):
    """An operational failure raised at the Jira adapter boundary."""


@dataclass(frozen=True)
class Outcome:
    """What the reset did, key by key, so the presenter can read the queue off it."""

    closed: list[str] = field(default_factory=list)
    """Taken out of the queue: Completed with a resolution, then Closed. In a dry run, the
    ones that have a road to Completed and would be."""

    left: dict[str, str] = field(default_factory=dict)
    """What the reset could not finish, each with why. A human finishes it."""

    unclosed: list[str] = field(default_factory=list)
    """Of `left`, the ones resolved with Done whose Close failed: out of the queue already,
    so only the Close is a human's."""

    skipped: list[str] = field(default_factory=list)
    """Open without a Fingerprint label, so not a Run's. Not touched."""

    stuck: list[str] = field(default_factory=list)
    """Done without a resolution: in the queue for good unless a human deletes them."""

    traffic_started: bool = False

    traffic_failure: str = ""
    """What `docker compose` said when it could not start the traffic, so the report still
    reaches the presenter with the one command left to run."""

    dry_run: bool = False

    resolved: list[str] = field(default_factory=list)
    """Resolved and left in the done role because this workflow has no close step."""

    status_done: str = COMPLETED

    jira_failure: str = ""
    """The failed Jira phase and diagnostic; the final queue state is unknown."""

    unknown: dict[str, str] = field(default_factory=dict)
    """Discovered Run keys whose current state could not be confirmed after a Jira failure."""

    @property
    def queue_is_empty(self) -> bool:
        return (
            not self.jira_failure
            and not self.unknown
            and not (self.left.keys() - set(self.unclosed))
            and not self.skipped
            and not self.stuck
        )

    @property
    def finished(self) -> bool:
        """The queue is empty and nothing is left for a human, not even a Close."""
        return self.queue_is_empty and not self.left


def reset(
    project_key: str,
    jira_as: JiraAs,
    compose: Compose | None = None,
    dry_run: bool = False,
    project: DemoProject | None = None,
) -> Outcome:
    """Empty the project's Incidents queue of every Run-created Incident, then start the traffic.

    A Run's Incident that an earlier reset left on Completed without a resolution is
    reopened first and taken out the same way. A `dry_run` asks the same questions, and
    whether each Run's Incident has a road out, but moves nothing, comments nothing and
    leaves the traffic as it is.
    """
    project = DemoProject(project_key) if project is None else project
    compose = run_compose if compose is None else compose

    def ask_jira(*arguments: str) -> str:
        try:
            return jira_as(*arguments)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as failure:
            raise _JiraFailure(str(failure)) from failure

    closed: list[str] = []
    resolved: list[str] = []
    left: dict[str, str] = {}
    unclosed: list[str] = []
    skipped: list[str] = []
    stuck: list[str] = []
    runs: list[tuple[str, bool]] = []
    unknown: dict[str, str] = {}
    jira_failure = ""
    traffic_started = False
    traffic_failure = ""
    current_key: str | None = None
    resolution_confirmed = False
    phase = "reading open incidents"
    try:
        # Both searches finish before anything moves. Otherwise a newly unresolved
        # Completed issue could be found again and reopened by this same reset.
        for issue in search(ask_jira, OPEN_INCIDENTS.format(key=project_key)):
            if is_a_runs(issue):
                runs.append((issue["key"], False))
            else:
                skipped.append(issue["key"])
        phase = "reading unresolved incidents"
        unresolved = search(
            ask_jira,
            UNRESOLVED_COMPLETED.replace(f'"{COMPLETED}"', json.dumps(project.status_done)).format(
                key=project_key
            ),
        )
        for issue in unresolved:
            if is_a_runs(issue):
                runs.append((issue["key"], True))
            else:
                left[issue["key"]] = NOT_A_RUNS
        for key, reopen in runs:
            current_key = key
            resolution_confirmed = False
            phase = "checking workflow" if dry_run else "resolving incident"
            if dry_run:
                why = road_out(ask_jira, key, reopen, project)
            elif (why := complete(ask_jira, key, reopen, project)) is None:
                resolution_confirmed = True
                phase = "closing incident" if project.status_closed else "recording resolved incident"
                why = close(ask_jira, key, project)
                if why is not None:
                    unclosed.append(key)
            if why is None:
                (closed if project.status_closed else resolved).append(key)
            else:
                left[key] = why
        current_key = None
        phase = "reading stuck incidents"
        stuck = [
            issue["key"]
            for issue in search(
                ask_jira,
                STUCK_INCIDENTS.replace(f'"{COMPLETED}"', json.dumps(project.status_done)).format(
                    key=project_key
                ),
            )
        ]
    except _JiraFailure as failure:
        jira_failure = f"{phase}: {failure}"
        if current_key is not None:
            confirmed = (
                f"transition to {project.status_done} was acknowledged and a nonempty "
                "resolution was read back; "
                if resolution_confirmed
                else ""
            )
            unknown[current_key] = f"{confirmed}current state is unknown after {phase}: {failure}"
        for key, _ in runs:
            if key not in closed and key not in resolved and key not in left and key not in unknown:
                unknown[key] = "not processed after Jira failure; current state is unknown"
    finally:
        if not dry_run:
            original_failure = sys.exception()
            try:
                compose("start", TRAFFIC_SERVICE)
                traffic_started = True
            except COMPOSE_FAILURES as failure:
                traffic_failure = str(failure)
            except Exception:
                # An unexpected recovery error must not mask the original Jira error.
                if original_failure is None:
                    raise
    return Outcome(
        closed=closed,
        resolved=resolved,
        status_done=project.status_done,
        left=left,
        unclosed=unclosed,
        skipped=skipped,
        stuck=stuck,
        dry_run=dry_run,
        jira_failure=jira_failure,
        unknown=unknown,
        traffic_started=traffic_started,
        traffic_failure=traffic_failure,
    )


def is_a_runs(issue: dict) -> bool:
    """Whether a searched issue carries a Fingerprint label, which only a Run gives it."""
    return any(label.startswith(FINGERPRINT_PREFIX) for label in issue["fields"]["labels"])


def road_out(
    jira_as: JiraAs, key: str, reopen: bool, project: DemoProject | None = None
) -> str | None:
    """What a dry run can tell without moving: whether the first step out exists.

    It cannot tell whether Jira will keep the resolution, or whether Completed has a Close;
    only a real run finds those out.
    """
    project = DemoProject(key="") if project is None else project
    if reopen:
        return (
            None
            if transition_to(jira_as, key, project.status_open) is not None
            else NO_ROAD_BACK.replace(OPEN, project.status_open)
        )
    return (
        None
        if transition_to(jira_as, key, project.status_done) is not None
        else NO_ROAD.replace(COMPLETED, project.status_done)
    )


def complete(
    jira_as: JiraAs, key: str, reopen: bool = False, project: DemoProject | None = None
) -> str | None:
    """Move `key` to Completed with a resolution; None when it holds one, else why it was left.

    Reaching Completed is not proof of a resolution. When the Resolve screen lacks the
    Resolution field, jira-as 2.0.0 retries the transition without it and only warns, so
    the issue is read again before anyone closes it: closed without a resolution, it would
    sit in the Incidents queue for good, where Completed keeps the road back to Open. That
    road is the one `reopen` takes first, for an Incident an earlier reset left there.
    """
    project = DemoProject(key="") if project is None else project
    if reopen and not move_to(jira_as, key, project.status_open):
        return NO_ROAD_BACK.replace(OPEN, project.status_open)
    if not move_to(jira_as, key, project.status_done, resolution=RESOLUTION):
        return NO_ROAD.replace(COMPLETED, project.status_done)
    if resolution_of(jira_as, key) is None:
        return UNRESOLVED
    return None


def close(jira_as: JiraAs, key: str, project: DemoProject | None = None) -> str | None:
    """Close `key`, which is Completed with a resolution; None when done, else why not.

    The comment goes first, because a Closed Incident may take none. A missing Close
    transition gets a correction. An adapter failure propagates: Close may have applied,
    so no further comment or mutation is safe in this reset.
    """
    project = DemoProject(key="") if project is None else project
    if not project.status_closed:
        jira_as(
            "collaborate",
            "comment",
            "add",
            key,
            "-b",
            f"Reset before the demo: resolved and left in {project.status_done}; no close step in this workflow.",
        )
        return None
    jira_as(
        "collaborate",
        "comment",
        "add",
        key,
        "-b",
        RESET_COMMENT.replace(COMPLETED, project.status_done),
    )
    if move_to(jira_as, key, project.status_closed):
        return None
    why = f"no transition to {project.status_closed} from {project.status_done}"
    jira_as(
        "collaborate",
        "comment",
        "add",
        key,
        "-b",
        CLOSE_FAILED_COMMENT.replace(COMPLETED, project.status_done),
    )
    return NOT_CLOSED.format(why=why)


def resolution_of(jira_as: JiraAs, key: str) -> str | None:
    """The name of `key`'s resolution as Jira holds it now, or None when it has none."""
    issue = json.loads(jira_as("issue", "get", key, "--fields", "resolution", "-o", "json"))
    return (issue["fields"].get("resolution") or {}).get("name")


def transition_to(jira_as: JiraAs, key: str, status: str) -> str | None:
    """The id of the transition that lands on `status`, read off the issue; None if there is none."""
    for transition in json.loads(jira_as("lifecycle", "transitions", key, "-o", "json")):
        if transition.get("to", {}).get("name") == status:
            return transition["id"]
    return None


def move_to(jira_as: JiraAs, key: str, status: str, resolution: str | None = None) -> bool:
    """Take the transition that lands on `status`, read off the issue; False if there is none."""
    transition = transition_to(jira_as, key, status)
    if transition is None:
        return False
    arguments = ["lifecycle", "transition", key, "--id", transition]
    if resolution is not None:
        arguments += ["--resolution", resolution]
    jira_as(*arguments)
    return True


def search(jira_as: JiraAs, jql: str) -> list[dict]:
    """Every issue `jql` matches, page after page, all read before the caller changes any.

    `search jql` answers one page of at most 50 with the `nextPageToken` Jira gave it, so
    a project with more is walked token by token. The walk finishes before anything moves,
    because closing an issue takes it out of the open search and shifts what a later page
    of that same search would have held.
    """
    issues: list[dict] = []
    token = None
    while True:
        arguments = ["search", "jql", jql, "--fields", "key,status,labels", "-o", "json"]
        if token:
            arguments += ["--page-token", token]
        page = json.loads(jira_as(*arguments))
        found = page.get("issues", [])
        issues += found
        token = page.get("nextPageToken")
        if page.get("isLast") or not token or not found:
            return issues


def jira_as_with(environment: Mapping[str, str]) -> JiraAs:
    """The real `jira-as`, started with `environment` and nothing of this shell's own.

    `environment` is `demo_config.jira_as_environment`'s: the credential and the
    project from `.env`, which is what keeps the reset on the demo's project.
    """
    environment = dict(environment)

    def run_jira_as(*arguments: str) -> str:
        answer = subprocess.run(
            [JIRA_AS, *arguments],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if answer.returncode != 0:
            raise RuntimeError(f"{JIRA_AS} {' '.join(arguments)} failed: {answer.stderr.strip()}")
        return answer.stdout

    return run_jira_as


def run_compose(*arguments: str) -> None:
    """One `docker compose` command against this repo's stack."""
    subprocess.run(["docker", "compose", *arguments], cwd=REPOSITORY, check=True, timeout=120)


def main(
    argv: list[str] | None = None,
    env_file: Path = ENV_FILE,
    compose: Compose | None = None,
    jira_as: JiraAs | None = None,
) -> int:
    """Reset, and print the report. `jira_as` replaces the real one built from `.env`,
    which is read and checked all the same."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list what the reset would change, and change nothing",
    )
    arguments = parser.parse_args(argv)
    try:
        values = read_env_file(env_file)
        environment = jira_as_environment(values)
        project = DemoProject.from_environment(values)
    except ConfigurationError as failure:
        print(failure, file=sys.stderr)
        return 1
    jira_as = jira_as_with(environment) if jira_as is None else jira_as
    outcome = reset(project.key, jira_as, compose, dry_run=arguments.dry_run, project=project)
    report(outcome)
    if outcome.dry_run:
        return 0 if outcome.finished else 1
    return 0 if outcome.finished and outcome.traffic_started else 1


def report(outcome: Outcome) -> None:
    """One line per key, then the traffic, then whether the queue is (or would be) empty."""
    for key in outcome.closed:
        would = "would be " if outcome.dry_run else ""
        print(f"{key}: {would}completed with resolution {RESOLUTION} and closed")
    for key in outcome.resolved:
        would = "would be " if outcome.dry_run else ""
        print(
            f"{key}: {would}resolved with resolution {RESOLUTION} and left in {outcome.status_done}; no close step in this workflow"
        )
    for key, why in outcome.left.items():
        print(f"{key}: {why}")
    for key, why in outcome.unknown.items():
        print(f"{key}: {why}")
    for key in outcome.skipped:
        print(f"{key}: open without a {FINGERPRINT_PREFIX} label, so not a Run's; left alone")
    for key in outcome.stuck:
        print(
            f"{key}: done without a resolution, so in the Incidents queue for good; "
            f"only `jira-as api call deleteIssue --issueIdOrKey {key} --confirm` removes it, "
            "and deleting is permanent: the Incident and its history cannot be restored"
        )
    if outcome.jira_failure:
        print(f"Jira reset stopped: {outcome.jira_failure}")
    if outcome.dry_run:
        print(f"{TRAFFIC_SERVICE} would be started")
        print("dry run: nothing was changed")
        if outcome.closed or outcome.resolved:
            print("dry run: a Resolve screen that drops the resolution shows only in a real run")
        if outcome.jira_failure or outcome.unknown:
            print("queue state would be unknown")
        else:
            print("queue would be empty" if outcome.queue_is_empty else "queue would NOT be empty")
        return
    if outcome.traffic_started:
        print(f"{TRAFFIC_SERVICE} started")
    else:
        print(f"{TRAFFIC_SERVICE} NOT started: {outcome.traffic_failure}")
        print(f"start the traffic with `docker compose start {TRAFFIC_SERVICE}`")
    if outcome.jira_failure or outcome.unknown:
        print("queue state is unknown")
    elif not outcome.queue_is_empty:
        print("queue is NOT empty")
    elif outcome.left:
        print(f"queue is empty; {len(outcome.left)} left for a human to close")
    else:
        print("queue is empty")


if __name__ == "__main__":
    raise SystemExit(main())
