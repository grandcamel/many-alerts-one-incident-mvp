"""Watching one Incident go through its whole lifecycle on the demo's project, stage by stage.

    python3 -m grafana_jsm_sandbox.verify [--replay | --live] [--receiver URL]
        [--fingerprint FP] [--firing-timeout S] [--repeat-timeout S]
        [--resolved-timeout S] [--run-timeout S]

`doctor` asks whether every part of the demo is there; this asks whether they
work together. It drives one Alert's lifetime and watches the project `.env`
names, by JQL through `jira-as` built from `.env` alone (`demo_config`), until
the Incident the Runs created is Completed, printing each stage with the time it
took and naming the stage that did not come, with its likely cause.

    --replay  (the default) posts the three canned Notifications at the Receiver,
              Firing, repeat and Resolved, each once the Incident has answered the
              one before, so Grafana is not involved. It is the demo's fallback and
              what `tests/test_end_to_end.py` runs.
    --live    stops the traffic, waits for Grafana's rule to fire and the Runs to
              open the Incident and move it to Work in progress on the repeat, then
              starts the traffic again and waits for the Resolved. Whatever happens,
              interrupted or not, it starts the traffic again on the way out, so the
              rule goes back to Normal.

    --mvp     watches the MVP's Incident instead of chapter one's: several related Alerts,
              grouped by Grafana, one Incident keyed by the group and session labels, updated
              and never duplicated (`verify_mvp`, and `docs/mvp-spec.md`'s Proof). It
              takes `--replay` or `--live` like the above, `--session` for the literal session id
              (`.env`'s `DEMO_SESSION_ID` by default) and `--group` for the group's name.

Rehearsals accumulate, so it identifies its own Incident rather than assuming the
project is empty: before it starts, it records which Incidents already carry the
Fingerprint label, and it watches only for one that was not there. It refuses to
start when an *open* Match exists, because the Runs would then comment on that
one instead of creating one, which is the demo working and this command being
asked the wrong question. `reset` closes it.

The Fingerprint is the canned Firing's, and the live Alert's is the same: Grafana
computes it from the Alert's labels, which this repo's provisioning fixes (the
Grafana checks hold the fixtures to them). `--fingerprint` names another, and when
an Incident with another `fp-` label appears while this one does not, the timeout
says which to pass.

Each stage's default timeout comes from the timed rehearsal the runbook's numbers
come from (recorded in the unpublished working notes),
with a wide margin, because a slow stage is not a failed one: Grafana fired about
60s after the traffic stopped, the first repeat's Run started 70s after the first
Run, and the Resolved's Run 19s after the traffic started; a Run took about 30s, and
may take up to `RUN_TIMEOUT` before the Receiver stops it. Each has a flag.

It only reads Jira. It creates, transitions, closes and deletes nothing there
itself, the Runs do, and it leaves the Incident it watched where the Runs left it:
Completed with a resolution is already out of the Incidents queue, and anything
short of that, after a failure, is `python3 -m grafana_jsm_sandbox.reset`'s to take
out. Its last line before the verdict says which.

Every line it prints is one of these, for a person at a terminal and for the
setup skill to parse:

    [+<seconds>s] WAIT <stage> — <what it is waiting for, and for how long at most>
    [+<seconds>s] OK <stage> — <what happened, and how long it took>
    [+<seconds>s] WARN <stage> — <what is off, which does not stop the verdict>
    [+<seconds>s] FAIL <stage> — <what did not happen, and the likely cause>[; ask: docs/admin-requests.md#<anchor>]
    [+<seconds>s] NOTE cleanup — <where the Incident was left, and what takes it out of the queue>
    VERIFIED: <key> Open → Work in progress → Completed with resolution <name> in <seconds>s
    NOT VERIFIED: <stage> — <what the first FAIL said>

The seconds are since the command started. The stages, in order, are
`preflight`, then for `--live` `traffic stopped` and `firing`, or for `--replay`
`posted` before each Run's stage, then `created`, `commented`, `work in
progress`, for `--live` `traffic started` and `normal`, and `completed`; the
cleanup note comes last, and NOT VERIFIED names `interrupted` after a Ctrl-C.
A FAIL ends the watch, and NOT VERIFIED repeats the first FAIL's stage and text. The
only stage lines that may come between a FAIL (or a Ctrl-C) and the cleanup note are
`--live`'s start of the traffic on the way out: a `WAIT traffic started` saying how to
start it by hand, then its OK, or a second FAIL when compose refused.

The exit status is 0 when it ends VERIFIED, 1 when it ends NOT VERIFIED, 130 when
interrupted (a Ctrl-C before the watch began prints only its NOT VERIFIED line), and
2 for a usage or configuration error before anything was asked, or a Python older
than 3.11.
"""

from __future__ import annotations

import sys

# Checked before anything else is imported, so an older python3 gets a sentence rather than a
# traceback from some later syntax. Everything below this line is only compiled on it.
if sys.version_info < (3, 11):  # noqa: UP036 - pyproject's floor is what this enforces
    sys.stderr.write(
        "python3 -m grafana_jsm_sandbox.verify needs Python 3.11 or newer, and this is "
        + sys.version.split()[0]
        + ": run it with a newer python3 (README, What you need)\n"
    )
    raise SystemExit(2)

import argparse
import json
import math
import re
import subprocess
import time
import urllib.error
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from grafana_jsm_sandbox.__main__ import RUN_TIMEOUT_VARIABLE
from grafana_jsm_sandbox.configure import (
    ADMIN_REQUESTS,
    RESOLUTION_SCREEN,
    WORK_IN_PROGRESS,
    one_line,
)
from grafana_jsm_sandbox.demo_config import (
    ENV_FILE,
    ConfigurationError,
    DemoProject,
    compose_environment,
    jira_as_environment,
    read_env_file,
)
from grafana_jsm_sandbox.doctor import (
    DEFAULT_GRAFANA_HOST_PORT,
    GRAFANA_HOST_PORT_VARIABLE,
    RULE_UID,
    GrafanaUnanswered,
    ask_grafana,
    rule_states,
    said,
)
from grafana_jsm_sandbox.replay import FIXTURES, SEQUENCE, default_receiver, laptop_url, post
from grafana_jsm_sandbox.reset import (
    COMPLETED,
    COMPOSE_FAILURES,
    FINGERPRINT_PREFIX,
    OPEN,
    REPOSITORY,
    RESOLUTION,
    TRAFFIC_SERVICE,
    Compose,
    JiraAs,
    jira_as_with,
    search,
)
from grafana_jsm_sandbox.run_spawner import RUN_TIMEOUT

COMMAND = "python3 -m grafana_jsm_sandbox.verify"

REPLAY = "replay"
LIVE = "live"

SESSION_ID_VARIABLE = "DEMO_SESSION_ID"
"""The `.env` name the Receiver renders the MVP's session label from (`--mvp`)."""

INCIDENT_GROUP = "checkout-outage"
"""The demo's `incident_group`, behind the MVP's group label (`--mvp`)."""

WAIT = "WAIT"
OK = "OK"
WARN = "WARN"
FAIL = "FAIL"
NOTE = "NOTE"
"""A line's level. Only FAIL ends the watch; WAIT says a stage has begun and how long it gets."""

PREFLIGHT = "preflight"
TRAFFIC_STOPPED = "traffic stopped"
FIRING = "firing"
POSTED = "posted"
CREATED = "created"
COMMENTED = "commented"
WORK_IN_PROGRESS_STAGE = "work in progress"
TRAFFIC_STARTED = "traffic started"
NORMAL = "normal"
COMPLETED_STAGE = "completed"
CLEANUP = "cleanup"
INTERRUPTED = "interrupted"
"""The stages, as the lines name them."""

FIRING_TIMEOUT = 180.0
"""Seconds from stopping the traffic to Grafana's rule Firing. Measured: about 60 (the rate
window empties, the thirty-second pending period, the next ten-second evaluation)."""

REPEAT_TIMEOUT = 180.0
"""Seconds Grafana may take to send the repeat, counted from the Incident's creation. Measured:
the repeat's Run started 70s after the first Run did, the policy's one-minute repeat plus a
group interval."""

RESOLVED_TIMEOUT = 120.0
"""Seconds from starting the traffic to Grafana's rule Normal again. Measured: 15, and the
Resolved's Run started 19s after the traffic did."""

RUN_MARGIN = 60.0
"""Seconds a Run's stage gets beyond `RUN_TIMEOUT`: Grafana's group wait before the first
Notification (up to 30s) and Jira's search index, which lags a change by ten to twenty."""

POLL = 5.0
"""Seconds between looks at the project and at Grafana, which are not to be hammered."""

JIRA_AS_FAILURES_TOLERATED = 3
"""Failed `jira-as` calls in a row a watch rides out, a network blip being no verdict. More is
a credential or a site that is not answering, which waiting out a stage would only hide."""

JIRA_AS_FAILURES = (RuntimeError, ValueError, OSError, subprocess.SubprocessError)
"""What a `jira-as` call can raise: a refusal (`RuntimeError`), an answer that is not the JSON
asked for (`ValueError`), no `jira-as` on PATH (`FileNotFoundError`), and no answer within
`reset.jira_as_with`'s timeout (`subprocess.TimeoutExpired`). Each must end as a FAIL line,
never a traceback, because the setup skill reads the lines."""

LABELLED = 'project = "{key}" AND issuetype = Incident AND labels = "{label}"'
"""Every Incident ever created for this Fingerprint, in any status."""

MATCH = LABELLED + " AND statusCategory != Done"
"""The Match as a Run defines it (ADR 0004): the one *open* Incident for a Fingerprint."""

RECENT = 'project = "{key}" AND issuetype = Incident AND created >= "-{minutes}m"'
"""What the project gained while this ran, to spot a Run's Incident under another label."""

LOGS = "check `docker compose logs demo` for [FAILED]"
"""Where a Run that did not do its part says why, with a `[hint]` for the known causes."""

RESET = "python3 -m grafana_jsm_sandbox.reset"
DOCTOR = "python3 -m grafana_jsm_sandbox.doctor"

TRAFFIC_BACK = f"start it with `docker compose start {TRAFFIC_SERVICE}`"

Post = Callable[[str, bytes], int]
"""`post(url, notification) -> status`, as `replay.post` sends one Notification."""

GrafanaState = Callable[[], "str | None"]
"""`state() -> str | None`: the rule's state as Grafana last evaluated it (`inactive`, `pending`
or `firing`), None before its first evaluation. Raises `GrafanaUnanswered`."""


@dataclass(frozen=True)
class Timeouts:
    """How long each stage may take, in seconds, before it is named as the one that did not come."""

    firing: float = FIRING_TIMEOUT
    repeat: float = REPEAT_TIMEOUT
    resolved: float = RESOLVED_TIMEOUT
    run: float = RUN_TIMEOUT + RUN_MARGIN


@dataclass
class World:
    """Everything the watch asks of the world, each replaceable in a test."""

    jira_as: JiraAs
    compose: Compose
    post: Post
    grafana_state: GrafanaState
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    out: Callable[[str], None] = print
    grafana_alerts: Callable[[], object] = list


@dataclass(frozen=True)
class Incident:
    """An Incident as the watch reads it: where it got to, and how much it said."""

    key: str
    status: str
    resolution: str | None
    comments: int


class NotVerified(Exception):
    """A stage failed; its FAIL line is already printed."""

    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage} — {message}")
        self.stage = stage
        self.message = message


class Watch:
    """One verification: the clock it prints against, and what it has learned so far."""

    def __init__(self, world: World, key: str, label: str, timeouts: Timeouts):
        self.world = world
        self.key = key
        self.label = label
        self.timeouts = timeouts
        self.started = world.now()
        self.before: set[str] = set()
        self.incident: Incident | None = None
        self.preflight_passed = False
        self.traffic_started = False
        self.jira_as_failures = 0
        self.last_jira_as_failure = ""

    def elapsed(self, since: float | None = None) -> int:
        return round(self.world.now() - (self.started if since is None else since))

    def line(self, level: str, stage: str, message: str, ask: tuple[str, ...] = ()) -> None:
        text = f"[+{self.elapsed()}s] {level} {stage} — {one_line(message)}"
        if ask:
            text += "; ask: " + " ".join(f"{ADMIN_REQUESTS}#{anchor}" for anchor in ask)
        self.world.out(text)

    def fail(self, stage: str, message: str, ask: tuple[str, ...] = ()) -> NotVerified:
        """Print the FAIL line; the caller raises what this returns."""
        self.line(FAIL, stage, message, ask)
        return NotVerified(stage, one_line(message))

    def wait_for(
        self,
        stage: str,
        deadline: float,
        look: Callable[[], object],
        timed_out: Callable[[], str],
    ):
        """Look until `look` gives something other than None, or the deadline passes.

        The last look is made at or after the deadline, so a stage that lands during the
        final pause still counts. A `jira-as` call that fails, or answers something other
        than JSON, is ridden out a few times in a row, then ends the stage, because a
        refused credential never comes right.
        """
        while True:
            try:
                found = look()
            except FileNotFoundError:
                raise self.fail(stage, NO_JIRA_AS) from None
            except JIRA_AS_FAILURES as failure:
                self.jira_as_failures += 1
                self.last_jira_as_failure = jira_as_said(failure)
                if self.jira_as_failures >= JIRA_AS_FAILURES_TOLERATED:
                    raise self.fail(
                        stage,
                        f"jira-as failed {self.jira_as_failures} times in a row, last: "
                        f"{self.last_jira_as_failure}: `{DOCTOR} --only env,jira` says why",
                    ) from None
                found = None
            else:
                self.jira_as_failures = 0
            if found is not None:
                return found
            if self.world.now() >= deadline:
                raise self.fail(stage, timed_out())
            self.world.sleep(POLL)

    # --- Jira, read only ---

    def labelled(self) -> set[str]:
        """Every Incident carrying the Fingerprint label, however it ended."""
        jql = LABELLED.format(key=self.key, label=self.label)
        return {issue["key"] for issue in search(self.world.jira_as, jql)}

    def open_matches(self) -> list[str]:
        jql = MATCH.format(key=self.key, label=self.label)
        return [issue["key"] for issue in search(self.world.jira_as, jql)]

    def new_incidents(self) -> list[str]:
        """This run's Incidents: carrying the label now, and not before it started."""
        return sorted(self.labelled() - self.before, key=issue_number)

    def read(self, key: str) -> Incident:
        """`key`'s status, resolution and comment count. JSON of another shape than these
        calls give is a `ValueError`, ridden out like any other bad answer."""
        jira_as = self.world.jira_as
        issue = json.loads(
            jira_as("issue", "get", key, "--fields", "status,resolution", "-o", "json")
        )
        comments = json.loads(jira_as("collaborate", "comment", "list", key, "-o", "json"))
        try:
            fields = issue["fields"]
            incident = Incident(
                key=key,
                status=fields["status"]["name"],
                resolution=(fields.get("resolution") or {}).get("name"),
                comments=int(comments.get("total", 0)),
            )
        except (KeyError, TypeError, AttributeError) as failure:
            raise ValueError(
                f"jira-as answered {key} in an unexpected shape ({failure!r})"
            ) from None
        self.incident = incident
        return incident

    def elsewhere(self) -> list[tuple[str, str]]:
        """Incidents created while this ran that carry another Fingerprint label, and which."""
        minutes = math.ceil((self.world.now() - self.started) / 60) + 1
        jql = RECENT.format(key=self.key, minutes=minutes)
        try:
            issues = search(self.world.jira_as, jql)
        except JIRA_AS_FAILURES:
            return []
        found = []
        for issue in issues:
            labels = [
                label
                for label in issue["fields"].get("labels", [])
                if label.startswith(FINGERPRINT_PREFIX) and label != self.label
            ]
            if labels and issue["key"] not in self.before:
                found.append((issue["key"], labels[0]))
        return found


NO_JIRA_AS = (
    "jira-as is not on PATH: install the Jira Assistant CLI 2.x (README, What you need); "
    f"`{DOCTOR} --only host` checks it"
)


def jira_as_said(failure: Exception) -> str:
    """A failed `jira-as` call in a few redacted words: a timeout says so, rather than
    `subprocess`'s own sentence, which repeats the whole command."""
    if isinstance(failure, subprocess.TimeoutExpired):
        return f"no answer within {failure.timeout:g}s"
    return said(str(failure))


def issue_number(key: str) -> tuple[int, str]:
    """`OPS-9` before `OPS-10`, as Jira numbers them."""
    number = key.rpartition("-")[2]
    return (int(number), key) if number.isdigit() else (0, key)


def fingerprint_label(fingerprint: str | None = None) -> str:
    """The label the Runs key their Incident by: the canned Firing's Fingerprint, or `fingerprint`."""
    if fingerprint is None:
        firing = json.loads((FIXTURES / SEQUENCE[0]).read_text())
        fingerprint = firing["alerts"][0]["fingerprint"]
    return FINGERPRINT_PREFIX + fingerprint.removeprefix(FINGERPRINT_PREFIX)


# --- The stages ---


def preflight(watch: Watch, mode: str) -> None:
    """No open Match, the Incidents already labelled noted, and Grafana quiet."""
    try:
        matches = watch.open_matches()
        watch.before = watch.labelled()
    except FileNotFoundError:
        raise watch.fail(PREFLIGHT, NO_JIRA_AS) from None
    except JIRA_AS_FAILURES as failure:
        raise watch.fail(
            PREFLIGHT,
            f"jira-as could not search {watch.key}: {jira_as_said(failure)}: "
            f"`{DOCTOR} --only env,jira` says why",
        ) from None
    if matches:
        raise watch.fail(
            PREFLIGHT,
            f"{', '.join(matches)} is open and already carries {watch.label}, so the Runs "
            f"would comment on it instead of creating one: `{RESET}` takes it out first",
        )
    try:
        state = watch.world.grafana_state()
    except GrafanaUnanswered as failure:
        if mode == LIVE:
            raise watch.fail(
                PREFLIGHT,
                f"Grafana did not answer ({failure}), and --live watches its rule: "
                f"`{DOCTOR} --only grafana`, or verify with --replay",
            ) from None
        state = None
        watch.line(
            WARN,
            PREFLIGHT,
            f"Grafana did not answer ({failure}), so whether its rule is Firing is not known: "
            "a Firing rule's Notifications would interleave with the replay's",
        )
    else:
        if state is None and mode == LIVE:
            raise watch.fail(
                PREFLIGHT,
                f"Grafana has not evaluated {RULE_UID} yet: wait a minute after "
                "`docker compose up -d` and run this again",
            )
        if state not in (None, "inactive"):
            raise watch.fail(
                PREFLIGHT,
                f"Grafana's rule {RULE_UID} is {state}, not Normal, so its Notifications would "
                f"land in the middle of this: `docker compose start {TRAFFIC_SERVICE}` (or "
                f"`{RESET}`) and wait for Normal",
            )
    earlier = sorted(watch.before, key=issue_number)
    shown = f" ({', '.join(earlier[:5])}{', ...' if len(earlier) > 5 else ''})" if earlier else ""
    grafana = f"; Grafana's rule {RULE_UID} is Normal" if state == "inactive" else ""
    watch.line(
        OK,
        PREFLIGHT,
        f"no open Incident in {watch.key} carries {watch.label}; {len(earlier)} earlier "
        f"one(s){shown} are not this run's{grafana}",
    )
    watch.preflight_passed = True


def post_notification(watch: Watch, receiver: str, filename: str) -> float:
    """Post one canned Notification; when it was accepted."""
    url = receiver.rstrip("/") + "/notification"
    try:
        status = watch.world.post(url, (FIXTURES / filename).read_bytes())
    except (urllib.error.URLError, OSError) as failure:
        reason = getattr(failure, "reason", failure)
        raise watch.fail(
            POSTED,
            f"nothing answered at {receiver} ({reason}): is the stack up? `docker compose ps`, "
            f"then `{DOCTOR}`",
        ) from None
    if status != 202:
        raise watch.fail(
            POSTED,
            f"the Receiver at {receiver} answered {filename} with {status}, not 202: "
            "`docker compose logs demo` says why it refused it",
        )
    watch.line(OK, POSTED, f"{filename}: the Receiver at {receiver} accepted it (202)")
    return watch.world.now()


def grafana_reaches(
    watch: Watch, stage: str, wanted: str, since: float, timeout: float, cause: str
) -> float:
    """Wait for Grafana's rule to be `wanted`; when it was seen so."""
    seen: dict[str, str] = {}

    def look() -> bool | None:
        try:
            state = watch.world.grafana_state()
        except GrafanaUnanswered as failure:
            seen["state"] = f"not answering ({failure})"
            return None
        seen["state"] = str(state)
        return True if state == wanted else None

    shown = "Normal" if wanted == "inactive" else wanted.capitalize()
    watch.line(WAIT, stage, f"up to {timeout:.0f}s for Grafana's rule {RULE_UID} to be {shown}")
    watch.wait_for(
        stage,
        since + timeout,
        look,
        lambda: (
            f"Grafana's rule {RULE_UID} is still {seen.get('state', 'unknown')} "
            f"{watch.elapsed(since)}s after {cause}"
        ),
    )
    return watch.world.now()


def created(watch: Watch, since: float, after: str) -> Incident:
    """Wait for an Incident this run's Runs created, and its opening comment."""
    timeout = watch.timeouts.run
    watch.line(
        WAIT,
        CREATED,
        f"up to {timeout:.0f}s for a Run to create an Incident carrying {watch.label}",
    )
    extra: dict[str, list[str]] = {}

    def look() -> Incident | None:
        # Read here rather than after the wait, so a failed read is ridden out like a search.
        found = watch.new_incidents()
        if len(found) > 1:
            extra["keys"] = found
        return watch.read(found[0]) if found else None

    def timed_out() -> str:
        message = f"no Incident within {watch.elapsed(since)}s of {after}: {LOGS}"
        others = watch.elsewhere()
        if others:
            key, label = others[0]
            message += (
                f"; {key} was created meanwhile with {label} instead: if that is this Alert, "
                f"run again with --fingerprint {label.removeprefix(FINGERPRINT_PREFIX)}"
            )
        return message

    incident = watch.wait_for(CREATED, since + timeout, look, timed_out)
    key = incident.key
    watch.line(OK, CREATED, f"{key} ({incident.status}), {watch.elapsed(since)}s after {after}")
    if extra.get("keys"):
        watch.line(
            WARN,
            CREATED,
            f"{', '.join(extra['keys'])} all carry {watch.label}: a Run missed the Match and "
            f"created a second Incident; watching {key}",
        )
    if incident.comments:
        watch.line(OK, COMMENTED, f"{key} has its opening comment")
        return incident

    def commented() -> Incident | None:
        incident = watch.read(key)
        return incident if incident.comments else None

    incident = watch.wait_for(
        COMMENTED,
        since + timeout,
        commented,
        lambda: (
            f"{key} has no comment {watch.elapsed(since)}s after {after}: the Run stopped "
            f"after the create; {LOGS}"
        ),
    )
    watch.line(
        OK, COMMENTED, f"{key} has its opening comment, {watch.elapsed(since)}s after {after}"
    )
    return incident


def moved_on(watch: Watch, key: str, since: float, timeout: float, after: str, cause: str) -> None:
    """Wait for the repeat's Run to move `key` to Work in progress with a trend comment."""
    watch.line(
        WAIT,
        WORK_IN_PROGRESS_STAGE,
        f"up to {timeout:.0f}s for the repeat's Run to comment a trend on {key} and move it to "
        f"{WORK_IN_PROGRESS}",
    )

    def look() -> Incident | None:
        incident = watch.read(key)
        if incident.status not in (OPEN, WORK_IN_PROGRESS):
            raise watch.fail(
                WORK_IN_PROGRESS_STAGE,
                f"{key} went to {incident.status} instead of {WORK_IN_PROGRESS}: a Run took it "
                f"off the demo's path; {LOGS}",
            )
        if incident.status == WORK_IN_PROGRESS and incident.comments >= 2:
            return incident
        return None

    def timed_out() -> str:
        seen = watch.incident
        where = f"still {seen.status} with {seen.comments} comment(s)" if seen else "unread"
        return f"{key} is {where} {watch.elapsed(since)}s after {after}: {cause}"

    watch.wait_for(WORK_IN_PROGRESS_STAGE, since + timeout, look, timed_out)
    watch.line(
        OK,
        WORK_IN_PROGRESS_STAGE,
        f"{key} is {WORK_IN_PROGRESS} with a trend comment, {watch.elapsed(since)}s after {after}",
    )


def completed(watch: Watch, key: str, since: float, after: str) -> Incident:
    """Wait for the Resolved's Run to complete `key`, and hold it to having a resolution."""
    timeout = watch.timeouts.run
    watch.line(
        WAIT, COMPLETED_STAGE, f"up to {timeout:.0f}s for the Resolved's Run to complete {key}"
    )

    def look() -> Incident | None:
        incident = watch.read(key)
        if incident.status == COMPLETED:
            return incident
        if incident.status not in (OPEN, WORK_IN_PROGRESS):
            raise watch.fail(
                COMPLETED_STAGE,
                f"{key} went to {incident.status} instead of {COMPLETED}: a Run took it off the "
                f"demo's path; {LOGS}",
            )
        return None

    incident = watch.wait_for(
        COMPLETED_STAGE,
        since + timeout,
        look,
        lambda: (
            f"{key} is still {watch.incident.status if watch.incident else 'unread'} "
            f"{watch.elapsed(since)}s after {after}: the Resolved's Run failed or never came; {LOGS}"
        ),
    )
    if incident.resolution is None:
        raise watch.fail(
            COMPLETED_STAGE,
            f"{key} is {COMPLETED} without a resolution: the Resolve screen dropped it, so the "
            "Incident stays in the Incidents queue, and closing it would leave it there for good",
            (RESOLUTION_SCREEN,),
        )
    watch.line(
        OK,
        COMPLETED_STAGE,
        f"{key} is {COMPLETED} with resolution {incident.resolution}, "
        f"{watch.elapsed(since)}s after {after}",
    )
    if incident.resolution != RESOLUTION:
        watch.line(
            WARN,
            COMPLETED_STAGE,
            f"the resolution is {incident.resolution}, not {RESOLUTION}, which the Skill sets",
        )
    if incident.comments < 3:
        watch.line(
            WARN,
            COMPLETED_STAGE,
            f"{key} has {incident.comments} comment(s), not the opening, trend and closing three: "
            f"the Resolved's Run completed it without its closing comment; {LOGS}",
        )
    return incident


# --- The two ways through ---


def replayed(watch: Watch, receiver: str) -> Incident:
    """The canned Notifications, each posted once the Incident has answered the one before."""
    firing, repeat, resolved = SEQUENCE
    posted = post_notification(watch, receiver, firing)
    incident = created(watch, posted, "posting the Firing")
    posted = post_notification(watch, receiver, repeat)
    moved_on(
        watch,
        incident.key,
        posted,
        watch.timeouts.run,
        "posting the repeat",
        f"its Run failed or never ran; {LOGS}",
    )
    posted = post_notification(watch, receiver, resolved)
    return completed(watch, incident.key, posted, "posting the Resolved")


def live(watch: Watch) -> Incident:
    """The real Alert: stop the traffic, and start it again on the way out, whatever happens."""
    compose = watch.world.compose
    stopped = watch.world.now()
    attempted = False
    try:
        try:
            compose("stop", TRAFFIC_SERVICE)
        except COMPOSE_FAILURES as failure:
            raise watch.fail(
                TRAFFIC_STOPPED,
                f"`docker compose stop {TRAFFIC_SERVICE}` failed: {said(str(failure))}",
            ) from None
        watch.line(OK, TRAFFIC_STOPPED, f"`docker compose stop {TRAFFIC_SERVICE}`")
        timeouts = watch.timeouts
        firing = grafana_reaches(
            watch,
            FIRING,
            "firing",
            stopped,
            timeouts.firing,
            "the traffic stopped: is it really stopped (`docker compose ps "
            f"{TRAFFIC_SERVICE}`), and does the rule's query match a series "
            f"(`{DOCTOR} --only grafana`)?",
        )
        watch.line(
            OK, FIRING, f"Grafana's rule is Firing, {watch.elapsed(stopped)}s after the stop"
        )
        incident = created(watch, firing, "the Firing")
        moved_on(
            watch,
            incident.key,
            watch.world.now(),
            timeouts.repeat + timeouts.run,
            "it was created",
            "Grafana repeats a Firing every minute, so either the repeat never came "
            f"(`{DOCTOR} --only grafana`) or its Run failed; {LOGS}",
        )
        restarted = start_traffic(watch)
        attempted = True
        if isinstance(restarted, NotVerified):
            raise restarted
        normal = grafana_reaches(
            watch,
            NORMAL,
            "inactive",
            restarted,
            timeouts.resolved,
            f"the traffic started: is it running (`docker compose ps {TRAFFIC_SERVICE}`)?",
        )
        watch.line(
            OK, NORMAL, f"Grafana's rule is Normal, {watch.elapsed(restarted)}s after the start"
        )
        return completed(watch, incident.key, normal, "Grafana went Normal")
    finally:
        # Also on a failure or an interruption, and whether or not the stop went through,
        # so the rule goes back to Normal and the next take starts clean. The way to do it by
        # hand is on screen first, in case a second Ctrl-C cuts the start short.
        if not attempted:
            watch.line(
                WAIT,
                TRAFFIC_STARTED,
                f"starting the traffic again on the way out; should this be cut short, "
                f"{TRAFFIC_BACK}",
            )
            start_traffic(watch)


def start_traffic(watch: Watch) -> float | NotVerified:
    """Start the traffic and say so; when it started, or, when compose failed, the failure for
    the caller to raise, its FAIL line printed. Never raises for compose, because it also runs
    on the way out of a failure that must still be reported."""
    try:
        watch.world.compose("start", TRAFFIC_SERVICE)
    except COMPOSE_FAILURES as failure:
        return watch.fail(
            TRAFFIC_STARTED,
            f"`docker compose start {TRAFFIC_SERVICE}` failed: {said(str(failure))}; "
            f"{TRAFFIC_BACK}",
        )
    watch.traffic_started = True
    watch.line(OK, TRAFFIC_STARTED, f"`docker compose start {TRAFFIC_SERVICE}`")
    return watch.world.now()


def cleanup_note(watch: Watch) -> None:
    """Where the Incident was left, and what takes it out of the queue, since verify never does."""
    if not watch.preflight_passed:
        return
    incident = watch.incident
    if incident is None:
        watch.line(
            NOTE,
            CLEANUP,
            "no Incident of this run was seen; should one appear later, "
            f"`{RESET}` takes it out of the queue (verify closes and deletes nothing)",
        )
    elif incident.status == COMPLETED and incident.resolution is not None:
        watch.line(
            NOTE,
            CLEANUP,
            f"{incident.key} is left {COMPLETED} with resolution {incident.resolution}, already out "
            "of the Incidents queue; verify closes and deletes nothing",
        )
    else:
        message = (
            f"{incident.key} is left {incident.status}: `{RESET}` takes it out of the queue "
            "(verify closes and deletes nothing)"
        )
        if watch.traffic_started:
            # The rule goes Normal after verify has gone, and the Resolved's Run may yet
            # complete the Incident, so what this says can be out of date by then.
            message += (
                "; with the traffic running again, the Resolved's Run may still complete it: "
                f"`{RESET} --dry-run` shows what is left"
            )
        watch.line(NOTE, CLEANUP, message)


def verify(
    mode: str,
    project_key: str,
    world: World,
    receiver: str | None = None,
    fingerprint: str | None = None,
    timeouts: Timeouts | None = None,
) -> int:
    """Watch one lifecycle and print the verdict; the exit status `main` returns.

    An interruption is reported like a failure, after `live` has started the traffic
    again, and then exits 130 as an interrupted command does.
    """
    watch = Watch(world, project_key, fingerprint_label(fingerprint), timeouts or Timeouts())
    try:
        preflight(watch, mode)
        if mode == LIVE:
            incident = live(watch)
        else:
            incident = replayed(watch, default_receiver() if receiver is None else receiver)
    except NotVerified as failure:
        cleanup_note(watch)
        world.out(f"NOT VERIFIED: {failure.stage} — {failure.message}")
        return 1
    except KeyboardInterrupt:
        cleanup_note(watch)
        world.out(f"NOT VERIFIED: {INTERRUPTED} — stopped by the user after {watch.elapsed()}s")
        return 130
    cleanup_note(watch)
    world.out(
        f"VERIFIED: {incident.key} {OPEN} → {WORK_IN_PROGRESS} → {COMPLETED} with resolution "
        f"{incident.resolution} in {watch.elapsed()}s"
    )
    return 0


# --- The real world ---


class ComposeFailed(subprocess.CalledProcessError):
    """`docker compose` exited non-zero; its message is what compose said, not only the status."""

    def __str__(self) -> str:
        return f"exit {self.returncode}: {(self.stderr or '').strip() or 'compose said nothing'}"


def run_compose(*arguments: str) -> None:
    """One `docker compose` command against this repo's stack, its chatter kept off the lines.

    Compose reports progress on stderr, which would land between the lines the setup
    skill reads; what it said is kept for the error when it fails.
    """
    done = subprocess.run(
        ["docker", "compose", *arguments],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
        check=False,
    )
    if done.returncode != 0:
        raise ComposeFailed(done.returncode, done.args, done.stdout, done.stderr)


def grafana_state_at(base: str) -> GrafanaState:
    """The rule's state as the laptop's Grafana reports it, on the port compose published."""

    def state() -> str | None:
        states = rule_states(base, RULE_UID)
        return ", ".join(states) if states else None

    return state


def grafana_alerts_at(base: str) -> Callable[[], object]:
    """Alertmanager's active Alerts, including the fingerprints sent in webhooks."""
    return lambda: ask_grafana(base, "/api/alertmanager/grafana/api/v2/alerts")


def run_timeout_from(values: Mapping[str, str]) -> float:
    """The Receiver's own limit on a Run, as `.env` sets it for the container."""
    raw = values.get(RUN_TIMEOUT_VARIABLE, "").strip()
    if not raw:
        return RUN_TIMEOUT
    try:
        seconds = float(raw)
    except ValueError:
        seconds = math.nan
    if not seconds > 0 or math.isinf(seconds):
        raise ConfigurationError(
            f"{RUN_TIMEOUT_VARIABLE} in .env is not a number of seconds: {raw!r}"
        )
    return seconds


def positive(text: str) -> float:
    try:
        seconds = float(text)
    except ValueError:
        seconds = math.nan
    if not seconds > 0 or math.isinf(seconds):
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text!r}")
    return seconds


FINGERPRINT = re.compile(r"(?:fp-)?[0-9a-f]{1,64}")
"""A Grafana Fingerprint, hex, with or without the label's prefix."""


def fingerprint_argument(text: str) -> str:
    if not FINGERPRINT.fullmatch(text):
        raise argparse.ArgumentTypeError(
            f"not a Fingerprint (hex, as in fp-87e2f184874a3b71): {text!r}"
        )
    return text


def main(
    argv: list[str] | None = None,
    env_file: Path = ENV_FILE,
    world: World | None = None,
) -> int:
    """Verify, and print each stage. `world` replaces every outside party; `.env` is read and
    checked all the same."""
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        description=__doc__.splitlines()[0],
        epilog=(
            "exit status: 0 VERIFIED; 1 NOT VERIFIED; 130 interrupted; 2 bad arguments, a "
            "configuration error, or a Python older than 3.11. verify never closes or deletes "
            f"an Incident: `{RESET}` takes a leftover out of the queue"
        ),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--replay",
        dest="mode",
        action="store_const",
        const=REPLAY,
        help="post the canned Notifications at the Receiver (the default)",
    )
    modes.add_argument(
        "--live",
        dest="mode",
        action="store_const",
        const=LIVE,
        help="stop the traffic and watch the real Alert; the traffic is started again on the way out",
    )
    parser.add_argument(
        "--mvp",
        action="store_true",
        help=(
            "watch the MVP's one Incident for a group of related Alerts (grp- and ses- labels, "
            "updated and never duplicated) instead of chapter one's single Alert"
        ),
    )
    parser.add_argument(
        "--session",
        metavar="ID",
        help=(
            "--mvp: the literal session id, not a label; ses- is added to it "
            f"(default: {SESSION_ID_VARIABLE} from .env)"
        ),
    )
    parser.add_argument(
        "--group",
        default=INCIDENT_GROUP,
        metavar="NAME",
        help=f"--mvp: the incident_group behind the grp- label (default {INCIDENT_GROUP})",
    )
    parser.add_argument(
        "--receiver",
        help="--replay only: the Receiver's base URL; by default where compose publishes it here",
    )
    parser.add_argument(
        "--fingerprint",
        type=fingerprint_argument,
        help="the Alert's Fingerprint, when it is not the canned Firing's",
    )
    parser.add_argument(
        "--firing-timeout",
        type=positive,
        default=FIRING_TIMEOUT,
        metavar="S",
        help=f"--live: seconds from the stop to Grafana Firing (default {FIRING_TIMEOUT:.0f})",
    )
    parser.add_argument(
        "--repeat-timeout",
        type=positive,
        default=REPEAT_TIMEOUT,
        metavar="S",
        help=f"--live: seconds Grafana may take to send the repeat (default {REPEAT_TIMEOUT:.0f})",
    )
    parser.add_argument(
        "--resolved-timeout",
        type=positive,
        default=RESOLVED_TIMEOUT,
        metavar="S",
        help=(f"--live: seconds from the start to Grafana Normal (default {RESOLVED_TIMEOUT:.0f})"),
    )
    parser.add_argument(
        "--run-timeout",
        type=positive,
        metavar="S",
        help=(
            f"seconds each Run's stage may take in all (default: {RUN_TIMEOUT_VARIABLE} from "
            f".env, or {RUN_TIMEOUT:.0f}, plus {RUN_MARGIN:.0f})"
        ),
    )
    arguments = parser.parse_args(argv)
    mode = arguments.mode or REPLAY
    if arguments.receiver and mode == LIVE:
        parser.error("--receiver is for --replay: --live posts nothing, Grafana does")
    if arguments.session is not None and not arguments.mvp:
        parser.error("--session is for --mvp: only the MVP's Incident carries a session label")
    if arguments.group != INCIDENT_GROUP and not arguments.mvp:
        parser.error("--group is for --mvp: only the MVP's Incident carries a group label")
    try:
        values = read_env_file(env_file)
        environment = jira_as_environment(values)
        project = DemoProject.from_environment(values)
        session = session_from(values, arguments.session) if arguments.mvp else None
        run_timeout = arguments.run_timeout or run_timeout_from(values) + RUN_MARGIN
        if world is None:
            published = compose_environment(env_file)
            grafana_base = laptop_url(
                GRAFANA_HOST_PORT_VARIABLE, DEFAULT_GRAFANA_HOST_PORT, published
            )
            world = World(
                jira_as=jira_as_with(environment),
                compose=run_compose,
                post=post,
                grafana_state=grafana_state_at(grafana_base),
                grafana_alerts=grafana_alerts_at(grafana_base),
            )
        receiver = arguments.receiver or (
            default_receiver(compose_environment(env_file)) if mode == REPLAY else None
        )
    except (ConfigurationError, OSError, UnicodeDecodeError) as failure:
        print(failure, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # Reading `.env` and asking compose where it published the ports can take a moment.
        print(f"NOT VERIFIED: {INTERRUPTED} — stopped by the user before anything was asked")
        return 130
    timeouts = Timeouts(
        firing=arguments.firing_timeout,
        repeat=arguments.repeat_timeout,
        resolved=arguments.resolved_timeout,
        run=run_timeout,
    )
    if session is not None:
        return verify_mvp(
            mode, project.key, session, world, receiver, arguments.group, timeouts, project
        )
    return verify(mode, project.key, world, receiver, arguments.fingerprint, timeouts)


def session_from(values: Mapping[str, str], session: str | None) -> str:
    """`--mvp`'s session id, from the flag or `.env`; `verify_mvp` holds it to the label's form."""
    from grafana_jsm_sandbox import verify_mvp as scenario

    return scenario.session_from(dict(values), session)


def verify_mvp(
    mode: str,
    project_key: str,
    session: str,
    world: World,
    receiver: str | None,
    group: str,
    timeouts: Timeouts,
    project: DemoProject | None = None,
) -> int:
    """`--mvp`'s watch. `verify_mvp` builds on this module, so it is imported here, when it
    is asked for, rather than at the top."""
    from grafana_jsm_sandbox import verify_mvp as scenario

    return scenario.verify_mvp(
        mode, project_key, session, world, receiver, group, timeouts, project
    )


if __name__ == "__main__":
    raise SystemExit(main())
