"""`verify --mvp`: one agent, many alerts, one Incident, watched stage by stage.

    python3 -m grafana_jsm_sandbox.verify --mvp [--replay | --live] [--session ID]
        [--group NAME] [--receiver URL] [--firing-timeout S] [--repeat-timeout S]
        [--resolved-timeout S] [--run-timeout S]

`verify` on its own watches chapter one's Incident, keyed by one Fingerprint label. This
scenario watches the MVP's (`docs/mvp-spec.md`): a fault makes several related Alerts
fire, Grafana sends them in one grouped Notification, one Run creates **one** Incident
carrying the group label `grp-<incident_group>`, the session label `ses-<DEMO_SESSION_ID>`
and one `fp-` label per Alert, and every later Run updates that same Incident. It holds
the Runs to the spec's Proof:

    1. exactly one open Incident carries the group and session labels, with at least two
       `fp-` labels (stages `created` and `grouped`);
    2. a repeat adds a comment, and no Incident (`updated`); in live mode it reports
       `New: none`, and at least two update comments follow the opening baseline;
    3. the sustained-outage Alert adds its own `fp-` label and a comment (`related`),
       identified in live mode by Grafana's Alertmanager API;
    4. after the traffic restarts, the Incident reaches its configured done status (`completed`);
    5. at no point do two open Incidents share the labels: every look at the project
       counts them, and a second one is `FAIL one incident` at once.

    --replay  (the default) posts the four grouped Notifications under `fixtures/mvp/`:
              three related Alerts firing, the same three again, the sustained-outage Alert
              joining them, and all four resolved, each once the Incident has answered the
              one before.
    --live    stops the traffic and waits for Grafana's rules to fire, for the repeat and
              the sustained-outage Alert to reach the Incident in whichever order Grafana
              sends them, then starts the traffic again and waits for the Resolved. The
              traffic is started again on the way out, whatever happens.

The session label is the Receiver's, from `.env`'s `DEMO_SESSION_ID`, so a rehearsal's
Incidents never match the real demo's; `--session` names another literal id, not a label. The lines, the exit
status and the cleanup note are `verify`'s own; the stages, in order, are `preflight`, then
for `--live` `traffic stopped` and `firing`, or for `--replay` `posted` before each Run's
stage, then `created`, `grouped`, `updated`, `related`, for `--live` `traffic started` and
`normal`, then `completed`, and the verdict is

    VERIFIED: <key> created with <n> fp- labels → updated → <label> added → <done status> with
        resolution <name> in <seconds>s

It only reads Jira, like `verify`: the Runs create, update and complete, and `reset` takes a
leftover out of the queue.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

from grafana_jsm_sandbox.configure import RESOLUTION_SCREEN
from grafana_jsm_sandbox.demo_config import (
    ConfigurationError,
    DemoProject,
    session_id_problem,
    session_label,
)
from grafana_jsm_sandbox.doctor import GrafanaUnanswered
from grafana_jsm_sandbox.replay import FIXTURES, default_receiver
from grafana_jsm_sandbox.reset import (
    COMPOSE_FAILURES,
    FINGERPRINT_PREFIX,
    RESOLUTION,
    TRAFFIC_SERVICE,
    search,
)
from grafana_jsm_sandbox.verify import (
    COMPLETED_STAGE,
    CREATED,
    DOCTOR,
    FIRING,
    INCIDENT_GROUP,
    INTERRUPTED,
    JIRA_AS_FAILURES,
    LIVE,
    LOGS,
    NORMAL,
    OK,
    RECENT,
    SESSION_ID_VARIABLE,
    TRAFFIC_BACK,
    TRAFFIC_STARTED,
    TRAFFIC_STOPPED,
    WAIT,
    WARN,
    Incident,
    NotVerified,
    Timeouts,
    Watch,
    World,
    cleanup_note,
    grafana_reaches,
    issue_number,
    post_notification,
    preflight,
    said,
    start_traffic,
)

MVP = "mvp"
"""The scenario's name, as `--mvp` selects it."""

GROUP_PREFIX = "grp-"
SESSION_PREFIX = "ses-"
"""The labels a Run keys the MVP's Incident by, beside the `fp-` ones (spec, shared interfaces)."""

SUSTAINED_TITLE = "rolldice outage is sustained"
"""The sustained-outage rule's title in grafana/provisioning/alerting/alert-rule.yaml."""

MVP_SEQUENCE = (
    "mvp/notification-group-firing.json",
    "mvp/notification-group-repeat.json",
    "mvp/notification-group-related.json",
    "mvp/notification-group-resolved.json",
)
"""The grouped Notifications, under `fixtures/`, in the order the replay posts them: three
related Alerts firing, the same three again, the sustained-outage Alert joining them, and all
four resolved."""

GROUPED = "grouped"
UPDATED = "updated"
RELATED = "related"
ONE_INCIDENT = "one incident"
"""The scenario's own stages, beside `verify`'s."""

GROUP_LABELLED = (
    'project = "{key}" AND issuetype = Incident AND labels = "{group}" AND labels = "{session}"'
)
"""Every Incident ever created for this group in this session, in any status."""

GROUP_MATCH = GROUP_LABELLED + " AND statusCategory != Done"
"""The Match as a Run defines it (spec, shared interfaces): the one *open* Incident for the
group and the session."""

AT_LEAST = 2
"""How many `fp-` labels the created Incident must carry: several related Alerts, not one."""


@dataclass(frozen=True)
class GroupIncident(Incident):
    """An Incident as this scenario reads it: `verify`'s view, plus its labels."""

    labels: frozenset[str] = frozenset()
    repeat_comments: int = 0
    commented_fingerprints: frozenset[str] = frozenset()

    @property
    def fingerprints(self) -> frozenset[str]:
        return frozenset(label for label in self.labels if label.startswith(FINGERPRINT_PREFIX))


def comment_text(body: object) -> str:
    """A Jira comment's plain text, whether the API gives a string or an ADF document."""
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        if body.get("type") == "text":
            return str(body.get("text", ""))
        return "".join(comment_text(child) for child in body.get("content", []))
    return ""


def is_repeat_comment(body: object) -> bool:
    """The Skill's update with `New: none`: a comment without an fp- label addition.

    Matched loosely, in any case and anywhere in the comment, so that a Run that words the
    Skill's template a little differently is not a paid lifecycle reported NOT VERIFIED.
    """
    text = " ".join(comment_text(body).split())
    return bool(re.search(r"\bnew:\s*none\b", text, flags=re.IGNORECASE))


def new_fingerprints(body: object) -> frozenset[str]:
    """The fp- labels a comment names, proving the Run that added them commented.

    Any fp- label in the comment counts, not only those in the template's `New:` list, for
    the same reason: the label on the Incident is the proof, and the comment only ties it to
    a Run.
    """
    text = " ".join(comment_text(body).split())
    return frozenset(re.findall(r"\bfp-[0-9a-f]{1,64}\b", text))


def sustained_label(watch: GroupWatch) -> str | None:
    """The sustained-outage Alert's own webhook fingerprint, read from Alertmanager."""
    try:
        alerts = watch.world.grafana_alerts()
    except GrafanaUnanswered as failure:
        raise watch.fail(RELATED, f"Grafana's Alertmanager could not be read: {failure}") from None
    if not isinstance(alerts, list):
        raise watch.fail(
            RELATED, "Grafana's Alertmanager answered something other than an Alert list"
        )
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") or {}
        if not isinstance(labels, dict):
            raise watch.fail(RELATED, "Grafana's Alertmanager returned malformed Alert labels")
        if labels.get("alertname") == SUSTAINED_TITLE and labels.get(
            "incident_group"
        ) == watch.group.removeprefix(GROUP_PREFIX):
            fingerprint = alert.get("fingerprint")
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{1,64}", fingerprint):
                raise watch.fail(RELATED, "the sustained-outage Alert has no valid fingerprint")
            return FINGERPRINT_PREFIX + fingerprint
    return None


def group_label(group: str) -> str:
    return GROUP_PREFIX + group.removeprefix(GROUP_PREFIX)


def session_from(values: dict[str, str], session: str | None) -> str:
    """The session id `--session` gives, else `.env`'s; a `ConfigurationError` when neither
    is there or one is not an id. The id is literal, even when it starts with `ses-`."""
    where = "--session" if session is not None else f"{SESSION_ID_VARIABLE} in .env"
    if session is None:
        session = values.get(SESSION_ID_VARIABLE, "").strip()
    if not session:
        raise ConfigurationError(
            f"{SESSION_ID_VARIABLE} is not set: --mvp watches the session label the Receiver "
            f"gives the Runs, {SESSION_PREFIX}<id>; set it in .env or pass --session ID (an id, not a label)"
        )
    problem = session_id_problem(session)
    if problem:
        raise ConfigurationError(
            f"{where} {problem}; set {SESSION_ID_VARIABLE} in .env or pass --session ID "
            "(an id, not a label)"
        )
    return session


class GroupWatch(Watch):
    """`verify`'s watch, keyed by the group and session labels rather than one Fingerprint.

    `label` is the two labels as a sentence, for the lines `preflight` and the cleanup note
    print; the searches use `group` and `session`.
    """

    def __init__(
        self,
        world: World,
        key: str,
        group: str,
        session: str,
        timeouts: Timeouts,
        project: DemoProject | None = None,
    ) -> None:
        self.project = DemoProject(key) if project is None else project
        self.group = group_label(group)
        self.session = session_label(session)
        super().__init__(world, key, f"{self.group} and {self.session}", timeouts)
        self.incident: GroupIncident | None = None

    # --- Jira, read only ---

    def snapshot(self) -> list[dict]:
        """Every Incident carrying both labels, as the search answers: key, status, labels."""
        jql = GROUP_LABELLED.format(key=self.key, group=self.group, session=self.session)
        return search(self.world.jira_as, jql)

    def labelled(self) -> set[str]:
        return {issue["key"] for issue in self.snapshot()}

    def open_matches(self) -> list[str]:
        jql = GROUP_MATCH.format(key=self.key, group=self.group, session=self.session)
        return [issue["key"] for issue in search(self.world.jira_as, jql)]

    def one_open(self, stage: str) -> list[dict]:
        """This run's Incidents, holding the project to one open Match at every look (Proof 5).

        The look that finds two ends the watch there and then, whatever stage it was in,
        because a second open Incident is the one thing the MVP promises never happens.
        """
        found = sorted(
            (issue for issue in self.snapshot() if issue["key"] not in self.before),
            key=lambda issue: issue_number(issue["key"]),
        )
        open_keys = [
            issue["key"]
            for issue in found
            if not (
                issue["fields"].get("status", {}).get("statusCategory", {}).get("key") == "done"
                or issue["fields"].get("status", {}).get("name")
                in {self.project.status_done, self.project.status_closed, "Canceled"}
            )
        ]
        if len(open_keys) > 1:
            raise self.fail(
                ONE_INCIDENT,
                f"{', '.join(open_keys)} are all open with {self.label} during {stage}: a Run "
                f"missed the Match and created a second Incident; {LOGS}",
            )
        return found

    def read(self, key: str) -> GroupIncident:
        """`key`'s status, resolution, labels and comment count."""
        jira_as = self.world.jira_as
        issue = json.loads(
            jira_as("issue", "get", key, "--fields", "status,resolution,labels", "-o", "json")
        )
        comments = json.loads(jira_as("collaborate", "comment", "list", key, "-o", "json"))
        try:
            fields = issue["fields"]
            incident = GroupIncident(
                key=key,
                status=fields["status"]["name"],
                resolution=(fields.get("resolution") or {}).get("name"),
                comments=int(comments.get("total", 0)),
                labels=frozenset(fields.get("labels") or ()),
                repeat_comments=sum(
                    is_repeat_comment(comment.get("body"))
                    for comment in comments.get("comments", [])
                ),
                commented_fingerprints=frozenset(
                    label
                    for comment in comments.get("comments", [])
                    for label in new_fingerprints(comment.get("body"))
                ),
            )
        except (KeyError, TypeError, AttributeError) as failure:
            raise ValueError(
                f"jira-as answered {key} in an unexpected shape ({failure!r})"
            ) from None
        self.incident = incident
        return incident

    def elsewhere(self) -> list[tuple[str, str]]:
        """Incidents created while this ran that carry the group label under another session
        label, and which: a `.env` whose session id is not the one this was given."""
        minutes = math.ceil((self.world.now() - self.started) / 60) + 1
        jql = RECENT.format(key=self.key, minutes=minutes)
        try:
            issues = search(self.world.jira_as, jql)
        except JIRA_AS_FAILURES:
            return []
        found = []
        for issue in issues:
            labels = issue["fields"].get("labels", [])
            sessions = [
                label
                for label in labels
                if label.startswith(SESSION_PREFIX) and label != self.session
            ]
            if self.group in labels and sessions and issue["key"] not in self.before:
                found.append((issue["key"], sessions[0]))
        return found


# --- The stages ---


def created(watch: GroupWatch, since: float, after: str) -> GroupIncident:
    """Wait for the one Incident a Run created for the group and the session."""
    timeout = watch.timeouts.run
    watch.line(
        WAIT,
        CREATED,
        f"up to {timeout:.0f}s for a Run to create an Incident carrying {watch.label}",
    )

    def look() -> GroupIncident | None:
        found = watch.one_open(CREATED)
        return watch.read(found[0]["key"]) if found else None

    def timed_out() -> str:
        message = f"no Incident within {watch.elapsed(since)}s of {after}: {LOGS}"
        others = watch.elsewhere()
        if others:
            key, label = others[0]
            message += (
                f"; {key} was created meanwhile with {label} instead of {watch.session}: if "
                f"that is this session, run again with --session "
                f"{label.removeprefix(SESSION_PREFIX)}, or set {SESSION_ID_VARIABLE} in .env"
            )
        return message

    incident = watch.wait_for(CREATED, since + timeout, look, timed_out)
    watch.line(
        OK,
        CREATED,
        f"{incident.key} ({incident.status}) carries {watch.label}, {watch.elapsed(since)}s "
        f"after {after}",
    )
    return incident


def grouped(
    watch: GroupWatch,
    key: str,
    since: float,
    timeout: float,
    after: str,
    expected: frozenset[str] | None,
) -> GroupIncident:
    """Wait for `key` to carry the group's `fp-` labels: `expected` when the replay knows
    them, else at least `AT_LEAST`. Also wait for the opening comment before taking
    the baseline, so it cannot pass as a repeat update."""
    wanted = (
        f"the {len(expected)} fp- labels of the posted Alerts"
        if expected
        else f"at least {AT_LEAST} fp- labels"
    )
    watch.line(
        WAIT,
        GROUPED,
        f"up to {timeout:.0f}s for {key} to carry {wanted} and have its opening comment",
    )

    def look() -> GroupIncident | None:
        watch.one_open(GROUPED)
        incident = watch.read(key)
        off_the_path(watch, GROUPED, incident)
        if incident.comments < 1:
            return None
        if expected is not None:
            return incident if expected <= incident.fingerprints else None
        return incident if len(incident.fingerprints) >= AT_LEAST else None

    def timed_out() -> str:
        seen = watch.incident
        have = sorted(seen.fingerprints) if seen else []
        message = (
            f"{key} carries {len(have)} fp- label(s) ({', '.join(have) or 'none'}), not "
            f"{wanted} with an opening comment ({seen.comments if seen else 0} comments), "
            f"{watch.elapsed(since)}s after {after}: "
        )
        if expected is not None:
            missing = sorted(expected - set(have))
            message += (
                f"the Run left off {', '.join(missing)}, one label per Alert in the "
                f"Notification is the Skill's; {LOGS}"
            )
        else:
            message += (
                "the other related rules did not fire, or their Alerts were not grouped with "
                f"this one (`{DOCTOR} --only grafana`, and the policy's group_by); {LOGS}"
            )
        return message

    incident = watch.wait_for(GROUPED, since + timeout, look, timed_out)
    watch.line(
        OK,
        GROUPED,
        f"{key} carries {len(incident.fingerprints)} fp- labels "
        f"({', '.join(sorted(incident.fingerprints))}), {watch.elapsed(since)}s after {after}",
    )
    return incident


def off_the_path(watch: GroupWatch, stage: str, incident: GroupIncident) -> None:
    """A Run that moved the Incident outside the configured open roles ends the stage."""
    if incident.status not in (watch.project.status_open, watch.project.status_in_progress):
        raise watch.fail(
            stage,
            f"{incident.key} went to {incident.status} instead of staying open: a Run took it "
            f"off the demo's path; {LOGS}",
        )


def updated(
    watch: GroupWatch,
    baseline: GroupIncident,
    since: float,
    timeout: float,
    after: str,
    cause: str,
    stages: tuple[str, ...],
    label: str | None = None,
    live: bool = False,
) -> GroupIncident:
    """Wait for the updates the Runs owe `baseline`'s Incident, in whichever order they come.

    In replay, `updated` is a further comment after the opening-comment baseline;
    `related` adds the fixture's own label with a comment. In live mode, `related`
    requires the sustained-outage fingerprint from Grafana's Alertmanager and its
    own update comment naming that fingerprint as new, while
    `updated` requires the Skill's `New: none` update comment. At least two comments
    after the creation baseline must land before traffic restarts. A health-probe
    update cannot pass as either the repeat or the sustained-outage Alert.
    """
    pending = list(stages)
    key = baseline.key
    wanted = {
        UPDATED: (
            f"a repeat comment with New: none and at least two update comments on {key}"
            if live
            else f"the repeat's Run to comment on {key}"
        ),
        RELATED: (
            f"the sustained-outage Alert's Run to add {label or 'its fp- label'} to {key} "
            "with a comment"
        ),
    }
    for stage in pending:
        watch.line(WAIT, stage, f"up to {timeout:.0f}s for {wanted[stage]}")

    def look() -> GroupIncident | None:
        """The Incident when a stage landed on this look, so the wait is re-entered under
        the next pending stage's name, or None."""
        nonlocal label
        watch.one_open(pending[0])
        incident = watch.read(key)
        off_the_path(watch, pending[0], incident)
        if live and label is None:
            label = sustained_label(watch)
        commented = incident.comments > baseline.comments
        repeated = commented and (
            not live
            or (
                incident.comments >= baseline.comments + 2
                and incident.repeat_comments > baseline.repeat_comments
            )
        )
        added = incident.fingerprints - baseline.fingerprints
        landed = False
        if UPDATED in pending and repeated:
            landed = True
            pending.remove(UPDATED)
            watch.line(
                OK,
                UPDATED,
                f"{key} has a new comment ({incident.comments} now) and is {incident.status}, "
                f"{watch.elapsed(since)}s after {after}; still the one Incident"
                + ("; New: none repeat and at least two update comments" if live else ""),
            )
            if incident.status != watch.project.status_in_progress:
                watch.line(
                    WARN,
                    UPDATED,
                    f"{key} is still {incident.status}, not {watch.project.status_in_progress}, which the Skill "
                    "moves it to on the first update",
                )
        if (
            RELATED in pending
            and commented
            and added
            and (label in added if live else label is None or label in added)
            and (
                not live
                or label in incident.commented_fingerprints - baseline.commented_fingerprints
            )
        ):
            landed = True
            pending.remove(RELATED)
            watch.line(
                OK,
                RELATED,
                f"{key} gained {', '.join(sorted(added))} with a comment, "
                f"{watch.elapsed(since)}s after {after}",
            )
        return incident if landed else None

    def timed_out() -> str:
        seen = watch.incident
        comments = seen.comments if seen else baseline.comments
        have = sorted(seen.fingerprints) if seen else sorted(baseline.fingerprints)
        stage = pending[0]
        if stage == UPDATED:
            return (
                f"{key} still has {comments} comment(s), "
                + (
                    "need a New: none repeat comment and at least two updates since "
                    if live
                    else "none since "
                )
                + f"{after}, "
                f"{watch.elapsed(since)}s later: {cause}"
            )
        return (
            f"{key} still carries only {', '.join(have)}, no new fp- label with a comment "
            f"{watch.elapsed(since)}s after {after}: "
            + (
                f"waiting for the sustained-outage fingerprint {label or 'from Alertmanager'}; "
                if live
                else ""
            )
            + cause
        )

    # One wait per stage still pending, each under its own name, so the FAIL that ends a
    # wait names the stage that did not come, not the first one asked for.
    incident = baseline
    while pending:
        incident = watch.wait_for(pending[0], since + timeout, look, timed_out)
    return incident


def completed(
    watch: GroupWatch, baseline: GroupIncident, since: float, after: str
) -> GroupIncident:
    """Wait for the Resolved's Run to complete the Incident, with a resolution (Proof 4)."""
    key = baseline.key
    timeout = watch.timeouts.run
    watch.line(
        WAIT, COMPLETED_STAGE, f"up to {timeout:.0f}s for the Resolved's Run to complete {key}"
    )

    def look() -> GroupIncident | None:
        watch.one_open(COMPLETED_STAGE)
        incident = watch.read(key)
        if incident.status == watch.project.status_done:
            return incident
        off_the_path(watch, COMPLETED_STAGE, incident)
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
            f"{key} is {watch.project.status_done} without a resolution: the Resolve screen dropped it, so the "
            "Incident stays in the Incidents queue, and closing it would leave it there for good",
            (RESOLUTION_SCREEN,),
        )
    watch.line(
        OK,
        COMPLETED_STAGE,
        f"{key} is {watch.project.status_done} with resolution {incident.resolution}, "
        f"{watch.elapsed(since)}s after {after}",
    )
    if incident.resolution != RESOLUTION:
        watch.line(
            WARN,
            COMPLETED_STAGE,
            f"the resolution is {incident.resolution}, not {RESOLUTION}, which the Skill sets",
        )
    if incident.comments <= baseline.comments:
        watch.line(
            WARN,
            COMPLETED_STAGE,
            f"{key} has no closing comment: the Resolved's Run completed it without one; {LOGS}",
        )
    return incident


# --- The two ways through ---


def fingerprints_in(filename: str) -> frozenset[str]:
    """The `fp-` labels the Alerts of one fixture Notification give the Incident."""
    notification = json.loads((FIXTURES / filename).read_text())
    return frozenset(FINGERPRINT_PREFIX + alert["fingerprint"] for alert in notification["alerts"])


@dataclass(frozen=True)
class Verified:
    """What the verdict line says: the Incident as created, what joined it, and as completed."""

    created: GroupIncident
    added: str
    completed: GroupIncident


def replayed(watch: GroupWatch, receiver: str) -> Verified:
    """The grouped Notifications, each posted once the Incident has answered the one before."""
    firing, repeat, related, resolved = MVP_SEQUENCE
    run = watch.timeouts.run
    posted = post_notification(watch, receiver, firing)
    incident = created(watch, posted, "posting the grouped Firing")
    first = grouped(
        watch, incident.key, posted, run, "posting the grouped Firing", fingerprints_in(firing)
    )
    posted = post_notification(watch, receiver, repeat)
    incident = updated(
        watch,
        first,
        posted,
        run,
        "posting the repeat",
        f"its Run failed, never ran, or created instead of updating; {LOGS}",
        (UPDATED,),
    )
    posted = post_notification(watch, receiver, related)
    new_labels = fingerprints_in(related) - fingerprints_in(firing)
    label = next(iter(new_labels)) if len(new_labels) == 1 else None
    before_related = incident
    incident = updated(
        watch,
        incident,
        posted,
        run,
        "posting the related Alert",
        f"its Run failed, or updated without adding the label; {LOGS}",
        (RELATED,),
        label,
    )
    added = ", ".join(sorted(incident.fingerprints - before_related.fingerprints))
    posted = post_notification(watch, receiver, resolved)
    return Verified(first, added, completed(watch, incident, posted, "posting the Resolved"))


def live(watch: GroupWatch) -> Verified:
    """The real Alerts: stop the traffic, and start it again on the way out, whatever happens."""
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
        # The first Notification carries two Alerts; probe and sustained outage join
        # on later group intervals. Wait for the opening comment before the baseline.
        first = grouped(
            watch,
            incident.key,
            watch.world.now(),
            timeouts.firing + timeouts.run,
            "it was created",
            None,
        )
        incident = updated(
            watch,
            first,
            watch.world.now(),
            timeouts.repeat + timeouts.run,
            "it was grouped",
            "Grafana repeats a Firing on the repeat interval and sends a new Alert on the "
            f"group interval, so either neither came (`{DOCTOR} --only grafana`) or its Run "
            f"failed; {LOGS}",
            (UPDATED, RELATED),
            live=True,
        )
        added = ", ".join(sorted(incident.fingerprints - first.fingerprints))
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
        return Verified(first, added, completed(watch, incident, normal, "Grafana went Normal"))
    finally:
        if not attempted:
            watch.line(
                WAIT,
                TRAFFIC_STARTED,
                f"starting the traffic again on the way out; should this be cut short, "
                f"{TRAFFIC_BACK}",
            )
            start_traffic(watch)


def verify_mvp(
    mode: str,
    project_key: str,
    session: str,
    world: World,
    receiver: str | None = None,
    group: str = INCIDENT_GROUP,
    timeouts: Timeouts | None = None,
    project: DemoProject | None = None,
) -> int:
    """Watch the MVP's one Incident and print the verdict; the exit status `main` returns."""
    watch = GroupWatch(world, project_key, group, session, timeouts or Timeouts(), project)
    try:
        preflight(watch, mode)
        if mode == LIVE:
            verified = live(watch)
        else:
            verified = replayed(watch, default_receiver() if receiver is None else receiver)
    except NotVerified as failure:
        cleanup_note(watch)
        world.out(f"NOT VERIFIED: {failure.stage} — {failure.message}")
        return 1
    except KeyboardInterrupt:
        cleanup_note(watch)
        world.out(f"NOT VERIFIED: {INTERRUPTED} — stopped by the user after {watch.elapsed()}s")
        return 130
    cleanup_note(watch)
    done = verified.completed
    world.out(
        f"VERIFIED: {done.key} created with {len(verified.created.fingerprints)} fp- labels "
        f"→ updated → {verified.added} added → {watch.project.status_done} with resolution {done.resolution} "
        f"in {watch.elapsed()}s"
    )
    return 0
