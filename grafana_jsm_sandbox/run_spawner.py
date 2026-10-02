"""Starting one Run for real: a child process that can only talk to Jira.

The Receiver injects one of these as its spawner. Around each Run it does the
three things that make the credential boundary true (ADR 0002): it builds the
Run's environment from scratch rather than inheriting one, it registers that
Run's sentinel with the Forwarder before the process starts, and it clears the
sentinel the moment the process ends, so a sentinel that leaks out of a
Transcript is worth nothing by the time anyone reads it.

Everything the Run says on stdout is a Transcript, rendered into the log by the
formatter as it arrives and teed, raw, to `transcript.jsonl` in the Run's own
working directory, because the log is trimmed and redacted and the question
after a failure is usually about what it left out. The stream is also where a
Run says whether it worked: a Run the API refused exits 0 all the same, so the
spawner reads the result event and hands the Receiver the reason with the exit
status. A Run that runs long is killed, because a demo cannot wait and the queue
behind it cannot either.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import subprocess
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Self, cast

from grafana_jsm_sandbox.forwarder import ENVIRONMENT_VARIABLES, Forwarder
from grafana_jsm_sandbox.incident_payload import (
    FACTS_FILE,
    PayloadError,
    create_fields,
    read_facts,
    read_group,
)
from grafana_jsm_sandbox.log_formatter import (
    DENIED,
    FAILED,
    HINT,
    LIMIT,
    RETRY,
    format_stream,
    redact,
    run_failure,
)
from grafana_jsm_sandbox.receiver import Run, RunOutcome
from grafana_jsm_sandbox.run_command import RENDERED_SKILL

logger = logging.getLogger(__name__)

API_KEY_VARIABLE = "ANTHROPIC_API_KEY"
"""A work API key (`sk-ant-api...`), the MVP's way for a Run to reach the model."""

OAUTH_TOKEN_VARIABLE = "CLAUDE_CODE_OAUTH_TOKEN"
"""A Claude Code OAuth token, what `claude setup-token` prints: chapter one's way, still taken."""

MODEL_CREDENTIAL_VARIABLES = (API_KEY_VARIABLE, OAUTH_TOKEN_VARIABLE)
"""The two names a Run's model credential may come under. Exactly one of them is set: the
Claude CLI reads both, and which it would prefer when handed both is its business, not the
demo's, so two is refused rather than guessed between. Whichever is set is the one real
credential a Run holds, passed on under its own name. Nothing documented can mask it; the
demo says so."""

CREDENTIAL_KINDS = {
    API_KEY_VARIABLE: "an Anthropic API key",
    OAUTH_TOKEN_VARIABLE: "a Claude Code OAuth token",
}
"""What each variable holds, in words a log or a doctor line may say: the kind, never the value."""

RUN_TIMEOUT = 300.0
"""Seconds a Run may take before it is killed. Long enough for the five operations, short
enough that a stuck Run does not eat the slot."""

SITE_OPERATIONS_VARIABLE = "JIRA_ALLOW_SITE_OPERATIONS"
"""jira-as refuses site-scoped calls unless this says otherwise, and a Run needs exactly one
of them: `getServerInfo`. A Run has no clock — `date` is not on its allow list — so every
duration it reports is Jira's `serverTime` minus the Incident's `created` (ticket 04). Without
this, a Run outside a tree holding a jira-as settings file cannot read the time at all.

It is not narrow. jira-as has no switch for one site-scoped call: this unlocks all of them,
610 of its operations in 2.0.0, users, groups and schemes among them, besides the one a Run
needs. What any of those can then do is whatever the account behind the Forwarder may do,
because the Forwarder swaps the sentinel for that account's real token on every request. So
the limit on a Run's site-wide reach is the Skill it follows and that account's own Jira
permissions, and the account the demo runs as should hold no more than the demo needs."""

ALLOWED_PROJECTS_VARIABLE = "JIRA_ALLOWED_PROJECTS"
"""The one Jira project a Run may name, the demo's own. jira-as refuses a call that names any
other project literally, as a project argument, in an issue key or in a JQL `project` clause,
before it sends anything; a `deleteIssue PROD-1` from a Run is refused in the Run, not left to
the account's permissions (the 2026-09-23 audit, F7). The variable wins over any
`allowed_projects` in a jira-as settings file (jira_as/config_manager.py:211-216 in 2.0.0).

It is jira-as's own defence in depth and not a boundary: by its own account it checks literal
references and does not evaluate JQL or authorize HTTP. The Forwarder still forwards whatever
path a Run's request names, so what bounds a Run's writes is still its tool allow list (ADR
0003), the Skill and the account's own permissions. With it set, jira-as also takes a label like
`fp-1234` in JQL for an issue key and refuses it, which a Fingerprint that happens to hold no
letter a-f would trip."""

TRUST_STORE_VARIABLES = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PIP_CERT",
    "NODE_EXTRA_CA_CERTS",
)
"""What the image sets, image-wide, so that every TLS client in it trusts the system bundle
and whatever corporate CA was installed into it at build time (ticket 02). A Run inherits
exactly these from the Receiver, when the Receiver has them: on a laptop behind an
intercepting proxy its Anthropic traffic goes through the same proxy the build did, and
Claude Code reads `NODE_EXTRA_CA_CERTS` for the CA. Its Jira traffic needs none of them,
because that goes to the Forwarder over loopback in plain HTTP.

They are the only thing a Run inherits: the environment is still built from scratch, and
the real Jira token still never reaches it (ADR 0002)."""

SENTINEL_BYTES = 24
"""How much randomness each Run's sentinel carries."""

STDERR_TIMEOUT = 5.0
"""Seconds to wait for a killed Run's stderr after the process is gone."""

STDERR_TAIL = 2000
"""How much of a failed Run's stderr reaches the log: the end of it, where a crash says
what went wrong. The log window is a screen in a room, not a file anyone will scroll."""


LEVELS = {
    FAILED: logging.ERROR,
    HINT: logging.WARNING,
    DENIED: logging.WARNING,
    RETRY: logging.WARNING,
    LIMIT: logging.WARNING,
}
"""The Transcript lines logged above INFO, by label: the ones that say a Run failed, was
refused something, or is waiting on the API. Everything else a Run says is INFO."""


class MissingModelCredential(ValueError):
    """No model credential, or two of them, so no Run could ever start; never a value."""


@dataclass(frozen=True)
class ModelCredential:
    """What a Run authenticates to the model with: the variable it came under, and its value.

    The variable is the name the Claude CLI reads it under, so it is the name the
    Run gets it under. `kind` is what a log line may say about it; `value` is what
    no log line ever says.
    """

    variable: str
    value: str

    @property
    def kind(self) -> str:
        return CREDENTIAL_KINDS[self.variable]

    def __repr__(self) -> str:
        # A traceback or a debug line must not carry the value.
        return f"ModelCredential(variable={self.variable!r}, value=<redacted>)"


def model_credential_from_environment(
    environment: Mapping[str, str] | None = None,
) -> ModelCredential:
    """The one model credential set, or say which variables are not set, or that both are."""
    environment = os.environ if environment is None else environment
    found = [
        ModelCredential(variable, environment[variable].strip())
        for variable in MODEL_CREDENTIAL_VARIABLES
        if environment.get(variable, "").strip()
    ]
    if not found:
        raise MissingModelCredential(
            f"neither {API_KEY_VARIABLE} nor {OAUTH_TOKEN_VARIABLE} is set: set exactly one"
        )
    if len(found) > 1:
        raise MissingModelCredential(
            f"both {API_KEY_VARIABLE} and {OAUTH_TOKEN_VARIABLE} are set: set exactly one, "
            "and leave the other unset"
        )
    return found[0]


def trust_store_from_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """The trust-store variables the Receiver was started with, and only those that are set."""
    environment = os.environ if environment is None else environment
    return {name: environment[name] for name in TRUST_STORE_VARIABLES if name in environment}


@dataclass(frozen=True)
class RunSpawner:
    """Starts one Run as a child process and renders its Transcript into the log.

    `command` is the same command line for every Run — what differs per Run is
    the working directory it is started in and the sentinel in its environment.
    """

    command: Sequence[str]
    forwarder: Forwarder
    model_credential: ModelCredential
    jira_email: str
    project_key: str
    timeout: float = RUN_TIMEOUT
    path: str = field(default_factory=lambda: os.environ.get("PATH", os.defpath))
    trust_store: Mapping[str, str] = field(default_factory=trust_store_from_environment)

    def __call__(self, run: Run) -> RunOutcome:
        """Run one Run to completion and say how it ended."""
        sentinel = secrets.token_urlsafe(SENTINEL_BYTES)
        try:
            group = read_group(run.notification_path)
            facts = read_facts(run.working_directory.parent / RENDERED_SKILL / FACTS_FILE)
            expected = create_fields(group, facts) if group.firing else None
        except PayloadError as failure:
            logger.warning("run %s has no create content: %s", run.run_id, failure)
            expected = None
        self.forwarder.set_sentinel(sentinel, expected)
        try:
            return self._execute(run, sentinel)
        finally:
            self.forwarder.clear_sentinel()

    def _execute(self, run: Run, sentinel: str) -> RunOutcome:
        timed_out = threading.Event()
        transcript = _Transcript(run.transcript_path)
        logger.info("run %s transcript: %s", run.run_id, run.transcript_path)
        process = subprocess.Popen(
            list(self.command),
            cwd=run.working_directory,
            env=self._environment(sentinel),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            errors="replace",
            # A Run is the Claude CLI, which runs jira-as through a shell of its own.
            # Its own session means the timeout can end all of them at once: a
            # grandchild left alive would hold the Transcript pipe open and the
            # Receiver's one worker would wait on it for as long as it lived.
            start_new_session=True,
        )
        # Both pipes were asked for above, so neither of them is None.
        errors = _Drained(cast("IO[str]", process.stderr))
        killer = threading.Timer(self.timeout, _kill, (process, timed_out))
        killer.start()
        try:
            # The timer stays armed across this whole block, the reaping in
            # `__exit__` included, so nothing here can outlive the timeout.
            with process, transcript:
                stream = transcript.tee(cast("IO[str]", process.stdout))
                for line in format_stream(stream):
                    logger.log(LEVELS.get(line.split(" ", 1)[0], logging.INFO), "%s", line)
                exit_status = process.wait()
        finally:
            killer.cancel()
        errors.join(STDERR_TIMEOUT)

        if timed_out.is_set():
            logger.error(
                "run %s exceeded its %.0fs timeout and was killed", run.run_id, self.timeout
            )
        if exit_status != 0 and errors.text:
            logger.warning("run %s wrote to stderr: %s", run.run_id, redact(errors.text))
        return RunOutcome(exit_status, self._failure(timed_out, transcript, exit_status))

    def _failure(
        self, timed_out: threading.Event, transcript: _Transcript, exit_status: int
    ) -> str | None:
        """Why the Run failed, most telling reason first, or None when it did its job.

        The Run's own result comes before its exit status, because it names the
        cause where a status only says there was one. A Run that exits 0 without
        a result at all did not finish either.
        """
        if timed_out.is_set():
            return f"killed after its {self.timeout:g}s timeout"
        if transcript.failure is not None:
            return transcript.failure
        if exit_status != 0:
            return f"exit status {exit_status}"
        if not transcript.finished:
            return "the Transcript ended without a result"
        return None

    def _environment(self, sentinel: str) -> dict[str, str]:
        """Everything the Run's process gets, and it is built here rather than inherited.

        The model credential goes under the name it came in under, an API key's
        or an OAuth token's, and the other name is not set at all. The Jira
        variables are the ones jira-as reads, so a Run needs no patching
        to talk to the Forwarder — it only ever holds the sentinel — and it may name
        the demo's project and no other. HOME is not among them: the Claude CLI
        falls back to the account's home directory, and leaving it out keeps the
        list short enough to read aloud. The trust
        store is the one thing carried over from the Receiver's own environment,
        and only when the Receiver has one.
        """
        return {
            **self.trust_store,
            self.model_credential.variable: self.model_credential.value,
            ENVIRONMENT_VARIABLES["site_url"]: self.forwarder.url,
            ENVIRONMENT_VARIABLES["email"]: self.jira_email,
            ENVIRONMENT_VARIABLES["api_token"]: sentinel,
            ALLOWED_PROJECTS_VARIABLE: self.project_key,
            SITE_OPERATIONS_VARIABLE: "true",
            "PATH": self.path,
        }


class _Transcript:
    """A Run's stdout on its way to the formatter: copied to disk, and read for its result.

    The copy is the raw stream-json, line for line, in the Run's working directory,
    so it is there for as long as the Run's Notification is, and a Run's `Read` rule
    reaches it exactly as it reaches the Notification. It is written as each line
    arrives, so a Run that is killed leaves everything it said up to then. A file
    that cannot be written costs one warning and the copy, never the Run: the log
    still gets every line.
    """

    def __init__(self, path: Path):
        self.path = path
        self.failure: str | None = None
        self.finished = False
        self._file: IO[str] | None = None

    def __enter__(self) -> Self:
        try:
            self._file = open(self.path, "w", encoding="utf-8", buffering=1)
        except OSError as error:
            logger.warning("the transcript %s cannot be written: %s", self.path, error)
        return self

    def __exit__(self, *exc_info) -> None:
        self._close()

    def tee(self, lines: Iterable[str]) -> Iterator[str]:
        for line in lines:
            self._write(line)
            self._read(line)
            yield line

    def _write(self, line: str) -> None:
        if self._file is None:
            return
        try:
            self._file.write(line)
        except OSError as error:
            logger.warning("the transcript %s stopped being written: %s", self.path, error)
            self._close()

    def _close(self) -> None:
        """Close the copy. A full tmpfs can refuse the last flush too, and that costs nothing."""
        file, self._file = self._file, None
        if file is not None:
            try:
                file.close()
            except OSError:
                pass

    def _read(self, line: str) -> None:
        """Note the result event: whether one came, and the first failure one reported."""
        try:
            event = json.loads(line)
        except ValueError:
            return
        if isinstance(event, dict) and event.get("type") == "result":
            self.finished = True
            self.failure = self.failure or run_failure(event)


class _Drained:
    """A stream being read to its end on a thread, so a full pipe can never wedge a Run.

    Only the tail is kept. A Run that never stops complaining is still bounded by
    its timeout, but what it said should not arrive in the log as one vast line.
    """

    def __init__(self, stream: IO[str]):
        self.text = ""
        self._thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self._thread.start()

    def _read(self, stream: IO[str]) -> None:
        self.text = stream.read().strip()[-STDERR_TAIL:]

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)


def _kill(process: subprocess.Popen, timed_out: threading.Event) -> None:
    """End a Run that has taken too long, and everything it started.

    The whole session goes, not just the Run: the Claude CLI's own children hold
    the Transcript pipe, so killing it alone would leave the Receiver reading a
    pipe that never closes.
    """
    if process.poll() is not None:
        # It finished on its own between this timer firing and now, so it did not
        # exceed anything and nothing should say it did.
        return
    timed_out.set()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()
