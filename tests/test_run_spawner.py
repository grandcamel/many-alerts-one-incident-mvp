"""The real Run spawner: the Receiver starting one headless Claude as a child process.

Every test here starts a real child process with a stand-in for the Claude CLI,
because what the ticket asks about a Run is true of the process or it is not
true at all: the environment it was given, what its sentinel can reach, what its
output turned into in the log, and whether a stuck one can be killed.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import pytest

from grafana_jsm_sandbox import run_spawner
from grafana_jsm_sandbox.log_formatter import HINT_CREDITS
from grafana_jsm_sandbox.notification import NOTIFICATION_FILENAME
from grafana_jsm_sandbox.receiver import TRANSCRIPT_FILENAME, Receiver, Run
from grafana_jsm_sandbox.run_command import read_rule
from grafana_jsm_sandbox.run_spawner import (
    ALLOWED_PROJECTS_VARIABLE,
    API_KEY_VARIABLE,
    MODEL_CREDENTIAL_VARIABLES,
    OAUTH_TOKEN_VARIABLE,
    SITE_OPERATIONS_VARIABLE,
    TRUST_STORE_VARIABLES,
    MissingModelCredential,
    ModelCredential,
    RunSpawner,
    model_credential_from_environment,
)
from tests.conftest import (
    FIXTURES,
    REAL_EMAIL,
    REAL_TOKEN,
    firing_notification,
    http_request,
    post_notification,
    wait_for_log,
)

OAUTH_TOKEN = ModelCredential(
    OAUTH_TOKEN_VARIABLE, "sk-ant-oat01-an-oauth-token-no-forwarder-can-hide"
)
API_KEY = ModelCredential(API_KEY_VARIABLE, "sk-ant-api03-a-work-api-key-no-forwarder-can-hide")
"""The two kinds of model credential a Run may be started with, one at a time."""

PROJECT_KEY = "SANDBOX"
"""The demo's project, as `DEMO_PROJECT_KEY` names it: deliberately not OPS."""

ENVIRONMENT_FILE = "environment.json"
"""Where a stand-in Run writes the environment it was started with."""

PLATFORM_ADDITIONS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
"""What macOS adds to every child process below the spawner. The container is Linux
and adds nothing, so these are excluded rather than allowed for."""

A_RUNS_VARIABLES = {
    OAUTH_TOKEN_VARIABLE,
    "JIRA_EMAIL",
    "JIRA_SITE_URL",
    "JIRA_API_TOKEN",
    ALLOWED_PROJECTS_VARIABLE,
    SITE_OPERATIONS_VARIABLE,
    "PATH",
}
"""Everything a Run is started with when the Receiver has no trust store to hand on, and its
credential is the OAuth token; with an API key, that name stands where the token's does."""

SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
"""Where the image points every TLS client, and so what a Run inherits (ticket 02)."""


def _program(*parts: str) -> list[str]:
    """A stand-in for the Claude CLI: this interpreter running the given source."""
    return [sys.executable, "-c", "\n".join(parts)]


DUMP_ENVIRONMENT = f"""\
import json, os, pathlib
pathlib.Path({ENVIRONMENT_FILE!r}).write_text(json.dumps(dict(os.environ)))
"""

CALL_JIRA = """\
import base64, os, urllib.request
credential = f"{os.environ['JIRA_EMAIL']}:{os.environ['JIRA_API_TOKEN']}".encode()
request = urllib.request.Request(
    os.environ["JIRA_SITE_URL"] + "/rest/api/3/search/jql?jql=project+%3D+OPS",
    headers={"Authorization": "Basic " + base64.b64encode(credential).decode()},
)
urllib.request.urlopen(request, timeout=5).read()
"""

EMIT_A_TRANSCRIPT = """\
import json
for event in [
    {"type": "assistant", "message": {"content": [
        {"type": "text", "text": "Searching OPS for a Match."},
        {"type": "tool_use", "name": "Bash", "input": {"command": "jira-as search jql 'project = OPS'"}},
    ]}},
    {"type": "result", "subtype": "success", "duration_ms": 1200, "num_turns": 2},
]:
    print(json.dumps(event), flush=True)
"""

COMPLAIN_AND_FAIL = """\
import sys
print("claude: onboarding was never accepted", file=sys.stderr)
sys.exit(3)
"""

LEAK_A_CREDENTIAL_ON_STDERR = """\
import sys
print("Authorization: Basic c2VudGluZWw6bm90LWZvci1hLXNjcmVlbg==", file=sys.stderr)
sys.exit(1)
"""

HANG = """\
import time
time.sleep(30)
"""

HANG_WITH_A_CHILD_OF_ITS_OWN = """\
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
time.sleep(30)
"""
"""What a real Run looks like: the Claude CLI with a shell of its own under it, holding
the same Transcript pipe. Killing only the Run leaves the Receiver reading that pipe."""


def a_run(directory: Path, run_id: str = "20260915T164012-abc123") -> Run:
    """A Run the way the Receiver prepares one: its own directory, Notification written."""
    working_directory = directory / run_id
    working_directory.mkdir(parents=True)
    (working_directory / NOTIFICATION_FILENAME).write_text(json.dumps(firing_notification()))
    return Run(run_id, working_directory)


def spawner_for(command: list[str], forwarder, **overrides) -> RunSpawner:
    return RunSpawner(
        **{
            "command": command,
            "forwarder": forwarder,
            "model_credential": OAUTH_TOKEN,
            "jira_email": REAL_EMAIL,
            "project_key": PROJECT_KEY,
            **overrides,
        }
    )


def environment_of(run: Run) -> dict[str, str]:
    """The environment the stand-in Run recorded for itself."""
    return json.loads((run.working_directory / ENVIRONMENT_FILE).read_text())


@pytest.fixture
def run(tmp_path) -> Run:
    return a_run(tmp_path / "runs")


def test_the_run_starts_in_its_own_working_directory(forwarder, run):
    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    assert (run.working_directory / ENVIRONMENT_FILE).exists()


def test_the_runs_environment_is_built_from_scratch(forwarder, run, monkeypatch):
    """A Receiver with no trust store of its own starts a Run with none either."""
    for variable in TRUST_STORE_VARIABLES:
        monkeypatch.delenv(variable, raising=False)

    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    assert set(environment_of(run)) - PLATFORM_ADDITIONS == A_RUNS_VARIABLES


def test_a_run_trusts_the_certificates_the_receiver_trusts_and_nothing_else_new(
    forwarder, run, monkeypatch
):
    """The image sets the trust-store variables for every process in it, and a Run's
    Anthropic traffic goes through the same intercepting proxy the build did (ticket 02).
    They are the only addition: the scrubbed environment of ADR 0002 stands."""
    for variable in TRUST_STORE_VARIABLES:
        monkeypatch.setenv(variable, SYSTEM_BUNDLE)

    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    environment = environment_of(run)
    assert {variable: environment[variable] for variable in TRUST_STORE_VARIABLES} == {
        variable: SYSTEM_BUNDLE for variable in TRUST_STORE_VARIABLES
    }
    assert set(environment) - PLATFORM_ADDITIONS == A_RUNS_VARIABLES | set(TRUST_STORE_VARIABLES)


def test_nothing_of_the_receivers_own_environment_reaches_the_run(forwarder, run, monkeypatch):
    monkeypatch.setenv("JIRA_API_TOKEN", REAL_TOKEN)
    monkeypatch.setenv(
        "AWS_SECRET_ACCESS_KEY", "something the Receiver happened to be started with"
    )

    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    environment = environment_of(run)
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert REAL_TOKEN not in environment.values()


def test_the_run_holds_a_sentinel_where_the_jira_token_would_be(forwarder, run):
    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    environment = environment_of(run)
    assert environment["JIRA_SITE_URL"] == forwarder.url
    assert environment["JIRA_SITE_URL"].startswith("http://127.0.0.1:")
    assert environment["JIRA_EMAIL"] == REAL_EMAIL
    assert environment["JIRA_API_TOKEN"] not in ("", REAL_TOKEN)
    assert environment[OAUTH_TOKEN_VARIABLE] == OAUTH_TOKEN.value


# --- The model credential: an API key or an OAuth token, exactly one, under its own name ---


@pytest.mark.parametrize("credential", [API_KEY, OAUTH_TOKEN], ids=lambda c: c.variable)
def test_the_run_gets_the_model_credential_under_its_own_name_and_no_other(
    forwarder, run, monkeypatch, credential
):
    """The Claude CLI reads each kind under its own variable, so that is where it goes; the
    other variable is not set at all, not even empty, so nothing can be read into it."""
    for variable in TRUST_STORE_VARIABLES:
        monkeypatch.delenv(variable, raising=False)

    spawner_for(_program(DUMP_ENVIRONMENT), forwarder, model_credential=credential)(run)

    environment = environment_of(run)
    assert environment[credential.variable] == credential.value
    (other,) = set(MODEL_CREDENTIAL_VARIABLES) - {credential.variable}
    assert other not in environment
    assert set(environment) - PLATFORM_ADDITIONS == (A_RUNS_VARIABLES - {OAUTH_TOKEN_VARIABLE}) | {
        credential.variable
    }


@pytest.mark.parametrize("credential", [API_KEY, OAUTH_TOKEN], ids=lambda c: c.variable)
def test_a_run_that_prints_its_model_credential_does_not_get_it_into_the_log(
    forwarder, run, caplog, credential
):
    """On stderr as a failed Run's complaint, and on stdout as a Transcript line: the log
    formatter's redaction stands for both kinds, by the value's own prefix and by its name."""
    caplog.set_level(logging.INFO)
    leak = f"""\
import json, os, sys
name = {credential.variable!r}
print(json.dumps({{"type": "assistant", "message": {{"content": [
    {{"type": "text", "text": name + "=" + os.environ[name]}}]}}}}), flush=True)
print("refused with " + os.environ[name], file=sys.stderr)
sys.exit(1)
"""

    spawner_for(_program(leak), forwarder, model_credential=credential)(run)

    assert credential.value not in caplog.text
    assert "<redacted>" in caplog.text


def test_a_model_credential_never_shows_its_value_when_printed():
    """A traceback, a debug line or an assertion message must not be where it leaks."""
    assert API_KEY.value not in repr(API_KEY)
    assert API_KEY.value not in str(API_KEY)
    assert API_KEY.variable in repr(API_KEY)


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        pytest.param({API_KEY_VARIABLE: API_KEY.value}, API_KEY, id="api-key-alone"),
        pytest.param({OAUTH_TOKEN_VARIABLE: OAUTH_TOKEN.value}, OAUTH_TOKEN, id="oauth-alone"),
        pytest.param(
            {API_KEY_VARIABLE: f"  {API_KEY.value}  ", OAUTH_TOKEN_VARIABLE: ""},
            API_KEY,
            id="api-key-padded-and-oauth-empty",
        ),
        pytest.param(
            {API_KEY_VARIABLE: "   ", OAUTH_TOKEN_VARIABLE: OAUTH_TOKEN.value},
            OAUTH_TOKEN,
            id="api-key-blank-and-oauth-set",
        ),
    ],
)
def test_exactly_one_model_credential_is_taken_whichever_kind_it_is(environment, expected):
    assert model_credential_from_environment(environment) == expected


@pytest.mark.parametrize(
    ("environment", "words"),
    [
        pytest.param({}, "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set", id="none"),
        pytest.param(
            {API_KEY_VARIABLE: "", OAUTH_TOKEN_VARIABLE: " "},
            "neither ANTHROPIC_API_KEY nor CLAUDE_CODE_OAUTH_TOKEN is set",
            id="both-empty",
        ),
        pytest.param(
            {API_KEY_VARIABLE: API_KEY.value, OAUTH_TOKEN_VARIABLE: OAUTH_TOKEN.value},
            "both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set",
            id="both",
        ),
    ],
)
def test_no_model_credential_or_two_is_refused_by_name_and_never_by_value(environment, words):
    with pytest.raises(MissingModelCredential) as refusal:
        model_credential_from_environment(environment)

    said = str(refusal.value)
    assert words in said and "set exactly one" in said
    assert API_KEY.value not in said and OAUTH_TOKEN.value not in said


def test_the_run_can_read_jiras_clock(forwarder, run):
    """A Run has no clock of its own, so every duration it reports comes from Jira's.

    Reading it is a site-scoped call, which jira-as refuses unless the Run is told
    otherwise. On a laptop a settings file up the tree hides this; in the container
    there is no such tree, and every duration in every comment would break.
    """
    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    assert environment_of(run)[SITE_OPERATIONS_VARIABLE] == "true"


def test_the_run_may_name_the_demo_s_project_and_no_other(forwarder, run):
    """jira-as refuses a call naming any other project before it is sent (audit F7)."""
    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    assert environment_of(run)[ALLOWED_PROJECTS_VARIABLE] == PROJECT_KEY


def test_each_run_gets_its_own_sentinel(forwarder, tmp_path):
    spawner = spawner_for(_program(DUMP_ENVIRONMENT), forwarder)
    first, second = a_run(tmp_path / "runs", "first"), a_run(tmp_path / "runs", "second")

    spawner(first)
    spawner(second)

    assert environment_of(first)["JIRA_API_TOKEN"] != environment_of(second)["JIRA_API_TOKEN"]


def test_the_run_reaches_jira_through_the_forwarder_with_its_sentinel(forwarder, upstream, run):
    spawner_for(_program(DUMP_ENVIRONMENT, CALL_JIRA), forwarder)(run)

    assert len(upstream.received) == 1
    assert upstream.received[0].basic_auth == (REAL_EMAIL, REAL_TOKEN)
    assert environment_of(run)["JIRA_API_TOKEN"] not in str(upstream.received[0].headers)


def test_the_sentinel_is_worth_nothing_once_the_run_has_ended(forwarder, upstream, run):
    spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)
    sentinel = environment_of(run)["JIRA_API_TOKEN"]

    answer = http_request(forwarder.url + "/rest/api/3/myself", basic_auth=(REAL_EMAIL, sentinel))

    assert answer.status == 401
    assert upstream.received == []


def test_the_transcript_is_rendered_into_the_log(forwarder, run, caplog):
    caplog.set_level(logging.INFO)

    spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    assert "[claude] Searching OPS for a Match." in caplog.text
    assert "[tool]   Bash: jira-as search jql 'project = OPS'" in caplog.text
    assert "[result] success in 1.2s" in caplog.text


def test_the_runs_exit_status_is_returned(forwarder, run):
    assert spawner_for(_program(COMPLAIN_AND_FAIL), forwarder)(run).exit_status == 3


def test_a_failed_runs_stderr_is_logged(forwarder, run, caplog):
    caplog.set_level(logging.INFO)

    spawner_for(_program(COMPLAIN_AND_FAIL), forwarder)(run)

    assert "claude: onboarding was never accepted" in caplog.text


def test_a_failed_runs_stderr_is_redacted_like_every_other_log_line(forwarder, run, caplog):
    caplog.set_level(logging.INFO)

    spawner_for(_program(LEAK_A_CREDENTIAL_ON_STDERR), forwarder)(run)

    assert "c2VudGluZWw6bm90LWZvci1hLXNjcmVlbg==" not in caplog.text
    assert "<redacted>" in caplog.text


def test_a_successful_runs_stderr_stays_out_of_the_log(forwarder, run, caplog):
    caplog.set_level(logging.INFO)
    noisy = """\
import sys
print("a warning nobody in the audience needs", file=sys.stderr)
"""

    spawner_for(_program(noisy), forwarder)(run)

    assert "a warning nobody in the audience needs" not in caplog.text


def test_a_run_that_exceeds_the_timeout_is_killed_and_logged(forwarder, run, caplog):
    caplog.set_level(logging.INFO)
    started_at = time.monotonic()

    outcome = spawner_for(_program(HANG), forwarder, timeout=0.5)(run)

    assert time.monotonic() - started_at < 10, "the timeout did not kill the Run"
    assert outcome.exit_status != 0
    assert outcome.failure == "killed after its 0.5s timeout"
    assert f"run {run.run_id} exceeded" in caplog.text


def test_the_timeout_also_ends_what_the_run_started(forwarder, run, caplog):
    """A grandchild left holding the Transcript pipe would hang the Receiver's one worker."""
    caplog.set_level(logging.INFO)
    started_at = time.monotonic()

    spawner_for(_program(HANG_WITH_A_CHILD_OF_ITS_OWN), forwarder, timeout=0.5)(run)

    assert time.monotonic() - started_at < 10, "a child of the Run outlived the timeout"
    assert f"run {run.run_id} exceeded" in caplog.text


def test_a_timed_out_run_does_not_stall_the_queue(forwarder, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    receiver = Receiver(
        spawn_run=spawner_for(_program(HANG), forwarder, timeout=0.5),
        runs_directory=tmp_path / "runs",
    )
    receiver.start()
    try:
        post_notification(receiver, firing_notification())
        post_notification(receiver, firing_notification())
        log = wait_for_log(caplog, "finished with exit status", count=2, timeout=15)
    finally:
        receiver.stop()

    assert log.count("exceeded") == 2


# --- Failures read as failures (step 05 of demo-onboarding) ---

REFUSED_TRANSCRIPT = FIXTURES / "run-transcript-refused.jsonl"
"""A Run the API refused: `subtype: success`, `is_error: true`, exit 0 (see test_log_formatter)."""


def replaying(transcript: Path, exit_status: int = 0) -> str:
    """A stand-in Run that writes a saved Transcript to stdout, byte for byte, and exits."""
    return f"""\
import sys
sys.stdout.write(open({str(transcript)!r}, encoding="utf-8").read())
sys.stdout.flush()
sys.exit({exit_status})
"""


EMIT_ONE_LINE_THEN_HANG = """\
import json, sys, time
print(json.dumps({"type": "assistant", "message": {"content": [
    {"type": "text", "text": "Searching OPS for a Match."}]}}), flush=True)
time.sleep(30)
"""

A_RAW_LINE = json.dumps(
    {
        "type": "user",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_01",
                    "content": "password hunter2-is-not-a-real-password-at-all",
                }
            ]
        },
    }
)
"""A tool result carrying something credential-shaped, which the log must redact."""


def test_a_refused_run_that_exits_0_is_reported_as_failed(forwarder, run):
    """The exit status says success; the Transcript's result says what happened."""
    outcome = spawner_for(_program(replaying(REFUSED_TRANSCRIPT)), forwarder)(run)

    assert outcome.exit_status == 0
    assert outcome.failure == (
        "api_error: You're out of usage credits · manage usage credits at claude.ai/settings/usage"
    )


def test_a_refused_run_s_log_ends_on_its_failure_and_hint(forwarder, run, caplog):
    caplog.set_level(logging.INFO)

    spawner_for(_program(replaying(REFUSED_TRANSCRIPT)), forwarder)(run)

    assert "[FAILED] api_error: You're out of usage credits" in caplog.text
    assert f"[hint]   {HINT_CREDITS}" in caplog.text
    assert "[result]" not in caplog.text


def test_a_run_that_finished_its_job_reports_no_failure(forwarder, run):
    outcome = spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    assert (outcome.exit_status, outcome.failure) == (0, None)


def test_a_nonzero_exit_without_a_result_is_the_reason(forwarder, run):
    assert spawner_for(_program(COMPLAIN_AND_FAIL), forwarder)(run).failure == "exit status 3"


def test_a_run_that_exits_0_without_a_result_did_not_finish(forwarder, run):
    outcome = spawner_for(_program(DUMP_ENVIRONMENT), forwarder)(run)

    assert outcome.failure == "the Transcript ended without a result"


def test_a_failed_result_is_the_reason_even_when_the_exit_status_is_not_0(forwarder, run):
    """The result names the cause; a status only says there was one."""
    outcome = spawner_for(_program(replaying(REFUSED_TRANSCRIPT, exit_status=1)), forwarder)(run)

    assert outcome.exit_status == 1
    assert outcome.failure.startswith("api_error: You're out of usage credits")


def test_the_receiver_logs_a_refused_run_as_failed(forwarder, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    receiver = Receiver(
        spawn_run=spawner_for(_program(replaying(REFUSED_TRANSCRIPT)), forwarder),
        runs_directory=tmp_path / "runs",
    )
    receiver.start()
    try:
        post_notification(receiver, firing_notification())
        log = wait_for_log(caplog, "FAILED: api_error", timeout=15)
    finally:
        receiver.stop()

    assert "finished with exit status 0" in log
    assert "FAILED: api_error: You're out of usage credits" in log


def test_the_raw_transcript_is_kept_beside_the_notification(forwarder, run):
    """Every byte the Run wrote on stdout, before the formatter trimmed or redacted any."""
    spawner_for(_program(replaying(REFUSED_TRANSCRIPT)), forwarder)(run)

    kept = run.working_directory / TRANSCRIPT_FILENAME
    assert run.transcript_path == kept
    assert kept.read_bytes() == REFUSED_TRANSCRIPT.read_bytes()


def test_the_transcript_s_path_is_logged(forwarder, run, caplog):
    caplog.set_level(logging.INFO)

    spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    assert f"run {run.run_id} transcript: {run.transcript_path}" in caplog.text


def test_the_transcript_stays_inside_what_a_run_may_read_and_nothing_wider(forwarder, run):
    """It is in the Run's own working directory, under the one directory the Read rule names."""
    spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    runs = run.working_directory.parent.resolve()
    assert run.transcript_path.resolve().parent == run.working_directory.resolve()
    assert run.transcript_path.resolve().is_relative_to(runs)
    assert read_rule(runs) == f"Read(/{runs}/**)"


def test_the_log_is_redacted_though_the_transcript_on_disk_is_raw(forwarder, run, caplog):
    caplog.set_level(logging.INFO)
    program = f"print({A_RAW_LINE!r}, flush=True)"

    spawner_for(_program(program), forwarder)(run)

    assert "hunter2-is-not-a-real-password-at-all" not in caplog.text
    assert "<redacted>" in caplog.text
    assert run.transcript_path.read_text(encoding="utf-8") == A_RAW_LINE + "\n"


def test_a_run_that_is_killed_leaves_what_it_said_up_to_then(forwarder, run):
    # Long enough for a loaded machine to start Python and print, far short of the child's 30s.
    spawner_for(_program(EMIT_ONE_LINE_THEN_HANG), forwarder, timeout=3)(run)

    [line] = run.transcript_path.read_text(encoding="utf-8").splitlines()
    assert "Searching OPS for a Match." in line


def test_a_transcript_that_cannot_be_written_costs_the_copy_and_not_the_run(forwarder, run, caplog):
    caplog.set_level(logging.INFO)
    run.transcript_path.mkdir()

    outcome = spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    assert (outcome.exit_status, outcome.failure) == (0, None)
    assert "[result] success in 1.2s" in caplog.text
    assert f"the transcript {run.transcript_path} cannot be written" in caplog.text


def test_a_failure_in_the_transcript_is_logged_above_info(forwarder, run, caplog):
    """So a log filtered to warnings still shows why a Run failed, and what it was refused."""
    caplog.set_level(logging.INFO)

    spawner_for(_program(replaying(REFUSED_TRANSCRIPT)), forwarder)(run)

    levels = {r.getMessage().split(" ", 1)[0]: r.levelno for r in caplog.records}
    assert levels["[FAILED]"] == logging.ERROR
    assert levels["[hint]"] == logging.WARNING
    assert levels["[claude]"] == logging.INFO


class FillsUp:
    """A file on a tmpfs that fills after one line: every later write, and the close, fail."""

    def __init__(self, path, *args, **kwargs):
        self.lines: list[str] = []
        self.path = path

    def write(self, line: str) -> int:
        if self.lines:
            raise OSError(28, "No space left on device")
        self.lines.append(line)
        return len(line)

    def close(self) -> None:
        raise OSError(28, "No space left on device")


def test_a_transcript_that_fills_its_tmpfs_costs_the_rest_of_the_copy_and_not_the_run(
    forwarder, run, caplog, monkeypatch
):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(run_spawner, "open", FillsUp, raising=False)

    outcome = spawner_for(_program(EMIT_A_TRANSCRIPT), forwarder)(run)

    assert (outcome.exit_status, outcome.failure) == (0, None)
    assert "[result] success in 1.2s" in caplog.text
    assert f"the transcript {run.transcript_path} stopped being written" in caplog.text
    assert caplog.text.count("stopped being written") == 1
