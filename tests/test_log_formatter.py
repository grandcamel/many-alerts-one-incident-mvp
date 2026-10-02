"""The log formatter renders one Run event into audience lines.

`format_event` is a pure function: one parsed Run event in, zero or more display
lines out. The table below is driven by events taken straight from the recorded
Transcript in `fixtures/run-transcript.jsonl` wherever a real event exists for
the case, so the expectations are pinned to what the Claude CLI actually emits
rather than to what we imagine it emits.
"""

from __future__ import annotations

import base64
import copy
import json
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass

import pytest

from grafana_jsm_sandbox.forwarder import (
    CREATE_INCOMPLETE,
    CREATE_REFUSAL,
    CREATE_REFUSED_BODY,
    incomplete_create_body,
)
from grafana_jsm_sandbox.log_formatter import (
    DIAGNOSTIC,
    FAILED,
    HINT,
    HINT_BUDGET,
    HINT_CREDITS,
    HINT_MODEL,
    HINT_RATE_LIMIT,
    HINT_TOKEN,
    REPORTED_FAILURE,
    RESULT,
    RUN,
    TRIM_CHARS,
    format_event,
    format_stream,
    redact,
    redact_stderr_chunks,
    run_failure,
)
from tests.conftest import FIXTURES, REPOSITORY

REPO_ROOT = FIXTURES.parent
TRANSCRIPT = FIXTURES / "run-transcript.jsonl"


def recorded(match) -> dict:
    """The first event in the recorded Transcript satisfying `match`."""
    for line in TRANSCRIPT.read_text().splitlines():
        event = json.loads(line)
        if match(event):
            return event
    raise AssertionError("no recorded event matched")


def assistant_event(content: list[dict]) -> dict:
    return {"type": "assistant", "message": {"role": "assistant", "content": content}}


def tool_call_event(name: str, tool_input: dict) -> dict:
    return assistant_event(
        [{"type": "tool_use", "id": "toolu_01", "name": name, "input": tool_input}]
    )


def bash_event(command: str) -> dict:
    return tool_call_event("Bash", {"command": command})


def tool_result_event(content, is_error: bool = False) -> dict:
    return {
        "type": "user",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_01",
                    "content": content,
                    "is_error": is_error,
                }
            ],
        },
    }


def long_tool_output(kind: str) -> str:
    if kind == "plain":
        return "x" * 200_000
    if kind == "key-name":
        return "token" * 40_000
    if kind == "flag-name":
        return "--" + "token" * 40_000
    if kind == "assignment-chain":
        return "label=" * 40_000
    if kind == "opaque-digits":
        return "1" * 200_000
    if kind == "whitespace":
        return "Authorization:" + " " * 200_000
    record = {"key": "value", "url": "https://lgtm.invalid/api/query?key=label"}
    record.update({f"token_key_secret_label_{i}": "value" for i in range(6000)})
    return json.dumps(record, separators=(",", ":"))


@pytest.mark.parametrize("kind", [
    "plain", "json", "key-name", "flag-name", "assignment-chain", "opaque-digits", "whitespace",
])
def test_large_tool_output_formats_well_under_a_second(kind):
    # Keep a quadratic regression from pinning the suite in a regex for minutes.
    code = """
import json, sys, time
from tests.test_log_formatter import long_tool_output, tool_result_event
from grafana_jsm_sandbox.log_formatter import format_event
event = tool_result_event(long_tool_output(sys.argv[1]))
start = time.perf_counter()
lines = format_event(event)
print(json.dumps([time.perf_counter() - start, lines]))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, kind], capture_output=True, text=True,
        timeout=2, check=True,
    )
    elapsed, lines = json.loads(result.stdout)
    assert elapsed < 0.5
    assert len(lines) == 1 and lines[0].startswith("[out]    ") and lines[0].endswith("...")


def test_large_tool_output_redacts_supplied_values_before_trimming():
    values = ("sentinel-private-value", "model-private-value", "viewer-private-value")
    body = " ".join(values) + " " + "x" * 200_000 + " " + " ".join(values)
    start = time.perf_counter()
    rendered = "\n".join(format_event(tool_result_event(body), active_secrets=values))
    assert time.perf_counter() - start < 0.5
    assert rendered.startswith("[out]    <redacted> <redacted> <redacted> ")
    for value in values:
        assert_no_secret_fragment(rendered, value)


def test_tool_output_is_sanitized_only_once(monkeypatch):
    from grafana_jsm_sandbox import log_formatter

    original = log_formatter.redact
    inputs = []

    def record(text, **kwargs):
        inputs.append(text)
        return original(text, **kwargs)

    monkeypatch.setattr(log_formatter, "redact", record)
    body = "safe output " + "x" * 200_000
    format_event(tool_result_event(body))
    assert inputs == [body]


@pytest.mark.parametrize("text", [
    'url="https://lgtm.invalid/query?api_key=private-value"',
    "--label=https://lgtm.invalid/query?token=private-value",
    "label=label=label=secret=private-value",
])
def test_nonsecret_names_do_not_hide_nested_credential_assignments(text):
    redacted = redact(text)
    assert "private-value" not in redacted
    assert "<redacted>" in redacted


def test_ordinary_presenter_lines_match_main():
    # Literal expectations captured from f910a5b, including all five presenter cues.
    events = [
        bash_event("grafana-query loki --query '{service=\"checkout\"}'"),
        tool_result_event("First line\n" + "x" * 220),
        tool_result_event("query refused", is_error=True),
        assistant_event([{"type": "text", "text": "OPS-41 is the Match."}]),
        result_event(),
    ]
    assert [line for event in events for line in format_event(event)] == [
        '[tool]   Bash: grafana-query loki --query \'{service="checkout"}\'',
        "[out]    First line",
        "[out]    " + "x" * 200 + "...",
        "[err]    query refused",
        "[claude] OPS-41 is the Match.",
        "[result] success in 1.5s, 2 turns, $0.1000",
    ]


def result_event(**fields) -> dict:
    return {
        "type": "result",
        "subtype": "success",
        "duration_ms": 1500,
        "num_turns": 2,
        "total_cost_usd": 0.1,
        **fields,
    }


REFUSAL_MESSAGE = json.loads(CREATE_REFUSED_BODY)["errorMessages"][0]

JIRA_AS_ON_THE_REFUSED_CREATE = f"""Exit code 1
[ERROR] Jira Error: Failed to create issue: {REFUSAL_MESSAGE}

This usually means the resource was modified by another user.
Try refreshing and applying your changes again.
  Details: [create issue] (HTTP 409) Failed to create issue: {REFUSAL_MESSAGE}

Response data: {{'errorMessages': ['{REFUSAL_MESSAGE}'], 'errors': {{}}}}"""
"""What a Run's Bash tool hands back when jira-as meets the Forwarder's 409, as jira-as 2.0.0
prints a ConflictError."""

LACKED = "its description is not a document with a bullet list"
INCOMPLETE_MESSAGE = json.loads(incomplete_create_body(LACKED))["errorMessages"][0]

JIRA_AS_ON_THE_INCOMPLETE_CREATE = f"""Exit code 1
[ERROR] Validation Error: {INCOMPLETE_MESSAGE}
  Details: [create issue] (HTTP 400) {INCOMPLETE_MESSAGE}

Response data: {{'errorMessages': ['{INCOMPLETE_MESSAGE}'], 'errors': {{}}}}"""
"""What a Run's Bash tool hands back when jira-as meets the Forwarder's 400 for a first create
that did not carry an Incident's content."""


@dataclass
class Case:
    id: str
    event: object
    expected: list[str]


CASES = [
    Case(
        id="run-start-names-the-permission-mode-and-allowed-tools",
        event=recorded(lambda e: e.get("subtype") == "init"),
        expected=["[run]    model=claude-fable-5-1 permission-mode=dontAsk tools=Bash,Read"],
    ),
    Case(
        id="assistant-text",
        event=recorded(
            lambda e: e.get("type") == "assistant" and e["message"]["content"][0]["type"] == "text"
        ),
        expected=["[claude] I'll run the two bash commands in order and report which worked."],
    ),
    Case(
        id="assistant-text-over-several-lines",
        event=assistant_event(
            [{"type": "text", "text": "Alert is firing.\n\nOPS-41 is the Match."}]
        ),
        expected=[
            "[claude] Alert is firing.",
            "[claude] OPS-41 is the Match.",
        ],
    ),
    Case(
        id="bash-tool-call-shows-its-command",
        event=recorded(
            lambda e: (
                e.get("type") == "assistant" and e["message"]["content"][0]["type"] == "tool_use"
            )
        ),
        expected=["[tool]   Bash: seq 1 40"],
    ),
    Case(
        id="read-tool-call-shows-its-path",
        event=tool_call_event(
            "Read", {"file_path": "/runs/20260915T164012-9f3ac1/notification.json"}
        ),
        expected=["[tool]   Read: /runs/20260915T164012-9f3ac1/notification.json"],
    ),
    Case(
        # Presenter story 5 wants every jira-as command in the log. A command cut
        # off halfway is the line that invites the question of what the rest said.
        id="long-command-is-shown-in-full",
        event=bash_event(
            "jira-as issue create --project OPS " + "--label fp-a1b2c3d4e5f60718 " * 12
        ),
        expected=[
            "[tool]   Bash: jira-as issue create --project OPS "
            + "--label fp-a1b2c3d4e5f60718 " * 12
        ],
    ),
    Case(
        id="tool-result-longer-than-the-trim-limit-is-trimmed",
        event=recorded(
            lambda e: e.get("type") == "user" and not e["message"]["content"][0].get("is_error")
        ),
        expected=[
            "[out]    1",
            "[out]    2",
            "[out]    3",
            "[out]    4",
            "[out]    5",
            "[out]    + 35 more lines",
        ],
    ),
    Case(
        id="tool-result-line-wider-than-the-trim-limit-is-truncated",
        event=tool_result_event("OPS-41 " + "x" * 400),
        expected=["[out]    OPS-41 " + "x" * 193 + "..."],
    ),
    Case(
        id="result-of-a-denied-call-is-not-echoed-a-second-time",
        event=recorded(lambda e: e.get("type") == "user" and e.get("tool_result_meta")),
        expected=[],
    ),
    Case(
        id="failing-tool-result-is-marked-as-error",
        event=tool_result_event("jira-as: no Incident matched", is_error=True),
        expected=["[err]    jira-as: no Incident matched"],
    ),
    Case(
        # jira-as wraps the Forwarder's 409 in "Jira Error", a hint to refresh and apply the
        # change again, and a copy of the response, which reads as a crash and says the
        # opposite of what the Forwarder means. The Transcript keeps all of it.
        id="a-second-create-the-forwarder-refused-reads-as-a-refusal-not-a-crash",
        event=tool_result_event(JIRA_AS_ON_THE_REFUSED_CREATE, is_error=True),
        expected=[
            (
                "[DENIED] Jira create refused by the Forwarder: this Run already made its one "
                "create attempt"
            )
        ],
    ),
    Case(
        id="a-first-create-without-an-incidents-content-reads-as-a-refusal-and-says-what-it-lacked",
        event=tool_result_event(JIRA_AS_ON_THE_INCOMPLETE_CREATE, is_error=True),
        expected=[f"[DENIED] Jira create refused by the Forwarder: {CREATE_INCOMPLETE} ({LACKED})"],
    ),
    Case(
        id="the-refusal-words-in-a-result-that-did-not-fail-are-just-output",
        event=tool_result_event(f"notes: {CREATE_REFUSAL}"),
        expected=[f"[out]    notes: {CREATE_REFUSAL}"],
    ),
    Case(
        id="permission-denied-is-unmistakable",
        event=recorded(lambda e: e.get("subtype") == "permission_denied"),
        expected=[
            (
                "[DENIED] Bash: Permission to use Bash has been denied because Claude Code "
                "is running in don't ask mode."
            ),
        ],
    ),
    Case(
        id="permission-denied-without-a-message-still-says-so",
        event={
            "type": "system",
            "subtype": "permission_denied",
            "tool_name": "WebFetch",
            "decision_reason_type": "mode",
        },
        expected=["[DENIED] WebFetch: denied (mode)"],
    ),
    Case(
        id="final-result-carries-cost-and-duration",
        event=recorded(lambda e: e.get("type") == "result"),
        expected=[
            "[DENIED] Bash: ls /etc",
            "[result] success in 10.0s, 3 turns, $0.4527",
        ],
    ),
    Case(
        id="result-without-denials-is-a-single-line",
        event=result_event(permission_denials=[]),
        expected=["[result] success in 1.5s, 2 turns, $0.1000"],
    ),
    Case(
        # An `error_` subtype is a failure whether or not `is_error` says so, and a
        # failure with nothing else to say still ends the log saying it failed.
        id="error-subtype-with-nothing-else-still-reads-as-failed",
        event={"type": "result", "subtype": "error_during_execution"},
        expected=["[FAILED] error_during_execution: no result text"],
    ),
    Case(
        id="system-chatter-renders-nothing",
        event=recorded(lambda e: e.get("subtype") == "task_summary"),
        expected=[],
    ),
    Case(
        id="unknown-event-type-gets-one-diagnostic-line",
        event={"type": "wobble", "payload": 1},
        expected=["[?]      unrecognised event type 'wobble'"],
    ),
    Case(
        id="event-that-is-not-an-object-gets-one-diagnostic-line",
        event=[1, 2, 3],
        expected=["[?]      event is not a JSON object"],
    ),
    Case(
        id="malformed-known-event-gets-one-diagnostic-line",
        event={"type": "assistant", "message": "this should have been an object"},
        expected=["[?]      'assistant' event could not be rendered"],
    ),
    Case(
        id="assistant-event-with-no-content-renders-nothing",
        event=assistant_event([]),
        expected=[],
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
def test_event_renders_its_audience_lines(case):
    assert format_event(case.event) == case.expected


# A per-Run sentinel is a random token with no recognisable prefix. The earlier
# version of this table used an ATATT-prefixed value, which the prefix rule
# rescued no matter what the rule under test did; four of these commands leaked.
# This one carries punctuation, so the catch-all for long opaque values cannot
# rescue the rules either: each has to fire on its own.
SENTINEL = "xK3-mZ9_qB7tW2vR5nL8pC4y"
BARE_SENTINEL = "9f3ac1d7e4b8c05a1d2e3f405162738495a6b7c8"
ATLASSIAN_TOKEN = "ATATT3xFfGF0aBcDeFgHiJkLmNoP"
BASIC_CREDENTIAL = "ZW1haWw6c2VjcmV0dG9rZW4="

CREDENTIAL_COMMANDS = [
    pytest.param(
        f"curl -H 'Authorization: Basic {SENTINEL}' https://site/rest", SENTINEL, id="basic-header"
    ),
    pytest.param(
        f'curl -H "Authorization: SSWS {SENTINEL}" https://site/rest', SENTINEL, id="other-scheme"
    ),
    pytest.param(
        f"curl -u user@example.invalid:{SENTINEL} https://site/rest", SENTINEL, id="curl-user-flag"
    ),
    pytest.param(f"jira-as issue get OPS-41 --token {SENTINEL}", SENTINEL, id="token-flag"),
    pytest.param(
        f'jira-as issue get OPS-41 --token "{SENTINEL}"', SENTINEL, id="quoted-token-flag"
    ),
    pytest.param(f"jira-as issue get OPS-41 --api-key={SENTINEL}", SENTINEL, id="api-key-flag"),
    pytest.param(
        f"env JIRA_API_TOKEN={SENTINEL} jira-as issue get OPS-41", SENTINEL, id="env-assignment"
    ),
    pytest.param(f'{{"jira_api_token": "{SENTINEL}"}}', SENTINEL, id="json-field"),
    pytest.param(
        f"machine site.atlassian.net login me password {SENTINEL}", SENTINEL, id="netrc-line"
    ),
    pytest.param(
        f"echo {BARE_SENTINEL} | mail me", BARE_SENTINEL, id="bare-value-with-no-clue-around-it"
    ),
    pytest.param(f"echo {ATLASSIAN_TOKEN} | mail me", ATLASSIAN_TOKEN, id="atlassian-token"),
    pytest.param(
        f"echo 'Basic {BASIC_CREDENTIAL}' >> notes", BASIC_CREDENTIAL, id="bare-basic-credential"
    ),
]


@pytest.mark.parametrize(("command", "credential"), CREDENTIAL_COMMANDS)
@pytest.mark.parametrize(
    "as_event",
    [
        pytest.param(bash_event, id="in-a-tool-call"),
        pytest.param(lambda text: tool_result_event(text), id="in-a-tool-result"),
        pytest.param(
            lambda text: result_event(
                permission_denials=[{"tool_name": "Bash", "tool_input": {"command": text}}]
            ),
            id="in-a-denied-command",
        ),
        pytest.param(
            lambda text: result_event(is_error=True, terminal_reason="api_error", result=text),
            id="in-a-failed-result",
        ),
    ],
)
def test_no_line_ever_carries_a_credential(as_event, command, credential):
    lines = format_event(as_event(command))

    assert lines, "the event rendered nothing, so the redaction was not exercised"
    rendered = "\n".join(lines)
    assert credential not in rendered
    leaked = [
        credential[at : at + 8]
        for at in range(len(credential) - 8)
        if credential[at : at + 8] in rendered
    ]
    assert not leaked, f"part of the credential survived: {leaked}"
    assert "Authorization: Basic" not in rendered
    assert "<redacted>" in rendered


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "The token is a sentinel, so the real password never reaches the Run.",
            id="prose-about-credentials",
        ),
        pytest.param(
            "jira-as issue create --project OPS --label fp-a1b2c3d4e5f60718",
            id="a-fingerprint-label",
        ),
        pytest.param(
            "https://site.atlassian.net/rest/api/3/issue/10001 at 2026-09-15T16:40:12Z",
            id="urls-and-timestamps",
        ),
    ],
)
def test_redaction_leaves_the_demo_vocabulary_alone(text):
    assert format_event(assistant_event([{"type": "text", "text": text}])) == [f"[claude] {text}"]


URLSAFE_SENTINEL = "aB3-cD4_eF5gH6iJ7kL8mN9oP0qR1sT2"


@pytest.fixture
def active_sentinel(monkeypatch):
    """Exercise the production factory's alphabet, using synthetic bytes only."""
    from grafana_jsm_sandbox.run_spawner import SENTINEL_BYTES

    raw = base64.urlsafe_b64decode(URLSAFE_SENTINEL)
    assert len(raw) == SENTINEL_BYTES == 24
    monkeypatch.setattr(secrets, "token_bytes", lambda size: raw if size == 24 else b"")
    generated = secrets.token_urlsafe(SENTINEL_BYTES)
    assert generated == URLSAFE_SENTINEL
    return generated


def assert_no_secret_fragment(rendered, secret):
    assert not any(secret[at : at + 8] in rendered for at in range(len(secret) - 7))


@pytest.mark.parametrize(
    "as_event",
    [
        pytest.param(lambda text: assistant_event([{"type": "text", "text": text}]), id="assistant"),
        pytest.param(tool_result_event, id="tool-output"),
        pytest.param(lambda text: tool_result_event(text, is_error=True), id="tool-error"),
        pytest.param(lambda text: result_event(result="failed: " + text), id="reported-failure"),
        pytest.param(lambda text: result_event(is_error=True, result=text), id="api-failure"),
        pytest.param(
            lambda text: result_event(permission_denials=[
                {"tool_name": "Bash", "tool_input": {"command": "echo " + text}}
            ]),
            id="denied-command",
        ),
        pytest.param(lambda text: {"type": text}, id="unknown-type"),
    ],
)
def test_live_projection_redacts_exact_factory_values_without_mutating_events(
    active_sentinel, as_event
):
    event = as_event(active_sentinel)
    original = copy.deepcopy(event)
    rendered = "\n".join(format_event(event, active_secrets=(active_sentinel,)))

    assert "<redacted>" in rendered
    assert_no_secret_fragment(rendered, active_sentinel)
    assert event == original


@pytest.mark.parametrize(("credential_text", "secret"), CREDENTIAL_COMMANDS)
@pytest.mark.parametrize(
    "surface", ["output", "error", "api-failure", "reported-failure", "failure-return"]
)
def test_supported_credentials_are_redacted_before_character_clipping(credential_text, secret, surface):
    # Only sixteen characters of the credential fit at the boundary: a regex
    # recognizing the full value must run before the formatter cuts it short.
    reason_width = (
        len("run reported failed: ") if surface == "reported-failure"
        else len("success: ") if surface not in {"output", "error"} else 0
    )
    lead = "evidence " + "." * (
        TRIM_CHARS - 16 - reason_width - len("evidence ") - credential_text.index(secret)
    )
    body = lead + credential_text
    if surface in {"output", "error"}:
        rendered = "\n".join(format_event(tool_result_event(body, is_error=surface == "error")))
    else:
        event = result_event(
            result=("failed: " if surface == "reported-failure" else "") + body,
            is_error=surface != "reported-failure",
        )
        rendered = (
            run_failure(event) if surface == "failure-return" else "\n".join(format_event(event))
        )

    assert rendered
    assert_no_secret_fragment(rendered, secret)
    assert "<redacted>" in rendered


@pytest.mark.parametrize("shape", ["unknown", "malformed"])
def test_fallback_diagnostics_always_redact_embedded_credentials(shape, monkeypatch):
    from grafana_jsm_sandbox import log_formatter

    kind = "sk-ant-api03-abcdefghijklmnop"
    if shape == "malformed":
        def cannot_render(event, **kwargs):
            raise ValueError("malformed event")

        monkeypatch.setitem(log_formatter._RENDERERS, kind, cannot_render)
    rendered = "\n".join(format_event({"type": kind}))

    assert rendered.startswith(DIAGNOSTIC)
    assert_no_secret_fragment(rendered, kind)
    assert "<redacted>" in rendered


@pytest.mark.parametrize("as_event", [
    lambda body: assistant_event([{"type": "text", "text": body}]),
    tool_result_event,
    lambda body: result_event(is_error=True, result=body),
    lambda body: {"type": "system", "subtype": "permission_denied", "message": body},
])
def test_credential_recognition_precedes_line_and_sentence_clipping(as_event):
    secret = "c2VudGluZWw6bm90LWZvci1hLXNjcmVlbg=="
    rendered = "\n".join(format_event(as_event("Authorization: Basic\n" + secret)))
    assert_no_secret_fragment(rendered, secret)
    assert "<redacted>" in rendered


def test_exact_context_preserves_normal_identifiers_and_stream_input(active_sentinel):
    text = (
        "fp-a1b2c3d4e5f60718 550e8400-e29b-41d4-a716-446655440000 "
        "https://site.atlassian.net/rest/api/3/issue/10001 OPS-41 "
        "2026-09-15T16:40:12Z"
    )
    event = assistant_event([{"type": "text", "text": text + " " + active_sentinel}])
    raw = json.dumps(event)
    assert list(format_stream([raw], active_secrets=(active_sentinel,))) == [
        f"[claude] {text} <redacted>"
    ]
    assert json.loads(raw) == event
    assert redact(text, active_secrets=(active_sentinel, "")) == text


def test_stream_renders_a_recorded_transcript_end_to_end():
    lines = list(format_stream(TRANSCRIPT.read_text().splitlines()))

    assert lines[0].startswith("[run]")
    assert any(line.startswith("[claude]") for line in lines)
    assert "[tool]   Bash: seq 1 40" in lines
    assert "[out]    + 35 more lines" in lines
    assert "[DENIED] Bash: ls /etc" in lines
    assert lines[-1].startswith("[result] success in ")


def test_stream_survives_a_line_that_is_not_json():
    lines = list(format_stream(["not json at all", '{"type": "result", "subtype": "success"}']))

    assert lines[0].startswith("[?]")
    assert lines[1].startswith("[result]")


def test_stream_reads_the_bytes_a_run_writes():
    written = json.dumps(
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "OPS-41 opened"}]}}
    ).encode()

    assert list(format_stream([written])) == ["[claude] OPS-41 opened"]


def test_stream_ignores_blank_lines():
    assert list(format_stream(["", "   ", ""])) == []


@pytest.mark.parametrize(
    ("argv", "stdin"),
    [
        pytest.param([str(TRANSCRIPT)], None, id="transcript-named-on-the-command-line"),
        pytest.param([], TRANSCRIPT.read_text(), id="transcript-on-standard-input"),
    ],
)
def test_command_line_entry_renders_the_recorded_transcript(argv, stdin):
    result = subprocess.run(
        [sys.executable, "-m", "grafana_jsm_sandbox.log_formatter", *argv],
        cwd=REPO_ROOT,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].startswith("[run]")
    assert "[DENIED] Bash: ls /etc" in lines
    assert lines[-1].startswith("[result] success in ")


INCIDENT_TRANSCRIPT = FIXTURES / "run-transcript-repeat-firing.jsonl"
"""A whole real Run: the repeat Firing that commented the trend and moved OPS-7 on."""


def test_a_whole_real_run_renders_without_a_single_diagnostic():
    """The Transcript a demo actually produces, rendered by the code a demo runs."""
    lines = list(format_stream(INCIDENT_TRANSCRIPT.read_text().splitlines()))

    unrendered = [line for line in lines if line.startswith(DIAGNOSTIC)]
    assert not unrendered, f"the formatter did not understand a real Run: {unrendered}"

    # The audience has to be able to read every jira-as command in full.
    assert any("jira-as collaborate comment add OPS-7" in line for line in lines)
    assert any("jira-as lifecycle transition OPS-7 --id 31" in line for line in lines)
    assert lines[0].startswith(RUN)
    assert lines[-1].startswith(RESULT)


def test_a_whole_real_run_puts_nothing_credential_shaped_on_the_screen():
    text = "\n".join(format_stream(INCIDENT_TRANSCRIPT.read_text().splitlines()))
    assert "Authorization" not in text
    assert "JIRA_API_TOKEN" not in text


# --- Failures read as failures (step 05 of demo-onboarding) ---

REFUSED_TRANSCRIPT = FIXTURES / "run-transcript-refused.jsonl"
"""A Run the API refused before it did anything, sanitized and rebuilt from what was recorded.

The owner's note from 2026-09-15 records a Run refused for want of usage credits: the
refusal text ("You're out of usage credits ... manage usage credits at
claude.ai/settings/usage", elided in the note), `subtype: success`, `is_error: true`,
`terminal_reason: api_error`, zero cost, one turn, and exit 0. The init and assistant lines
around that result take the shape of the recorded Transcripts beside it. Nothing in it
came from a real account: the session and message ids are made up, and no token was ever
in it to remove."""

REFUSAL = "You're out of usage credits · manage usage credits at claude.ai/settings/usage"


def refused_result() -> dict:
    """The refused Run's result event, as the fixture holds it."""
    for line in REFUSED_TRANSCRIPT.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("type") == "result":
            return event
    raise AssertionError("the refused Transcript has no result")


def test_a_refused_run_reads_as_failed_though_it_says_success():
    """`subtype: success` and exit 0 are what the Run says; `is_error` is what happened."""
    event = refused_result()
    assert (event["subtype"], event["is_error"], event["terminal_reason"]) == (
        "success",
        True,
        "api_error",
    )

    assert format_event(event) == [
        f"[FAILED] api_error: {REFUSAL}",
        f"[hint]   {HINT_CREDITS}",
    ]


def test_the_refused_transcript_ends_on_its_failure_and_its_hint():
    lines = list(format_stream(REFUSED_TRANSCRIPT.read_text(encoding="utf-8").splitlines()))

    assert lines[0].startswith(RUN)
    assert not [line for line in lines if line.startswith(DIAGNOSTIC)]
    assert not [line for line in lines if line.startswith(RESULT)], "it must not read as success"
    assert lines[-2] == f"[FAILED] api_error: {REFUSAL}"
    assert lines[-1].startswith(HINT)


def test_the_command_line_renders_a_refused_transcript_as_failed():
    result = subprocess.run(
        [sys.executable, "-m", "grafana_jsm_sandbox.log_formatter", str(REFUSED_TRANSCRIPT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"[FAILED] api_error: {REFUSAL}" in result.stdout.splitlines()


@pytest.mark.parametrize(
    ("fields", "hint"),
    [
        pytest.param({"result": REFUSAL}, HINT_CREDITS, id="out-of-usage-credits"),
        pytest.param(
            # The telemetry research's bare-mode Run, which had no credential it would read.
            {"result": "Not logged in · Please run /login"},
            HINT_TOKEN,
            id="not-logged-in",
        ),
        pytest.param(
            {"result": "OAuth token has expired", "api_error_status": 401},
            HINT_TOKEN,
            id="expired-oauth-token",
        ),
        pytest.param({"result": "API Error", "api_error_status": 401}, HINT_TOKEN, id="http-401"),
        pytest.param(
            {"result": "API Error: rate limit reached", "api_error_status": 429},
            HINT_RATE_LIMIT,
            id="rate-limit",
        ),
        # Unrecorded here: Claude Code's own words for a subscription limit, which may
        # arrive with api_error_status unset, as the recorded credit refusal did.
        pytest.param(
            {"result": "Claude AI usage limit reached|1790000000"},
            HINT_RATE_LIMIT,
            id="usage-limit-reached-unrecorded",
        ),
        pytest.param(
            {"result": "You've hit your limit · resets 5pm"},
            HINT_RATE_LIMIT,
            id="hit-your-limit-unrecorded",
        ),
        pytest.param(
            {
                "result": "There's an issue with the selected model (claude-opus-5). "
                "It may not exist or you may not have access to it.",
                "api_error_status": 404,
            },
            HINT_MODEL,
            id="model-not-available-to-the-seat",
        ),
        pytest.param(
            {"subtype": "error_max_budget_usd", "terminal_reason": None, "errors": []},
            HINT_BUDGET,
            id="budget-exceeded",
        ),
    ],
)
def test_a_known_cause_gets_its_hint_under_the_failure(fields, hint):
    lines = format_event(
        result_event(**{"is_error": True, "terminal_reason": "api_error", **fields})
    )

    assert lines[0].startswith(FAILED)
    assert lines[1:] == [f"[hint]   {hint}"]


@pytest.mark.parametrize(
    ("hint", "variable"),
    [(HINT_MODEL, "RUN_MODEL"), (HINT_CREDITS, "RUN_MODEL"), (HINT_BUDGET, "RUN_BUDGET_USD")],
)
def test_the_model_credit_and_budget_hints_name_the_knob_that_changes_them(hint, variable):
    """Each comes from `.env` (steps 06 and 09 of demo-onboarding), so the hint says which line."""
    assert variable in hint


def test_the_readme_quotes_the_refused_transcript_as_it_renders():
    """The README's refused-Run sample is this fixture's rendering, word for word."""
    readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    rendered = format_stream(REFUSED_TRANSCRIPT.read_text(encoding="utf-8").splitlines())

    for line in rendered:
        assert f"\n{line}\n" in readme, line


def test_an_unknown_cause_gets_no_hint_rather_than_a_wrong_one():
    event = result_event(is_error=True, terminal_reason="api_error", result="API Error: 500")

    assert format_event(event) == ["[FAILED] api_error: API Error: 500"]


def test_a_jira_authentication_failure_does_not_blame_the_claude_token():
    """jira-as's error can say "Authentication failed"; the Jira credential is the one at
    fault, and the Forwarder's 401 line says so."""
    event = result_event(
        subtype="error_during_execution",
        is_error=True,
        errors=["jira-as: Authentication failed (401)"],
    )

    assert format_event(event) == [
        "[FAILED] error_during_execution: jira-as: Authentication failed (401)"
    ]


def test_a_malformed_errors_field_costs_the_hint_but_never_the_failed_line():
    event = result_event(is_error=True, terminal_reason="api_error", result="boom", errors=5)

    assert format_event(event) == ["[FAILED] api_error: boom"]


def test_a_failure_names_the_terminal_reason_before_the_subtype():
    """At the turn limit the subtype is `error_max_turns` and the reason `max_turns`."""
    event = result_event(
        subtype="error_max_turns",
        is_error=True,
        terminal_reason="max_turns",
        errors=["Reached maximum number of turns (8)"],
    )

    assert format_event(event) == ["[FAILED] max_turns: Reached maximum number of turns (8)"]


def test_a_failure_shows_only_the_first_line_of_what_the_run_said():
    event = result_event(is_error=True, result="\nFirst line.\nSecond line.\n")

    assert format_event(event) == ["[FAILED] success: First line."]


def test_a_failed_run_still_recaps_its_denials_first():
    event = result_event(
        is_error=True,
        terminal_reason="api_error",
        result="API Error: 500",
        permission_denials=[{"tool_name": "Bash", "tool_input": {"command": "ls /etc"}}],
    )

    assert format_event(event) == ["[DENIED] Bash: ls /etc", "[FAILED] api_error: API Error: 500"]


def test_is_error_false_with_a_success_subtype_is_a_success():
    event = result_event(is_error=False, terminal_reason="completed")

    assert format_event(event) == ["[result] success in 1.5s, 2 turns, $0.1000"]
    assert run_failure(event) is None


def test_the_spawner_and_the_log_agree_on_why_a_run_failed():
    assert run_failure(refused_result()) == f"api_error: {REFUSAL}"


def test_the_reason_the_spawner_reports_is_redacted_too():
    event = result_event(is_error=True, result="Invalid API key sk-ant-api03-abcdefghijklmnop")

    failure = run_failure(event)

    assert failure is not None
    assert "abcdefghijklmnop" not in failure
    assert "<redacted>" in failure


@pytest.mark.parametrize(
    "event",
    [
        pytest.param({"type": "assistant", "message": {"content": []}}, id="not-a-result"),
        pytest.param([1, 2], id="not-an-object"),
    ],
)
def test_only_a_result_can_say_a_run_failed(event):
    assert run_failure(event) is None


@pytest.mark.parametrize(
    "problem",
    [
        "its body is not JSON",
        "its body has no fields object",
        "its description is not a document with a bullet list",
        "its labels have no group label starting grp-",
        "its labels have no session label starting ses-",
    ],
)
def test_every_reason_the_forwarder_gives_for_an_incomplete_create_reaches_the_log_whole(problem):
    message = json.loads(incomplete_create_body(problem))["errorMessages"][0]
    result = f"Exit code 1\n[ERROR] Validation Error: {message}\n  Details: (HTTP 400) {message}"

    assert format_event(tool_result_event(result, is_error=True)) == [
        f"[DENIED] Jira create refused by the Forwarder: {CREATE_INCOMPLETE} ({problem})"
    ]


# --- A Run that reports its own failure ---


def test_a_run_that_reports_failed_reads_as_failed_though_claude_code_says_success():
    """The Skill ends a Run that could not do its job with a message starting `failed:`. Claude
    Code calls that Run `success` with `is_error` false and exit status 0, since it finished."""
    event = result_event(
        is_error=False,
        terminal_reason="completed",
        result="failed: the create was refused (HTTP 409)\nno Incident was made",
    )

    assert format_event(event) == [
        "[FAILED] run reported failed: the create was refused (HTTP 409)"
    ]
    assert run_failure(event) == "run reported failed: the create was refused (HTTP 409)"


def test_the_denied_create_is_followed_by_failed_not_by_a_success_line():
    lines = [
        *format_event(tool_result_event(JIRA_AS_ON_THE_REFUSED_CREATE, is_error=True)),
        *format_event(result_event(result="failed: Jira refused a second create")),
    ]

    assert [line.split()[0] for line in lines] == ["[DENIED]", "[FAILED]"]
    assert not [line for line in lines if line.startswith(RESULT)]


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        pytest.param("failed: no resolution", "no resolution", id="plain"),
        pytest.param("\nfailed:   padded  \nmore", "padded", id="blank-lines-and-padding"),
        pytest.param("failed: ", "no reason given", id="no-reason"),
    ],
)
def test_the_run_reports_failed_by_beginning_its_first_line_with_it(result, reason):
    event = result_event(result=result)

    assert run_failure(event) == f"run reported failed: {reason}"
    assert REPORTED_FAILURE == "failed: "


@pytest.mark.parametrize(
    "result",
    [
        pytest.param("ok: checkout-outage OPS-12 created", id="a-finish-line"),
        pytest.param("ok: checkout-outage OPS-12 created\nfailed: one retry", id="a-later-line"),
        pytest.param("ok: failed DEMO-12 created", id="group-named-failed"),
        pytest.param("FAILED: no resolution", id="uppercase"),
        pytest.param("Failed: no resolution", id="capitalised"),
        pytest.param("failed:no resolution", id="missing-space"),
        pytest.param("  failed: no resolution", id="leading-space"),
        pytest.param("The create failed: but the retry made OPS-12", id="mid-sentence"),
        pytest.param("", id="empty"),
        pytest.param(None, id="no-text"),
        pytest.param(["failed: x"], id="not-text"),
    ],
)
def test_a_result_that_does_not_begin_with_failed_is_a_success(result):
    event = result_event(result=result)

    assert run_failure(event) is None
    assert format_event(event)[-1].startswith(RESULT)


def test_a_reported_failure_gets_no_hint_about_the_claude_account():
    """Its words are about Jira and the Incident, even when they say `rate limit` or `token`."""
    event = result_event(result="failed: Jira answered a rate limit and the create has no key")

    assert format_event(event) == [
        "[FAILED] run reported failed: Jira answered a rate limit and the create has no key"
    ]


def test_an_api_failure_still_names_its_own_reason_over_a_failed_line():
    event = result_event(is_error=True, terminal_reason="api_error", result="failed: and more")

    assert run_failure(event) == "api_error: failed: and more"


def test_the_reason_a_run_reports_is_redacted_too():
    event = result_event(result="failed: Invalid API key sk-ant-api03-abcdefghijklmnop")

    failure = run_failure(event)

    assert failure is not None
    assert "abcdefghijklmnop" not in failure


def test_an_api_retry_says_which_attempt_why_and_how_long_it_waits():
    event = {
        "type": "system",
        "subtype": "api_retry",
        "attempt": 2,
        "max_retries": 10,
        "retry_delay_ms": 4200,
        "error_status": 529,
        "error": "overloaded",
    }

    assert format_event(event) == [
        "[retry]  retrying the API, attempt 2 of 10, after overloaded (HTTP 529), next in 4.2s"
    ]


def test_an_api_retry_with_none_of_its_fields_still_says_it_is_retrying():
    assert format_event({"type": "system", "subtype": "api_retry"}) == ["[retry]  retrying the API"]


def recorded_rate_limit_event() -> dict:
    for line in INCIDENT_TRANSCRIPT.read_text().splitlines():
        event = json.loads(line)
        if event.get("type") == "rate_limit_event":
            return event
    raise AssertionError("the recorded Run has no rate-limit event")


def test_a_rate_limit_event_that_allows_the_run_is_not_worth_a_line():
    """Every real Transcript carries one; while it says `allowed` it is not news."""
    event = recorded_rate_limit_event()
    assert event["rate_limit_info"]["status"] == "allowed"

    assert format_event(event) == []


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param(
            "allowed_warning",
            "[limit]  allowed_warning: the five_hour limit, 37% used, resets 2026-09-15 01:20 UTC",
            id="warning",
        ),
        pytest.param(
            "rejected",
            "[limit]  rejected: the five_hour limit, 37% used, resets 2026-09-15 01:20 UTC",
            id="rejected",
        ),
    ],
)
def test_a_rate_limit_event_that_is_not_allowed_is_printed(status, expected):
    """The recorded event's own window and reset time, with only its status changed."""
    event = recorded_rate_limit_event()
    event["rate_limit_info"]["status"] = status

    assert format_event(event) == [expected]


def test_a_rate_limit_event_without_its_details_still_names_its_status():
    event = {"type": "rate_limit_event", "rate_limit_info": {"status": "rejected"}}

    assert format_event(event) == ["[limit]  rejected: a rate limit"]


@pytest.mark.parametrize("subtype", [None, "unknown"])
def test_a_failure_prefix_is_read_only_from_a_success_result(subtype):
    event = result_event(subtype=subtype, result="failed: no resolution")
    assert run_failure(event) is None


@pytest.mark.parametrize("width", [1, 7, 8192])
@pytest.mark.parametrize("body", [
    "aB3-cD4_eF5gH6iJ7kL8mN9oP0qR1sT2",
    "safe " + "aB3-cD4_eF5gH6iJ7kL8mN9oP0qR1sT2 " * 500 + " final",
    "x" * 8180 + "aB3-cD4_eF5gH6iJ7kL8mN9oP0qR1sT2" + " \t\n" * 5000,
    "prefix abcab ab abcab suffix",
])
def test_stderr_stream_redacts_exact_context_across_read_boundaries(width, body):
    secrets = (URLSAFE_SENTINEL, "abcab", "ab", "")
    chunks = (body[at:at + width] for at in range(0, len(body), width))
    assert "".join(redact_stderr_chunks(chunks, active_secrets=secrets)) == redact(
        body, active_secrets=secrets
    )


@pytest.mark.parametrize("width", [1, 7, 8192])
@pytest.mark.parametrize("shape", [
    "Authorization: Basic {value}", "Bearer {value}",
    "curl -u user@example.invalid:{value}", "--api-key={value}",
    "JIRA_API_TOKEN={value}", "password {value}", "sk-ant-api03-{value}",
])
def test_stderr_shape_values_can_continue_beyond_the_recognition_window(width, shape):
    value = "0123456789abcdef" * 2000
    body = "safe start " + shape.format(value=value) + " final diagnostic"
    chunks = (body[at:at + width] for at in range(0, len(body), width))
    output = "".join(redact_stderr_chunks(chunks))
    short_body = "safe start " + shape.format(value="0123456789abcdef" * 4) + " final diagnostic"
    assert output == redact(short_body)
    assert "<redacted>" in output
    assert "0123456789abcdef" not in output


@pytest.mark.parametrize("text", ["Authorization: opaque-value", "Bearer opaque-value", "sk-ant-api03-abcdefgh"])
def test_stderr_stream_cuts_preserve_the_actual_word_boundary(text):
    body = "x" * 8192 + text + " " * (16384 - len(text))
    output = "".join(redact_stderr_chunks(body[at:at + 8192] for at in range(0, len(body), 8192)))
    assert output == redact(body)


@pytest.mark.parametrize(("shape", "expected"), [("Bearer {value}", "Bearer <redacted>"),
                                                     ("sk-ant-{value}", "<redacted>")])
def test_stderr_continuation_uses_the_recognizers_unicode_case_alphabet(shape, expected):
    body = shape.format(value="a" * 32000 + "Kİıſ" * 4) + " final"
    output = "".join(redact_stderr_chunks(body[at:at + 8192] for at in range(0, len(body), 8192)))
    assert output == expected + " final"


def test_stderr_opaque_candidate_ambiguity_is_conservatively_redacted():
    # The late Unicode word character invalidates whole-regex trailing \b.
    # A bounded fallback has already hidden the recognized long ASCII value.
    body = "a1" * 32000 + "K final"
    output = "".join(redact_stderr_chunks(body[at:at + 8192] for at in range(0, len(body), 8192)))
    assert output == "<redacted>K final"
