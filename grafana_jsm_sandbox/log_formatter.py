"""Renders a Run's Transcript into lines an audience can read.

`format_event` is a pure function: one parsed Run event in, zero or more display
lines out. Nothing here holds state between events, so the Receiver can pipe a
Run's stdout through it a line at a time and the same function can render a
Transcript saved on disk.

A Run that failed says so. Its result event renders as `[FAILED]` with the
reason, plus a `[hint]` line when the cause is one a newcomer's setup is known to
hit. `run_failure` is the same judgement for the spawner, so the Receiver's
closing line about a Run and the Transcript's own last line always agree.

Every line goes through `redact` on the way out. A Run only ever holds a
sentinel, never the real Jira token (ADR 0002), but the log window is on a screen
in front of an audience, so anything credential-shaped is replaced before it can
be printed. The rules below prefer redacting one word too many over printing one
secret; the one thing they deliberately do not do is redact on the bare word
"token" alone, because a Run saying "the token is a sentinel" is exactly the
sentence the demo wants the audience to read.

Run it over a saved Transcript to see what the log window will look like:

    python3 -m grafana_jsm_sandbox.log_formatter fixtures/run-transcript.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

TRIM_LINES = 5
"""How many lines of one tool result reach the log."""

TRIM_CHARS = 200
"""How wide a line may be, where the line is not a command the audience must read."""

RUN = "[run]"
ASSISTANT = "[claude]"
TOOL = "[tool]"
OUTPUT = "[out]"
ERROR = "[err]"
DENIED = "[DENIED]"
RESULT = "[result]"
FAILED = "[FAILED]"
HINT = "[hint]"
RETRY = "[retry]"
LIMIT = "[limit]"
DIAGNOSTIC = "[?]"

_LABELS = (
    RUN,
    ASSISTANT,
    TOOL,
    OUTPUT,
    ERROR,
    DENIED,
    RESULT,
    FAILED,
    HINT,
    RETRY,
    LIMIT,
    DIAGNOSTIC,
)
_LABEL_WIDTH = max(len(label) for label in _LABELS)

REDACTED = "<redacted>"

_CREDENTIAL_WORD = r"token|password|passwd|secret|api[_-]?key|credential"
_QUOTE = r"['\"]?"
_VALUE = r"[^\s'\"]+"

_REDACTIONS = (
    # An Authorization header, whatever scheme it names. The scheme is swallowed
    # along with the credential, because a scheme this does not recognise is
    # precisely the case that used to publish the secret next to it.
    (
        re.compile(rf"(?i)\bauthorization\b\s*[:=]\s*(?:[A-Za-z][\w.-]*\s+)?{_VALUE}"),
        f"Authorization: {REDACTED}",
    ),
    # A bare basic/bearer credential not attached to a header name.
    (re.compile(r"(?i)\b(basic|bearer)\s+[A-Za-z0-9+/=_.\-]{8,}"), rf"\1 {REDACTED}"),
    # curl's basic-auth flag, whose value is a whole user:secret pair.
    (re.compile(rf"(?i)(\s-u\s+|--user[=\s]+)({_QUOTE}){_VALUE}"), rf"\1\2{REDACTED}"),
    # A command-line flag whose name says it carries a credential.
    (
        re.compile(rf"(?i)(--?[a-z\-]*(?:{_CREDENTIAL_WORD})[a-z\-]*[=\s]+)({_QUOTE}){_VALUE}"),
        rf"\1\2{REDACTED}",
    ),
    # An assignment to a credential-named key, in a shell, an env file or JSON.
    (
        re.compile(
            rf"(?i)(\"?[\w.\-]*(?:{_CREDENTIAL_WORD})[\w.\-]*\"?\s*[:=]\s*)"
            rf"({_QUOTE})[^\s\"',;}}]+"
        ),
        rf"\1\2{REDACTED}",
    ),
    # A credential word followed by an opaque value, as netrc and prompts write
    # it. The length gate is what keeps prose ("the token is a sentinel") intact.
    (re.compile(rf"(?i)\b({_CREDENTIAL_WORD})(\s+)[^\s'\"]{{16,}}"), rf"\1\2{REDACTED}"),
    # Credentials that announce themselves by prefix, wherever they appear.
    (re.compile(r"(?i)\b(?:ATATT|ATCTT|sk-ant-)[A-Za-z0-9+/=_.\-]{8,}"), REDACTED),
    # A long opaque run of letters and digits with nothing around it to say what
    # it is: a sentinel echoed on its own looks like this and nothing else here
    # does. Requiring a digit keeps long words out; allowing no punctuation keeps
    # Fingerprints, issue keys, URLs, UUIDs and timestamps out.
    (
        re.compile(r"\b(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{32,}\b"),
        REDACTED,
    ),
)


def redact(text: str) -> str:
    """Replace anything credential-shaped in a line bound for the log."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def format_event(event: object) -> list[str]:
    """Render one Run event as zero or more display lines.

    An event this function does not understand, or one that is shaped wrongly,
    costs at most one diagnostic line. Rendering a log must never be the thing
    that brings a Run down.
    """
    if not isinstance(event, dict):
        return [_line(DIAGNOSTIC, "event is not a JSON object")]

    kind = event.get("type")
    render = _RENDERERS.get(kind) if isinstance(kind, str) else None
    if render is None:
        return [_line(DIAGNOSTIC, f"unrecognised event type {kind!r}")]

    try:
        lines = render(event)
    except Exception:  # noqa: BLE001 - a malformed event is a log line, not a crash
        return [_line(DIAGNOSTIC, f"{kind!r} event could not be rendered")]
    return [redact(line) for line in lines]


def format_stream(chunks: Iterable[str | bytes]) -> Iterator[str]:
    """Render a whole Transcript, one line of JSON at a time."""
    for chunk in chunks:
        if isinstance(chunk, (bytes, bytearray)):
            chunk = chunk.decode("utf-8", errors="replace")
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            event = json.loads(chunk)
        except ValueError:
            yield _line(DIAGNOSTIC, "line is not JSON")
            continue
        yield from format_event(event)


def _render_system(event: dict) -> list[str]:
    subtype = event.get("subtype")
    if subtype == "init":
        tools = event.get("tools") or []
        return [
            _line(
                RUN,
                _truncated(
                    f"model={event.get('model', 'unknown')} "
                    f"permission-mode={event.get('permissionMode', 'unknown')} "
                    f"tools={','.join(str(tool) for tool in tools)}"
                ),
            )
        ]
    if subtype == "permission_denied":
        tool_name = event.get("tool_name", "a tool")
        reason = _first_sentence(event.get("message") or "")
        if not reason:
            reason = f"denied ({event.get('decision_reason_type', 'no reason given')})"
        return [_line(DENIED, _truncated(f"{tool_name}: {reason}"))]
    if subtype == "api_retry":
        # A Run that goes quiet while Claude Code retries the API looks stuck.
        # This line is what says it is waiting, and on what.
        return [_line(RETRY, _truncated(_retry(event)))]
    # Everything else a system event carries is progress chatter the audience
    # does not need: task summaries, turn summaries, and whatever is added next.
    return []


def _retry(event: dict) -> str:
    """One `system/api_retry` event as a sentence: which attempt, why, and how long it waits.

    The fields are the documented ones (`attempt`, `max_retries`, `retry_delay_ms`,
    `error_status`, `error`); a Run has not yet been seen to emit one, so each is
    optional here rather than trusted to be there.
    """
    attempt, most = event.get("attempt"), event.get("max_retries")
    text = "retrying the API"
    if attempt is not None:
        text += f", attempt {attempt}" + (f" of {most}" if most is not None else "")
    cause = " ".join(
        str(part)
        for part in (event.get("error"), _in_brackets(event.get("error_status")))
        if part is not None
    )
    if cause:
        text += f", after {cause}"
    delay = event.get("retry_delay_ms")
    if isinstance(delay, (int, float)):
        text += f", next in {delay / 1000:.1f}s"
    return text


def _in_brackets(status: object) -> str | None:
    return None if status is None else f"(HTTP {status})"


def _render_assistant(event: dict) -> list[str]:
    lines: list[str] = []
    for block in _content_blocks(event):
        kind = block.get("type")
        if kind == "text":
            lines.extend(
                _line(ASSISTANT, line)
                for line in str(block.get("text", "")).splitlines()
                if line.strip()
            )
        elif kind == "tool_use":
            call = _tool_call(block.get("name"), block.get("input"))
            lines.extend(_line(TOOL, text) for text in _trimmed_lines(call))
    return lines


def _render_user(event: dict) -> list[str]:
    never_ran = _tool_calls_that_never_ran(event)
    lines: list[str] = []
    for block in _content_blocks(event):
        if block.get("type") != "tool_result":
            continue
        if block.get("tool_use_id") in never_ran:
            # A denied call's result is the denial text handed back to the model.
            # The system event above it says so already, and the result event
            # recaps every denial at the end, so printing the paragraph a third
            # time only buries the line the audience is meant to notice.
            continue
        label = ERROR if block.get("is_error") else OUTPUT
        lines.extend(
            _line(label, _truncated(text))
            for text in _trimmed_lines(_as_text(block.get("content")))
        )
    return lines


def _render_result(event: dict) -> list[str]:
    duration_ms = event.get("duration_ms")
    duration = f"{duration_ms / 1000:.1f}s" if isinstance(duration_ms, (int, float)) else "unknown"
    cost = event.get("total_cost_usd")
    cost_text = f", ${cost:.4f}" if isinstance(cost, (int, float)) else ""
    turns = event.get("num_turns")
    turns_text = f", {turns} turns" if turns is not None else ""
    # The denial recap comes first so the result line is the last thing the log
    # says about a Run, the clean ending presenter story 5 asks the log for. A
    # failed Run ends on its hint instead, which belongs directly under the
    # failure it explains.
    lines = [
        _line(DENIED, _tool_call(denial.get("tool_name"), denial.get("tool_input")))
        for denial in event.get("permission_denials") or []
        if isinstance(denial, dict)
    ]
    failure = _failure(event)
    if failure is not None:
        lines.append(_line(FAILED, _truncated(failure)))
        hint = _hint(event)
        if hint is not None:
            lines.append(_line(HINT, hint))
        return lines
    lines.append(
        _line(RESULT, f"{event.get('subtype', 'finished')} in {duration}{turns_text}{cost_text}")
    )
    return lines


def _render_rate_limit(event: dict) -> list[str]:
    """A rate-limit event, when it is news: the account is near a limit or past one.

    Every real Transcript carries one of these with status `allowed`, and that is
    not worth a line. Anything else (`allowed_warning`, `rejected`) is the likeliest
    explanation for a Run about to stall or fail, so it is printed with the window
    and when it resets.
    """
    info = event.get("rate_limit_info")
    if not isinstance(info, dict):
        return []
    status = info.get("status")
    if status is None or status == "allowed":
        return []
    window = info.get("rateLimitType")
    text = f"{status}: the {window} limit" if window else f"{status}: a rate limit"
    utilization = info.get("utilization")
    windows = info.get("unifiedWindows")
    if utilization is None and isinstance(windows, dict) and isinstance(windows.get(window), dict):
        utilization = windows[window].get("utilization")
    if isinstance(utilization, (int, float)):
        text += f", {utilization:.0%} used"
    resets = info.get("resetsAt")
    if isinstance(resets, (int, float)):
        moment = datetime.fromtimestamp(resets, tz=UTC)
        text += f", resets {moment:%Y-%m-%d %H:%M} UTC"
    return [_line(LIMIT, _truncated(text))]


_RENDERERS = {
    "system": _render_system,
    "assistant": _render_assistant,
    "user": _render_user,
    "result": _render_result,
    # Rate-limit accounting arrives as its own Run event in every real Transcript.
    # It is known, not unrecognised, so it costs no diagnostic line either.
    "rate_limit_event": _render_rate_limit,
}


def run_failure(event: object) -> str | None:
    """Why a Run failed, if `event` is the result of one that did; otherwise None.

    What the spawner reports to the Receiver, redacted like any line bound for the
    log, and the same text the `[FAILED]` line carries. A result is a failure when
    `is_error` is true or its subtype starts `error_`; the subtype alone is not
    enough, because a Run the API refused outright (out of usage credits, in the
    owner's case) ends `subtype: success` with `is_error: true` and
    `terminal_reason: api_error`, and the process still exits 0.
    """
    if not isinstance(event, dict) or event.get("type") != "result":
        return None
    failure = _failure(event)
    return None if failure is None else redact(_truncated(failure))


def _failure(event: dict) -> str | None:
    """`<terminal_reason or subtype>: <first line of the result text>`, for a failed result."""
    subtype = event.get("subtype")
    failed = event.get("is_error") is True or (
        isinstance(subtype, str) and subtype.startswith("error_")
    )
    if not failed:
        return None
    reason = event.get("terminal_reason") or subtype or "unknown"
    return f"{reason}: {_failure_text(event)}"


def _failure_text(event: dict) -> str:
    """The first line of what the Run said went wrong: its result text, else its errors.

    The `error_*` shapes carry an `errors` list and may carry no result text.
    """
    candidates = [event.get("result")]
    errors = event.get("errors")
    if isinstance(errors, list):
        candidates.extend(errors)
    for candidate in candidates:
        if isinstance(candidate, str):
            for line in candidate.splitlines():
                if line.strip():
                    return line.strip()
    return "no result text"


# The one-line hints for the failures a newcomer's setup is known to hit.
HINT_TOKEN = (
    "the Claude token was refused: make a new one with `claude setup-token`, put it in "
    "CLAUDE_CODE_OAUTH_TOKEN in .env, and recreate the container with `docker compose up -d demo`"
)
HINT_CREDITS = (
    "the Claude account is out of usage credits for this model: top them up at "
    "claude.ai/settings/usage, or set RUN_MODEL in .env to a model the account has credits for "
    "and recreate the container with `docker compose up -d demo`"
)
HINT_RATE_LIMIT = (
    "the Claude account hit a rate limit: wait for it to reset (a [limit] line above says "
    "when, if the Run printed one), then send the Alert again"
)
HINT_MODEL = (
    "this Claude seat cannot use the model the Run asked for: ask the Claude org owner to "
    "allow it, or set RUN_MODEL in .env to a model the seat has and recreate the container "
    "with `docker compose up -d demo`"
)
HINT_BUDGET = (
    "the Run reached its spending cap (RUN_BUDGET_USD) before it finished: its "
    "transcript.jsonl shows what it spent it on"
)


def _hint(event: dict) -> str | None:
    """The hint for a failed result, or None when the cause is not a known one.

    It reads what the result event itself carries, since nothing here remembers
    the events before it: the subtype, the API's HTTP status in `api_error_status`,
    and the words of the result text. A refusal the API gives in words, like the
    usage-credit one, reaches the result with `api_error_status` unset, so the
    words are checked before the status. Credits come before the token, because a
    credit refusal can mention the account without the token being at fault, and
    before a usage limit, since "usage credits" and "usage limit" differ by one word.
    The token's words are the Claude API's own: a plain "authentication failed" in
    `errors` may be Jira's, which the Forwarder's 401 line already diagnoses.
    """
    if event.get("subtype") == "error_max_budget_usd":
        return HINT_BUDGET
    status = event.get("api_error_status")
    errors = event.get("errors")
    words = " ".join(
        text
        for text in [event.get("result"), *(errors if isinstance(errors, list) else [])]
        if isinstance(text, str)
    ).lower()
    if _mentions(words, "usage credits", "credit balance", "out of credits"):
        return HINT_CREDITS
    if status == 401 or _mentions(
        words, "oauth token", "invalid api key", "not logged in", "/login", "authentication_error"
    ):
        return HINT_TOKEN
    if status == 429 or _mentions(
        words, "rate limit", "rate_limit", "usage limit", "hit your limit", "limit reached"
    ):
        return HINT_RATE_LIMIT
    if status == 404 or _mentions(
        words, "selected model", "model_not_found", "may not exist or you may not have access"
    ):
        return HINT_MODEL
    return None


def _mentions(text: str, *phrases: str) -> bool:
    return any(phrase in text for phrase in phrases)


def _content_blocks(event: dict) -> list[dict]:
    content = event["message"].get("content")
    if not isinstance(content, list):
        return []
    return [block for block in content if isinstance(block, dict)]


def _tool_calls_that_never_ran(event: dict) -> set[str]:
    """Tool calls this event reports as refused rather than executed."""
    meta = event.get("tool_result_meta")
    if not isinstance(meta, list):
        return set()
    return {
        entry["id"]
        for entry in meta
        if isinstance(entry, dict) and entry.get("non_execution_kind") and "id" in entry
    }


def _tool_call(name: object, tool_input: object) -> str:
    """One tool call as the audience should read it: the tool and what it ran.

    Never truncated. Presenter story 5 wants every jira-as command in the log,
    and a command cut off halfway is exactly the line that invites the question
    of what the rest of it said.
    """
    tool = str(name) if name else "a tool"
    call = _tool_input(tool_input)
    return f"{tool}: {call}" if call else tool


def _tool_input(tool_input: object) -> str:
    """The part of a tool call worth showing: the command, the path, or all of it."""
    if not isinstance(tool_input, dict):
        return "" if tool_input is None else str(tool_input)
    for key in ("command", "file_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return json.dumps(tool_input, sort_keys=True)


def _as_text(content: object) -> str:
    """A tool result's content, which may be text or a list of content blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return "" if content is None else str(content)


def _trimmed_lines(text: str) -> list[str]:
    """The first few lines of `text`, with a count of the ones left behind."""
    lines = [line for line in text.splitlines() if line.strip()]
    kept = lines[:TRIM_LINES]
    remaining = len(lines) - len(kept)
    if remaining > 0:
        kept.append(f"+ {remaining} more lines")
    return kept


def _truncated(text: str) -> str:
    return text if len(text) <= TRIM_CHARS else text[:TRIM_CHARS] + "..."


def _first_sentence(text: str) -> str:
    return re.split(r"(?<=\.)\s", text.strip(), maxsplit=1)[0]


def _line(label: str, text: str) -> str:
    return f"{label:<{_LABEL_WIDTH}} {text}"


def main(argv: list[str] | None = None) -> int:
    """Render a saved Transcript, named on the command line or fed on stdin."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) > 1:
        print(
            "usage: python3 -m grafana_jsm_sandbox.log_formatter [transcript.jsonl]",
            file=sys.stderr,
        )
        return 2
    if argv:
        with open(argv[0], encoding="utf-8") as transcript:
            _write(format_stream(transcript))
    else:
        _write(format_stream(sys.stdin))
    return 0


def _write(lines: Iterable[str]) -> None:
    for line in lines:
        print(line, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
