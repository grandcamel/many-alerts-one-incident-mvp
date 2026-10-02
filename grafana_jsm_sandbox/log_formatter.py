"""Renders a Run's Transcript into lines an audience can read.

`format_event` is a pure function: one parsed Run event in, zero or more display
lines out. Nothing here holds state between events, so the Receiver can pipe a
Run's stdout through it a line at a time and the same function can render a
Transcript saved on disk.

A Run that failed says so. Its result event renders as `[FAILED]` with the
reason, plus a `[hint]` line when the cause is one a newcomer's setup is known to
hit. `run_failure` is the same judgement for the spawner, so the Receiver's
closing line about a Run and the Transcript's own last line always agree.

A failure is also one the Run reports itself. The Skill has a Run that could not do
its job, a create the Forwarder refused or an Incident that ended without a resolution,
begin its final message with `failed:`. Claude Code ends that Run `success`, with exit
status 0, because the Run did finish, so the line is read here: it is the only way the log
and the Receiver learn that the Incident is not what the audience was shown.

Every line goes through `redact` on the way out, and printable source text is
sanitized before shortening. Live projection also supplies the known active
secret values; saved Transcripts retain the credential-shape fallback. A Run only
ever holds a sentinel, never the real Jira token (ADR 0002), but the log window is on a screen
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

from grafana_jsm_sandbox.forwarder import CREATE_INCOMPLETE, CREATE_REFUSAL

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

REPORTED_FAILURE = "failed: "
"""How the Skill has a Run begin its final message when it failed. The Skill's Finish names the
same word; `test_skill_template` pins it there and `test_log_formatter` here."""

REPORTED_FAILURE_REASON = "run reported failed"
"""What the `[FAILED]` line names as the reason, in the place an API failure puts its
terminal reason."""

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


def redact(text: str, *, active_secrets: tuple[str, ...] = ()) -> str:
    """Replace known active secrets and credential-shaped text bound for the log."""
    # Exact context catches the factory's base64url alphabet without guessing
    # which unrelated identifiers or URLs are secrets. Replace longer values
    # first, and ignore empty values so they cannot insert markers everywhere.
    for secret in sorted(set(active_secrets) - {""}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def redact_stderr_chunks(
    chunks: Iterable[str], *, active_secrets: tuple[str, ...] = ()
) -> Iterator[str]:
    """Bounded credential-shape fallback for stderr, before suffix selection.

    Each rule processes blocks with an 8192-character recognition overlap. A value
    recognized within that context can continue for any length: its characters
    are discarded until the rule's value delimiter. This is deliberately not
    whole-stream regex parity for arbitrarily long credential key names or
    schemes, or a long opaque candidate whose later Unicode word character
    invalidates a provisional word boundary. Such ambiguity can over-redact. Exact active-value replacement happens before this fallback.
    """
    continuations = (
        re.compile(r"[^\s'\"]"), re.compile(r"[A-Za-z0-9+/=_.\-]", re.IGNORECASE),
        re.compile(r"[^\s'\"]"), re.compile(r"[^\s'\"]"),
        re.compile(r"[^\s\"',;}]"), re.compile(r"[^\s'\"]"),
        re.compile(r"[A-Za-z0-9+/=_.\-]", re.IGNORECASE), re.compile(r"[A-Za-z0-9]"),
    )

    guards = (
        re.compile(r"(?i)authorization"), re.compile(r"(?i)basic|bearer"),
        re.compile(r"(?i)-u|--user"), re.compile(rf"(?i){_CREDENTIAL_WORD}"),
        re.compile(rf'(?i)(?:{_CREDENTIAL_WORD})[\w.\-]*"?\s*[:=]'),
        re.compile(rf"(?i){_CREDENTIAL_WORD}"),
        re.compile(r"(?i)ATATT|ATCTT|sk-ant-"), re.compile(r"[0-9]"),
    )

    def apply(
        chunks: Iterable[str], pattern: re.Pattern[str], replacement: str,
        continuation: re.Pattern[str], guard: re.Pattern[str],
    ) -> Iterator[str]:
        pending = context = ""
        discarding = False
        for chunk in chunks:
            if discarding:
                at = 0
                while at < len(chunk) and continuation.fullmatch(chunk[at]):
                    at += 1
                if at:
                    context = chunk[at - 1]
                if at == len(chunk):
                    continue
                chunk = chunk[at:]
                discarding = False
            pending += chunk
            if len(pending) < 16384:
                continue
            cut = len(pending) - 8192
            view = context + pending
            offset = len(context)
            matches = list(pattern.finditer(view, offset)) if guard.search(pending) else []
            open_value = False
            for match in matches:
                start, end = match.start() - offset, match.end() - offset
                if start >= cut:
                    break
                if end > cut:
                    cut = end
                    open_value = end == len(pending)
                    break
            # Use matches from the contextual complete buffer: running the regex
            # again on a detached prefix would invent word boundaries at either end.
            parts = []
            at = offset
            for match in matches:
                if match.end() > cut + offset:
                    break
                parts.extend((view[at:match.start()], match.expand(replacement)))
                at = match.end()
            parts.append(view[at:cut + offset])
            yield "".join(parts)
            context = pending[cut - 1]
            pending = pending[cut:]
            discarding = open_value
        if pending:
            view = context + pending
            at = len(context)
            parts = []
            if guard.search(pending):
                for match in pattern.finditer(view, at):
                    parts.extend((view[at:match.start()], match.expand(replacement)))
                    at = match.end()
            parts.append(view[at:])
            yield "".join(parts)

    chunks = _redact_active_chunks(chunks, active_secrets)
    for (pattern, replacement), continuation, guard in zip(
        _REDACTIONS, continuations, guards, strict=True
    ):
        chunks = apply(chunks, pattern, replacement, continuation, guard)
    yield from chunks


def format_event(event: object, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
    """Render one Run event as zero or more display lines.

    An event this function does not understand, or one that is shaped wrongly,
    costs at most one diagnostic line. Rendering a log must never be the thing
    that brings a Run down.
    """
    if not isinstance(event, dict):
        lines = [_line(DIAGNOSTIC, "event is not a JSON object")]
    else:
        kind = event.get("type")
        render = _RENDERERS.get(kind) if isinstance(kind, str) else None
        if render is None:
            lines = [_line(DIAGNOSTIC, f"unrecognised event type {kind!r}")]
        else:
            try:
                lines = render(event, active_secrets=active_secrets)
            except Exception:  # noqa: BLE001 - malformed events must not crash logging
                lines = [_line(DIAGNOSTIC, f"{kind!r} event could not be rendered")]
    return [redact(line, active_secrets=active_secrets) for line in lines]


def format_stream(
    chunks: Iterable[str | bytes], *, active_secrets: tuple[str, ...] = ()
) -> Iterator[str]:
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
        yield from format_event(event, active_secrets=active_secrets)


def _render_system(event: dict, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
    subtype = event.get("subtype")
    if subtype == "init":
        tools = event.get("tools") or []
        return [
            _line(
                RUN,
                _truncated(
                    f"model={event.get('model', 'unknown')} "
                    f"permission-mode={event.get('permissionMode', 'unknown')} "
                    f"tools={','.join(str(tool) for tool in tools)}",
                    active_secrets=active_secrets,
                ),
            )
        ]
    if subtype == "permission_denied":
        tool_name = event.get("tool_name", "a tool")
        reason = _first_sentence(event.get("message") or "", active_secrets=active_secrets)
        if not reason:
            reason = f"denied ({event.get('decision_reason_type', 'no reason given')})"
        return [_line(DENIED, _truncated(f"{tool_name}: {reason}", active_secrets=active_secrets))]
    if subtype == "api_retry":
        # A Run that goes quiet while Claude Code retries the API looks stuck.
        # This line is what says it is waiting, and on what.
        return [_line(RETRY, _truncated(_retry(event), active_secrets=active_secrets))]
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


def _render_assistant(event: dict, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
    lines: list[str] = []
    for block in _content_blocks(event):
        kind = block.get("type")
        if kind == "text":
            text = redact(str(block.get("text", "")), active_secrets=active_secrets)
            lines.extend(
                _line(ASSISTANT, line)
                for line in text.splitlines()
                if line.strip()
            )
        elif kind == "tool_use":
            call = _tool_call(block.get("name"), block.get("input"))
            lines.extend(
                _line(TOOL, text) for text in _trimmed_lines(call, active_secrets=active_secrets)
            )
    return lines


def _render_user(event: dict, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
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
        content = redact(_as_text(block.get("content")), active_secrets=active_secrets)
        refusal = _create_refusal(content) if block.get("is_error") else None
        if refusal is not None:
            # The Forwarder refused a create on purpose, a second one or a first that did not
            # carry an Incident's content. jira-as wraps that in "Jira Error" and, for a 409, a
            # hint to refresh and apply the change again, which reads as a crash and says the
            # opposite, so the log says what happened. The Transcript keeps what jira-as printed.
            lines.append(_line(DENIED, f"Jira create refused by the Forwarder: {refusal}"))
            continue
        label = ERROR if block.get("is_error") else OUTPUT
        lines.extend(_line(label, _truncated(text)) for text in _trimmed_lines(content))
    return lines


def _create_refusal(content: str) -> str | None:
    """The Forwarder's own words for a create it refused, found in what jira-as printed."""
    if CREATE_REFUSAL in content:
        return CREATE_REFUSAL
    # The 400 names what the create lacked in the brackets after the words.
    match = re.search(rf"{re.escape(CREATE_INCOMPLETE)}(?: \([^)\n]*\))?", content)
    return match.group(0) if match else None


def _render_result(event: dict, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
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
    failure = _failure(event, active_secrets=active_secrets)
    if failure is not None:
        lines.append(_line(FAILED, _truncated(failure, active_secrets=active_secrets)))
        # A failure the Run reports is about Jira and the Incident, whatever its words: a
        # "rate limit" in it is not the Claude account's, so no hint for the account.
        hint = _hint(event) if _api_failed(event) else None
        if hint is not None:
            lines.append(_line(HINT, hint))
        return lines
    lines.append(
        _line(RESULT, f"{event.get('subtype', 'finished')} in {duration}{turns_text}{cost_text}")
    )
    return lines


def _render_rate_limit(event: dict, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
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
    return [_line(LIMIT, _truncated(text, active_secrets=active_secrets))]


_RENDERERS = {
    "system": _render_system,
    "assistant": _render_assistant,
    "user": _render_user,
    "result": _render_result,
    # Rate-limit accounting arrives as its own Run event in every real Transcript.
    # It is known, not unrecognised, so it costs no diagnostic line either.
    "rate_limit_event": _render_rate_limit,
}


def run_failure(event: object, *, active_secrets: tuple[str, ...] = ()) -> str | None:
    """Why a Run failed, if `event` is the result of one that did; otherwise None.

    What the spawner reports to the Receiver, redacted like any line bound for the
    log, and the same text the `[FAILED]` line carries. A result is a failure when
    `is_error` is true or its subtype starts `error_`; the subtype alone is not
    enough, because a Run the API refused outright (out of usage credits, in the
    owner's case) ends `subtype: success` with `is_error: true` and
    `terminal_reason: api_error`, and the process still exits 0. It is also a failure
    when the Run's own final message begins `failed:`, which ends `success` as well.
    """
    if not isinstance(event, dict) or event.get("type") != "result":
        return None
    failure = _failure(event, active_secrets=active_secrets)
    return None if failure is None else _truncated(failure, active_secrets=active_secrets)


def _api_failed(event: dict) -> bool:
    """Whether Claude Code itself says the Run failed, by `is_error` or an `error_*` subtype."""
    subtype = event.get("subtype")
    return event.get("is_error") is True or (
        isinstance(subtype, str) and subtype.startswith("error_")
    )


def _failure(event: dict, *, active_secrets: tuple[str, ...] = ()) -> str | None:
    """`<terminal_reason or subtype>: <first line of the result text>`, for a failed result.

    A Run that reports its own failure has no terminal reason, so its line reads
    `run reported failed: <what it said after "failed:">`.
    """
    if not _api_failed(event):
        reported = _reported_failure(event, active_secrets=active_secrets)
        return None if reported is None else f"{REPORTED_FAILURE_REASON}: {reported}"
    reason = event.get("terminal_reason") or event.get("subtype") or "unknown"
    return f"{reason}: {_failure_text(event, active_secrets=active_secrets)}"


def _reported_failure(event: dict, *, active_secrets: tuple[str, ...] = ()) -> str | None:
    """What the Run said after `failed:`, when its result text begins with it; else None.

    Only the first non-empty line counts, so a Run that mentions a failure further down, as a
    Finish naming a recovered step might, is not one that failed.
    """
    if event.get("subtype") != "success":
        return None
    result = event.get("result")
    if not isinstance(result, str):
        return None
    for line in redact(result, active_secrets=active_secrets).splitlines():
        text = line
        if text.strip():
            if not text.startswith(REPORTED_FAILURE):
                return None
            return text[len(REPORTED_FAILURE) :].strip() or "no reason given"
    return None


def _failure_text(event: dict, *, active_secrets: tuple[str, ...] = ()) -> str:
    """The first line of what the Run said went wrong: its result text, else its errors.

    The `error_*` shapes carry an `errors` list and may carry no result text.
    """
    candidates = [event.get("result")]
    errors = event.get("errors")
    if isinstance(errors, list):
        candidates.extend(errors)
    for candidate in candidates:
        if isinstance(candidate, str):
            for line in redact(candidate, active_secrets=active_secrets).splitlines():
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


def _trimmed_lines(text: str, *, active_secrets: tuple[str, ...] = ()) -> list[str]:
    """The first few lines of `text`, with a count of the ones left behind."""
    text = redact(text, active_secrets=active_secrets)
    lines = [line for line in text.splitlines() if line.strip()]
    kept = lines[:TRIM_LINES]
    remaining = len(lines) - len(kept)
    if remaining > 0:
        kept.append(f"+ {remaining} more lines")
    return kept


def _truncated(text: str, *, active_secrets: tuple[str, ...] = ()) -> str:
    text = redact(text, active_secrets=active_secrets)
    return text if len(text) <= TRIM_CHARS else text[:TRIM_CHARS] + "..."


def _first_sentence(text: str, *, active_secrets: tuple[str, ...] = ()) -> str:
    return re.split(r"(?<=\.)\s", redact(text, active_secrets=active_secrets).strip(), maxsplit=1)[0]


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


def _redact_active_chunks(chunks: Iterable[str], active_secrets: tuple[str, ...]) -> Iterator[str]:
    """Apply the exact-context replacements without retaining the complete stream.

    Each stage keeps at most 2 * len(secret) - 2 source characters plus
    one input block. Stages follow redact's longest-first replacement order, including
    its handling of overlapping secret values. No raw match crosses an emitted
    boundary, even when replacements shorten the stream.
    """
    def replace(chunks: Iterable[str], secret: str) -> Iterator[str]:
        pending = ""
        for chunk in chunks:
            pending += chunk
            cut = max(0, len(pending) - len(secret) + 1)
            at = pending.find(secret)
            while 0 <= at < cut:
                if at + len(secret) > cut:
                    cut = at
                    break
                at = pending.find(secret, at + len(secret))
            if cut:
                yield pending[:cut].replace(secret, REDACTED)
                pending = pending[cut:]
        if pending:
            yield pending.replace(secret, REDACTED)

    for secret in sorted(set(active_secrets) - {""}, key=len, reverse=True):
        chunks = replace(chunks, secret)
    yield from chunks
