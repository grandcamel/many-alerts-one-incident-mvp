"""Read Grafana's datasource proxy and keep the complete response in Run evidence.

The five display lines are compact enough for the Transcript; the sixth line and
the appended JSONL record keep the query, its times and all returned data. Only
the environment supplies the Viewer credential and internal/presenter origins.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

from grafana_jsm_sandbox.investigation_contract import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
)
from grafana_jsm_sandbox.loki_evidence import summarize_logs
from grafana_jsm_sandbox.tempo_evidence import (
    normalize_trace_id,
    summarize_search,
    summarize_trace,
)

TIMEOUT_SECONDS = 10
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
DECIMAL = r"(?:\d+(?:\.\d*)?|\.\d+)"
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})"
)


class QueryError(ValueError):
    """An invalid invocation, reported without exposing input values."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        # argparse's raw error can quote a credential passed as an unknown flag.
        if message.startswith("the following arguments are required:"):
            raise QueryError(message)
        if message.startswith("unrecognized arguments:"):
            flags = re.findall(r"(?<!\S)--[a-zA-Z][a-zA-Z0-9-]*", message)
            if flags:
                raise QueryError("unsupported flags: " + ", ".join(flags))
        if message.startswith("argument --"):
            flag = message.split(":", 1)[0].removeprefix("argument ")
            raise QueryError(flag + " requires a value")
        raise QueryError("invalid command or flags")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="grafana-query", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("instant", "range", "get", "logs", "traces", "trace"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--datasource", default=(
            "tempo" if name in {"traces", "trace"} else "loki" if name == "logs" else "prometheus"
        ))
        if name == "trace":
            command.add_argument("--id", required=True)
        elif name == "get":
            command.add_argument("--path", required=True)
            command.add_argument("--param", action="append", default=[])
        else:
            command.add_argument("--query", required=True)
            if name == "instant":
                command.add_argument("--time", default="now")
            else:
                command.add_argument("--start", default="now-10m")
                command.add_argument("--end", default="now")
                if name in {"logs", "traces"}:
                    command.add_argument("--limit", default="100" if name == "logs" else "20")
                    if name == "logs":
                        command.add_argument("--direction", default="backward")
                else:
                    command.add_argument("--step", default="10s")
    return parser


def _base_url(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme in {"http", "https"} and parts.hostname and parts.port != 0
            and parts.username is None and parts.password is None
            and "?" not in value and "#" not in value
            and not any(c.isspace() or ord(c) < 32 for c in value)
        )
    except ValueError:
        valid = False
    if not valid:
        raise QueryError(f"{name} must be an absolute http/https base URL")
    return value.rstrip("/")


def _configuration() -> tuple[str, str, str]:
    url = _base_url("DEMO_GRAFANA_URL", "http://localhost:3000")
    if "DEMO_GRAFANA_PRESENTER_URL" not in os.environ:
        try:
            port = int(os.environ.get("GRAFANA_HOST_PORT", "3000"))
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise QueryError("GRAFANA_HOST_PORT must be an integer from 1 to 65535") from None
        default = f"http://localhost:{port}"
    else:
        default = "http://localhost:3000"
    presenter = _base_url("DEMO_GRAFANA_PRESENTER_URL", default)
    raw_token = os.environ.get("DEMO_GRAFANA_VIEWER_TOKEN", "")
    token = raw_token.strip()
    if not token or "\r" in raw_token or "\n" in raw_token:
        raise QueryError("DEMO_GRAFANA_VIEWER_TOKEN must be nonblank and contain no CR/LF")
    return url, presenter, token


def _seconds(value: str, flag: str) -> Decimal:
    try:
        if not re.fullmatch(rf"[+-]?{DECIMAL}(?:[eE][+-]?\d+)?", value):
            raise ValueError
        number = Decimal(value)
        if not number.is_finite():
            raise ValueError
        return number
    except (InvalidOperation, ValueError):
        raise QueryError(f"{flag} must be finite seconds") from None


def _time(value: str, flag: str, now: Decimal) -> Decimal:
    if value == "now":
        result = now
    elif match := re.fullmatch(rf"now-({DECIMAL})([smhd])", value):
        amount = Decimal(match[1])
        if amount <= 0:
            raise QueryError(f"{flag} must use a positive relative duration")
        result = now - amount * UNITS[match[2]]
    elif RFC3339.fullmatch(value):
        try:
            result = Decimal(str(datetime.fromisoformat(value.replace("z", "Z")).timestamp()))
        except ValueError:
            raise QueryError(f"{flag} must be a valid RFC3339 time") from None
    else:
        result = _seconds(value, flag)
    # Every time also has to be representable in the required evidence format.
    try:
        _utc(result)
    except (OverflowError, OSError, ValueError):
        raise QueryError(f"{flag} must be a representable UTC time") from None
    return result


def _step(value: str, flag: str) -> Decimal:
    if match := re.fullmatch(rf"({DECIMAL})([smhd])", value):
        result = Decimal(match[1]) * UNITS[match[2]]
    else:
        result = _seconds(value, flag)
    if result <= 0:
        raise QueryError(f"{flag} must be positive finite seconds")
    return result


def _decimal(number: Decimal) -> str:
    return format(number, "f")


def _utc(seconds: Decimal) -> str:
    return datetime.fromtimestamp(float(seconds), UTC).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _loki_bound(seconds: Decimal) -> tuple[Decimal, str]:
    """Normalize a Loki request and Explore bound to the recorded UTC milliseconds."""
    bound = _utc(seconds)
    delta = datetime.fromisoformat(bound) - datetime(
        1970, 1, 1, tzinfo=UTC
    )
    milliseconds = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    return Decimal(milliseconds) / 1000, bound


def _invocation(args, now: Decimal):
    """The exact parameter order, and resolved bounds for evidence and links."""
    if not args.datasource:
        raise QueryError("--datasource must be nonempty")
    start = end = step = None
    if args.command == "trace":
        try:
            args.query = normalize_trace_id(args.id)
        except ValueError:
            raise QueryError("--id must be a nonzero 1 to 32 character hex trace ID") from None
        path = "/api/v2/traces/" + args.query
        parameters = []
    elif args.command == "traces":
        start = _time(args.start, "--start", now)
        end = _time(args.end, "--end", now)
        if not (0 <= start < 2 ** 32 and 0 <= end < 2 ** 32):
            raise QueryError("--start and --end must be nonnegative uint32 seconds")
        if start > end:
            raise QueryError("--start must be <= --end")
        start = start.to_integral_value(rounding=ROUND_FLOOR)
        end = end.to_integral_value(rounding=ROUND_FLOOR)
        if not re.fullmatch(r"[0-9]+", args.limit) or int(args.limit) <= 0:
            raise QueryError("--limit must be a positive integer")
        path = "/api/search"
        parameters = [("q", args.query), ("start", str(start)), ("end", str(end)),
                      ("limit", str(int(args.limit)))]
    elif args.command == "instant":
        start = end = _time(args.time, "--time", now)
        path = "/api/v1/query"
        parameters = [("query", args.query), ("time", _decimal(start))]
    elif args.command == "logs":
        start = _time(args.start, "--start", now)
        end = _time(args.end, "--end", now)
        if start > end:
            raise QueryError("--start must be <= --end")
        if not re.fullmatch(r"[0-9]+", args.limit) or int(args.limit) <= 0:
            raise QueryError("--limit must be a positive integer")
        if args.direction not in {"forward", "backward"}:
            raise QueryError("--direction must be forward or backward")
        # Resolve to the evidence's millisecond UTC window before constructing
        # the Explore bounds. Loki interprets integer times as nanoseconds.
        start, start_bound = _loki_bound(start)
        end, end_bound = _loki_bound(end)
        path = "/loki/api/v1/query_range"
        parameters = [
            ("query", args.query), ("start", start_bound), ("end", end_bound),
            ("limit", str(int(args.limit))), ("direction", args.direction),
        ]
    elif args.command == "range":
        start = _time(args.start, "--start", now)
        end = _time(args.end, "--end", now)
        step = _step(args.step, "--step")
        path = "/api/v1/query_range"
        parameters = [
            ("query", args.query), ("start", _decimal(start)),
            ("end", _decimal(end)), ("step", _decimal(step)),
        ]
    else:
        path = args.path
        try:
            parts = urlsplit(path)
        except ValueError:
            raise QueryError("--path must be an absolute datasource-relative path") from None
        if (
            not path.startswith("/") or path.startswith("//") or parts.scheme or parts.netloc
            or "?" in path or "#" in path or any(ord(c) < 32 or c.isspace() for c in path)
        ):
            raise QueryError("--path must be an absolute datasource-relative path")
        parameters = []
        for parameter in args.param:
            name, separator, value = parameter.partition("=")
            if not separator or not name:
                raise QueryError("--param must be NAME=VALUE")
            if name in {"start", "end", "time"}:
                resolved = _time(value, "--param " + name, now)
                if path.startswith("/loki/"):
                    resolved, value = _loki_bound(resolved)
                else:
                    value = _decimal(resolved)
                if name in {"start", "time"}:
                    start = resolved
                if name in {"end", "time"}:
                    end = resolved
            elif name == "step":
                step = _step(value, "--param step")
                value = _decimal(step)
            parameters.append((name, value))
    if start is not None and end is not None and start > end:
        raise QueryError("--start must be <= --end")
    return path, parameters, start, end, step


def _request(url: str, token: str) -> tuple[int, bytes]:
    """One GET with an elapsed deadline covering connection and the entire body.

    Socket timeouts alone reset on reads. A daemon worker lets the caller enforce
    the same ten-second deadline even while DNS or a trickling body is blocked.
    The worker never writes evidence or output and never retries or redirects.
    """
    result = queue.Queue(maxsize=1)
    cancelled = threading.Event()
    opened: list[socket.socket] = []

    def retrieve():
        parts = urlsplit(url)
        connection_type = (
            http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        )
        connection = connection_type(parts.hostname, parts.port, timeout=TIMEOUT_SECONDS)
        try:
            connection.connect()
            opened.append(connection.sock)
            if cancelled.is_set():
                raise TimeoutError
            target = parts.path + ("?" + parts.query if parts.query else "")
            connection.request("GET", target, headers={
                "Authorization": "Bearer " + token, "Accept": "application/json",
            })
            response = connection.getresponse()
            # HTTP errors carry no response in evidence; never read their raw body.
            body = response.read() if 200 <= response.status < 300 else b""
            result.put((response.status, body))
        except (OSError, http.client.HTTPException, ValueError, UnicodeError) as failure:
            result.put(failure)
        finally:
            connection.close()

    deadline = time.monotonic() + TIMEOUT_SECONDS
    threading.Thread(target=retrieve, name="grafana-query", daemon=True).start()
    try:
        received = result.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        cancelled.set()
        if opened:
            try:
                opened[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        raise TimeoutError from None
    if isinstance(received, Exception):
        raise received
    return received


def _empty_summary() -> dict:
    return {"result_type": None, "series_count": 0, "sample_count": 0,
            "unmodelled_count": 0, "discovery_items": None, "series": []}


def _sample(pair):
    if (
        not isinstance(pair, list) or len(pair) != 2
        or isinstance(pair[0], bool) or not isinstance(pair[0], (float, int, Decimal))
        or not Decimal(str(pair[0])).is_finite() or not isinstance(pair[1], str)
    ):
        raise ValueError
    return pair[0], pair[1]


def _series(labels, samples, unmodelled) -> tuple[dict, bool]:
    if not isinstance(labels, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in labels.items()
    ):
        raise ValueError
    latest = minimum = maximum = None
    all_zero = not unmodelled
    for pair in samples:
        timestamp, value = _sample(pair)
        if latest is None or timestamp >= latest["timestamp"]:
            latest = {"timestamp": timestamp, "value": value}
        try:
            number = Decimal(value)
        except InvalidOperation:
            number = Decimal("NaN")
        if number.is_finite():
            if minimum is None or number < minimum[0]:
                minimum = number, value
            if maximum is None or number > maximum[0]:
                maximum = number, value
        if not number.is_finite() or number != 0:
            all_zero = False
    return ({"labels": labels, "count": len(samples) + unmodelled, "latest": latest,
             "min": None if minimum is None else minimum[1],
             "max": None if maximum is None else maximum[1]}, all_zero)


def _summarize(response) -> tuple[dict, str]:
    if not isinstance(response, dict) or response.get("status") != "success":
        raise ValueError
    data = response.get("data")
    if not isinstance(data, dict) or "result" not in data:
        raise ValueError
    kind, result = data.get("resultType"), data["result"]
    summary = _empty_summary()
    summary["result_type"] = kind
    all_zero = True
    if kind in {"scalar", "string"}:
        entries = [({}, [result], 0)]
    elif kind in {"vector", "matrix"} and isinstance(result, list):
        entries = []
        for item in result:
            if not isinstance(item, dict) or "metric" not in item:
                raise ValueError
            if kind == "vector":
                samples = [item["value"]] if "value" in item else []
                histograms = [item["histogram"]] if "histogram" in item else []
                if not samples and not histograms:
                    raise ValueError
            else:
                samples, histograms = item.get("values", []), item.get("histograms", [])
                if not isinstance(samples, list) or not isinstance(histograms, list):
                    raise ValueError
                if "values" not in item and "histograms" not in item:
                    raise ValueError
            for histogram in histograms:
                if (
                    not isinstance(histogram, list) or len(histogram) != 2
                    or isinstance(histogram[0], bool)
                    or not isinstance(histogram[0], (int, float, Decimal))
                    or not Decimal(str(histogram[0])).is_finite()
                    or not isinstance(histogram[1], dict)
                ):
                    raise ValueError
            entries.append((item["metric"], samples, len(histograms)))
    else:
        raise ValueError
    for labels, samples, unmodelled in entries:
        series, zero = _series(labels, samples, unmodelled)
        all_zero = all_zero and zero
        summary["series"].append(series)
        summary["sample_count"] += series["count"]
        summary["unmodelled_count"] += unmodelled
    summary["series_count"] = len(entries)
    outcome = "no data" if not summary["sample_count"] else "observed zero" if all_zero else "ok"
    return summary, outcome


def _json(value) -> str:
    """Compact JSON, preserving finite decimal numbers without a float-size cap."""
    if isinstance(value, Decimal):
        return _decimal(value)
    if isinstance(value, dict):
        return "{" + ",".join(_json(k) + ":" + _json(v) for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_json(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _invalid_json_constant(value: str):
    raise ValueError("invalid JSON number")


def _get_summary(response) -> tuple[dict, str]:
    """Summarize known query data, retaining any other JSON as discovery."""
    try:
        return _summarize(response)
    except (ValueError, TypeError, OverflowError):
        summary = _empty_summary()
        data = (
            response["data"]
            if isinstance(response, dict) and response.get("status") == "success"
            and "data" in response else response
        )
        items = len(data) if isinstance(data, (dict, list)) else 1
        summary.update(result_type="discovery", discovery_items=items)
        return summary, "discovery data" if items else "no data"


def _presenter(base, args, proxy, parameters, start, end):
    base = quote(base, safe=":/%[]")
    if args.command == "get":
        return base + quote(proxy, safe="/%") + ("?" + urlencode(parameters) if parameters else "")
    if args.command in {"traces", "trace"}:
        query = {"refId": "A", "datasource": {"uid": args.datasource, "type": "tempo"},
                 "queryType": "traceql" if args.command == "traces" else "traceId",
                 "query": args.query}
        if args.command == "traces":
            query.update(filters=[], limit=int(args.limit))
        bounds = {"from": "now-10m", "to": "now"} if start is None else {
            "from": str(int(start * 1000)), "to": str(int(end * 1000)),
        }
        panes = {"A": {"datasource": args.datasource, "queries": [query], "range": bounds}}
        return base + "/explore?schemaVersion=1&panes=" + quote(_json(panes), safe="")
    panes = {"A": {"datasource": args.datasource, "queries": [{
        "refId": "A", "expr": args.query, "instant": args.command == "instant",
        "range": args.command in {"range", "logs"},
    }], "range": {"from": str(int(start * 1000)), "to": str(int(end * 1000))}}}
    if args.command == "logs":
        panes["A"]["queries"][0].update(
            queryType="range", direction=args.direction, maxLines=int(args.limit)
        )
    return base + "/explore?schemaVersion=1&panes=" + quote(_json(panes), safe="")


def _display(record, outcome: str, writable: bool) -> list[str]:
    summary, window = record["sample_summary"], record["window"]
    bounds = (
        f'{window["start"] or "none"}..{window["end"] or "none"}'
        if window["start"] is not None or window["end"] is not None else "none"
    )
    step = window["step_seconds"] if window["step_seconds"] is not None else "none"
    query = record["query"]
    if query is None:
        query = record["path"] + (
            "?" + urlencode(record["parameters"]) if record["parameters"] else ""
        )
    if record["status"] == "unavailable":
        detail = "unavailable"
    elif record["command"] == "traces":
        traces = record["trace_summary"]
        detail = "possibly incomplete (limit reached)" if traces["limit_reached"] else "returned traces"
        if not traces["trace_count"]:
            detail = "no data"
    elif record["command"] == "trace":
        trace = record["trace_summary"]
        detail = f'backend {trace["backend_status"]}; {trace["missing_parent_count"]} missing parents'
    elif record["command"] == "logs":
        logs = record["log_summary"]
        detail = "possibly incomplete (limit reached)" if logs["limit_reached"] else "returned data"
        if not logs["entry_count"]:
            detail = "no data"
    elif summary["discovery_items"] is not None:
        detail = f'discovery items={summary["discovery_items"]}'
    elif not summary["sample_count"]:
        detail = "no data"
    else:
        first = summary["series"][0]
        latest = first["latest"]
        detail = "labels=" + json.dumps(
            first["labels"], ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        detail += (
            f'; latest={latest["value"]}@{latest["timestamp"]}' if latest else "; latest=none"
        )
        detail += f'; min={first["min"] or "none"}; max={first["max"] or "none"}'
        if summary["series_count"] > 1:
            detail += f'; +{summary["series_count"] - 1} more series'
        if summary["unmodelled_count"]:
            detail += f'; unmodelled samples={summary["unmodelled_count"]}'
    counts = (
        f'trace: {record["trace_summary"]["span_count"]} observed spans'
        if record["command"] == "trace" and record["trace_summary"] is not None else
        "trace: unavailable" if record["command"] == "trace" else
        f'traces: {record["trace_summary"]["trace_count"]} returned traces'
        if record["command"] == "traces" and record["trace_summary"] is not None else
        "traces: unavailable" if record["command"] == "traces" else
        f'logs: {record["log_summary"]["stream_count"]} streams, '
        f'{record["log_summary"]["entry_count"]} returned entries'
        if record["command"] == "logs" and record["log_summary"] is not None else
        "logs: unavailable" if record["command"] == "logs" else
        f'samples: {summary["series_count"]} series, {summary["sample_count"]} samples'
    )
    lines = [
        "grafana-query: " + outcome,
        "query: " + query,
        (f'datasource: {record["datasource"]} | lookup by ID; no API time filter'
         if record["command"] == "trace" else
         f'datasource: {record["datasource"]} | window: {bounds} | step: {step}'),
        counts + " | " + detail,
        (f'evidence: {EVIDENCE_FILENAME if writable else "unavailable"} | '
         f'presenter: {record["presenter_link"] or "none"}'),
    ]
    collapsed = [" ".join(line.split()) for line in lines]
    return [line[:197] + "..." if len(line) > 200 else line for line in collapsed]


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        url, presenter, token = _configuration()
        now = Decimal(str(datetime.now(UTC).timestamp()))
        path, parameters, start, end, step = _invocation(args, now)
    except QueryError as failure:
        print("grafana-query: error: " + str(failure), file=sys.stderr)
        return 2
    proxy = "/api/datasources/proxy/uid/" + quote(args.datasource, safe="") + path
    target = url + proxy + ("?" + urlencode(parameters) if parameters else "")
    record = {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "command": args.command,
        "query": None if args.command == "get" else args.query,
        "datasource": args.datasource, "path": path, "parameters": parameters,
        "window": {"start": _utc(start) if start is not None else None,
                   "end": _utc(end) if end is not None else None,
                   "step_seconds": step},
        "retrieved_at": None, "status": "unavailable", "error": None,
        "sample_summary": _empty_summary(),
        "presenter_link": _presenter(presenter, args, proxy, parameters, start, end),
        "response": None,
    }
    if args.command == "logs":
        record["log_summary"] = None
    if args.command in {"traces", "trace"}:
        record["trace_summary"] = None

    def unavailable(kind, message, status=None):
        record["error"] = {"kind": kind, "message": message, "http_status": status}
        return "unavailable: " + message

    try:
        status, body = _request(target, token)
    except TimeoutError:
        outcome = unavailable("timeout", "timeout after 10s")
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        outcome = unavailable("unreachable", "unreachable")
    else:
        record["retrieved_at"] = datetime.now(UTC).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        if status == 401:
            outcome = unavailable("token_rejected", "token rejected", status)
        elif not 200 <= status < 300:
            outcome = unavailable("http_error", f"HTTP {status}", status)
        else:
            try:
                record["response"] = json.loads(
                    body, parse_float=Decimal, parse_constant=_invalid_json_constant
                )
                response = record["response"]
                if isinstance(response, dict) and response.get("status") == "error":
                    outcome = unavailable("query_error", "query error")
                else:
                    if args.command == "logs":
                        record["log_summary"] = summarize_logs(response, int(args.limit))
                        record["sample_summary"]["result_type"] = "streams"
                        outcome = "ok" if record["log_summary"]["entry_count"] else "no data"
                    elif args.command == "traces":
                        record["trace_summary"] = summarize_search(response, int(args.limit))
                        record["sample_summary"]["result_type"] = "traces"
                        outcome = "ok" if record["trace_summary"]["trace_count"] else "no data"
                    elif args.command == "trace":
                        record["trace_summary"] = summarize_trace(response, args.query)
                        record["sample_summary"]["result_type"] = "trace"
                        trace = record["trace_summary"]
                        outcome = "ok" if trace["span_count"] else "no data"
                        if trace["start_time_ns"] is not None:
                            # Navigation covers observed spans; the API lookup is unbounded.
                            lower_ms = int(trace["start_time_ns"]) // 1_000_000
                            upper_ms = (int(trace["end_time_ns"]) + 999_999) // 1_000_000
                            record["presenter_link"] = _presenter(
                                presenter, args, proxy, parameters,
                                Decimal(lower_ms) / 1000, Decimal(upper_ms) / 1000,
                            )
                    elif args.command == "get":
                        record["sample_summary"], outcome = _get_summary(response)
                    else:
                        record["sample_summary"], outcome = _summarize(response)
                    record["status"] = "empty" if outcome == "no data" else "ok"
            except (ValueError, TypeError, OverflowError):
                outcome = unavailable("malformed_response", "malformed response")
    if record["retrieved_at"] is None:
        record["retrieved_at"] = datetime.now(UTC).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
    serialized = (
        _json(record).replace("\u0085", "\\u0085")
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    )
    try:
        with Path(EVIDENCE_FILENAME).open("a", encoding="utf-8") as evidence:
            evidence.write(serialized + "\n")
    except OSError:
        print("\n".join(_display(
            record, "unavailable: evidence file could not be written", False
        )))
        return 3
    print("\n".join(_display(record, outcome, True)))
    print(serialized)
    return 1 if record["status"] == "unavailable" else 0


if __name__ == "__main__":
    raise SystemExit(main())
