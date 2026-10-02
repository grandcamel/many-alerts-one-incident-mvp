"""Mechanical summaries of Tempo search and V2 traces; raw data stays intact."""

from __future__ import annotations

import base64
import binascii
import re


class TempoShapeError(ValueError):
    """A Tempo search or trace without the shape these summaries read.

    A `ValueError`, so every caller that reports a malformed response keeps catching it.
    """


def normalize_trace_id(value: str) -> str:
    """Normalize Tempo's possibly trimmed hex ID, rejecting zero and excess bits."""
    if (
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,32}", value)
        or int(value, 16) == 0
    ):
        raise TempoShapeError("invalid trace ID")
    return value.lower().zfill(32)


def _uint(value, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2 ** bits:
        raise TempoShapeError("invalid unsigned integer")
    return value


def _nanoseconds(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise TempoShapeError("invalid nanosecond timestamp")
    return str(_uint(int(value), 64))


def _optional_string(data, key):
    if key not in data:
        return None
    if not isinstance(data[key], str):
        raise TempoShapeError("invalid string")
    return data[key]


def summarize_search(response, limit: int) -> dict:
    """Validate a search and summarize the three longest returned traces."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise TempoShapeError("invalid trace limit")
    if not isinstance(response, dict) or any(
        key in response for key in ("error", "errors", "errorType", "status", "message")
    ):
        raise TempoShapeError("invalid Tempo search")
    traces = response.get("traces", [])
    metrics = response.get("metrics", {})
    if not isinstance(traces, list) or not isinstance(metrics, dict):
        raise TempoShapeError("invalid Tempo search fields")
    excerpts = []
    for trace in traces:
        if not isinstance(trace, dict):
            raise TempoShapeError("invalid trace metadata")
        excerpts.append({
            "trace_id": normalize_trace_id(trace.get("traceID")),
            "root_service": _optional_string(trace, "rootServiceName"),
            "root_name": _optional_string(trace, "rootTraceName"),
            "start_time_ns": (
                _nanoseconds(trace["startTimeUnixNano"]) if "startTimeUnixNano" in trace else None
            ),
            "duration_ms": _uint(trace.get("durationMs", 0), 32),
        })
    excerpts.sort(key=lambda item: (-item["duration_ms"], item["trace_id"]))
    return {
        "kind": "search", "trace_count": len(traces), "limit_reached": len(traces) >= limit,
        "completed_jobs": _uint(metrics["completedJobs"], 32) if "completedJobs" in metrics else None,
        "total_jobs": _uint(metrics["totalJobs"], 32) if "totalJobs" in metrics else None,
        "excerpts": excerpts[:3],
    }


def _id(value, width: int) -> str:
    if not isinstance(value, str):
        raise TempoShapeError("invalid encoded ID")
    if re.fullmatch(rf"[0-9a-fA-F]{{{width * 2}}}", value):
        decoded = bytes.fromhex(value)
    else:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise TempoShapeError("invalid encoded ID") from None
        if base64.b64encode(decoded).decode() != value:
            raise TempoShapeError("noncanonical encoded ID")
    if len(decoded) != width or not any(decoded):
        raise TempoShapeError("invalid ID width or zero ID")
    return decoded.hex()


def _enum(value, names: tuple[str, ...]) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < len(names):
        return names[value]
    if isinstance(value, str) and value in names:
        return value
    raise TempoShapeError("unknown enum")


def _array(data, key):
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TempoShapeError("invalid repeated field")
    return value


def _service(resource_spans):
    resource = resource_spans.get("resource", {})
    if not isinstance(resource, dict):
        raise TempoShapeError("invalid resource")
    service = None
    for attribute in _array(resource, "attributes"):
        if not isinstance(attribute.get("key"), str) or not isinstance(attribute.get("value", {}), dict):
            raise TempoShapeError("invalid resource attribute")
        if attribute["key"] == "service.name":
            value = attribute.get("value", {})
            if set(value) != {"stringValue"} or not isinstance(value["stringValue"], str):
                raise TempoShapeError("invalid service name")
            if service is not None:
                raise TempoShapeError("duplicate service name")
            service = value["stringValue"]
    return service


def summarize_trace(response, expected_trace_id: str) -> dict:
    """Validate a V2 trace and summarize its envelope and five longest spans.

    Backend completeness describes retrieval only. Missing observed parents remain
    visible, and overlapping span durations are never summed into request latency.
    """
    expected = normalize_trace_id(expected_trace_id)
    if (
        not isinstance(response, dict) or not isinstance(response.get("trace"), dict)
        or any(key in response for key in ("error", "errors"))
    ):
        raise TempoShapeError("invalid V2 trace")
    if "batches" in response["trace"]:
        raise TempoShapeError("legacy trace shape")
    backend = _enum(response.get("status", 0), ("COMPLETE", "PARTIAL")).lower()
    message = _optional_string(response, "message")
    spans = []
    seen = set()
    for resource in _array(response["trace"], "resourceSpans"):
        service = _service(resource)
        for scope in _array(resource, "scopeSpans"):
            for span in _array(scope, "spans"):
                if _id(span.get("traceId"), 16) != expected:
                    raise TempoShapeError("mismatched trace ID")
                span_id = _id(span.get("spanId"), 8)
                if span_id in seen:
                    raise TempoShapeError("duplicate span ID")
                seen.add(span_id)
                parent = span.get("parentSpanId", "")
                parent = None if parent == "" else _id(parent, 8)
                start = _nanoseconds(span.get("startTimeUnixNano"))
                end = _nanoseconds(span.get("endTimeUnixNano"))
                if int(end) < int(start):
                    raise TempoShapeError("reversed span interval")
                name = span.get("name", "")
                status = span.get("status", {})
                if not isinstance(name, str) or not isinstance(status, dict):
                    raise TempoShapeError("invalid span name or status")
                spans.append({
                    "span_id": span_id, "parent_span_id": parent, "service": service,
                    "name": name, "kind": _enum(span.get("kind", 0), (
                        "SPAN_KIND_UNSPECIFIED", "SPAN_KIND_INTERNAL", "SPAN_KIND_SERVER",
                        "SPAN_KIND_CLIENT", "SPAN_KIND_PRODUCER", "SPAN_KIND_CONSUMER",
                    )), "status": _enum(status.get("code", 0), (
                        "STATUS_CODE_UNSET", "STATUS_CODE_OK", "STATUS_CODE_ERROR",
                    )), "start_time_ns": start, "end_time_ns": end,
                    "duration_ns": str(int(end) - int(start)),
                })
    spans.sort(key=lambda item: (-int(item["duration_ns"]), item["span_id"]))
    start = min((int(span["start_time_ns"]) for span in spans), default=None)
    end = max((int(span["end_time_ns"]) for span in spans), default=None)
    return {
        "kind": "trace", "trace_id": expected, "backend_status": backend,
        "backend_message": message, "span_count": len(spans),
        "services": sorted({span["service"] for span in spans if span["service"] is not None}),
        "root_span_count": sum(span["parent_span_id"] is None for span in spans),
        "missing_parent_count": sum(
            span["parent_span_id"] is not None and span["parent_span_id"] not in seen for span in spans
        ), "start_time_ns": None if start is None else str(start),
        "end_time_ns": None if end is None else str(end),
        "duration_ns": None if start is None else str(end - start), "spans": spans[:5],
    }
