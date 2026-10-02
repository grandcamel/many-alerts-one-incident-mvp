"""Mechanical Prometheus summaries shared by query capture and evidence display.

Pure: raw responses stay with the caller; counts, bounds and zero classification
are derived here, without query transport, configuration or Incident handling.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation


def empty_summary() -> dict:
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
    if latest is not None:
        # The payload renders this timestamp. Match its existing datetime range;
        # older samples and unmodelled histogram timestamps are not displayed.
        datetime.fromtimestamp(float(latest["timestamp"]), UTC)
    return ({"labels": labels, "count": len(samples) + unmodelled, "latest": latest,
             "min": None if minimum is None else minimum[1],
             "max": None if maximum is None else maximum[1]}, all_zero)


def summarize(response) -> tuple[dict, str]:
    """Validate metric data and derive counts, bounds and its display outcome."""
    if not isinstance(response, dict) or response.get("status") != "success":
        raise ValueError
    data = response.get("data")
    if not isinstance(data, dict) or "result" not in data:
        raise ValueError
    kind, result = data.get("resultType"), data["result"]
    summary = empty_summary()
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


def summarize_get(response) -> tuple[dict, str]:
    """Summarize known query data, retaining any other JSON as discovery."""
    if isinstance(response, dict) and response.get("status") == "error":
        raise ValueError("query error is not discovery data")
    try:
        return summarize(response)
    except (ValueError, TypeError, OverflowError):
        summary = empty_summary()
        data = (
            response["data"]
            if isinstance(response, dict) and response.get("status") == "success"
            and "data" in response else response
        )
        items = len(data) if isinstance(data, (dict, list)) else 1
        summary.update(result_type="discovery", discovery_items=items)
        return summary, "discovery data" if items else "no data"
