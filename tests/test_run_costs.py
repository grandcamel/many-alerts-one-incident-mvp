"""The accounting helper consumes the result lines the Receiver actually renders."""

from io import StringIO

from grafana_jsm_sandbox import log_formatter, run_costs


def result(cost=None, **changes):
    return log_formatter.format_event(
        {
            "type": "result",
            "subtype": "success",
            "duration_ms": 30000,
            "num_turns": 4,
            "total_cost_usd": cost,
            **changes,
        }
    )


def test_totals_rendered_result_lines_including_duplicates_and_zero():
    lines = [*result(0.1234), *result(0.1), *result(0.1), *result(0)]
    logged = [f"2026-09-30 INFO {line}\n" for line in lines]
    assert list(run_costs.cost_lines(logged)) == [
        *(line.rstrip() for line in logged),
        "Total: $0.3234 (Receiver result lines only)",
    ]


def test_ignores_chatter_unpriced_results_and_failed_runs():
    lines = [
        *log_formatter.format_event(
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "$20"}]}}
        ),
        *result(),
        *result(0.1234, is_error=True, result="failed"),
        "not a result, $1.2345",
    ]
    assert list(run_costs.cost_lines(lines)) == ["Total: $0.0000 (Receiver result lines only)"]


def test_empty_logs_have_a_zero_total():
    assert list(run_costs.cost_lines([])) == ["Total: $0.0000 (Receiver result lines only)"]


def test_cli_reads_stdin_and_prints_each_result_and_the_total(monkeypatch, capsys):
    lines = result(0.125) + result(0.375)
    monkeypatch.setattr(run_costs.sys, "stdin", StringIO("\n".join(lines)))
    assert run_costs.main([]) == 0
    assert capsys.readouterr().out.splitlines() == [
        *lines,
        "Total: $0.5000 (Receiver result lines only)",
    ]
