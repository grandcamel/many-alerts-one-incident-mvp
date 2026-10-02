"""Deterministic local failures must be refused before starting a model Run."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import replace
from email.message import Message
from unittest.mock import Mock

import pytest

from grafana_jsm_sandbox import run_spawner
from grafana_jsm_sandbox.incident_payload import FACTS_FILE, Facts
from grafana_jsm_sandbox.receiver import Receiver, Run
from grafana_jsm_sandbox.run_command import RENDERED_SKILL
from grafana_jsm_sandbox.run_spawner import API_KEY_VARIABLE, ModelCredential, RunSpawner
from tests.conftest import post_notification, wait_for_log


def prepare_run(tmp_path, notification=None):
    run = Run("preflight", tmp_path / "runs" / "preflight")
    run.working_directory.mkdir(parents=True)
    run.notification_path.write_text(json.dumps(notification if notification is not None else {
        "alerts": [{"fingerprint": "abc123", "status": "firing"}],
        "groupLabels": {"incident_group": "Checkout / Outage"},
    }))
    facts = run.working_directory.parent / RENDERED_SKILL / FACTS_FILE
    facts.parent.mkdir()
    facts.write_text(Facts("DEMO", "ses-demo", None, None, None, "Completed").as_json())
    return run, facts


def spawner(forwarder):
    event = {"type": "result", "subtype": "success", "is_error": False}
    return RunSpawner(
        [sys.executable, "-c", f"print({json.dumps(event)!r})"],
        forwarder,
        ModelCredential(API_KEY_VARIABLE, "synthetic-preflight-key"),
        "review@example.invalid",
        "DEMO",
        trust_store={},
    )


@pytest.mark.parametrize("notification, reason", [
    ({"alerts": []}, "has no alerts"),
    ({"alerts": [{"fingerprint": 123, "status": "firing"}],
      "groupLabels": {"incident_group": "x"}}, "fingerprint is not lower-case hex"),
    ({"alerts": [{"fingerprint": "abc123", "status": "unknown"}],
      "groupLabels": {"incident_group": "x"}}, "status is neither firing nor resolved"),
    ({"alerts": [{"fingerprint": "abc123", "status": "firing"}]},
     "has no groupLabels.incident_group"),
    ({"alerts": [{"fingerprint": "abc123", "status": "firing"}],
      "groupLabels": {"incident_group": "!!!"}}, "leaves nothing for the grp- label"),
])
def test_unusable_group_fails_before_authority_or_process_start(
    tmp_path, monkeypatch, notification, reason
):
    run, _ = prepare_run(tmp_path, notification)
    original = run.notification_path.read_bytes()
    forwarder = Mock(url="http://127.0.0.1:1")
    popen = Mock(side_effect=AssertionError("a refused Run must not launch"))
    monkeypatch.setattr(run_spawner.subprocess, "Popen", popen)
    generate = Mock(side_effect=AssertionError("a refused Run must not generate a Sentinel"))
    monkeypatch.setattr(run_spawner.secrets, "token_urlsafe", generate)

    outcome = spawner(forwarder)(run)

    assert outcome.exit_status != 0
    assert outcome.failure.startswith("preflight failed: ")
    assert reason in outcome.failure
    assert forwarder.mock_calls == []
    popen.assert_not_called()
    generate.assert_not_called()
    assert run.notification_path.read_bytes() == original
    assert not run.transcript_path.exists()


@pytest.mark.parametrize("problem, reason", [
    ("missing", "there are no project facts"),
    ("directory", "cannot be read"),
    ("invalid-encoding", "cannot be read"),
    ("invalid-json", "project facts are not JSON"),
    ("invalid-shape", "project facts are not a JSON object"),
    ("invalid-project", "project facts' project is not one"),
])
@pytest.mark.parametrize("resolved", [False, True])
def test_unusable_project_facts_fail_before_authority_or_process_start(
    tmp_path, monkeypatch, problem, reason, resolved
):
    run, facts = prepare_run(tmp_path)
    if resolved:
        notification = json.loads(run.notification_path.read_text())
        notification["alerts"][0]["status"] = "resolved"
        run.notification_path.write_text(json.dumps(notification))
    if problem in {"missing", "directory"}:
        facts.unlink()
        if problem == "directory":
            facts.mkdir()
    elif problem == "invalid-encoding":
        facts.write_bytes(b"\xff")
    else:
        facts.write_text({"invalid-json": "{", "invalid-shape": "[]",
                          "invalid-project": "{}"}[problem])
    forwarder = Mock(url="http://127.0.0.1:1")
    popen = Mock(side_effect=AssertionError("a refused Run must not launch"))
    monkeypatch.setattr(run_spawner.subprocess, "Popen", popen)
    generate = Mock(side_effect=AssertionError("a refused Run must not generate a Sentinel"))
    monkeypatch.setattr(run_spawner.secrets, "token_urlsafe", generate)

    outcome = spawner(forwarder)(run)

    assert outcome.exit_status != 0
    assert outcome.failure.startswith("preflight failed: ")
    assert reason in outcome.failure
    assert forwarder.mock_calls == []
    popen.assert_not_called()
    generate.assert_not_called()
    assert not run.transcript_path.exists()


@pytest.mark.parametrize("statuses", [("firing",), ("resolved",), ("firing", "resolved")])
def test_valid_group_launches_with_optional_display_fields_absent(tmp_path, statuses):
    notification = {
        "alerts": [{"fingerprint": f"abc{index}", "status": status}
                   for index, status in enumerate(statuses)],
        "groupLabels": {"incident_group": "Checkout / Outage"},
    }
    run, _ = prepare_run(tmp_path, notification)
    original = run.notification_path.read_bytes()
    forwarder = Mock(url="http://127.0.0.1:1")

    outcome = spawner(forwarder)(run)

    assert outcome.exit_status == 0 and outcome.failure is None
    forwarder.set_sentinel.assert_called_once()
    expected = forwarder.set_sentinel.call_args.args[1]
    if "firing" in statuses:
        assert set(expected["labels"]) == {
            "grp-checkout-outage", "ses-demo", *[f"fp-abc{i}" for i in range(len(statuses))]
        }
    else:
        assert expected is None
    forwarder.clear_sentinel.assert_called_once_with()
    assert run.notification_path.read_bytes() == original
    assert run.transcript_path.is_file()


@pytest.mark.parametrize("case", ["success", "refusal", "timeout", "spawn-error"])
def test_explicit_diagnostic_without_notification_registers_and_cleans_up(
    tmp_path, monkeypatch, case
):
    run = Run("doctor-probe", tmp_path / "doctor-probe")
    run.working_directory.mkdir()
    forwarder = Mock(url="http://127.0.0.1:1")
    probe = spawner(forwarder)
    if case == "refusal":
        event = {"type": "result", "subtype": "error_during_execution", "is_error": True,
                 "result": "diagnostic refused"}
        probe = replace(probe, command=[sys.executable, "-c", f"print({json.dumps(event)!r})"])
    elif case == "timeout":
        probe = replace(probe, command=[sys.executable, "-c", "import time; time.sleep(30)"],
                        timeout=0.15)
    elif case == "spawn-error":
        probe = replace(probe, command=[str(tmp_path / "no-such-cli")])
    real_popen = run_spawner.subprocess.Popen

    def launch(*args, **kwargs):
        forwarder.set_sentinel.assert_called_once_with(kwargs["env"]["JIRA_API_TOKEN"], None)
        forwarder.clear_sentinel.assert_not_called()
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(run_spawner.subprocess, "Popen", launch)
    if case == "spawn-error":
        with pytest.raises(FileNotFoundError):
            probe.run_diagnostic(run)
    else:
        outcome = probe.run_diagnostic(run)
        if case == "success":
            assert outcome.exit_status == 0 and outcome.failure is None
        elif case == "refusal":
            assert outcome.exit_status == 0
            assert outcome.failure == "error_during_execution: diagnostic refused"
        else:
            assert outcome.exit_status != 0 and "timeout" in outcome.failure
        assert run.transcript_path.is_file()
    forwarder.set_sentinel.assert_called_once()
    forwarder.clear_sentinel.assert_called_once_with()
    assert not run.notification_path.exists()


def test_explicit_diagnostic_has_no_incident_create_authority(tmp_path, monkeypatch):
    from grafana_jsm_sandbox.forwarder import Forwarder, JiraCredential
    from grafana_jsm_sandbox.receiver import RunOutcome
    from tests.conftest import basic_auth_header
    from tests.test_forwarder import ISSUE_BODY

    monkeypatch.setattr("grafana_jsm_sandbox.forwarder.ThreadingHTTPServer", lambda *args: None)
    forwarder = Forwarder(JiraCredential(
        "https://example.invalid", "review@example.invalid", "synthetic-forwarder-key"
    ))
    upstream = Mock(side_effect=AssertionError("diagnostic create must not reach upstream"))
    monkeypatch.setattr(forwarder, "_send_upstream", upstream)
    run = Run("doctor-probe", tmp_path / "doctor-probe")
    run.working_directory.mkdir()

    def execute(self, run, sentinel):
        assert forwarder._sentinel == sentinel
        assert forwarder._create_fields is None
        headers = Message()
        headers["Authorization"] = basic_auth_header(self.jira_email, sentinel)
        status, _, _ = forwarder.handle("POST", "/rest/api/3/issue", headers, ISSUE_BODY)
        assert status == 400
        upstream.assert_not_called()
        return RunOutcome(0)

    monkeypatch.setattr(RunSpawner, "_execute", execute)

    assert spawner(forwarder).run_diagnostic(run) == RunOutcome(0)
    assert forwarder._sentinel is None and forwarder._create_fields is None


def test_receiver_keeps_generic_admission_and_processes_valid_run_after_local_failure(
    tmp_path, caplog
):
    caplog.set_level(logging.INFO)
    prepared, _ = prepare_run(tmp_path)
    valid = prepared.notification_path.read_bytes()
    forwarder = Mock(url="http://127.0.0.1:1")
    receiver = Receiver(spawner(forwarder), prepared.working_directory.parent)
    receiver.start()
    try:
        assert post_notification(receiver, {"alerts": []}).status == 202
        assert post_notification(receiver, valid).status == 202
        log = wait_for_log(caplog, "finished with exit status", count=2)
    finally:
        receiver.stop()

    assert "FAILED: preflight failed:" in log
    assert "finished with exit status 0" in log
    forwarder.set_sentinel.assert_called_once()
    forwarder.clear_sentinel.assert_called_once_with()
