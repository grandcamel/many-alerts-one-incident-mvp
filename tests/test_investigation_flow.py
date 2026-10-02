"""Investigation through the real Receiver, RunSpawner and Forwarder on loopback.

A scripted child Run stands in for Claude and executes the real payload builder,
query CLI and jira-as against fake Jira and FakeGrafana. These tests prove
orchestration, not real-model behaviour or obedience to the Skill. No model or
real Grafana or Jira is contacted.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shlex
import subprocess
import sys
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from grafana_jsm_sandbox import grafana_query, incident_payload, skill_template
from grafana_jsm_sandbox.demo_config import InvestigationSettings
from grafana_jsm_sandbox.fake_jira import WORKFLOWS, FakeJira, Server
from grafana_jsm_sandbox.forwarder import Forwarder, JiraCredential
from grafana_jsm_sandbox.investigation_contract import EVIDENCE_FILENAME, is_investigation
from grafana_jsm_sandbox.receiver import Receiver
from grafana_jsm_sandbox.run_command import RENDERED_SKILL, build_run_command
from grafana_jsm_sandbox.run_spawner import API_KEY_VARIABLE, ModelCredential, RunSpawner
from grafana_jsm_sandbox.verify import Timeouts, World
from grafana_jsm_sandbox.verify_content import closing_problem
from grafana_jsm_sandbox.verify_mvp import MVP_SEQUENCE, GroupWatch, comment_text
from tests.conftest import FIXTURES, REPOSITORY, post_notification, wait_for_log
from tests.grafana_upstream import FakeGrafana
from tests.test_fake_jira import EMAIL, GROUP, KEY, SESSION, TOKEN, project_for
from tests.test_fake_jira import jira_as_cli as _jira_as_cli
from tests.test_tempo_query import TRACE_ID, fetched_trace

jira_as_cli = _jira_as_cli

VIEWER_TOKEN = "private-viewer-token-for-loopback-only"
PRESENTER_URL = "http://presenter.example.invalid:3300"
QUERY = 'sum(rate(http_server_duration_milliseconds_count{service_name="rolldice"}[5m]))'
LOG_QUERY = '{service_name="rolldice"}'
LOG_LINE = "demo's roll: 4; \"quoted\" $HOME `literal` café 🎲\nnext\\line"
TRACE_QUERY = '{ resource.service.name = "rolldice" && span:duration > 250ms }'


def scripted_run(
    jira_as: str, status_open: str, status_in_progress: str, status_done: str,
    with_logs: bool = False, with_traces: bool = False,
) -> None:
    """The child follows the lifecycle branches; it makes no model judgment."""
    working = Path.cwd()
    group = incident_payload.read_group(working / "notification.json")
    enabled = os.environ.get("DEMO_INVESTIGATION_ENABLED") == "true"
    (working / "run-details.json").write_text(
        json.dumps(
            {
                "argv": sys.argv[1:],
                "grafana_variables": sorted(
                    name for name in os.environ if name.startswith("DEMO_")
                ),
            }
        )
    )

    def tool(command: str, output: str, failed: bool = False) -> None:
        print(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "scripted",
                                "name": "Bash",
                                "input": {"command": command},
                            },
                        ]
                    },
                }
            ),
            flush=True,
        )
        print(
            json.dumps(
                {
                    "type": "user",
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "scripted",
                                "content": output,
                                "is_error": failed,
                            },
                        ]
                    },
                }
            ),
            flush=True,
        )

    def jira(*arguments: str, may_fail: bool = False) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [jira_as, *arguments], capture_output=True, text=True, timeout=30, check=False
        )
        tool(
            shlex.join(["jira-as", *arguments]),
            result.stdout + result.stderr,
            result.returncode != 0,
        )
        if not may_fail and result.returncode != 0:
            raise RuntimeError("scripted lifecycle Jira command failed")
        return result

    def printed(step: str, *arguments: str) -> list[str]:
        return [
            line
            for line in incident_payload.printed([step, *arguments], working)
            if not line.startswith("#")
        ]

    def execute(line: str, key: str = "") -> str:
        return jira(*shlex.split(line.replace("<key>", key))[1:]).stdout

    def move(key: str, target: str, resolve: bool = False) -> None:
        transitions = json.loads(jira("lifecycle", "transitions", key, "-o", "json").stdout)
        transition = next(t["id"] for t in transitions if t["to"]["name"] == target)
        arguments = ["lifecycle", "transition", key, "--id", transition]
        if resolve:
            result = jira(*arguments, "--resolution", "Done", may_fail=True)
            if result.returncode != 0:
                jira(*arguments)
        else:
            jira(*arguments)

    [search] = printed("match")
    matches = json.loads(execute(search))["issues"]
    investigation = ""
    if not matches and group.firing:
        dry_run, create, opening = printed("create")
        execute(dry_run)
        key = re.search(rf"\b({KEY}-\d+)\b", execute(create))[1]
        execute(opening, key)
        if enabled:
            output = io.StringIO()
            with redirect_stdout(output):
                status = grafana_query.main(["instant", "--query", QUERY])
            tool(
                shlex.join(["grafana-query", "instant", "--query", QUERY]),
                output.getvalue(),
                status != 0,
            )
            if with_logs:
                output = io.StringIO()
                with redirect_stdout(output):
                    log_status = grafana_query.main([
                        "logs", "--query=" + LOG_QUERY,
                        "--start=2023-11-14T22:12:00Z", "--end=2023-11-14T22:14:00Z",
                    ])
                tool("grafana-query logs --query='" + LOG_QUERY + "'",
                     output.getvalue(), log_status != 0)
            if with_traces:
                output = io.StringIO()
                with redirect_stdout(output):
                    trace_status = grafana_query.main([
                        "traces", "--query=" + TRACE_QUERY, "--start=1000", "--end=1001",
                    ])
                tool("grafana-query traces --query='" + TRACE_QUERY + "'",
                     output.getvalue(), trace_status != 0)
                found = json.loads(output.getvalue().splitlines()[-1])
                if trace_status == 0 and found["trace_summary"]["trace_count"]:
                    trace_id = found["trace_summary"]["excerpts"][0]["trace_id"]
                    output = io.StringIO()
                    with redirect_stdout(output):
                        fetch_status = grafana_query.main(["trace", "--id=" + trace_id])
                    tool("grafana-query trace --id=" + trace_id,
                         output.getvalue(), fetch_status != 0)
            [comment] = printed(
                "investigate",
                "--key",
                key,
                "--observation",
                "One current query returned samples",
                "--interpretation",
                "This describes completed requests only",
                "--unknown",
                "Check application reachability independently",
            )
            execute(comment)
            if status == 0:
                investigation = "; investigation recorded"
            else:
                record = json.loads((working / EVIDENCE_FILENAME).read_text())
                investigation = (
                    f"; investigation unavailable ({record['error']['message']})"
                    "; unavailable-evidence comment recorded"
                )
        action = "created"
    elif matches:
        [match] = matches
        key = match["key"]
        fields = match["fields"]
        server_time = json.loads(jira("-o", "json", "api", "call", "getServerInfo").stdout)
        arguments = [
            "--key",
            key,
            "--labels",
            ",".join(fields["labels"]),
            "--created",
            fields["created"],
            "--server-time",
            server_time["serverTime"],
        ]
        if group.firing:
            for line in printed("update", *arguments):
                execute(line)
            if fields["status"]["name"] == status_open:
                move(key, status_in_progress)
            action = "updated"
        else:

            def comments(limit: int) -> dict:
                return json.loads(
                    jira(
                        "collaborate",
                        "comment",
                        "list",
                        key,
                        "--order",
                        "asc",
                        "--limit",
                        str(limit),
                        "-o",
                        "json",
                    ).stdout
                )

            listed = comments(200)
            if len(listed["comments"]) != listed["total"]:
                listed = comments(listed["total"])
            assert len(listed["comments"]) == listed["total"]
            prior = sum(not is_investigation(comment_text(c["body"])) for c in listed["comments"])
            for line in printed("close", *arguments, "--runs", str(prior)):
                execute(line)
            move(key, status_done, resolve=True)
            action = "resolved"
    else:
        key, action = "none", "skipped resolved without Match"

    finish = f"ok: lifecycle completed\nIncident {key}: {action}{investigation}"
    print(
        json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": finish}),
        flush=True,
    )


@pytest.mark.parametrize("workflow", WORKFLOWS.values(), ids=lambda workflow: workflow.name)
@pytest.mark.parametrize("case", [
    "enabled", "disabled", "unreachable", "401", "timeout",
    "loki-success", "loki-empty", "loki-unavailable",
    "tempo-success", "tempo-empty", "tempo-unavailable",
])
def test_investigation_does_not_change_the_lifecycle_or_its_run_count(
    case, workflow, jira_as_cli, tmp_path, caplog, monkeypatch
):
    """Four lifecycle Runs, one possible evidence comment, on either Jira workflow."""
    caplog.set_level(logging.INFO)
    fake = FakeJira(workflow)
    project = project_for(workflow, fake)
    runs = tmp_path / "runs"
    enabled = case != "disabled"
    with_logs = case.startswith("loki-") or case == "tempo-success"
    upstream = FakeGrafana()
    upstream.start()
    try:
        if case == "unreachable":
            upstream.stop()
        elif case == "401":
            upstream.responses.append((401, VIEWER_TOKEN.encode(), 0))
        else:
            response = {
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {"metric": {"service_name": "rolldice"}, "value": [1700000000, "2"]},
                    ],
                },
            }
            upstream.responses.append(
                (200, json.dumps(response).encode(), 11 if case == "timeout" else 0)
            )
        if with_logs:
            if case == "loki-unavailable":
                upstream.responses.append((503, b"upstream unavailable", 0))
            else:
                streams = [] if case == "loki-empty" else [{
                    "stream": {"service_name": "rolldice", "severity_text": "WARN"},
                    "values": [["1700000000123456789", LOG_LINE, {"trace_id": "abc123"}]],
                }]
                upstream.responses.append((200, json.dumps({
                    "status": "success", "data": {"resultType": "streams", "result": streams},
                }).encode(), 0))
        if case.startswith("tempo-"):
            found = [] if case == "tempo-empty" else [{
                "traceID": TRACE_ID, "rootServiceName": "rolldice",
                "rootTraceName": "GET /rolldice", "durationMs": 800,
            }]
            upstream.responses.append((200, json.dumps({"traces": found}).encode(), 0))
            if case == "tempo-success":
                upstream.responses.append((200, json.dumps(fetched_trace()).encode(), 0))
            elif case == "tempo-unavailable":
                upstream.responses.append((503, b"upstream unavailable", 0))
        settings = InvestigationSettings.from_environment(
            {
                "DEMO_INVESTIGATION_ENABLED": "true" if enabled else "false",
                "DEMO_GRAFANA_URL": upstream.url if enabled else "ignored invalid URL",
                "DEMO_GRAFANA_PRESENTER_URL": PRESENTER_URL,
                "DEMO_GRAFANA_VIEWER_TOKEN": VIEWER_TOKEN,
            }
        )
        # Ambient enabled settings must not leak into a disabled child.
        for name, value in (
            InvestigationSettings(True, upstream.url, PRESENTER_URL, VIEWER_TOKEN)
            .run_environment()
            .items()
        ):
            monkeypatch.setenv(name, value)
        skill_template.materialize(
            REPOSITORY / "skill",
            runs / RENDERED_SKILL,
            project,
            investigation_enabled=settings.enabled,
        )
        command = build_run_command(runs, KEY, investigation_enabled=settings.enabled)
        source = (
            f"import sys; sys.path.insert(0, {str(REPOSITORY)!r}); "
            "from tests.test_investigation_flow import scripted_run; "
            f"scripted_run({jira_as_cli!r}, {project.status_open!r}, "
            f"{project.status_in_progress!r}, {project.status_done!r}, "
            f"with_logs={with_logs!r}, "
            f"with_traces={case.startswith('tempo-')!r})"
        )
        with Server(fake) as served:
            forwarder = Forwarder(JiraCredential(served.url, EMAIL, TOKEN))
            forwarder.start()
            try:
                spawner = RunSpawner(
                    [sys.executable, "-c", source, *command[1:]],
                    forwarder,
                    ModelCredential(API_KEY_VARIABLE, "not-a-real-model-key"),
                    EMAIL,
                    KEY,
                    timeout=60,
                    trust_store={},
                    path=str(Path(jira_as_cli).parent) + os.pathsep + os.defpath,
                    investigation_environment=settings.run_environment(),
                )
                if not enabled:
                    assert command == build_run_command(runs, KEY)
                    assert spawner._environment("comparison-sentinel") == replace(
                        spawner, investigation_environment={}
                    )._environment("comparison-sentinel")
                receiver = Receiver(spawner, runs)
                receiver.start()
                try:
                    # The verifier reads fake Jira as an operator, after each Run has ended.
                    def read_jira(*arguments: str) -> str:
                        result = subprocess.run(
                            [jira_as_cli, *arguments],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=True,
                            env={
                                "PATH": spawner.path,
                                "JIRA_SITE_URL": served.url,
                                "JIRA_EMAIL": EMAIL,
                                "JIRA_API_TOKEN": TOKEN,
                                "JIRA_ALLOWED_PROJECTS": KEY,
                            },
                        )
                        return result.stdout

                    world = World(
                        jira_as=read_jira,
                        compose=lambda *args: pytest.fail("unexpected compose"),
                        post=lambda *args: pytest.fail("unexpected verifier post"),
                        grafana_state=lambda: "inactive",
                    )
                    watch = GroupWatch(world, KEY, GROUP, SESSION, Timeouts(), project)
                    directories = []
                    for index, notification in enumerate(MVP_SEQUENCE, start=1):
                        response = post_notification(
                            receiver, (FIXTURES / notification).read_bytes()
                        )
                        assert response.status == 202
                        wait_for_log(caplog, "finished with exit status", count=index, timeout=60)
                        assert "finished with exit status 1" not in caplog.text
                        directory = next(
                            path
                            for path in runs.iterdir()
                            if path.name != RENDERED_SKILL and path not in directories
                        )
                        directories.append(directory)
                        incident = watch.read(f"{KEY}-1")
                        assert incident.comments == index
                        assert len(incident.comment_texts) == index
                        assert not any(is_investigation(text) for text in incident.comment_texts)
                        state = fake.state()["issues"]
                        assert len(state) == 1
                        marked = [
                            c["text"] for c in state[0]["comments"] if is_investigation(c["text"])
                        ]
                        assert len(marked) == int(enabled)
                    assert incident.status == project.status_done
                    assert incident.resolution == "Done"
                    assert incident.repeat_comments == 1
                    assert len(incident.fingerprints) == 4
                    assert closing_problem(incident.comment_texts[-1], {4}, {4}) is None
                    assert "4 Runs" in incident.comment_texts[-1]
                    assert [
                        text.split(":", 1)[0].split(" ")[0] for text in incident.comment_texts
                    ] == ["Opened", "Update", "Update", "Resolved"]
                    posted_comments = json.loads(read_jira(
                        "collaborate", "comment", "list", f"{KEY}-1", "--limit", "200",
                        "-o", "json",
                    ))["comments"]
                    posted_evidence = [
                        comment["body"] for comment in posted_comments
                        if is_investigation(comment_text(comment["body"]))
                    ]
                    assert "FAILED" not in caplog.text
                finally:
                    receiver.stop()
            finally:
                forwarder.stop()
    finally:
        upstream.stop()

    transcripts = [
        list(map(json.loads, (directory / "transcript.jsonl").read_text().splitlines()))
        for directory in directories
    ]
    finishes = [events[-1]["result"] for events in transcripts]
    assert all(finish.startswith("ok: ") for finish in finishes)
    assert all("investigation" not in finish for finish in finishes[1:])
    evidence_files = [directory / EVIDENCE_FILENAME for directory in directories]
    assert [path.exists() for path in evidence_files] == [enabled, False, False, False]
    body_files = [list(directory.glob("*.adf.json")) for directory in directories]
    assert [len(paths) for paths in body_files] == [int(enabled), 0, 0, 0]
    if enabled:
        evidence_commands = [
            block["input"]["command"]
            for event in transcripts[0] if event.get("type") == "assistant"
            for block in event["message"]["content"]
            if block.get("type") == "tool_use"
            and "--format adf" in block.get("input", {}).get("command", "")
        ]
        [delivery] = evidence_commands
        words = shlex.split(delivery)
        assert "--body-file" in words and "-b" not in words
        assert len(delivery.encode("utf-8")) < 256
        basename = words[words.index("--body-file") + 1]
        assert Path(basename).name == basename
        [body_file] = body_files[0]
        assert body_file == directories[0] / basename
        assert posted_evidence == [json.loads(body_file.read_text(encoding="utf-8"))]
    else:
        assert posted_evidence == []
    expected_error = {"unreachable": "unreachable", "401": "token_rejected", "timeout": "timeout"}
    if enabled:
        [record, *log_records] = [
            json.loads(line) for line in evidence_files[0].read_text().splitlines()
        ]
        if case in expected_error:
            assert record["status"] == "unavailable"
            assert record["error"]["kind"] == expected_error[case]
            assert "Observation: Evidence unavailable" in marked[0]
            assert "Interpretation: No conclusion from Grafana" in marked[0]
            assert record["error"]["message"] in marked[0] + finishes[0]
            assert "unavailable-evidence comment recorded" in finishes[0]
        else:
            assert record["status"] == "ok" and record["error"] is None
            assert record["sample_summary"]["sample_count"] == 1
            assert "investigation recorded" in finishes[0]
            assert record["presenter_link"].startswith(PRESENTER_URL + "/explore?")
            assert "Open in Grafana" in marked[0]
        assert record["query"] == QUERY
        if case.startswith("loki-"):
            [log_record] = log_records
            assert log_record["command"] == "logs"
            assert log_record["query"] == LOG_QUERY
            if case == "loki-success":
                assert log_record["status"] == "ok"
                assert LOG_LINE in marked[0]
                assert "1700000000123456789" in marked[0]
                assert "rolldice" in marked[0]
            elif case == "loki-empty":
                assert log_record["status"] == "empty"
                assert LOG_LINE not in marked[0]
                assert "no data" in marked[0].lower() or "no log" in marked[0].lower()
            else:
                assert log_record["status"] == "unavailable"
                assert "HTTP 503" in marked[0]
            assert "investigation recorded" in finishes[0]  # metric evidence remains usable
        elif case.startswith("tempo-"):
            if case == "tempo-success":
                log_record, *log_records = log_records
                assert log_record["command"] == "logs" and log_record["status"] == "ok"
                assert LOG_LINE in marked[0]
            search_record, *fetched = log_records
            assert search_record["command"] == "traces"
            assert search_record["query"] == TRACE_QUERY
            if case == "tempo-empty":
                assert search_record["status"] == "empty" and fetched == []
                assert "no data" in marked[0].lower() or "no traces" in marked[0].lower()
            else:
                assert search_record["status"] == "ok"
                assert TRACE_ID in marked[0]
                [trace_record] = fetched
                assert trace_record["command"] == "trace"
                if case == "tempo-success":
                    assert trace_record["status"] == "ok"
                    assert "rolldice.wait" in marked[0]
                    assert "500000000" in marked[0]
                else:
                    assert trace_record["status"] == "unavailable"
                    assert "HTTP 503" in marked[0]
            assert "investigation recorded" in finishes[0]
        else:
            assert log_records == []
    else:
        assert "investigation" not in finishes[0]
        assert json.loads((directories[0] / "run-details.json").read_text())["argv"] == command[1:]
        assert all(
            json.loads((directory / "run-details.json").read_text())["grafana_variables"] == []
            for directory in directories
        )
    trace_requests = (1 if case == "tempo-empty" else 2) if case.startswith("tempo-") else 0
    assert len(upstream.received) == (
        int(enabled and case != "unreachable") + int(with_logs) + trace_requests
    )
    for index, request in enumerate(upstream.received):
        assert request.method == "GET" and request.body == b""
        assert request.headers["Authorization"] == "Bearer " + VIEWER_TOKEN
        parsed = urlsplit(request.path)
        if index == 0:
            assert parsed.path == "/api/datasources/proxy/uid/prometheus/api/v1/query"
            assert parse_qs(parsed.query)["query"] == [QUERY]
        elif with_logs and index == 1:
            assert parsed.path == "/api/datasources/proxy/uid/loki/loki/api/v1/query_range"
            assert parse_qs(parsed.query)["query"] == [LOG_QUERY]
        elif case.startswith("tempo-"):
            if index == 1 + int(with_logs):
                assert parsed.path == "/api/datasources/proxy/uid/tempo/api/search"
                assert parse_qs(parsed.query)["q"] == [TRACE_QUERY]
            else:
                assert parsed.path == "/api/datasources/proxy/uid/tempo/api/v2/traces/" + TRACE_ID
                assert parsed.query == ""
        else:
            assert parsed.path == "/api/datasources/proxy/uid/loki/loki/api/v1/query_range"
            assert parse_qs(parsed.query)["query"] == [LOG_QUERY]
    saved = "".join(path.read_text() for directory in directories for path in directory.iterdir())
    assert VIEWER_TOKEN not in caplog.text + saved + repr(settings) + repr(spawner)
    assert TOKEN not in caplog.text + saved
