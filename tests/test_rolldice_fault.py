"""The optional diagnostic Fault at the app HTTP and emitted-log boundaries."""

from __future__ import annotations

import importlib.util
import logging
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPOSITORY = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    spec = importlib.util.spec_from_file_location(
        "rolldice_fault_app", REPOSITORY / "docker" / "rolldice" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with module.app.test_client() as client:
        yield client


def test_same_app_serves_healthy_requests_logs_the_fault_and_recovers(client, caplog):
    with caplog.at_level(logging.WARNING):
        healthy = client.get("/rolldice?player=demo")
        assert healthy.status_code == 200
        assert 1 <= int(healthy.data) <= 6
        assert "demo is rolling the dice:" in caplog.text

        caplog.clear()
        fault = client.get("/rolldice?player=demo&sides=six")
        assert fault.status_code == 500
        assert "Traceback (most recent call last):" in caplog.text
        assert "ValueError: invalid literal for int() with base 10: 'six'" in caplog.text
        errors = [record for record in caplog.records if record.exc_info]
        assert any(isinstance(record.exc_info[1], ValueError) for record in errors)

        caplog.clear()
        recovered = client.get("/rolldice?player=demo&sides=6")
        reset = client.get("/rolldice")
        assert recovered.status_code == reset.status_code == 200
        assert 1 <= int(recovered.data) <= 6
        assert 1 <= int(reset.data) <= 6
        assert "demo is rolling the dice:" in caplog.text
        assert "Anonymous player is rolling the dice:" in caplog.text
        assert not any(record.exc_info for record in caplog.records)


@pytest.mark.parametrize("query, upper_bound", [("", 6), ("?sides=1", 1), ("?sides=12", 12)])
def test_default_and_valid_sides_return_results_within_the_requested_bounds(client, query, upper_bound):
    for _ in range(20):
        response = client.get("/rolldice" + query)
        assert response.status_code == 200
        assert 1 <= int(response.data) <= upper_bound


@pytest.mark.parametrize("sides", [None, "six", "6"])
def test_traffic_forwards_default_fault_and_reset_and_keeps_requesting_after_failures(tmp_path, sides):
    services = yaml.safe_load((REPOSITORY / "docker-compose.yml").read_text())["services"]
    traffic = services["traffic"]
    assert traffic["environment"]["ROLLDICE_SIDES"] == "${ROLLDICE_SIDES:-6}"
    assert "ROLLDICE_SIDES" not in services["rolldice"]["environment"]
    command = traffic["command"]
    assert command[:2] == ["sh", "-c"]
    assert "$${ROLLDICE_SIDES}" in command[2]

    # Substitute only the external executables. wget's nonzero result models its
    # response to HTTP 500; the third sleep ends the otherwise unchanged loop.
    wget = tmp_path / "wget"
    wget.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRAFFIC_CALLS"\n'
        'printf "server returned HTTP 500\\n" >&2\nexit 8\n'
    )
    sleep = tmp_path / "sleep"
    sleep.write_text(
        '#!/bin/sh\nprintf "tick\\n" >> "$TRAFFIC_TICKS"\n'
        'if [ "$(wc -l < "$TRAFFIC_TICKS")" -ge 3 ]; then kill -TERM "$PPID"; fi\n'
    )
    wget.chmod(0o755)
    sleep.chmod(0o755)
    calls = tmp_path / "calls"
    ticks = tmp_path / "ticks"
    environment = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ.get("PATH", ""),
        "ROLLDICE_SIDES": "6" if sides is None else sides,
        "TRAFFIC_CALLS": str(calls),
        "TRAFFIC_TICKS": str(ticks),
    }
    completed = subprocess.run(
        [*command[:2], command[2].replace("$$", "$")],
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == -15
    expected_sides = "6" if sides is None else sides
    assert calls.read_text().splitlines() == [
        f"-qO- http://rolldice:8082/rolldice?player=demo&sides={expected_sides}"
    ] * 3
    assert completed.stderr.count("server returned HTTP 500") == 3
