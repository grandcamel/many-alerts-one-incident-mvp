"""Replaying the canned Notification sequence at a Receiver.

The replay is the demo's fallback when Grafana is uncooperative, and it is what
the end-to-end check posts. It drives a real Receiver over real HTTP here, the
same way it drives the container's one during a demo.
"""

from __future__ import annotations

import json
import runpy
import time
from pathlib import Path

import pytest

from grafana_jsm_sandbox import replay as replay_module
from grafana_jsm_sandbox.demo_config import compose_environment
from grafana_jsm_sandbox.replay import SEQUENCE, default_receiver, main, replay
from tests.conftest import FIXTURES


@pytest.fixture
def canned_sequence() -> list[dict]:
    return [json.loads((FIXTURES / filename).read_text()) for filename in SEQUENCE]


def test_every_canned_notification_is_accepted(receiver):
    assert replay(receiver.url, pause=0) == [202, 202, 202]


def test_the_sequence_arrives_in_order_and_starts_one_run_each(receiver, spawner, canned_sequence):
    replay(receiver.url, pause=0)

    spawner.wait_for_spawns(3)
    assert [run.notification for run in spawner.spawned] == canned_sequence


def test_the_pause_falls_between_the_notifications_and_not_after_the_last(
    receiver, spawner, monkeypatch
):
    # The order of posts and pauses, recorded rather than timed: a loaded machine
    # stretches a wall clock, but it cannot reorder this.
    happened = []
    real_post = replay_module.post

    def recording_post(url, notification):
        happened.append("post")
        return real_post(url, notification)

    monkeypatch.setattr(replay_module, "post", recording_post)

    replay(receiver.url, pause=30, sleep=lambda seconds: happened.append(("pause", seconds)))

    assert happened == ["post", ("pause", 30), "post", ("pause", 30), "post"]
    spawner.wait_for_spawns(3)


def test_by_default_the_pause_is_really_waited_out(receiver, spawner):
    # Only a lower bound: load can make a replay slower, never faster. That no
    # pause follows the last post is the recorded order's job, above.
    pause = 0.2
    started_at = time.monotonic()

    replay(receiver.url, pause=pause)

    assert time.monotonic() - started_at >= 2 * pause
    spawner.wait_for_spawns(3)


def test_a_receiver_that_is_not_there_says_so():
    with pytest.raises(OSError):
        replay("http://127.0.0.1:1", pause=0)


# --- Where compose publishes the Receiver on the laptop (step 01 of demo-onboarding) ---


def test_by_default_it_posts_to_the_laptop_s_loopback_where_compose_publishes_it():
    assert default_receiver({}) == "http://127.0.0.1:8080"


def test_a_receiver_moved_off_a_taken_port_is_followed():
    assert default_receiver({"RECEIVER_HOST_PORT": "18080"}) == "http://127.0.0.1:18080"


def test_an_empty_value_means_compose_s_default_as_it_does_for_compose():
    """`${RECEIVER_HOST_PORT:-8080}` takes the default for an empty value, not only a missing one."""
    assert default_receiver({"BIND_ADDRESS": " ", "RECEIVER_HOST_PORT": ""}) == (
        "http://127.0.0.1:8080"
    )


@pytest.mark.parametrize(
    ("address", "url"),
    [
        ("0.0.0.0", "http://localhost:8080"),
        ("::", "http://localhost:8080"),
        ("192.0.2.10", "http://192.0.2.10:8080"),
        ("::1", "http://[::1]:8080"),
    ],
)
def test_the_laptop_reaches_the_address_compose_binds(address, url):
    assert default_receiver({"BIND_ADDRESS": address}) == url


# --- Where compose publishes it when only .env moved it (step 02 of demo-onboarding) ---


def test_a_port_moved_only_in_env_is_followed(tmp_path):
    """Compose interpolates the published port from `.env`, so the replay reads it there too."""
    env_file = tmp_path / ".env"
    env_file.write_text("RECEIVER_HOST_PORT=18080\n")

    assert default_receiver(compose_environment(env_file, {})) == "http://127.0.0.1:18080"


def test_the_shell_moves_it_over_env_as_it_does_for_compose(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("RECEIVER_HOST_PORT=18080\n")
    shell = {"RECEIVER_HOST_PORT": "28080"}

    assert default_receiver(compose_environment(env_file, shell)) == "http://127.0.0.1:28080"


def test_an_env_file_compose_would_refuse_stops_the_replay_by_line(monkeypatch, tmp_path, capsys):
    """Without `--receiver` the default is read from `.env`; one compose cannot read either
    is said once, naming its line, rather than as a traceback."""
    env_file = tmp_path / ".env"
    env_file.write_text("RECEIVER_HOST_PORT='18080\n")
    monkeypatch.setattr(
        "grafana_jsm_sandbox.replay.compose_environment",
        lambda: compose_environment(env_file, {}),
    )

    assert main(["--pause", "0"]) == 1
    assert f"{env_file}:1: RECEIVER_HOST_PORT" in capsys.readouterr().err


def test_collecting_the_opt_in_grafana_checks_never_reads_env(monkeypatch):
    """Every suite collects `test_grafana`, skipped or not, so working out where compose
    published Grafana waits for a check that runs: a skipped one must not open `.env`, and a
    line in it compose would refuse must not stop the whole suite at collection."""

    def refuse():
        raise AssertionError("the Grafana checks read .env while being collected")

    monkeypatch.setattr("grafana_jsm_sandbox.replay.compose_environment", refuse)

    runpy.run_path(str(Path(__file__).with_name("test_grafana.py")))
