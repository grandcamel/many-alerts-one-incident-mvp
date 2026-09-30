"""Starting the container's main process: the Receiver, its Forwarder, its spawner.

A misconfigured container that starts anyway and no-ops is the worst thing that
can happen during the demo, because nothing says so until an Alert fires and
nothing happens. These tests are the fail-fast: every variable that is missing
is named, and named all at once, before anything is listening.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from grafana_jsm_sandbox import __main__ as process
from grafana_jsm_sandbox.__main__ import (
    LOG_FORMAT,
    LOG_TIME_FORMAT,
    RUN_BUDGET_VARIABLE,
    RUN_MODEL_VARIABLE,
    Settings,
    log_run_knobs,
    main,
    refuse_to_be_read,
    render_skill,
    serve,
)
from grafana_jsm_sandbox.demo_config import CONFIGURE, DemoProject
from grafana_jsm_sandbox.nondumpable import PR_SET_DUMPABLE
from grafana_jsm_sandbox.run_command import DEFAULT_MODEL, SKILL_FILE, build_run_command
from grafana_jsm_sandbox.run_spawner import (
    API_KEY_VARIABLE,
    OAUTH_TOKEN_VARIABLE,
    ModelCredential,
)

COMPLETE = {
    "JIRA_SITE_URL": "https://example.atlassian.net",
    "JIRA_EMAIL": "ops@example.invalid",
    "JIRA_API_TOKEN": "a-real-token",
    OAUTH_TOKEN_VARIABLE: "an-anthropic-oauth-token",
    "DEMO_PROJECT_KEY": "SANDBOX",
}

A_WORK_API_KEY = "sk-ant-api03-a-work-api-key-that-must-never-be-logged"


def complete_but(**overrides) -> dict[str, str]:
    """The complete environment with variables replaced, or removed when set to None."""
    environment = dict(COMPLETE, **overrides)
    return {name: value for name, value in environment.items() if value is not None}


def test_a_complete_environment_gives_the_receiver_everything_a_run_needs():
    settings = Settings.from_environment(COMPLETE)

    assert settings.credential.site_url == "https://example.atlassian.net"
    assert settings.credential.email == "ops@example.invalid"
    assert settings.credential.api_token == "a-real-token"
    assert settings.model_credential == ModelCredential(
        OAUTH_TOKEN_VARIABLE, "an-anthropic-oauth-token"
    )
    assert settings.project == DemoProject(key="SANDBOX")


# --- The model credential: a work API key, or the OAuth token, exactly one (the MVP spec) ---


def test_a_work_api_key_in_place_of_the_oauth_token_gives_the_receiver_what_a_run_needs():
    settings = Settings.from_environment(
        complete_but(**{OAUTH_TOKEN_VARIABLE: None, API_KEY_VARIABLE: A_WORK_API_KEY})
    )

    assert settings.model_credential == ModelCredential(API_KEY_VARIABLE, A_WORK_API_KEY)


def test_startup_stops_when_both_model_credentials_are_set_and_names_both(capsys):
    assert main([], environment=complete_but(**{API_KEY_VARIABLE: A_WORK_API_KEY})) == 1

    said = capsys.readouterr().err
    assert f"both {API_KEY_VARIABLE} and {OAUTH_TOKEN_VARIABLE} are set" in said
    assert A_WORK_API_KEY not in said and "an-anthropic-oauth-token" not in said


def test_startup_stops_when_no_model_credential_is_set_and_names_both_names(capsys):
    assert main([], environment=complete_but(**{OAUTH_TOKEN_VARIABLE: None})) == 1

    said = capsys.readouterr().err
    assert f"neither {API_KEY_VARIABLE} nor {OAUTH_TOKEN_VARIABLE} is set" in said


@pytest.mark.parametrize(
    ("variable", "value", "kind"),
    [
        (API_KEY_VARIABLE, A_WORK_API_KEY, "an Anthropic API key"),
        (OAUTH_TOKEN_VARIABLE, "an-anthropic-oauth-token", "a Claude Code OAuth token"),
    ],
)
def test_startup_logs_which_kind_of_model_credential_runs_hold_and_never_its_value(
    caplog, variable, value, kind
):
    caplog.set_level(logging.INFO)
    settings = Settings.from_environment(
        complete_but(**{OAUTH_TOKEN_VARIABLE: None, variable: value})
    )

    log_run_knobs(settings)

    assert f"runs authenticate with {kind} ({variable})" in caplog.text
    assert value not in caplog.text


def test_the_skill_directory_defaults_to_the_one_in_this_repo():
    settings = Settings.from_environment(COMPLETE)

    assert (settings.skill_directory / SKILL_FILE).is_file()


def test_the_receiver_listens_where_the_container_expects_it_to():
    settings = Settings.from_environment(COMPLETE)

    assert settings.host == "0.0.0.0"
    assert settings.port == 8080


def test_the_container_can_say_where_everything_lives(tmp_path):
    settings = Settings.from_environment(
        complete_but(
            RECEIVER_HOST="127.0.0.1",
            RECEIVER_PORT="9000",
            RUNS_DIRECTORY=str(tmp_path / "runs"),
            SKILL_DIRECTORY="/srv/skill",
            RUN_TIMEOUT="45",
        )
    )

    assert (settings.host, settings.port) == ("127.0.0.1", 9000)
    assert settings.runs_directory == tmp_path / "runs"
    assert settings.skill_directory == Path("/srv/skill")
    assert settings.run_timeout == 45


@pytest.mark.parametrize(
    "variable",
    ["JIRA_SITE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", OAUTH_TOKEN_VARIABLE, "DEMO_PROJECT_KEY"],
)
def test_startup_stops_and_names_a_missing_credential(variable, capsys):
    assert main([], environment=complete_but(**{variable: None})) == 1

    assert variable in capsys.readouterr().err


def test_startup_names_every_missing_credential_at_once(capsys):
    assert main([], environment={}) == 1

    said = capsys.readouterr().err
    for variable in COMPLETE:
        assert variable in said


def test_there_is_no_default_project_and_startup_says_what_to_do(capsys):
    """No OPS default: a default key would send Runs to whichever project has it (step 02)."""
    assert main([], environment=complete_but(DEMO_PROJECT_KEY=None)) == 1

    said = capsys.readouterr().err
    assert "DEMO_PROJECT_KEY is not set" in said
    assert CONFIGURE in said


def test_startup_names_the_project_key_alongside_a_missing_credential(capsys):
    assert main([], environment=complete_but(JIRA_EMAIL=None, DEMO_PROJECT_KEY=None)) == 1

    said = capsys.readouterr().err
    assert "JIRA_EMAIL" in said
    assert "DEMO_PROJECT_KEY" in said


@pytest.mark.parametrize(
    ("variable", "value"),
    [("DEMO_PROJECT_KEY", "ops"), ("DEMO_SEVERITY_FIELD", "Severity")],
)
def test_startup_stops_on_a_project_value_jira_would_not_have(variable, value, capsys):
    assert main([], environment=complete_but(**{variable: value})) == 1

    assert variable in capsys.readouterr().err


def test_the_project_s_field_ids_reach_the_settings():
    settings = Settings.from_environment(complete_but(DEMO_SOURCE_FIELD="customfield_10096"))

    assert settings.project.source_field == "customfield_10096"
    assert settings.project.severity_field is None


def test_startup_stops_on_a_site_url_that_is_not_a_url(capsys):
    assert main([], environment=complete_but(JIRA_SITE_URL="example.atlassian.net")) == 1

    assert "JIRA_SITE_URL" in capsys.readouterr().err


def test_startup_stops_on_a_port_that_is_not_a_number(capsys):
    assert main([], environment=complete_but(RECEIVER_PORT="eight thousand")) == 1

    assert "RECEIVER_PORT" in capsys.readouterr().err


def test_startup_stops_on_a_timeout_that_is_not_a_number(capsys):
    assert main([], environment=complete_but(RUN_TIMEOUT="five minutes")) == 1

    assert "RUN_TIMEOUT" in capsys.readouterr().err


def test_startup_says_nothing_of_the_credential_it_could_not_read(capsys):
    """A container that fails to start still prints its log where an audience can see it."""
    main([], environment=complete_but(JIRA_EMAIL=None))

    assert "a-real-token" not in capsys.readouterr().err


# --- The Skill is rendered from the project at every start (step 03 of demo-onboarding) ---


def settings_in(tmp_path: Path, **overrides) -> Settings:
    """Complete settings whose runs directory is a fresh one under `tmp_path`."""
    return Settings.from_environment(
        complete_but(RUNS_DIRECTORY=str(tmp_path / "runs"), **overrides)
    )


def test_every_start_renders_the_skill_for_the_project_into_the_runs_directory(tmp_path):
    settings = settings_in(tmp_path, DEMO_SEVERITY_FIELD="customfield_20001")

    rendered = render_skill(settings)

    assert rendered == tmp_path / "runs" / ".skill"
    skill = (rendered / SKILL_FILE).read_text(encoding="utf-8")
    assert "project = SANDBOX AND issuetype = Incident" in skill
    assert "customfield_20001" in skill
    assert "{{" not in skill


def test_a_restart_with_another_project_renders_the_skill_afresh(tmp_path):
    """The runs directory is a tmpfs in the container, but an ordinary one on a laptop."""
    render_skill(settings_in(tmp_path, DEMO_SEVERITY_FIELD="customfield_20001"))

    rendered = render_skill(settings_in(tmp_path, DEMO_PROJECT_KEY="OTHER"))

    skill = (rendered / SKILL_FILE).read_text(encoding="utf-8")
    assert "project = OTHER AND" in skill
    assert "SANDBOX" not in skill
    assert "customfield_20001" not in skill


def test_the_session_label_is_rendered_into_the_skill_from_env(tmp_path):
    """`{{SESSION_LABEL}}` is `ses-<DEMO_SESSION_ID>`, the label a Run matches and writes."""
    template = tmp_path / "skill" / "incident-sync"
    template.mkdir(parents=True)
    (template / "SKILL.md").write_text(
        'Project {{PROJECT_KEY}}: search labels = "{{SESSION_LABEL}}", add {{SESSION_LABEL}}.\n'
    )
    settings = settings_in(
        tmp_path, SKILL_DIRECTORY=str(tmp_path / "skill"), DEMO_SESSION_ID="rehearsal2"
    )

    rendered = render_skill(settings)

    assert (rendered / SKILL_FILE).read_text(encoding="utf-8") == (
        'Project SANDBOX: search labels = "ses-rehearsal2", add ses-rehearsal2.\n'
    )


def test_a_restart_with_another_session_renders_the_skill_afresh(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    template = tmp_path / "skill" / "incident-sync"
    template.mkdir(parents=True)
    (template / "SKILL.md").write_text("{{PROJECT_KEY}} {{SESSION_LABEL}}\n")
    skill_directory = str(tmp_path / "skill")
    render_skill(settings_in(tmp_path, SKILL_DIRECTORY=skill_directory, DEMO_SESSION_ID="take1"))

    rendered = render_skill(
        settings_in(tmp_path, SKILL_DIRECTORY=skill_directory, DEMO_SESSION_ID="take2")
    )

    assert (rendered / SKILL_FILE).read_text(encoding="utf-8") == "SANDBOX ses-take2\n"
    assert "session label ses-take2" in caplog.text


def test_startup_stops_on_a_session_id_the_label_could_not_carry(capsys):
    assert main([], environment=complete_but(DEMO_SESSION_ID="Take One")) == 1

    assert "DEMO_SESSION_ID is not a session id" in capsys.readouterr().err


def test_the_skill_is_rendered_where_every_run_is_pointed(tmp_path):
    settings = settings_in(tmp_path)

    rendered = render_skill(settings)

    command = build_run_command(settings.runs_directory, settings.project.key)
    assert command[command.index("--add-dir") + 1] == str(rendered.resolve())


class Started(Exception):
    """Raised by a stand-in Forwarder, so a test can stop `serve` at its first step after the
    Skill, rather than have it listen until interrupted."""


def test_the_skill_is_rendered_before_the_forwarder_starts(tmp_path, monkeypatch):
    settings = settings_in(tmp_path)
    found = []

    def forwarder(credential):
        found.append((settings.runs_directory / ".skill" / SKILL_FILE).is_file())
        raise Started

    monkeypatch.setattr(process, "Forwarder", forwarder)

    with pytest.raises(Started):
        serve(settings)
    assert found == [True]


def test_a_skill_that_cannot_be_rendered_stops_the_start_before_anything_listens(
    tmp_path, monkeypatch, capsys
):
    """Served anyway, every Run would fail, and only once an Alert had fired."""
    template = tmp_path / "skill" / "incident-sync"
    template.mkdir(parents=True)
    (template / "SKILL.md").write_text("Project {{PROJECT_KEY}}, queue {{NOBODY}}.\n")
    settings = settings_in(tmp_path, SKILL_DIRECTORY=str(tmp_path / "skill"))

    def forwarder(credential):
        raise AssertionError("the Forwarder started anyway")

    monkeypatch.setattr(process, "Forwarder", forwarder)

    assert serve(settings) == 1
    said = capsys.readouterr().err
    assert "cannot render the Run's Skill" in said
    assert "{{NOBODY}}" in said
    assert not (tmp_path / "runs" / ".skill").exists()


# --- No Run can read the Receiver's environment (step 01 of demo-onboarding) ---


def test_on_linux_the_receiver_marks_itself_non_dumpable():
    """The one call that makes /proc/1 root's: prctl(PR_SET_DUMPABLE, 0)."""
    calls = []

    def prctl(option, value):
        calls.append((option, value))
        return 0

    assert refuse_to_be_read(platform="linux", prctl=prctl) is True
    assert calls == [(PR_SET_DUMPABLE, 0)]


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_elsewhere_there_is_no_proc_to_close_and_nothing_is_called(platform):
    """Laptop mode on a Mac starts exactly as it did."""

    def prctl(option, value):
        raise AssertionError("prctl called off Linux")

    assert refuse_to_be_read(platform=platform, prctl=prctl) is False


def test_a_prctl_that_fails_is_an_error_not_a_quiet_start():
    with pytest.raises(OSError):
        refuse_to_be_read(platform="linux", prctl=lambda option, value: -1)


def test_startup_stops_rather_than_serve_a_receiver_a_run_could_read(monkeypatch, capsys):
    """Checked before anything listens: serving would hand every Run the real token."""

    def refuse():
        raise OSError(1, "Operation not permitted")

    def serve(settings):
        raise AssertionError("served anyway")

    monkeypatch.setattr(process, "refuse_to_be_read", refuse)
    monkeypatch.setattr(process, "serve", serve)

    assert main([], environment=COMPLETE) == 1
    said = capsys.readouterr().err
    assert "Operation not permitted" in said
    assert "a-real-token" not in said


def test_a_complete_environment_is_made_unreadable_and_then_served(monkeypatch):
    order = []
    monkeypatch.setattr(process, "refuse_to_be_read", lambda: order.append("refused") or True)
    monkeypatch.setattr(process, "serve", lambda settings: order.append("served") or 0)

    assert main([], environment=COMPLETE) == 0
    assert order == ["refused", "served"]


READ_A_NON_DUMPABLE_CHILD = """\
import os, sys, time
from grafana_jsm_sandbox.__main__ import refuse_to_be_read
assert refuse_to_be_read()
print("ready", flush=True)
time.sleep(30)
"""
"""A process that does what the Receiver does at startup, then waits to be read."""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc is Linux's")
def test_on_linux_a_process_of_the_same_uid_cannot_read_the_environment(tmp_path):
    """The real call, against the real kernel: the token in the environment stays there.

    As root, which holds CAP_SYS_PTRACE, the read would succeed; a Run holds no
    capability, so this is only meaningful as an ordinary user.
    """
    if os.geteuid() == 0:
        pytest.skip("root reads any process's /proc; a Run is not root")
    child = subprocess.Popen(
        [sys.executable, "-c", READ_A_NON_DUMPABLE_CHILD],
        env={**os.environ, "PROBE_TOKEN": "must-not-be-readable"},
        cwd=Path(__file__).resolve().parent.parent,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        for path in (f"/proc/{child.pid}/environ", f"/proc/{child.pid}/task/{child.pid}/environ"):
            with pytest.raises(PermissionError):
                Path(path).read_bytes()
    finally:
        child.kill()
        child.wait()


# --- Every log line has a time and a level (step 05 of demo-onboarding) ---


def test_the_receiver_logs_with_a_time_and_a_level(monkeypatch):
    configured = {}
    monkeypatch.setattr(process, "refuse_to_be_read", lambda: False)
    monkeypatch.setattr(process, "serve", lambda settings: 0)
    monkeypatch.setattr(logging, "basicConfig", lambda **given: configured.update(given))

    assert main([], environment=COMPLETE) == 0
    assert configured == {"level": logging.INFO, "format": LOG_FORMAT, "datefmt": LOG_TIME_FORMAT}


@pytest.mark.parametrize(
    ("level", "shown"),
    [(logging.INFO, "INFO   "), (logging.WARNING, "WARNING"), (logging.ERROR, "ERROR  ")],
)
def test_a_log_line_reads_time_level_message_with_the_transcript_labels_aligned(level, shown):
    record = logging.LogRecord("grafana_jsm_sandbox", level, __file__, 1, "[claude] hi", (), None)

    line = logging.Formatter(LOG_FORMAT, LOG_TIME_FORMAT).format(record)

    assert re.fullmatch(rf"\d{{4}}-\d\d-\d\d \d\d:\d\d:\d\d {shown} \[claude\] hi", line)


# --- The model a Run asks for, and what one may spend (step 06 of demo-onboarding) ---


def test_a_run_asks_for_opus_5_unless_the_environment_names_another_model():
    assert Settings.from_environment(COMPLETE).run_model == DEFAULT_MODEL == "claude-opus-5"
    assert Settings.from_environment(complete_but(RUN_MODEL="  ")).run_model == DEFAULT_MODEL

    chosen = Settings.from_environment(complete_but(RUN_MODEL=" claude-haiku-4-5 "))
    assert chosen.run_model == "claude-haiku-4-5"


@pytest.mark.parametrize("value", ["claude opus 5", "--dangerously-skip-permissions", "-x"])
def test_startup_stops_on_a_model_that_is_no_model_name(value, capsys):
    """One starting `-` would reach Claude Code as a flag, not as the value of `--model`."""
    assert main([], environment=complete_but(RUN_MODEL=value)) == 1

    assert RUN_MODEL_VARIABLE in capsys.readouterr().err


def test_by_default_a_run_has_no_spending_cap():
    assert Settings.from_environment(COMPLETE).run_budget_usd is None
    assert Settings.from_environment(complete_but(RUN_BUDGET_USD=" ")).run_budget_usd is None


@pytest.mark.parametrize(("value", "budget"), [("2", 2.0), (" 0.50 ", 0.5), ("1e1", 10.0)])
def test_a_budget_in_dollars_reaches_the_settings(value, budget):
    assert Settings.from_environment(complete_but(RUN_BUDGET_USD=value)).run_budget_usd == budget


@pytest.mark.parametrize("value", ["two dollars", "$2", "0", "-1", "nan", "inf"])
def test_startup_stops_on_a_budget_that_is_not_a_positive_number(value, capsys):
    """Zero, a negative, NaN or infinity is no cap anyone meant; refused rather than guessed."""
    assert main([], environment=complete_but(RUN_BUDGET_USD=value)) == 1

    assert RUN_BUDGET_VARIABLE in capsys.readouterr().err


def test_a_bad_model_and_a_bad_budget_are_named_with_every_other_failure(capsys):
    environment = complete_but(RUN_MODEL="-x", RUN_BUDGET_USD="0", JIRA_EMAIL=None)

    assert main([], environment=environment) == 1

    said = capsys.readouterr().err
    for variable in (RUN_MODEL_VARIABLE, RUN_BUDGET_VARIABLE, "JIRA_EMAIL"):
        assert variable in said


class StandInForwarder:
    """Enough of a Forwarder for `serve` to hand the spawner, without a thread or a socket."""

    def __init__(self, credential):
        self.credential = credential

    def start(self):
        pass

    def stop(self):
        pass


def test_every_run_is_started_with_the_model_and_the_budget_from_the_settings(
    tmp_path, monkeypatch
):
    settings = settings_in(tmp_path, RUN_MODEL="claude-haiku-4-5", RUN_BUDGET_USD="1.5")
    commands = []

    def spawner(command, **given):
        commands.append(command)
        raise Started

    monkeypatch.setattr(process, "Forwarder", StandInForwarder)
    monkeypatch.setattr(process, "RunSpawner", spawner)

    with pytest.raises(Started):
        serve(settings)
    [command] = commands
    assert command == build_run_command(
        settings.runs_directory, "SANDBOX", model="claude-haiku-4-5", budget_usd=1.5
    )


def test_startup_says_which_model_runs_use_and_that_there_is_no_cap(caplog):
    with caplog.at_level(logging.INFO, logger=process.__name__):
        log_run_knobs(Settings.from_environment(COMPLETE))

    said = caplog.text
    assert f"runs use model {DEFAULT_MODEL} (RUN_MODEL)" in said
    assert "runs have no spending cap (RUN_BUDGET_USD is not set)" in said


def test_startup_says_what_one_run_may_spend(caplog):
    settings = Settings.from_environment(complete_but(RUN_MODEL="opus", RUN_BUDGET_USD="2"))

    with caplog.at_level(logging.INFO, logger=process.__name__):
        log_run_knobs(settings)

    assert "runs use model opus (RUN_MODEL)" in caplog.text
    assert "each run may spend at most $2.0 (RUN_BUDGET_USD)" in caplog.text


def test_the_model_is_logged_once_the_receiver_is_listening(tmp_path, monkeypatch):
    """`serve` says it after the Receiver starts, with the other lines a presenter reads."""
    settings = settings_in(tmp_path)
    said = []

    class Receiver:
        url = "http://127.0.0.1:0"

        def __init__(self, **given):
            pass

        def start(self):
            said.append("listening")

        def stop(self):
            pass

    def logged(given):
        # Out of `serve` here, before it waits, so the test need not reach into how.
        said.append(given.run_model)
        raise Started

    monkeypatch.setattr(process, "Forwarder", StandInForwarder)
    monkeypatch.setattr(process, "Receiver", Receiver)
    monkeypatch.setattr(process, "log_run_knobs", logged)

    with pytest.raises(Started):
        serve(settings)
    assert said == ["listening", DEFAULT_MODEL]
