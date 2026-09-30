"""One configuration: `.env` as compose reads it, the demo's project, and a helper's jira-as.

`.env` is the single source. Compose hands it to the container, and the laptop
helpers read it here, so these tests hold the reader to compose's own reading
of the same lines, and hold a helper's `jira-as` environment to `.env` alone:
an engineer's shell configured for their production site must change nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from grafana_jsm_sandbox.demo_config import (
    CONFIGURE,
    DEFAULT_SESSION_ID,
    ConfigurationError,
    DemoProject,
    IncompleteDemoProject,
    InvalidSessionId,
    compose_environment,
    jira_as_environment,
    read_env_file,
    session_id_from_environment,
    session_label,
)
from grafana_jsm_sandbox.run_spawner import TRUST_STORE_VARIABLES

ENV_FILE_LINES = """\
# a comment
   # an indented comment

PLAIN=plain
DOUBLE="double quoted # not a comment"
SINGLE='single $X # kept'
INLINE=unquoted # an inline comment
HASH=unquoted#no-space
TAB=unquoted\t# kept after a tab
export EXPORTED=exported
SPACED = spaced
EMPTY=
ESCAPED="escaped \\" quote and \\\\ backslash"
PADDED='  padded  '
TRIMMED=  lead and trail
EQUALS=a=b
DEMO_STATUS_IN_PROGRESS=In Progress
BARE_NAME
"""
"""Every rule the reader follows, one per line, with what compose makes of it below."""

AS_COMPOSE_READS_IT = {
    "PLAIN": "plain",
    "DOUBLE": "double quoted # not a comment",
    "SINGLE": "single $X # kept",
    "INLINE": "unquoted",
    "HASH": "unquoted#no-space",
    "TAB": "unquoted\t# kept after a tab",
    "EXPORTED": "exported",
    "SPACED": "spaced",
    "EMPTY": "",
    "ESCAPED": 'escaped " quote and \\ backslash',
    "PADDED": "  padded  ",
    "TRIMMED": "lead and trail",
    "EQUALS": "a=b",
    "DEMO_STATUS_IN_PROGRESS": "In Progress",
}
"""What `docker compose config` resolved those lines to (compose 2.x, 2026-09-23). A bare name
is passed through from compose's own shell, which here has none, so it is absent."""

COMPLETE = {
    "JIRA_SITE_URL": "https://demo-site.atlassian.net",
    "JIRA_EMAIL": "demo@example.invalid",
    "JIRA_API_TOKEN": "the-token-in-dot-env",
    "CLAUDE_CODE_OAUTH_TOKEN": "an-anthropic-oauth-token",
    "DEMO_PROJECT_KEY": "SANDBOX",
}
"""A `.env` that describes a demo that could work, field ids left to `configure`."""

SHELL = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/Users/presenter",
    "JIRA_SITE_URL": "https://production.atlassian.net",
    "JIRA_EMAIL": "me@example.invalid",
    "JIRA_API_TOKEN": "the-token-for-production",
    "JIRA_ALLOWED_PROJECTS": "PROD",
    "JIRA_AS_TRANSPORT": "simulation",
    "AWS_SECRET_ACCESS_KEY": "something the shell happened to have",
}
"""An engineer's shell that uses jira-as every day, against another site and project."""

QUEUE = "https://demo-site.atlassian.net/jira/servicedesk/projects/SANDBOX/queues/custom/7"


def written(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text)
    return path


# --- Reading .env the way compose does ---


def test_the_reader_takes_each_line_the_way_compose_does(tmp_path):
    assert read_env_file(written(tmp_path, ENV_FILE_LINES)) == AS_COMPOSE_READS_IT


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs the docker compose CLI")
def test_compose_itself_reads_those_lines_the_same_way(tmp_path):
    """`docker compose config` against a throwaway project: no daemon, no image, no container."""
    written(tmp_path, ENV_FILE_LINES)
    (tmp_path / "compose.yml").write_text(
        "services:\n  probe:\n    image: alpine:3.20\n    env_file: [.env]\n"
    )
    resolved = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=tmp_path,
        # The shell compose runs in, less anything that would steer it elsewhere or fill
        # in the bare name.
        env={
            name: value
            for name, value in os.environ.items()
            if not name.startswith("COMPOSE_") and name not in ("BARE_NAME", "X")
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if resolved.returncode != 0:
        pytest.skip(f"docker compose config did not run here: {resolved.stderr.strip()}")
    environment = json.loads(resolved.stdout)["services"]["probe"]["environment"]
    # Compose writes a literal `$` back out escaped as `$$` in its own rendering.
    environment = {name: value.replace("$$", "$") for name, value in environment.items()}

    assert environment == AS_COMPOSE_READS_IT


@pytest.mark.parametrize("line", ["TOKEN='never closed", 'TOKEN="never closed'])
def test_a_quote_that_never_closes_is_refused_by_line_and_never_by_value(tmp_path, line):
    """Compose refuses it too; the value may be a token, so only its name and line are said."""
    path = written(tmp_path, f"# first\n{line}\n")

    with pytest.raises(ConfigurationError) as refusal:
        read_env_file(path)

    assert f"{path}:2: TOKEN" in str(refusal.value)
    assert "never closed" not in str(refusal.value)


def test_no_env_file_says_how_to_make_one(tmp_path):
    with pytest.raises(ConfigurationError, match=r"cp \.env\.example \.env"):
        read_env_file(tmp_path / ".env")


def test_what_compose_interpolates_is_env_with_the_shell_over_it(tmp_path):
    path = written(tmp_path, "RECEIVER_HOST_PORT=18080\nGRAFANA_HOST_PORT=13000\n")

    assert compose_environment(path, {"GRAFANA_HOST_PORT": "23000"}) == {
        "RECEIVER_HOST_PORT": "18080",
        "GRAFANA_HOST_PORT": "23000",
    }


def test_without_an_env_file_compose_interpolates_from_the_shell_alone(tmp_path):
    assert compose_environment(tmp_path / ".env", {"BIND_ADDRESS": "::1"}) == {
        "BIND_ADDRESS": "::1"
    }


# --- The demo's project ---


def test_a_project_is_its_key_and_the_facts_configure_wrote():
    project = DemoProject.from_environment(
        {
            "DEMO_PROJECT_KEY": " SANDBOX ",
            "DEMO_SEVERITY_FIELD": "customfield_10085",
            "DEMO_URGENCY_FIELD": "customfield_10079",
            "DEMO_SOURCE_FIELD": "",
            "DEMO_QUEUE_URL": QUEUE,
        }
    )

    assert project == DemoProject(
        key="SANDBOX",
        severity_field="customfield_10085",
        urgency_field="customfield_10079",
        source_field=None,
        major_incident_field=None,
        queue_url=QUEUE,
    )


def test_there_is_no_default_project_and_the_error_says_what_to_do():
    with pytest.raises(IncompleteDemoProject) as refusal:
        DemoProject.from_environment({})

    said = str(refusal.value)
    assert "DEMO_PROJECT_KEY is not set" in said
    assert CONFIGURE in said
    assert "OPS" not in said


@pytest.mark.parametrize("key", ["ops", "O", "1OPS", "OPS-1", "ABCDEFGHIJK", "OP S"])
def test_a_key_jira_would_not_have_is_refused_by_name(key):
    with pytest.raises(IncompleteDemoProject, match="DEMO_PROJECT_KEY is not a Jira project key"):
        DemoProject.from_environment({"DEMO_PROJECT_KEY": key})


@pytest.mark.parametrize("key", ["OP", "OPS", "IT_OPS", "ABCDEFGHIJ", "A1"])
def test_every_key_shape_jira_allows_is_taken(key):
    assert DemoProject.from_environment({"DEMO_PROJECT_KEY": key}).key == key


@pytest.mark.parametrize("value", ["Severity", "10085", "customfield_", "customfield_10085x"])
def test_a_field_that_is_not_a_custom_field_id_is_refused_by_name(value):
    with pytest.raises(IncompleteDemoProject, match="DEMO_URGENCY_FIELD is not a custom field id"):
        DemoProject.from_environment({"DEMO_PROJECT_KEY": "OPS", "DEMO_URGENCY_FIELD": value})


def test_every_problem_with_the_project_is_named_at_once():
    with pytest.raises(IncompleteDemoProject) as refusal:
        DemoProject.from_environment(
            {"DEMO_SEVERITY_FIELD": "Severity", "DEMO_MAJOR_INCIDENT_FIELD": "Major incident"}
        )

    said = str(refusal.value)
    for variable in ("DEMO_PROJECT_KEY", "DEMO_SEVERITY_FIELD", "DEMO_MAJOR_INCIDENT_FIELD"):
        assert variable in said


# --- The session: which take this is ---


def test_a_project_carries_the_session_id_and_its_label():
    project = DemoProject.from_environment(
        {"DEMO_PROJECT_KEY": "OPS", "DEMO_SESSION_ID": " take2 "}
    )

    assert project.session_id == "take2"
    assert project.session_label == "ses-take2"


def test_without_a_session_id_the_default_stands_so_an_older_env_still_runs():
    project = DemoProject.from_environment({"DEMO_PROJECT_KEY": "OPS", "DEMO_SESSION_ID": ""})

    assert project.session_id == DEFAULT_SESSION_ID == "demo"
    assert project.session_label == "ses-demo"
    assert session_id_from_environment({}) == DEFAULT_SESSION_ID


@pytest.mark.parametrize(
    "session_id", ["a", "rehearsal1", "take2", "a" * 32, "local1-demo", "reh-a2"]
)
def test_every_session_id_the_spec_allows_is_taken(session_id):
    assert session_id_from_environment({"DEMO_SESSION_ID": session_id}) == session_id
    assert session_label(session_id) == f"ses-{session_id}"


@pytest.mark.parametrize(
    "session_id", ["Take", "take_1", "take 1", "a" * 33, "take.1", "ses-1!", "tåke"]
)
def test_a_session_id_the_label_could_not_carry_is_refused_by_name(session_id):
    with pytest.raises(InvalidSessionId, match="DEMO_SESSION_ID is not a session id"):
        session_id_from_environment({"DEMO_SESSION_ID": session_id})
    with pytest.raises(IncompleteDemoProject, match="DEMO_SESSION_ID is not a session id"):
        DemoProject.from_environment({"DEMO_PROJECT_KEY": "OPS", "DEMO_SESSION_ID": session_id})


def test_a_bad_session_id_is_named_with_the_project_s_other_problems_at_once():
    with pytest.raises(IncompleteDemoProject) as refusal:
        DemoProject.from_environment({"DEMO_SESSION_ID": "Take One"})

    said = str(refusal.value)
    assert "DEMO_PROJECT_KEY is not set" in said
    assert "DEMO_SESSION_ID is not a session id" in said


# --- A laptop helper's jira-as, from .env and nothing else ---


def test_a_helper_s_jira_as_reaches_the_site_and_project_in_env_whatever_the_shell_says():
    environment = jira_as_environment(COMPLETE, shell=SHELL, warn=lambda message: None)

    assert environment == {
        "PATH": SHELL["PATH"],
        "HOME": SHELL["HOME"],
        "JIRA_SITE_URL": "https://demo-site.atlassian.net",
        "JIRA_EMAIL": "demo@example.invalid",
        "JIRA_API_TOKEN": "the-token-in-dot-env",
        "JIRA_ALLOWED_PROJECTS": "SANDBOX",
        "JIRA_ALLOW_SITE_OPERATIONS": "true",
    }


def test_the_trust_store_comes_from_the_shell_for_a_laptop_behind_a_proxy():
    shell = {**SHELL, **dict.fromkeys(TRUST_STORE_VARIABLES, "/etc/ssl/corporate.pem")}

    environment = jira_as_environment(COMPLETE, shell=shell, warn=lambda message: None)

    for variable in TRUST_STORE_VARIABLES:
        assert environment[variable] == "/etc/ssl/corporate.pem"


@pytest.mark.parametrize("variable", ["HTTPS_PROXY", "https_proxy", "NO_PROXY", "http_proxy"])
def test_the_laptop_s_explicit_proxy_comes_from_the_shell_too(variable):
    """A laptop that reaches the site only through a named proxy reached it that way before
    the helpers read `.env`, and must still."""
    shell = {**SHELL, variable: "http://proxy.corp.example:3128"}

    environment = jira_as_environment(COMPLETE, shell=shell, warn=lambda message: None)

    assert environment[variable] == "http://proxy.corp.example:3128"


def test_a_shell_pointed_at_another_site_is_said_out_loud_and_overruled():
    warnings: list[str] = []

    environment = jira_as_environment(COMPLETE, shell=SHELL, warn=warnings.append)

    assert len(warnings) == 1
    assert "production.atlassian.net" in warnings[0]
    assert "demo-site.atlassian.net" in warnings[0]
    assert "the-token" not in warnings[0]
    assert environment["JIRA_SITE_URL"] == COMPLETE["JIRA_SITE_URL"]


@pytest.mark.parametrize(
    "theirs", ["", "https://DEMO-SITE.atlassian.net/", "demo-site.atlassian.net"]
)
def test_a_shell_on_the_same_site_or_none_at_all_is_not_warned_about(theirs):
    warnings: list[str] = []

    jira_as_environment(COMPLETE, shell={"JIRA_SITE_URL": theirs}, warn=warnings.append)

    assert warnings == []


def test_an_env_file_missing_the_credential_and_the_key_names_them_all_and_no_value():
    values = {"JIRA_SITE_URL": "https://demo-site.atlassian.net", "JIRA_API_TOKEN": "secret-1"}

    with pytest.raises(ConfigurationError) as refusal:
        jira_as_environment(values, shell=SHELL, warn=lambda message: None)

    said = str(refusal.value)
    assert "JIRA_EMAIL" in said
    assert "DEMO_PROJECT_KEY" in said
    assert "secret-1" not in said


def test_status_roles_default_only_when_absent_and_preserve_an_empty_close():
    default = DemoProject.from_environment({"DEMO_PROJECT_KEY": "SANDBOX"})
    assert (
        default.status_open,
        default.status_in_progress,
        default.status_done,
        default.status_closed,
    ) == ("Open", "Work in progress", "Completed", "Closed")
    custom = DemoProject.from_environment(
        {
            "DEMO_PROJECT_KEY": "SANDBOX",
            "DEMO_STATUS_OPEN": "New",
            "DEMO_STATUS_IN_PROGRESS": "In Progress",
            "DEMO_STATUS_DONE": "Resolved",
            "DEMO_STATUS_CLOSED": "",
        }
    )
    assert (
        custom.status_open,
        custom.status_in_progress,
        custom.status_done,
        custom.status_closed,
    ) == ("New", "In Progress", "Resolved", "")


def test_env_writer_and_reader_round_trip_a_status_with_spaces(tmp_path):
    from grafana_jsm_sandbox.configure import Change, write

    path = written(tmp_path, "DEMO_STATUS_IN_PROGRESS=Work in progress # role\n")
    write(path, [Change("DEMO_STATUS_IN_PROGRESS", "Work in progress", "In Progress")])
    assert path.read_text() == "DEMO_STATUS_IN_PROGRESS=In Progress # role\n"
    assert read_env_file(path)["DEMO_STATUS_IN_PROGRESS"] == "In Progress"


@pytest.mark.parametrize(
    ("session_id", "read_as"),
    [("local-1", "local-1"), ("rehearsal-1", "rehearsal-1"), ("2026", "ses-2026")],
)
def test_a_session_id_whose_label_jira_as_reads_as_an_issue_key_is_refused(session_id, read_as):
    """jira-as 2.0.0's project guard reads any `<letters>-<digits>` in JQL as an issue key and
    refuses a search naming another project's, so `ses-local-1` would fail every Match search."""
    with pytest.raises(InvalidSessionId, match=f"reads {read_as} as an issue key"):
        session_id_from_environment({"DEMO_SESSION_ID": session_id})
