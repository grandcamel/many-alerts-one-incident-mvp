"""The Run's Skill, rendered from the demo's project at every Receiver start.

The Skill in the repo is a template, and what a Run reads is its rendering for
the project `.env` names. These tests render the real template, because the
Skill is read off a screen during the demo: every placeholder filled, the
project's key wherever the Skill names a project, the configured field ids in its
facts, and a field the project lacks named as one to leave off rather than left as
a gap for a Run to fill. Beside it the rendering holds the same facts as data, for
`incident-payload`, which builds every payload, so the Skill asks a Run to write no
ADF and no JSON of its own.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from grafana_jsm_sandbox.demo_config import DemoProject
from grafana_jsm_sandbox.incident_payload import FACTS_FILE, Facts
from grafana_jsm_sandbox.run_command import SKILL_FILE
from grafana_jsm_sandbox.skill_template import (
    DEFAULT_SESSION_LABEL,
    READ_ONLY_DIRECTORY,
    READ_ONLY_FILE,
    SkillTemplateError,
    facts,
    materialize,
    render,
)

TEMPLATE_DIRECTORY = Path(__file__).resolve().parent.parent / "skill"
TEMPLATE = (TEMPLATE_DIRECTORY / SKILL_FILE).read_text(encoding="utf-8")
"""The template this repo ships, which the image copies in and the Receiver renders."""

CONFIGURED = DemoProject(
    key="SANDBOX",
    severity_field="customfield_20001",
    urgency_field="customfield_20002",
    source_field="customfield_20003",
    major_incident_field="customfield_20004",
)
"""A project with every field, under ids that are nobody's real site's."""

BARE = DemoProject(key="SANDBOX")
"""A project that lacks every optional field."""

OWNER_S_IDS = ("customfield_10085", "customfield_10079", "customfield_10096", "customfield_10083")
"""The ids one site's Skill once carried by hand (the 2026-09-23 audit, F3)."""

SESSION = "ses-rehearsal1"
"""One demo session's label, as the Receiver renders it from `DEMO_SESSION_ID`."""

SESSIONED = replace(CONFIGURED, session_id="rehearsal1")
"""The configured project in the take `DEMO_SESSION_ID=rehearsal1`, whose label is `SESSION`."""


def match_search(skill: str) -> str:
    """The Skill's one Match search."""
    [line] = [line for line in skill.splitlines() if line.startswith("jira-as search jql")]
    return line


def commands(skill: str, prose: bool = True) -> list[str]:
    """Every command line the Skill spells out, fenced, then quoted in its prose.

    A prose quote that follows a "never" names a command not to run, and is left out.
    """
    fenced = [
        line
        for block in re.findall(r"```bash\n(.*?)```", skill, flags=re.DOTALL)
        for line in block.splitlines()
    ]
    if not prose:
        return fenced
    quoted = [
        found[1]
        for found in re.finditer(r"`((?:jira-as|incident-payload) [^`]+)`", skill)
        if "never" not in skill[max(0, found.start() - 40) : found.start()].lower()
    ]
    return fenced + quoted


def section(skill: str, heading: str) -> str:
    """One `## ` section of the Skill, its heading included, with its lines joined."""
    [body] = [part for part in skill.split("\n## ") if part.startswith(heading)]
    return " ".join(body.split())


def fact(skill: str, name: str) -> str:
    """One row's value in the Skill's table of project facts."""
    [value] = re.findall(rf"^\| {re.escape(name)} \| (.*) \|$", skill, flags=re.MULTILINE)
    return value


# --- The template ---


def test_the_template_carries_no_site_s_facts():
    """Nothing in the tracked file is one site's: no key, no field id (audit F2 and F3)."""
    assert "OPS" not in TEMPLATE
    assert "customfield_" not in TEMPLATE


def test_the_template_names_only_placeholders_that_are_filled():
    for project in (CONFIGURED, BARE):
        assert "{{" not in render(TEMPLATE, project)
        assert "}}" not in render(TEMPLATE, project)


# --- The session label (the MVP spec's `ses-<DEMO_SESSION_ID>`) ---


def test_the_session_label_placeholder_is_this_take_s_label():
    """`{{SESSION_LABEL}}` is filled wherever it stands, ready for a JQL clause or a labels
    argument as it is: a Jira label, with the prefix on."""
    template = (
        'labels = "{{SESSION_LABEL}}" AND project = {{PROJECT_KEY}} --labels {{SESSION_LABEL}}'
    )

    assert render(template, DemoProject(key="SANDBOX", session_id="rehearsal2")) == (
        'labels = "ses-rehearsal2" AND project = SANDBOX --labels ses-rehearsal2'
    )


def test_a_project_read_without_a_session_id_renders_the_default_label():
    assert render("{{SESSION_LABEL}}", BARE) == "ses-demo"


def test_the_session_label_is_rendered_whole_into_the_skill_directory(tmp_path):
    source = tmp_path / "skill"
    (source / "incident-sync").mkdir(parents=True)
    (source / "incident-sync" / "SKILL.md").write_text(
        "Match {{SESSION_LABEL}} on {{PROJECT_KEY}}.\n"
    )

    target = materialize(source, tmp_path / ".skill", DemoProject(key="SANDBOX", session_id="t-1"))

    assert (target / "incident-sync" / "SKILL.md").read_text() == "Match ses-t-1 on SANDBOX.\n"


def test_the_template_names_the_session_label_placeholder():
    """`{{SESSION_LABEL}}` is the one placeholder `configure` does not fill: the Receiver
    renders it from `DEMO_SESSION_ID` (Lane 3), and the spec puts it on every Incident."""
    assert "{{SESSION_LABEL}}" in TEMPLATE


# --- The group and the session ---


def test_the_facts_name_the_group_label_and_the_session_label():
    skill = render(TEMPLATE, SESSIONED)

    assert fact(skill, "Group label").startswith("`grp-<incident_group>`")
    assert fact(skill, "Session label").startswith(f"`{SESSION}`")
    assert fact(skill, "Fingerprint labels").startswith("`fp-<fingerprint>`")


def test_the_session_label_is_rendered_wherever_the_skill_names_the_session():
    skill = render(TEMPLATE, SESSIONED)

    assert "{{" not in skill
    assert f'labels = "{SESSION}"' in match_search(skill)
    assert f"`grp-<incident_group>`, `{SESSION}`, and `fp-<fingerprint>`" in skill
    assert "ses-<" not in skill, "a Run must never be left to spell the session label itself"


def test_without_a_configured_session_every_run_shares_one_label():
    """Until `DEMO_SESSION_ID` is configured and passed in, the label is a fixed one that is
    still a label a Run can search by and never a gap for a Run to fill."""
    skill = render(TEMPLATE, CONFIGURED)

    assert f"`{DEFAULT_SESSION_LABEL}`, and `fp-<fingerprint>`" in skill
    assert f'labels = "{DEFAULT_SESSION_LABEL}"' in match_search(skill)
    assert re.fullmatch(r"ses-[a-z0-9-]{1,32}", DEFAULT_SESSION_LABEL)


@pytest.mark.parametrize("session_id", ["", "Rehearsal", "take one", "take_1", "a" * 33])
def test_a_session_label_that_is_not_one_is_refused(session_id):
    """`DemoProject.from_environment` refuses these already; a project built any other way is
    refused here, before a Run could write the label onto an Incident or search by it."""
    with pytest.raises(SkillTemplateError, match="session label"):
        render(TEMPLATE, replace(CONFIGURED, session_id=session_id))


def test_the_match_is_the_open_incident_of_the_group_and_the_session_not_of_one_alert():
    """The spec's Match: `labels = "grp-…" AND labels = "ses-…" AND statusCategory != Done`."""
    search = match_search(render(TEMPLATE, SESSIONED))

    assert 'labels = "grp-<incident_group>"' in search
    assert f'labels = "{SESSION}"' in search
    assert "statusCategory != Done" in search
    assert "fp-" not in search


def test_the_skill_creates_one_incident_for_the_group_with_every_alert_s_fingerprint():
    skill = render(TEMPLATE, SESSIONED)
    text = " ".join(skill.split())

    assert "Handle every Alert in it independently" not in text
    assert "never creates one Incident per Alert" in text
    assert "never creates a second one for a group that already has one open" in text
    assert (
        f"`grp-<incident_group>`, `{SESSION}`, and `fp-<fingerprint>` for every Alert in the "
        "Notification, resolved ones included. No other label." in text
    )
    assert "[Create](#step-2a--create-the-incident) the one Incident" in skill
    assert "incident-payload create --component '<service>'" in commands(skill)


def test_the_skill_updates_an_open_match_by_adding_labels_and_one_comment():
    """The label add is jira-as 2.0.0's `api call editIssue` with an `update.labels` add, which
    `incident-payload update` prints: its `issue update --labels` replaces the set, which would
    drop the group and session labels."""
    skill = render(TEMPLATE, SESSIONED)
    update = section(skill, "Step 2b")

    assert (
        "incident-payload update --key <key> --labels '<label>,<label>' --created '<created>' "
        "--server-time '<serverTime>'" in commands(skill)
    )
    assert "an `api call editIssue` with an `update.labels` add" in update
    assert "Never use `jira-as issue update --labels` for this" in update
    assert not any(command.startswith("jira-as issue update") for command in commands(skill))
    assert "Never remove a label" in skill
    assert "[Update](#step-2b--update-the-incident) it, then move it to `Work in progress`" in skill
    assert "[Update](#step-2b--update-the-incident) it and nothing else" in skill
    assert "which Alerts are new, which repeat and which resolved" in update


def test_a_resolved_notification_closes_the_match_and_is_skipped_without_one():
    skill = render(TEMPLATE, SESSIONED)

    assert (
        "| `resolved` | `Open` or `Work in progress` | [Close](#step-2c--close-the-incident) it |"
        in skill
    )
    assert "| `resolved` | none | Do nothing. Say you skipped it and why" in skill
    assert "jira-as lifecycle transition <key> --id <id> --resolution Done" in skill


def test_chapter_one_s_rules_still_hold():
    skill = render(TEMPLATE, SESSIONED)

    assert "Never set `Sev-0`." in skill
    assert (
        "A Run never moves an\nIncident into any status other than `Work in progress` and `Completed`."
        in skill
    )
    assert "is human-owned: still add new `fp-` labels and comments" in skill
    assert "`critical` → `Sev-1`" in skill and "`Sev-1` → `Critical`" in skill
    assert "never pass `--to`" in skill
    assert "Never remove a label." in skill
    assert "and say in the finish that a duplicate exists" in " ".join(skill.split())


# --- A Run builds no payload by hand (the 2026-10-01 rehearsals) ---


def test_the_skill_asks_for_no_adf_and_no_hand_built_json():
    """Haiku wrote the Description's ADF under `--custom-fields` by hand, six times wrong. The
    Skill now names neither: `incident-payload` builds the payload and prints the command."""
    for project in (CONFIGURED, BARE):
        skill = render(TEMPLATE, project)

        assert '{"type":"doc"' not in skill
        assert "ADF" not in skill.split("## Step 2c")[0]
        assert "--custom-fields" not in skill and "--description" not in skill
        assert "`jira-as issue create" not in skill
        assert not any(command.startswith("jira-as issue create") for command in commands(skill))
        assert "You never build a Jira payload by hand." in skill


def test_every_step_s_payload_comes_from_incident_payload():
    skill = render(TEMPLATE, SESSIONED)
    fenced = commands(skill, prose=False)
    named = [command for command in fenced if command.startswith("incident-payload")]

    assert [command.split()[1] for command in named] == ["match", "create", "update", "close"]
    assert "incident-payload create" in commands(skill), "without a component"
    text = " ".join(skill.split())
    assert "exactly as printed. Change nothing in it except a literal `<key>`" in text
    assert "If it prints a line starting `incident-payload: error:`, stop there" in text
    assert "Never build the command yourself instead." in text


def test_the_create_is_dry_run_first_then_made_exactly_once():
    create = section(render(TEMPLATE, SESSIONED), "Step 2a")

    assert "**The dry run**" in create and "sends nothing to Jira" in create
    assert "holds a `bulletList` with one `listItem` per firing Alert" in create
    assert "Run it **exactly once**." in create
    assert "Never run the create a second time, never retry it with other fields" in create
    assert "never edit the Description afterwards" in create
    assert "never create an Incident to probe what the project accepts" in create


def test_every_jql_query_names_the_project():
    """Sonnet twice searched `key = <KEY>-NNN` and jira-as refused it for lacking one."""
    for project in (CONFIGURED, BARE, SESSIONED):
        skill = render(TEMPLATE, project)
        searches = [command for command in commands(skill) if " search jql " in command]

        assert searches
        for search in searches:
            assert search.startswith(f"jira-as search jql 'project = {project.key} AND ")
        assert f"Every JQL query names the project, `project = {project.key}`" in " ".join(
            skill.split()
        )


def test_a_known_key_is_read_with_issue_get_and_a_field_list_never_with_jql():
    """A whole issue on a work site was 20 to 40 KB of asset fields: `Output too large`."""
    skill = render(TEMPLATE, SESSIONED)
    reads = [command for command in commands(skill) if " issue get " in command]

    assert reads == ["jira-as issue get <key> --fields status,resolution -o json"]
    assert not re.search(r"issue get <key> -o json", skill)
    assert "never looked up with JQL" in " ".join(skill.split())
    assert "Never read a whole issue without `--fields`" in " ".join(skill.split())
    assert not any("key =" in command for command in commands(skill))


def test_the_duration_is_the_match_s_created_and_jira_s_clock_with_no_further_read():
    """The Match search returns `created`, so an update or a close reads no issue for it."""
    skill = render(TEMPLATE, SESSIONED)

    assert match_search(skill).endswith("--fields key,status,labels,created -o json")
    for heading in ("Step 2b", "Step 2c"):
        step = section(skill, heading)
        assert "jira-as -o json api call getServerInfo" in step
        assert "--created '<created>' --server-time '<serverTime>'" in step
        assert "search jql" not in step and "issue get <key> -o json" not in step
    assert "the Match's own `fields.created`, from the search" in section(skill, "Step 2b")


def test_a_close_is_checked_for_a_resolution_and_fails_without_one():
    close = section(render(TEMPLATE, SESSIONED), "Step 2c")

    assert "jira-as issue get <key> --fields status,resolution -o json" in close
    assert (
        "If its `fields.status.name` is `Completed` and its `fields.resolution` is null, "
        "finish `failed`" in close
    )
    assert "--leave-status" in close


# --- A project with every field ---


def test_every_place_the_skill_names_a_project_names_the_configured_one():
    skill = render(TEMPLATE, CONFIGURED)

    assert "OPS" not in skill
    assert "the Jira SANDBOX project" in skill.split("---")[1], "the frontmatter"
    assert fact(skill, "Project") == "`SANDBOX`"
    assert "jira-as search jql 'project = SANDBOX AND issuetype = Incident" in skill
    assert "jira-as -o json api call getProjectComponents --projectIdOrKey SANDBOX" in skill


def test_the_facts_name_each_configured_field_id_with_the_values_it_takes():
    skill = render(TEMPLATE, CONFIGURED)

    assert fact(skill, "Severity field") == "`customfield_20001`, one of `Sev-1`, `Sev-2`, `Sev-3`"
    assert (
        fact(skill, "Urgency field") == "`customfield_20002`, one of `Critical`, `High`, `Medium`"
    )
    assert fact(skill, "Source field") == "`customfield_20003`, always `Monitoring systems`"
    assert "Never touch Major incident (`customfield_20004`)." in skill


def test_the_facts_beside_the_skill_are_the_ones_it_shows(tmp_path):
    """`incident-payload` reads these, so they must say what the Skill's table says."""
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", SESSIONED)

    written = Facts.from_json((target / FACTS_FILE).read_text(encoding="utf-8"))
    assert written == facts(SESSIONED)
    assert written == Facts(
        project="SANDBOX",
        session_label=SESSION,
        severity_field="customfield_20001",
        urgency_field="customfield_20002",
        source_field="customfield_20003",
        status_done="Completed",
    )
    skill = (target / SKILL_FILE).read_text(encoding="utf-8")
    for field_id in (written.severity_field, written.urgency_field, written.source_field):
        assert f"`{field_id}`" in skill


def test_a_field_the_project_lacks_is_null_in_the_facts(tmp_path):
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", BARE)

    written = json.loads((target / FACTS_FILE).read_text(encoding="utf-8"))
    assert written["severity_field"] is None
    assert written["urgency_field"] is None and written["source_field"] is None
    assert "major_incident_field" not in written, "a Run never touches it, so the tool never does"


@pytest.mark.parametrize("project", [CONFIGURED, BARE])
def test_every_command_the_skill_spells_out_is_one_line_the_allow_list_matches(project):
    """One line of plain single quotes, or the permission boundary denies it whole (README)."""
    for command in commands(render(TEMPLATE, project)):
        assert command.split()[0] in ("jira-as", "incident-payload"), command
        assert shlex.split(command)
        assert "$'" not in command and "\\" not in command and "\n" not in command


def test_alert_text_quotes_are_replaced_without_shell_escape_syntax():
    skill = render(TEMPLATE, BARE)

    assert "`incident-payload` writes every `'` from alert text as `’` (U+2019)" in skill
    assert r"never use `'\''` or `$'…'`" in skill


def test_closing_reads_comments_to_count_runs():
    close = section(render(TEMPLATE, BARE), "Step 2c")

    assert "one per prior lifecycle comment, the opening one included" in close
    assert "--runs <count>" in close and "counts this Run as one more" in close


@pytest.mark.parametrize("enabled", [False, True])
def test_closing_counts_only_lifecycle_bodies_after_verifying_raw_completeness(enabled):
    close = " ".join(section(render(TEMPLATE, BARE, investigation_enabled=enabled), "Step 2c").split())
    assert "jira-as collaborate comment list <key> --order asc --limit 200 -o json" in close
    assert "--order asc --limit <total> -o json" in close
    assert "returned comment count equals the raw `total`" in close
    assert "Do not guess from a partial list" in close
    assert "[grafana-investigation] " in close
    assert "case-sensitive, including the trailing space" in close
    assert "Human and other unmarked comments count" in close
    assert "--runs <count>" in close


def test_a_successful_label_add_is_not_rechecked_or_retried():
    skill = render(TEMPLATE, BARE)

    assert "It prints `null` on success; do not re-check or retry it." in section(skill, "Step 2b")


def test_no_other_site_s_field_id_survives_rendering():
    skill = render(TEMPLATE, CONFIGURED)

    for field_id in OWNER_S_IDS:
        assert field_id not in skill


# --- A project that lacks a field ---


def test_a_project_with_no_optional_field_is_told_to_leave_each_off_naming_no_id():
    skill = render(TEMPLATE, BARE)

    assert "customfield_" not in skill
    assert fact(skill, "Severity field") == "none on this project, so leave Severity off"
    assert fact(skill, "Urgency field") == "none on this project, so leave Urgency off"
    assert fact(skill, "Source field") == "none on this project, so leave Source off"
    assert "Never touch Major incident." in skill


@pytest.mark.parametrize("missing", ["severity_field", "urgency_field", "source_field"])
def test_a_missing_field_is_left_out_of_the_skill_and_the_facts_and_the_rest_stay(missing):
    project = DemoProject(**{**CONFIGURED.__dict__, missing: None})
    skill = render(TEMPLATE, project)

    absent = getattr(CONFIGURED, missing)
    assert absent not in skill
    assert getattr(facts(project), missing) is None
    present = {"severity_field", "urgency_field", "source_field"} - {missing}
    for attribute in present:
        assert getattr(CONFIGURED, attribute) in skill
        assert getattr(facts(project), attribute) == getattr(CONFIGURED, attribute)


def test_a_missing_major_incident_field_leaves_the_rest_as_configured():
    project = DemoProject(**{**CONFIGURED.__dict__, "major_incident_field": None})
    skill = render(TEMPLATE, project)

    assert "customfield_20004" not in skill
    assert "Never touch Major incident." in skill
    assert facts(project) == facts(CONFIGURED)


def test_the_skill_says_a_field_it_lacks_stays_off_and_is_never_guessed():
    """Read naturally on screen whichever fields a site has, and give a Run no gap to fill."""
    for project in (CONFIGURED, BARE):
        assert "never guess one" in render(TEMPLATE, project)


# --- What is refused ---


def test_a_placeholder_nobody_fills_is_refused_by_name():
    with pytest.raises(SkillTemplateError) as refusal:
        render("Project {{PROJECT_KEY}}, queue {{QUEUE_ID}} and {{BOARD}}.", CONFIGURED)

    assert "{{QUEUE_ID}}" in str(refusal.value)
    assert "{{BOARD}}" in str(refusal.value)
    assert "{{PROJECT_KEY}}" not in str(refusal.value)


@pytest.mark.parametrize("template", ["{{ PROJECT_KEY }}", "{{project_key}}", "{{PROJECT_KEY"])
def test_a_misspelled_placeholder_is_refused_rather_than_left_for_a_run(template):
    with pytest.raises(SkillTemplateError, match="NAME"):
        render(template, CONFIGURED)


def test_a_project_with_no_key_leaves_the_key_unfilled_and_is_refused():
    with pytest.raises(SkillTemplateError, match=r"\{\{PROJECT_KEY\}\}"):
        render(TEMPLATE, DemoProject(key=""))


def test_rendering_is_the_same_every_time():
    assert render(TEMPLATE, CONFIGURED) == render(TEMPLATE, CONFIGURED)


# --- Materializing the whole skill directory ---


def test_the_whole_skill_directory_is_rendered_into_the_target(tmp_path):
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / "runs" / ".skill", CONFIGURED)

    assert target == tmp_path / "runs" / ".skill"
    assert (target / SKILL_FILE).read_text(encoding="utf-8") == render(TEMPLATE, CONFIGURED)


def test_the_session_label_is_rendered_into_the_whole_skill_directory(tmp_path):
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", SESSIONED)

    written = (target / SKILL_FILE).read_text(encoding="utf-8")
    assert written == render(TEMPLATE, SESSIONED)
    assert SESSION in written and DEFAULT_SESSION_LABEL not in written


def test_a_skill_directory_with_a_bad_session_label_is_not_written(tmp_path):
    with pytest.raises(SkillTemplateError, match="session label"):
        materialize(
            TEMPLATE_DIRECTORY, tmp_path / ".skill", replace(CONFIGURED, session_id="Take 1")
        )

    assert not (tmp_path / ".skill").exists()


def test_a_file_that_is_not_markdown_is_copied_as_it_is(tmp_path):
    source = tmp_path / "skill"
    (source / "incident-sync").mkdir(parents=True)
    (source / "incident-sync" / "SKILL.md").write_text("Project {{PROJECT_KEY}}.\n")
    (source / "incident-sync" / "example.json").write_bytes(b'{"kept": "{{AS_IS}}"}')

    target = materialize(source, tmp_path / ".skill", CONFIGURED)

    assert (target / "incident-sync" / "SKILL.md").read_text() == "Project SANDBOX.\n"
    assert (target / "incident-sync" / "example.json").read_bytes() == b'{"kept": "{{AS_IS}}"}'


def test_a_second_start_replaces_the_first_start_s_skill_entirely(tmp_path):
    """On a laptop the runs directory outlives the Receiver; the Skill must not."""
    target = tmp_path / ".skill"
    materialize(TEMPLATE_DIRECTORY, target, DemoProject(key="EARLIER"))
    source = tmp_path / "skill"
    (source / "incident-sync").mkdir(parents=True)
    (source / "incident-sync" / "SKILL.md").write_text("Project {{PROJECT_KEY}}.\n")

    materialize(source, target, CONFIGURED)

    assert (target / SKILL_FILE).read_text() == "Project SANDBOX.\n"
    assert sorted(p.relative_to(target) for p in target.rglob("*")) == [
        Path("incident-sync"),
        Path(SKILL_FILE),
        Path(FACTS_FILE),
    ]
    assert Facts.from_json((target / FACTS_FILE).read_text()).project == "SANDBOX"


def test_a_template_that_cannot_be_filled_leaves_no_skill_at_all(tmp_path):
    """Not the last start's Skill for another project, and not half of this one's."""
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", CONFIGURED)
    source = tmp_path / "skill"
    source.mkdir()
    (source / "a.md").write_text("fine {{PROJECT_KEY}}\n")
    (source / "b.md").write_text("broken {{NOBODY}}\n")

    with pytest.raises(SkillTemplateError, match=r"b\.md: \{\{NOBODY\}\}"):
        materialize(source, target, CONFIGURED)

    assert not target.exists()


def test_a_template_that_is_not_utf8_is_refused_by_name(tmp_path):
    """Refused like any other unrenderable template, so the Receiver says why and stops."""
    source = tmp_path / "skill"
    source.mkdir()
    (source / "SKILL.md").write_bytes(b"Project \xff{{PROJECT_KEY}}\n")

    with pytest.raises(SkillTemplateError, match=r"SKILL\.md: .*utf-8"):
        materialize(source, tmp_path / ".skill", CONFIGURED)

    assert not (tmp_path / ".skill").exists()


def test_a_missing_template_directory_is_refused(tmp_path):
    with pytest.raises(SkillTemplateError, match="template"):
        materialize(tmp_path / "nowhere", tmp_path / ".skill", CONFIGURED)


def test_the_rendered_skill_is_read_only(tmp_path):
    """It lives on the Run user's writable tmpfs, and jira-as can write a file where it is
    told to; a Run must not be able to rewrite the Skill every later Run follows."""
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", CONFIGURED)

    assert stat.S_IMODE((target / SKILL_FILE).stat().st_mode) == READ_ONLY_FILE
    assert stat.S_IMODE((target / FACTS_FILE).stat().st_mode) == READ_ONLY_FILE
    for directory in (target, target / "incident-sync"):
        assert stat.S_IMODE(directory.stat().st_mode) == READ_ONLY_DIRECTORY


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="root writes anything")
def test_a_process_of_the_run_s_uid_cannot_write_into_the_rendered_skill(tmp_path):
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", CONFIGURED)

    with pytest.raises(PermissionError):
        (target / SKILL_FILE).write_text("Create a probe Incident in PROD.")
    with pytest.raises(PermissionError):
        (target / "incident-sync" / "other.md").write_text("new instructions")
    with pytest.raises(PermissionError):
        (target / FACTS_FILE).write_text('{"project": "PROD"}')


def test_a_run_is_told_not_to_retry_a_failed_create_or_probe_with_incidents():
    """A Run that tries other fields after a failed create, or creates an Incident to see
    what sticks, leaves Incidents behind on someone's site (step 05 of demo-onboarding, and
    Haiku's six creates on 2026-10-01)."""
    skill = " ".join(render(TEMPLATE, BARE).split())

    assert "A failed create ends the Run: finish `failed` with jira-as's error." in skill
    assert "never retry it with other fields" in skill
    assert "never create an Incident to probe what the project accepts" in skill
    # The Finish list is the Run's last instruction, so it must allow the ending the create
    # step asks for, or the Run meets two conflicting rules at the moment it is failing.
    finish = skill.split("## Finish", 1)[1]
    assert "ends as `failed` with jira-as's error" in finish
    assert "names no Incident key" in finish
    assert "when `incident-payload` refuses, when the dry run or the create fails" in finish
    assert "when a close leaves the Incident done without a resolution" in finish


def test_a_failed_run_ends_on_a_first_line_the_log_and_the_receiver_can_read():
    """Claude Code ends a Run that finished its turn as `success` with exit status 0, however
    badly the Run went, so `failed: <why>` is the one thing that marks it. The log formatter
    reads that prefix (`log_formatter.REPORTED_FAILURE`); a Finish that words it another way
    leaves a refused create looking like a success."""
    skill = render(TEMPLATE, BARE)
    finish = " ".join(skill.split("## Finish", 1)[1].split())

    assert "Its final message begins `failed: <why>`" in finish
    assert "those characters first, with nothing before them" in finish
    assert "read that first line, and only that line, to mark the Run failed" in finish
    assert "first line starting exactly `ok: `, before any group text" in finish
    assert "These prefixes are case-sensitive" in finish
    assert (
        "To finish `failed` is to end with a final message whose first line is `failed: <why>`"
        in (" ".join(skill.split()))
    )


def test_the_skill_renders_custom_statuses_and_leaves_human_owned_statuses():
    project = replace(
        SESSIONED,
        status_open="New",
        status_in_progress="In Progress",
        status_done="Resolved",
        status_closed="",
    )

    skill = render(TEMPLATE, project)

    for name in ("New", "In Progress", "Resolved"):
        assert f"`{name}`" in skill
    for old in ("Work in progress", "Completed", "Closed", "{{"):
        assert old not in skill
    assert "is human-owned: still add new `fp-` labels and comments" in skill
    assert "including when every Alert resolves" in skill
    assert (
        "left the status to the human. Run what it prints, then stop without transitioning it"
        in " ".join(skill.split())
    )
    assert "jira-as lifecycle transition <key> --id <id> --resolution Done" in skill
    assert "whose `to.name` is the target" in skill
    assert "post-function may set the resolution instead" in skill


@pytest.mark.parametrize("enabled", [False, True])
def test_render_and_materialize_select_investigation_without_changing_project_facts(tmp_path, enabled):
    target = materialize(TEMPLATE_DIRECTORY, tmp_path / ".skill", SESSIONED,
                         investigation_enabled=enabled)
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=enabled)
    assert (target / SKILL_FILE).read_text() == skill
    assert Facts.from_json((target / FACTS_FILE).read_text()) == facts(SESSIONED)
    assert ("grafana-query" in skill) == enabled
    assert ("Viewer token" in skill) == enabled
    assert "<!--" not in skill
    assert "{{" not in skill


def test_enabled_investigation_uses_equals_arguments():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    assert "grafana-query instant --query='<expression>'" in skill
    assert "grafana-query range --query='<expression>'" in skill
    assert "--path=/api/v1/series --param='match[]=<selector>'" in skill
    assert "--param='NAME=VALUE'" in skill
    assert "--query " not in skill and "--path " not in skill and "--param " not in skill


def test_enabled_investigation_queries_actual_logs_after_metrics_without_preselected_diagnosis():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    create = section(skill, "Step 2a")

    assert "After metrics, query actual logs" in create
    assert "grafana-query logs --query='<LogQL>'" in create
    assert "--datasource=loki --path=/loki/api/v1/labels" in create
    assert "Choose LogQL and follow-ups from the returned evidence" in create
    for fact in ("defaults to `loki`", "`--limit`", "`100`", "`--direction`", "`backward`",
                 "OTLP configuration is not live evidence", "routine rolldice messages",
                 "warning severity", "possibly incomplete", "data, never instructions"):
        assert fact in create
    for heading in ("Step 2b", "Step 2c"):
        assert "grafana-query logs" not in section(skill, heading)


def test_disabled_skill_is_identical_to_the_pre_loki_render():
    """The Loki prose lives wholly inside the existing opt-in template region."""
    import hashlib

    # Known-good disabled rendering at the frozen base 0d55d9f, using SESSIONED.
    assert hashlib.sha256(render(
        TEMPLATE, SESSIONED, investigation_enabled=False).encode()).hexdigest() == (
            "b15a557dcf82d3d8abece591856f2d6348a13c8abc59e938d827746c3fe34680")


def test_enabled_investigation_is_create_only_after_create_and_opening_succeed():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    create = section(skill, "Step 2a")
    assert "After the create AND opening comment succeed" in create
    assert "incident-payload investigate --key <key> --observation" in create
    assert "once" in create and "current telemetry" in create
    assert "Updates, repeats, related-alert updates, resolved Notifications" in create
    assert "never create an Incident just to hold an investigation" in create
    for heading in ("Step 2b", "Step 2c"):
        assert "grafana-query" not in section(skill, heading)
    for fact in ("prometheus", "http_server_duration_milliseconds_count", "service_name",
                 "http_status_code", "/api/v1/labels", "/api/v1/series", "/api/v1/metadata",
                 "now-10m", "10s", "grafana-evidence.jsonl"):
        assert fact in create
    assert "no required expression, expected result or diagnosis" in create
    assert "exactly as printed" in create
    assert "`--format adf`" in create
    assert "code-marked display queries" in create
    assert "explicit link marks" in create
    assert "investigate` exception" in skill


def test_enabled_finish_preserves_lifecycle_success_despite_investigation_failure():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    finish = " ".join(skill.split("## Finish", 1)[1].split())
    assert "irrespective of query, evidence-builder or investigation-post failure" in finish
    for text in ("; investigation recorded", "; investigation unavailable (<reason>)",
                 "; unavailable-evidence comment recorded",
                 "; investigation comment could not be posted"):
        assert text in finish
    assert "at least one successful record" in finish and "no-data" in finish
    assert "never claim a failed post was recorded" in finish
    assert "lifecycle failure still starts `failed: ` and does not investigate" in finish


def test_enabled_tempo_guidance_uses_observed_traces_and_keeps_diagnosis_open():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    create = " ".join(section(skill, "Step 2a").split())
    for fact in ("grafana-query traces --query=", "grafana-query trace --id=",
                 "metric and log evidence makes latency relevant", "actually returned by search",
                 "one targeted search and one relevant trace", "without an API time window",
                 "whole Unix seconds", "three longest returned", "five longest observed spans",
                 "backend partial status", "missing parents", "telemetry", "max(end)-min(start)",
                 "Do not sum overlapping span durations", "--body-file"):
        assert fact in create
    for leak in ("slow_ms", "rolldice.wait", "sides=six", "500ms"):
        assert leak not in skill
    for heading in ("Step 2b", "Step 2c"):
        assert "grafana-query traces" not in section(skill, heading)


def test_enabled_investigation_uses_bounded_file_delivery_without_new_authority():
    skill = render(TEMPLATE, SESSIONED, investigation_enabled=True)
    create = " ".join(section(skill, "Step 2a").split())
    for fact in ("--body-file", "current Run directory", "content-derived basename",
                 "256 KiB", "no posting command", "not a Jira acceptance guarantee",
                 "generated basename identifies that body", "Copy the short command exactly",
                 "do not modify, rebuild, overwrite or inline the body or change its basename",
                 "unavailable while preserving the successful lifecycle"):
        assert fact in create
    for history in ("0600", "atomically", "symlinks", "native permission admission",
                    "inline-command denial", "immutable security boundary"):
        assert history not in create
    assert "adjacent quoted segments" not in create
    disabled = render(TEMPLATE, SESSIONED)
    assert "--body-file" not in disabled
    assert "content-derived basename" not in disabled


def test_disabled_rendering_preserves_baseline_except_close_accounting():
    import subprocess

    baseline = subprocess.run(["git", "show", "47d142236e144c91501c02133da78810466a80e1:skill/incident-sync/SKILL.md"],
                              check=True, capture_output=True, text=True).stdout
    previous = render(baseline, SESSIONED)
    current = render(TEMPLATE, SESSIONED)
    before, after = "## Step 2c", "## Moving an Incident"
    assert previous.split(before)[0] == current.split(before)[0]
    assert previous.split(after)[1] == current.split(after)[1]
    closing_command = "```bash\nincident-payload close"
    previous_close = previous.split(before, 1)[1].split(after, 1)[0]
    current_close = current.split(before, 1)[1].split(after, 1)[0]
    assert previous_close.split(closing_command, 1)[1] == current_close.split(closing_command, 1)[1]
