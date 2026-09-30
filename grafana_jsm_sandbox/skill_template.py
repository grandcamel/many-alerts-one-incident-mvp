"""The Run's Skill, rendered from the demo's project rather than edited by hand.

The Skill in this repo is a template. What differs between one Jira site and the
next, the project key, custom field ids and status roles, and between one take and the
next, the session label, is a `{{NAME}}` placeholder filled from `.env` through
`DemoProject`, so an engineer on another site never edits a tracked file and
never rebuilds the image to change a fact (the 2026-09-23 audit, F2 and F3). The
option values the Skill writes, `Sev-1` to `Sev-3`, `Critical` to `Medium` and
`Monitoring systems`, are the ITSM template's and stay in the Skill's own words;
only the ids that carry them are the site's.

The Receiver renders the template once at every start, into the runs directory,
which is a tmpfs in the container, so a Skill never outlives the configuration it
was rendered from. A field the project lacks is rendered as a field to leave off,
naming no id, because a Run shown a gap tends to go looking for something to fill
it with, and a Run that guesses a field id creates nothing.

Two functions do the work: `render`, which is pure and refuses a template that
names a placeholder it cannot fill, and `materialize`, which writes a whole
rendered skill directory where a Run will read it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from grafana_jsm_sandbox.demo_config import DEFAULT_SESSION_ID, DemoProject, session_label

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")
"""`{{NAME}}`, a spelling that appears nowhere else in the Skill: its JSON never opens two
braces in a row, so a stray `{{` can only be a placeholder gone wrong."""

OPENING = "{{"
"""The start of a placeholder, counted against `PLACEHOLDER`'s matches to catch a malformed one."""

RENDERED = ".md"
"""The suffix of the files that are templates. Anything else in the skill directory is copied
as it is."""

READ_ONLY_FILE = 0o444
"""The mode of every file in the rendered Skill, for the reason `READ_ONLY_DIRECTORY` gives."""

READ_ONLY_DIRECTORY = 0o555
"""The mode of every directory in the rendered Skill, and why both are read-only. It lives on the runs directory's tmpfs, which the Run user may
write, where the template's own copy sat on a read-only root. jira-as, the one command a Run
may execute, can write a file where it is told to, such as a downloaded attachment, and without
these one Run could rewrite the Skill every later Run follows. A process of the owning uid could
chmod them back; jira-as has no way to."""


class SkillTemplateError(ValueError):
    """The template cannot become a Skill a Run could follow, and says why."""


@dataclass(frozen=True)
class Field:
    """One of the project's custom fields, as the Skill names it and writes it."""

    placeholder: str
    attribute: str
    name: str
    values: str
    example: str


FIELDS = (
    Field(
        "SEVERITY_FIELD", "severity_field", "Severity", "one of `Sev-1`, `Sev-2`, `Sev-3`", "Sev-1"
    ),
    Field(
        "URGENCY_FIELD",
        "urgency_field",
        "Urgency",
        "one of `Critical`, `High`, `Medium`",
        "Critical",
    ),
    Field(
        "SOURCE_FIELD",
        "source_field",
        "Source",
        "always `Monitoring systems`",
        "Monitoring systems",
    ),
)
"""The fields a Run sets on create, in the order the create command sets them. The example is
the value the Skill's one example command writes, which is a critical Alert's."""

MAJOR_INCIDENT_ATTRIBUTE = "major_incident_field"
"""The field a Run is told never to touch, and so the one it is never given an example for."""

DESCRIPTION = '"description": <description>'
"""The last member of the create command's custom fields, which the Skill fills from its ADF
template. It is always there: the Description is a system field every project has."""

SESSION_PLACEHOLDER = "SESSION_LABEL"
"""The Jira label every Incident of one demo session carries, `ses-<DEMO_SESSION_ID>`, so a
rehearsal's Incidents never match the real demo's. The Receiver supplies it from `.env`."""

SESSION_LABEL = re.compile(r"ses-[a-z0-9-]{1,32}")
"""The shape of a session label: the prefix and `DEMO_SESSION_ID`'s own alphabet."""

DEFAULT_SESSION_LABEL = session_label(DEFAULT_SESSION_ID)
"""The session label while `DEMO_SESSION_ID` is not set: every Run then shares one session,
which is chapter one's behaviour and never a label a Run cannot search."""


def placeholders(project: DemoProject) -> dict[str, str]:
    """Every placeholder the Skill may name, and what it becomes for this project."""
    filled = {
        "PROJECT_KEY": project.key,
        SESSION_PLACEHOLDER: project.session_label,
        "STATUS_OPEN": project.status_open,
        "STATUS_IN_PROGRESS": project.status_in_progress,
        "STATUS_DONE": project.status_done,
    }
    custom_fields = []
    for field in FIELDS:
        field_id = getattr(project, field.attribute)
        if field_id:
            filled[field.placeholder] = f"`{field_id}`, {field.values}"
            custom_fields.append(f"{json.dumps(field_id)}: {json.dumps({'value': field.example})}")
        else:
            filled[field.placeholder] = f"none on this project, so leave {field.name} off"
    filled["CUSTOM_FIELDS"] = "{" + ", ".join([*custom_fields, DESCRIPTION]) + "}"
    major_incident = getattr(project, MAJOR_INCIDENT_ATTRIBUTE)
    filled["MAJOR_INCIDENT"] = (
        f"Major incident (`{major_incident}`)" if major_incident else "Major incident"
    )
    return filled


def render(template: str, project: DemoProject) -> str:
    """The Skill for `project`, or an error naming every placeholder it could not fill.

    A placeholder left in a rendered Skill would reach a Run as an instruction
    to use a project called `{{PROJECT_KEY}}`, so a template that names one this
    module does not know, spells one wrongly, or meets a project with no key is
    refused whole rather than rendered as far as it goes. So is a session label
    that is not one: a Run would write it onto every Incident and search by it.
    """
    if not SESSION_LABEL.fullmatch(project.session_label):
        raise SkillTemplateError(
            f"session label {project.session_label!r} is not ses-<id> with id of [a-z0-9-]{{1,32}}"
        )
    filled = placeholders(project)
    named = PLACEHOLDER.findall(template)
    unfilled = sorted({name for name in named if not filled.get(name)})
    malformed = template.count(OPENING) - len(named)
    failures = [f"{{{{{name}}}}} has no value" for name in unfilled]
    if malformed:
        failures.append(f"{malformed} `{OPENING}` open no placeholder of the form {{{{NAME}}}}")
    if failures:
        raise SkillTemplateError("; ".join(failures))
    return PLACEHOLDER.sub(lambda placeholder: filled[placeholder[1]], template)


def materialize(source: Path, target: Path, project: DemoProject) -> Path:
    """Write the whole skill directory `source`, rendered for `project`, as `target`.

    Whatever was at `target` goes first: a Skill rendered by an earlier start,
    from another `.env`, must not survive into this one, which matters on a
    laptop, where the runs directory is an ordinary directory rather than a
    tmpfs. Everything is then rendered before anything is written, so a template
    that cannot be filled leaves no Skill at all rather than half of one. The
    result is made read-only (`READ_ONLY_FILE`). Returns `target`.
    """
    source, target = Path(source), Path(target)
    if not source.is_dir():
        raise SkillTemplateError(f"{source} is not a directory holding the Skill's template")
    _remove(target)
    contents: dict[Path, bytes] = {}
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if path.suffix == RENDERED:
            try:
                rendered = render(path.read_text(encoding="utf-8"), project)
            except (SkillTemplateError, UnicodeDecodeError) as failure:
                raise SkillTemplateError(f"{relative}: {failure}") from None
            contents[relative] = rendered.encode("utf-8")
        else:
            contents[relative] = path.read_bytes()
    target.mkdir(parents=True)
    for relative, content in contents.items():
        written = target / relative
        written.parent.mkdir(parents=True, exist_ok=True)
        written.write_bytes(content)
        written.chmod(READ_ONLY_FILE)
    for directory, _, _ in os.walk(target):
        os.chmod(directory, READ_ONLY_DIRECTORY)
    return target


def _remove(target: Path) -> None:
    """Remove an earlier rendering, whose directories were left without a write bit."""
    if target.is_symlink() or target.is_file():
        target.unlink()
        return
    if not target.exists():
        return
    for directory, _, _ in os.walk(target):
        os.chmod(directory, stat.S_IRWXU)
    shutil.rmtree(target)
