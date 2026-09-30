---
name: incident-sync
description: Turn one Grafana Notification for a group of related Alerts into activity on that group's one Incident in the Jira {{PROJECT_KEY}} project.
---

# One group, one Incident

Read `notification.json` in your working directory. It is one Notification for
one **group** of related Alerts: `groupLabels.incident_group` names the group,
and every Alert in it carries that `incident_group` label. Handle the
Notification **as a whole**. A group has at most one open Incident: this Run
creates it when there is none and updates it when there is one. It never
creates one Incident per Alert, and it never creates a second one for a group
that already has one open.

An Alert is `firing` or `resolved`, and its `fingerprint` is its identity across
every Notification it ever appears in. The Notification's own `status` is
`firing` while any Alert in it fires, and `resolved` once every one of them has.

You can run `jira-as` and read files. Nothing else — no writing files, no `curl`,
no `date`, no other command. Every invocation below is one you can run as written.

**Write each `jira-as` invocation on a single line, in plain single quotes.** The
permission boundary denies a whole command that is split across lines with `\`,
that carries a newline inside an argument, or that uses `$'...'` — it will not
match the allow list however harmless it looks. Nothing you need has a newline in
it: the one field that wants paragraphs is the Description, and it gets them from
the ADF form below instead.
Write every `'` from alert text as `’` (U+2019); never use `'\''` or `$'…'`.

## The project

| Fact | Value |
| --- | --- |
| Project | `{{PROJECT_KEY}}` |
| Issue type | `Incident` |
| Group label | `grp-<incident_group>` — the `incident_group` label, lower-case, `[a-z0-9-]` only |
| Session label | `{{SESSION_LABEL}}` — on every Incident this demo session creates, so a rehearsal never matches the real demo |
| Fingerprint labels | `fp-<fingerprint>` — one per Alert the Incident has ever seen, added and never removed |
| Severity field | {{SEVERITY_FIELD}} |
| Urgency field | {{URGENCY_FIELD}} |
| Source field | {{SOURCE_FIELD}} |

The group and session labels together identify an Incident; the Fingerprint
labels record which Alerts it explains. Never remove a label.

Never set `Sev-0`. Never touch {{MAJOR_INCIDENT}}. A Run never moves an
Incident into any status other than `{{STATUS_IN_PROGRESS}}` and `{{STATUS_DONE}}`.
An open Match in any status other than `{{STATUS_OPEN}}` or
`{{STATUS_IN_PROGRESS}}` is human-owned: still add new `fp-` labels and comments,
but leave its status to the human, including when every Alert resolves.

## Step 1 — find the Match

The Match is the one open Incident carrying this group's label and this
session's label:

```bash
jira-as search jql 'project = {{PROJECT_KEY}} AND issuetype = Incident AND labels = "grp-<incident_group>" AND labels = "{{SESSION_LABEL}}" AND statusCategory != Done' --fields key,status,labels -o json
```

An empty `issues` array means there is no Match. Otherwise the one issue in it
is the Match: its `key`, its `fields.status.name`, which the next step branches
on, and its `fields.labels`, which say what the Incident has already seen. A
{{STATUS_DONE}} Incident is deliberately not a Match: a group that fires again after
its Incident was completed gets a new Incident. Should the search ever find more
than one issue — it should not, Runs happen one at a time — take the one with
the lowest number as the Match, never create another, never close either, and
say in the finish that a duplicate exists.

Then sort the Notification's Alerts against the Match. An Alert whose
`fp-<fingerprint>` label is already on the Match is a **repeat**; one whose
label is not there yet is **new**; and a `resolved` Alert is **resolved**,
whichever of those it would otherwise be. With no Match every firing Alert is new.

Then act on what you found:

| Notification | Match | What you do |
| --- | --- | --- |
| `firing` | none | [Create](#step-2a--create-the-incident) the one Incident |
| `firing` | `{{STATUS_OPEN}}` | [Update](#step-2b--update-the-incident) it, then move it to `{{STATUS_IN_PROGRESS}}` |
| `firing` | `{{STATUS_IN_PROGRESS}}` | [Update](#step-2b--update-the-incident) it and nothing else |
| `firing` | any other status | [Update](#step-2b--update-the-incident) labels and comment; leave the status to the human |
| `resolved` | `{{STATUS_OPEN}}` or `{{STATUS_IN_PROGRESS}}` | [Close](#step-2c--close-the-incident) it |
| `resolved` | any other status | Add new `fp-` labels and comment that every Alert resolved and the status was left to the human; do not transition |
| `resolved` | none | Do nothing. Say you skipped it and why: every Alert is resolved and no open Incident carries the group and session labels |

## Step 2a — create the Incident

Map the group onto the fields:

- **Summary** — the `incident_group` label, then `: `, then how many Alerts are
  firing, as `<n> alerts firing`, then ` on ` and the `service` label when every
  firing Alert carries the same one. So `checkout-outage: 3 alerts firing on rolldice`.
- **Description** — a short partial Report of every firing Alert: its name, its
  instance, its `summary` annotation, its value and when it started, and its
  `generatorURL`. Written as ADF, because that is the only way to get separate
  lines out of a command that cannot contain one. See
  [the template](#the-description) below.
- **Severity** — the worst across the firing Alerts' `severity` labels: any
  `critical` → `Sev-1`, otherwise any `warning` → `Sev-2`, otherwise `Sev-3`.
- **Urgency** — follows Severity: `Sev-1` → `Critical`, `Sev-2` → `High`,
  `Sev-3` → `Medium`.
- **Component** — the `service` label, but only if every firing Alert carries
  the same one and a component of that exact name already exists on
  {{PROJECT_KEY}}. Check with
  `jira-as -o json api call getProjectComponents --projectIdOrKey {{PROJECT_KEY}}`. If it is
  not there, leave the component off entirely. An unknown service must not fail
  the create.
- **Labels** — `grp-<incident_group>`, `{{SESSION_LABEL}}`, and `fp-<fingerprint>`
  for every Alert in the Notification, resolved ones included. No other label.

```bash
jira-as issue create -p {{PROJECT_KEY}} -t Incident -s '<summary>' --labels 'grp-<incident_group>,{{SESSION_LABEL}},fp-<fingerprint>,fp-<fingerprint>' --custom-fields '{{CUSTOM_FIELDS}}'
```

The labels are one comma-separated list, one `fp-` entry per Alert. That sets
exactly the fields [the project](#the-project) gives an id for. A field it says
this project lacks stays off: never look for its id, never guess one.

Add `--components '<service>'` only when that component exists. The Incident is
created in `{{STATUS_OPEN}}`; do not transition it on the first Firing.

If the create fails, do not retry it with other fields, and never create an
Incident to probe what the project accepts: finish as `failed`, with jira-as's
error.

Then record what it opened from, so the next Run can compare against it:

```bash
jira-as collaborate comment add <key> -b 'Opened from <n> firing Alerts in <incident_group>: <alertname> value=<current>; <alertname> value=<current>.'
```

One `<alertname> value=<current>` per firing Alert, separated by `; `.
`<current>` is that Alert's `values.A`.

### The description

The Description goes in under `--custom-fields` with the other fields, as one
line of ADF JSON — `issue create` has no `--description` that understands
paragraphs, and a command may not contain a newline. Fill in the placeholders,
repeat the `listItem` once per firing Alert in the order the Notification lists
them, change nothing else, and paste it in place of `<description>` above,
unquoted, as a JSON value among the others:

```json
{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":"Partial Report: <n> alerts firing in group <incident_group>."}]},{"type":"bulletList","content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"<alertname> on <instance>: <summary annotation>. value=<current>, since <startsAt>. <generatorURL>"}]}]}]}]}
```

`<startsAt>` is the Alert's own `startsAt`, copied as written: it is a fact about
the Alert, not a duration, so Grafana's clock is fine here.

## Step 2b — update the Incident

First give the Match the labels of the new Alerts, one `{"add":…}` per new
Alert, all in one command. Skip this command entirely when no Alert is new:

```bash
jira-as api call editIssue --issue-id-or-key <key> --field 'update.labels=[{"add":"fp-<fingerprint>"},{"add":"fp-<fingerprint>"}]'
```

That adds to the labels and changes nothing else. Never use
`jira-as issue update --labels` for this: it replaces the whole label set, and
would take the group and session labels off the Incident.
`jira-as api call editIssue` prints `null` on success; do not re-check or retry it.

Then read how long the Incident has been open: the Jira clock now, minus the
Incident's own `created`. Read both off Jira, never off the Alert — Grafana's
clock and Jira's are not the same clock, and a Notification replayed from a
fixture can carry a `startsAt` that has not happened yet:

```bash
jira-as -o json api call getServerInfo
jira-as issue get <key> -o json
```

`serverTime` from the first, `created` from the second. Write the difference like
`4m30s`. That is the only clock you can reach, so use it for every duration.

Then post one comment and no more than one, in exactly this shape, so the next
Run and the audience can read which Alerts are new and which repeat:

```bash
jira-as collaborate comment add <key> -b 'Update: <n> firing. New: <alertname> (fp-<fingerprint>) value=<current>; <alertname> (fp-<fingerprint>) value=<current>. Repeat: <alertname> value=<current>; <alertname> value=<current>. Resolved: <alertname>. Open for <duration>.'
```

Each of `New`, `Repeat` and `Resolved` lists its Alerts separated by `; `, and
reads `none` when there is no such Alert. `<current>` is that Alert's `values.A`.

If the Match is in `{{STATUS_OPEN}}`, move it on after commenting — see
[transitions](#moving-an-incident). If it is already in `{{STATUS_IN_PROGRESS}}`, stop
here: a repeat is idempotent apart from its comment. In any other status, also
stop after adding labels and commenting: a human owns the status.

## Step 2c — close the Incident

Every Alert in the Notification is resolved. If any of them has no `fp-` label on
the Match yet, add it first, exactly as in [step 2b](#step-2b--update-the-incident):
an Incident keeps the label of every Alert it ever saw. Count the Runs: one per
comment on the Incident, the opening one included, read with
`jira-as collaborate comment list <key> -o json`. The duration is the Jira
clock now minus the Incident's `created`, read the same way as in step 2b.

If the Match is in any status other than `{{STATUS_OPEN}}` or
`{{STATUS_IN_PROGRESS}}`, comment that every Alert resolved and that you
left the status to the human, then stop without transitioning it.

Otherwise post the closing comment:

```bash
jira-as collaborate comment add <key> -b 'Resolved after <duration>: every Alert in <incident_group> is resolved (<n> Alerts, <m> Runs). {{STATUS_DONE}} automatically from the Grafana Notification.'
```

Then move it to `{{STATUS_DONE}}` **with a resolution**:

```bash
jira-as lifecycle transition <key> --id <id> --resolution Done
```

Without the resolution the Incident stays in the Incidents queue forever, because
that queue is `resolution = Unresolved`. This is the one place a resolution is set.
jira-as 2.0.0 retries without `--resolution Done` when a transition screen rejects
it; a workflow post-function may set the resolution instead.

## Moving an Incident

To pick a transition, never pass `--to`. Read the transitions off the issue itself
and use the id of the one whose `to.name` is the target, `{{STATUS_IN_PROGRESS}}` on the first update
or `{{STATUS_DONE}}` when every Alert resolves:

```bash
jira-as lifecycle transitions <key> -o json
jira-as lifecycle transition <key> --id <id>
```

Read them every time. An id that was right last week is not a fact about this issue.

## Finish

End with one line for the Incident, naming the group, the Incident key and what
changed — `created`, `updated` with how many labels were added, `updated and
moved to {{STATUS_IN_PROGRESS}}`, `completed`, or `skipped` and why — and then one line
per Alert, naming its Fingerprint and whether it was `new`, `repeat` or
`resolved`. A Run whose create failed ends as `failed` with jira-as's error, and
names no Incident key because there is none. Nothing else after those lines.
