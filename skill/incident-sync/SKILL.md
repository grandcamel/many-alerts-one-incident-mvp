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

You can run `jira-as` and `incident-payload`, and read files. Nothing else — no
writing files, no `curl`, no `date`, no other command. Every invocation below is
one you can run as written.

## You decide; `incident-payload` writes the payloads

You make every judgment here: whether there is a Match, and whether to create,
update, close or skip. You never build a Jira payload by hand. `incident-payload`
reads `notification.json` and this project's facts itself, and prints the
`jira-as` lines for the step you name, each one complete:

- Run every printed line that starts with `jira-as`, in the order printed,
  exactly as printed. Change nothing in it except a literal `<key>`, which you
  replace with the Incident's key.
- A printed line that starts with `#` says what the next one does, or what to say
  when you finish. It is not a command.
- If it prints a line starting `incident-payload: error:`, stop there and finish
  `failed` with that line. Never build the command yourself instead.
- To finish `failed` is to end with a final message whose first line is `failed: <why>`;
  the [Finish](#finish) says how, and why it must be that line.

**Every command is one line, in plain single quotes.** The permission boundary
denies a whole command that is split across lines with `\`, that carries a newline
inside an argument, or that uses `$'...'` — it will not match the allow list however
harmless it looks. The lines below and the lines `incident-payload` prints are
already like that. Where you copy a value from jira-as's output into an argument,
such as `--labels` or `--created`, put it in plain single quotes.
`incident-payload` writes every `'` from alert text as `’` (U+2019); never use `'\''` or `$'…'`.

**Read Jira narrowly.** Every JQL query names the project, `project = {{PROJECT_KEY}}`,
as the Match search does. An Incident whose key you know is never looked up with
JQL: read it with `issue get` and an explicit `--fields` list, the one the step
names. Never read a whole issue without `--fields`: on a real site that is tens of
kilobytes of fields no step needs.

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
session's label. Ask for its search:

```bash
incident-payload match
```

It prints one search, which is always this one with the group's label filled in.
Run the line it printed:

```bash
jira-as search jql 'project = {{PROJECT_KEY}} AND issuetype = Incident AND labels = "grp-<incident_group>" AND labels = "{{SESSION_LABEL}}" AND statusCategory != Done' --fields key,status,labels,created -o json
```

An empty `issues` array means there is no Match. Otherwise the one issue in it
is the Match: its `key`; its `fields.status.name`, which the next step branches
on; its `fields.labels`, which say what the Incident has already seen; and its
`fields.created`, which an update and a close need. A {{STATUS_DONE}} Incident is
deliberately not a Match: a group that fires again after its Incident was
completed gets a new Incident. Should the search ever find more than one issue —
it should not, Runs happen one at a time — take the one with the lowest number as
the Match, never create another, never close either, and say in the finish that a
duplicate exists.

The Notification's Alerts sort against the Match. An Alert whose
`fp-<fingerprint>` label is already on the Match is a **repeat**; one whose
label is not there yet is **new**; and a `resolved` Alert is **resolved**,
whichever of those it would otherwise be. With no Match every firing Alert is new.
`incident-payload update` and `close` sort them this way and print the result.

Then act on what you found:

| Notification | Match | What you do |
| --- | --- | --- |
| `firing` | none | [Create](#step-2a--create-the-incident) the one Incident |
| `firing` | `{{STATUS_OPEN}}` | [Update](#step-2b--update-the-incident) it, then move it to `{{STATUS_IN_PROGRESS}}` |
| `firing` | `{{STATUS_IN_PROGRESS}}` | [Update](#step-2b--update-the-incident) it and nothing else |
| `firing` | any other status | [Update](#step-2b--update-the-incident) labels and comment; leave the status to the human |
| `resolved` | `{{STATUS_OPEN}}` or `{{STATUS_IN_PROGRESS}}` | [Close](#step-2c--close-the-incident) it |
| `resolved` | any other status | [Close](#step-2c--close-the-incident) with `--leave-status`: add new `fp-` labels and comment that every Alert resolved and the status was left to the human; do not transition |
| `resolved` | none | Do nothing. Say you skipped it and why: every Alert is resolved and no open Incident carries the group and session labels |

## Step 2a — create the Incident

First the component. When every firing Alert carries the same `service` label,
check whether a component of that exact name exists on {{PROJECT_KEY}}:

```bash
jira-as -o json api call getProjectComponents --projectIdOrKey {{PROJECT_KEY}}
```

If it is there, name it. If it is not, or the firing Alerts carry different
services, leave the component off entirely: an unknown service must not fail the
create.

```bash
incident-payload create --component '<service>'
```

Without the component, that is `incident-payload create`. It prints three
commands, in this order:

1. **The dry run**: the create with `--dry-run`, which sends nothing to Jira and
   prints the payload it would send. Run it. It must succeed, and its
   `fields.description` must be a document whose `content` holds a `bulletList`
   with one `listItem` per firing Alert. If the dry run fails, or its
   `description` holds the JSON as text instead, finish `failed`.
2. **The create**: the same command without `--dry-run`. Run it **exactly once**.
   It prints the new Incident's key.
3. **The opening comment**, with `<key>`: put that key in its place and run it.

A failed create ends the Run: finish `failed` with jira-as's error. Never run the
create a second time, never retry it with other fields, never edit the Description
afterwards, and never create an Incident to probe what the project accepts. The
Incident is created in `{{STATUS_OPEN}}`; do not transition it on the first Firing.

What `incident-payload` fills in, so you can read the dry run against it:

- **Summary** — the `incident_group` label, then `: `, then how many Alerts are
  firing, as `<n> alerts firing`, then ` on ` and the `service` label when every
  firing Alert carries the same one. So `checkout-outage: 3 alerts firing on rolldice`.
- **Description** — a short partial Report, `Partial Report: <n> alerts firing in
  group <incident_group>.`, then one bullet per firing Alert, in the order the
  Notification lists them: its name, its instance, its `summary` annotation, its
  value and when it started, and its `generatorURL`.
- **Severity** — the worst across the firing Alerts' `severity` labels: any
  `critical` → `Sev-1`, otherwise any `warning` → `Sev-2`, otherwise `Sev-3`.
- **Urgency** — follows Severity: `Sev-1` → `Critical`, `Sev-2` → `High`,
  `Sev-3` → `Medium`.
- **Source** — `Monitoring systems`.
- **Labels** — `grp-<incident_group>`, `{{SESSION_LABEL}}`, and `fp-<fingerprint>`
  for every Alert in the Notification, resolved ones included. No other label.

It sets exactly the fields [the project](#the-project) gives an id for. A field it
says this project lacks stays off: never look for its id, never guess one.

## Step 2b — update the Incident

Read Jira's clock:

```bash
jira-as -o json api call getServerInfo
```

How long the Incident has been open is that `serverTime` minus the Match's own
`fields.created`, from the search. Both come off Jira, never off the Alert:
Grafana's clock and Jira's are not the same clock, and a Notification replayed
from a fixture can carry a `startsAt` that has not happened yet. Give
`incident-payload` the Match's key, its `fields.labels` joined with commas, its
`fields.created` and the `serverTime`, each copied as jira-as printed it:

```bash
incident-payload update --key <key> --labels '<label>,<label>' --created '<created>' --server-time '<serverTime>'
```

It prints, in order, the label add for every Alert whose `fp-` label the Match
lacks, or a line saying none is needed, and then the one update comment, which
says which Alerts are new, which repeat and which resolved, their values, and how
long the Incident has been open. Run both. Post that one comment and no other.

The label add is an `api call editIssue` with an `update.labels` add, which adds
to the labels and changes nothing else. It prints `null` on success; do not
re-check or retry it. Never use
`jira-as issue update --labels` for this: it replaces the whole label set, and
would take the group and session labels off the Incident.

If the Match is in `{{STATUS_OPEN}}`, move it on after commenting — see
[transitions](#moving-an-incident). If it is already in `{{STATUS_IN_PROGRESS}}`, stop
here: a repeat is idempotent apart from its comment. In any other status, also
stop after adding labels and commenting: a human owns the status.

## Step 2c — close the Incident

Every Alert in the Notification is resolved. Read Jira's clock as in
[step 2b](#step-2b--update-the-incident), and count the Runs so far: one per
comment on the Incident, the opening one included. The count is the `total` of
the comment list, so ask for one comment: only the `total` matters, and each
comment is long.

```bash
jira-as -o json api call getServerInfo
jira-as collaborate comment list <key> --limit 1 -o json
```

Then give `incident-payload` what step 2b does, and that `total` as the count:

```bash
incident-payload close --key <key> --labels '<label>,<label>' --created '<created>' --server-time '<serverTime>' --runs <count>
```

It prints the label add for any Alert whose `fp-` label the Match lacks, because an
Incident keeps the label of every Alert it ever saw, and then the closing comment,
which counts this Run as one more.

If the Match is in any status other than `{{STATUS_OPEN}}` or
`{{STATUS_IN_PROGRESS}}`, add `--leave-status`: the comment it prints then says
that every Alert resolved and that you left the status to the human. Run what it
prints, then stop without transitioning it.

Otherwise run what it prints, and then move the Incident to `{{STATUS_DONE}}`
**with a resolution**, using the id of the transition whose `to.name` is
`{{STATUS_DONE}}`:

```bash
jira-as lifecycle transitions <key> -o json
jira-as lifecycle transition <key> --id <id> --resolution Done
```

Without the resolution the Incident stays in the Incidents queue forever, because
that queue is `resolution = Unresolved`. This is the one place a resolution is set.
jira-as 2.0.0 retries without `--resolution Done` when a transition screen rejects
it; a workflow post-function may set the resolution instead. So read what the
Incident ended as:

```bash
jira-as issue get <key> --fields status,resolution -o json
```

If its `fields.status.name` is `{{STATUS_DONE}}` and its `fields.resolution` is
null, finish `failed`: the Incident is done without a resolution, and will stay in
the queue. Do not transition it again.

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
`resolved`. `incident-payload update` and `close` print both as `#` lines; after a
create every firing Alert is `new` and every other one `resolved`.

A Run that failed ends differently. Its final message begins `failed: <why>`: those
characters first, with nothing before them, then jira-as's or `incident-payload`'s
error as the why. The Receiver and the log read that first line, and only that
line, to mark the Run failed; a Run that ends any other way is counted a success,
whatever the Incident holds.

A Run ends as `failed` with the error when `incident-payload` refuses, when the dry
run or the create fails (the Forwarder's refusal of a create included), or when a
close leaves the Incident done without a resolution. A Run whose create failed ends
as `failed` with jira-as's error, and names no Incident key because there is none;
after a close that left no resolution, the Incident's own Finish line follows the
`failed:` line. Nothing else after those lines.
