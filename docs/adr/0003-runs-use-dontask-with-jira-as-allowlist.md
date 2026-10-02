# Runs use `--permission-mode dontAsk` with an allow list, not skip-permissions

Every existing wrapper on this machine launches headless Claude with `--dangerously-skip-permissions`. We deliberately do not. A Run initially started with `--permission-mode dontAsk` and `--allowedTools "Bash(jira-as *)" "Read"`, so any tool call outside that list was denied without a prompt and surfaced as a `permission_denied` event in the stream-json output. The amendments below describe the scoped Read rule, local payload command and optional Grafana query command now available to a Run.

## Consequences

- The purpose-built Skill describes operations using the allowed commands: `jira-as`, `incident-payload` and, only when investigation is enabled, `grafana-query`.
- The log formatter prints denials, so a misbehaving prompt is visible rather than silent.

## Amendments

**2026-09-23, from the `/proc` probe (demo-onboarding step 01).** The bare `Read` on the allow list is replaced by `Read` scoped to two absolute directories: `Read(//<runs directory>/**)`, which holds each Run's working directory and its Notification, and `Read(//<skill directory>/**)` until the Skill is rendered under the runs directory. A leading `//` is Claude Code's form for an absolute path. The probe (probe-2026-09-23.md), on Claude Code 2.1.272 in the hardened container, showed why: with the bare rule, a Run whose prompt asked for the Jira token read it from `/proc/1/task/1/environ`, the Receiver's environment, which the Run's uid could read. With the scoped rules that path, `/proc/self/root/...`, a `..` walk out of the runs directory and `/home/demo/.claude.json` were all denied by permission, while the Notification and the Skill stayed readable. The allow list is still two tools; `Read` now reaches only what a Run is meant to read. A permission rule covers Claude's own tools and not the files jira-as opens itself, so the Receiver is also non-dumpable (ADR 0002's amendment).

**2026-09-23, the project allow list (demo-onboarding step 02).** A Run's environment now also carries `JIRA_ALLOWED_PROJECTS` set to `DEMO_PROJECT_KEY`, the demo's dedicated project, which `.env` names and which has no default. jira-as 2.0.0 then refuses, before sending anything, a call that names any other project literally: a project argument, an issue key, a JQL `project` clause, or `api call deleteIssue --issueIdOrKey PROD-1` (checked offline against an unreachable site). The variable wins over a `.claude/settings.json`'s `allowed_projects` (jira_as/config_manager.py:211-216). This narrows what a Run's one allowed command can reach without adding a tool; it is jira-as's check of literal references, which by its own account neither evaluates JQL nor authorizes HTTP, so the allow list above and the Skill remain the boundary. One side effect: with it set, jira-as reads an `fp-` label made only of decimal digits as an issue key of project `FP` and refuses the search, which a Fingerprint with no letter a-f would trip.

**2026-09-23, the rendered Skill (demo-onboarding step 03).** The Skill is now rendered from `.env` at every Receiver start into `<runs directory>/.skill`, so the second rule above is gone: the allow list is exactly `Bash(jira-as *)` and `Read(//<runs directory>/**)`, and `--add-dir` names the rendered skill directory. Run ids are timestamps, so no Run's working directory can take the name. The runs directory is a writable tmpfs where the template sat on a read-only root, and jira-as can write a file where it is told to, so the rendering is left read-only: files `0444`, directories `0555`. That no single Run can rewrite the Skill every later Run follows rests on those modes, not on the permission rules. The probe covered a rule over the runs directory reading `./notification.json`; that it also covers the dot-named `.skill` beneath it follows from the rules' gitignore matching and awaits the live check.

**2026-09-23, the kept Transcript (demo-onboarding step 05).** Each Run's raw stream-json is now teed to `transcript.jsonl` in its own working directory, beside its Notification, so the rule above reaches it with no new rule and nothing outside the runs directory. A Run can therefore read its own Transcript and every earlier Run's still on the tmpfs. What those hold is what earlier Runs read through jira-as, said and were told: the Skill, Notifications, Jira data the account already reaches, and each Run's sentinel, which the Forwarder forgets when that Run ends (ADR 0002). The copy is raw by design, because it is what the trimmed and redacted log leaves out; the log itself is still redacted line by line as before. The files are not made read-only as the Skill is, so a Run could overwrite an earlier Transcript by a file jira-as writes where it is told to, as it could a Notification; the container log, not the file, stays the record of what a Run did.

**2026-10-01, a local payload tool (the demo-run findings).** The allow list gains exactly one rule, `Bash(incident-payload *)`, and is now `Bash(jira-as *)`, `Bash(incident-payload *)` and `Read(//<runs directory>/**)`. In three rehearsal takes the cheapest model wrote the Description's ADF by hand inside a shell argument, closed it with the wrong brace six times, and created its Incident with the Description `Test`; the Skill's "do not retry" was not enough to stop it. A Run cannot hand jira-as a newline, so a bulleted Description has to be ADF, and building ADF is not a judgment. `incident-payload` builds it, with the summary, labels, fields, comment text, the new, repeat and resolved sort and the duration, and prints `jira-as` lines the Run runs as written; the Run keeps every judgment, from the Match to whether to create, update, close or skip. It joins the list because it adds no reach: it is this package's own module, run by the image's Python from a launcher in `/usr/local/bin`, both on the container's read-only root; it reads only `notification.json` in its working directory and the project facts the Receiver renders beside the Skill (`<runs directory>/.skill/project.json`, read-only like the Skill, and holding nothing the Skill does not already show), never a path from its command line; and it opens no socket, starts no process, writes no file and reads no environment variable, so it never holds the sentinel and cannot reach Jira. A printed line still goes through `Bash(jira-as *)`, the project allow list and the Forwarder like any other. `doctor --with-model` now asks for one harmless call of each rule, `incident-payload --help` among them.

**2026-10-01, opt-in Grafana investigation.** Enabled Runs gain exactly
`Bash(grafana-query *)` after `Bash(incident-payload *)`. The scoped Read rule stays as it is
and already reaches `grafana-evidence.jsonl` in the Run's working directory. Disabled Runs
keep the existing command and environment; both Skill renderings count only lifecycle
comments at close, excluding bodies beginning with the exact `[grafana-investigation] ` marker
after checking the raw list is complete. This marker is an accounting convention, not author
authentication. No Python, curl or general-purpose shell permission is added.

A Run has its model credential and, when enabled, a Grafana Viewer credential. Jira still
uses the Forwarder's sentinel. `grafana-query` authenticates datasource-proxy GETs with the
Viewer token and bypasses the Jira Forwarder. Arbitrary PromQL and discovery GETs are allowed;
there is no query allow list, attempt budget, retry policy, response-size limit, sample cap or
observation-window cap. The ten-second per-request elapsed timeout and compact Transcript
summary are usability measures; the existing Run timeout still applies. Grafana still permits
anonymous Admin, and presenter links open under the presenter's browser identity.

Only a successful create and opening comment are followed by investigation. The Run chooses
queries and judgments; `incident-payload investigate --key KEY --observation TEXT --interpretation
TEXT --unknown TEXT` also reads the fixed evidence file and prints one Jira comment command,
which the Run posts through its existing Jira path. It opens no socket and writes nothing.
An investigation query, evidence-builder or post failure preserves a successful lifecycle's
`ok: ` Finish. Disabled Skill rendering adds no investigation tool, query instructions or
token facts; its close-count correction still applies when a prior marked comment remains.

**2026-10-02, bounded investigation body files.** Investigation delivery amends the
payload tool's earlier no-file-write contract. Every `incident-payload investigate`
invocation serializes its ADF once as UTF-8 and publishes a body file under the
current Run directory, with a generated content-derived basename and no caller-supplied
output path. Publication is atomic with mode `0600`; an existing destination is reused
only when it is a regular non-symlink file containing identical bytes. Unsafe or
conflicting destinations and file failures are refused, temporary cleanup is attempted,
and no posting command is printed on write or cleanup failure. The local artifact cap is 256 KiB,
which bounds this writer and is not a Jira body-size or acceptance guarantee.

The helper prints the short command `jira-as collaborate comment add KEY --body-file
BASENAME --format adf`; jira-as reads the UTF-8 body and posts through the same project
allowlist and Forwarder. No permission rules, credential access, sockets, subprocesses
or Forwarder authority are added. All other payload steps retain their previous
outputs and filesystem behavior. Raw Grafana evidence and disclosed display
transformations are preserved. File publication or posting failure remains secondary
to a successful Incident lifecycle.

The digest basename binds a printed command to its generated body across later
helper invocations; it is provenance, not an immutable security boundary. The file
remains mutable under the Run's existing filesystem authority. This interface avoids
embedding the body in shell syntax. It does not establish why native Claude denied
the captured valid inline command: native permission admission and exact live posted
body read-back remain separate acceptance checks.
