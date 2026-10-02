---
name: demo-setup
description: Set up and rehearse this repo's basic demo (a Grafana alert becomes a Jira Service Management Incident) on the engineer's own Atlassian site, running every step from host check to verified lifecycle, reset and hand-off. Use when asked to set up the demo, run or rehearse the demo, put the demo on my Jira, or act on configure, doctor, verify or reset output. It is not the Run's Skill in skill/incident-sync/SKILL.md, which it never edits.
---

# Demo setup

You take an engineer from a fresh clone of this repo to one verified Incident lifecycle on a
Jira Service Management project of their own, and a clean reset after it. You run every command
yourself, from the repo root, in the order below. The scope is chapter one, the basic demo, on
Docker Compose on the engineer's laptop: Kubernetes, kind and chapter two are not needed
(README, "What the basic demo uses and what to ignore").

## Ground rules

- **The engineer's hands.** Hand over, and wait, for exactly these: creating tokens and typing
  them into `.env` in their own editor, running `claude setup-token` in their own terminal
  if they choose OAuth, sending admin requests, and the optional `rolldice` component. Everything else is yours.
- **`.env` is the engineer's.** It holds their real tokens, and the repo's
  `.claude/settings.json` denies Read and Edit of it. The only commands of yours that name it
  are `ls .env` and `cp .env.example .env`; its contents reach you only through `doctor`'s `env`
  layer and `configure`'s `.env:` lines, and they change only by the engineer's editor or by
  `configure --write` once the engineer has said yes. Secrets stay out of the chat: if the
  engineer pastes one, do not repeat it, and suggest they rotate it.
- **Consent before every Jira write or spend.** `configure` and `doctor` only read. Each run of
  `verify` (its Runs create, comment on and complete an Incident), each real `reset`, and
  `doctor --with-model` (it spends Claude usage) waits for a clear yes in chat to that command.
  One yes covers one run.
- **Act on the named blocker.** Every command ends on a verdict line (`READY`, `NOT READY: ...`,
  `VERIFIED`, `NOT VERIFIED: ...`, `queue is empty`) and names its first blocker with its fix or
  an admin request. Do that fix, or show that request, then rerun the same command. A rerun with
  nothing changed is only for the waits this skill names. Read
  [READING-OUTPUT.md](READING-OUTPUT.md) the first time a command ends anything but its done
  line, or exits nonzero.
- **This skill is not the Run's Skill.** `skill/incident-sync/SKILL.md` is the template the
  Receiver renders for each Run inside the container. Leave it as it is; the project's facts
  reach it through `.env` and `configure --write` alone.
- **Your shell forgets.** An `export` or `source` in one command is gone by the next. Every
  prefix this skill sets up (a virtualenv's Python or PATH in stage 2, the corporate CA in
  stage 3) is written in front of each command it applies to, every time.
- **A blocked command is the engineer's to allow.** In auto mode, Claude Code may refuse a
  command because it reaches the engineer's Jira with their credential. The 2026-09-24
  rehearsal saw this happen to a read-only `reset --dry-run`. Never route around a refusal with
  another command or tool. Name the blocked command and say why this stage needs it, then offer
  two ways on:
  - They approve it when prompted.
  - They add allow rules for the read-only commands to their own git-ignored
    `settings.local.json`, beside the repo's `.claude/settings.json`:
    `Bash(python3 -m grafana_jsm_sandbox.doctor *)`,
    `Bash(python3 -m grafana_jsm_sandbox.configure *)` and
    `Bash(python3 -m grafana_jsm_sandbox.reset --dry-run)`.

  Leave `verify` and the real `reset` without allow rules, so that each Jira write also stops at
  a permission prompt.
- **Tell the engineer where you are** in one line at the start of each stage.

## Resuming

Before stage 1, run `ls .env`. When it finds the file (the engineer asked to run the demo, or
a second session picks up), set up the prefixes an earlier session used before running
anything else:

```bash
ls .venv/bin/python certs/
```

A `.venv/bin/python` is stage 2's virtualenv: use it for `python3`. A file in `certs/` other
than `NO_EXTRA_CERTS` is a corporate CA: ask the engineer whether this laptop is behind an
intercepting proxy, and on yes carry stage 3's prefixes. Then run the whole preflight once:

```bash
python3 -m grafana_jsm_sandbox.doctor
```

Then start at the stage for the layer of its first blocker: `host` at 2, `facts` at 5, `stack`
or `grafana` at 6. An `env` or `jira` blocker is one value or one grant, not a new `.env`:
act on its line through [READING-OUTPUT.md](READING-OUTPUT.md) rather than handing over stage
4's settings again, and go on from stage 5 once `doctor --only env,jira` ends `READY`. On
`READY`, ask whether they want a rehearsal (stage 8) or only the hand-off (stage 10). Stage 1's
summary still comes first.

## 1. Orient

Check you are at the root of a clone of `many-alerts-one-incident-mvp`:

```bash
git rev-parse --show-toplevel
```

```bash
git remote -v
```

Tell the engineer in a few sentences what happens next: ten stages; what they do by hand (the
list in the ground rules); that the demo needs a Jira Service Management project of its own,
which a Jira admin creates; and that nothing writes to Jira until they say yes. Ask for the
project key they have or want: two to ten capitals, digits or `_`, starting with a letter.

Done when the engineer has agreed to go on and you know the key, and whether the project exists.

## 2. Host check

```bash
python3 --version
```

Every command needs Python 3.11 or newer. When `python3` is older (macOS ships 3.9), look for a
newer one with `command -v python3.13 python3.12 python3.11`, make a virtualenv from it:

```bash
python3.11 -m venv .venv
```

and from here on write `.venv/bin/python` wherever this skill says `python3`. When none is
installed, the engineer installs one (python.org or their package manager) and tells you.

```bash
python3 -m grafana_jsm_sandbox.doctor --only host
```

An `images` WARN before the first `up` is expected; its Docker admin request matters only if
stage 6's pull is refused. A missing or old `jira-as` is installed after the engineer says
yes. With pipx (`command -v pipx` finds it):

```bash
pipx install 'jira-as==2.0.0'
```

then `command -v jira-as`. When that finds nothing, pipx's bin directory (usually
`~/.local/bin`) is not on PATH: `pipx ensurepath` fixes it for new shells, and until then put
`PATH="$HOME/.local/bin:$PATH"` in front of every `python3 -m grafana_jsm_sandbox...` command.
Without pipx, install into the virtualenv (when there is none, `python3 -m venv .venv` makes
it):

```bash
.venv/bin/pip install 'jira-as==2.0.0'
```

and from here on put `PATH="$PWD/.venv/bin:$PATH"` in front of every
`python3 -m grafana_jsm_sandbox...` command, because the commands look for `jira-as` on PATH.

Done when it ends `READY`.

## 3. Admin prerequisites

Ask the engineer these in one message, each answered yes, no or don't know:

1. A company-managed Jira Service Management project from the IT service management template
   exists, with their account in its Administrators role:
   `docs/admin-requests.md#jira-admin-create-project`.
2. Their account holds a Jira Service Management agent licence on the site:
   `docs/admin-requests.md#atlassian-org-admin-agent-licence`.
3. <https://id.atlassian.com/manage-profile/security/api-tokens> lets them create an API token:
   `docs/admin-requests.md#atlassian-org-admin-api-tokens`.
4. The site has no IP allowlist, or their laptop is on it:
   `docs/admin-requests.md#atlassian-org-admin-ip-allowlist`.
5. They can use exactly one model credential: an API key (`sk-ant-api…`) from their
   organisation's Anthropic Console, or an OAuth token from `claude setup-token`. Only the
   OAuth route requires an Enterprise seat allowed to run `claude setup-token` for that
   organisation. The chosen route must allow the model and leave Claude Code's
   `--allowedTools` in force: `docs/admin-requests.md#claude-org-owner`.
6. Docker Desktop may pull from Docker Hub, or they know the mirror:
   `docs/admin-requests.md#docker-admin`.
7. Their network reaches Atlassian, Anthropic and the registries without an intercepting proxy:
   `docs/admin-requests.md#network`.

For each no or don't know, read that section of `docs/admin-requests.md`, show its fenced
request with the placeholders you know filled in (key, project name, site), and say who it goes
to. The engineer sends it. The Network section is a checklist rather than a request: go through
it with them. The Incident fields, Resolution screen, workflow and permissions
requests are not asked here: `configure` finds out.

Go on with every stage the gap does not block: without items 1, 2 or 4, stage 4 stops at the
`jira` layer (and item 4 again at stage 6's container check); without item 3, at the token;
item 5 blocks stages 7 and 8; item 6 blocks stage 6. Item 7 blocks stages 4 to 8 until the
corporate CA is in place, below.

**Behind an intercepting proxy** (item 7 is no or don't know, and the engineer's laptop runs
something like Zscaler): every TLS connection from the laptop, the shell's `jira-as` and the
image build included, ends in the corporate root CA, which nothing here trusts until told to.
Walk the engineer through steps 1 to 3 of
`docs/demo-runbook.md#on-the-work-laptop-the-corporate-ca`: they export the root CA as PEM into
`certs/` (you may run the `security find-certificate` and `openssl x509` commands it gives, once
they name the certificate), and you check it reads back with a subject and a fingerprint. Then,
with `<file>` the name in `certs/`, for the rest of the session:

- every `python3 -m grafana_jsm_sandbox...` command gets `REQUESTS_CA_BUNDLE=certs/<file>` in
  front, because `configure`, `doctor`, `verify` and `reset` call `jira-as` from your shell;
- every `docker compose up` gets `EXTRA_CA_CERT=certs/<file>` in front, because the build puts
  that certificate into the image's trust store before any install.

The runbook's `export` lines do not work for you: see the ground rules. When some hosts bypass
the proxy, use the combined bundle the runbook's step 3 builds instead. When the engineer does
not know whether there is a proxy, go on without the prefixes: a certificate error in stage 4
or 6 answers the question (READING-OUTPUT.md).

Done when every item is yes, or its request is shown and the engineer knows which stage waits
for it, and, behind a proxy, the certificate reads back.

## 4. Credentials

```bash
ls .env
```

Only when that finds no file:

```bash
cp .env.example .env
```

The repo's permission rules guard `.env`, so this may be refused; then ask the engineer to run
it in their own terminal.

Hand over. The engineer opens `.env` in their own editor and fills in the following; the
file's comments say where each comes from:

- `JIRA_SITE_URL`: `https://<site>.atlassian.net`, or the API gateway's
  `https://api.atlassian.com/ex/jira/<cloudId>` for a service account's scoped token.
- `JIRA_EMAIL` and `JIRA_API_TOKEN`: the account and a token created at the address in stage 3.
  Ask them to note its expiry date for stage 10.
- Exactly one model credential: uncomment and fill `ANTHROPIC_API_KEY` with an API key
  (`sk-ant-api…`) from their organisation's Anthropic Console, **or** uncomment and fill
  `CLAUDE_CODE_OAUTH_TOKEN` with what `claude setup-token` prints in their own terminal,
  choosing their Enterprise organisation on the consent screen. Leave the other variable
  empty and commented. The Enterprise-seat prerequisite applies only to OAuth.
- `DEMO_PROJECT_KEY`: the key from stage 1.

They keep the ignored configuration mode-0600. They leave the unused model credential empty,
keep the four investigation variables commented for now, and tell
you when the file is saved. Then:

```bash
python3 -m grafana_jsm_sandbox.doctor --only env,jira
```

An `env` FAIL is a value only the engineer can change: name the variable and what `doctor` said,
and wait for them.

Done when it ends `READY`.

## 5. Project facts

```bash
python3 -m grafana_jsm_sandbox.configure
```

Show the engineer every WARN and FAIL line, the `.env:` line and the planned `-`/`+` lines (the
four field ids and the queue address; never a secret). A WARN on `severity`, `urgency` or
`source` means the demo runs and its Incidents go without that field. A `component` WARN is
optional: the engineer adds `rolldice` under the project's settings, Components, or runs the
command the line prints, which uses their own `jira-as` credential.

When it ends `READY` and the `.env:` line plans changes, ask whether to write them. On yes:

```bash
python3 -m grafana_jsm_sandbox.configure --write
```

Keep the address on its `queue` line for stage 8. Then:

```bash
python3 -m grafana_jsm_sandbox.doctor --only host,env,jira,facts
```

Done when `configure` has ended `READY` with `.env: <n> change(s) written` or `.env: up to date`,
and this `doctor` ends `READY`.

## 6. Build and start

```bash
docker compose up -d --build
```

The first build pulls and builds for several minutes; give it at least 15 minutes, in the
background when your shell's timeout is shorter. Then check about every 15 seconds, for up to 3
minutes, until demo shows `healthy`:

```bash
docker compose ps
```

```bash
python3 -m grafana_jsm_sandbox.doctor --only stack,grafana
```

In the first minutes after `up`, a `[grafana] FAIL series` or a `[stack] WARN` that demo is
`starting` means wait a minute and rerun, at most three times.

Behind a proxy, check the certificate made it into the image (runbook step 4); it prints
`extra-ca.crt`, and prints nothing when the build ran without the prefix:

```bash
docker compose exec -T demo ls /usr/local/share/ca-certificates
```

Tell the engineer that the demo is now live on their project: from here on, anything that
makes the Alert fire, such as stopping the `traffic` container by hand, starts Runs that
create and comment on Incidents there, with no question from you first.

Done when `doctor --only stack,grafana` ends `READY` and, behind a proxy, the check prints
`extra-ca.crt`.

### Optional Grafana investigation

Offer this only when the engineer wants evidence on the newly created Incident. Only the Run
that creates the Incident investigates, after the create and opening comment succeed. Updates,
repeats, related-alert updates and resolved Notifications do not investigate. Read
`docs/mvp-runbook.md#optional-grafana-investigation` before proceeding; it defines the CLI,
evidence, presentation and acceptance steps. There is no optional doctor investigation check.

Hand over the token step: using the presenter's Admin access in Grafana, the engineer creates a
service account with role Viewer, then its token. They privately enter it as
`DEMO_GRAFANA_VIEWER_TOKEN` in the ignored mode-0600 configuration in their own editor, and set
`DEMO_INVESTIGATION_ENABLED=true`. The image defaults `DEMO_GRAFANA_URL` to `http://lgtm:3000`;
on a laptop, absent defaults to `http://localhost:3000`, so explicitly override it when needed.
Absent `DEMO_GRAFANA_PRESENTER_URL` defaults to `http://localhost:<GRAFANA_HOST_PORT>` (port
3000 by default). Keep its override commented when that default reaches the presenter's browser.
Enabled startup requires the token and valid, nonblank URLs; disabled ignores the Grafana values.
You never read, create or echo the token. Once the engineer has saved the values:

```bash
docker compose up -d --force-recreate demo
```

A restart keeps the old environment. Recreate the Viewer account/token after `lgtm` is recreated:
`/data/grafana` has no persistent volume here. A 401 reads `grafana-query: unavailable: token rejected`.

With separate permission for stack work, follow the runbook's free pinned-image probe before any
model or Jira rehearsal: the installed command, datasource-proxy GET, Viewer access, query output
and Explore link on `grafana/otel-lgtm:0.33.0`. Confirm links in the presenter's browser under its
identity; Viewer Explore access is not assumed. Say, “These queries authenticate with a Viewer
token.” Grafana still allows anonymous Admin and its query traffic bypasses the Jira Forwarder.

For any paid Run or live Jira write, first settle site/project/session, model, dollar cap,
acceptable added delay and go/no-go; the ground rules' consent still applies. Show investigation
on the live-fault path. A replay queries the current system, with actual query times. Keep zero,
no data and unavailable distinct and provide metric/label names and syntax, never an expected
diagnosis. The rule called a health probe counts completed requests rather than independent
reachability; the runbook gives the other evidence limits.

Real-model acceptance requires the installed tool in the demo container, a faithful evidence
comment on the same real Incident, the complete lifecycle and an unavailable-evidence rehearsal.
Record added latency, queue delay and displayed model cost against a disabled baseline. A
follow-up query is optional. Source checks and stand-ins do not establish live acceptance.
If investigation misses or misstates evidence, have the engineer set
`DEMO_INVESTIGATION_ENABLED=false` privately, then recreate demo with the command above and
retain the existing lifecycle demo. Query, builder and investigation-post failures preserve a
successful lifecycle's `ok: ` Finish; do not claim a failed post was recorded.

Done when the engineer declined investigation, or the probe and browser check are recorded and
the engineer knows which real-model acceptance still waits for stage 8's consent. A failed probe
is a blocker for investigation; retain the lifecycle fallback and report the gap.

## 7. Model preflight (optional)

Offer it: one short, real Run inside the container proves the Claude seat and its permission
rules before a lifecycle depends on them, and costs a little usage. Skipping it is fine; stage
8's first Run proves the same, later. On yes:

```bash
python3 -m grafana_jsm_sandbox.doctor --only stack --with-model
```

The `stack` layer runs `doctor --in-container --with-model` inside demo through
`docker compose exec -T`, and passes on its `[container]` and `[model]` lines.

Done when it ends `READY` and its `[model]` lines name the model the Run used, or the engineer
declined.

## 8. First lifecycle: one Incident for many Alerts (`verify --mvp`)

This is the MVP's proof (`docs/mvp-spec.md`): several related Alerts, one Incident,
updates rather than duplicates, then Completed. Chapter one's single-Alert `verify` without
`--mvp` is not part of this demo; do not run it.

Before each lifecycle, check with the engineer that `.env`'s `DEMO_SESSION_ID` is a new value
for this take (`rehearsal1`, `rehearsal2`, …; never a hyphen before a digit, which jira-as reads as an issue key), so that no earlier take's Incident matches.
They change it themselves, and the stack must then be restarted (stage 6's `up -d`) before the
Receiver sees it. Never read `.env` to check.

Ask first: about five Runs will create one Incident in their project, add labels and comments
to it, and move it through Work in progress to Completed. Each lifecycle costs roughly $1–2 of
model usage. Before and after each lifecycle, total the Receiver's displayed Run costs:

```bash
docker compose logs --no-log-prefix demo | python3 -m grafana_jsm_sandbox.run_costs
```

The helper prints each priced `[result]` line and the total; `verify` prints no costs. Add
about $0.12 for each `doctor --with-model`, including retries, because it runs outside the
Receiver. Record the current total before recreating or removing demo, then carry it forward
and add the new container's total; repeated snapshots of one container replace its subtotal
rather than being added again. These are displayed estimates: failed Runs and missing cost
lines need separate accounting from the organisation's usage records. Tell the engineer the
running total, and stop offering lifecycles at their budget ($20 for the first rehearsal).
Suggest they open the queue address from stage 5 and watch `docker compose logs -f demo` in
a terminal of their own. On yes:

```bash
python3 -m grafana_jsm_sandbox.verify --mvp --replay
```

It takes a few minutes and may take up to twenty: run it in the background when your shell's
timeout is shorter, and read its lines as they come. Tell the engineer the Incident key once
`created` names it.

Then offer the real Alerts: `verify --mvp --live` stops the traffic, waits for Grafana's rules to
fire, for the repeat and the sustained-outage Alert to reach the Incident, then starts the
traffic again. It takes longer than the replay, up to about 30 minutes, so always run it in the
background. Run it only when no other `verify` and no hand-stopped traffic is in progress. On
yes:

```bash
python3 -m grafana_jsm_sandbox.verify --mvp --live
```

It starts the traffic again itself on a FAIL or a Ctrl-C, but not when its process is killed.
When it ends any way other than its own `VERIFIED` or `NOT VERIFIED` line (your command timed
out, the process was killed, the session ended), start the traffic at once, before anything
else, because while it is stopped Grafana repeats every few minutes and each repeat starts a
Run that writes to the project:

```bash
docker compose start traffic
```

then confirm with `doctor --only stack` that traffic is running, and tell the engineer.

Done when `verify --mvp --replay` has ended `VERIFIED: ...`, and `verify --mvp --live` has too
or the engineer declined it.

## 9. Reset

```bash
python3 -m grafana_jsm_sandbox.reset --dry-run
```

Show its lines as printed.

When it names a key, ask whether to complete and close the Incidents it names and start the
traffic. On yes:

```bash
python3 -m grafana_jsm_sandbox.reset
```

When it names no key and ends `queue would be empty` (the usual case after a `VERIFIED`, whose
Incident is already Completed with a resolution), the project needs nothing and you skip the
real reset. A dry run does not say whether the traffic runs now, so check:

```bash
python3 -m grafana_jsm_sandbox.doctor --only stack
```

and when its `traffic` line is a WARN, start it with `docker compose start traffic` and rerun
that `doctor`.

A line offering `deleteIssue` is the engineer's decision: deletion is permanent, and you leave
it to them.

Done when `reset` printed `traffic started` and ended `queue is empty`, or, when the dry run
named nothing, `doctor --only stack` ends `READY` with no `traffic` WARN.

## 10. Hand-off

Give the engineer, briefly:

- **Presenting:** `docs/demo-runbook.md`, in particular
  `docs/demo-runbook.md#the-day-before-a-full-rehearsal`,
  `docs/demo-runbook.md#fifteen-minutes-before-pre-demo-checks`,
  `docs/demo-runbook.md#the-demo-step-by-step`, `docs/demo-runbook.md#fallback-the-replay` and
  `docs/demo-runbook.md#reset-between-takes-or-after-a-bad-one`.
- **Investigation, if opted in:** `docs/mvp-runbook.md#optional-grafana-investigation` for the
  live-fault presentation, evidence limits and disabled fallback. Report probe, real-model and
  unavailable-evidence results separately from lifecycle verification.
- **Token expiry:** the Jira token's date from stage 4. A new token of either kind goes into
  `.env` in their editor, followed by `docker compose up -d demo`; a `docker compose restart`
  keeps the old environment.
  The Viewer token must also be recreated after `lgtm` is recreated, then entered privately
  and loaded by recreating demo.
- **Teardown:** copy out any Transcript worth keeping first (READING-OUTPUT.md, "A failed
  Run"), then `docker compose down`. Revoke the Jira API token at the address in stage 3, and
  the Claude token from their Claude account or through their Claude org owner. The project
  is the Jira admin's to archive.
  Revoke the Grafana Viewer token too when investigation was enabled.

Done when the engineer has the hand-off and, when enabled, the investigation results and fallback.
