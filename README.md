# grafana-jsm-sandbox

A Grafana alert opens, updates and resolves a Jira Service Management Incident through a
headless Claude Code Run that holds no Jira credential. One `docker compose up` brings up a
Grafana LGTM stack with one group of related alert rules, the small app those rules watch, the synthetic traffic
whose absence fires it, and one hardened container whose main process receives the alert's
Notification and starts a Run for it: Claude Code in print mode, allowed two tools (Bash for
`jira-as` and `incident-payload`, plus `grafana-query` when investigation is enabled, and Read
of one directory), following one Skill,
reaching Jira through a localhost Forwarder that swaps a per-Run sentinel
for the real token. Stop the traffic and an Incident appears in the queue; start it again and
the Incident is Completed, with the trend commented in between. It was built as a demo of what a
sandboxed boundary looks like when the audience may ask what else the Run can reach, and
[the runbook](docs/demo-runbook.md) is the presenter's script.

## Quickstart

From a clean clone to one Incident's whole lifecycle on your own Atlassian site, and a clean
reset afterwards. Every command runs from the repo root. Each step says what done looks like;
when one does not get there, its line names the fix, and the sections after this one say more.
In Claude Code, ask to set up the demo and
[the setup skill](.claude/skills/demo-setup/SKILL.md) runs these steps with you, stopping for
the tokens and admin requests only you can give, and asking before anything writes to Jira.

1. **Prerequisites.** Docker with Compose v2 (2.17 or newer), Python 3.11 or newer, `jira-as`
   2.x on your PATH, a Jira Cloud site, and a Claude seat that may run `claude setup-token`.
   [What you need](#what-you-need) says why each and how to get it. Check the Python first:

    ```bash
    python3 --version
    ```

    The `python3` that macOS itself ships is 3.9, too old for every command below, which then
    exits 2 saying so. Install 3.11 or newer (python.org or your package manager) and make it
    the `python3` of every step. Clone the repo:

    ```bash
    git clone https://github.com/grandcamel/many-alerts-one-incident-mvp.git
    ```

    ```bash
    cd many-alerts-one-incident-mvp
    ```

    When `python3` was too old, make a virtualenv from the newer one, here 3.11, and activate
    it in each terminal you use for the steps below:

    ```bash
    python3.11 -m venv .venv
    ```

    ```bash
    . .venv/bin/activate
    ```

    Then check the host. Done is a `READY` at the end:

    ```bash
    python3 -m grafana_jsm_sandbox.doctor --only host
    ```

    Before the first `up`, an `images` WARN saying they are not pulled yet is expected: the
    Docker admin request it names applies only if the pull in step 7 is refused.

2. **Admin requests.** The demo writes to a Jira Service Management project of its own, created
   from the IT service management template, of which you are the administrator. Creating one
   needs a Jira admin: forward
   [the create-project request](docs/admin-requests.md#jira-admin-create-project). Your account
   also needs a Jira Service Management agent licence, API tokens your organisation allows, and
   a Claude seat allowed `claude setup-token`; [docs/admin-requests.md](docs/admin-requests.md)
   has each request ready to forward. You need not guess which apply: a FAIL from the commands
   below ends with `; ask: docs/admin-requests.md#<anchor>` when one does. A WARN may name one
   too; forward that only if you want what it says the demo goes without.

3. **`.env`.** Copy the example:

    ```bash
    cp .env.example .env
    ```

    and fill in five values in your own editor: `JIRA_SITE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
    `DEMO_PROJECT_KEY` and exactly one of `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`
    (what `claude setup-token` prints), leaving the other empty. The
    file's comments say where each comes from. Leave everything else as it is; `configure`
    writes the rest.

4. **Read the project.** `configure` asks Jira about the project, through `jira-as` with the
   credential and key in `.env`, and changes nothing:

    ```bash
    python3 -m grafana_jsm_sandbox.configure
    ```

    Done is `READY`, with the `.env` changes it plans. A FAIL names what stops the demo, and
    usually the admin request that fixes it. A WARN on `severity`, `urgency` or `source` means
    the project lacks that field or one of its values: the demo runs, and its Incidents go
    without it.

5. **Write what it found** into `.env`: the four field ids and the Incidents queue's address.
   Done is `.env: 5 change(s) written` (fewer when some were right already) and `READY`:

    ```bash
    python3 -m grafana_jsm_sandbox.configure --write
    ```

6. **Check everything the stack will stand on.** Done is `READY`:

    ```bash
    python3 -m grafana_jsm_sandbox.doctor --only host,env,jira,facts
    ```

7. **Start the stack.** The first build pulls and builds for a few minutes:

    ```bash
    docker compose up -d --build
    ```

8. **Check the whole path**, now including the running stack, the demo container's own view
   and Grafana. Give the stack about a minute after `up` first, until this shows demo
   `healthy`:

    ```bash
    docker compose ps
    ```

    and the traffic has had time to reach rolldice and its metrics to reach Grafana. Then
    run the full check. Done is `READY`:

    ```bash
    python3 -m grafana_jsm_sandbox.doctor
    ```

    In that first minute a `[grafana] FAIL series`, or a `[stack] WARN` that demo is still
    `starting`, means wait and run it again.

    Once, also let one short, real Run prove the Claude seat and its permissions. It costs a
    little usage:

    ```bash
    python3 -m grafana_jsm_sandbox.doctor --with-model
    ```

9. **Fire the Alert.** Watch the log in one terminal:

    ```bash
    docker compose logs -f demo
    ```

    and stop the traffic in another:

    ```bash
    docker compose stop traffic
    ```

    Open the Incidents queue at the address `configure` printed on its `queue` line (kept in
    `.env` as `DEMO_QUEUE_URL`). About a minute after the stop Grafana fires
    and a Run creates the Incident; about a minute later a repeat Firing's Run comments the
    trend and moves it to Work in progress. Then start the traffic again, and a third Run
    completes it, which takes it out of the queue:

    ```bash
    docker compose start traffic
    ```

10. **Verify.** Once the Incident is Completed and Grafana shows the rule Normal, watch one
    whole lifecycle stage by stage, replayed from the canned Notifications. Done is
    `VERIFIED`:

    ```bash
    python3 -m grafana_jsm_sandbox.verify
    ```

    `verify --live` does step 9 unattended instead: it stops the traffic, watches, and starts
    it again. Either refuses to start while an Incident for the Alert is still open, and says
    to run the reset.

11. **Reset.** Take every Incident a Run left in the queue out of it and start the traffic.
    It writes to Jira without asking, so see first what it would change; this changes
    nothing:

    ```bash
    python3 -m grafana_jsm_sandbox.reset --dry-run
    ```

    Then run it. Done is `queue is empty`:

    ```bash
    python3 -m grafana_jsm_sandbox.reset
    ```

    The demo is ready for its audience;
    [the runbook](docs/demo-runbook.md) is how to present it. A Run that failed is in the log
    with a `[FAILED]` line, and [its Transcript](#fetching-a-transcript) has the rest.

## Optional Grafana investigation

Investigation is disabled by default. Only the Run that creates the Incident investigates,
after the create and opening comment succeed, using current read-only PromQL and discovery
GETs of its choosing through `grafana-query`. It adds one evidence comment to that same
confirmed Incident. Updates, repeats, related-alert updates and resolved Notifications do not
investigate; no Incident is created just to hold evidence. Query, builder and post failures
leave a successful lifecycle Finish starting `ok: `.

The four commented settings in `.env.example` are `DEMO_INVESTIGATION_ENABLED`,
`DEMO_GRAFANA_URL`, `DEMO_GRAFANA_PRESENTER_URL` and `DEMO_GRAFANA_VIEWER_TOKEN`. Follow the
[manual Viewer-token and opt-in steps](docs/mvp-runbook.md#optional-grafana-investigation), or
ask [the setup skill](.claude/skills/demo-setup/SKILL.md). The operator creates a Viewer
service account and token with their Admin access, enters it privately in the ignored
mode-0600 configuration, then recreates demo. Recreate the account/token after `lgtm` is
recreated; its Grafana data has no persistent volume. A 401 reads `token rejected`.

The image defaults the internal URL to `http://lgtm:3000`; on a laptop the absent URL defaults
to `http://localhost:3000`, with an explicit override when needed. The default presenter URL
is `http://localhost:<GRAFANA_HOST_PORT>`, port `3000` when absent. Compose carries the resolved
published port into the Receiver even for a shell override. Presenter links open in the
presenter's browser under its identity, not the Run's token. Say, “These queries authenticate
with a Viewer token.” Grafana still allows anonymous Admin, and query traffic bypasses the Jira Forwarder.
A Run holds its model credential and, when enabled, a Grafana Viewer credential; Jira still
uses the Forwarder's sentinel. The whole Grafana deployment is not read-only.

The CLI offers `instant --query=EXPR`, `range --query=EXPR` and `get --path=PATH`, with flags
after the subcommand and values given with `=`, so an expression that starts with `-` is not read
as a flag. It reads its environment only and appends full JSON evidence to
`grafana-evidence.jsonl` in the Run's directory. There is no query allow list, attempt budget,
retry policy, response-size limit, sample cap or observation-window cap. The ten-second
per-request elapsed timeout and first-five-line Transcript summary keep it usable; the
existing Run timeout still applies. The evidence comment starts with `[grafana-investigation] `
and includes Observation, Interpretation, Unknown / next check and mechanical evidence with
presenter links. Investigation comments do not count as lifecycle Runs at close or in verification.

Show investigation on the live-fault path. All four rules derive from
`http_server_duration_milliseconds_count` for `service_name="rolldice"`. The rule called a
health probe is another view of completed requests, not an independent reachability check.
Another query of that metric adds context, not independent corroboration. `checkout-outage`
is a demonstration group label, not proof of a checkout service. Keep returned zero, no data and unavailable
distinct: missing error series do not establish zero errors, fresh telemetry does not establish
a healthy application, and absent traffic does not explain why it stopped. A replay investigates
the current system with actual query times, not its historical window. Give metric/label names
and query syntax, never an expected diagnosis. Do not claim measured time savings or autonomous
root-cause discovery.

The installed tool, Viewer access, proxy path and presenter Explore form on the pinned
`grafana/otel-lgtm:0.33.0` still require a separately authorized free probe, without a model or
Jira. Offline checks do not establish live acceptance. Before paid Runs or live Jira writes,
settle the site/project/session, model, dollar cap, acceptable added delay and go/no-go. Then
rehearse a faithful evidence comment on the same real Incident, the complete lifecycle and
unavailable evidence; record added latency, queue delay and displayed model cost against a
disabled baseline. If investigation misses or misstates evidence, privately set
`DEMO_INVESTIGATION_ENABLED=false`, recreate demo and retain the existing lifecycle presentation.

## What the basic demo uses and what to ignore

The Quickstart is chapter one, the basic demo. This repository also carries chapter two, work
in progress that the basic demo neither runs nor imports.

| The basic demo uses | What it is |
| --- | --- |
| `docker-compose.yml`, `Dockerfile`, `docker/`, `grafana/provisioning/alerting/`, `certs/` | The stack, the demo image and its hardening, and the Alert |
| `grafana_jsm_sandbox/`: `__main__`, `receiver`, `notification`, `forwarder`, `run_command`, `run_spawner`, `skill_template`, `log_formatter`, `nondumpable`, `incident_payload`, `grafana_query`, `investigation_contract` | What runs in the demo container |
| `grafana_jsm_sandbox/`: `demo_config`, `configure`, `doctor`, `verify`, `reset`, `replay` | The laptop commands, all reading `.env` |
| `skill/incident-sync/` | The template of the Skill a Run follows |
| `fixtures/` | The canned Notifications, recorded Transcripts, and a made-up Jira project for the tests |
| `docs/demo-runbook.md`, `docs/mvp-runbook.md`, `docs/admin-requests.md`, ADRs 0001 to 0005 | How to present it, opt into investigation, what to ask for, and why it is built this way |
| The tests `python3 -m pytest --basic-demo` runs | Chapter one's tests, listed in `tests/conftest.py` |

Everything else is chapter two's, and a newcomer to the basic demo can ignore it:

- the twenty `grafana_jsm_sandbox/forwarder_*.py` modules, a mediated Forwarder still being
  built (`forwarder.py`, without the underscore, is chapter one's), and `docs/forwarder-control.md`;
- `prototype/` and `docs/research/`, which are experiments and research notes;
- ADRs 0006 onward, and the parts of `CONTEXT.md` about Faults, Cascades, Problems, Reports and
  Memory;
- the test files off the `--basic-demo` list, which are most of the default run;
- Kubernetes, kind and DigitalOcean: the basic demo is Docker Compose on a laptop and needs no
  cluster.

The demo image carries the whole package, chapter two's modules included, but nothing the
Receiver starts imports them.

## Chapter two

**This repository is chapter two, and it opens with chapter one's code.** Chapter one, the
basic demo above, was finished in `grafana-jsm-sandbox`, a demo in which one Grafana alert
becomes one Jira Service Management Incident through a Run that holds no Jira credential. That
repository, where chapter one was first built, is not published; everything it held is here,
so this repository is the one that moves from here, and the one to clone. Chapter two asks the harder question it is named for:
when one Fault in a simulated distributed system raises a Cascade of Alerts, how do many
Notifications become one Incident whose Suggested root cause cites the evidence a Run
retrieved? It is being charted before it is built. The vocabulary is in [CONTEXT.md](CONTEXT.md)
and the decisions are in [docs/adr](docs/adr); the working notes and research behind them are
not published. None of it has changed how the basic demo runs.

## What you need

- **Docker** with Compose v2. The demo is `docker compose up`: the images are pulled from Docker
  Hub or built here, and nothing else is installed for the demo itself. Compose applies
  `pids_limit` from 2.2 and `cpus` from 2.17; an older one silently leaves them off, and the
  runbook says how to tell and what to do meanwhile. Where Docker Desktop's policy restricts
  images, [the Docker admin request](docs/admin-requests.md#docker-admin) names them.
- **A Jira Cloud site with a Jira Service Management project of the demo's own**, created from
  the IT service management template by a Jira admin, with you as its administrator
  ([the request](docs/admin-requests.md#jira-admin-create-project)); a project admin cannot
  create one. Its key goes in `.env` as `DEMO_PROJECT_KEY`, which has no default: the Receiver
  refuses to start without it. Use a project nobody else works in, because the reset closes
  every open Incident a Run made there and the queue must start empty.
- **An Atlassian account with a Jira Service Management agent licence** on that site and an API
  token for it: a classic token from
  <https://id.atlassian.com/manage-profile/security/api-tokens> with the site's bare address as
  `JIRA_SITE_URL`, or a service account's scoped token with the API gateway's
  `https://api.atlassian.com/ex/jira/<cloudId>`. The Forwarder holds it, and no Run ever does.
- **A Claude Code OAuth token**, from `claude setup-token` on a machine where Claude Code is
  logged in, on a seat your Claude organisation allows it for. It is the Run's model credential;
  when investigation is enabled the Run also holds a Grafana Viewer credential. Each Run asks
  for Opus 5 unless `RUN_MODEL` in `.env` names another model.
- **Python 3.11 or newer** for the laptop commands (`configure`, `doctor`, `verify`, `reset`,
  `replay`). They are standard library only, so nothing is installed to run them; the tests
  need pytest and PyYAML (below). Check `python3 --version`: the `python3` macOS ships is 3.9,
  and on it each command exits 2 with one sentence pointing here. Install 3.11 or newer
  (python.org or your package manager) and run every command with it, for example from a
  virtualenv made with `python3.11 -m venv .venv` and activated with `. .venv/bin/activate`.
- **`jira-as` on your own PATH**, the Jira Assistant CLI 2.x; `pip install 'jira-as==2.0.0'`
  into a virtualenv, or `pipx install 'jira-as==2.0.0'`, gives you the version the image
  carries. The image has its own copy for Runs; yours is for the laptop commands. None of them
  uses the credential or project your shell's jira-as is configured with: each starts it with
  the site, credential and project key from `.env` alone, and warns when the shell's own
  `JIRA_SITE_URL` names another site.

## The setup commands: configure, doctor, verify

**The field ids come from `.env`, never from an edit to the Skill.** Custom field ids differ on
every Jira site. [`skill/incident-sync/SKILL.md`](skill/incident-sync/SKILL.md) is a template
with `{{PROJECT_KEY}}` and the field ids as placeholders, and the Receiver renders it at every
start from `DEMO_PROJECT_KEY` and the Severity, Urgency, Source and Major incident ids in
`DEMO_SEVERITY_FIELD`, `DEMO_URGENCY_FIELD`, `DEMO_SOURCE_FIELD` and
`DEMO_MAJOR_INCIDENT_FIELD`. A field left empty is one the project lacks: the rendered Skill
names no id for it and tells a Run to leave it off. So nothing tracked is edited and the image
is not rebuilt to point the demo at your site. After changing `.env`, recreate the container
with `docker compose up -d demo`: a `docker compose restart` keeps the environment the container
was created with, and would render the Skill from the old values. `configure` reads the ids off
the project, with the credential and key already in `.env`:

```bash
python3 -m grafana_jsm_sandbox.configure
```

```bash
python3 -m grafana_jsm_sandbox.configure --write
```

The first prints what it found and the `.env` diff; the second makes that diff in `.env`. It
only reads Jira. It takes each field by its exact name from the project's own create
metadata for the Incident type, never from the site's field list, and checks that it offers
the values the Skill writes (`Sev-1`..`Sev-3`, `Critical`/`High`/`Medium`, `Monitoring
systems`). It also checks the account's permissions on the project, the Incident workflow's
Open, Work in progress, Completed and Closed, the resolution Done, and the service desk's
Incidents queue, whose address it writes as `DEMO_QUEUE_URL`. It warns when the project holds
open Incidents without an `fp-` label, and prints, rather than runs, the command that adds the
optional `rolldice` component, pinned to `.env`'s site and key so your own jira-as setup cannot
send it elsewhere. A Severity, Urgency or Source it cannot pin down is written empty, and its
line is a WARN naming the optional admin request (`docs/admin-requests.md#<anchor>`): the demo
runs and a Run leaves the field off. A create screen that lacks Labels or Description, or
requires a field no Run fills, is a FAIL, because every create would be refused. `--write`
changes only those five keys: in place when `.env` has them, keeping comments and order, and
otherwise under a marked `site facts written by configure` block at the end. A key whose check
Jira refused is left as it is and named on a `.env: not checked:` line. It needs `.env` to
exist (`cp .env.example .env` first) and never prints a credential. It prints one
`OK`/`WARN`/`FAIL` line per check and ends `READY` (exit 0) or `NOT READY: <first failure>`
(exit 1); exit 2 is a usage or `.env` error before Jira was asked. `READY` is about the project:
whether `.env` already holds what it found is the `.env:` line's to say, so a first run without
`--write` can be `READY` with changes still planned. The line format is in the module's
docstring. Transition ids need no such step: a Run reads them off each Incident as it goes.

`doctor` checks the whole path in order and stops at the first layer that fails:

```bash
python3 -m grafana_jsm_sandbox.doctor
```

```bash
python3 -m grafana_jsm_sandbox.doctor --only env,jira
```

```bash
python3 -m grafana_jsm_sandbox.doctor --with-model
```

The first runs every layer: host, env, jira, facts, stack, grafana. `--only` runs just the
layers it names, still in order, and `--with-model` adds one short, real Run in the container.
`host` is Docker, Compose, this Python, `jira-as` 2.x, whether the images compose pulls are here,
and whether the ports compose publishes on are free or already this stack's. `env` reads `.env`:
no `.env.example` placeholder left, `JIRA_SITE_URL` a site's bare address or the API gateway's
`/ex/jira/<cloudId>`, the Claude token's shape, the project key, and whether the Receiver would
start on it. `jira` asks, through `jira-as` with `.env`, who the credential is, the site, the
project and the permissions, and classifies a 401, an IP-allowlist 403 and a 404. `facts` holds
the field ids in `.env` to the project's own create screen, as `configure` reads it, with the
workflow and the resolution. `stack` is `docker compose ps`, the demo container's health, and
`doctor --in-container` run through `docker compose exec -T demo`, which checks that the
Receiver's `/proc/1/environ` is unreadable, that the rendered Skill names the key, and that Jira
answers `/rest/api/3/myself` for the container's credential through a Forwarder, printing only
the status and what it means; a refusal there is classified exactly as the laptop's is. `grafana`
asks the running Grafana, on `GRAFANA_HOST_PORT`, for the contact point, the one-minute repeat,
the rule, a series for the rule's query, and whether the rule is Normal. `--with-model` starts
one Run inside the container with the real flags and allow list, whose Jira is an address where
nothing listens, and asks it only for `jira-as --version`, `incident-payload --help` and its Skill:
it reports the model the seat ran, a failure in the log's own `[FAILED]` and `[hint]` words, and
whether any allowed call was denied, which points at the organisation's managed permission rules. Each line is
`[<layer>] OK|WARN|FAIL <check> — <what it found, or the fix>`, a FAIL, or a WARN an admin could
clear, naming the admin request (`docs/admin-requests.md#<anchor>`) where one fixes it; it ends
`READY` (exit 0) or `NOT READY: <first blocker>` (exit 1), and exit 2 is a usage error. The line
format is in the module's docstring.

`verify` then watches one whole lifecycle happen on the project, stage by stage:

```bash
python3 -m grafana_jsm_sandbox.verify
```

```bash
python3 -m grafana_jsm_sandbox.verify --live
```

The first replays the canned Notifications at the Receiver; `--live` stops the traffic and
watches the real Alert. It first refuses when an open Incident already carries the Fingerprint
label (the Runs would comment on it rather than create one; `reset` takes it out), and notes
which Incidents carry it already, so a rehearsal's leftover is never taken for this run's.
`--replay`, the default, posts the Firing, the repeat and the Resolved, each once the Incident
has answered the one before. `--live` stops the traffic, waits for Grafana's rule to fire, and
starts the traffic again once the repeat has moved the Incident to Work in progress; it starts
the traffic on the way out whatever happens, a failure or Ctrl-C included. Either way it
watches, by JQL through `jira-as` with `.env`, for the Incident to be created, to get its
opening comment, to reach Work in progress with a trend comment and to be Completed with a
resolution, printing each stage with its elapsed time as
`[+<seconds>s] WAIT|OK|WARN|FAIL|NOTE <stage> — <message>`. A stage that does not come in time
is named with its likely cause (``no Incident within 360s of the Firing: check `docker compose
logs demo` for [FAILED]``), and Completed without a resolution names
`docs/admin-requests.md#jira-admin-resolution-screen`. The waits come from the rehearsal's
timings with wide margins, and a Run's is `RUN_TIMEOUT` plus a minute; each has a flag
(`--help`). It ends `VERIFIED: ...` (exit 0) or `NOT VERIFIED: <stage> — <why>` (exit 1; 130 when
interrupted, 2 a usage or `.env` error). It only reads Jira: it closes and deletes nothing, and
leaves the Incident where the Runs left it, Completed with a resolution being already out of the
queue; after a failure, `reset` takes what is left out. The line format is in the module's
docstring.

Domain vocabulary is in [CONTEXT.md](CONTEXT.md); decisions are in [docs/adr](docs/adr); the
MVP's design is in [docs/mvp-spec.md](docs/mvp-spec.md). The specs and tickets the work was
planned in are working notes, and are not published; the ticket, step and story numbers in the
ADRs, docs and code comments refer to them.

## What exists today

The **Receiver** — the HTTP endpoint that accepts Notifications and starts Runs, one at a time.

- `POST /notification` — a Grafana webhook contact point body. A valid Notification is
  acknowledged with `202` and queued; the Run starts afterwards, so Grafana never waits on it.
  A body that is not JSON, has no `alerts` array, or has an Alert without a `fingerprint` and a
  `status`, gets a `400` and starts nothing.
- `GET /health` — `200` while the Receiver is up.

Each Notification becomes one Run with its own working directory under the Receiver's runs
directory, containing the Notification exactly as Grafana sent it as `notification.json`. Runs
execute one at a time in arrival order, so two Firings of the same Alert cannot race into
duplicate Incidents. The Receiver logs each accepted Notification (its Alert count, the Run it
queued and how many Runs are ahead of it), each rejected POST with the reason, and each Run's
start, end, exit status and duration. A Run that failed ends on `run <id> FAILED: <reason>` at
ERROR, whatever its exit status said; a Run that blows up is logged the same way and the next one
still starts.

The process that actually spawns a Run is injected into the `Receiver` at construction, so it
stays a seam a test can substitute; the real spawner is `RunSpawner`, below.

The **log formatter** — what turns a Run's Transcript into the log window the audience watches.

`format_event` is a pure function: one Run event in, zero or more display lines out. It renders
the Run's own text, every tool call with its command in full, tool results trimmed to a few lines,
and permission denials on a `[DENIED]` line — the audience-visible proof that a Run cannot do
anything except talk to Jira (ADR 0003). An event it does not understand costs one diagnostic
line, never a crash. Every line is redacted on the way out, so no Authorization header and nothing
token-shaped can reach a screen.

A Run that failed ends on `[FAILED] <terminal_reason or subtype>: <first line of what it said>`
instead of `[result]`: any result with `is_error: true` or an `error_` subtype. A Run the API
refused outright reports `subtype: success` and exits 0, so neither of those is trusted. A Run
that could not do its job, because the Forwarder refused its create or a close left no
resolution, ends its message `failed: <why>` (the Skill's Finish) and is `success` too; that line
renders as `[FAILED] run reported failed: <why>`. The first non-empty line of a `success` result
must start exactly `failed: ` for this marker to apply. A successful Finish starts `ok: ` before
the group text (`ok: failed DEMO-12 created` succeeds); `FAILED: ` is not a failure marker.
A create the Forwarder refused prints a
`[DENIED]` line before it. When the cause is one a newcomer's setup is known to hit (a Claude token that is invalid or expired,
usage credits run out, a rate limit, a model the seat cannot use, a spent budget) a `[hint]`
line under it says what to do. Claude Code retrying the API prints `[retry]`, and a rate-limit
event prints `[limit]` only when its status is not `allowed`.

Render a saved Transcript to see what the log window will look like:

```bash
python3 -m grafana_jsm_sandbox.log_formatter fixtures/run-transcript.jsonl
```

```
[run]    model=claude-fable-5-1 permission-mode=dontAsk tools=Bash,Read
[claude] I'll run the two bash commands in order and report which worked.
[tool]   Bash: seq 1 40
[out]    1
[out]    2
[out]    3
[out]    4
[out]    5
[out]    + 35 more lines
[tool]   Bash: ls /etc
[DENIED] Bash: Permission to use Bash has been denied because Claude Code is running in don't ask mode.
[claude] The first command (`seq 1 40`) worked and printed 1 through 40; the second (`ls /etc`) was denied by the permission mode and did not run.
[DENIED] Bash: ls /etc
[result] success in 10.0s, 3 turns, $0.4527
```

The fixtures were recorded on Fable 5.1, so they name `claude-fable-5-1` and its costs. A Run
now asks for Opus 5 unless `RUN_MODEL` names another (below). Its log has the same shape, but
its turns, time and text differ: on Opus 5 a Run took 22 to 25 seconds, 7 to 11 turns and $0.33
to $0.46 (2026-09-24). The fixtures themselves have not been re-recorded.

`fixtures/run-transcript-refused.jsonl` is a Run refused for want of usage credits, rebuilt
from the recorded shape of one with nothing of a real account in it:

```
[run]    model=claude-fable-5-1 permission-mode=dontAsk tools=Bash,Read
[claude] You're out of usage credits · manage usage credits at claude.ai/settings/usage
[FAILED] api_error: You're out of usage credits · manage usage credits at claude.ai/settings/usage
[hint]   the Claude account is out of usage credits for this model: top them up at claude.ai/settings/usage, or set RUN_MODEL in .env to a model the account has credits for and recreate the container with `docker compose up -d demo`
```

The Receiver pipes every live Run through it, one line at a time, as the Run produces it. In the
container log each line also carries the time and a level: `[FAILED]` is ERROR, and `[hint]`,
`[DENIED]`, `[retry]` and `[limit]` are WARNING, so a log filtered to warnings still shows what
went wrong. The same refused Run, as `docker compose logs demo` shows it:

```
2026-09-23 21:46:00 INFO    notification accepted: 1 alert, run 20260923T214600-a7ae37 queued, 0 ahead
2026-09-23 21:46:00 INFO    run 20260923T214600-a7ae37 started in /app/runs/20260923T214600-a7ae37
2026-09-23 21:46:00 INFO    run 20260923T214600-a7ae37 transcript: /app/runs/20260923T214600-a7ae37/transcript.jsonl
2026-09-23 21:46:00 INFO    [run]    model=claude-fable-5-1 permission-mode=dontAsk tools=Bash,Read
2026-09-23 21:46:00 INFO    [claude] You're out of usage credits · manage usage credits at claude.ai/settings/usage
2026-09-23 21:46:00 ERROR   [FAILED] api_error: You're out of usage credits · manage usage credits at claude.ai/settings/usage
2026-09-23 21:46:00 WARNING [hint]   the Claude account is out of usage credits for this model: top them up at claude.ai/settings/usage, or set RUN_MODEL in .env to a model the account has credits for and recreate the container with `docker compose up -d demo`
2026-09-23 21:46:00 INFO    run 20260923T214600-a7ae37 finished with exit status 0 in 0.04s
2026-09-23 21:46:00 ERROR   run 20260923T214600-a7ae37 FAILED: api_error: You're out of usage credits · manage usage credits at claude.ai/settings/usage
```

The **skill** a Run follows, and the command line that starts one.

[`skill/incident-sync/SKILL.md`](skill/incident-sync/SKILL.md) is the whole of what a Run knows
about the project: the Fingerprint label format, the match JQL, the field mapping, the lifecycle
rule, and every operation written as a `jira-as` or `incident-payload` invocation, plus
`grafana-query` when investigation is enabled. It
is short on purpose — it is meant to be read off a screen during the demo. What a Run reads is its
rendering for `.env`'s project, which `skill_template.py` writes read-only into `.skill` in the runs
directory at every Receiver start (`/app/runs/.skill` in the container, on its tmpfs). The
Receiver replaces it itself; to delete a laptop's `runs` by hand, `chmod -R u+w runs/.skill` first.

`build_run_command` is the command line that starts one Run: print mode, the model
(`--model claude-opus-5` unless `RUN_MODEL` names another), a spending cap when `RUN_BUDGET_USD`
sets one (`--max-budget-usd`), `dontAsk`, an allow list of `Bash(jira-as *)`,
`Bash(incident-payload *)` and `Read` scoped to
one absolute directory, the runs directory, which holds the rendered Skill too
(`Read(//app/runs/**)` in the container), stream-json with `--verbose`, and the rendered skill
directory added so the Run can read it (ADR 0003). When investigation is enabled,
`Bash(grafana-query *)` is added after the payload rule; no general-purpose shell rule is added.
A bare `Read` was enough for a Run to read the
real Jira token out of the Receiver's `/proc` entry; the Receiver is also non-dumpable on Linux, so
that entry is root's and no Run can open it by any route (ADR 0002). A process Docker execs into
the container, any `docker compose exec`, still carries the token in its environment while it
lives; ADR 0002's amendment records that open route and its fix. The healthcheck starts its probe
through `env -i`, so the probe holds no environment at all, and `doctor --in-container` (below)
makes itself non-dumpable before its own imports, which leaves the token readable only while
the interpreter starts. Print the command line to start a Run
by hand, from a runs directory a Receiver has rendered the Skill into (it names the default model
and no cap, whatever `.env` says):

```bash
python3 -m grafana_jsm_sandbox.run_command runs <KEY>
```

with your project's key for `<KEY>`, which the prompt names. A Run's environment also carries
`JIRA_ALLOWED_PROJECTS` set to that key, so its `jira-as` refuses any call that names another
project, before sending it. That is jira-as's own check of literal project references, not a
boundary: the allow list and the Skill still are.

Two things the permission boundary decides for the skill, both found by running it:

- A `jira-as` command that is split across lines, carries a newline inside an argument, or uses
  `$'...'` does not match the allow list and is denied whole. Every invocation in the skill is one
  line of plain single quotes; the Description gets its paragraphs from one line of ADF instead,
  which `incident-payload` builds and prints in the `jira-as issue create` line, so no Run writes
  ADF by hand.
- A Run has no clock of its own — `date` is not on the allow list — so every duration it reports is
  Jira's `serverTime` minus the Incident's `created`. Grafana's clock is never used for a duration,
  which is also what keeps a replayed fixture from reporting a negative one.

The **Forwarder** — the localhost process that holds the real Jira credential so a Run never does.

A Run's environment points jira-as at the Forwarder over plain http, with a per-Run **sentinel**
in place of the API token. The Forwarder swaps that sentinel for the real email and token and
forwards the request to the configured Atlassian site (ADR 0002). It binds to loopback only, takes
its upstream from configuration and never from the request, hands a redirect back rather than
following it somewhere else, and refuses a request whose sentinel is missing, wrong, or left over
from a Run that has ended. Neither the token nor an Authorization header reaches any log line.
Each request it forwards is one `forwarded <method> <path>, upstream said <status>` line. A 4xx
or 5xx is a WARNING, and a 401, a 403 or a 404 carries what it most likely means for the demo:
the credential in `.env` refused, the site's IP allowlist (when the 403's body says so, gzip or
deflate undone first), a missing permission, or a project key the account cannot see. A 403 whose
body cannot be read names both of its likely causes. The body itself is never logged.

Each Run gets one create attempt. Before starting it, the spawner registers the create content
`incident-payload create` would print for its Notification and project facts. The Forwarder
admits only single-issue creates whose Summary and parsed ADF Description equal that content
and whose label set equals the registered set. Other fields pass through. Without firing
Alerts, no create is registered. Bulk and Service Management creates are always refused.
A refused first create gets a Jira-shaped 400 naming the field or endpoint and spends the
attempt without going upstream; every later create gets 409. Sentinel registration, validation
and spending use the same lock; clearing the sentinel clears the content and attempt too.

Run it on its own to point a jira-as on this machine at the real site through a sentinel:

```bash
python3 -m grafana_jsm_sandbox.forwarder
```

```
forwarding to https://example.atlassian.net as you@example.invalid
point jira-as at the Forwarder with a sentinel in place of the token:

    export JIRA_SITE_URL=http://127.0.0.1:61545
    export JIRA_API_TOKEN=<a fresh 32-character sentinel>

forwarded GET /rest/api/3/search/jql?jql=project+%3D+DEMO, upstream said 200
refused a GET /rest/api/3/myself with no valid sentinel
```

It reads `JIRA_SITE_URL`, `JIRA_EMAIL` and `JIRA_API_TOKEN` from its own environment and fails at
startup, naming every variable that is missing, rather than no-opping during the demo. The
Receiver owns it, and the spawner below registers each Run's sentinel around that Run.

The **Run spawner** — what the Receiver starts for each Notification, for real.

`RunSpawner` builds the Run's environment from scratch rather than inheriting one: the Anthropic
OAuth token, the Jira email, `JIRA_SITE_URL` pointing at the Forwarder over plain http,
`JIRA_API_TOKEN` set to that Run's sentinel, `JIRA_ALLOW_SITE_OPERATIONS` so the Run can ask Jira
what time it is, and `PATH`. Nothing else — not the real Jira token, not whatever else the
Receiver happened to be started with. The sentinel is registered with the
Forwarder before the process starts and cleared the moment it ends, so a sentinel that turns up in
a Transcript afterwards is worth nothing.

The Run's stdout is its Transcript, rendered into the log by the formatter as it arrives and
kept raw, line for line as it arrives, as `transcript.jsonl` in the Run's working directory,
whose path is logged when the Run starts. That copy is not trimmed or redacted: it is what the
log left out. It sits beside the Notification, inside the one directory a Run may read, and lasts
as long as the runs directory does, which in the container is a tmpfs emptied whenever the
container stops or is recreated. The spawner
also reads the Transcript's result event and hands the Receiver the reason a Run failed with its
exit status. Its stderr is captured and logged only if it exits non-zero, redacted like every
other line. A Run that outlives its timeout is killed and logged, and the queue behind it keeps
moving.

## Laptop mode: development only

**Present from the container, never from here.** Laptop mode is for working on the Receiver
itself. It has none of the container's boundary: a Run is a child of your own shell's user, with
your files and tools in reach of anything jira-as opens, the Receiver is not made non-dumpable
off Linux, and it listens on `0.0.0.0`, so anything on the same network can post a Notification
and start a paid Run that writes to Jira. The Quickstart does not use it.

The Receiver, the Forwarder and real Runs are one process — the demo container's main process,
and this on a laptop:

```bash
python3 -m grafana_jsm_sandbox
```

It refuses to start without a Jira credential, an Anthropic token and the demo's project key,
naming everything that is missing at once, so a half-filled env file is fixed in one pass rather
than three restarts. On the laptop it reads them from the shell's environment, not from `.env`.

| Variable | What it is |
| --- | --- |
| `JIRA_SITE_URL` | The real Atlassian site. Only the Forwarder ever sees it |
| `JIRA_EMAIL` | The account the Forwarder acts as |
| `JIRA_API_TOKEN` | The real token. It never reaches a Run |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | What a Run authenticates with. Set exactly one, leaving the other empty |
| `DEMO_PROJECT_KEY` | The dedicated project's key. No default |
| `DEMO_SEVERITY_FIELD`, `DEMO_URGENCY_FIELD`, `DEMO_SOURCE_FIELD`, `DEMO_MAJOR_INCIDENT_FIELD` | The project's `customfield_<n>` ids, checked for shape and rendered into the Skill; empty means the project lacks the field and a Run leaves it off |
| `RECEIVER_HOST` / `RECEIVER_PORT` | Where the Receiver listens. `0.0.0.0` and `8080` |
| `RUNS_DIRECTORY` | Where each Run's working directory goes, and the rendered Skill in `.skill`. `runs` |
| `SKILL_DIRECTORY` | The Skill's template, rendered at every start. This repo's `skill` |
| `RUN_TIMEOUT` | Seconds before a stuck Run is killed. `300` |
| `RUN_SETTLE_SECONDS` | Seconds after a Run ends before the next starts. `30`. This gives Jira's search index time to find the new Incident and avoids a duplicate |
| `RUN_MODEL` | The model every Run asks for, logged at startup. `claude-opus-5` |
| `RUN_BUDGET_USD` | The most one Run may spend, in dollars, as Claude Code estimates it (`--max-budget-usd`). No cap |

Then drive it with the canned Notification sequence — a Firing, a repeat Firing, a Resolved —
which is also the demo's fallback if Grafana is uncooperative:

```bash
python3 -m grafana_jsm_sandbox.replay --receiver http://localhost:8080 --pause 30
```

## Running the demo in the container

`docker compose up` is the whole demo: the LGTM stack the Alert fires from, one demo container
whose main process is the Receiver, the rolldice app the Alert is about, and the synthetic
traffic whose absence fires it — on one network so that Grafana's contact point can name `demo`
by service name. The [Quickstart](#quickstart) is the way from a clone to a running stack; this
section is what it brings up.

The LGTM stack is pinned to `grafana/otel-lgtm:0.33.0`, by tag and by the digest of its
multi-platform index (linux/amd64 and linux/arm64): the release that `latest` was on the
owner's laptop when it was pinned, on 2026-09-23. `latest` moves every week or so, and with the
rule's no-data state at OK a metric that drifted would leave the Alert silently never firing.
The pin carries Grafana 13.2.1, a major version past the 12.3.1 the owner's laptop ran in
mid-September, and the lifecycle measured below has yet to be rehearsed on it. `LGTM_IMAGE`, in the shell or
`.env`, names another image, such as the same one in an internal mirror.

The image carries only what a Run needs (ADR 0005). It is built from the slim official Node
image at a pinned tag, plus the distribution's Python 3 and TLS roots, and installs exactly Claude
Code and `jira-as` at pinned versions, this package and the skill. It runs as `demo`, a non-root
user the Dockerfile creates; the base image's own account and package managers are removed. There
is no `sudo`, no `docker` CLI or group, no `gh`, `git`, `curl` or `jq` — `ls /usr/local/bin` inside
the container includes `claude`, `jira-as`, `incident-payload`, `grafana-query`, `node`, `nodejs`,
`npm` and `npx`, and that is the answer to "what else can a
Run reach for". The entrypoint pre-accepts Claude Code's onboarding with Python's standard library
and the healthcheck asks the health endpoint the same way, because nothing else is there to do it
with. It mounts no Docker socket and holds no credential — those arrive at `docker compose up`
from `.env`, which git ignores and the build context refuses. The image is 539 MB; the developer
image it replaced was 4.35 GB.

The container runs the way Anthropic's secure-deployment guide describes a headless agent, and
the compose file is the whole list: every Linux capability dropped, `no-new-privileges`, a
read-only root filesystem, a process limit, and memory and CPU limits sized for three Runs in a
row on a laptop. The three directories a Run writes are tmpfs, and nothing else is writable:
`/tmp`, the runs directory, and the Run user's home, where the entrypoint writes the onboarding
flag and Claude Code its configuration and Transcripts. They are exactly what `docker diff`
lists after three Runs, and none survives a restart. The default test run reads each control
off the compose file; the opt-in stack checks read them back from the running container's
kernel, a write refused on the read-only root and accepted on each tmpfs among them, and say so
when a Compose too old to apply a limit has left it off (`pids_limit` needs Compose 2.2, `cpus`
2.17). Which controls are the guide's and which are this repo's is in the runbook's spoken
points.

On a laptop behind an intercepting proxy, one variable names the corporate root CA as a PEM
file under `certs/`, a directory git takes nothing from but the empty placeholder the build
defaults to. Both images install it into their system trust store before any `npm` or `pip`
install, and the demo image points Python, `requests`, pip and Claude Code at that store
through the standard trust-store variables, which each Run inherits alongside its model
credential, Jira sentinel and, when enabled, Grafana investigation settings. The runbook has
the presenter's steps.

```bash
EXTRA_CA_CERT=certs/corporate-root.crt docker compose up -d --build
```

The Receiver answers on the compose network at `http://demo:8080`, which is what Grafana will
post to, and on the laptop at `http://localhost:8080`, which is where the replay script posts by
default:

```bash
curl -fsS http://localhost:8080/health
python3 -m grafana_jsm_sandbox.replay --pause 30
```

Grafana is on the laptop at <http://localhost:3000>, anonymous admin, no login form.

Both are published on the laptop's loopback address and nowhere else, and OTLP is not published
at all: Grafana's anonymous user is an Admin, and anything that can post to the Receiver starts a
paid Run that writes to Jira. Three variables, in the shell or `.env`, move the laptop side and
never the containers' own ports, so the contact point is untouched:

| Variable | What it moves | Default |
| --- | --- | --- |
| `BIND_ADDRESS` | The laptop address both are published on | `127.0.0.1` |
| `GRAFANA_HOST_PORT` | Grafana's laptop port, when 3000 is taken | `3000` |
| `RECEIVER_HOST_PORT` | The Receiver's laptop port, when 8080 is taken | `8080` |

The replay script's default follows `BIND_ADDRESS` and `RECEIVER_HOST_PORT` as compose does:
from `.env`, with the shell's own over it.

### Firing the Alert for real

Grafana's contact point, notification policy and alert rules are provisioned from
[`grafana/provisioning/alerting`](grafana/provisioning/alerting), mounted read-only into the LGTM
container. Nothing inside the published image is edited; these three files are the whole of the
alerting configuration. Grafana reads the
directory once, at startup, so a change to any of the three files is `docker compose restart lgtm`.

| File | What it provisions |
| --- | --- |
| `contact-point.yaml` | `demo-receiver`, a webhook at `http://demo:8080/notification` |
| `notification-policy.yaml` | One route, everything to `demo-receiver`, grouped by `incident_group`: group wait 30s, group interval 1m, repeat interval **3m** |
| `alert-rule.yaml` | One group of four related rules on rolldice, evaluated every 10s, all labelled `incident_group=checkout-outage` |

The four rules, and about when each fires after `docker compose stop traffic`:

| Rule | Condition | Pending | Fires |
| --- | --- | --- | --- |
| `rolldice request rate is zero` | request rate zero (chapter one's rule) | 30s | ~1m |
| `rolldice successful responses have dropped` | fewer than half the expected 2xx answers a second | 30s | ~1m |
| `rolldice health probe is failing` | the synthetic probe completed no request in the last minute | 20s | ~1m30 |
| `rolldice outage is sustained` | request rate zero, held longer | 2m | ~2m40 |

Every rule watches `http_server_duration_milliseconds_count{service_name="rolldice"}`, which is
what the Python auto-instrumentation in the rolldice image actually exports to Prometheus — asked
of Prometheus with rolldice under traffic, not guessed — and nothing else, so nothing but the demo
app can fire the group. The rolldice app keeps exporting the counter after its traffic stops, so
the rate reads zero rather than going missing, and no-data is deliberately Normal on every rule so
that a rolldice that has not yet served a request starts no Run. The first two rules fire
together and arrive in one Notification; the probe rule joins on the next group interval; the
sustained-outage rule fires last, on purpose, as the related alert that exercises the update path.

**The grouping and the repeat interval override are the two things not to lose.** The policy
groups by `incident_group` alone: grouping by folder and alert name, Grafana's default, would send
each rule as its own Notification and start a Run, and a candidate Incident, per rule. Grafana's
default repeat interval is four hours, which means the group fires once and the repeat Firings
that add comments never arrive during a demo. `repeat_interval: 3m` in `notification-policy.yaml`
is the override, with the group wait at 30s so the rules that fire within seconds of each other
arrive together, and the group interval at 1m so a rule that fires later joins as an update.

The `traffic` service sends rolldice one request a second. The presenter's one action, and its
undo:

```bash
docker compose stop traffic
```

```bash
docker compose start traffic
```

Measured on the owner's laptop, from the container log: the Firing Notification arrives 70s after the
stop, the first repeat 70s after that, and the Resolved 20s after traffic is started again. The
whole lifecycle — Incident created, moved to Work in progress with a trend comment, Completed
with a resolution — took 3m30s, three Runs, $0.47. That was measured with Runs on Fable 5.1
and Grafana 12.3.1. Re-measured on 2026-09-24 with `verify --live`, on the pinned Grafana 13.2.1
with Runs on Opus 5: Firing 52s after the stop, the Incident 38s after that, the repeat about 70s
later, Normal 15s after traffic started again, Completed 22s after that. That is 3m18s from the stop
to Completed, three Runs, $1.13. `verify --replay` drove the same lifecycle in 85s for $1.14.

The canned fixtures under `fixtures/` are the three Notifications Grafana posted during that
rehearsal, so the replay script drives the same Alert, Fingerprint included. That is deliberate:
if the live Alert has already opened an Incident when the fallback is needed, the replayed Firing
comments on it rather than opening a second one, which is the demo working. It also means the
replay and the live Alert must not be run at the same time.

Everything a Run does arrives in `docker compose logs -f demo` through the formatter — its own
text, every `jira-as` command in full, every denial, and a `[FAILED]` line when it fails. Each
line starts with the time and a level.

### Fetching a Transcript

The log is trimmed; a Run's Transcript is not. Each Run's raw stream-json is kept as
`transcript.jsonl` in its working directory on the runs tmpfs, only until the demo container
stops or is recreated, so copy it out before a restart. The log names each one on a
`run <id> transcript:` line:

```bash
docker compose logs demo | grep 'transcript:'
```

Copy one out with its run id (`docker compose cp` cannot read a tmpfs). The `env -i` is the
healthcheck's pattern: a `docker compose exec` is handed both real tokens, and this way only
`env` holds them, for the instant before it starts `cat` with an empty environment
([ADR 0002](docs/adr/0002-jira-token-behind-localhost-forwarder.md)):

```bash
docker compose exec -T demo env -i /bin/cat /app/runs/<run id>/transcript.jsonl > transcript.jsonl
```

and render it the way the log window did:

```bash
python3 -m grafana_jsm_sandbox.log_formatter transcript.jsonl
```

It is raw, not redacted: it holds whatever Jira answered the Run, so keep it out of git and
share it with care. Its sentinel is worthless once the Run has ended.

To look around inside, the entrypoint honours a command:

```bash
docker compose run --rm demo sh
```

### Presenting it

[`docs/demo-runbook.md`](docs/demo-runbook.md) is the runbook: the three-window screen layout,
the pre-demo checks, every presenter action with what the audience sees and how long each wait
is, the five spoken points, the replay fallback, and the reset. Its numbers come from a timed
rehearsal recorded in the unpublished working notes.

Rehearsals leave Incidents behind, and the Incidents queue must start empty. The reset takes
every open Incident a Run made — the ones with an `fp-` label — out of the queue the only clean
way this workflow has, `Resolve` with a resolution and then `Close` (ADR 0004), and starts the
traffic so the rule goes back to Normal:

```bash
python3 -m grafana_jsm_sandbox.reset
```

It runs on the laptop against the project and credential in `.env`, prints what it did per key,
and exits non-zero if anything a human has to finish is still open or the traffic did not start.
It never cancels and never deletes, and it never closes an Incident that reached Completed
without a resolution, which would strand it in the queue; the next reset reopens it and takes it
out again. `--dry-run` lists what it would change and changes nothing.

## Layout

| Path | What it holds |
| --- | --- |
| `grafana_jsm_sandbox/receiver.py` | The Receiver, its Run queue and the `Run` record |
| `grafana_jsm_sandbox/notification.py` | Validation of an incoming Notification |
| `grafana_jsm_sandbox/log_formatter.py` | Rendering a Run's Transcript, and the redaction rules |
| `grafana_jsm_sandbox/forwarder.py` | The Forwarder, the sentinel check and the Jira credential |
| `grafana_jsm_sandbox/run_command.py` | The command line that starts one Run, and its allow list |
| `grafana_jsm_sandbox/run_spawner.py` | Starting one Run for real: its scrubbed environment, its sentinel |
| `grafana_jsm_sandbox/replay.py` | Posting the canned Notification sequence at a Receiver |
| `grafana_jsm_sandbox/reset.py` | Emptying the Incidents queue of a rehearsal's Incidents and restarting the traffic |
| `grafana_jsm_sandbox/demo_config.py` | Reading `.env`, the demo's project, and the environment a laptop helper's `jira-as` gets |
| `grafana_jsm_sandbox/configure.py` | Reading the project's field ids, workflow, queue and permissions off Jira, and writing the ids and queue to `.env` |
| `grafana_jsm_sandbox/doctor.py` | The ordered preflight: host, `.env`, Jira, the project's facts, the stack (and the container's own checks), Grafana |
| `grafana_jsm_sandbox/verify.py` | Watching one Incident's whole lifecycle on the project, replayed or live, stage by stage |
| `docs/demo-runbook.md` | The presenter's runbook: screen, checks, actions, spoken points, fallback, reset |
| `docs/admin-requests.md` | Each request an engineer forwards to a Jira, Atlassian, Claude or Docker admin, and how the commands detect the need |
| `.claude/skills/demo-setup/` | The Claude Code skill that walks an engineer through the Quickstart on their own site; not the Run's Skill |
| `grafana_jsm_sandbox/__main__.py` | The whole process: configuration, the Forwarder, the Receiver |
| `grafana_jsm_sandbox/nondumpable.py` | Making a process's `/proc` entries root's, for the Receiver and `doctor --in-container` |
| `skill/incident-sync/SKILL.md` | The template of the skill a Run follows to turn a Notification into Incidents |
| `grafana_jsm_sandbox/skill_template.py` | Rendering that template for `.env`'s project into the runs directory |
| `Dockerfile` | The demo image: slim Node plus Python, Claude Code, `jira-as`, the package and the skill, one non-root user |
| `docker/entrypoint.sh` | What the container starts: onboarding pre-accepted, then the Receiver |
| `docker-compose.yml` | The LGTM stack, the demo container, rolldice and its traffic, on one network |
| `docker/rolldice/` | The rolldice example app, copied from the `grafana/docker-otel-lgtm` examples under Apache-2.0, auto-instrumented |
| `certs/` | Where a corporate root CA goes for a build behind a proxy; only the empty placeholder is committed |
| `grafana/provisioning/alerting/` | The contact point, the notification policy and the related alert rules Grafana loads |
| `.env.example` | Every variable the demo reads, with placeholders; the project key left for you |
| `LICENSE`, `NOTICE` | MIT for this repository; the Apache-2.0 attribution for the copied rolldice files |
| `fixtures/notification-*.json` | The canned Notification sequence as Grafana really posted it: firing, repeat, resolved |
| `fixtures/run-transcript.jsonl` | A recorded Run Transcript, including a real denial |
| `fixtures/run-transcript-repeat-firing.jsonl` | A recorded Run that commented a trend on a real Incident |
| `fixtures/run-transcript-refused.jsonl` | A Run the API refused for want of usage credits, sanitized: `subtype: success`, `is_error: true`, exit 0 |
| `fixtures/jira/` | Sanitized answers of a made-up ITSM project, for `configure`'s tests: create metadata, workflow, queues, permissions |
| `tests/` | pytest, driving a real Receiver and Forwarder over real HTTP on ephemeral ports |

## Running the tests

Python 3.11 or newer. The runtime is standard library only; the dev dependencies are pytest
and PyYAML, which the container checks use to read `docker-compose.yml`. In a virtualenv, which
git ignores as `.venv`:

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e '.[dev]'
```

pip fetches setuptools, pytest and PyYAML from the package index for that; behind a registry
mirror, point pip at it.

`--basic-demo` runs only the basic demo's tests (chapter one: the Receiver, the Forwarder, the
Run and the laptop commands) and never imports chapter two's code; `tests/conftest.py` lists the
files. It is the run that checks what the Quickstart uses:

```bash
.venv/bin/python -m pytest --basic-demo
```

Without it, pytest runs everything, chapter two included, which takes a few minutes:

```bash
.venv/bin/python -m pytest
```

The default run is offline: no Jira, no model, nothing but real HTTP on ephemeral ports and real
child processes. The one test that touches Jira is opt-in: it is `verify` run as a test, so it
asserts by JQL that the canned sequence drove one Incident in the demo's project to `Completed`
with a resolution, stage by stage. It needs a Receiver already running, `jira-as` on the PATH and
a filled-in `.env`, whose project and credential it uses. `DEMO_END_TO_END=live` runs `verify
--live` instead, `DEMO_RECEIVER_URL` points the replay at another Receiver and
`DEMO_END_TO_END_RUN_TIMEOUT` gives each Run longer. Like `verify`, it closes and deletes nothing;
`reset` takes out whatever a failed run leaves open:

```bash
DEMO_END_TO_END=1 python3 -m pytest tests/test_end_to_end.py
```

The checks that need the container are opt-in the same way, and need nothing but `docker compose
up -d` first. They ask the questions compose cannot answer on its own: whether the health
endpoint answers the laptop and the `lgtm` container, whether the Receiver is really running
as a user who is not root with the allowed executables on its PATH (including `grafana-query`), and whether
`sudo`, `docker`, `gh`, `git`, `curl` and `jq` are really absent from it, along with any `docker`
group, on a Node new enough to read the operating system trust store. When the shell's
`EXTRA_CA_CERT` names a certificate, they also find its fingerprint in the container's bundle and
confirm Python's default SSL context loads it; when it names none, that nothing was added.

```bash
DEMO_CONTAINER=1 python3 -m pytest tests/test_container.py
```

The same flag runs the Grafana checks, which ask the running Grafana what it was provisioned with
rather than reading the files back — a typo in a provisioning file makes Grafana skip it and say
so only in its own log. They check the contact point aims at the Receiver on the compose network,
the policy groups by `incident_group` on the demo timings, every rule carries that label, the
rules evaluate every ten seconds and the first fires after thirty, each rule's own query matches a
series rolldice really exports, every rule is Normal while traffic flows, and the canned fixtures
describe the Alert Grafana is provisioned to send:

```bash
DEMO_CONTAINER=1 python3 -m pytest tests/test_grafana.py
```

The rule set itself is checked offline, by default, in `tests/test_alert_rules.py`: it reads the
provisioning files and holds every related rule to the `incident_group` label, the policy to
grouping by it with the demo timings, and every query to the demo app's series and nothing else.

Everything else in `tests/test_container.py` runs by default and builds nothing: it reads the
committed `Dockerfile`, `docker-compose.yml` and `.env.example` and drives them against the code
they configure — the example is fed to the real configuration reader, its values through the real
redaction, the ignore rules through real `git check-ignore`, and the entrypoint is run under `sh`
on a PATH holding only what the slim image carries. It holds the Dockerfile to ADR 0005: the base
is the slim Node image at a pinned tag, Claude Code and `jira-as` are pinned, the distribution
adds nothing but TLS roots and a Python, no line installs an escalation tool, and the last `USER`
is one the Dockerfile created. It holds both Dockerfiles to the certificate mechanism: the
corporate CA is installed before anything reaches npm or PyPI, the trust-store variables point at
the system bundle, compose hands the same argument to both builds, and git ignores everything in
`certs/` but the placeholder. It also holds compose to the three things the live Alert depends
on: every service on the one network, this repo's provisioning directory mounted where Grafana
reads it, and a stopped `traffic` staying stopped.

## License

MIT, in [LICENSE](LICENSE). The three files under `docker/rolldice/` are copied from
[grafana/docker-otel-lgtm](https://github.com/grafana/docker-otel-lgtm) and stay under the
Apache License 2.0; [NOTICE](NOTICE) says which, and what was changed.
