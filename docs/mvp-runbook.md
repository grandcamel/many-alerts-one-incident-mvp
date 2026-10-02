# MVP runbook

**Status:** proven end to end. `verify --mvp --replay` and `verify --mvp --live` both end `VERIFIED` against a real
Jira Service Management project with a real Claude Run, and a replay against the local fake Jira covers a custom
Incident workflow.

The whole stack, a real Run included, can be rehearsed without a real Jira against a local fake one, on either the stock
or a custom Incident workflow: `docs/local-fake-jira-rehearsal.md`.

This runbook is self-contained. A fresh Claude Code session on the machine that runs the demo can start from
**"Follow docs/mvp-runbook.md"**. The session starts cold: read each file before editing it.

**What the MVP shows:** a fault makes several related Grafana alerts fire. One Claude Run creates **one** Jira
Incident. Repeated or related alerts **update** that Incident (labels and comments); they never duplicate it. Restoring
service closes it. The design is in `docs/mvp-spec.md`.

## Variables (the presenter supplies these; none are written into the repo)

| Variable | Meaning |
|---|---|
| `$JIRA_SITE_URL` | The Jira site, as `https://<site>.atlassian.net` |
| `$PROJECT_KEY` | A JSM project with an `Incident` issue type |
| `$JIRA_EMAIL` / `$JIRA_API_TOKEN` | An account that can create, edit, comment on and transition issues in that project |
| `$ANTHROPIC_API_KEY` | An Anthropic API key (or set `CLAUDE_CODE_OAUTH_TOKEN` instead; exactly one) |
| `$DEMO_SESSION_ID` | `[a-z0-9-]{1,32}`, starting with a letter, with no hyphen before a digit (jira-as would read `reh-1` as an issue key). Use a new value for every take, rehearsals and the demo itself (`opus1`, `sonnet1`, `haiku1`, …; section 5) |

## 0. Prerequisites

- Docker Desktop with Compose v2 (Compose 2.17 or later applies `cpus`).
- `git`.
- Claude Code.
- Python 3.11 or later for the host-side helpers.
- **Corporate network:** if the laptop's traffic passes through a TLS-inspecting proxy, put the corporate root CA
  (`.pem`) in `certs/` before building (see `certs/NO_EXTRA_CERTS` and the README). `doctor` reports when it's needed.

## 1. Get the code

```bash
git clone https://github.com/grandcamel/many-alerts-one-incident-mvp.git && cd many-alerts-one-incident-mvp && git pull --ff-only
```

If you commit from the machine that runs the demo, set a repo-local git identity first (`git config user.name …`,
`git config user.email …`).

## 2. `.env` (the presenter does this, in their own editor)

```bash
cp .env.example .env
```

Fill in `JIRA_SITE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `DEMO_PROJECT_KEY`, `ANTHROPIC_API_KEY` and
`DEMO_SESSION_ID`. Leave `CLAUDE_CODE_OAUTH_TOKEN` empty: use exactly one model credential. **Never paste a token into
chat.** Claude never reads `.env`; the repo's settings deny it.

## 3. Setup, driven by the repo's own skill

Start Claude Code in the repo and say **"set up the demo"**. That invokes `.claude/skills/demo-setup`, which runs, in
order, asking before every Jira write or paid step:

1. `configure`: reads the project's field IDs, service desk and queue from the site (read-only).
2. `configure --write`: with the presenter's yes, writes those facts into `.env`, including the `DEMO_STATUS_*`
   variables from the project's Incident workflow. On a workflow that isn't the stock ITSM one, `configure` prints
   `WARN statuses: … proposed DEMO_STATUS_OPEN=…, DEMO_STATUS_IN_PROGRESS=…, DEMO_STATUS_DONE=…,
   DEMO_STATUS_CLOSED=(empty, no close step)`. Check that the proposal names the created, in-progress and resolved
   statuses (never a cancel status) before saying yes. Runs only ever move an Incident to the in-progress and done
   statuses; any other open status is left to a human.
   Severity, Urgency, Source and Major incident fields the project lacks are written empty, and Runs leave them off;
   Priority keeps the project's default.
3. `doctor --only host,env,jira,facts`, then `docker compose … up -d --build`, then `doctor --only stack,grafana`.
4. `doctor --only stack --with-model`: one small paid call, about $0.12. It reports the model the Run asked for beside
   the model that answered (section 5, "Model preflight").
5. The first lifecycle, `verify --mvp --replay` then `--live` (section 4). The skill asks before each one.

Tell the session your model budget up front, for example **"the model budget is $20 in total"**.

**The Incidents queue.** The demo opens one queue beside Grafana, and `DEMO_QUEUE_URL` in `.env` is its address. A
completed Incident must leave it, so the queue's JQL must filter on `resolution = Unresolved`.

- `configure` first looks for a queue named `Incidents` and takes it when exactly one has that name. It warns when
  that queue's JQL does not filter on the resolution.
- When no queue has that name, or several do, `configure` takes the one queue whose JQL is exactly the project,
  `issuetype = Incident` and `resolution = Unresolved`, with no other condition, and only when exactly one queue
  qualifies. It prints the queue's name, so you can see what it chose.
- When it cannot choose, it leaves `DEMO_QUEUE_URL` as it is, prints a `queue` WARN that says why, and lists each
  candidate as `candidate "<name>" (id <n>): <address>; JQL: …`. `doctor`'s `queue url` line then says to set the
  address by hand, and does not suggest `configure --write`, which would write nothing.
- To set it by hand, in your own editor: open the project's Queues in Jira, click the queue that shows the open
  Incidents, and copy the address from the browser, `<site>/jira/servicedesk/projects/<KEY>/queues/custom/<id>`, into
  `DEMO_QUEUE_URL`. If no queue shows them, create one with the JQL
  `project = <KEY> AND issuetype = Incident AND resolution = Unresolved ORDER BY created DESC`. Then run `configure`
  again: it checks that the address is on the demo's site, names this project's key and is a queue of the project's
  service desk (a FAIL when not), and warns when its JQL lets a resolved Incident stay in it.

If Claude Code's **auto mode** refuses the helpers as "production reads", run the session in default mode, or add
allow rules for `configure`, `doctor`, `verify` and `reset` to the git-ignored `.claude/settings.local.json`.

## 4. Prove it: `verify --mvp` (paid; keep to your budget)

1. `verify --mvp --replay` replays grouped alerts through the real Run and Jira. It expects:
   - one Incident with `grp-checkout-outage` and `ses-$DEMO_SESSION_ID`, carrying at least two `fp-` labels;
   - comments for repeated and related alerts, with no duplicate;
   - Completed after the resolve, with a resolution.

   It also reads what the Runs wrote, in the stage where each fact first shows: the Summary names the group and the
   firing count; the Description names each firing Alert and carries its generator URL; the opening comment names each
   firing Alert with a value; an update comment lists the Alerts as New, Repeat and Resolved; the closing comment gives
   the duration, the Alert count and the Run count. Order does not matter. An Incident that is complete in every
   label and status but has the Description `Test` ends `NOT VERIFIED: created — …` and names the Description.
2. `verify --mvp --live`: the same, driven by stopping and restarting real traffic. It waits for a repeat comment
   before it restarts the traffic, which the presenter's shortest take does not (section 6).

Each lifecycle costs roughly $1–2. Before and after each lifecycle, total the Receiver's displayed Run costs:

```bash
docker compose logs --no-log-prefix demo | python3 -m grafana_jsm_sandbox.run_costs
```

This prints each priced `[result]` line and the total; `verify` prints no costs. Add about **$0.12 for each
`doctor --with-model`**, including retries, because those calls run outside the Receiver. Record the total before
recreating or removing demo and carry it forward, adding the new container's total. Repeated snapshots of the same
container replace its subtotal; do not add them twice. Failed Runs and results without cost lines are absent from
this estimate: account for them separately using the organisation's usage records. **Stop at your budget.**

## 5. Before every take

A take is one stop of the traffic and the lifecycle that follows it. Do these three things before each one.

### A new session id

Give every take its own `DEMO_SESSION_ID`: `opus1`, `sonnet1`, `haiku1`, and `opus2` for the next Opus take. The id is
the `ses-<id>` label on every Incident the take creates and part of every Match search, so no earlier take's Incident
can match, and the history of each take stays apart. A completed Incident is not a Match anyway, so a reused id does
not cause cross-take updates, but the log and the queue become hard to read.

The rules, from `demo_config`: 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter, with no hyphen
before a digit (jira-as would read `ses-reh-1` as an issue key and refuse every search). `reh1` is fine; `reh-1` is
not.

1. Set `DEMO_SESSION_ID` in `.env`, in your own editor.
2. Recreate the demo container so the Receiver renders the Skill and the label from the new value. The compose
   service is `demo`:

   ```bash
   docker compose up -d demo
   ```

   Do not use `docker compose restart demo`: a restart keeps the environment the container was created with, and
   the old id stays in force.
3. Check it. `python3 -m grafana_jsm_sandbox.doctor --only env` prints `[env] OK session — DEMO_SESSION_ID=<id>, so
   this take's Incidents carry ses-<id>` for `.env`, and the Receiver's start-up log line
   `skill rendered for project <KEY>, session label ses-<id>, at …` (`docker compose logs demo`) shows the
   container has it.

### Model preflight

`RUN_MODEL` in `.env` is the configured model, and the Receiver's start-up log says only that: `runs use model <name>
(RUN_MODEL)`, followed by a line that start-up does not check that the Claude seat can run it. It proves which string
each Run will be given, nothing more; a misspelled name or a model the seat may not use shows up as a failed Run. The
`[run] model=…` line of a Run's log is what Claude Code reports it started with, so it does not show the model that
answered either.

Before a take on a model you have not tried, and before any public demo on a newly chosen one, recreate the container
(above) and run the model preflight, which is one small paid call, about $0.12:

```bash
python3 -m grafana_jsm_sandbox.doctor --only stack --with-model
```

It starts one real Run in the container and prints a `[model]` line that gives the requested model beside the one that
ran, read from the Run's Transcript:

- `OK`, `requested claude-opus-5, ran claude-opus-5`: the same.
- `OK`, `requested opus, ran claude-opus-5: the same model, as Claude Code names it; RUN_MODEL=claude-opus-5 pins it`:
  an alias, resolved. Pin the full name before a presentation, because the alias moves with releases.
- `WARN`, `requested X, but ran Y: that is not the same model`: the seat chose for the Run, or `X` is misspelled. Set
  `RUN_MODEL` to a model the seat can run, then `docker compose up -d demo`, and run the preflight again.
- `WARN`, `no model answered the Run, so which one ran is not known`: the Transcript names no model, so all that is
  known is what Claude Code started with. Check the `run` line beside it.

Write model ids as Claude Code names them, with hyphens and no dots: `claude-opus-5` (the default), `claude-sonnet-5-5`
for Sonnet 5.5 and `claude-haiku-4-5` for Haiku 4.5. Start-up accepts a name with a dot as readily as one without and
cannot say whether the seat will run it. This repo has not checked the Sonnet and Haiku ids against a seat; the
preflight is how you do.

### Settle

Before `docker compose stop traffic`, every related Grafana rule must be back to Normal, and Alertmanager must have
let go of the last take's group. All four rules, in the `demo` folder's `rolldice` group (`rolldice request rate is
zero`, `rolldice successful responses have dropped`, `rolldice health probe is failing` and `rolldice outage is
sustained`), show Normal in Grafana's alert rule list. (`verify` checks only the first.)

Alertmanager is the slower part. The group's timings are `group_wait: 30s`, `group_interval: 1m` and
`repeat_interval: 3m` (`grafana/provisioning/alerting/notification-policy.yaml`). After the traffic restarts:

| Step | Time after the restart |
|---|---|
| Every rule is Normal | about 20 s |
| The Resolved Notification goes out at the group's next tick, one `group_interval` at most | up to 1 m 20 s |
| The next tick after that, by which Alertmanager has dropped the resolved Alerts and the empty group | up to 2 m 20 s |

So **wait 3 minutes after the traffic restart**, which is also `repeat_interval`, and in any case until the closing
Run's `run … finished` line has appeared in the log. These numbers are derived from the timings above and from how
Alertmanager is documented to group, not measured.

A fresh take's first Notification normally carries 2 Alerts (`notification accepted: 2 alerts, run … queued`,
section 6). More than two is a cue to inspect that Notification, not proof that an earlier group remains: delayed
delivery or coalescing can bring three or four fresh firing Alerts together. If the Notification actually carries
resolved Alerts from an earlier take, restart the traffic, run `reset`, wait the three minutes, give the next take a
new id and begin again. The Incident that Run opened labels every Alert in its Notification, as the Skill says to,
but its Summary and Description cover only the firing ones, which reads as confusing on screen.

Nothing in the repo reports lingering resolved Alerts before a take. The check above is a wait and a look at the first
Notification.

## 6. The demo itself

1. Do the three things in section 5, then open Grafana (alerting) and the Jira queue side by side.
2. Stop the demo traffic (`docker compose stop traffic`), as `verify --mvp --live` does. The measured rule
   timeline after the stop is: 2xx drop at about 45 s, rate zero at 65 s, health probe at 90 s and sustained outage
   at 151 s. All four share `incident_group=checkout-outage`.
3. With `group_wait: 30s`, `group_interval: 1m` and `repeat_interval: 3m`, the first Notification arrives about
   **75 s after the stop, carrying 2 alerts**. **One** Incident appears once that Run finishes, typically 1–2
   minutes after the Notification.
4. The health probe joins the Notification at about 135 s and the sustained outage at about 195 s after the stop.
   Each arrives as an update to the **same** Incident about a minute apart, plus the Runs' time and any queueing.
5. **The cue to restart the traffic** is the sustained-outage update's Run finishing, not a clock. In the log
   (`docker compose logs -f demo`) it is this sequence, with the Run's `[claude]` lines and its other `jira-as` calls
   left out:

   ```
   notification accepted: 4 alerts, run … queued, 0 ahead
   run … started in …
   [tool]   Bash: incident-payload update --key <KEY>-n --labels … --created … --server-time …
   [tool]   Bash: jira-as collaborate comment add <KEY>-n -b 'Update: 4 firing. New: rolldice outage is sustained (fp-…) value=…. Repeat: …'
   [claude] ok: checkout-outage <KEY>-n updated and moved to <in-progress status>
   [result] success in …
   run … finished with exit status 0 in …
   ```

   The comment says `New: rolldice outage is sustained`, and the `finished` line follows it. That is about 195 s after
   the stop plus the Run's own 20 to 30 s, so about 4 minutes after the stop. Restart the traffic then
   (`docker compose start traffic`).
6. Every rule is inactive within about 20 s. The Incident moves to the configured done status within about a minute
   of the restart, **plus that Run's time**. The queue is then empty, because it lists only unresolved Incidents,
   once Jira's search index catches up (10 to 20 s).

**The shortest lifecycle take** is the path above: create, the probe's update, the sustained outage's update, and the
resolve, four Runs. It never shows an unchanged repeat. The reason to restart on the cue is that Grafana resends an
unchanged firing group `repeat_interval` after the last Notification that changed it, so the first repeat arrives
about 375 s (195 s plus 3 minutes) after the stop. A take that leaves the traffic stopped past that gets a comment-only
Run, `Update: 4 firing. New: none. …`, and each further 3 minutes another, which costs a Run each (about a third of a
dollar each on Opus 5, in the takes this was written from) and makes the audience wait without a new fact.

**A repeat-focused take** is the one where the repeat is the point: leave the traffic stopped until the repeat's
comment appears, about 6 minutes after the stop, then restart it on that Run's `finished` line. `verify --mvp --live`
takes this path, because it requires a separate repeat update before it restarts the traffic. State which take you are
giving before you start, so nobody reads a missing repeat as a failure.

## 7. What a Run does now

Three changes since the first rehearsals show in the log and in Jira.

- **The Run writes no Jira payload.** The Skill has it run `incident-payload match`, `create`, `update` or `close`, a
  local command that reads `notification.json` and the project facts the Receiver rendered beside the Skill, and
  prints complete one-line `jira-as` commands. The Run runs them as printed. It still decides whether there is a Match
  and whether to create, update, close or skip. In the log, `[tool] Bash: incident-payload …` comes before the
  `jira-as` call it printed. The allow list is `Bash(jira-as *)`, `Bash(incident-payload *)` and the `Read` of the runs
  directory (ADR 0003's 2026-10-01 amendment).
- **One create attempt per Run, enforced by the Forwarder.** The first issue create a Run makes is its attempt, and the
  spawner registers the create fields `incident-payload create` would print for that Run's Notification. The
  Forwarder admits a single-issue create only when `fields.summary` and the parsed ADF `fields.description` equal
  those fields, and the set of `fields.labels` equals the registered set. Other fields pass through. Nothing firing
  means no create is registered. Bulk and Service Management creates are always refused. Any refused first create
  is answered 400, names the differing field or forbidden endpoint, and spends the attempt without going upstream.
  Every later create is answered 409.
  The log shows either as a WARNING `refused a POST …` from the Forwarder and a
  `[DENIED] Jira create refused by the Forwarder: …` line. The Run then begins its final message `failed: <why>`, which
  the log shows as `[FAILED] run reported failed: <why>` and the Receiver as `run … FAILED: …`, though Claude Code
  calls the Run a success. A successful Finish starts `ok: ` before any group text; a failed Finish starts
  `failed: `. The formatter reads only the first non-empty line of a `success` result, case-sensitively, so
  `ok: failed DEMO-12 created` succeeds and `FAILED: …` is not a failure marker. A refused first create leaves no Incident behind (ADR 0002's 2026-10-01 amendment).
- **A close is checked.** After the transition to the done status, the Run reads `status` and `resolution` of the
  Incident, and ends `failed:` if it is done with no resolution. Until the Jira admin puts Resolution on the Resolve
  screen (`docs/admin-requests.md#jira-admin-resolution-screen`), each close also shows a WARNING
  `forwarded POST … upstream said 400` on the transition and a retry that returns 204. That is the screen refusing the
  resolution, not a Run failing, and the Incident still completes.

Reads are narrow too: the Match search returns `key,status,labels,created`, every `issue get` names its `--fields`, and
every JQL carries `project = <KEY>`, so a Run should log no `Output too large` and no refused JQL.

## 8. Reset and teardown

Run `reset` (it asks before closing any leftover `fp-` or `grp-` Incidents), then `docker compose … down`. After a
`reset` that stopped a take partway, settle (section 5) before the next one.

## Troubleshooting

See `.claude/skills/demo-setup/READING-OUTPUT.md` for `doctor` and `verify` output.
