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
| `$DEMO_SESSION_ID` | `[a-z0-9-]{1,32}`, starting with a letter, with no hyphen before a digit (jira-as would read `reh-1` as an issue key). Use a new value per rehearsal (`reh1`, `reh2`, …) and a final value for the demo |

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
4. `doctor --only stack --with-model`: one small paid call, about $0.12.
5. The first lifecycle, `verify --mvp --replay` then `--live` (section 4). The skill asks before each one.

Tell the session your model budget up front, for example **"the model budget is $20 in total"**.

If Claude Code's **auto mode** refuses the helpers as "production reads", run the session in default mode, or add
allow rules for `configure`, `doctor`, `verify` and `reset` to the git-ignored `.claude/settings.local.json`.

## 4. Prove it: `verify --mvp` (paid; keep to your budget)

1. `verify --mvp --replay` replays grouped alerts through the real Run and Jira. It expects:
   - one Incident with `grp-checkout-outage` and `ses-$DEMO_SESSION_ID`, carrying at least two `fp-` labels;
   - comments for repeated and related alerts, with no duplicate;
   - Completed after the resolve.
2. `verify --mvp --live`: the same, driven by stopping and restarting real traffic.

Each lifecycle costs roughly $1–2. Before and after each lifecycle, total the Receiver's displayed Run costs:

```bash
docker compose logs --no-log-prefix demo | python3 -m grafana_jsm_sandbox.run_costs
```

This prints each priced `[result]` line and the total; `verify` prints no costs. Add about **$0.12 for each
`doctor --with-model`**, including retries, because those calls run outside the Receiver. Record the total before
recreating or removing demo and carry it forward, adding the new container's total. Repeated snapshots of the same
container replace its subtotal; do not add them twice. Failed Runs and results without cost lines are absent from
this estimate: account for them separately using the organisation's usage records. **Stop at your budget.**

Change `DEMO_SESSION_ID` before each rehearsal, so earlier rehearsal Incidents never match.

## 5. The demo itself

1. Set a fresh `DEMO_SESSION_ID`, then restart the stack if `.env` changed.
2. Open Grafana (alerting) and the Jira queue side by side.
3. Stop the demo traffic (`docker compose stop traffic`), as `verify --mvp --live` does. The measured rule
   timeline after the stop is: 2xx drop at about 45 s, rate zero at 65 s, health probe at 90 s and sustained outage
   at 151 s. All four share `incident_group=checkout-outage`.
4. With `group_wait: 30s`, `group_interval: 1m` and `repeat_interval: 3m`, the first Notification arrives about
   **75 s after the stop, carrying 2 alerts**. **One** Incident appears once that Run finishes, typically 1–2
   minutes after the Notification.
5. The health probe joins the Notification at about 135 s and the sustained outage at about 195 s after the stop.
   Each arrives as an update to the **same** Incident about a minute apart, plus the Runs' time and any queueing.
   Wait for a repeat comment too; `verify` requires the sustained-outage fingerprint and a separate repeat update
   before restarting traffic.
6. Restart traffic (`docker compose start traffic`). Every rule is inactive within about 20 s. The Incident moves
   to the configured done status within about a minute of the restart, **plus that Run's time**.

## 6. Reset and teardown

Run `reset` (it asks before closing any leftover `fp-` or `grp-` Incidents), then `docker compose … down`.

## Troubleshooting

See `.claude/skills/demo-setup/READING-OUTPUT.md` for `doctor` and `verify` output.
