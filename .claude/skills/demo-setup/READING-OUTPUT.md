# Reading the commands' output

The line formats below are stable: the commands print them for the engineer and for this skill
alike. Each module's docstring is the source; this is the part the stages act on.

## Verdicts and exit codes

**configure** (`python3 -m grafana_jsm_sandbox.configure [--write]`)

```text
OK   <check>: <what it found>
WARN <check>: <what is off, what it costs>[; ask: docs/admin-requests.md#<anchor> ...]
FAIL <check>: <what stops the demo>[; ask: docs/admin-requests.md#<anchor> ...]
.env: not checked: <NAME>, ...; left as .env has them
.env: up to date | .env: <n> change(s) planned; ... | .env: <n> change(s) written; ...
- <NAME>=<value .env has now>
+ <NAME>=<value configure found>
READY | NOT READY: <check>: <what the first FAIL said>
```

Checks: `project`, `permissions`, `issue type`, `severity`, `urgency`, `source`,
`major incident`, `create screen`, `statuses`, `resolution`, `service desk`, `queue`,
`component`, `dedicated`. A FAIL names the request that fixes it; a `severity`, `urgency` or
`source` WARN names an optional one, which the engineer forwards only if they want that field
on the demo's Incidents. `READY` is about the project; the `.env:`
line says whether `--write` still has work. Exit 0 `READY`, 1 `NOT READY`, 2 a usage or `.env`
error before Jira was asked (its sentence is on stderr).

**doctor** (`python3 -m grafana_jsm_sandbox.doctor [--only LAYER,...] [--with-model]`)

```text
[<layer>] OK|WARN|FAIL <check> — <message>[; ask: docs/admin-requests.md#<anchor> ...]
not checked: <layer>, ...; an earlier layer failed
READY | NOT READY: [<layer>] <check> — <what the first FAIL said>
```

Layers in order: `host`, `env`, `jira`, `facts`, `stack`, `grafana`; from inside the container,
`container` and `model`. It stops at the first layer with a FAIL. A WARN may name a request too,
when an admin could take its cost away. Exit 0 `READY`, 1 `NOT READY`, 2 bad arguments or an
old Python.

**verify** (`python3 -m grafana_jsm_sandbox.verify [--replay | --live]`)

```text
[+<seconds>s] WAIT|OK|WARN|FAIL|NOTE <stage> — <message>[; ask: docs/admin-requests.md#<anchor>]
VERIFIED: <key> Open → Work in progress → Completed with resolution <name> in <seconds>s
NOT VERIFIED: <stage> — <what the first FAIL said>
```

Stages: `preflight`; `posted` before each Run's stage (replay) or `traffic stopped` and
`firing` (live); `created`, `commented`, `work in progress`; `traffic started` and `normal`
(live); `completed`; `cleanup` (NOTE) last; `interrupted` after a Ctrl-C. After a FAIL in
`--live`, a way-out `traffic started` WAIT then OK (or a second FAIL) may follow. Exit 0
`VERIFIED`, 1 `NOT VERIFIED`, 130 interrupted, 2 bad arguments, a `.env` error or an old
Python.

**verify --mvp** (`python3 -m grafana_jsm_sandbox.verify --mvp [--replay | --live] [--session ID]`),
the MVP's proof: the same line shapes and exit statuses, and the verdict

```text
VERIFIED: <key> created with <n> fp- labels → updated → <label> added → Completed with resolution <name> in <seconds>s
```

Stages: `preflight`; `posted` before each Run's stage (replay) or `traffic stopped` and
`firing` (live); `created`, `grouped`, `updated`, `related`; `traffic started` and `normal`
(live); `completed`. `FAIL one incident` at any stage means two open Incidents carry the same
group and session labels: the promise is broken, so stop and show the engineer both keys. A
`DEMO_SESSION_ID` error is exit 2 before anything is asked: the engineer fixes `.env`.
`--session` takes the literal id, not the label: `ses-x` is watched as `ses-ses-x`.

`grouped` waits for the creation labels **and the opening comment** before recording the
baseline. In replay, `updated` needs a further comment. In live mode, `related` needs the
sustained-outage Alert's own `fp-` label (read from Grafana's Alertmanager API) and a comment
naming it as new. `updated` needs a comment reporting `New: none`, plus at least two comments after the opening baseline.
A health-probe update cannot pass either check. The stages can finish in either order.
Remaining in the open status after an update is a WARN; it does not fail the one-Incident proof.

**reset** (`python3 -m grafana_jsm_sandbox.reset [--dry-run]`)

```text
<KEY>: [would be ]completed with resolution Done and closed
<KEY>: <why it was left for a human>
<KEY>: open without a fp- label, so not a Run's; left alone
<KEY>: done without a resolution, so in the Incidents queue for good; only `jira-as api call deleteIssue ...` removes it, ...
```

A dry run then prints `traffic would be started`, `dry run: nothing was changed` and
`queue would be empty` or `queue would NOT be empty`. A real run prints `traffic started` or
`traffic NOT started: <why>`, and ends `queue is empty`,
`queue is empty; <n> left for a human to close` or `queue is NOT empty`. Exit 0 when nothing is
left (and, for real, the traffic started), else 1; a `.env` error is exit 1 with its sentence on
stderr.

## Acting on a blocker

Work from the first blocker only: later lines may be its consequences.

- **`; ask: docs/admin-requests.md#<anchor>`.** Read that section, show its fenced request with
  the placeholders you know filled in, and say who it goes to. The engineer sends it. Go on with
  whatever does not depend on it; rerun the command once the engineer says it is done. An
  `ask:` on a WARN line is optional and blocks nothing: show it once, say what it would add,
  and go on whether or not the engineer sends it.
- **A fix in the message.** Most FAIL lines end with the command or change that fixes them. Run a
  command of this skill's yourself (with consent when it writes to Jira); hand a change to
  `.env` or to the engineer's accounts to the engineer.
- **Exit 2.** The sentence names a configuration gap before anything was asked: no `.env`
  (stage 4), a missing credential or key (the engineer's edit), no `jira-as` or an old Python
  (stage 2).

By layer or stage, where the line alone may not say enough:

| Blocker | What to do |
| --- | --- |
| `[host]` Docker not answering | The engineer starts Docker Desktop; rerun. |
| `[host]` a port in use | The line names the variable that moves it (`GRAFANA_HOST_PORT`, `RECEIVER_HOST_PORT`): the engineer frees the port or sets it in `.env`. |
| `[env]` a placeholder or malformed value | The engineer edits the variable named. An `sk-ant-api` token belongs in `ANTHROPIC_API_KEY`; OAuth output belongs in `CLAUDE_CODE_OAUTH_TOKEN`. Leave the other empty. |
| `[jira]` 401 | The email and token do not match, or the token expired or is blocked: a new token; when none can be made, `docs/admin-requests.md#atlassian-org-admin-api-tokens`. |
| `[jira]` 403 naming the IP allowlist | `docs/admin-requests.md#atlassian-org-admin-ip-allowlist`, or the engineer joins the VPN. |
| `[jira]` 404 | `JIRA_SITE_URL` is not the site: the engineer corrects it. |
| `[jira]`, or any `configure`, `verify` or `reset` line, saying `CERTIFICATE_VERIFY_FAILED`, `certificate verify failed` or `SSLError` | An intercepting proxy: SKILL.md stage 3, "Behind an intercepting proxy". When the prefix is already there, the file in `certs/` is not the root the proxy signs with, or some hosts bypass the proxy and need the runbook's combined bundle. |
| `[facts]` an id in `.env` the project does not give | Rerun `configure`, write with consent, then `docker compose up -d demo` when the stack is up. |
| `[stack]` demo not running, or `unhealthy` | `docker compose logs --tail 50 demo`: the Receiver names what it refused on. Then `docker compose up -d`. |
| `[stack]` or `[container]` names the key or `.env` changed | `docker compose up -d demo` recreates it; `docker compose restart` keeps the old environment. |
| `[container]` or `[stack]` says the image predates something | `docker compose up -d --build demo`, with the `EXTRA_CA_CERT` prefix behind a proxy. |
| `[container]` Jira check failing on a certificate, or a `[model]` Run failing to reach Anthropic on one | The image was built without the corporate CA: stage 3's proxy branch, then `docker compose up -d --build demo` with the `EXTRA_CA_CERT` prefix. |
| `[grafana]` anything but a first-minute `series` | Report the line to the engineer; the provisioning files are the repo's and stay as they are. |
| `[model]` FAIL naming `claude-org-owner` | The seat's managed rules, credits or model list: show that request. |
| `[model]` token refused | The engineer replaces the API key in `ANTHROPIC_API_KEY`, or reruns `claude setup-token` and replaces `CLAUDE_CODE_OAUTH_TOKEN`, according to the chosen route. Leave the other empty, then `docker compose up -d demo`. |
| `[model]` model not available | The engineer sets `RUN_MODEL` in `.env` to a model the seat has, then `docker compose up -d demo`. |
| `docker compose up` refused a pull | `denied` or `unauthorized`: `docs/admin-requests.md#docker-admin`. `x509`: Docker Desktop's own daemon does not trust the corporate CA, a Docker Desktop setting outside this repo (`docs/demo-runbook.md#on-the-work-laptop-the-corporate-ca`, last paragraph); the engineer pulls the images on another network or asks their Docker admin. `toomanyrequests`: wait, or a mirror. |
| `docker compose up --build` failing inside the build on a certificate: npm's `SELF_SIGNED_CERT_IN_CHAIN` or `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, pip's `CERTIFICATE_VERIFY_FAILED` | An intercepting proxy: SKILL.md stage 3, "Behind an intercepting proxy", then the same `up` with the `EXTRA_CA_CERT` prefix. |
| The build stops with `EXTRA_CA_CERT is not a PEM certificate` | The export was DER: the runbook's step 1 converts it. |
| verify `preflight` names `reset` | An open Incident already carries the Alert's label: stage 9, then rerun. |
| verify `preflight`, rule Firing or Pending | Traffic is stopped or just restarted: `docker compose start traffic`, wait for Normal, rerun. |
| verify a stage timed out | Look at the failed Run (below). When the message names another `fp-` label, rerun with the `--fingerprint` it suggests. |
| verify `completed` without a resolution | `docs/admin-requests.md#jira-admin-resolution-screen`. |
| verify jira-as failing | `python3 -m grafana_jsm_sandbox.doctor --only env,jira`. |
| reset `completed without a resolution` | `docs/admin-requests.md#jira-admin-resolution-screen`; the next reset takes it out once fixed. |
| reset `... by hand` | The engineer does it in Jira; the line says what. |
| reset `traffic NOT started` | `docker compose start traffic`. |

## A failed Run

A Run that failed leaves a `[FAILED]` line in the log, usually followed by a `[hint]` line naming
the cause, and the Receiver logs `run <id> FAILED: <reason>`:

```bash
docker compose logs --since 30m demo
```

Act on the `[hint]`. Denials show as `[DENIED]`, and a Jira refusal as a WARNING
`upstream said` line with its likely meaning. For the whole Run, find its Transcript:

```bash
docker compose logs demo | grep 'transcript:'
```

copy it out with the run id from that line (it lives only until the container stops) into
`runs/`, which git and the image build both ignore:

```bash
mkdir -p runs
```

```bash
docker compose exec -T demo env -i /bin/cat /app/runs/<run id>/transcript.jsonl > runs/transcript-<run id>.jsonl
```

and render it:

```bash
python3 -m grafana_jsm_sandbox.log_formatter runs/transcript-<run id>.jsonl
```

It is raw: it holds whatever Jira answered the Run. Delete it once the engineer is done with it.
