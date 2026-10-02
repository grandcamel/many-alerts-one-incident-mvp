# Rehearsing the MVP against a local fake Jira

**What this is for.** The MVP has passed only offline tests. This runbook rehearses the whole stack on the Mac, a
**real** Claude Run following the rendered Skill included, against a fake Jira Cloud that runs on the laptop, so no
real site is touched. It answers the one question the offline suite cannot: does a real model carry out Skill v2's
create → add labels → comment → move → resolve sequence, on the stock ITSM workflow and on a different one?

**What is real and what is not.** The Jira is fake (`python3 -m grafana_jsm_sandbox.fake_jira`, an in-memory
server that answers the REST calls jira-as 2.0.0 makes and nothing else). The Grafana stack, the container, the
Receiver, the Forwarder and the Runs are the real ones. **The model credential is real, and each lifecycle
(`verify --mvp --replay`) costs about $1–2 of it.** Total it from the Receiver's log with
`docker compose logs --no-log-prefix demo | python3 -m grafana_jsm_sandbox.run_costs` (`verify` prints no costs).

The fake keeps no credential: it accepts any non-empty email and token. So the Jira "token" in `.env` below is a
made-up word, and nothing in this rehearsal can reach a real site.

## The two workflows

| `--workflow` | Statuses (category) | Resolve screen |
|---|---|---|
| `itsm` | Open (To Do) → Work in progress (In Progress) → Completed (Done) → Closed (Done); also Pending (To Do) and Canceled (Done) | takes `resolution` |
| `custom` | New (To Do), In Progress (In Progress), Waiting for customer (To Do), Pending (To Do), Resolved (Done), Canceled (Done); no Closed | **rejects** `resolution` with Jira's own 400; moving to Resolved sets resolution Done itself, as a post-function would |

`itsm` offers the Severity, Urgency, Source and Major incident custom fields; `custom` offers none, so
`configure` writes their ids empty and a Run leaves them off. Rehearse both: the first paid runs will meet one of
each.

## How the host and the container both reach it

`.env`'s `JIRA_SITE_URL` is read by the host-side helpers (`configure`, `doctor`, `verify`, `reset`) and, through
compose's `env_file`, by the Receiver in the `demo` container. One value has to work from both places, and on Docker
Desktop for Mac a container's `localhost` is the container, not the Mac. So the fake runs as a compose service named
`fakejira`, under the `fake-jira` profile (a plain `docker compose up` never starts it), on the same network as
`demo`, and published on the Mac's loopback at port 8090. The value is

    JIRA_SITE_URL=http://fakejira:8090

The container resolves `fakejira` on the compose network. The Mac resolves it once, and only once, you add this line
to `/etc/hosts` (it needs `sudo`; it is harmless to leave there):

    127.0.0.1 fakejira

That is the one host-side arrangement. There is no switch anywhere that could send a real run to the fake or a
rehearsal to a real site: what decides is `JIRA_SITE_URL` alone, exactly as for a real site. The Forwarder accepts
`http://` sites as it always has, and nothing in it changed.

If 8090 is taken, set both `FAKE_JIRA_PORT=18090` and `JIRA_SITE_URL=http://fakejira:18090` in `.env`, and
use port 18090 in the `curl` lines below. The variable moves the container's port and the published port
together, which is what keeps one value valid on both sides; in `.env` it also survives every later
`docker compose` command, where a shell-only value would be lost.

## 0. Prerequisites

Everything in `docs/mvp-runbook.md` section 0, plus jira-as 2.0.0 on the Mac (`pip install
jira-as==2.0.0`; `doctor --only host` checks it). Nothing here needs a Jira account or an Atlassian API
token. It needs the Anthropic API while Runs run and, for the build and the jira-as install, Docker Hub,
`registry.npmjs.org`, `pypi.org` with `files.pythonhosted.org`, and `deb.debian.org`
([Network](admin-requests.md#network)).

## 1. `.env`

Start from the example and set exactly these; fill in only the model credential and the session id:

```
JIRA_SITE_URL=http://fakejira:8090
JIRA_EMAIL=rehearsal@example.invalid
JIRA_API_TOKEN=not-a-real-token
ANTHROPIC_API_KEY=<your work API key>
DEMO_SESSION_ID=<a new id per rehearsal, such as fake1>
DEMO_PROJECT_KEY=FAKE
```

`FAKE` is the one project the fake has. Leave `CLAUDE_CODE_OAUTH_TOKEN` unset (exactly one model credential), and
leave the `DEMO_*` site facts to `configure --write`. To rehearse the second workflow, also set

```
FAKE_JIRA_WORKFLOW=custom
```

(`itsm` is the default), and recreate the fake and the demo container afterwards (step 4), because the `DEMO_STATUS_*`
values `configure` writes differ between the two.

## 2. Start the fake and configure

```bash
docker compose --profile fake-jira up -d --build fakejira
curl -s http://fakejira:8090/__fake__/state
```

The second line proves the Mac reaches it under the shared name; it prints an empty project (`"issues": []`). Then:

```bash
python3 -m grafana_jsm_sandbox.configure
python3 -m grafana_jsm_sandbox.configure --write
```

On `itsm` every check is OK and `.env` gains the four field ids and the queue URL; the status roles are the stock
ones (`Open`, `Work in progress`, `Completed`, `Closed`), which are the defaults, so no `DEMO_STATUS_*` line is
written. On `custom` the field checks are WARN (the project lacks them, so their ids are written empty), the four
`DEMO_STATUS_*` lines are written, and the statuses line reads

    WARN statuses: the Incident workflow: proposed DEMO_STATUS_OPEN=New, DEMO_STATUS_IN_PROGRESS=In Progress, DEMO_STATUS_DONE=Resolved, DEMO_STATUS_CLOSED=(empty, no close step)

which is right: a Run only ever moves an Incident to the in-progress and done statuses, and this workflow has no
close step.

## 3. `doctor`

`doctor`'s `env` layer holds `JIRA_SITE_URL` to `https://`, because a real Jira Cloud answers only over TLS, and it
stops at the first failing layer. That check is meant to fail here, so run the layers around it:

```bash
python3 -m grafana_jsm_sandbox.doctor --only host,jira,facts
```

`jira` says who the credential is (the fake's one account) and `facts` holds `.env` to the fake's create screen and
workflow, exactly as it would against a real site.

## 4. Bring the stack up

```bash
docker compose --profile fake-jira up -d --build
docker compose logs -f demo
```

The `--profile` flag keeps `fakejira` in the set compose manages, so the same command recreates it after a change
to `FAKE_JIRA_WORKFLOW` or `.env`. Wait for the Receiver's startup lines, then

```bash
python3 -m grafana_jsm_sandbox.doctor --only stack,grafana
```

The `stack` layer asks Jira `/rest/api/3/myself` from inside the container, through a Forwarder, the way a Run's
call goes; against the fake it answers 200. `doctor --only stack --with-model` is optional here and costs about
$0.12.

## 5. The rehearsal: `verify --mvp --replay` (paid, about $1–2)

```bash
python3 -m grafana_jsm_sandbox.verify --mvp --replay
```

It posts the four grouped Notifications at the Receiver, each once the Incident has answered the one before, and
watches the fake project through jira-as: one Incident created with `grp-checkout-outage`, `ses-<session>` and
three `fp-` labels; a comment and the move to the in-progress status on the repeat; a fourth `fp-` label with a
comment on the related Alert; the done status with resolution `Done` on the Resolved. It ends `VERIFIED: FAKE-1
created with 3 fp- labels → updated → fp-… added → Completed with resolution Done in …s` (`Resolved` on `custom`).

`docker compose logs demo` shows each Run's Transcript and its `[result]` line with the cost. `docker compose logs fakejira` shows
one line per request the Runs made: the method, the path and the status, never a body.

## 6. Read the evidence

```bash
curl -s http://fakejira:8090/__fake__/state | python3 -m json.tool
```

The dump is the whole project: every issue with its key, summary, status, resolution, labels, custom fields,
comments and status history, each transition with what asked for it. Confirm:

- exactly one issue carries `grp-checkout-outage` and this session's `ses-` label;
- its labels hold one `fp-` per Alert (three from the Firing, the fourth from the related Alert);
- its comments are the opening one, one per update, and the closing one;
- its status history is Open → Work in progress → Completed (or New → In Progress → Resolved), with the
  resolution set on the last step, on `custom` by the fake's post-function after the Run's `--resolution Done` was
  refused and retried without it, as jira-as 2.0.0 does.

A second issue with the same two labels, a missing `fp-` label, or a status outside that path is the finding this
rehearsal exists to make before a real site sees it.

## 7. Reset and teardown

`reset` works against the fake as against a real site, and `POST /__fake__/reset` empties it outright:

```bash
python3 -m grafana_jsm_sandbox.reset --dry-run
curl -s -X POST http://fakejira:8090/__fake__/reset
docker compose --profile fake-jira down
```

Before the first run against a real site, put the real `JIRA_SITE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` and
`DEMO_PROJECT_KEY` back in `.env`, run `configure --write` again (the field ids and status names are the real
project's, not the fake's), and recreate the demo container. The `/etc/hosts` line does nothing once no value names
`fakejira`.
