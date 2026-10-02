# Demo runbook: Grafana Alert to Incident

For the presenter, to be followed cold. The demo is one Incident's lifetime for a group of related
Alerts: traffic stops, Grafana fires several rules, a Run opens one Incident; as more rules join, Runs
update that same Incident and move it on; traffic returns, Grafana resolves, a Run completes it. The
shortest take is four Runs, and [the MVP runbook](mvp-runbook.md#6-the-demo-itself) has its log lines,
timings and the cue to start the traffic. The times and costs below were measured with chapter one's
single rule (2026-09-24: about four minutes and three Runs, about $1.15 on Opus 5; about $0.50 on Fable 5.1).

Vocabulary is [CONTEXT.md](../CONTEXT.md). Every command below is run from the repo root, in a
shell that has Docker and `jira-as`, with the demo set up as the README's Quickstart leaves it:
`.env` filled in and `configure --write` run. The laptop commands (`doctor`, `verify`, `reset`,
the replay) take the Jira credential, the project key (`DEMO_PROJECT_KEY`) and the queue's
address (`DEMO_QUEUE_URL`) from `.env`, not from the shell. `<KEY>` below is your project's key.

## The screen

One screen, three windows, arranged before anyone is watching. Left column is what the machine
does; right column is what the audience believes.

| Window | Where | What it shows |
| --- | --- | --- |
| Top left: **Grafana** | <http://localhost:3000/alerting/list?search=rolldice> | The four related rules on rolldice, `rolldice request rate is zero` first, and their states: Normal, Pending, Firing. No login |
| Bottom left: **container log** | a terminal running `docker compose logs -f demo` | Every Run as it happens, each line after its time and level: its reasoning, every `jira-as` command in full, every `forwarded` line, any `[DENIED]`, and a `[FAILED]` line with its `[hint]` if a Run fails |
| Right: **Incidents queue** | `DEMO_QUEUE_URL` from `.env`: `<site>/jira/servicedesk/projects/<KEY>/queues/custom/<queue-id>` | The Incident appearing, changing status, and leaving |
| Hidden: **presenter shell** | a second terminal, repo root | The two commands the presenter types. Keep it out of the projected area or the audience reads ahead |

The queue's address is your site's own: `python3 -m grafana_jsm_sandbox.configure` prints it on
its `queue` line and `--write` keeps it in `.env` as `DEMO_QUEUE_URL`. When it could not (the
line says why), open the project's **Queues**, click **Incidents**, and copy the address bar.
Open the address once to check it lands on the queue, and bookmark it the day before rather
than typing it live. Grafana is on `GRAFANA_HOST_PORT` and the Receiver on `RECEIVER_HOST_PORT`
when `.env` moves them off 3000 and 8080.

Reload the queue and the Grafana list by hand when the log says a Run has finished. Neither
refreshes fast enough on its own to be trusted during the demo.

Have two more tabs ready but not shown: the Skill exactly as a Run reads it, rendered for your
project when the container started, and the Incident itself once it exists (click it in the
queue), for the comments. The Skill is not the template in the repo, which carries placeholders;
print the rendering into its own terminal tab:

```bash
docker compose exec -T demo env -i /bin/cat /app/runs/.skill/incident-sync/SKILL.md
```

## On the work laptop: the corporate CA

Skip this on a laptop with no intercepting proxy. On one that has one, such as Zscaler, every
TLS connection from this machine, including from inside a container, presents a chain ending in
the corporate root CA, and nothing trusts it until it is told to: the build's `npm` and `pip`
installs, the Forwarder's calls to Atlassian, a Run's calls to Anthropic, and the shell's own
`jira-as`. Four things, done once, the morning of.

1. **Export the corporate root CA as PEM into `certs/`.** Git ignores everything in that
   directory except the empty placeholder, so the certificate cannot be committed. On macOS,
   Keychain Access, System keychain, find the corporate root, File, Export Items, format
   Privacy Enhanced Mail; or from the shell, with the certificate's name as the keychain shows it:

    ```bash
    security find-certificate -c "Corporate Root CA" -p /Library/Keychains/System.keychain > certs/corporate-root.crt
    ```

    On Windows, `certmgr.msc`, Trusted Root Certification Authorities, export as Base-64
    encoded X.509. Then read it back; it must print a subject and a fingerprint:

    ```bash
    openssl x509 -in certs/corporate-root.crt -noout -subject -fingerprint -sha256
    ```

    `unable to load certificate` means the export was DER, not PEM: convert it with
    `openssl x509 -inform der -in exported.cer -out certs/corporate-root.crt`. Only PEM works;
    the build stops with `EXTRA_CA_CERT is not a PEM certificate` on anything else.

2. **Name it for the build.** One variable, read by both images this repo builds; the
   certificate goes into each image's system trust store before any install, and the demo
   image points Python, `requests`, pip and Claude Code at that store, which every Run inherits:

    ```bash
    export EXTRA_CA_CERT=certs/corporate-root.crt
    ```

    Then the usual `docker compose up -d --build`. Unset, the build uses the committed
    placeholder and is the same build as on the personal laptop. Export it in the shell rather
    than typing it per command, because the pre-demo check in step 4 reads the same variable.

3. **Tell the shell's own `jira-as` the same.** `configure`, `doctor`, `verify` and the reset
   call `jira-as` from this shell, not from the container, and it uses the `requests` library:

    ```bash
    export REQUESTS_CA_BUNDLE=certs/corporate-root.crt
    ```

    That replaces the bundle rather than adding to it, which is right when every connection
    goes through the proxy. If some hosts bypass it, hand `requests` both:
    `cat "$(python3 -c 'import certifi; print(certifi.where())')" certs/corporate-root.crt > certs/bundle.pem`
    and name `certs/bundle.pem` instead.

4. **Check the certificate is really in the running container.** After the stack is up, with
   `EXTRA_CA_CERT` still exported: the opt-in container checks find the certificate's
   fingerprint in the container's bundle and confirm Python's default SSL context loads it.
   They fail on purpose if the shell names a certificate the container was not built with, or
   names none when it was:

    ```bash
    DEMO_CONTAINER=1 python3 -m pytest tests/test_container.py -q
    ```

    The one-line glance, which prints `extra-ca.crt` after a build with a certificate and
    nothing after one without:

    ```bash
    docker compose exec -T demo ls /usr/local/share/ca-certificates
    ```

**Docker Desktop pulls are outside this repo.** The base images (`node`, `python`,
`grafana/otel-lgtm`, `alpine`) are pulled by Docker Desktop's own daemon, which must trust the
corporate CA itself; on macOS it reads the system keychain. A pull that fails with `x509:
certificate signed by unknown authority` is a Docker Desktop setting, not anything here. Pull
the four images the day before, on any network that lets you, and the build touches Docker Hub
no further. Where Docker Desktop's policy refuses one, the request to forward is
[Docker admin](admin-requests.md#docker-admin).

## The day before: a full rehearsal

Rehearse one whole grouped lifecycle with the real Alerts, unattended, and let it name the stage that
did not come:

```bash
python3 -m grafana_jsm_sandbox.verify --mvp --live
```

It stops the traffic, waits for Grafana's rules to fire, watches one Incident be created with the
group and session labels, updated for the repeat and for the sustained-outage Alert, then starts the
traffic again and watches it reach the configured done status with a resolution, printing each stage
with its elapsed time. It ends `VERIFIED` or `NOT VERIFIED: <stage> — <why>`, and starts the traffic
on the way out whatever happens. It waits for a repeat, so it takes up to about 30 minutes. For a
replay, use `verify --mvp --replay`: it posts the grouped Notifications under `fixtures/mvp/`
instead of waiting for Grafana to send them. If Grafana answers the preflight, its rule must be
Normal; if it is unavailable, replay warns and continues. Run it the day before, or at least well
before the fifteen minutes below: it leaves a completed Incident behind and, live, takes the rules
through Firing. Then run the reset (step 3 below). `verify` without `--mvp` is chapter one's single-
Alert check; its replay Notifications carry no `incident_group`, which this demo's Runs need.

## Fifteen minutes before: pre-demo checks

Run them in this order. Every one must pass before the audience arrives; none takes more than a
minute except the first.

1. **Stack up.** `docker compose ps` shows four services running and `demo` healthy. If not:

    ```bash
    docker compose up -d --build
    ```

    A cold build pulls nothing new when the images are already on this machine; it has been
    known to hang for minutes on a Docker Hub pull if they are not. Start early.

2. **Doctor ready.** One pass from the laptop's tools through `.env`, Jira and the project's
   fields to the stack, the container's own view and the running Grafana:

    ```bash
    python3 -m grafana_jsm_sandbox.doctor
    ```

    It ends `READY`. `NOT READY: <first blocker>` names what failed and its fix, and a FAIL that
    ends `; ask: docs/admin-requests.md#<anchor>` is one a colleague has to fix, which is not a
    fifteen-minute job. It changes nothing, so the reset is still a step of its own. The one-line
    glance, when there is no time for more, is the Receiver's health endpoint, which prints `ok`:

    ```bash
    curl -fsS http://localhost:8080/health
    ```

    (or your `RECEIVER_HOST_PORT` in place of 8080, when `.env` moves it).

3. **Queue empty, traffic flowing.** The reset closes every open Incident a rehearsal left
   behind and starts the traffic service:

    ```bash
    python3 -m grafana_jsm_sandbox.reset
    ```

    Prints one line per Incident it closed or left alone, then `queue is empty` and exit 0
    when nothing is left for a human and the traffic started. A key it leaves names the reason: an open
    Incident in a status a Run never uses, or without an `fp-` label, finished in the Jira UI;
    one it completed but Jira left without a resolution, which needs the Jira admin to put
    Resolution on the Resolve screen, after which the next reset reopens and closes it; one
    with no transition to `Close`, already out of the queue and ending the report with `queue is empty;
    N left for a human to close`; or a `Canceled` or `Closed` Incident with no resolution, which
    only deletion removes from the queue and which it prints the delete command for. If `docker
    compose` fails, the report still prints, with the `docker compose start traffic` to run by
    hand. `--dry-run` shows all this first without changing anything. See
    [Reset](#reset-between-takes-or-after-a-bad-one) for what it does and does not do.

4. **Grafana provisioned, the rule Normal, the boundary in place.** The opt-in checks ask the
   running Grafana what it was actually given, and the running container's kernel what it
   enforces: who the process is, no capability left, a write refused on the root filesystem
   and accepted on each tmpfs, and the process, memory and CPU limits the compose file declares:

    ```bash
    DEMO_CONTAINER=1 python3 -m pytest tests/test_grafana.py tests/test_container.py -q
    ```

    All pass. On the work laptop, `EXTRA_CA_CERT` must still name the certificate the image
    was built with (see above). The rule check needs the traffic to have been flowing for a
    minute, so run it after step 3, not before. If a provisioning file was edited since the
    stack came up, Grafana has not seen it: `docker compose restart lgtm`, wait a minute, rerun.

    A limit check that fails with `Compose <version> did not apply it` means Docker Desktop's
    Compose is older than the key: `pids_limit` needs Compose 2.2, `cpus` needs 2.17, and a
    current Docker Desktop has both. Do not present a limit the kernel is not enforcing. The
    stopgap puts both on the running container until it is next recreated; then rerun the check:

    ```bash
    docker update --pids-limit 256 --cpus 2 "$(docker compose ps -q demo)"
    ```

5. **Eyes.** Grafana's list shows the rule **Normal**. The Incidents queue shows nothing a Run
   made. The log's last lines are a `receiver listening` or a finished Run, not a Run in
   progress. Nothing else is posting at the Receiver: no replay, no `verify`, no end-to-end test
   in another shell.

**If the reset names an Incident as stuck.** A `Canceled` or `Closed` Incident with no
resolution stays in the queue, because the queue filters on resolution and no transition on
this workflow can give it one afterwards (ADR 0004). Nothing but deletion removes it, one key at
a time, and the reset never deletes; that is the presenter's call. The reset prints the command
for each such key:

```bash
jira-as api call deleteIssue --issueIdOrKey <KEY>-n --confirm
```

Without `--confirm`, jira-as only shows the request it would send. With it, the deletion is
permanent: jira-as rates the operation irreversible, and the Incident's history goes with it.
Unlike the reset, this is your own shell's `jira-as`, with whatever site and credential it is
configured with, so check that it points at the demo's site before deleting anything, and that
the account it uses holds Delete issues on the project.

The alternative is to project a filter instead of the queue, which needs no deletion:
`project = <KEY> AND issuetype = Incident AND statusCategory != Done ORDER BY created DESC`.

## The demo, step by step

**The rule set.** Four related rules on rolldice, one group in the `demo` folder, every one
labelled `incident_group=checkout-outage`, and the policy groups by that label alone with a 30s
group wait, a 1m group interval and a 3m repeat. Stopping the traffic fires them in order:
`rolldice request rate is zero` and `rolldice successful responses have dropped` about a minute
after the stop, together in the first Notification; `rolldice health probe is failing` about
thirty seconds later, joining on the next group interval; and `rolldice outage is sustained`,
pending for two minutes, at about 2m40, the related alert that arrives after the Incident exists.
The README's "Firing the Alert for real" has the conditions and the file.

Times are from the one action, measured in the rehearsal this runbook was written from (the
record is at the bottom), on Grafana 12.3.1 and Runs on Fable 5.1, with chapter one's single rule
and a one-minute repeat; with the grouped rule set the repeat comes every three minutes and the
updates come as the related rules join, so expect the later rows to move. Chapter one's historical
`verify --live` on the pinned Grafana 13.2.1 with Runs on Opus 5 (2026-09-24) ran a little faster:
Firing 52s after the stop, the Incident 38s later, the whole lifecycle 3m18s. Your own
`verify --mvp --live` gives your laptop's
grouped figures. Grafana's parts add up: the rate window empties, then the thirty-second pending period, then the next
ten-second evaluation. The waits are real and worth narrating rather than filling.

| When | Presenter does | Audience sees | Say meanwhile |
| --- | --- | --- | --- |
| T+0:00 | In the hidden shell: `docker compose stop traffic` (returns in about a second) | Nothing yet | What just happened: the only synthetic traffic to rolldice stopped. Grafana is about to notice |
| ~T+0:30 | Nothing | Grafana: **Pending** (reload) | The rule: request rate zero for thirty seconds, evaluated every ten. Point at the log: nothing has happened yet, because nothing has been sent |
| ~T+1:00 | Nothing | Grafana: **Firing** (reload) | Grafana has now posted one Notification at the Receiver. The Receiver acknowledged it in milliseconds and queued one Run |
| ~T+1:10 | Nothing | Log: `notification accepted: 2 alerts, run ... queued, 0 ahead`, `run ... started`, then `[claude]` lines, then `[tool] Bash: incident-payload match` and the `jira-as search jql ...` it printed, then `forwarded GET ... upstream said 200` | Walk the log as it scrolls: it read the Notification, searched the project for an open Incident with this group's and this take's labels, found nothing, is creating. Every `forwarded` line is the Forwarder swapping the sentinel for the real token |
| After the create Run | Reload the queue | **<KEY>-n** in the queue, status Open, Sev-1, Urgency Critical, Source Monitoring systems (each only where the project has the field) | Open it. Summary names the group and firing count; Description lists the firing Alerts and their generator links; `grp-`, `ses-` and `fp-` labels; the opening comment with the value. The Run took about 30s |
| ~T+2:20 | Nothing | Log: second `run ... started` | This is the health probe joining: the policy sends the group again on the next group interval when a related rule joins it. The Run finds the Match this time |
| ~T+2:45 | Reload the Incident | An update comment: `Update: 3 firing. New: rolldice health probe is failing (fp-…) value=…. Repeat: …`; status **Work in progress** | The comment sorts the Alerts into new, repeat and resolved, with how long the Incident has been open, read off Jira's clock. The first update moves it on; later ones only comment |
| After the sustained-outage Run, about T+4–5m | In the hidden shell: `docker compose start traffic` | Nothing yet | Traffic is back. Grafana needs one evaluation to see the rate, then sends the Resolved on the next group tick |
| After recovery | Nothing | Grafana: **Normal**; log: resolve `run ... started` | The Run is closing it: one comment with total duration, Alert count and Run count, then the `Resolve` transition with resolution Done |
| After the resolve Run | Wait 20s, then reload the queue | Queue **empty**; the Incident is **Completed** with resolution Done | Completed, not Closed: a human closes, and Completed is the clean trigger for chapter three |

With the grouped rules there is one more update before the restart: the sustained outage joins at
about 3m15, and the cue to start the traffic is that update's Run finishing in the log, about 4 to 5
minutes after the stop ([the MVP runbook](mvp-runbook.md#6-the-demo-itself)), so follow that cue
rather than the old chapter-one clock. Jira's search index lags a resolution by ten to twenty
seconds, so a queue reloaded the instant the log says `finished` can still show the Incident. Count
to twenty, then reload.

Notifications can be grouped or coalesced, so follow the log and the Incident's comments rather than a
fixed Run count. The Resolved Notification still comes, at most one group interval after the rules go
Normal, and its Run completes the Incident.

A Run that fails says so, whatever its exit status: its `[result]` line becomes `[FAILED]`
(ERROR) with the reason, a `[hint]` under it when the cause is a known one (the Claude token,
usage credits, a rate limit, the model, the budget), and then `run ... FAILED: <reason>`. A 401,
403 or 404 from Jira shows as a WARNING `forwarded ... upstream said` line saying what it most
likely means. Its untrimmed Transcript is at the path its `run ... transcript:` line names, on a
tmpfs that empties when the demo container stops or is recreated: copy it out with
`docker compose exec -T demo env -i /bin/cat <that path> > transcript.jsonl` before any restart
(the `env -i` keeps the tokens out of the `cat`, as README's "Fetching a Transcript" says). Fix
the cause off screen, then switch to the replay below.

Do not `stop traffic` again for a second take until Grafana shows Normal and the queue is empty.
A re-fire deliberately gets a new Incident, which is the chapter two story, not a duplicate.

## What to say

These are the five points the audience is there for, in the order the demo makes them
available. Each has one thing on screen to point at.

**The Run's tools are explicitly allowed.** A Run is headless Claude Code in print mode with
`--permission-mode dontAsk`. With investigation disabled, its allow list has three rules:
`Bash(jira-as *)`, `Bash(incident-payload *)`, and `Read` of the runs directory, which holds
each Run's Notification and Transcript and the rendered Skill. With investigation enabled,
`run_command.py` adds `Bash(grafana-query *)` as a fourth rule.
`incident-payload` prints the `jira-as` lines to run; its `investigate` subcommand also writes
one ADF body file in the Run's directory for `jira-as ... --body-file ... --format adf`.
Anything else is denied without a prompt, and the denial is printed on a `[DENIED]` line in the
log window (ADR 0003). Show the command line:

```bash
python3 -m grafana_jsm_sandbox.run_command runs <KEY>
```

with the project's key for `<KEY>`. This command prints the investigation-disabled baseline;
investigation-enabled Runs add the fourth rule described above.

The live Runs have so far never tried anything off the list, so the log has shown no denial.
The recorded Transcript in the repo has one, from a Run that was asked to `ls /etc`; render it
if the point needs a picture:

```bash
python3 -m grafana_jsm_sandbox.log_formatter fixtures/run-transcript.jsonl
```

**The Jira token lives in the Forwarder; the Run holds a sentinel.** The real token exists in
one process: the Receiver, and the Forwarder thread it owns, bound to the container's loopback.
Each Run gets an environment built from scratch, not inherited: `JIRA_SITE_URL` pointing at the
Forwarder over plain http and `JIRA_API_TOKEN` set to a random per-Run sentinel that the
Forwarder registers when the Run starts and forgets when it ends. The Receiver is non-dumpable,
so its `/proc` entry, where its environment and the real token are, is root's and no Run can
read it. The only other thing it inherits
is the container's trust store, five variables pointing at the one system bundle, so that on the
work laptop a Run reaches Anthropic through the same proxy the build did. Every `forwarded ... upstream
said` line in the log is the swap happening; a sentinel copied out of a Transcript is worth
nothing afterwards (ADR 0002). Show `RunSpawner` in
[`grafana_jsm_sandbox/run_spawner.py`](../grafana_jsm_sandbox/run_spawner.py) if asked how.

**The container is the boundary, in the shape Anthropic's guide gives it.** The demo service
runs the way Anthropic's secure-deployment guide says to run a headless agent, and the list is
short: every capability dropped, no new privileges, a read-only root with tmpfs for the three
directories a Run writes, a process limit, a memory and a CPU limit, all declared in the compose
file; a non-root user, from the Dockerfile; no Docker socket; and credentials behind a proxy,
which is the Forwarder. Say which is whose. All of those controls are the guide's, the
Forwarder being its credential-proxy recommendation done for Jira. This repo's own are the
image carrying nothing but Claude Code and `jira-as` (ADR 0005), the sizes of the limits, the
sentinel the Forwarder swaps, and the `dontAsk` permission mode with its three-rule allow list
when investigation is disabled (four rules when enabled), which the guide is explicit is a
permission gate and not a boundary. Two things the guide has
that the demo does not: a custom seccomp profile (Docker's default one is what runs) and
`--network none`, because the Receiver must accept Grafana's Notifications and reach Jira and
Anthropic; an egress allowlist of exactly those hosts is the next step, not what is running. The pre-demo check read every control back from the
container's kernel; the one-liner, in the hidden shell, prints `Read-only file system` from
inside the directory the Run user owns:

```bash
docker compose exec -T demo sh -c 'touch /app/probe'
```

**The one credential that is not masked.** Say it plainly: the Anthropic OAuth token is in the
Run's environment, because the Run is Claude Code and that is how it authenticates. Nothing
documented masks it. Claude Code's native sandbox credential masking is the built-in equivalent
of the Forwarder, and it is the stretch goal, not what is running.

**What comes next.** Every Incident carries its Fingerprint label from day one, so chapter two,
grouping repeated Incidents of the same Alert under one Problem with the `is caused by` link, is
a lookup and one link, not a matching design. Chapter three drafts the post-incident review from
the comment history when an Incident Completes; that is why the automation stops at Completed
and never Closes.

Honest small print, if it comes up: the Description's Dashboard and Panel lines are empty
because the rule is linked to no dashboard; the repeat's value is the same zero as the first
Firing, so the trend reads `unchanged`; a lifecycle is three Runs and about $1.15 on Opus 5, the
default (about fifty cents on Fable 5.1).

## Fallback: the replay

Switch to it when any of these happens. Nothing is restarted.

- Grafana has not shown Pending within a minute of the stop, or Firing within two.
- The log shows no `run ... started` within two minutes of Firing.
- Grafana's page is down or will not load.

Two commands in the hidden shell, in this order:

```bash
docker compose start traffic
```

```bash
python3 -m grafana_jsm_sandbox.verify --mvp --replay
```

Traffic first, so the rules go back to Normal; wait for Normal before replaying. `verify` refuses to
start while `rolldice request rate is zero` is not Normal, or while an open Incident already carries
this take's group and session labels, and then names the cleanup needed. If Grafana does not answer,
replay warns and continues. It posts the four grouped Notifications under `fixtures/mvp/`, each once
the Incident has answered the one before, and prints each stage; the log, the queue and the Incident
show the grouped lifecycle, minus Grafana's own state changes. It takes a few minutes. Do not use
`python3 -m grafana_jsm_sandbox.replay` here: it posts chapter one's single-Alert Notifications,
which carry no `groupLabels.incident_group`, so the MVP payload tool raises `PayloadError` and no
create is registered. This demo's Runs cannot match, create or update anything with them. `python3
-m grafana_jsm_sandbox.replay` has no option for grouped fixtures; use `verify --mvp --replay`.

## Reset: between takes, or after a bad one

```bash
python3 -m grafana_jsm_sandbox.reset
```

It finds every open Incident carrying an `fp-` label in the project `.env` names, takes each
out of the queue the only clean way this workflow has, `Resolve` with resolution Done and then
`Close`, leaves a comment saying the reset did it, and then starts the traffic service so that
the rule returns to Normal. It reads every page of the search before it moves anything.
Between `Resolve` and `Close` it reads the Incident again: when the Resolve screen has no
Resolution field, jira-as 2.0.0 quietly resolves without one, and closing that Incident would
strand it in the queue, so the reset leaves it on Completed and says to ask the Jira admin to put
Resolution on the Resolve screen. Completed keeps the road back, so once the admin has, the next
reset reopens that Incident, resolves it with Done and closes it; one without an `fp-` label it
names instead, for a human to reopen and resolve. When there is no transition to `Close`,
it is left for a human too,
with a second comment saying so; it is already resolved and out of the queue, so the report ends
`queue is empty; N left for a human to close`, and the exit is 1.
It prints what it did per key and ends with `queue is empty` and exit 0, or names what it left:
an `fp-` Incident with no road to Completed from where it is (`Pending`, which only a human
uses), one completed without a resolution or not closed, an open Incident with no `fp-` label,
which is not a Run's and is not touched, or a `Canceled` or `Closed` Incident with no
resolution, which nothing but deletion can take out of the queue and which it prints the delete
command for, with `--confirm` and a warning that deletion is permanent. It never offers to delete
a Completed one. It does not cancel anything: `Canceled` carries no
resolution and stays in the queue for good (ADR 0004). It does not delete anything either.
If Jira fails, the reset keeps confirmed earlier results, names the current and remaining known
Incidents whose state is unknown, and stops further Jira calls without retrying a write. It still
tries to start traffic once, but ends `queue state is unknown` and exits 1. A failed final search
also makes the queue state unknown, even when the earlier Incidents were closed.
If `docker compose` fails to start the traffic, the report still prints, with a line naming
`docker compose start traffic` to run by hand, and the exit is 1.
`python3 -m grafana_jsm_sandbox.reset --dry-run` prints the same report in the conditional
("would be completed", "traffic would be started") and changes nothing in Jira or the stack. It
checks only the first step out of each Incident's status, so a Resolve screen that drops the
resolution, or a Completed with no `Close`, shows up only in a real run.

After a clean take nothing is open and the reset only starts traffic. After an abandoned take,
run it, then wait for Grafana to show Normal before the next `stop traffic`. If a Run is still
in progress in the log, let it finish first; a stuck one is killed by the Receiver after five
minutes and the queue moves on.

Reset does not reload changed provisioning files: run `docker compose restart lgtm`, then
allow a minute for Grafana to come back. It also leaves injected malformed-input or slowdown
settings in the traffic container: `reset.py` only starts the existing container. Before the
next take, recreate traffic with the defaults (`ROLLDICE_SIDES=6`, and `ROLLDICE_SLOW_MS=0`
for the slow-response overlay), following the recovery commands in
[Loki investigation](loki-investigation.md#optional-malformed-input-fault) and
[slow-response investigation](slow-response-investigation.md#inject-inspect-recover).

## Rehearsal record

This runbook's numbers come from a timed rehearsal recorded in the working notes, which are not
published.
