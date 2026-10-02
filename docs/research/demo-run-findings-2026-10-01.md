# Demo run findings, 2026-10-01 (sanitized record)

Source: a presenter's review of the Run logs of three rehearsal takes on a real Jira Service Management site, one take
each with Opus 5, Sonnet 5.5 and Haiku 4.5. This record carries no site name, project key, Incident key or URL: `<KEY>`
is the project key and "the Haiku Incident" is that take's Incident. It records each finding and what became of it.
A status of **done** means the code, test or document named exists in the tree and its tests passed offline.
Nothing here was re-run against a live Jira, Grafana or Claude seat, so every acceptance bullet that needs a live Run
is listed under "Not verified live" at the end.

## What the takes showed

All three models kept one Incident per cycle and moved it through the expected lifecycle. The cheapest model exposed a
weakness in the interface: the Skill asked the model to build deeply nested ADF JSON inside a shell argument. Haiku
closed the outer `--custom-fields` object with the wrong brace, attempted the same malformed create six times, then
created its Incident with the Description `Test` and tried an unsupported description edit (HTTP 400). The Run still
reported success, because the issue, labels, comment and later transitions all succeeded.

## Findings and their status

| # | Finding | Status | Where |
|---|---|---|---|
| P0 | The Skill had the model hand-author ADF under `--custom-fields`; the installed jira-as takes a JSON-object `--description` as ADF, and a Run cannot pass a newline, so a bullet list needs ADF that the model must not write. | **done** | `grafana_jsm_sandbox/incident_payload.py` and `docker/incident-payload` build the payloads; `skill/incident-sync/SKILL.md` has the Run run the printed lines; `run_command.py` adds `Bash(incident-payload *)`; `Dockerfile` installs the launcher; `docs/adr/0003-…` records why. Tests: `tests/test_incident_payload.py` (punctuation, both quote kinds, URLs, parentheses, Unicode, a newline in an annotation, and the printed create run through jira-as's offline `--dry-run`), `tests/test_skill_template.py`. |
| P0 | Nothing stopped a Run from probing Jira with altered creates after a failed one. | **done**, and tighter than the finding asked | `grafana_jsm_sandbox/forwarder.py` counts issue creates per sentinel: the spawner registers the helper's expected Summary, label set and ADF Description for the Notification, and only an exact single-issue create passes. A first refusal gets a Jira-shaped 400 and spends the attempt; every later create gets 409. Bulk and Service Management creates are always refused, including decoy bodies. Nothing firing registers no create. The extra check is needed because a mangled `--custom-fields` fails inside jira-as before any request, and the create that made the placeholder was the Run's first request. `log_formatter.py` shows a refusal as `[DENIED] Jira create refused by the Forwarder: …`. The Finish starts `ok: ` for success or `failed: ` for failure before group text; only exact, case-sensitive `failed: ` on a success result's first non-empty line marks failure. `docs/adr/0002-…` records it. Tests: `tests/test_forwarder.py`, `tests/test_log_formatter.py`. |
| P0 | A Run that could not write the Incident still ended `success`. | **done** | The Skill's Finish has a Run begin its final message `failed: <why>`; `log_formatter.REPORTED_FAILURE` reads that line, so the log shows `[FAILED] run reported failed: <why>` and the Receiver logs `run … FAILED: …`. Tests: `tests/test_log_formatter.py`, `tests/test_skill_template.py`. |
| P1 | `jira-as issue get <key> -o json` returned 20 to 40 KB on a site with many asset fields. | **done** | The Skill names `--fields` on every `issue get`. The Match search returns `key,status,labels,created`, so the duration needs no read. The comment count is `jira-as collaborate comment list <key> --limit 1`'s `total`. Test: `tests/test_skill_template.py`. |
| P1 | A Run improvised JQL without a project clause and the allow list refused it. | **done** | The Skill says every JQL query contains `project = <KEY>` and reads a known key with `issue get --fields`, never JQL. `incident-payload match` prints the one search. The project allow list stays as defence in depth. Tests: `tests/test_skill_template.py` (every JQL has a project clause, the duration path uses the Match's `created` and no JQL). |
| P1 | The Resolve transition screen: `--resolution Done` got HTTP 400, jira-as retried without it, and a workflow post function happened to set Done. | **partly done; the cause needs an admin** | Admin request: `docs/admin-requests.md#jira-admin-resolution-screen`, which now says what the presenter sees until it is done. In the Run, the Skill reads `status,resolution` after the close and finishes `failed:` if the Incident is done without a resolution. In `verify --mvp`, the `completed` stage fails without one. Until the admin acts, every close still shows the 400 and the 204 retry in the log. |
| P1 | Verification passed an Incident whose Description was `Test`. | **done** | `grafana_jsm_sandbox/verify_content.py` and `verify_mvp.py` check, in the stage where each fact first shows: the Summary (group and firing count), the Description (each firing Alert and its generator URL), the opening comment (each firing Alert with a value), update comments (New, Repeat, Resolved), the closing comment (duration, Alert count, Run count) and the resolution. A failure names the field: `NOT VERIFIED: created — …`. Ordering is tolerated. Tests: `tests/test_verify_mvp.py` (the Haiku case, a done Incident with no resolution, reordered Alerts). |
| P2 | Takes reused one `DEMO_SESSION_ID`, and one take began with resolved Alerts left from the take before. | **partly done** | `docs/mvp-runbook.md` section 5: a new id per take, how to recreate the container (`docker compose up -d demo`, not `restart`), and a settle wait of 3 minutes after the traffic restart, derived from `group_wait`, `group_interval` and `repeat_interval`. Not built: a preflight that reports lingering resolved Alerts. Whether Grafana's Alertmanager API still lists resolved Alerts waiting in a group was not checked, so the runbook gives a wait and a look at the first Notification's Alert count instead. |
| P2 | Traffic stayed stopped long enough for two comment-only repeat Runs in the Opus take. | **done** (a document) | `docs/mvp-runbook.md` section 6: the cue is the sustained-outage update Run's `run … finished` line, about 4 minutes after the stop, before the first repeat at about 6 minutes. It separates the shortest lifecycle take (four Runs: create, two related updates, resolve) from a repeat-focused take. |
| P2 | `configure` found only a queue named exactly `Incidents`, and `doctor` then advised `configure --write`, which could not help. | **done** | `grafana_jsm_sandbox/configure.py` (`check_queue`) takes a queue when exactly one has the name, else the one queue whose JQL is exactly the project, `issuetype = Incident` and `resolution = Unresolved`, else lists candidates with their ids and addresses and leaves `DEMO_QUEUE_URL` alone. A hand-set address must be a queue of the project's service desk (FAIL otherwise) and warns when its JQL keeps resolved Incidents. `grafana_jsm_sandbox/doctor.py` (`queue_url_line`) says "set it by hand" when `configure` cannot find the queue. Tests: `tests/test_configure.py`, `tests/test_doctor.py`. |
| P2 | Start-up accepted any model-shaped name, so a dot-versus-hyphen typo got through. | **done**, but the check is on request | `doctor --only stack --with-model` reports the requested model beside the one the Transcript says answered, and an alias or a substitution is visible (`model_line` in `doctor.py`). Start-up still does not call the seat; its log says so and names the command (`__main__.py`). The runbook, section 5, separates the configured model from the model that ran. Tests: `tests/test_doctor.py`, `tests/test_startup.py`. |

## Observed model comparison (directional, not a benchmark)

| Model | Runs | Displayed total | Run duration | Main friction |
|---|---|---|---|---|
| Opus 5 | 6 | about $2.00 | 20–28 s | two unnecessary repeats; Resolve-screen 400 |
| Sonnet 5.5 | 5 | about $0.80 | 20–21 s | two unscoped JQL attempts; Resolve-screen 400 |
| Haiku 4.5 | 4 | about $0.36 | 23–60 s | six malformed creates; placeholder Description; unsupported update; Resolve-screen 400 |

Haiku was cheapest, but its create path was not reliable enough for a public demo. Sonnet was much cheaper than Opus
and wrote the content correctly, with recoverable query friction. The interface changes above are meant to remove the
Haiku and Sonnet friction. Whether model tier alone still decides reliability has not been measured.

## The payload tool

The owner was open to local tools in the Run's shell that help cheaper models build payloads, and `incident-payload`
is that tool. It does the mechanical parts (summary, labels, fields, the ADF Description, comment text, which Alerts are
new, repeat or resolved, and the duration) and leaves every judgment to the Run: whether there is a Match, and
whether to create, update, close or skip. The tool is local: it opens no socket, starts no process and
reads no environment variable, and the Forwarder's one-create rule holds whatever it prints. Its lifecycle
steps write no file; `investigate`, added after this record, writes one ADF body file under the Run
directory and prints a `--body-file` command (ADR 0003's 2026-10-02 amendment).

## Not verified live

- That a replay creates its Incident on the first create attempt, with a Description that lists every firing Alert
  and its value, and that no `Invalid JSON` line appears in a Run log. The printed create was run through jira-as's
  offline `--dry-run` and the Forwarder's content check on its payloads, not against a site.
- That no Run logs `Output too large`, and that no Run issues JQL without a project clause.
- That the Resolve transition succeeds on its first POST. That depends on the admin request.
- That a fresh take's first Notification carries no resolved Alerts from the take before, and the 3-minute settle
  wait itself. The wait is derived, not measured.
- The Docker build with `COPY --chmod`, and the exact words jira-as prints for the Forwarder's 400.
- The step the findings list last: rerunning one fixture sequence on Opus, Sonnet and Haiku and recording cost,
  duration, command failures and the final Jira content. It needs a live seat and a real site, and has not been done.
- The model ids `claude-sonnet-5-5` and `claude-haiku-4-5` in the runbook, which were not checked against a seat.
