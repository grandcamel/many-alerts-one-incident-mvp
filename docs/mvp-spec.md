# MVP: one agent, many alerts, one Incident (48-hour demo)

**The promise:** a fault makes several related Grafana alerts fire. Grafana sends them to the Receiver in one webhook,
and one Claude Run creates **one** Jira Incident. When those alerts repeat, or more related alerts fire, later Runs
**update** that same Incident: they add labels and comments. They never create a duplicate.

Out of scope until non-prod: hardening, chapter two's journal and containment, Kubernetes, and a Forwarder-side model
proxy. The only runtime is Docker Compose, as verified live on 2026-09-24.

## Shared interfaces (every lane codes to these)

| Item | Value |
|---|---|
| Group label on every related alert rule | `incident_group` (demo value: `checkout-outage`) |
| Grafana grouping | `group_by: [incident_group]`. Demo timings: `group_wait: 30s`, `group_interval: 1m`, `repeat_interval: 3m` |
| Jira group label | `grp-<incident_group>`, lower-case, `[a-z0-9-]` only |
| Jira session label | `ses-<DEMO_SESSION_ID>`, set by the Receiver from `.env` `DEMO_SESSION_ID` (`[a-z0-9-]{1,32}`), so rehearsals don't match the real demo |
| Jira Fingerprint labels | `fp-<fingerprint>`, one per alert ever seen in the group (added, never removed) |
| Match | open Incident: `labels = "grp-…" AND labels = "ses-…" AND statusCategory != Done` |
| Model credential | `ANTHROPIC_API_KEY` (a work API key) is passed to the Run process environment. `CLAUDE_CODE_OAUTH_TOKEN` still works; set exactly one of the two |
| Runs | strictly one at a time (the Receiver's queue), so no two Runs race to create |

## Behaviour (Skill v2)

| Notification | Match | Action |
|---|---|---|
| firing, one or more alerts | none | **Create one Incident**: summary from the group, labels `grp-`, `ses-` and every `fp-`, Description a short partial Report of all firing alerts (values, start times) |
| firing, new or repeat alerts | open | **Update**: add any new `fp-` labels, and comment which alerts are new, which repeat, and their values. Move `Open` to `Work in progress` on the first update |
| resolved, every alert in the group | open | Comment and close (chapter one's close path) |
| resolved | none | Do nothing, and say why |

## Demo alert rules

Three to four rules on the existing demo app, all labelled `incident_group=checkout-outage`, so that stopping traffic
(chapter one's existing fault) fires several of them within about a minute:
- the existing traffic-absence rule;
- a success-rate or 2xx drop rule;
- a synthetic health-probe failure rule;
- one "sustained outage" rule with a longer pending period, which fires later as a **related** alert and so exercises
  the update path.

## Proof

`verify --mvp --replay` posts four grouped, canned Notifications and watches their Jira
effects while leaving traffic untouched. `verify --mvp --live` stops traffic, watches the
real grouped Notifications and restores traffic. Both modes use paid Runs and write Jira
Incidents. They assert:
1. exactly one Incident with `grp-` and `ses-` exists, carrying at least two `fp-` labels;
2. a later repeat produces a comment, not a new Incident;
3. the sustained-outage alert adds its `fp-` label and a comment;
4. the closing Resolved Notification completes the Incident (after traffic restarts in live mode);
5. at no point do two open Incidents share the group and session labels.
