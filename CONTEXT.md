# Many Alerts to One Incident

A demo in which the Alerts one Fault raises across a simulated distributed system each trigger a headless Claude run inside a container, and those runs reduce the Alerts to one Incident in the Jira OPS project, with a suggested root cause a responder can check.

## Language

### Simulation side

**Fault**:
One injected failure in the simulated system, with a documented Ground truth.
_Avoid_: scenario, chaos experiment, failure mode, incident, outage

**Ground truth**:
The documented true cause of a Fault, written when the Fault is, in two layers: the **Mechanism**, what actually breaks stated in system terms, and the **Trigger**, the switch that injected it. A Report's Suggested root cause is judged against the Mechanism alone, so naming the Trigger is not a diagnosis.
_Avoid_: root cause, answer key, expected result

**Cascade**:
The set of Alerts one Fault fires.
_Avoid_: alert storm, flood, correlated alerts, alert group

**Event**:
A timestamped, named, structured record that something happened, as distinct from a log line. The only sense the word has here; an Alert and a Notification are not Events. Three kinds: Kubernetes Event, Change and Run event.
_Avoid_: structured event, log event, occurrence

**Kubernetes Event**:
An Event the cluster itself records about a pod, node or rollout, such as OOMKilled, BackOff or FailedScheduling.
_Avoid_: k8s event, cluster event, pod event

**Change**:
An Event recording something someone did to the system: a deploy, a config edit, a feature-flag flip.
_Avoid_: deployment event, annotation, change event, release

### Alerting side

**Alertable condition**:
One distinct thing that is true of the system while a Fault is firing, named against a signal that exists. The unit a Cascade is designed in, before any threshold turns it into an Alert.
_Avoid_: alert rule, condition, symptom, trigger

**Alert**:
One Grafana alert rule instance, identified by its Fingerprint. It is either Firing or Resolved.
_Avoid_: alarm, event, rule

**Fingerprint**:
Grafana's stable hash of an Alert's label set. The identity of an Alert across every Notification.
_Avoid_: alert id, hash, key

**Notification**:
One webhook POST from Grafana, carrying one or more Alerts.
_Avoid_: webhook, payload, message, event

**Firing**:
The Alert state meaning the condition currently holds. A Notification may report the same Firing Alert repeatedly.
_Avoid_: active, triggered, alerting

**Resolved**:
The Alert state meaning the condition no longer holds.
_Avoid_: cleared, ok, recovered

### Sync side

**Receiver**:
The HTTP endpoint inside the container that accepts Notifications, suppresses exact repeats and coalesces pending Alerts while starting Runs one at a time.
_Avoid_: harness, server, listener, webhook handler

**Run**:
One headless Claude invocation, started by the Receiver to handle Alerts from one or more Notifications, possibly coalesced.
_Avoid_: harness, agent, session, job

**Skill**:
The one file that tells a Run the demo project's facts and how to act on an Alert. The repo
holds it as a template, copied into the image; the Receiver renders it from `.env` at every
start, and a Run reads that rendering, never the template. Nothing else instructs a Run.
_Avoid_: prompt, playbook, instructions, runbook

**Forwarder**:
The Receiver-controlled service that holds the managed service credentials and mediates a Run’s authorized Jira, Confluence, Grafana and Kubernetes requests. A Run presents a service-scoped Sentinel, not the corresponding real credential.
_Avoid_: proxy, sidecar, hand, vault

**Sentinel**:
The random token registered with the Forwarder for one Run and one service. It grants only that Run’s declared service scope during its authorized lifetime, and is invalid for another service or after revocation or expiry.
_Avoid_: fake token, dummy credential, placeholder, api key

**Transcript**:
The stream-json output of one Run, one Run event per line. The Receiver renders it into the container log as it arrives and keeps it raw as `transcript.jsonl` in the Run's working directory, and a recorded Transcript is committed as a fixture.
_Avoid_: log, output, stream, session log

**Run event**:
One line of a Transcript: one thing the Run did — assistant text, a tool call, a tool result, a denial, or the final result. Never shortened to "event" on its own: an Event is the wider term, and an Alert and a Notification are not Events.
_Avoid_: event, message, chunk

**Eyes**:
The read-only tools a Run may execute to look at telemetry: queries against logs, metrics, traces and Events, and whatever read-only view of the cluster the map grants.
_Avoid_: query tools, observability tools, read tools, sensors

**Hands**:
The tools a Run may execute that change something outside itself: the Jira and Confluence operations. Never the cluster or the system; a Run reports and does not remediate.
_Avoid_: write tools, actions, actuators, effectors

**Memory**:
What a Run can consult across Runs: authoritative Incidents in OPS, reviewed reference knowledge in Confluence, and cited observations and retrieval hints in the Memory directory.
_Avoid_: state, history, cache, context, knowledge base

**Memory directory**:
The directory that retains a Run’s cited observations and retrieval hints for later Runs within a rehearsal. It records learning, not authoritative Incident state.
_Avoid_: notes, scratch, memory file, cache

### Jira side

**Incident**:
An OPS issue of type Incident that represents one Fault's lifetime as the Run understands it, carrying the Fingerprint of every Alert it explains.
_Avoid_: ticket, issue, case, request

**Match**:
The open Incident a Run judges an Alert to belong to. A judgment, not a label lookup; an Alert has at most one Match.
_Avoid_: duplicate, existing incident, correlation

**Report**:
The body a Run writes into an Incident: what happened, to what, in what order, on what evidence, with a Suggested root cause and a suggested remediation.
_Avoid_: description, summary, postmortem, RCA, write-up

**Suggested root cause**:
The cause a Report names, with the evidence it cites and the confidence it states. The Run's claim, never shortened to "root cause", which would blur it with the Ground truth.
_Avoid_: root cause, diagnosis, finding, conclusion

**Problem**:
An OPS issue of type Problem that groups Incidents that recur. Reserved; not built in this effort.
_Avoid_: parent, root cause ticket

**Recovery journal**:
The Receiver’s record of admitted work, its processing outcomes and evidence needed to reconcile uncertain external effects. It preserves unfinished work for an explicit recovery decision; it is not authoritative Incident state or Run-written Memory.
_Avoid_: Transcript, Memory directory, Incident database
