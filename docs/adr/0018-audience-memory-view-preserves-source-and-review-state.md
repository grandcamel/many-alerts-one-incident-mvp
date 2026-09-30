# The audience Memory view preserves source and review state

Status: accepted, 2026-09-18, resolving ticket 34 through one approved decision round and a consistency audit. Applies the authority, telemetry, scoring and approval boundaries in ADRs 0009, 0010, 0014 and 0017.

Showing more Memory records must not imply better diagnosis or turn a draft into approved knowledge. Use one operator-only read-only presentation view, screen-shared by the presenter, with four sections: Incident state (OPS), Observations and hypotheses (Memory directory), Postmortem drafts, and Approved references. This is a projection of verified sources, not another Incident or Memory authority. Keep it outside Run-readable feeds. Do not publish a dashboard, give attendees new account access or stream raw Transcripts. Existing Grafana activity/timeline is complementary, not the source of human scoring verdicts.

## Scope and provenance

Default to the current rehearsal and selected Incident/Run. Every item has a short sanitized summary, source class, verification/review status, source revision or observation time, and a safe provenance reference the presenter may inspect. Mark hypotheses explicitly, drafts unapproved, and references with actual manifest approval/version provenance. Distinguish what was available to a Run from what retrieval evidence shows it received; availability does not prove use. Count confirmed records by category, with gaps and unknown counts visible. A total Memory count is not a quality score.

A rehearsal switch visibly resets context and does not import prior artifacts automatically. Source access and reference approval remain governed by ADRs 0009/0017, independent of presentation selection. Keep identity, credentials, raw errors, adjudication Ground truth and private audit bodies out of rendered cards and shared telemetry.

## Story and review

Use a presenter-controlled before/after sequence: show approved references and prior cited observations available at admission, then confirmed learning/draft changes after the Run. A pinned before snapshot records historical context; later updates must not rewrite what the earlier Run saw. Overlay visible current corrections/revocations on historical items. A snapshot cannot make withdrawn material currently approved or serve it back to a Run.

Label cold-start and Memory-assisted conditions explicitly. Demonstrate provenance and changed content, without claiming Memory improved diagnosis or speed absent a controlled comparison. Include a separately sourced sanitized human-review summary, labelled pending, reviewed or disputed with qualified rationale. It is neither an execution-success indicator nor reference-publication approval. Never expose Ground truth or raw audit evidence through that summary. A newly confirmed draft remains unreviewed until the curator actually approves a separate reference.

## Refresh, failure and replay

Refresh projections every five seconds when available. Preserve source observation/verification times; a successful refresh does not make old source data fresh. After 30 seconds without successful refresh, mark the affected section stale with its last verified time. These are display policies, not guarantees of backend latency or freshness. Show unknown, unavailable, revoked, write pending/failed and correction required distinctly rather than zero, empty or success.

Keep confirmed OPS updates visible when optional Memory fails. Failed secondary writes must not appear as newly learned content, and revocation/cancellation must not visually roll back confirmed OPS effects. Show collection/verification gaps explicitly. Projection failures cannot block Incident work or fall back to raw output that exposes identity or secrets.

Live/replay mode, rehearsal/Run identity and recorded sample time remain visible. Replay stays labelled throughout, uses the same status vocabulary, and cannot masquerade as current live work. Permit presenter selection, pin/unpin and safe provenance inspection only. Approve, publish, retry, reset and other mutation controls belong outside this audience surface. Unavailable or redacted details are labelled, never replaced with invented content.

## Evidence and follow-up

Accepted constraint evidence records the existing source-authority, privacy, comparison and approval boundaries. This decision specifies presentation behavior, not an implemented UI or a new data-access grant.

Ticket 44 specifies field allowlists, source/projection identities, selection/snapshot/revocation and refresh behavior, access separation and offline acceptance. Tickets 32/35/39/43 supply storage, timeline, review and reference-state interfaces. No dashboard, runtime, Skill, sharing/grant, publication, model or demo changes occurred.
