# One Forwarder sidecar with scoped TLS endpoints

Status: accepted, 2026-09-18, resolving ticket 17 through two human-approved rounds. Extends ADR 0002 and clarifies ADR 0007.

Jira, Confluence, Grafana and Kubernetes need distinct credentials and operation boundaries, while Runs must hold only revocable sentinels for these services. We choose one Forwarder sidecar in the Receiver/Run pod, with a separate loopback HTTPS port for each service. The Receiver and its Run children remain in the main container; the Forwarder occupies a second container. This corrects ADR 0007's claim that a pod is one container without changing the in-cluster venue.

## Routing and trust

Each listener fixes the service and upstream origin, preserves native client API paths (including Confluence's /wiki), and requires a sentinel for that service. Jira and Confluence have separate credential/routing configuration even when they share a site. Unknown operations, caller-selected upstreams and unsafe paths are denied. The chosen topology avoids multiple Forwarder processes and client-specific route prefixes.

Use deployment-local TLS rather than patching Confluence to allow HTTP. Operator-controlled tooling creates the CA and endpoint certificate. The CA signing key stays outside the pod and image; only the Forwarder mounts the server private key. Clients receive public CA trust alongside needed public roots and verify hostname/IP and expiry. Rotate through a controlled deployment restart; never bypass verification. Exact ports, certificate lifetime and client trust wiring remain specification and acceptance work.

## Credentials and authority

Give each Run separate per-service sentinels, valid only for declared service scopes and the Run lifetime. The Forwarder holds independently scoped upstream credentials, including a narrowly scoped Kubernetes service-account credential. Never mount that token or other managed upstream credentials in the Run container. ADR 0013 supersedes ADR 0002's Anthropic credential exception: add a fifth fixed Anthropic endpoint, retain its API key outside Runs, and require per-Run sentinels and verified client compatibility.

Receiver registration/revocation uses an authenticated control channel inaccessible to Runs, backed by an enforced OS/credential boundary rather than just an omitted environment variable. Register scopes before launch, revoke on all exit/timeout paths, and invalidate previous admissions after Receiver or Forwarder restart. Bound orphaned authority through leases tied to ticket 21's Run budget. A Forwarder restart begins with no valid sentinels; do not restore them from a persisted token list. Revocation cannot roll back an upstream request already dispatched, whose outcome may be unknown.

Kubernetes access is mediated read access, including required pod status; ticket 12 chooses the exact tools/resources. Runs get no general-purpose API proxy, writes, Secret reads, exec, attach or port-forward. Jira and Confluence retain only explicitly authorized writes. Enforce allowed request operations and telemetry rehearsal scope through validated requests, not merely HTTP verbs, a Viewer role or dashboard filters. A query that cannot be safely scoped is refused, not silently broadened.

## Bypass, responses and readiness

Disable anonymous Grafana access, block direct Run access to unauthenticated telemetry backends, isolate service credential mounts and scope upstream roles/RBAC. Ordinary pod-level network policy is not proof of separation between sibling containers; the specification must prove actual routing, authentication and OS boundaries, including the mediated Anthropic path required by ADR 0013 and the telemetry-export exception. A service route without enforceable scope remains unavailable.

Reject upstream redirects instead of relaying Location to clients; configure canonical upstream addresses. Strip caller Authorization, Host and proxy/hop credentials before adding the service credential. Bound request/body/response sizes and timeouts. Never transparently retry a mutation after timeout, disconnect or uncertain delivery; report it for reconciliation under ticket 21 and the relevant Jira/Confluence contract. Truncation and timeout must not be presented as success.

Require the Forwarder, control channel, TLS boundary and mandatory Jira, Grafana and Kubernetes read routes to be ready before new Runs start. This does not authorize discarding received/pending Notifications; Receiver admission/recovery is a separate contract. Confluence may be unavailable with visible missing Memory under ADR 0009. Mid-Run transport/tool errors remain explicit, with overall classification/recovery owned by ticket 21. No direct-upstream, real-token or broadened-access fallback is allowed. ADR 0010's telemetry export remains best effort and cannot become a mandatory Run gate.

## Evidence and remaining work

Offline source facts show that current code is an in-process, loopback HTTP Forwarder with one Jira Basic credential and one active sentinel. It fixes the upstream origin and does not itself follow redirects, but returns redirects to the client. The installed Confluence client requires HTTPS. No current sidecar, TLS listener, multi-service credential support, Kubernetes mediation or control-channel isolation is implied by this ADR.

Ticket 36 specifies endpoints, trust/lease/size/time bounds, process identities, control transport, secret mounts, query-aware enforcement and rejection/read-back tests. Ticket 12 chooses Eyes tools/operations, ticket 19 must prototype against this accepted boundary, ticket 33 defines Confluence grants, and ticket 21 owns Run outcome/retry behavior. Client trust, actual upstream roles, scope enforcement and bypass resistance require acceptance evidence. No runtime/Skill changes, live credentials, cluster or demo were used to accept this planning decision.

ADR 0013 adds the fifth Anthropic listener and makes its readiness mandatory for model Run admission; the four-service layout above records this ADR's original scope. No mediated Anthropic implementation is implied.
