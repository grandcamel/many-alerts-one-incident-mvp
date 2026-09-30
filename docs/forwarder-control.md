# Forwarder service, lease and control core

The application modules `forwarder_services` and `forwarder_leases` provide the
first local implementation unit of the reviewed Forwarder contract. They are
not wired into the legacy HTTP/OAuth launcher. No listener, native client or
provider connection is started by importing or using these modules.

`SERVICE_PROFILES` pins five immutable IPv4 loopback listener descriptions.
`classify_readiness` requires explicit Boolean route facts: missing Jira,
Grafana/Eyes, Kubernetes or Anthropic readiness holds the mandatory route set.
Missing Confluence readiness is reported separately as degraded optional Memory.
The result classifies supplied facts; it does not attest them or authorize a Run.

`LeaseRegistry` belongs to a trusted Receiver control adapter. It creates a fresh
Forwarder generation and scoped random sentinels, supports registration followed
by explicit activation, and preserves immutable Run/attempt/service bindings.
An exact live registration replay returns its grant. Changed scope or expiry,
expired/revoked replay, and wrong service or generation cannot restore authority.

The registry uses one monotonic clock and lock. Leases expire at their supplied
deadline, no later than the bounded registration/launch window. Heartbeat loss,
control EOF and Receiver boot replacement invalidate existing authority. A late
heartbeat or repeated handshake cannot revive it. Clock failure or regression
holds the registry; restart recovery belongs to the durable Receiver journal.

The grant intentionally carries its sentinel to the trusted controller, with
the secret excluded from its representation. Receipts and snapshot projections
contain metadata only. Control reason codes are closed values. Count, age and
encoded-byte limits bound retained metadata; these are not measurements of the
Python process's heap. History is diagnostic rather than a durable audit log.
The limits are 256 live leases, 1,024 retained lease records, 128 diagnostic
receipts, and 512 KiB of encoded metadata. Registration reserves space for future
state changes and a full diagnostic ring, so the byte budget can refuse a new
lease before the record-count limit. Recent lease records are never evicted to
admit another lease; diagnostic receipt loss is counted explicitly. Records and
receipts age out after 310 seconds. `metadata_bytes` counts the full snapshot's
canonical JSON encoding, including that count field.

`check` is an instantaneous authorization observation. It does not authorize a
later network write: the future transport must recheck current authority and
coordinate dispatch initiation with revocation. This module cannot prove socket
peer identity, kernel isolation, safe native-client configuration, provider
credential custody, or the disposition of bytes already sent.

## Authenticated control sessions

`ForwarderControl` serves an already accepted Unix stream socket. Both sides
check the actual OS peer UID: the server uses the configured Receiver UID, and
`authenticate_receiver` uses the configured Forwarder UID. Darwin uses
[`getpeereid`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
to obtain effective credentials established at connection time. The Linux
`SO_PEERCRED` branch needs validation on Linux. Unsupported identity mechanisms
deny authentication.

Construction supplies a 32-byte control secret. A fresh challenge, generation
and Receiver boot ID bind role-separated HMAC-SHA256 proofs. The Receiver helper
verifies the Forwarder proof before returning handshake metadata. The raw secret
is never transmitted. A successful registration response intentionally delivers
the lease sentinel over that authenticated channel; diagnostics do not retain it.

Commands are limited to registration, activation, revocation and heartbeat.
Every controller refuses registration for a service without a scope type (only
Jira has one). A controller given a dispatch gate replaces registration with
scoped registration, which carries one attachment of at most 16 KiB within two
seconds, and adds a closeout command (see "Scope delivery and control
closeout"). Exact parameter sets and increasing sequence numbers prevent extra control
fields from overriding session identity. Frames are length-prefixed UTF-8 JSON,
limited to 8 KiB, four object levels and bounded scalar fields. Each frame uses
one absolute deadline, at most ten seconds in this controller. Malformed frames,
duplicate keys and unsupported values fail closed.

One connection owns control. Successful replacement revokes the previous
connection's leases, including when the Receiver boot ID is unchanged. Old
commands and finalizers cannot act on a replacement owner. EOF, timeout, failed
response or rejected commands release authority before any error response is
written. If closeout fails, `LeaseRegistry.hold()` permanently denies authority
without reconstructing a clock; recovery needs a fresh registry generation. A
post-install fence stops a session replaced or closed during scope installation
from writing a scoped grant. As with Register, a replacement or shutdown after
that fence can still let the reply reach the old peer; the replacement revokes
that lease, or the shutdown holds the registry. An uncertain closeout
observed by any session holds the registry.

At most four accepted connections execute per controller. Unauthenticated peers
can occupy these slots until their bounded frame deadlines. The caller must
provision the listener and restrict access; this module does not create a socket
path, verify its directory ownership or mount permissions, or load a mode-0400
secret. The caller must also give this adapter exclusive control of its registry.
Local socket tests do not establish deployed UID/mount/kernel or secret isolation.

## Private listener and shutdown

`PrivateControlListener` creates one filesystem Unix socket beneath an
operator-provisioned absolute parent with exact owner UID, control GID and mode
0710. A fresh exclusive child stays private during preparation, then publishes
as mode 02710 with a mode-0660 socket. The complete endpoint is limited to 100
encoded bytes. Directory descriptors anchor identity checks and cleanup; parent
and endpoint permissions are checked before and after accepting a connection.
Accept has a finite deadline of at most one second. Accepted sockets still need
`ForwarderControl` authentication before they can control leases.
Use one accept caller at a time. A lifecycle lock protects open/close and
filesystem guards, while close can interrupt the blocking accept. The returned
endpoint and accepted socket are observations at their checks; later shutdown
still requires the controller's admission gate and caller-owned worker tracking.

The operator must establish stable protected ancestors, trusted group membership,
ACL and mount policy, and distinct deployed identities. Local pathname checks
cannot establish these conditions. Cleanup preserves replaced or unexpectedly
populated paths and reports `unknown`; it never recursively removes a directory
or sweeps stale endpoints. Portable identity-check/unlink operations do not form
an atomic guarantee against trusted same-UID/operator filesystem mutation.

`ForwarderControl.shutdown()` permanently holds lease authority under the same
lock used for admission, then interrupts all admitted sockets outside that lock.
Later connections receive `control_closed`, including when old handlers still
occupy every slot. Call it before removing the private listener. Socket closure
does not prove handler completion: the caller must observe or join its workers.
A held registry requires a fresh controller and registry generation for recovery;
failed revocation remains `unknown` rather than a successful closeout receipt.

## Managed local control service

`ControlService` owns an unopened `PrivateControlListener` and an unused
`ForwarderControl`. Its constructor starts no work; `start()` opens the endpoint
and starts one accept loop. The service admits at most four handler threads,
retaining their records until thread termination is observed. One additional
transient accepted socket can belong to the accept loop during dispatch or
capacity rejection; there is no user-space queue of waiting clients.

Use `stop(timeout=2.0)` to hold controller authority, close owned descriptors and
the listener, and observe the accept loop and handlers against a shared join
deadline. The finite timeout must be positive and at most ten seconds. A
`ServiceCloseout` reports `state`, `reason`, `listener_state` and `threads_alive`.
The reason records the shutdown request or failure; `state` determines whether
cleanup completed. Thus a requested stop can have reason `stopped` and state
`unknown` while threads or startup work are still pending.
`stopped` requires completed cleanup and no live owned threads; `unknown` keeps
incomplete joins, fatal failures and uncertain endpoint cleanup visible. A later
stop may observe that threads exited, but cannot convert uncertain endpoint
cleanup into a successful removal receipt. Python scheduling and OS stalls are
not hard real-time bounded by this join timeout.

Start and stop are terminal: a stopped service never restarts its held registry
generation. Authentication failures from ordinary clients do not themselves
poison the service. Unexpected accept/worker orchestration failures initiate
shutdown with fixed diagnostics. The owner must keep this service's listener and
controller exclusive; importing or constructing it does not wire the legacy
launcher, load a secret or establish deployment isolation.

## Fixed service TLS client boundary

`connect_service_tls(service, ca_pem=..., timeout=1.0)` returns an exclusively
caller-owned SSL socket connected to the service profile's fixed IPv4 loopback
address and port. It sends no application bytes, accepts no alternate destination,
and performs no DNS lookup, proxy selection or retry. A successful connection is
a transport observation; it supplies no lease or request authority.

The function accepts only bounded public CA certificate PEM supplied in memory,
with no private-key blocks or non-CA certificates. It creates a fresh client
context with certificate and hostname verification, TLS 1.2 or newer, and no
common-name fallback. It loads only that CA bundle, without loading system roots,
environment settings or files. Python documents these verification controls in
the [ssl reference](https://docs.python.org/3.13/library/ssl.html).

After the verified handshake, the certificate must name exactly the fixed service
DNS identity and 127.0.0.1 in its SAN. Wildcards, additional identities and missing
IP SANs are rejected. Leaf validity must be positive and at most 24 hours, with
at least ten minutes remaining. These are the local ticket-36 certificate-policy
bounds, not evidence of deployed CA custody or certificate rotation.

One monotonic deadline covers TCP connect, TLS handshake and certificate policy
evaluation. Clock faults or regression deny the connection. Setup failures close
owned sockets; interrupted setup still attempts cleanup. If close and detach both
fail, the code preserves the original failure rather than closing a descriptor
still owned by another socket object. Exceptions do not report raw SSL details.
The caller owns request deadlines and socket closure after a successful return.

Tests use real local TLS handshakes and synthetic certificates. A test adapter
asserts the selected fixed destination before connecting to an ephemeral fixture
port; this does not qualify actual fixed-port listener binding or native clients.

## Fixed service TLS listeners

`FixedTLSListener(service, context=...)` adopts a trusted operator-supplied
server SSL context. The operator loads its certificate/key first, then transfers
exclusive ownership: the context must not be reused or mutated afterwards.
Duplicate adoption and TLS key logging are rejected. The constructor starts no
listener, loads no files and does not prove certificate custody or freshness.
Certificate CA, identity and lifetime validation still belongs to the strict
client/readiness probe.

The listener configures TLS 1.2 or newer and HTTP/1.1 ALPN. Its SNI callback rejects
missing or mismatched service names with an unrecognized-name alert. Python's
[SSL context reference](https://docs.python.org/3.13/library/ssl.html#ssl.SSLContext.sni_callback)
describes SNI callbacks and TLS configuration. Client certificates are not used
for request authentication; the request sentinel and scope checks remain required.

`open()` binds only the selected profile's fixed IPv4 loopback port, with backlog
four and no address/port reuse or fallback. Opening is one-shot, including after
failure or close. `accept(timeout=1.0)` admits at most one caller and uses one
finite deadline (at most ten seconds) across waiting and TLS handshake. Idle
accept polls at most 0.1 seconds at a time, clipped to the remaining deadline,
so terminal shutdown can be observed on systems where socket close does not
promptly wake a blocked accept. TLS handshake steps run nonblocking under the
state lock; read/write readiness waits run outside that lock for at most 0.1
seconds, clipped to the same original deadline. Only TLS want-read/want-write
continues the same handshake; fatal failure receives no automatic retry. A
successful handshake restores a finite remaining timeout before transfer.
All owned sockets are non-inheritable.

`close()` interrupts the listening socket and an in-flight handshake, while
preserving the caller's ownership of previously returned connections. It returns
`unknown` while accept is exiting; a later call may observe `closed`. Failed
socket cleanup retains its handle for safe retry and permanently latches
`unknown`, denying subsequent accepts. Cleanup and raw-to-TLS ownership transfer
are serialized. The caller owns worker joins and returned socket closure; Python
and OS stalls are not a hard real-time shutdown guarantee.

Local tests cover real TLS for all five services, strict-client and parser
composition, exact/missing/wrong SNI, HTTP/1.1 ALPN, stalled/plaintext peers and
shutdown interruption. Handshake fixtures assert the fixed address selection
before redirecting to ephemeral ports. A separate test binds each actual fixed
port and verifies exclusive occupancy without fallback. These observations do
not qualify deployed namespace isolation or native client configuration. The listener fixture
uses known-length collection; the bounded collector below adds incremental
request receipt. Response handling and service route policy remain subsequent
implementation units.

## Common HTTP request structure

`parse_request(data, service, allowed_query_keys=frozenset(),
accept="application/json")` validates one complete byte buffer. It accepts
HTTP/1.1 origin-form requests using the deliberately narrow local profile in
`forwarder_http`. The parser rejects ambiguous framing and path aliases, drawing
on the message syntax in [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
and URI grammar in [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html). This
profile is stricter than general HTTP syntax; native client compatibility still
requires separate evidence.

The request line including CRLF is at most 2 KiB; headers after that line,
including the final blank CRLF, are at most 16 KiB and 64 fields; the body is at
most 256 KiB. GET permits no body, absent length or canonical zero. POST, PUT,
PATCH and DELETE require an exact canonical Content-Length and application/json
Content-Type. The body is preserved as bytes; route-specific JSON validation is
still required. Any captured bytes beyond the declared body are rejected.

Host must match the selected service DNS and fixed port. Authorization and Accept
are required. The narrow header allowlist also permits Content-Length,
Content-Type and an optional User-Agent, which is discarded. Every duplicate or
unrecognized header fails closed. The expected Accept and query-key allowlist
are trusted route configuration, never caller-requested authority. Queries are
denied by default. Values require separate operation-specific validation; decoded
query delimiters remain values and must be safely encoded if reconstructed.

Jira and Confluence use canonical Basic credentials with user `run` and the lease
sentinel as password. The other services use canonical Bearer sentinels. Each
sentinel must encode exactly 32 bytes as unpadded base64url, including canonical
pad bits. The immutable result excludes path, query, body and sentinel from its
representation and retains no raw headers. Parsing only extracts the token;
the current generation, lease, service and scope must still be checked.

This module opens no sockets and grants no dispatch or readiness authority. A
future server must bound receipt while collecting the buffer, enforce TLS and
absolute deadlines, close after one request, select an authorized route, and
coordinate lease checks with dispatch and revocation. A complete-buffer parser
cannot detect bytes that arrive later or establish deployed transport behavior.
The existing launcher is not wired to it.

## Bounded request collection over TLS

`parse_request_head` shares the complete parser's header validation and returns
the declared body length without allocating a body. It requires exactly a
complete request line and header section. `receive_request(connection, service,
deadline=...)` uses that same grammar while collecting one request from an
already handshaken server TLS socket. The caller must bind `service` to its
listener; transport-state checks do not attest service or lease authority.

The absolute monotonic deadline comes from the original handler budget clipped
to its lease. It must be finite, future and at most forty seconds away when
collection starts. Each read uses the remaining time, with clock checks before
and after reads and after restoring the socket's prior timeout. A slow sender
cannot reset the budget by producing another fragment. Malformed input, EOF,
timeouts and restoration faults cannot become a successful request result.

Line/header collection obeys the existing 2 KiB/16 KiB caps and uses reads of at
most 4 KiB, further clipped to the applicable cap plus one. Validated headers
supply a body length of at most 256 KiB; body reads are at most 64 KiB and the
remaining body plus one. Coalesced body prefixes are preserved. Captured bytes
past the declared body are rejected; exact completion does not wait for EOF or
perform a blocking extra-byte probe. Body contents remain unchanged for later
route-specific validation.

A permanent socket marker, claimed under a lock, prevents a second or concurrent
collection attempt, including after failure. The caller retains socket ownership
and must close after one response or any error. The collector sends nothing,
closes nothing and retries no request. It cannot detect later bytes or another
unread TLS record; those bytes must never be interpreted as another request.
Timeout restoration failures preserve an existing receive error or interruption,
and cannot silently permit success when called from another exception handler.

Local TLS tests compose the listener, strict client and collector with fragmented
and opaque bodies, malformed heads, captured pipelining, EOF and stalled input.
No native client, upstream effect, route authorization, response writer or
production admission is qualified by these tests.

## Non-streaming response structure

`forwarder_http_response.parse_response(data)` validates one complete buffered
HTTP/1.1 response. The narrow local profile accepts 2xx, 4xx and 5xx statuses;
all informational and redirect statuses are rejected. It limits the status line
to 2 KiB, the header region to 16 KiB/64 fields and the body to 1 MiB. It rejects
duplicate fields, malformed framing, chunked or compressed transfer, upgrades,
truncation and captured excess bytes. Other well-formed upstream headers and the
raw reason phrase are discarded, including Location and credential headers.

Body responses require canonical Content-Length and exactly
`Content-Type: application/json`. Their bytes remain opaque: this codec does not
validate JSON structure, returned scope or a service's success schema. Status 204
requires no body, length or content type; 205 requires exactly zero length and
no body or content type. Connection options naming a framing field are rejected.
These conservative framing/content-type choices do not establish compatibility
with any real upstream or native client. SSE remains a separate qualified route.

`serialize_response(response)` revalidates the public immutable status/body value
and constructs a canonical response with a fixed reason, computed length where
allowed, and `Connection: close`. It emits no supplied upstream headers and
excludes the body from object representations. Serialization is a pure operation:
it opens no socket and sends nothing. Trusted route policy must still validate
the body; a sanitized receipt must be produced before any response is returned
to a client. Creating bytes is neither dispatch permission nor effect evidence.

Complete-buffer bounds do not bound an upstream socket read or detect later
unread bytes. The transport owner must enforce collection and original handler
deadlines, then coordinate receipt-before-send and close after one response.

## Bounded TLS response collection

`parse_response_head` shares the full response parser's framing rules and returns
only status and declared body length, without allocating a dummy body.
`receive_response(connection, deadline=...)` then collects one response from an
already established client TLS socket. It checks current TLS/client verification
configuration and accepts only absent ALPN or HTTP/1.1. The connection owner still
must establish approved fixed-origin identity/trust; these checks cannot attest
how an existing connection was created or authorize an upstream route.

The caller supplies its original absolute monotonic handler deadline clipped to
the lease, at most forty seconds away. Each read is limited to twenty seconds or
the remaining deadline, whichever is smaller. Clock checks before/after reads
and timeout restoration reject expiry, faults or regression. A completed read
that took twenty seconds or more also rejects, even if the overall deadline
remains open. Fragments do not reset that deadline. Timeouts and read errors
are not retried.

Status-line and header reads obey the 2 KiB/16 KiB caps, at most 4 KiB per read
and further clipped to the applicable remaining cap plus one. Shared head parsing
rejects redirects, unsupported framing and invalid lengths before further body
reads. A coalesced body prefix is preserved; body reads are at most 64 KiB and
remaining length plus one, with an overall 1 MiB body cap. Headerless 204 and
205 framing finish without waiting for EOF. Captured excess bytes are rejected;
exact completion does not probe for later bytes or another unread TLS record.

A permanent socket claim prevents repeated or concurrent collection, including
after failure. The owner must close the socket after this exchange and must not
remove the marker or share the socket. Timeout restoration cannot falsely return
success or mask an earlier failure. The collector sends nothing, closes nothing
and returns only status/opaque body; it does not create a receipt or classify an
external effect. The owner must use dispatch context to retain uncertain or
partial outcomes. A parsed 2xx response is not external-effect confirmation.

Real local TLS fixtures exercise fragmented responses, opaque bytes, no-body
statuses, invalid heads, captured extras, stalled input and EOF. They do not
qualify a real upstream, native client, credential boundary or deployment.

## Sanitized receipts and receipt-gated response send

`forwarder_receipts.ReceiptLedger(generation=..., clock=...)` records one
sanitized `ForwarderReceipt` per handled request before any response bytes are
returned. A handler calls `reserve` before opening an upstream connection,
`begin_connect` immediately before opening it, `begin_dispatch` immediately
before the first possible upstream write, and `finalize` once the outcome is
known. These explicit transitions are the seam for later lease, permit and
upstream units; this module opens no connection and checks no lease or route.

Dispatch states follow the ticket-36 receipt vocabulary. A reservation that never
began connecting can only become `NOT_DISPATCHED`. After `begin_connect` (where a
future dispatch permit is consumed) it becomes `FAILED` when the connection
attempt failed before any write, or `DISPATCHED_UNKNOWN`. After `begin_dispatch`
it becomes `DISPATCHED_UNKNOWN`, `PARTIAL` or `TRANSPORT_CONFIRMED`. Each state
accepts a closed set of reasons. Every non-`ok` reason names one fixed local JSON
response (400, 403, 502, 503 or 504) containing no caller data. `ok` returns the
complete upstream response, and `response_policy_rejected` records the upstream
digest and status class while returning a fixed 502.

Receipts carry lease, attempt, optional operation, service, route and request
digest correlation, dispatch state, reason, optional status class and upstream
digest/body length, the digest and length of the exact client bytes, and
monotonic start/completion times. They exclude URLs, headers, sentinels,
credentials and bodies. A receipt is dispatch correlation, not effect
confirmation, billing evidence or a durable journal record.

The ledger retains at most 2,048 entries and 2 MiB. Each reservation is charged
the canonical size of its worst-case finalized snapshot record, at most 8 KiB,
so later finalization and delivery cannot exceed the charge. Capacity failure
occurs at `reserve`, before any upstream connection; the owner then closes
without response bytes because no receipt-less send path exists. Entries are
never evicted to admit another. Finalized entries age out 310 seconds after
completion. An unfinalized entry whose handler deadline (at most 40 seconds)
passes is finalized as `abandoned`: `NOT_DISPATCHED` if it never began
connecting, otherwise `DISPATCHED_UNKNOWN`, stamped at its deadline. A clock
exception, invalid value or regression permanently holds the ledger; snapshots
remain readable. Reservations, receipts and delivery claims are authenticated by
object identity. The ledger keeps a private copy of each receipt, and retention,
snapshots and delivery checks never read the caller's instance.

`forwarder_response_send.send_response(connection, ledger, receipt, response,
deadline=...)` permanently claims a server-side TLS 1.2+ socket, serializes the
response and asks the ledger to claim delivery for that digest. The ledger
compares it with its private record under its lock, so different bytes send
nothing and claim nothing. Delivery is one-use per receipt and per socket. Writes
use chunks of at most 16 KiB, each bounded by ten seconds and the caller's
absolute deadline, without retry. The outcome is recorded as `sent`, `not_sent`
(no send began) or `send_unknown` (with the accepted byte count), and the prior
timeout is restored. Primary failures and interruptions propagate unchanged;
after a complete send, an unrecorded outcome raises `delivery_unrecorded`, then a
failed restore raises `timeout_restore_failed`. An asynchronous interruption
between the ledger's claim and its return leaves that delivery `sending` until
retention. `sent` means the local TLS layer accepted every byte, not that the
client read them. The caller owns and closes the socket and binds the receipt's
service to its listener.

Deterministic tests use injected clocks and fake sockets; real local TLS tests
compose the fixed listener, strict client, request collector, ledger, sender and
response collector with synthetic in-memory upstream responses. No upstream
connection, lease check, route policy, dispatch permit, durable journal, native
client or deployment is qualified by these tests.

## Strict JSON and read-only Jira route policy

`forwarder_json.parse_json(data, max_bytes=..., numbers="integer")` accepts only
strict UTF-8 RFC 8259 JSON without a byte-order mark, comments or non-JSON
whitespace. It limits depth to 16, arrays to 256 items and each key or string to
16 KiB after UTF-8 encoding. It rejects duplicate keys after unescaping, U+0000,
lone surrogates and non-finite numbers. Integer mode accepts integers within
2^53-1 only; finite mode, used only for upstream responses, keeps fractional
lexemes as `JSONDecimal` text and never converts them to floats. A linear
prescan bounds depth before the standard decoder runs. `canonical_json` emits a
sorted, whitespace-free RFC 8785 subset and `tagged_digest` domain-separates
SHA-256 digests. Error handlers only record fixed codes; a fresh error is raised
outside every handler, so raised errors carry no caller input in their arguments
or exception chain. An exception already active in the caller's own handler still
attaches as context, and traceback frame locals remain outside that guarantee.

`forwarder_routes.RoutePolicy(jira=JiraVenuePolicy(...))` turns one parsed
request and a Receiver `ScopeManifest` into a `RoutedRequest` or a closed
`RoutePolicyError`. Only `jira.issue.get` (manifest-registered issues) and the
first page of `jira.search` are matchable, and both are marked `partial`. The
other 23 catalog routes are unavailable, each with named missing inputs such as
tenant field IDs, dispatch permits, projection, continuation tracking or Eyes
schemas. No readiness fact is true yet.

The operator `JiraVenuePolicy` supplies project and issue-type IDs, a closed
system-field allowlist (no custom, comment, user-identity or description
fields), search templates with one quoted `{label}` placeholder and open status
category keys. Its canonical bytes produce `policy_digest`. The manifest binds
service, Run, attempt, rehearsal, revision, routes, policy digest, registered
issues and search labels; its digest is exactly the lease `scope_digest`.
`require_manifest_binding` compares manifest identity with a grant before a
future store installs it. Caller path and body values only select within the
manifest: issue selectors resolve by exact ID or key, and search JQL must match
exactly one template and manifest label. The upstream request is rebuilt from
manifest, policy and template values plus the caller's `maxResults` integer,
bounded by the policy cap; the caller's JQL, query spelling, headers and sentinel
never reach it. Its version-1 `request_digest` binds
service, route, policy and scope digests, method, target and body digest, but
not an upstream origin, so it may never satisfy a dispatch permit. Denials carry
a constant per-route denial digest and a receipt reason (`request_rejected` or
`route_denied`).

`check_response` validates an issued `RoutedRequest`'s response without
projection. Only status 200 can pass. Issue responses must return the selected
ID/key and configured project and type; search responses must stay within the
requested count, carry the selected label, configured identity, unique numeric
IDs and an open status category. Every other result becomes
`response_policy_rejected` and the fixed 502. Passing responses still carry
upstream `self`, avatar and icon URLs, no 30-minute window check, no completeness
claim and no error-status visibility.

Both modules open no socket, read no clock and never read the sentinel.
Deterministic and adversarial tests cover golden digests, strict JSON edge cases,
exception chains, AST import and handler rules, smuggling attempts and
composition with the lease registry and receipt ledger. No lease resolution,
dispatch, upstream serialization, credential, tenant ID, native client or
deployment is qualified.

## Dispatch admission, write fence and the one-request exchange

`forwarder_dispatch.DispatchGate(registry=..., ledger=...)` is the dispatch
authority for one Forwarder generation. It permanently claims exactly one lease
registry and one receipt ledger with the same generation; a second gate over
either object is refused. It never calls a mutating registry method: only
`ForwarderControl` mutates the registry, and only the gate and `send_response`
write the ledger. One gate lock is held across each authorizing lease check and
the ledger transition it justifies, with no I/O or injected code in between
except the three monotonic clocks, which must share one domain. Lock order is the
control lock, then the gate lock, then the registry lock; the gate lock also
precedes the ledger lock, and neither inner lock calls outward. The control lock
is never held across a `DispatchGate` call, and control's closeout holds call
`LeaseRegistry.hold()` with the control lock released, taking only the registry
lock.

There are two linearization points. `admit` runs the lease check with the stored
record generation and moves the ledger entry to `connecting`; `begin_write` runs
the final lease check and moves it to `dispatched` immediately before the first
possible upstream write. Every retirement (revoke, control EOF, owner
replacement, hold, expiry and heartbeat loss) is ordered with these checks under
the registry lock. After a retirement or gate shutdown returns, no later admit or
write fence succeeds for that lease. An admitted request stopped at the fence is
finalized `FAILED` with zero application bytes; a request whose fence preceded
the retirement may still complete and is delivered. The consume-at-admit,
re-verify-at-fence rule for future AuthorizeDispatch permits is decided but not
implemented; permit routes are denied at both slots.

`install_scope` installs a Receiver scope manifest only after
`require_manifest_binding` and exact comparison with the registry record, and
indexes it by a keyed HMAC of service and sentinel; the raw sentinel is not kept.
Entries are count- and byte-bounded and age out after 310 seconds. Its caller is
gated scoped registration over control (see "Scope delivery and control
closeout"). Handles,
admissions and scope entries are authenticated by identity.

Deadlines share one clock domain. The inbound handler deadline is `started + 40`;
every reserved receipt is clipped to the lease expiry; upstream work ends one
second earlier, leaving margin to finalize and deliver before the ledger sweep.
Admission requires at least two seconds of budget and the fence at least half a
second of write budget. The connect deadline is at most five seconds and the
write deadline at most ten, both clipped to the exchange deadline. The precheck
denial alone keeps the unclipped handler deadline, because the lease may already
have expired.

A flight whose deadline passes is marked overdue by the next gate call that ticks
the gate clock (there is no timer), rather than deleted: its abort callable then fires
once outside the gate lock, it keeps its capacity slot, and `closeout` reports
`overdue` (to be treated as unknown) until its owner returns. A connector that
ignores both its deadline and its abort holds that slot until it returns; the
client sees EOF, and deadlines are not hard real-time.
`closeout(lease_id)` reports `open`, `draining`, `overdue`, `quiescent` or
`unknown` from in-process registry, ledger and gate observations only; gated
control presents it in Revoke and closeout replies (see "Scope delivery and
control closeout"). A held gate (clock fault or clock-domain mismatch) closes
every new request without bytes; a closed gate after `shutdown` answers with
receipt-backed 403 denials. Shutdown aborts channels already attached to admitted
or writing flights without holding the registry; a connect in progress is not
interrupted and is then denied at the fence. The intended supervisor order is
control service stop, then gate shutdown, then listener close.

`forwarder_exchange.serve_request` serves one request on an accepted inbound TLS
socket: sized request collection, sentinel resolution, lease precheck, route
policy, a connector-prepared request digest (never the version-1 route digest),
reservation, admission, connect, write fence, send, receive, response policy,
finalization and receipt-gated delivery. No response byte is sent without a
recorded receipt. Parse, sentinel, capacity, held-gate, expired-deadline and
internal failures close without response bytes; those before reservation leave no
receipt, while a deadline after reservation leaves the ledger's swept `abandoned`
receipt.
`serve_one` binds the receipt service to the accepting listener and closes the
connection after the response. The upstream is an injected connector; source
ships none, so `upstream=None` yields a 403. The two existing-module changes are
additive: `receive_request_sized` returns the exact inbound byte count, and
`FixedTLSListener.service` exposes the bound service.

Deterministic, adversarial, real-thread race and real-local-TLS tests with fake
connectors cover admission and fence ordering against every retirement cause,
overdue and shutdown behavior, capacity, forgeries, error chains, event order and
receipt mapping. No real upstream connection, connector contract, credential,
AuthorizeDispatch permit, worker supervisor, readiness wiring, durable journal,
native client or deployment is qualified.
`FAILED` is truthful only if a connector's `connect` writes no application bytes,
and ledger clock divergence is detected only partially.

## Synthetic fixed-origin upstream connector

`forwarder_upstream.JiraUpstreamConnector(endpoint=..., credential=...)` is the
trusted connector for `jira.issue.get` and `jira.search`. It has no production
caller. `UpstreamEndpoint` is an operator configuration shape (service, revision,
host, IPv4 address literal, port, public CA bundle and credential ID) filled only
in memory by tests. The `synthetic-only.v1` policy accepts only an RFC 6761
`.invalid` host on an RFC 5737 documentation address; any other endpoint that
passes the shape checks is refused with `endpoint_unqualified`. Real origins,
address stability, IPv6 and the CA issuer remain the spec's unresolved
decisions, so production stays unavailable until they are reviewed. Source
performs no DNS, proxy, environment, file or mount read, and it rejects
loopback, link-local, multicast, reserved and unspecified addresses. Local tests cannot show that a documentation address is unroutable
on another network; the absence of a production caller is the guarantee.

Each connect builds a fresh client context: explicit `cadata` as the only trust
source, TLS 1.2 or newer, required certificates and hostname checks without
common-name fallback, strict X.509 verification, no compression, renegotiation or
tickets, and HTTP/1.1 ALPN. Its options, flags, trust-store count and trusted
certificate digests are read back at runtime before use. After the handshake the
connector checks the version, ALPN, compression, session reuse and that a peer
certificate was presented. Unlike the local listener policy, upstream
verification accepts wildcard and long-lived public leaves; pinning is a
deferred issuer decision. The process-level OpenSSL configuration is not
attested.

`BasicCredential` binds a synthetic user and token to `jira`/`basic`. It is
redacted in every representation, cannot be pickled, copied, subclassed or
re-initialized, and can be claimed by only one connector. Within Python, the
encoded header is copied only into the channel's send buffer, which is zeroed
after the write (OpenSSL record buffers are outside this claim), and the channel
drops its reference after sending or aborting. Code inside the process can
still read the credential object's slot, and no credential loader exists.

`prepare(routed)` is pure. It re-verifies the route shape and the unit-12 version-1
digest, then returns a version-2 request digest that binds the endpoint digest
(including trust digests) and the Host authority. It never returns the version-1
digest and refuses, at prepare time, any request whose canonical wire would
exceed the 2 KiB request-line, 16 KiB head or 256 KiB body bound. The wire
contains exactly the request line, `Host`, `Authorization`, `Accept`,
`Accept-Encoding: identity`, `Content-Type` and `Content-Length` for bodies, and
`Connection: close`; `Accept-Encoding` and `Connection` are upstream-only
additions beyond the spec's reconstructed header list. No caller header,
sentinel or inbound Host reaches it.

`connect` refuses the version-1 digest, another route's or endpoint's digest, a
second connect for the same admission and any deadline beyond the admission's
connect deadline, all before creating a socket. It then opens TCP and completes
TLS within five seconds and writes no application bytes. The returned channel
sends the request at most once, when 13a calls `send` after its write fence, in
chunks of at most 16 KiB within ten seconds; receives one response through
`receive_response`; and maps failures to `connect_failed`, `upstream_tls_failed`,
`write_failed`, `receive_failed` or `deadline` for 13a's receipt mapping. `abort`
is idempotent and non-blocking and shuts the socket down beneath its TLS object,
so a later write fails rather than falling back to plaintext; `close` during
active I/O is deferred until that I/O ends. Nothing is retried, and redirects
never reach the caller.

Deterministic tests cover endpoint and credential validation, context read-back,
golden digests and wire bytes, pre-socket refusals and channel state. Real local
TLS tests use a synthetic upstream that records every raw byte behind an
asserting address adapter with DNS tripwires. They show zero application bytes on
connect failures and aborts, byte-exact canonical requests, the trust matrix with
strict-flag controls, and composition through `serve_one` with revocation at the
fence. No real Jira site, real credential, CA custody, deployment or native client
is qualified.

## Scope delivery and control closeout

`ForwarderControl(..., gate=gate)` pairs the controller with the
`DispatchGate` of its registry's generation. `forwarder_control_scope` checks
the exact types and generation equality; exclusive ownership stays a caller
precondition. Without a gate, `register` for a profiled service without a scope
type fails with `scope_type_unavailable` before the owner fence and any registry
call; only Jira has a scope type. A gated controller refuses every plain
`register` with `scope_required`, refuses `register_scoped` for such a service
with `scope_type_unavailable` before reading any attachment byte, and adds two
commands on the same authenticated connection. Without a gate, the commands,
replies and codes are otherwise unchanged.

`register_scoped` carries the Register parameters plus `manifest_bytes` in one
JSON header, followed immediately by one attachment: a four-byte big-endian length
and the canonical `ScopeManifest` bytes, 1 to 16,384 bytes. The two declared
lengths must match before any body byte is read, and the attachment has its own
deadline of at most two seconds. The service, the length, the canonical parse and
the manifest's binding to service, run, attempt and scope digest are all checked
before the registry changes. The lease is then registered behind the owner
fence, the gate installs the scope with the control lock released, and a
post-install owner fence runs before the reply. Only that reply carries the
sentinel, together with `installed_at`. A failure after registration ends the
session, which revokes all of its leases, or holds the registry if that release
fails, before the error frame. A replacement or shutdown during installation is
caught by the post-install fence, so that session never writes the scoped grant.
A replacement or shutdown after the fence can still let the reply reach the old
peer, as with Register, but the replacement revokes that lease and a shutdown
holds the registry. An entry installed for an already retired lease is inert. An
exact replay returns the same grant and `installed_at`.

In gated mode a Revoke reply keeps the committed receipt and adds `revoked_at`,
`closeout_state` and a nested `closeout` observation. `ok:true` means the lease is
retired and its closeout is `draining` or `quiescent` with no overdue flight.
The `closeout` command returns the same observation for any lease ID of the
generation and spends no authority, although the gate call's registry snapshot
and clock tick can retire expired or heartbeat-late leases, prune scope entries,
mark flights overdue and run their aborts before the reply. The
observation fields are `generation`, `lease_id`, `lease_state`,
`closeout_state`, the counts `pending`, `in_flight`, `overdue` and `uncertain`,
`drain_deadline` and `observed_at`.

Every uncertain observation holds the registry before the error frame, and the
command fails:
- `closeout_overdue`: any overdue flight, including one of an `open` lease;
- `closeout_unknown`: the gate call failed, or the state is `unknown` after a
  revoke or for a lease the Forwarder still knows;
- `closeout_inconsistent`: a wrong type, an out-of-range or non-finite value, or
  incoherent states (including a lease state other than `revoked` or `pruned`
  after a revoke).

The hold is terminal for the generation, and new sessions get `registry_held`.
A session replaced after its command's owner fence can still hold the
generation its successor uses; that is the only cross-owner effect, and it only
removes authority. The only unheld `unknown` is a `closeout` answer for an ID the Forwarder has no
record of. Lease state `pruned` means the registry record aged out while the
scope entry remains; after the entry's 310 seconds the answer is `unknown`.

The Receiver obligations are:
- keep the five-second heartbeat cadence, because a `register_scoped` can take
  about twelve seconds to read and fifteen seconds without a heartbeat revoke
  the session's leases, and write the attachment immediately after the header;
- compute the drain budget as `drain_deadline - observed_at` from one reply,
  valid only while the gate and ledger share one clock domain;
- record every `closeout_*` error, a Revoke that failed that way and any
  `unknown` as UNKNOWN;
- use `closeout`, not Revoke, for leases it believes are already retired, and
  after EOF or replacement poll `closeout` on a new session before treating any
  lease as quiescent;
- read closeout within 310 seconds, and keep scope-store use within 2 MiB and
  1,024 entries over any 310-second window, retired leases included.

The control lock is never held across a gate call or the attachment read, and
the holds added here take only the registry lock. Gateless mode still registers
Jira without a scope, so it cannot create a dispatchable lease over control; the
launcher unit must require `gate=`. Deterministic, real-thread race, socketpair
and pathname-socket tests cover framing, refusal order, installation, replay,
both replacement windows, shutdown, holds, custody and lock ownership. No
AuthorizeDispatch permit, Ready reply, Receiver client, durable closeout
evidence, gate-side overdue hold, Linux peer validation or deployment is
qualified.

The next integration units are the durable Receiver journal and recovery
(ticket 37), accounting (ticket 38), then AuthorizeDispatch permits, a worker
supervisor with readiness, and the guarded launcher. Real provider/tenant
operations, native execution and deployment remain gated by their own
acceptance evidence. Local module tests cannot replace that
evidence or human Report adjudication.

Run the focused local tests from the repository root:

```sh
pytest -q tests/test_forwarder_services.py tests/test_forwarder_leases.py tests/test_forwarder_control.py tests/test_forwarder_control_protocol.py tests/test_forwarder_listener.py tests/test_forwarder_listener_control.py tests/test_forwarder_supervisor.py tests/test_forwarder_supervisor_integration.py tests/test_forwarder_tls.py tests/test_forwarder_tls_integration.py tests/test_forwarder_http.py tests/test_forwarder_http_adversarial.py tests/test_forwarder_server_tls.py tests/test_forwarder_server_tls_integration.py tests/test_forwarder_http_head.py tests/test_forwarder_http_receive.py tests/test_forwarder_http_receive_integration.py tests/test_forwarder_http_response.py tests/test_forwarder_http_response_adversarial.py tests/test_forwarder_response_receive.py tests/test_forwarder_response_receive_adversarial.py tests/test_forwarder_response_receive_integration.py tests/test_forwarder_receipts.py tests/test_forwarder_receipts_adversarial.py tests/test_forwarder_response_send.py tests/test_forwarder_response_send_integration.py tests/test_forwarder_json.py tests/test_forwarder_json_adversarial.py tests/test_forwarder_routes.py tests/test_forwarder_routes_adversarial.py tests/test_forwarder_dispatch.py tests/test_forwarder_dispatch_seams.py tests/test_forwarder_dispatch_races.py tests/test_forwarder_dispatch_adversarial.py tests/test_forwarder_exchange.py tests/test_forwarder_exchange_integration.py tests/test_forwarder_exchange_adversarial.py tests/test_forwarder_upstream.py tests/test_forwarder_upstream_integration.py tests/test_forwarder_upstream_adversarial.py tests/test_forwarder_control_attachment.py tests/test_forwarder_control_scope.py tests/test_forwarder_control_gate.py tests/test_forwarder_control_gate_closeout.py tests/test_forwarder_control_gate_races.py
```
