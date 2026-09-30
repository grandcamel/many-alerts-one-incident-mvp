# How a Run could see telemetry: read-only Eyes into Grafana, Loki, Tempo and Prometheus (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and public citations retained. This is not a fresh capability or version verification. Source commit: `9dc705f753b02a0dcc337a93299e1f7ff38a9939`.

Written 2026-09-15 for ticket 03 of the many-alerts-one-incident map. Question: which read-only,
shell-executable tools could a Run use to query Grafana, Loki, Tempo and Mimir from the demo
image (no `curl`, no `jq`; Python 3, Node 24, Claude Code, `jira-as`; ADR 0005), what would each
need to authenticate, what would the `dontAsk` allow list say about it (ADR 0003), and can the
`grafana/otel-lgtm` image stop being anonymous-Admin and hand a Run a token the Forwarder can
swap (ADR 0002)?

**Method.** Every claim cites the page it came from, all fetched 2026-09-15: Grafana's HTTP API,
service account, RBAC and configuration docs, the Loki, Tempo, Mimir and Prometheus tool docs,
the `grafana/mcp-grafana` and `grafana/docker-otel-lgtm` repositories, and Claude Code's
permission and MCP docs. Release asset names and sizes come from the GitHub API. Where the docs
were silent on a permission, the question was put to the software: a throwaway
`grafana/otel-lgtm:latest` container (the image already on this laptop, Grafana 12.3.1) was
started with `GF_AUTH_ANONYMOUS_ENABLED=false`, a Viewer service account and token were minted
with the default admin account, and every endpoint below was called with that token. The Python
and Node one-liners in this document were run as written against it. Nothing was downloaded;
none of the CLIs was executed, and that is said again under "Could not verify".

## Short answer

1. **The otel-lgtm image runs Prometheus, not Mimir.** Its Dockerfile pins `GRAFANA_VERSION=v13.2.1`,
   `PROMETHEUS_VERSION=v3.14.0`, `LOKI_VERSION=v3.7.7`, `TEMPO_VERSION=v3.0.3` and copies in no CLI
   ([otel-lgtm-dockerfile]); the Grafana datasource is `uid: prometheus` at `http://127.0.0.1:9090`
   ([otel-lgtm-datasources]). `mimirtool` has no query command anyway ([mimirtool]). The metrics
   tools that apply are `promtool` and the Prometheus HTTP API.
2. **Only Grafana has a credential to swap.** Loki runs with `auth_enabled: false`
   ([otel-lgtm-loki-config]), Tempo without `multitenancy_enabled` (default `false`,
   [otel-lgtm-tempo-config], [tempo-config]), Prometheus with no auth flag ([otel-lgtm-run-prometheus]),
   and Loki's own docs say "authorization needs to be done separately" ([loki-api]). All three
   listen on every interface: from inside the running demo container, `lgtm:3100`, `lgtm:3200`
   and `lgtm:9090` answered `200` with no header at all, and so did `lgtm:3000/api/datasources` as
   the anonymous Admin ([empirical]). Today the allow list is the only thing between a Run's
   `python3` and the whole stack. Eyes through a sentinel therefore means Eyes through Grafana,
   with the backends bound to loopback so Grafana is the only door.
3. **Anonymous access turns off with one variable, and a Viewer token can be minted at startup
   but not provisioned from a file.** `run-grafana.sh` defaults `GF_AUTH_ANONYMOUS_ENABLED` to
   `true` and the role to `Admin` only when the variable is unset ([otel-lgtm-run-grafana],
   [local-image]); with it `false`, an unauthenticated request got `401` ([empirical]). Grafana's
   file provisioning covers data sources, plugins, dashboards and alerting, not service accounts
   ([grafana-provisioning]); the token comes from `POST /api/serviceaccounts` and
   `POST /api/serviceaccounts/:id/tokens` with the admin's basic auth ([grafana-sa-api],
   [grafana-sa-tutorial]), which the Receiver can do with `urllib` before the first Run.
4. **Viewer is enough for everything a Run reads, and blocks everything it must not write.** With
   a Viewer token: `POST /api/ds/query` against Prometheus and Loki `200`, the datasource proxy
   for Loki, Prometheus and Tempo `200`, annotations `200`, Grafana-managed alert rules and
   firing alerts `200`, dashboard search `200`; `POST /api/annotations` `403`,
   `POST /api/serviceaccounts` `403` ([empirical]). The docs agree in principle: "data sources in
   an organization can be queried by any user in that organization" and "a user with the `Viewer`
   role can issue any possible query to a data source" ([grafana-ds-mgmt]); the datasource
   permission levels that would narrow that are Enterprise and Cloud only ([grafana-ds-mgmt]).
5. **mcp-grafana is the one option built for exactly this shape.** One static Go binary
   (`CGO_ENABLED=0`, [mcp-grafana-dockerfile]; 17.6 MB tarball, [gh-releases]), stdio is its
   default transport, it talks only to Grafana with `GRAFANA_SERVICE_ACCOUNT_TOKEN` as a Bearer
   header ([mcp-grafana], [mcp-grafana-src]), its Loki tool goes through Grafana's datasource proxy
   ([mcp-grafana-loki-src]), and `--disable-write` plus `--enabled-tools` shrink its 106 tools to
   the read-only categories a Run needs ([mcp-grafana]). Claude Code's allow list can name it
   tool by tool (`mcp__grafana__query_loki_logs`) or as `mcp__grafana__*`, since allow globs are
   accepted after a literal server prefix ([cc-permissions]).
6. **The shell alternatives each cost something the sentinel design does not want.** `logcli`
   sends `LOKI_BEARER_TOKEN` as an Authorization header and takes a base URL, so it can be pointed
   at Grafana's proxy prefix; `promtool` takes a server URL but its auth is a config file or a
   `--header`; `tempo-cli query api search` takes `<host-port>`, not a URL, so it cannot address a
   path under Grafana at all ([loki-logcli], [promtool], [tempo-cli]). Three binaries, three auth
   styles, 37 MB to 107 MB of archives, and none of them speaks to Grafana's own APIs (annotations,
   alert state). A `python3 -c` one-liner does everything through Grafana with nothing added to
   the image, but `Bash(python3 -c *)` is an allow rule for arbitrary code, and Claude Code's own
   docs call argument-constraining patterns fragile ([cc-permissions]).

## What the image actually runs

The `docker/` tree of `grafana/docker-otel-lgtm` holds `loki-config.yaml`, `tempo-config.yaml`,
`prometheus.yaml`, `run-grafana.sh`, `run-prometheus.sh`, `grafana-datasources.yaml` and the
Dockerfile ([otel-lgtm-tree]). The README calls the image one "intended for development, demo,
and testing environments", lists Grafana on 3000, Tempo 3200, Pyroscope 4040, OTLP 4317/4318 and
Prometheus 9090, says "Grafana is configured via `GF_*` environment variables", and shows the
override pattern `docker run -v ./my-loki-config.yaml:/otel-lgtm/loki-config.yaml:ro
grafana/otel-lgtm` ([otel-lgtm-readme]). The Dockerfile is `FROM redhat/ubi9-micro`, exposes
3000, 3200, 4040, 4317, 4318 and 9090, and copies in none of `logcli`, `tempo-cli`, `promtool` or
`mimirtool` ([otel-lgtm-dockerfile]).

The image on this laptop is `grafana/otel-lgtm:latest` pulled 2026-01-09, Grafana 12.3.1. Its
`run-grafana.sh` defaulted anonymous access to enabled with the `Admin` role only when
`GF_AUTH_ANONYMOUS_ENABLED` was unset. Its `run-prometheus.sh` passes `--web.enable-remote-write-receiver --web.enable-otlp-receiver
--enable-feature=exemplar-storage --storage.tsdb.path=/data/prometheus --config.file=./prometheus.yaml`
and no `--web.listen-address` ([local-image]). The `main` branch's scripts do the same with
`${GF_AUTH_ANONYMOUS_ENABLED:-true}` and `${GF_AUTH_ANONYMOUS_ORG_ROLE:-Admin}`
([otel-lgtm-run-grafana], [otel-lgtm-run-prometheus]). Either way, a compose `environment:` entry
wins. This repo's compose sets `GF_AUTH_ANONYMOUS_ENABLED: "true"`,
`GF_AUTH_ANONYMOUS_ORG_ROLE: Admin` and `GF_AUTH_DISABLE_LOGIN_FORM: "true"` today.

The datasources Grafana is provisioned with are `prometheus` (`http://127.0.0.1:9090`), `tempo`
(`http://127.0.0.1:3200`), `loki` (`http://127.0.0.1:3100`) and `pyroscope`
([otel-lgtm-datasources]). Because Grafana reaches the backends on loopback, binding them to
loopback changes nothing for Grafana: Loki's `server.http_listen_address` defaults to `0.0.0.0`
([loki-config]), Tempo's `server.http_listen_address` is "HTTP server listen host"
([tempo-config]), and Prometheus's `--web.listen-address` defaults to `0.0.0.0:9090`
([prom-flags]). The first two are a mounted config file; the third needs a replacement
`run-prometheus.sh` mounted over the original, since the script hardcodes its flags.

### What the demo container can reach today

Run from inside `grafana-jsm-sandbox_demo_1` with Python's `urllib`, no headers ([empirical]):

| Target | Status |
| --- | --- |
| `http://lgtm:3100/loki/api/v1/labels` | 200 |
| `http://lgtm:3200/api/echo` | 200 |
| `http://lgtm:9090/api/v1/query?query=up` | 200 |
| `http://lgtm:3000/api/datasources` (anonymous, Admin) | 200 |

`python3` is in the image; `Bash(jira-as *)` is what stops a Run from running that line. The
earlier research already said the allow list "is a permission gate parsed from the command's AST;
it is not what keeps the Jira token out of the Run" (`harness-sandbox-containers-2026-09.md`). For
Eyes the same holds, with the difference that today there is no token to keep out.

## Turning anonymous off and minting a Viewer token

Grafana's defaults are `[auth.anonymous] enabled = false`, `org_role = Viewer`, `[auth.basic]
enabled = true`, `disable_login_form = false`, `admin_user = admin`, `admin_password = admin`
([grafana-defaults]). Any of them is overridden by `GF_<SECTION NAME>_<KEY>`, uppercase, dots and
dashes to underscores ([grafana-config]); `GF_<SectionName>_<KeyName>__FILE` reads the value from
a file, the documented way to keep `GF_SECURITY_ADMIN_PASSWORD` out of the environment
([grafana-docker]). `admin_password` is "Set once on first-run" ([grafana-config]), which is every
run for this image, since `/data/grafana` is not a volume in this repo's compose.

Service accounts are Grafana's answer to "automated workloads"; they take the organization roles
`Viewer`, `Editor` or `Admin`, "Service account access tokens inherit permissions from the
service account", and creating one needs "Admin rights, or the roles `fixed:roles:reader` and
`fixed:serviceaccounts:creator`" ([grafana-sa]). The API is `POST /api/serviceaccounts` with
`{"name": ..., "role": "Viewer"}` (permission `serviceaccounts:create`) and
`POST /api/serviceaccounts/:id/tokens` with `{"name": ..., "secondsToLive": ...}` (permission
`serviceaccounts:write`), which returns the token once in `key` ([grafana-sa-api]). Grafana's own
tutorial does both with `http://admin:admin@localhost:3000/...` ([grafana-sa-tutorial]). The HTTP
API accepts "basic authentication or a service account token", the header being
`Authorization: Bearer <YOUR_SERVICE_ACCOUNT_TOKEN>` ([grafana-auth]). Note the deprecation
banner: from Grafana 13 "`/api` endpoints are being deprecated in favor of the `/apis` route",
though the legacy routes still work ([grafana-sa-api]).

Observed on the throwaway container ([empirical]): unauthenticated `GET /api/org` and
`POST /api/ds/query` both `401`; the admin's basic auth created service account `sa-1-eyes` with
role `Viewer` and a token beginning `glsa_`, 46 characters; `GET /api/user` with that token
returned `"login":"sa-1-eyes"`, `"isGrafanaAdmin":false`.

Two consequences for the compose file. `GF_AUTH_DISABLE_LOGIN_FORM: "true"` must go, or the
presenter has no way into the UI once anonymous is off; and something must mint the token before
the first Run. File provisioning cannot ([grafana-provisioning]); the Receiver, which already
starts before Grafana's contact point can reach it, can do it with `urllib` and keep the token in
the Forwarder, exactly where the Jira token lives.

## What a Viewer token can and cannot read

Grafana's role table gives Viewer "View dashboards", "View annotations" and "Query data sources
directly", and withholds Explore, adding or editing data sources, and adding or editing
annotations ([grafana-roles]). In RBAC terms the Viewer basic role is built from
`fixed:datasources.id:reader`, `fixed:annotations:reader`, `fixed:alerting:reader` (itself the
rules, instances and notifications readers), `fixed:dashboards.insights:reader`,
`fixed:folders.general:reader` and a few more ([grafana-basic-roles]). The actions:
`datasources:query` "Query data sources", `datasources:read` "List data sources",
`datasources:explore` "Enable access to the Explore tab", `alert.rules:read`,
`alert.instances:read` "Read alerts and silences in the current organization",
`alert.provisioning:read` "Read all Grafana alert rules, notification policies, etc via
provisioning API. Permissions to folders and datasource are not required.", `annotations:read`
([grafana-actions]). The alerting RBAC page confirms Viewer can view alert rules, silences,
contact points and notification policies, and adds that "Access to alert rules also requires
permission to read the folder containing the rules and permission to query the data sources used
in the rules" ([grafana-alerting-rbac]).

The data source API page documents `POST /api/ds/query` (body: `queries[]` with
`datasource.uid`, `refId`, datasource-specific fields such as `expr`, plus `from`/`to` in epoch
milliseconds or `now-5m` form) and `GET /api/datasources/proxy/uid/:uid/*`, which "Proxies all
calls to the actual data source identified by the `uid`", but names a required permission only
for listing (`datasources:read`) ([grafana-ds-api]). The annotations API is
`GET /api/annotations?from=&to=&tags=&type=&limit=&dashboardUID=` with `annotations:read`
([grafana-annotations-api]). The Grafana-managed alerting routes are registered in Grafana's
source at `GET /api/prometheus/grafana/api/v1/alerts` and `.../rules` ([grafana-ngalert-routes]),
guarded by `alert.instances:read` and `alert.rules:read` respectively, as is
`GET /api/alertmanager/grafana/api/v2/alerts` (`alert.instances:read`); the provisioning
`GET /api/v1/provisioning/alert-rules` passes with `alert.provisioning:read` or with
`alert.rules:read` plus `folders:read` ([grafana-ngalert-authz]). The provisioning API page itself
carries "This API is deprecated and will be removed in a future release. Use the Grafana App
Platform alerting APIs instead" ([grafana-alerting-provisioning-api]).

Observed with the Viewer token on Grafana 12.3.1 ([empirical]):

| Request | Status | Note |
| --- | --- | --- |
| `POST /api/ds/query` Prometheus, `{"expr":"up","instant":true}` | 200 | frames returned |
| `POST /api/ds/query` Loki, `{"expr":"{service_name=~\".+\"}","queryType":"range","maxLines":5}` | 200 | frames returned |
| `POST /api/ds/query` Tempo, a guessed TraceQL body | 500 | "Internal Server Error", not a permission error; body shape unverified |
| `GET /api/datasources/proxy/uid/loki/loki/api/v1/labels`, `.../query_range` | 200 | Loki's own JSON |
| `GET /api/datasources/proxy/uid/prometheus/api/v1/query?query=up` | 200 | Prometheus's own JSON |
| `GET /api/datasources/proxy/uid/tempo/api/echo`, `.../api/search?q={}` | 200 | Tempo's own JSON |
| `GET /api/datasources`, `GET /api/datasources/uid/loki` | 200 | see below |
| `GET /api/annotations?limit=2` | 200 | |
| `GET /api/prometheus/grafana/api/v1/rules`, `.../alerts` | 200 | |
| `GET /api/alertmanager/grafana/api/v2/alerts` | 200 | |
| `GET /api/v1/provisioning/alert-rules` | 200 | `alert.rules:read` + `folders:read` path in [grafana-ngalert-authz] |
| `GET /api/search?limit=2` | 200 | |
| `POST /api/annotations` | 403 | "Access denied to save the annotation" |
| `POST /api/serviceaccounts` | 403 | "Permissions needed: serviceaccounts:create" |
| any of the above with a wrong token | 401 | |

So Viewer suffices for `/api/ds/query` and for the datasource proxy; nothing above Viewer is
needed for any read a Run would make. One result was more than the docs implied: `GET
/api/datasources` returned the full list, internal URLs included, to a role whose basic-role
definition lists `datasources.id:read` rather than `datasources:read`. The response carried no
secrets (no `secureJsonData`), and the docs do not explain the grant; it is recorded as observed.

## The options, from their own documentation

### 1. Grafana's HTTP API from Python or Node, nothing added to the image

Node's global `fetch` is "No longer experimental" since v21 ([node-fetch]); the image runs Node
24. `urllib.request.Request(url, data=None, headers={}, ...)` and `urlopen` are the standard
library ([python-urllib]). Both of these ran as written, one line each, against the throwaway
Grafana with the token in `GRAFANA_TOKEN` ([empirical]):

```
python3 -c "import os,urllib.request as u;print(u.urlopen(u.Request('http://localhost:3300/api/datasources/proxy/uid/loki/loki/api/v1/labels',headers={'Authorization':'Bearer '+os.environ['GRAFANA_TOKEN']})).read().decode())"
```

```
node -e "fetch('http://localhost:3300/api/datasources/proxy/uid/prometheus/api/v1/query?query=up',{headers:{Authorization:'Bearer '+process.env.GRAFANA_TOKEN}}).then(r=>r.text()).then(console.log)"
```

and the same shape for `POST /api/ds/query` with a JSON body, Tempo search through the proxy,
and the Prometheus-compatible alert rules endpoint. Through the Forwarder the host would be
`127.0.0.1:<port>` and the token a per-Run sentinel, as with `JIRA_API_TOKEN`; the Forwarder
swaps the `Authorization` header instead of the basic-auth one.

*Allow list.* The rule would be `Bash(python3 -c *)` or `Bash(node -e *)`. Claude Code matches
"everything before the first `*` as written" ([cc-permissions]), so that approves any Python. A
pattern that tries to pin the URL is the case the docs warn against: "Bash permission patterns
that try to constrain command arguments are fragile" ([cc-permissions]). The honest form of this
option is a small purpose-built CLI in the image, `eyes` say, written on the standard library like
the Receiver, with the URL and the header inside it and subcommands the rule can name
(`Bash(eyes logs *)`, `Bash(eyes metrics *)`). That is what `jira-as` is to the Hands: the command
the Skill can describe and the audience can read. Cost to the image: one file.

### 2. `logcli` for Loki

Binaries are on the Loki releases page; `LOKI_ADDR`/`--addr` (default `http://localhost:3100`),
`LOKI_BEARER_TOKEN`/`--bearer-token` "adds the Authorization header to API requests",
`LOKI_ORG_ID`/`--org-id` "adds X-Scope-OrgID", plus basic-auth and TLS variables ([loki-logcli]).
Subcommands: `query` (`--since=1h --limit=30 --output=default|raw|jsonl`), `instant-query`,
`labels`, `series` ([loki-logcli]). The Loki HTTP API underneath is
`GET /loki/api/v1/query_range?query=&limit=&start=&end=&since=&direction=`, `/labels`, `/series`
([loki-api]). Loki itself has no auth: "authorization needs to be done separately, for example,
using an open-source load-balancer such as NGINX" ([loki-api]); `auth_enabled: false` means "the
OrgID will always be set to 'fake'" ([loki-config]).

Because `logcli` appends `/loki/api/v1/...` to `LOKI_ADDR`, the address can be Grafana's proxy
prefix, `http://<forwarder>/api/datasources/proxy/uid/loki`, and the Bearer header is then the
Grafana token. The request that produces,
`GET .../proxy/uid/loki/loki/api/v1/query_range?query=...&limit=1` with a Viewer Bearer, answered
`200` ([empirical]); `logcli` itself was not run.

One line: `logcli query --since=15m --limit=50 --output=jsonl '{service_name="rolldice"}'`
with `LOKI_ADDR` and `LOKI_BEARER_TOKEN` in the Run's scrubbed environment.

*Image cost.* `logcli-linux-amd64.zip`, 37,394,362 bytes for v3.7.7 ([gh-releases]); the size
of the unzipped binary was not measured. *Allow list.* `Bash(logcli query *)`,
`Bash(logcli instant-query *)`, `Bash(logcli labels *)`, `Bash(logcli series *)`.

### 3. `tempo-cli` and the Tempo HTTP API

Tempo's read API: `GET /api/traces/<traceid>` (and `/api/v2/traces/`), `GET /api/search?q=<traceql>`
with `limit`, `start`, `end`, `spss`, `GET /api/search/tags`, `GET /api/search/tag/<tag>/values`,
`GET /api/echo`, `GET /ready`; the docs' example is
`curl -G -s http://localhost:3200/api/search --data-urlencode 'q={ status=error }' | jq`
([tempo-api]). `multitenancy_enabled` is "Optional. Setting to true enables multitenancy and
requires X-Scope-OrgID header on all requests", default `false` ([tempo-config]); the otel-lgtm
config does not set it ([otel-lgtm-tempo-config]).

`tempo-cli` "is available as source code and as a Docker image" ([tempo-cli]); the release
tarball `tempo_3.0.3_linux_amd64.tar.gz` (70,157,712 bytes, [gh-releases]) is built from the
goreleaser ids `tempo`, `tempo-query` and `tempo-cli` ([tempo-goreleaser]), so the binary is in
there with two others. Its query forms: `tempo-cli query api trace-id <api-endpoint> <trace-id>`
with `--org-id` and `--header` (the docs' example passes `--header "X-TOKEN=<API_TOKEN>"`),
`tempo-cli query api search <host-port> <trace-ql> [<start> <end>]` with `--org-id`, `--header`,
`--limit`, `--secure`, `search-tags`, `search-tag-values`, and `metrics` for TraceQL metrics
([tempo-cli]). `search` takes a `<host-port>`, not a URL, so it cannot name a path under Grafana;
to go through Grafana the Forwarder would have to listen as a host and add the
`/api/datasources/proxy/uid/tempo` prefix itself.

One line: `tempo-cli query api search 127.0.0.1:3200 '{ status = error }' now-15m now --header 'Authorization=Bearer ...'`
(the `--header` value format is from the trace-id example and was not exercised).

*Allow list.* `Bash(tempo-cli query api *)`.

### 4. `promtool`, `mimirtool` and the Prometheus HTTP API

The API is `GET|POST /api/v1/query?query=&time=` and `/api/v1/query_range?query=&start=&end=&step=`,
returning `{"status":"success","data":{"resultType":"vector","result":[...]}}` ([prom-api]).
`promtool query instant <server> <expr>` with `--time`, `--header` "Extra headers to send to
server", `--format`, and `--http.config.file` "HTTP client configuration file" for auth;
`query range`, `query series --match`, `query labels` ([promtool]). `promtool` is built alongside
`prometheus` ([prom-promu]) and ships in `prometheus-3.14.0.linux-amd64.tar.gz`, 107,111,714
bytes ([gh-releases]); the binary's own size was not measured. The request `promtool` would make
against Grafana's proxy, `GET .../proxy/uid/prometheus/api/v1/query?query=up` with a Viewer
Bearer, answered `200` ([empirical]); whether `promtool` accepts a server URL with a path is
unverified.

One line: `promtool query instant http://127.0.0.1:9090 'sum(rate(http_server_duration_count[5m])) by (service_name)'`.

`mimirtool` does not apply. Its commands are `alertmanager`, `rules`, `remote-read`, `analyze`,
`bucket-validation`, `acl`, `config`, `backfill`, `blocks` and `partition-ring`; there is no
instant-query command, and `remote-read` fetches series, not a PromQL result ([mimirtool]). Its
auth would be `MIMIR_ADDRESS`, `MIMIR_API_USER`, `MIMIR_API_KEY` (basic) and `MIMIR_TENANT_ID`
([mimirtool]); Mimir's own API lives under `/prometheus/api/v1/...` and "If you disable
multi-tenancy, Grafana Mimir doesn't require any request to include the `X-Scope-OrgID` header"
([mimir-api]). The single binary `mimirtool-linux-amd64` is 86,384,802 bytes ([gh-releases]).
None of this is in the otel-lgtm image.

*Allow list.* `Bash(promtool query *)`.

### 5. `grafana/mcp-grafana`

The README's tool table lists 106 tools across categories including Search (`search_dashboards`),
Dashboard, Datasources (`list_datasources`, `get_datasource`), Prometheus (`query_prometheus`,
`list_prometheus_metric_names`, label names and values, histogram), Loki (`query_loki_logs`,
`list_loki_label_names`, `list_loki_label_values`, `query_loki_stats`, `query_loki_patterns`),
Alerting (`alerting_manage_rules`, `alerting_manage_routing`, `alerting_manage_silences`),
Annotations (`get_annotations` plus create, update, delete, patch), Incident, OnCall, Sift,
Pyroscope, SQL, CloudWatch and more ([mcp-grafana]). Auth is `GRAFANA_URL` and
`GRAFANA_SERVICE_ACCOUNT_TOKEN` (or `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE`; `GRAFANA_API_KEY` is
deprecated; `GRAFANA_USERNAME`/`GRAFANA_PASSWORD` for basic auth), and the source sets
`Authorization: Bearer ` + the token on every request, defaulting the URL to
`http://localhost:3000` ([mcp-grafana-src]). "Queries go through Grafana's datasource plugins, so
authentication is handled by datasource configuration — credentials are never seen by the MCP
server" ([mcp-grafana]); `tools/loki.go` builds its URL from `datasourceProxyPaths(uid)` under the
Grafana URL, and `query_loki_logs` "Defaults to the last hour, a limit of 10 entries, and
'backward' direction" ([mcp-grafana-loki-src]). Its RBAC table wants `datasources:query` on the
datasource uid for `query_prometheus` and `query_loki_logs`, `datasources:read` for
`list_datasources`, `alert.rules:read` for `alerting_manage_rules` (plus write for mutations),
`annotations:read` for `get_annotations`, `dashboards:read` for `search_dashboards`
([mcp-grafana]); every one of those a Viewer token answered above.

Transports: "The transport type defaults to `stdio`", with `sse` and `streamable-http` as the
served forms; flags `-t/--transport`, `--address`, `--debug`, `--enabled-tools` (a category list:
`search, datasource, prometheus, loki, alerting, annotation, ...`), `--disable-<category>`,
`--disable-write` ("a way to run the MCP server in read-only mode") and `--enable-write-tools` to
re-admit named ones ([mcp-grafana]). The Docker image's entrypoint is the served form,
`--transport sse --address 0.0.0.0:8000`, as user `mcp-grafana` uid 1000, on `debian:bookworm-slim`,
built with `CGO_ENABLED=0` ([mcp-grafana-dockerfile]); the release for this laptop's architecture
is `mcp-grafana_Linux_x86_64.tar.gz`, 17,625,900 bytes, v1.4.2 published 2026-09-14
([gh-releases]). Inside the demo image there is no `docker`, so the binary is copied in and
Claude Code spawns it as a stdio child, the same way it would spawn `jira-as`.

Claude Code's side: a stdio server is `{"mcpServers":{"grafana":{"command":"...","args":[...],"env":{...}}}}`
with `${VAR}` and `${VAR:-default}` expansion in `command`, `args` and `env` ([cc-mcp]); a Run passes
it with `--mcp-config` and, with `--strict-mcp-config`, "uses only the MCP servers you pass"
([cc-mcp]). With `-p`, "Claude Code waits for still-pending servers to connect before running the
first turn, up to the `MCP_TIMEOUT` startup timeout, 30 seconds by default" (v2.1.221+)
([cc-cli]). In `dontAsk`, "Claude Code denies every call that would otherwise prompt", and calls
covered by `--allowedTools` run ([cc-headless]), so the allow list names the tools:
`mcp__grafana__query_loki_logs` matches one tool, `mcp__grafana` any tool of the server, and
`mcp__grafana__*` "matches every tool from the `grafana` server", because "Allow rules accept
tool-name globs only after a literal `mcp__<server>__` prefix" ([cc-permissions]). Deny rules take
globs anywhere, so `--disallowedTools "mcp__grafana__create_*"` is legal ([cc-permissions]), though
`--disable-write` at the server is the cleaner cut. Tool output over 25,000 tokens by default is
written to a file and referenced ([cc-mcp]).

One line (the config the Run is launched with; the Run then calls the tool by name):

```
--mcp-config '{"mcpServers":{"grafana":{"command":"/usr/local/bin/mcp-grafana","args":["-t","stdio","--disable-write","--enabled-tools","prometheus,loki,alerting,annotation,search"],"env":{"GRAFANA_URL":"${GRAFANA_URL}","GRAFANA_SERVICE_ACCOUNT_TOKEN":"${GRAFANA_TOKEN}"}}}}' --strict-mcp-config --allowedTools "mcp__grafana__*" "Bash(jira-as *)" "Read"
```

*What the allow list says about such a Run.* Exactly what it says now, one line longer: the audience
reads `tools=Bash,Read,mcp__grafana__*`. This repo's log formatter prints any tool call as
`<name>: <input>`, JSON when the input is not a command or a path, so
`mcp__grafana__query_loki_logs: {"datasourceUid": "loki", "logql": "..."}` renders today without
a change; whether that reads as well as a command on the demo screen is a rehearsal question.

## Comparison

| Tool | What it can read | Auth it needs | One-line invocation | Image cost | Allow-list form |
| --- | --- | --- | --- | --- | --- |
| Grafana HTTP API via `python3 -c` | Everything Grafana exposes: `/api/ds/query` and the datasource proxy for Loki, Prometheus and Tempo, annotations, alert rules and firing alerts, dashboard search ([grafana-ds-api], [empirical]) | `Authorization: Bearer <SA token>`, Viewer ([grafana-auth], [empirical]) | `python3 -c "import os,urllib.request as u;print(u.urlopen(u.Request('http://127.0.0.1:PORT/api/datasources/proxy/uid/loki/loki/api/v1/labels',headers={'Authorization':'Bearer '+os.environ['GRAFANA_TOKEN']})).read().decode())"` | none | `Bash(python3 -c *)`: any Python. Wrap it as an `eyes` CLI and the rule is `Bash(eyes *)` |
| Grafana HTTP API via `node -e` | Same | Same | `node -e "fetch('http://127.0.0.1:PORT/api/datasources/proxy/uid/prometheus/api/v1/query?query=up',{headers:{Authorization:'Bearer '+process.env.GRAFANA_TOKEN}}).then(r=>r.text()).then(console.log)"` | none | `Bash(node -e *)`: any JavaScript |
| `logcli` | Loki only: `query`, `instant-query`, `labels`, `series` ([loki-logcli]) | None against Loki directly; `LOKI_BEARER_TOKEN` as an Authorization header if pointed at Grafana's proxy prefix ([loki-logcli]) | `logcli query --since=15m --limit=50 --output=jsonl '{service_name="rolldice"}'` | `logcli-linux-amd64.zip`, 37.4 MB zipped ([gh-releases]) | `Bash(logcli query *)`, `Bash(logcli labels *)`, `Bash(logcli series *)`, `Bash(logcli instant-query *)` |
| `tempo-cli` | Tempo only: trace by id, TraceQL search, tags, tag values, TraceQL metrics ([tempo-cli]) | None against Tempo directly; `--header` for a token, but `search` takes `<host-port>`, so no Grafana path prefix ([tempo-cli]) | `tempo-cli query api search 127.0.0.1:3200 '{ status = error }' now-15m now` | inside `tempo_3.0.3_linux_amd64.tar.gz`, 70.2 MB with `tempo` and `tempo-query` ([gh-releases], [tempo-goreleaser]) | `Bash(tempo-cli query api *)` |
| Tempo HTTP API via `python3`/`node` | `/api/search?q=`, `/api/traces/<id>`, `/api/search/tags` ([tempo-api]) | As row 1, through the proxy ([empirical]) | as row 1 with `.../proxy/uid/tempo/api/search?q=%7B%7D&limit=5` | none | as row 1 |
| `promtool` | Prometheus only: instant, range, series, labels ([promtool]) | None against Prometheus directly; `--http.config.file` or `--header` for a token ([promtool]) | `promtool query instant http://127.0.0.1:9090 'sum(rate(http_server_duration_count[5m])) by (service_name)'` | inside `prometheus-3.14.0.linux-amd64.tar.gz`, 107.1 MB with `prometheus` ([gh-releases], [prom-promu]) | `Bash(promtool query *)` |
| `mimirtool` | Rules, alertmanager config, remote-read series, analysis; no PromQL query command ([mimirtool]) | `MIMIR_ADDRESS`, `MIMIR_API_USER`/`MIMIR_API_KEY`, `MIMIR_TENANT_ID` ([mimirtool]) | not applicable: the image runs Prometheus ([otel-lgtm-dockerfile]) | `mimirtool-linux-amd64`, 86.4 MB ([gh-releases]) | `Bash(mimirtool *)` |
| `mcp-grafana`, stdio | Through Grafana: Prometheus, Loki, alert rules, annotations, dashboards, datasources; 106 tools, cut down with `--enabled-tools` and `--disable-write` ([mcp-grafana]) | `GRAFANA_URL` + `GRAFANA_SERVICE_ACCOUNT_TOKEN`, sent as Bearer ([mcp-grafana-src]); Viewer answers every read tool's RBAC row ([empirical]) | `--mcp-config '{"mcpServers":{"grafana":{"command":"/usr/local/bin/mcp-grafana","args":["-t","stdio","--disable-write","--enabled-tools","prometheus,loki,alerting,annotation,search"],"env":{"GRAFANA_URL":"${GRAFANA_URL}","GRAFANA_SERVICE_ACCOUNT_TOKEN":"${GRAFANA_TOKEN}"}}}}' --strict-mcp-config` | `mcp-grafana_Linux_x86_64.tar.gz`, 17.6 MB, static ([gh-releases], [mcp-grafana-dockerfile]) | `mcp__grafana__query_loki_logs` per tool, or `mcp__grafana__*` ([cc-permissions]) |

**Editorial license lookup, 2026-09-18.** The root license files at the researched release tags identify:

| Candidate | Upstream repository license at researched tag |
| --- | --- |
| logcli / Loki v3.7.7 | AGPL v3 ([tagged LICENSE](https://raw.githubusercontent.com/grafana/loki/v3.7.7/LICENSE)) |
| tempo-cli / Tempo v3.0.3 | AGPL v3 ([tagged LICENSE](https://raw.githubusercontent.com/grafana/tempo/v3.0.3/LICENSE)) |
| promtool / Prometheus v3.14.0 | Apache 2.0 ([tagged LICENSE](https://raw.githubusercontent.com/prometheus/prometheus/v3.14.0/LICENSE)) |
| mcp-grafana v1.4.2 | Apache 2.0 ([tagged LICENSE](https://raw.githubusercontent.com/grafana/mcp-grafana/v1.4.2/LICENSE)) |

These are repository-level identifications, not a completed license inventory for a distributed
binary or its dependencies. Before bundling a selected binary, verify its pinned artifact and
applicable license/notice material and add it to this repository's NOTICE. A NOTICE entry alone
is not claimed to satisfy all distribution conditions. This editorial change adds no binary;
NOTICE remains unchanged.

## What this means for the map

- **Eyes go through Grafana, and Grafana becomes the only door.** The sentinel pattern needs a
  credential to swap, and the backends have none. Turn anonymous off
  (`GF_AUTH_ANONYMOUS_ENABLED=false`), mint one Viewer service account token at Receiver startup
  with the admin's basic auth, keep it in the Forwarder, and give each Run a sentinel in
  `GRAFANA_TOKEN` with `GRAFANA_URL` pointing at the Forwarder, which swaps the `Authorization`
  header. Mount `loki-config.yaml`, `tempo-config.yaml` and a `run-prometheus.sh` that bind
  Loki, Tempo and Prometheus to `127.0.0.1`; Grafana already talks to them there. Without that
  last step the sentinel decorates a stack the Run's `python3` can reach for free.
- **The "Forwarder's growth" question has a shape now.** One Forwarder, two routes: the Atlassian
  site (basic auth swap) and Grafana (Bearer swap). The Confluence peer is a third basic-auth
  route on the same site, not a third Forwarder.
- **Viewer is the role.** It answers every read a Run would make, including alert state and the
  provisioning GET, and refuses every write tried. Nothing in the demo needs Editor.
- **The compose file changes.** Drop `GF_AUTH_DISABLE_LOGIN_FORM`; the presenter logs in.
  Decide whether `admin`/`admin` is acceptable for a demo or whether `GF_SECURITY_ADMIN_PASSWORD`
  comes from `.env` like the other secrets. Grafana's own data directory is not a volume, so the
  service account is re-minted on every `up`, which is fine.
- **Choose the tool by what the allow list can say and the Skill can describe.** Two candidates
  survive: `mcp-grafana` in stdio with `--disable-write --enabled-tools ...`, whose allow-list
  form is a tool name and whose auth is exactly the Bearer header the Forwarder swaps; or a
  standard-library `eyes` CLI in the image, whose allow-list form is `Bash(eyes *)` and whose
  stdout is the evidence a Report cites. `logcli`, `promtool` and `tempo-cli` bring three
  binaries, three auth styles, no view of Grafana's own annotations or alert state, and one of
  them cannot go through Grafana at all; they are not worth 200 MB of archives. `mimirtool` is
  for a Mimir this image does not run. Prototype `mcp-grafana` first: it is a day's work to find
  out whether its tool names read well on the demo screen, whether the 25,000-token output cap
  and the 10-line Loki default fit a five-minute Run, and what the 30-second MCP startup wait does
  to the slot. If it disappoints, `eyes` is the fallback and needs no third party.
- **The Skill's per-signal query guides are written against whichever tool wins**, in the same
  one-line, single-quoted form the Hands use, because the Bash separator list includes newlines
  and "A rule must match each subcommand independently" ([cc-permissions]).
- **The `ls /usr/local/bin` line of ADR 0005 grows by one name.** Either `mcp-grafana` or `eyes`.
  That is the decision to revisit there, as the ADR says.

## Could not verify

- None of `logcli`, `tempo-cli`, `promtool`, `mimirtool` or `mcp-grafana` was executed; none is
  installed on this laptop and nothing was downloaded. The request paths `logcli` and `promtool`
  build were exercised with `curl` against Grafana's proxy and answered `200`; whether `logcli`
  accepts a `LOKI_ADDR` carrying a path prefix end to end, whether `promtool` accepts a server URL
  with a path, and the `--header` value format for `tempo-cli` and `promtool` are not confirmed.
- The `/api/ds/query` body for a Tempo TraceQL search: the guess used returned `500`; the proxy
  route to the same Tempo API returned `200`, so the failure is the body, not the role.
- Why a Viewer token can `GET /api/datasources` on 12.3.1 when the basic-role definition lists
  `datasources.id:read` and the endpoint wants `datasources:read`. Observed, not explained.
- The permission Grafana checks on `/api/ds/query` and on the datasource proxy is not on the
  documentation page; `datasources:query` is the action mcp-grafana's table names, and Viewer
  passed both routes empirically.
- Tests ran on Grafana 12.3.1, the image on this laptop; the `main` Dockerfile of otel-lgtm pins
  Grafana v13.2.1, whose docs carry the `/api` to `/apis` deprecation. The routes used are the
  legacy ones and still answered on 12.3.1.
- Unpacked binary sizes: only archive sizes are known for `logcli` (zip), `tempo-cli` (tarball
  with two other binaries), `promtool` (tarball with `prometheus`) and `mcp-grafana` (tarball).
- Whether `mcp-grafana`'s Prometheus, alerting and annotations tools also route through Grafana's
  proxy or Grafana's own APIs is stated by the README for queries in general; only `tools/loki.go`
  was read.
- Whether `mcp-grafana -t stdio` runs under the compose hardening (`cap_drop: [ALL]`,
  `read_only: true`, tmpfs home) is untested; a static Go binary that writes nothing suggests yes.
- `--strict-mcp-config` appears on the MCP page and not in the CLI reference excerpt fetched;
  its stated effect is from the MCP page.
- Whether the Grafana file-provisioning system cannot create service accounts is taken from the
  provisioning page listing data sources, plugins, dashboards, alerting and RBAC and nothing
  else; an absence, not a statement.
- The `X-TOKEN` header form in the tempo-cli example is the docs' example for a Grafana Cloud
  style gateway; whether a `Authorization=Bearer ...` value passes through unchanged is untested.

## Sources

- [grafana-auth] https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/authentication/
- [grafana-sa] https://grafana.com/docs/grafana/latest/administration/service-accounts/
- [grafana-sa-api] https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/
- [grafana-sa-tutorial] https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/examples/create-api-tokens-for-org/
- [grafana-ds-api] https://grafana.com/docs/grafana/latest/developers/http_api/data_source/
- [grafana-annotations-api] https://grafana.com/docs/grafana/latest/developers/http_api/annotations/
- [grafana-alerting-provisioning-api] https://grafana.com/docs/grafana/latest/developers/http_api/alerting_provisioning/
- [grafana-ngalert-routes] https://raw.githubusercontent.com/grafana/grafana/main/pkg/services/ngalert/api/generated_base_api_prometheus.go
- [grafana-ngalert-authz] https://raw.githubusercontent.com/grafana/grafana/main/pkg/services/ngalert/api/authorization.go
- [grafana-roles] https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/
- [grafana-ds-mgmt] https://grafana.com/docs/grafana/latest/administration/data-source-management/
- [grafana-basic-roles] https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/
- [grafana-actions] https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/custom-role-actions-scopes/
- [grafana-alerting-rbac] https://grafana.com/docs/grafana/latest/alerting/set-up/configure-rbac/
- [grafana-anon] https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/anonymous-auth/
- [grafana-defaults] https://raw.githubusercontent.com/grafana/grafana/main/conf/defaults.ini
- [grafana-config] https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/
- [grafana-docker] https://grafana.com/docs/grafana/latest/setup-grafana/configure-docker/
- [grafana-provisioning] https://grafana.com/docs/grafana/latest/administration/provisioning/
- [loki-logcli] https://grafana.com/docs/loki/latest/query/logcli/getting-started/
- [loki-api] https://grafana.com/docs/loki/latest/reference/loki-http-api/
- [loki-config] https://grafana.com/docs/loki/latest/configure/
- [tempo-api] https://grafana.com/docs/tempo/latest/api_docs/
- [tempo-cli] https://grafana.com/docs/tempo/latest/operations/tempo_cli/
- [tempo-config] https://grafana.com/docs/tempo/latest/configuration/
- [tempo-goreleaser] https://raw.githubusercontent.com/grafana/tempo/main/.goreleaser.yml
- [mimirtool] https://grafana.com/docs/mimir/latest/manage/tools/mimirtool/
- [mimir-api] https://grafana.com/docs/mimir/latest/references/http-api/
- [promtool] https://prometheus.io/docs/prometheus/latest/command-line/promtool/
- [prom-api] https://prometheus.io/docs/prometheus/latest/querying/api/
- [prom-flags] https://prometheus.io/docs/prometheus/latest/command-line/prometheus/
- [prom-promu] https://raw.githubusercontent.com/prometheus/prometheus/main/.promu.yml
- [mcp-grafana] https://github.com/grafana/mcp-grafana (README)
- [mcp-grafana-src] https://raw.githubusercontent.com/grafana/mcp-grafana/main/mcpgrafana.go
- [mcp-grafana-loki-src] https://raw.githubusercontent.com/grafana/mcp-grafana/main/tools/loki.go
- [mcp-grafana-dockerfile] https://raw.githubusercontent.com/grafana/mcp-grafana/main/Dockerfile
- [otel-lgtm-readme] https://github.com/grafana/docker-otel-lgtm
- [otel-lgtm-tree] https://github.com/grafana/docker-otel-lgtm/tree/main/docker
- [otel-lgtm-dockerfile] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/Dockerfile
- [otel-lgtm-run-grafana] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/run-grafana.sh
- [otel-lgtm-run-prometheus] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/run-prometheus.sh
- [otel-lgtm-datasources] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/grafana-datasources.yaml
- [otel-lgtm-loki-config] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/loki-config.yaml
- [otel-lgtm-tempo-config] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/tempo-config.yaml
- [cc-permissions] https://code.claude.com/docs/en/permissions
- [cc-mcp] https://code.claude.com/docs/en/mcp
- [cc-cli] https://code.claude.com/docs/en/cli-reference
- [cc-headless] https://code.claude.com/docs/en/headless
- [node-fetch] https://nodejs.org/api/globals.html
- [python-urllib] https://docs.python.org/3/library/urllib.request.html
- [gh-releases] `gh api repos/<owner>/<repo>/releases/latest`, 2026-09-15: grafana/loki v3.7.7, grafana/tempo v3.0.3, grafana/mimir mimir-3.2.1, prometheus/prometheus v3.14.0, grafana/mcp-grafana v1.4.2
- [local-image] `grafana/otel-lgtm:latest` on this laptop (pulled 2026-01-09): `docker run --rm --entrypoint cat ... /otel-lgtm/run-grafana.sh`, `.../run-prometheus.sh`, `--entrypoint grep` over `loki-config.yaml` and `tempo-config.yaml`, `grafana --version` = 12.3.1
- [empirical] a throwaway `grafana/otel-lgtm:latest` container started 2026-09-15 with `GF_AUTH_ANONYMOUS_ENABLED=false` and ports 3000, 3100, 3200 and 9090 published; a Viewer service account and token minted with `admin:admin`; each request above made with `curl`, `python3 -c` or `node -e` from the laptop; plus one `docker exec` into the running `grafana-jsm-sandbox_demo_1` with `urllib` and no headers. The container was removed afterwards.
