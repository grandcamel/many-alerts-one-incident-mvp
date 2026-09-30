# The OpenTelemetry Demo as the system under simulation (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and source citations retained. This is not a fresh capability or version verification. Source commit: `86913f9f1a0f5f1d4b0fc3d44afe5ac1d03cec48`.

Written 2026-09-15. Question (ticket 01 of the many-alerts-one-incident map): is the
OpenTelemetry Demo the system the next chapter simulates, and what would it cost to run it beside
the `grafana/otel-lgtm` stack on this laptop (Intel MacBook Pro, 4 physical cores and 8 threads, 16 GB; Docker Desktop
reports 4 CPUs and 7.8 GiB to containers)?

**Method.** Primary sources only, all fetched 2026-09-15: the demo docs on opentelemetry.io, the
raw files of `open-telemetry/opentelemetry-demo` at `main` (commit `1a6043d`, 2026-09-15) and its
3.0.0 release notes, the `opentelemetry-demo` Helm chart (0.41.2, appVersion 3.0.0) and the
collector chart it wraps, flagd's docs and source, the OpenFeature hook sources the demo services
use, the `grafana/docker-otel-lgtm` README and manifests, and the demo's own GitHub issues for what
small machines report. Memory figures are given three ways and labelled: what the docs claim, what
the compose and Helm files declare as limits, and what issue reporters measured. Nothing was run;
the only local facts are `docker info` and `docker image ls`.

## Short answer

1. **Yes, it is the system.** Twenty-one services in twelve languages, all traced, most emitting
   OTLP logs and metrics, with **fifteen fault flags on `main`** (fourteen in the 3.0.0 release)
   that default to off and flip at runtime through a JSON file or a bundled UI ([flags-json],
   [feature-flags]). Nothing else off the shelf gives a Run a cascade to reduce.
2. **The default deployment does not fit this laptop.** `make start` declares **7.9 GB of memory
   limits across 28 containers**; the docs say it needs 6 GB of RAM and 14 GB of disk; Docker
   Desktop here has 7.8 GiB total ([compose], [compose-full], [compose-obs], [docker-deployment],
   [docker-info]). The Helm chart is larger still: **8.5 GiB of limits**, and it turns on the LLM
   agent, chatbot and MCP services by default ([helm-values]).
3. **The subset that fits is the demo's own core layer with its observability layer removed.**
   `compose.yaml` alone is 20 containers and 4.2 GB of declared limits, and it already exports to
   nothing but the debug exporter, which is exactly the seam for pointing it at LGTM ([compose],
   [otelcol-base]). Thirteen of the fifteen flags work in that mode; `kafkaQueueProblems` needs
   the Kafka layer (+1.1 GB) and `failedReadinessProbe` needs Kubernetes.
4. **Pointing it at LGTM is a documented seam, not a fork.** `otelcol-config-extras.yml` and
   `compose.extras.yaml` are "always loaded last" for this purpose; add one `otlp_http` exporter
   at `lgtm:4318` and repeat the upstream exporter arrays ([otelcol-extras], [compose-extras],
   [docker-deployment]). On Helm, the four bundled backends each have an `enabled` switch
   ([helm-chart]).
5. **Compose services carry no Kubernetes-shaped attributes and never will.** On Compose the
   SDKs send `service.name`, `service.namespace=opentelemetry-demo`, `service.version` and a
   demo-specific `service.criticality`; the collector adds `host.name` and `os.type` from the
   Docker daemon, and `container.*` only on the `docker_stats` metrics ([dotenv], [compose],
   [otelcol-base], [docker-detector], [dockerstats]). On Kubernetes the `k8sattributes` preset
   adds `k8s.pod.name`, `k8s.namespace.name`, `k8s.deployment.name`, `k8s.node.name` and twenty
   more ([collector-config-tpl]).
6. **A flag flip is not recorded anywhere a Run can query.** flagd emits a `configuration_change`
   event on its gRPC event stream and logs one Info line; neither becomes a span, metric or OTLP
   log record ([flagd-providers], [flagd-filesync], [log-coverage]). The Change has to be built:
   a watcher on that stream that posts a Grafana annotation and an OTLP log record is about thirty
   lines ([grafana-annotations], [semconv-ff-events]).
7. **Pin a commit.** `main` and the 3.0.0 release disagree about the load generator (Locust
   versus k6) and about which load-generator flags exist; the docs and the Helm chart describe
   3.0.0, the repo at `main` does not ([changelog], [loadgen-commits], [flagd-json-commits]).

## What the demo is, as of 3.0.0 and `main`

The Astronomy Shop: a web store whose `frontend` (TypeScript) calls `ad` (Java), `cart` (.NET,
backed by Valkey), `checkout` (Go), `currency` (C++), `product-catalog` (Go, backed by
PostgreSQL), `recommendation` (Python), `shipping` (Rust, which calls `quote` in PHP), `payment`
(JavaScript) and `email` (Ruby); `checkout` also publishes orders to Kafka for `accounting` (.NET)
and `fraud-detection` (Kotlin). Envoy fronts everything on port 8080 as `frontend-proxy`; nginx
serves product images; a Python `load-generator` drives traffic; `flagd` (Go) serves the flags and
`flagd-ui` (Elixir) edits them ([services], [architecture]). Every service is traced; OTLP logs are
present for fourteen of twenty-one and marked "not present (yet)" for `frontend`, `flagd`,
`flagd-ui`, `image-provider`, `agent`, `chatbot` and `mcp`; metrics are auto-instrumented on the
main languages and manual on a few ([telemetry-features], [log-coverage], [metric-coverage]).

The latest release is 3.0.0 (2026-07-24); `main` was at `1a6043d` on 2026-09-15 ([release],
[main-commit]). Two things changed between them that matter here. The 3.0.0 release "Replaced
Locust with k6" (PR #3564, merged 2026-07-17) and added the `loadGeneratorTraffic` and
`loadGeneratorVUs` flags; on 2026-09-01 `main` reverted that ("revert(load-generator): replace k6
with Locust", PR #3873), restoring `loadGeneratorFloodHomepage`, and on 2026-09-08 `main` gained
`productCatalogLockContention` ([changelog], [loadgen-commits], [flagd-json-commits]). The docs
page and the Helm chart's embedded flag file still show the 3.0.0 set ([feature-flags],
[helm-flags]). The `.env` on `main` pulls `ghcr.io/open-telemetry/demo:latest-<service>` images
while setting `LOCUST_*` environment variables; the release workflow pushes both the version tag
and `latest-<service>` from the same job, so what `latest` currently is could not be determined
without registry access ([dotenv], [release-workflow]). Pin `DEMO_VERSION` to `3.0.0` or build
from a pinned commit.

## Footprint on Docker Compose

The docs require Docker Compose v2.0.0+, "6 GB of RAM for the application (or ~3 GB using
minimal mode)" and "14 GB of disk space" ([docker-deployment]). The compose files are layered
and every service declares a `deploy.resources.limits.memory`; the sums below are those declared
limits, not measurements ([compose], [compose-full], [compose-obs], [makefile]).

| Layer (make target) | Containers | Declared memory limits | What it adds |
| --- | --- | --- | --- |
| `compose.yaml` only (`start-minimal-no-o11y`) | 20 | 4,155 MB | 14 app services, flagd, flagd-ui, telemetry-docs, Postgres, Valkey, collector |
| + `compose.full.yaml` (`start-no-o11y`) | 23 | 5,235 MB | Kafka (620 M), accounting (160 M), fraud-detection (300 M) |
| `compose.yaml` + `compose.observability.yaml` (`start-minimal`) | 25 | 6,819 MB | Jaeger (1,200 M), OpenSearch (1 G), Prometheus (200 M), Grafana (175 M), OpAMP server (65 M) |
| all three (`start`, the default) | 28 | 7,899 MB | |
| + `compose.agent.yaml` (`start-agentic`) | 31 | +1,500 MB | agent, mcp, chatbot at 500 M each |

Inside the core layer the big items are `load-generator` at 1,500 M (it runs headless Chromium
for browser users), `recommendation` at 500 M ("high to enable supporting the recommendationCache
feature flag use case"), `otel-collector` at 400 M and `ad` at 300 M; the Go and Rust services are
20 M each ([compose]). Each container is its own image: 21 built by the demo
(`ghcr.io/open-telemetry/demo:<version>-<service>`) plus flagd v0.16.0, Postgres 18.4, Valkey 9.0.4,
collector-contrib 0.159.0, Jaeger 2.19.0, Grafana 13.1.0 and Prometheus v3.13.1 ([dotenv]).

What reporters measured is consistently above the limits the maintainers set. "Demo reliability,
various services experiencing memory issues" (2026-02-25, Helm) measured `ad` at ~452 Mi against a
300 Mi limit, `fraud-detection` ~362 Mi against 300 Mi, `kafka` ~642 Mi against 600 Mi, and flagd
OOM-killed; it was closed by raising limits ([issue-3034]). The load generator "eats all the
available RAM that i set in the memory limit" (2025-10-23, v2.1.3, limit raised 1500 Mi to
2000 Mi) ([issue-2678]). `flagd-ui` once consumed 2.3 GB until a BEAM VM fix in 3.0.0
([release]). The demo's own issue list has thirty-six items with "memory" in the title, most of
them limit adjustments ([issues-memory]). No report of a Docker Desktop run on an 8 GB VM was
found; the closest is a Helm run on a 4 vCPU / 8 GiB node where Prometheus alone OOM-looped 126
times at its 400 Mi limit (2026-08-06, open) ([issue-3811]).

Locally: Docker Desktop exposes `NCPU=4` and `MemTotal=8347045888` (7.8 GiB) to containers, on
Docker Engine 20.10.8; whether the installed Compose is v2 was not checked ([docker-info]). The
`grafana/otel-lgtm:latest` image is present, 1.94 GB on disk and eight months old; no demo images
are ([docker-images]).

## Footprint on Kubernetes

The docs require Kubernetes 1.24+, "6 GB of free RAM for the application", Helm 3.14+ and chart
0.11.0 or newer; the chart "does not support being upgraded from one version to another", and the
generated manifests were removed from the demo repo in 3.0.0 in favour of `helm template`
([kubernetes-deployment], [changelog]). The chart (0.41.2, appVersion 3.0.0) pulls in the
`opentelemetry-collector` chart 0.165.0 as a DaemonSet, Jaeger 4.11.1, Prometheus 29.18.0,
Grafana 12.7.2 and OpenSearch 3.7.0, each behind an `enabled` condition ([helm-chart]).

Declared limits in `values.yaml`: 26 demo containers (including the flagd-ui sidecar at 250 Mi)
sum to **5,492 Mi**, and unlike Compose the chart enables `agent`, `chatbot` and `mcp` by default
at 500 Mi each and gives Kafka 700 Mi and the load generator 512 Mi; the backends add collector
400 Mi, Jaeger 600 Mi, Prometheus 400 Mi, Grafana 300 Mi plus a 256 Mi sidecar, OpenSearch
1,100 Mi, for **3,056 Mi**; total **8,548 Mi** ([helm-values]). The chart README's parameter
table still quotes older figures (collector 200 Mi, Jaeger 400 Mi, Grafana 175 Mi) and should not
be trusted over `values.yaml` ([helm-readme]). Requests are not set anywhere in the chart, so a
scheduler will place all of it on one node and the kernel will do the arbitration; that is the
shape of the Prometheus OOM loop above ([issue-3811]).

The load generator in the chart is the k6 one (`LOAD_GENERATOR_VUS`, `K6_TARGET_URL`), matching
3.0.0, not `main` ([helm-values]).

## The fault flags

All flags live in one file, `src/flagd/demo.flagd.json`, mounted into `flagd` at
`/etc/flagd/demo.flagd.json` and into `flagd-ui` at `/app/data`; every flag ships with
`state: ENABLED` and `defaultVariant: off` ([flags-json], [compose]). The UI at
`http://localhost:8080/feature` has a Basic view (default variants only) and an Advanced view
(the raw JSON with schema checking) and writes the file through its `/write` endpoint
([feature-flags], [flagd-ui-readme]). flagd watches the file with fsnotify and reloads on
`Create`/`Write` events; runtime reload without a restart has worked since the flagd 0.11.2
upgrade in August 2024, which closed the issue that reported edits were "a noop" ([flagd-filesync],
[issue-1625], [pr-1711]).

The fifteen flags on `main`, with what each breaks (from the docs and, where fetched, the code),
and which signals the demo's own pipeline would show ([feature-flags], [flags-json]):

| Flag | Service | Mechanism | Where it shows |
| --- | --- | --- | --- |
| `adFailure` | ad | `GetAds` throws `UNAVAILABLE` on 1 in 10 calls ([ad-source]) | error spans on ad and on the frontend client; `span_metrics` error rate; ad's OTLP logs |
| `adHighCpu` | ad | spawns CPU-load threads; docs say set CPU limits to demo throttling ([ad-source]) | `container.cpu.utilization` from `docker_stats`; JVM metrics from the Java agent; latency |
| `adManualGc` | ad | forces full GCs ([ad-source]) | JVM GC metrics; latency spikes |
| `cartFailure` | cart | the chosen percentage of `EmptyCart` calls go to a store at `badhost:1234` ([cart-source]) | exceptions on cart spans; OpenFeature `MetricsHook` counters and `TraceEnricherHook` span events carry the variant |
| `emailMemoryLeak` | email | pads each confirmation body by 1x to 10,000x | `container.memory.usage.total` climbing for `email`; eventually an OOM restart |
| `failedReadinessProbe` | cart | readiness endpoint reports unhealthy, "Kubernetes deployments only" | pod `Ready=False`, removed from Service endpoints, a kubelet Event; no restart ([k8s-probes]) |
| `imageSlowLoad` | frontend-proxy | Envoy fault injection delays image responses by 5 or 10 s | long Envoy spans on the image route; browser (`frontend-web`) spans |
| `intlShippingSlowdown` | shipping | non-US quotes sleep 5 or 10 s | shipping and checkout span durations; `span_metrics` p95 |
| `kafkaQueueProblems` | checkout, fraud-detection | floods the `orders` topic and delays the consumer | `kafka.consumer_group.lag` and `lag_sum` from the `kafkametrics` receiver, full mode only ([kafkametrics], [otelcol-full]) |
| `loadGeneratorFloodHomepage` | load-generator | each Locust user hits `/` N times in a `user_flood_home` span with `demo.request.flood.count` ([locustfile]) | request-rate step on every service; `http_check` on the proxy |
| `paymentFailure` | payment | the chosen percentage of `charge` calls error | payment error spans; checkout client errors |
| `paymentUnreachable` | checkout | checkout dials a bad payment address | checkout client-span errors; payment goes silent |
| `productCatalogFailure` | product-catalog | `GetProduct` errors for product `OLJCESPC7Z` via a targeting rule | error spans on one product; the frontend page for it fails |
| `productCatalogLockContention` | product-catalog | holds an `ACCESS EXCLUSIVE` lock on `catalog.products` for up to 30 s, with a log line ([lock-commit]) | product-catalog and checkout latency; `postgresql` receiver metrics (`postgresql.deadlocks` is enabled) ([otelcol-base]) |
| `recommendationCacheFailure` | recommendation | the cache list grows by a quarter of itself on roughly half of requests ([recommendation-source]) | CPU and memory spikes, p95/p99 long tail, `demo.recommendation.cache_hit=false` and `demo.feature_flag.recommendation_cache=true` span attributes, a "cache miss" log line ([recommendation-cache]) |

Two details from the file itself. `productCatalogFailure` ships with a targeting rule whose
`if` returns `"off"` on both branches, so flipping its `defaultVariant` alone does nothing until
the rule's first branch is edited to `"on"` ([flags-json]). `paymentFailure`'s `"90%"` variant is
`0.95` ([flags-json]).

The 3.0.0 release instead carries `loadGeneratorTraffic` (default `on`; off pauses all synthetic
traffic) and `loadGeneratorVUs` (5, 10, 25, 50; "changing it restarts k6 on the next poll"), and
lacks the two `main`-only flags ([feature-flags], [helm-flags], [changelog]).

### Flag evaluations are already in the telemetry

This is the part a reasoning Run can lean on. The Python services (`recommendation`,
`load-generator`) register OpenFeature's `TracingHook`, which adds a `feature_flag.evaluation`
span event with `feature_flag.key`, `feature_flag.result.value`, `feature_flag.result.reason`,
`feature_flag.result.variant`, `feature_flag.context.id` and `feature_flag.provider.name` on
every evaluation ([recommendation-source], [locustfile], [python-hook]). `cart` registers the .NET
`MetricsHook` (meter `OpenFeature`: `feature_flag.active`, `feature_flag.requests.total`,
`feature_flag.success.total`, `feature_flag.error.total`, tagged with key, provider, reason,
variant) and `TraceEnricherHook` ([cart-source], [dotnet-metrics-hook]). `ad` builds its
`FlagdProvider` with `withGlobalTelemetry(true)`, which traces the gRPC evaluation calls into
flagd ([ad-source], [java-flagd-provider]). flagd itself, given `OTEL_EXPORTER_OTLP_ENDPOINT` as
the compose file does, exports `feature_flag.flagd.impression` and
`feature_flag.flagd.result.reason` counters tagged with `feature_flag.key`,
`feature_flag.result.variant`, `feature_flag.provider.name` and the reason, plus
`flagEvaluationService(resolveX)` spans ([flagd-monitoring], [compose]). The event convention
those hooks follow is Release Candidate in semconv ([semconv-ff-events]). So after a flip, the
variant label on flagd's impression counter changes, and every affected span carries the new
variant, before any symptom appears.

## Pointing it at LGTM (or Alloy) instead of the bundled backends

The collector config is layered the same way as compose: `otelcol-config.yml` is "the base
configuration, always loaded" and exports only to `debug`; `otelcol-config-full.yml` adds the
Kafka receiver; `otelcol-config-observability.yml` "wires up the bundled backends (Jaeger,
Prometheus, and OpenSearch)"; `otelcol-config-extras.yml` is "your own additions, always loaded
last" ([docker-deployment], [otelcol-base], [otelcol-obs]). The documented recipe is to add an
exporter in the extras file and "override the `exporters` for telemetry pipelines that you want to
use for your backend", with one constraint: preserve `span_metrics` in both the traces exporter list and the metrics
receiver list. Removing that connection breaks collector startup ([docker-deployment]). The extras file's own
comment adds the second trap: the collector "REPLACES arrays, not appends", so an override of the
metrics pipeline must repeat the whole receiver list (`docker_stats`, `http_check/frontend-proxy`,
`host_metrics`, `nginx`, `otlp`, `redis`, `postgresql`, `prometheus/ad`, `span_metrics`, and
`kafkametrics` in full mode) ([otelcol-extras], [otelcol-full]).

`compose.extras.yaml` is the matching seam for the container: "intentionally empty", "always
loaded last", with an example that adds a backend service and a `depends_on` on the collector
([compose-extras]). So the LGTM wiring is: run without `compose.observability.yaml` (`make
start-no-o11y` or `start-minimal-no-o11y`, which is also what removes Jaeger, Prometheus,
Grafana, OpenSearch and the OpAMP server), put an `lgtm` service in `compose.extras.yaml`, and in
`otelcol-config-extras.yml` add `otlp_http/lgtm` with `endpoint: http://lgtm:4318` and pipelines
`traces: [debug, span_metrics, otlp_http/lgtm]`, `metrics: [debug, otlp_http/lgtm]`, `logs:
[debug, otlp_http/lgtm]`. LGTM's collector receives OTLP on 4317 and 4318 and routes metrics to
Prometheus (`/api/v1/otlp`), traces to Tempo, logs to Loki and profiles to Pyroscope; Grafana is
on 3000 with `admin`/`admin`; "There's no need to configure anything: the Docker image works with
OpenTelemetry's defaults" ([lgtm-readme], [lgtm-otelcol]). Alloy is the same shape:
`otelcol.receiver.otlp` listens on `0.0.0.0:4317` and `0.0.0.0:4318` and forwards to
`otelcol.exporter.otlphttp` ([alloy-otlp]).

The shortcut of setting `OTEL_COLLECTOR_HOST=lgtm` in `.env.override` so every service exports
straight to LGTM works on paper, because every service's endpoint is built from that variable
([dotenv], [compose]), but it discards the demo collector's receivers (host, Docker, Redis,
PostgreSQL, nginx, the ad Prometheus scrape) and its `span_metrics` connector, which is where the
RED metrics the demo's dashboards use come from; LGTM's collector has no span-metrics stage
([lgtm-otelcol]). Keep the demo collector and chain it.

On Helm, set `jaeger.enabled`, `prometheus.enabled`, `grafana.enabled` and `opensearch.enabled` to
`false`, disable the `opamp-server` component, and override `opentelemetry-collector.config` with
an `otlphttp` exporter to the `lgtm` Service; the docs repeat the `spanmetrics` warning for the
chart ([helm-chart], [helm-values], [kubernetes-deployment]). `docker-otel-lgtm` ships a
`k8s/lgtm.yaml` Deployment with no resource requests or limits and six ports (3000, 3200, 4040,
4317, 4318, 9090), all `emptyDir` ([lgtm-k8s]).

## Resource attributes: Compose versus Kubernetes

On Compose, `.env` sets `OTEL_RESOURCE_ATTRIBUTES=service.namespace=opentelemetry-demo,service.version=3.0.0`
and each service appends `service.criticality=<critical|high|medium|low>` and sets
`OTEL_SERVICE_NAME` ([dotenv], [compose]). The collector's `resource_detection` runs `env`,
`docker` and `system`; the Docker detector, with the socket mounted, sets `host.name` and
`os.type` by default (`container.name` and `container.image.name` exist but are off), and the
contrib README notes "Docker detection does not work on macOS" for a collector run natively, which
does not apply to one in a container ([otelcol-base], [docker-detector], [resourcedetection]).
`container.id`, `container.name`, `container.image.name`, `container.hostname` and
`container.runtime` appear only as resource attributes of the `docker_stats` metrics, not on
application spans or logs ([dockerstats]). No `k8s.*` attribute exists in this mode, and nothing
in the demo fakes one.

On Kubernetes the SDK-level environment is thinner, not richer: `OTEL_SERVICE_NAME` comes from the
pod label `app.kubernetes.io/component`, `OTEL_RESOURCE_ATTRIBUTES` is `service.version=3.0.0`
plus the same `service.criticality` suffix, and `service.namespace` is a pod annotation
`resource.opentelemetry.io/service.namespace: opentelemetry-demo` ([helm-values]). The collector
chart's `kubernetesAttributes` preset renders a `k8sattributes` processor with
`otel_annotations: true` (which turns that annotation into the resource attribute) and extracts
`k8s.namespace.name`, `k8s.pod.name`, `k8s.pod.uid`, `k8s.node.name`, `k8s.pod.start_time`,
`k8s.deployment.name`, `k8s.replicaset.name`/`uid`, `k8s.daemonset.name`/`uid`,
`k8s.job.name`/`uid`, `k8s.container.name`, `k8s.cronjob.name`, `k8s.statefulset.name`/`uid`,
`container.image.tag`, `container.image.name`, `k8s.cluster.uid` and the `service.*` set
([collector-config-tpl], [k8sattributes]); the demo chart then copies `k8s.pod.uid` into
`service.instance.id` ([helm-values]). The `hostMetrics`, `kubeletMetrics` and `clusterMetrics`
presets are on; the collector chart's `kubernetesEvents` preset (a `k8sobjects` or `k8s_events`
receiver) exists but the demo chart does not enable it, so Kubernetes Events, including the
readiness-probe failures `failedReadinessProbe` produces, are not collected unless added
([helm-values], [collector-chart-readme]).

## Can a flag flip be recorded as a Change?

Not by anything that ships. What exists on a flip:

- flagd logs, at Info, `filepath event: <path> WRITE` from its fsnotify loop ([flagd-filesync]).
  flagd's logs are "not present (yet)" in the OTLP coverage table and the demo collector reads no
  container stdout, so the line stays in `docker logs` ([log-coverage], [otelcol-base]).
- flagd computes a delta between the old and new flag sets, one entry per changed key with a type
  of `create`, `update` or `delete`, and sends it as a `configuration_change` event on its gRPC
  `EventStream`; the documented payload shape is `{"type": "write", "source":
  "/flag-configuration.json", "flagKey": "foo"}`. RPC providers turn it into OpenFeature's
  `PROVIDER_CONFIGURATION_CHANGED` and invalidate their caches; in-process providers get the same
  through the sync stream ([flagd-notifications], [flagd-protos], [flagd-providers],
  [openfeature-events]).
- Nothing in flagd's monitoring page ties a metric, span or log record to the change itself; the
  only telemetry-side trace of it is that `feature_flag.flagd.impression` starts counting under a
  new `feature_flag.result.variant` label, and the hooks above start stamping the new variant on
  spans ([flagd-monitoring], [python-hook]).

Two ways to make the Change explicit, both small:

1. **A watcher.** A process that opens flagd's `EventStream` (or, more crudely, polls
   `/feature/read` on flagd-ui) and on each `configuration_change` does two things: `POST
   /api/annotations` to Grafana with `time`, `tags: ["feature_flag", "<key>"]` and a `text` naming
   the key and new variant, which needs the `annotations:create` permission and which any
   dashboard can then overlay by tag ([grafana-annotations]); and emit one OTLP log record through
   the demo collector into Loki with `feature_flag.key` and the new variant as attributes. There is
   no semconv event for a flag *change*, only for an *evaluation* (`feature_flag.evaluation`), so
   the record's `event.name` is the demo's to choose ([semconv-ff-events]).
2. **A hook on the writer.** In the demo the only writer is `flagd-ui`'s `/write` endpoint
   (`/feature/write` through Envoy); a reverse-proxy rule or a sidecar that sees that POST has the
   diff before flagd does ([flagd-ui-readme], [compose]). This misses edits made by hand to the
   JSON, which the watcher does not.

Either gives the Run an annotation and a log line with a timestamp to correlate against the first
alert. Neither exists today.

## A minimal subset

The demo supports subsets at two grains. On Compose the grain is the layer: the Makefile's
`start-minimal` "excludes Kafka and its dependent services (accounting, fraud-detection, kafka),
reducing memory usage to ~3 GB", and `start-minimal-no-o11y` runs `compose.yaml` alone
([docker-deployment], [makefile]). On Helm the grain is the component: every one of the 27 demo
components has its own `enabled`, and the four backends and the collector do too ([helm-values],
[helm-chart]).

Below the core layer there is no supported subset, because of `depends_on`. `frontend` waits on
`ad`, `cart`, `checkout`, `currency`, `product-catalog`, `quote`, `recommendation`, `shipping`,
`image-provider`, `flagd` and the collector; `checkout` waits on `cart`, `currency`, `email`,
`payment`, `product-catalog` and `shipping`; `frontend-proxy` waits on `frontend`,
`load-generator`, `flagd-ui` and `telemetry-docs` ([compose]). The three that carry no fault and
could go with an override file that drops the `depends_on` are `load-generator` (1,500 M, if the
Run's traffic comes from elsewhere), `flagd-ui` (200 M, if flags are flipped by editing the JSON)
and `telemetry-docs` (100 M); that leaves seventeen containers and about 2.4 GB of declared
limits, with all thirteen non-Kafka, non-Kubernetes flags intact. Dropping the load generator
also drops the demo's only source of steady background traffic, which every latency and error-rate
symptom above depends on; a lighter driver (a `k6` or `hey` loop against `:8080`) would have to
replace it.

## What this means for the map

- **The system is settled.** Use the OpenTelemetry Demo; the fault surface is fifteen documented
  flags whose evaluations are already stamped on spans and counted by flagd, so the Run can see
  the cause in the same data as the symptoms.
- **The laptop runs the core layer, not the default.** Budget: `compose.yaml` alone is 4.2 GB of
  declared limits (2.4 GB with the three dispensable containers removed), plus LGTM (usage
  unstated anywhere; image 1.94 GB on disk), plus this repo's Receiver and Runs, inside a 7.8 GiB
  Docker Desktop VM. `make start` (7.9 GB) and `start-minimal` (6.8 GB) are out. Disk is 14 GB.
- **Kubernetes on the laptop is out; the chart is the DigitalOcean shape.** 8.5 GiB of limits with
  the LLM services on by default, no requests set, and one open OOM report on a 4 vCPU / 8 GiB
  node. If the chapter needs `k8s.*` attributes or a real `NotReady` Event, that is ticket 05's
  cluster, with `agent`, `chatbot`, `mcp` and the four bundled backends switched off and LGTM in
  the cluster.
- **Two flags need the bigger deployments.** `kafkaQueueProblems` needs the Kafka layer
  (+1.1 GB on Compose); `failedReadinessProbe` needs Kubernetes and the `kubernetesEvents` preset
  turned on for the Event to reach the backend. The other thirteen work in the core layer.
- **The Change is a small build.** A flagd `EventStream` watcher that posts a Grafana annotation
  and an OTLP log record; nothing shipped does it. The demo's flag file is the Change source of
  truth, and its edits are what the Run should be asked to correlate.
- **Pin 3.0.0 or a commit, and say which.** The load generator and two flags differ between the
  release, the docs, the Helm chart and `main`; `latest` images are pushed by the same workflow
  as version tags.
- **Chain the demo collector into LGTM; do not bypass it.** The `span_metrics` RED metrics, the
  Docker and PostgreSQL receivers, and the redaction transforms all live in the demo collector.

## Could not verify

- What `ghcr.io/open-telemetry/demo:latest-*` resolves to today (3.0.0 with k6, or a `main`
  build with Locust); the registry's tag list needs authentication.
- Any measured memory or CPU figure on this laptop: nothing was started. Every number above is a
  declared limit, a docs claim, or another reporter's measurement on their machine.
- The `grafana/otel-lgtm` image's own memory and CPU use; the README, the anniversary post and the
  Kubernetes manifest state none.
- Whether the Compose installed alongside Docker Engine 20.10.8 here is v2.0.0+, which the demo
  requires; `docker compose version` was not run.
- Whether the `k8s_cluster` receiver's per-container readiness gauge (if it exists in the version
  the chart pins) would show `failedReadinessProbe` without the Events preset.
- Whether Tempo's metrics generator inside LGTM could stand in for the demo's `span_metrics`
  connector; LGTM's shipped collector config has no such stage and Tempo's config was not read.
- The exact Envoy route and fault-injection config behind `imageSlowLoad`, and the cart readiness
  handler behind `failedReadinessProbe`; both are described here from the docs table only.
- Whether flagd-ui's Basic view can enable `productCatalogFailure` given its shipped targeting
  rule, or whether the Advanced view is required.
- The chart README's resource table disagrees with `values.yaml` (collector 200 Mi vs 400 Mi,
  Jaeger 400 Mi vs 600 Mi, Grafana 175 Mi vs 300 Mi); `values.yaml` was taken as authoritative.

## Sources

- [docker-deployment] https://opentelemetry.io/docs/demo/docker-deployment/
- [kubernetes-deployment] https://opentelemetry.io/docs/demo/kubernetes-deployment/
- [feature-flags] https://opentelemetry.io/docs/demo/feature-flags/ and its source https://raw.githubusercontent.com/open-telemetry/opentelemetry.io/main/content/en/docs/demo/feature-flags/_index.md
- [recommendation-cache] https://opentelemetry.io/docs/demo/feature-flags/recommendation-cache/
- [architecture] https://opentelemetry.io/docs/demo/architecture/
- [services] https://opentelemetry.io/docs/demo/services/
- [telemetry-features] https://opentelemetry.io/docs/demo/telemetry-features/
- [log-coverage] https://opentelemetry.io/docs/demo/telemetry-features/log-coverage/
- [metric-coverage] https://opentelemetry.io/docs/demo/telemetry-features/metric-coverage/
- [compose] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/compose.yaml
- [compose-full] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/compose.full.yaml
- [compose-obs] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/compose.observability.yaml
- [compose-extras] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/compose.extras.yaml
- [makefile] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/Makefile
- [dotenv] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/.env
- [flags-json] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/flagd/demo.flagd.json
- [otelcol-base] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/otel-collector/otelcol-config.yml
- [otelcol-full] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/otel-collector/otelcol-config-full.yml
- [otelcol-obs] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/otel-collector/otelcol-config-observability.yml
- [otelcol-extras] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/otel-collector/otelcol-config-extras.yml
- [locustfile] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/load-generator/locustfile.py
- [flagd-ui-readme] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/flagd-ui/README.md
- [recommendation-source] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/recommendation/recommendation_server.py
- [ad-source] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/ad/src/main/java/oteldemo/AdService.java
- [cart-source] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/src/cart/src/Program.cs
- [changelog] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/CHANGELOG.md
- [release] https://github.com/open-telemetry/opentelemetry-demo/releases/tag/3.0.0 (via the GitHub releases API)
- [main-commit] https://api.github.com/repos/open-telemetry/opentelemetry-demo/commits/main
- [loadgen-commits] https://api.github.com/repos/open-telemetry/opentelemetry-demo/commits?path=src/load-generator
- [flagd-json-commits] https://api.github.com/repos/open-telemetry/opentelemetry-demo/commits?path=src/flagd/demo.flagd.json
- [lock-commit] https://github.com/open-telemetry/opentelemetry-demo/commit/6065aea229 (PR #3931)
- [release-workflow] https://raw.githubusercontent.com/open-telemetry/opentelemetry-demo/main/.github/workflows/component-build-images.yml
- [issue-3034] https://github.com/open-telemetry/opentelemetry-demo/issues/3034
- [issue-3811] https://github.com/open-telemetry/opentelemetry-demo/issues/3811
- [issue-2678] https://github.com/open-telemetry/opentelemetry-demo/issues/2678
- [issue-1625] https://github.com/open-telemetry/opentelemetry-demo/issues/1625
- [pr-1711] https://github.com/open-telemetry/opentelemetry-demo/pull/1711
- [issues-memory] https://api.github.com/search/issues?q=repo:open-telemetry/opentelemetry-demo+memory+in:title
- [helm-chart] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-demo/Chart.yaml
- [helm-values] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-demo/values.yaml
- [helm-readme] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-demo/README.md
- [helm-flags] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-demo/flagd/demo.flagd.json
- [collector-chart-readme] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-collector/README.md
- [collector-config-tpl] https://raw.githubusercontent.com/open-telemetry/opentelemetry-helm-charts/main/charts/opentelemetry-collector/templates/_config.tpl
- [k8sattributes] https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/processor/k8sattributesprocessor/README.md
- [resourcedetection] https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/processor/resourcedetectionprocessor/README.md
- [docker-detector] https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/processor/resourcedetectionprocessor/internal/docker/documentation.md
- [dockerstats] https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/receiver/dockerstatsreceiver/documentation.md
- [kafkametrics] https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/receiver/kafkametricsreceiver/documentation.md
- [flagd-monitoring] https://flagd.dev/reference/monitoring/
- [flagd-providers] https://flagd.dev/reference/specifications/providers/
- [flagd-protos] https://raw.githubusercontent.com/open-feature/flagd-schemas/main/protobuf/flagd/evaluation/v1/evaluation.proto
- [flagd-filesync] https://raw.githubusercontent.com/open-feature/flagd/main/core/pkg/sync/file/filepath_sync.go
- [flagd-notifications] https://raw.githubusercontent.com/open-feature/flagd/main/core/pkg/notifications/notifications.go
- [openfeature-events] https://openfeature.dev/specification/sections/events
- [python-hook] https://raw.githubusercontent.com/open-feature/python-sdk-contrib/main/hooks/openfeature-hooks-opentelemetry/src/openfeature/contrib/hook/opentelemetry/__init__.py
- [dotnet-metrics-hook] https://raw.githubusercontent.com/open-feature/dotnet-sdk/main/src/OpenFeature/Hooks/MetricsHook.cs and TraceEnricherHook.cs
- [java-flagd-provider] https://raw.githubusercontent.com/open-feature/java-sdk-contrib/main/providers/flagd/README.md
- [semconv-ff-events] https://opentelemetry.io/docs/specs/semconv/feature-flags/feature-flags-events/
- [grafana-annotations] https://grafana.com/docs/grafana/latest/developers/http_api/annotations/
- [k8s-probes] https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/
- [lgtm-readme] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/README.md (latest release v0.33.0, 2026-09-11)
- [lgtm-otelcol] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/docker/otelcol-config.yaml
- [lgtm-k8s] https://raw.githubusercontent.com/grafana/docker-otel-lgtm/main/k8s/lgtm.yaml
- [alloy-otlp] https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.otlp/
- [docker-info] `docker info --format '{{.NCPU}} {{.MemTotal}} {{.ServerVersion}}'` on this laptop, 2026-09-15
- [docker-images] `docker image ls grafana/otel-lgtm` and `docker image ls ghcr.io/open-telemetry/demo`, 2026-09-15
