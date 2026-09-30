# Where a real Kubernetes could run (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and source citations retained. This is not a fresh capability or version verification. Source commit: `a34e932ecdbcf3b5417854febcff38f2b4238e26`.

Written 2026-09-15. Question: what does a real Kubernetes cost on this laptop, and on
DigitalOcean, for a demo that needs a cluster, a multi-service system (the OpenTelemetry Demo),
the LGTM stack and one Claude container, for a live showing?

**Method.** Primary sources only: Docker's, kind's, DigitalOcean's, k3s's, Grafana Alloy's, the
OpenTelemetry Collector's, the OpenTelemetry Demo's and Kubernetes' own documentation, all fetched
2026-09-15, plus three things read off this machine the same day: `sysctl`, Docker Desktop's
settings file and `docker info`/`docker stats`, and DigitalOcean's live price list through
`doctl compute size list`. Every claim cites the page it came from. Where a
page did not say something, the gap is listed at the end rather than filled by inference.

## Short answer

1. **The laptop as it stands cannot hold it, and the first cost is an upgrade, not memory.** The
   machine is a four-core, eight-thread i5 with 16 GiB ([host]), running Docker Desktop **4.0.0**
   (September 2021: Engine 20.10.8, kernel 5.10 linuxkit, HyperKit) allocated 4 CPUs and 8192 MiB
   ([dd-settings-file], [docker-info]). The current release is 4.91.0, dated 2026-09-14
   ([dd-release-notes]). Docker Desktop's kind provisioner appears by 4.43.0 and became the default at
   4.65.0; the Kubernetes view in the Dashboard is 4.51 and later
   ([dd-release-notes], [dd-k8s]). Upgrade first, whatever else.
2. **At 12 GiB the workload fits on paper with nothing to spare.** The OpenTelemetry Demo wants
   "6 GB of free RAM for the application" on Kubernetes ([otel-demo-k8s]); the LGTM container is
   using 650 MiB idle today and the demo container is capped at 2 GiB ([docker-stats],
   [compose]); the control plane's own cost is not stated by Docker or kind and is the unknown
   on top. That is 8.7 GiB before Kubernetes itself, inside a VM that leaves macOS, a browser and
   screen sharing 4 GiB. A rehearsal, yes, with the Demo's bundled Jaeger, Prometheus, Grafana and
   OpenSearch turned off ([otel-demo-chart]). A live demo on four physical cores is a gamble.
3. **DigitalOcean is about three and a half dollars a day, but the defaults are a trap.** Worker
   nodes are billed per second at Droplet prices; the standard control plane is free
   ([doks-pricing]). Two `s-4vcpu-8gb` nodes are $48/month each, $0.0714/hour each, so
   $3.43 for a 24-hour day, with 12 GiB allocatable for pods ([doctl-sizes], [doks-limits]).
   But on DOKS 1.36 and later, which is every version on offer, the high-availability control plane
   is **on by default when the flag is omitted**, costs $40/month prorated hourly, and "once
   enabled, you cannot disable" it ([doks-ha], [doctl-create], [doctl-versions]); and
   `doctl kubernetes cluster create` defaults to three `s-1vcpu-2gb-intel` nodes with 1 GiB
   allocatable each ([doctl-create], [doks-limits]). Always pass `--ha=false --size --count`.
4. **A single k3s Droplet is not meaningfully cheaper.** An `s-4vcpu-16gb-amd` Droplet that holds
   k3s, the Demo, LGTM and the demo container is $84/month, $0.125/hour, $3.00 a day
   ([doctl-sizes]); the two-node DOKS cluster is $3.43. The difference buys a managed API server,
   a kubeconfig `doctl` writes for you and a `delete --dangerous` that takes the load balancers
   and volumes with it, against copying `/etc/rancher/k3s/k3s.yaml` off a box by hand
   ([doctl-delete], [k3s-access]).
5. **Kubernetes Events reach Loki over OTLP, through the collector the Demo already runs.** The
   `grafana/otel-lgtm` image accepts OTLP on 4317 and 4318 and nothing else by default
   ([lgtm-config], [lgtm-readme]); Loki's 3100 is not in its `EXPOSE` list ([lgtm-dockerfile]).
   The Collector's `k8sobjects` receiver (beta) watches `events.k8s.io` and, with a second
   entry, pods, which is where an `OOMKilled` actually shows up ([k8sobjects], [k8s-oom]).
6. **The Run's `kubectl` holds nothing.** `kubectl proxy` "acts as a reverse proxy. It handles
   locating the API server and authenticating" ([k8s-access-api]); the Receiver runs it with a
   read-only ServiceAccount kubeconfig, behind the existing Forwarder, and the Run's `kubectl`
   presents the per-Run sentinel as its bearer token. ADR 0002, verbatim, one more upstream.
7. **On the laptop, the cluster sits beside Compose; on DigitalOcean, everything goes in.** The
   first keeps chapter one untouched at the price of three commands instead of one. The second
   is the only shape in which Grafana's webhook and the Demo's collector can reach the Receiver
   and LGTM without a tunnel, and it is `doctl ... create` then `kubectl apply -k`.

## Baseline: the laptop, measured

| Fact | Value |
| --- | --- |
| CPU | Intel i5-1038NG7, 4 physical cores, 8 logical ([host]) |
| RAM | 17,179,869,184 bytes, 16 GiB ([host]) |
| Docker Desktop | 4.0.0; `useVirtualizationFramework = False`, so HyperKit ([dd-settings-file]) |
| Engine inside the VM | 20.10.8, kernel 5.10.47-linuxkit, 4 CPUs, 7.774 GiB visible ([docker-info]) |
| Allocation | `cpus = 4`, `memoryMiB = 8192`, `swapMiB = 1024`, `diskSizeMiB = 61035` ([dd-settings-file]) |
| Kubernetes | `kubernetesEnabled = False`, `kubernetesInitialInstallPerformed = False` ([dd-settings-file]) |
| Chapter one, idle | lgtm 650 MiB and 10.9 % CPU; demo 16.5 MiB of its 2 GiB limit; rolldice 41 MiB; traffic 0.5 MiB ([docker-stats]) |
| Compose limits on `demo` | `mem_limit: 2g`, `cpus: 2`, `pids_limit: 256` ([compose]) |
| Tools | `kubectl`, `doctl`; no `kind`, `k3d`, `minikube`, `helm` |

The "8 cores" in the ticket are eight hyperthreads on four cores. Docker Desktop's 4 CPUs are
already half of the logical count.

## The laptop options

### Docker Desktop's built-in cluster

Docker Desktop "includes a standalone Kubernetes server and client" that "runs as a single or
multi-node cluster, within Docker containers"; enabling it "sets up the images required to run the
Kubernetes server as containers, and installs the `kubectl` command-line tool on your system at
`/usr/local/bin/kubectl`" ([dd-k8s]). Two provisioners: `kubeadm`, "the older provisioner",
single-node, version fixed, "not supported by Enhanced Container Isolation"; and `kind`, "the newer
provisioner", multi-node, version selectable, "faster to provision than `kubeadm`", containerd image
store only ([dd-k8s]). In `kind` mode it pulls `kindest/node`, `docker/desktop-cloud-provider-kind`
and `docker/desktop-containerd-registry-mirror`; in `kubeadm` mode ten `docker/desktop-kubernetes-*`
images ([dd-k8s]). `kindest/node:v1.37.0` is 388 MB compressed on Docker Hub; the kubeadm
`docker/desktop-kubernetes` image is 171 MB ([hub-kindest], [hub-dd-k8s]). On this machine, Docker
Hub pulls of that size take minutes.

Neither Docker page states what the cluster costs in RAM or CPU ([dd-k8s], [dd-settings]). The
resources page says the memory limit "Defaults to 50% of your host's memory" and, in general, "If
you feel Docker Desktop starting to get slow or you're running multi-container workloads, increase
the memory and disk image space allocation"; it names no maximum ([dd-settings]). Whether the
slider goes to 12 GiB on a 16 GiB Mac is therefore not documented; it is read off the Resources
pane after the upgrade.

The release notes place `kind` mode no later than 4.43.0 (the oldest mention on the page, a bug
fix) and record "Kubernetes now defaults to kind for new clusters" at 4.65.0; the Kubernetes view
in the Dashboard is "Docker Desktop version 4.51 and later" ([dd-release-notes], [dd-k8s]). None of
that exists in 4.0.0.

### kind, the CLI

`brew install kind`, then `kind create cluster` and `kind delete cluster`; deleting a cluster that
does not exist "will not return an error" ([kind-quickstart]). Multi-node is a three-line config
(`control-plane`, `worker`, `worker`) ([kind-quickstart]). The cited resource guidance distinguishes node-image builds from running a cluster: on macOS
or Windows, building Kubernetes requires at least 6 GB assigned to Docker's VM, with 8 GB
recommended; requirements otherwise depend on workload ([kind-quickstart]). Pre-built images
avoid the build. The fetched site did not quantify a running control plane's footprint.

Known issues that apply here: on Docker for Mac "the container networks are not exposed to the
host", so traffic into the cluster goes through `extraPortMappings` ("a cross-platform option to
get traffic into your kind cluster") ([kind-known-issues], [kind-config]); a `kubectl` version-skew
issue "frequently occurs when running `kind` alongside Docker For Mac" ([kind-known-issues]); and
with many pods the VM's inotify defaults ("8192 and 128 respectively") are "not enough", the fix
being `fs.inotify.max_user_watches = 524288` and `fs.inotify.max_user_instances = 512`
([kind-known-issues]). The Demo is twenty application services and nine infrastructure components
([otel-demo-arch]), which is "many pods". kind "creates a separate docker network named kind"
([kind-known-issues]), and `kind get kubeconfig --internal` will "use internal address instead of
external" ([kind-source-kubeconfig]); those two facts are how a Compose container reaches the API
server, below.

### What 12 GiB leaves

The Demo's Kubernetes page: "6 GB of free RAM for the application", "Kubernetes 1.24+", "Helm 3.14+"
([otel-demo-k8s]); the chart's own README says "Helm 4.0+" ([otel-demo-chart]). The Compose page
gives "6 GB of RAM for the application (or ~3 GB using minimal mode)" and "14 GB" of disk
([otel-demo-docker]); there is no documented minimal mode for the chart, but its sub-charts switch
off individually (`jaeger.enabled`, `prometheus.enabled`, `grafana.enabled`, `opensearch.enabled`,
`opentelemetry-collector.enabled`, all default `true`) and their limits are 400Mi, 200Mi, 175Mi,
1100Mi and 200Mi ([otel-demo-chart]). Switching off the four backends, which LGTM replaces, removes
roughly 1.9 GiB of limits, and the page says the collector's config "allows merging custom
exporters into existing pipelines via a values file" for "an observability backend you already
have" ([otel-demo-k8s]).

The sum inside the VM: Demo 6 GiB (call it 4 to 4.5 with the backends off), LGTM 0.65 GiB idle and
more under twenty services' telemetry, the demo container up to 2 GiB, plus a control plane and
kubelet that no page sizes. Twelve gigabytes is the floor, not a comfortable figure, and the Mac
keeps four for itself, the browser showing Grafana, and whatever shares the screen. On CPU, thirty
containers and the LGTM stack on four physical cores that macOS also uses. That is the laptop
verdict: a rehearsal venue after the upgrade, if the slider allows 12 GiB; not the venue for the
live showing.

## DigitalOcean

### Prices, live from the API

`doctl compute size list` on 2026-09-15 ([doctl-sizes]):

| Slug | vCPU / RAM | $/month | $/hour | 24 hours |
| --- | --- | --- | --- | --- |
| `s-1vcpu-2gb` | 1 / 2 GiB | 12.00 | 0.01786 | $0.43 |
| `s-1vcpu-2gb-intel` (doctl's default) | 1 / 2 GiB | 14.00 | 0.02083 | $0.50 |
| `s-2vcpu-4gb` | 2 / 4 GiB | 24.00 | 0.03571 | $0.86 |
| `s-2vcpu-8gb-amd` | 2 / 8 GiB | 42.00 | 0.06250 | $1.50 |
| `s-4vcpu-8gb` | 4 / 8 GiB | 48.00 | 0.07143 | $1.71 |
| `s-4vcpu-16gb-amd` | 4 / 16 GiB | 84.00 | 0.12500 | $3.00 |

All of these appear in `doctl kubernetes options sizes` ([doctl-sizes]). Billing: worker nodes
"charged per second at the same price as Droplets", "a minimum charge of 60 seconds or $0.01 per
node", a "monthly usage cap of 672 hours (28 days)" for bundled plans; the standard control plane is
"fully managed by DigitalOcean and included at no cost"; the HA control plane is "$40.00 per month,
prorated hourly" ([doks-pricing]). The public pricing page agrees: "the DigitalOcean control plane
is free", "$40/month" for HA, "$12/month/node" for "1 vCPU, 2 GB RAM", and "We recommend using a
minimum of two nodes to prevent downtime during upgrades or maintenance" ([do-pricing-page]). A
powered-off Droplet is still billed: "To end billing, destroy the Droplet" ([do-droplet-pricing]).

### The smallest viable cluster

What a node can actually run is smaller than its RAM. The limits page: 2 GiB nodes give pods 1 GiB;
4 GiB gives 2.5 GiB; 8 GiB gives 6 GiB; 16 GiB gives 13 GiB; and "we recommend using nodes with
less than 2 GB of allocatable memory only for development purposes" ([doks-limits]). The Demo's
6 GiB is exactly one `s-4vcpu-8gb` node's allocatable, with nothing left for LGTM and the demo
container if they are in the cluster too. So:

- **Smallest that fits the story**: two `s-4vcpu-8gb`, 12 GiB allocatable, $96/month, $0.143/hour,
  **$3.43 a day**, control plane free with `--ha=false`.
- **Smallest that starts at all**: one `s-4vcpu-8gb`, 6 GiB allocatable, $1.71 a day; only with the
  Demo's four bundled backends off and LGTM and the Receiver left on the laptop, which does not
  work for the reasons in the last section.
- **What the defaults give you**: three `s-1vcpu-2gb-intel` ($42/month, 3 GiB allocatable in total)
  plus an HA control plane on any current version ($40/month), about $82/month, and HA cannot be
  turned off afterwards ([doctl-create], [doks-ha], [doks-limits]).

### The doctl steps

Create ([doctl-create]; `--ha` and `--enable-coredns-autoscaler` both read "When omitted, API
applies version-specific default (true for 1.36.0+; false for older)", and the versions on offer
today are 1.36.3, 1.35.7 and 1.34.10 ([doctl-versions])):

```bash
doctl kubernetes cluster create otel-demo \
  --region nyc1 --version latest \
  --ha=false --size s-4vcpu-8gb --count 2 \
  --wait            # default true; also writes ~/.kube/config and sets the context
```

`--update-kubeconfig` and `--set-current-context` default to `true` ([doctl-create]); the saved
kubeconfig carries "a revocable OAuth token" visible under Applications & API
([doks-connect]). That token is the cluster admin and must never be what a Run can see.

Destroy ([doctl-delete]):

```bash
doctl kubernetes cluster delete otel-demo --force --dangerous
```

`--force` "Deletes the cluster without a confirmation prompt"; `--dangerous` "Deletes the cluster's
associated resources like load balancers, volumes and volume snapshots"; `--update-kubeconfig`
(default `true`) removes the entry from the kubeconfig ([doctl-delete]). Without `--dangerous`, a
LoadBalancer Service the Demo's chart may have created keeps billing after the cluster is gone.

### A single Droplet running k3s

k3s wants 2 cores and 2 GB for a server node, 1 core and 512 MB for an agent, "port 6443 to be
accessible by all nodes", and "an SSD when possible" ([k3s-req]). Install is
`curl -sfL https://get.k3s.io | sh -`, which writes "A kubeconfig file ... to
`/etc/rancher/k3s/k3s.yaml`" and installs `kubectl`, `crictl`, `ctr`, `k3s-killall.sh` and
`k3s-uninstall.sh` ([k3s-quickstart]). For remote access, copy the generated kubeconfig to the other machine and change its server
address to the K3s host. It carries `system:admin` authority; K3s rotates its embedded
certificates at startup, so copied configurations need updating ([k3s-access]).

The Droplet: `doctl compute droplet create otel-demo --size s-4vcpu-16gb-amd --image ubuntu-24-04-x64
--region nyc1 --ssh-keys <id> --user-data-file k3s-cloud-init.yaml --wait` ([doctl-droplet-create])
and `doctl compute droplet delete otel-demo --force` ([doctl-droplet-delete]). k3s server 2 GiB +
Demo 6 GiB + LGTM + demo container 2 GiB puts it on the 16 GiB plan: $3.00 a day against DOKS's
$3.43. Forty-three cents buys the managed API endpoint, the kubeconfig `doctl` writes, the
`--dangerous` cleanup, and no `system:admin` file to copy around. Cheaper is not the axis; the
Droplet is the choice only if the story wants to show the node itself.

## The table

| Option | RAM/CPU overhead or node size | Price | Setup steps | Teardown |
| --- | --- | --- | --- | --- |
| Docker Desktop, `kubeadm` mode | Single node inside the existing VM; overhead not stated ([dd-k8s]). VM at 8 GiB today; 12 GiB is the floor for this workload | $0 | Upgrade Docker Desktop 4.0.0 to 4.91.0; raise Resources; Kubernetes view, Create cluster, Kubeadm (pulls ten `docker/desktop-kubernetes-*` images) ([dd-k8s]) | Reset Kubernetes cluster, "Delete all stacks and Kubernetes resources" ([dd-settings]) |
| Docker Desktop, `kind` mode | Multi-node kind inside the VM; overhead not stated; the default since 4.65.0 ([dd-release-notes]) | $0 | Upgrade; raise Resources; Create cluster, kind, pick version and node count (pulls `kindest/node`, 388 MB compressed) ([dd-k8s], [hub-kindest]) | Same |
| kind CLI | One or more `kindest/node` containers on the `kind` docker network; running overhead not stated; 6 GiB min / 8 GiB recommended VM is for *building* node images ([kind-quickstart]) | $0 | Upgrade (kind on Engine 20.10.8 unverified); `brew install kind`; `kind create cluster --config` with `extraPortMappings`; raise inotify sysctls in the VM ([kind-quickstart], [kind-config], [kind-known-issues]) | `kind delete cluster` ([kind-quickstart]) |
| DOKS, 2 x `s-4vcpu-8gb` | 12 GiB allocatable, 8 vCPU ([doks-limits]) | $96/mo, $0.143/hr, $3.43/day; control plane free with `--ha=false` ([doctl-sizes], [doks-pricing]) | `doctl kubernetes cluster create --ha=false --size s-4vcpu-8gb --count 2 --wait`; kubeconfig written ([doctl-create]) | `doctl kubernetes cluster delete --force --dangerous` ([doctl-delete]) |
| DOKS, 1 x `s-4vcpu-8gb` | 6 GiB allocatable, the Demo's stated need exactly ([doks-limits], [otel-demo-k8s]) | $48/mo, $1.71/day | Same with `--count 1` | Same |
| DOKS, doctl defaults | 3 x `s-1vcpu-2gb-intel`, 3 GiB allocatable, HA control plane on ([doctl-create], [doks-ha]) | ~$82/mo; HA is irreversible | Do not | Same |
| k3s on 1 x `s-4vcpu-16gb-amd` | 16 GiB, 4 vCPU; k3s server needs 2 cores / 2 GB ([k3s-req]) | $84/mo, $0.125/hr, $3.00/day ([doctl-sizes]) | `doctl compute droplet create ... --user-data-file`; `curl -sfL https://get.k3s.io \| sh -`; copy `/etc/rancher/k3s/k3s.yaml`, rewrite `server` ([doctl-droplet-create], [k3s-quickstart], [k3s-access]) | `doctl compute droplet delete --force` ([doctl-droplet-delete]) |

## Kubernetes Events into Loki

What the LGTM image will take. Its collector config has two receivers, `otlp` (gRPC 4317, HTTP
4318) and a Prometheus self-scrape; its logs pipeline is `otlp` in, `otlp_http/logs` out to
`127.0.0.1:3100/otlp` ([lgtm-config]). The README: "There's no need to configure anything: the
Docker image works with OpenTelemetry's defaults" ([lgtm-readme]). The Dockerfile exposes 3000,
3200, 4040, 4317, 4318 and 9090; not 3100 ([lgtm-dockerfile]); the `k8s/lgtm.yaml` Service lists
the same six ([lgtm-k8s]). So the image ingests OTLP directly; anything that speaks the Loki push
API would first need Loki's port published and its bind address checked, which no page documents.

An Event is "a report of an event somewhere in the cluster. Events have a limited retention time
... Events should be treated as informative, best-effort, supplemental data" ([k8s-event-api]).
The fault this chapter wants is not guaranteed to be one: when a container exceeds its limit "the
Container is terminated. If a terminated Container can be restarted, the kubelet restarts it", and
what records it is the pod's status, `STATUS OOMKilled`, `RESTARTS 1`, and
`lastState.terminated.reason: OOMKilled`, `exitCode: 137` ([k8s-oom]). Whatever ships Events should
ship pod status changes too.

The three routes:

1. **Grafana Alloy, `loki.source.kubernetes_events`.** "Tails events from the Kubernetes API and
   converts them into log lines to forward to other `loki` components"; `namespaces` defaults to
   all, `log_format` to `logfmt`, labels `namespace`, `job`, `instance`; "When watching all
   namespaces, Alloy must have permissions to watch events at the cluster scope (such as using a
   ClusterRoleBinding)" ([alloy-events]). Its `forward_to` takes any Loki `LogsReceiver`
   ([alloy-events]); to reach LGTM without a Loki port that is `otelcol.receiver.loki`, which
   "receives Loki log entries, converts them to the OpenTelemetry logs format, and forwards them to
   other `otelcol.*` components", then `otelcol.exporter.otlphttp` ([alloy-receiver-loki]). Events
   only; no pods.
2. **OpenTelemetry Collector contrib, `k8sobjects`.** Stability "beta: logs". Two modes: pull,
   "read all objects of this type use the list API at an interval", and watch, "do setup a long
   connection using the watch API to just get updates". The events example is `name: events`,
   `mode: watch`, `group: events.k8s.io`; `exclude_watch_type` drops `ADDED`, `MODIFIED`,
   `DELETED`, `BOOKMARK` or `ERROR`; RBAC is `get, list, watch`; `auth_type` is `none`,
   `serviceAccount` or `kubeConfig` ([k8sobjects]). A second object entry, `name: pods`,
   `mode: watch`, carries the `OOMKilled` status. Exports over OTLP like everything else.
3. **OpenTelemetry Collector contrib, `k8s_events`.** "collects events from the Kubernetes API
   server. It collects all the new or updated events that come in"; stability "alpha: logs";
   `auth_type` default `serviceAccount`, `namespaces` default `all`; RBAC `get, list, watch` on
   `events` ([k8sevents]). The README fetched carries **no deprecation notice**; it is simply the
   alpha, events-only sibling of the beta receiver.
4. **kubernetes-event-exporter.** "an active fork of Opsgenie Kubernetes Event Exporter since that
   is not maintained since November 2021"; sinks include Loki, webhooks/HTTP, Slack, Kafka, and
   others; deployment by Kustomize or "Please use Bitnami Chart" ([kee]). Its Loki sink is the push
   API, so it needs the port the LGTM image does not expose; no OTLP sink.

**Recommendation.** The `k8sobjects` receiver, added to the OpenTelemetry Collector the Demo's chart
already installs (`opentelemetry-collector.enabled: true` by default, its config open to "merging
custom exporters into existing pipelines via a values file" ([otel-demo-chart], [otel-demo-k8s])),
watching `events.k8s.io` and `pods`, exporting logs to `lgtm:4318` alongside the Demo's own
telemetry. One agent, one protocol, one exporter, one ClusterRole with `get, list, watch` on
`events` and `pods`, and no Loki port. Alloy is the choice only if the story wants Grafana's own
agent on screen; then the `otelcol.receiver.loki` bridge keeps LGTM unchanged. kubernetes-event-
exporter adds a fourth process to expose a port for; skip it.

## Read-only kubectl, and who holds the credential

**The role.** RBAC's own shape, verbs `get`, `watch`, `list` on a resource list, bound to a
ServiceAccount named `system:serviceaccount:<namespace>:<name>` ([k8s-rbac]). The built-in `view`
ClusterRole is read-only but "Cannot view: Secrets" and RoleBindings by design, and it does see
ConfigMaps ([k8s-rbac]); a Run has no business reading configuration, so a narrower custom role:

```bash
kubectl create namespace incident
kubectl create serviceaccount run -n incident
kubectl create clusterrole incident-reader --verb=get,list,watch \
  --resource=pods,pods/log,events,events.events.k8s.io,deployments.apps,replicasets.apps,nodes
kubectl create clusterrolebinding incident-reader --clusterrole=incident-reader \
  --serviceaccount=incident:run
kubectl auth can-i --list --as=system:serviceaccount:incident:run
kubectl auth can-i delete pods --as=system:serviceaccount:incident:run   # no
```

The `create clusterrole`/`create clusterrolebinding` forms are from the RBAC page; `auth can-i`
"pairs nicely with impersonation" and its examples include `--as=system:serviceaccount:dev:foo`
and `--list` ([k8s-rbac], [k8s-can-i]).

**The token.** `kubectl create token run -n incident --duration 10m`: "Requested lifetime of the
issued token ... The server may return a token with a longer or shorter lifetime"; tokens can be
bound to a Secret "to allow revoking a token by deleting the Secret" ([k8s-create-token],
[k8s-sa-admin]). Long-lived Secret-based tokens are the discouraged path ([k8s-sa-admin]).

**Who holds it.** The chapter-one rule is that the Run never holds the real credential and presents
a per-Run sentinel to a loopback Forwarder that swaps it for the real one ([adr-0002],
[forwarder]). Kubernetes ships the swap half already: "The following command runs kubectl in a
mode where it acts as a reverse proxy. It handles locating the API server and authenticating",
`kubectl proxy --port=8080 &` then `curl http://localhost:8080/api/`; "This method is
recommended, since it uses the stored API server location and verifies the identity of the API
server using a self-signed certificate" ([k8s-access-api]). Its defaults are already defensive:
`--address 127.0.0.1`, `--accept-hosts` localhost only, `--reject-paths` covering
`pods/.*/exec` and `pods/.*/attach`, and `--reject-methods` takes a regular expression such as
`'POST,PUT,PATCH'` ([k8s-kubectl-proxy]). So:

- The Receiver starts `kubectl proxy --port 0 --reject-methods='POST,PUT,PATCH,DELETE'` with a
  kubeconfig it builds from the cluster's server address, its CA, and a `create token` bound to a
  Secret it can delete; that kubeconfig lives where the Jira token lives, in the Receiver, not in
  a Run's environment ([forwarder]). Two gates on writes, RBAC and the proxy, in case one is
  misconfigured.
- The Forwarder gets a second upstream, `127.0.0.1:<proxy port>`, and does for
  `Authorization: Bearer <sentinel>` what it does for basic auth today: checks the sentinel, drops
  the header, forwards ([forwarder]).
- The Run's environment carries `KUBECONFIG` pointing at a file with one cluster,
  `server: http://127.0.0.1:<forwarder>`, and `--token` or a user entry holding the sentinel. The
  kubeconfig merging rules let `--server` and `--token` override the file and say "The user and
  cluster can be empty at this point" ([k8s-kubeconfig]). Nothing real is in the Run.
- The allow list is `Bash(kubectl get *)`, `Bash(kubectl describe *)`, `Bash(kubectl logs *)`,
  `Bash(kubectl top *)`; but as chapter one already says of `Bash(jira-as *)`, the allow list is a
  gate, not the boundary; RBAC plus `--reject-methods` are ([harness-sandbox]).

The fallback is the per-Run bound token itself in the Run's environment: real, read-only, ten
minutes, revocable by deleting its Secret. Simpler, and a step back from "never holds".

Two credentials must never reach that proxy: the DOKS admin kubeconfig with its "revocable OAuth
token" ([doks-connect]) and k3s's `system:admin` file ([k3s-access]). Both stay with the presenter.

## Inside the cluster, or beside it on Compose

**Beside, on the laptop.** LGTM, the Receiver and rolldice stay exactly as chapter one has them; a
kind cluster runs on the same Docker Desktop. Two wires cross the boundary. The Demo's collector
must reach LGTM: Docker Desktop resolves `host.docker.internal` "to the internal IP address of your
host" and Compose already publishes 4318 ([dd-net-howto], [compose]); whether a pod inside a kind
node resolves that name is not documented, so the safer wire is to attach the `demo` service to the
`kind` docker network and export to the LGTM container by name ([kind-known-issues]). The Run's
proxy must reach the API server: `kind get kubeconfig --internal` gives the address on that network
([kind-source-kubeconfig]); the external one is `127.0.0.1` and a random port on the Mac
([kind-config]), which a container cannot use as-is. "One command" becomes three: `docker compose
up -d`, `kind create cluster --config kind.yaml`, `helm install`; a Compose service cannot create
the cluster without the Docker socket the demo refuses to mount ([compose]). A `make up` is the
honest answer.

**Inside, on DigitalOcean.** Nothing on the laptop but `doctl`, `kubectl` and a browser. LGTM from
the image's own `k8s/lgtm.yaml`, "intended for demo / testing purposes only, not for production
usage", with `kubectl port-forward service/lgtm 3000:3000 ...` for the presenter ([lgtm-k8s],
[lgtm-readme]). The Receiver as a Deployment whose Service Grafana's contact point names; `.env`
becomes a Secret; the Compose hardening translates to a `securityContext` (`capabilities.drop:
[ALL]`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `emptyDir` with `medium:
Memory` for the three tmpfs paths); `pids_limit` has no per-pod equivalent. Then it is two
commands: `doctl kubernetes cluster create ...` and `kubectl apply -k`. The hybrid, cluster in the
cloud and LGTM or the Receiver on the laptop, needs a tunnel in one direction or the other for the
webhook or the OTLP stream, and is not worth it.

## What this means for the map

- **Ticket 08, can the laptop hold it:** not at 8 GiB; at 12 GiB only as a rehearsal, with the
  Demo's four bundled backends off, after upgrading Docker Desktop from 4.0.0 to 4.91.0, and only
  if the Resources slider allows 12 GiB, which is a fact to read off the pane, not the docs.
- **Ticket 09, which system and where it runs:** the live venue is DOKS, two `s-4vcpu-8gb`,
  `--ha=false`, about $3.43 a day, created the morning of and destroyed with `--dangerous` after.
  Rehearsal days on DigitalOcean cost the same; four rehearsals and the demo are under $20.
- **Ticket 10, faults and cascades:** an OOMKill is a pod status, not a reliable Event; the
  `k8sobjects` receiver watches both. The kubelet restarts the container, so the fault is a restart
  loop, and the alert that fires is whatever the restart count or the service's latency does.
- **Ticket 12, eyes:** a Run's `kubectl` through `kubectl proxy` behind the Forwarder, the sentinel
  as its bearer token, `--reject-methods` on writes, one ClusterRole. ADR 0002 unchanged.
- **Ticket 07, seed the new repo:** `k8s/lgtm.yaml` from the image, the Demo chart with a values
  file that turns off Jaeger, Prometheus, Grafana and OpenSearch and adds the receiver, a
  Kustomization for the Receiver, a `make up`/`make down` that wraps `doctl` and `kubectl`.
- **A rule for the runbook:** never run `doctl kubernetes cluster create` without `--ha=false`,
  `--size` and `--count`. The defaults are three tiny nodes and an irreversible $40/month.

## Could not verify

- Docker Desktop's maximum memory allocation on a 16 GiB Mac; the docs state the default (50 %),
  not a ceiling ([dd-settings]).
- The idle RAM and CPU of a kind control-plane node, or of Docker Desktop's built-in cluster in
  either mode; neither doc set gives a number, and nothing was installed or enabled to measure it.
- Whether kind v0.33 runs against Docker Engine 20.10.8 in Docker Desktop 4.0.0; moot after the
  upgrade.
- Which Docker Desktop release introduced kind mode; the release-notes page's oldest mention is a
  4.43.0 bug fix ([dd-release-notes]).
- Whether Loki inside `grafana/otel-lgtm` binds 3100 on all interfaces; only that it is not
  exposed ([lgtm-dockerfile], [lgtm-k8s]).
- Whether pods inside a kind node on Docker Desktop resolve `host.docker.internal`, and whether the
  kind API server's certificate would accept that name; the `kind` network route avoids both.
- `kubectl` against an `http://` proxy with an empty user: implied by the merging rules and the
  `curl http://localhost:8080/api/` example, not stated for `kubectl` in words ([k8s-kubeconfig],
  [k8s-access-api]). `kubectl --server` with a path prefix under the Forwarder: untested.
- The hour basis DigitalOcean prorates the $40 HA charge by (720 or 672); a day is $1.33 or $1.43.
- The Demo's memory on Kubernetes with its bundled backends disabled; the "~3 GB" figure is
  Compose's minimal mode ([otel-demo-docker]). Whether all of it schedules on one 6 GiB-allocatable
  node: untested.
- Helm 3.14+ ([otel-demo-k8s]) versus Helm 4.0+ ([otel-demo-chart]); two pages disagree.
- kubernetes-event-exporter's latest release and date; not on the page fetched ([kee]).
- How to persist the inotify sysctls inside Docker Desktop's VM; the kind page gives the values,
  not the Docker Desktop mechanism ([kind-known-issues]).

## Sources

- [host] `sysctl -n hw.memsize hw.ncpu hw.physicalcpu machdep.cpu.brand_string`, 2026-09-15
- [dd-settings-file] `~/Library/Group Containers/group.com.docker/settings.json` and
  `/Applications/Docker.app/Contents/Info.plist`, 2026-09-15
- [docker-info] `docker info`, 2026-09-15
- [docker-stats] `docker stats --no-stream`, chapter one running, 2026-09-15
- [doctl-sizes] `doctl compute size list` and `doctl kubernetes options sizes`, 2026-09-15
- [doctl-versions] `doctl kubernetes options versions`, 2026-09-15
- [compose] `docker-compose.yml` in this repository
- [forwarder] `grafana_jsm_sandbox/forwarder.py` and `run_spawner.py` in this repository
- [adr-0002] `docs/adr/0002-jira-token-behind-localhost-forwarder.md` in this repository
- [harness-sandbox] `docs/research/harness-sandbox-containers-2026-09.md` in this repository
- [dd-settings] https://docs.docker.com/desktop/settings-and-maintenance/settings/
- [dd-k8s] https://docs.docker.com/desktop/use-desktop/kubernetes/
- [dd-release-notes] https://docs.docker.com/desktop/release-notes/
- [dd-net-howto] https://docs.docker.com/desktop/features/networking/networking-how-tos/
- [dd-mac-install] https://docs.docker.com/desktop/setup/install/mac-install/
- [hub-kindest] https://hub.docker.com/v2/repositories/kindest/node/tags
- [hub-dd-k8s] https://hub.docker.com/v2/repositories/docker/desktop-kubernetes/tags
- [kind-quickstart] https://kind.sigs.k8s.io/docs/user/quick-start/
- [kind-known-issues] https://kind.sigs.k8s.io/docs/user/known-issues/
- [kind-config] https://kind.sigs.k8s.io/docs/user/configuration/
- [kind-source-kubeconfig] https://github.com/kubernetes-sigs/kind/blob/main/pkg/cmd/kind/get/kubeconfig/kubeconfig.go
- [doks-pricing] https://docs.digitalocean.com/products/kubernetes/details/pricing/
- [do-pricing-page] https://www.digitalocean.com/pricing/kubernetes
- [do-droplet-pricing] https://docs.digitalocean.com/products/droplets/details/pricing/
- [doks-limits] https://docs.digitalocean.com/products/kubernetes/details/limits/
- [doks-ha] https://docs.digitalocean.com/products/kubernetes/how-to/enable-high-availability/
- [doks-create-how-to] https://docs.digitalocean.com/products/kubernetes/how-to/create-clusters/
- [doks-connect] https://docs.digitalocean.com/products/kubernetes/how-to/connect-to-cluster/
- [doctl-create] https://docs.digitalocean.com/reference/doctl/reference/kubernetes/cluster/create/
- [doctl-delete] https://docs.digitalocean.com/reference/doctl/reference/kubernetes/cluster/delete/
- [doctl-droplet-create] https://docs.digitalocean.com/reference/doctl/reference/compute/droplet/create/
- [doctl-droplet-delete] https://docs.digitalocean.com/reference/doctl/reference/compute/droplet/delete/
- [k3s-req] https://docs.k3s.io/installation/requirements
- [k3s-quickstart] https://docs.k3s.io/quick-start
- [k3s-access] https://docs.k3s.io/cluster-access
- [otel-demo-k8s] https://opentelemetry.io/docs/demo/kubernetes-deployment/
- [otel-demo-docker] https://opentelemetry.io/docs/demo/docker-deployment/
- [otel-demo-arch] https://opentelemetry.io/docs/demo/architecture/
- [otel-demo-chart] https://github.com/open-telemetry/opentelemetry-helm-charts/blob/main/charts/opentelemetry-demo/README.md
- [lgtm-readme] https://github.com/grafana/docker-otel-lgtm
- [lgtm-dockerfile] https://github.com/grafana/docker-otel-lgtm/blob/main/docker/Dockerfile
- [lgtm-config] https://github.com/grafana/docker-otel-lgtm/blob/main/docker/otelcol-config.yaml
- [lgtm-k8s] https://github.com/grafana/docker-otel-lgtm/blob/main/k8s/lgtm.yaml
- [alloy-events] https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.kubernetes_events/
- [alloy-receiver-loki] https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.loki/
- [k8sobjects] https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/k8sobjectsreceiver/README.md
- [k8sevents] https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/k8seventsreceiver/README.md
- [kee] https://github.com/resmoio/kubernetes-event-exporter
- [k8s-rbac] https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- [k8s-sa-admin] https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
- [k8s-create-token] https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/
- [k8s-can-i] https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/
- [k8s-access-api] https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/
- [k8s-kubectl-proxy] https://kubernetes.io/docs/reference/kubectl/generated/kubectl_proxy/
- [k8s-kubeconfig] https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
- [k8s-oom] https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/
- [k8s-event-api] https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/
