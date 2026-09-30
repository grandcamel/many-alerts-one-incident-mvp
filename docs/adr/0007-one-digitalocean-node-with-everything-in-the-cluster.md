# The demo runs on one DigitalOcean node, with everything inside the cluster

Status: accepted, 2026-09-16, resolving "Which system, and where it runs" on the many-alerts-one-incident map.

The capacity prototype asked whether the laptop could hold the simulation and answered yes, and not narrowly: the OpenTelemetry Demo's Compose core layer beside an idle kind cluster, the LGTM stack and one Claude container left 8.39 GiB of 11.68 GiB free with a fault firing. But memory was never the binding constraint. The containers used 215.8% of 800% of the VM's CPU while the *host* hit a load average of 8.84 on 8 threads, and on the day that host also has to run a browser and screen sharing. The laptop has headroom for the simulation and none for the act of presenting. Two further facts pointed the same way: the shape the story's Kubernetes-native Fault actually needs — the Demo deployed on Kubernetes through its Helm chart — was never measured on the laptop, and the first ceiling the prototype hit was VM disk, 7.1 G free against roughly 14 G of images, raised to 102 G by hand.

We decided the demo runs on DigitalOcean Kubernetes: **one `s-8vcpu-16gb` node** at 1.36.3-do.5, with the OpenTelemetry Demo installed from **Helm chart 0.41.2** (appVersion 3.0.0), and with the LGTM stack, the Receiver and each Run inside that same cluster. A single node costs $0.142860 an hour, about $3.43 a day — to the cent what the two `s-4vcpu-8gb` nodes the research priced would cost — but it gives one 16 GiB, 8-vCPU scheduling domain instead of 12 GiB allocatable split across two, and 320 GB of disk, so the disk ceiling that bit the laptop cannot recur. Nothing is exposed publicly: the cluster needs no ingress and no load balancer, and the presenter reaches Grafana through `kubectl port-forward`.

The alternatives were real. Compose on the laptop is everything already measured and needs no network, but it makes the Kubernetes-native Fault synthetic and leaves the host CPU contending with the presentation. The chart on kind, on the laptop, keeps the Fault real and the demo offline, but the chart declares 8,548 Mi against Compose's 3,167 Mi and would make the host-CPU problem worse rather than better. A split with the Demo in the cloud and LGTM on the laptop was rejected outright: it puts telemetry ingress on the laptop, so the cloud has to reach inward through a tunnel, which is strictly harder than the laptop reaching out.

## Consequences

- **The deployment is the chart's default component set, minus four.** `agent`, `chatbot` and `mcp` (500 Mi each) and the chart's four bundled backends go off. `kafka`, `accounting`, `fraud-detection` and `load-generator` ship enabled and stay enabled — on Helm, removing them is the work, not adding them. That leaves all **13 fault flags** usable, where the Compose core layer left 11.
- **The load generator answers "what drives the system".** It was dropped on the laptop for memory, which is why `traffic.sh` existed as a stopgap; that reason is gone. A flipped Fault now produces symptoms immediately, and `loadGeneratorTraffic` and `loadGeneratorVUs` keep the volume a knob.
- **The version trap the prototype found is Compose-only.** The 3.0.0 git tag sets `DEMO_VERSION=latest` while reporting `service.version=3.0.0`, so a clean Compose clone runs newer code than it claims. The chart has no such seam: its image tag defaults to its appVersion from `ghcr.io/open-telemetry/demo`. The spec sets the tag explicitly anyway, so the pin survives a chart bump.
- **Every network path points outward.** Grafana delivers a Notification to the Receiver in-cluster; a Run's Eyes queries and its own OTLP export stay inside the cluster; the only outbound calls are to the Atlassian site and the Anthropic API. Nothing has to reach in, so there is no tunnel on demo day.
- **The Atlassian token and the Anthropic key become Kubernetes Secrets** on a cloud cluster rather than staying on the laptop, created from environment at `make up` and never committed. ADR 0002's Forwarder becomes a sidecar. [ADR 0011](0011-one-forwarder-sidecar-with-scoped-tls-endpoints.md) clarifies the container layout: the Receiver and Run children share the main container, while the Forwarder occupies a separate container in the same pod.
- **The Receiver's image is published to `ghcr.io` publicly**, matching the public repo. ADR 0005 keeps credentials out of the image, so a public image leaks nothing and `make up` needs no pull secret.
- **"One command brings everything up" survives, qualified.** `make up` stays one idempotent command, but creating the cluster requires `CREATE_CLUSTER=1` and otherwise fails loudly against a missing cluster, because a stray invocation would otherwise provision $96 a month. The research's runbook rule — never `doctl kubernetes cluster create` without `--ha=false`, `--size` and `--count` — is enforced inside that path rather than remembered. `make down` is part of the spec, not the runbook: an undestroyed cluster is the only way this demo costs real money.
- **Nothing is shared by URL except what already is one.** The Incident lands in a real Atlassian OPS project and its link works for anyone with site access today; the repo is public; the Transcript is a recorded fixture. Grafana stays unexposed, which also keeps "anonymous Grafana access goes away" intact — exposing it anonymously for an audience would hand a Run a way around its own sentinel.
- **The simulation spec describes this venue only.** The laptop Compose stack stays a measured fact, pointed at in one paragraph. Specifying it a second time would roughly double the spec — two deployment shapes, two Fault menus, two answers for Kubernetes Events — to hedge a risk the replay script already covers.
- **Installing `helm` is a prerequisite of the next prototype,** not a ticket of its own.
- **The chosen shape is unmeasured end to end.** The prototype measured Compose on the laptop; nothing has stood the chart up on a DOKS node. "Can one DOKS node hold the chart" carries that risk and blocks the Fault menu.
- **flagd's flag config is a ConfigMap on the chart**, so the presenter's flip becomes a Kubernetes API write with a real resource-version change. That may make a Fault's cause citable without the watcher the research sketched. It is a lead for "The Change: making a Fault's cause citable", not a decision taken here.

## Amendments

**2026-09-16, from "Can one DOKS node hold the chart" (ticket 26).** The
decision stands and the capacity gate passed with room to spare: allocatable is
7880m and 13.33 GiB, and everything up with a fault firing and a Run's 2 GiB cap
genuinely exercised leaves 9.68 GiB available on a node at about 19% of eight
CPUs. Nothing OOMKilled, nothing evicted. The measurements correct five of the
consequences above.

- **"That leaves all 13 fault flags usable" should read 13 enabled, 12 usable.**
  `failedReadinessProbe` is flippable and inert: the chart templates no probe on
  the cart Deployment it names, so it produces no Event, no endpoint change and
  no restart. The Kubernetes-native Fault this venue was chosen to make real is
  not that flag, and which Fault takes its place belongs to ticket 10.
- **"two answers for Kubernetes Events" assumed this venue already had one.** It
  does not, as described here. The `kubernetesEvents` preset is not in the demo
  chart; it belongs to collector subchart 0.165.0 and defaults to off, and even
  enabled it is skipped by `daemonsetConfig`, which is the mode the chart ships.
  This ADR must pin `opentelemetry-collector.mode: deployment`, and that line is
  part of the one-node decision: a Deployment collector under-collects
  node-local metrics on a multi-node cluster. Enabling the preset without the
  mode change is worse than a no-op, because the ClusterRole still gains
  `events.k8s.io` and nothing reads it.
- **"the chart declares 8,548 Mi against Compose's 3,167 Mi" is a
  declared-against-declared comparison and was load-bearing in rejecting
  chart-on-kind.** Measured, our shape declares 4,317 Mi and the node's actual
  working set is 5.34 GiB under fault. The memory half of that rejection does
  not hold; the host-CPU half, which is what actually decided the venue, does.
- **"one 16 GiB, 8-vCPU scheduling domain instead of 12 GiB allocatable split
  across two" compares capacity to allocatable.** Like for like, the measured
  figure is 13.33 GiB allocatable and 7880m CPU. The comparison still favours
  one node; ticket 05's 12 GiB was never measured either.
- **"One command brings everything up" carries three more qualifications, not
  one.** `make up` cannot treat helm's exit code as proof of health —
  `helm upgrade --install --wait --timeout 20m` exited 0 after 90 seconds with
  the collector in `CrashLoopBackOff` — so it needs its own readiness gate. It
  must install metrics-server, which DOKS does not ship, **with
  `--kubelet-insecure-tls`**, without which the upstream manifest rolls out and
  still fails. And it must rewrite all three collector exporter arrays
  wholesale, re-listing the `span_metrics` connector in `traces`, because a
  partial override crashes every collector pod.

The closing bullet on flagd is **re-gated, not withdrawn**. The flag config is a
ConfigMap, but flagd does not read it: the chart copies it once into an
`emptyDir` from an init container and sets no `checksum/config`, so a ConfigMap
write changes nothing a service can see. The flip only takes effect with
`kubectl rollout restart deploy/flagd`. Ticket 25's lead survives in that
modified form — the write is a real API write and the rollout emits its own
Events — but the restart has to be part of the presenter's one action.

## Accepted venue lifetime extension

[ADR 0016](0016-venue-lifetime-is-bounded-with-protected-teardown.md) adds fresh venues per presentation/full rehearsal, age/readiness admission gates, a separate cloud budget and verified off-cluster recovery handoff before teardown. Its thresholds are policy limits requiring acceptance; historical prices, capacity and memory observations above are not current billing or safe-duration guarantees.
