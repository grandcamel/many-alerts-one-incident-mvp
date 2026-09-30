# Sandbox containers for a headless, tool-restricted Claude Code Run (September 2026)

Editorial cleanup, 2026-09-18: quotations shortened; historical findings and source citations retained. This is not a fresh capability or version verification. Source commit: `c789840ede31d73748738c8ffe69ee9375b7b6cc`.

Written 2026-09-15. Question: what are engineers using, as of now, to run a headless Claude Code
harness as an untrusted, tool-restricted worker inside a container, and should this repo's demo
image stop extending `grandcamel/claude-devcontainer`?

**Method.** A deep-research workflow (107 agents: five search angles, fifteen fetched sources,
three-vote adversarial verification per claim) produced ten surviving findings; it left the two
questions this repo hinges on unanswered and ranked no third-party sandbox, so the pages that
own those answers were then fetched directly. Every claim below cites the page it came from, all
fetched 2026-09-15. Anything the sources did not say is marked as such rather than inferred.

## Short answer

1. **Keep a container as the outer boundary; make it minimal and hardened.** Anthropic's own
   secure-deployment guide prescribes the shape: `--cap-drop ALL`, `no-new-privileges`, a
   seccomp profile, `--read-only` root with `tmpfs` scratch, `--pids-limit`, `--user 1000:1000`,
   and no sensitive host directories mounted ([secure-deployment]). None of that depends on the
   base image, but a 4.1 GB image carrying `sudo`, the `docker` CLI and `docker`-group membership
   is the opposite of what the guide describes.
2. **The Forwarder follows Anthropic's recommended credential boundary.** An external proxy
   attaches the API key, letting the agent make requests without possessing it
   ([secure-deployment]). Claude Code's built-in `mask`/`injectHosts`, Docker Sandboxes,
   E2B and Daytona all implement the same sentinel-plus-proxy design.
3. **Do not rely on the built-in Bash sandbox inside the container.** In an unprivileged
   container bubblewrap cannot mount `/proc`; the documented fix, `enableWeakerNestedSandbox`,
   "considerably weakens security and should only be used when additional isolation is otherwise
   enforced" ([sandboxing]). The container is that isolation; the inner sandbox would be a second
   layer of uncertain value.
4. **The one unmasked credential has a documented answer now.** `--bare` is "the recommended mode
   for scripted and SDK calls" and "never reads OAuth credentials or the system keychain"; it
   takes `ANTHROPIC_API_KEY`, which `ANTHROPIC_BASE_URL` can route through a proxy that injects
   the key ([headless], [secure-deployment]). That would let the Receiver hold the Anthropic key
   the way it already holds the Jira token.
5. **If kernel-level isolation is ever required, gVisor or a microVM is the step up**, not a
   different devcontainer. Anthropic rates containers "setup dependent", gVisor and Firecracker
   "excellent (with correct setup)" ([secure-deployment]).

## Baseline: the image this repo extends today

Read off the image itself with `docker image inspect` and a shell inside it, 2026-09-15.

| Fact | Value |
| --- | --- |
| Image | `grandcamel/claude-devcontainer:latest`, built 2026-01-02, revision `10eb5c1b`, MIT |
| Size | 4.1 GB, Debian 12, 555 packages |
| User | `devuser` (uid 1000), groups `node` and **`docker`** |
| On PATH | `claude` 2.0.76 (the demo Dockerfile upgrades to 2.1.272 at build), `node`, `python3`, **`docker`**, `gh`, **`sudo`**, `iptables`, `aws`, plus roughly thirty developer tools |
| Repo | `github.com/grandcamel/claude-devcontainer`, last commit 2026-02-01, `FROM node:20-bookworm` |

None of `sudo`, `docker` or the `docker` group is reachable in the demo, since no socket is mounted
and no capability is added, but each is surface a Run's `Bash(jira-as *)` allow list is the only
thing standing in front of. The image was built for interactive development, which is what its
README says.

## The options, from their own documentation

### 1. Anthropic's reference devcontainer

`anthropics/claude-code/.devcontainer`. `FROM node:20`, `npm install -g
@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}` with `latest` as the default, `USER node`, and
one sudoers line: `node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh`. It installs
`iptables`, `ipset`, `gh`, `zsh`, `fzf`, `vim` and the rest of a developer's kit ([devcontainer-Dockerfile]).
The firewall sets default DROP on all three chains and allows DNS, SSH, loopback, the host subnet
and an `allowed-domains` ipset; it needs `--cap-add=NET_ADMIN --cap-add=NET_RAW`, which "are not
required for Claude Code itself" ([devcontainer]). The page warns that a malicious project can exfiltrate material available inside the
container, including credentials in `~/.claude` ([devcontainer]).

*For this repo:* it is a developer environment with an egress firewall, the same category as the
home-grown image, only smaller. Its firewall script is the one reusable part: a default-deny
egress allowlist is the control that would stop the OAuth token leaving.

### 2. Claude Code's built-in sandboxed Bash tool

Seatbelt on macOS, bubblewrap on Linux and WSL2; on Linux it needs `bubblewrap` and `socat`, with
`ripgrep` bundled and a seccomp filter optional ([sandboxing]). Its boundary covers Bash and its children, leaving built-in file tools, MCP servers and hooks
outside it. That limited coverage does not suffice for unattended execution
([sandbox-environments]).

Credential masking exists and is first-party. With `"mode": "mask"` (v2.1.199+), a per-session sentinel replaces the credential inside the
sandbox. The proxy substitutes the real value only on requests to the entry's `injectHosts`. It requires
`network.tlsTerminate` so the proxy can see request contents, substitutes in headers and bodies,
and is "honored only from settings you or your administrator control: user settings, managed
settings, and the `--settings` CLI flag" ([sandboxing]). Masked files (v2.1.221+) work the same
way on Linux and are blocked outright on macOS.

Inside an unprivileged container, bubblewrap's fresh `/proc` mount can fail. The documented
`enableWeakerNestedSandbox` workaround exposes process information normally hidden by that
mount; the security guidance requires another isolation boundary because this weakens the
sandbox ([sandboxing]). `docker` commands are "incompatible with the
sandbox" ([sandboxing]).

Print mode: neither the sandboxing page nor the headless page says in words whether `sandbox`
settings are honored under `-p`. What the pages do say is that `mask` is honored from the
`--settings` CLI flag and that `-p` loads settings like an interactive session unless `--bare`
([sandboxing], [headless]). Treat "works in `-p`" as likely but **unverified**; it is a
ten-minute test, not a fact.

*For this repo:* the `mask` design is the Forwarder, built in, with TLS termination the Forwarder
avoids by speaking plain HTTP on loopback. Layering it inside the container means bubblewrap, socat,
`enableWeakerNestedSandbox`, a TLS-terminating proxy and user-scope settings in the image, to
protect a credential the Forwarder already keeps out of the Run. Not worth it for day one; ADR 0002
stands.

### 3. `@anthropic-ai/sandbox-runtime`

Version 0.0.76, published 2026-09-10 ([npm]); "a beta research preview, and its configuration
format may change" ([sandbox-environments]). It applies Seatbelt or bubblewrap to the whole process, covering tools, hooks and MCP servers
as well as Bash. Launch is `npx
@anthropic-ai/sandbox-runtime claude` (or `srt <command>`) with `~/.srt-settings.json` or
`--settings`; it needs the same `bubblewrap` and `socat` on Linux, denies network by default, and
on Linux requires network access through its Unix-domain-socket proxies ([sandbox-environments], [sandbox-runtime]). Its
README carries the same `enableWeakerNestedSandbox` option "for Docker environments without
privileged namespaces" ([sandbox-runtime]). Anthropic's table rates it "Good (secure defaults),
very low overhead, low complexity" and notes "Same-host kernel" and "No TLS inspection... domain
fronting" as its limits ([secure-deployment]). Whether it needs root on Linux is not stated on any
page fetched; the workflow's claim that it does was refuted 0-3, which is not evidence it does not.

*For this repo:* the whole-process wrapper is what Anthropic says to use *instead of* a container
when there is no Docker. Inside an unprivileged container it meets the same `/proc` wall as option
2. It is the right tool for the laptop-process form of the demo (`python3 -m grafana_jsm_sandbox`
with no container), not for the container.

### 4. A hardened custom container, per Anthropic's guide

The guidance targets teams already using containers or CI runners ([sandbox-environments]).
Its example combines dropped capabilities, privilege-escalation prevention and seccomp with a
read-only root, bounded temporary filesystems, CPU/memory/process limits, a non-root identity,
a read-only workspace and a mounted proxy socket. Networking is disabled in that example
([secure-deployment]); consult the source for the complete invocation rather than treating these
notes as a runnable deployment recipe.

The guide routes external access through a mounted Unix socket when container networking is
disabled. Its host proxy can restrict destinations, attach credentials and record requests;
sandbox-runtime uses the same general boundary ([secure-deployment]). For the Claude API,
`ANTHROPIC_BASE_URL` redirects sampling to a proxy that can inspect and modify the HTTP request.
For other HTTPS services, the guide describes either a custom proxy-aware tool or TLS termination
with an agent-trusted CA ([secure-deployment]). Every option runs unprivileged; nothing in it needs bubblewrap.

*For this repo:* this is the design the demo already approximates (non-root, no socket, secrets by
env file, Forwarder on loopback) and the checklist for what it lacks: `cap_drop`,
`no-new-privileges`, a read-only root, `pids_limit`, and the Anthropic credential behind the
Forwarder too. The one thing the demo cannot copy is `--network none`, because the Receiver must
accept Grafana's webhook and reach Jira and Anthropic; the equivalent is a container-level egress
allowlist of exactly those hosts.

### 5. gVisor (`runsc`)

A Docker runtime that "intercept[s] system calls in userspace before they reach the host kernel".
Register it in `daemon.json` and run with `docker run --runtime=runsc`; installation is `sudo
runsc install` ([secure-deployment], [gvisor-docker]). Overhead: "~0%" for CPU-bound work, "~2×"
for simple syscalls, "10-200×" for heavy file I/O ([secure-deployment]). Anthropic rates its
isolation "Excellent (with correct setup)". No page fetched states whether it works under Docker
Desktop on macOS, which is where this demo runs; treat as Linux-host tooling until checked.

### 6. Claude Managed Agents

Beta; "All Managed Agents endpoints require the `managed-agents-2026-04-01` beta header" and access
is "enabled by default for all API accounts". An Environment is "an Anthropic-managed cloud
sandbox, or a self-hosted sandbox on your own infrastructure" ([managed-agents-overview]). For
self-hosted sandboxes: "The confinement is a guardrail for the file tools only, not a sandbox; it
does not constrain bash", and the stronger-isolation pattern is one `docker run --rm` per session
with `--stop-timeout 30` ([managed-agents-self-hosted]). (Workflow findings, 3-0 and 2-1 votes;
the key-separation model was refuted as stated and should be read from the page.)

*For this repo:* the same one-container-per-event shape as the Receiver, with Anthropic running
the agent loop. It replaces the harness, not the sandbox, and it is beta.

### 7. Docker Sandboxes

"Docker Sandboxes run AI coding agents in isolated microVM sandboxes"; "Each sandbox gets its own
Docker daemon, filesystem, and network" ([docker-sandboxes]); "a free, standalone product from
Docker that does not require Docker Desktop" ([sandbox-environments]). Credentials: "`sbx secret
set` stores credential values... in your OS keychain"; "For proxy-managed credentials, the real
value never enters the sandbox — the agent sees only a sentinel like `proxy-managed`", replaced
by the proxy "on outbound requests to bound domains" recorded in `~/.config/sbx/credentials.yaml`
([docker-sandboxes-credentials]). The Claude Code page's default command is `claude
--dangerously-skip-permissions`; no non-interactive `-p` invocation is documented
([docker-sandboxes-claude]). Hypervisor, host platforms and a headless API are not stated on the
pages fetched.

*For this repo:* an interactive developer product with the right credential model and no
documented way to be spawned per webhook. Watch it; do not build on it yet.

### 8. E2B

E2B describes separate Firecracker microVMs, each with its own kernel and hypervisor isolation
from the host and other sandboxes; it reports SOC 2 Type II and supports BYOC
([e2b-security]). Commands run via `sandbox.commands.run(...)`,
custom templates install packages ([e2b-docs]). Secrets are not environment variables: a
`Secret.fill('name')` reference belongs to network configuration; the egress proxy resolves and
injects the current secret only for matching HTTPS requests to trusted hosts ([e2b-secrets]).

### 9. Daytona

From the workflow, verified 3-0 against `daytona.io/docs/en/secrets/`: "A secret never enters the
sandbox in plaintext"; an opaque `dtn_secret_<random>` placeholder is swapped by an outbound proxy
when the destination matches the secret's host allowlist, responses containing the real value are
rewritten back to the placeholder, substitution is header-only and never on plain HTTP
([daytona-secrets]). Daytona is also listed by Anthropic as a self-hosted Managed Agents backend.

### 10. Modal Sandboxes

"Sandboxes are built on top of gVisor" ([modal-networking]). `Sandbox.create()` with a custom
image, `sandbox.exec(...)`, default lifetime five minutes ([modal-sandbox]). Network controls:
`block_network=True`, `outbound_cidr_allowlist`, `outbound_domain_allowlist` (beta), and an
experimental sidecar proxy; by default a sandbox "can make outbound connections to any public IP
address" ([modal-networking]). Secrets are "exposed as environment variables within the container"
with no masking documented ([modal-sandbox]).

### 11. Fly Machines

"Fast-launching VMs; they can be started and stopped at subsecond speeds", created with `fly
machine run` or the Machines REST API ([fly-machines]). The Firecracker claim commonly made about
Fly was **not found on either page fetched** (`/docs/machines/`, `/docs/security/`), so it is not
asserted here. No secret masking or egress policy detail was on those pages either.

## Restricting tools headlessly, as documented

- `-p` starts in Manual mode on every plan, so the mode is passed explicitly. `dontAsk`: "Claude
  Code denies every call that would otherwise prompt, which is useful for locked-down CI runs";
  `--allowedTools` uses permission-rule syntax with prefix matching, `Bash(jira-as *)` style
  ([headless]). This is what `run_command.py` does today (ADR 0003).
- `--permission-prompts none` (v2.1.259+) additionally "tells Claude not to retry" denied requests;
  denials "appear as `permission_denied` system messages, and the final result message lists them
  in `permission_denials`" in stream-json ([headless]). The log formatter already renders both.
- The fetched headless documentation recommends `--bare` for scripted/SDK calls and describes
  a future change to make it the print-mode default. It skips hooks, skills, plugins, MCP servers,
  auto memory and CLAUDE.md; it avoids OAuth/keychain credentials and instead uses
  `ANTHROPIC_API_KEY` or an `apiKeyHelper` in settings ([headless]). Without it, print mode may
  execute project hooks and connect configured MCP servers even without prior folder trust
  ([headless]).
- `--dangerously-skip-permissions` is refused as root, and "the check is skipped automatically
  inside a recognized sandbox" ([sandboxing]). This repo does not use the flag; the note matters
  only if someone reaches for it.
- Anthropic's caution that applies to every allow list, from the Managed Agents page: tool
  confinement "does not constrain bash" ([managed-agents-self-hosted]). `Bash(jira-as *)` is a
  permission gate parsed from the command's AST ([secure-deployment]); it is not what keeps the
  Jira token out of the Run. The Forwarder is.

## Recommendation for `grafana-jsm-sandbox`

Replace the base image, keep the architecture.

1. **Base image.** Build the demo image from a slim official runtime, `node:20-bookworm-slim`
   plus `python3` and `pip`, or the reference devcontainer's `node:20` if its firewall script is
   wanted. Install exactly `@anthropic-ai/claude-code@<pinned>` and `jira-as==<pinned>`, create a
   non-root user, and nothing else. No `sudo`, no `docker`, no `gh`, no `iptables` unless the
   egress firewall is adopted, in which case `NET_ADMIN`/`NET_RAW` are added for the firewall
   script alone, as the reference does. Expected size: well under 1 GB against 4.1 GB.
2. **Compose hardening**, straight from the guide: `cap_drop: [ALL]`, `security_opt:
   [no-new-privileges:true]`, `read_only: true` with `tmpfs` for `/tmp` and the runs directory,
   `pids_limit`, memory and CPU limits, `user: 1000:1000`. Test each against the existing opt-in
   container checks; `read_only` will need the Receiver's runs directory and Claude Code's
   `~/.claude` moved onto tmpfs.
3. **Egress allowlist** at the container level: the Atlassian site, `api.anthropic.com`, and the
   OAuth hosts if OAuth stays. This is the control that addresses "the OAuth token is the one
   unmasked credential"; without it the honest line in the runbook stays honest.
4. **Then consider `--bare` with an API key behind the Forwarder.** `ANTHROPIC_BASE_URL` pointed
   at the Forwarder, which injects the key, makes the Run's environment hold no real credential at
   all. It changes billing from subscription to API and skips the repo's CLAUDE.md and skills
   unless passed explicitly (`--add-dir` loads skills), so it is a ticket, not a tweak.
5. **Do not** add bubblewrap, `enableWeakerNestedSandbox`, or the sandbox runtime to the container.
   Use the sandbox runtime for the laptop-process form of the demo if that form is kept.
6. **Revisit** gVisor or a Firecracker host (E2B with BYOC, or Managed Agents self-hosted) only if
   the audience's threat model requires kernel separation; the guide's own ranking says that is the
   next rung, and none of those changes the harness or the Forwarder.

## Open questions and staleness

- Whether `sandbox` and `mask` settings are active under `claude -p`: not stated in words on any
  page; likely from the `--settings` delivery rule; untested here.
- Whether `runsc` runs under Docker Desktop on macOS: not on the pages fetched.
- Fly Machines' isolation technology: not on the pages fetched.
- The sandbox runtime's root requirement on Linux: not stated; a refuted claim is not a negative.
- The reference devcontainer's exact allowed-domain list was refuted as the workflow stated it;
  read `init-firewall.sh` before copying it.
- The Anthropic sandboxing engineering post is dated 2025-10-20, older than the March 2026 line the
  question drew; the docs pages it links to carry version gates up to v2.1.260 and are current.
  Docker Sandboxes, E2B, Modal, Daytona and Fly pages are undated.
- Managed Agents facts are workflow findings (3-0 and 2-1); the two 2-1 votes are marked above.

## Sources

- [sandboxing] https://code.claude.com/docs/en/sandboxing
- [sandbox-environments] https://code.claude.com/docs/en/sandbox-environments
- [secure-deployment] https://code.claude.com/docs/en/agent-sdk/secure-deployment
- [headless] https://code.claude.com/docs/en/headless
- [devcontainer] https://code.claude.com/docs/en/devcontainer
- [devcontainer-Dockerfile] https://raw.githubusercontent.com/anthropics/claude-code/main/.devcontainer/Dockerfile
- [sandbox-runtime] https://github.com/anthropic-experimental/sandbox-runtime
- [npm] `npm view @anthropic-ai/sandbox-runtime version time.modified`, 2026-09-15
- [anthropic-sandboxing-post] https://www.anthropic.com/engineering/claude-code-sandboxing (2025-10-20)
- [managed-agents-overview] https://platform.claude.com/docs/en/managed-agents/overview
- [managed-agents-self-hosted] https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes
- [docker-sandboxes] https://docs.docker.com/ai/sandboxes/
- [docker-sandboxes-claude] https://docs.docker.com/ai/sandboxes/agents/claude-code/
- [docker-sandboxes-credentials] https://docs.docker.com/ai/sandboxes/configuration/credentials/
- [e2b-docs] https://docs.e2b.dev/
- [e2b-security] https://docs.e2b.dev/faq/security-and-compliance.md
- [e2b-secrets] https://docs.e2b.dev/secrets/inject.md
- [daytona-secrets] https://www.daytona.io/docs/en/secrets/
- [modal-sandbox] https://modal.com/docs/guide/sandbox
- [modal-networking] https://modal.com/docs/guide/sandbox-networking
- [gvisor-docker] https://gvisor.dev/docs/user_guide/quick_start/docker/
- [fly-machines] https://fly.io/docs/machines/ and https://fly.io/docs/security/
- Baseline image: `docker image inspect grandcamel/claude-devcontainer:latest` and a shell inside it, 2026-09-15
