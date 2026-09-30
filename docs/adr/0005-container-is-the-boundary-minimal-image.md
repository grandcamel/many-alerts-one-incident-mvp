# The container is the boundary, and the image carries only what a Run needs

The demo image used to extend a batteries-included developer image: 4.1 GB with `sudo`, the `docker` CLI and group, `gh`, `git`, `curl`, `jq`, `iptables` and some thirty developer tools that no Run needs and that an audience asks about. Anthropic's secure-deployment guide describes the boundary for a headless, tool-restricted agent as a minimal container hardened from the outside — capabilities dropped, `no-new-privileges`, a read-only root with tmpfs scratch, a process limit, a non-root user, credentials behind a proxy — and not as isolation layered inside the container (`docs/research/harness-sandbox-containers-2026-09.md`). We rebuilt the image to match: the slim official Node image at a pinned tag, the distribution's Python 3 and TLS roots, Claude Code and `jira-as` at pinned versions, this package and the Skill, and one non-root user created by the Dockerfile. Nothing else is installed, the base's own `node` account and package managers are removed, and the last `USER` is the one this Dockerfile made. The runtime controls the guide prescribes belong in the compose file, not the image: `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true` with tmpfs for the temp directory, the runs directory and the Run user's home, `pids_limit`, and memory and CPU limits.

Bubblewrap-based sandboxing — Claude Code's built-in Bash sandbox, `enableWeakerNestedSandbox`, or the sandbox runtime — is deliberately not layered inside the container. Inside an unprivileged container bubblewrap cannot mount `/proc`, and the documented workaround is the one Anthropic's own sandboxing guide says "considerably weakens security". The boundary is the container, the permission mode (ADR 0003) and the sentinel (ADR 0002); the original Anthropic credential exception is superseded by ADR 0013, which keeps its API key outside Runs behind a fifth mediated endpoint.

## Consequences

- The answer to "what else can the Run reach for" is `ls /usr/local/bin`: `claude`, `jira-as`, `node`, `nodejs`, `npm` and `npx`. `sudo`, `docker`, `gh`, `git`, `curl` and `jq` are not there to explain away, and the default test run fails if a Dockerfile line brings one back.
- The entrypoint and the healthcheck use Python's standard library, because there is no `jq` and no `curl`; nothing the container starts with is anything a Run could not also find.
- `jira-as` lives in its own virtual environment with a symlink on the PATH, so its dependencies stay out of the interpreter the Receiver runs on and the Receiver stays standard library only.
- The base tag is pinned and overridable through `BASE_IMAGE`, so a build on another laptop produces the image that was rehearsed, and a mirror on a restricted network can be named without editing the file.
- The image is a fraction of the old one (539 MB against 4.35 GB), so a rebuild an hour before the demo is minutes.
- A future need for a developer tool in a Run is a decision to revisit here, not a package to add.

## Chapter-two persistence extensions

[ADR 0009](0009-memory-has-one-incident-authority-and-reviewed-learning.md) adds rehearsal-scoped Run learning through the Memory directory. [ADR 0012](0012-run-outcomes-and-recovery-are-explicit.md) separately adds a Receiver-owned durable recovery journal for admitted work and operation reconciliation. Both are explicit planned exceptions to tmpfs-only persistence; neither changes the current runtime implementation by itself.

[ADR 0013](0013-demo-spend-is-metered-reserved-and-qualified.md) adds week-scoped spend accounting across rehearsal resets. [ADR 0015](0015-changes-record-operator-actions-and-observed-stages.md) adds a separate operator-only durable Change journal (100 MiB including 10 MiB recovery reserve, seven-day retention with explicit unresolved-state handoff). These are planned persistence exceptions and do not grant Runs access to operator state or mutation credentials.
