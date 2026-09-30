# One container; each Run is a child process of the Receiver

The demo needs a visible blast-radius boundary. We chose a single container built in this repo, with the Receiver as the main process and each Run a child process, serialized one at a time. The earlier demo's pattern of spawning a fresh container per run was rejected because it requires a Docker socket inside the receiver, which is a larger hole than the isolation it buys. The Claude Code native sandbox without Docker was rejected because it removes the container from the story.

## Consequences

- No Docker socket is mounted anywhere.
- Two Notifications never run concurrently, so duplicate Incidents cannot race into existence.
- The whole demo starts with one docker compose that also runs the LGTM stack.
