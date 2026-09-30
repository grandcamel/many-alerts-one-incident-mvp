#!/bin/sh
# The demo container's entrypoint: get Claude Code past onboarding, then become the
# Receiver.
#
# Headless Claude will not start against a config that has never been through
# onboarding, and there is no one here to click through it, so this writes the one
# flag that says it has been. It writes only that one, and keeps whatever Claude
# Code itself has already written next to it.
#
# The existing container entrypoints on this machine also pre-accept bypass
# permissions mode. This one deliberately does not: a Run's boundary is the
# permission mode it is started in, and ADR 0003 is explicit that this demo does
# not take the skip-permissions route every other wrapper here takes. There is
# nothing in this container that would let a Run out of `dontAsk`.
#
# The flag is written with Python's standard library because the image carries
# no jq (ADR 0005): nothing the entrypoint calls is anything a Run could not also
# find, and there is nothing else in the image to find.
#
# Nothing else is done. The Receiver reads its own configuration and refuses to
# start without a Jira credential and an Anthropic token, which is a better message
# than anything this script could print.
#
# A command given to the container is honoured — `docker compose run --rm demo sh`
# is how you look around inside.
set -eu

CLAUDE_CONFIG_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
ONBOARDING="$CLAUDE_CONFIG_DIR/.claude.json"

mkdir -p "$CLAUDE_CONFIG_DIR"
python3 - "$ONBOARDING" <<'EOF'
import json
import os
import sys

path = sys.argv[1]
try:
    with open(path) as existing:
        config = json.load(existing)
except FileNotFoundError:
    config = {}
config["hasCompletedOnboarding"] = True
with open(path + ".tmp", "w") as written:
    json.dump(config, written)
os.replace(path + ".tmp", path)
EOF
chmod 600 "$ONBOARDING"

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec python3 -m grafana_jsm_sandbox
