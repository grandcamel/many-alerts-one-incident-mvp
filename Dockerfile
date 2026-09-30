# The demo container: the Receiver is its main process, and a Run is a child of that.
#
# The image carries what a Run needs and nothing else (ADR 0005): the slim official
# Node image plus the distribution's Python, Claude Code and jira-as at pinned
# versions, this package and the Skill, run by a non-root user created here. No
# sudo, no docker CLI or group, no gh, no git, no curl, no jq, no developer kit.
# The answer to "what else can a Run reach for" is `ls /usr/local/bin`.
#
# No bubblewrap, no sandbox package, no Docker socket. The boundary a Run runs
# inside is the container itself, the permission mode it is started with (ADR
# 0003) and the sentinel in its environment (ADR 0002), not anything installed here.
#
#     docker compose build
#     EXTRA_CA_CERT=certs/corporate-root.crt docker compose build    # behind a proxy
#
# The base is pinned to the tag the demo was rehearsed on. Node 22.15 or newer is
# required: that is the runtime from which Claude Code reads the operating system
# trust store, which the work laptop behind an intercepting proxy depends on.

ARG BASE_IMAGE=node:24.21.0-trixie-slim
FROM ${BASE_IMAGE}

ARG CLAUDE_CODE_VERSION=2.1.272
ARG JIRA_AS_VERSION=2.0.0

# One user, made here. The base image's `node` account goes, along with yarn,
# corepack and the base's own entrypoint, so that the only account and the only
# executables in the image are the ones this file put there.
RUN userdel -r node \
    && useradd --uid 1000 --user-group --create-home --shell /bin/bash demo \
    && rm -rf /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
        /usr/local/bin/corepack /usr/local/bin/docker-entrypoint.sh

# TLS roots, and a Python: the Receiver is standard library only, and jira-as is
# a Python CLI. python3-venv is what lets jira-as live in its own environment
# rather than in the distribution's site-packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# An optional corporate CA, for a laptop behind an intercepting proxy such as
# Zscaler (ticket 02). The argument names a PEM file in the build context; the
# default is a committed placeholder that is intentionally empty, and with it the
# build is exactly the one above. A named certificate goes into the system trust
# store here, before anything below reaches npm or PyPI through that proxy, and a
# file that is not PEM stops the build now rather than as a TLS error three
# layers down.
ARG EXTRA_CA_CERT=certs/NO_EXTRA_CERTS
COPY ${EXTRA_CA_CERT} /tmp/extra-ca.crt
RUN if [ -s /tmp/extra-ca.crt ]; then \
        grep -q "BEGIN CERTIFICATE" /tmp/extra-ca.crt \
            || { echo "EXTRA_CA_CERT is not a PEM certificate" >&2; exit 1; }; \
        install -m 644 /tmp/extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt \
        && update-ca-certificates; \
    fi \
    && rm -f /tmp/extra-ca.crt

# Every TLS client the image carries, pointed at that one bundle, image-wide and
# before the installs that need them: Python's ssl module and so the Forwarder's
# urllib, the requests library jira-as uses, pip, curl-style clients, and Claude
# Code, which documents NODE_EXTRA_CA_CERTS as its custom-CA setting. The Receiver
# hands exactly these five on to each Run, and nothing else new (ADR 0002).
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# A Run's Transcript is what the audience reads and the formatter renders its
# Run event shapes, so Claude Code is pinned to the version the container was
# rehearsed on rather than left to drift. Its install script is the one npm is
# allowed to run: it copies the native Linux binary over the `claude` stub, so a
# Run is that binary and not a Node wrapper around it.
RUN npm install -g --allow-scripts="@anthropic-ai/claude-code" \
        "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force

# The only thing a Run may execute. Pinned, because the skill is written in its
# invocations and was verified against this version. Its own venv keeps its
# dependencies out of the interpreter the Receiver runs on; the symlink puts the
# one command a Run may call on the PATH next to `claude`.
RUN python3 -m venv /opt/jira-as \
    && /opt/jira-as/bin/pip install --no-cache-dir "jira-as==${JIRA_AS_VERSION}" \
    && ln -s /opt/jira-as/bin/jira-as /usr/local/bin/jira-as

# /app is the Receiver's home and the parent of every Run's working directory, so
# it belongs to the user the Receiver runs as.
RUN mkdir -p /app/runs && chown -R demo:demo /app

WORKDIR /app
COPY --chown=demo:demo grafana_jsm_sandbox/ /app/grafana_jsm_sandbox/
COPY --chown=demo:demo skill/ /app/skill/
COPY --chown=demo:demo docker/entrypoint.sh /app/entrypoint.sh

# Where this container keeps the two directories the Receiver is told about. The
# credentials are not here and are not in the image: compose hands them in from an
# env file that git and the build context both refuse.
ENV SKILL_DIRECTORY=/app/skill \
    RUNS_DIRECTORY=/app/runs \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER demo

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
