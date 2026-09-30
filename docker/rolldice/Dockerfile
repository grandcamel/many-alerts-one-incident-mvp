# Adapted from grafana/docker-otel-lgtm, examples/python/Dockerfile
# (https://github.com/grafana/docker-otel-lgtm), Copyright Grafana Labs, and
# licensed under the Apache License, Version 2.0; a copy of the License is at
# http://www.apache.org/licenses/LICENSE-2.0. Modified for this repository: the
# base image, the build context and the corporate CA step below. See NOTICE.
#
# The synthetic traffic's target: the rolldice Flask app from the otel-lgtm
# examples, auto-instrumented so that every request becomes a metric the Alert
# rule can watch. Copied from those examples rather than built from that repo,
# because story 53 keeps it read-only and this one self-contained.
#
# One departure from the example: a Debian slim base instead of alpine, because
# every dependency has a wheel for it and none has to be compiled during a build
# that might happen an hour before the demo.
#
# What compose sets for it: OTEL_SERVICE_NAME=rolldice, the OTLP endpoint on the
# lgtm service, and a five-second metric export interval so the rate the rule
# reads moves on demo timescales.
#
# The build context is the repo root, not this directory, so that the one
# certificate directory serves both images this repo builds; the two files this
# image needs are copied from under docker/rolldice.
FROM python:3.13-slim

WORKDIR /app

# The same optional corporate CA as the demo image (ticket 02): a PEM file named
# by the presenter's shell, or the committed empty placeholder, installed into the
# system trust store before pip and the bootstrap below reach PyPI through the
# proxy. PIP_CERT points both of them at that store.
ARG EXTRA_CA_CERT=certs/NO_EXTRA_CERTS
COPY ${EXTRA_CA_CERT} /tmp/extra-ca.crt
RUN if [ -s /tmp/extra-ca.crt ]; then \
        grep -q "BEGIN CERTIFICATE" /tmp/extra-ca.crt \
            || { echo "EXTRA_CA_CERT is not a PEM certificate" >&2; exit 1; }; \
        install -m 644 /tmp/extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt \
        && update-ca-certificates; \
    fi \
    && rm -f /tmp/extra-ca.crt
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt

COPY docker/rolldice/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# renovate: datasource=pypi depName=opentelemetry-distro
ENV OPENTELEMETRY_DISTRO_VERSION=0.60b0
RUN pip install --no-cache-dir "opentelemetry-distro[otlp]==$OPENTELEMETRY_DISTRO_VERSION" \
    && opentelemetry-bootstrap -a install

COPY docker/rolldice/app.py .

# Logging support is still in alpha, so we need to enable it explicitly
ENV OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED=true
ENV OTEL_LOGS_EXPORTER=otlp

EXPOSE 8082

CMD ["opentelemetry-instrument", "flask", "run", "--host", "0.0.0.0", "--port", "8082"]
