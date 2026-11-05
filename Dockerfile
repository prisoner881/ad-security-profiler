# syntax=docker/dockerfile:1
#
# The collector image, fortifydata/collector-ad: collector_daemon.py with the
# scripts, schema files and plugins. Built for linux/amd64 and linux/arm64.
# See docs/CONTAINER.md; releases are built and pushed by
# .github/workflows/collector-image.yml.
#
#   docker build --build-arg COLLECTOR_VERSION=1.2.0 -t fortifydata/collector-ad:v1.2.0 .
#
# COLLECTOR_VERSION is the version the image reports to the platform (semver,
# without the "v": 1.2.0, or 1.2.0-dev.7 for a development build). Left
# empty, collector_daemon.py's own VERSION is reported.
#
# PYTHON_IMAGE can point at a mirror of the same official image when Docker
# Hub is rate-limited, e.g.
#   --build-arg PYTHON_IMAGE=mirror.gcr.io/library/python:3.13-slim-trixie

ARG PYTHON_IMAGE=python:3.13-slim-trixie

# --- dependencies, in a virtual environment ---------------------------------
FROM ${PYTHON_IMAGE} AS deps
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --only-binary=:all: -r /tmp/requirements.txt

# --- the image ---------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ARG COLLECTOR_VERSION=""
LABEL org.opencontainers.image.title="FortifyData AD/Entra audit collector" \
      org.opencontainers.image.description="collector_daemon.py: daily AD and Entra ID collection, evaluation and push" \
      org.opencontainers.image.version="${COLLECTOR_VERSION}" \
      org.opencontainers.image.source="https://github.com/prisoner881/ad-security-profiler"

# pg_dump, for the backup schema_setup.py takes before it migrates the schema
# of an existing database (PostgreSQL 17, the server's version).
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client-17 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=deps /opt/venv /opt/venv
WORKDIR /opt/collector
COPY *.py *.sql requirements.txt collector_daemon.example.toml ./
COPY docs/ docs/
COPY migrations/ migrations/
COPY plugins/ plugins/

# Compiled once here: the root filesystem is read-only at run time, and the
# children run with PYTHONDONTWRITEBYTECODE.
ENV COLLECTOR_VERSION=${COLLECTOR_VERSION}
RUN python -m compileall -q /opt/collector /opt/venv \
 && chmod -R a+rX /opt/collector /opt/venv \
 && /opt/venv/bin/python /opt/collector/collector_daemon.py --version \
 && pg_dump --version

# No user database entry is needed: the container runs as whatever numeric
# user compose.yaml sets (the owner of the secret files), 10001 by default.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    ADAUDIT_DAEMON_CONFIG=/config/collector.toml
USER 10001:10001

# Healthy while the daemon is alive and reporting (status.json fresh); see
# docs/DAEMON.md, section 5. compose.yaml sets the same.
HEALTHCHECK --interval=1m --timeout=30s --start-period=5m --retries=3 \
    CMD ["python", "/opt/collector/collector_daemon.py", "--healthcheck"]

ENTRYPOINT ["python", "/opt/collector/collector_daemon.py"]
