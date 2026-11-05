# syntax=docker/dockerfile:1
#
# The collector image: collector_daemon.py with the scripts, schema files
# and plugins. See CONTAINER.md.
#
#   docker build -t fortifydata-ad-collector:1.0.2 .
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
ARG VERSION=1.0.2
LABEL org.opencontainers.image.title="FortifyData AD/Entra audit collector" \
      org.opencontainers.image.description="collector_daemon.py: daily AD and Entra ID collection, evaluation and push" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/prisoner881/ad-security-profiler"

COPY --from=deps /opt/venv /opt/venv
WORKDIR /opt/collector
COPY *.py *.sql requirements.txt RELEASE_NOTES.md DAEMON.md CONTAINER.md PERMISSIONS.md \
     collector_daemon.example.toml ./
COPY plugins/ plugins/

# Compiled once here: the root filesystem is read-only at run time, and the
# children run with PYTHONDONTWRITEBYTECODE.
RUN python -m compileall -q /opt/collector /opt/venv \
 && chmod -R a+rX /opt/collector /opt/venv \
 && /opt/venv/bin/python /opt/collector/collector_daemon.py --version

# No user database entry is needed: the container runs as whatever numeric
# user compose.yaml sets (the owner of the secret files), 10001 by default.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    ADAUDIT_DAEMON_CONFIG=/config/collector.toml
USER 10001:10001

ENTRYPOINT ["python", "/opt/collector/collector_daemon.py"]
