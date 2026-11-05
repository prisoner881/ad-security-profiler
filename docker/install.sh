#!/usr/bin/env bash
# install.sh -- creates (or updates) a collector installation directory.
# See CONTAINER.md.
#
#   docker/install.sh [DIR]          default DIR: /opt/fortifydata-collector
#
# Creates DIR/compose.yaml, DIR/.env, DIR/config/collector.toml,
# DIR/secrets/* and DIR/data/{state,logs}. Safe to run again (e.g. for an
# upgrade): it replaces compose.yaml (keeping the old one as
# compose.yaml.previous when it differs) and never overwrites the
# configuration, .env or a secret.
#
# The PostgreSQL password is generated here and never leaves this machine.
# The collector container runs as the user who owns these files: the user
# running this script, or uid 10001 when it is run as root.

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-/opt/fortifydata-collector}"
IMAGE_DEFAULT="fortifydata-ad-collector:1.0.1"

umask 077

if [ "$(id -u)" -eq 0 ]; then
    OWNER_UID="${COLLECTOR_UID:-10001}"
    OWNER_GID="${COLLECTOR_GID:-10001}"
else
    OWNER_UID="$(id -u)"
    OWNER_GID="$(id -g)"
fi

mkdir -p "$DIR/config" "$DIR/secrets" "$DIR/data/state" "$DIR/data/logs"
chmod 700 "$DIR/secrets" "$DIR/data/state"
chmod 755 "$DIR" "$DIR/config" "$DIR/data" "$DIR/data/logs"

# compose.yaml: always the current one.
if [ -f "$DIR/compose.yaml" ] && ! cmp -s "$SRC/compose.yaml" "$DIR/compose.yaml"; then
    cp -p "$DIR/compose.yaml" "$DIR/compose.yaml.previous"
    echo "Kept the previous compose.yaml as compose.yaml.previous"
fi
install -m 644 "$SRC/compose.yaml" "$DIR/compose.yaml"

# The configuration: only when there is none.
if [ ! -f "$DIR/config/collector.toml" ]; then
    install -m 644 "$SRC/collector.toml" "$DIR/config/collector.toml"
    echo "Created config/collector.toml -- edit it before starting"
fi

# .env: only when there is none.
if [ ! -f "$DIR/.env" ]; then
    cat > "$DIR/.env" <<EOF
# Read by docker compose (see CONTAINER.md).
COLLECTOR_IMAGE=${COLLECTOR_IMAGE:-$IMAGE_DEFAULT}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-postgres:17-trixie}
COLLECTOR_UID=$OWNER_UID
COLLECTOR_GID=$OWNER_GID
# Outbound proxy for the platform and Microsoft Graph, if needed:
# HTTPS_PROXY=http://proxy.corp.example.com:3128
# NO_PROXY=
EOF
    chmod 600 "$DIR/.env"
    echo "Created .env"
fi

# Secrets: each one a file holding the secret on its first line.
if [ ! -s "$DIR/secrets/pg_password" ]; then
    # 32 characters from [A-Za-z0-9]: no quoting problems anywhere. (tr
    # ends on SIGPIPE when head has enough: not an error here.)
    password="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 || true)"
    if [ "${#password}" -ne 32 ]; then
        echo "Could not generate the PostgreSQL password" >&2
        exit 1
    fi
    printf '%s\n' "$password" > "$DIR/secrets/pg_password"
    unset password
    echo "Generated the PostgreSQL password (secrets/pg_password)"
fi
for name in ad_bind_password entra_app_secret fd_activation_key; do
    if [ ! -e "$DIR/secrets/$name" ]; then
        : > "$DIR/secrets/$name"
    fi
done
chmod 600 "$DIR"/secrets/*

if [ "$(id -u)" -eq 0 ]; then
    chown -R "$OWNER_UID:$OWNER_GID" "$DIR/config" "$DIR/secrets" "$DIR/data" "$DIR/.env"
fi

cat <<EOF

Installation directory: $DIR (collector runs as uid $OWNER_UID)

Next:
  1. Load the image (if you received it as a file):
       docker load -i fortifydata-ad-collector-<version>.tar.gz
  2. Edit $DIR/config/collector.toml (schedule, [ad], optional [entra]).
  3. Write the secrets, one per file, on the first line:
       $DIR/secrets/ad_bind_password     the AD bind account's password
       $DIR/secrets/entra_app_secret     the Entra app secret (if [entra] is used)
       $DIR/secrets/fd_activation_key    the activation key (to push results)
     e.g.  printf '%s\n' 'the password' > $DIR/secrets/ad_bind_password
  4. cd $DIR
     docker compose run --rm collector --check-config
     docker compose up -d
     docker compose logs -f collector
EOF
