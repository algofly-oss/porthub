#!/bin/bash
set -e

RATHOLE_CONFIG_PATH="${RATHOLE_SERVER_CONFIG_PATH:-/runtime/rathole/server.toml}"
RATHOLE_CONFIG_DIR="$(dirname "$RATHOLE_CONFIG_PATH")"
RATHOLE_BIND_PORT="${RATHOLE_PORT:-2334}"
RATHOLE_DUMMY_SERVICE_NAME="${RATHOLE_DUMMY_SERVICE_NAME:?Missing RATHOLE_DUMMY_SERVICE_NAME}"
RATHOLE_DUMMY_SERVICE_TOKEN="${RATHOLE_DUMMY_SERVICE_TOKEN:?Missing RATHOLE_DUMMY_SERVICE_TOKEN}"
RATHOLE_DUMMY_SERVICE_BIND_ADDR="${RATHOLE_DUMMY_SERVICE_BIND_ADDR:?Missing RATHOLE_DUMMY_SERVICE_BIND_ADDR}"

if [ -d "$RATHOLE_CONFIG_PATH" ]; then
    echo "Rathole config path is a directory: $RATHOLE_CONFIG_PATH" >&2
    exit 1
fi

mkdir -p "$RATHOLE_CONFIG_DIR"

cat > "$RATHOLE_CONFIG_PATH" <<EOF
# Managed by PortHub. Manual changes will be overwritten.
# source: entrypoint-bootstrap
[server]
bind_addr = "0.0.0.0:${RATHOLE_BIND_PORT}"

[server.services.${RATHOLE_DUMMY_SERVICE_NAME}]
token = "${RATHOLE_DUMMY_SERVICE_TOKEN}"
bind_addr = "${RATHOLE_DUMMY_SERVICE_BIND_ADDR}"
EOF

if [ "${API_DEBUG:-False}" = "True" ]; then
    echo "Running Development Server"
    exec uvicorn main:app --reload --host 0.0.0.0 --port 8080
else
    echo "Running Production Server"
    exec uvicorn main:app --host 0.0.0.0 --port 8080 --workers "${API_NUM_WORKERS:-4}"
fi
