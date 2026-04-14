#!/bin/bash
set -e

FW_DB_PATH="${FW_DB_PATH:-/state/firewall.db}"
FW_DB_DIR="$(dirname "$FW_DB_PATH")"

mkdir -p "$FW_DB_DIR"

if [ "${FW_DEBUG:-False}" = "True" ]; then
    echo "Running Firewall Development Server"
    exec uvicorn main:app --reload --host "${FW_HOST:-0.0.0.0}" --port "${FW_PORT:-8001}"
else
    echo "Running Firewall Production Server"
    exec uvicorn main:app --host "${FW_HOST:-0.0.0.0}" --port "${FW_PORT:-8001}" --workers "${FW_NUM_WORKERS:-2}"
fi
