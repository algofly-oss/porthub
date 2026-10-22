#!/bin/sh
# Single PortHub server container. PORTHUB_MODE=prod (default) or dev.
set -eu
MODE="${PORTHUB_MODE:-prod}"
mkdir -p /data/mongo /data/firewall /runtime/rathole /runtime/traefik /runtime/traefik-access
# PortHub app routes (8345/8346) point at this host's loopback services.
sed -e 's#http://api:8080#http://127.0.0.1:47080#' -e 's#http://ui:3000#http://127.0.0.1:47030#' \
    -e 's#http://api:8091#http://127.0.0.1:47091#' -e 's#/porthub/certificate/#/app/traefik/certificate/#' \
    /app/traefik/internal.yml > /runtime/traefik/porthub-internal.yml
# First start: create the database root user (restoring a migration archive once).
if [ ! -f /data/mongo/.porthub-initialized ]; then
    python3 /app/deploy/mongo_init.py
fi
exec porthub supervise --procfile "/app/deploy/Procfile.$MODE"
