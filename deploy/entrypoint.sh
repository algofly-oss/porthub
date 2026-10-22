#!/bin/sh
# Single PortHub server container. PORTHUB_MODE=prod (default) or dev.
set -eu
MODE="${PORTHUB_MODE:-prod}"
mkdir -p /data/mongo /data/firewall /runtime/rathole /runtime/traefik /runtime/traefik-access
# PortHub app routes (8345/8346) point at this host's loopback services.
cp /app/deploy/traefik.yml /runtime/traefik/porthub-internal.yml
# First start: create the database root user (restoring a migration archive once).
if [ ! -f /data/mongo/.porthub-initialized ]; then
    porthub-api init-db
fi
exec porthub supervise --procfile "/app/deploy/Procfile.$MODE"
