#!/bin/sh
# Build and (re)start the single PortHub server container.
set -e
docker compose build porthub
docker compose up -d porthub
docker compose logs -f --tail 50 porthub
