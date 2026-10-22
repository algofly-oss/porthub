#!/bin/sh
# Build and (re)start the single PortHub server container.
set -e
PORTHUB_VERSION="$(git rev-parse --short=12 HEAD)" docker compose build porthub
docker compose up -d porthub
docker compose logs -f --tail 50 porthub
