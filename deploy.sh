#!/bin/sh
# Build and start the three native PortHub roles after migration readiness checks.
set -eu
PORTHUB_VERSION="${PORTHUB_VERSION:-$(sh "$(dirname "$0")/scripts/release-version.sh")}"
PORTHUB_SOURCE_REVISION="${PORTHUB_SOURCE_REVISION:-$(git rev-parse HEAD 2>/dev/null || printf '%s' "$PORTHUB_VERSION")}"
PORTHUB_MODE="${PORTHUB_MODE:-prod}"
case "$PORTHUB_MODE" in
  prod) PORTHUB_CORE_READ_ONLY=true ;;
  dev) PORTHUB_CORE_READ_ONLY=false ;;
  *) echo "PORTHUB_MODE must be prod or dev" >&2; exit 1 ;;
esac
export PORTHUB_VERSION PORTHUB_SOURCE_REVISION PORTHUB_MODE PORTHUB_CORE_READ_ONLY
docker compose config --quiet
docker compose build core edge firewall
if [ "$PORTHUB_MODE" = dev ]; then
  docker compose up -d --wait core edge firewall
  docker compose watch --no-up --prune=false core edge firewall
else
  docker compose up -d --wait core edge firewall
  docker compose logs --tail 50 core edge firewall
fi
