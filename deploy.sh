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
if [ "$PORTHUB_MODE" = prod ] && [ -n "${PORTHUB_RELEASE_BUNDLE:-}" ]; then
  python3 "$(dirname "$0")/deploy/native/stage_client_bundle.py" --source "$PORTHUB_RELEASE_BUNDLE" --version "$PORTHUB_VERSION"
fi
docker compose --project-name porthub config --quiet
docker compose --project-name porthub build core edge firewall
# Stable role tags select the current build; version aliases identify the release.
# Check every role before starting any container or publishing release aliases.
for role in core edge firewall; do
  image_version=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "porthub:$role")
  if [ "$image_version" != "$PORTHUB_VERSION" ]; then
    echo "porthub:$role does not match release $PORTHUB_VERSION" >&2
    exit 1
  fi
done
for role in core edge firewall; do
  docker image tag "porthub:$role" "porthub:$role-$PORTHUB_VERSION"
done
if [ "$PORTHUB_MODE" = dev ]; then
  docker compose --project-name porthub up -d --wait core edge firewall
  docker compose --project-name porthub watch --no-up --prune=false core edge firewall
else
  docker compose --project-name porthub up -d --wait core edge firewall
  docker compose --project-name porthub logs --tail 50 core edge firewall
fi
