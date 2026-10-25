#!/bin/sh
# Build and start the three native PortHub roles after migration readiness checks.
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"
PORTHUB_VERSION="${PORTHUB_VERSION:-$(sh "$ROOT_DIR/scripts/release-version.sh")}"
PORTHUB_SOURCE_REVISION="${PORTHUB_SOURCE_REVISION:-$(git rev-parse HEAD 2>/dev/null || printf '%s' "$PORTHUB_VERSION")}"
PORTHUB_MODE="${PORTHUB_MODE:-prod}"
case "$PORTHUB_MODE" in
  prod) PORTHUB_READ_ONLY=true ;;
  dev) PORTHUB_READ_ONLY=false ;;
  *) echo "PORTHUB_MODE must be prod or dev" >&2; exit 1 ;;
esac
if [ -z "${PORTHUB_VOLUME_ROOT:-}" ] && [ -f "$ROOT_DIR/.env" ]; then
  PORTHUB_VOLUME_ROOT=$(sed -n 's/^PORTHUB_VOLUME_ROOT=//p' "$ROOT_DIR/.env" | tail -n 1)
fi
PORTHUB_VOLUME_ROOT="${PORTHUB_VOLUME_ROOT:-./volumes/porthub}"
mkdir -p "$PORTHUB_VOLUME_ROOT"
PORTHUB_VOLUME_ROOT=$(CDPATH= cd -- "$PORTHUB_VOLUME_ROOT" && pwd)
export PORTHUB_VERSION PORTHUB_SOURCE_REVISION PORTHUB_MODE PORTHUB_READ_ONLY PORTHUB_VOLUME_ROOT
if [ "$PORTHUB_MODE" = prod ] && [ -n "${PORTHUB_RELEASE_BUNDLE:-}" ]; then
  python3 "$ROOT_DIR/deploy/native/stage_client_bundle.py" --source "$PORTHUB_RELEASE_BUNDLE" --version "$PORTHUB_VERSION"
fi
if [ "$PORTHUB_MODE" = prod ] && [ ! -f "$ROOT_DIR/deploy/native/client-bin/porthub-x86_64.version" ]; then
  echo "Stage the verified release bundle first, or set PORTHUB_RELEASE_BUNDLE=/path/to/bundle" >&2
  exit 1
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
# Bind mounts keep deployment state visible under the host's ./volumes tree.
# Prepare only the mount roots so existing database/file ownership is preserved.
docker run --rm --user 0:0 --mount "type=bind,src=$PORTHUB_VOLUME_ROOT,dst=/porthub-volumes" \
  --entrypoint /bin/sh porthub:core -c '
    set -eu
    mkdir -p /porthub-volumes/data /porthub-volumes/firewall-data /porthub-volumes/api-socket \
      /porthub-volumes/edge-socket /porthub-volumes/firewall-socket \
      /porthub-volumes/routing-config /porthub-volumes/certificates /porthub-volumes/web-activity
    chown 10001:10001 /porthub-volumes/data /porthub-volumes/api-socket /porthub-volumes/routing-config
    chown 0:10001 /porthub-volumes/firewall-data /porthub-volumes/edge-socket \
      /porthub-volumes/firewall-socket /porthub-volumes/certificates /porthub-volumes/web-activity
    chmod 0750 /porthub-volumes/data /porthub-volumes/routing-config
    chmod 0770 /porthub-volumes/firewall-data /porthub-volumes/api-socket \
      /porthub-volumes/edge-socket /porthub-volumes/firewall-socket \
      /porthub-volumes/certificates /porthub-volumes/web-activity
    mkdir -p /porthub-volumes/data/mongo
    chown 10001:10001 /porthub-volumes/data/mongo
    chmod 0750 /porthub-volumes/data/mongo
  '
if [ "$PORTHUB_MODE" = dev ]; then
  docker compose --project-name porthub up -d --wait core edge firewall
  docker compose --project-name porthub watch --no-up --prune=false core edge firewall
else
  docker compose --project-name porthub up -d --wait core edge firewall
  docker compose --project-name porthub logs --tail 50 core edge firewall
fi
