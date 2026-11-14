#!/bin/sh
# Native musl C/C++/Rust build; Cargo artifacts remain in the host cache.
set -eu
server_target=${1:?usage: build-server-linux.sh TARGET}
case "$server_target:$(uname -m)" in
  x86_64-unknown-linux-musl:x86_64|aarch64-unknown-linux-musl:aarch64) ;;
  *) echo 'Server builds require a matching native Linux runner' >&2; exit 1 ;;
esac
server_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
server_cargo=${CARGO_HOME:-"$HOME/.cargo"}
server_version=${PORTHUB_VERSION:-$(sh "$server_root/scripts/release-version.sh")}
server_revision=${PORTHUB_SOURCE_REVISION:-unknown}
docker build -f "$server_root/deploy/Dockerfile.server-static" -t porthub-server-static-toolchain "$server_root"
docker run --rm --user "$(id -u):$(id -g)" \
  --volume "$server_root:/src" --volume "$server_cargo:/cargo" \
  --env "PORTHUB_VERSION=$server_version" --env "PORTHUB_SOURCE_REVISION=$server_revision" \
  --env "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}" --env RUST_MIN_STACK=33554432 \
  --env "PORTHUB_SERVER_TARGET=$server_target" \
  porthub-server-static-toolchain sh -ec '
    cargo build --locked --release -p porthub-api -p porthub-edge -p porthub-runtime -p porthub-firewall --target "$PORTHUB_SERVER_TARGET" --timings
    cargo test --locked -p porthub-edge --target "$PORTHUB_SERVER_TARGET"
  '
