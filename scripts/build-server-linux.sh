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
    # A distributed ARM binary must not inherit the hosted runner CPU ISA.
    # The sys crate watches this variable and forwards it after its defaults,
    # so cached native builds are reconfigured when this policy changes.
    if [ "$PORTHUB_SERVER_TARGET" = aarch64-unknown-linux-musl ]; then
      export TRANSCRIBE_CMAKE_ARGS="-DGGML_NATIVE=OFF -DGGML_CPU_ARM_ARCH=armv8-a"
    fi
    cargo build --locked --release -p porthub-api -p porthub-edge -p porthub-runtime -p porthub-firewall --target "$PORTHUB_SERVER_TARGET" --timings
    for binary in porthub-api porthub-edge porthub-runtime porthub-firewall; do
      artifact="target/$PORTHUB_SERVER_TARGET/release/$binary"
      if readelf -l "$artifact" | grep -q INTERP || readelf -d "$artifact" | grep -q NEEDED; then
        echo "$binary must be fully static, including its C++ runtime" >&2
        exit 1
      fi
      "$artifact" --help >/dev/null
    done
    cargo test --locked -p porthub-edge --target "$PORTHUB_SERVER_TARGET"
    if [ "$PORTHUB_SERVER_TARGET" = aarch64-unknown-linux-musl ]; then
      cargo test --locked --release -p porthub-api --test speech_portability --target "$PORTHUB_SERVER_TARGET" --no-run --message-format=json > "target/$PORTHUB_SERVER_TARGET/release/speech-probe-build.jsonl"
    fi
  '
if [ "$server_target" = aarch64-unknown-linux-musl ]; then
  python3 "$server_root/scripts/verify-speech-portability.py"
fi
