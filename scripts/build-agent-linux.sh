#!/bin/sh
# Build the same self-contained Linux artifact on a native x86_64/arm64 runner.
# Cargo's target directory stays on the host so CI can restore it between runs.
set -eu
agent_target=${1:?usage: build-agent-linux.sh TARGET ARTIFACT}
agent_artifact=${2:?usage: build-agent-linux.sh TARGET ARTIFACT}
case "$agent_target:$agent_artifact" in
  x86_64-unknown-linux-musl:x86_64|aarch64-unknown-linux-musl:arm64) ;;
  *) echo 'Unsupported Linux artifact/target pair' >&2; exit 1 ;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
PORTHUB_VERSION=${PORTHUB_VERSION:-$(sh scripts/release-version.sh)}
export PORTHUB_VERSION
# Both targets compile natively with the host's musl toolchain.
target_key=$(printf '%s' "$agent_target" | tr '[:lower:]-' '[:upper:]_')
cc_key=$(printf '%s' "$agent_target" | tr '-' '_')
export "CARGO_TARGET_${target_key}_LINKER=musl-gcc"
export "CC_${cc_key}=musl-gcc"
cargo build --locked --release -p porthub-agent --bin porthub --target "$agent_target" --timings
agent="${CARGO_TARGET_DIR:-target}/$agent_target/release/porthub"
"$agent" version
elf=$(mktemp)
trap 'rm -f "$elf"' EXIT HUP INT TERM
readelf -l "$agent" > "$elf"
if grep -q INTERP "$elf"; then
  echo 'Agent must not require a dynamic loader' >&2
  exit 1
fi
mkdir -p dist
output="dist/porthub-$agent_artifact"
cp "$agent" "$output"
printf '%s\n' "$PORTHUB_VERSION" > "$output.version"
(cd dist && sha256sum "porthub-$agent_artifact" > "porthub-$agent_artifact.sha256")
