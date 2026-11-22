#!/bin/sh
# Shared native server build/validation, run as the ordinary builder UID.
set -eu
    mkdir -p "target/$PORTHUB_SERVER_TARGET/release"
    rustc -Vv > "target/$PORTHUB_SERVER_TARGET/release/server-rustc.txt"
    if [ "${PORTHUB_SERVER_LOCAL_LIMITS:-0}" = 1 ]; then
      for controller in cpu.max memory.max memory.swap.max pids.max io.max; do
        cat "/sys/fs/cgroup/$controller" > "target/$PORTHUB_SERVER_TARGET/release/server-cgroup.$controller"
      done
    fi
    # Explicit values replace old CMake cache entries as well as defaults.
    export TRANSCRIBE_CMAKE_ARGS="$(sh scripts/speech-cpu-policy.sh "$PORTHUB_SERVER_TARGET")"
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
    cargo test --locked --release -p porthub-api --test speech_portability --target "$PORTHUB_SERVER_TARGET" --no-run --message-format=json > "target/$PORTHUB_SERVER_TARGET/release/speech-probe-build.jsonl"
