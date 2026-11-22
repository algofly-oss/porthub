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
server_cache=${PORTHUB_SERVER_TARGET_CACHE:-"$server_root/target"}
mkdir -p "$server_cache" "$server_cargo" "$server_root/target"
if [ "${PORTHUB_SERVER_LOCAL_LIMITS:-0}" = 1 ]; then
  # Bootstrap the same SDK inside the limited compiler container. Nothing is
  # installed into the deployment host, and no persistent build runner is made.
  case "${PORTHUB_SERVER_CPUS:-}:${CARGO_BUILD_JOBS:-}" in 1:1|2:1|2:2) ;; *) echo 'Invalid local CPU/job limits' >&2; exit 1;; esac
  case "${PORTHUB_SERVER_MEMORY_BYTES:-}" in ''|*[!0-9]*) exit 1;; esac
  test "$PORTHUB_SERVER_MEMORY_BYTES" -ge 2147483648
  test "$PORTHUB_SERVER_MEMORY_BYTES" -le 8589934592
  test -b "$PORTHUB_SERVER_IO_DEVICE"
  server_image=rust:1.99.1-alpine3.22
  server_user=0:0
else
  docker build -f "$server_root/deploy/Dockerfile.server-static" -t porthub-server-static-toolchain "$server_root"
  server_image=porthub-server-static-toolchain
  server_user="$(id -u):$(id -g)"
fi
server_cid=$(mktemp "$server_root/.server-build-cid.XXXXXX")
rm "$server_cid"
cleanup_server() {
  if [ -s "$server_cid" ]; then
    server_id=$(cat "$server_cid")
    if printf '%s' "$server_id" | grep -Eq '^[a-f0-9]{64}$'; then
      docker stop --time 5 "$server_id" >/dev/null 2>&1 || true
      docker rm -f "$server_id" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$server_cid"
}
trap cleanup_server EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
set -- docker run --rm --cidfile "$server_cid" --user "$server_user" --workdir /src \
  --volume "$server_cargo:/cargo" --volume "$server_cache:/src/target" \
  --env "PORTHUB_VERSION=$server_version" --env "PORTHUB_SOURCE_REVISION=$server_revision" \
  --env "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}" --env RUST_MIN_STACK=33554432 \
  --env CARGO_HOME=/cargo --env RUSTUP_HOME=/usr/local/rustup --env CARGO_INCREMENTAL=0 \
  --env "PORTHUB_SERVER_TARGET=$server_target" --env "PORTHUB_SERVER_HOST_UID=$(id -u)" \
  --env "PORTHUB_SERVER_HOST_GID=$(id -g)" --env "PORTHUB_SERVER_LOCAL_LIMITS=${PORTHUB_SERVER_LOCAL_LIMITS:-0}"
if [ "${PORTHUB_SERVER_LOCAL_LIMITS:-0}" = 1 ]; then
  set -- "$@" --volume "$server_root:/src:ro" --cpus "$PORTHUB_SERVER_CPUS" \
    --label "porthub.native.server.worker=bounded-v1" --label "porthub.native.server.source=$server_revision" \
    --env "PORTHUB_SERVER_CPUS=$PORTHUB_SERVER_CPUS" \
    --env "PORTHUB_SERVER_MEMORY_BYTES=$PORTHUB_SERVER_MEMORY_BYTES" \
    --env "PORTHUB_SERVER_IO_DEVICE_NUMBER=$PORTHUB_SERVER_IO_DEVICE_NUMBER" \
    --memory "$PORTHUB_SERVER_MEMORY_BYTES" --memory-swap "$PORTHUB_SERVER_MEMORY_BYTES" \
    --pids-limit 384 --cpu-shares 128 --oom-score-adj 500 --blkio-weight 100 \
    --device-read-bps "$PORTHUB_SERVER_IO_DEVICE:41943040" \
    --device-write-bps "$PORTHUB_SERVER_IO_DEVICE:41943040" \
    --security-opt no-new-privileges --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID --cap-add SETGID \
    --tmpfs /tmp:rw,size=536870912,mode=1777 --env HOME=/tmp/porthub-build-home
else
  set -- "$@" --volume "$server_root:/src"
fi
"$@" "$server_image" sh -ec '
  if [ "$PORTHUB_SERVER_LOCAL_LIMITS" = 1 ]; then
    # Check the compiler container itself, not the SSH/systemd parent cgroup.
    set -- $(cat /sys/fs/cgroup/cpu.max)
    test "$1" -eq "$((PORTHUB_SERVER_CPUS * $2))"
    test "$(cat /sys/fs/cgroup/memory.max)" = "$PORTHUB_SERVER_MEMORY_BYTES"
    test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0
    test "$(cat /sys/fs/cgroup/pids.max)" = 384
    io_line=$(grep "^$PORTHUB_SERVER_IO_DEVICE_NUMBER " /sys/fs/cgroup/io.max)
    case "$io_line" in *"rbps=41943040"*"wbps=41943040"*) ;; *) exit 1;; esac
    apk add --no-cache build-base cmake linux-headers perl
    rm -f /usr/lib/libstdc++.so
    CARGO_HOME=/usr/local/cargo rustup component add rustfmt clippy
    if [ "$PORTHUB_SERVER_TARGET" = x86_64-unknown-linux-musl ]; then
      apk add --no-cache qemu-x86_64
      mkdir -p /src/target/.native-tools
      cp /usr/bin/qemu-x86_64 /src/target/.native-tools/qemu-x86_64
      chown "$PORTHUB_SERVER_HOST_UID:$PORTHUB_SERVER_HOST_GID" /src/target/.native-tools /src/target/.native-tools/qemu-x86_64
    fi
    addgroup -g "$PORTHUB_SERVER_HOST_GID" porthub-build
    adduser -D -u "$PORTHUB_SERVER_HOST_UID" -G porthub-build -h /tmp/porthub-build-home porthub-build
    exec su -p -s /bin/sh porthub-build -c "exec sh scripts/build-server-user.sh"
  fi
  exec sh scripts/build-server-user.sh
'
if [ "${PORTHUB_SERVER_LOCAL_LIMITS:-0}" = 1 ] && [ "$server_target" = x86_64-unknown-linux-musl ]; then
  export PORTHUB_QEMU_X86_64="$server_cache/.native-tools/qemu-x86_64"
fi
python3 "$server_root/scripts/verify-speech-portability.py" "$server_target"
