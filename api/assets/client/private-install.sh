#!/usr/bin/env bash
set -euo pipefail
SERVER=__PRIVATE_SERVER__
TICKET=__PRIVATE_TICKET__
case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) target=x86_64 ;;
  Linux:arm64|Linux:aarch64) target=arm64 ;;
  Linux:armv7l) target=armv7 ;;
  Linux:armv6l|Linux:armhf) target=armhf ;;
  Darwin:arm64) target=darwin_arm64 ;;
  Darwin:x86_64) target=darwin_x86_64 ;;
  *) printf 'Unsupported platform\n' >&2; exit 1 ;;
esac
SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO=sudo; sudo -v </dev/tty; fi
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
printf 'Downloading PortHub private network client…\n'
curl -fsSL --connect-timeout 10 --max-time 300 "$SERVER/api/downloads/porthub/$target" -o "$work_dir/porthub"
chmod 755 "$work_dir/porthub"
printf '%s' "$TICKET" | "$work_dir/porthub" enroll --server "$SERVER" --profile "$work_dir/private.json"
$SUDO "$work_dir/porthub" service install --profile "$work_dir/private.json"
printf 'PortHub private networking installed. It will start at boot.\n'
