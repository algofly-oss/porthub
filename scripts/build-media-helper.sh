#!/usr/bin/env bash
# Build-host only: native GNU target, pinned PipeWire headers/library, no daemon.
# Does not install anything on client machines or publish release assets.
set -euo pipefail
media_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# != 5 ]]; then
  echo "Usage: build-media-helper.sh TARGET RELEASE MIN_AGENT_VERSION SOURCE_REVISION OUTPUT_DIRECTORY" >&2
  exit 2
fi
media_target=$1
media_release=$2
media_core=$3
media_revision=$4
media_output=$5
case "$media_target" in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) exit 2 ;; esac
cd "$media_root"
python3 - "$media_root" "$media_revision" <<'PY'
import importlib.util,sys,subprocess,re
from pathlib import Path
root=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('media_package',root/'scripts/package-media-helper.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.frozen_inputs(sys.argv[2])
version=subprocess.check_output(['getconf','GNU_LIBC_VERSION'],text=True).strip()
match=re.fullmatch(r'glibc (\d+)\.(\d+)',version)
if not match or tuple(map(int,match.groups()))>(2,35):raise SystemExit('A GNU build host with GLIBC <=2.35 is required')
PY
media_native=$(rustc -vV | sed -n 's/^host: //p')
if [[ "$media_native" != "$media_target" ]]; then
  echo "Use a native baseline builder for $media_target, not an unverified cross sysroot" >&2
  exit 2
fi
# The caller bootstraps the checksum-pinned PipeWire source into an isolated
# prefix as described in docs/design/native-media-publication.md.
if [[ "$(pkg-config --modversion libpipewire-0.3)" != "0.3.68" ]]; then
  echo "Build against the pinned PipeWire 0.3.68 prefix via PKG_CONFIG_PATH" >&2
  exit 2
fi
cargo build --locked --release -p porthub-media-helper --target "$media_target"
media_target_directory=${CARGO_TARGET_DIR:-"$media_root/target"}
python3 scripts/package-media-helper.py --binary "$media_target_directory/$media_target/release/porthub-media-helper" --target "$media_target" --source-revision "$media_revision" --release "$media_release" --core ">=$media_core" --output "$media_output"
