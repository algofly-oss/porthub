#!/usr/bin/env bash
# Builds the firmware in Espressif's Docker image (no local toolchain) and
# writes one merged image per chip, flashed at offset 0 by the setup page
# (an update preserves settings at 0x9000-0x10000):
#   dist/porthub-keyboard-esp32.bin, dist/porthub-keyboard-esp32c3.bin
# Usage: firmware/keyboard/build.sh [version] [chip ...]
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:-dev}"
[ $# -gt 0 ] && shift
CHIPS=("$@")
[ ${#CHIPS[@]} -gt 0 ] || CHIPS=(esp32 esp32c3)
IDF_IMAGE="${IDF_IMAGE:-espressif/idf:v5.4.2}"
mkdir -p dist
for chip in "${CHIPS[@]}"; do
  echo "==> $chip ($VERSION)"
  # Capped CPUs: full-parallel builds set off a kernel RCU bug on the build host.
  docker run --rm --cpus "${BUILD_CPUS:-4}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e VK_VERSION="$VERSION" \
    -v "$PWD:/project" -w /project "$IDF_IMAGE" bash -c "
      set -e
      # set-target only on the first build: it wipes the build folder.
      [ -f build/$chip/sdkconfig ] || idf.py -B build/$chip -D SDKCONFIG=build/$chip/sdkconfig set-target $chip >/dev/null
      # reconfigure: the version is read at configure time, and a quick rebuild would keep the old one
      idf.py -B build/$chip -D SDKCONFIG=build/$chip/sdkconfig reconfigure build
      cd build/$chip && esptool.py --chip $chip merge_bin -o ../../dist/porthub-keyboard-$chip.bin @flash_args"
  ls -l "dist/porthub-keyboard-$chip.bin"
done
