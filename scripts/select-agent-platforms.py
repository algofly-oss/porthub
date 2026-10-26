#!/usr/bin/env python3
"""Select agent build platforms without rebuilding successful unrelated targets."""
import json
import os
from pathlib import Path

NATIVE = [{'os': 'ubuntu-24.04',
  'target': 'x86_64-unknown-linux-gnu',
  'artifact': 'x86_64',
  'extension': ''},
 {'os': 'ubuntu-24.04-arm',
  'target': 'aarch64-unknown-linux-gnu',
  'artifact': 'arm64',
  'extension': ''},
 {'os': 'macos-15-intel',
  'target': 'x86_64-apple-darwin',
  'artifact': 'darwin_x86_64',
  'extension': ''},
 {'os': 'macos-15', 'target': 'aarch64-apple-darwin', 'artifact': 'darwin_arm64', 'extension': ''},
 {'os': 'windows-latest',
  'target': 'x86_64-pc-windows-msvc',
  'artifact': 'windows_x86_64',
  'extension': '.exe'},
 {'os': 'windows-11-arm',
  'target': 'aarch64-pc-windows-msvc',
  'artifact': 'windows_arm64',
  'extension': '.exe'},
 {'os': 'windows-latest',
  'target': 'i686-pc-windows-msvc',
  'artifact': 'windows_x86',
  'extension': '.exe'}]
LINUX_32 = [{'target': 'i686-unknown-linux-gnu',
  'artifact': 'x86',
  'compiler': 'gcc',
  'ar': 'ar',
  'packages': 'gcc-multilib'},
 {'target': 'armv7-unknown-linux-gnueabihf',
  'artifact': 'armv7',
  'compiler': 'arm-linux-gnueabihf-gcc',
  'ar': 'arm-linux-gnueabihf-ar',
  'packages': 'gcc-arm-linux-gnueabihf libc6-dev-armhf-cross'},
 {'target': 'arm-unknown-linux-gnueabihf',
  'artifact': 'armhf',
  'compiler': 'arm-linux-gnueabihf-gcc',
  'ar': 'arm-linux-gnueabihf-ar',
  'packages': 'gcc-arm-linux-gnueabihf libc6-dev-armhf-cross'}]

selected = os.environ.get("PORTHUB_BUILD_PLATFORM", "all") or "all"
valid = {item["artifact"] for item in NATIVE + LINUX_32}
if selected not in {"all", "windows"} and selected not in valid:
    raise SystemExit("Unknown agent platform")
with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
    for key, values in (("native", NATIVE), ("linux", LINUX_32)):
        matrix = [item for item in values if selected in ("all", item["artifact"]) or selected == "windows" and item["artifact"].startswith("windows_")]
        output.write(f"{key}={json.dumps(matrix)}\n")
        output.write(f"has_{key}={str(bool(matrix)).lower()}\n")
