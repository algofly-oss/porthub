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
  'compiler': 'i686-linux-gnu-gcc',
  'ar': 'i686-linux-gnu-ar',
  'packages': 'gcc-i686-linux-gnu libc6-dev-i386-cross'},
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

def select(selected, core_only=False, root=None, source=None, depot='', stage=None, restore_fn=None, wait_seconds=0):
    valid = {item['artifact'] for item in NATIVE + LINUX_32}
    requested = set((selected or 'all').split(','))
    if not requested or not requested <= valid | {'all','windows'}:
        raise ValueError('Unknown agent platform')
    def wanted(item): return 'all' in requested or item['artifact'] in requested or 'windows' in requested and item['artifact'].startswith('windows_')
    native=[dict(item) for item in NATIVE if wanted(item)]
    local=[]
    if core_only and depot:
        import importlib.util
        spec=importlib.util.spec_from_file_location('local_core_lane',Path(__file__).with_name('local-core-lane.py'))
        lane=importlib.util.module_from_spec(spec);spec.loader.exec_module(lane)
        restore_fn=restore_fn or lane.restore
        import time
        deadline=time.monotonic()+max(0,min(1800,wait_seconds))
        candidates=[item for item in native if item['target'] in lane.load('native-core-validation').SUPPORTED]
        while candidates:
            for item in list(candidates):
                try:
                    if restore_fn(root,source,item['target'],depot,stage/item['artifact']):
                        native.remove(item);local.append(item);candidates.remove(item)
                except Exception:
                    # Missing, offline or invalid proof never removes a native
                    # check. Retry only within the configured handoff deadline.
                    continue
            remaining=deadline-time.monotonic()
            if remaining<=0 or not candidates: break
            time.sleep(min(15,remaining))
    return {'native':native,'linux':[dict(item) for item in LINUX_32 if wanted(item)],'local_native':local}


def main():
    import subprocess
    root=Path(__file__).resolve().parents[1]
    source=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    selected=select(os.environ.get('PORTHUB_BUILD_PLATFORM','all'),
        core_only=os.environ.get('PORTHUB_CORE_ONLY')=='true' and os.environ.get('PORTHUB_VERIFY_ONLY')!='true',
        root=root,source=source,depot=os.environ.get('PORTHUB_LOCAL_DEPOT',''),stage=root/'local-core-native',wait_seconds=int(os.environ.get('PORTHUB_LOCAL_CORE_WAIT_SECONDS','0')))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        for key,matrix in selected.items():
            output.write(f'{key}={json.dumps(matrix)}\n')
            output.write(f'has_{key}={str(bool(matrix)).lower()}\n')


if __name__=='__main__': main()
