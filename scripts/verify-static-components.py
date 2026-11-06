#!/usr/bin/env python3
"""Reject Linux release components that depend on a host dynamic loader/libraries."""
import argparse
import importlib.util
from pathlib import Path
import json
import subprocess

spec=importlib.util.spec_from_file_location('component_coordinator',Path(__file__).with_name('build-component-platform.py'))
coordinator=importlib.util.module_from_spec(spec);spec.loader.exec_module(coordinator)


def verify_binary(binary):
    for arguments, forbidden in [(['--program-headers','--wide'],'INTERP'), (['--dynamic','--wide'],'(NEEDED)')]:
        result=subprocess.run(['readelf',*arguments,str(binary)],capture_output=True,text=True,timeout=15)
        if result.returncode or forbidden in result.stdout:
            raise ValueError('Linux component must be a valid ELF executable with no dynamic loader or shared-library dependencies')


def verify(builds):
    index=json.loads((builds/'index.json').read_text())
    target=index['target']
    if '-linux-musl' not in target:
        raise ValueError('Linux production components require a musl build target')
    entries=coordinator.previous_builds(builds,target,index)
    for _,binary in entries.values():
        verify_binary(binary)
    return len(entries)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builds',type=Path,required=True)
    args=parser.parse_args()
    print('Verified '+str(verify(args.builds))+' self-contained Linux components')


if __name__=='__main__':main()
