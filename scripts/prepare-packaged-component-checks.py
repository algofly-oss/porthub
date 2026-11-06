#!/usr/bin/env python3
"""Prepare native lifecycle checks against exact packaged core/helper binaries."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


coordinator = load('platform_coordinator', 'build-component-platform.py')
fixture = load('component_fixture', 'seed-component-fixture.py')


def prepare(builds, core_output, cache):
    index = json.loads((builds/'index.json').read_text())
    target = index['target']
    verified = coordinator.previous_builds(builds, target, index)
    cores = [row for (tool, _), row in verified.items() if tool == 'core']
    if len(cores) != 1:
        raise ValueError('Native checks require exactly one verified core')
    core, executable = cores[0]
    inputs = []
    for tool in ('stats', 'sync', 'terminal', 'tor'):
        candidates = [row for (name, _), row in verified.items() if name == tool]
        if not candidates:
            raise ValueError('Native checks require every optional packaged tool')
        receipt, binary = max(candidates, key=lambda row: coordinator.planner.stable_version(row[0]['version']))
        inputs.append((tool,binary))
    if core_output.exists() or core_output.is_symlink():
        raise ValueError('Packaged core check output must be a new file')
    fixture.seed(cache,target,core['version'],core['source_revision'],inputs)
    core_output.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(executable,core_output); core_output.chmod(0o755)
    coordinator.planner.verify_reuse(core,core_output)
    return {'PORTHUB_TEST_AGENT_EXECUTABLE':str(core_output.resolve()),
            'PORTHUB_TEST_SYNC_EXECUTABLE':str(dict(inputs)['sync'].resolve()),
            'PORTHUB_COMPONENT_CACHE':str(cache.resolve()),
            'PORTHUB_COMPONENT_SHARED_CACHE':'off','PORTHUB_COMPONENT_SOURCE':'github'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builds',required=True,type=Path)
    parser.add_argument('--core-output',required=True,type=Path)
    parser.add_argument('--cache',required=True,type=Path)
    args=parser.parse_args()
    environment=prepare(args.builds,args.core_output,args.cache)
    if os.environ.get('GITHUB_ENV'):
        with open(os.environ['GITHUB_ENV'],'a') as output:
            for key,value in environment.items():
                if '\n' in value or '\r' in value:
                    raise ValueError('Unsafe native check environment path')
                output.write(key+'='+value+'\n')
    print('Native checks prepared against exact verified packaged binaries')


if __name__=='__main__': main()
