#!/usr/bin/env python3
"""Emit the closed optional-helper CI matrix; legacy releases remain helper-free."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

RUNNERS = {
    'x86_64-unknown-linux-gnu': ('ubuntu-24.04', 'gnu'),
    'aarch64-unknown-linux-gnu': ('ubuntu-24.04-arm', 'gnu'),
    'x86_64-pc-windows-msvc': ('windows-2025', 'windows'),
}


def prepare(root, revision, gateway, targets, previous=None, fetch=True):
    root = Path(root)
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip() != revision:
        raise ValueError('Helper job source differs from the prepared commit')
    if not (root / 'crates/porthub-media-helper/Cargo.toml').exists():
        return {'enabled': False, 'mode': 'none', 'matrix': []}
    spec = importlib.util.spec_from_file_location('optional_helper_plan', Path(__file__).with_name('media-helper-plan.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    core = tomllib.loads((root / 'crates/porthub-agent/Cargo.toml').read_text())['package']['version']
    release = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    if module.media.numeric(core) < (1, 11, 34):
        raise ValueError('A release containing media helpers requires agent >=1.11.34')
    module.media.numeric(release)
    if fetch:
        previous = module.media.fetch_catalog(gateway)
    plan = module.plan(root, revision, targets, previous)
    matrix = [{'target': target, 'runner': RUNNERS[target][0], 'kind': RUNNERS[target][1]}
              for target in plan['targets']] if plan['mode'] == 'build' else []
    return dict(plan, enabled=True, core=core, release=release, matrix=matrix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--targets', default=','.join(sorted(RUNNERS)))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plan = prepare(args.root, args.revision, args.gateway, args.targets.split(','))
    with args.output.open('x') as stream:
        json.dump(plan, stream, indent=2)
        stream.write('\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            for name, value in {'enabled': str(plan['enabled']).lower(), 'mode': plan['mode'],
                                'matrix': json.dumps(plan['matrix'], separators=(',', ':')),
                                'core': plan.get('core', ''), 'release': plan.get('release', ''),
                                'artifact_revision': plan.get('artifact_source_revision', plan.get('revision', ''))}.items():
                stream.write(name + '=' + value + '\n')


if __name__ == '__main__':
    main()
