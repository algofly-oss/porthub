#!/usr/bin/env python3
"""Build verified release components on the current native host; never publish."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_target(system, machine):
    arch = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}.get(machine.lower())
    suffix = {'Linux': 'unknown-linux-musl', 'Darwin': 'apple-darwin', 'Windows': 'pc-windows-msvc'}.get(system)
    if not arch or not suffix:
        raise ValueError('Unsupported native build host')
    return arch + '-' + suffix


def run(root, revision, output, execute=False, tools=None, previous=None):
    builder = load('build-component-platform')
    planner = builder.planner
    root = root.resolve()
    if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise ValueError('Use the full lowercase source commit SHA')
    planner.require_clean_source(root, revision)
    target = native_target(platform.system(), platform.machine())
    environment = planner.shipping_environment(root, target)
    if environment is None:
        raise ValueError('Native target lacks a shipping recipe')
    selected = tools or sorted(planner.read_recipes(root))
    if not selected or len(set(selected)) != len(selected) or any(t not in planner.read_recipes(root) for t in selected):
        raise ValueError('Select unique configured tools')
    if output.exists() or output.is_symlink():
        raise ValueError('Output must be a new directory')
    plan = {'schema_version': 1, 'source_revision': revision, 'target': target,
            'tools': selected, 'output': str(output.resolve()), 'execute': execute,
            'shipping_environment': environment, 'publishes': False}
    if not execute:
        return plan
    old_environment = os.environ.copy()
    try:
        # The underlying recorder rejects unknown compiler overrides. Do not
        # silently erase inherited flags to make an untrusted build look clean.
        for key, value in environment.items():
            if os.environ.get(key) not in (None, '', value):
                raise ValueError('Conflicting shipping compiler setting: ' + key)
            os.environ[key] = value
        if platform.system() != 'Windows' and 'terminal' in selected:
            terminal = subprocess.run([sys.executable, str(root/'scripts/build-terminal-helper.py'), '--target', target],
                                      cwd=root, check=True, capture_output=True, text=True)
            bundle = terminal.stdout.strip().splitlines()[-1]
            if not Path(bundle).is_file():
                raise ValueError('Terminal builder did not return a bundle file')
            os.environ['PORTHUB_TERMINAL_BUNDLE'] = bundle
        builder.run(root, target, revision, output, previous, selected)
        # Verify every resulting binary against the existing raw-hash/size receipt
        # contract, including retained/reused artifacts, before declaring success.
        verified = builder.previous_builds(output, target)
        plan['verified_builds'] = len(verified)
        return plan
    finally:
        os.environ.clear()
        os.environ.update(old_environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tool', action='append')
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.root, args.source_revision, args.output, args.execute, args.tool, args.previous), sort_keys=True))


if __name__ == '__main__':
    main()
