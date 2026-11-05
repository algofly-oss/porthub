#!/usr/bin/env python3
"""Plan or execute independent Cargo builds, reusing verified recovered binaries."""
import argparse
import importlib.util
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import tempfile

spec = importlib.util.spec_from_file_location('component_planner', Path(__file__).with_name('component-build-plan.py'))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def previous_builds(directory, target):
    if directory is None:
        return {}
    directory = directory.resolve(strict=True)
    index_path = directory/'index.json'
    if index_path.is_symlink() or index_path.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid recovered build index')
    index = json.loads(index_path.read_text())
    if index.get('schema_version') != 1 or index.get('target') != target:
        raise ValueError('Recovered build index target or schema mismatch')
    builds = index.get('builds')
    if not isinstance(builds, list) or len(builds) > 128:
        raise ValueError('Invalid recovered build list')
    result = {}
    for row in builds:
        paths = []
        for key in ('receipt', 'binary'):
            relative = PurePosixPath(row[key])
            if relative.is_absolute() or '..' in relative.parts or '\\' in row[key] or ':' in row[key]:
                raise ValueError('Unsafe recovered build path')
            path = directory
            for part in relative.parts:
                path = path/part
                if path.is_symlink():
                    raise ValueError('Recovered build paths cannot contain symlinks')
            planner.relative(directory, path)
            if not path.is_file():
                raise ValueError('Recovered build input is not a regular file')
            paths.append(path)
        receipt_path, binary = paths
        receipt = planner.read_receipt(receipt_path)
        if receipt['tool'] != row['tool'] or receipt['version'] != row['version'] or receipt['target'] != target:
            raise ValueError('Recovered build index differs from receipt')
        if not re.fullmatch(r'[a-z][a-z0-9_-]*', receipt['tool']) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', receipt['binary']['name']):
            raise ValueError('Unsafe recovered tool or executable identity')
        planner.verify_reuse(receipt, binary)
        identity = (row['tool'], row['version'])
        if identity in result:
            raise ValueError('Duplicate recovered build identity')
        result[identity] = (receipt, binary)
    return result


def run(root, target, revision, output=None, previous=None, tools=None):
    root = root.resolve()
    planner.require_clean_source(root, revision)
    recipes = planner.read_recipes(root)
    selected = sorted(tools if tools is not None else recipes)
    if not selected or len(set(selected)) != len(selected) or any(tool not in recipes for tool in selected):
        raise ValueError('Select unique configured tools')
    for tool in selected:
        if not re.fullmatch(r'[a-z][a-z0-9_-]*', tool) or not re.fullmatch(r'[a-z][a-z0-9_-]*', recipes[tool]['binary']):
            raise ValueError('Unsafe configured tool or executable name')
    old = previous_builds(previous, target)
    choices = []
    inputs = {}
    for tool in selected:
        candidates = [(receipt, binary) for (name, _), (receipt, binary) in old.items() if name == tool]
        latest = max(candidates, key=lambda row: planner.stable_version(row[0]['version']), default=None)
        choice = planner.plan(root, tool, target, latest[0] if latest else None)
        choices.append(choice)
        if choice['action'] == 'reuse':
            inputs[tool] = latest
    if output is None:
        return choices
    if output.exists() or output.is_symlink():
        raise ValueError('Build output must be a new directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.porthub-build-', dir=output.parent) as temporary:
        stage = Path(temporary)/'builds'; stage.mkdir()
        index = []
        for choice in choices:
            tool, version = choice['tool'], choice['version']
            folder = stage/tool/version; folder.mkdir(parents=True)
            filename = recipes[tool]['binary'] + ('.exe' if 'windows' in target else '')
            binary = folder/filename
            if choice['action'] == 'reuse':
                receipt, source = inputs[tool]
                planner.verify_reuse(receipt, source)
                shutil.copyfile(source, binary); binary.chmod(0o755)
                planner.verify_reuse(receipt, binary)
            else:
                # Each tool gets its own Cargo invocation, avoiding feature
                # unification that would pull optional dependencies into core.
                receipt = planner.build_and_record(root, tool, target, revision, version, binary)
            if receipt['tool'] != tool or receipt['version'] != version or receipt['target'] != target:
                raise ValueError('Build result differs from selected identity')
            planner.verify_reuse(receipt, binary)
            receipt_path = folder/'build-receipt.json'
            receipt_path.write_bytes(planner.canonical(receipt)+b'\n')
            receipt_path.chmod(0o644)
            index.append({'tool': tool, 'version': version, 'receipt': receipt_path.relative_to(stage).as_posix(),
                          'binary': binary.relative_to(stage).as_posix(), 'action': choice['action']})
        # Keep older helper versions available for activated fallback and older
        # compatible cores after the latest-only release pruning policy runs.
        emitted = {(row['tool'], row['version']) for row in index}
        for (tool, version), (receipt, source) in sorted(old.items()):
            if tool == 'core' or tool not in selected or (tool, version) in emitted:
                continue
            folder = stage/tool/version; folder.mkdir(parents=True)
            binary = folder/receipt['binary']['name']
            planner.verify_reuse(receipt, source)
            shutil.copyfile(source, binary); binary.chmod(0o755)
            planner.verify_reuse(receipt, binary)
            receipt_path = folder/'build-receipt.json'
            receipt_path.write_bytes(planner.canonical(receipt)+b'\n')
            receipt_path.chmod(0o644)
            index.append({'tool': tool, 'version': version, 'receipt': receipt_path.relative_to(stage).as_posix(),
                          'binary': binary.relative_to(stage).as_posix(), 'action': 'retain'})
        planner.require_clean_source(root, revision)
        (stage/'index.json').write_bytes(planner.canonical({'schema_version': 1, 'target': target, 'builds': index})+b'\n')
        stage.rename(output)
    return choices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--target', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--tool', action='append')
    parser.add_argument('--output', type=Path, help='Execute and atomically publish selected builds; otherwise only plan')
    args = parser.parse_args()
    print(json.dumps(run(args.root, args.target, args.source_revision, args.output, args.previous, args.tool), sort_keys=True))


if __name__ == '__main__':
    main()
