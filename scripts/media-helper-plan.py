#!/usr/bin/env python3
"""Plan optional helper builds without changing sources or legacy catalogs.

Reuse retains the prior artifact's complete provenance. Mechanical versions of
unrelated workspace packages do not require rebuilding an unchanged helper.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tomllib


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
package = load('media_package_plan', HERE / 'package-media-helper.py')
media = load('media_release_plan', HERE / 'media-release.py')



def minimum_core(root, building_core):
    package = tomllib.loads((Path(root) / 'crates/porthub-media-helper/Cargo.toml').read_text())['package']
    metadata = package.get('metadata', {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get('porthub_media', {}), dict):
        raise ValueError('Invalid media helper compatibility metadata')
    minimum = metadata.get('porthub_media', {}).get('minimum_core', '1.11.34')
    if not (1, 11, 34) <= media.numeric(minimum) <= media.numeric(building_core):
        raise ValueError('Media helper minimum core must be >=1.11.34 and <=building core')
    return minimum


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, timeout=30)


def inputs(root, revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Exact helper source revision required')
    tree = git(root, 'ls-tree', '-rz', '--full-tree', revision, '--', *package.INPUTS)
    records = {}
    for row in tree.split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, blob = header.split()
        name = name.decode('utf-8')
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise ValueError('Helper inputs must be regular tracked files')
        size = int(git(root, 'cat-file', '-s', blob.decode()))
        if size > 8 * 1024 * 1024 or len(records) >= 2048:
            raise ValueError('Helper source input exceeds bound')
        data = git(root, 'cat-file', 'blob', blob.decode())
        if len(data) != size or sum(map(len, records.values())) + size > 32 * 1024 * 1024:
            raise ValueError('Helper source input exceeds bound')
        records[name] = data
    for name in package.INPUTS:
        if name not in records and not any(p.startswith(name + '/') for p in records):
            raise ValueError('Missing reviewed helper build input: ' + name)
    return records


def source_digest(records):
    return hashlib.sha256(canonical([
        {'path': p, 'sha256': hashlib.sha256(data).hexdigest()}
        for p, data in sorted(records.items())
    ])).hexdigest()


def helper_lock(lock):
    """Retain every locked dependency reachable on any helper platform."""
    rows = lock['package']
    roots = [p for p in rows if p['name'] == 'porthub-media-helper' and 'source' not in p]
    if len(roots) != 1:
        raise ValueError('Unambiguous locked helper package required')
    pending, result = roots[:], {}
    while pending:
        row = pending.pop()
        key = (row['name'], row['version'], row.get('source', ''))
        if key in result:
            continue
        result[key] = row
        for edge in row.get('dependencies', []):
            words = edge.split(' ', 2)
            choices = [p for p in rows if p['name'] == words[0]]
            if len(words) >= 2:
                choices = [p for p in choices if p['version'] == words[1]]
            if len(words) == 3:
                choices = [p for p in choices if p.get('source') == words[2].strip('()')]
            if len(choices) != 1:
                raise ValueError('Ambiguous locked helper dependency')
            pending.extend(choices)
    if any(key[0] in {'porthub-agent', 'porthub-api', 'porthub-edge',
                      'porthub-firewall', 'porthub-runtime'} for key in result):
        raise ValueError('Helper unexpectedly depends on a versioned service')
    if any(not key[2] and key[0] not in {'porthub-media-helper', 'porthub-components'}
           for key in result):
        raise ValueError('Local helper dependency is outside reviewed source inputs')
    return {'version': lock.get('version'), 'package': [result[k] for k in sorted(result)]}


def semantic_digest(records):
    # These packages have independent versions; otherwise workspace.version
    # could affect their compiled code and must not be ignored.
    for name in ['crates/porthub-media-helper/Cargo.toml', 'crates/porthub-components/Cargo.toml']:
        if not isinstance(tomllib.loads(records[name].decode())['package']['version'], str):
            raise ValueError('Helper packages require independent explicit versions')
    normalized = dict(records)
    workspace = tomllib.loads(records['Cargo.toml'].decode())
    workspace['workspace']['package'].pop('version', None)
    normalized['Cargo.toml'] = canonical(workspace)
    normalized['Cargo.lock'] = canonical(helper_lock(tomllib.loads(records['Cargo.lock'].decode())))
    return source_digest(normalized)


def plan(root, revision, targets, previous=None):
    root = Path(root)
    if git(root, 'rev-parse', 'HEAD').decode().strip() != revision:
        raise ValueError('Checkout differs from reviewed helper source')
    if git(root, 'status', '--porcelain', '--untracked-files=all', '--', *package.INPUTS):
        raise ValueError('Helper build inputs must be committed and unchanged')
    current = inputs(root, revision)
    lock = helper_lock(tomllib.loads(current['Cargo.lock'].decode()))
    version = tomllib.loads(current['crates/porthub-media-helper/Cargo.toml'].decode())['package']['version']
    media.numeric(version)
    if not any(p['name'] == 'porthub-media-helper' and p['version'] == version
               for p in lock['package']):
        raise ValueError('Helper manifest and lock versions differ')
    targets = set(targets)
    if not media.GNU <= targets or not targets <= media.TARGETS:
        raise ValueError('Both GNU helpers and only known optional targets are required')
    output = {'mode': 'build', 'version': version, 'revision': revision,
              'build_inputs': source_digest(current), 'targets': sorted(targets)}
    if previous is None:
        return output
    previous = media.parse(canonical(previous), previous['release'])
    old = previous['artifacts'][0]
    if media.numeric(version) < media.numeric(old['version']):
        raise ValueError('Helper version downgrade rejected')
    if version != old['version']:
        return output
    if targets != {a['target'] for a in previous['artifacts']}:
        raise ValueError('Bump helper version before changing published platforms')
    prior = inputs(root, old['source_revision'])
    if source_digest(prior) != old['build_inputs']:
        raise ValueError('Prior helper source does not match its published provenance')
    if semantic_digest(current) != semantic_digest(prior):
        raise ValueError('Bump helper version before changing its build inputs')
    output.update(mode='reuse', manifest=previous, build_inputs=old['build_inputs'],
                  artifact_source_revision=old['source_revision'])
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=HERE.parent)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--target', action='append', required=True, choices=sorted(media.TARGETS))
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = plan(args.root, args.revision, args.target, media.fetch_catalog(args.gateway))
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print('Optional helper plan: ' + value['mode'])


if __name__ == '__main__':
    main()
