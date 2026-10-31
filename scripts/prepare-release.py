#!/usr/bin/env python3
"""Prepare an immutable release commit; dry run unless --execute is supplied.

Main pushes advance the patch version only when the workspace version has already
been published. Explicit release tags must match the committed workspace version.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")

def numeric(value):
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        raise ValueError('Release versions must use major.minor.patch')
    return tuple(map(int, value.split('.')))

def choose_version(workspace, latest=None, tag=None):
    current = numeric(workspace)
    published = numeric(latest) if latest is not None else None
    if tag is not None:
        if tag != 'v' + workspace:
            raise ValueError('Release tag must match the committed Cargo workspace version')
        if published is not None and current < published:
            raise ValueError('Refusing to replace latest with an older release')
        return workspace
    if published is None or current > published:
        return workspace
    return '.'.join(map(str, (published[0], published[1], published[2] + 1)))

def git(root, *arguments, check=True):
    result = subprocess.run(['git', '-C', str(root), *arguments], capture_output=True, text=True)
    if check and result.returncode:
        # Git credential helpers can include credentials in diagnostics.
        raise RuntimeError('Release Git operation failed: ' + arguments[0])
    return result

def version_files(root, version):
    numeric(version)
    manifest_path, lock_path = root/'Cargo.toml', root/'Cargo.lock'
    manifest_text, lock_text = manifest_path.read_text(), lock_path.read_text()
    manifest = tomllib.loads(manifest_text)
    previous = manifest['workspace']['package']['version']
    names = set()
    for member in manifest['workspace']['members']:
        for path in root.glob(member):
            package = tomllib.loads((path/'Cargo.toml').read_text())['package']
            if package.get('version') == {'workspace': True}:
                names.add(package['name'])
    section = re.search(r'(?ms)^\[workspace\.package\]\s*\n(.*?)(?=^\[|\Z)', manifest_text)
    if section is None or not names:
        raise ValueError('Workspace release manifests are unavailable')
    body, count = re.subn(r'(?m)^version = "' + re.escape(previous) + r'"$',
                         'version = "' + version + '"', section.group(1), count=1)
    if count != 1:
        raise ValueError('Workspace release version is unavailable')
    updated = manifest_text[:section.start(1)] + body + manifest_text[section.end(1):]
    blocks = re.split(r'(?m)(?=^\[\[package\]\]$)', lock_text)
    changed = set()
    for index, block in enumerate(blocks):
        if not block.startswith('[[package]]'):
            continue
        package = tomllib.loads(block)['package'][0]
        if package['name'] not in names or package.get('source') is not None:
            continue
        if package['name'] in changed or package['version'] != previous:
            raise ValueError('Workspace lockfile release versions disagree')
        blocks[index], found = re.subn(r'(?m)^version = "' + re.escape(previous) + r'"$',
                                      'version = "' + version + '"', block, count=1)
        if found != 1:
            raise ValueError('Workspace lockfile version unavailable')
        changed.add(package['name'])
    if changed != names:
        raise ValueError('Workspace lockfile is missing release packages')
    return {manifest_path: updated, lock_path: ''.join(blocks)}

def replace(path, text):
    with tempfile.NamedTemporaryFile(mode='w', prefix='.release-version-', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(path.stat().st_mode & 0o777)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

def remote_head(root, branch):
    output = git(root, 'ls-remote', 'origin', 'refs/heads/' + branch).stdout.split()
    if len(output) != 2 or not re.fullmatch(r'[0-9a-f]{40}', output[0]):
        raise ValueError('Default branch source is unavailable')
    return output[0]

def prepare(root, ref, trigger_sha, latest=None, branch='main', execute=False):
    if not re.fullmatch(r'[0-9a-f]{40}', trigger_sha):
        raise ValueError('A full source revision is required')
    root = Path(root).resolve()
    head = git(root, 'rev-parse', 'HEAD').stdout.strip()
    trigger = git(root, 'rev-parse', trigger_sha + '^{commit}').stdout.strip()
    if head != trigger or git(root, 'status', '--porcelain', '--untracked-files=no').stdout:
        raise ValueError('Release preparation requires an unchanged checkout of the trigger commit')
    if ref != 'refs/heads/' + branch and not ref.startswith('refs/tags/v'):
        raise ValueError('Only the default branch or an explicit release tag can publish')
    workspace = tomllib.loads((root/'Cargo.toml').read_text())['workspace']['package']['version']
    latest_version = None
    latest_commit = None
    if latest is not None:
        if latest.get('draft') or latest.get('prerelease') or not latest.get('tag_name', '').startswith('v'):
            raise ValueError('Latest release metadata is not a stable numeric version')
        latest_version = latest['tag_name'][1:]
        numeric(latest_version)
        latest_commit = git(root, 'rev-parse', 'refs/tags/' + latest['tag_name'] + '^{commit}').stdout.strip()
        if git(root, 'merge-base', '--is-ancestor', latest_commit, head, check=False).returncode:
            raise ValueError('Latest release source must remain in the new release history')
    tag = ref.removeprefix('refs/tags/') if ref.startswith('refs/tags/') else None
    version = choose_version(workspace, latest_version, tag)
    result = {'version': version, 'revision': head, 'tag': 'v' + version,
              'skip': False, 'already_published': False, 'would_commit': version != workspace}
    if latest_commit == head and latest_version == workspace:
        result.update(version=workspace, tag='v'+workspace, already_published=True, would_commit=False)
        return result
    if tag is not None:
        if latest_version == version:
            raise ValueError('Published versions cannot be reused for different source')
        return result
    if remote_head(root, branch) != head:
        result['skip'] = True
        return result
    if not execute or version == workspace:
        return result
    updates = version_files(root, version)  # Validate both files before changing either.
    for path, text in updates.items():
        replace(path, text)
    git(root, 'config', 'user.name', 'github-actions[bot]')
    git(root, 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    git(root, 'add', '--', 'Cargo.toml', 'Cargo.lock')
    git(root, 'commit', '-m', 'chore(release): ' + version + ' [skip ci]')
    prepared = git(root, 'rev-parse', 'HEAD').stdout.strip()
    pushed = git(root, 'push', 'origin', 'HEAD:refs/heads/' + branch, check=False)
    if pushed.returncode:
        if remote_head(root, branch) != head:
            result['skip'] = True
            return result
        raise RuntimeError('Release version push failed; check default-branch push permissions')
    result['revision'] = prepared
    return result

def latest_release(repository):
    if not isinstance(repository,str) or not re.fullmatch(r'[\w.-]+/[\w.-]+', repository):
        raise ValueError('Invalid release repository')
    result = subprocess.run(['gh', 'api', 'repos/'+repository+'/releases/latest'], capture_output=True, text=True)
    if result.returncode:
        if 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError('Latest release lookup failed; no source was changed')
    return json.loads(result.stdout)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--ref', default=os.environ.get('GITHUB_REF'))
    parser.add_argument('--trigger-sha', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--default-branch', default='main')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if not args.ref or not args.trigger_sha or not args.repository:
        parser.error('repository, ref and trigger SHA are required')
    result = prepare(args.root, args.ref, args.trigger_sha, latest_release(args.repository), args.default_branch, args.execute)
    print(json.dumps(result, sort_keys=True))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            for key, value in result.items():
                output.write(key+'='+str(value).lower()+'\n')

if __name__ == '__main__':
    main()
