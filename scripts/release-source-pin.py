#!/usr/bin/env python3
"""Create-only temporary source tags; no branch creation or version-tag moves."""
import argparse
import json
import os
import re
import subprocess
from urllib.parse import quote

PREFIX = 'porthub-prepared/'
VERSION = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
PIN = re.compile(r'^refs/tags/' + PREFIX + r'v(' + VERSION + r')$')


def numeric(version):
    if not re.fullmatch(VERSION, version):
        raise ValueError('Numeric release version required')
    return tuple(map(int, version.split('.')))


def name(version, source):
    numeric(version)
    if not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('Immutable source required')
    return 'refs/tags/' + PREFIX + 'v' + version


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository or ''):
            raise ValueError('Explicit repository required')
        self.repository = repository
        self.prefix = 'repos/' + repository

    def api(self, path, method='GET', fields=()):
        argv = ['gh', 'api', '--method', method, self.prefix + path]
        for key, value in fields:
            argv += ['-f', key + '=' + value]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if result.returncode:
            if method == 'GET' and 'HTTP 404' in result.stderr:
                return None
            raise RuntimeError('GitHub source pin operation failed: ' + method)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def ref(self, ref):
        return self.api('/git/ref/' + quote(ref.removeprefix('refs/'), safe='/'))

    def commit(self, ref):
        row = self.ref(ref)
        if row is None:
            return None
        obj = row['object']
        for _ in range(4):
            if obj['type'] == 'commit':
                return obj['sha']
            if obj['type'] != 'tag':
                break
            obj = self.api('/git/tags/' + obj['sha'])['object']
        raise ValueError('Version tag does not resolve to a commit')

    def create(self, ref, source):
        # POST can only create a missing ref: never PATCH or force-update a tag.
        return self.api('/git/refs', 'POST', [('ref', ref), ('sha', source)])

    def delete(self, ref, expected):
        remote = subprocess.run(['git', 'remote', 'get-url', 'origin'], capture_output=True, text=True, timeout=10)
        allowed = ('https://github.com/' + self.repository, 'git@github.com:' + self.repository)
        if remote.returncode or remote.stdout.strip().removesuffix('.git') not in allowed:
            raise ValueError('Pin cleanup requires the exact repository origin')
        conditional_delete(ref, expected)


    def pins(self):
        return self.api('/git/matching-refs/tags/' + PREFIX) or []

    def latest(self):
        return self.api('/releases/latest')

    def contains(self, older, current):
        return older == current or self.api('/compare/' + older + '...' + current)['status'] in ('ahead', 'identical')


def conditional_delete(ref, expected, cwd=None):
    if not PIN.fullmatch(ref) or not re.fullmatch('[a-f0-9]{40}', expected):
        raise ValueError('Only exact prepared tag deletion is supported')
    result = subprocess.run(['git', 'push', '--porcelain', '--force-with-lease=' + ref + ':' + expected,
                             'origin', ':' + ref], cwd=cwd, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Source pin conditional deletion deferred; no tag update attempted')


def check_reference(github, version, source, branch='main'):
    ref = name(version, source)
    target = github.commit('refs/tags/v' + version)
    if target is not None:
        if target != source:
            raise ValueError('Version tag source mismatch')
        return 'version-tag'
    row = github.ref(ref)
    if row is not None:
        if row.get('object', {}).get('type') != 'commit' or row['object'].get('sha') != source:
            raise ValueError('Prepared source tag mismatch')
        return 'prepared-tag'
    if github.commit('refs/heads/' + branch) == source:
        return 'main-head'
    raise ValueError('Unreferenced release source: reserve its prepared tag before builds; token workflow permission is intentionally not expanded')


def pins(github):
    rows = github.pins()
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError('Bounded source-pin inventory exceeded')
    result = []
    versions = {}
    for row in rows:
        match = PIN.fullmatch(row.get('ref', ''))
        if not match:
            raise ValueError('Unexpected prepared-source tag')
        version, source = match[1], row.get('object', {}).get('sha', '')
        if row.get('object', {}).get('type') != 'commit' or not re.fullmatch('[a-f0-9]{40}', source):
            raise ValueError('Prepared-source tag identity mismatch')
        if version in versions and versions[version] != source:
            raise ValueError('Different sources reserved one release version')
        versions[version] = source
        result.append(dict(version=version, source=source, ref=row['ref']))
    return result


def reservations(github, releases):
    result = list(releases)
    existing = {row['tag_name']: row for row in releases}
    for pin in pins(github):
        tag = 'v' + pin['version']
        if tag in existing:
            row = existing[tag]
            if row.get('draft') and row.get('target_commitish') != pin['source']:
                raise ValueError('Draft and prepared source reservations disagree')
            continue
        result.append(dict(tag_name=tag, draft=True, prerelease=False, target_commitish=pin['source']))
    return result


def reserve(github, version, source, branch='main', execute=False):
    ref = name(version, source)
    version_source = github.commit('refs/tags/v' + version)
    if version_source is not None:
        if version_source != source:
            raise ValueError('Version tag already points to different source')
        return dict(status='version-tag-present', ref=ref)
    row = github.ref(ref)
    if row is not None:
        if row.get('ref') != ref or row.get('object', {}).get('type') != 'commit' or row['object'].get('sha') != source:
            raise ValueError('Prepared source tag cannot be moved')
        return dict(status='already-pinned', ref=ref)
    if len(pins(github)) >= 256:
        raise ValueError('Prepared source pin capacity reached; cleanup superseded reservations first')
    if github.commit('refs/heads/' + branch) != source:
        raise ValueError('Prepared source is no longer main head and has no existing pin; rebuild preparation or use verified operator recovery')
    if not execute:
        return dict(status='ready', ref=ref)
    try:
        github.create(ref, source)
    except RuntimeError:
        row = github.ref(ref)  # A simultaneous identical reservation is safe.
        if row is None or row.get('object', {}).get('type') != 'commit' or row['object'].get('sha') != source:
            raise
    row = github.ref(ref)
    if row is None or row.get('ref') != ref or row.get('object', {}).get('type') != 'commit' or row['object'].get('sha') != source:
        raise ValueError('Prepared source pin readback failed')
    return dict(status='pinned', ref=ref)


def cleanup(github, version, source, execute=False):
    name(version, source)
    def verify():
        row = github.latest()
        if not row or row.get('tag_name') != 'v' + version or row.get('draft') or row.get('prerelease') or github.commit('refs/tags/v' + version) != source:
            raise ValueError('Source pins require the exact latest verified stable version tag before cleanup')
    verify()
    selected = [row for row in pins(github) if numeric(row['version']) < numeric(version) or row['version'] == version and row['source'] == source]
    retained = []
    for row in selected:
        if not github.contains(row['source'], source):
            retained.append(row['ref'])
            continue
        verify()
        current = github.ref(row['ref'])
        if current is None:
            continue
        if current.get('object', {}).get('type') != 'commit' or current['object'].get('sha') != row['source']:
            raise ValueError('Prepared source tag changed before cleanup')
        if execute:
            github.delete(row['ref'], row['source'])
    return dict(status='cleaned' if execute else 'ready', pins=[row['ref'] for row in selected if row['ref'] not in retained], retained=retained)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('reserve', 'cleanup'))
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--default-branch', default='main')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    github = GitHub(args.repository)
    result = reserve(github, args.version, args.revision, args.default_branch, args.execute) if args.mode == 'reserve' else cleanup(github, args.version, args.revision, args.execute)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
