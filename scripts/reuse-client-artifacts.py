#!/usr/bin/env python3
"""Reuse successful client packages only when their production inputs are identical."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('stage', ROOT / 'scripts/stage-verified-release.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
INPUTS = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo', 'crates', 'vendor',
          'scripts/build-agent-linux.sh', 'scripts/build-terminal-helper.py',
          'scripts/release-version.sh', 'scripts/select-agent-platforms.py',
          'deploy/components.toml', 'deploy/component-platforms.toml',
          'scripts/component-build-plan.py', 'scripts/build-component-platform.py',
          'scripts/prepare-packaged-component-checks.py', 'scripts/seed-component-fixture.py',
          'scripts/verify-static-components.py']


def git(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=ROOT)


def recipe(workflow):
    # Whole native/cross jobs include compiler flags, toolchain installation,
    # environment, packaging and platform checks. Selection/reuse cannot hide a
    # changed build recipe. Global compiler environment/defaults count too.
    sections = []
    for name, indent in [('env', ''), ('defaults', ''), ('native', '  '), ('linux-32', '  ')]:
        match = re.search(r'(?ms)^' + indent + name + r':\n(.*?)(?=^' + indent + r'[A-Za-z][\w-]*:|\Z)', workflow)
        if name in ('native', 'linux-32') and match is None:
            raise ValueError('Client build recipe is missing')
        sections.append(match.group(0) if match else '')
    return '\n'.join(sections)


def fingerprint(revision):
    listing = git('ls-tree', '-r', revision, '--', *INPUTS)
    if not listing:
        raise ValueError('Client production input tree is missing')
    workflow = git('show', revision + ':.github/workflows/agent-platforms.yml').decode()
    return hashlib.sha256(listing + recipe(workflow).encode()).hexdigest()


def matrices():
    tree = ast.parse((ROOT / 'scripts/select-agent-platforms.py').read_text())
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id in ('NATIVE', 'LINUX_32')}
    return values['NATIVE'], values['LINUX_32']


def retained(run, jobs, artifacts, repository, native, cross):
    if (run.get('status') != 'completed' or run.get('conclusion') not in ('success', 'failure')
            or run.get('event') != 'workflow_dispatch'
            or run.get('path') != '.github/workflows/agent-platforms.yml'
            or (run.get('head_repository') or {}).get('full_name') != repository
            or not re.fullmatch('[a-f0-9]{40}', run.get('head_sha', ''))):
        raise ValueError('Reuse requires a completed native-platform run in this repository')
    selected = []
    for platform in native + cross:
        name = platform['artifact']
        def matches(job):
            return job.get('name') == name if platform in native else job.get('name', '').startswith(
                'linux-32 (' + platform['target'] + ', ' + name + ',')
        successful = [job for job in jobs if matches(job) and job.get('status') == 'completed'
                      and job.get('conclusion') == 'success']
        candidates = [item for item in artifacts if item.get('name') == 'porthub-' + name]
        if not successful or not candidates:
            continue
        if len(successful) != 1 or len(candidates) != 1:
            raise ValueError('Ambiguous platform artifact provenance')
        artifact = candidates[0]
        source = artifact.get('workflow_run') or {}
        if (artifact.get('expired') or source.get('id') != run['id']
                or source.get('head_sha') != run['head_sha']
                or not isinstance(artifact.get('id'), int) or artifact['id'] <= 0
                or not isinstance(artifact.get('size_in_bytes'), int)
                or not 0 < artifact['size_in_bytes'] <= 256 * 1024 * 1024
                or not re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', ''))):
            raise ValueError('Reusable artifact identity, digest, size or expiry is invalid')
        selected.append(dict(platform=name, id=artifact['id'], digest=artifact['digest'],
                             size=artifact['size_in_bytes']))
    return selected


def plan(repository, run_id):
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository) or not re.fullmatch('[1-9][0-9]*', str(run_id)):
        raise ValueError('Explicit repository and source run are required')
    prefix = '/actions/runs/' + str(run_id)
    run = stage.api(repository, prefix)
    native, cross = matrices()
    selected = retained(run, stage.pages(repository, prefix + '/jobs', 'jobs'),
                        stage.pages(repository, prefix + '/artifacts', 'artifacts'), repository, native, cross)
    if git('status', '--porcelain', '--untracked-files=no').strip():
        raise ValueError('Artifact reuse requires an unchanged source checkout')
    revision = git('rev-parse', 'HEAD').decode().strip()
    subprocess.run(['git', 'merge-base', '--is-ancestor', run['head_sha'], revision], cwd=ROOT, check=True)
    source = fingerprint(run['head_sha'])
    if source != fingerprint(revision):
        raise ValueError('Production sources or client build recipes changed; rebuild all platforms')
    if not selected:
        raise ValueError('No successfully verified client artifacts can be reused')
    return dict(repository=repository, run=int(run_id), source_revision=run['head_sha'],
                revision=revision, production_fingerprint=source, retained=selected)


def extract(archive, item, destination):
    if archive.stat().st_size != item['size'] or 'sha256:' + hashlib.sha256(archive.read_bytes()).hexdigest() != item['digest']:
        raise ValueError('Reusable artifact does not match GitHub digest and size')
    asset = 'porthub-' + item['platform'] + ('.exe' if item['platform'].startswith('windows_') else '')
    expected = {asset + suffix for suffix in ('', '.version', '.sha256')}
    target = destination / ('porthub-' + item['platform'])
    if target.exists() or target.is_symlink():
        raise ValueError('Reusable artifact collides with a newly built platform')
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        if any(entry.filename == 'index.json' for entry in entries):
            extract_indexed(zipped, entries, item['platform'], target)
            return
        if len(entries) != 3 or {entry.filename for entry in entries} != expected:
            raise ValueError('Reusable artifact must contain exactly three canonical files')
        for entry in entries:
            limit = 512 if entry.filename != asset else 128 * 1024 * 1024
            if not 0 < entry.file_size <= limit or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG):
                raise ValueError('Unsafe or oversized reusable artifact entry')
        target.mkdir(parents=True)
        try:
            for entry in entries:
                (target / entry.filename).write_bytes(zipped.read(entry))
        except BaseException:
            shutil.rmtree(target)
            raise


def extract_indexed(zipped, entries, platform, target):
    # Accept only the exact receipt/binary closure, never ZIP directory entries,
    # links, duplicate names or paths which the OS could interpret differently.
    if not 1 <= len(entries) <= 257:
        raise ValueError('Invalid indexed artifact member count')
    names = set()
    total = 0
    for entry in entries:
        path = PurePosixPath(entry.filename)
        if (entry.filename in names or path.is_absolute() or '..' in path.parts
                or str(path) != entry.filename or '\\' in entry.filename or ':' in entry.filename
                or entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)):
            raise ValueError('Unsafe indexed artifact member')
        limit = 1024 * 1024 if entry.filename == 'index.json' else 128 * 1024 * 1024
        total += entry.file_size
        if not 0 < entry.file_size <= limit or total > 1024 * 1024 * 1024:
            raise ValueError('Oversized indexed artifact')
        names.add(entry.filename)
    index = json.loads(zipped.read('index.json'))
    native, cross = matrices()
    expected_target = next(row['target'] for row in native + cross if row['artifact'] == platform)
    expected_target = expected_target.replace('linux-gnu', 'linux-musl')
    if index.get('target') != expected_target:
        raise ValueError('Indexed artifact platform differs from selected job')
    rows = index.get('builds')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise ValueError('Invalid indexed build list')
    expected = {'index.json'}
    for row in rows:
        for key in ('receipt', 'binary'):
            value = row.get(key)
            if not isinstance(value, str) or value in expected:
                raise ValueError('Duplicate or invalid indexed artifact path')
            expected.add(value)
    if names != expected:
        raise ValueError('Indexed artifact contains missing or unreferenced files')
    spec = importlib.util.spec_from_file_location('reused_platform', ROOT/'scripts/build-component-platform.py')
    coordinator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coordinator)
    with tempfile.TemporaryDirectory(prefix='.porthub-reuse-', dir=target.parent) as temporary:
        staged = Path(temporary)/'platform'
        staged.mkdir()
        for entry in entries:
            output = staged/entry.filename
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(zipped.read(entry))
        verified = coordinator.previous_builds(staged, expected_target, index)
        if {tool for tool, _ in verified} != {'core', 'stats', 'sync', 'terminal', 'tor'}:
            raise ValueError('Indexed platform must contain core and every optional tool')
        staged.rename(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id')
    parser.add_argument('--download', type=Path)
    args = parser.parse_args()
    if args.download:
        expected = json.loads(os.environ['PORTHUB_REUSE_PLAN'])
        if expected['repository'] != os.environ['GITHUB_REPOSITORY']:
            raise ValueError('Foreign repository reuse is forbidden')
        proof = plan(expected['repository'], expected['run'])
        if proof != expected:
            raise ValueError('Reuse provenance changed after platform selection')
        args.download.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='client-reuse-') as temporary:
            for item in proof['retained']:
                archive = Path(temporary) / (item['platform'] + '.zip')
                with archive.open('xb') as output:
                    subprocess.run(['gh', 'api', 'repos/' + proof['repository'] + '/actions/artifacts/'
                                    + str(item['id']) + '/zip'], stdout=output, check=True, timeout=600)
                extract(archive, item, args.download)
        (args.download.parent / 'release-provenance.json').write_text(json.dumps(proof, indent=2) + '\n')
        print('Reused ' + str(len(proof['retained'])) + ' digest-verified platform artifacts')
        return
    if not args.run_id:
        parser.error('--run-id or --download is required')
    proof = plan(os.environ['GITHUB_REPOSITORY'], args.run_id)
    reused = {item['platform'] for item in proof['retained']}
    native, cross = matrices()
    native = [item for item in native if item['artifact'] not in reused]
    cross = [item for item in cross if item['artifact'] not in reused]
    outputs = dict(native=json.dumps(native), linux=json.dumps(cross), has_native=str(bool(native)).lower(),
                   has_linux=str(bool(cross)).lower(), plan=json.dumps(proof, separators=(',', ':')))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        for key, value in outputs.items():
            output.write(key + '=' + value + '\n')
    print('Reuse: ' + ', '.join(sorted(reused)))
    print('Build: ' + ', '.join(item['artifact'] for item in native + cross))


if __name__ == '__main__':
    main()
