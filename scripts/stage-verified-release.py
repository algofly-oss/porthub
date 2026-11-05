#!/usr/bin/env python3
"""Stage a successful ten-platform CI bundle without rebuilding its binaries."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import tomllib
import zipfile

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-release.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
package_spec = importlib.util.spec_from_file_location('component_packager', Path(__file__).with_name('package-components.py'))
component_packager = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(component_packager)



def validate(run, jobs, artifacts, repository):
    if (run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or run.get('event') != 'workflow_dispatch'
            or run.get('path') != '.github/workflows/agent-platforms.yml'
            or (run.get('head_repository') or {}).get('full_name') != repository):
        raise ValueError('Promotion requires a successful native-platform dispatch in this repository')
    revision = run.get('head_sha', '')
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Missing immutable build source')
    if not any(job.get('name') == 'Validate complete release bundle'
               and job.get('status') == 'completed' and job.get('conclusion') == 'success' for job in jobs):
        raise ValueError('The complete ten-platform release gate did not pass')
    selected = [artifact for artifact in artifacts if artifact.get('name') == 'porthub-release-bundle']
    if len(selected) != 1:
        raise ValueError('Exactly one complete release artifact is required')
    artifact = selected[0]
    source = artifact.get('workflow_run', {})
    if (artifact.get('expired') or not isinstance(artifact.get('id'), int)
            or artifact['id'] <= 0 or source.get('id') != run.get('id')
            or source.get('head_sha') != revision
            or not isinstance(artifact.get('size_in_bytes'), int)
            or not 0 < artifact['size_in_bytes'] <= 1536 * 1024 * 1024
            or not re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', ''))):
        raise ValueError('Artifact provenance, digest or size is invalid')
    return revision, artifact


def extract(archive, artifact, destination, version, artifact_verifier=None):
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if archive.stat().st_size != artifact['size_in_bytes'] or 'sha256:' + digest != artifact['digest']:
        raise ValueError('Downloaded artifact does not match GitHub size and digest')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Use a new staging directory')
    legacy = {asset + suffix for asset in publisher.ASSETS for suffix in ('', '.version', '.sha256')}
    compact = set(publisher.ASSETS) | {'porthub-components.json'} | {
        'porthub-tools-' + canonical + '.tar.gz' for _, canonical in component_packager.TARGETS.values()}
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        is_compact = any(entry.filename == 'porthub-components.json' for entry in entries)
        expected = compact if is_compact else legacy
        if len(entries) != len(expected) or {entry.filename for entry in entries} != expected:
            raise ValueError('Artifact must contain one exact complete legacy or compact release')
        if is_compact and artifact_verifier is None:
            raise ValueError('Compact staging requires an explicit Rust artifact verifier')
        if sum(entry.file_size for entry in entries) > 2 * 1024 * 1024 * 1024:
            raise ValueError('Release artifact exceeds total expansion limit')
        for entry in entries:
            if entry.filename == 'porthub-components.json': limit = 512 * 1024
            elif is_compact and entry.filename.endswith('.tar.gz'): limit = 512 * 1024 * 1024
            elif is_compact: limit = 256 * 1024 * 1024
            else: limit = 512 if entry.filename.endswith(('.version', '.sha256')) else 128 * 1024 * 1024
            if (not 0 < entry.file_size <= limit
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)):
                raise ValueError('Unsafe or oversized release artifact entry')
        destination.mkdir(mode=0o700)
        for entry in entries:
            path = destination / entry.filename
            with bundle.open(entry) as source, path.open('xb') as target:
                while chunk := source.read(65536):
                    target.write(chunk)
            path.chmod(0o600)
        return publisher.assets(destination, version, artifact_verifier)


def api(repository, suffix):
    result = subprocess.run(['gh', 'api', 'repos/' + repository + suffix],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('GitHub verification request failed')
    return json.loads(result.stdout)


def pages(repository, suffix, field):
    result = []
    page = 1
    while True:
        value = api(repository, suffix + '?per_page=100&page=' + str(page))
        result.extend(value[field])
        if len(result) >= value['total_count']:
            return result
        if not value[field] or page >= 100:
            raise ValueError('Incomplete GitHub provenance listing')
        page += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--artifact-verifier', type=Path, help='Absolute trusted porthub-api executable required for compact staging')
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r'[\w.-]+/[\w.-]+', args.repository) or not re.fullmatch(r'[1-9][0-9]*', args.run_id):
        parser.error('An explicit repository and numeric CI run ID are required')
    prefix = '/actions/runs/' + args.run_id
    run = api(args.repository, prefix)
    revision, artifact = validate(run, pages(args.repository, prefix + '/jobs', 'jobs'),
                                  pages(args.repository, prefix + '/artifacts', 'artifacts'), args.repository)
    # Require the already reviewed source to remain in this checkout's history.
    subprocess.run(['git', 'merge-base', '--is-ancestor', revision, 'HEAD'], check=True)
    cargo = subprocess.check_output(['git', 'show', revision + ':Cargo.toml'], text=True)
    version = tomllib.loads(cargo)['workspace']['package']['version']
    publisher.numeric(version)
    destination = args.destination.absolute()
    proof = destination.with_name(destination.name + '.proof.json')
    if destination.exists() or destination.is_symlink() or proof.exists() or proof.is_symlink():
        raise ValueError('Staging destination and proof must not exist')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.release-download-', dir=destination.parent) as temporary:
        archive = Path(temporary) / 'bundle.zip'
        with archive.open('xb') as target:
            result = subprocess.run(['gh', 'api', 'repos/' + args.repository + '/actions/artifacts/' + str(artifact['id']) + '/zip'],
                                    stdout=target, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            raise RuntimeError('Verified artifact download failed')
        expected = extract(archive, artifact, destination, version, args.artifact_verifier)
    payload = dict(run=int(args.run_id), revision=revision, version=version, artifact=artifact['id'],
                   artifact_digest=artifact['digest'], assets=expected)
    with proof.open('x') as stream:
        os.chmod(proof, 0o600)
        json.dump(payload, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: payload[key] for key in ('run', 'revision', 'version', 'artifact')}))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('revision=' + revision + '\nversion=' + version + '\n')


if __name__ == '__main__':
    main()
