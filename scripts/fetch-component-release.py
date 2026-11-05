#!/usr/bin/env python3
"""Stage a public compact release for verified component build reuse."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

spec = importlib.util.spec_from_file_location('release_recovery', Path(__file__).with_name('recover-component-builds.py'))
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
REPOSITORY = 'algofly-oss/porthub'


class ReleaseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
                or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError('Unexpected release asset redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, size, digest):
    deadline = time.monotonic()+180
    sha = hashlib.sha256(); received = 0
    with build_opener(ReleaseRedirects()).open(Request(url, headers={'User-Agent':'PortHub build reuse'}), timeout=15) as response:
        if response.status != 200:
            raise ValueError('Release asset download failed')
        with destination.open('xb') as output:
            while True:
                if time.monotonic() > deadline:
                    raise ValueError('Release asset download exceeded deadline')
                chunk = response.read(1024*1024)
                if not chunk:
                    break
                received += len(chunk)
                if received > size:
                    raise ValueError('Release asset exceeded declared size')
                sha.update(chunk); output.write(chunk)
    if received != size or sha.hexdigest() != digest:
        raise ValueError('Release asset size or checksum mismatch')
    destination.chmod(0o644)


def stage(release, output, verifier):
    if output.exists() or output.is_symlink():
        raise ValueError('Release staging requires a new output directory')
    tag = release.get('tag_name', '')
    if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('Build reuse requires a stable published release')
    assets = release.get('assets')
    if not isinstance(assets, list) or len(assets) > 30:
        raise ValueError('Unexpected release asset inventory')
    names = [asset.get('name') for asset in assets]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate release asset names')
    publisher = recovery.publisher
    if 'porthub-components.json' not in names:
        legacy = {name+suffix for name in publisher.ASSETS for suffix in ('', '.version', '.sha256')}
        if set(names) != legacy:
            raise ValueError('Published release has no complete supported artifact format')
        return None  # First modular release must build without previous receipts.
    expected = publisher.ASSETS | {'porthub-components.json'} | {
        'porthub-tools-'+canonical+'.tar.gz' for _, canonical in recovery.packager.TARGETS.values()}
    if set(names) != expected:
        raise ValueError('Compact release requires exactly 21 expected assets')
    total = 0
    for asset in assets:
        size = asset.get('size'); digest = asset.get('digest', '')
        maximum = 512*1024 if asset['name'] == 'porthub-components.json' else (512 if asset['name'].endswith('.tar.gz') else 256)*1024*1024
        if (asset.get('state') != 'uploaded' or type(size) is not int or not 0 < size <= maximum
                or not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)):
            raise ValueError('Invalid release asset size, digest or upload state')
        total += size
    if total > 6*1024*1024*1024:
        raise ValueError('Release assets exceed aggregate limit')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.porthub-fetch-', dir=output.parent) as temporary:
        directory = Path(temporary)/'release'; directory.mkdir()
        for asset in sorted(assets, key=lambda item: item['name']):
            # Construct the official immutable URL; never trust arbitrary URLs
            # embedded in release JSON. System proxy and verified TLS stay on.
            url = 'https://github.com/'+REPOSITORY+'/releases/download/'+quote(tag, safe='')+'/'+quote(asset['name'], safe='')
            path = directory/asset['name']
            download(url, path, asset['size'], asset['digest'][7:])
            if path.is_symlink() or path.stat().st_size != asset['size'] or recovery.planner.file_digest(path) != asset['digest'][7:]:
                raise ValueError('Downloaded release differs from GitHub metadata')
        publisher.assets(directory, tag[1:], verifier)
        directory.rename(output)
    return tag[1:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--inspect-only', action='store_true')
    parser.add_argument('--recover-output', type=Path)
    parser.add_argument('--artifact-verifier', type=Path)
    args = parser.parse_args()
    result = subprocess.run(['gh','api','repos/'+REPOSITORY+'/releases/latest'], capture_output=True, text=True, timeout=30)
    if result.returncode:
        if 'HTTP 404' in result.stderr:
            release = None
        else:
            raise ValueError('Published release metadata unavailable; no build reuse authorized')
    elif len(result.stdout) > 1024*1024:
        raise ValueError('Published release metadata exceeds limit')
    else:
        release = json.loads(result.stdout)
    compact = release is not None and any(asset.get('name') == 'porthub-components.json' for asset in release.get('assets', []))
    if args.inspect_only:
        print(json.dumps({'compact':compact}))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('compact='+str(compact).lower()+'\n')
        return
    if args.output is None or args.artifact_verifier is None:
        parser.error('--output and --artifact-verifier are required for staging')
    version = stage(release, args.output, args.artifact_verifier) if release is not None else None
    if version is not None and args.recover_output is not None:
        if args.recover_output.exists() or args.recover_output.is_symlink():
            raise ValueError('Recovered builds require a new output directory')
        args.recover_output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.porthub-recover-all-', dir=args.recover_output.parent) as temporary:
            root = Path(temporary)/'platforms'; root.mkdir()
            for target in recovery.packager.TARGETS:
                recovery.recover(args.output, root/target, target, version, args.artifact_verifier)
            root.rename(args.recover_output)
    print(json.dumps({'release':version, 'reuse_available':version is not None}))


if __name__ == '__main__': main()
