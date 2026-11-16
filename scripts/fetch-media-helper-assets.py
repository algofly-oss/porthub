#!/usr/bin/env python3
"""Recover an unchanged helper set from the configured HTTPS gateway, not latest binaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

spec = importlib.util.spec_from_file_location('media_reuse', Path(__file__).with_name('media-release.py'))
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Media reuse gateway redirect rejected')


def recover(plan, gateway, destination, opener=None, validate_executable=None):
    if plan.get('mode') != 'reuse':
        raise ValueError('An explicitly verified helper reuse plan is required')
    parsed = urlsplit(gateway)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
        raise ValueError('Use the configured HTTPS media gateway')
    manifest = plan['manifest']
    manifest = media.parse(json.dumps(manifest), manifest['release'])
    if destination.exists() or destination.is_symlink():
        raise ValueError('Use a new media recovery directory')
    destination.parent.mkdir(parents=True, exist_ok=True)
    opener = opener or build_opener(NoRedirect())
    with tempfile.TemporaryDirectory(prefix='.porthub-media-reuse-', dir=destination.parent) as temporary:
        directory = Path(temporary) / 'assets'
        directory.mkdir(mode=0o700)
        for artifact in manifest['artifacts']:
            url = (gateway.rstrip('/') + '/api/downloads/media/' + artifact['version'] + '/'
                   + artifact['target'] + '/' + artifact['executable']['sha256'])
            archive = directory / ('porthub-media-helper-' + artifact['target'] + '.tar.gz')
            digest, total = hashlib.sha256(), 0
            deadline = time.monotonic() + 120
            with opener.open(Request(url, headers={'User-Agent': 'PortHub-helper-reuse'}), timeout=30) as response:
                if response.status != 200:
                    raise ValueError('Exact prior helper archive unavailable')
                with archive.open('xb') as output:
                    while True:
                        chunk = response.read1(min(65536, artifact['archive']['size'] - total + 1))
                        if time.monotonic() > deadline:
                            raise ValueError('Prior helper archive exceeded deadline')
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > artifact['archive']['size']:
                            raise ValueError('Prior helper archive exceeds bound')
                        output.write(chunk)
                        digest.update(chunk)
            if total != artifact['archive']['size'] or digest.hexdigest() != artifact['archive']['sha256']:
                raise ValueError('Prior helper archive checksum differs')
            archive.chmod(0o600)
        (directory / media.ASSET).write_text(json.dumps(manifest, indent=2) + '\n')
        (directory / media.ASSET).chmod(0o600)
        media.verify(directory, manifest['release'], validate_executable)
        directory.rename(destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.plan.is_symlink() or args.plan.stat().st_size > media.MAX_MANIFEST + 16384:
        raise ValueError('Invalid bounded helper reuse plan')
    recover(json.loads(args.plan.read_text()), args.gateway, args.output)
    print('Verified prior helper archives recovered without changing their provenance')


if __name__ == '__main__':
    main()
