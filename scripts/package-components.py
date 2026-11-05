#!/usr/bin/env python3
"""Package verified build receipts into a compact, deterministic release directory."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location('component_build_plan', Path(__file__).with_name('component-build-plan.py'))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
# Runtime catalog names stay stable; Linux release builds must use musl.
TARGETS = {
    'x86_64-unknown-linux-musl': ('x86_64', 'x86_64-unknown-linux-gnu'),
    'i686-unknown-linux-musl': ('x86', 'i686-unknown-linux-gnu'),
    'aarch64-unknown-linux-musl': ('arm64', 'aarch64-unknown-linux-gnu'),
    'arm-unknown-linux-musleabihf': ('armhf', 'arm-unknown-linux-gnueabihf'),
    'armv7-unknown-linux-musleabihf': ('armv7', 'armv7-unknown-linux-gnueabihf'),
    'x86_64-apple-darwin': ('darwin_x86_64', 'x86_64-apple-darwin'),
    'aarch64-apple-darwin': ('darwin_arm64', 'aarch64-apple-darwin'),
    'x86_64-pc-windows-msvc': ('windows_x86_64', 'x86_64-pc-windows-msvc'),
    'i686-pc-windows-msvc': ('windows_x86', 'i686-pc-windows-msvc'),
    'aarch64-pc-windows-msvc': ('windows_arm64', 'aarch64-pc-windows-msvc'),
}
TOOLS = {'sync', 'tor', 'terminal', 'stats', 'transfer'}


def package(entries, output, release, *, verify_only=False):
    planner.stable_version(release)
    if output.exists() or output.is_symlink():
        raise ValueError('Output must be a new release directory')
    records = []
    identities = set()
    for receipt_path, binary in entries:
        if receipt_path.is_symlink() or not receipt_path.is_file() or not binary.is_file():
            raise ValueError('Release inputs must be regular files')
        receipt = planner.read_receipt(receipt_path)
        planner.verify_reuse(receipt, binary)
        target, tool = receipt['target'], receipt['tool']
        if target not in TARGETS or tool not in TOOLS | {'core'}:
            raise ValueError('Unsupported release tool or target')
        if receipt['binary']['size'] > 256 * 1024 * 1024:
            raise ValueError('Executable exceeds component protocol limit')
        recipe = receipt['build']['recipe']
        expected = ('porthub' if tool == 'core' else 'porthub-' + tool) + ('.exe' if 'windows' in target else '')
        if receipt['binary']['name'] != expected or recipe['profile'] != 'release':
            raise ValueError('Release requires the expected optimized executable')
        if planner.stable_version(receipt['version']) > planner.stable_version(release):
            raise ValueError('Tool cannot have a future release version')
        key = (target, tool, receipt['version'])
        if key in identities:
            raise ValueError('Duplicate tool version and platform')
        identities.add(key)
        records.append((receipt, binary))
    cores = {}
    groups = {}
    for receipt, binary in records:
        target = receipt['target']
        if receipt['tool'] == 'core':
            if target in cores or receipt['version'] != release:
                raise ValueError('Each platform requires exactly one matching core version')
            cores[target] = (receipt, binary)
        else:
            groups.setdefault(target, []).append((receipt, binary))
    if len({receipt['source_revision'] for receipt, _ in cores.values()}) != 1:
        raise ValueError('Core platform builds must share one immutable source revision')
    if not cores or set(groups) != set(cores) or (not verify_only and set(cores) != set(TARGETS)):
        raise ValueError('Release requires core and tool archives for every selected platform')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.porthub-package-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'release'
        stage.mkdir()
        core_assets, artifacts = [], []
        for target in sorted(cores):
            legacy, canonical = TARGETS[target]
            receipt, binary = cores[target]
            asset = 'porthub-' + legacy + ('.exe' if 'windows' in target else '')
            shutil.copyfile(binary, stage / asset)
            # Verify the copied bytes as well, catching input changes during packaging.
            planner.verify_reuse(receipt, stage / asset)
            core_assets.append({'target': legacy, 'asset': asset,
                                'executable': {k: receipt['binary'][k] for k in ('size', 'sha256')}})
            if len(groups[target]) > 128 or sum(item['binary']['size'] for item, _ in groups[target]) > 1024 * 1024 * 1024:
                raise ValueError('Platform tool archive exceeds extraction limits')
            archive = stage / ('porthub-tools-' + canonical + '.tar.gz')
            with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                    for item, path in sorted(groups[target], key=lambda row: (row[0]['tool'], row[0]['version'])):
                        planner.verify_reuse(item, path)
                        member = item['tool'] + '/' + item['version'] + '/' + item['binary']['name']
                        header = tarfile.TarInfo(member)
                        header.size = item['binary']['size']; header.mode = 0o755
                        with path.open('rb') as stream:
                            tar.addfile(header, stream)
            expected = {item['tool'] + '/' + item['version'] + '/' + item['binary']['name']: item['binary'] for item, _ in groups[target]}
            with tarfile.open(archive) as packed:
                for member in packed:
                    digest = hashlib.sha256()
                    with packed.extractfile(member) as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk)
                    if member.size != expected[member.name]['size'] or digest.hexdigest() != expected[member.name]['sha256']:
                        raise ValueError('Tool changed while packaging')
            if archive.stat().st_size > 512 * 1024 * 1024:
                raise ValueError('Platform archive exceeds download limit')
            blob = {'size': archive.stat().st_size, 'sha256': planner.file_digest(archive)}
            for item, _path in sorted(groups[target], key=lambda row: (row[0]['tool'], row[0]['version'])):
                recipe = item['build']['recipe']
                protocols = recipe['protocols']
                if not protocols or any(type(p) is not int or p < 1 for p in protocols) or len(set(protocols)) != len(protocols):
                    raise ValueError('Invalid tool protocol contract')
                artifacts.append({'component': item['tool'], 'version': item['version'], 'target': canonical,
                    'core': recipe['core'], 'protocols': protocols,
                    'source_revision': item['source_revision'], 'build_inputs': item['fingerprint'],
                    'executable': {k: item['binary'][k] for k in ('size', 'sha256')},
                    'release': release, 'archive': blob})
        manifest = {'schema_version': 2, 'repository': 'algofly-oss/porthub', 'release': release,
                    'core_assets': core_assets, 'components': {'schema_version': 1,
                    'repository': 'algofly-oss/porthub', 'release': release, 'artifacts': artifacts}}
        payload = planner.canonical(manifest) + b'\n'
        if len(payload) > 512 * 1024:
            raise ValueError('Release manifest exceeds gateway limit')
        (stage / 'porthub-components.json').write_bytes(payload)
        os.rename(stage, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input', nargs=2, action='append', required=True, metavar=('RECEIPT', 'BINARY'))
    parser.add_argument('--verify-only', action='store_true', help='Permit a platform subset for unpublished fixture validation')
    args = parser.parse_args()
    package([(Path(a), Path(b)) for a, b in args.input], args.output, args.release, verify_only=args.verify_only)


if __name__ == '__main__':
    main()
