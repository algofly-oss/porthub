#!/usr/bin/env python3
"""Recover CI reuse inputs from a locally staged, Rust-verified compact release."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load('component_packager', 'package-components.py')
publisher = load('component_publisher', 'publish-release.py')
planner = packager.planner


def recover(directory, output, target, release, verifier):
    if target not in packager.TARGETS:
        raise ValueError('Unsupported build target')
    if output.exists() or output.is_symlink():
        raise ValueError('Recovery requires a new output directory')
    # This performs the full Rust contract/archive verification and checks every
    # file before and after. A receipt's own checksum is not a trust root.
    verified = publisher.assets(directory, release, verifier)
    manifest_path = directory / 'porthub-components.json'
    manifest = json.loads(manifest_path.read_bytes())
    legacy, canonical = packager.TARGETS[target]
    core = next(asset for asset in manifest['core_assets'] if asset['target'] == legacy)
    tools = [artifact for artifact in manifest['components']['artifacts'] if artifact['target'] == canonical]
    archive_path = directory / ('porthub-tools-' + canonical + '.tar.gz')
    if not tools:
        raise ValueError('Platform has no tool metadata')
    for path in (manifest_path, archive_path, directory / core['asset']):
        expected = verified[path.name]
        if path.is_symlink() or not path.is_file() or path.stat().st_size != expected['size'] or 'sha256:' + planner.file_digest(path) != expected['digest']:
            raise ValueError('Release changed after verification')
    with tarfile.open(archive_path) as archive:
        member = archive.getmember('.porthub-build-receipts.json')
        if not member.isfile() or not 0 < member.size <= 8 * 1024 * 1024:
            raise ValueError('Invalid build receipt envelope')
        with archive.extractfile(member) as stream:
            envelope = json.load(stream)
        if envelope.get('schema_version') != 1 or not isinstance(envelope.get('receipts'), list):
            raise ValueError('Unsupported build receipt envelope')
        receipts = envelope['receipts']
        if len(receipts) != len(tools) + 1:
            raise ValueError('Build receipts do not match platform artifacts')
        expected_tools = {(tool['component'], tool['version']): tool for tool in tools}
        seen = set()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.porthub-recover-', dir=output.parent) as temporary:
            stage = Path(temporary) / 'builds'
            stage.mkdir()
            index = []
            for receipt in receipts:
                if len(json.dumps(receipt).encode()) > planner.MAX_RECEIPT:
                    raise ValueError('Individual build receipt exceeds size limit')
                planner.validate_receipt(receipt)
                identity = (receipt['tool'], receipt['version'])
                if identity in seen or receipt['target'] != target:
                    raise ValueError('Duplicate or wrong-platform build receipt')
                seen.add(identity)
                tool, version = identity
                expected_name = ('porthub' if tool == 'core' else 'porthub-' + tool) + ('.exe' if 'windows' in target else '')
                if receipt['binary']['name'] != expected_name or receipt['build']['recipe']['profile'] != 'release':
                    raise ValueError('Invalid optimized executable identity')
                if tool == 'core':
                    if version != manifest.get('core_version', manifest['release']):
                        raise ValueError('Core receipt version differs from executable version')
                    declared = core['executable']
                    source = directory / core['asset']
                    member_name = None
                else:
                    artifact = expected_tools.get(identity)
                    if artifact is None or receipt['source_revision'] != artifact['source_revision'] or receipt['fingerprint'] != artifact['build_inputs']:
                        raise ValueError('Tool receipt provenance differs from manifest')
                    declared = artifact['executable']
                    source = None
                    member_name = tool + '/' + version + '/' + receipt['binary']['name']
                if any(receipt['binary'][key] != declared[key] for key in ('sha256', 'size')):
                    raise ValueError('Receipt binary identity differs from manifest')
                folder = stage / tool / version
                folder.mkdir(parents=True)
                binary = folder / receipt['binary']['name']
                if source is not None:
                    shutil.copyfile(source, binary)
                else:
                    member = archive.getmember(member_name)
                    if not member.isfile() or member.size != declared['size']:
                        raise ValueError('Invalid executable archive member')
                    with archive.extractfile(member) as stream, binary.open('wb') as destination:
                        shutil.copyfileobj(stream, destination, 1024 * 1024)
                binary.chmod(0o755)
                planner.verify_reuse(receipt, binary)
                receipt_path = folder / 'build-receipt.json'
                receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
                receipt_path.chmod(0o644)
                index.append({'tool': tool, 'version': version,
                              'receipt': receipt_path.relative_to(stage).as_posix(),
                              'binary': binary.relative_to(stage).as_posix()})
            if sum(tool == 'core' for tool, _ in seen) != 1 or set(expected_tools) != seen - {('core', manifest.get('core_version', manifest['release']))}:
                raise ValueError('Build receipt identities are incomplete')
            # Input files can change while being read. Verify again before
            # publishing recovered inputs; output remains private until rename.
            for path in (manifest_path, archive_path, directory / core['asset']):
                if 'sha256:' + planner.file_digest(path) != verified[path.name]['digest']:
                    raise ValueError('Release changed during recovery')
            (stage / 'index.json').write_text(json.dumps({'schema_version': 1, 'target': target, 'release': release, 'builds': index}, sort_keys=True) + '\n')
            stage.rename(output)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target', required=True, choices=sorted(packager.TARGETS))
    parser.add_argument('--release', required=True)
    parser.add_argument('--artifact-verifier', required=True, type=Path)
    args = parser.parse_args()
    recover(args.input, args.output, args.target, args.release, args.artifact_verifier)


if __name__ == '__main__':
    main()
