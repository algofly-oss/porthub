#!/usr/bin/env python3
"""Assemble ten platform artifacts and verify the complete release atomically."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('release_recovery', Path(__file__).with_name('recover-component-builds.py'))
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)


def assemble(source, destination, version, verifier=None):
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Platform artifact source must be a real directory')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Release output must be a new directory')
    recovery.publisher.numeric(version)
    directories = []
    for asset in sorted(recovery.publisher.ASSETS):
        directory = source/asset.removesuffix('.exe')
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Missing or unsafe platform artifact directory')
        directories.append(directory)
    indexes = [directory for directory in directories if (directory/'index.json').exists() or (directory/'index.json').is_symlink()]
    if indexes and len(indexes) != 10:
        raise ValueError('Cannot mix indexed component builds and legacy platform artifacts')
    if not indexes and recovery.publisher.numeric(version) >= (1,11,0):
        raise ValueError('Modular releases require all ten platform build indexes')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.porthub-assemble-', dir=destination.parent) as temporary:
        output = Path(temporary)/'release'
        if indexes:
            entries = recovery.packager.entries_from_indexes(indexes)
            recovery.packager.package(entries, output, version)
        else:
            spec = importlib.util.spec_from_file_location('legacy_client_collection', Path(__file__).resolve().parents[1]/'deploy/native/collect_client_bundle.py')
            collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
            collector.collect(source, output, version)
        verified = recovery.publisher.assets(output, version, verifier)
        output.rename(destination)
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--artifact-verifier', type=Path)
    args = parser.parse_args()
    assets = assemble(args.source, args.destination, args.version, args.artifact_verifier)
    print('Assembled and verified '+str(len(assets))+' release assets')


if __name__ == '__main__': main()
