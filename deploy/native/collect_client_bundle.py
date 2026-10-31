#!/usr/bin/env python3
"""Collect only validated platform clients from a shared workflow artifact root."""
import argparse
from pathlib import Path
from migrate import ASSETS, artifact_bundle


def collect(source, destination, version):
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError('platform artifact root must be a real directory')
    files = {}
    for asset in sorted(ASSETS):
        directory = source / asset.removesuffix('.exe')
        expected = {asset + suffix for suffix in ('', '.version', '.sha256')}
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError('missing platform artifact: ' + asset)
        if {entry.name for entry in directory.iterdir()} != expected:
            raise RuntimeError('unexpected platform artifact entries: ' + asset)
        captured = artifact_bundle(directory, version, {})
        if set(captured) != expected:
            raise RuntimeError('platform artifact is incomplete: ' + asset)
        files.update(captured)
    if destination.is_symlink() or destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise RuntimeError('client collection destination must be empty')
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (destination / name).write_bytes(content)
    return sorted(files)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--version', required=True)
    arguments = parser.parse_args()
    names = collect(arguments.source, arguments.destination, arguments.version)
    print('Collected ' + str(len(names)) + ' verified client assets')
