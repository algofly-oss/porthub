#!/usr/bin/env python3
"""Build-only staging of one complete release into the production image context."""
import argparse
import os
import pathlib
import shutil
import tempfile
from migrate import ASSETS, artifact_bundle


def stage(source, destination, version):
    files = artifact_bundle(source, version, {})
    expected = {name + suffix for name in ASSETS for suffix in ("", ".version", ".sha256")}
    if set(files) != expected:
        raise RuntimeError("production requires a complete ten-platform client release")
    if {path.name for path in source.iterdir()} - (expected | {".gitkeep"}):
        raise RuntimeError("release source contains unexpected files or historical releases")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RuntimeError("client build context must not be a symlink")
    if destination.exists():
        for path in destination.iterdir():
            if path.name not in expected | {".gitkeep"} or path.is_symlink() or not path.is_file():
                raise RuntimeError("client build context contains unexpected entries")
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=".client-bundle-", dir=destination.parent))
    backup = None
    try:
        for name, content in files.items():
            path = temporary / name
            path.write_bytes(content)
            path.chmod(0o444 if name.endswith((".version", ".sha256")) else 0o555)
        (temporary / ".gitkeep").touch()
        if artifact_bundle(temporary, version, {}) != files:
            raise RuntimeError("staged client release verification failed")
        if destination.exists():
            backup = pathlib.Path(tempfile.mkdtemp(prefix=".previous-client-bundle-", dir=destination.parent))
            backup.rmdir()
            os.rename(destination, backup)
        try:
            os.rename(temporary, destination)
        except BaseException:
            if backup is not None:
                os.rename(backup, destination)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    stage(args.source, pathlib.Path(__file__).parent / "client-bin", args.version)
    print("Staged one complete client release for the production image: " + args.version)
