"""Verified cold state snapshots with online staging of immutable release blobs.

Live MongoDB is never copied, linked, or considered immutable. Only a component
object whose bytes match the SHA256 in its content-addressed filename can be
reused from the online phase, and both file identities must still match at the
cold boundary. All other files are copied from the stopped core.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import shutil

_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+-([0-9a-f]{64})(?:\.tar\.gz)?$")

class ChangedSource(RuntimeError):
    pass


def identity(metadata):
    return tuple(getattr(metadata, field) for field in (
        'st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid',
        'st_mtime_ns', 'st_ctime_ns'))


def tree(source):
    if source.is_symlink() or not source.is_dir():
        raise ValueError('PortHub state directory is unavailable')
    paths = sorted([source, *source.rglob('*')], key=lambda path: (len(path.parts), str(path)))
    for path in paths:
        metadata = path.lstat()
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise ValueError('PortHub state contains unsupported filesystem entries')
    return paths


def hash_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def copy_verified(source, destination):
    """One source read computes the digest while copying; read back the copy."""
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('PortHub backup source must be a regular file')
    digest = hashlib.sha256()
    copied_bytes = 0
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as incoming:
        if identity(os.fstat(incoming.fileno())) != identity(before):
            raise ChangedSource('PortHub backup source changed during open')
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as copied:
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                digest.update(chunk)
                copied_bytes += len(chunk)
                copied.write(chunk)
            if copied_bytes != before.st_size:
                raise ChangedSource('PortHub backup source changed size during copy')
            copied.flush()
            os.fchown(copied.fileno(), before.st_uid, before.st_gid)
            shutil.copystat(source, destination, follow_symlinks=False)
            os.fsync(copied.fileno())
            copied_metadata = os.fstat(copied.fileno())
        try:
            current = source.lstat()
        except FileNotFoundError as error:
            raise ChangedSource('PortHub backup source was replaced during copy') from error
        if identity(current) != identity(before) or identity(os.fstat(incoming.fileno())) != identity(before):
            raise ChangedSource('PortHub backup source changed during copy')
    checksum = digest.hexdigest()
    if hash_file(destination) != checksum or identity(destination.lstat()) != identity(copied_metadata):
        raise RuntimeError('PortHub cold backup integrity check failed')
    return {'source': identity(before), 'copy': identity(copied_metadata), 'sha256': checksum}


def immutable_digest(relative):
    if len(relative.parts) != 3 or relative.parts[:2] != ('agent-releases', 'components'):
        return None
    match = _COMPONENT.fullmatch(relative.name)
    return match.group(1) if match else None


_MIN_MUTABLE_STAGE = 16 * 1024 * 1024


def hash_stopped_source(path, expected):
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as file:
        if identity(os.fstat(file.fileno())) != expected:
            raise ChangedSource('PortHub backup source changed during open')
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
        if identity(os.fstat(file.fileno())) != expected or identity(path.lstat()) != expected:
            raise ChangedSource('PortHub backup source changed during verification')
    return digest.hexdigest()


def prepare_snapshot(source, destination):
    """Stage immutable objects and large files eligible for cold revalidation."""
    paths = tree(source)  # Reject unsafe entries before any service is stopped.
    destination.mkdir(mode=0o700)
    staged = {}
    for path in paths:
        relative = path.relative_to(source)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        expected = immutable_digest(relative)
        if not stat.S_ISREG(metadata.st_mode):
            continue
        if expected is None and metadata.st_size < _MIN_MUTABLE_STAGE:
            continue
        copied = destination / relative
        copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            receipt = copy_verified(path, copied)
            if expected is None or receipt['sha256'] == expected:
                staged[str(relative)] = {**receipt, 'cold_revalidate': expected is None}
            else:
                # An unverified cache object is backed up as ordinary cold data.
                copied.unlink()
        except (ChangedSource, FileNotFoundError):
            if copied.exists():
                copied.unlink()
    return {'source': source, 'destination': destination, 'staged': staged}


def finish_snapshot(prepared):
    """Capture the stopped-core tree and verify staged mutable bytes against it."""
    source, destination, staged = (prepared[key] for key in ('source', 'destination', 'staged'))
    paths = tree(source)
    relative_paths = {str(path.relative_to(source)) for path in paths}
    # Objects removed while staging must not reappear when a backup is restored.
    for copied in sorted(destination.rglob('*'), key=lambda path: len(path.parts), reverse=True):
        metadata = copied.lstat()
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ValueError('PortHub backup contains unsupported filesystem entries')
        if str(copied.relative_to(destination)) not in relative_paths:
            if copied.is_dir():
                copied.rmdir()
            else:
                copied.unlink()
    ownership, checksums = {}, {}
    cold_bytes = staged_bytes = 0
    directories = []
    for path in paths:
        relative = path.relative_to(source)
        metadata = path.lstat()
        ownership[str(relative)] = (metadata.st_uid, metadata.st_gid)
        copied = destination / relative
        if stat.S_ISDIR(metadata.st_mode):
            copied.mkdir(mode=0o700, exist_ok=True)
            directories.append((copied, metadata))
            continue
        receipt = staged.get(str(relative))
        reusable = receipt is not None and identity(metadata) == receipt['source']
        if reusable:
            try:
                reusable = identity(copied.lstat()) == receipt['copy']
            except FileNotFoundError:
                reusable = False
        if reusable and receipt.get('cold_revalidate', False):
            # The hot copy is an I/O optimization, never the consistency boundary.
            reusable = hash_stopped_source(path, receipt['source']) == receipt['sha256']
        if reusable:
            checksums[str(relative)] = receipt['sha256']
            staged_bytes += metadata.st_size
        else:
            if copied.exists():
                copied.unlink()
            receipt = copy_verified(path, copied)
            checksums[str(relative)] = receipt['sha256']
            cold_bytes += metadata.st_size
    for copied, metadata in reversed(directories):
        os.chown(copied, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
        shutil.copystat(source / copied.relative_to(destination), copied, follow_symlinks=False)
        descriptor = os.open(copied, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {'ownership': ownership, 'sha256': checksums,
            'staged_bytes': staged_bytes, 'cold_bytes': cold_bytes}
