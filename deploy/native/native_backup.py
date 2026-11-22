"""Verified cold state snapshots with online staging of immutable release blobs.

A live database is never a source of staged file contents. Content-addressed
components can be staged from the live core. An optional independent copy of a
prior verified backup is accepted only after hashing the stopped source. Other
files are copied from the stopped core.
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


def tree(source, *, online=False):
    if source.is_symlink() or not source.is_dir():
        raise ValueError('PortHub state directory is unavailable')
    paths = sorted([source, *source.rglob('*')], key=lambda path: (len(path.parts), str(path)))
    observed = []
    for path in paths:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if online and path != source:
                continue
            raise
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise ValueError('PortHub state contains unsupported filesystem entries')
        observed.append(path)
    return observed


def stream_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest.hexdigest()


def hash_file(path):
    with path.open('rb') as stream:
        return stream_digest(stream)


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


def prefill_file(previous, destination, expected, live):
    """Stage prior bytes and current metadata. The running database is never opened."""
    live_metadata = live.lstat()
    if not stat.S_ISREG(live_metadata.st_mode):
        return None
    source_fd = os.open(previous, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(source_fd, 'rb') as source:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Prior snapshot file is not an independent regular file')
        copy_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(copy_fd, 'wb') as copied:
            shutil.copyfileobj(source, copied, length=1024 * 1024)
            copied.flush()
            # Linux O_PATH pins metadata without permitting a read of live
            # database bytes, even if an application renames the original path.
            metadata_fd = os.open(live, os.O_PATH | os.O_NOFOLLOW)
            try:
                if identity(os.fstat(metadata_fd)) != identity(live_metadata):
                    raise ChangedSource('Live metadata changed during staging')
                os.fchown(copy_fd, live_metadata.st_uid, live_metadata.st_gid)
                shutil.copystat(f'/proc/self/fd/{metadata_fd}', f'/proc/self/fd/{copy_fd}')
            finally:
                os.close(metadata_fd)
            os.fsync(copy_fd)
            metadata = os.fstat(copy_fd)
        if identity(before) != identity(os.fstat(source_fd)) or identity(before) != identity(previous.lstat()):
            raise ChangedSource('The prior backup changed during staging')
    if (hash_file(destination) != expected or identity(metadata) != identity(destination.lstat())
            or identity(live_metadata) != identity(live.lstat())):
        destination.unlink()
        return None
    return {'copy': identity(metadata), 'sha256': expected, 'metadata_source': identity(live_metadata), 'size': metadata.st_size}


def reuse_prefill(source, destination, metadata, receipt):
    """Only stopped source bytes can authorize reusing independently staged data."""
    if metadata.st_size != receipt['size'] or identity(destination.lstat()) != receipt['copy']:
        return False
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(source_fd, 'rb') as incoming:
        before = identity(metadata)
        if before != identity(os.fstat(source_fd)):
            raise ChangedSource('Stopped backup source was replaced')
        checksum = stream_digest(incoming)
        if before != identity(os.fstat(source_fd)) or before != identity(source.lstat()):
            raise ChangedSource('Stopped backup source changed while verifying staged data')
        if checksum != receipt['sha256'] or identity(destination.lstat()) != receipt['copy']:
            return False
        if before == receipt['metadata_source']:
            # The independent inode was fsynced after copying these metadata
            # online; stopped bytes were checked independently above.
            return True
        # A clean database shutdown can touch metadata without changing bytes.
        # If an old xattr would survive copystat, use a fresh cold copy instead.
        copy_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if identity(os.fstat(copy_fd)) != receipt['copy']:
                return False
            if set(os.listxattr(copy_fd)) - set(os.listxattr(source_fd)):
                return False
            os.fchown(copy_fd, metadata.st_uid, metadata.st_gid)
            shutil.copystat(f'/proc/self/fd/{source_fd}', f'/proc/self/fd/{copy_fd}')
            os.fsync(copy_fd)
            settled = identity(os.fstat(copy_fd))
            if hash_file(destination) != checksum or identity(destination.lstat()) != settled:
                raise RuntimeError('Staged prior data changed during metadata reconciliation')
            if identity(os.fstat(source_fd)) != before or identity(source.lstat()) != before:
                raise ChangedSource('Stopped source changed during metadata reconciliation')
            return True
        finally:
            os.close(copy_fd)


def stage_prior_files(source, destination, paths, prior_record, project):
    from backup_retention import private_json, safe_path, snapshot
    prior_record = safe_path(prior_record)
    if any(path == prior_record or prior_record in path.parents or path in prior_record.parents
           for path in (source, destination)):
        raise ValueError('Prior backup must be independent of the source and destination')
    snapshot(prior_record, project, source)
    previous = prior_record / 'core-backup'
    hashes = private_json(previous / 'verified.json')['sha256']
    receipts = {}
    for path in paths:
        relative = path.relative_to(source)
        checksum = hashes.get(str(relative))
        if checksum is None or immutable_digest(relative) is not None:
            continue
        old = previous / 'data' / relative
        copied = destination / relative
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or old.lstat().st_size != metadata.st_size:
                continue
            copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            receipt = prefill_file(old, copied, checksum, path)
        except (ChangedSource, FileNotFoundError):
            # These files can still be copied from the stopped tree.
            copied.unlink(missing_ok=True)
            continue
        if receipt:
            receipts[str(relative)] = receipt
    return receipts


def prepare_snapshot(source, destination, prior_record=None, project=None):
    """Stage immutable release assets and optional independent prior backup data."""
    paths = tree(source, online=True)  # Reject unsafe entries before any service is stopped.
    destination.mkdir(mode=0o700)
    staged = {}
    for path in paths:
        relative = path.relative_to(source)
        expected = immutable_digest(relative)
        if expected is None or not path.is_file():
            continue
        copied = destination / relative
        copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            receipt = copy_verified(path, copied)
            if receipt['sha256'] == expected:
                staged[str(relative)] = receipt
            else:
                # An unverified cache object is backed up as ordinary cold data.
                copied.unlink()
        except (ChangedSource, FileNotFoundError):
            if copied.exists():
                copied.unlink()
    # Capture mutable file metadata last, after the larger release-component
    # staging pass and as close as possible to the cold boundary.
    prefills = stage_prior_files(source, destination, paths, prior_record, project) if prior_record is not None else {}
    return {'source': source, 'destination': destination, 'staged': staged, 'prefills': prefills,
            'prior_staged_bytes': sum(item['size'] for item in prefills.values())}


def finish_snapshot(prepared):
    """Complete and verify the snapshot while the core is stopped."""
    source, destination, staged = (prepared[key] for key in ('source', 'destination', 'staged'))
    paths = tree(source)
    source_directories = {str(path.relative_to(source)): stat.S_ISDIR(path.lstat().st_mode) for path in paths}
    # Objects removed while staging must not reappear when a backup is restored.
    for copied in sorted(destination.rglob('*'), key=lambda path: len(path.parts), reverse=True):
        metadata = copied.lstat()
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ValueError('PortHub backup contains unsupported filesystem entries')
        if source_directories.get(str(copied.relative_to(destination))) != stat.S_ISDIR(metadata.st_mode):
            if stat.S_ISDIR(metadata.st_mode):
                copied.rmdir()
            else:
                copied.unlink()
    ownership, checksums = {}, {}
    cold_bytes = staged_bytes = prior_bytes = 0
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
        prefill = prepared.get('prefills', {}).get(str(relative))
        reusable = receipt is not None and identity(metadata) == receipt['source']
        if reusable:
            try:
                reusable = identity(copied.lstat()) == receipt['copy']
            except FileNotFoundError:
                reusable = False
        if reusable:
            checksums[str(relative)] = receipt['sha256']
            staged_bytes += metadata.st_size
        elif prefill and copied.is_file() and reuse_prefill(path, copied, metadata, prefill):
            checksums[str(relative)] = prefill['sha256']
            prior_bytes += metadata.st_size
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
            'staged_bytes': staged_bytes, 'cold_bytes': cold_bytes, 'prior_verified_bytes': prior_bytes,
            'prior_staged_bytes': prepared.get('prior_staged_bytes', 0)}
