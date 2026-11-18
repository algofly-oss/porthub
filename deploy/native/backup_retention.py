"""Prune only proven completed-upgrade snapshots, never deployment roots/state.

The upgrade's existing per-project lock must cover this operation. A private
registry follows the core state across separate versioned deployment roots.
Legacy snapshots without our completion marker are deliberately not adopted.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time

MARKER = 'backup-retention-complete.json'
INTENT = 'backup-retention-pruning.json'

def registry_path(source, project):
    identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    return source.parent / ('.porthub-backup-retention-' + project + '-' + identity + '.json')
MAX_ROOTS = 64


def safe_path(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Retention requires absolute unaliased paths')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Retention paths must not traverse symlinks')
    return path


def private_json(path):
    safe_path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 16 * 1024 * 1024:
        raise ValueError('Unsafe retention metadata')
    return json.loads(path.read_text())


def save(path, value):
    safe_path(path)
    fd, name = tempfile.mkstemp(prefix='.retention-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mounted_paths():
    # stat.st_dev misses same-device bind mounts; mountinfo includes those too.
    result = set()
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        raw = line.split()[4]
        result.add(Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), raw)))
    return result


def entry_identity(info):
    result = [info.st_dev, info.st_ino, info.st_mode]
    if stat.S_ISREG(info.st_mode):
        result += [info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    return result


def walk_snapshot(backup, record, mounts, allowed=None, identities=None):
    """Check each entry before descending, including same-device bind mounts."""
    device = record.stat().st_dev
    pending = [backup]
    while pending:
        path = pending.pop()
        safe_path(path)
        info = path.lstat()
        relative = str(path.relative_to(backup))
        if path in mounts or info.st_dev != device or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('Snapshot contains a mount or unsupported entry')
        if allowed is not None and relative not in allowed:
            raise ValueError('Prune remainder contains undeclared data')
        if identities is not None and identities.get(relative) != entry_identity(info):
            raise ValueError('Prune remainder entry was replaced or changed')
        yield path
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())


def record_identity(record, project, source):
    """Validate completed-record identity even after a partial prune."""
    record = safe_path(record)
    match = re.fullmatch(r'([0-9a-f]{40})-[A-Za-z0-9_\-]+', record.name)
    if not match or record.parent.name != 'upgrade-records' or record.parent.parent.name != 'native' or record.parent.parent.parent.name != 'deploy':
        raise ValueError('Not an upgrade-owned record')
    info = record.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe upgrade record')
    mounts = mounted_paths()
    # Release roots may live on their own filesystem; no mounted descendant
    # inside the upgrade record namespace may become deletion authority.
    if any(path in mounts for path in (record, record.parent, record.parent.parent, record.parent.parent.parent)):
        raise ValueError('Upgrade record namespace contains a mount')
    marker = private_json(record / MARKER)
    if marker.get('schema') != 1 or marker.get('project') != project or marker.get('source') != str(source) or marker.get('record') != str(record) or marker.get('revision') != match[1] or not isinstance(marker.get('completed_ns'), int) or marker['completed_ns'] <= 0:
        raise ValueError('Snapshot completion identity mismatch')
    return marker, mounts


def snapshot(record, project, source):
    """Validate provenance and the exact removable tree, without rereading GBs."""
    marker, mounts = record_identity(record, project, source)
    backup = safe_path(record / 'core-backup')
    if backup in mounts or backup.lstat().st_dev != record.stat().st_dev or not backup.is_dir():
        raise ValueError('Snapshot root contains a mount or changed type')
    backup = record / 'core-backup'
    verified = private_json(backup / 'verified.json')
    if marker.get('manifest_sha256') != digest(backup / 'verified.json') or verified.get('source') != str(source) or not isinstance(verified.get('container'), str) or not verified['container']:
        raise ValueError('Snapshot verification identity mismatch')
    files = verified.get('sha256')
    if not isinstance(files, dict) or not isinstance(verified.get('ownership'), dict) or 'mongo' not in verified['ownership']:
        raise ValueError('Snapshot lacks MongoDB verification')
    expected = {'verified.json', 'data'}
    for name, checksum in files.items():
        relative = Path(name)
        if not name or relative.is_absolute() or any(part in ('.', '..') for part in relative.parts) or str(relative) != name or not re.fullmatch('[0-9a-f]{64}', checksum):
            raise ValueError('Invalid snapshot manifest path')
        expected.add('data/' + name)
        expected.update('data/' + str(parent) for parent in relative.parents if str(parent) != '.')
    # Include empty directories declared by the original verified ownership map.
    for name in verified['ownership']:
        if name == '.':
            continue
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError('Invalid ownership manifest path')
        expected.add('data/' + name)
    mounts = mounted_paths()
    if record in mounts:
        raise ValueError('Upgrade record is a mount')
    observed = set()
    for path in walk_snapshot(backup, record, mounts):
        if path != backup:
            observed.add(str(path.relative_to(backup)))
    if observed != expected:
        raise ValueError('Snapshot contains undeclared or missing data')
    for name in files:
        if not (backup / 'data' / name).is_file():
            raise ValueError('Snapshot file changed type')
    return marker


def remove_snapshot(record, project, source, resume=False):
    """Durable exact-tree intent allows retry after partial filesystem failure."""
    backup = record / 'core-backup'
    intent_path = record / INTENT
    record_identity(record, project, source)
    if not resume:
        snapshot(record, project, source)
        identities = {str(p.relative_to(backup)): entry_identity(p.lstat()) for p in walk_snapshot(backup, record, mounted_paths())}
        allowed = list(identities)
        save(intent_path, dict(schema=1, project=project, source=str(source), record=str(record),
                               marker_sha256=digest(record / MARKER), allowed=allowed, identities=identities))
    if any(path in mounted_paths() for path in (record, record.parent, record.parent.parent, record.parent.parent.parent)):
        raise ValueError('Prune record namespace contains a mount')
    intent = private_json(intent_path)
    if intent.get('schema') != 1 or intent.get('project') != project or intent.get('source') != str(source) or intent.get('record') != str(record) or intent.get('marker_sha256') != digest(record / MARKER) or not isinstance(intent.get('allowed'), list) or not isinstance(intent.get('identities'), dict):
        raise ValueError('Prune intent identity mismatch')
    allowed = set(intent['allowed'])
    mounts = mounted_paths()
    if backup.exists() or backup.is_symlink():
        list(walk_snapshot(backup, record, mounts, allowed, intent['identities']))
        shutil.rmtree(backup)
    intent_path.unlink()


def complete(record, project, source, revision):
    """Called only after activate+health+ordinary release selection succeed."""
    record, source = safe_path(record), safe_path(source)
    verified = private_json(record / 'core-backup' / 'verified.json')
    if verified.get('source') != str(source):
        raise ValueError('Completed snapshot state mismatch')
    save(record / MARKER, dict(schema=1, project=project, source=str(source), record=str(record), revision=revision,
                              completed_ns=time.time_ns(), manifest_sha256=digest(record / 'core-backup' / 'verified.json')))
    snapshot(record, project, source)


def prune(source, project, current_record, roots, keep=2, protected_sources=()):
    """Automatic after success; the current backup and newest recovery survive."""
    if not re.fullmatch('[a-z0-9][a-z0-9_-]*', project) or not isinstance(keep, int) or not 2 <= keep <= 16:
        raise ValueError('Invalid bounded retention policy')
    source, current_record = safe_path(source), safe_path(current_record)
    registry = registry_path(source, project)
    previous = private_json(registry) if registry.exists() or registry.is_symlink() else dict(schema=1, projects={})
    if previous.get('schema') != 1 or not isinstance(previous.get('projects'), dict):
        raise ValueError('Invalid retention registry')
    remembered = previous['projects'].get(project, [])
    if not isinstance(remembered, list) or len(remembered) > MAX_ROOTS:
        raise ValueError('Invalid retained roots')
    candidates = sorted({str(safe_path(Path(root))) for root in [*roots, *remembered]})
    if len(candidates) > MAX_ROOTS:
        raise ValueError('Retention root capacity exceeded')
    entries, pending, skipped = [], [], []
    in_use = [Path(path).resolve() for path in protected_sources]
    def mounted_by_container(record):
        backup = record / 'core-backup'
        return any(path == backup or path in backup.parents or backup in path.parents for path in in_use)
    for root in candidates:
        records = safe_path(Path(root) / 'deploy/native/upgrade-records')
        if not records.exists():
            continue
        if any(path in mounted_paths() for path in (records, records.parent, records.parent.parent)):
            raise ValueError('Retention record namespace contains a mount')
        for record in records.iterdir():
            if not (record / MARKER).exists():
                continue  # Never infer successful history from legacy names.
            try:
                if (record / INTENT).exists():
                    record_identity(record, project, source)
                    pending.append(record)
                    continue
                if not (record / 'core-backup').exists():
                    continue  # A prior completed prune keeps tiny history.
                marker = snapshot(record, project, source)
                entries.append((marker['completed_ns'], str(record)))
            except (OSError, ValueError, TypeError, KeyError):
                skipped.append(str(record))
    if str(current_record) not in {row[1] for row in entries}:
        raise ValueError('Current verified recovery point is unavailable')
    # Persist discovery before destructive work, so interrupted cleanup cannot
    # orphan a separate versioned root from the next successful upgrade.
    previous['projects'][project] = candidates
    save(registry, previous)
    ordered = sorted(entries, reverse=True)
    protected = {str(current_record)}
    for _, name in ordered:
        if len(protected) < keep:
            protected.add(name)
    protected.update(name for _, name in entries if mounted_by_container(Path(name)))
    removed = []
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError('Symlink-safe snapshot removal is unavailable')
    unresolved = {str(Path(name).parents[3]) for name in skipped}
    for record in pending:
        if len(entries) < 2 or mounted_by_container(record):
            unresolved.add(str(record.parents[3]))
            skipped.append(str(record))
            continue
        if str(record) in protected:
            raise ValueError('Protected recovery has an unfinished prune')
        remove_snapshot(record, project, source, resume=True)
        removed.append(str(record))
    for _, name in ordered:
        if name in protected:
            continue
        record = Path(name)
        snapshot(record, project, source)  # Recheck immediately before removal.
        remove_snapshot(record, project, source)
        # Keep tiny previous image/env/configuration records and the completion
        # marker for operator history; never remove the deployment directory.
        removed.append(name)
    live_roots = sorted(unresolved | {str(Path(name).parents[3]) for _, name in entries if name not in removed})
    previous['projects'][project] = live_roots
    save(registry, previous)
    return dict(keep=keep, protected=sorted(protected), removed=removed, skipped=skipped, roots=live_roots)
