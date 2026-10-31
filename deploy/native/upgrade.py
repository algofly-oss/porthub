#!/usr/bin/env python3
"""Upgrade only an existing native PortHub Compose deployment; dry-run by default."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile

ROLES = ('firewall', 'core', 'edge')


def run(arguments, cwd=None):
    try:
        result = subprocess.run(arguments, cwd=cwd, capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        raise RuntimeError('PortHub upgrade operation timed out: ' + arguments[0]) from None
    if result.returncode:
        # Compose diagnostics/configuration can contain interpolated secrets.
        raise RuntimeError('PortHub upgrade operation failed: ' + arguments[0])
    return result.stdout


def inspect(kind, name):
    return json.loads(run(['docker', kind, 'inspect', name]))[0]


def validate(current, images, configuration, revision, version, architecture, project):
    if not re.fullmatch(r'[a-f0-9]{40}', revision) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('A full source revision and numeric version are required')
    for role in ROLES:
        old, image = current[role], images[role]
        labels = old['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.service') != role:
            raise ValueError('Existing container is not the expected PortHub role')
        if not old['State'].get('Running') or old['State'].get('Health', {}).get('Status') != 'healthy':
            raise ValueError('Existing PortHub roles must be healthy before upgrading')
        wanted_user = '10001:10001' if role == 'core' else '0:10001'
        metadata = image['Config'].get('Labels') or {}
        if image['Architecture'] != architecture or image['Config'].get('User') != wanted_user:
            raise ValueError('Candidate architecture or role privileges do not match')
        if metadata.get('org.opencontainers.image.revision') != revision or metadata.get('org.opencontainers.image.version') != version:
            raise ValueError('Candidate source or version does not match')
        service = configuration['services'][role]
        if service.get('privileged') or service.get('user', wanted_user) != wanted_user:
            raise ValueError('Candidate Compose changes role privileges')
        if not service.get('read_only') or 'ALL' not in service.get('cap_drop', []):
            raise ValueError('Candidate Compose must retain restricted runtime settings')
        allowed = {'core': set(), 'edge': {'NET_BIND_SERVICE'}, 'firewall': {'NET_ADMIN'}}[role]
        if set(service.get('cap_add', [])) != allowed:
            raise ValueError('Candidate Compose changes role capabilities')
        if role == 'core' and (service.get('network_mode') == 'host' or service.get('ports')):
            raise ValueError('Core must retain its private network')
        if role != 'core' and service.get('network_mode') != 'host':
            raise ValueError('Edge and firewall require their existing host network')
        # State/socket/certificate mounts must keep their source and access mode.
        previous = {mount['Destination']: (mount['Source'], not mount['RW']) for mount in old['Mounts'] if mount['Type'] == 'bind'}
        candidate = {mount['target']: (mount['source'], mount.get('read_only', False)) for mount in service.get('volumes', []) if mount['type'] == 'bind'}
        if previous != candidate:
            raise ValueError('Candidate Compose changes existing persistent or socket mounts')
    labels = [current[role]['Config']['Labels'] for role in ROLES]
    origins = {(item.get('com.docker.compose.project.working_dir'), item.get('com.docker.compose.project.config_files')) for item in labels}
    if len(origins) != 1 or not all(next(iter(origins))):
        raise ValueError('Existing roles must share a recoverable Compose deployment')
    return next(iter(origins))


def override(images, version):
    result = {'services': {role: {'image': images[role]} for role in ROLES}}
    result['services']['core']['environment'] = {'PORTHUB_VERSION': version}
    return result


def activate(compose, previous_compose, ensure_others):
    watched = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    previous_handlers = {number: signal.getsignal(number) for number in watched}
    def interrupted(_number, _frame):
        raise InterruptedError('PortHub upgrade interrupted; restoring previous images')
    try:
        for number in watched:
            signal.signal(number, interrupted)
        # No dependencies: each replacement is explicitly scoped to one role.
        for role in ROLES:
            run([*compose, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', '--wait', '--wait-timeout', '180', role])
        ensure_others()
    except BaseException:
        for number in watched:
            signal.signal(number, signal.SIG_IGN)
        # A CLI error can follow an already-applied replacement. Restore all
        # three previous immutable image IDs, even for the first failed command.
        for role in ROLES:
            run([*previous_compose, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', '--wait', '--wait-timeout', '180', role])
        ensure_others()
        raise
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


def perform(args):
    root = args.root.resolve()
    current = {role: inspect('container', args.project+'-'+role) for role in ROLES}
    images = {role: inspect('image', 'porthub-ci:'+role+'-'+args.revision) for role in ROLES}
    architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine, os.uname().machine)
    base = ['docker', 'compose', '--project-name', args.project, '--project-directory', str(root), '-f', str(root/'docker-compose.yml')]
    configuration = json.loads(run([*base, 'config', '--format', 'json']))
    previous_root, previous_files = validate(current, images, configuration, args.revision, args.version, architecture, args.project)
    files = [Path(name) for name in previous_files.split(',')]
    if not Path(previous_root).is_dir() or any(not path.is_absolute() or not path.is_file() for path in files):
        raise ValueError('Previous Compose files are unavailable for rollback')
    if root == Path(previous_root).resolve():
        raise ValueError('Stage an independent deployment directory to preserve rollback configuration')
    def ensure_others():
        if not others <= set(run(['docker', 'ps', '--quiet', '--no-trunc']).split()):
            raise RuntimeError('An unrelated previously running container is no longer running')
    # Use full IDs for the baseline as well as the subsequent check.
    others = set(run(['docker', 'ps', '--quiet', '--no-trunc']).split()) - {item['Id'] for item in current.values()}
    previous_version = next((value.split('=', 1)[1] for value in current['core']['Config'].get('Env', [])
                             if value.startswith('PORTHUB_VERSION=')), None)
    if not previous_version:
        raise ValueError('Previous runtime version is unavailable for rollback')
    print('Preflight passed: source, version, architecture, privileges, state mounts and rollback configuration')
    if not args.apply:
        return
    records = root/'deploy/native/upgrade-records'
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = Path(tempfile.mkdtemp(prefix=args.revision+'-', dir=records))
    for name, payload in [('candidate.json', override({role: images[role]['Id'] for role in ROLES}, args.version)),
                          ('previous.json', override({role: current[role]['Image'] for role in ROLES}, previous_version))]:
        path = record/name
        path.write_text(json.dumps(payload)+'\n')
        path.chmod(0o600)
    previous = ['docker', 'compose', '--project-name', args.project, '--project-directory', previous_root]
    for path in files:
        previous.extend(['-f', str(path)])
    previous.extend(['-f', str(record/'previous.json')])
    activate([*base, '-f', str(record/'candidate.json')], previous, ensure_others)
    print('PortHub roles healthy; previous immutable image references retained at '+str(record))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--project', default='porthub')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', args.project):
        raise ValueError('Invalid Compose project name')
    if not args.apply:
        return perform(args)
    # Serialize even when separate release directories target the same project.
    path = Path(tempfile.gettempdir()) / ('porthub-native-upgrade-'+args.project+'.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        metadata = os.fstat(lock.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('Unsafe upgrade lock ownership or permissions')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        perform(args)


if __name__ == '__main__':
    main()
