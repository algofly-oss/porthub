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
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
from urllib.request import urlopen

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


def validate(current, images, configuration, revision, version, architecture, project, roles=ROLES):
    if not re.fullmatch(r'[a-f0-9]{40}', revision) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('A full source revision and numeric version are required')
    for role in roles:
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
    origins = {}
    for role in roles:
        labels = current[role]['Config']['Labels']
        origin = (labels.get('com.docker.compose.project.working_dir'), labels.get('com.docker.compose.project.config_files'))
        if not all(origin):
            raise ValueError('Selected role has no recoverable previous Compose deployment')
        origins[role] = origin
    return origins


def override(images, version):
    result = {'services': {role: {'image': image} for role,image in images.items()}}
    if 'core' in images:
        result['services']['core']['environment'] = {'PORTHUB_VERSION': version}
    return result


def check_routes(urls):
    for index, url in enumerate(urls, 1):
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Upgrade probes require HTTP(S) URLs without credentials or fragments')
        try:
            with urlopen(url, timeout=8) as response:
                if not 200 <= response.status < 400:
                    raise RuntimeError('Unexpected probe status')
        except Exception:
            # URLs can contain private route identifiers; never print them.
            raise RuntimeError('PortHub route probe failed: '+str(index)) from None


def core_data(container):
    mounts = [mount for mount in container['Mounts'] if mount['Destination']=='/data' and mount['Type']=='bind']
    if len(mounts)!=1:
        raise ValueError('Core requires one persistent /data bind mount for its backup')
    return Path(mounts[0]['Source'])


def backup_core(container, destination, deadline=90):
    from migrate import snapshot, file_hash, private_file
    source = core_data(container)
    if not isinstance(deadline,int) or not 1<=deadline<=3600:
        raise ValueError('Core backup requires a bounded deadline')
    if source.is_symlink() or destination.is_symlink():
        raise ValueError('Backup paths must not be symlinks')
    source = source.resolve()
    destination = destination.resolve()
    if destination==source or source in destination.parents or destination in source.parents:
        raise ValueError('Backup destination must be independent of the live state directory')
    if not (source/'mongo').is_dir():
        raise ValueError('Core MongoDB directory is unavailable for backup')
    destination.mkdir(mode=0o700)
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_number, _frame):
        raise TimeoutError('PortHub core backup exceeded its deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(deadline)
    try:
        run(['docker','stop','--time','20',container['Id']])
        ownership = snapshot(source,destination/'data')
        files = {}
        for relative,(uid,gid) in ownership.items():
            copied = destination/'data'/relative
            os.chown(copied,uid,gid,follow_symlinks=False)
            if copied.is_file():
                files[relative] = file_hash(copied).hex()
                with copied.open('rb') as stream:os.fsync(stream.fileno())
        for relative in reversed(list(ownership)):
            copied=destination/'data'/relative
            if copied.is_dir():
                fd=os.open(copied,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
        private_file(destination/'verified.json',json.dumps({'source':str(source),'container':container['Id'],'ownership':ownership,'sha256':files},sort_keys=True).encode())
        for directory in (destination,destination.parent):
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM,previous)



def image_reference(reference):
    values = run(['docker', 'image', 'ls', '--quiet', '--no-trunc', reference]).split()
    if len(set(values)) > 1:
        raise ValueError('Ambiguous PortHub image reference')
    return values[0] if values else None


def replace_private(path, payload, metadata):
    """Replace release metadata without changing its owner or permissions."""
    fd, temporary = tempfile.mkstemp(prefix='.porthub-release-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ReleaseSelection:
    """Preflight and transaction for the ordinary Compose restart configuration."""
    def __init__(self, root, current, images, configuration, revision, version, namespace="porthub"):
        self.path = root / '.env'
        self.metadata = self.path.lstat()
        if not stat.S_ISREG(self.metadata.st_mode) or self.metadata.st_mode & 0o077:
            raise ValueError('Release .env must be a private regular file')
        self.original = self.path.read_bytes()
        self.images = images
        self.aliases = {}
        for role, image in images.items():
            stable = namespace + ':' + role
            if configuration['services'][role]['image'] != stable:
                raise ValueError('Release persistence requires the standard PortHub image names')
            immutable = stable + '-' + version
            previous = current[role]['Image']
            rollback = namespace + ':rollback-' + role + '-' + previous.removeprefix('sha256:')[:12]
            for reference, expected in ((immutable, image['Id']), (rollback, previous)):
                existing = image_reference(reference)
                if existing is not None and existing != expected:
                    raise ValueError('An immutable PortHub image alias already has different contents')
                self.aliases[reference] = (existing, expected)
            self.aliases[stable] = (image_reference(stable), image['Id'])
        changes = {}
        if 'core' in images:
            changes['PORTHUB_VERSION'] = version
        if set(images) == set(ROLES):
            changes['PORTHUB_SOURCE_REVISION'] = revision
        lines = self.original.decode('utf-8').splitlines(keepends=True)
        self.updated = ''.join(line for line in lines if not any(
            re.match(r'^\s*(?:export\s+)?' + key + r'\s*=', line) for key in changes))
        if self.updated and not self.updated.endswith('\n'):
            self.updated += '\n'
        self.updated = (self.updated + ''.join(key + '=' + value + '\n' for key, value in changes.items())).encode()

    def apply(self, record, verify):
        from migrate import private_file
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        current = self.path.lstat()
        if any(getattr(current, key) != getattr(self.metadata, key) for key in fields) or self.path.read_bytes() != self.original:
            raise ValueError('Release .env changed since preflight')
        private_file(record / 'previous-release.env', self.original)
        changed = []
        try:
            for reference, (old, wanted) in self.aliases.items():
                if old != wanted:
                    changed.append((reference, old))
                    run(['docker', 'image', 'tag', wanted, reference])
            replace_private(self.path, self.updated, self.metadata)
            verify()
        except BaseException as original:
            failures = []
            try:
                replace_private(self.path, self.original, self.metadata)
            except Exception:
                failures.append('release environment')
            for reference, old in reversed(changed):
                try:
                    if old is None:
                        run(['docker', 'image', 'rm', reference])
                    else:
                        run(['docker', 'image', 'tag', old, reference])
                except Exception:
                    failures.append('image alias')
            if failures:
                raise RuntimeError('Release selection rollback incomplete: ' + ', '.join(failures)) from original
            raise


def activate(compose, previous_compose, ensure_others, verify_routes=lambda: None, roles=ROLES, before_role=lambda role: None, after_roles=lambda: None):
    watched = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    previous_handlers = {number: signal.getsignal(number) for number in watched}
    def interrupted(_number, _frame):
        raise InterruptedError('PortHub upgrade interrupted; restoring previous images')
    attempted = []
    try:
        for number in watched:
            signal.signal(number, interrupted)
        # No dependencies: each replacement is explicitly scoped to one role.
        for role in roles:
            attempted.append(role)
            before_role(role)
            run([*compose, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', '--wait', '--wait-timeout', '180', role])
        verify_routes()
        ensure_others()
        after_roles()
    except BaseException as original:
        for number in watched:
            signal.signal(number, signal.SIG_IGN)
        # A CLI error can follow an already-applied replacement. Restore each
        # attempted role even if its command returned an error. Unattempted
        # roles remain untouched by --no-deps and must not be recreated.
        failures = []
        for role in attempted:
            try:
                previous = previous_compose[role] if isinstance(previous_compose,dict) else previous_compose
                run([*previous, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', '--wait', '--wait-timeout', '180', role])
            except Exception:
                failures.append(role)
        try:
            ensure_others()
        except Exception:
            failures.append('unrelated-container check')
        try:
            verify_routes()
        except Exception:
            failures.append('public-route check')
        if failures:
            raise RuntimeError('PortHub rollback incomplete: '+', '.join(failures)+
                               '; recover using the retained previous image/configuration records') from original
        raise
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


def perform(args):
    root = args.root.resolve()
    roles = tuple(role for role in ROLES if role in args.roles)
    current = {role: inspect('container', args.project+'-'+role) for role in roles}
    images = {role: inspect('image', 'porthub-ci:'+role+'-'+args.revision) for role in roles}
    architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine, os.uname().machine)
    base = ['docker', 'compose', '--project-name', args.project, '--project-directory', str(root), '-f', str(root/'docker-compose.yml')]
    configuration = json.loads(run([*base, 'config', '--format', 'json']))
    origins = validate(current, images, configuration, args.revision, args.version, architecture, args.project, roles)
    for previous_root, previous_files in origins.values():
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
    previous_version = next((value.split('=', 1)[1] for value in current.get('core', {}).get('Config', {}).get('Env', [])
                             if value.startswith('PORTHUB_VERSION=')), None)
    if 'core' in roles and not previous_version:
        raise ValueError('Previous runtime version is unavailable for rollback')
    selection = ReleaseSelection(root, current, images, configuration, args.revision, args.version, args.project)
    check_routes(args.probe_url)
    print('Preflight passed: source, version, architecture, privileges, state mounts and rollback configuration')
    if not args.apply:
        return
    if 'core' in roles:
        source=core_data(current['core'])
        if os.geteuid()!=0 and source.stat().st_uid!=os.geteuid():
            raise ValueError('Core backup requires state ownership permissions; run the upgrade with sudo')
        if not (source/'mongo').is_dir():
            raise ValueError('Core MongoDB directory is unavailable for backup')
        estimated=sum(path.stat().st_size for path in source.rglob('*') if path.is_file())
        if shutil.disk_usage(root).free < estimated*2+64*1024*1024:
            raise ValueError('Insufficient space for a verified core backup')
    records = root/'deploy/native/upgrade-records'
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = Path(tempfile.mkdtemp(prefix=args.revision+'-', dir=records))
    from migrate import private_file
    for name, payload in [('candidate.json', override({role: images[role]['Id'] for role in roles}, args.version)),
                          ('previous.json', override({role: current[role]['Image'] for role in roles}, previous_version))]:
        private_file(record/name,(json.dumps(payload)+'\n').encode())
    for directory in (record,records,records.parent):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    previous = {}
    for role, (previous_root, previous_files) in origins.items():
        command = ['docker', 'compose', '--project-name', args.project, '--project-directory', previous_root]
        for path in previous_files.split(','):
            command.extend(['-f', path])
        command.extend(['-f', str(record/'previous.json')])
        previous[role] = command
    def before_role(role):
        if role=='core':
            backup_core(current['core'],record/'core-backup')
            print('Verified PortHub core backup retained at '+str(record/'core-backup'),flush=True)
    def verify_selection():
        normal = json.loads(run([*base, 'config', '--format', 'json']))
        for role, image in images.items():
            if image_reference(normal['services'][role]['image']) != image['Id']:
                raise RuntimeError('Ordinary Compose configuration selects a different release image')
        if 'core' in images and normal['services']['core']['environment'].get('PORTHUB_VERSION') != args.version:
            raise RuntimeError('Ordinary Compose configuration selects a different core version')
        ensure_others()
        check_routes(args.probe_url)
    activate([*base, '-f', str(record/'candidate.json')], previous, ensure_others,
             lambda: check_routes(args.probe_url), roles, before_role,
             lambda: selection.apply(record, verify_selection))
    print('PortHub roles healthy ('+', '.join(roles)+'); unselected roles retained; previous immutable image references at '+str(record))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--project', default='porthub')
    parser.add_argument('--roles', nargs='+', choices=ROLES, default=list(ROLES), help='Replace only these roles; omitted roles must keep running unchanged')
    parser.add_argument('--probe-url', action='append', default=[], help='Existing application HTTP(S) URL to check before and after upgrade/rollback; repeatable')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', args.project):
        raise ValueError('Invalid Compose project name')
    if not args.apply:
        return perform(args)
    # Serialize even when separate release directories target the same project.
    if 'core' in args.roles and os.geteuid()!=0:
        source = core_data(inspect('container',args.project+'-core'))
        if source.stat().st_uid!=os.geteuid():
            raise ValueError('Core backup requires state ownership permissions; run the upgrade with sudo')
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
