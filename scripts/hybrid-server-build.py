#!/usr/bin/env python3
"""Exact-source local server artifacts; bounded native workers and hosted fallback.

No deployment, enrollment, source tag mutation or hosted workflow dispatch.
The existing operator-owned native depot transports these build inputs.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
import zipfile

TARGETS = {
    'aarch64-unknown-linux-musl': {'arch': 'arm64', 'os': 'ubuntu-24.04-arm', 'machine': 'aarch64', 'elf': 183},
    'x86_64-unknown-linux-musl': {'arch': 'x86_64', 'os': 'ubuntu-24.04', 'machine': 'x86_64', 'elf': 62},
}
ROLES = ('porthub-api', 'porthub-edge', 'porthub-runtime', 'porthub-firewall')
MAX_ARCHIVE = 512 * 1024**2
MAX_EXPANDED = 1024**3
RECIPE = ('scripts/build-server-linux.sh', 'scripts/build-server-user.sh',
          'scripts/verify-speech-portability.py', 'scripts/speech-cpu-policy.sh',
          'deploy/Dockerfile.server-static', 'rust-toolchain.toml', 'Cargo.toml', 'Cargo.lock')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while True:
            block = stream.read(1024**2)
            if not block:
                return h.hexdigest()
            h.update(block)


def command(argv, timeout=30, cwd=None, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, check=True, capture_output=True, timeout=timeout).stdout


def git(root, *args):
    return command(['git', '-C', str(root), *args]).decode().strip()


def expected(root, source, target):
    if target not in TARGETS or not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('Exact supported server source/target required')
    if git(root, 'rev-parse', 'HEAD') != source:
        raise ValueError('Server checkout source mismatch')
    command(['git', '-C', str(root), 'diff', '--quiet', 'HEAD', '--'])
    version = command(['sh', str(root/'scripts/release-version.sh')]).decode().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid server version')
    return {'source_revision': source, 'source_tree': git(root, 'rev-parse', 'HEAD^{tree}'),
            'target': target, 'version': version, 'toolchain_release': re.search(r'channel\s*=\s*"([^"]+)"', (root/'rust-toolchain.toml').read_text()).group(1), 'recipe': {p: digest(root/p) for p in RECIPE}}


def static_elf(path, target):
    if not 64 <= Path(path).stat().st_size <= 150_000_000:
        raise ValueError('Bounded ELF required')
    data = Path(path).read_bytes()
    if not 64 <= len(data) <= 150_000_000 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Bounded little-endian ELF64 required')
    if struct.unpack_from('<H', data, 18)[0] != TARGETS[target]['elf']:
        raise ValueError('Server ELF architecture mismatch')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if not 1 <= count <= 1024 or size != 56 or offset + count * size > len(data):
        raise ValueError('Invalid server ELF program headers')
    for i in range(count):
        at = offset + i * size
        kind = struct.unpack_from('<I', data, at)[0]
        if kind == 3:
            raise ValueError('Server ELF needs a dynamic interpreter')
        if kind == 2:
            start, length = struct.unpack_from('<Q', data, at+8)[0], struct.unpack_from('<Q', data, at+32)[0]
            if start + length > len(data) or length % 16:
                raise ValueError('Invalid ELF dynamic segment')
            for cursor in range(start, start+length, 16):
                tag = struct.unpack_from('<q', data, cursor)[0]
                if tag == 1:
                    raise ValueError('Server ELF has dynamic dependencies')
                if tag == 0:
                    break


def verify_limits(limits):
    if (type(limits.get('host_cpus')) is not int or limits['host_cpus'] < 2
            or limits.get('cpus') not in (1, 2) or limits['cpus'] > limits['host_cpus']//2
            or limits.get('jobs') != limits['cpus'] or limits.get('memory_bytes') != 6*1024**3
            or limits.get('pids') != 384 or limits.get('read_bps') != 40*1024**2
            or limits.get('write_bps') != 40*1024**2):
        raise ValueError('Native server resource envelope mismatch')
    observed = limits.get('observed', {})
    cpu = observed.get('cpu.max', '').split()
    if (len(cpu) != 2 or not all(v.isdigit() for v in cpu) or int(cpu[0]) != limits['cpus']*int(cpu[1])
            or observed.get('memory.max') != str(limits['memory_bytes'])
            or observed.get('memory.swap.max') != '0' or observed.get('pids.max') != '384'):
        raise ValueError('Actual compiler cgroup limits were not enforced')
    device = limits.get('io_device_number', '')
    if not re.fullmatch(r'\d+:\d+', device):
        raise ValueError('Invalid compiler IO device identity')
    row = next((v.split() for v in observed.get('io.max', '').splitlines() if v.startswith(device+' ')), [])
    if not {'rbps=41943040', 'wbps=41943040'} <= set(row[1:]):
        raise ValueError('Actual compiler IO cap was not enforced')


def verify_tree(root, source, target, directory):
    receipt_path = directory/'server-receipt.json'
    if receipt_path.is_symlink() or receipt_path.stat().st_size > 65536:
        raise ValueError('Invalid server receipt')
    receipt = json.loads(receipt_path.read_text())
    state = expected(root, source, target)
    if receipt.get('schema_version') != 1 or receipt.get('kind') != 'native-server' or receipt.get('build') != state:
        raise ValueError('Server compiled source/recipe mismatch')
    validation = receipt.get('validation', {})
    if (validation.get('native_machine') != TARGETS[target]['machine']
            or any(validation.get(k) is not True for k in ('edge_tests', 'role_help', 'speech_portability'))
            or validation.get('rustc_release') != state['toolchain_release'] or validation.get('rustc_host') != target
            or not re.fullmatch('[a-f0-9]{64}', validation.get('log_sha256', ''))):
        raise ValueError('Native server validation missing')
    verify_limits(receipt.get('limits', {}))
    arch = TARGETS[target]['arch']
    required = {'server-artifacts/'+n for n in (*ROLES, 'source-revision', 'SHA256SUMS')}
    required |= {'server-speech-probe/'+n for n in ('porthub-speech-probe-'+arch, 'proof.json', 'source-revision', 'SHA256SUMS')}
    files = receipt.get('files', {})
    if set(files) != required:
        raise ValueError('Incomplete server/probe artifact set')
    seen = set()
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in server artifacts')
        if path.is_file():
            seen.add(path.relative_to(directory).as_posix())
    if seen != required | {'server-receipt.json'}:
        raise ValueError('Undeclared server artifact')
    for name, identity in files.items():
        path = directory/name
        if (set(identity) != {'size', 'sha256'} or type(identity['size']) is not int
                or not 0 < identity['size'] <= 150_000_000
                or not re.fullmatch('[a-f0-9]{64}', identity['sha256'])
                or not path.is_file() or path.stat().st_size != identity['size'] or digest(path) != identity['sha256']):
            raise ValueError('Server artifact hash/size mismatch')
    for name in ROLES:
        static_elf(directory/'server-artifacts'/name, target)
    probe = directory/'server-speech-probe'/('porthub-speech-probe-'+arch)
    static_elf(probe, target)
    for folder in ['server-artifacts', 'server-speech-probe']:
        if (directory/folder/'source-revision').read_text().strip() != source:
            raise ValueError('Server artifact provenance mismatch')
        sums = {}
        for line in (directory/folder/'SHA256SUMS').read_text().splitlines():
            sha, name = line.split('  ', 1)
            if '/' in name or name in ('.', '..') or not re.fullmatch('[a-f0-9]{64}', sha) or name in sums:
                raise ValueError('Invalid server checksum list')
            sums[name] = sha
        wanted = set(ROLES) if folder == 'server-artifacts' else {'porthub-speech-probe-'+arch, 'proof.json', 'source-revision'}
        if set(sums) != wanted or any(digest(directory/folder/name) != sha for name, sha in sums.items()):
            raise ValueError('Server checksum list mismatch')
    proof = json.loads((directory/'server-speech-probe/proof.json').read_text())
    if (proof.get('source_revision') != source or proof.get('target') != target
            or proof.get('ggml_native') != 'OFF' or proof.get('enumeration_passed') is not True
            or proof.get('model_loaded') is not False or proof.get('app_created') is not False
            or proof.get('executable_sha256') != digest(probe)
            or proof.get('executable_size') != probe.stat().st_size
            or proof.get('baseline_qemu64_enumeration') != (arch == 'x86_64')
            or proof.get('cpu_isa_flags') != ([] if arch == 'x86_64' else ['-march=armv8-a'])
            or (arch == 'arm64' and proof.get('ggml_cpu_arm_arch') != 'armv8-a')):
        raise ValueError('Portable CPU native probe proof mismatch')
    return receipt


def unpack(archive, destination):
    if archive.is_symlink() or not 0 < archive.stat().st_size <= MAX_ARCHIVE:
        raise ValueError('Invalid server archive')
    with zipfile.ZipFile(archive) as stream:
        rows = stream.infolist()
        if not rows or len(rows) > 32 or sum(r.file_size for r in rows) > MAX_EXPANDED:
            raise ValueError('Oversized server archive')
        names = set()
        for row in rows:
            path = PurePosixPath(row.filename)
            mode = row.external_attr >> 16
            if (not path.parts or path.as_posix() != row.filename or path.is_absolute() or '..' in path.parts or '\\' in row.filename or ':' in row.filename
                    or row.is_dir() or row.filename.casefold() in names
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError('Unsafe server archive member')
            names.add(row.filename.casefold())
        stream.extractall(destination)


def verify_archive(root, source, target, archive, output=None):
    original_source = expected(root, source, target)
    before = (archive.stat().st_size, digest(archive))
    with tempfile.TemporaryDirectory(prefix='porthub-server-verify-', dir=output.parent if output else None) as temporary:
        tree = Path(temporary)/'tree'
        unpack(archive, tree)
        receipt = verify_tree(root, source, target, tree)
        if expected(root, source, target) != original_source:
            raise ValueError('Server source changed during verification')
        if archive.is_symlink() or (archive.stat().st_size, digest(archive)) != before:
            raise ValueError('Server archive changed during verification')
        if output is not None:
            if output.exists() or output.is_symlink():
                raise ValueError('Server output already exists')
            for path in tree.rglob('porthub-*'):
                if path.is_file():
                    path.chmod(0o755)
            tree.rename(output)
        return receipt


def safe_cache(cache, create=False):
    if not cache.is_absolute() or cache == Path('/'):
        raise ValueError('Explicit dedicated server cache required')
    for path in [cache, *cache.parents]:
        if path.is_symlink():
            raise ValueError('Server cache symlink')
    marker = cache/'.porthub-server-cache-v1'
    if create and not cache.exists():
        cache.mkdir(mode=0o700, parents=True)
        marker.write_text('porthub-server-native-cache-v1\n')
    if cache.exists():
        info = cache.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or marker.is_symlink() or not marker.is_file() or marker.read_text() != 'porthub-server-native-cache-v1\n':
            raise ValueError('Unowned server cache')
    return cache


def capacity(target, cache):
    if platform.system() != 'Linux' or target not in TARGETS or platform.machine() != TARGETS[target]['machine']:
        raise ValueError('Matching native Linux server host required')
    cpus = os.cpu_count() or 0
    memory = dict(re.findall(r'^(\w+):\s+(\d+)', Path('/proc/meminfo').read_text(), re.M))
    if cpus < 2 or int(memory.get('MemAvailable', 0))*1024 < 8*1024**3:
        raise ValueError('Insufficient reserved native server CPU/RAM capacity')
    controllers = Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()
    if not {'cpu', 'memory', 'pids', 'io'} <= set(controllers):
        raise ValueError('Native server cgroup-v2 resource controls unavailable')
    ancestor = cache
    while not ancestor.exists():
        ancestor = ancestor.parent
    if shutil.disk_usage(ancestor).free < 20*1024**3 or os.getloadavg()[0] > cpus*.75:
        raise ValueError('Native server host is busy or lacks disk reserve')
    device = command(['findmnt', '-n', '-o', 'SOURCE', '-T', str(ancestor)]).decode().strip()
    parent = command(['lsblk', '-ndo', 'PKNAME', device]).decode().strip()
    device = '/dev/'+parent if parent else device
    if not re.fullmatch(r'/dev/(?:sd[a-z]+|vd[a-z]+|nvme\d+n\d+)', device) or not stat.S_ISBLK(Path(device).stat().st_mode):
        raise ValueError('Cannot pin build cache block-device IO controller')
    if command(['docker', 'ps', '--quiet', '--filter', 'label=porthub.native.server.worker=bounded-v1']).strip():
        raise ValueError('A bounded server build is already active')
    core = json.loads(command(['docker', 'inspect', 'porthub-core']))[0]
    if not core['State'].get('Running') or core['State'].get('Health', {}).get('Status') != 'healthy':
        raise ValueError('Production core must be healthy before optional build')
    quota = min(2, cpus//2)
    return {'cpus': quota, 'jobs': quota, 'memory_bytes': 6*1024**3, 'pids': 384, 'io_device': device,
            'read_bps': 40*1024**2, 'write_bps': 40*1024**2, 'host_cpus': cpus,
            'io_device_number': str(os.major(Path(device).stat().st_rdev))+':'+str(os.minor(Path(device).stat().st_rdev))}


def worker(root, source, target, cache, output, budget=2700):
    state = expected(root, source, target)
    safe_cache(cache, create=True)
    with (cache/'worker.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        limits = capacity(target, cache)
        if output.exists() or output.is_symlink() or not 60 <= budget <= 3600:
            raise ValueError('Fresh bounded server output required')
        if int(command(['du', '-skx', str(cache)], timeout=15).split()[0])*1024 > 32*1024**3:
            raise ValueError('Dedicated server cache cap reached; operator cleanup required')
        target_cache = cache/'target'; cargo_cache = cache/'cargo'
        target_cache.mkdir(exist_ok=True); cargo_cache.mkdir(exist_ok=True)
        env = dict(os.environ, PORTHUB_VERSION=state['version'], PORTHUB_SOURCE_REVISION=source,
                   PORTHUB_SERVER_LOCAL_LIMITS='1', PORTHUB_SERVER_CPUS=str(limits['cpus']),
                   CARGO_BUILD_JOBS=str(limits['jobs']), PORTHUB_SERVER_MEMORY_BYTES=str(limits['memory_bytes']),
                   PORTHUB_SERVER_IO_DEVICE=limits['io_device'], PORTHUB_SERVER_IO_DEVICE_NUMBER=limits['io_device_number'], PORTHUB_SERVER_TARGET_CACHE=str(target_cache),
                   CARGO_HOME=str(cargo_cache))
        log = output.with_suffix('.validation.log')
        with log.open('wb') as stream:
            child = subprocess.Popen(['sh', str(root/'scripts/build-server-linux.sh'), target], cwd=root,
                                     env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic()+budget
            next_capacity = time.monotonic()
            try:
                while child.poll() is None:
                    if time.monotonic() >= deadline or shutil.disk_usage(cache).free < 10*1024**3:
                        raise TimeoutError('Optional server build exceeded deadline/disk reserve')
                    if time.monotonic() >= next_capacity:
                        if int(command(['du', '-skx', str(cache)], timeout=15).split()[0])*1024 > 32*1024**3:
                            raise RuntimeError('Dedicated server cache cap reached')
                        next_capacity = time.monotonic()+30
                    time.sleep(2)
                if child.returncode:
                    raise RuntimeError('Optional native server validation failed')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
        expected(root, source, target)
        rustc = (target_cache/target/'release/server-rustc.txt').read_text()
        if ('release: '+state['toolchain_release']+'\n' not in rustc or 'host: '+target+'\n' not in rustc):
            raise ValueError('Native server compiler differs from pinned toolchain')
        limits['observed'] = {k: (target_cache/target/'release'/('server-cgroup.'+k)).read_text().strip()
                              for k in ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'io.max')}
        verify_limits(limits)
        with tempfile.TemporaryDirectory(prefix='.server-package-', dir=output.parent) as temporary:
            tree = Path(temporary)/'tree'; artifacts = tree/'server-artifacts'; artifacts.mkdir(parents=True)
            for name in ROLES:
                path = target_cache/target/'release'/name
                static_elf(path, target); shutil.copyfile(path, artifacts/name)
            (artifacts/'source-revision').write_text(source+'\n')
            (artifacts/'SHA256SUMS').write_text(''.join(digest(artifacts/n)+'  '+n+'\n' for n in ROLES))
            shutil.copytree(root/'server-speech-probe', tree/'server-speech-probe')
            files = {p.relative_to(tree).as_posix(): {'sha256': digest(p), 'size': p.stat().st_size}
                     for p in tree.rglob('*') if p.is_file()}
            receipt = {'schema_version': 1, 'kind': 'native-server', 'build': state, 'files': files,
                       'validation': {'native_machine': platform.machine(), 'edge_tests': True,
                                      'role_help': True, 'speech_portability': True, 'log_sha256': digest(log),
                                      'rustc_release': state['toolchain_release'], 'rustc_host': target},
                       'limits': limits}
            (tree/'server-receipt.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')
            verify_tree(root, source, target, tree)
            staged = Path(temporary)/'server.zip'
            with zipfile.ZipFile(staged, 'w', zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(tree.rglob('*')):
                    if path.is_file(): archive.write(path, path.relative_to(tree).as_posix())
            verify_archive(root, source, target, staged)
            staged.rename(output)
        return {'source_revision': source, 'target': target, 'sha256': digest(output), 'size': output.stat().st_size}


def control(root, source, config, output, hybrid):
    """Operator-configured native producers; cached verified ZIPs resume upload."""
    builders = config.get('server_builders', [])
    if not isinstance(builders, list) or len(builders) > 2:
        raise ValueError('At most two native server builders are supported')
    names = [b['target'] for b in builders]
    if len(set(names)) != len(names) or any(t not in TARGETS for t in names):
        raise ValueError('Duplicate/unsupported native server producer')
    manifest = json.loads((output/'manifest.json').read_text())
    rows = dict(manifest.get('servers', {}))
    result = {'targets': {}}
    lock = __import__('threading').Lock()
    depot = config['depot']

    def publish(target, row):
        with lock:
            rows[target] = row
            hybrid.publish_manifest(depot, source, output,
                {'schema_version': 1, 'source_revision': source, 'servers': dict(rows)}, group='servers')

    def attempt(builder):
        target = builder['target']
        folder = output/('server-'+target); folder.mkdir(exist_ok=True)
        archive = folder/'server.zip'
        values = {'root': str(root), 'revision': source, 'target': target,
                  'archive': str(archive), 'output': str(folder/'build')}
        stage = 'source_compatibility'
        try:
            if not hybrid.source_supported(root, builder.get('minimum_source_revision'), source):
                raise ValueError('Server producer does not support historical source')
            budget = int(builder.get('build_timeout_seconds', 2700))
            if not 60 <= budget <= 3300:
                raise ValueError('Bounded native server budget required')
            if not archive.exists() and not archive.is_symlink():
                if rows.get(target, {}).get('status') == 'ready':
                    raise ValueError('Published server result missing from private cache; refusing duplicate build')
                stage = 'probe'
                publish(target, {'status': 'checking', 'deadline_unix': int(time.time())+90})
                hybrid.command(builder['probe'], values, 15)
                stage = 'build'
                publish(target, {'status': 'building', 'deadline_unix': int(time.time())+budget+180})
                hybrid.command(builder['build'], values, budget+90)
                stage = 'fetch'
                hybrid.command(builder['fetch'], values, 120)
            stage = 'verify'
            verify_archive(root, source, target, archive)
            checksum = digest(archive)
            key = source+'/'+target+'/'+checksum+'.zip'
            stage = 'upload'
            hybrid.command(depot['upload'], {'file': str(archive), 'key': key}, 120)
            publish(target, {'status': 'ready', 'url': depot['base_url'].rstrip('/')+'/'+key,
                             'sha256': checksum, 'size': archive.stat().st_size})
            result['targets'][target] = {'status': 'local_verified', 'sha256': checksum}
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile):
            result['targets'][target] = {'status': 'github_fallback', 'failed_phase': stage}
            try:
                publish(target, {'status': 'unavailable', 'failed_phase': stage})
            except (OSError, ValueError, subprocess.SubprocessError):
                result['manifest_unavailable'] = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(attempt, builders))
    (output/'server-controller-receipt.json').write_text(json.dumps(result, sort_keys=True)+'\n')
    return result


def restore(root, source, target, depot, row, output, hybrid):
    checksum, size = row.get('sha256', ''), row.get('size')
    if (row.get('status') != 'ready' or not re.fullmatch('[a-f0-9]{64}', checksum)
            or type(size) is not int or not 0 < size <= MAX_ARCHIVE
            or row.get('url') != depot.rstrip('/')+'/'+source+'/'+target+'/'+checksum+'.zip'):
        raise ValueError('Invalid exact-source native server artifact pointer')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-server-download-', dir=output.parent) as temporary:
        archive = Path(temporary)/'server.zip'
        hybrid.download(row['url'], archive, size, time.monotonic()+120)
        if archive.stat().st_size != size or digest(archive) != checksum:
            raise ValueError('Native server download hash/size mismatch')
        verify_archive(root, source, target, archive, output)
    return True


def resolve(root, source, platform_name, depot, output, hybrid, initial_wait=90):
    if not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('Exact server source revision required')
    if platform_name not in ('arm64', 'x86_64', 'all'):
        raise ValueError('Unsupported requested server platform')
    targets = [t for t, m in TARGETS.items() if platform_name in ('all', m['arch'])]
    matrix = [{'target': t, 'arch': TARGETS[t]['arch'], 'os': TARGETS[t]['os']} for t in targets]
    result = {'matrix': matrix, 'hosted': [], 'local_arches': []}
    if not depot:
        result['hosted'] = matrix
        return result
    hybrid.https_url(depot)
    if __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(depot).query:
        raise ValueError('Server depot must not contain a query')
    remaining = set(targets)
    started = time.monotonic(); deadline = started+3600
    output.mkdir(parents=True, exist_ok=True)
    while remaining:
        pending = set()
        try:
            with tempfile.TemporaryDirectory(prefix='server-pointer-') as temporary:
                manifest_path = Path(temporary)/'manifest.json'
                hybrid.download(depot.rstrip('/')+'/'+source+'/manifest.json', manifest_path, 65536,
                                min(deadline, time.monotonic()+15))
                manifest = json.loads(manifest_path.read_text())
            if not isinstance(manifest, dict) or manifest.get('schema_version') != 1 or manifest.get('source_revision') != source:
                raise ValueError('Native server pointer has stale source')
            rows = manifest.get('servers', {})
            if not isinstance(rows, dict) or len(rows) > 2 or any(t not in TARGETS for t in rows):
                raise ValueError('Invalid server target pointer set')
            for target in sorted(remaining):
                row = rows.get(target, {})
                if not isinstance(row, dict):
                    raise ValueError('Invalid server target row')
                if not row and time.monotonic()-started < initial_wait:
                    # The client producer can publish this exact source first.
                    # Absence is not an explicit server failure during pickup.
                    pending.add(target)
                    continue
                if row.get('status') == 'ready':
                    try:
                        restore(root, source, target, depot, row, output/TARGETS[target]['arch'], hybrid)
                        result['local_arches'].append(TARGETS[target]['arch'])
                    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile):
                        result['hosted'].append(next(m for m in matrix if m['target'] == target))
                    remaining.remove(target)
                elif (row.get('status') in ('checking', 'building')
                      and type(row.get('deadline_unix')) is int
                      and time.time() < row['deadline_unix'] <= time.time()+3600):
                    pending.add(target)
                else:
                    result['hosted'].append(next(m for m in matrix if m['target'] == target))
                    remaining.remove(target)
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            if time.monotonic()-started < initial_wait:
                pending = set(remaining)
        if not pending or time.monotonic() >= deadline:
            result['hosted'].extend(m for m in matrix if m['target'] in remaining)
            break
        time.sleep(min(15, max(0, deadline-time.monotonic())))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for name in ('worker', 'probe', 'resolve'):
        p = sub.add_parser(name)
        p.add_argument('--root', type=Path)
        p.add_argument('--source-revision')
        p.add_argument('--target', choices=TARGETS)
        p.add_argument('--cache', type=Path)
        p.add_argument('--output', type=Path)
        p.add_argument('--budget-seconds', type=int, default=2700)
        p.add_argument('--platform', default='arm64')
        p.add_argument('--depot', default='')
    args = parser.parse_args()
    if args.mode == 'probe':
        if args.cache is None or args.target is None:
            parser.error('target and dedicated cache are required')
        safe_cache(args.cache)
        result = capacity(args.target, args.cache)
    elif args.mode == 'worker':
        if any(v is None for v in (args.root, args.source_revision, args.target, args.cache, args.output)):
            parser.error('worker requires exact source, target, cache and archive output')
        result = worker(args.root.resolve(), args.source_revision, args.target, args.cache, args.output, args.budget_seconds)
    else:
        if any(v is None for v in (args.root, args.source_revision, args.output)):
            parser.error('resolver requires exact source and owned staging')
        spec = importlib.util.spec_from_file_location('hybrid', Path(__file__).with_name('hybrid-native-build.py'))
        hybrid = importlib.util.module_from_spec(spec); spec.loader.exec_module(hybrid)
        result = resolve(args.root.resolve(), args.source_revision, args.platform, args.depot, args.output, hybrid)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                for key, value in [('matrix', result['matrix']), ('hosted', result['hosted']), ('local_arches', result['local_arches'])]:
                    stream.write(key+'='+json.dumps(value, separators=(',', ':'))+'\n')
                stream.write('hosted_count='+str(len(result['hosted']))+'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'unavailable', 'error_type': type(error).__name__}), file=__import__('sys').stderr)
        raise SystemExit(1)
