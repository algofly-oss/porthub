#!/usr/bin/env python3
"""Trusted native controller and bounded release-workflow artifact restoration.

No daemon, public runner, fleet publication, or host provisioning. Builder argv
and depot configuration are local trusted operator inputs, never workflow inputs.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.request
from urllib.parse import urlsplit
import zipfile

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Use a trusted HTTPS depot without embedded credentials')
    return value


def revision(value):
    if not re.fullmatch('[0-9a-f]{40}', value):
        raise ValueError('Full immutable source revision required')
    return value


def verify(root, directory, target, source, controller=False):
    builder = load('build-component-platform')
    planner = builder.planner
    builds = builder.previous_builds(directory, target)
    recipes = planner.read_recipes(root)
    if not builds or not {tool for tool, _ in builds} <= set(recipes):
        raise ValueError('Native artifact contains no configured release components')
    for (tool, version), (receipt, binary) in builds.items():
        if receipt['source_revision'] != source:
            raise ValueError('Local artifact source mismatch')
        if controller:
            # Cross-host controller verifies the compiled source/locked closure;
            # generated native terminal bytes are revalidated on the hosted OS.
            state = receipt['build']
            nodes = [{k:v for k,v in node.items() if k not in ('checksum','edges')} for node in state['dependencies']]
            expected = {'recipe': recipes[tool], 'target': target, 'toolchain': planner.toolchain(root),
                'profile': planner.profile_state(root, recipes[tool]['profile'], nodes),
                'environment': planner.shipping_environment(root,target),
                'resolver': tomllib.loads((root/'Cargo.toml').read_text()).get('workspace',{}).get('resolver'),
                'patches': planner.patch_state(root,nodes),
                'inputs': [planner.input_state(root,row[0],row[1]) for row in state['inputs']],
                'dependencies': [planner.dependency_state(planner.lock_packages(root),node) for node in nodes]}
            observed = {key:value for key,value in state.items() if key != 'derived_inputs'}
            if observed != expected:
                raise ValueError('Controller compiled input closure mismatch')
            # Generated terminal bytes require the corresponding native SDK;
            # the hosted target recomputes those before accepting reuse.
            if 'derived_inputs' in state and recipes[tool]['package'] != 'porthub-terminal-cli':
                raise ValueError('Unexpected generated native input')
        elif planner.plan(root, tool, target, receipt, planner.shipping_environment(root, target))['action'] != 'reuse':
            raise ValueError('Local artifact differs from release inputs')
    return builds


def unpack(archive, destination):
    with zipfile.ZipFile(archive) as stream:
        rows = stream.infolist()
        expanded=sum(row.file_size for row in rows)
        if not rows or len(rows) > 2048 or expanded > MAX_EXPANDED or expanded+128*1024**2 > shutil.disk_usage(destination.parent).free:
            raise ValueError('Oversized native artifact')
        seen = set()
        for row in rows:
            name = PurePosixPath(row.filename)
            mode = row.external_attr >> 16
            if (name.is_absolute() or '..' in name.parts or '\\' in row.filename or ':' in row.filename
                    or not name.parts or name.as_posix().casefold() in seen
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError('Unsafe native archive path')
            seen.add(name.as_posix().casefold())
        stream.extractall(destination)


def pack(directory, output):
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as stream:
        for path in sorted(directory.rglob('*')):
            if path.is_symlink():
                raise ValueError('Symlink in native output')
            if path.is_file():
                stream.write(path, path.relative_to(directory).as_posix())
    if output.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Native archive too large')


def command(argv, values, timeout):
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
        raise ValueError('Configured command must be a nonempty argv list')
    # No shell interpolation. Credentials belong in SSH agents/control sockets or
    # the trusted uploader's environment, never in the depot URL or manifest.
    expanded = [arg.format_map(values) for arg in argv]
    subprocess.run(expanded, check=True, timeout=timeout, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def control(root, source, config, output):
    revision(source)
    load('component-build-plan').require_clean_source(root, source)
    prior = None
    if output.exists() and any(output.iterdir()):
        prior = json.loads((output/'manifest.json').read_text())
        if prior.get('source_revision') != source or prior.get('schema_version') != 1:
            raise ValueError('Controller resume source mismatch')
    if config.get('schema_version') != 1 or not isinstance(config.get('builders'), list) or len(config['builders']) > 10:
        raise ValueError('Invalid trusted builder configuration')
    depot = config['depot']
    https_url(depot['base_url'])
    if urlsplit(depot['base_url']).query:
        raise ValueError('Depot base URL cannot contain a query')
    output.mkdir(parents=True, exist_ok=True)
    manifest = {'schema_version': 1, 'source_revision': source, 'targets': {}}
    if prior is None:
        # Record the exact revision before any remote work can be interrupted.
        pending = output/'manifest.pending.json'
        pending.write_text(json.dumps(manifest, sort_keys=True))
        pending.replace(output/'manifest.json')
    report = {'schema_version': 1, 'source_revision': source, 'targets': {}}
    targets = set()
    for builder in config['builders']:
        target = builder['target']
        if target in targets or load('component-build-plan').shipping_environment(root, target) is None:
            raise ValueError('Duplicate or unknown builder target')
        targets.add(target)
    publication_lock = threading.Lock()
    def attempt(builder):
        target = builder['target']
        folder = output/target
        folder.mkdir(exist_ok=True)
        archive = folder/'components.zip'
        values = {'revision': source, 'target': target, 'output': str(folder/'components'),
                  'archive': str(archive), 'root': str(root)}
        stage = 'probe'
        try:
            retained = (prior or {}).get('targets', {}).get(target)
            if retained and archive.is_file() and sha(archive) == retained['sha256']:
                verify(root, folder/'verified', target, source, controller=True)
                report['targets'][target] = {'status': 'local_verified_reused', 'sha256': retained['sha256']}
                with publication_lock:
                    manifest['targets'][target] = retained
                return
            stage='capacity'
            if shutil.disk_usage(output).free < 768*1024**2:
                raise ValueError('Insufficient owned staging capacity')
            stage='probe'
            command(builder['probe'], values, 8)
            stage = 'build'
            command(builder['build'], values, min(1800, max(1, int(builder.get('build_timeout_seconds', 900)))))
            stage = 'fetch'
            command(builder['fetch'], values, 120)
            if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
                raise ValueError('Builder archive missing/oversized')
            extracted = folder/'verified'
            if extracted.exists():
                shutil.rmtree(extracted)
            unpack(archive, extracted)
            stage = 'verify'
            verify(root, extracted, target, source, controller=True)
            digest = sha(archive)
            key = source + '/' + target + '/' + digest + '.zip'
            stage = 'upload'
            command(depot['upload'], {'file': str(archive), 'key': key}, 120)
            report['targets'][target] = {'status': 'local_verified', 'sha256': digest}
            with publication_lock:
                manifest['targets'][target] = {'url': depot['base_url'].rstrip('/')+'/'+key,
                    'sha256': digest, 'size': archive.stat().st_size}
                publish_manifest(depot, source, output, manifest)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile, RuntimeError):
            # No raw command/error output: it can contain private builder paths.
            report['targets'][target] = {'status': 'github_fallback', 'failed_phase': stage}
    # Native hosts are independent; one sleeping/offline builder cannot hold a
    # faster host's build or manifest publication behind its full build budget.
    with ThreadPoolExecutor(max_workers=3) as executor:
        list(executor.map(attempt, config['builders']))
    manifest_path = output/'manifest.json'
    final_bytes=json.dumps(manifest, sort_keys=True)
    acknowledgement=output/'manifest-uploaded.sha256'
    unchanged=acknowledgement.exists() and acknowledgement.read_text()==hashlib.sha256(final_bytes.encode()).hexdigest()
    pending_manifest=output/'manifest.pending.json'
    pending_manifest.write_text(final_bytes)
    pending_manifest.replace(manifest_path)
    report_path = output/'controller-receipt.json'
    report_path.write_text(json.dumps(report, sort_keys=True))
    # Upload last, so readers only discover verified, completed immutable ZIPs.
    # The source-keyed pointer is untrusted until HTTPS/source/input verification.
    try:
        if not unchanged:
            publish_manifest(depot,source,output,manifest)
        report['manifest_url'] = depot['base_url'].rstrip('/')+'/'+source+'/manifest.json'
        report['manifest_sha256'] = sha(manifest_path)
    except (OSError, ValueError, subprocess.SubprocessError):
        report['manifest_unavailable'] = True
    report_path.write_text(json.dumps(report, sort_keys=True))
    return report


def publish_manifest(depot, source, output, manifest):
    path = output/'manifest.json'
    pending = output/'manifest.pending.json'
    pending.write_text(json.dumps(manifest, sort_keys=True))
    pending.replace(path)
    command(depot['upload'], {'file': str(path), 'key': source+'/manifest.json'}, 30)
    acknowledgement=output/'manifest-uploaded.pending.sha256'
    acknowledgement.write_text(sha(path))
    acknowledgement.replace(output/'manifest-uploaded.sha256')


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        if urlsplit(req.full_url).netloc != urlsplit(newurl).netloc:
            raise ValueError('Cross-origin depot redirect rejected')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, path, maximum, deadline):
    https_url(url)
    opener = urllib.request.build_opener(SecureRedirect())
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Depot budget expired')
    with opener.open(url, timeout=min(10, remaining)) as response, path.open('wb') as stream:
        size = 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('Depot budget expired')
            block = response.read(min(65536, maximum-size+1))
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise ValueError('Depot response too large')
            stream.write(block)


def restore(root, source, target, endpoint, output, manifest_sha=None, previous=None, trusted_depot=None):
    revision(source)
    if output.exists() or output.is_symlink():
        raise ValueError('Restore output already exists')
    if not endpoint:
        return False
    if not trusted_depot or endpoint != https_url(trusted_depot).rstrip('/')+'/'+source+'/manifest.json':
        raise ValueError('Manifest must be the exact source-keyed operator-configured depot URL')
    deadline = time.monotonic()+150
    with tempfile.TemporaryDirectory(prefix='porthub-hybrid-') as temporary:
        temporary = Path(temporary)
        manifest_path = temporary/'manifest.json'
        download(endpoint, manifest_path, 65536, min(deadline,time.monotonic()+15))
        if manifest_sha and (not re.fullmatch('[a-f0-9]{64}', manifest_sha) or sha(manifest_path) != manifest_sha):
            raise ValueError('Manifest digest mismatch')
        manifest = json.loads(manifest_path.read_text())
        if manifest.get('schema_version') != 1 or manifest.get('source_revision') != source:
            raise ValueError('Stale local controller manifest')
        row = manifest['targets'].get(target)
        if row is None:
            return False
        if (not re.fullmatch('[a-f0-9]{64}', row['sha256']) or type(row['size']) is not int
                or not 0 < row['size'] <= MAX_ARCHIVE):
            raise ValueError('Invalid local artifact metadata')
        # A trusted endpoint cannot redirect execution/download to arbitrary sites.
        expected_url = trusted_depot.rstrip('/')+'/'+source+'/'+target+'/'+row['sha256']+'.zip'
        if row['url'] != expected_url:
            raise ValueError('Artifact must be the exact content-addressed trusted depot URL')
        archive = temporary/'artifact.zip'
        download(row['url'], archive, row['size'], deadline)
        if archive.stat().st_size != row['size'] or sha(archive) != row['sha256']:
            raise ValueError('Native artifact digest/size mismatch')
        extracted = temporary/'extracted'
        unpack(archive, extracted)
        verify(root, extracted, target, source)
        if previous is not None:
            merge_previous(extracted, previous, target)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Same-filesystem staging supports atomic install on every native OS.
        with tempfile.TemporaryDirectory(prefix='.hybrid-', dir=output.parent) as stage:
            staged = Path(stage)/'components'
            shutil.copytree(extracted, staged)
            for path in staged.rglob('*'):
                if path.is_file() and path.name not in ('index.json', 'build-receipt.json'):
                    path.chmod(0o755)
            staged.rename(output)
        return True


def merge_previous(local, previous, target):
    builder = load('build-component-platform')
    current = builder.previous_builds(local, target)
    old = builder.previous_builds(previous, target)
    index = json.loads((local/'index.json').read_text())
    for identity, (receipt, binary) in old.items():
        if identity in current:
            if current[identity][0]['binary'] != receipt['binary']:
                raise ValueError('Conflicting same-version recovered artifact')
            continue
        tool, version = identity
        folder = local/tool/version
        folder.mkdir(parents=True)
        shutil.copyfile(binary, folder/binary.name)
        receipt_path = folder/'build-receipt.json'
        receipt_path.write_bytes(builder.planner.canonical(receipt)+b'\n')
        index['builds'].append({'tool': tool, 'version': version, 'binary': (folder/binary.name).relative_to(local).as_posix(),
                                'receipt': receipt_path.relative_to(local).as_posix(), 'action': 'retain'})
    (local/'index.json').write_text(json.dumps(index,sort_keys=True))



def worker(root, source, output, tools=None, timeout=840):
    """Native opt-in builder. Only the newly spawned build process tree is owned."""
    revision(source)
    load('component-build-plan').require_clean_source(root, source)
    target = load('build-local-native').native_target(__import__('platform').system(), __import__('platform').machine())
    if output.exists() or output.is_symlink():
        raise ValueError('Worker archive must be a new path')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='porthub-native-worker-',dir=output.parent) as temporary:
        temporary = Path(temporary)
        builds = temporary/'components'
        argv = [__import__('sys').executable, str(root/'scripts/build-local-native.py'),
                '--root', str(root), '--source-revision', source, '--output', str(builds), '--execute']
        for tool in tools or []:
            argv += ['--tool', tool]
        with (temporary/'build.log').open('wb') as log:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=os.name != 'nt', creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
            try:
                status = process.wait(timeout=min(1700,max(1,timeout)))
            except subprocess.TimeoutExpired:
                if os.name == 'nt':
                    subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                else:
                    os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=10)
                raise
        if status:
            raise ValueError('Owned native build failed; no artifact published')
        verify(root,builds,target,source,controller=True)
        archive=temporary/'components.zip'
        pack(builds,archive)
        archive.rename(output)
    return {'source_revision':source,'target':target,'sha256':sha(output),'size':output.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['controller','restore','worker'])
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--target')
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--tool', action='append')
    parser.add_argument('--timeout-seconds', type=int, default=840)
    parser.add_argument('--manifest-url', default='')
    parser.add_argument('--trusted-depot', default='')
    parser.add_argument('--manifest-sha256', default='')
    args = parser.parse_args()
    if args.mode == 'controller':
        print(json.dumps(control(args.root, args.source_revision, json.loads(args.config.read_text()), args.output), sort_keys=True))
    elif args.mode == 'worker':
        print(json.dumps(worker(args.root,args.source_revision,args.output,args.tool,args.timeout_seconds),sort_keys=True))
    else:
        try:
            ok = restore(args.root, args.source_revision, args.target, args.manifest_url, args.output, args.manifest_sha256, args.previous, args.trusted_depot)
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
            ok = False
        print(json.dumps({'target': args.target, 'source_revision': args.source_revision,
                          'status': 'local_verified' if ok else 'github_fallback'}))
        raise SystemExit(0 if ok else 1)


if __name__ == '__main__':
    main()
