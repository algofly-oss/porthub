#!/usr/bin/env python3
"""Actual agent/API native exit or paired-stream fixture; disposable Docker only."""
import argparse
import hashlib
import ipaddress
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)

def output(argv):
    return subprocess.check_output(argv, text=True, timeout=30).strip()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sparse', action='store_true')
    parser.add_argument('--worker-profile', choices=['test', 'agent-dev'], default='test', help='explicit worker-only profile; host API fixture remains test profile')
    parser.add_argument('--scenario', choices=['exits', 'peers'], default='exits')
    parser.add_argument('--source', required=True, help='exact immutable source SHA')
    parser.add_argument('--image', required=True, help='existing local sha256 image ID; no pull/build')
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.source)
    assert re.fullmatch('sha256:[0-9a-f]{64}', args.image)
    assert args.scenario != 'peers' or args.sparse, 'paired quic3 proof requires sparse negotiation'
    assert output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']) == args.source
    assert not output(['git', '-C', str(ROOT), 'diff', '--name-only', 'HEAD']), 'tracked source changes present'
    receipt = pathlib.Path(args.receipt)
    assert not receipt.exists(), 'preserve existing evidence; choose a fresh receipt'
    env = {**os.environ, 'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_TEST_DEBUG': '0',
           'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_INCREMENTAL': '0'}
    artifacts = {}
    proof = {'source': args.source, 'sparse': args.sparse, 'scenario': args.scenario,
             'image': args.image, 'worker_profile': args.worker_profile, 'host_api_profile': 'test', 'native_executed': False, 'completed': False,
             'network_cleanup': False, 'preexisting_containers_preserved': False}
    networks = []
    runtime_stage = None
    before = set()
    network_before = set()
    try:
        for package, target, features in [('porthub-agent', 'exit_worker', ['netns-tests']),
                                          ('porthub-api', 'exit_network', [])]:
            if args.sparse:
                features.append('private-sparse')
            command = [str(pathlib.Path.home()/'.cargo/bin/cargo'), 'test', '-p', package]
            if features:
                command += ['--features', ','.join(features)]
            command += ['--test', target, '--no-run', '--locked', '--message-format=json']
            if target == 'exit_worker' and args.worker_profile != 'test':
                command += ['--profile', args.worker_profile]
            build_log = receipt.with_name(receipt.stem + '-' + target + '-cargo.jsonl')
            with build_log.open('x+') as build_output:
                build = subprocess.run(command, cwd=ROOT, env=env, stdout=build_output)
                build_output.seek(0)
                messages = [json.loads(line) for line in build_output]
            proof.setdefault('build_logs', {})[target] = {'path': str(build_log), 'sha256': hashlib.sha256(build_log.read_bytes()).hexdigest()}
            if build.returncode:
                for item in messages:
                    if item.get('reason') == 'compiler-message':
                        print(item['message'].get('rendered', ''), flush=True)
                build.check_returncode()
            artifact = next(item for item in messages
                            if item.get('reason') == 'compiler-artifact' and item.get('executable')
                            and item['target']['name'] == target)
            expected_opt = '3' if target == 'exit_worker' and args.worker_profile == 'agent-dev' else '0'
            assert artifact['profile']['opt_level'] == expected_opt, 'unexpected native fixture optimization profile'
            proof.setdefault('compiler_profiles', {})[target] = artifact['profile']
            artifacts[target] = artifact['executable']
        proof['executables'] = {name: {'path': path, 'bytes': pathlib.Path(path).stat().st_size,
                                     'sha256': hashlib.file_digest(open(path, 'rb'), 'sha256').hexdigest()}
                                for name, path in artifacts.items()}
        if args.build_only:
            proof['build_only'] = True
            proof['completed'] = True
            return
        assert env.get('PORTHUB_TEST_MONGO_URI', '').startswith('mongodb://127.0.0.1:'), 'isolated loopback Mongo required'
        if args.sparse:
            source = (ROOT/'crates/porthub-agent/src/private_network/stream_offer.rs').read_text()
            assert 'const NATIVE_LIFECYCLE_APPROVED: bool = true;' in source, 'reviewed native lifecycle transition not enabled; no runtime bypass'
        image = json.loads(output(['docker', 'image', 'inspect', args.image]))[0]
        assert image['Id'] == args.image and image['Os'] == 'linux'
        # Reuse the existing native fixture's root-owned system ELF dependency
        # checks; old images must not supply a mismatched glibc to a new worker.
        spec = importlib.util.spec_from_file_location('native_dependencies', ROOT/'scripts/private-sparse-native-netns.py')
        dependencies = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dependencies)
        libraries, loader = dependencies.dependencies(pathlib.Path(artifacts['exit_worker']))
        assert loader, 'matching system runtime loader missing'
        runtime_stage = pathlib.Path(tempfile.mkdtemp(prefix='porthub-exit-runtime-'))
        runtime_stage.chmod(0o700)
        runtime_root = runtime_stage/'lib'
        runtime_root.mkdir(mode=0o755)
        runtime_files = {}
        for library in libraries:
            target = runtime_root/library.name
            digest = hashlib.sha256(library.read_bytes()).hexdigest()
            assert library.name not in runtime_files or runtime_files[library.name] == digest, 'conflicting ELF dependency basename'
            shutil.copyfile(library, target)
            target.chmod(0o555)
            assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
            runtime_files[library.name] = digest
        proof['matching_runtime'] = {'stage': str(runtime_stage), 'files': runtime_files, 'loader': pathlib.Path(loader).name,
                                     'validator_sha256': hashlib.sha256((ROOT/'scripts/private-sparse-native-netns.py').read_bytes()).hexdigest()}
        before = set(output(['docker', 'ps', '-aq', '--no-trunc']).splitlines())
        network_before = set(output(['docker', 'network', 'ls', '-q', '--no-trunc']).splitlines())
        routes = json.loads(output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
        subnets = ['198.18.10.0/24', '203.0.113.0/24']
        for subnet in subnets:
            candidate = ipaddress.ip_network(subnet)
            assert not any(route.get('dst') not in (None, 'default') and candidate.overlaps(
                ipaddress.ip_network(route['dst'], strict=False)) for route in routes), f'fixture subnet overlap: {subnet}'
        prefix = 'porthub-exit-test-' + secrets.token_hex(8)
        proof['nonce'] = prefix
        for suffix, subnet in zip(['control', 'external'], subnets):
            name = prefix + '-' + suffix
            identifier = output(['docker', 'network', 'create', '--internal', '--label',
                                 'porthub.exit_fixture=' + prefix, '--subnet', subnet, name])
            networks.append((name, identifier))
        env.update(PORTHUB_TEST_CONTROL_NETWORK=networks[0][0], PORTHUB_TEST_EXTERNAL_NETWORK=networks[1][0],
                   PORTHUB_TEST_WORKER_BINARY=artifacts['exit_worker'], PORTHUB_TEST_WORKER_IMAGE=args.image,
                   PORTHUB_TEST_FIXTURE_NONCE=prefix, PORTHUB_TEST_SPARSE='1' if args.sparse else '0',
                   PORTHUB_TEST_RUNTIME_ROOT=str(runtime_root), PORTHUB_TEST_RUNTIME_LOADER=pathlib.Path(loader).name)
        test = 'native_agents_use_two_exits_and_preserve_established_tcp' if args.scenario == 'exits' else 'native_agents_negotiate_quic3_and_transfer_owned_tcp'
        proof['test'] = test
        proof['native_executed'] = True
        run([artifacts['exit_network'], '--ignored', '--exact', test, '--nocapture'], cwd=ROOT, env=env, timeout=300)
        proof['completed'] = True
    finally:
        cleanup_errors = []
        for name, identifier in networks:
            # Per-action failures retain the receipt and do not skip other own
            # cleanup. No failed identity lookup authorizes a delete.
            try:
                ids = output(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=porthub.exit_fixture=' + proof['nonce']]).splitlines()
            except Exception:
                cleanup_errors.append('owned-container-list-unavailable')
                ids = []
            for container in ids:
                try:
                    info = json.loads(output(['docker', 'inspect', container]))[0]
                    if (info['Id'] in before or info['Config']['Labels'].get('porthub.exit_fixture') != proof['nonce']
                            or info['Image'] != args.image):
                        cleanup_errors.append('foreign-container-identity')
                        continue
                    result = subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, timeout=30)
                    if result.returncode: cleanup_errors.append('owned-container-remove')
                except Exception:
                    cleanup_errors.append('owned-container-cleanup-unavailable')
            try:
                info = json.loads(output(['docker', 'network', 'inspect', identifier]))[0]
                if info['Id'] != identifier or info['Name'] != name or info['Labels'].get('porthub.exit_fixture') != proof['nonce']:
                    cleanup_errors.append('foreign-network-identity')
                    continue
                result = subprocess.run(['docker', 'network', 'rm', identifier], stdout=subprocess.DEVNULL, timeout=30)
                if result.returncode: cleanup_errors.append('owned-network-remove')
            except Exception:
                cleanup_errors.append('owned-network-cleanup-unavailable')
        if networks:
            try:
                after = set(output(['docker', 'ps', '-aq', '--no-trunc']).splitlines())
                proof['preexisting_containers_preserved'] = before <= after
                network_after = set(output(['docker', 'network', 'ls', '-q', '--no-trunc']).splitlines())
                proof['preexisting_networks_preserved'] = network_before <= network_after
                proof['owned_networks_absent'] = not ({identifier for _, identifier in networks} & network_after)
                remaining = output(['docker', 'ps', '-aq', '--filter', 'label=porthub.exit_fixture=' + proof['nonce']])
                proof['owned_containers_absent'] = not remaining
                if not all(proof[key] for key in ['preexisting_containers_preserved', 'preexisting_networks_preserved', 'owned_networks_absent', 'owned_containers_absent']):
                    cleanup_errors.append('independent-final-cleanup-mismatch')
            except Exception:
                cleanup_errors.append('independent-final-cleanup-unavailable')
            proof['network_cleanup'] = not cleanup_errors
        if runtime_stage is not None:
            if proof.get('owned_containers_absent'):
                try:
                    shutil.rmtree(runtime_stage)
                    proof['runtime_stage_removed'] = not runtime_stage.exists()
                except Exception:
                    cleanup_errors.append('owned-runtime-stage-remove')
            else:
                proof['runtime_stage_removed'] = False
        proof['cleanup_errors'] = cleanup_errors
        receipt.write_text(json.dumps(proof, indent=2) + '\n')
        if networks:
            assert not cleanup_errors and proof['preexisting_containers_preserved'], 'fixture cleanup failed; see receipt'

if __name__ == '__main__':
    main()
