#!/usr/bin/env python3
"""Record actual Cargo inputs; select unchanged helper artifacts without Cargo.

Build invokes a separate pinned Cargo package build and records its merged .d
file and target-filtered dependency tree. Plan recomputes those inputs from a prior verified
receipt, so ordinary agent edits need neither helper compilation nor downloading
all registry manifests in the selection job. Artifact reuse always verifies the
binary separately before it can be copied into a release.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit

SCHEMA = 1
MAX_RECEIPT = 2 * 1024 * 1024
PRIVATE_NAMES = {'.env', '.netrc', '.npmrc', 'credentials.toml'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def relative(root, path):
    root = Path(root).resolve()
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    try:
        value = resolved.relative_to(root).as_posix()
    except ValueError:
        raise ValueError('Build input escapes the repository') from None
    if not value or any(part in PRIVATE_NAMES or part == '.git' for part in Path(value).parts):
        raise ValueError('Private configuration cannot be a published build input')
    # Stop at the resolved repository boundary. macOS /var aliases and Windows
    # 8.3 temp-directory names above that boundary are valid; source symlinks
    # inside it are still rejected, even when they point back into the checkout.
    for parent in [path, *path.parents]:
        if parent == root:
            break
        try:
            reparse = getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400
        except FileNotFoundError:
            reparse = False
        if parent.is_symlink() or reparse:
            raise ValueError('Build inputs must not contain symlinks or reparse points')
        if parent.resolve() == root:
            break
    return value


def manifest(root, name):
    data = tomllib.loads((root / name).read_text())
    workspace = tomllib.loads((root / 'Cargo.toml').read_text()).get('workspace', {})
    data = copy.deepcopy(data)
    for key, value in list(data.get('package', {}).items()):
        if isinstance(value, dict) and value.get('workspace') is True:
            data['package'][key] = copy.deepcopy(workspace.get('package', {})[key])

    def dependencies(table):
        for section in ('dependencies', 'build-dependencies'):
            for key, value in list(table.get(section, {}).items()):
                if isinstance(value, dict) and value.get('workspace') is True:
                    inherited = copy.deepcopy(workspace.get('dependencies', {})[key])
                    if isinstance(inherited, str):
                        inherited = {'version': inherited}
                    # Workspace dependency paths are rooted at the workspace,
                    # not the member. Normalize both kinds to repository paths.
                    if 'path' in inherited:
                        inherited['path'] = relative(root, inherited['path'])
                    features = set(inherited.get('features', [])) | set(value.get('features', []))
                    inherited.update({k: v for k, v in value.items() if k not in ('workspace', 'features')})
                    if features:
                        inherited['features'] = sorted(features)
                    table[section][key] = inherited
                elif isinstance(value, dict) and 'path' in value:
                    value['path'] = relative(root, (root / name).parent / value['path'])
    if data.get('lints', {}).get('workspace') is True:
        data['lints'] = copy.deepcopy(workspace.get('lints', {}))
    dependencies(data)
    for target in data.get('target', {}).values():
        dependencies(target)
    # Tests, examples and workspace membership are not shipping build inputs.
    for key in ('dev-dependencies', 'test', 'example', 'bench', 'workspace'):
        data.pop(key, None)
    for target in data.get('target', {}).values():
        target.pop('dev-dependencies', None)
    return data


def dep_paths(text):
    """Read Cargo's merged Make dependency rule, including escaped Windows paths."""
    text = text.replace('\\\r\n', '').replace('\\\n', '')
    line = next((line for line in text.splitlines() if ': ' in line), '')
    if not line:
        raise ValueError('Cargo dependency rule is missing')
    body = line.split(': ', 1)[1]
    values, current, index = [], [], 0
    while index < len(body):
        char = body[index]
        if char == '\\' and index + 1 < len(body) and body[index + 1] in '\\ \t#:':
            current.append(body[index + 1]); index += 2
        elif char == '$' and index + 1 < len(body) and body[index + 1] == '$':
            current.append('$'); index += 2
        elif char.isspace():
            if current:
                values.append(''.join(current)); current = []
            index += 1
        else:
            current.append(char); index += 1
    if current:
        values.append(''.join(current))
    if not values:
        raise ValueError('Cargo dependency rule has no inputs')
    return values


def lock_packages(root):
    return tomllib.loads((root / 'Cargo.lock').read_text())['package']


def locked(packages, node):
    choices = [row for row in packages if row['name'] == node['name']
               and row['version'] == node['version'] and row.get('source') == node.get('source')]
    if len(choices) != 1:
        raise ValueError('A selected locked dependency changed')
    return choices[0]


def dependency_name(value):
    return value.split(' ', 1)[0]


def dependency_state(packages, node):
    row = locked(packages, node)
    return {**node, 'checksum': row.get('checksum'),
            'edges': sorted(edge for edge in row.get('dependencies', [])
                            if dependency_name(edge) in node['edge_names'])}


def cargo_graph(root, recipe, target, text=None):
    root = Path(root).resolve()
    if text is None:
        command = ['cargo', '+' + toolchain(root)['channel'], 'tree', '--locked', '-p', recipe['package'], '--target', target,
                   '--edges', 'normal,build', '--prefix', 'depth', '--format', '{p}|{f}']
        if not recipe['default_features']:
            command.append('--no-default-features')
        if recipe['features']:
            command += ['--features', ','.join(recipe['features'])]
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if result.returncode:
            raise ValueError('Cannot inspect the completed package build graph')
        text = result.stdout
    packages, nodes = lock_packages(root), {}
    for line in text.splitlines():
        if line.strip() in ('[build-dependencies]',):
            continue
        match = re.fullmatch(r'\d+([A-Za-z0-9_-]+) v([0-9A-Za-z.+-]+)(.*)\|([^|]*)', line)
        if not match:
            raise ValueError('Unrecognized Cargo dependency row')
        name, version, location, features = match.groups()
        choices = [row for row in packages if row['name'] == name and row['version'] == version]
        local = re.search(r'\((/.*|[A-Za-z]:[/\\].*)\)$', location.strip())
        if local:
            choices = [row for row in choices if 'source' not in row]
        if len(choices) != 1:
            raise ValueError('Ambiguous locked package identity; rebuild with an unambiguous graph')
        row = choices[0]
        source = row.get('source')
        if source and urlsplit(re.sub(r'^(registry|git)\+', '', source)).username:
            raise ValueError('Credential-bearing dependency sources cannot be recorded')
        key = (name, version, source)
        node = nodes.setdefault(key, {'name': name, 'version': version, 'source': source, 'features': []})
        node['features'] = sorted(set(node['features']) | set(filter(None, features.removesuffix(' (*)').split(','))))
        if local:
            node['manifest'] = relative(root, Path(local.group(1)) / 'Cargo.toml')
    if not nodes or not any(node['name'] == recipe['package'] for node in nodes.values()):
        raise ValueError('The selected package is absent from the build graph')
    names = {node['name'] for node in nodes.values()}
    for node in nodes.values():
        row = locked(packages, node)
        # Cargo.lock can unify inactive edges from other workspace members. Only
        # names present in this separately built package's active tree matter.
        # Ambiguous versions of one active name are conservatively fingerprinted.
        node['edge_names'] = sorted({dependency_name(edge) for edge in row.get('dependencies', [])} & names)
    return sorted(nodes.values(), key=lambda row: (row['name'], row['version'], row['source'] or ''))


def input_state(root, path, kind):
    name = relative(root, path)
    item = root / name
    if kind == 'manifest':
        return [name, kind, digest(manifest(root, name))]
    if kind == 'directory':
        entries = []
        for child in sorted(item.rglob('*')):
            child_name = relative(root, child)
            if child.is_file():
                entries.append([child_name, file_digest(child)])
            elif not child.is_dir():
                raise ValueError('Unsupported build input type')
        return [name, kind, digest(entries)]
    if kind != 'file' or not item.is_file():
        raise ValueError('Build input is missing or not a regular file')
    return [name, kind, file_digest(item)]


def toolchain(root):
    data = tomllib.loads((root / 'rust-toolchain.toml').read_text())['toolchain']
    # Installing rustfmt/clippy or changing their installation profile does not
    # change generated binaries. Compiler changes do.
    return {'channel': data['channel']}


def patch_state(root, nodes):
    data = tomllib.loads((root / 'Cargo.toml').read_text())
    names = {node['name'] for node in nodes}
    result = {}
    for registry, patches in data.get('patch', {}).items():
        for name, value in patches.items():
            if name in names or isinstance(value, dict) and value.get('package') in names:
                value = copy.deepcopy(value)
                if isinstance(value, dict) and 'path' in value:
                    value['path'] = relative(root, value['path'])
                result.setdefault(registry, {})[name] = value
    return result


def profile_state(root, name, nodes):
    profiles = tomllib.loads((root / 'Cargo.toml').read_text()).get('profile', {})
    active = {node['name'] for node in nodes}
    visited = set()
    def resolve(current):
        if current in visited:
            raise ValueError('Build profiles contain an inheritance cycle')
        visited.add(current)
        data = copy.deepcopy(profiles.get(current, {}))
        parent = data.pop('inherits', None)
        overrides = data.pop('package', {})
        if overrides:
            selected = {key: value for key, value in overrides.items()
                        if key == '*' or key.split('@', 1)[0].split(':', 1)[0] in active}
            if selected:
                data['package'] = selected
        return {'name': current, 'settings': data, 'inherits': resolve(parent) if parent else None}
    return resolve(name)


def compiler_environment(target, profile):
    names = {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CC', 'CXX', 'AR', 'CFLAGS', 'CXXFLAGS', 'ARFLAGS', 'CARGO_INCREMENTAL', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'}
    target_key = target.replace('-', '_')
    for prefix in ['CC', 'CXX', 'AR', 'CFLAGS', 'CXXFLAGS', 'ARFLAGS']:
        names.add(prefix + '_' + target_key)
    for suffix in ['LINKER', 'RUSTFLAGS']:
        names.add('CARGO_TARGET_' + target_key.upper() + '_' + suffix)
    profile_key = 'CARGO_PROFILE_' + profile.upper().replace('-', '_') + '_'
    names.update(name for name in os.environ if name.startswith(profile_key))
    return {name: os.environ[name] for name in sorted(names) if name in os.environ}


def normalize_environment(root, environment):
    cache = Path(os.environ.get('PORTHUB_TERMINAL_HELPER_CACHE_ROOT', root/'target/terminal-helper')).resolve()
    prefix = str(cache).replace('\\','/').rstrip('/')+'/'
    normalized = {}
    for name, value in environment.items():
        if not value:
            continue
        portable = value.replace('\\','/')
        if portable.startswith(prefix):
            value = '{terminal-cache}/'+portable[len(prefix):]
        elif (name.split('_', 1)[0] in ('CC', 'CXX', 'AR') or name.endswith('_LINKER')) and Path(value).is_absolute():
            # macOS /var aliases and Windows short temporary directory names
            # can spell the same compiler cache differently. Resolve both sides
            # before deciding whether this is a portable cache-relative path.
            try:
                relative = Path(value).resolve().relative_to(cache)
            except ValueError:
                pass
            else:
                value = '{terminal-cache}/'+relative.as_posix()
        normalized[name] = value
    return normalized


def shipping_environment(root, target):
    path = root/'deploy/component-platforms.toml'
    if not path.is_file():
        return None
    data = tomllib.loads(path.read_text())
    if data.get('schema_version') != 1 or set(data.get('defaults',{})) != {'CARGO_INCREMENTAL'}:
        raise ValueError('Unsupported shipping compiler environment recipe')
    config = data['targets'].get(target)
    if config is None:
        return None
    if set(config)-{'compiler','ar','terminal_compiler','source_cc','rustflags'}:
        raise ValueError('Unknown shipping compiler environment setting')
    if 'terminal_compiler' in config and type(config['terminal_compiler']) is not bool:
        raise ValueError('Shipping terminal compiler selection must be boolean')
    environment = dict(data['defaults'])
    if any(not isinstance(value,str) for value in environment.values()):
        raise ValueError('Shipping environment values must be strings')
    key = target.replace('-','_')
    compiler = config.get('compiler')
    if config.get('terminal_compiler'):
        if compiler is not None or not isinstance(config.get('source_cc'),str):
            raise ValueError('Invalid shipping terminal compiler recipe')
        identity = hashlib.sha256((root/'vendor/terminal/sources.json').read_bytes()
            +(root/'scripts/build-terminal-helper.py').read_bytes()+target.encode()+config['source_cc'].encode()).hexdigest()[:20]
        compiler = '{terminal-cache}/'+target+'/'+identity+'/musl-runtime/bin/musl-gcc'
    if compiler is not None:
        environment['CC_'+key] = compiler
        environment['CARGO_TARGET_'+key.upper()+'_LINKER'] = compiler
    if config.get('ar'):
        environment['AR_'+key] = config['ar']
    if config.get('rustflags'):
        environment['RUSTFLAGS'] = config['rustflags']
    if any(not isinstance(value,str) or not value for value in environment.values()):
        raise ValueError('Invalid shipping environment value')
    return environment


def require_clean_source(root, revision):
    result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True)
    if result.returncode or result.stdout.strip() != revision:
        raise ValueError('Build source does not match the requested immutable revision')
    if subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root).returncode:
        raise ValueError('Release build source contains uncommitted changes')


def derived_inputs(root, recipe, target):
    if recipe['package'] != 'porthub-terminal-cli' or 'windows' in target:
        return {}
    if not {'scripts/build-terminal-helper.py', 'vendor/terminal/sources.json'}.issubset(recipe['extra_inputs']):
        raise ValueError('Terminal bundle requires tracked producer and source pins')
    configured = os.environ.get('PORTHUB_TERMINAL_BUNDLE')
    if not configured:
        raise ValueError('Terminal build requires its generated bundle')
    bundle = Path(configured)
    if bundle.is_symlink() or not bundle.is_file() or not 0 < bundle.stat().st_size <= 8*1024*1024:
        raise ValueError('Invalid generated terminal bundle')
    return {'terminal_bundle': {'size': bundle.stat().st_size, 'sha256': file_digest(bundle)}}


def build_state(root, recipe, target, paths, nodes, environment=None):
    packages = lock_packages(root)
    state = {'recipe': recipe, 'target': target, 'toolchain': toolchain(root),
            'profile': profile_state(root, recipe['profile'], nodes),
            'environment': normalize_environment(root, compiler_environment(target, recipe['profile'])) if environment is None else environment,
            'resolver': tomllib.loads((root / 'Cargo.toml').read_text()).get('workspace', {}).get('resolver'),
            'patches': patch_state(root, nodes),
            'inputs': [input_state(root, path, kind) for path, kind in sorted(paths)],
            'dependencies': [dependency_state(packages, node) for node in nodes]}
    generated = derived_inputs(root, recipe, target)
    if generated:
        state['derived_inputs'] = generated
    return state


def read_recipes(root):
    data = tomllib.loads((root / 'deploy/components.toml').read_text())
    if data.get('schema_version') != SCHEMA:
        raise ValueError('Unsupported component build recipe schema')
    return data['tools']


def stable_version(version):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Component versions must be stable numeric versions')
    return tuple(map(int, version.split('.')))


def current_version(root, recipe):
    return manifest(root, recipe['manifest'])['package']['version']


def validate_receipt(receipt):
    if receipt.get('schema_version') != SCHEMA:
        raise ValueError('Unsupported build receipt schema')
    payload = {key: value for key, value in receipt.items() if key != 'receipt_sha256'}
    if receipt.get('receipt_sha256') != digest(payload) or receipt.get('fingerprint') != digest(receipt['build']):
        raise ValueError('Build receipt integrity mismatch')
    stable_version(receipt['version'])
    if not re.fullmatch(r'[a-f0-9]{40}', receipt['source_revision']):
        raise ValueError('Build receipt requires immutable source provenance')
    binary = receipt['binary']
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+', binary['name']) or not 0 < binary['size'] <= 512 * 1024 * 1024
            or not re.fullmatch(r'[a-f0-9]{64}', binary['sha256'])):
        raise ValueError('Invalid recorded binary identity')
    return receipt


def record(root, tool, target, binary, dep_info, revision, version=None, tree=None, script_dep_infos=()):
    root = Path(root).resolve()
    recipe = read_recipes(root)[tool]
    nodes = cargo_graph(root, recipe, target, tree)
    generated = derived_inputs(root, recipe, target)
    generated_bundle = Path(os.environ['PORTHUB_TERMINAL_BUNDLE']).resolve() if generated else None
    paths = set()
    dependency_paths = []
    for information in [dep_info, *script_dep_infos]:
        dependency_paths.extend(dep_paths(information.read_text()))
    for value in dependency_paths:
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        if generated_bundle is not None and path.resolve() == generated_bundle:
            continue  # Exact derived artifact is hashed separately, never trusted as source.
        try:
            name = path.resolve().relative_to(root).as_posix()
        except ValueError:
            continue  # Registry sources are pinned by locked identities/checksums.
        if name.startswith('target/'):
            continue  # Generated outputs are covered by source/build-script inputs.
        paths.add((name, 'directory' if path.is_dir() else 'file'))
    for node in nodes:
        if 'manifest' not in node:
            continue
        name = node['manifest']; paths.add((name, 'manifest'))
        package = manifest(root, name)['package']
        build = package.get('build', 'build.rs')
        if build and isinstance(build, str):
            script = (root / name).parent / build
            if script.exists():
                paths.add((relative(root, script), 'file'))
    for name in recipe['extra_inputs']:
        paths.add((relative(root, name), 'directory' if (root / name).is_dir() else 'file'))
    for config in ['.cargo/config', '.cargo/config.toml']:
        if (root / config).exists():
            paths.add((config, 'file'))
    if not any(path.endswith('.rs') for path, _ in paths):
        raise ValueError('Build receipt requires actual compiled Rust source inputs')
    build = build_state(root, recipe, target, paths, nodes)
    receipt = {'schema_version': SCHEMA, 'tool': tool, 'target': target,
               'version': version or current_version(root, recipe), 'source_revision': revision,
               'binary': {'name': recipe['binary'] + ('.exe' if 'windows' in target else ''),
                          'size': binary.stat().st_size, 'sha256': file_digest(binary)},
               'build': build, 'fingerprint': digest(build)}
    receipt['receipt_sha256'] = digest(receipt)
    return validate_receipt(receipt)


def plan(root, tool, target, previous=None, environment=None):
    root = Path(root).resolve()
    recipe = read_recipes(root)[tool]
    version = current_version(root, recipe)
    reason = 'No previous compatible build receipt'
    if previous is not None:
        validate_receipt(previous)
        if previous['tool'] == tool and previous['target'] == target:
            nodes = [{key: value for key, value in node.items() if key not in ('checksum', 'edges')}
                     for node in previous['build']['dependencies']]
            paths = [(row[0], row[1]) for row in previous['build']['inputs']]
            try:
                current = build_state(root, recipe, target, paths, nodes, environment)
                if digest(current) == previous['fingerprint']:
                    return {'tool': tool, 'target': target, 'action': 'reuse',
                            'version': previous['version'], 'fingerprint': previous['fingerprint'],
                            'requires_artifact_verification': True}
                reason = 'Compiled inputs, dependency selection, toolchain or build recipe changed'
            except (ValueError, KeyError, FileNotFoundError):
                reason = 'A recorded build input or dependency is no longer available'
            old = stable_version(previous['version']); requested = stable_version(version)
            if tool == 'core' and requested <= old:
                raise ValueError('Changed core contents require a new release version')
            if tool != 'core' and requested <= old:
                version = '.'.join(map(str, (old[0], old[1], old[2] + 1)))
    return {'tool': tool, 'target': target, 'action': 'build', 'version': version, 'reason': reason}


def verify_reuse(receipt, binary):
    validate_receipt(receipt)
    if binary.is_symlink() or binary.stat().st_size != receipt['binary']['size'] or file_digest(binary) != receipt['binary']['sha256']:
        raise ValueError('Previous component binary does not match its verified build receipt')


def read_receipt(path):
    if path.stat().st_size > MAX_RECEIPT:
        raise ValueError('Build receipt exceeds limit')
    return validate_receipt(json.loads(path.read_text()))


def build_and_record(root, tool, target, revision, version=None, binary_output=None):
    require_clean_source(root, revision)
    recipe = read_recipes(root)[tool]
    version = version or current_version(root, recipe)
    requested = stable_version(version)
    current = stable_version(current_version(root, recipe))
    if tool == 'core' and requested != current or tool != 'core' and requested < current:
        raise ValueError('Build version does not match the selected package version policy')
    expected_environment = shipping_environment(root, target)
    if expected_environment is not None and normalize_environment(root, compiler_environment(target, recipe['profile'])) != expected_environment:
        raise ValueError('Shipping compiler environment differs from deploy/component-platforms.toml')
    generated_before = derived_inputs(root, recipe, target)
    command = ['cargo', '+' + toolchain(root)['channel'], 'build', '--locked',
               '-p', recipe['package'], '--bin', recipe['binary'], '--target', target,
               '--profile', recipe['profile'], '--message-format=json-render-diagnostics']
    if not recipe['default_features']:
        command.append('--no-default-features')
    if recipe['features']:
        command += ['--features', ','.join(recipe['features'])]
    environment = os.environ.copy()
    if tool != 'core':
        environment['PORTHUB_COMPONENT_VERSION'] = version
    else:
        environment.pop('PORTHUB_COMPONENT_VERSION', None)
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True)
    sys.stderr.write(result.stderr)
    outputs = set()
    script_dep_infos = set()
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == recipe['binary'] and message.get('executable'):
            outputs.add(message['executable'])
        if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('kind') == ['custom-build']:
            source = Path(message['target']['src_path']).resolve()
            if source.is_relative_to(root):
                dependencies = {path for filename in message.get('filenames', [])
                    for path in Path(filename).parent.glob('build_script_build-*.d')}
                if len(dependencies) != 1:
                    raise ValueError('Local build-script dependency information is unavailable')
                script_dep_infos.update(dependencies)
        if message.get('reason') == 'compiler-message':
            sys.stderr.write(message.get('message', {}).get('rendered') or '')
    if result.returncode or len(outputs) != 1:
        raise ValueError('The selected component build did not produce exactly one executable')
    require_clean_source(root, revision)
    binary = Path(outputs.pop())
    receipt = record(root, tool, target, binary, binary.with_suffix('.d'), revision, version,
                     script_dep_infos=sorted(script_dep_infos))
    if receipt['build'].get('derived_inputs', {}) != generated_before:
        raise ValueError('Generated terminal bundle changed during compilation')
    # CI provenance must not attest arbitrary untracked inputs merely because
    # their paths were named by a generated dependency file.
    for name, kind, _ in receipt['build']['inputs']:
        tracked = subprocess.run(['git', 'ls-files', '--error-unmatch', '--', name], cwd=root, capture_output=True)
        if tracked.returncode:
            raise ValueError('A compiled input is not part of the immutable checkout')
    if binary_output is not None:
        import shutil
        binary_output = Path(binary_output)
        if binary_output.exists() or binary_output.is_symlink():
            raise ValueError('Build binary output must be a new file')
        shutil.copyfile(binary, binary_output)
        binary_output.chmod(0o755)
        verify_reuse(receipt, binary_output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    sub = parser.add_subparsers(dest='command', required=True)
    capture = sub.add_parser('build')
    for name in ['tool', 'target', 'source-revision']:
        capture.add_argument('--' + name, required=True)
    for name in ['output']:
        capture.add_argument('--' + name, type=Path, required=True)
    capture.add_argument('--version')
    capture.add_argument('--binary-output', type=Path)
    select = sub.add_parser('plan')
    select.add_argument('--tool', required=True); select.add_argument('--target', required=True)
    select.add_argument('--previous', type=Path)
    select.add_argument('--shipping-environment', action='store_true', help='Plan from the declared target environment without compiling')
    verify = sub.add_parser('verify-reuse')
    verify.add_argument('--receipt', type=Path, required=True); verify.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args(); root = args.root.resolve()
    if args.command == 'build':
        receipt = build_and_record(root, args.tool, args.target, args.source_revision, args.version, args.binary_output)
        args.output.write_bytes(canonical(receipt) + b'\n')
        print(json.dumps({'tool': args.tool, 'fingerprint': receipt['fingerprint'], 'inputs': len(receipt['build']['inputs'])}))
    elif args.command == 'plan':
        print(json.dumps(plan(root, args.tool, args.target, read_receipt(args.previous) if args.previous else None,
                              shipping_environment(root,args.target) if args.shipping_environment else None)))
    else:
        verify_reuse(read_receipt(args.receipt), args.binary)
        print('Previous component binary matches its verified build receipt')


if __name__ == '__main__':
    main()
