#!/usr/bin/env python3
"""Opt-in disposable native Windows SCM updater gate; never runs on import.

This controller uses real versioned executables and normal service installation.
It is intentionally separate from production release workflows and host upgrades.
This revision implements success/rollback with two enrollments and higher shared
CLI/GUI. Revocation and crash-recovery native scenarios remain separate gates.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import time
import uuid


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cold = load('cold_prerequisites', 'test-windows-usb-prerequisites.py')
gateway_module = load('update_gateway', 'windows-update-fixture-gateway.py')


def ps_result(script):
    environment = os.environ.copy()
    environment.pop('PSModulePath', None)
    executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
    encoded = base64.b64encode((prefix + script).encode('utf-16le')).decode()
    result = subprocess.run([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            env=environment, capture_output=True, timeout=60, creationflags=0x08000000)
    if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 32768:
        raise RuntimeError('Bounded native PowerShell fixture operation failed')
    return result


def ps(script):
    return ps_result(script).stdout.decode('utf-8-sig', errors='strict').strip()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def wait_for(predicate, seconds, label):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if time.monotonic() >= deadline:
            break  # A late return cannot prove a bounded operation.
        if value:
            return value
        time.sleep(min(.2, max(0, deadline - time.monotonic())))
    raise RuntimeError('Timed out: ' + label)


def artifacts_from_manifest(path):
    receipt_path = Path(path)
    if receipt_path.stat().st_size > 65536:
        raise ValueError('Native receipt exceeds bound')
    value = json.loads(receipt_path.read_text())
    if set(value) != {'schema', 'wrapper_source', 'artifacts'} or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Invalid private native artifact receipt')
    if not isinstance(value['wrapper_source'], str) or len(value['wrapper_source']) != 40 or any(c not in '0123456789abcdef' for c in value['wrapper_source']):
        raise ValueError('Invalid controller source revision')
    rows = value['artifacts']
    if len(rows) != 3 or [r['role'] for r in rows] != ['a', 'b', 'c']:
        raise ValueError('Exactly ordered A/B/C artifacts required')
    previous = None
    for row in rows:
        if set(row) != {'role', 'path', 'version', 'source', 'sha256', 'size', 'target', 'os', 'arch', 'asset'}:
            raise ValueError('Unknown artifact receipt field')
        version = tuple(int(x) for x in row['version'].split('.'))
        if len(version) != 3 or (previous is not None and version <= previous):
            raise ValueError('A < B < C real versions required')
        previous = version
        if (row['target'], row['os'], row['arch'], row['asset']) != ('windows_x86_64', 'windows', 'x86_64', 'porthub-windows_x86_64.exe'):
            raise ValueError('Only reviewed Windows x64 native gate supported')
        if (len(row['source']) != 40 or any(c not in '0123456789abcdef' for c in row['source'])
                or type(row['size']) is not int or not 0 < row['size'] <= 256 * 1024 * 1024):
            raise ValueError('Invalid native source/size receipt')
        supplied = Path(row['path'])
        if supplied.is_symlink() or getattr(supplied.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse native artifact refused')
        path = supplied.resolve(strict=True)
        if path.is_symlink() or path.stat().st_size != row['size'] or digest(path) != row['sha256']:
            raise ValueError('Native artifact changed')
        row['path'] = str(path)
    return value


def run_case(adapter, rollback):
    """Same orchestration for real SCM and offline failure-injection adapters."""
    proof = {'completed': False, 'scenario': 'rollback' if rollback else 'success', 'cleanup_errors': []}
    try:
        proof['preflight'] = adapter.preflight()
        adapter.stage()
        adapter.install_pair()
        baseline = adapter.preservation_snapshot()
        adapter.advertise(rollback)
        adapter.assert_disabled()
        adapter.enable_updates()
        proof['transaction'] = adapter.wait_transaction(rollback)
        adapter.assert_preserved(baseline)
        adapter.assert_ack(rollback)
        proof['completed'] = True
    except Exception as error:
        proof['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        # A failed earlier cleanup step never skips later ownership checks.
        for name in ('disable_updates', 'stop_workers', 'uninstall_pair', 'cleanup_desktop',
                     'restore_path', 'postcheck', 'remove_staging', 'close_gateway'):
            try:
                getattr(adapter, name)()
            except Exception as error:
                proof['cleanup_errors'].append(name + ': ' + type(error).__name__ + ': ' + str(error))
    if proof['cleanup_errors']:
        proof['completed'] = False
    return proof


class Native(cold.Native):
    def __init__(self, receipt):
        a, self.b, self.c = receipt['artifacts']
        super().__init__(a['path'], a['sha256'], receipt['wrapper_source'])
        self.a = a
        self.rows = receipt['artifacts']
        self.gateway = None
        self.profiles = {}
        self.installed_ids = []
        self.claimed_published = False
        self.claimed_status = False
        self.extra_claims = []
        self.user_state = Path(os.environ.get('LOCALAPPDATA', '')) / 'porthub'
        self.component_state = self.root.with_name('PortHubComponents')
        self.grant_fixture_user = False
        self.status_root = self.root.with_name('PortHubStatus')
        self.published = Path(os.environ.get('ProgramFiles', '')) / 'PortHub'

    def preflight(self):
        result = super().preflight()
        if any(os.path.lexists(path) for path in (self.user_state, self.component_state)):
            raise RuntimeError('Existing user/component fixture namespace; preserved')
        if os.path.lexists(self.status_root):
            raise RuntimeError('Existing readable status root; preserved')
        if os.path.lexists(self.published):
            raise RuntimeError('Existing published CLI root; preserved')
        if self.before['tasks']:
            raise RuntimeError('Existing PortHub desktop task; preserved')
        ps("if(Get-Service -Name 'porthub-*' -ErrorAction SilentlyContinue){throw 'Existing PortHub service'}")
        for row in self.rows:
            output = subprocess.run([row['path'], 'version'], capture_output=True, timeout=10, creationflags=0x08000000)
            wanted = 'porthub ' + row['version'] + '\nbuild ' + row['source'] + '\ntarget x86_64-pc-windows-msvc'
            if output.returncode or output.stdout.decode().strip().replace('\r\n', '\n') != wanted:
                raise RuntimeError('Native artifact version/source/target differs from receipt')
        return result

    def stage(self):
        # Exclusive ownership claims and protected marker checks are inherited
        # from the independently tested cold-runner wrapper.
        machines = [self.machine, uuid.uuid4().hex[:24]]
        tokens = {machine: uuid.uuid4().hex for machine in machines}
        self.gateway = gateway_module.Gateway({r['version']: r for r in self.rows}, tokens, self.journal_for)
        self.origin = self.gateway.start()
        self.identity = hashlib.sha256((self.origin + '\n' + self.machine).encode()).hexdigest()
        self.profile = self.root / 'native' / (self.identity + '.json')
        self.service = 'porthub-' + self.identity[:24]
        super().stage()
        self.status_root.mkdir()
        self.claimed_status = True
        self.claim(self.status_root, 'readable-status')
        for path, kind in ((self.user_state, 'desktop-state'), (self.component_state, 'component-state')):
            path.mkdir()
            self.extra_claims.append(kind)
            self.grant_fixture_user = kind == 'desktop-state'
            try:
                self.claim(path, kind)
            finally:
                self.grant_fixture_user = False
        for index, machine in enumerate(machines):
            identity = hashlib.sha256((self.origin + '\n' + machine).encode()).hexdigest()
            profile = self.root / 'native' / (identity + '.json')
            input_path = self.folder / ('profile.json' if index == 0 else 'other-profile.json')
            self.private(input_path, dict(format_version=1, server=self.origin, machine_id=machine,
                                         token=tokens[machine], fallback_servers=[], setup_overrides={},
                                         allow_insecure_http_for_tests=True))
            for suffix, features in [('.client-features.json', cold.BASE_FEATURES),
                                     ('.media-policy.json', cold.MEDIA_FEATURES),
                                     ('.drive-health-policy.json', ('drive-health', 'drive-tests'))]:
                self.private(Path(str(profile) + suffix), {'disabled': dict.fromkeys(features, True)})
            self.profiles[machine] = dict(identity=identity, profile=profile, input=input_path)
        self.profile = self.profiles[self.machine]['profile']
        self.identity = self.profiles[self.machine]['identity']
        self.service = 'porthub-' + self.identity[:24]

    def journal_for(self, machine):
        row = self.profiles.get(machine)
        if not row:
            return None
        try:
            return json.loads(Path(str(row['profile']) + '.windows-update.json').read_text())
        except (OSError, ValueError):
            return None

    def claim(self, path, kind):
        super().claim(path, kind)
        if kind == 'readable-status':
            # The normal status reader parses every *.json. Keep ownership
            # metadata outside that protocol without changing its validation.
            directory, identity, marker, sha = self.claims[kind]
            target = marker.with_suffix('.owner')
            marker.rename(target)
            self.claims[kind] = (directory, identity, target, sha)

    def protect_directory(self, path):
        if not self.grant_fixture_user:
            return super().protect_directory(path)
        # Only this newly claimed user's own private directory. This creates no
        # service grant, account, task, or persistent system-wide permission.
        ps('$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;icacls ' + cold.quote(path) +
           " /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' ('*'+$sid+':(OI)(CI)(F)')|Out-Null;if($LASTEXITCODE){throw 'Fixture directory ACL failed'}")

    def invoke(self, row, *args):
        result = subprocess.run([row['path'], *map(str, args)], capture_output=True,
                                timeout=180, creationflags=0x08000000)
        if result.returncode or len(result.stdout) > 131072 or len(result.stderr) > 32768:
            raise RuntimeError('Native fixture CLI failed: ' + str(args[:2]))
        return result.stdout.decode('utf-8', errors='strict')

    def install_pair(self):
        import winreg
        self.validate_claim('managed')
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment') as key:
            self.old_path, self.path_type = winreg.QueryValueEx(key, 'Path')
        self.published.mkdir()
        self.claimed_published = True
        self.claim(self.published, 'published')
        # Normal installation alone is allowed to publish/grant the runner's own
        # desktop. No manually forged production grants or task definitions.
        for machine, row in zip(self.profiles, [self.a, self.c]):
            profile = self.profiles[machine]
            self.installed_ids.append(machine)
            self.invoke(row, 'service', 'install', '--profile', profile['input'], '--publish-cli')
        self.cli_path = self.published / 'bin/porthub.exe'
        if digest(self.cli_path) != self.c['sha256']:
            raise RuntimeError('Other enrollment did not publish the higher CLI')
        self.published_created = True
        self.task_before = wait_for(self.task_snapshot, 40, 'higher shared GUI process ready')
        if self.task_before['sha256'] != self.c['sha256']:
            raise RuntimeError('Higher shared GUI task was not installed')

    def task_snapshot(self):
        raw = ps(r"""
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$svc=[Activator]::CreateInstance([type]::GetTypeFromProgID('Schedule.Service'));$svc.Connect()
$t=$svc.GetFolder('\').GetTask('PortHubKeyboard-'+$sid);$d=$t.Definition
function SID($s){if($s -like 'S-1-*'){return $s};([Security.Principal.NTAccount]$s).Translate([Security.Principal.SecurityIdentifier]).Value}
if((SID $d.Principal.UserId) -ne $sid -or [int]$d.Principal.LogonType -ne 3 -or [int]$d.Principal.RunLevel -ne 0 -or $d.Actions.Count -ne 1){throw 'Unexpected fixture desktop ownership'}
$a=$d.Actions.Item(1);if($a.Arguments -ne 'keyboard startup'){throw 'Unexpected fixture desktop action'}
$f=[IO.File]::OpenRead($a.Path);try{$sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($f)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}finally{$f.Dispose()}
$processes=@();foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'")){
 if($p.ExecutablePath -eq $a.Path -and $p.SessionId -gt 0 -and $p.CommandLine -match '(?i)\skeyboard\s+startup\s*$'){
  $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
  if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid){$processes+=@{pid=$p.ProcessId;created=[string]$p.CreationDate}}
 }
}
@{path=[string]$a.Path;sha256=$hash;xml=[string]$t.Xml;sd=[string]$t.GetSecurityDescriptor(7);enabled=[bool]$t.Enabled;state=[int]$t.State;processes=@($processes)}|ConvertTo-Json -Depth 4 -Compress
""")
        value = json.loads(raw)
        expected = self.root / 'releases' / self.c['sha256'] / 'porthub.exe'
        if Path(value['path']) != expected or value['sha256'] != self.c['sha256']:
            raise RuntimeError('Shared GUI action is not the pinned higher image')
        if not value['enabled'] or value['state'] != 4 or len(value['processes']) != 1:
            return None
        return value

    def preservation_snapshot(self):
        other = next(value for machine, value in self.profiles.items() if machine != self.machine)
        paths = [other['profile'], Path(str(other['profile']) + '.service.json')]
        for value in self.profiles.values():
            paths.extend(Path(str(value['profile']) + suffix) for suffix in
                         ('.client-features.json', '.media-policy.json', '.drive-health-policy.json', '.local-access.json'))
        task = self.task_snapshot()
        process = self.scm_snapshot(other['identity'])
        if task is None or process['sha256'] != self.c['sha256']:
            raise RuntimeError('Higher shared enrollment/GUI not ready at baseline')
        return {'files': {str(path): digest(path) for path in paths if path.exists()},
                'other_identity': other['identity'], 'other_process': process, 'task': task}

    def scm_snapshot(self, identity):
        service = 'porthub-' + identity[:24]
        raw = ps('$s=Get-CimInstance Win32_Service -Filter ' + cold.quote("Name='" + service + "'") +
                 ";if($s.State -ne 'Running' -or $s.StartName -ne 'LocalSystem'){throw 'Fixture SCM service not running'};" +
                 '$p=Get-CimInstance Win32_Process -Filter ("ProcessId="+$s.ProcessId);@{pid=$p.ProcessId;path=$p.ExecutablePath}|ConvertTo-Json -Compress')
        value = json.loads(raw)
        if not value.get('pid') or not value.get('path'):
            raise RuntimeError('SCM process metadata unavailable')
        value['sha256'] = digest(value['path'])
        return value

    def advertise(self, rollback):
        self.gateway.fail_version = self.b['version'] if rollback else None
        self.request_id = self.gateway.advertise(self.machine, self.b['version'])

    def assert_disabled(self):
        wait_for(lambda: any(e['kind'] == 'request-observed' and e.get('machine') == self.machine for e in self.gateway.events),
                 40, 'disabled client observed the actual update request')
        start = time.monotonic()
        while time.monotonic() - start < 5:
            if self.journal_for(self.machine) or any(e['kind'] == 'download' for e in self.gateway.events):
                raise RuntimeError('Disabled AutoUpdate performed staging')
            time.sleep(.1)

    def enable_updates(self):
        self.cli('features', '--registration', self.identity, 'enable', 'auto-update')

    def wait_transaction(self, rollback):
        phase = 'rolled-back' if rollback else 'committed'
        record = wait_for(lambda: (r if (r := self.journal_for(self.machine)) and r.get('phase') == phase else None),
                          150, 'real native transaction ' + phase)
        expected = self.a if rollback else self.b
        spec = json.loads(Path(str(self.profile) + '.service.json').read_text())
        if digest(spec['executable']) != expected['sha256']:
            raise RuntimeError('SCM registration has wrong endpoint image')
        service = 'porthub-' + self.identity[:24]
        raw = ps('$s=Get-CimInstance Win32_Service -Filter ' + cold.quote("Name='" + service + "'") +
                      ";if($s.State -ne 'Running' -or $s.StartName -ne 'LocalSystem'){throw 'Fixture service not ready'};" +
                      '$p=Get-CimInstance Win32_Process -Filter ("ProcessId="+$s.ProcessId);@{pid=$p.ProcessId;path=$p.ExecutablePath}|ConvertTo-Json -Compress')
        process = json.loads(raw)
        if Path(process['path']) != Path(spec['executable']) or digest(process['path']) != expected['sha256']:
            raise RuntimeError('Actual SCM process differs from pinned registration')
        return {'phase': phase, 'request_id': record['request']['id'],
                'version': expected['version'], 'pid': process['pid']}

    def assert_preserved(self, baseline):
        for path, sha in baseline['files'].items():
            # AutoUpdate is intentionally toggled for the updated enrollment.
            if path == str(self.profile) + '.client-features.json':
                continue
            if digest(path) != sha:
                raise RuntimeError('Other enrollment or protected policy changed')
        if self.scm_snapshot(baseline['other_identity']) != baseline['other_process']:
            raise RuntimeError('Other enrollment SCM process changed')
        if digest(self.cli_path) != self.c['sha256'] or self.task_snapshot() != baseline['task']:
            raise RuntimeError('Higher shared CLI/GUI command or XML/SD was rewound')

    def assert_ack(self, rollback):
        def acknowledged():
            return any(e.get('handled') == self.request_id for e in self.gateway.events)
        if rollback:
            if acknowledged():
                raise RuntimeError('Rolled-back request acknowledged')
        else:
            wait_for(acknowledged, 45, 'committed request acknowledgment')
        if self.gateway.overflow:
            raise RuntimeError('Fixture observation bounds exceeded')
        if any(e['kind'] == 'invalid-ack' for e in self.gateway.events):
            raise RuntimeError('Observed acknowledgment before matching durable commit')

    def disable_updates(self):
        if self.installed_ids and self.profile.exists():
            self.cli('features', '--registration', self.identity, 'disable', 'auto-update')

    def workers(self):
        root = str(self.root / 'releases')
        value = ps('$r=' + cold.quote(root) + r""";$o=@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($r+'\',[StringComparison]::OrdinalIgnoreCase) -and $_.CommandLine -match '\s__windows-update\s'} | Select-Object ProcessId);ConvertTo-Json -InputObject @($o) -Compress""")
        return json.loads(value)

    def stop_workers(self):
        if not self.created_root:
            return
        self.validate_claim('managed')
        wait_for(lambda: not self.workers(), 60, 'fixture maintenance process exit')

    def uninstall_pair(self):
        if not self.created_root:
            return
        self.validate_claim('managed')
        if self.workers():
            raise RuntimeError('Maintenance worker still active; registration cleanup refused')
        errors = []
        for machine in reversed(self.installed_ids):
            try:
                self.cli('service', 'uninstall', '--profile', self.profiles[machine]['profile'], '--purge')
            except Exception as error:
                errors.append(type(error).__name__)
        if errors:
            raise RuntimeError('Fixture uninstall failure: ' + ','.join(errors))

    def cleanup_desktop(self):
        if not self.created_root:
            return
        self.validate_claim('managed')
        # Reuse the existing independently reviewed copied-installer cleanup. It
        # accepts only digest-backed immutable releases beneath this owned root.
        lifecycle = load('install_lifecycle', 'test-windows-install-lifecycle.py')
        lifecycle.ps = ps_result
        lifecycle.cleanup_desktop(self.root)

    def restore_path(self):
        if not hasattr(self, 'old_path'):
            return
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            actual, kind = winreg.QueryValueEx(key, 'Path')
            cli = str(self.published / 'bin').rstrip(chr(92)).lower()
            filtered = ';'.join(p for p in actual.split(';') if p.rstrip(chr(92)).lower() != cli)
            original = ';'.join(p for p in self.old_path.split(';') if p.rstrip(chr(92)).lower() != cli)
            if filtered != original or kind != self.path_type:
                raise RuntimeError('Unexpected PATH change preserved')
            winreg.SetValueEx(key, 'Path', 0, self.path_type, self.old_path)

    def postcheck(self):
        if not self.created_root:
            return
        self.validate_claim('managed')
        for machine in self.installed_ids:
            service = 'porthub-' + self.profiles[machine]['identity'][:24]
            ps('if(Get-Service -Name ' + cold.quote(service) + " -ErrorAction SilentlyContinue){throw 'Owned service remains'}")
        if self.workers():
            raise RuntimeError('Owned maintenance process remains')
        ps('$r=' + cold.quote(str(self.root / 'releases')) + r""";if(@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($r+'\',[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'Owned immutable process remains'}""")
        ps("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;if(Get-ScheduledTask -TaskName ('PortHubKeyboard-'+$sid) -ErrorAction SilentlyContinue){throw 'Fixture GUI task remains'}")

    def allowed_managed(self):
        files, dirs = super().allowed_managed()
        suffixes = ('', '.lock', '.config.json', '.status.json', '.local-access.json',
                    '.client-features.json', '.media-policy.json', '.drive-health-policy.json',
                    '.drive-health-schedule.json', '.service.json', '.windows-update.json',
                    '.windows-update.json.worker.lock')
        for row in self.profiles.values():
            identity = row['identity']
            files.update('native/' + identity + '.json' + suffix for suffix in suffixes)
            files.add('native/' + identity + '.service.json')
            files.add('services/porthub-' + identity[:24] + '.json')
        for row in self.rows:
            files.add('releases/' + row['sha256'] + '/porthub.exe')
            dirs.add('releases/' + row['sha256'])
        return files, dirs

    def remove_scope(self, kind, files, directories, executable=False):
        path, marker = self.validate_claim(kind)
        entries = list(path.rglob('*'))
        if len(entries) > 256:
            raise RuntimeError('Owned namespace exceeds cleanup bound')
        for entry in entries:
            if entry == marker:
                continue
            relative = entry.relative_to(path).as_posix()
            if (entry.is_symlink() or getattr(entry.lstat(), 'st_file_attributes', 0) & 0x400
                    or (entry.is_dir() and relative not in directories)
                    or (not entry.is_dir() and relative not in files)):
                raise RuntimeError('Unknown scoped fixture state preserved')
            if executable and entry.is_file() and digest(entry) not in [row['sha256'] for row in self.rows]:
                raise RuntimeError('Foreign published image preserved')
        self.validate_claim(kind)
        shutil.rmtree(path)

    def remove_staging(self):
        self.postcheck()  # No directory deletion while a fixture process exists.
        errors = []
        for kind in self.extra_claims:
            directories = {'media', 'components', 'porthub', 'porthub/data', 'porthub/data/keyboard'} if kind == 'desktop-state' else set()
            files = {'porthub/data/keyboard/' + row['identity'] + '.lock' for row in self.profiles.values()} if kind == 'desktop-state' else set()
            try:
                self.remove_scope(kind, files, directories)
            except Exception as error:
                errors.append(kind + ': ' + str(error))
        if self.claimed_status:
            try:
                self.remove_scope('readable-status', {row['identity'] + '.json' for row in self.profiles.values()}, set())
            except Exception as error:
                errors.append('readable-status: ' + str(error))
        if self.claimed_published:
            try:
                self.remove_scope('published', {'bin/porthub.exe'}, {'bin'}, executable=True)
            except Exception as error:
                errors.append('published: ' + str(error))
        if self.created_temp:
            try:
                self.validate_claim('temp')
                other = self.folder / 'other-profile.json'
                if other.exists():
                    if other.is_symlink() or other.stat().st_size > 65536:
                        raise RuntimeError('Invalid owned fixture input preserved')
                    other.unlink()
            except Exception as error:
                errors.append('other-input: ' + str(error))
        try:
            super().remove_staging()
        except Exception as error:
            errors.append('canonical-staging: ' + str(error))
        if errors:
            raise RuntimeError('; '.join(errors))

    def close_gateway(self):
        if self.gateway:
            self.gateway.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--execute-native-scm', action='store_true')
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--scenario', choices=['success', 'rollback'], default='success')
    args = parser.parse_args()
    receipt = artifacts_from_manifest(args.manifest)
    if args.execute_native_scm:
        result = run_case(Native(receipt), args.scenario == 'rollback')
        Path(args.receipt).write_text(json.dumps(result, indent=2))
        raise SystemExit(0 if result['completed'] and not result['cleanup_errors'] else 1)
    Path(args.receipt).write_text(json.dumps({'prepared': True, 'executed': False,
                                            'wrapper_source': receipt['wrapper_source'],
                                            'artifacts': [{k: v for k, v in r.items() if k != 'path'} for r in receipt['artifacts']]}, indent=2))


if __name__ == '__main__':
    main()
