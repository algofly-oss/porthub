#!/usr/bin/env python3
"""Opt-in disposable native Windows SCM updater gate; never runs on import.

This controller uses real versioned executables and normal service installation.
It is intentionally separate from production release workflows and host upgrades.
Each explicitly selected scenario uses two enrollments and a higher shared CLI/GUI.
Default invocation validates artifacts only. No native execution occurs on import.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import queue
import threading
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
    prefix = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
              r'Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1" -ErrorAction Stop;'
              r'Import-Module -Name "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop;')
    encoded = base64.b64encode((prefix + script).encode('utf-16le')).decode()
    args = [str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
    if len(subprocess.list2cmdline(args)) > 30000:
        raise RuntimeError('Fixture PowerShell command exceeds conservative native limit')
    result = subprocess.run(args,
                            env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, creationflags=0x08000000)
    if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 32768:
        raise RuntimeError('Bounded native PowerShell fixture operation failed')
    return result


def ps(script):
    return ps_result(script).stdout.decode('utf-8-sig', errors='strict').strip()


# Retain the reviewed cold-wrapper ownership logic, but use the same bounded,
# hidden Windows PowerShell transport with a clean PSModulePath for its probes.
cold.ps = ps


@contextmanager
def shared_reader(path):
    """Observers must not block the agent's atomic journal/config publication."""
    if sys.platform != 'win32':
        with Path(path).open('rb') as stream:
            yield stream
        return
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x00200000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        stream = os.fdopen(descriptor, 'rb')
    except Exception:
        os.close(descriptor)
        raise
    with stream:
        yield stream


def read_json(path):
    with shared_reader(path) as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError('Fixture JSON observer exceeds bound')
    return json.loads(data.decode('utf-8'))


def digest(path):
    with shared_reader(path) as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class ProcessBirthWatch:
    """Ephemeral read-only WMI subscription; no production hooks or privileges."""
    def __init__(self, root):
        self.stop_path = Path(root) / ('process-watch-stop-' + uuid.uuid4().hex)
        self.stop_identity = None

    def __enter__(self):
        script = Path(__file__).with_name('windows-update-process-watch.ps1').read_text()
        encoded = base64.b64encode(script.encode('utf-16le')).decode()
        executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        environment = os.environ.copy()
        environment.pop('PSModulePath', None)
        environment['PORTHUB_UPDATE_OBSERVER_STOP'] = str(self.stop_path)
        if os.path.lexists(self.stop_path):
            raise RuntimeError('Observer stop marker already exists')
        self.child = subprocess.Popen([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      env=environment, creationflags=0x08000000)
        self.frames = queue.Queue(maxsize=2)
        def read():
            try:
                for _ in range(2):
                    line = self.child.stdout.readline(4097)
                    if not line or len(line) > 4096:
                        raise RuntimeError('Missing/bounded process observer frame')
                    self.frames.put(json.loads(line.decode('utf-8-sig')), timeout=1)
            except Exception:
                try:
                    self.frames.put({'error': True}, timeout=1)
                except queue.Full:
                    pass
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            if self.frames.get(timeout=10) != {'ready': True}:
                raise RuntimeError('Native process observer did not become ready')
        except Exception:
            self.close(force=True)
            raise
        return self

    def close(self, force=False):
        try:
            if force:
                if self.child.poll() is None:
                    self.child.terminate()  # Exact retained Popen process handle.
                self.child.wait(timeout=3)
                return
            if self.child.poll() is not None:
                raise RuntimeError('Process observer expired before verification')
            with self.stop_path.open('xb') as marker:
                info = os.fstat(marker.fileno())
                self.stop_identity = (info.st_dev, info.st_ino)
                marker.flush()
                os.fsync(marker.fileno())
            frame = self.frames.get(timeout=3)
            self.child.wait(timeout=3)
            if self.child.returncode or frame.get('error') or frame.get('expired') or frame.get('count') != 0:
                raise RuntimeError('Repeated committed headers started a new PortHub process or observer failed')
            self.proof = {'new_porthub_processes': 0, 'read_only_wmi': True}
        finally:
            if self.child.poll() is None:
                self.child.terminate()
                self.child.wait(timeout=3)
            self.reader.join(timeout=2)
            if self.reader.is_alive():
                raise RuntimeError('Process observer pipe reader did not stop')
            self.child.stdout.close()
            if self.stop_identity is not None:
                info = self.stop_path.lstat()
                if (self.stop_path.is_symlink() or not self.stop_path.is_file()
                        or (info.st_dev, info.st_ino) != self.stop_identity or info.st_size != 0
                        or getattr(info, 'st_file_attributes', 0) & 0x400):
                    raise RuntimeError('Changed observer stop marker preserved')
                self.stop_path.unlink()

    def __exit__(self, kind, value, traceback):
        self.close(force=kind is not None)


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


def service_manifest_path(profile, identity):
    profile = Path(profile)
    if profile.name != identity + '.json':
        raise ValueError('Enrollment profile does not match service identity')
    # service::manifest uses layout.state/<identity>.service.json, whereas
    # policy/journal siblings append their suffix to the complete profile name.
    return profile.parent / (identity + '.service.json')


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
    scenario = ('rollback' if rollback else 'success') if isinstance(rollback, bool) else rollback
    rollback = scenario in ('rollback', 'readiness-revoke', 'download-revoke', 'foreground-reject')
    proof = {'completed': False, 'scenario': scenario, 'cleanup_errors': []}
    adapter.fixture_scenario = scenario
    try:
        proof['preflight'] = adapter.preflight()
        adapter.stage()
        adapter.install_pair()
        baseline = adapter.preservation_snapshot()
        if scenario == 'legacy-supersession':
            adapter.prepare_scenario(scenario)
        adapter.advertise(rollback)
        if scenario != 'default-on':
            adapter.assert_disabled()
        if scenario not in ('success', 'rollback', 'default-on', 'legacy-supersession'):
            adapter.prepare_scenario(scenario)
        if scenario not in ('foreground-reject', 'default-on'):
            adapter.enable_updates()
        proof['transaction'] = (adapter.wait_transaction(rollback) if scenario in ('success', 'rollback', 'default-on')
                                else adapter.exercise_scenario(scenario))
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
    if isinstance(adapter, Native) and hasattr(adapter, 'final_observations'):
        proof['observations'] = adapter.final_observations
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
        self.cli_path = self.published / 'bin/porthub.exe'

    def system_snapshot(self):
        return json.loads(ps(r"""
@{tasks=@(Get-ScheduledTask|Where-Object TaskName -like 'PortHub*'|ForEach-Object {$_.TaskPath+$_.TaskName}|Sort-Object);
porthub_services=@(Get-CimInstance Win32_Service -Filter "Name LIKE 'porthub-%'"|Select-Object -ExpandProperty Name|Sort-Object);
usbipd_service=[bool](Get-Service usbipd -ErrorAction SilentlyContinue);
usbip_products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object DisplayName -match 'USB.?IP'|Select-Object -ExpandProperty PSChildName|Sort-Object);
usbip_drivers=@(Get-CimInstance Win32_PnPSignedDriver|Where-Object {$_.DeviceName -match 'USB.?IP' -or $_.DriverProviderName -match 'usbip|VirtualHere'}|Select-Object DeviceID,InfName,DriverVersion|Sort-Object DeviceID,InfName,DriverVersion);
cli=[bool](Test-Path "$env:ProgramFiles\PortHub\bin\porthub.exe")}|ConvertTo-Json -Depth 6 -Compress
"""))

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
        ps("if(Get-Service -Name 'porthub-*' -ErrorAction SilentlyContinue){throw 'Existing PortHub service'};if(Get-CimInstance Win32_Process -Filter \"Name='porthub.exe'\"){throw 'Existing PortHub process'}")
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
                disabled = dict.fromkeys(features, True)
                if index == 0 and suffix == '.client-features.json' and getattr(self, 'fixture_scenario', '') == 'default-on':
                    disabled.pop('auto-update')  # Exercise the real default, not an explicit enable.
                self.private(Path(str(profile) + suffix), {'disabled': disabled})
            self.profiles[machine] = dict(identity=identity, profile=profile, input=input_path)
        self.profile = self.profiles[self.machine]['profile']
        self.identity = self.profiles[self.machine]['identity']
        self.service = 'porthub-' + self.identity[:24]

    def journal_for(self, machine):
        row = self.profiles.get(machine)
        if not row:
            return None
        try:
            return read_json(Path(str(row['profile']) + '.windows-update.json'))
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
            captured = self.file_snapshot(self.cli_path, private=False)
            if not captured['exists'] or captured['sha256'] != row['sha256']:
                raise RuntimeError('Normal installation did not publish its pinned CLI image')
            self.shared_cli_snapshot = captured
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

    def file_snapshot(self, path, private=True):
        path = Path(path)
        if not os.path.lexists(path):
            return {'exists': False}
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or getattr(metadata, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('Unsafe preservation path')
        before = digest(path)
        security = json.loads(ps('$path=' + cold.quote(path) + r""";
$a=Get-Acl -LiteralPath $path
$owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
$sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
$allow=@($a.Access|Where-Object AccessControlType -eq Allow|ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}|Sort-Object -Unique)
@{owner=$owner;protected=[bool]$a.AreAccessRulesProtected;sddl=$a.GetSecurityDescriptorSddlForm($sections);allow=@($allow)}|ConvertTo-Json -Compress
"""))
        if private and (not security['protected'] or any(sid not in ('S-1-5-18', 'S-1-5-32-544') for sid in security['allow'])):
            raise RuntimeError('Private enrollment/config/policy DACL is not protected')
        if digest(path) != before:
            raise RuntimeError('Preservation file changed during inspection')
        return {'exists': True, 'sha256': before, 'security': security}

    def policy_paths(self):
        result = set()
        for row in self.profiles.values():
            profile = row['profile']
            for suffix in ('.client-features.json', '.media-policy.json', '.drive-health-policy.json', '.local-access.json'):
                result.add(str(profile) + suffix)
            for path in profile.parent.glob(profile.name + '*'):
                if path.name.endswith(('-policy.json', '-features.json', '-access.json')):
                    result.add(str(path))
        return result

    def preservation_snapshot(self):
        other = next(value for machine, value in self.profiles.items() if machine != self.machine)
        paths = {str(service_manifest_path(other['profile'], other['identity']))}
        for row in self.profiles.values():
            paths.update(str(row['profile']) + suffix for suffix in ('', '.config.json', '.private-module.json'))
        policies = self.policy_paths()
        paths.update(policies)
        task = self.task_snapshot()
        process = self.scm_snapshot(other['identity'])
        if task is None or process['sha256'] != self.c['sha256']:
            raise RuntimeError('Higher shared enrollment/GUI not ready at baseline')
        snapshots = {path: self.file_snapshot(path) for path in sorted(paths)}
        mandatory = [str(row['profile']) for row in self.profiles.values()] + [str(service_manifest_path(other['profile'], other['identity']))]
        if any(not snapshots[path]['exists'] for path in mandatory):
            raise RuntimeError('Required enrollment/other manifest missing at baseline')
        self.shared_cli_snapshot = self.file_snapshot(self.cli_path, private=False)
        if not self.shared_cli_snapshot['exists'] or self.shared_cli_snapshot['sha256'] != self.c['sha256']:
            raise RuntimeError('Higher shared CLI missing/changed before baseline')
        return {'files': snapshots,
                'policy_paths': sorted(policies), 'cli': self.shared_cli_snapshot,
                'other_identity': other['identity'], 'other_process': process, 'task': task,
                'own_policy': read_json(Path(str(self.profile) + '.client-features.json'))}

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
        self.request_id = self.gateway.advertise(self.machine, getattr(self, 'initial_target', self.b['version']))

    def assert_disabled(self):
        wait_for(lambda: any(e['kind'] == 'request-observed' and e.get('machine') == self.machine and e.get('request_id') == self.request_id for e in self.gateway.events),
                 40, 'disabled client observed the actual update request')
        start = time.monotonic()
        while time.monotonic() - start < 5:
            if self.journal_for(self.machine) or any(e['kind'] == 'download' for e in self.gateway.events):
                raise RuntimeError('Disabled AutoUpdate performed staging')
            time.sleep(.1)

    def enable_updates(self):
        self.cli('features', '--registration', self.identity, 'enable', 'auto-update')

    def prepare_scenario(self, scenario):
        if scenario == 'download-revoke':
            self.gateway.hold_download = True
            self.gateway.release_download.clear()
        elif scenario in ('readiness-revoke', 'worker-loss', 'restart-recovery', 'tamper'):
            self.gateway.fail_version = self.b['version']
            self.gateway.candidate_sync_seen.clear()
        elif scenario == 'legacy-supersession':
            self.initial_target = self.a['version']
        elif scenario not in ('foreign-worker', 'foreground-reject'):
            raise ValueError('Unknown native scenario')

    def assert_previous_without_attempt(self):
        if self.journal_for(self.machine) or self.workers():
            return False
        if (self.root / 'releases' / self.b['sha256']).exists():
            return False
        return self.scm_snapshot(self.identity)['sha256'] == self.a['sha256']

    def candidate_pending(self):
        record = self.journal_for(self.machine)
        if (not record or record.get('phase') not in ('applying', 'verifying')
                or record.get('request', {}).get('id') != self.request_id
                or not self.gateway.candidate_sync_seen.is_set()):
            return None
        if self.scm_snapshot(self.identity)['sha256'] != self.b['sha256']:
            return None
        return record

    def pin_worker(self, action, record, inspected=None):
        workers = self.workers()
        if len(workers) != 1:
            raise RuntimeError('Expected exactly one fixture maintenance worker')
        script = Path(__file__).with_name('windows-update-worker-pin.ps1').read_text()
        command = '& ([ScriptBlock]::Create(' + cold.quote(script) + ')) -Action ' + cold.quote(action)
        for key, value in [('ProcessId', workers[0]['ProcessId']), ('Image', record['candidate']),
                           ('Sha256', self.b['sha256']), ('Record', str(self.profile) + '.windows-update.json'),
                           ('Nonce', record['nonce'])]:
            command += ' -' + key + ' ' + cold.quote(value)
        if inspected:
            if workers[0]['ProcessId'] != inspected['pid']:
                raise RuntimeError('Maintenance process changed before intervention')
            command += ' -ExpectedCreation ' + cold.quote(inspected['creation'])
        return json.loads(ps(command))

    def start_exact_candidate(self, record, allow_failure=False):
        # Start SCM directly only for the recovery cases whose exact current
        # image/unit was independently checked before metadata crash injection.
        expected = str(self.root / 'releases' / self.b['sha256'] / 'porthub.exe')
        if record['candidate'] != expected:
            raise RuntimeError('Journal candidate changed')
        service = 'porthub-' + self.identity[:24]
        command = ('$s=Get-CimInstance Win32_Service -Filter ' + cold.quote("Name='" + service + "'") +
                   ';if($s.PathName -notlike (' + cold.quote('"' + expected + '"') + "+'*')){throw 'SCM image changed before recovery start'};")
        if allow_failure:
            command += 'try{Start-Service -Name ' + cold.quote(service) + ";@{started=$true}|ConvertTo-Json -Compress}catch{@{started=$false}|ConvertTo-Json -Compress}"
            return json.loads(ps(command))
        ps(command + 'Start-Service -Name ' + cold.quote(service))


    def exercise_scenario(self, scenario):
        if scenario == 'foreground-reject':
            return self.exercise_foreground()
        if scenario == 'download-revoke':
            wait_for(self.gateway.download_started.is_set, 40, 'download paused after first bounded chunk')
            self.disable_updates()
            self.gateway.release_download.set()
            wait_for(self.assert_previous_without_attempt, 5, 'revoked download removed staging without mutation')
            self.terminal_observed = time.monotonic()
            self.terminal_sequence = max((e['sequence'] for e in self.gateway.events), default=0)
            self.terminal_downloads = sum(e['kind'] == 'download' for e in self.gateway.events)
            return {'phase': 'cancelled-before-journal', 'scm_unchanged': True, 'journal_absent': True}
        if scenario == 'legacy-supersession':
            legacy = self.request_id
            wait_for(lambda: any(e['kind'] == 'request-observed' and e.get('request_id') == legacy for e in self.gateway.events),
                     40, 'equal legacy request observed by actual client')
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if not self.assert_previous_without_attempt() or any(e.get('handled') == legacy for e in self.gateway.events):
                    raise RuntimeError('Equal unproven legacy request installed or acknowledged')
                time.sleep(.1)
            self.request_id = self.gateway.advertise(self.machine, self.b['version'])
            result = self.wait_transaction(False)
            result['equal_legacy_request_unacknowledged'] = True
            return result
        if scenario == 'foreign-worker':
            result = self.wait_transaction(False)
            path = Path(str(self.profile) + '.windows-update.json')
            before = digest(path)
            copy = self.folder / 'foreign-record.json'
            self.private(copy, read_json(path))
            try:
                attempt = subprocess.run([self.b['path'], '__windows-update', '--record', str(copy)],
                                         capture_output=True, timeout=10, creationflags=0x08000000)
                if attempt.returncode == 0 or digest(path) != before:
                    raise RuntimeError('Out-of-layout worker record was accepted/mutated enrollment')
            finally:
                if copy.exists() and not copy.is_symlink():
                    copy.unlink()
            result['foreign_worker_rejected'] = True
            return result
        record = wait_for(self.candidate_pending, 25, 'actual candidate SCM running while readiness blocked')
        if scenario == 'readiness-revoke':
            self.disable_updates()
            self.gateway.fail_version = None
            return self.wait_transaction(True)
        inspected = self.pin_worker('Inspect', record)
        if scenario in ('restart-recovery', 'tamper'):
            self.cli('service', 'stop', '--profile', str(self.profile))
        killed = self.pin_worker('Terminate', record, inspected)
        if not killed.get('terminated') or killed['creation'] != inspected['creation']:
            raise RuntimeError('Held maintenance process was not terminated')
        if scenario == 'tamper':
            return self.exercise_tamper(record, killed)
        if scenario == 'restart-recovery':
            manifest = service_manifest_path(self.profile, self.identity)
            with shared_reader(manifest) as stream:
                saved = stream.read(4 * 1024 * 1024 + 1)
            previous = bytes(record['previous_manifest'])
            if saved == previous:
                raise RuntimeError('No candidate manifest to exercise mixed-state recovery')
            self.injected_metadata = (manifest, saved, hashlib.sha256(previous).hexdigest())
            self.write_metadata(manifest, previous)
        self.gateway.fail_version = None
        if scenario == 'restart-recovery':
            self.start_exact_candidate(record)
        result = self.wait_transaction(False)
        result['terminated_worker'] = killed
        result['restart_mixed_metadata'] = scenario == 'restart-recovery'
        return result

    def exercise_foreground(self):
        copy = self.folder / 'foreground-profile.json'
        self.private(copy, json.loads(self.profiles[self.machine]['input'].read_text()))
        base = dict.fromkeys(cold.BASE_FEATURES, True)
        base['auto-update'] = False  # Enable only this copied foreground profile.
        self.private(Path(str(copy) + '.client-features.json'), {'disabled': base})
        self.private(Path(str(copy) + '.media-policy.json'), {'disabled': dict.fromkeys(cold.MEDIA_FEATURES, True)})
        self.private(Path(str(copy) + '.drive-health-policy.json'), {'disabled': {'drive-health': True, 'drive-tests': True}})
        child = None
        try:
            child = subprocess.Popen([self.a['path'], 'run', '--profile', str(copy)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, creationflags=0x08000000)
            self.foreground_child = child
            status = Path(str(copy) + '.status.json')
            def running():
                if child.poll() is not None:
                    raise RuntimeError('Copied foreground agent exited before authorization test')
                try:
                    value = read_json(status)
                except (OSError, ValueError):
                    return False
                return value.get('state') == 'running' and value.get('pid') == child.pid
            wait_for(running, 30, 'actual copied-profile foreground runtime control sync')
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if child.poll() is not None or not self.assert_previous_without_attempt():
                    raise RuntimeError('Foreground copied profile authorized a native update or exited')
                time.sleep(.1)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.terminate()  # Python retains the exact owned native handle.
                child.wait(timeout=10)
                self.foreground_child = None
            known = {'', '.lock', '.config.json', '.status.json', '.client-features.json',
                     '.media-policy.json', '.drive-health-policy.json'}
            for path in self.folder.glob('foreground-profile.json*'):
                suffix = path.name.removeprefix('foreground-profile.json')
                if suffix not in known or path.is_symlink() or not path.is_file() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
                    raise RuntimeError('Unknown copied foreground state preserved')
                path.unlink()
        self.terminal_observed = time.monotonic()
        self.terminal_sequence = max((e['sequence'] for e in self.gateway.events), default=0)
        self.terminal_downloads = sum(e['kind'] == 'download' for e in self.gateway.events)
        return {'phase': 'foreground-rejected', 'journal_absent': True, 'scm_unchanged': True}

    def write_metadata(self, path, data):
        self.validate_claim('managed')
        # Fixture-only exact existing regular protected file, no replacement
        # path/ACL/symlink changes. All relevant processes are stopped first.
        if path.is_symlink() or not path.is_file() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('Unsafe metadata intervention refused')
        with path.open('r+b') as stream:
            stream.write(data)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())

    def exercise_tamper(self, record, killed):
        path = Path(record['previous']['unit'])
        if path.parent != self.root / 'services':
            raise RuntimeError('Unit intervention is outside exact fixture services')
        with shared_reader(path) as stream:
            saved = stream.read(4 * 1024 * 1024 + 1)
        value = json.loads(saved)
        value['fixture_operator_change'] = record['nonce']
        foreign = json.dumps(value, sort_keys=True).encode()
        self.injected_metadata = (path, saved, hashlib.sha256(foreign).hexdigest())
        self.write_metadata(path, foreign)
        self.gateway.fail_version = None
        # An expected failed service start is observed rather than hidden; no
        # arbitrary process launch bypasses native service-start authorization.
        start_result = self.start_exact_candidate(record, allow_failure=True)
        until = time.monotonic() + 35
        while time.monotonic() < until:
            if digest(path) != self.injected_metadata[2] or any(e.get('handled') == self.request_id for e in self.gateway.events):
                raise RuntimeError('Foreign metadata overwritten or falsely acknowledged')
            time.sleep(.2)
        self.restore_injected_metadata()
        self.start_exact_candidate(record)
        result = self.wait_transaction(False)
        result['foreign_metadata_start_accepted'] = start_result['started']
        result['foreign_metadata_preserved_seconds'] = 35
        result['terminated_worker'] = killed
        return result

    def restore_injected_metadata(self):
        if not getattr(self, 'injected_metadata', None):
            return
        path, original, changed_sha = self.injected_metadata
        if digest(path) == hashlib.sha256(original).hexdigest():
            self.injected_metadata = None
            return
        if digest(path) != changed_sha:
            raise RuntimeError('Unknown third metadata state preserved')
        self.write_metadata(path, original)
        self.injected_metadata = None

    def wait_transaction(self, rollback):
        phase = 'rolled-back' if rollback else 'committed'
        record = wait_for(lambda: (r if (r := self.journal_for(self.machine)) and r.get('phase') == phase else None),
                          150, 'real native transaction ' + phase)
        expected = self.a if rollback else self.b
        spec = read_json(service_manifest_path(self.profile, self.identity))
        if digest(spec['executable']) != expected['sha256']:
            raise RuntimeError('SCM registration has wrong endpoint image')
        service = 'porthub-' + self.identity[:24]
        raw = ps('$s=Get-CimInstance Win32_Service -Filter ' + cold.quote("Name='" + service + "'") +
                      ";if($s.State -ne 'Running' -or $s.StartName -ne 'LocalSystem'){throw 'Fixture service not ready'};" +
                      '$p=Get-CimInstance Win32_Process -Filter ("ProcessId="+$s.ProcessId);@{pid=$p.ProcessId;path=$p.ExecutablePath}|ConvertTo-Json -Compress')
        process = json.loads(raw)
        if Path(process['path']) != Path(spec['executable']) or digest(process['path']) != expected['sha256']:
            raise RuntimeError('Actual SCM process differs from pinned registration')
        self.terminal_observed = time.monotonic()
        self.terminal_sequence = max((e['sequence'] for e in self.gateway.events), default=0)
        self.terminal_downloads = sum(e['kind'] == 'download' for e in self.gateway.events)
        if rollback:
            age = max(0, time.time() - record['updated'])
            self.cooldown_deadline = self.terminal_observed + max(0, 29 - age)
        return {'phase': phase, 'request_id': record['request']['id'],
                'version': expected['version'], 'pid': process['pid']}

    def assert_preserved(self, baseline):
        own_policy = str(self.profile) + '.client-features.json'
        if sorted(self.policy_paths()) != baseline['policy_paths']:
            raise RuntimeError('Unexpected policy/access file added or removed')
        scenario = getattr(self, 'fixture_scenario', 'success')
        toggled = scenario not in ('default-on', 'foreground-reject')
        for path, expected in baseline['files'].items():
            current = self.file_snapshot(path)
            if path == own_policy and toggled:
                if not current['exists'] or current['security'] != expected['security']:
                    raise RuntimeError('Local AutoUpdate policy owner/DACL changed')
            elif current != expected:
                raise RuntimeError('Enrollment/config/protected policy bytes or security changed')
        current_policy = read_json(Path(own_policy))
        expected_policy = json.loads(json.dumps(baseline['own_policy']))
        if toggled:
            if scenario in ('download-revoke', 'readiness-revoke'):
                expected_policy['disabled']['auto-update'] = True
            else:
                expected_policy['disabled'].pop('auto-update', None)
        if current_policy != expected_policy:
            raise RuntimeError('Unexpected local feature delta or AutoUpdate state')
        if self.scm_snapshot(baseline['other_identity']) != baseline['other_process']:
            raise RuntimeError('Other enrollment SCM process changed')
        if self.file_snapshot(self.cli_path, private=False) != baseline['cli'] or self.task_snapshot() != baseline['task']:
            raise RuntimeError('Higher shared CLI/GUI bytes, owner, DACL or command changed')
        self.preservation_proof = {'cli': baseline['cli'],
                                   'task_xml_sha256': hashlib.sha256(baseline['task']['xml'].encode()).hexdigest(),
                                   'task_sd_sha256': hashlib.sha256(baseline['task']['sd'].encode()).hexdigest(),
                                   'helper_processes': baseline['task']['processes'],
                                   'other_scm_process': baseline['other_process'],
                                   'enrollment_config_policy_snapshots': baseline['files'],
                                   'intended_auto_policy_delta': scenario,
                                   'other_permissions_unchanged': True}

    def assert_final_observations(self):
        if self.gateway and (self.gateway.overflow or any(e['kind'] in ('invalid-ack', 'artifact-changed', 'download-barrier-timeout') for e in self.gateway.events)):
            raise RuntimeError('Fixture integrity/acknowledgment observation failed')

    def idempotence_snapshot(self):
        record = self.journal_for(self.machine)
        if not record or record['phase'] != 'committed' or self.workers():
            raise RuntimeError('Committed idempotence snapshot has an active worker or wrong phase')
        return {'scm': self.scm_snapshot(self.identity),
                'journal_nonce': record['nonce'], 'journal_attempts': record['attempts'],
                'journal_sha256': digest(Path(str(self.profile) + '.windows-update.json')),
                'cli': self.file_snapshot(self.cli_path, private=False), 'gui': self.task_snapshot(),
                'downloads': sum(e['kind'] == 'download' for e in self.gateway.events)}

    def assert_repeated_headers_idempotent(self):
        wait_for(lambda: not self.workers(), 5, 'committed maintenance worker exited')
        self.validate_claim('temp')
        with ProcessBirthWatch(self.folder) as observer:
            before = self.idempotence_snapshot()
            if before['gui'] is None:
                raise RuntimeError('Shared GUI unavailable before idempotence observation')
            sequence = max((e['sequence'] for e in self.gateway.events), default=0)
            started = time.monotonic()
            def repeated():
                cycles = [e for e in self.gateway.events if e['kind'] == 'changes-cycle'
                          and e.get('machine') == self.machine and e.get('request_id') == self.request_id
                          and e.get('target_version') == self.b['version'] and e.get('journal_phase') == 'committed'
                          and e['sequence'] > sequence]
                return cycles if len(cycles) >= 2 else None
            cycles = wait_for(repeated, 5, 'two normal authenticated repeated post-commit header cycles')
            observed = time.monotonic() - started
            after = self.idempotence_snapshot()
            if after != before:
                raise RuntimeError('Repeated committed headers changed SCM, journal, CLI/GUI or downloaded again')
        self.idempotence_proof = {'cycles': len(cycles), 'first_sequence': cycles[0]['sequence'],
                                  'last_sequence': cycles[-1]['sequence'], 'cycle_seconds': observed,
                                  'process_observer': observer.proof,
                                  'stable': {key: value for key, value in before.items() if key != 'gui'}}

    def assert_ack(self, rollback):
        def acknowledged():
            return any(e.get('handled') == self.request_id for e in self.gateway.events)
        if rollback:
            terminal = self.journal_for(self.machine)
            phase = 'rolled-back' if terminal else None
            after = getattr(self, 'terminal_sequence', max((e['sequence'] for e in self.gateway.events), default=0))
            heartbeat = wait_for(lambda: next((e for e in self.gateway.events
                                 if e['kind'] == 'sync' and e.get('machine') == self.machine
                                 and e.get('version') == self.a['version'] and e.get('journal_phase') == phase
                                 and e['sequence'] > after and not e.get('handled')), None),
                     20, 'old core authenticated post-terminal heartbeat without acknowledgment')
            downloads = getattr(self, 'terminal_downloads', sum(e['kind'] == 'download' for e in self.gateway.events))
            if sum(e['kind'] == 'download' for e in self.gateway.events) != downloads:
                raise RuntimeError('Retry occurred before post-terminal heartbeat')
            # Stay strictly inside the first actual 30-second retry cooldown.
            # A five-second quiet interval after a real heartbeat is additional
            # evidence, not a claim that a disabled process can never retry.
            started = time.monotonic()
            if terminal and started + 5 > getattr(self, 'cooldown_deadline', self.terminal_observed + 27):
                raise RuntimeError('No bounded cooldown observation budget remained')
            while time.monotonic() - started < 5:
                current = self.journal_for(self.machine)
                if (acknowledged() or sum(e['kind'] == 'download' for e in self.gateway.events) != downloads
                        or (current.get('phase') if current else None) != phase):
                    raise RuntimeError('Rollback/cancel acknowledgment or early retry observed')
                time.sleep(.1)
            if phase is None and not self.assert_previous_without_attempt():
                raise RuntimeError('Revoked download left a staged image or service mutation')
            self.ack_proof = {'phase': phase, 'post_terminal_heartbeat_sequence': heartbeat['sequence'],
                              'quiet_seconds': time.monotonic() - started, 'new_downloads': 0, 'handled': False}
        else:
            wait_for(acknowledged, 45, 'committed request acknowledgment')
            self.assert_repeated_headers_idempotent()
        self.assert_final_observations()

    def disable_updates(self):
        try:
            if self.installed_ids and self.profile.exists():
                self.cli('features', '--registration', self.identity, 'disable', 'auto-update')
        finally:
            # Never release the intentionally stalled download before the real
            # local permission change has returned. Cleanup still unblocks the
            # HTTP thread if the CLI fails, and reports that failure.
            if self.gateway:
                self.gateway.release_download.set()

    def workers(self):
        root = str(self.root / 'releases')
        value = ps('$r=' + cold.quote(root) + r""";$o=@(Get-CimInstance Win32_Process -Filter "Name='porthub.exe'" | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($r+'\',[StringComparison]::OrdinalIgnoreCase) -and $_.CommandLine -match '\s__windows-update\s'} | Select-Object ProcessId);ConvertTo-Json -InputObject @($o) -Compress""")
        return json.loads(value)

    def stop_workers(self):
        child = getattr(self, 'foreground_child', None)
        if child is not None:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
            self.foreground_child = None
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
        self.restore_injected_metadata()
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
        child = getattr(self, 'foreground_child', None)
        if child is not None and child.poll() is None:
            raise RuntimeError('Owned foreground test process remains')
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
        self.assert_global_preserved()

    def assert_global_preserved(self, final=False):
        current = self.system_snapshot()
        expected = dict(self.before)
        current_cli = current.pop('cli')
        expected_cli = expected.pop('cli')
        if current != expected:
            raise RuntimeError('Unexpected global PortHub service/task or USB prerequisite change; preserved')
        if final:
            if current_cli != expected_cli:
                raise RuntimeError('Global CLI baseline not restored')
        elif current_cli:
            if not getattr(self, 'shared_cli_snapshot', None) or self.file_snapshot(self.cli_path, private=False) != self.shared_cli_snapshot:
                raise RuntimeError('Unexpected shared CLI security/bytes preserved')

    def allowed_managed(self):
        files, dirs = super().allowed_managed()
        suffixes = ('', '.lock', '.config.json', '.status.json', '.local-access.json',
                    '.client-features.json', '.media-policy.json', '.drive-health-policy.json',
                    '.drive-health-schedule.json', '.windows-update.json',
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
        try:
            if hasattr(self, 'before'):
                self.assert_global_preserved(final=True)
            elif self.created_root:
                raise RuntimeError('Managed state created without a global baseline')
        except Exception as error:
            errors.append('global-baseline: ' + str(error))
        if errors:
            raise RuntimeError('; '.join(errors))

    def close_gateway(self):
        if self.gateway:
            try:
                self.assert_final_observations()
            finally:
                try:
                    self.gateway.close()
                finally:
                    self.final_observations = {'events': list(self.gateway.events),
                                               'ack_proof': getattr(self, 'ack_proof', None),
                                               'preservation': getattr(self, 'preservation_proof', None),
                                               'idempotence': getattr(self, 'idempotence_proof', None)}
                    self.assert_final_observations()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--execute-native-scm', action='store_true')
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--scenario', choices=['success', 'rollback', 'default-on', 'download-revoke', 'readiness-revoke', 'worker-loss', 'restart-recovery', 'tamper', 'legacy-supersession', 'foreign-worker', 'foreground-reject'], default='success')
    args = parser.parse_args()
    receipt = artifacts_from_manifest(args.manifest)
    if args.execute_native_scm:
        result = run_case(Native(receipt), args.scenario)
        Path(args.receipt).write_text(json.dumps(result, indent=2))
        raise SystemExit(0 if result['completed'] and not result['cleanup_errors'] else 1)
    Path(args.receipt).write_text(json.dumps({'prepared': True, 'executed': False,
                                            'wrapper_source': receipt['wrapper_source'],
                                            'artifacts': [{k: v for k, v in r.items() if k != 'path'} for r in receipt['artifacts']]}, indent=2))


if __name__ == '__main__':
    main()
