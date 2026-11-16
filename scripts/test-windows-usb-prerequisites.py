#!/usr/bin/env python3
"""OPT-IN real signed-driver gate on a clean disposable GitHub Windows runner.
No physical USB bind/attach, production enrollment, GUI task, or driver uninstall.
Importing this module performs no OS operations. Default invocation never runs it.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

BASE_FEATURES = ('keyboard', 'usb', 'metrics', 'images', 'terminal', 'expose',
                 'public-forwarding', 'private-network', 'auto-update', 'direct-connections')
MEDIA_FEATURES = ('microphone-share', 'camera-share', 'media-receive')


def run_trial(adapter):
    """Exercise real preparation through ordinary SCM registration, not direct calls."""
    receipt = {'completed': False, 'steps': [], 'cleanup_errors': []}
    started = False
    try:
        receipt['preflight'] = adapter.preflight()
        started = True
        adapter.stage()
        adapter.install()
        receipt['steps'].append(adapter.wait_state('all-off', False, False, False))
        adapter.enable('media-receive')
        receipt['steps'].append(adapter.wait_state('receive-only', False, True, False))
        adapter.enable('direct-connections')
        receipt['steps'].append(adapter.wait_state('receive-direct', False, True, True))
        adapter.enable('usb')
        receipt['steps'].append(adapter.wait_state('raw-usb', True, True, True))
        receipt['cache'] = adapter.verify_cache()
        receipt['preservation'] = adapter.preservation()
        receipt['completed'] = True
    except Exception as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)[:1024]
    finally:
        if started:
            # Each action is independent, including when stop or uninstall fails.
            for name in ('stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'):
                try:
                    receipt[name] = getattr(adapter, name)()
                except Exception as error:
                    receipt['cleanup_errors'].append(name + ': ' + str(error)[:512])
    return receipt


def ps(script):
    encoded = base64.b64encode(("$ErrorActionPreference='Stop';" + script).encode('utf-16le')).decode()
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError('PowerShell probe/action failed (exit %d)' % result.returncode)
    if len(result.stdout) > 262144 or len(result.stderr) > 32768:
        raise RuntimeError('Probe output exceeds limit')
    return result.stdout.decode('utf-8-sig', errors='strict').strip()


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def receive_ready():
    # Same interface GUID and access/share flags as usb/windows.rs::controller.
    from ctypes import wintypes as w
    class GUID(ctypes.Structure):
        _fields_ = [('a', w.DWORD), ('b', w.WORD), ('c', w.WORD), ('d', ctypes.c_ubyte * 8)]
    class Interface(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('guid', GUID), ('flags', w.DWORD), ('reserved', ctypes.c_size_t)]
    raw = uuid.UUID('b4030c06-dc5f-4fcc-87eb-e5515a0935c0').bytes_le
    guid = GUID.from_buffer_copy(raw)
    api = ctypes.WinDLL('setupapi', use_last_error=True)
    api.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), w.LPCWSTR, w.HWND, w.DWORD]
    api.SetupDiGetClassDevsW.restype = w.HANDLE
    api.SetupDiEnumDeviceInterfaces.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), w.DWORD, ctypes.POINTER(Interface)]
    api.SetupDiEnumDeviceInterfaces.restype = w.BOOL
    api.SetupDiGetDeviceInterfaceDetailW.argtypes = [w.HANDLE, ctypes.POINTER(Interface), ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    api.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL
    api.SetupDiDestroyDeviceInfoList.argtypes = [w.HANDLE]
    api.SetupDiDestroyDeviceInfoList.restype = w.BOOL
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    invalid = ctypes.c_void_p(-1).value
    handle = api.SetupDiGetClassDevsW(ctypes.byref(guid), None, None, 0x12)
    if handle == invalid:
        return False
    try:
        item = Interface(); item.size = ctypes.sizeof(item)
        if not api.SetupDiEnumDeviceInterfaces(handle, None, ctypes.byref(guid), 0, ctypes.byref(item)):
            return False
        length = w.DWORD()
        api.SetupDiGetDeviceInterfaceDetailW(handle, ctypes.byref(item), None, 0, ctypes.byref(length), None)
        if not 8 <= length.value <= 32768:
            raise RuntimeError('Invalid receive-controller path length')
        buffer = ctypes.create_string_buffer(length.value)
        ctypes.cast(buffer, ctypes.POINTER(w.DWORD))[0] = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
        if not api.SetupDiGetDeviceInterfaceDetailW(handle, ctypes.byref(item), buffer, length, None, None):
            return False
        path = ctypes.wstring_at(ctypes.addressof(buffer) + 4)
        device = kernel.CreateFileW(path, 0xc0000000, 3, None, 3, 0x80, None)
        if device == invalid:
            return False
        kernel.CloseHandle(device)
        return True
    finally:
        api.SetupDiDestroyDeviceInfoList(handle)


class Native:
    def __init__(self, executable, expected_sha, revision):
        self.exe = Path(executable).resolve(strict=True)
        self.expected_sha = expected_sha
        self.revision = revision
        self.machine = uuid.uuid4().hex[:24]
        self.identity = hashlib.sha256(('https://fixture.invalid\n' + self.machine).encode()).hexdigest()
        self.service = 'porthub-' + self.identity[:24]
        self.rule = 'PortHub-USB-' + self.machine
        self.root = Path(os.environ.get('ProgramData', '')) / 'PortHub'
        self.profile = self.root / 'native' / (self.identity + '.json')
        self.host = Path(os.environ.get('ProgramFiles', '')) / 'usbipd-win/usbipd.exe'
        self.folder = None
        self.created_root = False
        self.created_temp = False
        self.claims = {}
        self.nonce = uuid.uuid4().hex
        self.expected_paths = {}
        self.sha = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.immutable = self.root / 'releases' / self.sha / 'porthub.exe'

    def cli(self, *args):
        result = subprocess.run([str(self.exe), *args], capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError('Native CLI failed: ' + ' '.join(args[:2]) + ' exit=' + str(result.returncode))
        if len(result.stdout) > 131072 or len(result.stderr) > 32768:
            raise RuntimeError('Native CLI output exceeds limit')
        return result.stdout.decode('utf-8', errors='strict')

    def preflight(self):
        if sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
            raise RuntimeError('Disposable GitHub-hosted Windows runner required')
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('Administrator token required')
        if self.sha != self.expected_sha or len(self.revision) != 40 or any(c not in '0123456789abcdef' for c in self.revision):
            raise RuntimeError('Reviewed executable/source provenance mismatch')
        if os.path.lexists(self.root) or self.host.exists() or receive_ready():
            raise RuntimeError('Not a clean runner: managed state or USB prerequisite exists')
        checked_out = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parents[1], timeout=10).decode().strip()
        if checked_out != self.revision:
            raise RuntimeError('Checked-out wrapper source differs from reviewed revision')
        self.before = self.system_snapshot()
        if self.before['usbipd_service'] or self.before['usbip_products'] or self.before['usbip_drivers']:
            raise RuntimeError('Existing USB/IP installation found; refusing uninstall')
        return {'agent_sha256': self.sha, 'agent_size': self.exe.stat().st_size, 'source_revision': self.revision, 'version': self.cli('--version').strip(), 'baseline': self.before}

    def system_snapshot(self):
        return json.loads(ps("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + r"""
$o=@{tasks=@(Get-ScheduledTask | Where-Object TaskName -like 'PortHub*' | ForEach-Object { $_.TaskPath+$_.TaskName } | Sort-Object); usbipd_service=[bool](Get-Service usbipd -ErrorAction SilentlyContinue); usbip_products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -match 'USB.?IP' | Select-Object -ExpandProperty PSChildName); usbip_drivers=@(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -match 'USB.?IP' -or $_.DriverProviderName -match 'usbip|VirtualHere' } | Select-Object DeviceID,InfName,DriverVersion); cli=[bool](Test-Path "$env:ProgramFiles\PortHub\bin\porthub.exe")}; $o|ConvertTo-Json -Depth 6 -Compress
"""))

    def private(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')
        ps('icacls ' + quote(path) + " /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null; if($LASTEXITCODE){throw 'ACL failed'}")

    def claim(self, path, kind):
        # Only call after exclusive mkdir/mkdtemp succeeded. The process keeps
        # the directory identity and nonce-bound marker digest out of the tree.
        info = path.lstat()
        if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400 or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError('Invalid newly created fixture directory')
        marker = path / ('.porthub-cold-owner-' + self.nonce + '.json')
        value = {'schema': 1, 'nonce': self.nonce, 'kind': kind, 'path': str(path.resolve()),
                 'identity': self.identity, 'executable_sha256': self.sha}
        data = json.dumps(value, sort_keys=True).encode()
        with marker.open('xb') as file:
            file.write(data); file.flush(); os.fsync(file.fileno())
        self.protect_directory(path)
        self.protect_marker(marker)
        self.claims[kind] = (path, (info.st_dev, info.st_ino), marker, hashlib.sha256(data).hexdigest())

    def protect_directory(self, path):
        ps('icacls ' + quote(path) + " /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null; if($LASTEXITCODE){throw 'ACL failed'}")

    def protect_marker(self, marker):
        ps('icacls ' + quote(marker) + " /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null; if($LASTEXITCODE){throw 'ACL failed'}")

    def validate_claim(self, kind):
        if kind not in self.claims:
            raise RuntimeError('No successful ownership claim for ' + kind)
        path, inode, marker, digest = self.claims[kind]
        info = path.lstat()
        if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400 or (info.st_dev, info.st_ino) != inode:
            raise RuntimeError('Owned directory identity changed')
        before = marker.lstat()
        if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400 or before.st_size > 4096:
            raise RuntimeError('Invalid ownership marker')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(marker, flags)
        with os.fdopen(fd, 'rb') as file:
            held = os.fstat(file.fileno()); data = file.read(4097)
        after = marker.lstat()
        if (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino) or (held.st_dev, held.st_ino) != (after.st_dev, after.st_ino) or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Ownership marker changed')
        value = json.loads(data)
        if value['path'] != str(path.resolve()) or value['nonce'] != self.nonce or value['identity'] != self.identity or value['executable_sha256'] != self.sha:
            raise RuntimeError('Ownership marker binding mismatch')
        ps('$a=Get-Acl -LiteralPath ' + quote(marker) + ";if(!$a.AreAccessRulesProtected){throw 'Unprotected ownership marker'};foreach($r in $a.Access){if([string]$r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Foreign marker principal'}}")
        return path, marker

    def stage(self):
        self.folder = Path(tempfile.mkdtemp(prefix='porthub-usb-cold-'))
        self.created_temp = True
        self.claim(self.folder, 'temp')
        self.root.mkdir()  # FileExists is a refusal, never an ownership grant.
        self.created_root = True
        self.claim(self.root, 'managed')
        (self.root / 'native').mkdir()
        ps('icacls ' + quote(self.root) + " /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null; if($LASTEXITCODE){throw 'ACL failed'}")
        ps('icacls ' + quote(self.root / 'native') + " /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null; if($LASTEXITCODE){throw 'ACL failed'}")
        self.input = self.folder / 'profile.json'
        self.private(self.input, {'format_version': 1, 'server': 'https://fixture.invalid',
                                 'machine_id': self.machine, 'token': uuid.uuid4().hex,
                                 'fallback_servers': [], 'setup_overrides': {}, 'allow_insecure_http_for_tests': False})
        for suffix, names in (('.client-features.json', BASE_FEATURES), ('.media-policy.json', MEDIA_FEATURES),
                              ('.drive-health-policy.json', ('drive-health', 'drive-tests'))):
            self.private(Path(str(self.profile) + suffix), {'disabled': dict.fromkeys(names, True)})

    def install(self):
        self.cli('service', 'install', '--profile', str(self.input))
        if not self.immutable.is_file() or hashlib.sha256(self.immutable.read_bytes()).hexdigest() != self.sha:
            raise RuntimeError('Installed immutable executable mismatch')
        self.scm()
        self.protection()

    def protection(self):
        paths = [self.profile, Path(str(self.profile) + '.client-features.json'), Path(str(self.profile) + '.media-policy.json'), Path(str(self.profile) + '.drive-health-policy.json')]
        for path in paths:
            ps('$a=Get-Acl -LiteralPath ' + quote(path) + ";if(!$a.AreAccessRulesProtected){throw 'Unprotected private file'};foreach($r in $a.Access){if([string]$r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Unexpected private file principal'}}")
        return True

    def scm(self):
        data = json.loads(ps("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);Get-CimInstance Win32_Service -Filter " + quote("Name='" + self.service + "'") + '|Select-Object Name,State,StartName,ProcessId,PathName|ConvertTo-Json -Compress'))
        if data['State'] != 'Running' or data['StartName'] != 'LocalSystem' or data['ProcessId'] <= 0 or str(self.immutable).lower() not in data['PathName'].lower():
            raise RuntimeError('Actual SCM registration/PID mismatch')
        return {'pid': data['ProcessId'], 'service': data['Name']}

    def enable(self, feature):
        self.cli('features', '--registration', self.identity, 'enable', feature)

    def rules(self):
        return json.loads(ps("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$r=Get-NetFirewallRule -Name " + quote(self.rule) + " -ErrorAction SilentlyContinue;$raw=@(Get-NetFirewallRule -ErrorAction Stop|Where-Object {$_.DisplayName -eq 'usbipd' -or $_.Name -eq 'usbipd'});$o=@{raw_enabled=@($raw|Where-Object {[string]$_.Enabled -eq 'True'}).Count;app=$null};if($r){$o.app=@{name=$r.Name;group=$r.Group;enabled=[string]$r.Enabled;direction=[string]$r.Direction;action=[string]$r.Action;program=@($r|Get-NetFirewallApplicationFilter|Select-Object -ExpandProperty Program);remote=@($r|Get-NetFirewallAddressFilter|Select-Object -ExpandProperty RemoteAddress);protocol=@($r|Get-NetFirewallPortFilter|Select-Object -ExpandProperty Protocol)}};$o|ConvertTo-Json -Depth 6 -Compress"))

    def wait_state(self, phase, host, receive, direct):
        until = time.monotonic() + (15 if phase == 'all-off' else 900)
        stable = None
        while True:
            self.scm()
            got_host, got_receive, rules = self.host.is_file(), receive_ready(), self.rules()
            if got_host and not host:
                raise RuntimeError('Unrequested host driver was installed')
            cache = self.root / 'drivers/usb-installers'
            if phase == 'all-off' and cache.exists() and any(cache.iterdir()):
                raise RuntimeError('Prerequisite downloaded despite all-off policy')
            if not host and cache.exists() and any(p.suffix.lower() == '.msi' for p in cache.iterdir()):
                raise RuntimeError('Unrequested host MSI was downloaded')
            app = rules['app']
            app_ok = bool(app and app['group'] == 'PortHub managed USB bulk' and app['enabled'] == 'True'
                          and app['direction'] == 'Inbound' and app['action'] == 'Allow'
                          and app['program'] == [str(self.immutable)] and app['remote'] == ['LocalSubnet']
                          and app['protocol'] in (['TCP'], [6], ['6']))
            if not direct and app:
                raise RuntimeError('Unexpected direct application rule')
            ready = got_host == host and got_receive == receive and app_ok == direct and rules['raw_enabled'] == 0
            if ready:
                stable = stable or time.monotonic()
                if time.monotonic() - stable >= (10 if phase == 'all-off' else 2):
                    return {'phase': phase, 'host': got_host, 'receive': got_receive, 'direct': app_ok, 'raw_rules_enabled': 0}
            else:
                stable = None
            if time.monotonic() >= until:
                raise RuntimeError('Prerequisite readiness timed out: ' + phase)
            time.sleep(1)

    def verify_cache(self):
        # Read expected hashes from exact checked-out production source, not from
        # unsigned upstream metadata. Both installer bytes and signatures checked.
        import re
        source = Path(__file__).resolve().parents[1] / 'crates/porthub-agent/src/usb/windows_drivers.rs'
        expected = dict(re.findall(r'file:"([^"]+)".*?hash:"([a-f0-9]{64})"', source.read_text()))
        rows = []
        for path in sorted((self.root / 'drivers/usb-installers').glob('*')):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if path.name not in expected or digest != expected[path.name]:
                raise RuntimeError('Installer cache digest mismatch')
            valid = ps('(Get-AuthenticodeSignature -LiteralPath ' + quote(path) + ').Status')
            if valid != 'Valid':
                raise RuntimeError('Installer signature invalid')
            rows.append({'name': path.name, 'sha256': digest, 'signature': valid})
        if len(rows) != 2:
            raise RuntimeError('Expected both pinned prerequisite installers')
        return rows

    def preservation(self):
        self.protection()
        after = self.system_snapshot()
        if after['tasks'] != self.before['tasks'] or after['cli'] != self.before['cli']:
            raise RuntimeError('Unexpected GUI task/global CLI publication')
        return {'tasks_unchanged': True, 'global_cli_unchanged': True}

    def stop(self):
        if not self.created_root: return 'not-created; skipped'
        self.validate_claim('managed')
        self.cli('service', 'stop', '--profile', str(self.profile)); return True

    def uninstall(self):
        if not self.created_root: return 'not-created; skipped'
        self.validate_claim('managed')
        self.cli('service', 'uninstall', '--profile', str(self.profile), '--purge'); return True

    def cleanup_rule(self):
        if not self.created_root: return 'not-created; skipped'
        self.validate_claim('managed')
        ps('$r=Get-NetFirewallRule -Name ' + quote(self.rule) + " -ErrorAction SilentlyContinue;if($r){if($r.Group -ne 'PortHub managed USB bulk'){throw 'Foreign rule'};$r|Remove-NetFirewallRule}")
        return True

    def postcheck(self):
        ps("if(Get-Service -Name " + quote(self.service) + " -ErrorAction SilentlyContinue){throw 'Owned service remains'};if(Get-NetFirewallRule -Name " + quote(self.rule) + " -ErrorAction SilentlyContinue){throw 'Owned rule remains'}")
        ps("if(@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq " + quote(self.immutable) + " }).Count){throw 'Owned immutable process remains'}")
        after=self.system_snapshot()
        if after['tasks']!=self.before['tasks'] or after['cli']!=self.before['cli']:
            raise RuntimeError('GUI/globalCLI differs after cleanup')
        return True

    def allowed_managed(self):
        # Exact known fixture/runtime paths, never a prefix wildcard over other
        # registration IDs. Unexpected files survive for diagnosis.
        files = {'native/installations.lock', 'services/' + self.service + '.json',
                 'releases/' + self.sha + '/porthub.exe'}
        for suffix in ('', '.lock', '.config.json', '.status.json', '.local-access.json',
                       '.client-features.json', '.media-policy.json', '.drive-health-policy.json',
                       '.drive-health-schedule.json', '.update-attempt.json', '.update-commit.json'):
            files.add('native/' + self.identity + '.json' + suffix)
        files.add('native/' + self.identity + '.service.json')
        import re
        source = Path(__file__).resolve().parents[1] / 'crates/porthub-agent/src/usb/windows_drivers.rs'
        files.update('drivers/usb-installers/' + name for name in re.findall(r'file:"([^"]+)"', source.read_text()))
        dirs = {'native', 'services', 'releases', 'releases/' + self.sha, 'drivers', 'drivers/usb-installers'}
        return files, dirs

    def remove_claimed(self, kind):
        path, marker = self.validate_claim(kind)
        files, dirs = self.allowed_managed() if kind == 'managed' else ({'profile.json'}, set())
        entries = list(path.rglob('*'))
        if len(entries) > 256:
            raise RuntimeError('Owned staging exceeds cleanup bound')
        for entry in entries:
            info = entry.lstat()
            if entry.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise RuntimeError('Reparse point in staging; preserved')
            if entry == marker:
                continue
            relative = entry.relative_to(path).as_posix()
            if (stat.S_ISDIR(info.st_mode) and relative not in dirs) or (not stat.S_ISDIR(info.st_mode) and relative not in files):
                raise RuntimeError('Unknown staging entry preserved: ' + relative)
        self.validate_claim(kind)  # Recheck held directory/marker identities.
        shutil.rmtree(path)

    def remove_staging(self):
        errors = []
        # Refuse to delete any managed files while an owned service survives.
        try:
            self.postcheck()
        except Exception as error:
            errors.append('postcheck: ' + str(error))
        else:
            if self.created_root:
                try:
                    self.remove_claimed('managed')
                except Exception as error:
                    errors.append('managed: ' + str(error))
            elif os.path.lexists(self.root):
                errors.append('Foreign managed root preserved: trial did not create it')
        if self.created_temp:
            try:
                self.remove_claimed('temp')
            except Exception as error:
                errors.append('temp: ' + str(error))
        if errors:
            raise RuntimeError('; '.join(errors))
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable')
    parser.add_argument('--execute-cold-driver-install', action='store_true')
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    if not args.execute_cold_driver_install:
        parser.error('Explicit --execute-cold-driver-install opt-in required')
    receipt = run_trial(Native(args.executable, args.expected_sha256, args.source_revision))
    receipt['agent_sha256'] = args.expected_sha256
    receipt['source_revision'] = args.source_revision
    Path(args.receipt).write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if receipt['completed'] and not receipt['cleanup_errors'] else 1


if __name__ == '__main__':
    sys.exit(main())
