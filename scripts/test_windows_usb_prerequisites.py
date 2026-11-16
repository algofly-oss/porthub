#!/usr/bin/env python3
"""Run real wrapper orchestration with refusing/mocked OS actions; no installers."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
import os
import shutil
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('trial', Path(__file__).with_name('test-windows-usb-prerequisites.py'))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class Fake:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail
    def action(self, name, value=True):
        self.calls.append(name)
        if name == self.fail:
            raise RuntimeError('injected ' + name)
        return value
    def preflight(self): return self.action('preflight')
    def stage(self): return self.action('stage')
    def install(self): return self.action('install')
    def enable(self, role): return self.action('enable:' + role)
    def wait_state(self, name, host, receive, direct):
        return self.action('wait:' + name, {'phase': name, 'host': host, 'receive': receive, 'direct': direct})
    def verify_cache(self): return self.action('verify_cache')
    def preservation(self): return self.action('preservation')
    def stop(self): return self.action('stop')
    def uninstall(self): return self.action('uninstall')
    def cleanup_rule(self): return self.action('cleanup_rule')
    def postcheck(self): return self.action('postcheck')
    def remove_staging(self): return self.action('remove_staging')


class Flow(unittest.TestCase):
    def test_success_roles_order_and_no_host_during_media_receive(self):
        a = Fake(); r = trial.run_trial(a)
        self.assertTrue(r['completed']); self.assertEqual(r['cleanup_errors'], [])
        self.assertEqual([(s['host'], s['receive'], s['direct']) for s in r['steps']],
                         [(False, False, False), (False, True, False), (False, True, True), (True, True, True)])
        self.assertLess(a.calls.index('wait:receive-only'), a.calls.index('enable:usb'))
        self.assertEqual(a.calls[-5:], ['stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'])
    def test_refused_existing_machine_never_mutates_or_cleans(self):
        a = Fake('preflight'); r = trial.run_trial(a)
        self.assertFalse(r['completed']); self.assertEqual(a.calls, ['preflight'])
    def test_partial_staging_failure_still_attempts_all_cleanup(self):
        a = Fake('stage'); r = trial.run_trial(a)
        self.assertFalse(r['completed']); self.assertEqual(a.calls[-5:], ['stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'])
    def test_every_execution_failure_stops_without_advancing_and_cleans(self):
        for failure in ('install', 'wait:all-off', 'enable:media-receive', 'wait:receive-only',
                        'enable:direct-connections', 'wait:receive-direct', 'enable:usb',
                        'wait:raw-usb', 'verify_cache', 'preservation'):
            with self.subTest(failure=failure):
                a = Fake(failure); r = trial.run_trial(a)
                self.assertFalse(r['completed']); self.assertEqual(a.calls[-5:], ['stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'])
    def test_each_cleanup_failure_does_not_skip_other_cleanup(self):
        for failure in ('stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'):
            with self.subTest(failure=failure):
                a = Fake(failure); r = trial.run_trial(a)
                self.assertEqual(len(r['cleanup_errors']), 1)
                self.assertEqual(a.calls[-5:], ['stop', 'uninstall', 'cleanup_rule', 'postcheck', 'remove_staging'])
    def test_generated_powershell_parses_without_executing_os_actions(self):
        pwsh = shutil.which('pwsh')
        if not pwsh:
            candidate = Path('/tmp/porthub-review-powershell-7.7/pwsh')
            pwsh = str(candidate) if candidate.is_file() else None
        if not pwsh:
            self.skipTest('PowerShell parser unavailable')
        scripts = []
        with tempfile.TemporaryDirectory(prefix='cold-usb-pure-') as folder:
            root = Path(folder); exe = root / 'porthub.exe'; exe.write_bytes(b'not-executed')
            with patch.dict(os.environ, {'ProgramData': str(root), 'ProgramFiles': str(root)}):
                n = trial.Native(exe, '0' * 64, '0' * 40)
            baseline = {'tasks': [], 'cli': False, 'usbipd_service': False, 'usbip_products': [], 'usbip_drivers': []}
            def capture(script):
                scripts.append(script)
                if 'Select-Object Name,State,StartName,ProcessId,PathName' in script:
                    return json.dumps({'Name': n.service, 'State': 'Running', 'StartName': 'LocalSystem', 'ProcessId': 1, 'PathName': str(n.immutable)})
                if '$o=@{raw_enabled' in script:
                    return json.dumps({'raw_enabled': 0, 'app': None})
                if 'ConvertTo-Json' in script:
                    return json.dumps(baseline)
                return ''
            def owned_temp(**kwargs):
                path = root / 'temporary-stage'; path.mkdir(); return str(path)
            with patch.object(trial, 'ps', capture), patch.object(trial.tempfile, 'mkdtemp', owned_temp):
                n.before = n.system_snapshot(); n.stage(); n.protection(); n.scm()
                n.rules(); n.cleanup_rule(); n.postcheck()
            payload = root / 'scripts.json'; payload.write_text(json.dumps(scripts))
            command = "param([string]$Path)\n$ErrorActionPreference='Stop';$s=Get-Content -Raw -LiteralPath $Path|ConvertFrom-Json;foreach($x in $s){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($x,[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)}};Write-Output $s.Count"
            parser = root / 'parse.ps1'; parser.write_text(command)
            result = subprocess.run([pwsh, '-NoProfile', '-File', str(parser), str(payload)], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout.decode().strip(), str(len(scripts)))
            self.assertGreaterEqual(len(scripts), 10)
    def test_powershell_quoting_is_literal(self):
        self.assertEqual(trial.quote("x';$(bad)"), "'x'';$(bad)'")


class CleanupFilesystem(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cold-usb-cleanup-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        exe = self.base / 'porthub.exe'; exe.write_bytes(b'never-executed')
        with patch.dict(os.environ, {'ProgramData': str(self.base), 'ProgramFiles': str(self.base)}):
            self.native = trial.Native(exe, '0' * 64, '0' * 40)
        self.ps_patch = patch.object(trial, 'ps', return_value='')
        self.ps_patch.start(); self.addCleanup(self.ps_patch.stop)
        self.native.postcheck = lambda: True  # Explicit OS boundary; no SCM exists.
        def owned_temp(**kwargs):
            path = self.base / 'temporary-stage'; path.mkdir(); return str(path)
        self.stage_patch = patch.object(trial.tempfile, 'mkdtemp', owned_temp)
        self.stage_patch.start(); self.addCleanup(self.stage_patch.stop)

    def test_root_appearing_after_preflight_is_never_deleted(self):
        n = self.native; n.root.mkdir(); foreign = n.root / 'foreign-secret'; foreign.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError): n.stage()
        self.assertFalse(n.created_root)
        with self.assertRaisesRegex(RuntimeError, 'Foreign managed root preserved'): n.remove_staging()
        self.assertEqual(foreign.read_bytes(), b'preserve')
        self.assertFalse(n.folder.exists())

    def test_partial_stage_after_claim_cleans_only_created_roots(self):
        n = self.native
        with patch.object(n, 'private', side_effect=RuntimeError('partial write failure')):
            with self.assertRaisesRegex(RuntimeError, 'partial write'): n.stage()
        self.assertTrue(n.created_root and n.created_temp)
        n.remove_staging(); self.assertFalse(n.root.exists()); self.assertFalse(n.folder.exists())

    def test_missing_marker_preserves_root_but_cleans_other_owned_temp(self):
        n = self.native; n.stage()
        n.claims['managed'][2].unlink()
        with self.assertRaises(RuntimeError): n.remove_staging()
        self.assertTrue(n.root.exists()); self.assertFalse(n.folder.exists())

    def test_wrong_marker_preserves_root(self):
        n = self.native; n.stage()
        n.claims['managed'][2].write_bytes(b'foreign marker')
        with self.assertRaisesRegex(RuntimeError, 'Ownership marker changed'): n.remove_staging()
        self.assertTrue(n.root.exists())

    def test_ordinary_cleanup_and_marker_binding(self):
        n = self.native; n.stage()
        marker = json.loads(n.claims['managed'][2].read_text())
        self.assertEqual(marker['nonce'], n.nonce)
        self.assertEqual(marker['executable_sha256'], n.sha)
        self.assertEqual(marker['path'], str(n.root.resolve()))
        n.remove_staging(); self.assertFalse(n.root.exists()); self.assertFalse(n.folder.exists())

    def test_unknown_runtime_file_preserved(self):
        n = self.native; n.stage(); unknown = n.root / 'native' / 'another-registration.json'
        unknown.write_bytes(b'foreign')
        with self.assertRaisesRegex(RuntimeError, 'Unknown staging entry preserved'): n.remove_staging()
        self.assertEqual(unknown.read_bytes(), b'foreign')

    def test_replaced_root_identity_preserved(self):
        n = self.native; n.stage(); original = n.root.with_name('old-owned-root')
        n.root.rename(original); n.root.mkdir(); (n.root / 'foreign').write_bytes(b'preserve')
        with self.assertRaisesRegex(RuntimeError, 'Owned directory identity changed'): n.remove_staging()
        self.assertEqual((n.root / 'foreign').read_bytes(), b'preserve')

    def test_reparse_entry_preserves_staging(self):
        n = self.native; n.stage(); outside = self.base / 'outside'; outside.mkdir()
        (n.root / 'native' / 'alias').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'Reparse point'): n.remove_staging()
        self.assertTrue(outside.exists()); self.assertTrue(n.root.exists())

if __name__ == '__main__':
    unittest.main()
