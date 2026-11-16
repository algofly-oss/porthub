"""Exercise the actual controller branches with OS/SCM boundaries refusing/mocked.
No task, process, driver, service, or Windows file operation is executed.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('controller', Path(__file__).with_name('test-windows-core-update.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class Clock:
    def __init__(self):
        self.now = 0
    def monotonic(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.adapter = controller.Native.__new__(controller.Native)
        a = self.adapter
        a.root = self.root
        (self.root / 'native').mkdir()
        (self.root / 'services').mkdir()
        a.profile = self.root / 'native' / ('a' * 64 + '.json')
        a.profile.write_text('{}')
        a.folder = self.root
        a.machine = 'machine'
        a.identity = 'a' * 64
        a.request_id = 'request'
        a.a = dict(version='1.11.34', sha256='a' * 64)
        a.b = dict(version='1.11.35', sha256='b' * 64, path=str(self.root / 'B.exe'))
        gate = types.SimpleNamespace(download_started=threading.Event(), release_download=threading.Event(),
                                     fail_version='1.11.35', events=[], candidate_sync_seen=threading.Event())
        gate.download_started.set()
        gate.advertise = lambda machine, version: 'next-request'
        a.gateway = gate
        self.calls = []
        a.validate_claim = lambda _: (self.root, None)
        a.disable_updates = lambda: self.calls.append('disable')
        a.assert_previous_without_attempt = lambda: True
        a.cli = lambda *args: self.calls.append(('cli', args))
        a.private = lambda path, value: path.write_text(json.dumps(value))
        self.manifest = Path(str(a.profile) + '.service.json')
        self.manifest.write_bytes(b'candidate-manifest')
        self.unit = self.root / 'services' / 'porthub-owned.json'
        self.unit.write_text('{"owned":true}')
        self.record = dict(nonce='c' * 32, candidate=str(self.root / 'releases' / ('b' * 64) / 'porthub.exe'),
                           previous_manifest=list(b'previous-manifest'), previous=dict(unit=str(self.unit)))
        a.candidate_pending = lambda: self.record
        def pin(action, record, inspected=None):
            self.calls.append(action)
            return dict(pid=9, creation='123', terminated=action == 'Terminate')
        a.pin_worker = pin
        def start(record, allow_failure=False):
            self.calls.append(('start', allow_failure))
            if not allow_failure and getattr(a, 'injected_metadata', None):
                path, original, _ = a.injected_metadata
                path.write_bytes(original)  # Simulated actual OS reconciliation boundary.
            return {'started': not allow_failure}
        a.start_exact_candidate = start
        a.wait_transaction = lambda rollback: dict(phase='rolled-back' if rollback else 'committed')
        self.clock = Clock()
        self.monotonic = patch.object(controller.time, 'monotonic', self.clock.monotonic)
        self.sleep = patch.object(controller.time, 'sleep', self.clock.sleep)
        self.monotonic.start()
        self.sleep.start()

    def tearDown(self):
        self.monotonic.stop()
        self.sleep.stop()
        self.temporary.cleanup()

    def test_download_revokes_before_release_and_never_creates_journal(self):
        self.adapter.disable_updates = lambda: self.assertFalse(self.adapter.gateway.release_download.is_set())
        proof = self.adapter.exercise_scenario('download-revoke')
        self.assertTrue(self.adapter.gateway.release_download.is_set())
        self.assertEqual(proof['phase'], 'cancelled-before-journal')
        self.assertTrue(proof['journal_absent'])

    def test_readiness_revoke_releases_candidate_then_requires_rollback(self):
        proof = self.adapter.exercise_scenario('readiness-revoke')
        self.assertEqual(self.calls, ['disable'])
        self.assertIsNone(self.adapter.gateway.fail_version)
        self.assertEqual(proof['phase'], 'rolled-back')

    def test_worker_loss_uses_inspected_instance_and_does_not_restart_scm(self):
        proof = self.adapter.exercise_scenario('worker-loss')
        self.assertEqual(self.calls, ['Inspect', 'Terminate'])
        self.assertEqual(proof['terminated_worker']['creation'], '123')
        self.assertFalse(proof['restart_mixed_metadata'])

    def test_restart_injects_exact_old_manifest_only_after_stop_and_held_kill(self):
        def start(record, allow_failure=False):
            self.assertEqual(self.manifest.read_bytes(), b'previous-manifest')
            self.assertEqual(self.calls[0], 'Inspect')
            self.assertEqual(self.calls[1][0], 'cli')
            self.assertEqual(self.calls[2], 'Terminate')
            self.manifest.write_bytes(b'candidate-manifest')
        self.adapter.start_exact_candidate = start
        proof = self.adapter.exercise_scenario('restart-recovery')
        self.assertTrue(proof['restart_mixed_metadata'])
        self.adapter.restore_injected_metadata()
        self.assertIsNone(self.adapter.injected_metadata)

    def test_tamper_preserved_then_only_exact_injected_bytes_restored(self):
        proof = self.adapter.exercise_scenario('tamper')
        self.assertEqual(proof['foreign_metadata_preserved_seconds'], 35)
        self.assertEqual(self.unit.read_text(), '{"owned":true}')
        self.assertEqual([x for x in self.calls if isinstance(x, tuple) and x[0] == 'start'],
                         [('start', True), ('start', False)])

    def test_third_metadata_state_is_never_overwritten_by_cleanup(self):
        self.adapter.injected_metadata = (self.unit, b'original', 'a' * 64)
        self.unit.write_text('third operator state')
        with self.assertRaises(RuntimeError):
            self.adapter.restore_injected_metadata()
        self.assertEqual(self.unit.read_text(), 'third operator state')

    def test_legacy_equal_request_waits_without_ack_then_newer_request_executes(self):
        self.adapter.gateway.events = [dict(kind='request-observed', request_id=self.adapter.request_id)]
        proof = self.adapter.exercise_scenario('legacy-supersession')
        self.assertGreaterEqual(self.clock.now, 5)
        self.assertTrue(proof['equal_legacy_request_unacknowledged'])
        self.assertEqual(self.adapter.request_id, 'next-request')

    def test_foreign_record_worker_rejected_without_touching_actual_journal(self):
        path = Path(str(self.adapter.profile) + '.windows-update.json')
        path.write_text('{"phase":"committed"}')
        with patch.object(controller.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1)) as run:
            proof = self.adapter.exercise_scenario('foreign-worker')
        self.assertTrue(proof['foreign_worker_rejected'])
        self.assertIn('__windows-update', run.call_args.args[0])
        self.assertFalse((self.root / 'foreign-record.json').exists())
        self.assertEqual(path.read_text(), '{"phase":"committed"}')

    def test_actual_disable_method_releases_barrier_after_cli_even_on_failure(self):
        a = self.adapter
        a.installed_ids = ['machine']
        def cli(*_):
            self.assertFalse(a.gateway.release_download.is_set())
            raise RuntimeError('injected policy failure')
        a.cli = cli
        with self.assertRaises(RuntimeError):
            controller.Native.disable_updates(a)
        self.assertTrue(a.gateway.release_download.is_set())

    def test_post_rollback_requires_later_old_heartbeat_and_quiet_no_retry(self):
        a = self.adapter
        a.gateway.overflow = False
        a.gateway.events = [dict(kind='download', sequence=1)]
        a.terminal_sequence = 1
        a.terminal_downloads = 1
        a.terminal_observed = self.clock.now
        a.journal_for = lambda _: {'phase': 'rolled-back'}
        def sleep(seconds):
            self.clock.sleep(seconds)
            if len(a.gateway.events) == 1:
                a.gateway.events.append(dict(kind='sync', machine=a.machine, version=a.a['version'],
                                             journal_phase='rolled-back', sequence=2, handled=''))
        with patch.object(controller.time, 'sleep', sleep):
            a.assert_ack(True)
        self.assertGreaterEqual(self.clock.now, 5)

    def test_post_terminal_retry_and_late_invalid_ack_fail_closed(self):
        a = self.adapter
        a.gateway.overflow = False
        a.gateway.events = [dict(kind='download', sequence=1),
                            dict(kind='sync', machine=a.machine, version=a.a['version'], journal_phase='rolled-back', sequence=2, handled=''),
                            dict(kind='download', sequence=3)]
        a.terminal_sequence = 1
        a.terminal_downloads = 1
        a.terminal_observed = self.clock.now
        a.journal_for = lambda _: {'phase': 'rolled-back'}
        with self.assertRaises(RuntimeError):
            a.assert_ack(True)
        closed = []
        a.gateway.close = lambda: closed.append(True)
        a.gateway.events.append(dict(kind='invalid-ack'))
        with self.assertRaises(RuntimeError):
            a.close_gateway()
        self.assertEqual(closed, [True])

    def test_final_http_drain_catches_ack_arriving_during_gateway_close(self):
        a = self.adapter
        a.gateway.overflow = False
        a.gateway.close = lambda: a.gateway.events.append(dict(kind='invalid-ack', sequence=1))
        with self.assertRaises(RuntimeError):
            a.close_gateway()
        self.assertEqual(a.final_observations['events'][0]['kind'], 'invalid-ack')

    def test_copied_foreground_runs_with_only_its_auto_flag_and_owned_handle_cleanup(self):
        a = self.adapter
        seed = self.root / 'seed.json'
        seed.write_text('{"format_version":1,"server":"http://127.0.0.1:9","machine_id":"machine","token":"fixture-only"}')
        a.profiles = {a.machine: {'input': seed}}
        a.a['path'] = str(self.root / 'A.exe')
        created = []
        test = self
        class Child:
            pid = 99
            stopped = False
            def __init__(self, args, **kwargs):
                created.append(self)
                test.assertEqual(args[1:3], ['run', '--profile'])
                test.assertEqual(kwargs['creationflags'], 0x08000000)
                source = Path(args[3])
                flags = json.loads(Path(str(source) + '.client-features.json').read_text())['disabled']
                test.assertFalse(flags['auto-update'])
                test.assertTrue(all(v for k, v in flags.items() if k != 'auto-update'))
                Path(str(source) + '.status.json').write_text(json.dumps(dict(state='running', pid=self.pid)))
            def poll(self):
                return 0 if self.stopped else None
            def terminate(self):
                self.stopped = True
            def wait(self, timeout):
                test.assertTrue(self.stopped)
                return 0
        with patch.object(controller.subprocess, 'Popen', Child):
            proof = a.exercise_foreground()
        self.assertTrue(created[0].stopped)
        self.assertEqual(proof['phase'], 'foreground-rejected')
        self.assertEqual(list(self.root.glob('foreground-profile.json*')), [])
        self.assertIsNone(a.foreground_child)

    def test_preservation_allows_only_auto_flag_change_not_keyboard_permission(self):
        a = self.adapter
        path = Path(str(a.profile) + '.client-features.json')
        original = {'disabled': {'auto-update': True, 'keyboard': True}}
        path.write_text(json.dumps(original))
        a.cli_path = self.root / 'shared.exe'
        a.cli_path.write_bytes(b'owned-shared-cli')
        a.c = {'sha256': controller.digest(a.cli_path)}
        task = dict(xml='<Task/>', sd='fixed-sddl', processes=[dict(pid=8, created='fixed')])
        other = dict(pid=7, sha256=a.c['sha256'])
        baseline = dict(files={str(path): controller.digest(path)}, own_policy=original,
                        other_identity='other', other_process=other, task=task)
        a.task_snapshot = lambda: task
        a.scm_snapshot = lambda _: other
        path.write_text(json.dumps({'disabled': {'auto-update': False, 'keyboard': True}}))
        a.assert_preserved(baseline)
        self.assertTrue(a.preservation_proof['other_permissions_unchanged'])
        path.write_text(json.dumps({'disabled': {'auto-update': False, 'keyboard': False}}))
        with self.assertRaises(RuntimeError):
            a.assert_preserved(baseline)

    def test_native_ps_wrapper_rejects_command_limit_and_sanitizes_module_path(self):
        with patch.dict(controller.os.environ, {'SystemRoot': 'C:/Windows', 'PSModulePath': 'foreign-modules'}):
            with patch.object(controller.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')) as run:
                controller.ps_result("'small trusted fixture command'")
                self.assertNotIn('PSModulePath', run.call_args.kwargs['env'])
                self.assertEqual(run.call_args.kwargs['creationflags'], 0x08000000)
                with self.assertRaises(RuntimeError):
                    controller.ps_result('x' * 20000)
                self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
