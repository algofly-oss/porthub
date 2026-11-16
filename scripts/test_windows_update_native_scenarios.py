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

    def test_native_ps_wrapper_rejects_command_limit_and_sanitizes_module_path(self):
        with patch.dict(controller.os.environ, {'SystemRoot': 'C:/Windows', 'PSModulePath': 'foreign-modules'}):
            with patch.object(controller.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')) as run:
                controller.ps_result("'small trusted fixture command'")
                self.assertNotIn('PSModulePath', run.call_args.kwargs['env'])
                self.assertEqual(run.call_args.kwargs['creationflags'], 0x08000000)
                with self.assertRaises(RuntimeError):
                    controller.ps_result('x' * 20000)
                self.assertEqual(run.call_count, 1)

    def test_repeated_headers_require_two_cycles_and_identical_postcommit_state(self):
        a = self.adapter
        a.workers = lambda: []
        a.gateway.events = [dict(kind='sync', sequence=1)]
        stable = dict(gui={'fixed': True}, scm={'pid': 99}, journal_nonce='nonce', journal_attempts=0, downloads=1)
        a.idempotence_snapshot = lambda: dict(stable)
        class Observer:
            def __init__(self, *_): pass
            proof = {'new_porthub_processes': 0}
            def __enter__(self): return self
            def __exit__(self, *_): return False
        def sleep(seconds):
            self.clock.sleep(seconds)
            a.gateway.events.append(dict(kind='changes-cycle', machine=a.machine, request_id=a.request_id,
                                         target_version=a.b['version'], journal_phase='committed', sequence=len(a.gateway.events)+1))
        with patch.object(controller, 'ProcessBirthWatch', Observer), patch.object(controller.time, 'sleep', sleep):
            a.assert_repeated_headers_idempotent()
        self.assertGreaterEqual(a.idempotence_proof['cycles'], 2)
        self.assertLessEqual(a.idempotence_proof['cycle_seconds'], 5)
        calls = []
        def changed():
            calls.append(True)
            return dict(stable, scm={'pid': 100 if len(calls) > 1 else 99})
        a.idempotence_snapshot = changed
        with patch.object(controller, 'ProcessBirthWatch', Observer), patch.object(controller.time, 'sleep', sleep):
            with self.assertRaises(RuntimeError):
                a.assert_repeated_headers_idempotent()

    def test_committed_snapshot_rejects_any_active_worker(self):
        self.adapter.journal_for = lambda _: {'phase': 'committed'}
        self.adapter.workers = lambda: [dict(ProcessId=9)]
        with self.assertRaises(RuntimeError):
            self.adapter.idempotence_snapshot()

    def test_process_observer_transport_rejects_births_and_closes_owned_pipes(self):
        import io
        made = []
        count = [0]
        class Child:
            returncode = None
            def __init__(self, *args, **kwargs):
                self.stdin = io.BytesIO()
                self.stdout = io.BytesIO((json.dumps({'ready': True})+'\n'+json.dumps({'count': count[0], 'expired': False})+'\n').encode())
                made.append(self)
            def poll(self): return self.returncode
            def wait(self, timeout): self.returncode = 0; return 0
            def terminate(self): self.returncode = -1
        with patch.dict(controller.os.environ, {'SystemRoot':'C:/Windows'}), patch.object(controller.subprocess, 'Popen', Child):
            with controller.ProcessBirthWatch(self.root) as observer:
                pass
            self.assertEqual(observer.proof['new_porthub_processes'], 0)
            self.assertEqual(list(self.root.glob('process-watch-stop-*')), [])
            self.assertTrue(made[-1].stdout.closed)
            count[0] = 1
            with self.assertRaises(RuntimeError):
                with controller.ProcessBirthWatch(self.root):
                    pass
            self.assertTrue(made[-1].stdout.closed)


class PreservationTests(unittest.TestCase):
    def setUp(self):
        import copy
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.a = controller.Native.__new__(controller.Native)
        a = self.a
        a.machine = 'a'
        a.profile = root / 'a.json'
        other = root / 'c.json'
        a.profiles = {'a': {'identity': 'a', 'profile': a.profile}, 'c': {'identity': 'c', 'profile': other}}
        a.fixture_scenario = 'success'
        for profile in (a.profile, other):
            profile.write_text(json.dumps(dict(token='original-token', server='https://original.invalid', machine_id=profile.stem)))
            Path(str(profile) + '.config.json').write_text('{"machine_id":"original","version":"fixed","toml":"fixed"}')
            Path(str(profile) + '.client-features.json').write_text(json.dumps({'disabled': {'auto-update': True, 'keyboard': True}}))
            for suffix in ('.media-policy.json', '.drive-health-policy.json', '.local-access.json'):
                Path(str(profile) + suffix).write_text('{"original":true}')
        Path(str(other) + '.service.json').write_text('{"other":"unchanged"}')
        a.cli_path = root / 'shared.exe'
        a.cli_path.write_bytes(b'shared-cli')
        a.c = {'sha256': controller.digest(a.cli_path)}
        self.task = dict(xml='<Task/>', sd='fixed-sddl', processes=[dict(pid=8, created='fixed')])
        a.task_snapshot = lambda: self.task
        a.scm_snapshot = lambda _: dict(pid=7, sha256=a.c['sha256'])
        self.security = dict(owner='S-1-5-18', protected=True, sddl='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)', allow=['S-1-5-18','S-1-5-32-544'])
        self.overrides = {}
        def os_security(script):
            for path, value in self.overrides.items():
                if '$path=' + controller.cold.quote(path) + ';' in script:
                    return json.dumps(value)
            return json.dumps(self.security)
        self.patch = patch.object(controller, 'ps', side_effect=os_security)
        self.patch.start()
        self.baseline = a.preservation_snapshot()
        self.enable_own()

    def enable_own(self):
        path = Path(str(self.a.profile) + '.client-features.json')
        value = json.loads(path.read_text())
        value['disabled'].pop('auto-update', None)
        path.write_text(json.dumps(value))

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_both_profiles_and_configs_are_frozen_with_security(self):
        for row in self.a.profiles.values():
            for suffix in ('', '.config.json'):
                saved = self.baseline['files'][str(row['profile']) + suffix]
                self.assertTrue(saved['exists'])
                self.assertEqual(saved['security']['owner'], 'S-1-5-18')
                self.assertTrue(saved['security']['protected'])
        self.a.assert_preserved(self.baseline)

    def test_token_server_machine_and_config_mutations_rejected_for_both_enrollments(self):
        for row in self.a.profiles.values():
            for suffix, field in [('', 'token'), ('', 'server'), ('', 'machine_id'), ('.config.json', 'toml')]:
                path = Path(str(row['profile']) + suffix)
                original = path.read_bytes()
                value = json.loads(original)
                value[field] = 'unexpected mutation'
                path.write_text(json.dumps(value))
                with self.subTest(profile=path.name, field=field), self.assertRaises(RuntimeError):
                    self.a.assert_preserved(self.baseline)
                path.write_bytes(original)

    def test_owner_dacl_unprotected_and_cli_permission_mutations_rejected(self):
        import copy
        for path in [str(self.a.profile), str(self.a.profile) + '.config.json', str(self.a.cli_path)]:
            for mutation in [{'owner': 'S-1-5-21-foreign'}, {'protected': False},
                             {'sddl': 'widened-dacl', 'allow': ['S-1-1-0']}]:
                changed = copy.deepcopy(self.security)
                changed.update(mutation)
                self.overrides[path] = changed
                with self.subTest(path=path, mutation=mutation), self.assertRaises(RuntimeError):
                    self.a.assert_preserved(self.baseline)
                self.overrides.clear()

    def test_extra_feature_top_level_and_new_policy_file_rejected(self):
        path = Path(str(self.a.profile) + '.client-features.json')
        original = path.read_bytes()
        for mutation in [{'disabled': {'keyboard': False}}, {'disabled': {'keyboard': True}, 'extra': True},
                         {'disabled': {'keyboard': True, 'auto-update': False}}]:
            path.write_text(json.dumps(mutation))
            with self.assertRaises(RuntimeError):
                self.a.assert_preserved(self.baseline)
        path.write_bytes(original)
        extra = Path(str(self.a.profile) + '.unexpected-policy.json')
        extra.write_text('{}')
        with self.assertRaises(RuntimeError):
            self.a.assert_preserved(self.baseline)

    def test_default_omission_and_foreground_no_toggle_are_exact(self):
        for scenario, omit in [('default-on', True), ('foreground-reject', False)]:
            self.a.fixture_scenario = scenario
            path = Path(str(self.a.profile) + '.client-features.json')
            value = {'disabled': {'keyboard': True}}
            if not omit:
                value['disabled']['auto-update'] = True
            path.write_text(json.dumps(value))
            baseline = self.a.preservation_snapshot()
            self.a.assert_preserved(baseline)
            value['disabled']['auto-update'] = False
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                self.a.assert_preserved(baseline)

    def test_revocation_allows_exact_off_state_but_not_missing_override(self):
        self.a.fixture_scenario = 'readiness-revoke'
        path = Path(str(self.a.profile) + '.client-features.json')
        path.write_text(json.dumps(self.baseline['own_policy'], indent=2))
        self.a.assert_preserved(self.baseline)
        self.enable_own()
        with self.assertRaises(RuntimeError):
            self.a.assert_preserved(self.baseline)

    def test_unknown_global_services_tasks_and_usb_changes_preserved(self):
        import copy
        baseline = dict(tasks=[], porthub_services=[], usbipd_service=False, usbip_products=[], usbip_drivers=[], cli=False)
        self.a.before = baseline
        sentinel = self.a.profile
        for field, value in [('porthub_services', ['porthub-foreign']), ('tasks', ['\\PortHubForeign']),
                             ('usbip_products', ['foreign-usb-install']), ('usbip_drivers', [{'DeviceID':'foreign'}])]:
            changed = copy.deepcopy(baseline)
            changed[field] = value
            self.a.system_snapshot = lambda changed=changed: copy.deepcopy(changed)
            self.a.postcheck = self.a.assert_global_preserved
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.a.remove_staging()
            self.assertTrue(sentinel.exists())

    def test_global_cli_security_widening_rejected_and_final_cli_absence_required(self):
        import copy
        baseline = dict(tasks=[], porthub_services=[], usbipd_service=False, usbip_products=[], usbip_drivers=[], cli=False)
        self.a.before = baseline
        current = dict(baseline, cli=True)
        self.a.system_snapshot = lambda: dict(current)
        self.a.assert_global_preserved()
        self.overrides[str(self.a.cli_path)] = dict(self.security, sddl='widened-cli')
        with self.assertRaises(RuntimeError):
            self.a.assert_global_preserved()
        self.overrides.clear()
        with self.assertRaises(RuntimeError):
            self.a.assert_global_preserved(final=True)
        current['cli'] = False
        self.a.assert_global_preserved(final=True)


if __name__ == '__main__':
    unittest.main()
