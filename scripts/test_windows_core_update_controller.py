import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('controller', Path(__file__).with_name('test-windows-core-update.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class Adapter:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []

    def __getattr__(self, name):
        def call(*args):
            self.calls.append(name)
            if name == self.fail:
                raise RuntimeError('injected ' + name)
            if name == 'preservation_snapshot':
                return {'other': 'unchanged'}
            if name == 'wait_transaction':
                return {'phase': 'rolled-back' if args[0] else 'committed'}
            return True
        return call


class FlowTests(unittest.TestCase):
    def test_success_and_rollback_use_same_real_orchestration(self):
        for rollback in [False, True]:
            adapter = Adapter()
            receipt = controller.run_case(adapter, rollback)
            self.assertTrue(receipt['completed'])
            self.assertEqual(receipt['cleanup_errors'], [])
            self.assertEqual(adapter.calls[:8], ['preflight', 'stage', 'install_pair', 'preservation_snapshot',
                                                 'advertise', 'assert_disabled', 'enable_updates', 'wait_transaction'])
            self.assertEqual(receipt['transaction']['phase'], 'rolled-back' if rollback else 'committed')

    def test_every_main_failure_runs_all_independent_cleanup_steps(self):
        for failure in ['preflight', 'stage', 'install_pair', 'preservation_snapshot', 'advertise',
                        'assert_disabled', 'enable_updates', 'wait_transaction', 'assert_preserved', 'assert_ack']:
            adapter = Adapter(failure)
            receipt = controller.run_case(adapter, False)
            self.assertFalse(receipt['completed'], failure)
            self.assertIn(failure, receipt['error'])
            self.assertEqual(adapter.calls[-8:], ['disable_updates', 'stop_workers', 'uninstall_pair',
                                                'cleanup_desktop', 'restore_path', 'postcheck',
                                                'remove_staging', 'close_gateway'])

    def test_default_on_and_foreground_do_not_explicitly_enable_installed_policy(self):
        for scenario in ['default-on', 'foreground-reject']:
            adapter = Adapter()
            result = controller.run_case(adapter, scenario)
            self.assertTrue(result['completed'])
            self.assertNotIn('enable_updates', adapter.calls)
            if scenario == 'default-on':
                self.assertNotIn('assert_disabled', adapter.calls)

    def test_equal_legacy_header_is_selected_before_initial_advertisement(self):
        adapter = Adapter()
        self.assertTrue(controller.run_case(adapter, 'legacy-supersession')['completed'])
        self.assertLess(adapter.calls.index('prepare_scenario'), adapter.calls.index('advertise'))

    def test_cleanup_failure_does_not_skip_later_cleanup(self):
        for failure in ['disable_updates', 'stop_workers', 'uninstall_pair', 'cleanup_desktop',
                        'restore_path', 'postcheck', 'remove_staging', 'close_gateway']:
            adapter = Adapter(failure)
            receipt = controller.run_case(adapter, False)
            self.assertEqual(len(receipt['cleanup_errors']), 1)
            self.assertEqual(adapter.calls[-1], 'close_gateway')

    def test_late_predicate_cannot_prove_timing_bound(self):
        from unittest.mock import patch
        with patch.object(controller.time, 'monotonic', side_effect=[0, 0, 6]):
            with self.assertRaises(RuntimeError):
                controller.wait_for(lambda: True, 5, 'late predicate')

class ArtifactTests(unittest.TestCase):
    def test_real_files_receipt_pinning_versions_and_symlink(self):
        import hashlib
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = []
            for role, version in zip('abc', ['1.11.34', '1.11.35', '1.11.36']):
                path = root / (role + '.exe')
                path.write_bytes(role.encode())
                rows.append(dict(role=role, path=str(path), version=version, source='a' * 40,
                                 sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=1,
                                 target='windows_x86_64', os='windows', arch='x86_64', asset='porthub-windows_x86_64.exe'))
            receipt = root / 'receipt.json'
            value = dict(schema=1, wrapper_source='b' * 40, artifacts=rows)
            receipt.write_text(json.dumps(value))
            self.assertEqual(len(controller.artifacts_from_manifest(receipt)['artifacts']), 3)
            rows[1]['version'] = '1.11.34'
            receipt.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                controller.artifacts_from_manifest(receipt)
            rows[1]['version'] = '1.11.35'
            Path(rows[1]['path']).write_bytes(b'changed')
            receipt.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                controller.artifacts_from_manifest(receipt)
            Path(rows[1]['path']).write_bytes(b'b')
            link = root / 'linked.exe'
            try:
                link.symlink_to(rows[1]['path'])
            except OSError:
                return
            rows[1]['path'] = str(link)
            receipt.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                controller.artifacts_from_manifest(receipt)


class OwnershipTests(unittest.TestCase):
    def fixture(self, path, kind='managed'):
        from unittest.mock import Mock
        adapter = controller.Native.__new__(controller.Native)
        adapter.identity = 'a' * 64
        adapter.sha = 'b' * 64
        adapter.nonce = 'c' * 32
        adapter.claims = {}
        adapter.rows = [{'sha256': 'b' * 64}]
        adapter.protect_directory = Mock()
        adapter.protect_marker = Mock()
        adapter.claim(path, kind)
        return adapter

    def test_real_files_owned_scope_removed_only_with_valid_marker(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.cold, 'ps', return_value=''):
            path = Path(temporary) / 'own'
            path.mkdir()
            adapter = self.fixture(path)
            (path / 'bin').mkdir()
            (path / 'bin/known.txt').write_text('known')
            adapter.remove_scope('managed', {'bin/known.txt'}, {'bin'})
            self.assertFalse(path.exists())

    def test_unknown_file_and_changed_marker_preserve_real_directory(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.cold, 'ps', return_value=''):
            path = Path(temporary) / 'own'
            path.mkdir()
            adapter = self.fixture(path)
            (path / 'foreign.txt').write_text('foreign')
            with self.assertRaises(RuntimeError):
                adapter.remove_scope('managed', set(), set())
            self.assertEqual((path / 'foreign.txt').read_text(), 'foreign')
            (path / 'foreign.txt').unlink()
            adapter.claims['managed'][2].write_text('tampered')
            with self.assertRaises(RuntimeError):
                adapter.remove_scope('managed', set(), set())
            self.assertTrue(path.exists())

    def test_replaced_directory_and_foreign_executable_not_deleted(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.cold, 'ps', return_value=''):
            path = Path(temporary) / 'own'
            path.mkdir()
            adapter = self.fixture(path)
            (path / 'agent.exe').write_bytes(b'foreign-image')
            with self.assertRaises(RuntimeError):
                adapter.remove_scope('managed', {'agent.exe'}, set(), executable=True)
            self.assertTrue((path / 'agent.exe').exists())
            path.rename(path.with_name('held-original'))
            path.mkdir()
            (path / 'foreign.txt').write_text('foreign')
            with self.assertRaises(RuntimeError):
                adapter.remove_scope('managed', {'foreign.txt'}, set())
            self.assertTrue((path / 'foreign.txt').exists())

    def test_readable_status_marker_is_not_a_protocol_json_record(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.cold, 'ps', return_value=''):
            path = Path(temporary) / 'own'
            path.mkdir()
            adapter = self.fixture(path, 'readable-status')
            self.assertEqual(list(path.glob('*.json')), [])
            self.assertEqual(adapter.validate_claim('readable-status')[0], path)


if __name__ == '__main__':
    unittest.main()
