"""Real temporary snapshot trees; no Docker, deployment or production cleanup."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import backup_retention as retention
import native_backup


class Retention(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'state' / 'core'
        (self.source / 'mongo').mkdir(parents=True)
        (self.source / 'mongo' / 'table').write_bytes(b'consistent stopped database')
        self.roots = []

    def make(self, number, project='porthub', source=None, mark=True):
        source = source or self.source
        root = self.root / ('release-' + str(number))
        record = root / 'deploy/native/upgrade-records' / (format(number, '040x') + '-owned')
        record.mkdir(parents=True, mode=0o700)
        record.chmod(0o700)
        backup = record / 'core-backup'
        backup.mkdir(mode=0o700)
        prepared = native_backup.prepare_snapshot(source, backup / 'data')
        proof = native_backup.finish_snapshot(prepared)
        retention.save(backup / 'verified.json', dict(source=str(source), container='owned-core-id', **proof))
        (record / 'previous.json').write_text('retained previous immutable image')
        if mark:
            retention.complete(record, project, source, format(number, '040x'))
            value = retention.private_json(record / retention.MARKER)
            value['completed_ns'] = number
            retention.save(record / retention.MARKER, value)
        self.roots.append(root)
        return record

    def run_prune(self, record, roots=None, **kw):
        return retention.prune(self.source, 'porthub', record, roots or [record.parents[3]], **kw)

    def test_cross_release_roots_keep_current_and_latest_recovery_without_deleting_configs(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        result = self.run_prune(c, self.roots)
        self.assertEqual(result['removed'], [str(a)])
        self.assertFalse((a / 'core-backup').exists())
        self.assertTrue((a / 'previous.json').exists())
        self.assertTrue((b / 'core-backup/data/mongo/table').exists())
        self.assertTrue((c / 'core-backup/data/mongo/table').exists())
        self.assertEqual((self.source / 'mongo/table').read_bytes(), b'consistent stopped database')
        self.assertEqual(self.run_prune(c)['removed'], [])

    def test_legacy_failed_foreign_and_other_state_snapshots_are_not_adopted(self):
        legacy = self.make(1, mark=False)
        foreign = self.make(2, project='other')
        other = self.root / 'other-state'
        (other / 'mongo').mkdir(parents=True)
        (other / 'mongo/table').write_bytes(b'foreign')
        different = self.make(3, source=other)
        current = self.make(4)
        self.run_prune(current, self.roots)
        for record in (legacy, foreign, different):
            self.assertTrue((record / 'core-backup/data/mongo/table').exists())
        self.assertFalse((legacy / retention.MARKER).exists())

    def test_registry_survives_database_restore_and_discovers_old_release_roots(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        self.run_prune(c, self.roots)
        registry = retention.registry_path(self.source, 'porthub')
        before = registry.read_bytes()
        shutil.rmtree(self.source)
        shutil.copytree(b / 'core-backup/data', self.source)
        self.assertEqual(registry.read_bytes(), before)
        d = self.make(4)
        self.run_prune(d)  # No explicit old roots needed after a restore.
        self.assertFalse((b / 'core-backup').exists())
        self.assertTrue((c / 'core-backup').exists())
        self.assertTrue((d / 'core-backup').exists())

    def test_interrupted_partial_prune_is_durably_retried(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        remove = shutil.rmtree
        def interrupted(path):
            (path / 'data/mongo/table').unlink()
            raise OSError('disk operation interrupted')
        with patch.object(retention.shutil, 'rmtree', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.run_prune(c, self.roots)
        self.assertTrue((a / retention.INTENT).exists())
        self.assertIn(str(a.parents[3]), retention.private_json(retention.registry_path(self.source, 'porthub'))['projects']['porthub'])
        result = self.run_prune(c)
        self.assertEqual(result['removed'], [str(a)])
        self.assertFalse((a / 'core-backup').exists())
        self.assertFalse((a / retention.INTENT).exists())
        self.assertTrue((b / 'core-backup/data/mongo/table').exists())

    def test_no_symlinks_mounts_foreign_files_or_forged_manifest_are_removed(self):
        for kind in ('symlink', 'mount', 'extra', 'manifest'):
            with self.subTest(kind=kind):
                a, b, c = [self.make(n) for n in range(len(self.roots) + 1, len(self.roots) + 4)]
                backup = a / 'core-backup'
                if kind == 'symlink':
                    (backup / 'data/mongo/table').unlink()
                    (backup / 'data/mongo/table').symlink_to(self.source / 'mongo/table')
                elif kind == 'extra':
                    (backup / 'foreign-important').write_text('leave intact')
                elif kind == 'manifest':
                    manifest = retention.private_json(backup / 'verified.json')
                    manifest['source'] = '/foreign'
                    retention.save(backup / 'verified.json', manifest)
                mounts = {backup / 'data/mongo'} if kind == 'mount' else set()
                with patch.object(retention, 'mounted_paths', return_value=mounts):
                    result = self.run_prune(c, self.roots[-3:])
                self.assertIn(str(a), result['skipped'])
                self.assertTrue(backup.exists())

    def test_parent_symlink_rejected_and_prune_resume_never_deletes_new_foreign_data(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        alias = self.root / 'alias'
        alias.symlink_to(a.parents[3], target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run_prune(c, [alias])
        with patch.object(retention.shutil, 'rmtree', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.run_prune(c, self.roots)
        (a / 'core-backup/foreign').write_text('new data')
        with self.assertRaises(ValueError):
            self.run_prune(c)
        self.assertTrue((a / 'core-backup/foreign').exists())

    def test_running_current_protected_even_if_completion_clock_moves_backwards(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        value = retention.private_json(c / retention.MARKER)
        value['completed_ns'] = 1
        retention.save(c / retention.MARKER, value)
        result = self.run_prune(c, self.roots)
        self.assertIn(str(c), result['protected'])
        self.assertIn(str(b), result['protected'])

    def test_registry_stays_bounded_during_many_normal_release_root_upgrades(self):
        prior = None
        for number in range(1, 70):
            current = self.make(number)
            roots = [current.parents[3]] + ([prior.parents[3]] if prior else [])
            self.run_prune(current, roots)
            registry = retention.private_json(retention.registry_path(self.source, 'porthub'))
            self.assertLessEqual(len(registry['projects']['porthub']), 2)
            prior = current
        self.assertEqual(len(list(self.root.glob('release-*/deploy/native/upgrade-records/*/core-backup'))), 2)

    def test_partial_cleanup_waits_for_two_valid_recoveries_and_retries_later(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        with patch.object(retention.shutil, 'rmtree', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.run_prune(c, self.roots)
        shutil.rmtree(b / 'core-backup')  # A separate missing recovery point.
        result = self.run_prune(c)
        self.assertIn(str(a), result['skipped'])
        self.assertTrue((a / retention.INTENT).exists())
        d = self.make(4)
        result = self.run_prune(d)
        self.assertIn(str(a), result['removed'])
        self.assertFalse((a / 'core-backup').exists())

    def test_skipped_roots_remain_discoverable_until_repaired(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        foreign = a / 'core-backup/unexpected'
        foreign.write_text('not declared')
        self.run_prune(c, self.roots)
        registry = retention.private_json(retention.registry_path(self.source, 'porthub'))
        self.assertIn(str(a.parents[3]), registry['projects']['porthub'])
        foreign.unlink()
        d = self.make(4)
        self.assertIn(str(a), self.run_prune(d)['removed'])

    def test_docker_bind_sources_protect_backup_parent_or_child_even_without_host_mount(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        for mount in (a / 'core-backup', a / 'core-backup/data/mongo', a.parents[3]):
            result = self.run_prune(c, self.roots, protected_sources=[mount])
            self.assertIn(str(a), result['protected'])
            self.assertTrue((a / 'core-backup/data/mongo/table').exists())
        result = self.run_prune(c)
        self.assertIn(str(a), result['removed'])

    def test_normal_upgrade_hook_uses_all_container_bind_sources_and_defers_errors(self):
        import upgrade
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        inventory = json.dumps([{'Mounts': [{'Type': 'bind', 'Source': str(a / 'core-backup/data')}]}])
        with patch.object(upgrade, 'run', side_effect=['owned-container', inventory]) as run:
            upgrade.retain_core_backups(self.source, 'porthub', c, c.parents[3],
                                       {'core': (str(b.parents[3]), 'unused')}, format(3, '040x'), extra_roots=[a.parents[3]])
        self.assertEqual(run.call_args_list[0].args[0], ['docker', 'ps', '--all', '--quiet', '--no-trunc'])
        self.assertTrue((a / 'core-backup').exists())
        with patch.object(upgrade, 'run', side_effect=RuntimeError('container disappeared during inspect')):
            upgrade.retain_core_backups(self.source, 'porthub', c, c.parents[3], {}, format(3, '040x'))
        self.assertTrue((c / 'core-backup').exists())


    def test_mount_is_rejected_before_traversal(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        mounted = a / 'core-backup/data/mongo'
        original = Path.iterdir
        def guarded(path):
            if path == mounted:
                raise AssertionError('Mounted subtree was traversed')
            return original(path)
        with patch.object(retention, 'mounted_paths', return_value={mounted}), patch.object(Path, 'iterdir', guarded):
            result = self.run_prune(c, self.roots)
        self.assertIn(str(a), result['skipped'])
        self.assertTrue((mounted / 'table').exists())


    def test_resume_rejects_replaced_data_even_at_an_original_manifest_path(self):
        a, b, c = [self.make(n) for n in (1, 2, 3)]
        with patch.object(retention.shutil, 'rmtree', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.run_prune(c, self.roots)
        original = a / 'core-backup/data/mongo/table'
        original.write_bytes(b'new unrelated contents at the same old path')
        with self.assertRaises(ValueError):
            self.run_prune(c)
        self.assertEqual(original.read_bytes(), b'new unrelated contents at the same old path')


    def test_missing_staged_retention_module_does_not_fail_healthy_upgrade(self):
        import upgrade
        current = self.make(1)
        with patch.dict(sys.modules, {'backup_retention': None}):
            upgrade.retain_core_backups(self.source, 'porthub', current, current.parents[3], {}, format(1, '040x'))
        self.assertTrue((current / 'core-backup/data/mongo/table').exists())


    def test_keep_policy_and_unsafe_registry_fail_closed(self):
        current = self.make(1)
        with self.assertRaises(ValueError):
            self.run_prune(current, keep=1)
        registry = retention.registry_path(self.source, 'porthub')
        registry.symlink_to(self.source / 'mongo/table')
        with self.assertRaises(ValueError):
            self.run_prune(current)
        self.assertTrue((current / 'core-backup').exists())


if __name__ == '__main__':
    unittest.main()
