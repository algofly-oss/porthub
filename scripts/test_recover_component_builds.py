import importlib.util
import builtins
import json
import io
import os
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('recover', Path(__file__).with_name('recover-component-builds.py'))
recover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recover)
fixture = recover.load('packaging_fixture', 'test_package_components.py')


class Recovery(unittest.TestCase):
    def setUp(self):
        self.case = fixture.Packaging(); self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.release = self.root/'release'
        self.target = next(iter(recover.packager.TARGETS))
        self.entries = self.case.complete()
        recover.packager.package(self.entries, self.release, '1.12.0')
        # Unit tests isolate recovery from the subprocess. The real Rust verifier
        # is exercised separately against this exact packaging format.
        self.snapshot = {p.name: {'size': p.stat().st_size, 'digest': 'sha256:'+recover.planner.file_digest(p)} for p in self.release.iterdir()}

    def run_recovery(self, output):
        with patch.object(recover.publisher, 'assets', return_value=self.snapshot):
            return recover.recover(self.release, output, self.target, '1.12.0', Path('/trusted/verifier'))

    def test_recovers_core_and_tools_with_original_receipts(self):
        output = self.root/'recovered'
        builds = self.run_recovery(output)
        self.assertEqual([(b['tool'], b['version']) for b in builds], [('core','1.11.0'), ('stats','0.1.0'), ('sync','0.1.0'), ('terminal','0.1.0'), ('tor','0.1.0')])
        for build in builds:
            receipt = recover.planner.read_receipt(output/build['receipt'])
            recover.planner.verify_reuse(receipt, output/build['binary'])
        self.assertEqual(json.loads((output/'index.json').read_text())['release'], '1.12.0')

    def test_rejects_changed_release_without_publishing_output(self):
        (self.release/'porthub-x86_64').write_bytes(b'damaged')
        output = self.root/'recovered'
        with self.assertRaises(ValueError): self.run_recovery(output)
        self.assertFalse(output.exists())

    def test_rejects_wrong_target_and_existing_output(self):
        output = self.root/'recovered'; output.mkdir(); (output/'keep').write_text('keep')
        with self.assertRaises(ValueError): self.run_recovery(output)
        self.assertEqual((output/'keep').read_text(), 'keep')
        with self.assertRaises(ValueError): recover.recover(self.release, self.root/'other', '../invalid', '1.12.0', Path('/verifier'))

    def test_self_consistent_receipt_cannot_override_manifest_provenance(self):
        canonical = recover.packager.TARGETS[self.target][1]
        archive = self.release/('porthub-tools-'+canonical+'.tar.gz')
        with tarfile.open(archive) as packed:
            members = [(m, packed.extractfile(m).read()) for m in packed]
        with tarfile.open(archive, 'w:gz') as packed:
            for member, payload in members:
                if member.name == '.porthub-build-receipts.json':
                    envelope = json.loads(payload)
                    receipt = envelope['receipts'][1]
                    receipt['source_revision'] = 'b'*40
                    receipt.pop('receipt_sha256')
                    receipt['receipt_sha256'] = recover.planner.digest(receipt)
                    payload = json.dumps(envelope).encode()
                    member.size = len(payload)
                packed.addfile(member, io.BytesIO(payload))
        self.snapshot[archive.name] = {'size': archive.stat().st_size, 'digest': 'sha256:'+recover.planner.file_digest(archive)}
        output = self.root/'recovered'
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.run_recovery(output)
        self.assertFalse(output.exists())

    def test_standalone_targets_each_invoke_the_full_rust_verifier(self):
        verifier = self.root/'verifier'; verifier.write_text('trusted executable fixture')
        checked = SimpleNamespace(returncode=0, stdout=json.dumps({'version':'1.12.0', 'releases':[{}]*10}))
        with patch.object(recover.publisher.subprocess, 'run', return_value=checked) as rust:
            recover.recover(self.release, self.root/'one', self.target, '1.12.0', verifier)
            self.assertEqual(rust.call_count, 1)
            recover.recover(self.release, self.root/'two', list(recover.packager.TARGETS)[1], '1.12.0', verifier)
            self.assertEqual(rust.call_count, 2)

    def test_all_outputs_remain_private_on_late_target_failure(self):
        original = recover._recover_verified
        last = list(recover.packager.TARGETS)[-1]
        def fail(directory, output, target, release, verified):
            if target == last:
                raise OSError('late target extraction failed')
            return original(directory, output, target, release, verified)
        output = self.root/'all'
        with patch.object(recover, '_recover_verified', side_effect=fail):
            with self.assertRaises(OSError): recover._recover_all_verified(self.release, output, '1.12.0', self.snapshot)
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob('.porthub-recover-all-*')))

    def test_late_change_to_already_recovered_input_rejects_whole_batch(self):
        original = recover._recover_verified
        first = True
        def tamper(*args):
            nonlocal first
            result = original(*args)
            if first:
                first = False
                p = self.release/'porthub-x86_64'
                b = bytearray(p.read_bytes()); b[0] ^= 1; p.write_bytes(b)
            return result
        output = self.root/'all'
        with patch.object(recover, '_recover_verified', side_effect=tamper):
            with self.assertRaises(ValueError): recover._recover_all_verified(self.release, output, '1.12.0', self.snapshot)
        self.assertFalse(output.exists())

    def test_final_fence_checks_optional_media_not_read_by_target_recovery(self):
        media_fixture = recover.load('optional_media_fixture', 'test_media_release.py')
        media_fixture.fixture(self.release, version='1.12.0')
        snapshot = {p.name: {'size':p.stat().st_size, 'digest':'sha256:'+recover.planner.file_digest(p)} for p in self.release.iterdir()}
        optional = next(self.release.glob('porthub-media-helper-*.tar.gz'))
        original = recover._recover_verified
        first = True
        def tamper(*args):
            nonlocal first
            result = original(*args)
            if first:
                first = False
                optional.write_bytes(optional.read_bytes()[:-1])
            return result
        output = self.root/'all'
        with patch.object(recover, '_recover_verified', side_effect=tamper):
            with self.assertRaises(ValueError): recover._recover_all_verified(self.release, output, '1.12.0', snapshot)
        self.assertFalse(output.exists())

    def test_post_read_fence_rejects_symlink_size_and_same_size_tampering(self):
        original = recover.planner.verify_reuse
        source = self.release/'porthub-x86_64'
        original_bytes = source.read_bytes()
        for mutation in ['symlink', 'truncate', 'same-size']:
            with self.subTest(mutation=mutation):
                if mutation == 'symlink' and os.name == 'nt':
                    self.skipTest('File symlink privilege is not assumed on Windows')
                touched = False
                def tamper(receipt, binary):
                    nonlocal touched
                    result = original(receipt, binary)
                    if not touched:
                        touched = True
                        if mutation == 'symlink':
                            replacement = self.root/'same-bytes'; replacement.write_bytes(original_bytes)
                            source.unlink(); source.symlink_to(replacement)
                        elif mutation == 'truncate': source.write_bytes(original_bytes[:-1])
                        else: source.write_bytes(bytes([original_bytes[0] ^ 1])+original_bytes[1:])
                    return result
                output = self.root/('mutated-'+mutation)
                try:
                    with patch.object(recover.planner, 'verify_reuse', side_effect=tamper):
                        with self.assertRaises(ValueError): recover._recover_all_verified(self.release, output, '1.12.0', self.snapshot)
                    self.assertFalse(output.exists())
                finally:
                    source.unlink(); source.write_bytes(original_bytes)

    def test_final_inventory_addition_and_release_identity_are_rejected(self):
        original = recover._recover_verified
        def extra(*args):
            result = original(*args)
            (self.release/'unexpected').write_bytes(b'not authorized')
            return result
        with self.assertRaisesRegex(ValueError, 'identity'):
            recover._recover_all_verified(self.release, self.root/'wrong', '1.13.0', self.snapshot)
        with patch.object(recover, '_recover_verified', side_effect=extra):
            with self.assertRaisesRegex(ValueError, 'inventory'):
                recover._recover_all_verified(self.release, self.root/'extra', '1.12.0', self.snapshot)
        self.assertFalse((self.root/'wrong').exists()); self.assertFalse((self.root/'extra').exists())

    def test_artifact_validation_import_does_not_require_posix_locking(self):
        original = builtins.__import__
        def portable_import(name, *args, **kwargs):
            if name == 'fcntl':
                raise AssertionError('Artifact validation must work without fcntl')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=portable_import):
            spec = importlib.util.spec_from_file_location('portable_migration_check', Path(__file__).resolve().parents[1]/'deploy/native/migrate.py')
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
        self.assertEqual(len(migration.ASSETS), 10)

    def test_verifier_failure_publishes_nothing(self):
        output = self.root/'recovered'
        with patch.object(recover.publisher, 'assets', side_effect=ValueError('rejected')):
            with self.assertRaises(ValueError): recover.recover(self.release, output, self.target, '1.12.0', Path('/verifier'))
        self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
