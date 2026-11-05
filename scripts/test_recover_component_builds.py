import importlib.util
import builtins
import json
import io
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
