import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('packager', Path(__file__).with_name('package-components.py'))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.count = 0

    def entry(self, target, tool, version=None):
        version = version or ('1.11.0' if tool == 'core' else '0.1.0')
        self.count += 1
        binary = self.root / ('binary-' + str(self.count))
        binary.write_bytes((tool + target + version).encode())
        recipe = {'profile': 'release', 'core': '>=1.11.0, <2.0.0', 'protocols': [1]}
        build = {'recipe': recipe, 'target': target}
        receipt = {'schema_version': 1, 'tool': tool, 'target': target, 'version': version,
            'source_revision': 'a'*40, 'build': build, 'fingerprint': packager.planner.digest(build),
            'binary': {'name': ('porthub' if tool == 'core' else 'porthub-'+tool) + ('.exe' if 'windows' in target else ''),
                       'size': binary.stat().st_size, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}}
        receipt['receipt_sha256'] = packager.planner.digest(receipt)
        path = self.root / ('receipt-' + str(self.count) + '.json')
        path.write_text(json.dumps(receipt))
        return path, binary

    def complete(self):
        return [self.entry(target, tool) for target in packager.TARGETS for tool in ('core', 'sync', 'tor')]

    def test_full_release_has_exactly_twenty_one_assets_and_is_reproducible(self):
        entries = self.complete()
        one, two = self.root/'one', self.root/'two'
        manifest = packager.package(entries, one, '1.11.0')
        packager.package(entries, two, '1.11.0')
        self.assertEqual(len(list(one.iterdir())), 21)
        self.assertEqual(len(manifest['core_assets']), 10)
        self.assertEqual(len(manifest['components']['artifacts']), 20)
        for path in one.iterdir():
            self.assertEqual(path.read_bytes(), (two/path.name).read_bytes())
            if path.name.endswith('.tar.gz'):
                with tarfile.open(path) as archive:
                    self.assertEqual(len(archive.getmembers()), 3)
                    receipts = json.load(archive.extractfile('.porthub-build-receipts.json'))
                    self.assertEqual([r['tool'] for r in receipts['receipts']], ['core', 'sync', 'tor'])
                    for receipt in receipts['receipts']:
                        stored = dict(receipt); checksum = stored.pop('receipt_sha256')
                        self.assertEqual(packager.planner.digest(stored), checksum)
                    self.assertTrue(all(member.isfile() and member.uid == member.gid == member.mtime == 0 for member in archive))

    def test_older_helper_versions_are_repacked_with_original_provenance(self):
        target = next(iter(packager.TARGETS))
        entries = [self.entry(target, 'core'), self.entry(target, 'sync'), self.entry(target, 'sync', '0.1.1')]
        manifest = packager.package(entries, self.root/'out', '1.11.0', verify_only=True)
        artifacts = manifest['components']['artifacts']
        self.assertEqual([a['version'] for a in artifacts], ['0.1.0', '0.1.1'])
        self.assertEqual(artifacts[0]['archive'], artifacts[1]['archive'])
        self.assertEqual(artifacts[0]['source_revision'], 'a'*40)

    def test_partial_release_requires_explicit_verification_mode(self):
        target = next(iter(packager.TARGETS))
        with self.assertRaises(ValueError):
            packager.package([self.entry(target, 'core'), self.entry(target, 'sync')], self.root/'out', '1.11.0')
        self.assertFalse((self.root/'out').exists())

    def test_corrupt_binary_and_duplicate_receipt_cannot_publish(self):
        entries = self.complete()
        entries[-1][1].write_bytes(b'damaged')
        with self.assertRaises(ValueError): packager.package(entries, self.root/'out', '1.11.0')
        self.assertFalse((self.root/'out').exists())
        entries = self.complete()
        with self.assertRaises(ValueError): packager.package(entries + [entries[0]], self.root/'duplicate', '1.11.0')

    def test_helper_only_release_preserves_core_version(self):
        entries = self.complete()
        manifest = packager.package(entries, self.root/'out', '1.12.0')
        self.assertEqual(manifest['release'], '1.12.0')
        self.assertEqual(manifest['core_version'], '1.11.0')
        self.assertEqual(manifest['components']['release'], '1.12.0')

    def test_helper_version_is_independent_of_release_version(self):
        target = next(iter(packager.TARGETS))
        manifest = packager.package([self.entry(target, 'core'), self.entry(target, 'sync', '3.0.0')],
                                   self.root/'out', '1.12.0', verify_only=True)
        self.assertEqual(manifest['components']['artifacts'][0]['version'], '3.0.0')

    def test_mixed_core_versions_are_rejected(self):
        entries = self.complete()
        entries[0] = self.entry(next(iter(packager.TARGETS)), 'core', '1.12.0')
        with self.assertRaises(ValueError):
            packager.package(entries, self.root/'out', '1.12.0')
        self.assertFalse((self.root/'out').exists())

    def test_existing_output_is_preserved(self):
        output = self.root/'out'; output.mkdir(); (output/'keep').write_text('existing')
        with self.assertRaises(ValueError): packager.package(self.complete(), output, '1.11.0')
        self.assertEqual((output/'keep').read_text(), 'existing')


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--fixture-output':
        case = Packaging()
        case.setUp()
        try:
            packager.package(case.complete(), Path(sys.argv[2]), '1.11.0')
        finally:
            case.doCleanups()
    else:
        unittest.main()
