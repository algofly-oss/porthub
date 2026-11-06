import importlib.util
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-client-release.py'))
assembly = importlib.util.module_from_spec(spec); spec.loader.exec_module(assembly)
fixture = assembly.recovery.load('packaging_fixture', 'test_package_components.py')


class Assembly(unittest.TestCase):
    def setUp(self):
        self.case = fixture.Packaging(); self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.root = self.case.root; self.source = self.root/'platforms'; self.source.mkdir()
        by_target = {}
        for receipt_path, binary in self.case.complete():
            receipt = assembly.recovery.planner.read_receipt(receipt_path)
            target = receipt['target']; legacy = assembly.recovery.packager.TARGETS[target][0]
            directory = self.source/('porthub-'+legacy); directory.mkdir(exist_ok=True)
            folder = directory/receipt['tool']/receipt['version']; folder.mkdir(parents=True)
            output_binary = folder/receipt['binary']['name']; shutil.copyfile(binary,output_binary)
            output_receipt = folder/'receipt.json'; shutil.copyfile(receipt_path,output_receipt)
            by_target.setdefault(target, []).append({'tool':receipt['tool'], 'version':receipt['version'],
                'receipt':output_receipt.relative_to(directory).as_posix(), 'binary':output_binary.relative_to(directory).as_posix()})
        for target, rows in by_target.items():
            legacy = assembly.recovery.packager.TARGETS[target][0]
            (self.source/('porthub-'+legacy)/'index.json').write_text(json.dumps({'schema_version':1,'target':target,'builds':rows}))

    def test_all_platform_indexes_assemble_exact_compact_release(self):
        output = self.root/'release'
        def verify(directory, version, verifier):
            self.assertEqual(len(list(directory.iterdir())),21)
            self.assertFalse(output.exists())
            manifest = json.loads((directory/'porthub-components.json').read_text())
            self.assertEqual(manifest['core_version'],'1.11.0')
            self.assertEqual(len(manifest['components']['artifacts']),40)
            return {'verified':True}
        with patch.object(assembly.recovery.publisher,'assets',side_effect=verify):
            self.assertEqual(assembly.assemble(self.source,output,'1.12.0',Path('/verifier')),{'verified':True})
        self.assertEqual(len(list(output.iterdir())),21)

    def test_missing_or_mixed_platforms_never_publish(self):
        directory = self.source/'porthub-x86_64'
        (directory/'index.json').unlink()
        with self.assertRaisesRegex(ValueError,'mix'):
            assembly.assemble(self.source,self.root/'release','1.12.0',Path('/verifier'))
        shutil.rmtree(directory)
        with self.assertRaises(ValueError): assembly.assemble(self.source,self.root/'release','1.12.0',Path('/verifier'))
        self.assertFalse((self.root/'release').exists())

    def test_verifier_failure_and_corrupt_binary_leave_no_output(self):
        with patch.object(assembly.recovery.publisher,'assets',side_effect=ValueError('rejected')):
            with self.assertRaises(ValueError): assembly.assemble(self.source,self.root/'release','1.12.0',Path('/verifier'))
        binary = self.source/'porthub-x86_64/core/1.11.0/porthub'; binary.write_bytes(b'corrupt')
        with self.assertRaises(ValueError): assembly.assemble(self.source,self.root/'release','1.12.0',Path('/verifier'))
        self.assertFalse((self.root/'release').exists())


if __name__ == '__main__': unittest.main()
