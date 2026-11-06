import importlib.util
from pathlib import Path
import unittest
import subprocess
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('checks',Path(__file__).with_name('prepare-packaged-component-checks.py'))
checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks)
spec=importlib.util.spec_from_file_location('assembly_fixture',Path(__file__).with_name('test_assemble_client_release.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


class PackagedChecks(unittest.TestCase):
    def setUp(self):
        self.case=fixture.Assembly();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.root=self.case.root
        self.builds=self.case.source/'porthub-x86_64'

    def test_checks_use_verified_packaged_core_and_all_helpers(self):
        output=self.root/'dist/porthub';cache=self.root/'cache'
        with patch.object(checks.fixture,'seed') as seed, patch.object(checks.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'porthub 1.11.0\n','')) as version:
            environment=checks.prepare(self.builds,output,cache)
        self.assertEqual(version.call_args.args[0], [str(output.resolve()), 'version'])
        self.assertEqual(output.read_bytes(),(self.builds/'core/1.11.0/porthub').read_bytes())
        args=seed.call_args.args
        self.assertEqual(args[:4],(cache,'x86_64-unknown-linux-musl','1.11.0','a'*40))
        self.assertEqual({tool for tool,_ in args[4]},{'sync','stats','tor','terminal'})
        self.assertEqual(environment['PORTHUB_TEST_AGENT_EXECUTABLE'],str(output.resolve()))
        self.assertEqual(environment['PORTHUB_COMPONENT_CACHE'],str(cache.resolve()))

    def test_carrier_version_in_core_is_rejected_before_seeding_helpers(self):
        output=self.root/'dist/porthub';cache=self.root/'cache'
        with patch.object(checks.fixture,'seed') as seed, patch.object(checks.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'porthub 1.11.2\n','')):
            with self.assertRaisesRegex(ValueError,'version differs'):
                checks.prepare(self.builds,output,cache)
            seed.assert_not_called()
        self.assertFalse(output.exists())

    def test_core_version_probe_timeout_fails_closed(self):
        output=self.root/'dist/porthub'
        with patch.object(checks.fixture,'seed') as seed, patch.object(checks.subprocess,'run',side_effect=subprocess.TimeoutExpired('porthub',10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                checks.prepare(self.builds,output,self.root/'cache')
            seed.assert_not_called()
        self.assertFalse(output.exists())

    def test_corrupt_packaged_binary_is_rejected_before_seed(self):
        (self.builds/'sync/0.1.0/porthub-sync').write_bytes(b'corrupt')
        with patch.object(checks.fixture,'seed') as seed:
            with self.assertRaises(ValueError): checks.prepare(self.builds,self.root/'core',self.root/'cache')
            seed.assert_not_called()
        self.assertFalse((self.root/'core').exists())

    def test_existing_core_output_is_preserved(self):
        output=self.root/'core';output.write_bytes(b'existing')
        with patch.object(checks.fixture,'seed') as seed:
            with self.assertRaises(ValueError): checks.prepare(self.builds,output,self.root/'cache')
            seed.assert_not_called()
        self.assertEqual(output.read_bytes(),b'existing')


if __name__=='__main__':unittest.main()
