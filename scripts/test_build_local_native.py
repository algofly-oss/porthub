import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('local_native', Path(__file__).with_name('build-local-native.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeBuildTests(unittest.TestCase):
    def test_native_targets(self):
        for system, machine, target in [('Linux','x86_64','x86_64-unknown-linux-musl'),
                ('Windows','AMD64','x86_64-pc-windows-msvc'), ('Darwin','arm64','aarch64-apple-darwin')]:
            self.assertEqual(module.native_target(system,machine),target)
        with self.assertRaises(ValueError):
            module.native_target('Linux','riscv64')

    def test_plan_never_builds(self):
        builder = Mock()
        builder.planner.shipping_environment.return_value = {'CARGO_INCREMENTAL':'0'}
        builder.planner.read_recipes.return_value = {'core':{}}
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'load',return_value=builder), patch.object(module.subprocess,'run') as process:
            result = module.run(Path(directory),'a'*40,Path(directory)/'output',tools=['core'])
        builder.run.assert_not_called()
        process.assert_not_called()
        self.assertFalse(result['publishes'])

    def test_execution_verifies_output_and_restores_environment(self):
        builder = Mock()
        builder.planner.shipping_environment.return_value = {'CARGO_INCREMENTAL':'0'}
        builder.planner.read_recipes.return_value = {'core':{}}
        builder.previous_builds.return_value = {'core':{}}
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'load',return_value=builder), patch.object(module.platform,'system',return_value='Windows'), patch.object(module.platform,'machine',return_value='AMD64'), patch.dict(module.os.environ,{'CARGO_INCREMENTAL':''}):
            result = module.run(Path(directory),'a'*40,Path(directory)/'output',True,['core'])
            self.assertEqual(module.os.environ['CARGO_INCREMENTAL'],'')
        builder.run.assert_called_once()
        builder.previous_builds.assert_called_once()
        self.assertEqual(result['verified_builds'],1)

    def test_reject_conflicting_environment_and_short_revision(self):
        builder = Mock()
        builder.planner.shipping_environment.return_value = {'CARGO_INCREMENTAL':'0'}
        builder.planner.read_recipes.return_value = {'core':{}}
        with tempfile.TemporaryDirectory() as directory, patch.object(module,'load',return_value=builder), patch.dict(module.os.environ,{'CARGO_INCREMENTAL':'1'}):
            for revision in ['abc','a'*40]:
                with self.assertRaises(ValueError):
                    module.run(Path(directory),revision,Path(directory)/'output',True,['core'])
        builder.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
