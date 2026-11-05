import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('platform_build', Path(__file__).with_name('build-component-platform.py'))
platform = importlib.util.module_from_spec(spec); spec.loader.exec_module(platform)
spec = importlib.util.spec_from_file_location('planner_fixture', Path(__file__).with_name('test_component_build_plan.py'))
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)


class PlatformBuild(unittest.TestCase):
    def setUp(self):
        self.case = fixture.BuildPlanTests(); self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.previous = self.root/'previous'; self.previous.mkdir()
        (self.previous/'receipt.json').write_text(json.dumps(self.case.receipt))
        (self.previous/'tool').write_bytes(self.case.binary.read_bytes())
        self.row = {'tool':'tool', 'version':'0.1.0', 'receipt':'receipt.json', 'binary':'tool'}
        self.index()
        patcher = patch.object(platform.planner, 'require_clean_source'); patcher.start(); self.addCleanup(patcher.stop)

    def index(self):
        (self.previous/'index.json').write_text(json.dumps({'schema_version':1, 'target':fixture.TARGET, 'builds':[self.row]}))

    def run_build(self, output=None):
        return platform.run(self.root, fixture.TARGET, 'a'*40, output, self.previous, ['tool'])

    def test_unchanged_tool_reuses_verified_binary_without_cargo(self):
        output = self.root/'output'
        with patch.object(platform.planner, 'build_and_record', side_effect=AssertionError('must reuse')):
            choices = self.run_build(output)
        self.assertEqual(choices[0]['action'], 'reuse')
        builds = platform.previous_builds(output, fixture.TARGET)
        self.assertEqual(set(builds), {('tool','0.1.0')})
        self.assertEqual(builds[('tool','0.1.0')][1].read_bytes(), self.case.binary.read_bytes())

    def test_corrupt_previous_binary_fails_before_selection(self):
        (self.previous/'tool').write_bytes(b'corrupt')
        with self.assertRaises(ValueError): self.run_build(self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_changed_tool_builds_once_at_new_version(self):
        self.case.write('tool/src/main.rs', 'fn main(){println!("changed");}')
        output = self.root/'output'
        def build(root, tool, target, revision, version, binary):
            self.assertEqual((tool, version), ('tool','0.1.1'))
            binary.write_bytes(b'new executable')
            receipt = dict(self.case.receipt); receipt['version'] = version
            receipt['binary'] = {'name':'tool', 'size':14, 'sha256':platform.planner.file_digest(binary)}
            receipt.pop('receipt_sha256'); receipt['receipt_sha256'] = platform.planner.digest(receipt)
            return receipt
        with patch.object(platform.planner, 'build_and_record', side_effect=build) as mocked:
            self.assertEqual(self.run_build(output)[0]['action'], 'build')
            mocked.assert_called_once()
        recovered = platform.previous_builds(output, fixture.TARGET)
        self.assertEqual(set(recovered), {('tool','0.1.0'), ('tool','0.1.1')})

    def test_failed_build_does_not_publish_partial_output(self):
        self.case.write('tool/src/main.rs', 'changed')
        output = self.root/'output'
        with patch.object(platform.planner, 'build_and_record', side_effect=ValueError('failed')):
            with self.assertRaises(ValueError): self.run_build(output)
        self.assertFalse(output.exists())

    def test_unsafe_or_mismatched_index_cannot_select_files(self):
        for path in ('../outside', '/etc/passwd', 'C:/outside', 'folder\\outside'):
            self.row['binary'] = path; self.index()
            with self.assertRaises(ValueError): self.run_build()
        self.row['binary']='tool'; self.row['version']='0.2.0'; self.index()
        with self.assertRaises(ValueError): self.run_build()


if __name__ == '__main__': unittest.main()
