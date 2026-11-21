#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('helper_plan', Path(__file__).with_name('media-helper-plan.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in module.package.INPUTS:
            path = self.root / name
            if name in ('crates/porthub-media-helper', 'crates/porthub-components'):
                path.mkdir(parents=True)
                (path / 'Cargo.toml').write_text('[package]\nname="' + path.name + '"\nversion="0.1.0"\n')
                (path / 'source.rs').write_text('// reviewed helper source\n')
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture input\n')
        (self.root / 'Cargo.toml').write_text(
            '[workspace]\nresolver="2"\nmembers=["crates/porthub-media-helper","crates/porthub-components"]\n'
            '[workspace.package]\nversion="1.11.51"\nedition="2021"\n')
        (self.root / 'Cargo.lock').write_text('''version = 4
[[package]]
name = "porthub-media-helper"
version = "0.1.0"
dependencies = ["porthub-components", "serde"]
[[package]]
name = "porthub-components"
version = "0.1.0"
dependencies = ["serde"]
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "porthub-agent"
version = "1.11.34"
''')
        self.run_git('init', '-q')
        self.run_git('config', 'user.email', 'fixture@example.invalid')
        self.run_git('config', 'user.name', 'Helper fixture')
        self.old = self.commit()
        digest = module.source_digest(module.inputs(self.root, self.old))
        self.previous = {'schema_version': 1, 'namespace': 'porthub-media',
                         'repository': 'algofly-oss/porthub', 'release': '1.11.51', 'artifacts': []}
        for target in sorted(module.media.TARGETS):
            blob = {'size': 1, 'sha256': '1' * 64}
            self.previous['artifacts'].append({'version': '0.1.0', 'target': target,
                'core': '>=1.11.34', 'protocol': 1, 'source_revision': self.old,
                'build_inputs': digest, 'executable': blob, 'archive': blob})

    def run_git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.DEVNULL).decode().strip()

    def commit(self):
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'Reviewed fixture change')
        return self.run_git('rev-parse', 'HEAD')

    def plan(self, previous=None, revision=None, targets=None):
        return module.plan(self.root, revision or self.run_git('rev-parse', 'HEAD'),
                           targets or module.media.TARGETS, previous)

    def test_initial_build_and_exact_prior_reuse(self):
        self.assertEqual(self.plan()['mode'], 'build')
        reused = self.plan(self.previous)
        self.assertEqual(reused['mode'], 'reuse')
        self.assertEqual(reused['manifest'], self.previous)

    def test_workspace_and_unrelated_lock_changes_preserve_exact_artifact_provenance(self):
        path = self.root / 'Cargo.toml'
        path.write_text(path.read_text().replace('1.11.51', '1.11.52'))
        path = self.root / 'Cargo.lock'
        path.write_text(path.read_text().replace('1.11.34', '1.11.35') + '\n[[package]]\nname="unrelated-api-dependency"\nversion="9.0.0"\n')
        self.commit()
        reused = self.plan(self.previous)
        self.assertEqual(reused['mode'], 'reuse')
        self.assertEqual(reused['artifact_source_revision'], self.old)
        self.assertEqual(reused['build_inputs'], self.previous['artifacts'][0]['build_inputs'])
        self.assertEqual(reused['manifest'], self.previous)

    def test_unrelated_workspace_member_reuses_original_provenance(self):
        manifest = self.root / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('members=[', 'members=["crates/porthub-forward-ssh",'))
        self.commit()
        reused = self.plan(self.previous)
        self.assertEqual(reused['mode'], 'reuse')
        self.assertEqual(reused['manifest'], self.previous)
        self.assertEqual(reused['artifact_source_revision'], self.old)
        self.assertEqual(reused['build_inputs'], self.previous['artifacts'][0]['build_inputs'])

    def test_membership_and_workspace_changes_affecting_helper_require_bump(self):
        manifest = self.root / 'Cargo.toml'
        original = manifest.read_text()
        for changed in (original.replace(',"crates/porthub-components"', ''),
                        original.replace('members=[', 'members=["crates/*",'),
                        original.replace('resolver="2"', 'resolver="3"'),
                        original + '\n[profile.release]\nlto=true\n'):
            with self.subTest(manifest=changed):
                manifest.write_text(changed)
                self.commit()
                with self.assertRaisesRegex(ValueError, 'Bump helper version'):
                    self.plan(self.previous)

    def test_changed_helper_or_dependency_or_build_recipe_requires_version_bump(self):
        for name in ['crates/porthub-media-helper/source.rs', 'scripts/build-media-helper-windows.ps1', 'rust-toolchain.toml']:
            with self.subTest(name=name):
                self.run_git('reset', '--hard', self.old)
                path = self.root / name
                path.write_text(path.read_text() + '// changed\n')
                self.commit()
                with self.assertRaisesRegex(ValueError, 'Bump helper version'):
                    self.plan(self.previous)
        self.run_git('reset', '--hard', self.old)
        path = self.root / 'Cargo.lock'
        path.write_text(path.read_text().replace('aaaaaaaa', 'bbbbbbbb'))
        self.commit()
        with self.assertRaisesRegex(ValueError, 'Bump helper version'):
            self.plan(self.previous)

    def test_new_helper_version_builds_and_old_version_cannot_downgrade(self):
        path = self.root / 'crates/porthub-media-helper/Cargo.toml'
        path.write_text(path.read_text().replace('0.1.0', '0.1.1'))
        lock = self.root / 'Cargo.lock'
        lock.write_text(lock.read_text().replace('name = "porthub-media-helper"\nversion = "0.1.0"', 'name = "porthub-media-helper"\nversion = "0.1.1"'))
        self.commit()
        self.assertEqual(self.plan(self.previous)['mode'], 'build')
        path.write_text(path.read_text().replace('0.1.1', '0.0.9'))
        lock.write_text(lock.read_text().replace('name = "porthub-media-helper"\nversion = "0.1.1"', 'name = "porthub-media-helper"\nversion = "0.0.9"'))
        self.commit()
        with self.assertRaisesRegex(ValueError, 'downgrade'):
            self.plan(self.previous)

    def test_dirty_source_changed_platforms_and_forged_prior_provenance_rejected(self):
        with self.assertRaisesRegex(ValueError, 'platforms'):
            self.plan(self.previous, targets=module.media.GNU)
        forged = json.loads(json.dumps(self.previous))
        for artifact in forged['artifacts']:
            artifact['build_inputs'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.plan(forged)
        (self.root / 'rust-toolchain.toml').write_text('uncommitted')
        with self.assertRaisesRegex(ValueError, 'committed'):
            self.plan(self.previous)


if __name__ == '__main__':
    unittest.main()
