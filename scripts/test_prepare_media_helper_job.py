#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import shutil
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


job = load('helper_job', 'prepare-media-helper-job.py')
fixtures = load('helper_job_fixtures', 'test_media_helper_plan.py')


class JobTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PlannerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        agent = self.fixture.root / 'crates/porthub-agent/Cargo.toml'
        agent.parent.mkdir(parents=True)
        agent.write_text('[package]\nname="porthub-agent"\nversion="1.11.34"\n')
        self.fixture.commit()

    def prepare(self, previous=None):
        f = self.fixture
        return job.prepare(f.root, f.run_git('rev-parse', 'HEAD'), 'https://portal.example',
                           job.RUNNERS, previous, fetch=False)

    def test_all_required_native_targets_build_but_exact_prior_assets_skip_every_build(self):
        plan = self.prepare()
        self.assertTrue(plan['enabled'])
        self.assertEqual(plan['mode'], 'build')
        self.assertEqual({p['target'] for p in plan['matrix']}, set(job.RUNNERS))
        self.assertEqual(plan['core'], '1.11.34')
        reused = self.prepare(self.fixture.previous)
        self.assertEqual(reused['mode'], 'reuse')
        self.assertEqual(reused['matrix'], [])
        self.assertEqual(reused['manifest'], self.fixture.previous)

    def test_declared_protocol_one_minimum_is_independent_of_building_core(self):
        root = self.fixture.root
        agent = root / 'crates/porthub-agent/Cargo.toml'
        agent.write_text(agent.read_text().replace('1.11.34', '1.11.35'))
        helper = root / 'crates/porthub-media-helper/Cargo.toml'
        helper.write_text(helper.read_text().replace('version="0.1.0"', 'version="0.2.1"') + '\n[package.metadata.porthub_media]\nminimum_core="1.11.34"\n')
        lock = root / 'Cargo.lock'
        lock.write_text(lock.read_text().replace('name = "porthub-media-helper"\nversion = "0.1.0"', 'name = "porthub-media-helper"\nversion = "0.2.1"'))
        self.fixture.commit()
        plan = self.prepare()
        self.assertEqual(plan['core'], '1.11.34')
        self.assertEqual(plan['building_core'], '1.11.35')
        release = load('helper_release_minimum', 'prepare-release.py')
        self.assertEqual(release.media_build_plan(root, '1.11.35', job.RUNNERS)['media_min_core'], '1.11.34')

    def test_minimum_rejects_future_malformed_and_below_protocol_floor(self):
        root = self.fixture.root
        helper = root / 'crates/porthub-media-helper/Cargo.toml'
        original = helper.read_text()
        release = load('helper_release_minimum_reject', 'prepare-release.py')
        for minimum in ['1.11.35', '1.11.33', 'invalid', 34]:
            with self.subTest(minimum=minimum):
                import json
                helper.write_text(original + '\n[package.metadata.porthub_media]\nminimum_core=' + json.dumps(minimum) + '\n')
                self.fixture.commit()
                with self.assertRaises(ValueError):
                    self.prepare()
                with self.assertRaises(ValueError):
                    release.media_build_plan(root, '1.11.34', job.RUNNERS)

    def test_pre_feature_helper_release_fails_and_legacy_without_helper_needs_no_assets(self):
        root = self.fixture.root
        agent = root / 'crates/porthub-agent/Cargo.toml'
        agent.write_text(agent.read_text().replace('1.11.34', '1.11.33'))
        self.fixture.commit()
        with self.assertRaisesRegex(ValueError, '1.11.34'):
            self.prepare()
        shutil.rmtree(root / 'crates/porthub-media-helper')
        self.fixture.commit()
        self.assertEqual(self.prepare(), {'enabled': False, 'mode': 'none', 'matrix': []})


if __name__ == '__main__':
    unittest.main()
