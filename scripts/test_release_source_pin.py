import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('source_pin', HERE/'release-source-pin.py')
pin = importlib.util.module_from_spec(spec); spec.loader.exec_module(pin)
A, B = 'a'*40, 'b'*40


class GitHub:
    def __init__(self):
        self.refs = {'refs/heads/main': A}
        self.writes = []
        self.current = None
        self.diverged = set()

    def ref(self, ref):
        return dict(ref=ref, object=dict(type='commit', sha=self.refs[ref])) if ref in self.refs else None

    def commit(self, ref):
        return self.refs.get(ref)

    def pins(self):
        return [self.ref(ref) for ref in self.refs if ref.startswith('refs/tags/'+pin.PREFIX)]

    def create(self, ref, source):
        if ref in self.refs:
            raise RuntimeError('Ref already exists')
        self.refs[ref] = source; self.writes.append(('create', ref, source))

    def delete(self, ref, expected):
        if self.refs[ref] != expected:
            raise RuntimeError('Lease changed')
        del self.refs[ref]; self.writes.append(('delete', ref, expected))

    def latest(self):
        return copy.deepcopy(self.current)

    def contains(self, older, current):
        return older not in self.diverged

    def published(self, version, source=A):
        self.current = dict(tag_name='v'+version, draft=False, prerelease=False)
        self.refs['refs/tags/v'+version] = source


class Pins(unittest.TestCase):
    def test_source_stays_referenced_after_main_advances_without_version_tag(self):
        github = GitHub()
        pin.reserve(github, '1.9.0', A, execute=True)
        github.refs['refs/heads/main'] = B
        self.assertEqual(pin.check_reference(github, '1.9.0', A), 'prepared-tag')
        self.assertNotIn('refs/tags/v1.9.0', github.refs)
        self.assertEqual(github.writes, [('create', pin.name('1.9.0', A), A)])
        self.assertEqual(pin.reserve(github, '1.9.0', A, execute=True)['status'], 'already-pinned')
        with self.assertRaises(ValueError):
            pin.reserve(github, '1.9.0', B, execute=True)
        self.assertEqual(len(github.writes), 1)

    def test_unreferenced_old_source_fails_before_builds_or_release_upload(self):
        github = GitHub(); github.refs['refs/heads/main'] = B
        with self.assertRaisesRegex(ValueError, 'no longer main head'):
            pin.reserve(github, '1.9.0', A, execute=True)
        with self.assertRaisesRegex(ValueError, 'Unreferenced release source'):
            pin.check_reference(github, '1.9.0', A)
        self.assertEqual(github.writes, [])

    def test_failed_pin_reserves_version_and_conflicting_draft_rejected(self):
        github = GitHub(); pin.reserve(github, '1.9.0', A, execute=True)
        rows = pin.reservations(github, [])
        self.assertEqual(rows, [dict(tag_name='v1.9.0', draft=True, prerelease=False, target_commitish=A)])
        self.assertEqual(pin.reservations(github, rows), rows)
        with self.assertRaises(ValueError):
            pin.reservations(github, [dict(rows[0], target_commitish=B)])

    def test_dry_runs_and_existing_version_tag_make_no_mutations(self):
        github = GitHub()
        self.assertEqual(pin.reserve(github, '1.9.0', A)['status'], 'ready')
        self.assertEqual(github.writes, [])
        github.published('1.9.0')
        self.assertEqual(pin.reserve(github, '1.9.0', A, execute=True)['status'], 'version-tag-present')
        with self.assertRaises(ValueError):
            pin.reserve(github, '1.9.0', B, execute=True)
        self.assertEqual(github.writes, [])

    def test_cleanup_requires_verified_stable_tag_and_preserves_future_failed_pin(self):
        github = GitHub()
        for version in ('1.8.9', '1.9.0', '1.9.1'):
            github.create(pin.name(version, A), A)
        github.writes.clear()
        with self.assertRaises(ValueError):
            pin.cleanup(github, '1.9.0', A, True)
        self.assertEqual(github.writes, [])
        github.published('1.9.0')
        pin.cleanup(github, '1.9.0', A, False)
        self.assertEqual(github.writes, [])
        result = pin.cleanup(github, '1.9.0', A, True)
        self.assertEqual(len(result['pins']), 2)
        self.assertEqual(github.refs[pin.name('1.9.1', A)], A)
        self.assertEqual(github.refs['refs/tags/v1.9.0'], A)
        self.assertNotIn(pin.name('1.9.0', A), github.refs)
        self.assertEqual(pin.cleanup(github, '1.9.0', A, True)['pins'], [])

    def test_cleanup_preserves_diverged_sources_and_latest_change_stops_deletion(self):
        github = GitHub(); github.create(pin.name('1.8.9', B), B); github.diverged.add(B)
        github.published('1.9.0')
        self.assertEqual(pin.cleanup(github, '1.9.0', A, True)['retained'], [pin.name('1.8.9', B)])
        github.diverged.clear(); github.writes.clear()
        latest = github.latest
        with patch.object(github, 'latest', side_effect=[latest(), dict(tag_name='v1.9.1', draft=False)]):
            with self.assertRaises(ValueError):
                pin.cleanup(github, '1.9.0', A, True)
        self.assertEqual(github.writes, [])

    def test_create_race_accepts_only_exact_identical_source(self):
        for competing, accepted in ((A, True), (B, False)):
            github = GitHub()
            def race(ref, source):
                github.refs[ref] = competing
                raise RuntimeError('Concurrent creation')
            with patch.object(github, 'create', side_effect=race):
                if accepted:
                    self.assertEqual(pin.reserve(github, '1.9.0', A, execute=True)['status'], 'pinned')
                else:
                    with self.assertRaises(RuntimeError):
                        pin.reserve(github, '1.9.0', A, execute=True)
            self.assertEqual(github.refs[pin.name('1.9.0', A)], competing)

    def test_malformed_pins_and_capacity_fail_closed(self):
        github = GitHub()
        github.refs['refs/tags/porthub-prepared/not-a-version'] = A
        with self.assertRaises(ValueError):
            pin.pins(github)
        with patch.object(github, 'pins', return_value=[{}]*257):
            with self.assertRaises(ValueError):
                pin.pins(github)

    def test_all_push_filters_exclude_internal_tags_without_changing_version_tag_pipeline(self):
        root=HERE.parent/'.github/workflows'
        continuous=(root/'continuous-release.yml').read_text()
        migration=(root/'migration-preflight.yml').read_text()
        components=(root/'component-contracts.yml').read_text()
        self.assertIn("tags: ['v*']",continuous)
        self.assertIn("branches: ['**']",migration)
        self.assertIn("tags-ignore: ['porthub-prepared/**']",migration)
        self.assertIn('branches: [main, codex/on-demand-components]',components)
        import re
        for path in root.glob('*.yml'):
            if re.search(r'^  push:',path.read_text(),re.M):
                self.assertIn(path.name,{'continuous-release.yml','migration-preflight.yml','component-contracts.yml'})
        reserve=(root/'agent-platforms.yml').read_text().split('  reserve-publication-source:',1)[1].split('  select-platforms:',1)[0]
        self.assertIn('inputs.verify_only != true',reserve)
        self.assertIn('inputs.publish_release == true',reserve)
        self.assertIn('inputs.core_only != true',reserve)
        self.assertIn('contents: write',reserve)
        select=(root/'agent-platforms.yml').read_text().split('  select-platforms:',1)[1].split('  local-native-core:',1)[0]
        self.assertIn('contents: read',select)
        self.assertIn('needs.reserve-publication-source.result',select)

    def test_rest_creation_is_only_post_and_cleanup_rejects_foreign_origin(self):
        github=pin.GitHub('owner/repo')
        with patch.object(github,'api',return_value={}) as api:
            github.create(pin.name('1.9.0',A),A)
            self.assertEqual(api.call_args.args[1],'POST')
            self.assertEqual(api.call_args.args[2],[('ref',pin.name('1.9.0',A)),('sha',A)])
        result=subprocess.CompletedProcess([],0,'https://github.com/foreign/repo.git\n','')
        with patch.object(pin.subprocess,'run',return_value=result) as run:
            with self.assertRaises(ValueError):github.delete(pin.name('1.9.0',A),A)
            self.assertEqual(run.call_count,1)



class GitLease(unittest.TestCase):
    def test_real_bare_git_compare_and_delete_never_removes_rebound_tag(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); work = root/'work'; work.mkdir(); remote = root/'remote.git'
            def git(*argv, check=True):
                return subprocess.run(['git', '-C', str(work), *argv], capture_output=True, text=True, check=check)
            subprocess.run(['git','init','--bare',str(remote)],check=True,capture_output=True)
            git('init'); git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
            f=work/'data';f.write_text('first');git('add','.');git('commit','-m','first');first=git('rev-parse','HEAD').stdout.strip()
            f.write_text('second');git('commit','-am','second');second=git('rev-parse','HEAD').stdout.strip()
            git('remote','add','origin',str(remote)); ref=pin.name('1.9.0',first)
            git('push','origin','HEAD:refs/heads/main')  # Make both owned commit objects available remotely.
            git('push','origin',first+':'+ref)
            subprocess.run(['git','--git-dir',str(remote),'update-ref',ref,second,first],check=True,capture_output=True)  # Owned fixture race only.
            with self.assertRaises(RuntimeError):
                pin.conditional_delete(ref,first,cwd=work)
            self.assertEqual(git('ls-remote','origin',ref).stdout.split()[0],second)
            pin.conditional_delete(ref,second,cwd=work)
            self.assertEqual(git('ls-remote','origin',ref).stdout,'')
            with self.assertRaises(ValueError):
                pin.conditional_delete('refs/tags/v1.9.0',second,cwd=work)


if __name__ == '__main__':
    unittest.main()
