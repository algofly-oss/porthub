import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location('prepare_release', Path(__file__).with_name('prepare-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class Versions(unittest.TestCase):
    def test_reservations_support_older_gh_and_keep_every_page(self):
        pages = [[{'tag_name':'v1.8.9','draft':False}], [{'tag_name':'v1.9.0','draft':True}]]
        output = '\n'.join(json.dumps(page) for page in pages)
        with patch.object(release.subprocess, 'run', return_value=Mock(returncode=0, stdout=output)) as invoke:
            self.assertEqual(release.release_reservations('owner/repo'), pages[0]+pages[1])
        self.assertNotIn('--slurp', invoke.call_args.args[0])

    def test_reservations_reject_failed_or_non_list_lookup(self):
        with patch.object(release.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, 'lookup failed'):
                release.release_reservations('owner/repo')
        for output in ['{}', '[]\n{"message":"failure"}', '[]\ninvalid']:
            with patch.object(release.subprocess, 'run', return_value=Mock(returncode=0, stdout=output)):
                with self.assertRaises(ValueError):
                    release.release_reservations('owner/repo')

    def test_atomic_replace_closes_writer_before_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'version.txt'; path.write_text('old')
            original_create, original_replace = release.tempfile.NamedTemporaryFile, Path.replace
            streams = []
            def create(*args, **kwargs):
                stream = original_create(*args, **kwargs); streams.append(stream)
                return stream
            def rename(source, destination):
                self.assertTrue(streams[-1].closed)
                return original_replace(source, destination)
            with patch.object(release.tempfile, 'NamedTemporaryFile', side_effect=create), patch.object(Path, 'replace', rename):
                release.replace(path, 'new')
            self.assertEqual(path.read_text(), 'new')
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_main_uses_explicit_bump_or_advances_latest_patch(self):
        self.assertEqual(release.choose_version('1.9.0','1.8.9'),'1.9.0')
        self.assertEqual(release.choose_version('1.8.9','1.8.9'),'1.8.10')
        self.assertEqual(release.choose_version('1.8.9','1.9.2'),'1.9.3')
        self.assertEqual(release.choose_version('1.9.0'),'1.9.0')
    def test_explicit_tag_must_match_committed_version_without_downgrade(self):
        self.assertEqual(release.choose_version('1.9.0','1.8.9','v1.9.0'),'1.9.0')
        for workspace,latest,tag in [('1.8.9','1.8.8','v9.0.0'),('1.8.9','1.9.0','v1.8.9'),('1.9.0','1.8.9','v1.9.0-preview')]:
            with self.assertRaises(ValueError):release.choose_version(workspace,latest,tag)
        for value in ['1.09.0','next','1.9.0-rc','1.9']:
            with self.assertRaises(ValueError):release.numeric(value)

class Repository(unittest.TestCase):
    def setUp(self):
        self.temp=self.enterContext(tempfile.TemporaryDirectory())
        self.root=Path(self.temp)/'work';self.root.mkdir()
        self.origin=Path(self.temp)/'remote.git'
        subprocess.run(['git','init','--bare','--initial-branch=main',str(self.origin)],check=True,capture_output=True)
        self.run_git('init','--initial-branch=main')
        self.run_git('config','user.name','Release fixture')
        self.run_git('config','user.email','fixture@example.test')
        (self.root/'Cargo.toml').write_text('[workspace]\nmembers=["app","stable"]\n[workspace.package]\nversion = "1.8.9"\n')
        for name,version in [('app','version.workspace=true'),('stable','version="0.1.0"')]:
            directory=self.root/name;directory.mkdir()
            (directory/'Cargo.toml').write_text(f'[package]\nname="{name}"\n{version}\n')
        (self.root/'Cargo.lock').write_text('version = 4\n\n[[package]]\nname = "app"\nversion = "1.8.9"\n\n[[package]]\nname = "stable"\nversion = "0.1.0"\n\n[[package]]\nname = "external"\nversion = "1.8.9"\nsource = "registry+https://example.test"\n')
        self.run_git('add','.')
        self.run_git('commit','-m','fixture baseline')
        self.run_git('tag','v1.8.9')
        self.run_git('remote','add','origin',str(self.origin))
        self.run_git('push','origin','main','--tags')
        self.latest={'tag_name':'v1.8.9','draft':False,'prerelease':False}
    def run_git(self,*args):
        return release.git(self.root,*args).stdout.strip()
    def change(self):
        (self.root/'README').write_text('new source\n')
        self.run_git('add','README');self.run_git('commit','-m','source change');self.run_git('push','origin','main')
        return self.run_git('rev-parse','HEAD')
    def test_dry_run_does_not_change_version_source_or_remote(self):
        head=self.change()
        result=release.prepare(self.root,'refs/heads/main',head,self.latest)
        self.assertEqual(result['version'],'1.8.10');self.assertTrue(result['would_commit'])
        self.assertEqual(release.remote_head(self.root,'main'),head)
        self.assertEqual(self.run_git('status','--porcelain'),'')
    def test_execution_pushes_only_matching_workspace_versions_and_lock_entries(self):
        head=self.change()
        result=release.prepare(self.root,'refs/heads/main',head,self.latest,execute=True)
        self.assertNotEqual(result['revision'],head)
        self.assertEqual(release.remote_head(self.root,'main'),result['revision'])
        self.assertEqual(tomllib.loads((self.root/'Cargo.toml').read_text())['workspace']['package']['version'],'1.8.10')
        packages={item['name']:item['version'] for item in tomllib.loads((self.root/'Cargo.lock').read_text())['package']}
        self.assertEqual(packages,{'app':'1.8.10','stable':'0.1.0','external':'1.8.9'})
        self.assertEqual(set(self.run_git('diff-tree','--no-commit-id','--name-only','-r','HEAD').splitlines()),{'Cargo.toml','Cargo.lock'})
        self.assertEqual(self.run_git('status','--porcelain'),'')
    def test_source_fix_skips_draft_and_reserved_tag_without_overwriting(self):
        head=self.change()
        self.run_git('tag','v1.8.11',self.run_git('rev-parse','v1.8.9'))
        draft={'tag_name':'v1.8.10','draft':True,'target_commitish':'a'*40}
        result=release.prepare(self.root,'refs/heads/main',head,self.latest,reservations=[draft])
        self.assertEqual(result['version'],'1.8.12')
        self.assertEqual(self.run_git('status','--porcelain'),'')
    def test_same_source_draft_can_resume_without_version_change(self):
        head=self.change()
        prepared=release.prepare(self.root,'refs/heads/main',head,self.latest,execute=True)
        draft={'tag_name':'v1.8.10','draft':True,'prerelease':False,'target_commitish':prepared['revision']}
        result=release.prepare(self.root,'refs/heads/main',prepared['revision'],self.latest,reservations=[draft])
        self.assertEqual(result['version'],'1.8.10')
        self.assertFalse(result['would_commit'])
        draft['target_commitish']='a'*40
        result=release.prepare(self.root,'refs/heads/main',prepared['revision'],self.latest,reservations=[draft])
        self.assertEqual(result['version'],'1.8.11')
    def test_draft_cannot_reserve_the_future_version_commit_for_current_source(self):
        head=self.change()
        draft={'tag_name':'v1.8.10','draft':True,'target_commitish':head}
        result=release.prepare(self.root,'refs/heads/main',head,self.latest,reservations=[draft])
        self.assertEqual(result['version'],'1.8.11')
    def test_workspace_section_is_updated_without_touching_an_earlier_dependency_version(self):
        manifest=self.root/'Cargo.toml'
        manifest.write_text('[dependencies.external]\nversion = "1.8.9"\n'+manifest.read_text())
        updates=release.version_files(self.root,'1.8.10')
        parsed=tomllib.loads(updates[manifest])
        self.assertEqual(parsed['workspace']['package']['version'],'1.8.10')
        self.assertEqual(parsed['dependencies']['external']['version'],'1.8.9')

    def test_newer_remote_source_supersedes_old_run_without_a_version_commit(self):
        head=self.change()
        (self.root/'README').write_text('newer source\n');self.run_git('add','README');self.run_git('commit','-m','newer');self.run_git('push','origin','main')
        newer=self.run_git('rev-parse','HEAD');self.run_git('checkout','--detach',head)
        result=release.prepare(self.root,'refs/heads/main',head,self.latest,execute=True)
        self.assertTrue(result['skip']);self.assertEqual(release.remote_head(self.root,'main'),newer)
        self.assertEqual(self.run_git('rev-parse','HEAD'),head)
    def test_published_source_is_idempotent(self):
        head=self.run_git('rev-parse','HEAD')
        result=release.prepare(self.root,'refs/tags/v1.8.9',head,self.latest,execute=True)
        self.assertTrue(result['already_published']);self.assertEqual(result['revision'],head)
    def test_dirty_source_bad_tag_and_missing_lock_entries_cannot_push(self):
        head=self.change()
        with self.assertRaises(ValueError):release.prepare(self.root,'refs/tags/v2.0.0',head,self.latest,execute=True)
        (self.root/'Cargo.lock').write_text('version=4\n')
        with self.assertRaises(ValueError):release.prepare(self.root,'refs/heads/main',head,self.latest,execute=True)
        self.run_git('add','Cargo.lock');self.run_git('commit','-m','broken lock');self.run_git('push','origin','main')
        broken=self.run_git('rev-parse','HEAD');before=(self.root/'Cargo.toml').read_bytes()
        with self.assertRaises(ValueError):release.prepare(self.root,'refs/heads/main',broken,self.latest,execute=True)
        self.assertEqual((self.root/'Cargo.toml').read_bytes(),before)
        self.assertEqual(release.remote_head(self.root,'main'),broken)

class IndependentCore(unittest.TestCase):
    def setUp(self):
        self.fixture = Repository(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        manifest = self.root/'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('"app","stable"', '"app","stable","crates/porthub-agent"'))
        directory = self.root/'crates/porthub-agent'; directory.mkdir(parents=True)
        (directory/'Cargo.toml').write_text('[package]\nname="porthub-agent"\nversion = "1.8.9"\n')
        lock = self.root/'Cargo.lock'
        lock.write_text(lock.read_text()+'\n[[package]]\nname = "porthub-agent"\nversion = "1.8.9"\n')
        self.fixture.run_git('add','.')
        self.fixture.run_git('commit','-m','independent core baseline')
        self.fixture.run_git('tag','-f','v1.8.9')
        self.fixture.run_git('push','origin','main','--force','--tags')

    def test_no_reuse_proof_advances_core_and_workspace_atomically(self):
        head = self.fixture.change()
        result = release.prepare(self.root,'refs/heads/main',head,self.fixture.latest,execute=True)
        self.assertEqual(result['core_version'], '1.8.10')
        self.assertEqual(release.core_package(self.root)[2], '1.8.10')
        packages = {p['name']:p['version'] for p in tomllib.loads((self.root/'Cargo.lock').read_text())['package']}
        self.assertEqual(packages['porthub-agent'], '1.8.10')
        self.assertEqual(packages['app'], '1.8.10')
        self.assertEqual(self.fixture.run_git('status','--porcelain'), '')

    def proof(self):
        coordinator, packager = Mock(), Mock()
        targets = ['target'+str(i) for i in range(10)]
        packager.TARGETS = targets
        directories = []
        for target in targets:
            directory = self.root/target; directory.mkdir()
            (directory/'index.json').write_text(json.dumps({'target':target}))
            directories.append(directory)
        coordinator.previous_builds.return_value = {('core','1.8.9'): ({'version':'1.8.9'}, Path('/verified/core'))}
        coordinator.planner.plan.return_value = {'action':'reuse'}
        return coordinator, packager, directories

    def test_complete_reuse_proof_preserves_core_during_server_bump(self):
        coordinator, packager, directories = self.proof()
        head = self.fixture.change()
        with patch.object(release, 'core_build_modules', return_value=(coordinator,packager)):
            result = release.prepare(self.root,'refs/heads/main',head,self.fixture.latest,execute=True,previous_core_builds=directories)
        self.assertEqual(result['version'], '1.8.10')
        self.assertEqual(result['core_version'], '1.8.9')
        self.assertEqual(release.core_package(self.root)[2], '1.8.9')
        self.assertEqual(coordinator.planner.plan.call_count, 10)
        self.assertEqual(self.fixture.run_git('status','--porcelain','--untracked-files=no'), '')

    def test_partial_proof_and_changed_platform_never_allow_reuse(self):
        coordinator, packager, directories = self.proof()
        with patch.object(release, 'core_build_modules', return_value=(coordinator,packager)):
            with self.assertRaises(ValueError): release.choose_core(self.root,'1.8.9',directories[:-1])
            coordinator.planner.plan.side_effect = ValueError('Changed core contents require a new release version')
            self.assertEqual(release.choose_core(self.root,'1.8.9',directories), '1.8.10')

    def test_explicit_tag_cannot_reuse_published_core_without_proof(self):
        for path, text in release.version_files(self.root, '1.9.0').items():
            path.write_text(text)
        self.fixture.run_git('add','.')
        self.fixture.run_git('commit','-m','server version only')
        head = self.fixture.run_git('rev-parse','HEAD')
        with self.assertRaisesRegex(ValueError, 'committed, unused core version'):
            release.prepare(self.root,'refs/tags/v1.9.0',head,self.fixture.latest,execute=True)
        self.assertEqual(release.core_package(self.root)[2], '1.8.9')
        self.assertEqual(self.fixture.run_git('status','--porcelain'), '')

    def reserve_draft_core(self):
        for path, text in release.core_version_files(self.root, '1.8.10', {}).items():
            path.write_text(text)
        self.fixture.run_git('add','.')
        self.fixture.run_git('commit','-m','draft core source')
        revision = self.fixture.run_git('rev-parse','HEAD')
        return {'tag_name':'v1.9.9', 'draft':True, 'prerelease':False, 'target_commitish':revision}

    def test_different_carrier_does_not_reuse_core_version_from_old_draft(self):
        draft = self.reserve_draft_core()
        head = self.fixture.change()
        result = release.prepare(self.root,'refs/heads/main',head,self.fixture.latest,reservations=[draft])
        self.assertEqual(result['version'], '1.8.10')
        self.assertEqual(result['core_version'], '1.8.11')

    def test_exact_source_draft_preserves_core_version(self):
        draft = self.reserve_draft_core()
        head = self.fixture.run_git('rev-parse','HEAD')
        self.fixture.run_git('push','origin','main')
        result = release.prepare(self.root,'refs/heads/main',head,self.fixture.latest,reservations=[draft])
        self.assertEqual(result['core_version'], '1.8.10')

    def test_unknown_reserved_source_fails_without_mutating_versions(self):
        head = self.fixture.change()
        before = (self.root/'Cargo.lock').read_bytes()
        draft = {'tag_name':'v1.9.9', 'draft':True, 'target_commitish':'unfixed-branch'}
        with self.assertRaisesRegex(ValueError, 'immutable'):
            release.prepare(self.root,'refs/heads/main',head,self.fixture.latest,execute=True,reservations=[draft])
        self.assertEqual((self.root/'Cargo.lock').read_bytes(), before)
        self.assertEqual(self.fixture.run_git('status','--porcelain'), '')

    def test_published_same_source_reports_actual_core_version(self):
        head = self.fixture.run_git('rev-parse','HEAD')
        result = release.prepare(self.root,'refs/heads/main',head,self.fixture.latest)
        self.assertTrue(result['already_published'])
        self.assertEqual(result['core_version'], '1.8.9')


if __name__=='__main__':unittest.main()
