import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

spec = importlib.util.spec_from_file_location('prepare_release', Path(__file__).with_name('prepare-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class Versions(unittest.TestCase):
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

if __name__=='__main__':unittest.main()
