import copy
import hashlib
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import zipfile

spec = importlib.util.spec_from_file_location('reuse', Path(__file__).with_name('reuse-client-artifacts.py'))
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class Reuse(unittest.TestCase):
    def setUp(self):
        self.repo = 'algofly-oss/porthub'
        self.run = dict(id=42, status='completed', conclusion='failure', event='workflow_dispatch',
                        path='.github/workflows/agent-platforms.yml', head_sha='a'*40,
                        head_repository=dict(full_name=self.repo))
        self.native = [dict(artifact='x86_64', target='x86_64-unknown-linux-gnu')]
        self.cross = [dict(artifact='armv7', target='armv7-unknown-linux-gnueabihf')]
        self.jobs = [dict(name='x86_64', status='completed', conclusion='success'),
                     dict(name='linux-32 (armv7-unknown-linux-gnueabihf, armv7, compiler)',
                          status='completed', conclusion='failure')]
        self.artifact = dict(id=3, name='porthub-x86_64', expired=False, size_in_bytes=100,
                             digest='sha256:'+'b'*64, workflow_run=dict(id=42, head_sha='a'*40))

    def selected(self, artifacts=None):
        return reuse.retained(self.run, self.jobs, artifacts or [self.artifact], self.repo, self.native, self.cross)

    def test_only_successful_platforms_are_reused_from_a_failed_run(self):
        self.assertEqual([item['platform'] for item in self.selected()], ['x86_64'])
        self.jobs[0]['conclusion'] = 'failure'
        self.assertEqual(self.selected(), [])

    def test_foreign_incomplete_and_wrong_workflow_runs_are_rejected(self):
        for key, value in [('status','in_progress'), ('conclusion','cancelled'),
                           ('event','pull_request'), ('path','.github/workflows/other.yml'),
                           ('head_repository',dict(full_name='foreign/repo'))]:
            with self.subTest(key=key):
                original = self.run[key]
                self.run[key] = value
                with self.assertRaises(ValueError): self.selected()
                self.run[key] = original

    def test_expired_corrupt_and_ambiguous_artifact_provenance_is_rejected(self):
        original = copy.deepcopy(self.artifact)
        for key, value in [('expired',True), ('digest','sha256:bad'), ('size_in_bytes',0),
                           ('workflow_run',dict(id=99,head_sha='a'*40)),
                           ('workflow_run',dict(id=42,head_sha='c'*40))]:
            self.artifact = {**original,key:value}
            with self.subTest(key=key), self.assertRaises(ValueError): self.selected()
        self.artifact = original
        with self.assertRaises(ValueError): self.selected([original,original])

    def test_compile_recipe_flags_and_global_environment_are_part_of_identity(self):
        current = (reuse.ROOT/'.github/workflows/agent-platforms.yml').read_text()
        orchestration = current.replace('  select-platforms:', '  different-selection:')
        self.assertEqual(reuse.recipe(current), reuse.recipe(orchestration))
        self.assertIn('--output component-builds',current)
        changed = current.replace('--output component-builds','--output component-builds --tool core')
        self.assertNotEqual(reuse.recipe(changed),reuse.recipe(current))
        self.assertNotEqual(reuse.recipe('env:\n  RUSTFLAGS: custom\n'+current),reuse.recipe(current))

    def test_real_git_fingerprint_rejects_changed_runtime_but_accepts_test_only_followup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            def command(*args):
                return subprocess.check_output(['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid',*args],cwd=root,stderr=subprocess.DEVNULL)
            command('init','-q')
            (root/'.github/workflows').mkdir(parents=True);(root/'crates/client/src').mkdir(parents=True);(root/'scripts').mkdir()
            (root/'.github/workflows/agent-platforms.yml').write_text('jobs:\n  native:\n    run: cargo build --release\n  linux-32:\n    run: cargo build --release\n')
            (root/'Cargo.toml').write_text('[workspace]\n');runtime=root/'crates/client/src/lib.rs';runtime.write_text('pub fn release() {}\n')
            def commit():
                command('add','.');command('commit','-qm','fixture');return command('rev-parse','HEAD').decode().strip()
            with patch.object(reuse,'ROOT',root):
                first=commit();original=reuse.fingerprint(first)
                (root/'scripts/test-fixture.py').write_text('new test harness\n');second=commit()
                self.assertEqual(original,reuse.fingerprint(second))
                runtime.write_text('pub fn changed() {}\n');third=commit()
                self.assertNotEqual(original,reuse.fingerprint(third))
                (root/'deploy').mkdir()
                (root/'deploy/component-platforms.toml').write_text('shipping flags changed\n')
                fourth=commit()
                self.assertNotEqual(reuse.fingerprint(third),reuse.fingerprint(fourth))
                (root/'scripts/build-component-platform.py').write_text('component recipe changed\n')
                fifth=commit()
                self.assertNotEqual(reuse.fingerprint(fourth),reuse.fingerprint(fifth))

    def test_matrix_catalog_is_read_without_executing_selector(self):
        native, cross = reuse.matrices()
        self.assertEqual(len(native)+len(cross),10)
        self.assertEqual(len({item['artifact'] for item in native+cross}),10)

    def test_archive_digest_canonical_paths_links_and_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);archive=root/'input.zip';destination=root/'platforms';destination.mkdir()
            def write(link=False):
                with zipfile.ZipFile(archive,'w') as zipped:
                    entry=zipfile.ZipInfo('porthub-x86_64')
                    if link:entry.external_attr=(stat.S_IFLNK|0o777)<<16
                    zipped.writestr(entry,b'binary')
                    zipped.writestr('porthub-x86_64.version',b'1.10.0\n')
                    zipped.writestr('porthub-x86_64.sha256',b'checksum')
                return dict(platform='x86_64',size=archive.stat().st_size,
                            digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
            item=write()
            with self.assertRaises(ValueError):reuse.extract(archive,{**item,'digest':'sha256:'+'0'*64},destination)
            with self.assertRaises(ValueError):reuse.extract(archive,write(link=True),destination)
            item=write();reuse.extract(archive,item,destination)
            self.assertEqual((destination/'porthub-x86_64/porthub-x86_64').read_bytes(),b'binary')
            with self.assertRaises(ValueError):reuse.extract(archive,item,destination)

    def test_indexed_artifact_verifies_receipts_and_rejects_corruption_atomically(self):
        spec = importlib.util.spec_from_file_location('indexed_fixture', Path(__file__).with_name('test_assemble_client_release.py'))
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        case = fixture.Assembly(); case.setUp(); self.addCleanup(case.doCleanups)
        source = case.source/'porthub-x86_64'
        destination = case.root/'reused'; destination.mkdir()
        archive = case.root/'indexed.zip'
        def package(extra=False):
            with zipfile.ZipFile(archive, 'w') as zipped:
                for path in source.rglob('*'):
                    if path.is_file(): zipped.write(path, path.relative_to(source).as_posix())
                if extra: zipped.writestr('../escape', b'bad')
            return dict(platform='x86_64',size=archive.stat().st_size,
                        digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
        with self.assertRaises(ValueError): reuse.extract(archive, package(True), destination)
        self.assertFalse((destination/'porthub-x86_64').exists())
        reuse.extract(archive, package(), destination)
        self.assertEqual((destination/'porthub-x86_64/index.json').read_bytes(), (source/'index.json').read_bytes())
        import shutil
        shutil.rmtree(destination/'porthub-x86_64')
        (source/'sync/0.1.0/porthub-sync').write_bytes(b'corrupt')
        with self.assertRaises(ValueError): reuse.extract(archive, package(), destination)
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__': unittest.main()
