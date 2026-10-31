import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import stat
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location('stage', Path(__file__).with_name('stage-verified-release.py'))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class Provenance(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.run = dict(id=42, status='completed', conclusion='success', event='workflow_dispatch',
                        path='.github/workflows/agent-platforms.yml', head_sha=self.sha,
                        head_repository=dict(full_name='algofly-oss/porthub'))
        self.jobs = [dict(name='Validate complete release bundle', status='completed', conclusion='success')]
        self.artifact = dict(id=123, name='porthub-release-bundle', expired=False, size_in_bytes=100,
                             digest='sha256:'+'b'*64, workflow_run=dict(id=42, head_sha=self.sha))

    def validate(self):
        return stage.validate(self.run, self.jobs, [self.artifact], 'algofly-oss/porthub')

    def test_successful_original_source_is_returned(self):
        self.assertEqual(self.validate(), (self.sha, self.artifact))

    def test_incomplete_failed_foreign_or_other_workflows_are_rejected(self):
        for field, value in [('status','in_progress'), ('conclusion','failure'), ('event','pull_request'),
                             ('path','.github/workflows/untrusted.yml'), ('head_sha','main'),
                             ('head_repository',dict(full_name='fork/porthub')), ('head_repository',None)]:
            with self.subTest(field=field, value=value):
                original=copy.deepcopy(self.run); self.run[field]=value
                with self.assertRaises(ValueError): self.validate()
                self.run=original

    def test_complete_platform_gate_must_have_passed(self):
        for jobs in [[], [dict(self.jobs[0],conclusion='skipped')], [dict(self.jobs[0],status='in_progress')]]:
            with self.assertRaises(ValueError): stage.validate(self.run,jobs,[self.artifact],'algofly-oss/porthub')

    def test_artifact_identity_hash_size_and_expiry_are_required(self):
        for field,value in [('expired',True),('id',0),('size_in_bytes',0),('digest','sha256:invalid'),
                            ('workflow_run',dict(id=99,head_sha=self.sha)),('workflow_run',dict(id=42,head_sha='c'*40))]:
            with self.subTest(field=field):
                original=copy.deepcopy(self.artifact); self.artifact[field]=value
                with self.assertRaises(ValueError): self.validate()
                self.artifact=original
        for artifacts in [[], [self.artifact,self.artifact]]:
            with self.assertRaises(ValueError): stage.validate(self.run,self.jobs,artifacts,'algofly-oss/porthub')


class Bundle(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.files={}
        for asset in stage.publisher.ASSETS:
            payload=('fixture '+asset).encode()
            self.files.update({asset:payload,asset+'.version':b'1.9.0\n',
                asset+'.sha256':(hashlib.sha256(payload).hexdigest()+'  '+asset+'\n').encode()})

    def bundle(self, entries=None):
        archive=self.root/'bundle.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(archive,'w') as target:
                for name,value in entries if entries is not None else self.files.items(): target.writestr(name,value)
        proof=dict(size_in_bytes=archive.stat().st_size,digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest())
        return archive,proof

    def test_exact_bundle_is_verified_without_executing_foreign_binaries(self):
        archive,proof=self.bundle()
        assets=stage.extract(archive,proof,self.root/'assets','1.9.0')
        self.assertEqual(set(assets),set(self.files))
        self.assertEqual((self.root/'assets').stat().st_mode&0o777,0o700)

    def test_zip_digest_or_size_mismatch_creates_no_staging_directory(self):
        archive,proof=self.bundle()
        for bad in [dict(proof,digest='sha256:'+'0'*64),dict(proof,size_in_bytes=proof['size_in_bytes']+1)]:
            with self.assertRaises(ValueError): stage.extract(archive,bad,self.root/'assets','1.9.0')
        self.assertFalse((self.root/'assets').exists())

    def test_extra_traversal_duplicate_or_missing_entries_are_rejected(self):
        entries=list(self.files.items())
        for invalid in [entries+[('../escape',b'x')],entries+[entries[0]],entries[:-1],entries[:-1]+[('../escape',b'x')]]:
            archive,proof=self.bundle(invalid)
            with self.assertRaises(ValueError): stage.extract(archive,proof,self.root/'assets','1.9.0')
        self.assertFalse((self.root/'escape').exists())

    def test_corrupt_platform_hash_and_mixed_versions_are_rejected(self):
        for suffix,value in [('.sha256',b'bad hash'),('.version',b'2.0.0\n')]:
            entries=dict(self.files); entries[next(iter(stage.publisher.ASSETS))+suffix]=value
            archive,proof=self.bundle(entries.items())
            with self.assertRaises((ValueError,RuntimeError)):
                stage.extract(archive,proof,self.root/('bad'+suffix),'1.9.0')

    def test_symlinks_and_oversized_metadata_are_rejected_before_extraction(self):
        entries=list(self.files.items())
        link=zipfile.ZipInfo(entries[0][0]);link.create_system=3
        link.external_attr=(stat.S_IFLNK|0o777)<<16
        archive,proof=self.bundle([(link,b'target')]+entries[1:])
        with self.assertRaises(ValueError): stage.extract(archive,proof,self.root/'linked','1.9.0')
        entries=dict(self.files)
        entries[next(iter(stage.publisher.ASSETS))+'.version']=b'x'*513
        archive,proof=self.bundle(entries.items())
        with self.assertRaises(ValueError): stage.extract(archive,proof,self.root/'oversized','1.9.0')
        self.assertFalse((self.root/'linked').exists())
        self.assertFalse((self.root/'oversized').exists())

    def test_existing_destination_is_never_overwritten(self):
        archive,proof=self.bundle(); destination=self.root/'assets';destination.mkdir();(destination/'keep').write_text('unchanged')
        with self.assertRaises(ValueError): stage.extract(archive,proof,destination,'1.9.0')
        self.assertEqual((destination/'keep').read_text(),'unchanged')


if __name__ == '__main__':
    unittest.main()
