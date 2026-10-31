import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('publisher',Path(__file__).with_name('publish-release.py'))
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

class GitHub:
    def __init__(self,expected):
        self.expected=expected
        self.current={'tag_name':'v1.8.9','draft':False,'prerelease':False}
        self.value=None;self.target=None;self.writes=[];self.bad_upload=False;self.newer_on_upload=False
    def latest(self):return copy.deepcopy(self.current)
    def release(self,tag):return copy.deepcopy(self.value)
    def tag_commit(self,tag):return self.target
    def metadata(self,names):return [dict(name=name,state='uploaded',**self.expected[name]) for name in names]
    def create(self,tag,revision,paths):
        self.writes.append(('create',len(paths)))
        self.value={'tag_name':tag,'target_commitish':revision,'draft':True,'prerelease':False,'assets':self.metadata(self.expected)}
        if self.bad_upload:self.value['assets'].pop()
        if self.newer_on_upload:self.current=dict(self.current,tag_name='v2.0.0')
    def upload(self,tag,paths):
        self.writes.append(('upload',len(paths)))
        present={asset['name']:asset for asset in self.value['assets']}
        for path in paths:present[path.name]=self.metadata([path.name])[0]
        self.value['assets']=list(present.values())
    def promote(self,tag):
        self.writes.append(('promote',tag));self.value['draft']=False
        self.target=self.value['target_commitish'];self.current=copy.deepcopy(self.value)

class Publication(unittest.TestCase):
    def setUp(self):
        self.temp=self.enterContext(tempfile.TemporaryDirectory());self.directory=Path(self.temp)
        for name in publisher.ASSETS:
            payload=('fixture '+name).encode();(self.directory/name).write_bytes(payload)
            (self.directory/(name+'.version')).write_text('1.9.0\n')
            (self.directory/(name+'.sha256')).write_text(hashlib.sha256(payload).hexdigest()+'  '+name+'\n')
        self.expected=publisher.assets(self.directory,'1.9.0');self.github=GitHub(self.expected);self.sha='a'*40
    def publish(self,execute=True):return publisher.publish(self.github,self.directory,'1.9.0',self.sha,execute)
    def draft(self):self.github.create('v1.9.0',self.sha,[]);self.github.writes.clear()
    def test_complete_draft_is_verified_before_promotion(self):
        self.assertEqual(self.publish()['status'],'published')
        self.assertEqual(self.github.writes,[('create',30),('promote','v1.9.0')])
    def test_dry_run_never_creates_or_changes_a_release(self):
        self.assertEqual(self.publish(False)['status'],'ready');self.assertEqual(self.github.writes,[])
    def test_partial_upload_never_changes_latest(self):
        self.github.bad_upload=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.github.current['tag_name'],'v1.8.9')
        self.assertFalse(any(operation[0]=='promote' for operation in self.github.writes))
    def test_retry_uploads_only_missing_draft_assets(self):
        self.draft();self.github.value['assets']=self.github.value['assets'][:27]
        self.assertEqual(self.publish()['status'],'published')
        self.assertEqual(self.github.writes[0],('upload',3))
    def test_complete_draft_retry_does_not_upload_again(self):
        self.draft();self.assertEqual(self.publish()['status'],'published')
        self.assertEqual(self.github.writes,[('promote','v1.9.0')])
    def test_published_retry_is_idempotent_and_immutable(self):
        self.publish();self.github.writes.clear()
        self.assertEqual(self.publish()['status'],'already-published');self.assertEqual(self.github.writes,[])
        self.github.value['assets'][0]['digest']='sha256:'+'b'*64
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.github.writes,[])
    def test_mismatched_tag_or_draft_source_is_never_replaced(self):
        self.github.target='b'*40
        with self.assertRaises(ValueError):self.publish()
        self.github.target=None;self.draft();self.github.value['target_commitish']='b'*40
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.github.writes,[])
    def test_newer_latest_before_or_during_upload_cannot_be_downgraded(self):
        self.github.current['tag_name']='v2.0.0'
        self.assertEqual(self.publish()['status'],'superseded');self.assertEqual(self.github.writes,[])
        self.github.current['tag_name']='v1.8.9';self.github.newer_on_upload=True
        self.assertEqual(self.publish()['status'],'superseded')
        self.assertEqual(self.github.writes,[('create',30)])
    def test_missing_or_unexpected_local_assets_fail_without_writes(self):
        extra=self.directory/'unexpected';extra.touch()
        with self.assertRaises(ValueError):self.publish()
        extra.unlink();(self.directory/'porthub-x86').unlink()
        with self.assertRaises((ValueError,RuntimeError)):self.publish()
        self.assertEqual(self.github.writes,[])
    def test_unexpected_draft_assets_are_not_deleted_or_replaced(self):
        self.draft();self.github.value['assets'].append({'name':'user-note.txt','state':'uploaded'})
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.github.writes,[])

if __name__=='__main__':unittest.main()
