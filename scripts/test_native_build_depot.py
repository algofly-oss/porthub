import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('depot',Path(__file__).with_name('native-build-depot.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)


class DepotTests(unittest.TestCase):
    def test_exact_upload_and_hash_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);payload=b'owned archive';sha=hashlib.sha256(payload).hexdigest()
            key='a'*40+'/aarch64-apple-darwin/'+sha+'.zip'
            result=d.install(root,key,io.BytesIO(payload))
            self.assertEqual(result['sha256'],sha)
            self.assertEqual((root/key).read_bytes(),payload)
            with self.assertRaises(ValueError):d.install(root,key,io.BytesIO(b'changed'))
            self.assertEqual((root/key).read_bytes(),payload)
            self.assertEqual(list(root.glob('.incoming-*')),[])

    def test_caps_reject_without_evicting_active_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for source in ['a'*40,'b'*40]:
                data=json.dumps({'schema_version':1,'source_revision':source,'targets':{}}).encode()
                if source.startswith('a'):d.install(root,source+'/manifest.json',io.BytesIO(data),max_revisions=1)
                else:
                    with self.assertRaises(ValueError):d.install(root,source+'/manifest.json',io.BytesIO(data),max_revisions=1)
            self.assertTrue((root/('a'*40)/'manifest.json').is_file())
            with self.assertRaises(ValueError):d.install(root,'a'*40+'/manifest.json',io.BytesIO(data),max_bytes=1)

    def test_prune_requires_active_list_and_preserves_foreign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'unrelated').mkdir()
            for c in 'abc':
                source=c*40
                d.install(root,source+'/manifest.json',io.BytesIO(json.dumps({'schema_version':1,'source_revision':source}).encode()))
            with self.assertRaises(ValueError):d.prune(root,[])
            planned=d.prune(root,['a'*40],keep=1)
            self.assertFalse(planned['execute']);self.assertTrue((root/('b'*40)).exists())
            result=d.prune(root,['a'*40],keep=1,execute=True)
            self.assertEqual([row['source_revision'] for row in result['removed']],['b'*40])
            self.assertTrue((root/'unrelated').is_dir());self.assertTrue((root/('a'*40)).is_dir())

    def test_escaping_key_and_symlink_rejected(self):
        for key in ['../private','a'*40+'/../escape','a'*40+'/manifest.json/other']:
            with self.assertRaises(ValueError):d.validate_key(key)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);outside=root/'outside';outside.mkdir();(root/('a'*40)).symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError):d.install(root,'a'*40+'/manifest.json',io.BytesIO(b'{}'))


if __name__=='__main__':unittest.main()
