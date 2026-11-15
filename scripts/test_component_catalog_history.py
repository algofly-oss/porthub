import copy
import hashlib
import json
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('history',Path(__file__).with_name('component-catalog-history.py'))
history=importlib.util.module_from_spec(spec);spec.loader.exec_module(history)

def catalog(version='0.1.4',release='1.11.40'):
    return {'schema_version':1,'repository':'algofly-oss/porthub','release':release,'artifacts':[{'component':'stats','version':version,'target':'x86_64-unknown-linux-gnu','core':'>=1.11.0, <2.0.0','protocols':[1],'source_revision':'a'*40,'build_inputs':'b'*64,'executable':{'size':10,'sha256':'c'*64},'release':release,'archive':{'size':20,'sha256':'d'*64}}]}
class History(unittest.TestCase):
    def test_all_published_tool_identity_fields_are_immutable(self):
        old=catalog();new=catalog(release='1.11.46')
        for field,value in [('core','>=1.12.0'),('protocols',[2]),('source_revision','f'*40),('build_inputs','e'*64),('executable',{'size':11,'sha256':'c'*64})]:
            bad=copy.deepcopy(new);bad['artifacts'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):history.validate_successor(bad,old)
        history.validate_successor(new,old)
    def test_fresh_versions_do_not_require_retaining_unavailable_old_archives(self):
        history.validate_successor(catalog('0.1.5','1.11.46'),catalog())
        new=catalog(release='1.11.46');new['artifacts'][0]['archive']['sha256']='e'*64
        history.validate_successor(new,catalog())
    def test_release_identity_downgrade_and_duplicate_versions_fail_closed(self):
        old=catalog();bad=copy.deepcopy(old);bad['artifacts'][0]['build_inputs']='f'*64
        with self.assertRaises(ValueError):history.validate_successor(bad,old)
        with self.assertRaises(ValueError):history.validate_successor(catalog(release='1.11.39'),old)
        old['artifacts']*=2
        with self.assertRaises(ValueError):history.catalog(old)
    def test_acquisition_receipt_detects_artifact_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'catalog.json';path.write_text(json.dumps(catalog()))
            receipt={'schema_version':1,'gateway':'https://trusted.invalid','release':'1.11.40','sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            path.with_name('catalog.json.provenance.json').write_text(json.dumps(receipt))
            self.assertEqual(history.read_trusted(path)['release'],'1.11.40')
            path.write_text(json.dumps(catalog('0.1.99')))
            with self.assertRaises(ValueError):history.read_trusted(path)

    def test_reuse_provenance_matches_all_immutable_fields(self):
        old=catalog();row=old['artifacts'][0]
        receipt={'tool':'stats','version':'0.1.4','target':'x86_64-unknown-linux-musl','source_revision':row['source_revision'],'fingerprint':row['build_inputs'],'binary':dict(row['executable'],name='porthub-stats'),'build':{'recipe':{'core':row['core'],'protocols':row['protocols']}}}
        self.assertTrue(history.reuse_safe(old,receipt))
        receipt['source_revision']='e'*40
        self.assertFalse(history.reuse_safe(old,receipt))

    def test_no_history_credentials_http_or_redirects(self):
        with patch.object(history,'build_opener') as opener:
            for base in ['http://gateway.invalid','https://user:secret@gateway.invalid','https://gateway.invalid/?token=secret']:
                with self.assertRaises(ValueError):history.fetch(base)
            opener.assert_not_called()
        with self.assertRaises(ValueError):history.NoRedirect().redirect_request(None,None,None,None,None,None)
if __name__=='__main__':unittest.main()
