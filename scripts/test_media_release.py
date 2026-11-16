import importlib.util,json,hashlib,tarfile,io,tempfile,copy
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('media_release',Path(__file__).with_name('media-release.py'));media=importlib.util.module_from_spec(spec);spec.loader.exec_module(media)
def blob(b):return {'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def fixture(root,targets=media.GNU,member_override=None,version='1.11.51'):
 artifacts=[]
 for target in sorted(targets):
  payload=b'synthetic validation bytes, not a native artifact';member='media-helper/0.1.0/porthub-media-helper'+('.exe' if 'windows' in target else '')
  stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w:gz') as tar:
   entry=tarfile.TarInfo(member_override or member);entry.mode=0o755;entry.size=len(payload);tar.addfile(entry,io.BytesIO(payload))
  archive=stream.getvalue();path=root/('porthub-media-helper-'+target+'.tar.gz');path.write_bytes(archive);path.chmod(0o600)
  artifacts.append({'version':'0.1.0','target':target,'core':'>=1.11.34','protocol':1,'source_revision':'a'*40,'build_inputs':'b'*64,'archive':blob(archive),'executable':blob(payload)})
 m={'schema_version':1,'namespace':'porthub-media','repository':'algofly-oss/porthub','release':version,'artifacts':artifacts};(root/media.ASSET).write_text(json.dumps(m));(root/media.ASSET).chmod(0o600);return m
class MediaReleaseTests(unittest.TestCase):
 def test_legacy_absence_and_exact_known_optional_targets(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);self.assertEqual(media.verify(p,'1.11.51'),set());fixture(p);calls=[]
   result=media.verify(p,'1.11.51',lambda binary,target:calls.append((binary.read_bytes(),target)))
   self.assertEqual(len(result),3);self.assertEqual({t for _,t in calls},media.GNU)
   fixture(p,media.TARGETS);self.assertEqual(len(media.verify(p,'1.11.51',lambda *_:None)),4)
   (p/'porthub-media-helper-unknown.tar.gz').write_bytes(b'x')
   with self.assertRaisesRegex(ValueError,'unknown'):media.verify(p,'1.11.51',lambda *_:None)
 def test_partial_corrupt_and_wrong_member_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);m=fixture(p);a=m['artifacts'][0];archive=p/('porthub-media-helper-'+a['target']+'.tar.gz');archive.unlink()
   with self.assertRaisesRegex(ValueError,'Incomplete'):media.verify(p,'1.11.51',lambda *_:None)
   fixture(p);archive.write_bytes(b'corrupt')
   with self.assertRaisesRegex(ValueError,'size/type'):media.verify(p,'1.11.51',lambda *_:None)
   fixture(p,member_override='../outside')
   with self.assertRaisesRegex(ValueError,'member'):media.verify(p,'1.11.51',lambda *_:None)
 def test_platform_merge_rewraps_release_without_rewriting_immutable_artifacts(self):
  spec=importlib.util.spec_from_file_location('media_merge',Path(__file__).with_name('merge-media-release.py'));merge=importlib.util.module_from_spec(spec);spec.loader.exec_module(merge)
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);inputs=[]
   for index,target in enumerate(sorted(media.GNU)):
    source=p/str(index);source.mkdir();fixture(source,{target});inputs.append(source)
   destination=p/'merged';merge.merge(inputs,destination,'1.11.52','a'*40,lambda *_:None)
   result=json.loads((destination/media.ASSET).read_text());self.assertEqual(result['release'],'1.11.52');self.assertEqual(len(result['artifacts']),2)
   with self.assertRaisesRegex(ValueError,'Duplicate'):merge.merge([inputs[0],inputs[0]],p/'bad','1.11.52',validate_executable=lambda *_:None)
   self.assertFalse((p/'bad').exists())
 def test_preparation_rejects_media_on_cores_without_feature(self):
  spec=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare-release.py'));prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);self.assertEqual(prepare.media_build_plan(root,'1.11.33',[]),{})
   helper=root/'crates/porthub-media-helper';helper.mkdir(parents=True);(helper/'Cargo.toml').write_text('[package]')
   with self.assertRaisesRegex(ValueError,'1.11.34'):prepare.media_build_plan(root,'1.11.33',media.GNU)
   plan=prepare.media_build_plan(root,'1.11.34',media.GNU);self.assertEqual(plan['media_min_core'],'1.11.34')
   with self.assertRaisesRegex(ValueError,'GNU'):prepare.media_build_plan(root,'1.11.34',['x86_64-pc-windows-msvc'])
 def test_history_rejects_reused_identity_and_downgrade(self):
  with tempfile.TemporaryDirectory() as directory:
   m=fixture(Path(directory));changed=copy.deepcopy(m);changed['release']='1.11.52';media.validate_successor(changed,m)
   changed['artifacts'][0]['executable']['sha256']='c'*64
   with self.assertRaisesRegex(ValueError,'identity'):media.validate_successor(changed,m)
   changed=copy.deepcopy(m);changed['release']='1.11.50'
   with self.assertRaisesRegex(ValueError,'downgrade'):media.validate_successor(changed,m)
   for base in ['http://host','https://user:secret@host','https://host/?query=1']:
    with self.assertRaises(ValueError):media.fetch_catalog(base)
 def test_namespace_minimum_protocol_and_executable_binding(self):
  with tempfile.TemporaryDirectory() as directory:
   p=Path(directory);m=fixture(p)
   for field,value in [('namespace','other'),('repository','attacker/repo'),('schema_version',True)]:
    changed=copy.deepcopy(m);changed[field]=value
    with self.assertRaises(ValueError):media.parse(json.dumps(changed),'1.11.51')
   for field,value in [('core','>=1.11.33'),('protocol',2),('protocol',True),('source_revision','unknown')]:
    changed=copy.deepcopy(m);changed['artifacts'][0][field]=value
    with self.assertRaises(ValueError):media.parse(json.dumps(changed),'1.11.51')
   m['artifacts'][0]['executable']['sha256']='c'*64;(p/media.ASSET).write_text(json.dumps(m))
   with self.assertRaisesRegex(ValueError,'digest'):media.verify(p,'1.11.51',lambda *_:None)
if __name__=='__main__':unittest.main()
