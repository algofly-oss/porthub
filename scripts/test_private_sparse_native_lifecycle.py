#!/usr/bin/env python3
"""No native/network operations. Test the actual outer's bounds and finally."""
import argparse,importlib.util,json,os,pathlib,sys,tempfile,unittest
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('native_gate',pathlib.Path(__file__).with_name('private-sparse-native-lifecycle.py'))
gate=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(gate)
class Outer(unittest.TestCase):
 def test_real_child_overflow_reaps_held_process_and_retains_bounded_metadata(self):
  with self.assertRaises(gate.CommandError) as caught:gate.run([sys.executable,'-c','import sys;sys.stdout.write("x"*100000);sys.stdout.flush()'],cap=4096,seconds=3)
  self.assertLessEqual(len(caught.exception.stdout)+len(caught.exception.stderr),4096)
 def test_real_child_timeout_is_bounded_and_does_not_rely_on_pipe_eof(self):
  import time
  start=time.monotonic()
  with self.assertRaises(gate.CommandError):gate.run([sys.executable,'-c','import time;time.sleep(30)'],cap=4096,seconds=.1)
  self.assertLess(time.monotonic()-start,3)
 def test_missing_exact_compiled_test_rejects_before_any_snapshot(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);binary=root/'tests';binary.write_bytes(b'not executed')
   args=argparse.Namespace(contract='linux',purpose=gate.PURPOSE,build_json='unused',outer_timeout_seconds=90,log_cap_bytes=4096,offline_mock_only=True)
   with patch.object(gate,'source_guard',return_value=root),patch.object(gate.platform,'system',return_value='Linux'),patch.object(gate.os,'geteuid',return_value=0,create=True),patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','PORTHUB_NATIVE_SOURCE_REVISION':'d'*40,'PORTHUB_NATIVE_CONTROLLER_REVISION':'e'*40}),patch.object(gate,'exact_executable',return_value=binary),patch.object(gate,'run',return_value='running 0 tests'),patch.object(gate,'unix_snapshot') as snapshot:
    with self.assertRaisesRegex(RuntimeError,'native test missing'):gate.execute(args)
    snapshot.assert_not_called()
 def scenario(self,fail,changed=False):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);binary=root/'tests';binary.write_bytes(b'not executed');test=gate.TESTS['linux'][0]
   for name in gate.INPUTS:
    source=root/name;source.parent.mkdir(parents=True,exist_ok=True);source.write_bytes(b'OFFLINE MOCK INPUT ONLY')
   args=argparse.Namespace(contract='linux',purpose=gate.PURPOSE,build_json='unused',outer_timeout_seconds=90,log_cap_bytes=4096,offline_mock_only=True)
   def run(argv,**kwargs):
    if argv[0]=='git':return 'd'*40
    if '--list' in argv:return test+': test\n'
    self.assertIn('--exact',argv);self.assertIn('--ignored',argv)
    kwargs['on_started'](None)
    if fail:raise gate.CommandError('injected native failure',b'bounded native diagnosis',b'failure')
    return 'running 1 test\n'+test+' ... ok\n1 passed; 0 failed\n'
   with patch.object(gate,'source_guard',return_value=root),patch.object(gate.platform,'system',return_value='Linux'),patch.object(gate.os,'geteuid',return_value=0,create=True),patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','PORTHUB_NATIVE_SOURCE_REVISION':'d'*40,'PORTHUB_NATIVE_CONTROLLER_REVISION':'e'*40}),patch.object(gate,'exact_executable',return_value=binary),patch.object(gate,'run',side_effect=run),patch.object(gate,'unix_snapshot',side_effect=([{'foreign':'stable'}]+[{'foreign':'changed'}]*200 if changed else [{'foreign':'stable'},{'foreign':'stable'}])):
    if fail or changed:
     with self.assertRaisesRegex(RuntimeError,'injected native failure' if fail else 'independent cleanup'):gate.execute(args)
    else:gate.execute(args)
   receipt=json.loads((root/'private-sparse-native-receipts/linux-receipt.json').read_text())
   self.assertTrue(receipt['offline_mock_only']);self.assertEqual(receipt['source'],'d'*40);self.assertEqual(receipt['controller_revision'],'e'*40)
   if changed:
    self.assertFalse(receipt['cleanup_complete']);self.assertTrue(pathlib.Path(receipt['stage']).is_dir())
    self.assertEqual(pathlib.Path(receipt['stage']).name,'native-lifecycle-'+receipt['nonce'])
    import shutil;shutil.rmtree(receipt['stage'])
   else:
    self.assertTrue(receipt['cleanup_complete']);self.assertTrue(receipt['stage_absent']);self.assertFalse(pathlib.Path(receipt['stage']).exists())
   if fail:self.assertEqual((root/'private-sparse-native-receipts/linux-failed-child.stdout.log').read_bytes(),b'bounded native diagnosis')
 def test_actual_whole_outer_success_and_stage_cleanup_offline(self):self.scenario(False)
 def test_actual_whole_outer_failure_still_snapshots_cleans_and_saves_metadata_offline(self):self.scenario(True)
 def test_changed_foreign_baseline_fails_and_preserves_recovery_journals(self):self.scenario(False,True)
 def test_actual_windows_run_controlflow_binds_job_before_releasing_start_gate(self):
  import io
  order=[]
  class Child:
   stdout=io.BytesIO(b'bounded');stderr=io.BytesIO();returncode=0
   def poll(self):return 0
   def wait(self,timeout):return 0
  with patch.object(gate.os,'name','nt'),patch.object(gate.subprocess,'CREATE_NO_WINDOW',0,create=True),patch.object(gate.subprocess,'Popen',return_value=Child()),patch.object(gate,'windows_job',side_effect=lambda child:(order.append('job_bound') or (lambda:order.append('job_closed')))):
   gate.run(['not-executed'],on_started=lambda child:order.append('gate_released'))
  self.assertEqual(order,['job_bound','gate_released','job_closed'])
 def netns_scenario(self,failed):
  import types,time
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);receipts=root/'receipts';receipts.mkdir();binary=root/'binary';binary.write_bytes(b'OFFLINE')
   image='sha256:'+'a'*64;state={'image':False};module=types.SimpleNamespace(command=lambda *a,**k:None)
   def native(args):
    stage=gate.netns_stage(args.nonce);stage.mkdir(mode=0o700);state['stage']=stage
    (stage/'receipt.json').write_text(json.dumps({'offline_mock_only':True,'container_absent':True,'rootfs_removed':True}))
    (stage/'stdout.log').write_text('OFFLINE bounded native metadata')
    if failed:raise RuntimeError('preserved native failure')
   module.run=native
   loader=types.SimpleNamespace(exec_module=lambda module:None)
   def run(argv,**kwargs):
    if argv[0]=='git':return 'd'*40
    if argv[:2]==['docker','import']:
     state['nonce']=argv[argv.index('--change')+1].split('=')[1];state['image']=True;return image
    if argv[:3]==['docker','image','inspect']:return json.dumps([{'Id':image,'RepoTags':['porthub-sparse-native:'+state['nonce']],'Config':{'Labels':{'porthub.sparse.native.nonce':state['nonce']}}}])
    if argv[:2]==['docker','ps']:return ''
    if argv[:3]==['docker','image','rm']:state['image']=False;return ''
    if argv[:3]==['docker','image','ls']:return image if state['image'] else ''
    raise AssertionError('unexpected Docker mock command '+str(argv))
   prior=gate.COMMAND_DEADLINE;gate.COMMAND_DEADLINE=time.monotonic()+90
   try:
    with patch.object(gate.importlib.util,'spec_from_file_location',return_value=types.SimpleNamespace(loader=loader)),patch.object(gate.importlib.util,'module_from_spec',return_value=module),patch.object(gate,'run',side_effect=run),patch.object(gate,'netns_stage',side_effect=lambda nonce:root/('porthub-sparse-native-'+nonce)):
     if failed:
      with self.assertRaisesRegex(RuntimeError,'preserved native failure'):gate.netns_gate(root,binary,receipts,30,time.monotonic()+100)
     else:gate.netns_gate(root,binary,receipts,30,time.monotonic()+100)
   finally:gate.COMMAND_DEADLINE=prior
   self.assertFalse(state['image']);self.assertFalse(state['stage'].exists())
   proof=json.loads((receipts/'linux-netns-image-cleanup.json').read_text());self.assertTrue(proof['image_absent']);self.assertTrue(proof['container_absent'])
   self.assertTrue(json.loads((receipts/'linux-netns-receipt.json').read_text())['offline_mock_only'])
 def test_netns_actual_image_controller_success_removes_only_exact_owned_image_offline(self):self.netns_scenario(False)
 def test_netns_actual_image_controller_preserves_native_failure_and_cleans_offline(self):self.netns_scenario(True)
 def test_controller_checkout_cannot_substitute_for_exact_reviewed_payload(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);binary=root/'tests';binary.write_bytes(b'not executed');test=gate.TESTS['linux'][0]
   args=argparse.Namespace(contract='linux',purpose=gate.PURPOSE,build_json='unused',outer_timeout_seconds=90,log_cap_bytes=4096,offline_mock_only=True)
   def run(argv,**kwargs):return test+': test\n' if '--list' in argv else 'd'*40
   with patch.object(gate,'source_guard',return_value=root),patch.object(gate.platform,'system',return_value='Linux'),patch.object(gate.os,'geteuid',return_value=0,create=True),patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','PORTHUB_NATIVE_SOURCE_REVISION':'f'*40,'PORTHUB_NATIVE_CONTROLLER_REVISION':'d'*40}),patch.object(gate,'exact_executable',return_value=binary),patch.object(gate,'run',side_effect=run),patch.object(gate,'unix_snapshot') as snapshot:
    with self.assertRaisesRegex(RuntimeError,'exact reviewed revision'):gate.execute(args)
    snapshot.assert_not_called()
   self.assertFalse((root/'private-sparse-native-receipts').exists())
 def test_actual_windows_acl_helper_uses_separate_native_operations(self):
  path=r'C:\ProgramData\PortHub\native-lifecycle-owned\profile.json';calls=[]
  with patch.object(gate,'run',side_effect=lambda argv,**kwargs:calls.append(argv)):
   gate.secure_windows_paths([path])
  self.assertEqual(calls,[['icacls',path,'/inheritance:r','/grant:r','*S-1-5-18:(F)','*S-1-5-32-544:(F)'],['icacls',path,'/setowner','*S-1-5-32-544']])
  self.assertTrue(all('"' not in token for call in calls for token in call))
 def test_non_hosted_context_rejects_before_os_snapshot(self):
  args=argparse.Namespace(contract='linux',purpose=gate.PURPOSE)
  with patch.object(gate,'source_guard'),patch.object(gate.platform,'system',return_value='Linux'),patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),patch.object(gate,'unix_snapshot') as snapshot:
   with self.assertRaisesRegex(RuntimeError,'disposable hosted'):gate.execute(args)
   snapshot.assert_not_called()
if __name__=='__main__':unittest.main()
