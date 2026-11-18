#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os
import sys
from unittest.mock import patch,Mock

HERE=Path(__file__).parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

v=load('native-core-validation');lane=load('local-core-lane');selection=load('select-agent-platforms')
SOURCE='a'*40;TARGET='aarch64-apple-darwin'

class LocalCoreTests(unittest.TestCase):
    def fixture(self,root):
        (root/'.github/workflows').mkdir(parents=True);(root/'scripts').mkdir()
        (root/'.github/workflows/agent-platforms.yml').write_text('workflow')
        (root/'scripts/native-core-validation.py').write_text('runner')
        binary=root/'porthub';binary.write_bytes(b'actual-fixture-bytes')
        receipt={'schema_version':1,'mode':'core_only','source_revision':SOURCE,'target':TARGET,'plan_sha256':v.plan_hash(root,TARGET),'system':'Darwin','machine':'arm64','kernel':'27','status':'passed','binary_sha256':v.sha(binary),'steps':[{'name':name,'exit_code':0,'elapsed_seconds':.1} for name in ['terminal-runtime']+[row['name'] for row in v.plan(TARGET)]+['core-build','core-startup']]}
        path=root/'native-validation.json';path.write_text(json.dumps(receipt))
        return path,receipt,{('core','1.2.3'):({},binary)}

    def test_only_validated_target_removed_from_hosted_matrix(self):
        with tempfile.TemporaryDirectory() as raw:
            seen=[]
            def restore(root,source,target,depot,path): seen.append(target);return target==TARGET
            result=selection.select('all',True,Path(raw),SOURCE,'https://trusted.example',Path(raw)/'stage',restore)
            self.assertEqual([row['artifact'] for row in result['local_native']],['darwin_arm64'])
            self.assertNotIn(TARGET,[row['target'] for row in result['native']])
            self.assertEqual(len(result['native']),6)
            self.assertEqual(len(result['linux']),3)
            self.assertEqual(seen,[TARGET])

    def test_missing_or_invalid_native_proof_always_keeps_hosted(self):
        with tempfile.TemporaryDirectory() as raw:
            for restore in [lambda *args:False,Mock(side_effect=ValueError('bad native proof'))]:
                result=selection.select('darwin_arm64',True,Path(raw),SOURCE,'https://trusted.example',Path(raw)/'stage',restore)
                self.assertEqual(result['local_native'],[])
                self.assertEqual(result['native'][0]['target'],TARGET)

    def test_local_handoff_can_become_ready_before_hosted_selection(self):
        with tempfile.TemporaryDirectory() as raw:
            restore=Mock(side_effect=[False,True])
            with patch('time.sleep'),patch('time.monotonic',side_effect=[0,1,2]):
                result=selection.select('darwin_arm64',True,Path(raw),SOURCE,'https://trusted.example',Path(raw)/'stage',restore,30)
            self.assertEqual(result['native'],[])
            self.assertEqual(result['local_native'][0]['target'],TARGET)
            self.assertEqual(restore.call_count,2)

    def test_full_release_never_bypasses_native_on_core_proof(self):
        forbidden=Mock(side_effect=AssertionError('must not attempt local core bypass'))
        result=selection.select('darwin_arm64',False,restore_fn=forbidden)
        self.assertEqual(len(result['native']),1);self.assertEqual(result['local_native'],[]);forbidden.assert_not_called()

    def test_receipt_requires_all_steps_exact_source_and_current_plan(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);path,receipt,builds=self.fixture(root)
            hybrid=Mock();hybrid.verify.return_value=builds
            with patch.object(v,'load',return_value=hybrid):
                self.assertEqual(v.verify(root,root,TARGET,SOURCE)['status'],'passed')
                for field,value in [('source_revision','b'*40),('mode','full_release'),('plan_sha256','0'*64),('status','failed'),('binary_sha256','0'*64)]:
                    changed=dict(receipt,**{field:value});path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):v.verify(root,root,TARGET,SOURCE)
                for steps in [receipt['steps'][:-1],receipt['steps'][::-1],receipt['steps']+[receipt['steps'][0]]]:
                    path.write_text(json.dumps(dict(receipt,steps=steps)))
                    with self.assertRaises(ValueError):v.verify(root,root,TARGET,SOURCE)
                path.write_text(json.dumps(receipt));(root/'.github/workflows/agent-platforms.yml').write_text('new required workflow check')
                with self.assertRaises(ValueError):v.verify(root,root,TARGET,SOURCE)

    def test_failed_or_nonfinite_step_and_wrong_binary_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);path,receipt,builds=self.fixture(root);hybrid=Mock();hybrid.verify.return_value=builds
            with patch.object(v,'load',return_value=hybrid):
                for field,value in [('exit_code',1),('exit_code',False),('elapsed_seconds',float('nan'))]:
                    changed=json.loads(json.dumps(receipt));changed['steps'][0][field]=value;path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):v.verify(root,root,TARGET,SOURCE)
                path.write_text(json.dumps(receipt));(root/'porthub').write_bytes(b'changed-after-native-check')
                with self.assertRaises(ValueError):v.verify(root,root,TARGET,SOURCE)

    def test_unvalidated_plain_build_cannot_skip_hosted(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ValueError):v.verify(Path(raw),Path(raw),TARGET,SOURCE)

    def test_restore_rejects_redirected_payload_before_download(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);h=Mock();h.https_url.side_effect=lambda value:value;h.MAX_ARCHIVE=512*1024**2
            def download(url,path,*args):path.write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'targets':{TARGET:{'sha256':'b'*64,'size':1,'url':'https://attacker.invalid/payload'}}}))
            h.download.side_effect=download
            with patch.object(lane,'load',side_effect=lambda name:h if name=='hybrid-native-build' else v):
                with self.assertRaises(ValueError):lane.restore(root,SOURCE,TARGET,'https://trusted.example',root/'output')
            self.assertEqual(h.download.call_count,1)

    def test_plan_contains_all_applicable_hosted_mac_core_checks(self):
        rows=v.plan(TARGET);commands=[' '.join(row['argv']) for row in rows]
        self.assertTrue(any(all('-p '+p in cmd for p in v.PACKAGES) and '--no-run' not in cmd for cmd in commands))
        for needle in ['--features ssh','--test native_direct','--lib direct::viewer','--lib terminal_','--lib terminal_policy','--test launchd_live','native_terminal_join_is_opt_in']:
            self.assertTrue(any(needle in cmd for cmd in commands),needle)
        launch=next(row for row in rows if row['name']=='native-launchd')
        self.assertEqual(launch['env'],{'PORTHUB_TEST_LAUNCHD':'1'})

    def test_owned_validation_timeout_reaps_its_process(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);log=root/'bounded.log'
            with self.assertRaises(TimeoutError):
                v.execute([sys.executable,'-c','import os,time; print(os.getpid(),flush=True); time.sleep(30)'],root,os.environ.copy(),log,.1)
            pid=int(log.read_text().strip())
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_launchd_cleanup_only_new_exact_owned_program(self):
        with patch.object(v,'launchd_labels',side_effect=[{'existing','porthub-owned','porthub-foreign'},{'existing','porthub-foreign'}]),patch.object(v.subprocess,'run') as run:
            run.side_effect=[Mock(returncode=0,stdout='program = /owned/nonce/target/porthub'),Mock(returncode=0)]
            # Use one new label to avoid unordered set iteration in this case.
            with patch.object(v,'launchd_labels',side_effect=[{'existing','porthub-owned'},{'existing'}]):v.cleanup_launchd({'existing'},Path('/owned/nonce/target/porthub'))
            self.assertIn('bootout',run.call_args_list[-1].args[0])

if __name__=='__main__':unittest.main()
