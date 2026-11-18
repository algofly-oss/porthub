#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import os
import time

spec=importlib.util.spec_from_file_location('adapter',Path(__file__).with_name('ssh-native-builder.py'))
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)

class AdapterTests(unittest.TestCase):
    def test_snapshot_is_exact_shallow_checkout_without_history(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)/'original';root.mkdir()
            def git(*args): return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL)
            git('init','-q');git('config','user.email','fixture@example.invalid');git('config','user.name','fixture')
            (root/'unchanged').write_text('original')
            git('add','.');git('commit','-qm','first')
            (root/'nested').mkdir();(root/'nested/new').write_text('current')
            git('add','.');git('commit','-qm','second')
            revision=git('rev-parse','HEAD').decode().strip()
            pack=Path(raw)/'source.pack';adapter.snapshot(root,revision,pack)
            target=Path(raw)/'target';target.mkdir()
            subprocess.run(['git','init','-q',str(target)],check=True)
            with pack.open('rb') as stream: subprocess.run(['git','-C',str(target),'unpack-objects','-q'],stdin=stream,check=True)
            (target/'.git/shallow').write_text(revision+'\n')
            subprocess.run(['git','-C',str(target),'update-ref','HEAD',revision],check=True)
            subprocess.run(['git','-C',str(target),'reset','--hard',revision],check=True,stdout=subprocess.DEVNULL)
            self.assertEqual((target/'unchanged').read_text(),'original')
            self.assertEqual((target/'nested/new').read_text(),'current')
            self.assertEqual(subprocess.check_output(['git','-C',str(target),'rev-parse','HEAD']).decode().strip(),revision)
            subprocess.run(['git','-C',str(target),'diff','--quiet','HEAD','--'],check=True)
            (root/'unchanged').write_text('dirty')
            with self.assertRaises(subprocess.CalledProcessError): adapter.snapshot(root,revision,Path(raw)/'dirty.pack')

    def test_config_rejects_host_key_policy_override(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'config.json'
            path.write_text(json.dumps({'schema_version':1,'hosts':{'a':{'platform':'posix','destination':'fixture','target':'aarch64-apple-darwin','ssh_options':['-oStrictHostKeyChecking=no']}}}))
            with self.assertRaises(ValueError): adapter.config(path,'a')

    def test_cleanup_never_accepts_nonowned_stage(self):
        with self.assertRaises(ValueError):
            adapter.cleanup({}, {'nonce':'a'*32,'stage':'/home/fixture/production'})

    def test_state_collision_precedes_any_host_call(self):
        with tempfile.TemporaryDirectory() as raw:
            state=Path(raw)/'state';state.write_text(json.dumps({'revision':'b'*40,'target':'fixture'}))
            with self.assertRaises(ValueError): adapter.build({'target':'fixture'},Path(raw),'a'*40,state,60)

    def test_verified_fetch_survives_cleanup_failure_and_retries(self):
        with tempfile.TemporaryDirectory() as raw:
            state=Path(raw)/'state';archive=Path(raw)/'components.zip'
            archive.write_bytes(b'verified archive')
            result={'revision':'a'*40,'target':'fixture','size':archive.stat().st_size,'sha256':adapter.digest(archive)}
            state.write_text(json.dumps({'revision':'a'*40,'target':'fixture','nonce':'b'*32,'stage':'/owned/.porthub-native-build-'+'b'*32,'python':'python3','result':result}))
            with mock.patch.object(adapter,'cleanup',side_effect=OSError('offline')):
                self.assertTrue(adapter.fetch({'target':'fixture'},'a'*40,state,archive)['cleanup_pending'])
            with mock.patch.object(adapter,'cleanup') as cleanup, mock.patch.object(adapter,'copy') as copy:
                self.assertFalse(adapter.fetch({'target':'fixture'},'a'*40,state,archive)['cleanup_pending'])
                cleanup.assert_called_once();copy.assert_not_called()
            archive.write_bytes(b'foreign artifact')
            with self.assertRaises(ValueError): adapter.fetch({'target':'fixture'},'a'*40,state,archive)

    def test_cleanup_rejects_live_worker_even_after_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            stage=Path(raw)/'owned';stage.mkdir();(stage/'owner').write_text('fixture')
            (stage/'active.json').write_text(json.dumps({'deadline':time.time()-1,'pid':os.getpid()}))
            with self.assertRaises(RuntimeError): exec(adapter.CLEANUP,{'STAGE':str(stage),'NONCE':'fixture'})
            self.assertTrue(stage.exists())
            (stage/'active.json').write_text(json.dumps({'deadline':time.time()+60}))
            with self.assertRaises(RuntimeError): exec(adapter.CLEANUP,{'STAGE':str(stage),'NONCE':'fixture'})
            (stage/'finished').write_text('finished')
            exec(adapter.CLEANUP,{'STAGE':str(stage),'NONCE':'fixture'})
            self.assertFalse(stage.exists())

    def test_same_revision_resume_requires_remote_digest_verification(self):
        with tempfile.TemporaryDirectory() as raw:
            state=Path(raw)/'state';state.write_text(json.dumps({'revision':'a'*40,'target':'fixture'}))
            with mock.patch.object(adapter,'remote_result',side_effect=ValueError('digest mismatch')):
                with self.assertRaises(ValueError): adapter.build({'target':'fixture'},Path(raw),'a'*40,state,60)
            with mock.patch.object(adapter,'remote_result',return_value={'sha256':'verified'}):
                self.assertTrue(adapter.build({'target':'fixture'},Path(raw),'a'*40,state,60)['resumed'])

    def test_remote_script_parses_and_no_publication(self):
        compile(adapter.REMOTE,'remote.py','exec')
        self.assertIn("'--tool','core'",adapter.REMOTE)
        self.assertNotIn('git push',adapter.REMOTE)
        self.assertIn("shutil.rmtree(stage/'target'",adapter.REMOTE)

if __name__=='__main__': unittest.main()
