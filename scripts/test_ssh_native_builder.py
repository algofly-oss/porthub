#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

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
            state=Path(raw)/'state';state.write_text('{}')
            with self.assertRaises(ValueError): adapter.build({},Path(raw),'a'*40,state,60)

    def test_remote_script_parses_and_no_publication(self):
        compile(adapter.REMOTE,'remote.py','exec')
        self.assertIn("'--tool','core'",adapter.REMOTE)
        self.assertNotIn('git push',adapter.REMOTE)
        self.assertIn("shutil.rmtree(stage/'target'",adapter.REMOTE)

if __name__=='__main__': unittest.main()
