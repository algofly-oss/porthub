import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import zipfile

spec = importlib.util.spec_from_file_location('hybrid', Path(__file__).with_name('hybrid-native-build.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
SOURCE = 'a'*40
TARGET = 'aarch64-apple-darwin'


class HybridTests(unittest.TestCase):
    def fixture(self, root):
        files = root/'original'
        files.mkdir()
        (files/'index.json').write_text('{}')
        (files/'porthub').write_bytes(b'fake-native-artifact')
        archive = root/'input.zip'
        h.pack(files,archive)
        return archive

    def config(self):
        return {'schema_version':1, 'depot':{'base_url':'https://trusted.example/builds','upload':['upload','{file}','{key}']},
                'builders':[{'target':TARGET,'probe':['probe'],'build':['build'],'fetch':['fetch','{archive}']}]}

    def controller(self, phase=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = self.fixture(root)
        calls = []
        def command(argv,values,timeout):
            calls.append(argv[0])
            if argv[0] == phase:
                raise subprocess.TimeoutExpired(argv,timeout)
            if argv[0]=='fetch':
                Path(values['archive']).write_bytes(source.read_bytes())
        planner = Mock()
        with patch.object(h,'load',return_value=planner), patch.object(h,'command',side_effect=command), patch.object(h,'verify'):
            result = h.control(root,SOURCE,self.config(),root/'output')
        return root, result, calls, command, planner

    def test_unavailable_falls_back_without_build(self):
        _, result, calls, _, _ = self.controller('probe')
        self.assertEqual(result['targets'][TARGET]['failed_phase'],'probe')
        self.assertNotIn('build',calls)

    def test_disappearing_builder_or_build_failure_falls_back(self):
        for phase in ['build','fetch','upload']:
            _,result,_,_,_ = self.controller(phase)
            self.assertEqual(result['targets'][TARGET]['status'],'github_fallback')

    def test_success_and_resume_never_duplicate_build(self):
        root,result,calls,command,planner = self.controller()
        self.assertEqual(result['targets'][TARGET]['status'],'local_verified')
        with patch.object(h,'load',return_value=planner), patch.object(h,'command',side_effect=command), patch.object(h,'verify'):
            again=h.control(root,SOURCE,self.config(),root/'output')
        self.assertEqual(again['targets'][TARGET]['status'],'local_verified_reused')
        self.assertEqual(calls.count('build'),1)

    def test_interrupted_first_probe_can_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root/'output'
            output.mkdir()
            with patch.object(h, 'load'), patch.object(h, 'command', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    h.control(root, SOURCE, self.config(), output)
            self.assertEqual(json.loads((output/'manifest.json').read_text())['source_revision'], SOURCE)
            with patch.object(h, 'load'), patch.object(h, 'command', side_effect=OSError):
                result = h.control(root, SOURCE, self.config(), output)
            self.assertEqual(result['targets'][TARGET]['failed_phase'], 'probe')

    def test_fast_builder_publishes_before_slow_builder_finishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=self.fixture(root);published=threading.Event()
            config=self.config();slow='x86_64-apple-darwin'
            config['builders'].append(dict(config['builders'][0],target=slow))
            def command(argv,values,timeout):
                if argv[0]=='build' and values['target']==slow:
                    self.assertTrue(published.wait(2),'slow build blocked fast publication')
                if argv[0]=='fetch':Path(values['archive']).write_bytes(source.read_bytes())
                if argv[0]=='upload' and values['key'].endswith('manifest.json'):
                    manifest=json.loads(Path(values['file']).read_text())
                    if TARGET in manifest['targets']:published.set()
            with patch.object(h,'load'),patch.object(h,'command',side_effect=command),patch.object(h,'verify'):
                result=h.control(root,SOURCE,config,root/'output')
            self.assertTrue(published.is_set())
            self.assertTrue(all(row['status']=='local_verified' for row in result['targets'].values()))

    def test_minimum_source_rejects_history_and_accepts_equal_or_newer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            subprocess.run(['git','init','--quiet',str(root)],check=True)
            def git(*args):
                return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
            git('config','user.name','Owned Fixture');git('config','user.email','fixture@example.invalid')
            commits=[]
            for value in ['old','minimum','new']:
                (root/'source').write_text(value);git('add','source');git('commit','--quiet','-m',value);commits.append(git('rev-parse','HEAD'))
            self.assertFalse(h.source_supported(root,commits[1],commits[0]))
            self.assertTrue(h.source_supported(root,commits[1],commits[1]))
            self.assertTrue(h.source_supported(root,commits[1],commits[2]))
            self.assertFalse(h.source_supported(root,'f'*40,commits[2]))
            self.assertTrue(h.source_supported(root,None,commits[0]))

    def test_incompatible_builder_never_probes_builds_fetches_or_reuses(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);config=self.config();config['builders'][0]['minimum_source_revision']='b'*40
        with patch.object(h,'load'),patch.object(h,'source_supported',return_value=False),patch.object(h,'command') as command:
            result=h.control(root,SOURCE,config,root/'outputs')
        self.assertEqual(result['targets'][TARGET],{'status':'github_fallback','failed_phase':'source_compatibility'})
        self.assertFalse(any(call.args[0][0] in ('probe','build','fetch') for call in command.call_args_list))

    def test_restoration_hash_permissions_and_partial_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); archive=self.fixture(root)
            manifest={'schema_version':1,'source_revision':SOURCE,'targets':{TARGET:{'url':'https://trusted.example/'+SOURCE+'/'+TARGET+'/'+h.sha(archive)+'.zip','size':archive.stat().st_size,'sha256':h.sha(archive)}}}
            def download(url,path,maximum,deadline):
                path.write_bytes(json.dumps(manifest).encode() if url.endswith('manifest.json') else archive.read_bytes())
            with patch.object(h,'download',side_effect=download), patch.object(h,'verify') as verify:
                self.assertTrue(h.restore(root,SOURCE,TARGET,'https://trusted.example/'+SOURCE+'/manifest.json',root/'restored',trusted_depot='https://trusted.example'))
                verify.assert_called_once()
            self.assertTrue((root/'restored/porthub').stat().st_mode & 0o111)
            # Archive corruption never installs a partially trusted output.
            manifest['targets'][TARGET]['sha256']='0'*64
            with patch.object(h,'download',side_effect=download), self.assertRaises(ValueError):
                h.restore(root,SOURCE,TARGET,'https://trusted.example/'+SOURCE+'/manifest.json',root/'bad',trusted_depot='https://trusted.example')
            self.assertFalse((root/'bad').exists())

    def test_stale_missing_and_unavailable_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.assertFalse(h.restore(root,SOURCE,TARGET,'',root/'out',trusted_depot='https://trusted.example'))
            for source in ['b'*40,SOURCE]:
                def download(url,path,maximum,deadline):
                    path.write_text(json.dumps({'schema_version':1,'source_revision':source,'targets':{}}))
                with patch.object(h,'download',side_effect=download):
                    if source != SOURCE:
                        with self.assertRaises(ValueError):
                            h.restore(root,SOURCE,TARGET,'https://trusted.example/'+SOURCE+'/manifest.json',root/'out',trusted_depot='https://trusted.example')
                    else:
                        self.assertFalse(h.restore(root,SOURCE,TARGET,'https://trusted.example/'+SOURCE+'/manifest.json',root/'out',trusted_depot='https://trusted.example'))

    def test_escaping_archives_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name in ['../escape','/absolute','C:/escape','a\\b']:
                archive=root/'bad.zip'
                with zipfile.ZipFile(archive,'w') as stream:
                    stream.writestr(name,b'bad')
                with self.assertRaises(ValueError):
                    h.unpack(archive,root/'out')

    def test_workflow_preserves_native_gates_and_fallback(self):
        workflow=Path(__file__).resolve().parents[1]/'.github/workflows/agent-platforms.yml'
        source=workflow.read_text()
        self.assertEqual(source.count('hybrid-native-build.py restore'),2)
        self.assertEqual(source.count('previous=(--previous local-component-builds)'),2)
        self.assertIn('vars.PORTHUB_TRUSTED_NATIVE_DEPOT',source)
        self.assertIn('Verify packaged native core startup',source)
        self.assertIn('Test native macOS service lifecycle',source)
        self.assertNotIn('runs-on: self-hosted',source)

    def test_untrusted_endpoint_override_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(h,'download') as download:
            with self.assertRaises(ValueError):
                h.restore(Path(temporary),SOURCE,TARGET,'https://evil.example/'+SOURCE+'/manifest.json',Path(temporary)/'out',trusted_depot='https://trusted.example')
            download.assert_not_called()

    def test_partial_archive_reuses_core_without_requiring_helpers(self):
        builder = Mock()
        builder.planner.read_recipes.return_value = {'core':{},'terminal':{}}
        builder.previous_builds.return_value = {('core','1.2.3'):({'source_revision':SOURCE},Path('porthub'))}
        builder.planner.plan.return_value = {'action':'reuse'}
        with patch.object(h,'load',return_value=builder):
            self.assertEqual(len(h.verify(Path('.'),Path('builds'),TARGET,SOURCE)),1)
        builder.planner.plan.return_value = {'action':'build'}
        with patch.object(h,'load',return_value=builder), self.assertRaises(ValueError):
            h.verify(Path('.'),Path('builds'),TARGET,SOURCE)

    def test_source_mismatch_rejected_even_with_valid_binary(self):
        builder = Mock()
        builder.planner.read_recipes.return_value = {'core':{}}
        builder.previous_builds.return_value = {('core','1.2.3'):({'source_revision':'b'*40},Path('porthub'))}
        with patch.object(h,'load',return_value=builder), self.assertRaises(ValueError):
            h.verify(Path('.'),Path('builds'),TARGET,SOURCE)

    def test_worker_timeout_reaps_only_owned_build_tree(self):
        process = Mock(pid=123456)
        process.wait.side_effect = [subprocess.TimeoutExpired(['owned'],1),0]
        with tempfile.TemporaryDirectory() as temporary, patch.object(h,'load') as loader, patch.object(h.subprocess,'Popen',return_value=process) as launch, patch.object(h.os,'killpg') as kill:
            loader.return_value.native_target.return_value = TARGET
            output=Path(temporary)/'artifact.zip'
            with self.assertRaises(subprocess.TimeoutExpired):
                h.worker(Path(temporary),SOURCE,output,timeout=1)
            self.assertFalse(output.exists())
            if h.os.name != 'nt': kill.assert_called_once_with(123456,h.signal.SIGKILL)
            for variable in ('CARGO_TARGET_DIR', 'PORTHUB_TERMINAL_HELPER_CACHE_ROOT'):
                cache = Path(launch.call_args.kwargs['env'][variable])
                self.assertEqual(cache.parent.parent, output.parent)
                self.assertFalse(cache.parent.exists())
            self.assertEqual(process.wait.call_count,2)

    def test_urls_disallow_credentials_and_plain_http(self):
        for url in ['http://trusted/a','https://user:secret@trusted/a','file:///private']:
            with self.assertRaises(ValueError): h.https_url(url)


if __name__ == '__main__': unittest.main()
