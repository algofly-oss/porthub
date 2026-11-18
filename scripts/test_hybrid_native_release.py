import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

spec=importlib.util.spec_from_file_location('release',Path(__file__).with_name('hybrid-native-release.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
SOURCE='a'*40
REPOSITORY='algofly-oss/porthub'


class ReleaseTests(unittest.TestCase):
    def run_metadata(self,**changes):
        result={'id':123,'head_sha':'b'*40,'head_branch':'main','event':'push','status':'in_progress',
                'path':'.github/workflows/continuous-release.yml','head_repository':{'full_name':REPOSITORY}}
        result.update(changes);return result

    def test_idle_is_one_request_and_no_build(self):
        for runs in [[],[self.run_metadata(status='completed')]]:
            with patch.object(r,'gh',return_value={'workflow_runs':runs}) as gh:
                self.assertEqual(list(r.requests(REPOSITORY,'main')),[])
                gh.assert_called_once()

    def test_untrusted_run_never_reads_artifact_or_credentials(self):
        for changes in [{'event':'pull_request'},{'head_branch':'untrusted'},{'head_repository':{'full_name':'evil/fork'}},{'path':'arbitrary.yml'}]:
            with patch.object(r,'gh',return_value={'workflow_runs':[self.run_metadata(**changes)]}) as gh:
                self.assertEqual(list(r.requests(REPOSITORY,'main')),[]);gh.assert_called_once()

    def test_active_main_prepared_request_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);config=root/'builders.json';config.write_text(json.dumps({'builders':[{'target':'native'}]}));config.chmod(0o600)
            state=root/'state';controller=Mock()
            controller.control.return_value={'targets':{'native':{'status':'local_verified'}}}
            def git(repo,*args):
                if args[:3]==('remote','get-url','origin'):return 'git@github.com:'+REPOSITORY+'.git'
                return ''
            request={'schema_version':1,'source_revision':SOURCE}
            with patch.object(r,'requests',return_value=iter([({},self.run_metadata())])),patch.object(r,'read_request',return_value=request),patch.object(r,'git',side_effect=git) as commands,patch.object(r,'load_controller',return_value=controller):
                result=r.run_once(root,REPOSITORY,'main',config,state)
            self.assertEqual(result['status'],'processed')
            self.assertTrue(json.loads((state/'checkpoint.json').read_text())['sources'][SOURCE]['complete'])
            self.assertTrue(any(call.args[1:]==('merge-base','--is-ancestor',SOURCE,'FETCH_HEAD') for call in commands.call_args_list))
            with patch.object(r,'requests',return_value=iter([({},self.run_metadata())])),patch.object(r,'read_request',return_value=request),patch.object(r,'git') as commands,patch.object(r,'load_controller') as loader:
                self.assertEqual(r.run_once(root,REPOSITORY,'main',config,state)['status'],'no_eligible_prepared_release')
                commands.assert_not_called();loader.assert_not_called()

    def test_unavailable_builder_retries_with_bounded_backoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root/'config'
            config.write_text('{"builders":[{"target":"windows"}]}')
            config.chmod(0o600)
            controller = Mock()
            controller.control.return_value = {'targets': {'windows': {'status': 'github_fallback'}}}
            state = root/'state'
            with patch.object(r, 'requests', return_value=[({}, self.run_metadata())]), \
                 patch.object(r, 'read_request', return_value={'source_revision': SOURCE}), \
                 patch.object(r, 'git', return_value='https://github.com/'+REPOSITORY), \
                 patch.object(r, 'load_controller', return_value=controller), patch.object(r.time, 'time') as now:
                for timestamp, delay in [(1000, 60), (1060, 120), (1180, 240), (1420, 300), (1720, 300)]:
                    now.return_value = timestamp
                    self.assertEqual(r.run_once(root, REPOSITORY, 'main', config, state)['status'], 'processed')
                    entry = json.loads((state/'checkpoint.json').read_text())['sources'][SOURCE]
                    self.assertEqual(entry['retry_delay_seconds'], delay)
                    now.return_value = timestamp + delay - 1
                    self.assertEqual(r.run_once(root, REPOSITORY, 'main', config, state)['status'], 'no_eligible_prepared_release')
                self.assertEqual(controller.control.call_count, 5)

    def test_native_core_request_uses_explicit_validation_command_and_new_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);config=root/'builders.json'
            config.write_text(json.dumps({'builders':[{'target':'native','build':['plain-build'],'validation_build':['validated-build']}]}));config.chmod(0o600)
            state=root/'state';state.mkdir(mode=0o700)
            (state/'checkpoint.json').write_text(json.dumps({'schema_version':1,'sources':{SOURCE:{'complete':True,'run_id':122}}}))
            controller=Mock();controller.control.return_value={'targets':{'native':{'status':'local_verified'}}}
            request={'schema_version':1,'source_revision':SOURCE,'purpose':'core_only_validation'}
            def git(repo,*args):
                if args[:3]==('remote','get-url','origin'):return 'git@github.com:'+REPOSITORY+'.git'
                return ''
            metadata=self.run_metadata(path='.github/workflows/agent-platforms.yml',event='workflow_dispatch')
            with patch.object(r,'requests',return_value=iter([({},metadata)])),patch.object(r,'read_request',return_value=request),patch.object(r,'git',side_effect=git),patch.object(r,'load_controller',return_value=controller):
                result=r.run_once(root,REPOSITORY,'main',config,state)
            self.assertEqual(result['status'],'processed')
            call=controller.control.call_args.args
            self.assertEqual(call[2]['builders'][0]['build'],['validated-build'])
            self.assertEqual(call[3].name,'core-validation-outputs')
            checkpoint=json.loads((state/'checkpoint.json').read_text())
            self.assertTrue(checkpoint['sources'][SOURCE]['complete'])
            self.assertTrue(checkpoint['sources'][SOURCE+':core_only_validation']['complete'])

    def test_plain_builder_is_not_silently_promoted_to_validation(self):
        original={'builders':[{'target':'a','build':['plain']},{'target':'b','validation_build':['exact','--validate-core']}]}
        selected=r.validation_config(original)
        self.assertEqual([row['target'] for row in selected['builders']],['b'])
        self.assertEqual(selected['builders'][0]['build'],['exact','--validate-core'])
        self.assertEqual(original['builders'][0]['build'],['plain'])

    def test_active_main_core_workflow_is_eligible_but_not_arbitrary_workflow(self):
        artifact={'name':'native-build-request','expired':False,'id':456,'size_in_bytes':1024,'digest':'sha256:'+'a'*64}
        for metadata in [self.run_metadata(path='.github/workflows/agent-platforms.yml',event='workflow_dispatch'),self.run_metadata()]:
            with patch.object(r,'gh',side_effect=[{'workflow_runs':[metadata]},{'artifacts':[artifact]}]) as gh:
                self.assertEqual(len(list(r.requests(REPOSITORY,'main'))),1)
                self.assertEqual(gh.call_count,2)

    def test_foreign_local_origin_stops_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);config=root/'config';config.write_text('{"builders":[]}');config.chmod(0o600)
            with patch.object(r,'requests',return_value=iter([({},self.run_metadata())])),patch.object(r,'read_request',return_value={'source_revision':SOURCE}),patch.object(r,'git',return_value='git@github.com:evil/fork.git'),patch.object(r,'load_controller') as loader,self.assertRaises(ValueError):
                r.run_once(root,REPOSITORY,'main',config,root/'state')
            loader.assert_not_called()


if __name__=='__main__':unittest.main()
