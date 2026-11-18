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

    def test_foreign_local_origin_stops_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);config=root/'config';config.write_text('{"builders":[]}');config.chmod(0o600)
            with patch.object(r,'requests',return_value=iter([({},self.run_metadata())])),patch.object(r,'read_request',return_value={'source_revision':SOURCE}),patch.object(r,'git',return_value='git@github.com:evil/fork.git'),patch.object(r,'load_controller') as loader,self.assertRaises(ValueError):
                r.run_once(root,REPOSITORY,'main',config,root/'state')
            loader.assert_not_called()


if __name__=='__main__':unittest.main()
