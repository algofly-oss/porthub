"""Preflight must reject unsafe candidates before replacing any running role."""
import copy
import os
import signal
import json
import hashlib
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('upgrade', Path(__file__).with_name('upgrade.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)

class Upgrade(unittest.TestCase):
    def setUp(self):
        self.revision='a'*40
        self.current={}; self.images={}; self.configuration={'services':{}}
        for role in upgrade.ROLES:
            user='10001:10001' if role=='core' else '0:10001'
            self.current[role]={'Config':{'Labels':{'com.docker.compose.project':'porthub','com.docker.compose.service':role,'com.docker.compose.project.working_dir':'/old','com.docker.compose.project.config_files':'/old/docker-compose.yml'}},'State':{'Running':True,'Health':{'Status':'healthy'}},'Mounts':[{'Type':'bind','Source':'/state/'+role,'Destination':'/data','RW':True}]}
            self.images[role]={'Architecture':'arm64','Config':{'User':user,'Labels':{'org.opencontainers.image.revision':self.revision,'org.opencontainers.image.version':'1.9.0'}}}
            self.configuration['services'][role]={'read_only':True,'cap_drop':['ALL'],'cap_add':{'core':[],'edge':['NET_BIND_SERVICE'],'firewall':['NET_ADMIN']}[role],'volumes':[{'type':'bind','source':'/state/'+role,'target':'/data','read_only':False}]}
            if role!='core':self.configuration['services'][role]['network_mode']='host'
    def validate(self):
        return upgrade.validate(self.current,self.images,self.configuration,self.revision,'1.9.0','arm64','porthub')
    def test_matching_healthy_scoped_deployment_is_recoverable(self):
        self.assertEqual(self.validate(),{role:('/old','/old/docker-compose.yml') for role in upgrade.ROLES})
    def test_foreign_or_unhealthy_container_is_rejected(self):
        for mutation in [lambda:self.current['core']['Config']['Labels'].update({'com.docker.compose.project':'foreign'}),lambda:self.current['edge']['State']['Health'].update(Status='unhealthy')]:
            original=copy.deepcopy(self.current);mutation()
            with self.assertRaises(ValueError):self.validate()
            self.current=original
    def test_wrong_architecture_source_version_and_uid_are_rejected(self):
        for field,value in [('architecture','amd64'),('revision','b'*40),('version','1.8.9'),('user','root')]:
            original=copy.deepcopy(self.images)
            image=self.images['edge']
            if field=='architecture':image['Architecture']=value
            elif field=='user':image['Config']['User']=value
            else:image['Config']['Labels']['org.opencontainers.image.'+field]=value
            with self.assertRaises(ValueError):self.validate()
            self.images=original
    def test_state_mount_source_access_and_missing_mount_are_rejected(self):
        service=self.configuration['services']['core']
        for volumes in [[{'type':'bind','source':'/empty','target':'/data'}],[{'type':'bind','source':'/state/core','target':'/data','read_only':True}],[]]:
            service['volumes']=volumes
            with self.assertRaises(ValueError):self.validate()
    def test_privilege_escalation_and_core_public_network_are_rejected(self):
        for change in [{'privileged':True},{'read_only':False},{'cap_add':['SYS_ADMIN']},{'network_mode':'host'},{'ports':[{'target':47017,'published':'47017'}]}]:
            original=copy.deepcopy(self.configuration)
            self.configuration['services']['core'].update(change)
            with self.assertRaises(ValueError):self.validate()
            self.configuration=original
    def test_each_role_retains_its_independent_previous_compose_origin(self):
        self.current['edge']['Config']['Labels']['com.docker.compose.project.working_dir']='/different'
        self.assertEqual(self.validate()['edge'][0],'/different')
    def test_failed_first_replacement_restores_only_the_attempted_role_without_down(self):
        calls=[]
        def run(arguments):
            calls.append(arguments)
            if arguments[0]=='candidate':raise RuntimeError('partial replacement')
        with patch.object(upgrade,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'partial replacement'):
                upgrade.activate(['candidate'],['previous'],lambda:None)
        self.assertEqual([call[-1] for call in calls],['firewall','firewall'])
        for call in calls:
            self.assertIn('--no-deps',call);self.assertIn('--no-build',call);self.assertNotIn('down',call)
    def test_health_success_keeps_all_other_containers_checked(self):
        checked=[]
        with patch.object(upgrade,'run') as run:
            upgrade.activate(['candidate'],['previous'],lambda:checked.append(True))
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],list(upgrade.ROLES))
        self.assertEqual(checked,[True])
    def test_sigterm_restores_previous_roles_and_signal_handlers(self):
        previous=signal.getsignal(signal.SIGTERM)
        calls=[]
        def run(arguments):
            calls.append(arguments)
            if arguments[0]=='candidate':os.kill(os.getpid(),signal.SIGTERM)
            else:self.assertEqual(signal.getsignal(signal.SIGTERM),signal.SIG_IGN)
        with patch.object(upgrade,'run',side_effect=run):
            with self.assertRaises(InterruptedError):
                upgrade.activate(['candidate'],['previous'],lambda:None)
        self.assertEqual(signal.getsignal(signal.SIGTERM),previous)
        self.assertEqual([call[-1] for call in calls],['firewall','firewall'])
    def test_failed_rollback_role_does_not_prevent_other_restoration_attempts(self):
        calls=[]
        def run(arguments):
            calls.append(arguments)
            if arguments[0]=='candidate' and arguments[-1]=='edge' or arguments[0]=='previous' and arguments[-1]=='firewall':
                raise RuntimeError('Docker failure')
        checked=[]
        with patch.object(upgrade,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'rollback incomplete: firewall'):
                upgrade.activate(['candidate'],['previous'],lambda:checked.append(True))
        self.assertEqual([call[-1] for call in calls],['firewall','core','edge','firewall','core','edge'])
        self.assertEqual(checked,[True])
    def test_public_probe_failure_restores_images_and_rechecks_routes(self):
        attempts=[]
        def probe():
            attempts.append(True)
            if len(attempts)==1:raise RuntimeError('route unavailable')
        with patch.object(upgrade,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'route unavailable'):
                upgrade.activate(['candidate'],['previous'],lambda:None,probe)
        self.assertEqual([call.args[0][0] for call in run.call_args_list],['candidate']*3+['previous']*3)
        self.assertEqual(len(attempts),2)
    def test_probe_rejects_credentials_and_hides_private_urls_in_errors(self):
        with self.assertRaises(ValueError):upgrade.check_routes(['http://user:password@example.test'])
        with patch.object(upgrade,'urlopen',side_effect=OSError('private URL details')):
            with self.assertRaisesRegex(RuntimeError,'^PortHub route probe failed: 1$'):
                upgrade.check_routes(['https://example.test/private-route'])
    def test_selected_core_edge_accept_an_independently_deployed_firewall(self):
        self.current['firewall']['Config']['Labels']['com.docker.compose.project.working_dir']='/older-firewall'
        current={role:self.current[role] for role in ('core','edge')}
        images={role:self.images[role] for role in ('core','edge')}
        self.assertEqual(upgrade.validate(current,images,self.configuration,self.revision,'1.9.0','arm64','porthub',('core','edge')), {role:('/old','/old/docker-compose.yml') for role in ('core','edge')})
        self.assertEqual(set(upgrade.override({'core':'sha256:core','edge':'sha256:edge'},'1.9.0')['services']),{'core','edge'})
    def test_selected_role_failure_never_recreates_the_unselected_firewall(self):
        calls=[]
        def run(arguments):
            calls.append(arguments)
            if arguments[0]=='candidate':raise RuntimeError('partial replacement')
        with patch.object(upgrade,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'partial replacement'):
                upgrade.activate(['candidate'],['previous'],lambda:None,roles=('core','edge'))
        self.assertEqual([call[-1] for call in calls],['core','core'])

class ColdBackup(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data=self.root/'live';(self.data/'mongo').mkdir(parents=True)
        self.file=self.data/'mongo/WiredTiger.fixture';self.file.write_bytes(b'owned database state')
        self.container={'Id':'owned-core','Mounts':[{'Destination':'/data','Type':'bind','Source':str(self.data)}]}
    def test_cold_copy_is_hash_verified_and_preserves_ownership(self):
        backup=self.root/'backup'
        with patch.object(upgrade,'run') as run:
            upgrade.backup_core(self.container,backup)
        run.assert_called_once_with(['docker','stop','--time','20','owned-core'])
        manifest=json.loads((backup/'verified.json').read_text())
        self.assertEqual(manifest['sha256']['mongo/WiredTiger.fixture'],hashlib.sha256(self.file.read_bytes()).hexdigest())
        copied=backup/'data/mongo/WiredTiger.fixture'
        self.assertEqual(copied.read_bytes(),self.file.read_bytes())
        self.assertEqual((copied.stat().st_uid,copied.stat().st_gid),(self.file.stat().st_uid,self.file.stat().st_gid))
        self.assertEqual(backup.stat().st_mode&0o077,0)
    def test_nested_backup_is_rejected_before_stopping_core(self):
        with patch.object(upgrade,'run') as run:
            with self.assertRaises(ValueError):upgrade.backup_core(self.container,self.data/'backup')
        run.assert_not_called()
    def test_bad_copy_is_never_marked_verified(self):
        import migrate
        original=migrate.shutil.copytree
        def corrupt(source,destination,*args,**kwargs):
            result=original(source,destination,*args,**kwargs)
            if Path(source)==self.data:
                (Path(destination)/'mongo/WiredTiger.fixture').write_bytes(b'corrupted copy')
            return result
        with patch.object(upgrade,'run'),patch.object(migrate.shutil,'copytree',side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError,'integrity check failed'):
                upgrade.backup_core(self.container,self.root/'backup')
        self.assertFalse((self.root/'backup/verified.json').exists())
        self.assertEqual(self.file.read_bytes(),b'owned database state')
    def test_failed_backup_restores_core_without_touching_edge(self):
        def failed(role):raise RuntimeError('backup failed after core stop')
        with patch.object(upgrade,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'backup failed'):
                upgrade.activate(['candidate'],{'core':['old-core'],'edge':['old-edge']},lambda:None,roles=('core','edge'),before_role=failed)
        self.assertEqual([call.args[0][0] for call in run.call_args_list],['old-core'])
    def test_backup_timeout_leaves_no_verified_marker_and_restores_alarm_handler(self):
        import migrate
        previous=signal.getsignal(signal.SIGALRM)
        def stalled(*args):signal.raise_signal(signal.SIGALRM)
        with patch.object(upgrade,'run'),patch.object(migrate,'snapshot',side_effect=stalled):
            with self.assertRaises(TimeoutError):upgrade.backup_core(self.container,self.root/'backup')
        self.assertEqual(signal.getsignal(signal.SIGALRM),previous)
        self.assertFalse((self.root/'backup/verified.json').exists())
    def test_symlinked_state_is_rejected_before_stopping_core(self):
        alias=self.root/'alias';alias.symlink_to(self.data,target_is_directory=True)
        self.container['Mounts'][0]['Source']=str(alias)
        with patch.object(upgrade,'run') as run:
            with self.assertRaises(ValueError):upgrade.backup_core(self.container,self.root/'backup')
        run.assert_not_called()

class ReleaseSelection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = self.root / '.env'
        self.original = b'# retained settings\nSECRET=keep-this-private\nexport PORTHUB_VERSION=1.0.0\nPORTHUB_VERSION=1.0.1\nPORTHUB_SOURCE_REVISION=old\n'
        self.env.write_bytes(self.original)
        self.env.chmod(0o600)
        self.current = {role: {'Image': 'sha256:' + str(index)*64} for index,role in enumerate(upgrade.ROLES, 1)}
        self.images = {role: {'Id': 'sha256:' + str(index)*64} for index,role in enumerate(upgrade.ROLES, 4)}
        self.config = {'services': {role: {'image': 'porthub:'+role} for role in upgrade.ROLES}}
        self.tags = {'porthub:'+role: value['Image'] for role,value in self.current.items()}
        self.calls = []
        self.lookup = patch.object(upgrade, 'image_reference', side_effect=lambda name: self.tags.get(name))
        self.lookup.start(); self.addCleanup(self.lookup.stop)
        self.runner = patch.object(upgrade, 'run', side_effect=self.run_command)
        self.runner.start(); self.addCleanup(self.runner.stop)
    def run_command(self, arguments):
        self.calls.append(arguments)
        if arguments[:3] == ['docker', 'image', 'tag']:
            self.tags[arguments[4]] = arguments[3]
        elif arguments[:3] == ['docker', 'image', 'rm']:
            self.tags.pop(arguments[3], None)
        else:
            self.fail('Unexpected Docker command')
    def selection(self, roles=upgrade.ROLES):
        return upgrade.ReleaseSelection(self.root, {r:self.current[r] for r in roles},
            {r:self.images[r] for r in roles}, self.config, 'a'*40, '1.11.0')
    def test_promotion_preserves_credentials_permissions_and_previous_images(self):
        selection = self.selection()
        selection.apply(self.root, lambda: None)
        updated = self.env.read_bytes()
        self.assertIn(b'SECRET=keep-this-private\n', updated)
        self.assertEqual(updated.count(b'PORTHUB_VERSION='), 1)
        self.assertIn(b'PORTHUB_VERSION=1.11.0\n', updated)
        self.assertIn(b'PORTHUB_SOURCE_REVISION='+b'a'*40+b'\n', updated)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root/'previous-release.env').read_bytes(), self.original)
        for role in upgrade.ROLES:
            self.assertEqual(self.tags['porthub:'+role], self.images[role]['Id'])
            self.assertEqual(self.tags['porthub:'+role+'-1.11.0'], self.images[role]['Id'])
            previous = self.current[role]['Image']
            self.assertEqual(self.tags['porthub:rollback-'+role+'-'+previous[7:19]], previous)
    def test_failed_verification_restores_all_tags_and_environment(self):
        original_tags = dict(self.tags)
        def fail(): raise RuntimeError('probe failed')
        with self.assertRaisesRegex(RuntimeError, 'probe failed'):
            self.selection().apply(self.root, fail)
        self.assertEqual(self.tags, original_tags)
        self.assertEqual(self.env.read_bytes(), self.original)
    def test_conflicting_immutable_tag_is_rejected_before_any_mutation(self):
        self.tags['porthub:core-1.11.0'] = 'sha256:'+'f'*64
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.selection()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.env.read_bytes(), self.original)
    def test_changed_environment_is_rejected_without_overwriting_it(self):
        selection = self.selection()
        self.env.write_bytes(b'SECRET=changed-by-admin\n')
        with self.assertRaisesRegex(ValueError, 'changed since preflight'):
            selection.apply(self.root, lambda: None)
        self.assertEqual(self.env.read_bytes(), b'SECRET=changed-by-admin\n')
        self.assertEqual(self.calls, [])
    def test_partial_edge_upgrade_does_not_change_core_or_whole_release_version(self):
        self.selection(('edge',)).apply(self.root, lambda: None)
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(self.tags['porthub:core'], self.current['core']['Image'])
        self.assertEqual(self.tags['porthub:edge'], self.images['edge']['Id'])
    def test_finalization_failure_also_rolls_back_running_roles(self):
        calls = []
        def fail(): raise RuntimeError('finalization failed')
        with patch.object(upgrade, 'run', side_effect=lambda args: calls.append(args)):
            with self.assertRaisesRegex(RuntimeError, 'finalization failed'):
                upgrade.activate(['candidate'], ['previous'], lambda: None, after_roles=fail)
        self.assertEqual([call[0] for call in calls], ['candidate']*3+['previous']*3)

if __name__=='__main__':unittest.main()
