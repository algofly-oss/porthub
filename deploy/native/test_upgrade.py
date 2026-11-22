"""Preflight must reject unsafe candidates before replacing any running role."""
import copy
import os
import signal
import json
import hashlib
import tempfile
import shutil
import subprocess
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

class NativeBuildDepot(unittest.TestCase):
    def setUp(self):
        self.temporary=self.enterContext(tempfile.TemporaryDirectory())
        self.root=Path(self.temporary)
        self.release=self.root/'release';self.release.mkdir()
        (self.release/'docker-compose.yml').write_text('services: {}\n')
        (self.release/'docker-compose.native-builds.yml').write_text('services: {}\n')
        (self.release/'.env').write_text('SECRET=retained\n');(self.release/'.env').chmod(0o600)
        self.path=self.root/'depot';self.path.mkdir(mode=0o755)
        self.fixture=Upgrade();self.fixture.setUp()
        self.current=self.fixture.current;self.configuration=self.fixture.configuration
        self.uid=os.getuid()

    def opted(self):
        return upgrade.native_build_depot(self.current,self.release,self.path,self.uid)

    def add_candidate(self,path=None,readonly=True):
        core=self.configuration['services']['core']
        core['volumes'].append({'type':'bind','source':str(path or self.path),'target':'/native-builds',
            'read_only':readonly,'bind':{'create_host_path':False}})
        core['environment']={'PORTHUB_NATIVE_BUILD_DEPOT_ROOT':'/native-builds','PORTHUB_NATIVE_BUILD_DEPOT_OWNER_UID':str(self.uid)}

    def validate(self,depot):
        return upgrade.validate(self.current,self.fixture.images,self.configuration,self.fixture.revision,'1.9.0','arm64','porthub',depot=depot)

    def existing(self):
        self.current['core']['Mounts'].append({'Type':'bind','Source':str(self.path),'Destination':'/native-builds','RW':False})
        self.current['core']['Config']['Env']=['PORTHUB_NATIVE_BUILD_DEPOT_ROOT=/native-builds','PORTHUB_NATIVE_BUILD_DEPOT_OWNER_UID='+str(self.uid)]

    def test_first_opt_in_allows_only_the_validated_readonly_extra_mount(self):
        depot=self.opted();self.add_candidate()
        self.assertEqual(set(self.validate(depot)),set(upgrade.ROLES))
        with self.assertRaises(ValueError):self.validate(None)
        self.configuration['services']['core']['volumes'][0]['source']='/changed-live-state'
        with self.assertRaises(ValueError):self.validate(depot)

    def test_wrong_depot_source_rw_duplicate_or_autocreate_is_rejected(self):
        depot=self.opted();self.add_candidate()
        baseline=copy.deepcopy(self.configuration)
        for mutate in [lambda:self.configuration['services']['core']['volumes'][-1].update(read_only=False),
            lambda:self.configuration['services']['core']['volumes'][-1].update(source='/other'),
            lambda:self.configuration['services']['core']['volumes'][-1]['bind'].update(create_host_path=True),
            lambda:self.configuration['services']['core']['volumes'].append(copy.deepcopy(self.configuration['services']['core']['volumes'][-1])),
            lambda:self.configuration['services']['core']['environment'].update(PORTHUB_NATIVE_BUILD_DEPOT_OWNER_UID='123456')]:
            self.configuration=copy.deepcopy(baseline);mutate()
            with self.assertRaises(ValueError):self.validate(depot)

    def test_previously_enabled_depot_is_preserved_without_flags(self):
        self.existing();self.add_candidate()
        depot=upgrade.native_build_depot(self.current,self.release)
        self.assertEqual(depot,{'path':self.path,'uid':self.uid})
        self.validate(depot)
        with self.assertRaises(ValueError):upgrade.native_build_depot(self.current,self.release,self.root/'other',self.uid)

    def test_invalid_old_depot_or_env_only_cannot_be_adopted(self):
        self.existing();self.current['core']['Mounts'][-1]['RW']=True
        with self.assertRaises(ValueError):upgrade.native_build_depot(self.current,self.release)
        self.current['core']['Mounts'].pop()
        with self.assertRaises(ValueError):upgrade.native_build_depot(self.current,self.release)

    def test_relative_symlink_worldwritable_state_or_release_overlap_rejected(self):
        linked=self.root/'linked';linked.symlink_to(self.path,target_is_directory=True)
        for path in [Path('relative'),linked,self.release,self.root]:
            with self.assertRaises(ValueError):upgrade.native_build_depot(self.current,self.release,path,self.uid)
        self.path.chmod(0o777)
        with self.assertRaises(ValueError):self.opted()
        self.path.chmod(0o755)
        self.current['core']['Mounts'][0]['Source']=str(self.path/'live-state')
        with self.assertRaises(ValueError):self.opted()

    def test_default_stays_off_and_unselected_core_cannot_opt_in(self):
        self.assertIsNone(upgrade.native_build_depot(self.current,self.release))
        with self.assertRaises(ValueError):upgrade.native_build_depot({},self.release,self.path,self.uid)

    def test_overlay_and_private_temp_env_used_then_removed(self):
        with upgrade.candidate_compose(self.release,'porthub',self.opted()) as command:
            self.assertIn(str(self.release/'docker-compose.native-builds.yml'),command)
            env=Path(command[command.index('--env-file',command.index('--env-file')+1)+1])
            self.assertEqual(env.stat().st_mode&0o777,0o600)
            self.assertIn(str(self.path),env.read_text())
        self.assertFalse(env.exists())
        with upgrade.candidate_compose(self.release,'porthub',None) as command:
            self.assertNotIn(str(self.release/'docker-compose.native-builds.yml'),command)

    def test_failed_first_activation_rolls_back_without_the_new_overlay(self):
        calls=[]
        with upgrade.candidate_compose(self.release,'porthub',self.opted()) as candidate:
            def run(command):
                calls.append(command)
                if str(self.release/'docker-compose.native-builds.yml') in command:
                    raise RuntimeError('candidate depot unhealthy')
            previous=['docker','compose','-f','/old/docker-compose.yml']
            with patch.object(upgrade,'run',side_effect=run),self.assertRaisesRegex(RuntimeError,'candidate depot unhealthy'):
                upgrade.activate(candidate,previous,lambda:None,roles=('core',))
        self.assertEqual(len(calls),2)
        self.assertIn(str(self.release/'docker-compose.native-builds.yml'),calls[0])
        self.assertNotIn(str(self.release/'docker-compose.native-builds.yml'),calls[1])
        self.assertIn('/old/docker-compose.yml',calls[1])
        self.assertTrue(self.path.is_dir())

    def test_missing_overlay_fails_without_creating_depot(self):
        (self.release/'docker-compose.native-builds.yml').unlink()
        with self.assertRaises(ValueError):
            with upgrade.candidate_compose(self.release,'porthub',self.opted()):pass

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
        import native_backup
        original=native_backup.hash_file
        def corrupt(path):
            if path.name=='WiredTiger.fixture':path.write_bytes(b'corrupted copy')
            return original(path)
        with patch.object(upgrade,'run'),patch.object(native_backup,'hash_file',side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError,'integrity check failed'):
                upgrade.backup_core(self.container,self.root/'backup')
        self.assertFalse((self.root/'backup/verified.json').exists())
        self.assertEqual(self.file.read_bytes(),b'owned database state')
    def test_copy_changed_after_hash_readback_is_never_marked_verified(self):
        import native_backup
        original=native_backup.hash_file
        def corrupt_after_readback(path):
            digest=original(path)
            if path.name=='WiredTiger.fixture':path.write_bytes(b'late corruption')
            return digest
        with patch.object(upgrade,'run'),patch.object(native_backup,'hash_file',side_effect=corrupt_after_readback):
            with self.assertRaisesRegex(RuntimeError,'integrity check failed'):
                upgrade.backup_core(self.container,self.root/'backup')
        self.assertFalse((self.root/'backup/verified.json').exists())
    def test_failed_backup_restores_core_without_touching_edge(self):
        def failed(role):raise RuntimeError('backup failed after core stop')
        with patch.object(upgrade,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'backup failed'):
                upgrade.activate(['candidate'],{'core':['old-core'],'edge':['old-edge']},lambda:None,roles=('core','edge'),before_role=failed)
        self.assertEqual([call.args[0][0] for call in run.call_args_list],['old-core'])
    def test_backup_timeout_leaves_no_verified_marker_and_restores_alarm_handler(self):
        import native_backup
        previous=signal.getsignal(signal.SIGALRM)
        def stalled(*args):signal.raise_signal(signal.SIGALRM)
        with patch.object(upgrade,'run'),patch.object(native_backup,'finish_snapshot',side_effect=stalled):
            with self.assertRaises(TimeoutError):upgrade.backup_core(self.container,self.root/'backup')
        self.assertEqual(signal.getsignal(signal.SIGALRM),previous)
        self.assertFalse((self.root/'backup/verified.json').exists())
    def test_symlinked_state_is_rejected_before_stopping_core(self):
        alias=self.root/'alias';alias.symlink_to(self.data,target_is_directory=True)
        self.container['Mounts'][0]['Source']=str(alias)
        with patch.object(upgrade,'run') as run:
            with self.assertRaises(ValueError):upgrade.backup_core(self.container,self.root/'backup')
        run.assert_not_called()

    def component(self,content=b'immutable artifact old'):
        path=self.data/'agent-releases/components'/('terminal-1.0-'+hashlib.sha256(content).hexdigest())
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
        return path
    def test_only_verified_immutable_components_are_staged_while_core_is_online(self):
        import native_backup
        component=self.component();backup=self.root/'backup';copied=backup/'data'/component.relative_to(self.data)
        def stop(arguments):
            self.assertEqual(arguments,['docker','stop','--time','20','owned-core'])
            self.assertEqual(copied.read_bytes(),component.read_bytes())
            self.assertFalse((backup/'data/mongo/WiredTiger.fixture').exists())
            self.file.write_bytes(b'consistent state after database shutdown')
        original=native_backup.copy_verified
        with patch.object(upgrade,'run',side_effect=stop),patch.object(native_backup,'copy_verified',wraps=original) as copy:
            upgrade.backup_core(self.container,backup)
        self.assertEqual(sum(call.args[0]==component for call in copy.call_args_list),1,'immutable data is not copied again during downtime')
        manifest=json.loads((backup/'verified.json').read_text())
        self.assertEqual(manifest['online_staged_bytes'],component.stat().st_size)
        self.assertEqual(manifest['cold_copied_bytes'],self.file.stat().st_size)
        self.assertEqual((backup/'data/mongo/WiredTiger.fixture').read_bytes(),self.file.read_bytes())
        self.assertNotEqual(copied.stat().st_ino,component.stat().st_ino,'live state is never hardlinked into a backup')
        original_copy=(backup/'data/mongo/WiredTiger.fixture').read_bytes();self.file.write_bytes(b'new live database writes')
        self.assertEqual((backup/'data/mongo/WiredTiger.fixture').read_bytes(),original_copy)
    def test_blob_changed_with_same_size_and_mtime_is_recopied_from_cold_state(self):
        component=self.component();before=component.stat();backup=self.root/'backup'
        def stop(_arguments):
            component.write_bytes(b'immutable artifact new')
            os.utime(component,ns=(before.st_atime_ns,before.st_mtime_ns))
        with patch.object(upgrade,'run',side_effect=stop):upgrade.backup_core(self.container,backup)
        copied=backup/'data'/component.relative_to(self.data)
        self.assertEqual(copied.read_bytes(),b'immutable artifact new')
        manifest=json.loads((backup/'verified.json').read_text())
        self.assertEqual(manifest['online_staged_bytes'],0)
        self.assertEqual(manifest['sha256'][str(component.relative_to(self.data))],hashlib.sha256(copied.read_bytes()).hexdigest())
    def test_tampered_staged_copy_is_repaired_before_verification(self):
        component=self.component();backup=self.root/'backup';copied=backup/'data'/component.relative_to(self.data)
        def stop(_arguments):copied.write_bytes(b'corrupted staged copy')
        with patch.object(upgrade,'run',side_effect=stop):upgrade.backup_core(self.container,backup)
        self.assertEqual(copied.read_bytes(),component.read_bytes())
        self.assertTrue((backup/'verified.json').is_file())
    def test_added_and_removed_files_match_the_cold_boundary(self):
        component=self.component();relative=str(component.relative_to(self.data));backup=self.root/'backup'
        def stop(_arguments):
            component.unlink();(self.data/'mongo/new-table').write_bytes(b'new consistent table')
        with patch.object(upgrade,'run',side_effect=stop):upgrade.backup_core(self.container,backup)
        manifest=json.loads((backup/'verified.json').read_text())
        self.assertNotIn(relative,manifest['sha256']);self.assertFalse((backup/'data'/relative).exists())
        self.assertEqual((backup/'data/mongo/new-table').read_bytes(),b'new consistent table')
    def test_online_staging_failure_never_stops_the_core(self):
        import native_backup
        self.component()
        with patch.object(upgrade,'run') as run,patch.object(native_backup,'copy_verified',side_effect=OSError('staging write failed')):
            with self.assertRaises(OSError):upgrade.backup_core(self.container,self.root/'backup')
        run.assert_not_called();self.assertFalse((self.root/'backup/verified.json').exists())
    def test_state_child_symlink_is_rejected_before_stopping_the_core(self):
        (self.data/'mongo/unsafe').symlink_to(self.file)
        with patch.object(upgrade,'run') as run:
            with self.assertRaises(ValueError):upgrade.backup_core(self.container,self.root/'backup')
        run.assert_not_called()
    def test_filename_digest_mismatch_is_cold_copied_instead_of_trusted(self):
        component=self.component();component.write_bytes(b'damaged cached artifact');backup=self.root/'backup'
        with patch.object(upgrade,'run'):upgrade.backup_core(self.container,backup)
        manifest=json.loads((backup/'verified.json').read_text())
        self.assertEqual(manifest['online_staged_bytes'],0)
        self.assertEqual((backup/'data'/component.relative_to(self.data)).read_bytes(),component.read_bytes())
    def test_online_staging_timeout_never_stops_the_core(self):
        import native_backup
        self.component();previous=signal.getsignal(signal.SIGALRM)
        def stalled(*_args):signal.raise_signal(signal.SIGALRM)
        with patch.object(upgrade,'run') as run,patch.object(native_backup,'copy_verified',side_effect=stalled):
            with self.assertRaises(TimeoutError):upgrade.backup_core(self.container,self.root/'backup')
        run.assert_not_called();self.assertEqual(signal.getsignal(signal.SIGALRM),previous)
        self.assertFalse((self.root/'backup/verified.json').exists())

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
    def test_depot_opt_in_persists_normal_restart_and_rolls_back_exact_bytes(self):
        depot={'path':Path('/owned/artifacts'),'uid':12345}
        selection=upgrade.ReleaseSelection(self.root,self.current,self.images,self.config,'a'*40,'1.11.0',depot=depot)
        selection.apply(self.root,lambda:None)
        self.assertIn(b'COMPOSE_FILE=docker-compose.yml:docker-compose.native-builds.yml\n',self.env.read_bytes())
        self.assertIn(b'PORTHUB_NATIVE_BUILD_DEPOT_HOST_PATH=/owned/artifacts\n',self.env.read_bytes())
        self.assertIn(b'SECRET=keep-this-private\n',self.env.read_bytes())
        # Separate failed transaction restores the prior deployment's exact env.
        prior=self.env.read_bytes();tags=dict(self.tags)
        selection=upgrade.ReleaseSelection(self.root,self.current,self.images,self.config,'a'*40,'1.11.0',depot=depot)
        def failed():raise RuntimeError('depot probe failed')
        record=self.root/'second-record';record.mkdir()
        with self.assertRaisesRegex(RuntimeError,'depot probe failed'):selection.apply(record,failed)
        self.assertEqual(self.env.read_bytes(),prior);self.assertEqual(self.tags,tags)

    def test_first_depot_finalization_failure_restores_disabled_environment(self):
        selection=upgrade.ReleaseSelection(self.root,self.current,self.images,self.config,'a'*40,'1.11.0',depot={'path':Path('/owned/artifacts'),'uid':12345})
        def failed():raise RuntimeError('depot setup failed')
        with self.assertRaises(RuntimeError):selection.apply(self.root,failed)
        self.assertEqual(self.env.read_bytes(),self.original)

    def test_depot_does_not_replace_custom_compose_overlays(self):
        self.env.write_bytes(self.original+b'COMPOSE_FILE=docker-compose.yml:operator-private.yml\n')
        with self.assertRaisesRegex(ValueError,'custom Compose'):
            upgrade.ReleaseSelection(self.root,self.current,self.images,self.config,'a'*40,'1.11.0',depot={'path':Path('/owned/artifacts'),'uid':12345})
        self.assertEqual(self.calls,[])

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



class ComposeWorkingDirectory(unittest.TestCase):
    def test_configuration_runner_anchors_the_release_directory(self):
        root=Path('/independent/staged-release')
        with patch.object(upgrade,'run',return_value='{"services":{}}') as runner:
            self.assertEqual(upgrade.compose_configuration(['docker','compose'],root),{'services':{}})
        runner.assert_called_once_with(['docker','compose','config','--format','json'],cwd=root)

    def test_actual_compose_resolves_relative_depot_overlay_from_unrelated_cwd(self):
        docker=shutil.which('docker')
        if not docker or subprocess.run([docker,'compose','version'],capture_output=True,timeout=15).returncode:
            self.skipTest('Docker Compose CLI unavailable; no daemon is required')
        with tempfile.TemporaryDirectory(prefix='porthub-compose-cwd-') as temporary:
            root=Path(temporary)/'release';root.mkdir()
            outside=Path(temporary)/'unrelated';outside.mkdir()
            (root/'docker-compose.yml').write_text('services:\n  core:\n    image: porthub:core-fixture\n')
            (root/'docker-compose.native-builds.yml').write_text('services:\n  core:\n    environment:\n      DEPOT_FIXTURE: enabled\n')
            env=root/'.env';env.write_text('COMPOSE_FILE=docker-compose.yml:docker-compose.native-builds.yml\n');env.chmod(0o600)
            arguments=[docker,'compose','--project-name','porthub-cwd-fixture','--project-directory',str(root),'--env-file',str(env)]
            before={f.name:f.read_bytes() for f in root.iterdir()}
            original=Path.cwd()
            try:
                os.chdir(outside)
                configuration=upgrade.compose_configuration(arguments,root)
            finally:
                os.chdir(original)
            self.assertEqual(configuration['services']['core']['environment']['DEPOT_FIXTURE'],'enabled')
            self.assertEqual({f.name:f.read_bytes() for f in root.iterdir()},before)


if __name__ == '__main__':
    unittest.main()
