"""Preflight must reject unsafe candidates before replacing any running role."""
import copy
import os
import signal
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
        self.assertEqual(self.validate(),('/old','/old/docker-compose.yml'))
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
    def test_inconsistent_previous_compose_origin_is_rejected(self):
        self.current['edge']['Config']['Labels']['com.docker.compose.project.working_dir']='/different'
        with self.assertRaises(ValueError):self.validate()
    def test_failed_first_replacement_restores_every_previous_role_without_down(self):
        calls=[]
        def run(arguments):
            calls.append(arguments)
            if arguments[0]=='candidate':raise RuntimeError('partial replacement')
        with patch.object(upgrade,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'partial replacement'):
                upgrade.activate(['candidate'],['previous'],lambda:None)
        self.assertEqual([call[-1] for call in calls],['firewall','firewall','core','edge'])
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
        self.assertEqual([call[-1] for call in calls],['firewall','firewall','core','edge'])

if __name__=='__main__':unittest.main()
