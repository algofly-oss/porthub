#!/usr/bin/env python3
"""Opt-in real Docker upgrade/rollback fixture; never uses production resources."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
ROLES = ('firewall', 'core', 'edge')


def run(*arguments, check=True):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=240)
    if check and result.returncode:
        raise RuntimeError('Fixture command failed: '+arguments[0]+'\n'+result.stderr[-2000:])
    return result


def inspect(name):
    return json.loads(run('docker', 'container', 'inspect', name).stdout)[0]


def main():
    project = 'porthub-upgrade-fixture-'+uuid.uuid4().hex[:10]
    revisions = {kind: hashlib.sha256((project+kind).encode()).hexdigest()[:40] for kind in ('old','bad','good')}
    tags = []
    with tempfile.TemporaryDirectory(prefix=project+'-') as temporary:
        root = Path(temporary)
        try:
            for kind in revisions:
                directory = root/kind
                directory.mkdir()
                for role in ROLES:
                    tag = 'porthub-ci:'+role+'-'+revisions[kind]
                    tags.append(tag)
                    user = '10001:10001' if role == 'core' else '0:10001'
                    entry = 'exit 1' if kind == 'bad' and role == 'core' else 'exec sleep 3600'
                    (root/'Dockerfile').write_text(f'''FROM busybox:1.37.0
    LABEL org.opencontainers.image.revision="{revisions[kind]}" org.opencontainers.image.version="1.9.0"
    USER {user}
    ENTRYPOINT ["/bin/sh", "-c", "{entry}"]
    ''')
                    run('docker', 'build', '--quiet', '-t', tag, str(root))
                services = {}
                for role in ROLES:
                    state = root/('state-'+role)
                    state.mkdir(exist_ok=True)
                    service = {'image':'porthub-ci:'+role+'-'+revisions[kind],
                               'container_name':project+'-'+role, 'read_only':True, 'stop_grace_period':'1s',
                               'cap_drop':['ALL'], 'cap_add':{'core':[],'edge':['NET_BIND_SERVICE'],'firewall':['NET_ADMIN']}[role],
                               'environment':{'PORTHUB_VERSION':'1.9.0'},
                               'volumes':[{'type':'bind','source':str(state),'target':'/state'}],
                               'healthcheck':{'test':['CMD','/bin/true'],'interval':'1s','timeout':'1s','retries':2}}
                    if role != 'core':service['network_mode']='host'
                    services[role]=service
                (directory/'docker-compose.yml').write_text(json.dumps({'services':services}))
            base = ['docker','compose','--project-name',project,'--project-directory',str(root/'old'),'-f',str(root/'old/docker-compose.yml')]
            run(*base,'up','-d','--wait','--wait-timeout','15')
            original = {role:inspect(project+'-'+role)['Image'] for role in ROLES}
            unrelated = set(run('docker','ps','-q','--no-trunc').stdout.split()) - {inspect(project+'-'+role)['Id'] for role in ROLES}
            def upgrade(kind, apply=False):
                arguments = [sys.executable,str(ROOT/'deploy/native/upgrade.py'),'--root',str(root/kind),'--revision',revisions[kind],'--version','1.9.0','--project',project]
                arguments.extend(['--roles','core','edge'])
                if apply:arguments.append('--apply')
                return run(*arguments,check=False)
            before = {role:inspect(project+'-'+role)['Id'] for role in ROLES}
            assert upgrade('bad').returncode == 0, 'dry-run must validate without starting the intentionally failing image'
            assert before == {role:inspect(project+'-'+role)['Id'] for role in ROLES}, 'dry-run must not recreate containers'
            failed = upgrade('bad',True)
            assert failed.returncode != 0, 'intentionally failing core must trigger rollback'
            for role in ROLES:
                current=inspect(project+'-'+role)
                assert current['Image'] == original[role], 'rollback must restore previous immutable image: '+role
                assert current['State']['Health']['Status'] == 'healthy'
            success = upgrade('good',True)
            assert success.returncode == 0, success.stderr[-2000:]
            for role in ROLES:
                current=inspect(project+'-'+role)
                expected=original[role] if role=='firewall' else json.loads(run('docker','image','inspect','porthub-ci:'+role+'-'+revisions['good']).stdout)[0]['Id']
                assert current['Image'] == expected, 'successful upgrade must run the pinned candidate: '+role
                assert current['State']['Health']['Status'] == 'healthy'
            assert inspect(project+'-firewall')['Id']==before['firewall'], 'unselected firewall must never be recreated'
            assert unrelated <= set(run('docker','ps','-q','--no-trunc').stdout.split()), 'unrelated containers must remain running'
            print('PASS real Docker: read-only preflight, partial upgrade rollback, previous immutable images restored, healthy core/edge upgrade, unchanged firewall and unrelated containers retained')
        finally:
            # Fixture-specific names only; no compose down or global pruning.
            owned = run('docker','ps','-aq','--filter','label=com.docker.compose.project='+project,check=False).stdout.split()
            for identity in owned:
                run('docker','rm','--force',identity,check=False)
            run('docker','network','rm',project+'_default',check=False)
            for tag in tags:
                run('docker','image','rm',tag,check=False)
            (Path(tempfile.gettempdir())/('porthub-native-upgrade-'+project+'.lock')).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
