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
                (directory/'.env').write_text('SECRET=fixture-only\nPORTHUB_VERSION=1.9.0\nPORTHUB_SOURCE_REVISION='+revisions['old']+'\n')
                (directory/'.env').chmod(0o600)
                for role in ROLES:
                    tag = 'porthub-ci:'+role+'-'+revisions[kind]
                    tags.append(tag)
                    user = '10001:10001' if role == 'core' else '0:10001'
                    entry = 'exit 1' if kind == 'bad' and role == 'core' else 'trap exit TERM; while :; do sleep 1 & wait $!; done'
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
                    if role=='core':
                        (state/'mongo').mkdir(exist_ok=True)
                        (state/'mongo/WiredTiger.fixture').write_text('owned fixture database state')
                    service = {'image':project+':'+role,
                               'container_name':project+'-'+role, 'read_only':True, 'stop_grace_period':'1s',
                               'cap_drop':['ALL'], 'cap_add':{'core':[],'edge':['NET_BIND_SERVICE'],'firewall':['NET_ADMIN']}[role],
                               'environment':{'PORTHUB_VERSION':'${PORTHUB_VERSION}'},
                               'volumes':[{'type':'bind','source':str(state),'target':'/data' if role=='core' else '/state'}],
                               'healthcheck':{'test':['CMD','/bin/true'],'interval':'1s','timeout':'1s','retries':2}}
                    if role != 'core':service['network_mode']='host'
                    services[role]=service
                (directory/'docker-compose.yml').write_text(json.dumps({'services':services}))
            for role in ROLES:
                run('docker','image','tag','porthub-ci:'+role+'-'+revisions['old'],project+':'+role)
                tags.extend([project+':'+role, project+':'+role+'-1.9.0'])
            base = ['docker','compose','--project-name',project,'--project-directory',str(root/'old'),'-f',str(root/'old/docker-compose.yml')]
            run(*base,'up','-d','--wait','--wait-timeout','15')
            original = {role:inspect(project+'-'+role)['Image'] for role in ROLES}
            tags.extend(project+':rollback-'+role+'-'+image.removeprefix('sha256:')[:12] for role,image in original.items())
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
            assert (root/'good/.env').read_text().startswith('SECRET=fixture-only\n')
            assert (root/'good/.env').stat().st_mode & 0o777 == 0o600
            rendered=json.loads(run('docker','compose','--project-name',project,'--project-directory',str(root/'good'),'-f',str(root/'good/docker-compose.yml'),'config','--format','json').stdout)
            for role in ('core','edge'):
                selected=json.loads(run('docker','image','inspect',rendered['services'][role]['image']).stdout)[0]['Id']
                assert selected==inspect(project+'-'+role)['Image'], 'ordinary Compose must select the upgraded image'
            assert len(list((root/'good').glob('deploy/native/upgrade-records/*/previous-release.env')))==1

            snapshots=list(root.glob('*/deploy/native/upgrade-records/*/core-backup/verified.json'))
            assert len(snapshots)==2, 'both core replacement attempts require a verified backup'
            for manifest in snapshots:
                proof=json.loads(manifest.read_text())
                assert proof['sha256']['mongo/WiredTiger.fixture']==hashlib.sha256(b'owned fixture database state').hexdigest()
                assert (manifest.parent/'data/mongo/WiredTiger.fixture').read_bytes()==b'owned fixture database state'
            missing = unrelated - set(run('docker','ps','-q','--no-trunc').stdout.split())
            if missing:
                details = []
                for identity in sorted(missing):
                    result = run('docker', 'container', 'inspect', identity, check=False)
                    if result.returncode:
                        details.append({'id': identity, 'state': 'removed externally'})
                    else:
                        container = json.loads(result.stdout)[0]
                        state = container['State']
                        details.append({'id': identity, 'name': container['Name'],
                                        'status': state['Status'], 'exit_code': state['ExitCode'],
                                        'oom_killed': state['OOMKilled'], 'finished_at': state['FinishedAt']})
                raise AssertionError('Unrelated baseline containers no longer running: '+json.dumps(details))
            print('PASS real Docker: read-only preflight, partial upgrade rollback, verified cold backups, previous immutable images restored, healthy core/edge upgrade, unchanged firewall and unrelated containers retained')
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
