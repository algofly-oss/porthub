#!/usr/bin/env python3
"""One-shot trusted controller for prepared main-branch release requests.

Suitable for a user timer. Reads GitHub metadata only; no workflow dispatch,
publication, fleet setup, or long-lived polling process.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import zipfile


def gh(repository,path,output=None):
    command=['gh','api','repos/'+repository+path]
    if output is None:
        result=subprocess.run(command,check=True,capture_output=True,timeout=20)
        if len(result.stdout)>1024*1024:raise ValueError('GitHub response exceeds bound')
        return json.loads(result.stdout)
    with output.open('wb') as stream:
        subprocess.run(command,check=True,stdout=stream,stderr=subprocess.DEVNULL,timeout=20)
    if output.stat().st_size>65536:raise ValueError('Request artifact exceeds bound')


def git(root,*args):
    result=subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,text=True,timeout=60)
    return result.stdout.strip()


def requests(repository,branch,completed_runs=()):
    # One small request when quiet. Only active trusted-main runs cause an
    # artifact lookup; never walk twenty completed runs every timer tick.
    runs=gh(repository,'/actions/workflows/continuous-release.yml/runs?branch='+branch+'&per_page=10').get('workflow_runs',[])
    if not isinstance(runs,list) or len(runs)>10:raise ValueError('Invalid workflow run list')
    for run in runs:
        run_id=run.get('id')
        if run_id in completed_runs:continue
        if (type(run_id)is not int or run.get('path')!='.github/workflows/continuous-release.yml'
                or run.get('head_branch')!=branch or run.get('event') not in ('push','workflow_dispatch')
                or run.get('status') not in ('queued','in_progress')
                or (run.get('head_repository') or {}).get('full_name')!=repository):continue
        artifacts=gh(repository,'/actions/runs/'+str(run_id)+'/artifacts?name=native-build-request&per_page=10').get('artifacts',[])
        if not isinstance(artifacts,list) or len(artifacts)>10:raise ValueError('Invalid request artifact list')
        for artifact in artifacts:
            if (artifact.get('name')!='native-build-request' or artifact.get('expired')
                    or type(artifact.get('id'))is not int
                    or not 0<artifact.get('size_in_bytes',0)<=65536):continue
            digest=artifact.get('digest','')
            if not re.fullmatch('sha256:[a-f0-9]{64}',digest):continue
            yield artifact,run


def read_request(repository,artifact,run):
    with tempfile.TemporaryDirectory(prefix='porthub-native-request-') as temporary:
        path=Path(temporary)/'request.zip'
        gh(repository,'/actions/artifacts/'+str(artifact['id'])+'/zip',path)
        import hashlib
        if hashlib.sha256(path.read_bytes()).hexdigest()!=artifact['digest'].split(':')[1]:
            raise ValueError('Request artifact digest mismatch')
        with zipfile.ZipFile(path) as stream:
            rows=stream.infolist()
            if len(rows)!=1 or rows[0].filename!='native-build-request.json' or rows[0].file_size>4096:
                raise ValueError('Invalid prepared request archive')
            request=json.loads(stream.read(rows[0]))
    if (request.get('schema_version')!=1 or request.get('repository')!=repository
            or request.get('run_id')!=run['id'] or request.get('head_sha')!=run['head_sha']
            or not re.fullmatch('[a-f0-9]{40}',request.get('source_revision',''))):
        raise ValueError('Prepared request identity mismatch')
    return request


def load_controller():
    spec=importlib.util.spec_from_file_location('hybrid_native',Path(__file__).with_name('hybrid-native-build.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


@contextmanager
def locked(state):
    import fcntl
    with (state/'controller.lock').open('a+b') as stream:
        try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            yield False;return
        yield True


def run_once(root,repository,branch,config_path,state):
    if not re.fullmatch(r'[\w.-]+/[\w.-]+',repository) or not re.fullmatch(r'[\w./-]+',branch):
        raise ValueError('Explicit trusted repository and branch required')
    information=config_path.stat()
    if config_path.is_symlink() or information.st_uid!=os.getuid() or information.st_mode & 0o022:
        raise ValueError('Builder configuration must be operator-owned and not group/world writable')
    config=json.loads(config_path.read_text())
    state.mkdir(parents=True,exist_ok=True,mode=0o700)
    if state.is_symlink() or state.stat().st_uid!=os.getuid() or state.stat().st_mode & 0o077:
        raise ValueError('Controller state must be private and operator-owned')
    with locked(state) as acquired:
        if not acquired:return {'status':'controller_already_active'}
        checkpoint=state/'checkpoint.json'
        current=json.loads(checkpoint.read_text()) if checkpoint.exists() else {'schema_version':1,'sources':{}}
        if current.get('schema_version')!=1 or not isinstance(current.get('sources'),dict):
            raise ValueError('Invalid controller checkpoint')
        complete_runs={row.get('run_id') for row in current['sources'].values() if row.get('complete')}
        for artifact,run in requests(repository,branch,complete_runs):
            request=read_request(repository,artifact,run);source=request['source_revision']
            previous=current['sources'].get(source,{})
            if previous.get('complete') or time.time()-previous.get('attempted_at',0)<60:continue
            # Never execute a request from a fork/PR/arbitrary workflow ref. The
            # prepared commit must actually belong to the operator's main branch.
            origin=git(root,'remote','get-url','origin')
            suffix=repository.removesuffix('.git')
            if origin not in ('https://github.com/'+suffix,'https://github.com/'+suffix+'.git','git@github.com:'+suffix+'.git','git@github.com:'+suffix):
                raise ValueError('Local repository origin differs from trusted GitHub repository')
            git(root,'fetch','--no-tags','origin','refs/heads/'+branch)
            git(root,'merge-base','--is-ancestor',source,'FETCH_HEAD')
            git(root,'merge-base','--is-ancestor',run['head_sha'],source)
            owned=state/source
            if not owned.exists():
                # Refuse growth rather than deleting a potentially active source.
                retained=[p for p in state.iterdir() if re.fullmatch('[a-f0-9]{40}',p.name)]
                size=sum(p.stat().st_size for folder in retained for p in folder.rglob('*') if p.is_file() and not p.is_symlink())
                if len(retained)>=12 or size>=4*1024**3:
                    return {'status':'state_cap_reached_github_fallback'}
                owned.mkdir(mode=0o700)
            checkout=owned/'repo'
            if not checkout.exists():git(root,'worktree','add','--detach',str(checkout),source)
            controller=load_controller()
            report=controller.control(checkout,source,config,owned/'outputs')
            current['sources'][source]={'attempted_at':int(time.time()),'run_id':run['id'],
                'targets':report['targets'],'complete':not report.get('manifest_unavailable') and len(report['targets'])==len(config['builders']) and all(row['status'] in ('local_verified','local_verified_reused') for row in report['targets'].values())}
            current['sources']=dict(list(current['sources'].items())[-32:])
            pending=state/'checkpoint.pending.json';pending.write_text(json.dumps(current,sort_keys=True));pending.replace(checkpoint)
            return {'status':'processed','source_revision':source,'run_id':run['id'],'targets':report['targets'],'complete':not report.get('manifest_unavailable') and len(report['targets'])==len(config['builders']) and all(row['status'] in ('local_verified','local_verified_reused') for row in report['targets'].values())}
        return {'status':'no_eligible_prepared_release'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--repository',required=True)
    parser.add_argument('--branch',default='main')
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--state',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(run_once(args.root,args.repository,args.branch,args.config,args.state),sort_keys=True))


if __name__=='__main__':main()
