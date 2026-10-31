#!/usr/bin/env python3
"""Publish one complete immutable client release; retries can finish its draft."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'deploy/native'))
from migrate import ASSETS, artifact_bundle

spec = importlib.util.spec_from_file_location('release_retention', Path(__file__).with_name('prune-github-releases.py'))
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


def numeric(value):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('Release versions must use major.minor.patch')
    return tuple(map(int, value.split('.')))


def assets(directory, version):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Release assets must be a real directory')
    expected = {name+suffix for name in ASSETS for suffix in ('','.version','.sha256')}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError('Publication requires exactly thirty client assets')
    captured = artifact_bundle(directory,version,{})
    if set(captured) != expected:
        raise ValueError('Publication requires all ten platforms')
    result = {}
    for name, payload in captured.items():
        if (directory/name).read_bytes() != payload:
            raise ValueError('Release metadata must be canonical before upload')
        result[name] = {'size':len(payload), 'digest':'sha256:'+hashlib.sha256(payload).hexdigest()}
    return result


def verify_uploaded(release, expected):
    uploaded = release.get('assets', [])
    if len(uploaded) != len(expected) or {asset.get('name') for asset in uploaded} != set(expected):
        raise ValueError('GitHub release is missing or has unexpected platform assets')
    for asset in uploaded:
        proof = expected[asset['name']]
        if asset.get('state') != 'uploaded' or asset.get('size') != proof['size'] or asset.get('digest') != proof['digest']:
            raise ValueError('GitHub release asset does not match verified contents: '+asset['name'])


class GitHub(retention.GitHub):
    def optional(self,suffix):
        try:return self.api(suffix)
        except subprocess.CalledProcessError as error:
            if 'HTTP 404' in (error.stderr or ''):return None
            raise RuntimeError('GitHub release lookup failed') from None
    def latest(self):return self.optional('/releases/latest')
    def release(self,tag):return self.optional('/releases/tags/'+quote(tag,safe=''))
    def tag_commit(self,tag):
        obj=self.optional('/git/ref/tags/'+quote(tag,safe=''))
        return self.commit(tag) if obj is not None else None
    def command(self,*arguments):
        result=subprocess.run(['gh','release',*arguments,'--repo',self.prefix.removeprefix('repos/')],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError('GitHub release operation failed: '+arguments[0])
    def create(self,tag,revision,paths):
        self.command('create',tag,*map(str,paths),'--draft','--target',revision,'--title','PortHub '+tag.removeprefix('v'),
                     '--notes','Verified complete ten-platform PortHub release. Source: '+revision)
    def upload(self,tag,paths):self.command('upload',tag,*map(str,paths),'--clobber')
    def promote(self,tag):self.command('edit',tag,'--draft=false','--latest')


def superseded(latest, version):
    if latest is None:return False
    if latest.get('draft') or latest.get('prerelease') or not latest.get('tag_name','').startswith('v'):
        raise ValueError('Latest release is not a stable numeric version')
    return numeric(latest['tag_name'][1:]) > numeric(version)


def publish(github,directory,version,revision,execute=False):
    numeric(version)
    if not re.fullmatch(r'[a-f0-9]{40}',revision):raise ValueError('A full verified source revision is required')
    expected=assets(directory,version)
    tag='v'+version
    if superseded(github.latest(),version):return {'tag':tag,'status':'superseded'}
    existing=github.release(tag)
    target=github.tag_commit(tag)
    if target is not None and target != revision:
        raise ValueError('Release tag points to different source; version reuse is forbidden')
    if existing is not None:
        if existing.get('prerelease'):raise ValueError('A preview cannot be silently promoted into this stable release')
        if not existing.get('draft'):
            if target != revision:raise ValueError('Published source does not match the verified release')
            verify_uploaded(existing,expected)
            return {'tag':tag,'status':'already-published'}
        if existing.get('target_commitish') != revision:
            raise ValueError('Existing draft is pinned to different source; prepare a new version')
    if not execute:return {'tag':tag,'status':'ready','assets':len(expected)}
    paths=[directory/name for name in sorted(expected)]
    if existing is None:github.create(tag,revision,paths)
    else:
        present={asset.get('name'):asset for asset in existing.get('assets',[])}
        if len(present)!=len(existing.get('assets',[])) or set(present)-set(expected):
            raise ValueError('Draft contains unexpected assets; no files were replaced')
        pending=[directory/name for name,proof in expected.items() if name not in present or
                 any(present[name].get(key)!=value for key,value in proof.items()) or present[name].get('state')!='uploaded']
        if pending:github.upload(tag,pending)
    draft=github.release(tag)
    if draft is None or not draft.get('draft') or draft.get('target_commitish') != revision:
        raise ValueError('Uploaded draft source does not match the verified release')
    verify_uploaded(draft,expected)
    # A concurrent publisher must not let this older run replace newer latest.
    if superseded(github.latest(),version):return {'tag':tag,'status':'superseded'}
    github.promote(tag)
    published=github.release(tag)
    if published is None or published.get('draft') or published.get('prerelease') or github.tag_commit(tag) != revision:
        raise ValueError('Published release source verification failed')
    verify_uploaded(published,expected)
    retention.validate_latest(github.latest(),tag)
    return {'tag':tag,'status':'published'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--assets',type=Path,required=True)
    parser.add_argument('--version',required=True)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    result=publish(GitHub(args.repository),args.assets,args.version,args.revision,args.execute)
    print(json.dumps(result,sort_keys=True))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as output:
            output.write('status='+result['status']+'\n')


if __name__=='__main__':main()
