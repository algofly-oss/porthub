#!/usr/bin/env python3
"""Seed an isolated CI cache with exact locally built helper bytes; never publish it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def seed(cache, target, core, revision, inputs):
    if cache.exists() or cache.is_symlink():
        raise ValueError('Fixture requires a fresh private cache directory')
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('Fixture requires source provenance')
    cache.mkdir(mode=0o700, parents=True)
    artifacts = []
    seen = set()
    for tool, executable in inputs:
        if tool not in {'sync','tor','terminal','stats'} or tool in seen:
            raise ValueError('Unknown or duplicate fixture tool')
        seen.add(tool)
        executable = Path(executable)
        version = subprocess.check_output([str(executable.resolve()), '--version'], text=True, timeout=10).strip().split()[-1]
        if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
            raise ValueError('Fixture helper has no stable version')
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        destination = cache / f'{tool}-{version}-{digest}{".exe" if "windows" in target else ""}'
        shutil.copyfile(executable, destination); destination.chmod(0o755)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise ValueError('Fixture binary changed while copying')
        artifacts.append({'component':tool,'version':version,'target':target.replace('-musl','-gnu'),
            'core':'>=1.11.0, <2.0.0','protocols':[1],'source_revision':revision,
            'build_inputs':hashlib.sha256(('fixture:'+digest).encode()).hexdigest(),
            'executable':{'size':destination.stat().st_size,'sha256':digest},
            'release':core,'archive':{'size':1,'sha256':'0'*64}})
    (cache/'porthub-components.json').write_text(json.dumps({'schema_version':1,
        'repository':'algofly-oss/porthub','release':core,'artifacts':artifacts}))
    (cache/'porthub-components.json').chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--target',required=True)
    parser.add_argument('--core',required=True)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--input',nargs=2,action='append',required=True,metavar=('TOOL','EXECUTABLE'))
    args=parser.parse_args()
    seed(args.cache,args.target,args.core,args.revision,args.input)


if __name__=='__main__':main()
