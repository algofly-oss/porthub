#!/usr/bin/env python3
"""Accept only complete source-pinned native validation for core-only CI bypass."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import time


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def restore(root,source,target,depot,output):
    """No arbitrary URLs, no native execution on Ubuntu, and no proof-less reuse."""
    hybrid=load('hybrid-native-build');validator=load('native-core-validation')
    hybrid.revision(source)
    if target not in validator.SUPPORTED or not depot: return False
    base=hybrid.https_url(depot).rstrip('/')
    from urllib.parse import urlsplit
    if urlsplit(base).query: raise ValueError('Trusted depot cannot contain query')
    if output.exists() or output.is_symlink(): raise ValueError('New local lane destination required')
    deadline=time.monotonic()+150
    with tempfile.TemporaryDirectory(prefix='local-core-lane-') as raw:
        stage=Path(raw);manifest=stage/'manifest.json'
        hybrid.download(base+'/'+source+'/manifest.json',manifest,65536,min(deadline,time.monotonic()+15))
        data=json.loads(manifest.read_text())
        if data.get('schema_version')!=1 or data.get('source_revision')!=source: raise ValueError('Local source manifest mismatch')
        row=data.get('targets',{}).get(target)
        if row is None: return False
        if not re.fullmatch('[a-f0-9]{64}',row['sha256']) or type(row['size']) is not int or not 0<row['size']<=hybrid.MAX_ARCHIVE: raise ValueError('Invalid local artifact metadata')
        expected=base+'/'+source+'/'+target+'/'+row['sha256']+'.zip'
        if row['url']!=expected: raise ValueError('Local payload URL differs from trusted content address')
        archive=stage/'components.zip';hybrid.download(expected,archive,row['size'],deadline)
        if archive.stat().st_size!=row['size'] or hybrid.sha(archive)!=row['sha256']: raise ValueError('Local artifact digest mismatch')
        components=stage/'components';hybrid.unpack(archive,components)
        validator.verify(root,components,target,source)
        output.parent.mkdir(parents=True,exist_ok=True)
        # Same-filesystem staging for atomic install. Components remain data on
        # the Linux verifier: native checks were executed on the trusted host.
        with tempfile.TemporaryDirectory(prefix='.local-core-',dir=output.parent) as owned:
            candidate=Path(owned)/'components';shutil.copytree(components,candidate);candidate.rename(output)
    return True


def verify(root,source,target,directory):
    return load('native-core-validation').verify(root,directory,target,source)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['restore','verify']);p.add_argument('--root',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--target',required=True);p.add_argument('--directory',type=Path,required=True);p.add_argument('--depot',default='');a=p.parse_args()
    ok=restore(a.root,a.source,a.target,a.depot,a.directory) if a.mode=='restore' else bool(verify(a.root,a.source,a.target,a.directory))
    if not ok: raise SystemExit(1)
    print(json.dumps({'source':a.source,'target':a.target,'mode':'core_only','native_validation':'passed'}))
if __name__=='__main__':main()
