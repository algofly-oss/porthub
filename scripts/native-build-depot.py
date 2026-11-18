#!/usr/bin/env python3
"""Bounded trusted SSH depot upload and explicit protected-source cleanup.

The depot root must be a dedicated operator-owned directory, not a profile or
application data directory. No listener, credentials, or container is created.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 4 * 1024**3
MAX_REVISIONS = 12
KEY = re.compile(r'([a-f0-9]{40})/(manifest\.json|[a-z0-9_-]+/[a-f0-9]{64}\.zip)\Z')


def validate_key(key):
    match=KEY.fullmatch(key)
    if match is None: raise ValueError('Invalid exact source/content-addressed key')
    return match.group(1)


def root_directory(root):
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError('Use an existing dedicated absolute depot directory')
    for parent in root.parents:
        if parent.is_symlink(): raise ValueError('Depot path contains a symlink')
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o022:
        raise ValueError('Depot root must be operator-owned and not group/world writable')
    return root


class Lock:
    def __init__(self,root): self.root=root
    def __enter__(self):
        import fcntl
        self.stream=(self.root/'.native-depot.lock').open('a+b')
        deadline=time.monotonic()+8
        while True:
            try:
                fcntl.flock(self.stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic()>=deadline:
                    self.stream.close();raise TimeoutError('Depot busy')
                time.sleep(.05)
    def __exit__(self,*unused): self.stream.close()


def inventory(root):
    result=[]
    for path in root.iterdir():
        if not re.fullmatch('[a-f0-9]{40}',path.name): continue
        if path.is_symlink() or not path.is_dir(): raise ValueError('Invalid managed revision')
        size=0
        for entry in path.rglob('*'):
            if entry.is_symlink(): raise ValueError('Symlink in managed revision')
            if entry.is_file(): size+=entry.stat().st_size
        stamp=path/'manifest.json'
        result.append({'source_revision':path.name,'size':size,'mtime':stamp.stat().st_mtime if stamp.exists() else path.stat().st_mtime})
    return result


def install(root,key,stream,max_bytes=MAX_BYTES,max_revisions=MAX_REVISIONS):
    source=validate_key(key)
    root_directory(root)
    # Temporary uploads are capped independently and never visible to HTTP reads.
    maximum=65536 if key.endswith('manifest.json') else 512*1024**2
    with tempfile.NamedTemporaryFile(prefix='.incoming-',dir=root,delete=False) as temporary:
        temporary_path=Path(temporary.name)
        try:
            digest=hashlib.sha256();size=0
            while True:
                block=stream.read(min(65536,maximum-size+1))
                if not block: break
                size+=len(block)
                if size>maximum: raise ValueError('Upload exceeds bound')
                digest.update(block);temporary.write(block)
            temporary.flush();os.fsync(temporary.fileno())
            if key.endswith('.zip') and digest.hexdigest()!=Path(key).stem:
                raise ValueError('Content-addressed upload hash mismatch')
            if key.endswith('manifest.json'):
                manifest=json.loads(temporary_path.read_text())
                if manifest.get('schema_version')!=1 or manifest.get('source_revision')!=source:
                    raise ValueError('Manifest source mismatch')
            with Lock(root):
                rows=inventory(root)
                target=root/key
                for parent in [target,*target.parents]:
                    if parent==root: break
                    if parent.is_symlink(): raise ValueError('Upload path symlink')
                replaced=target.stat().st_size if target.is_file() else 0
                if sum(row['size'] for row in rows)+size-replaced>max_bytes:
                    raise ValueError('Depot byte cap reached; explicit protected-source prune required')
                if source not in {row['source_revision'] for row in rows} and len(rows)>=max_revisions:
                    raise ValueError('Depot revision cap reached; explicit protected-source prune required')
                directory = root
                for component in Path(key).parts[:-1]:
                    directory = directory / component
                    if not directory.exists():
                        directory.mkdir(mode=0o755)
                        # The API reads published paths under a different UID.
                        directory.chmod(0o755)
                    if directory.stat().st_mode & 0o022:
                        raise ValueError('Published directory must not be group/world writable')
                temporary_path.chmod(0o644)
                temporary_path.replace(target)
            return {'installed':key,'size':size,'sha256':digest.hexdigest()}
        finally:
            temporary_path.unlink(missing_ok=True)


def prune(root,protected,keep=4,execute=False):
    root_directory(root)
    if not protected or any(not re.fullmatch('[a-f0-9]{40}',value) for value in protected):
        raise ValueError('Explicit active/protected source list required')
    if not 1<=keep<=MAX_REVISIONS: raise ValueError('Invalid retention count')
    with Lock(root):
        rows=sorted(inventory(root),key=lambda row:row['mtime'],reverse=True)
        retained=set(protected)|{row['source_revision'] for row in rows[:keep]}
        removed=[row for row in rows if row['source_revision'] not in retained]
        if execute:
            for row in removed: shutil.rmtree(root/row['source_revision'])
    return {'execute':execute,'protected':sorted(protected),'removed':removed}


def upload(host,remote_script,remote_root,file,key):
    validate_key(key)
    # SSH invokes the remote shell: only fixed simple tokens are supported.
    for token in [host,remote_script,remote_root]:
        if not re.fullmatch(r'[A-Za-z0-9_@./:-]+',token) or token.startswith('-'):
            raise ValueError('SSH host/script/root must be fixed simple tokens')
    with file.open('rb') as stream:
        subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oConnectTimeout=5',host,
            'python3',remote_script,'install','--root',remote_root,'--key',key],stdin=stream,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=115)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['upload','install','prune'])
    parser.add_argument('--root',type=Path)
    parser.add_argument('--host')
    parser.add_argument('--remote-script')
    parser.add_argument('--remote-root')
    parser.add_argument('--file',type=Path)
    parser.add_argument('--key')
    parser.add_argument('--protected-source',action='append',default=[])
    parser.add_argument('--keep',type=int,default=4)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if args.mode=='upload': upload(args.host,args.remote_script,args.remote_root,args.file,args.key)
    elif args.mode=='install': print(json.dumps(install(args.root,args.key,sys.stdin.buffer),sort_keys=True))
    else: print(json.dumps(prune(args.root,args.protected_source,args.keep,args.execute),sort_keys=True))


if __name__=='__main__':main()
