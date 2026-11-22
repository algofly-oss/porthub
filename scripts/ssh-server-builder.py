#!/usr/bin/env python3
"""Operator-owned native Linux server adapter; no enrollment/deployment changes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

spec = importlib.util.spec_from_file_location('transport', Path(__file__).with_name('ssh-native-builder.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

PROBE = '''import json,os,pathlib,platform,shutil,subprocess,sys
assert sys.version_info >= (3,10)
assert platform.system() == 'Linux'
assert all(shutil.which(x) for x in ('git','docker','readelf','findmnt','lsblk'))
subprocess.run(['docker','info','--format','{{.ServerVersion}}'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
print(json.dumps({'machine':platform.machine(),'python':sys.executable,'home':str(pathlib.Path.home())}))
'''


def state_read(path, revision, target):
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('Private adapter state required')
    row = json.loads(path.read_text())
    if row['source'] != revision or row['target'] != target:
        raise ValueError('Adapter state belongs to another immutable job')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('probe', 'build', 'fetch'))
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--host', required=True)
    p.add_argument('--root', type=Path)
    p.add_argument('--revision')
    p.add_argument('--target', required=True, choices=('aarch64-unknown-linux-musl','x86_64-unknown-linux-musl'))
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--archive', type=Path)
    p.add_argument('--timeout', type=int, default=2700)
    args = p.parse_args()
    host = t.config(args.config, args.host)
    if host['platform'] != 'posix' or host['target'] != args.target:
        raise ValueError('Exact trusted Linux host target required')
    capability = json.loads(t.inline(host, PROBE, 12))
    machine = 'aarch64' if args.target.startswith('aarch64') else 'x86_64'
    if capability['machine'] != machine:
        raise ValueError('Native architecture mismatch')
    cache = host.get('server_cache')
    if not isinstance(cache, str) or not cache.startswith('/') or '..' in Path(cache).parts:
        raise ValueError('Dedicated absolute operator server cache required')
    if args.mode == 'probe':
        # The worker rechecks actual load, RAM, disk and container limits before
        # starting any compiler. This transport probe never pulls an image.
        print(json.dumps({'available': True, 'machine': machine}))
        return
    if not args.revision or not t.REV.fullmatch(args.revision) or not 60 <= args.timeout <= 3300:
        raise ValueError('Immutable bounded server build required')
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.mode == 'build':
        if args.state.exists():
            row = state_read(args.state, args.revision, args.target)
            # A completed retained stage can be fetched again after upload loss;
            # never overwrite or restart a potentially still active stage.
            code = f"import pathlib,json; p=pathlib.Path({row['stage']!r}); assert (p/'complete.json').is_file(); print((p/'complete.json').read_text())"
            completed = json.loads(t.inline(host, code, 8))
            if completed.get('source') != args.revision:
                raise ValueError('Retained server result identity mismatch')
            return
        if args.root is None:
            raise ValueError('Exact local source checkout required')
        stage = capability['home']+'/.cache/porthub-server-stage-'+secrets.token_hex(16)
        row = {'source': args.revision, 'target': args.target, 'stage': stage}
        # Persist identity BEFORE any remote side effect, so interruption cannot
        # make this operator start a duplicate untracked build.
        fd = os.open(args.state, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(row, stream)
        with tempfile.TemporaryDirectory(prefix='porthub-server-pack-') as temporary:
            pack = Path(temporary)/'source.pack'
            t.snapshot(args.root, args.revision, pack)
            sha = t.digest(pack)
            t.inline(host, f"import pathlib; p=pathlib.Path({stage!r}); p.mkdir(mode=0o700); (p/'owner.json').write_text({json.dumps(row)!r})", 8)
            t.copy(host, pack, stage+'/source.pack')
        code = f'''import hashlib,json,pathlib,subprocess,sys
p=pathlib.Path({stage!r}); revision={args.revision!r}
assert json.loads((p/'owner.json').read_text()) == {row!r}
assert hashlib.sha256((p/'source.pack').read_bytes()).hexdigest() == {sha!r}
repo=p/'repo'; repo.mkdir(); subprocess.run(['git','init','-q',str(repo)],check=True,timeout=10)
with (p/'source.pack').open('rb') as stream: subprocess.run(['git','-C',str(repo),'index-pack','--stdin'],stdin=stream,stdout=subprocess.DEVNULL,check=True,timeout=60)
subprocess.run(['git','-C',str(repo),'checkout','--detach',revision],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30)
subprocess.run([sys.executable,str(repo/'scripts/hybrid-server-build.py'),'worker','--root',str(repo),'--source-revision',revision,'--target',{args.target!r},'--cache',{cache!r},'--output',str(p/'server.zip'),'--budget-seconds',{str(args.timeout)!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout={args.timeout+45})
archive=p/'server.zip'; result={{'source':revision,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'size':archive.stat().st_size}}
(p/'complete.json').write_text(json.dumps(result)); print(json.dumps(result))
'''
        t.inline(host, code, args.timeout+80)
    else:
        if args.archive is None:
            raise ValueError('Owned local archive destination required')
        row = state_read(args.state, args.revision, args.target)
        stage = row['stage']
        code = f"import pathlib,json; p=pathlib.Path({stage!r}); assert json.loads((p/'owner.json').read_text()) == {row!r}; print((p/'complete.json').read_text())"
        complete = json.loads(t.inline(host, code, 8))
        if complete['source'] != args.revision or not re.fullmatch('[a-f0-9]{64}', complete['sha256']):
            raise ValueError('Remote server completion mismatch')
        temporary = args.archive.with_suffix('.pending.zip')
        if temporary.exists() or temporary.is_symlink() or args.archive.is_symlink():
            raise ValueError('Unsafe local server archive destination')
        t.copy(host, temporary, stage+'/server.zip', upload=False)
        if temporary.stat().st_size != complete['size'] or t.digest(temporary) != complete['sha256']:
            temporary.unlink()
            raise ValueError('Fetched server archive mismatch')
        temporary.replace(args.archive)
        # Cleanup failures retain private job state and a valid verified archive;
        # controller upload retries never rebuild that archive.
        cleanup = f"import pathlib,json,shutil; p=pathlib.Path({stage!r}); assert p.parent == pathlib.Path.home()/'.cache'; assert json.loads((p/'owner.json').read_text()) == {row!r}; assert (p/'complete.json').is_file(); shutil.rmtree(p)"
        try:
            t.inline(host, cleanup, 20)
            args.state.unlink()
        except Exception:
            print(json.dumps({'fetched': True, 'cleanup_pending': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'unavailable','error_type':type(error).__name__}))
        raise SystemExit(1)
