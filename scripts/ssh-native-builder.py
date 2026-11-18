#!/usr/bin/env python3
"""Trusted SSH native builder adapter. No publication or installed-agent changes.

Config is operator-owned: schema_version=1, hosts keyed by an explicit host ID.
Each host has platform (windows|posix), destination, ssh_options, scp_options,
python (bootstrap executable), target. SSH host-key checking is mandatory.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

REV = re.compile(r'[0-9a-f]{40}\Z')
HOST = re.compile(r'[a-zA-Z0-9_.-]{1,64}\Z')


def run(argv, timeout=30, **kw):
    return subprocess.run(argv, check=True, timeout=timeout, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kw).stdout


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def config(path, name):
    data = json.loads(Path(path).read_text())
    if data.get('schema_version') != 1 or not HOST.fullmatch(name):
        raise ValueError('Invalid trusted host configuration')
    host = data['hosts'][name]
    if host['platform'] not in ('windows', 'posix') or not isinstance(host['destination'], str):
        raise ValueError('Invalid host platform/destination')
    # Options are trusted operator input, but never permit weakened host identity.
    for key in ('ssh_options', 'scp_options'):
        host.setdefault(key, [])
        if not all(isinstance(x, str) for x in host[key]):
            raise ValueError('Invalid transport options')
        if any('stricthostkeychecking' in x.lower() or 'userknownhostsfile' in x.lower() for x in host[key]):
            raise ValueError('Host-key policy is fixed by the adapter')
    return host


def quote(host, value):
    return subprocess.list2cmdline([str(value)]) if host['platform'] == 'windows' else shlex.quote(str(value))


def ssh(host, command, timeout=30):
    return run(['ssh', '-n', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
                '-oConnectTimeout=5', *host['ssh_options'], host['destination'], command], timeout)


def copy(host, local, remote, upload=True):
    # SFTP absolute Windows paths require /C:/..., rather than C:/... .
    remote_path = '/' + remote if re.match(r'^[A-Za-z]:/', remote) else remote
    peer = host['destination'] + ':' + remote_path
    run(['scp', '-q', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
         '-oConnectTimeout=5', *host['scp_options'],
         *([str(local), peer] if upload else [peer, str(local)])], 110)


def inline(host, source, timeout=8):
    encoded = base64.b64encode(source.encode()).decode()
    code = "import base64;exec(base64.b64decode('%s'))" % encoded
    return ssh(host, quote(host, host.get('python', 'python' if host['platform'] == 'windows' else 'python3'))
               + ' -c ' + quote(host, code), timeout)


PROBE = '''import json,os,pathlib,platform,shutil,subprocess,sys
if sys.version_info<(3,11): raise RuntimeError('Python 3.11 required by verified worker')
import tomllib
home=pathlib.Path.home()
cargo=shutil.which('cargo') or str(home/'.cargo/bin'/('cargo.exe' if os.name=='nt' else 'cargo'))
rustc=shutil.which('rustc') or str(home/'.cargo/bin'/('rustc.exe' if os.name=='nt' else 'rustc'))
for exe in (cargo,rustc): subprocess.run([exe,'--version'],check=True,capture_output=True,timeout=3)
if not shutil.which('git'): raise RuntimeError('Git unavailable')
vcvars=None
if os.name=='nt':
 vs=pathlib.Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
 location=subprocess.run([str(vs),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],check=True,capture_output=True,text=True,timeout=3).stdout.strip()
 vcvars=str(pathlib.Path(location)/'VC/Auxiliary/Build/vcvars64.bat')
 if not pathlib.Path(vcvars).is_file(): raise RuntimeError('MSVC unavailable')
elif not shutil.which('clang') and platform.system()=='Darwin': raise RuntimeError('Clang unavailable')
arch={'arm64':'aarch64','aarch64':'aarch64','amd64':'x86_64','x86_64':'x86_64'}[platform.machine().lower()]
target=arch+{'Darwin':'-apple-darwin','Windows':'-pc-windows-msvc','Linux':'-unknown-linux-musl'}[platform.system()]
print(json.dumps(dict(python=sys.executable,cargo=cargo,rustc=rustc,vcvars=vcvars,target=target,home=str(home))))
'''


def probe(host):
    host = dict(host)
    if host['platform'] == 'posix' and host.get('python') in (None, 'python3', '/usr/bin/python3'):
        discovery = """import pathlib,subprocess,sys
home=pathlib.Path.home()
candidates=[pathlib.Path(sys.executable),pathlib.Path('/opt/homebrew/bin/python3'),pathlib.Path('/usr/local/bin/python3')]
candidates+=sorted((home/'.local/share/uv/python').glob('cpython-3.*/bin/python3'))[:32]
for p in candidates:
 if p.is_file():
  r=subprocess.run([str(p),'-c','import sys,tomllib; assert sys.version_info>=(3,11); print(sys.executable)'],capture_output=True,text=True,timeout=2)
  if r.returncode==0:
   print(r.stdout.strip());sys.exit(0)
sys.exit(3)
"""
        host['python']=inline(host,discovery,8).decode().strip()
    if host['platform'] == 'windows'  and host.get('python') in (None, 'python'):
        # WindowsApps python.exe is an installation alias, not a usable runtime.
        powershell = r"""$ErrorActionPreference='Stop'; $c=@(); $cmd=Get-Command python.exe -ErrorAction SilentlyContinue; if($cmd -and $cmd.Source -notlike '*WindowsApps*'){$c+=$cmd.Source}; foreach($r in @('HKCU:\Software\Python\PythonCore','HKLM:\Software\Python\PythonCore','HKLM:\Software\WOW6432Node\Python\PythonCore')){if(Test-Path $r){Get-ChildItem $r | ForEach-Object {$v=Get-ItemProperty ($_.PSPath+'\InstallPath') -ErrorAction SilentlyContinue; if($v){$c+=Join-Path $v.'(default)' 'python.exe'}}}}; foreach($r in @((Join-Path $env:USERPROFILE '.local\share\uv\python'),(Join-Path $env:APPDATA 'uv\python'))){if(Test-Path $r){$c+=Get-ChildItem $r -Filter python.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 32 -ExpandProperty FullName}}; foreach($p in ($c | Select-Object -Unique)){if(Test-Path $p){& $p -c 'import sys,tomllib; assert sys.version_info >= (3,11); print(sys.executable)' 2>$null; if($LASTEXITCODE -eq 0){exit 0}}}; exit 3"""
        command='powershell -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(powershell.encode('utf-16le')).decode()
        host['python']=ssh(host,command,8).decode().strip()
    result = json.loads(inline(host, PROBE).decode())
    if result['target'] != host['target']:
        raise ValueError('Native target differs from configured target')
    return result


def snapshot(root, revision, output):
    if not REV.fullmatch(revision):
        raise ValueError('Full immutable revision required')
    if run(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip() != revision:
        raise ValueError('Source checkout revision mismatch')
    run(['git', '-C', str(root), 'diff', '--quiet', 'HEAD', '--'])
    objects = [revision, run(['git', '-C', str(root), 'rev-parse', revision+'^{tree}']).decode().strip()]
    tree = run(['git', '-C', str(root), 'ls-tree', '-r', '-t', revision]).decode()
    for line in tree.splitlines():
        mode, kind, oid = line.split('\t', 1)[0].split()
        if kind == 'commit':
            raise ValueError('Submodule source is not closed')
        objects.append(oid)
    with output.open('wb') as stream:
        subprocess.run(['git', '-C', str(root), 'pack-objects', '--stdout'],
                       input=('\n'.join(sorted(set(objects)))+'\n').encode(),
                       stdout=stream, stderr=subprocess.PIPE, check=True, timeout=60)


REMOTE = '''import hashlib,json,os,pathlib,shutil,subprocess,sys
stage=pathlib.Path(__file__).resolve().parent
job=json.loads((stage/'job.json').read_text())
if (stage/'owner').read_text()!=job['nonce']: raise RuntimeError('Stage ownership mismatch')
def sha(p):
 with p.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
if sha(stage/'source.pack')!=job['pack_sha256']: raise RuntimeError('Source pack mismatch')
source=stage/'source'
source.mkdir()
subprocess.run(['git','init','--quiet',str(source)],check=True)
subprocess.run(['git','-C',str(source),'config','core.autocrlf','false'],check=True)
subprocess.run(['git','-C',str(source),'config','core.eol','lf'],check=True)
with (stage/'source.pack').open('rb') as f: subprocess.run(['git','-C',str(source),'unpack-objects','-q'],stdin=f,check=True)
(source/'.git/shallow').write_text(job['revision']+'\\n')
subprocess.run(['git','-C',str(source),'update-ref','HEAD',job['revision']],check=True)
subprocess.run(['git','-C',str(source),'reset','--hard',job['revision']],check=True,stdout=subprocess.DEVNULL)
env=os.environ.copy()
env['PATH']=str(pathlib.Path(job['tools']['cargo']).parent)+os.pathsep+env.get('PATH','')
env.update(CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_TARGET_DIR=str(stage/'target'),RUST_MIN_STACK='33554432')
if job['tools']['vcvars']:
 cmd='"'+job['tools']['vcvars']+'" >nul && set'
 text=subprocess.run(['cmd.exe','/d','/s','/c',cmd],check=True,capture_output=True,text=True,timeout=30).stdout
 for line in text.splitlines():
  if '=' in line and not line.startswith('='):
   key,value=line.split('=',1); env[key]=value
 env['PATH']=str(pathlib.Path(job['tools']['cargo']).parent)+os.pathsep+env.get('Path',env.get('PATH',''))
try:
 with (stage/'worker.log').open('wb') as log:
  subprocess.run([sys.executable,str(source/'scripts/hybrid-native-build.py'),'worker','--root',str(source),'--source-revision',job['revision'],'--output',str(stage/'components.zip'),'--tool','core','--timeout-seconds',str(job['timeout'])],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
 archive=stage/'components.zip'
 (stage/'result.json').write_text(json.dumps(dict(revision=job['revision'],target=job['tools']['target'],sha256=sha(archive),size=archive.stat().st_size)))
finally:
 shutil.rmtree(stage/'target',ignore_errors=True)
 shutil.rmtree(source,ignore_errors=True)
'''


def build(host, root, revision, state, timeout):
    if state.exists() or state.is_symlink():
        raise ValueError('Build state already exists; fetch or clean previous stage first')
    tools = probe(host)
    nonce = os.urandom(16).hex()
    stage = tools['home'].replace('\\', '/') + '/.porthub-native-build-' + nonce
    mkdir = "import pathlib; p=pathlib.Path(%r);p.mkdir(mode=0o700);(p/'owner').write_text(%r)" % (stage, nonce)
    inline(host, mkdir)
    record = dict(schema_version=1, revision=revision, target=host['target'], stage=stage, nonce=nonce, python=tools['python'])
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(record))
    with tempfile.TemporaryDirectory(prefix='porthub-ssh-build-') as directory:
        directory = Path(directory)
        pack = directory/'source.pack'
        snapshot(root, revision, pack)
        job = dict(record, pack_sha256=digest(pack), tools=tools, timeout=timeout)
        (directory/'job.json').write_text(json.dumps(job))
        (directory/'remote.py').write_text(REMOTE)
        for name in ('source.pack', 'job.json', 'remote.py'):
            copy(host, directory/name, stage+'/'+name)
        ssh(host, quote(host, tools['python'])+' '+quote(host, stage+'/remote.py'), timeout+60)
    return record


def cleanup(host, record):
    if not re.fullmatch(r'[0-9a-f]{32}',record['nonce']) or not record['stage'].replace('\\','/').endswith('/.porthub-native-build-'+record['nonce']):
        raise ValueError('Invalid owned stage')
    code = "import pathlib,shutil;p=pathlib.Path(%r);assert (p/'owner').read_text()==%r;shutil.rmtree(p)" % (record['stage'],record['nonce'])
    # Use the proven bootstrap executable saved at build time; never re-resolve aliases.
    configured=dict(host,python=record['python'])
    inline(configured, code)


def fetch(host, revision, state, archive):
    record = json.loads(state.read_text())
    if record['revision'] != revision or record['target'] != host['target'] or not re.fullmatch(r'[0-9a-f]{32}',record['nonce']):
        raise ValueError('Build state identity mismatch')
    if archive.exists() or archive.is_symlink():
        raise ValueError('Fetch destination already exists')
    stage = record['stage']
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=archive.parent) as folder:
        result = Path(folder)/'result.json'
        copy(host, result, stage+'/result.json', False)
        expected = json.loads(result.read_text())
        if expected['revision'] != revision or expected['target'] != host['target'] or not 0 < expected['size'] <= 512*1024*1024:
            raise ValueError('Remote result mismatch')
        temporary = Path(folder)/'components.zip'
        copy(host, temporary, stage+'/components.zip', False)
        if temporary.stat().st_size != expected['size'] or digest(temporary) != expected['sha256']:
            raise ValueError('Fetched archive mismatch')
        temporary.rename(archive)
    cleanup(host, record)
    return expected


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['probe','build','fetch','cleanup'])
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--host',required=True)
    p.add_argument('--root',type=Path)
    p.add_argument('--revision')
    p.add_argument('--state',type=Path)
    p.add_argument('--archive',type=Path)
    p.add_argument('--timeout',type=int,default=780)
    a=p.parse_args(); host=config(a.config,a.host)
    if a.mode=='probe': result=probe(host)
    else:
        if not a.revision or not REV.fullmatch(a.revision) or not a.state: p.error('revision/state required')
        if a.mode=='build':
            if not a.root or not 1<=a.timeout<=1640: p.error('root and bounded timeout required')
            result=build(host,a.root,a.revision,a.state,a.timeout)
        elif a.mode=='cleanup':
            record=json.loads(a.state.read_text())
            if record['revision']!=a.revision or record['target']!=host['target']: raise ValueError('Cleanup identity mismatch')
            cleanup(host,record); result={'status':'cleaned'}
        else:
            if not a.archive: p.error('archive required')
            result=fetch(host,a.revision,a.state,a.archive)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try: main()
    except Exception as error:
        # Do not leak private compiler/SSH output, paths, credentials, or arguments.
        print(json.dumps({'status':'unavailable','error_type':type(error).__name__}),file=sys.stderr)
        sys.exit(1)
