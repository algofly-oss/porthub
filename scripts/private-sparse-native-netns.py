"""Reviewed-source candidate ONLY. Default self-test/preparation never runs Docker.
Execution requires explicit Root GO, exact local test ELF/image/source pins.
"""
import argparse,hashlib,json,os,pathlib,re,shutil,stat,subprocess,tempfile,uuid
TEST='private_network::native_lifecycle_fixture::linux_owned_capture_overlap_withdrawal_connected_socket_and_drop_boundaries'
PURPOSE='reviewed-disposable-netns-v1'
def digest(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def command(args,timeout=10,check=True):return subprocess.run(args,check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
def own(cid,nonce,image):
 result=command(['docker','inspect',cid],check=False)
 if result.returncode:
  # An inspect error is not evidence of absence. Require an independently
  # successful complete-ID listing; daemon/permission/transient errors fail
  # closed and leave the rootfs/journals available for exact owned repair.
  listed=command(['docker','ps','--all','--no-trunc','--format','{{.ID}}'],check=False)
  if listed.returncode:raise RuntimeError('cannot establish container absence: Docker enumeration failed')
  ids=listed.stdout.decode('ascii').splitlines()
  if len(ids)>4096 or any(not re.fullmatch('[0-9a-f]{64}',item) for item in ids):raise RuntimeError('cannot establish container absence: invalid bounded complete-ID inventory')
  if cid in ids:raise RuntimeError('owned container still listed but cannot be inspected; rootfs retained')
  return None
 row=json.loads(result.stdout)[0]
 if row['Name']!='/porthub-sparse-native-'+nonce or row['Image']!=image or row['Config']['Labels'].get('porthub.sparse.native.nonce')!=nonce:raise RuntimeError('container ownership changed; refusing mutation')
 return row
def valid_scope(cfg):
 # Moby canonicalizes these exact flags to CAP_-prefixed names. No added
 # capability is accepted: https://github.com/moby/moby/blob/v28.3.2/oci/caps/utils.go#L45-L70
 caps=cfg.get('CapAdd') or [];drops=cfg.get('CapDrop') or []
 if not all(isinstance(c,str) for c in caps+drops):return False
 normalized={c.removeprefix('CAP_') for c in caps}
 return cfg.get('NetworkMode')=='none' and not cfg.get('Privileged') and cfg.get('ReadonlyRootfs') is True and normalized=={'NET_ADMIN','SYS_CHROOT'} and {c.removeprefix('CAP_') for c in drops}=={'ALL'} and not cfg.get('Devices') and cfg.get('DeviceCgroupRules')==['c 10:200 rw'] and cfg.get('Tmpfs')=={'/fixture/state':'rw,noexec,nosuid,nodev,size=1048576,mode=0700'}

def valid_mounts(mounts,root):
 expected={'/fixture':str(root),'/fixture/proc':'/proc','/fixture/dev/net/tun':'/dev/net/tun'}
 if not isinstance(mounts,list):return False
 # Docker versions may report tmpfs separately; never accept another writable mount.
 tmpfs=[m for m in mounts if m.get('Destination')=='/fixture/state']
 if len(tmpfs)>1 or any(m.get('Type')!='tmpfs' or m.get('RW') is not True for m in tmpfs):return False
 mounts=[m for m in mounts if m.get('Destination')!='/fixture/state']
 if len(mounts)!=len(expected):return False
 seen=set()
 for mount in mounts:
  destination=mount.get('Destination')
  if destination not in expected or destination in seen or mount.get('Type')!='bind' or mount.get('Source')!=expected[destination] or mount.get('RW') is not False:return False
  seen.add(destination)
 return seen==set(expected)

def recipe(root,nonce,image,spec_hash,loader,library_dirs):
 return ['docker','run','--detach','--pull=never','--name','porthub-sparse-native-'+nonce,'--label','porthub.sparse.native.nonce='+nonce,'--read-only','--network','none','--user','0:0','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','SYS_CHROOT','--security-opt','no-new-privileges:true','--pids-limit','96','--memory','512m','--cpus','1','--ulimit','nofile=256:256','--log-opt','max-size=1m','--log-opt','max-file=1','--mount',f'type=bind,source={root},target=/fixture,readonly','--mount','type=bind,source=/proc,target=/fixture/proc,readonly','--mount','type=bind,source=/dev/net/tun,target=/fixture/dev/net/tun,readonly','--device-cgroup-rule','c 10:200 rw','--tmpfs','/fixture/state:rw,noexec,nosuid,nodev,size=1048576,mode=0700','--env','PORTHUB_SPARSE_NATIVE_FIXTURE='+PURPOSE,'--env','PORTHUB_SPARSE_NATIVE_SPEC_SHA256='+spec_hash,'--env','RUST_LOG=off','--env','RUST_BACKTRACE=0','--entrypoint','/fixture'+loader,image,'--library-path',':'.join('/fixture'+p for p in library_dirs),'/fixture/chroot','/fixture','/porthub-tests','--ignored','--exact',TEST,'--nocapture','--test-threads=1']
def dependencies(binary):
 env=os.environ.copy()
 for key in ['LD_PRELOAD','LD_LIBRARY_PATH','BASH_ENV','ENV']:env.pop(key,None)
 env['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
 result=subprocess.run(['/usr/bin/ldd',str(binary)],env=env,check=True,capture_output=True,text=True,timeout=10)
 paths=[];loader=None
 for line in result.stdout.splitlines():
  found=re.search(r'(?:=>\s+|^\s*)(/[^\s]+)\s+\(',line)
  if not found:continue
  path=pathlib.Path(found.group(1));resolved=path.resolve(strict=True);meta=resolved.stat()
  if not str(path).startswith(('/lib/','/lib64/','/usr/lib/','/usr/lib64/')) or not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:raise RuntimeError('untrusted/non-system dependency')
  paths.append(path)
  if 'ld-linux' in path.name or 'ld-musl' in path.name:loader=str(path)
 return paths,loader
def run(args):
 if not re.fullmatch('[0-9a-f]{64}',args.sha or '') or not re.fullmatch('sha256:[0-9a-f]{64}',args.image or '') or not re.fullmatch('[0-9a-f]{40}',args.source or ''):raise RuntimeError('exact binary/image/source pins required')
 binary=pathlib.Path(args.binary).resolve(strict=True)
 if binary.is_symlink() or not binary.is_file() or binary.stat().st_size>256*1024*1024 or digest(binary)!=args.sha or binary.open('rb').read(4)!=b'\x7fELF':raise RuntimeError('test ELF pin mismatch')
 root=pathlib.Path(__file__).resolve().parents[1];actual=command(['git','-C',str(root),'-c','safe.directory='+str(root),'rev-parse','HEAD']).stdout.decode().strip()
 if actual!=args.source or command(['git','-C',str(root),'-c','safe.directory='+str(root),'status','--porcelain','--untracked-files=no']).stdout.strip():raise RuntimeError('fixture source is not exact clean revision')
 nonce=getattr(args,'nonce',None) or uuid.uuid4().hex
 if not re.fullmatch('[0-9a-f]{32}',nonce):raise RuntimeError('invalid owned container nonce')
 stage=pathlib.Path('/tmp/porthub-sparse-native-'+nonce);stage.mkdir(mode=0o700);fs=stage/'rootfs';fs.mkdir(mode=0o755)
 receipt={'offline_mock_only':bool(getattr(args,'offline_mock',False)),'nonce':nonce,'source':args.source,'test_executable_sha256':args.sha,'image':args.image,'test':TEST,'executed':False,'container_absent':None,'rootfs_removed':False};cid=None
 try:
  chroot=pathlib.Path('/usr/sbin/chroot')
  if not chroot.is_file():raise RuntimeError('reviewed system chroot utility absent')
  libs1,loader=dependencies(binary);libs2,other_loader=dependencies(chroot)
  if not loader or loader!=other_loader:raise RuntimeError('incompatible runtime loader')
  files={path:str(path).lstrip('/') for path in libs1+libs2};files[binary]='porthub-tests';files[chroot]='chroot';manifest={}
  for source,target in files.items():
   dest=fs/target;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest);dest.chmod(0o555);manifest['/'+target]=digest(dest)
  if manifest['/porthub-tests']!=args.sha:raise RuntimeError('executable changed while snapshotting')
  for directory in ['proc','dev/net','state']:(fs/directory).mkdir(parents=True,exist_ok=True)
  (fs/'dev/net/tun').touch(mode=0o600)
  spec={'authorization':PURPOSE,'nonce':nonce,'parent_netns_inode':os.stat('/proc/self/ns/net').st_ino}
  (fs/'spec.json').write_text(json.dumps(spec,separators=(',',':')));(fs/'spec.json').chmod(0o444)
  recipe_args=recipe(fs,nonce,args.image,digest(fs/'spec.json'),loader,sorted({str(path.parent) for path in libs1+libs2}))
  receipt.update(stage=str(stage),manifest=manifest,recipe=recipe_args)
  if not args.execute:
   receipt['prepared_only']=True;return receipt
  # This is the ONLY execution boundary; Root reviews this complete candidate
  # and exact hashes before authorizing --execute. No implicit retry exists.
  image=json.loads(command(['docker','image','inspect',args.image]).stdout)[0]
  if image['Id']!=args.image:raise RuntimeError('existing immutable image pin mismatch')
  device=os.stat('/dev/net/tun')
  if not stat.S_ISCHR(device.st_mode) or (os.major(device.st_rdev),os.minor(device.st_rdev))!=(10,200):raise RuntimeError('existing TUN character device absent; no modprobe/mknod authorized')
  cid=command(recipe_args,timeout=15).stdout.decode().strip()
  if not re.fullmatch('[0-9a-f]{64}',cid):raise RuntimeError('invalid container ID')
  receipt.update(executed=True,container_id=cid)
  row=own(cid,nonce,args.image);cfg=row['HostConfig']
  receipt['observed_scope']={key:cfg.get(key) for key in ['NetworkMode','Privileged','ReadonlyRootfs','CapAdd','CapDrop','SecurityOpt','PidsLimit','Memory','NanoCpus','Devices','DeviceCgroupRules','Tmpfs']}
  receipt['observed_mounts']=[{key:mount.get(key) for key in ['Type','Source','Destination','RW','Propagation']} for mount in row.get('Mounts',[])]
  if not valid_scope(cfg) or not valid_mounts(row.get('Mounts'),fs):raise RuntimeError('native container scope/mount differs; exact observations retained')
  waited=command(['docker','wait',cid],timeout=30);receipt['native_exit_code']=int(waited.stdout.strip())
  logs=command(['docker','logs',cid],timeout=10)
  if len(logs.stdout)>512*1024 or len(logs.stderr)>512*1024:raise RuntimeError('native metadata log exceeded bounded cap')
  (stage/'stdout.log').write_bytes(logs.stdout);(stage/'stderr.log').write_bytes(logs.stderr)
  text=logs.stdout.decode(errors='replace')+logs.stderr.decode(errors='replace')
  receipt['test_pass']=receipt['native_exit_code']==0 and 'running 1 test' in text and TEST in text and '1 passed; 0 failed' in text and 'native_owned_interfaces_and_routes_absent=true' in text
  if not receipt['test_pass']:raise RuntimeError('native contract failed; retain exact log; no retry')
  return receipt
 except BaseException as error:
  receipt['error']=str(error)[:512]
  raise
 finally:
  cleanup=[]
  if cid:
   try:
    row=own(cid,nonce,args.image)
    if row is not None:
     if row['State']['Running']:command(['docker','stop','--time','5',cid],timeout=10)
     logs=command(['docker','logs',cid],timeout=10,check=False)
     (stage/'stdout.log').write_bytes(logs.stdout[:512*1024]);(stage/'stderr.log').write_bytes(logs.stderr[:512*1024])
     if len(logs.stdout)>512*1024 or len(logs.stderr)>512*1024:cleanup.append('bounded log exceeded cap')
     command(['docker','rm','--volumes',cid],timeout=10)
    receipt['container_absent']=own(cid,nonce,args.image) is None
   except BaseException as error:cleanup.append(str(error)[:256])
  if args.execute and fs.exists() and (not cid or receipt['container_absent']):
   try:
    if fs.is_symlink() or fs.parent!=stage:raise RuntimeError('staging ownership changed')
    shutil.rmtree(fs);receipt['rootfs_removed']=True
   except BaseException as error:cleanup.append(str(error)[:256])
  receipt['cleanup_errors']=cleanup
  (stage/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
  print(json.dumps({'receipt':str(stage/'receipt.json'),'executed':receipt['executed'],'offline_mock_only':receipt['offline_mock_only'],'container_absent':receipt['container_absent'],'rootfs_removed':receipt['rootfs_removed'],'cleanup_errors':cleanup}))
  if cleanup and 'error' not in receipt:raise RuntimeError('native cleanup incomplete; inspect retained receipt')

def self_test():
 cmd=recipe('/tmp/owned-root','a'*32,'sha256:'+'b'*64,'c'*64,'/lib64/ld-linux-x86-64.so.2',['/lib/x86_64-linux-gnu'])
 assert cmd[cmd.index('--network')+1]=='none' and '--privileged' not in cmd and 'SYS_ADMIN' not in cmd and 'host' not in cmd
 assert cmd.count('--cap-add')==2 and '--read-only' in cmd and 'no-new-privileges:true' in cmd
 assert '--device' not in cmd and cmd[cmd.index('--device-cgroup-rule')+1]=='c 10:200 rw'
 assert 'type=bind,source=/dev/net/tun,target=/fixture/dev/net/tun,readonly' in cmd
 assert all(value.endswith(',readonly') for i,value in enumerate(cmd) if i and cmd[i-1]=='--mount')
 assert cmd[-5:]==['--ignored','--exact',TEST,'--nocapture','--test-threads=1']
 assert '--pull=never' in cmd
 assert cmd[cmd.index('--tmpfs')+1]=='/fixture/state:rw,noexec,nosuid,nodev,size=1048576,mode=0700'
 base={'NetworkMode':'none','Privileged':False,'ReadonlyRootfs':True,'CapAdd':['NET_ADMIN','SYS_CHROOT'],'CapDrop':['ALL'],'Devices':[],'DeviceCgroupRules':['c 10:200 rw'],'Tmpfs':{'/fixture/state':'rw,noexec,nosuid,nodev,size=1048576,mode=0700'}}
 assert valid_scope(base) and valid_scope(dict(base,CapAdd=['CAP_NET_ADMIN','CAP_SYS_CHROOT']))
 assert not valid_scope(dict(base,CapAdd=['CAP_NET_ADMIN','CAP_SYS_CHROOT','CAP_SYS_ADMIN']))
 assert not valid_scope(dict(base,CapAdd=['CAP_NET_ADMIN'])) and not valid_scope(dict(base,CapDrop=[]))
 assert not valid_scope(dict(base,DeviceCgroupRules=['c 10:200 rwm'])) and not valid_scope(dict(base,DeviceCgroupRules=['c 10:201 rw']))
 assert not valid_scope(dict(base,Tmpfs={}))
 assert not valid_scope(dict(base,Tmpfs={'/fixture/state':'size=2097152'}))
 assert not valid_scope(dict(base,Devices=[{'PathInContainer':'/fixture/dev/net/tun'}]))
 mounts=[{'Type':'bind','Source':source,'Destination':destination,'RW':False} for destination,source in [('/fixture','/tmp/owned-root'),('/fixture/proc','/proc'),('/fixture/dev/net/tun','/dev/net/tun')]]
 assert valid_mounts(mounts,'/tmp/owned-root')
 assert valid_mounts(mounts+[{'Type':'tmpfs','Destination':'/fixture/state','RW':True}],'/tmp/owned-root')
 assert not valid_mounts(mounts+[{'Type':'bind','Destination':'/fixture/state','RW':True}],'/tmp/owned-root')
 assert not valid_mounts(mounts[:-1]+[dict(mounts[-1],RW=True)],'/tmp/owned-root')
 assert not valid_mounts(mounts[:-1]+[dict(mounts[-1],Source='/dev/null')],'/tmp/owned-root')
 assert not valid_mounts(mounts+[dict(mounts[-1],Destination='/foreign')],'/tmp/owned-root')
 import types
 original_command=globals()['command'];original_dependencies=globals()['dependencies'];original_stat=os.stat
 try:
  for mode in ['success','failure','timeout','inspect_error_live','inspect_error_daemon']:
   state={'exists':False,'nonce':None,'running':True,'stage':None,'mutations':[]};image='sha256:'+'b'*64;cid='d'*64
   def fake(args,timeout=10,check=True):
    if args[:2]==['git','-C']:
     return types.SimpleNamespace(returncode=0,stdout=(b'a'*40+b'\n') if args[-2:]==['rev-parse','HEAD'] else b'',stderr=b'')
    if args[:3]==['docker','image','inspect']:return types.SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':image}]).encode(),stderr=b'')
    if args[:2]==['docker','run']:
     state.update(exists=True,nonce=args[args.index('--name')+1].removeprefix('porthub-sparse-native-'))
     state['stage']=pathlib.Path(args[args.index('--mount')+1].split('source=')[1].split(',')[0]).parent
     return types.SimpleNamespace(returncode=0,stdout=(cid+'\n').encode(),stderr=b'')
    if args[:2]==['docker','ps']:
     return types.SimpleNamespace(returncode=1 if mode=='inspect_error_daemon' else 0,stdout=(cid+'\n').encode() if state['exists'] else b'',stderr=b'injected daemon error' if mode=='inspect_error_daemon' else b'')
    if args[:2]==['docker','inspect']:
     if state['exists'] and mode.startswith('inspect_error'):return types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'injected inspection failure')
     if not state['exists']:return types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'absent')
     row={'Name':'/porthub-sparse-native-'+state['nonce'],'Image':image,'Config':{'Labels':{'porthub.sparse.native.nonce':state['nonce']}},'HostConfig':{'NetworkMode':'none','Privileged':False,'ReadonlyRootfs':True,'CapAdd':['NET_ADMIN','SYS_CHROOT'],'CapDrop':['ALL'],'Devices':[],'DeviceCgroupRules':['c 10:200 rw'],'Tmpfs':{'/fixture/state':'rw,noexec,nosuid,nodev,size=1048576,mode=0700'}},'State':{'Running':state['running']},'Mounts':[{'Type':'bind','Source':source,'Destination':destination,'RW':False} for destination,source in [('/fixture',str(state['stage']/'rootfs')),('/fixture/proc','/proc'),('/fixture/dev/net/tun','/dev/net/tun')]]}
     return types.SimpleNamespace(returncode=0,stdout=json.dumps([row]).encode(),stderr=b'')
    if args[:2]==['docker','wait']:
     if mode=='timeout':raise subprocess.TimeoutExpired(args,timeout)
     state['running']=False;return types.SimpleNamespace(returncode=0,stdout=b'0\n' if mode=='success' else b'1\n',stderr=b'')
    if args[:2]==['docker','logs']:
     text='running 1 test\n'+TEST+'\nnative_owned_interfaces_and_routes_absent=true\ntest result: ok. 1 passed; 0 failed\n' if mode=='success' else 'bounded original native cause\n'
     return types.SimpleNamespace(returncode=0,stdout=text.encode(),stderr=b'')
    if args[:2]==['docker','stop']:state['mutations'].append('stop');state['running']=False;return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    if args[:2]==['docker','rm']:state['mutations'].append('rm');state['exists']=False;return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    raise AssertionError('unreviewed fake command '+repr(args))
   def fake_stat(path,*args,**kwargs):
    if str(path)=='/dev/net/tun':return types.SimpleNamespace(st_mode=stat.S_IFCHR,st_rdev=os.makedev(10,200))
    return original_stat(path,*args,**kwargs)
   globals()['command']=fake;globals()['dependencies']=lambda _: ([], '/lib64/ld-linux-x86-64.so.2');os.stat=fake_stat
   with tempfile.TemporaryDirectory(prefix='porthub-native-outer-offline-') as temporary:
    binary=pathlib.Path(temporary)/'fake-elf';binary.write_bytes(b'\x7fELFoffline mock ONLY')
    failed=False
    try:run(types.SimpleNamespace(binary=str(binary),sha=digest(binary),source='a'*40,image=image,execute=True,offline_mock=True))
    except (RuntimeError,subprocess.TimeoutExpired):failed=True
    assert failed==(mode!='success')
    receipt=json.loads((state['stage']/'receipt.json').read_text());assert receipt['offline_mock_only']
    if mode.startswith('inspect_error'):
     assert state['exists'] and state['running'] and not state['mutations']
     assert receipt['container_absent'] is not True and not receipt['rootfs_removed'] and receipt['cleanup_errors']
     assert (state['stage']/'rootfs').is_dir() and receipt['error']
     # Only this offline mock is discarded after proving the real finally
     # retained a live container's filesystem. No Docker command is executed.
     state['exists']=False
    else:
     assert not state['exists'] and receipt['container_absent'] and receipt['rootfs_removed'] and not receipt['cleanup_errors']
     if mode!='success':assert receipt['error'] and 'bounded original native cause' in (state['stage']/'stdout.log').read_text()
    shutil.rmtree(state['stage'])
 finally:globals()['command']=original_command;globals()['dependencies']=original_dependencies;os.stat=original_stat
 print('offline whole outer 5 PASS: success/native failure/wait timeout/inspect error with live container/daemon error with live container; exact absence or retained rootfs. NO Docker/native execution')
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--self-test',action='store_true');parser.add_argument('--binary');parser.add_argument('--sha');parser.add_argument('--source');parser.add_argument('--image');parser.add_argument('--execute',action='store_true');args=parser.parse_args()
 if args.self_test:self_test()
 else:run(args)
