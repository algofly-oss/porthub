#!/usr/bin/env python3
"""Opt-in native VM gate. Never run on a personal/self-hosted machine.
Default/source validation performs NO network/device/configuration operations.
The exact ignored tests use production adapter/route/resolver implementations.
"""
import argparse, hashlib, importlib.util, json, os, pathlib, platform, re, shutil, signal, subprocess, sys, tempfile, threading, time, uuid
PURPOSE='reviewed-disposable-sparse-lifecycle-v1'
COMMAND_DEADLINE=None
INPUTS=['Cargo.lock','rust-toolchain.toml','crates/porthub-agent/Cargo.toml',
 'scripts/private-sparse-native-lifecycle.py','scripts/private-sparse-native-netns.py',
 *['crates/porthub-agent/src/private_network/'+name for name in ['native_lifecycle_fixture.rs','native_desktop_lifecycle_fixture.rs','native_resolver_lifecycle_fixture.rs','device.rs','device_windows.rs','device_macos.rs','dns.rs','dns_windows.rs','windows_nrpt.rs','windows_nrpt.ps1','windows_state.rs','native_ownership.rs','stream_offer.rs']],
 'crates/porthub-agent/assets/wintun/amd64/wintun.dll']
TESTS={
 'linux':['private_network::native_resolver_lifecycle_fixture::linux_real_resolver_suffix_replace_and_native_owner_teardown'],
 'windows':['private_network::dns_windows::tests::native_same_account_reuse_cannot_bind_dns_endpoint','private_network::dns_windows::tests::native_foreign_udp_or_tcp_listener_prevents_dns_bind_without_takeover','private_network::native_desktop_lifecycle_fixture::native_interface_resolver_collision_connected_owner_and_drop'],
 'macos':['private_network::native_desktop_lifecycle_fixture::native_interface_resolver_collision_connected_owner_and_drop'],
}
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as stream:
  for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
class CommandError(RuntimeError):
 def __init__(self,message,stdout=b'',stderr=b'',returncode=None):
  super().__init__(message);self.stdout=stdout;self.stderr=stderr;self.returncode=returncode

def windows_job(child):
 """Assign held child before parent releases the fixture's no-mutation gate."""
 import ctypes as c
 from ctypes import wintypes as w
 class Basic(c.Structure):_fields_=[('process_time',c.c_int64),('job_time',c.c_int64),('flags',w.DWORD),('min_ws',c.c_size_t),('max_ws',c.c_size_t),('active',w.DWORD),('affinity',c.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
 class Io(c.Structure):_fields_=[(name,c.c_uint64) for name in ['read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes']]
 class Extended(c.Structure):_fields_=[('basic',Basic),('io',Io),('process_memory',c.c_size_t),('job_memory',c.c_size_t),('peak_process',c.c_size_t),('peak_job',c.c_size_t)]
 api=c.WinDLL('kernel32',use_last_error=True);api.CreateJobObjectW.argtypes=[c.c_void_p,w.LPCWSTR];api.CreateJobObjectW.restype=w.HANDLE
 api.SetInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD];api.SetInformationJobObject.restype=w.BOOL
 api.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE];api.AssignProcessToJobObject.restype=w.BOOL
 api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle.restype=w.BOOL
 handle=api.CreateJobObjectW(None,None)
 if not handle:raise RuntimeError('cannot create owned bounded child job')
 info=Extended();info.basic.flags=0x2000
 if not api.SetInformationJobObject(handle,9,c.byref(info),c.sizeof(info)) or not api.AssignProcessToJobObject(handle,w.HANDLE(int(child._handle))):
  api.CloseHandle(handle);raise RuntimeError('cannot bind exact child to owned kill-on-close job')
 return lambda:api.CloseHandle(handle)

def run(argv,*,env=None,seconds=15,cap=1048576,cwd=None,on_started=None):
 """Continuously drain both pipes; hard combined bytes/deadline, held child only."""
 if COMMAND_DEADLINE is not None:
  seconds=min(seconds,COMMAND_DEADLINE-time.monotonic())
  if seconds<=0:raise RuntimeError('outer command budget exhausted before spawn')
 flags={'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {'start_new_session':True}
 child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=cwd,**flags)
 close_job=None
 try:
  if os.name=='nt':close_job=windows_job(child)
  if on_started:on_started(child)
 except BaseException:
  child.kill();child.wait(timeout=5)
  for pipe in [child.stdout,child.stderr]:pipe.close()
  if close_job:close_job()
  raise
 chunks=[bytearray(),bytearray()];lock=threading.Lock();overflow=threading.Event()
 def drain(pipe,index):
  try:
   while True:
    block=pipe.read(8192)
    if not block:break
    with lock:
     left=cap-len(chunks[0])-len(chunks[1]);chunks[index].extend(block[:max(left,0)])
     if len(block)>left:overflow.set()
  finally:pipe.close()
 readers=[threading.Thread(target=drain,args=(pipe,i),daemon=True) for i,pipe in enumerate((child.stdout,child.stderr))]
 for thread in readers:thread.start()
 reason=None;start=time.monotonic()
 try:
  while child.poll() is None:
   if overflow.is_set():reason='bounded child output exceeded';break
   if time.monotonic()-start>seconds:reason='bounded child deadline exceeded';break
   time.sleep(.01)
 finally:
  if child.poll() is None:
   if os.name=='nt':child.kill()
   else:os.killpg(child.pid,signal.SIGKILL)
  child.wait(timeout=5)
  if close_job:close_job()
  for thread in readers:thread.join(timeout=2)
  if any(thread.is_alive() for thread in readers):raise RuntimeError('owned child pipe readers did not reap')
 if reason or overflow.is_set():raise CommandError(reason or 'bounded child output exceeded',bytes(chunks[0]),bytes(chunks[1]),child.returncode)
 if child.returncode:raise CommandError('child failed '+str(child.returncode)+': '+chunks[1].decode(errors='replace')[:512],bytes(chunks[0]),bytes(chunks[1]),child.returncode)
 return chunks[0].decode(errors='strict')
def ps(code,seconds=20):
 import base64
 executable=pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 code="[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;"+code
 return run([str(executable),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],seconds=seconds)
def windows_snapshot():
 # Stable configuration only: do not compare byte/packet counters or live ages.
 code=r'''$ErrorActionPreference='Stop';$o=[ordered]@{
 adapters=@(Get-NetAdapter -IncludeHidden|Sort-Object InterfaceGuid|Select-Object Name,InterfaceGuid,ifIndex,Status);
 addresses=@(Get-NetIPAddress -AddressFamily IPv4|Sort-Object InterfaceIndex,IPAddress|Select-Object InterfaceIndex,IPAddress,PrefixLength);
 routes=@(Get-NetRoute -AddressFamily IPv4|Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric);
 dns_servers=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses);
 dns_clients=@(Get-DnsClient|Sort-Object InterfaceIndex|Select-Object InterfaceIndex,ConnectionSpecificSuffix,RegisterThisConnectionsAddress,UseSuffixWhenRegistering);
 global_dns=@(Get-DnsClientGlobalSetting|Select-Object SuffixSearchList,UseDevolution,DevolutionLevel);
 nrpt=@(Get-DnsClientNrptRule|Sort-Object Name|ForEach-Object{if($null -eq $_.CimInstanceProperties){throw 'Unknown NRPT metadata shape'};$r=[ordered]@{};foreach($p in ($_.CimInstanceProperties|Sort-Object Name)){$r[$p.Name]=$p.Value};[pscustomobject]$r});
 effective_nrpt=@(Get-DnsClientNrptPolicy -Effective|Sort-Object Namespace|ForEach-Object{if($null -eq $_.CimInstanceProperties){throw 'Unknown effective NRPT metadata shape'};$r=[ordered]@{};foreach($p in ($_.CimInstanceProperties|Sort-Object Name)){$r[$p.Name]=$p.Value};[pscustomobject]$r});
 };$o|ConvertTo-Json -Depth 8 -Compress'''
 return json.loads(ps(code))
def file_snapshot(root):
 root=pathlib.Path(root)
 if not root.exists():return {}
 result={}
 for path in root.iterdir():
  if path.is_symlink():result[path.name]={'symlink':os.readlink(path)}
  elif path.is_file():result[path.name]={'sha256':sha(path),'mode':path.stat().st_mode&0o777,'uid':path.stat().st_uid,'gid':path.stat().st_gid}
  else:result[path.name]={'other':True}
 return result
def unix_snapshot(contract):
 if contract=='macos':
  routes=run(['/usr/sbin/netstat','-rn','-f','inet'])
  normalized=sorted(' '.join(line.split()[:4]) for line in routes.splitlines() if line and line[0].isdigit())
  return {'routes':normalized,'resolver_files':file_snapshot('/etc/resolver'),'dns':run(['/usr/sbin/scutil','--dns'])}
 routes=json.loads(run(['/usr/sbin/ip','-j','-4','route','show','table','all']))
 for row in routes:row.pop('cache',None);row.pop('expires',None)
 return {'routes':sorted(routes,key=lambda r:json.dumps(r,sort_keys=True)),'resolver_dns':run(['/usr/bin/resolvectl','dns']),'resolver_domains':run(['/usr/bin/resolvectl','domain']),'resolv_conf_sha256':sha('/etc/resolv.conf')}
def exact_executable(build):
 found=[]
 for line in pathlib.Path(build).read_text().splitlines():
  try:row=json.loads(line)
  except ValueError:continue
  if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='porthub_agent' and row.get('profile',{}).get('test') and row.get('executable'):found.append(pathlib.Path(row['executable']).resolve(strict=True))
 if len(set(found))!=1:raise RuntimeError('expected one actual native agent lib-test executable')
 binary=found[0]
 if not binary.is_file() or binary.stat().st_size>256*1024*1024:raise RuntimeError('native test executable invalid')
 return binary
def source_guard(contract):
 root=pathlib.Path(__file__).resolve().parents[1]
 fixture=root/'crates/porthub-agent/src/private_network'/('native_resolver_lifecycle_fixture.rs' if contract=='linux' else 'native_desktop_lifecycle_fixture.rs')
 if not fixture.is_file():raise RuntimeError('actual native fixture source absent')
 if not re.search(r'const NATIVE_LIFECYCLE_APPROVED:\s*bool\s*=\s*false\s*;',fixture.with_name('stream_offer.rs').read_text()):raise RuntimeError('native production approval must remain false during fixture validation')
 for name in TESTS[contract]:
  leaf=name.split('::')[-1]
  source=fixture if 'dns_windows' not in name else fixture.with_name('dns_windows.rs')
  if 'async fn '+leaf not in source.read_text():raise RuntimeError('exact native test absent: '+name)
 return root

def netns_gate(root,binary,receipt_dir,seconds,cleanup_deadline):
 """Import an empty local image; no registry/network or host network mutation."""
 global COMMAND_DEADLINE
 execution_deadline=COMMAND_DEADLINE;netns_deadline=min(execution_deadline,time.monotonic()+seconds)
 spec=importlib.util.spec_from_file_location('private_sparse_netns',root/'scripts/private-sparse-native-netns.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 original_command=module.command
 def bounded_netns_command(argv,timeout=10,check=True):
  cleanup=argv[:2] in [['docker','inspect'],['docker','stop'],['docker','rm'],['docker','logs']]
  remaining=(cleanup_deadline if cleanup else netns_deadline)-time.monotonic()
  if remaining<=0:raise RuntimeError('netns command budget exhausted before spawn')
  return original_command(argv,timeout=min(timeout,remaining),check=check)
 module.command=bounded_netns_command
 nonce=uuid.uuid4().hex;image=None;stage=pathlib.Path('/tmp/porthub-sparse-native-'+nonce)
 receipt={'nonce':nonce,'image_absent':False,'container_absent':False};error=None
 try:
  import tarfile
  with tempfile.TemporaryDirectory(prefix='porthub-sparse-empty-image-') as temp:
   archive=pathlib.Path(temp)/'empty.tar'
   with tarfile.open(archive,'w'):pass
   image=run(['docker','import','--change','LABEL porthub.sparse.native.nonce='+nonce,str(archive),'porthub-sparse-native:'+nonce],seconds=20).strip()
  if not re.fullmatch('sha256:[0-9a-f]{64}',image):raise RuntimeError('local native image identity invalid')
  row=json.loads(run(['docker','image','inspect',image]))[0]
  if row['Id']!=image or row['Config']['Labels'].get('porthub.sparse.native.nonce')!=nonce:raise RuntimeError('local native image binding changed')
  receipt['image']=image
  module.run(argparse.Namespace(binary=str(binary),sha=sha(binary),source=run(['git','-c','safe.directory='+str(root),'rev-parse','HEAD'],cwd=root).strip(),image=image,execute=True,nonce=nonce))
 except BaseException as failure:error=failure
 finally:
  COMMAND_DEADLINE=cleanup_deadline
  try:
   proof=stage/'receipt.json'
   if proof.exists():
    value=json.loads(proof.read_text());receipt['container_absent']=value.get('container_absent') is True
    for name in ['receipt.json','stdout.log','stderr.log']:
     source=stage/name
     if source.exists():shutil.copyfile(source,receipt_dir/('linux-netns-'+name))
    if not value.get('container_absent') or not value.get('rootfs_removed'):raise RuntimeError('netns independent cleanup failed; stage retained')
    if {p.name for p in stage.iterdir()}-{'receipt.json','stdout.log','stderr.log'}:raise RuntimeError('unexpected own netns stage entries; retained')
    shutil.rmtree(stage)
   if image:
    row=json.loads(run(['docker','image','inspect',image]))[0]
    if row['Id']!=image or row['Config']['Labels'].get('porthub.sparse.native.nonce')!=nonce or row.get('RepoTags')!=['porthub-sparse-native:'+nonce]:raise RuntimeError('refusing changed image cleanup')
    if run(['docker','ps','-aq','--filter','ancestor='+image]).strip():raise RuntimeError('image still has container users; no force removal')
    run(['docker','image','rm',image])
    remaining=run(['docker','image','ls','--no-trunc','--format','{{.ID}}']).splitlines()
    if image in remaining:raise RuntimeError('owned image still present after removal')
    receipt['image_absent']=True
  except BaseException as failure:
   receipt['cleanup_error']=str(failure)[:512]
   if error is None:error=failure
  (receipt_dir/'linux-netns-image-cleanup.json').write_text(json.dumps(receipt,indent=2)+'\n')
  COMMAND_DEADLINE=execution_deadline
 if error:raise error
 if not receipt['container_absent'] or not receipt['image_absent']:raise RuntimeError('netns gate did not prove exact cleanup')

def execute(args):
 global COMMAND_DEADLINE
 root=source_guard(args.contract)
 expected={'linux':'Linux','macos':'Darwin','windows':'Windows'}[args.contract]
 if platform.system()!=expected or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or args.purpose!=PURPOSE:raise RuntimeError('requires explicitly reviewed disposable hosted OS runner')
 if not 90<=args.outer_timeout_seconds<=180 or not 4096<=args.log_cap_bytes<=1048576:raise RuntimeError('unsafe outer limits')
 if args.contract!='windows' and os.geteuid()!=0:raise RuntimeError('native outer must run as disposable VM root')
 binary=exact_executable(args.build_json);binary_sha=sha(binary)
 listed=run([str(binary),'--list'],seconds=15)
 for test in TESTS[args.contract]:
  if test+': test' not in listed:raise RuntimeError('native test missing from actual executable: '+test)
 nonce=uuid.uuid4().hex;receipt_dir=root/'private-sparse-native-receipts';receipt_dir.mkdir(exist_ok=True)
 receipt={'purpose':PURPOSE,'contract':args.contract,'nonce':nonce,'source':run(['git','-c','safe.directory='+str(root),'rev-parse','HEAD'],cwd=root).strip(),'exe_sha256':binary_sha,'tests':[],'native_executed':False,'cleanup_complete':False,'driver_package_scope':('signed bundled Wintun may remain in disposable VM driver store; no global driver removal' if args.contract=='windows' else None),'error':None,'offline_mock_only':bool(getattr(args,'offline_mock_only',False))}
 receipt['inputs']={name:sha(root/name) for name in INPUTS}
 stage=None;managed_created=False;hard_deadline=time.monotonic()+args.outer_timeout_seconds;deadline=hard_deadline-60
 prior_deadline=COMMAND_DEADLINE;COMMAND_DEADLINE=deadline
 receipt['outer_budget_seconds']=args.outer_timeout_seconds;receipt['cleanup_reserve_seconds']=60
 try:
  if args.contract=='windows':
   if ps("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)").strip()!='True':raise RuntimeError('native Wintun test requires existing elevated runner token')
   baseline=windows_snapshot();managed=pathlib.Path(os.environ['ProgramData'])/'PortHub'
   if managed.exists():raise RuntimeError('managed PortHub root preexists; refusing native test/adoption')
   managed.mkdir();managed_created=True;stage=managed/('native-lifecycle-'+nonce);stage.mkdir()
  else:
   baseline=unix_snapshot(args.contract)
   if args.contract=='linux' and not getattr(args,'offline_mock_only',False):
    netns_gate(root,binary,receipt_dir,min(60,deadline-time.monotonic()),hard_deadline-10)
   stage=pathlib.Path('/private/var/tmp' if args.contract=='macos' else tempfile.gettempdir())/('native-lifecycle-'+nonce);stage.mkdir(mode=0o700)
  receipt['baseline']=baseline;receipt['stage']=str(stage)
  profile={'server':'https://native-fixture.invalid','workspace':'native-fixture-'+nonce,'peer_id':'native-fixture-'+nonce,'token':'fixture-no-network-credential'}
  for name in ['profile.json','foreign.json']:
   value=dict(profile);value['peer_id']+=('-foreign' if name=='foreign.json' else '')
   (stage/name).write_text(json.dumps(value));(stage/name).chmod(0o600)
  purpose='reviewed-disposable-resolved-v1' if args.contract=='linux' else 'reviewed-disposable-desktop-v1'
  spec={'authorization':purpose,'nonce':nonce}
  if args.contract!='linux':spec['profile']=str(stage/'profile.json')
  (stage/'spec.json').write_text(json.dumps(spec));(stage/'spec.json').chmod(0o600)
  if args.contract=='windows':
   # Fresh private managed root only. No inherited/foreign principal adoption.
   for path in [managed,stage,*stage.iterdir()]:
    run(['icacls',str(path),'/inheritance:r','/grant:r','*S-1-5-18:(F)','*S-1-5-32-544:(F)','/setowner','*S-1-5-32-544'],seconds=15)
  env=os.environ.copy();env.update(PORTHUB_SPARSE_NATIVE_FIXTURE=purpose,PORTHUB_SPARSE_NATIVE_SPEC=str(stage/'spec.json'),PORTHUB_SPARSE_NATIVE_SPEC_SHA256=sha(stage/'spec.json'),PORTHUB_TEST_DISPOSABLE_WINDOWS_DNS='1',RUST_LOG='off',RUST_BACKTRACE='0')
  for test in TESTS[args.contract]:
   gate=stage/'start.gate'
   if gate.exists():gate.unlink()
   if sha(binary)!=binary_sha or any(sha(root/name)!=expected for name,expected in receipt['inputs'].items()):raise RuntimeError('native executable or source input changed')
   remaining=deadline-time.monotonic()
   if remaining<10:raise RuntimeError('outer budget insufficient for another native test')
   receipt['native_executed']=True;receipt.setdefault('attempted_tests',[]).append(test)
   text=run([str(binary),'--exact',test,'--ignored','--nocapture','--test-threads=1'],env=env,seconds=min(100,remaining),cap=args.log_cap_bytes,on_started=lambda child:gate.write_text(nonce))
   (receipt_dir/(args.contract+'-'+test.split('::')[-1]+'.log')).write_text(text)
   if 'running 1 test' not in text or '1 passed; 0 failed' not in text:raise RuntimeError('native exact test did not pass one case')
   receipt['native_executed']=True;receipt['tests'].append({'test':test,'passed':True,'log_sha256':hashlib.sha256(text.encode()).hexdigest()})
 except BaseException as error:
  receipt['error']=str(error)[:512]
  if isinstance(error,CommandError):
   (receipt_dir/(args.contract+'-failed-child.stdout.log')).write_bytes(error.stdout)
   (receipt_dir/(args.contract+'-failed-child.stderr.log')).write_bytes(error.stderr)
 finally:
  COMMAND_DEADLINE=hard_deadline-10
  errors=[]
  try:
   until=time.monotonic()+5
   while True:
    after=windows_snapshot() if args.contract=='windows' else unix_snapshot(args.contract)
    if 'baseline' not in receipt or after==receipt['baseline'] or time.monotonic()>=until:break
    time.sleep(.05)
   receipt['after']=after
   if 'baseline' in receipt and after!=receipt['baseline']:raise RuntimeError('independent native baseline differs; preserve owned journals for exact repair')
   receipt['foreign_configuration_unchanged']=True
  except BaseException as error:errors.append(str(error)[:512])
  # Never delete recovery journals while OS entries remain or baseline differs.
  if not errors and stage:
   try:
    if args.contract=='windows':
     allowed={'profile.json','foreign.json','spec.json','profile.json.wintun-ownership.json','foreign.json.wintun-ownership.json','profile.json.wintun-ownership.json.lock','foreign.json.wintun-ownership.json.lock','start.gate','profile.json.nrpt-ownership.json','profile.json.nrpt-ownership.json.lock'}
     unexpected={p.name for p in stage.iterdir()}-allowed
     if unexpected:raise RuntimeError('unexpected stage files; no broad cleanup: '+','.join(sorted(unexpected)))
    shutil.rmtree(stage);receipt['stage_absent']=not stage.exists()
   except BaseException as error:errors.append(str(error)[:512])
  if managed_created and not errors:
   try:
    # Bundled driver is the only allowed new canonical runtime file. Never
    # remove a driver package, service, registration, or unexpected root entry.
    allowed={managed/'drivers',managed/'drivers'/'wintun.dll'}
    actual=set(managed.rglob('*'))
    if not actual.issubset(allowed) or any(p.is_symlink() for p in actual):raise RuntimeError('unexpected managed root contents; preserve')
    driver=managed/'drivers'/'wintun.dll'
    expected=root/'crates/porthub-agent/assets/wintun/amd64/wintun.dll'
    if driver.exists() and sha(driver)!=sha(expected):raise RuntimeError('bundled runtime driver hash changed; preserve')
    shutil.rmtree(managed);receipt['managed_root_absent']=not managed.exists()
   except BaseException as error:errors.append(str(error)[:512])
  receipt['cleanup_errors']=errors;receipt['cleanup_complete']=not errors and receipt.get('stage_absent',stage is None)
  (receipt_dir/(args.contract+'-receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
  COMMAND_DEADLINE=prior_deadline
 if receipt['error'] or not receipt['cleanup_complete']:raise RuntimeError(receipt['error'] or 'native independent cleanup failed')
 print(json.dumps({'contract':args.contract,'native_cases':len(receipt['tests']),'cleanup_complete':True,'offline_mock_only':receipt['offline_mock_only']}))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--contract',choices=TESTS,required=True);parser.add_argument('--validate-source-only',action='store_true');parser.add_argument('--build-json');parser.add_argument('--purpose');parser.add_argument('--outer-timeout-seconds',type=int,default=180);parser.add_argument('--log-cap-bytes',type=int,default=1048576);args=parser.parse_args()
 if args.validate_source_only:source_guard(args.contract);print('actual fixture source present; no native operations');return
 if not args.build_json:parser.error('explicit build JSON required')
 execute(args)
if __name__=='__main__':main()
