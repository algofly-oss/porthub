import pathlib,re,json,hashlib,subprocess,base64,unittest,os,shutil,time,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=(ROOT/'crates/porthub-agent/src/keyboard/windows_refresh.rs').read_text()
BOOT=re.search(r'const BOOTSTRAP: &str = r#"(.*?)"#;',source,re.S)[1]
PWSH=os.environ.get('PORTHUB_REFRESH_TEST_POWERSHELL') or shutil.which('powershell.exe') or shutil.which('pwsh')
if not PWSH: raise RuntimeError('PowerShell executable required')
CHILD_ENV={k:v for k,v in os.environ.items() if k.lower() not in ('psmodulepath','psmoduleanalysiscachepath')}
class Bootstrap(unittest.TestCase):
 def run_child(self,text,payload):
  command=base64.b64encode(text.encode('utf-16le')).decode();self.assertLess(len(command),8192)
  started=time.monotonic()
  try:r=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=payload,capture_output=True,timeout=5,env=CHILD_ENV)
  except subprocess.TimeoutExpired as error:
   out=error.stdout or b'';err=error.stderr or b''
   stages=re.findall(r'BOOT_PROBE_[A-Za-z0-9_:]+',err.decode('utf-8',errors='replace'))[:12]
   raise AssertionError(f'PS child deadline: elapsed_ms={int((time.monotonic()-started)*1000)} stdout_bytes={len(out)} stderr_bytes={len(err)} stages={stages}') from None
  r.stdout=r.stdout.decode('utf-8',errors='strict');r.stderr=r.stderr.decode('utf-8',errors='replace');return r
 def test_00_process_startup(self):
  r=self.run_child("[Console]::Write('BOOT_READY')",b'');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'BOOT_READY')
 def test_01_raw_pipe_eof(self):
  text="[Console]::Error.WriteLine('BOOT_PROBE_START');[Console]::Error.WriteLine('BOOT_PROBE_REDIRECTED_'+[Console]::IsInputRedirected);[Console]::Error.WriteLine('BOOT_PROBE_BEFORE_OPEN');$s=[Console]::OpenStandardInput();[Console]::Error.WriteLine('BOOT_PROBE_AFTER_OPEN');[Console]::Error.WriteLine('BOOT_PROBE_BEFORE_ALLOC');$b=[Array]::CreateInstance([byte],2048);[Console]::Error.WriteLine('BOOT_PROBE_AFTER_ALLOC');[Console]::Error.WriteLine('BOOT_PROBE_BEFORE_READ');$n=$s.Read($b,0,$b.Length);[Console]::Error.WriteLine('BOOT_PROBE_FIRST_'+$n);$end=$s.Read($b,0,$b.Length);[Console]::Error.WriteLine('BOOT_PROBE_EOF_'+$end);[Console]::Write('read='+$n+';eof='+$end)"
  r=self.run_child(text,b'probe');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'read=5;eof=0')
 def run_packet(self,script,request=None,expected=None,raw=None):
  digest=expected or hashlib.sha256(script.encode()).hexdigest();text=BOOT.replace('__SCRIPT_SHA256__',digest)
  packet=raw if raw is not None else json.dumps({'script':script,'request':request or {'value':'inert'}})
  payload=packet.encode('utf-8')
  try:return self.run_child(text,payload)
  except AssertionError:
   self.trace_failed_bootstrap(text,payload)
   raise
 def trace_failed_bootstrap(self,text,payload):
  # Test-only replay NEVER replaces the original uninstrumented failure.
  markers=[
   ('$buffer=', 'BEFORE_ALLOC'),
   ('$inputStream=[Console]::OpenStandardInput()', 'BEFORE_OPEN'),
   ('try{\n while(', 'BEFORE_READ'),
   ('$utf8=', 'AFTER_EOF'),
   ('[Console]::OutputEncoding=', 'BEFORE_OUTPUT_ENCODING'),
   ('$packet=$json|ConvertFrom-Json', 'BEFORE_JSON'),
   ("if($packet -isnot", 'AFTER_JSON'),
   ('$hash=[Security.Cryptography.SHA256]', 'BEFORE_HASH'),
   ("if($digest -cne", 'BEFORE_DIGEST_GUARD')]
  trace="[Console]::Error.WriteLine('BOOT_STAGE_ENTRY');"+text
  for anchor,label in markers:
   if trace.count(anchor)!=1:raise AssertionError('Diagnostic anchor mismatch')
   trace=trace.replace(anchor,"[Console]::Error.WriteLine('BOOT_STAGE_"+label+"');"+anchor,1)
  command=base64.b64encode(trace.encode('utf-16le')).decode();self.assertLess(len(command),8192)
  code=None;timed_out=False
  try:
   result=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=payload,capture_output=True,timeout=5,env=CHILD_ENV);out,err=result.stdout,result.stderr;code=result.returncode
  except subprocess.TimeoutExpired as error:out,err=error.stdout or b'',error.stderr or b'';timed_out=True
  stages=re.findall(r'BOOT_STAGE_[A-Z_]+',err.decode('utf-8',errors='replace'))[:16]
  print('BOOT_DIAGNOSTIC_ONLY '+json.dumps({'timeout':timed_out,'returncode':code,'stdout_bytes':len(out),'stderr_bytes':len(err),'stages':stages}),file=sys.stderr)
 def test_success_real_child_large_script_small_argv(self):
  script=('# inert padding 摄影机\n'*1800)+"\nfunction Invoke-PortHubDesktopRefresh($Request){return @{ok=$true;value=$Request.value}}"
  r=self.run_packet(script,request={'value':r'C:\Users\测试\PortHub®'});self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),{'ok':True,'value':r'C:\Users\测试\PortHub®'})
 def test_hash_mismatch(self):
  r=self.run_packet("throw 'must never execute'",expected='0'*64);self.assertNotEqual(r.returncode,0);self.assertIn('digest mismatch',r.stderr)
 def test_input_bound(self):
  r=self.run_packet('',raw=' '*131073);self.assertNotEqual(r.returncode,0);self.assertIn('input exceeds bounds',r.stderr)
 def test_script_bound(self):
  r=self.run_packet(' '*49153);self.assertNotEqual(r.returncode,0);self.assertIn('Invalid desktop refresh envelope',r.stderr)
 def test_unknown_envelope_field(self):
  r=self.run_packet('',raw=json.dumps({'script':'','request':{},'other':True}));self.assertNotEqual(r.returncode,0);self.assertIn('Invalid desktop refresh envelope',r.stderr)
 def test_invalid_utf8(self):
  text=BOOT.replace('__SCRIPT_SHA256__','0'*64)
  r=self.run_child(text,b'\xff');self.assertNotEqual(r.returncode,0)
 def test_actual_source_bound_and_pin(self):
  script=(ROOT/'crates/porthub-agent/src/keyboard/windows_refresh.ps1').read_text()
  text=BOOT.replace('__SCRIPT_SHA256__',hashlib.sha256(script.encode()).hexdigest());self.assertLess(len(base64.b64encode(text.encode('utf-16le'))),8192);self.assertLess(len(script),49152)
if __name__=='__main__':unittest.main(verbosity=2,failfast=True)
