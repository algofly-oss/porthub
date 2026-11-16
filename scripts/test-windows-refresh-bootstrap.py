import pathlib,re,json,hashlib,subprocess,base64,unittest,os,shutil,time,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=(ROOT/'crates/porthub-agent/src/keyboard/windows_refresh.rs').read_text()
BOOT=re.search(r'const BOOTSTRAP: &str = r#"(.*?)"#;',source,re.S)[1]
PWSH=os.environ.get('PORTHUB_REFRESH_TEST_POWERSHELL') or shutil.which('powershell.exe') or shutil.which('pwsh')
if not PWSH: raise RuntimeError('PowerShell executable required')
# Hosted ARM PS5 cold start took 5.518s; a digest-reject child took 5.156s.
# Bound test children at 10s; production refresh retains its independent 120s limit.
CHILD_TIMEOUT_SECONDS=10
CHILD_ENV={k:v for k,v in os.environ.items() if k.lower() not in ('psmodulepath','psmoduleanalysiscachepath')}
def diagnostic_utility_probe(mode,budget):
 # Metadata only: fixed JSON, numeric timing, trusted OS module origin. Never a PASS substitute.
 prefix="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::Error.WriteLine('UTILITY_PROBE_ENTRY');$watch=[Diagnostics.Stopwatch]::StartNew();"
 if mode=='explicit':
  prefix+="$module=[IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1');[Console]::Error.WriteLine('UTILITY_PROBE_BEFORE_IMPORT');Import-Module -Name $module -ErrorAction Stop;[Console]::Error.WriteLine('UTILITY_PROBE_AFTER_IMPORT');"
 text=prefix+"[Console]::Error.WriteLine('UTILITY_PROBE_BEFORE_UTILITY');$parsed=ConvertFrom-Json -InputObject '{\"ok\":true}';[Console]::Error.WriteLine('UTILITY_PROBE_AFTER_UTILITY');[Console]::WriteLine('UTILITY_ELAPSED_MS:'+ $watch.ElapsedMilliseconds);[Console]::WriteLine('UTILITY_JSON_VALID:'+($parsed.ok -is [bool] -and $parsed.ok));[Console]::WriteLine('UTILITY_ORIGIN:'+(Get-Command ConvertFrom-Json).Module.Path)"
 command=base64.b64encode(text.encode('utf-16le')).decode();started=time.monotonic();timed=False;code=None
 try:
  result=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=b'',capture_output=True,timeout=budget,env=CHILD_ENV);out,err=result.stdout,result.stderr;code=result.returncode
 except subprocess.TimeoutExpired as error:out,err=error.stdout or b'',error.stderr or b'';timed=True
 output=out[:16384].decode('utf-8',errors='replace');errors=err[:16384].decode('utf-8',errors='replace')
 origins=re.findall(r'^UTILITY_ORIGIN:([^\r\n]{0,512})\r?$',output,re.M)
 elapsed=re.findall(r'^UTILITY_ELAPSED_MS:([0-9]{1,9})\r?$',output,re.M)
 valid=re.findall(r'^UTILITY_JSON_VALID:(True|False)\r?$',output,re.M)
 print('UTILITY_DIAGNOSTIC_ONLY '+json.dumps({'mode':mode,'timeout':timed,'deadline_seconds':round(budget,3),'wall_ms':int((time.monotonic()-started)*1000),'returncode':code,'stdout_bytes':len(out),'stderr_bytes':len(err),'stages':re.findall(r'UTILITY_PROBE_[A-Z_]+',errors)[:8],'module_origin':origins[0] if origins else None,'utility_elapsed_ms':int(elapsed[0]) if elapsed else None,'fixed_json_valid':valid[0]=='True' if valid else None}),file=sys.stderr)

class Bootstrap(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('PORTHUB_REFRESH_UTILITY_DIAGNOSTICS')!='1':return
  # Two independent diagnostics share <60s budget; nine strict test children retain bounded 10s deadlines.
  end=time.monotonic()+58
  for mode in ('autoload','explicit'):
   diagnostic_utility_probe(mode,min(29,max(1,end-time.monotonic()-1)))
 def run_child(self,text,payload):
  command=base64.b64encode(text.encode('utf-16le')).decode();self.assertLess(len(command),8192)
  started=time.monotonic()
  try:r=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=payload,capture_output=True,timeout=CHILD_TIMEOUT_SECONDS,env=CHILD_ENV)
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
   ('Import-Module -Name $utility', 'BEFORE_UTILITY_IMPORT'),
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
   result=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=payload,capture_output=True,timeout=CHILD_TIMEOUT_SECONDS,env=CHILD_ENV);out,err=result.stdout,result.stderr;code=result.returncode
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
