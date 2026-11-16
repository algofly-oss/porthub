import pathlib,re,json,hashlib,subprocess,base64,unittest,os,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=(ROOT/'crates/porthub-agent/src/keyboard/windows_refresh.rs').read_text()
BOOT=re.search(r'const BOOTSTRAP: &str = r#"(.*?)"#;',source,re.S)[1]
PWSH=os.environ.get('PORTHUB_REFRESH_TEST_POWERSHELL') or shutil.which('powershell.exe') or shutil.which('pwsh')
if not PWSH: raise RuntimeError('PowerShell executable required')
CHILD_ENV={k:v for k,v in os.environ.items() if k.lower() not in ('psmodulepath','psmoduleanalysiscachepath')}
class Bootstrap(unittest.TestCase):
 def run_packet(self,script,request=None,expected=None,raw=None):
  digest=expected or hashlib.sha256(script.encode()).hexdigest();text=BOOT.replace('__SCRIPT_SHA256__',digest)
  command=base64.b64encode(text.encode('utf-16le')).decode();self.assertLess(len(command),8192)
  packet=raw if raw is not None else json.dumps({'script':script,'request':request or {'value':'inert'}})
  return subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=packet,text=True,encoding='utf-8',capture_output=True,timeout=5,env=CHILD_ENV)
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
  text=BOOT.replace('__SCRIPT_SHA256__','0'*64);command=base64.b64encode(text.encode('utf-16le')).decode()
  r=subprocess.run([PWSH,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',command],input=b'\xff',capture_output=True,timeout=5,env=CHILD_ENV);self.assertNotEqual(r.returncode,0)
 def test_actual_source_bound_and_pin(self):
  script=(ROOT/'crates/porthub-agent/src/keyboard/windows_refresh.ps1').read_text()
  text=BOOT.replace('__SCRIPT_SHA256__',hashlib.sha256(script.encode()).hexdigest());self.assertLess(len(base64.b64encode(text.encode('utf-16le'))),8192);self.assertLess(len(script),49152)
if __name__=='__main__':unittest.main(verbosity=2)
