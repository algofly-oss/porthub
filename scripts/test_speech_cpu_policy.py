#!/usr/bin/env python3
"""Exercise policy output and actual CMake replacement of a previously native cache."""
import pathlib, subprocess, tempfile, unittest, shutil, re
ROOT=pathlib.Path(__file__).resolve().parents[1]
X86_OFF={'GGML_NATIVE','GGML_SSE42','GGML_AVX','GGML_AVX_VNNI','GGML_AVX2','GGML_BMI2','GGML_FMA','GGML_F16C','GGML_AVX512','GGML_AVX512_VBMI','GGML_AVX512_VNNI','GGML_AVX512_BF16','GGML_AMX_TILE','GGML_AMX_INT8','GGML_AMX_BF16'}
def args(target):return subprocess.check_output(['sh',str(ROOT/'scripts/speech-cpu-policy.sh'),target],text=True).split()
class Policy(unittest.TestCase):
 def test_both_x86_targets_use_same_explicit_baseline(self):
  left=args('x86_64-unknown-linux-gnu');self.assertEqual(left,args('x86_64-unknown-linux-musl'))
  self.assertEqual(set(left),{'-D'+key+'=OFF' for key in X86_OFF}|{'-DTRANSCRIBE_X86_CONSERVATIVE=ON'})
 def test_arm_floor_preserved(self):self.assertEqual(args('aarch64-unknown-linux-musl'),['-DGGML_NATIVE=OFF','-DGGML_CPU_ARM_ARCH=armv8-a'])
 def test_unsupported_target_cannot_silently_use_host(self):
  p=subprocess.run(['sh',str(ROOT/'scripts/speech-cpu-policy.sh'),'unexpected'],capture_output=True,text=True);self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,'')
 def test_real_cmake_reconfiguration_replaces_all_cached_on_values(self):
  self.assertTrue(shutil.which('cmake'),'CMake is required for the native-cache regression')
  with tempfile.TemporaryDirectory(prefix='porthub-cpu-policy-') as tmp:
   source=pathlib.Path(tmp)/'source';build=pathlib.Path(tmp)/'build';source.mkdir()
   (source/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.16)\nproject(policy NONE)\n'+''.join('option('+key+' "cached ISA option" ON)\n' for key in sorted(X86_OFF)))
   command=['cmake','-S',str(source),'-B',str(build)]
   subprocess.run(command,check=True,capture_output=True)
   def cache():return dict(re.findall(r'^([A-Z0-9_]+):[^=]+=([^\n]*)$',(build/'CMakeCache.txt').read_text(),re.M))
   self.assertTrue(all(cache()[key]=='ON' for key in X86_OFF))
   subprocess.run(command+args('x86_64-unknown-linux-gnu'),check=True,capture_output=True)
   self.assertTrue(all(cache()[key]=='OFF' for key in X86_OFF))
   self.assertEqual(cache()['TRANSCRIBE_X86_CONSERVATIVE'],'ON')
if __name__=='__main__':unittest.main()
