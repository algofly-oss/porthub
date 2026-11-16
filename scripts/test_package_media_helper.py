#!/usr/bin/env python3
import importlib.util
import json
import struct
import stat
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,MagicMock
SPEC=importlib.util.spec_from_file_location('package_media',Path(__file__).with_name('package-media-helper.py'))
module=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(module)
def pe_fixture(name='KERNEL32.dll',pdb=None):
 data=bytearray(2048);data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0'
 struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,240,0x22);opt=152
 struct.pack_into('<H',data,opt,0x20b);struct.pack_into('<I',data,opt+60,512);struct.pack_into('<H',data,opt+68,3);struct.pack_into('<H',data,opt+70,0x160);struct.pack_into('<I',data,opt+108,16)
 struct.pack_into('<II',data,opt+120,0x1000,40);section=opt+240;data[section:section+8]=b'.rdata\0\0';struct.pack_into('<IIII',data,section+8,1536,0x1000,1536,512)
 struct.pack_into('<I',data,512+12,0x1080);value=name.encode()+b'\0';data[640:640+len(value)]=value
 if pdb is not None:
  struct.pack_into('<II',data,opt+112+6*8,0x1100,28);record=b'RSDS'+bytes(20)+pdb.encode()+b'\0';struct.pack_into('<III',data,768+12,2,len(record),0x1180);struct.pack_into('<I',data,768+24,896);data[896:896+len(record)]=record
 return data
class PackagingTests(unittest.TestCase):
 def test_published_helper_rejects_agents_without_media(self):
  args=SimpleNamespace(release='1.11.51',core='>=1.11.33')
  with self.assertRaisesRegex(ValueError,'1.11.34'):module.package(args)
 def test_real_elf_inspection_rejects_newer_glibc_and_private_library_paths(self):
  def output(args,**kwargs):
   if '-hW' in args:return 'ELF64 Advanced Micro Devices X86-64'
   if '-lW' in args:return 'INTERP'
   if '-dW' in args:return 'Shared library: [libpipewire-0.3.so.0]\nShared library: [libc.so.6]'
   return 'GLIBC_2.35 GLIBC_2.17'
  with patch.object(module.subprocess,'check_output',side_effect=output):self.assertEqual(module.validate_elf('fixture','x86_64-unknown-linux-gnu')['glibc_maximum_required'],'2.35')
  with patch.object(module.subprocess,'check_output',side_effect=lambda args,**kwargs:'GLIBC_2.39' if '--version-info' in args else output(args)):
   with self.assertRaisesRegex(ValueError,'GLIBC'):module.validate_elf('fixture','x86_64-unknown-linux-gnu')
  with patch.object(module.subprocess,'check_output',side_effect=lambda args,**kwargs:output(args)+'\nRUNPATH /private' if '-dW' in args else output(args)):
   with self.assertRaisesRegex(ValueError,'RPATH'):module.validate_elf('fixture','x86_64-unknown-linux-gnu')
 def test_archive_is_reproducible_and_manifest_binds_exact_executable(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);binary=root/'helper';binary.write_bytes(b'unit test bytes, not a native executable')
   args=SimpleNamespace(binary=str(binary),target='x86_64-unknown-linux-gnu',source_revision='a'*40,release='1.11.48',core='>=1.11.34',output=str(root/'out'))
   with patch.object(module,'frozen_inputs',return_value='b'*64),patch.object(module,'validate_elf',return_value={'fixture_only':True}):
    module.package(args);archive=next((root/'out').glob('*.tar.gz'));first=archive.read_bytes();module.package(args);self.assertEqual(first,archive.read_bytes())
   manifest=json.loads((root/'out'/module.ASSET).read_text());artifact=manifest['artifacts'][0]
   self.assertEqual(artifact['executable'],module.blob(binary));self.assertEqual(artifact['archive'],module.blob(archive))
   with tarfile.open(archive) as tar:
    members=tar.getmembers();self.assertEqual(len(members),1);self.assertTrue(members[0].isreg());self.assertEqual(tar.extractfile(members[0]).read(),binary.read_bytes());self.assertEqual(members[0].mode,0o755)
 def test_pe_real_parser_accepts_only_bounded_native_amd64_system_dependencies(self):
  with tempfile.TemporaryDirectory() as directory:
   binary=Path(directory)/'helper.exe';binary.write_bytes(pe_fixture())
   result=module.validate_executable(binary,'x86_64-pc-windows-msvc');self.assertEqual(result['needed_libraries'],['kernel32.dll']);self.assertFalse(result['dynamic_crt_imports'])
   for name in ['vcruntime140.dll','ucrtbase.dll','msvcrt.dll','private.dll','C:\\private\\evil.dll']:
    binary.write_bytes(pe_fixture(name));
    with self.assertRaisesRegex(ValueError,'non-system|CRT'):module.validate_pe(binary,module.WINDOWS_TARGET)
 def test_camera_system_imports_are_explicit_and_similar_private_names_stay_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   binary=Path(directory)/'helper.exe'
   for name in ['mf.dll','mfplat.dll','mfreadwrite.dll','mf-private.dll','mfplat.dll.evil.dll']:
    data=pe_fixture();struct.pack_into('<I',data,152+124,60)
    struct.pack_into('<I',data,532+12,0x10a0)
    value=name.encode()+b'\0';data[672:672+len(value)]=value;binary.write_bytes(data)
    if name in {'mf.dll','mfplat.dll','mfreadwrite.dll'}:
     self.assertEqual(module.validate_pe(binary,module.WINDOWS_TARGET)['needed_libraries'],['kernel32.dll',name])
    else:
     with self.assertRaisesRegex(ValueError,name.replace('.',r'\.')):module.validate_pe(binary,module.WINDOWS_TARGET)
 def test_pe_rejects_wrong_platform_security_truncation_rvas_and_delay_imports(self):
  cases=[]
  value=pe_fixture();struct.pack_into('<H',value,132,0x14c);cases.append(value)
  value=pe_fixture();struct.pack_into('<H',value,150,0x2022);cases.append(value)
  value=pe_fixture();struct.pack_into('<H',value,152,0x10b);cases.append(value)
  value=pe_fixture();struct.pack_into('<H',value,222,0);cases.append(value)
  value=pe_fixture();struct.pack_into('<I',value,512+12,0xffffff00);cases.append(value)
  value=pe_fixture();struct.pack_into('<II',value,152+112+13*8,0x1000,32);cases.append(value)
  cases.extend([pe_fixture()[:200],bytearray(b'MZ')])
  with tempfile.TemporaryDirectory() as directory:
   binary=Path(directory)/'helper.exe'
   for data in cases:
    binary.write_bytes(data)
    with self.assertRaises(ValueError):module.validate_pe(binary,module.WINDOWS_TARGET)
 def test_pe_rejects_build_private_debug_paths_and_checkout_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   binary=Path(directory)/'helper.exe';binary.write_bytes(pe_fixture(pdb='porthub-media-helper.pdb'));module.validate_pe(binary,module.WINDOWS_TARGET)
   for name in ['C:\\Users\\developer\\helper.pdb','/home/private/helper.pdb']:
    binary.write_bytes(pe_fixture(pdb=name))
    with self.assertRaisesRegex(ValueError,'private PDB'):module.validate_pe(binary,module.WINDOWS_TARGET)
   data=pe_fixture();data.extend(str(module.ROOT).encode('utf-16le'));binary.write_bytes(data)
   with self.assertRaisesRegex(ValueError,'private build'):module.validate_pe(binary,module.WINDOWS_TARGET)
 def test_windows_archive_member_and_digest_match_exact_pe_without_linux_runtime_claim(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);binary=root/'helper.exe';binary.write_bytes(pe_fixture())
   args=SimpleNamespace(binary=str(binary),target=module.WINDOWS_TARGET,source_revision='a'*40,release='1.11.51',core='>=1.11.34',output=str(root/'out'))
   with patch.object(module,'frozen_inputs',return_value='b'*64):
    module.package(args);archive=next((root/'out').glob('*.tar.gz'));first=archive.read_bytes();module.package(args);self.assertEqual(first,archive.read_bytes())
   manifest=json.loads((root/'out'/module.ASSET).read_text());artifact=manifest['artifacts'][0];self.assertEqual(artifact['executable'],module.blob(binary));self.assertEqual(artifact['archive'],module.blob(archive));self.assertEqual(artifact['core'],'>=1.11.34')
   with tarfile.open(archive) as tar:
    members=tar.getmembers();self.assertEqual(len(members),1);self.assertTrue(members[0].name.endswith('/porthub-media-helper.exe'));self.assertEqual(tar.extractfile(members[0]).read(),binary.read_bytes())
   receipt=json.loads(next((root/'out').glob('media-build-receipt-*.json')).read_text());self.assertEqual(receipt['runtime']['format'],'PE32+');self.assertNotIn('pipewire_minimum_required',receipt['runtime']);self.assertFalse(receipt['published'])
 def test_pe_read_is_bounded_before_allocation_even_if_file_grows(self):
  for advertised in [4097,1024]:
   handle=MagicMock();handle.__enter__.return_value=handle;handle.fileno.return_value=123;handle.read.return_value=b'x'*4097
   with patch.object(module,'MAX_PE_SIZE',4096),patch.object(Path,'open',return_value=handle),patch.object(module.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG,st_size=advertised)):
    with self.assertRaisesRegex(ValueError,'bounded PE'):module.validate_pe('nonexistent-owned-fixture.exe',module.WINDOWS_TARGET)
   if advertised>4096:handle.read.assert_not_called()
   else:handle.read.assert_called_once_with(4097)
 def test_provenance_is_identical_for_windows_and_posix_path_order(self):
  records=[{'path':name,'sha256':'a'*64} for name in ['Cargo.toml','crates/example/Cargo.toml','crates/example/src/lib.rs','scripts/build.ps1','Rust.txt','rust-toolchain.toml']]
  windows=sorted(records,key=lambda record:record['path'].lower());posix=sorted(records,key=lambda record:record['path'])
  self.assertNotEqual(windows,posix);self.assertEqual(module.input_digest(windows),module.input_digest(posix))
if __name__=='__main__':unittest.main()
