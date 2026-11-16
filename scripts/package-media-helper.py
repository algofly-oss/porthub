#!/usr/bin/env python3
"""Package a reviewed native media helper; never upload or change releases.

Run in a frozen checkout. Build separately in the pinned GNU baseline environment,
then pass its real binary. All native-format and byte hashes are checked before packaging.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import stat
import tarfile

ROOT=Path(__file__).resolve().parent.parent
ELF_TARGETS={'x86_64-unknown-linux-gnu':'Advanced Micro Devices X86-64','aarch64-unknown-linux-gnu':'AArch64'}
WINDOWS_TARGET='x86_64-pc-windows-msvc'
TARGETS=(*ELF_TARGETS,WINDOWS_TARGET)
MAX_PE_SIZE=128*1024*1024
ASSET='porthub-media-components.json'
INPUTS=['Cargo.toml','Cargo.lock','crates/porthub-media-helper','crates/porthub-components','scripts/package-media-helper.py','scripts/build-media-helper.sh','scripts/build-media-helper-windows.ps1','scripts/bootstrap-media-pipewire.sh','vendor/media/Dockerfile.glibc235','rust-toolchain.toml','vendor/media/build-inputs.json']
def digest(data):return hashlib.sha256(data).hexdigest()
def blob(path):data=Path(path).read_bytes();return {'size':len(data),'sha256':digest(data)}
def version(text):
 if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',text):raise ValueError('A stable semantic version is required')
 return text

def validate_elf(binary,target):
 if target not in ELF_TARGETS:raise ValueError('Unsupported optional media platform')
 env=dict(os.environ,LC_ALL='C')
 def read(*args):return subprocess.check_output(['readelf',*args,str(binary)],text=True,env=env)
 headers=read('-hW')
 if 'ELF64' not in headers or ELF_TARGETS[target] not in headers:raise ValueError('ELF architecture does not match artifact target')
 if 'INTERP' not in read('-lW'):raise ValueError('GNU media helper must use the reviewed dynamic runtime')
 dependencies=set(re.findall(r'Shared library: \[([^\]]+)\]',read('-dW')))
 allowed={'libpipewire-0.3.so.0','libgcc_s.so.1','libm.so.6','libc.so.6','libpthread.so.0','libdl.so.2','ld-linux-x86-64.so.2','ld-linux-aarch64.so.1'}
 if 'libpipewire-0.3.so.0' not in dependencies or dependencies-allowed:raise ValueError('Unexpected media helper dependencies: '+repr(sorted(dependencies)))
 requirements={tuple(map(int,v.split('.'))) for v in re.findall(r'GLIBC_(\d+\.\d+(?:\.\d+)?)',read('--version-info'))}
 if not requirements or max(requirements)>(2,35):raise ValueError('Media helper exceeds the GLIBC 2.35 runtime baseline')
 if 'RPATH' in read('-dW') or 'RUNPATH' in read('-dW'):raise ValueError('Media helper cannot retain a build-time RPATH or RUNPATH')
 return {'glibc_maximum_required':'.'.join(map(str,max(requirements))),'needed_libraries':sorted(dependencies)}

# Microsoft PE/COFF specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
# Deliberately no DLL search, native execution or external tool output is used.
SYSTEM_DLLS={'advapi32.dll','avrt.dll','bcrypt.dll','bcryptprimitives.dll','cfgmgr32.dll','combase.dll','comdlg32.dll','crypt32.dll','d3d11.dll','dnsapi.dll','dwmapi.dll','dxgi.dll','gdi32.dll','imm32.dll','iphlpapi.dll','kernel32.dll','mmdevapi.dll','ncrypt.dll','ntdll.dll','ole32.dll','oleaut32.dll','powrprof.dll','propsys.dll','rpcrt4.dll','secur32.dll','setupapi.dll','shell32.dll','shlwapi.dll','user32.dll','userenv.dll','version.dll','winhttp.dll','winmm.dll','winspool.drv','ws2_32.dll','wtsapi32.dll'}
# MFEnumDeviceSources, MFStartup and MFCreateSourceReaderFromMediaSource:
# documented Windows Media Foundation imports, observed in the native helper PE.
SYSTEM_DLLS.update({'mf.dll','mfplat.dll','mfreadwrite.dll'})
def validate_pe(binary,target):
 if target!=WINDOWS_TARGET:raise ValueError('Unsupported Windows media target')
 path=Path(binary)
 if path.is_symlink():raise ValueError('PE executable must not be a symlink')
 with path.open('rb') as handle:
  metadata=os.fstat(handle.fileno())
  if not stat.S_ISREG(metadata.st_mode) or not 256<=metadata.st_size<=MAX_PE_SIZE:raise ValueError('Invalid bounded PE executable')
  data=handle.read(MAX_PE_SIZE+1)
 if not 256<=len(data)<=MAX_PE_SIZE:raise ValueError('Invalid bounded PE executable')
 def field(fmt,offset):
  size=struct.calcsize(fmt)
  if offset<0 or offset+size>len(data):raise ValueError('Truncated PE structure')
  return struct.unpack_from(fmt,data,offset)[0]
 if data[:2]!=b'MZ':raise ValueError('Windows helper requires DOS/PE headers')
 pe=field('<I',60)
 if pe<64 or data[pe:pe+4]!=b'PE\0\0':raise ValueError('Invalid PE signature')
 machine=field('<H',pe+4);sections=field('<H',pe+6);optional_size=field('<H',pe+20);flags=field('<H',pe+22);opt=pe+24
 if machine!=0x8664 or not 1<=sections<=96 or not 240<=optional_size<=4096:raise ValueError('PE architecture/header does not match AMD64 target')
 if flags&0x3000 or not flags&2:raise ValueError('Windows helper must be a user executable, not a DLL/driver')
 if field('<H',opt)!=0x20b or field('<H',opt+68)!=3:raise ValueError('Windows helper requires PE32+ console subsystem for inherited pipes')
 security=field('<H',opt+70)
 if security&0x160!=0x160:raise ValueError('Windows helper requires ASLR, high-entropy VA and NX protections')
 count=field('<I',opt+108)
 if count!=16:raise ValueError('Unsupported PE data-directory layout')
 header_size=field('<I',opt+60);section_table=opt+optional_size
 if header_size<section_table+sections*40 or header_size>len(data):raise ValueError('Invalid PE header extent')
 ranges=[]
 for i in range(sections):
  at=section_table+i*40;virtual=field('<I',at+12);raw_size=field('<I',at+16);raw=field('<I',at+20)
  if raw_size and (raw<header_size or raw+raw_size>len(data)):raise ValueError('PE section exceeds file bounds')
  ranges.append((virtual,raw_size,raw))
 def rva(address,size):
  matches=[raw+address-base for base,length,raw in ranges if base<=address and address+size<=base+length]
  if size<0 or len(matches)!=1:raise ValueError('PE RVA is not uniquely file-backed')
  return matches[0]
 def directory(index):return field('<I',opt+112+index*8),field('<I',opt+116+index*8)
 def cstring(address,limit=256):
  start=rva(address,1);end=data.find(b'\0',start,min(len(data),start+limit))
  if end<0:raise ValueError('Unterminated PE import name')
  rva(address,end-start+1)
  try:return data[start:end].decode('ascii').lower()
  except UnicodeDecodeError:raise ValueError('Non-ASCII PE import name') from None
 imports=[];unapproved=[];address,size=directory(1)
 if not address or not 20<=size<=65536:raise ValueError('Missing/bounded PE imports required')
 offset=rva(address,size);terminated=False
 for at in range(offset,offset+size-19,20):
  if data[at:at+20]==bytes(20):terminated=True;break
  name=cstring(field('<I',at+12))
  if not re.fullmatch(r'[a-z0-9_.-]+\.(dll|drv)',name) or name not in SYSTEM_DLLS and not re.fullmatch(r'api-ms-win-core-[a-z0-9-]+\.dll',name):unapproved.append(name)
  imports.append(name)
 if unapproved:raise ValueError('Windows helper imports a non-system or dynamic CRT library: '+', '.join(sorted(set(unapproved))))
 if not terminated or not imports or 'kernel32.dll' not in imports:raise ValueError('Incomplete PE import table')
 if any(directory(13)):raise ValueError('Unreviewed delayed PE imports are unsupported')
 debug,debug_size=directory(6)
 if bool(debug)!=bool(debug_size) or debug_size>65536 or debug_size%28:raise ValueError('Invalid PE debug directory')
 if debug:
  offset=rva(debug,debug_size)
  for at in range(offset,offset+debug_size,28):
   kind=field('<I',at+12);length=field('<I',at+16);pointer=field('<I',at+24)
   if pointer+length>len(data) or length>512*1024:raise ValueError('PE debug record exceeds bound')
   if kind==2:
    record=data[pointer:pointer+length]
    if not record.startswith(b'RSDS') or len(record)<25:raise ValueError('Unsupported PE CodeView record')
    name=record[24:].split(b'\0',1)[0]
    if not re.fullmatch(rb'[a-zA-Z0-9_.-]+\.pdb',name):raise ValueError('Windows helper retains a private PDB path')
 # Explicitly prevent the packaging checkout path from leaking in panic/debug strings.
 for text in {str(ROOT),str(ROOT).replace('\\','/'),str(ROOT).replace('/','\\')}:
  if text.encode().lower() in data.lower() or text.encode('utf-16le').lower() in data.lower():raise ValueError('Windows helper retains a private build checkout path')
 return {'format':'PE32+','machine':'AMD64','subsystem':'console','needed_libraries':sorted(set(imports)),'dynamic_crt_imports':False}

def validate_executable(binary,target):
 return validate_pe(binary,target) if target==WINDOWS_TARGET else validate_elf(binary,target)

def input_digest(records):
 # Windows Path ordering is case-insensitive; serialize explicit POSIX names so
 # identical frozen bytes have the same provenance on every build platform.
 return digest(json.dumps(sorted(records,key=lambda item:item['path']),sort_keys=True,separators=(',',':')).encode())

def frozen_inputs(revision):
 if not re.fullmatch('[0-9a-f]{40}',revision):raise ValueError('Exact source revision required')
 actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
 if actual!=revision:raise ValueError('Checkout differs from requested source revision')
 dirty=subprocess.check_output(['git','status','--porcelain','--untracked-files=all','--',*INPUTS],cwd=ROOT,text=True)
 if dirty:raise ValueError('Media build inputs must be committed and unchanged')
 files=[]
 for item in INPUTS:
  path=ROOT/item
  files.extend(sorted(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else [path])
 records=[{'path':p.relative_to(ROOT).as_posix(),'sha256':blob(p)['sha256']} for p in set(files)]
 return input_digest(records)

def package(args):
 version(args.release)
 if not re.fullmatch(r'>=\d+\.\d+\.\d+',args.core):raise ValueError('Explicit minimum compatible agent version is required')
 if tuple(map(int,args.core[2:].split('.')))<(1,11,34):raise ValueError('Production media helpers require agent >=1.11.34')
 inputs=frozen_inputs(args.source_revision)
 binary=Path(args.binary)
 if binary.is_symlink() or not binary.is_file() or not 0<binary.stat().st_size<=128*1024*1024:raise ValueError('A bounded regular helper executable is required')
 binary=binary.resolve(strict=True)
 executable=validate_executable(binary,args.target)
 runtime=json.loads((ROOT/'vendor/media/build-inputs.json').read_text())
 if args.target in ELF_TARGETS:
  executable['pipewire_minimum_required']=runtime['pipewire_minimum_runtime']
  executable['pipewire_build_version']=runtime['pipewire_build']['version']
 helper=version(re.search(r'(?ms)^\[package\]\s*.*?^version\s*=\s*"([^"]+)"',(ROOT/'crates/porthub-media-helper/Cargo.toml').read_text()).group(1))
 output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=True)
 archive=output/f'porthub-media-helper-{args.target}.tar.gz'
 data=binary.read_bytes()
 with archive.open('wb') as raw:
  with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as gz:
   with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as tar:
    item=tarfile.TarInfo(f'media-helper/{helper}/porthub-media-helper'+('.exe' if args.target==WINDOWS_TARGET else ''));item.size=len(data);item.mode=0o755;item.mtime=0;item.uid=0;item.gid=0
    tar.addfile(item,io.BytesIO(data))
 artifact={'version':helper,'target':args.target,'core':args.core,'protocol':1,'source_revision':args.source_revision,'build_inputs':inputs,'executable':blob(binary),'archive':blob(archive)}
 (output/f'media-artifact-{args.target}.json').write_text(json.dumps(artifact,indent=2)+'\n')
 manifest={'schema_version':1,'namespace':'porthub-media','repository':'algofly-oss/porthub','release':args.release,'artifacts':[artifact]}
 (output/ASSET).write_text(json.dumps(manifest,indent=2)+'\n')
 (output/f'media-build-receipt-{args.target}.json').write_text(json.dumps({'schema_version':1,'source_revision':args.source_revision,'build_inputs':inputs,'target':args.target,'runtime':executable,'artifact':artifact,'release_assets':[ASSET,archive.name],'published':False},indent=2)+'\n')
 print(json.dumps({'archive':str(archive),'manifest':str(output/ASSET),'published':False}))
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--binary',required=True);parser.add_argument('--target',required=True,choices=TARGETS);parser.add_argument('--source-revision',required=True);parser.add_argument('--release',required=True);parser.add_argument('--core',required=True);parser.add_argument('--output',required=True)
 package(parser.parse_args())
