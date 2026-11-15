#!/usr/bin/env python3
"""The real Git checkout must preserve common helper provenance on Windows."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parent.parent
SAMPLES=['Cargo.toml','Cargo.lock','rust-toolchain.toml','crates/porthub-components/src/lib.rs','crates/porthub-media-helper/Cargo.toml','crates/porthub-media-helper/src/windows_session.rs','scripts/package-media-helper.py','scripts/test_package_media_helper.py','scripts/build-media-helper-windows.ps1','scripts/build-media-helper.sh','vendor/media/Dockerfile.glibc235','vendor/media/build-inputs.json']
class SourceAttributesTests(unittest.TestCase):
 def test_every_native_helper_input_has_explicit_lf_checkout(self):
  output=subprocess.check_output(['git','check-attr','eol','--stdin'],cwd=ROOT,input='\n'.join(SAMPLES)+'\n',text=True)
  self.assertEqual(output.splitlines(),[f'{path}: eol: lf' for path in SAMPLES])
 def test_windows_autocrlf_checkout_retains_exact_frozen_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory);environment=dict(os.environ,GIT_INDEX_FILE=str(directory/'private.index'))
   subprocess.run(['git','read-tree','--empty'],cwd=ROOT,env=environment,check=True)
   # Use representative LF source blobs even before optional helper files ship.
   # The real production attributes file controls the isolated checkout below.
   content={path:(b'first line\nsecond line\n' if path!='.gitattributes' else (ROOT/path).read_bytes()) for path in ['.gitattributes',*SAMPLES]}
   # Embedded CRLF in native/JPEG bytes must survive text normalization.
   for path in ['crates/porthub-media-helper/tests/data/fixture.jpg','crates/porthub-components/tests/data/fixture.bin','vendor/media/fixture.exe']:
    content[path]=b'\x00\xffbinary\r\nbytes\r\n'
   for path,data in content.items():
    digest=subprocess.check_output(['git','hash-object','-w','--stdin'],cwd=ROOT,input=data).decode().strip()
    subprocess.run(['git','update-index','--add','--cacheinfo',f'100644,{digest},{path}'],cwd=ROOT,env=environment,check=True)
   checkout=directory/'checkout';checkout.mkdir()
   subprocess.run(['git','-c','core.autocrlf=true','checkout-index','--force','--prefix='+str(checkout)+'/', '--stdin'],cwd=ROOT,env=environment,input=('\n'.join(content)+'\n').encode(),check=True)
   for path,data in content.items():self.assertEqual((checkout/path).read_bytes(),data,path)
if __name__=='__main__':unittest.main()
