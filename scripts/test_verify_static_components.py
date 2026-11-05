import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('static_check',Path(__file__).with_name('verify-static-components.py'))
check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)


@unittest.skipUnless(shutil.which('readelf') and shutil.which('cc'),'ELF compiler/tools are required')
class StaticChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/'main.c';self.source.write_text('int main(void) { return 0; }\n')

    def test_accepts_static_and_rejects_dynamic_executables(self):
        static,dynamic=self.root/'static',self.root/'dynamic'
        result=subprocess.run(['cc','-static',str(self.source),'-o',str(static)],capture_output=True)
        if result.returncode:self.skipTest('Host static C runtime is unavailable')
        subprocess.run(['cc',str(self.source),'-o',str(dynamic)],check=True,capture_output=True)
        check.verify_binary(static)
        with self.assertRaises(ValueError):check.verify_binary(dynamic)

    def test_rejects_non_elf_payload(self):
        binary=self.root/'invalid';binary.write_bytes(b'not ELF')
        with self.assertRaises(ValueError):check.verify_binary(binary)


if __name__=='__main__':unittest.main()
