#!/usr/bin/env python3
"""Verify the package gate against actual compiler-produced ELF files."""
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('terminal_helper', pathlib.Path(__file__).with_name('build-terminal-helper.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc') and shutil.which('readelf'), 'requires Linux GCC and readelf')
class BinaryGate(unittest.TestCase):
    def test_real_32_bit_binary_cannot_be_mislabelled_as_64_bit(self):
        with tempfile.TemporaryDirectory() as temp:
            source = pathlib.Path(temp) / 'entry.c'
            source.write_text('void _start(void) { for (;;) {} }\n')
            binary = pathlib.Path(temp) / 'helper'
            subprocess.run(['gcc', '-m32', '-static', '-nostdlib', '-fno-stack-protector', str(source), '-o', str(binary)], check=True, capture_output=True)
            helper.validate_linux_binary(binary, 'i686-unknown-linux-gnu')
            with self.assertRaisesRegex(RuntimeError, 'architecture'):
                helper.validate_linux_binary(binary, 'x86_64-unknown-linux-gnu')
            with self.assertRaisesRegex(RuntimeError, 'architecture'):
                helper.validate_linux_binary(binary, 'armv7-unknown-linux-gnueabihf')

    def test_dynamic_loader_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = pathlib.Path(temp) / 'entry.c'
            source.write_text('int main(void) { return 0; }\n')
            binary = pathlib.Path(temp) / 'helper'
            subprocess.run(['gcc', str(source), '-o', str(binary)], check=True, capture_output=True)
            with self.assertRaisesRegex(RuntimeError, 'dynamic loader'):
                helper.validate_linux_binary(binary, 'x86_64-unknown-linux-gnu')

if __name__ == '__main__':
    unittest.main()
