#!/usr/bin/env python3
"""Verify the package gate against actual compiler-produced ELF files."""
import importlib.util
import hashlib
import io
import os
import tarfile
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('terminal_helper', pathlib.Path(__file__).with_name('build-terminal-helper.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class SourceCache(unittest.TestCase):
    def archive(self, root, extra=()):
        archive = root / 'source.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, content in [('pkg/spawn.c', b'original spawn'), ('pkg/configure', b'configure'), ('pkg/include/header.h', b'header')]:
                member = tarfile.TarInfo(name); member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
            for member in extra:
                tar.addfile(member, io.BytesIO(b'x') if member.isfile() else None)
        return archive, {'name': 'tmux', 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}

    def test_partial_restore_reconstructs_exact_source_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); archive, item = self.archive(root); destination = root / 'tmux'
            destination.mkdir(); (destination / 'include').mkdir(); (destination / 'stale-build').write_text('partial')
            neighbor = root / 'other-package'; neighbor.mkdir(); (neighbor / 'keep').write_text('unchanged')
            helper.extract_source(item, archive, destination)
            self.assertEqual((destination / 'spawn.c').read_bytes(), b'original spawn')
            self.assertEqual((destination / 'include/header.h').read_bytes(), b'header')
            self.assertFalse((destination / 'stale-build').exists())
            self.assertEqual((neighbor / 'keep').read_text(), 'unchanged')
            self.assertTrue(archive.is_file())

    def test_complete_configured_patched_tree_reuses_without_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); archive, item = self.archive(root); destination = root / 'tmux'
            helper.extract_source(item, archive, destination)
            (destination / 'spawn.c').write_text('legitimate PortHub patch')
            sentinel = destination / 'config.status'; sentinel.write_text('configured')
            before = (destination.stat().st_ino, sentinel.stat().st_ino)
            helper.extract_source(item, archive, destination)
            self.assertEqual((destination.stat().st_ino, sentinel.stat().st_ino), before)
            self.assertEqual((destination / 'spawn.c').read_text(), 'legitimate PortHub patch')

    def test_missing_non_spawn_file_and_empty_restore_reconstruct(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); archive, item = self.archive(root); destination = root / 'tmux'
            helper.extract_source(item, archive, destination)
            (destination / 'include/header.h').unlink()
            helper.extract_source(item, archive, destination)
            self.assertEqual((destination / 'include/header.h').read_bytes(), b'header')
            (destination / 'configure').write_bytes(b'')
            helper.extract_source(item, archive, destination)
            self.assertEqual((destination / 'configure').read_bytes(), b'configure')

    def test_invalid_checksum_does_not_replace_partial_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); archive, item = self.archive(root); destination = root / 'tmux'; destination.mkdir()
            marker = destination / 'keep'; marker.write_text('prior')
            item['sha256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                helper.extract_source(item, archive, destination)
            self.assertEqual(marker.read_text(), 'prior')

    def test_escaping_members_links_and_malformed_roots_preserve_prior(self):
        for bad in ['../escaped', '/absolute', 'second/file', 'pkg/../../escaped']:
            with self.subTest(member=bad), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp); member = tarfile.TarInfo(bad); member.size = 1
                archive, item = self.archive(root, [member]); destination = root / 'tmux'; destination.mkdir()
                with self.assertRaises((RuntimeError, tarfile.FilterError)):
                    helper.extract_source(item, archive, destination)
                self.assertEqual(list(destination.iterdir()), [])
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); member = tarfile.TarInfo('pkg/escape'); member.type = tarfile.SYMTYPE; member.linkname = '../../outside'
            archive, item = self.archive(root, [member]); destination = root / 'tmux'; destination.mkdir()
            with self.assertRaises(tarfile.FilterError): helper.extract_source(item, archive, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_symlink_cache_root_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); archive, item = self.archive(root); foreign = root / 'foreign'; foreign.mkdir()
            destination = root / 'tmux'; destination.symlink_to(foreign, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'plain directory'): helper.extract_source(item, archive, destination)
            self.assertTrue(destination.is_symlink()); self.assertEqual(list(foreign.iterdir()), [])

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
