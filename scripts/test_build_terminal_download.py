#!/usr/bin/env python3
"""Pinned terminal source downloads recover transport failures atomically."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('terminal_builder', Path(__file__).with_name('build-terminal-helper.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
class Response(io.BytesIO):
    def geturl(self): return 'https://sources.example/archive.tar.gz'
class Broken(Response):
    def read(self, _size=-1): raise ConnectionResetError('fixture reset')
class DownloadTests(unittest.TestCase):
    def fixture(self, directory):
        payload = b'verified source archive'
        return {'name':'fixture', 'url':'https://sources.example/archive.tar.gz', 'sha256':hashlib.sha256(payload).hexdigest()}, Path(directory)/'archive.tar.gz', payload
    def test_reset_retries_and_never_publishes_partial_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            with patch.object(builder.urllib.request, 'urlopen', side_effect=[Broken(),Response(payload)]) as get, patch.object(builder.time, 'sleep'):
                builder.download_source(item, archive)
            self.assertEqual(get.call_count, 2)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertEqual([p.name for p in Path(directory).iterdir()], [archive.name])
    def test_checksum_failure_never_publishes_and_cleans_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, _ = self.fixture(directory)
            with patch.object(builder.urllib.request, 'urlopen', return_value=Response(b'wrong source')):
                with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'): builder.download_source(item, archive)
            self.assertEqual(list(Path(directory).iterdir()), [])
    def test_cached_corruption_is_repaired_then_valid_cache_needs_no_network(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            archive.write_bytes(b'corrupt cache')
            with patch.object(builder.urllib.request, 'urlopen', return_value=Response(payload)):
                builder.download_source(item, archive)
            with patch.object(builder.urllib.request, 'urlopen') as get:
                builder.download_source(item, archive)
                get.assert_not_called()
    def test_source_size_is_bounded_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            with patch.object(builder, 'MAX_SOURCE_BYTES', 4), patch.object(builder.urllib.request, 'urlopen', return_value=Response(payload)):
                with self.assertRaisesRegex(RuntimeError, 'size limit'): builder.download_source(item, archive)
            self.assertFalse(archive.exists())
if __name__ == '__main__': unittest.main()
