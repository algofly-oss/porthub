#!/usr/bin/env python3
"""Pinned terminal source downloads recover transport failures atomically."""
import hashlib
import importlib.util
import io
import contextlib
import urllib.error
import urllib.request
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
    def read1(self, _size=-1): raise ConnectionResetError('fixture reset')
class DownloadTests(unittest.TestCase):
    def fixture(self, directory):
        payload = b'verified source archive'
        return {'name':'fixture', 'url':'https://sources.example/archive.tar.gz', 'sha256':hashlib.sha256(payload).hexdigest()}, Path(directory)/'archive.tar.gz', payload
    def test_reset_retries_and_never_publishes_partial_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            with patch.object(builder, 'open_source', side_effect=[Broken(),Response(payload)]) as get, patch.object(builder.time, 'sleep'):
                builder.download_source(item, archive)
            self.assertEqual(get.call_count, 2)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertEqual([p.name for p in Path(directory).iterdir()], [archive.name])
    def test_checksum_failure_never_publishes_and_cleans_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, _ = self.fixture(directory)
            with patch.object(builder, 'open_source', return_value=Response(b'wrong source')):
                with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'): builder.download_source(item, archive)
            self.assertEqual(list(Path(directory).iterdir()), [])
    def test_cached_corruption_is_repaired_then_valid_cache_needs_no_network(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            archive.write_bytes(b'corrupt cache')
            with patch.object(builder, 'open_source', return_value=Response(payload)):
                builder.download_source(item, archive)
            with patch.object(builder, 'open_source') as get:
                builder.download_source(item, archive)
                get.assert_not_called()
    def test_source_size_is_bounded_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            with patch.object(builder, 'MAX_SOURCE_BYTES', 4), patch.object(builder, 'open_source', return_value=Response(payload)):
                with self.assertRaisesRegex(RuntimeError, 'size limit'): builder.download_source(item, archive)
            self.assertFalse(archive.exists())
    def test_primary_timeout_uses_checksum_verified_mirror(self):
        with tempfile.TemporaryDirectory() as directory:
            item, archive, payload = self.fixture(directory)
            item['mirrors']=['https://mirror.example/archive.tar.gz']
            with patch.object(builder, 'open_source', side_effect=[TimeoutError('secret URL'),Response(payload)]) as get, patch.object(builder.time,'sleep'):
                builder.download_source(item,archive)
            self.assertEqual([c.args[0].full_url for c in get.call_args_list],[item['url'],item['mirrors'][0]])
            self.assertEqual(archive.read_bytes(),payload)
    def test_mirror_checksum_mismatch_is_fatal_without_third_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,_=self.fixture(directory);item['mirrors']=['https://mirror.example/archive.tar.gz']
            with patch.object(builder,'open_source',side_effect=[TimeoutError(),Response(b'wrong')]) as get, patch.object(builder.time,'sleep'):
                with self.assertRaisesRegex(RuntimeError,'checksum mismatch'):builder.download_source(item,archive)
            self.assertEqual(get.call_count,2);self.assertEqual(list(Path(directory).iterdir()),[])
    def test_plaintext_initial_or_redirect_endpoint_is_never_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,_=self.fixture(directory);item['mirrors']=['http://mirror.example/source']
            with patch.object(builder,'open_source') as get:
                with self.assertRaisesRegex(ValueError,'HTTPS'):builder.download_source(item,archive)
                get.assert_not_called()
        handler=builder.HTTPSOnlyRedirect(builder.time.monotonic()+180)
        request=urllib.request.Request('https://source.example/source');request.timeout=60
        with self.assertRaisesRegex(RuntimeError,'away from HTTPS'):
            handler.redirect_request(request,None,302,'Found',{},'http://mirror.example/source')
    def test_three_endpoints_share_attempt_budget_and_sanitized_error(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,_=self.fixture(directory);item['mirrors']=['https://one.example/source','https://two.example/source']
            error=urllib.error.URLError('https://user:password@proxy.invalid/private')
            stderr=io.StringIO()
            with patch.object(builder,'open_source',side_effect=error) as get, patch.object(builder.time,'sleep'), contextlib.redirect_stderr(stderr):
                with self.assertRaisesRegex(RuntimeError,'URLError/str, URLError/str, URLError/str') as caught:builder.download_source(item,archive)
            self.assertEqual(get.call_count,3)
            self.assertNotIn('password',str(caught.exception)+stderr.getvalue());self.assertNotIn('proxy.invalid',stderr.getvalue())
            self.assertEqual(list(Path(directory).iterdir()),[])
    def test_global_deadline_prevents_mirror_and_late_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,payload=self.fixture(directory);item['mirrors']=['https://mirror.example/source']
            clock=[0]
            class Late(Response):
                def read1(self,size=-1):clock[0]=181;return super().read1(size)
            with patch.object(builder.time,'monotonic',side_effect=lambda:clock[0]), patch.object(builder,'open_source',return_value=Late(payload)) as get, patch.object(builder.time,'sleep'):
                with self.assertRaisesRegex(RuntimeError,'bounded retries'):builder.download_source(item,archive)
            self.assertEqual(get.call_count,1);self.assertEqual(list(Path(directory).iterdir()),[])
    def test_http_status_diagnostic_retained_without_response_body(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,_=self.fixture(directory)
            error=urllib.error.HTTPError(item['url'],503,'SECRET BODY',{},None)
            with patch.object(builder,'open_source',side_effect=error),patch.object(builder.time,'sleep'):
                with self.assertRaisesRegex(RuntimeError,'HTTP 503, HTTP 503, HTTP 503') as caught:builder.download_source(item,archive)
            self.assertNotIn('SECRET',str(caught.exception))
    def test_redirect_expiry_and_endpoint_count_are_bounded(self):
        request=urllib.request.Request('https://source.example/source');request.timeout=60
        with patch.object(builder.time,'monotonic',return_value=181):
            with self.assertRaises(TimeoutError):builder.HTTPSOnlyRedirect(180).redirect_request(request,None,302,'Found',{},'https://mirror.example/source')
        with tempfile.TemporaryDirectory() as directory:
            item,archive,_=self.fixture(directory);item['mirrors']=['https://one.example/source','https://two.example/source','https://three.example/source']
            with patch.object(builder,'open_source') as get:
                with self.assertRaisesRegex(ValueError,'endpoint count'):builder.download_source(item,archive)
                get.assert_not_called()
    def test_read_socket_timeout_shrinks_with_shared_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            item,archive,payload=self.fixture(directory)
            class Socket:
                values=[]
                def settimeout(self,value):self.values.append(value)
            class Raw:pass
            class FP:pass
            response=Response(payload);sock=Socket();response.fp=FP();response.fp.raw=Raw();response.fp.raw._sock=sock
            clock=iter([0,0,170,171,172,173,174,175,176])
            with patch.object(builder.time,'monotonic',side_effect=lambda:next(clock)),patch.object(builder,'open_source',return_value=response):builder.download_source(item,archive)
            self.assertTrue(sock.values);self.assertLessEqual(max(sock.values),9)
            self.assertEqual(archive.read_bytes(),payload)
if __name__ == '__main__': unittest.main()
