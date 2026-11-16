#!/usr/bin/env python3
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


fetch = module('media_fetch', 'fetch-media-helper-assets.py')
fixtures = module('media_fixtures', 'test_media_release.py')


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, directory, corrupt=False):
        self.directory, self.corrupt, self.urls = directory, corrupt, []

    def open(self, request, timeout):
        self.urls.append(request.full_url)
        target = request.full_url.split('/')[-2]
        data = (self.directory / ('porthub-media-helper-' + target + '.tar.gz')).read_bytes()
        return Response(data + b'corrupt' if self.corrupt else data)


class RecoveryTests(unittest.TestCase):
    def test_exact_prior_archives_and_provenance_survive_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            manifest = fixtures.fixture(source)
            opener = Opener(source)
            destination = root / 'verified'
            fetch.recover({'mode': 'reuse', 'manifest': manifest}, 'https://portal.example',
                          destination, opener, lambda *_: None)
            self.assertEqual(json.loads((destination / fetch.media.ASSET).read_text()), manifest)
            for artifact in manifest['artifacts']:
                name = 'porthub-media-helper-' + artifact['target'] + '.tar.gz'
                self.assertEqual((destination / name).read_bytes(), (source / name).read_bytes())
                suffix = '/0.1.0/' + artifact['target'] + '/' + artifact['executable']['sha256']
                self.assertTrue(any(url.endswith(suffix) for url in opener.urls))

    def test_bad_download_or_wrong_archive_member_never_publishes_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            manifest = fixtures.fixture(source)
            with self.assertRaisesRegex(ValueError, 'bound'):
                fetch.recover({'mode': 'reuse', 'manifest': manifest}, 'https://portal.example',
                              root / 'bad', Opener(source, True), lambda *_: None)
            self.assertFalse((root / 'bad').exists())
            manifest = fixtures.fixture(source, member_override='../outside')
            with self.assertRaisesRegex(ValueError, 'member'):
                fetch.recover({'mode': 'reuse', 'manifest': manifest}, 'https://portal.example',
                              root / 'wrong-member', Opener(source), lambda *_: None)
            self.assertFalse((root / 'wrong-member').exists())
            self.assertFalse((root / 'outside').exists())

    def test_no_redirect_plaintext_credentials_or_implicit_build_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            manifest = fixtures.fixture(source)
            for gateway in ['http://portal.example', 'https://user:secret@portal.example',
                            'https://portal.example/?secret=value']:
                with self.assertRaisesRegex(ValueError, 'HTTPS'):
                    fetch.recover({'mode': 'reuse', 'manifest': manifest}, gateway, root / 'bad')
            with self.assertRaisesRegex(ValueError, 'reuse plan'):
                fetch.recover({'mode': 'build'}, 'https://portal.example', root / 'bad')
            with self.assertRaisesRegex(ValueError, 'redirect'):
                fetch.NoRedirect().redirect_request(None, None, None, None, None, None)


if __name__ == '__main__':
    unittest.main()
