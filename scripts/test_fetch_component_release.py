import importlib.util
import json
import sys
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fetch_release', Path(__file__).with_name('fetch-component-release.py'))
fetch = importlib.util.module_from_spec(spec); spec.loader.exec_module(fetch)
fixture = fetch.recovery.load('packaging_fixture', 'test_package_components.py')


class FetchRelease(unittest.TestCase):
    def setUp(self):
        self.case = fixture.Packaging(); self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.root = self.case.root; self.input = self.root/'input'
        fetch.recovery.packager.package(self.case.complete(), self.input, '1.12.0')
        self.release = {'tag_name':'v1.12.0', 'draft':False, 'prerelease':False, 'assets':[
            {'name':p.name, 'size':p.stat().st_size, 'digest':'sha256:'+fetch.recovery.planner.file_digest(p),
             'state':'uploaded', 'browser_download_url':'http://untrusted.invalid/ignored'} for p in self.input.iterdir()]}

    def copy_asset(self, url, path, size, digest):
        self.assertTrue(url.startswith('https://github.com/algofly-oss/porthub/releases/download/v1.12.0/'))
        path.write_bytes((self.input/path.name).read_bytes())

    def test_complete_release_is_verified_before_atomic_publication(self):
        output = self.root/'staged'
        with patch.object(fetch, 'download', side_effect=self.copy_asset) as downloads, patch.object(fetch.recovery.publisher, 'assets') as verify:
            self.assertEqual(fetch.stage(self.release, output, Path('/verifier')), '1.12.0')
            self.assertEqual(downloads.call_count, 21)
            verify.assert_called_once()
        self.assertEqual(len(list(output.iterdir())), 21)

    def test_legacy_release_requests_fresh_build_without_downloads(self):
        legacy = dict(self.release, assets=[{'name':name+suffix} for name in fetch.recovery.publisher.ASSETS for suffix in ('','.version','.sha256')])
        with patch.object(fetch, 'download', side_effect=AssertionError('No legacy downloads')):
            self.assertIsNone(fetch.stage(legacy, self.root/'staged', Path('/verifier')))
        self.assertFalse((self.root/'staged').exists())

    def test_partial_or_invalid_metadata_does_not_start_download(self):
        for assets in (self.release['assets'][:-1], self.release['assets']+[self.release['assets'][0]],
                       [dict(a, size=True) for a in self.release['assets']]):
            with patch.object(fetch, 'download', side_effect=AssertionError('Invalid metadata')):
                with self.assertRaises(ValueError): fetch.stage(dict(self.release, assets=assets), self.root/'staged', Path('/verifier'))
        self.assertFalse((self.root/'staged').exists())

    def test_corrupt_download_and_failed_verifier_publish_nothing(self):
        with patch.object(fetch, 'download', side_effect=lambda url,path,*args:path.write_bytes(b'corrupt')):
            with self.assertRaises(ValueError): fetch.stage(self.release, self.root/'staged', Path('/verifier'))
        with patch.object(fetch, 'download', side_effect=self.copy_asset), patch.object(fetch.recovery.publisher, 'assets', side_effect=ValueError('Rust rejected')):
            with self.assertRaises(ValueError): fetch.stage(self.release, self.root/'staged', Path('/verifier'))
        self.assertFalse((self.root/'staged').exists())

    def test_cli_recovers_all_platforms_only_after_verified_staging(self):
        output, recovered = self.root/'staged', self.root/'builds'
        def recover(directory, destination, target, version, verifier):
            self.assertEqual(directory, output)
            self.assertEqual(version, '1.12.0')
            destination.mkdir()
            (destination/'index.json').write_text('{}')
        args = ['fetch', '--output', str(output), '--artifact-verifier', '/verifier', '--recover-output', str(recovered)]
        response = SimpleNamespace(returncode=0, stdout=json.dumps(self.release), stderr='')
        with patch.object(sys, 'argv', args), patch.object(fetch.subprocess, 'run', return_value=response), patch.object(fetch, 'stage', return_value='1.12.0') as staged, patch.object(fetch.recovery, 'recover', side_effect=recover) as restored:
            fetch.main()
            staged.assert_called_once()
            self.assertEqual(restored.call_count, 10)
        self.assertEqual(len(list(recovered.iterdir())), 10)

    def test_unsafe_redirects_are_rejected(self):
        handler = fetch.ReleaseRedirects()
        for url in ('http://github.com/file', 'https://evil.test/file', 'https://user:password@github.com/file', 'https://github.com:8443/file'):
            with self.assertRaises(ValueError): handler.redirect_request(None,None,302,'',{},url)


if __name__ == '__main__': unittest.main()
