import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('gateway', Path(__file__).with_name('windows-update-fixture-gateway.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / 'agent.exe'
        path.write_bytes(b'not-an-executable-test-bytes')
        self.artifact = dict(path=str(path), target='windows_x86_64', os='windows', arch='x86_64',
                             asset='porthub-windows_x86_64.exe', version='1.11.35', source='a' * 40,
                             sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)
        self.journal = None
        self.gateway = module.Gateway({'1.11.35': self.artifact}, {'a': 'secret-a', 'c': 'secret-c'}, lambda _: self.journal)
        self.origin = self.gateway.start()
        self.request = self.gateway.advertise('a', '1.11.35')

    def tearDown(self):
        self.gateway.close()
        self.tmp.cleanup()

    def fetch(self, path, value=None):
        data = None if value is None else json.dumps(value).encode()
        with urlopen(Request(self.origin + path, data=data), timeout=3) as response:
            return response.status, response.read(), response.headers

    def test_all_routes_reject_wrong_enrollment_credentials(self):
        for path, value in [('/api/machines/a/wrong/downloads/releases', None),
                            ('/api/machines/client/changes.toml?machine_id=a&token=wrong', None),
                            ('/api/machines/client/sync', {'machine_id': 'a', 'token': 'wrong'})]:
            with self.assertRaises(HTTPError) as error:
                self.fetch(path, value)
            self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.gateway.events, [])

    def test_catalog_exact_artifact_and_other_profile_has_no_request(self):
        _, data, _ = self.fetch('/api/machines/a/secret-a/downloads/releases')
        self.assertEqual(json.loads(data)['releases'][0]['sha256'], self.artifact['sha256'])
        _, data, headers = self.fetch('/api/machines/a/secret-a/downloads/agent/windows_x86_64')
        self.assertEqual(hashlib.sha256(data).hexdigest(), headers['x-porthub-agent-sha256'])
        _, _, headers = self.fetch('/api/machines/client/changes.toml?machine_id=c&token=secret-c')
        self.assertNotIn('x-porthub-client-update-requested', headers)

    def test_ack_requires_real_committed_journal_and_matching_version(self):
        value = dict(machine_id='a', token='secret-a', client_version='1.11.35',
                     client_update_last_handled_request_id=self.request)
        for phase in [None, 'prepared', 'verifying', 'rolled-back']:
            self.journal = None if phase is None else dict(phase=phase, request={'id': self.request}, release={'version': '1.11.35'})
            with self.assertRaises(HTTPError) as error:
                self.fetch('/api/machines/client/sync', value)
            self.assertEqual(error.exception.code, 409)
        self.journal['phase'] = 'committed'
        self.journal['source_revision'] = self.artifact['source']
        self.journal['release']['sha256'] = self.artifact['sha256']
        self.assertEqual(self.fetch('/api/machines/client/sync', value)[0], 200)
        value['client_version'] = '1.11.34'
        with self.assertRaises(HTTPError):
            self.fetch('/api/machines/client/sync', value)

    def test_readiness_failure_only_affects_candidate_sync(self):
        self.gateway.fail_version = '1.11.35'
        for version, expected in [('1.11.34', 200), ('1.11.35', 503)]:
            value = dict(machine_id='a', token='secret-a', client_version=version)
            if expected == 200:
                self.assertEqual(self.fetch('/api/machines/client/sync', value)[0], expected)
            else:
                with self.assertRaises(HTTPError) as error:
                    self.fetch('/api/machines/client/sync', value)
                self.assertEqual(error.exception.code, expected)

    def test_changed_artifact_is_not_served(self):
        Path(self.artifact['path']).write_bytes(b'changed')
        with self.assertRaises(HTTPError) as error:
            self.fetch('/api/machines/a/secret-a/downloads/agent/windows_x86_64')
        self.assertEqual(error.exception.code, 409)

    def test_download_barrier_holds_after_first_chunk_and_releases_exact_binary(self):
        import threading
        path = Path(self.artifact['path'])
        path.write_bytes(b'x' * 131072)
        self.artifact.update(size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.gateway.hold_download = True
        self.gateway.release_download.clear()
        results = []
        def read():
            results.append(self.fetch('/api/machines/a/secret-a/downloads/agent/windows_x86_64')[1])
        thread = threading.Thread(target=read)
        thread.start()
        try:
            self.assertTrue(self.gateway.download_started.wait(2))
            self.assertTrue(thread.is_alive())
            self.gateway.release_download.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(hashlib.sha256(results[0]).hexdigest(), self.artifact['sha256'])
        finally:
            self.gateway.release_download.set()
            thread.join(timeout=3)

    def test_sync_observations_bind_post_terminal_phase_to_monotonic_sequence(self):
        self.journal = {'phase': 'rolled-back'}
        self.fetch('/api/machines/client/sync', dict(machine_id='a', token='secret-a', client_version='1.11.34'))
        event = next(e for e in self.gateway.events if e['kind'] == 'sync')
        self.assertEqual(event['journal_phase'], 'rolled-back')
        self.assertEqual(event['handled'], '')
        self.assertGreater(event['sequence'], 0)
        self.assertGreater(event['monotonic'], 0)


if __name__ == '__main__':
    unittest.main()
