import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


s = load('hybrid-server-build')
h = load('hybrid-native-build')
r = load('hybrid-native-release')
SOURCE = 'a'*40
ARM = 'aarch64-unknown-linux-musl'


class ServerTests(unittest.TestCase):
    def test_unconfigured_depot_immediately_keeps_all_hosted_targets(self):
        result = s.resolve(Path('/unused'), SOURCE, 'all', '', Path('/unused'), h)
        self.assertEqual(len(result['hosted']), 2)
        self.assertEqual(result['local_arches'], [])

    def test_source_manifest_disjoint_maps_survive_concurrent_publication(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(h, 'command') as upload:
            output = Path(temp)
            barrier = threading.Barrier(2)
            def publish(group):
                barrier.wait()
                h.publish_manifest({'upload':['upload']}, SOURCE, output,
                    {'schema_version':1,'source_revision':SOURCE,group:{group:True}}, group)
            threads = [threading.Thread(target=publish, args=(group,)) for group in ('targets','servers')]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            value = json.loads((output/'manifest.json').read_text())
            self.assertEqual(value['servers'], {'servers':True})
            self.assertEqual(value['targets'], {'targets':True})
            self.assertEqual(upload.call_count, 2)
            # Invalid own-map entries can be removed, but other map is retained.
            h.publish_manifest({'upload':['upload']}, SOURCE, output, {'schema_version':1,'source_revision':SOURCE,'targets':{}})
            value = json.loads((output/'manifest.json').read_text())
            self.assertEqual(value['targets'], {})
            self.assertEqual(value['servers'], {'servers':True})

    def test_manifest_upload_resume_does_not_upload_unchanged_bytes(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(h, 'command') as upload:
            output = Path(temp)
            value = {'schema_version':1,'source_revision':SOURCE,'targets':{}}
            h.publish_manifest({'upload':['upload']}, SOURCE, output, value)
            h.publish_manifest({'upload':['upload']}, SOURCE, output, value)
            self.assertEqual(upload.call_count, 1)

    def test_foreign_manifest_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(h, 'command') as upload:
            output = Path(temp)
            original = json.dumps({'schema_version':1,'source_revision':'b'*40})
            (output/'manifest.json').write_text(original)
            with self.assertRaises(ValueError):
                h.publish_manifest({'upload':['upload']}, SOURCE, output, {'schema_version':1,'source_revision':SOURCE,'targets':{}})
            self.assertEqual((output/'manifest.json').read_text(), original)
            upload.assert_not_called()

    def test_completed_client_only_checkpoint_does_not_skip_new_server_config(self):
        row = {'complete':True}
        self.assertTrue(r.cohort_complete(row, {}))
        config = {'server_builders':[{'target':ARM}]}
        self.assertFalse(r.cohort_complete(row, config))
        row['servers'] = {ARM:{'status':'local_verified'}}
        self.assertTrue(r.cohort_complete(row, config))

    def test_actual_container_cpu_headroom_and_io_caps_required(self):
        limits = {'host_cpus':2,'cpus':1,'jobs':1,'memory_bytes':6*1024**3,'pids':384,
                  'read_bps':40*1024**2,'write_bps':40*1024**2,'io_device_number':'8:0',
                  'observed':{'cpu.max':'100000 100000','memory.max':str(6*1024**3),
                              'memory.swap.max':'0','pids.max':'384','io.max':'8:0 rbps=41943040 wbps=41943040'}}
        s.verify_limits(limits)
        for key, value in [('cpus',2),('jobs',2)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.verify_limits(dict(limits, **{key:value}))
        with self.assertRaises(ValueError):
            s.verify_limits(dict(limits, observed=dict(limits['observed'], **{'memory.swap.max':'max'})))

    def test_zip_traversal_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('../outside','/absolute','a\\b'):
                with self.subTest(name=name):
                    archive = root/'server.zip'
                    with zipfile.ZipFile(archive, 'w') as z: z.writestr(name, b'x')
                    with self.assertRaises(ValueError): s.unpack(archive, root/'out')
            with zipfile.ZipFile(root/'server.zip','w') as z:
                info = zipfile.ZipInfo('link'); info.external_attr = 0o120777 << 16
                z.writestr(info, 'target')
            with self.assertRaises(ValueError): s.unpack(root/'server.zip', root/'out')

    def test_cache_rejects_foreign_marker_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp)/'cache'
            s.safe_cache(cache, create=True)
            (cache/'.porthub-server-cache-v1').write_text('unrelated')
            with self.assertRaises(ValueError): s.safe_cache(cache)
            link = Path(temp)/'link'; link.symlink_to(cache)
            with self.assertRaises(ValueError): s.safe_cache(link)

    def test_cached_verified_server_archive_retries_upload_without_build(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output/'manifest.json').write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'targets':{}}))
            folder = output/('server-'+ARM); folder.mkdir()
            (folder/'server.zip').write_bytes(b'cached-verified-by-fixture')
            config = {'server_builders':[{'target':ARM,'probe':['probe'],'build':['build'],'fetch':['fetch']}],
                      'depot':{'upload':['upload'],'base_url':'https://trusted.example/builds'}}
            with patch.object(s,'verify_archive') as verify, patch.object(h,'source_supported',return_value=True), patch.object(h,'command') as command:
                result = s.control(output,SOURCE,config,output,h)
            self.assertEqual(result['targets'][ARM]['status'],'local_verified')
            verify.assert_called_once()
            self.assertTrue(all(call.args[0] == ['upload'] for call in command.call_args_list))

    def test_tampered_cached_server_archive_never_uploads_or_rebuilds(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output/'manifest.json').write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'targets':{}}))
            folder = output/('server-'+ARM); folder.mkdir()
            (folder/'server.zip').write_bytes(b'tampered')
            config = {'server_builders':[{'target':ARM,'probe':['probe'],'build':['build'],'fetch':['fetch']}],
                      'depot':{'upload':['upload'],'base_url':'https://trusted.example/builds'}}
            with patch.object(s,'verify_archive',side_effect=ValueError('tampered')), patch.object(h,'source_supported',return_value=True), patch.object(h,'command') as command:
                result = s.control(output,SOURCE,config,output,h)
            self.assertEqual(result['targets'][ARM]['failed_phase'],'verify')
            # A redacted unavailable manifest can be uploaded; no archive/build.
            self.assertTrue(all(call.args[1]['key'].endswith('/manifest.json') for call in command.call_args_list))

    def test_resolver_rejects_cross_source_url_before_download(self):
        row = {'status':'ready','sha256':'b'*64,'size':100,
               'url':'https://trusted.example/builds/'+('c'*40)+'/'+ARM+'/'+('b'*64)+'.zip'}
        with patch.object(h,'download') as download, self.assertRaises(ValueError):
            s.restore(Path('/unused'), SOURCE, ARM, 'https://trusted.example/builds', row, Path('/unused'), h)
        download.assert_not_called()

    def test_client_only_manifest_gets_discovery_grace_until_building_and_ready(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rows = [{}, {ARM:{'status':'building','deadline_unix':1000}},
                    {ARM:{'status':'ready'}}]
            clock = [0]
            downloads = []
            def download(url, path, maximum, deadline):
                downloads.append(url)
                path.write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'targets':{},'servers':rows.pop(0)}))
            def sleep(seconds): clock[0] += seconds
            with patch.object(h,'download',side_effect=download), patch.object(s,'restore') as restore, \
                    patch.object(s.time,'monotonic',side_effect=lambda:clock[0]), \
                    patch.object(s.time,'time',return_value=100), patch.object(s.time,'sleep',side_effect=sleep):
                result = s.resolve(root,SOURCE,'arm64','https://trusted.example/builds',root/'out',h)
            self.assertEqual(len(downloads),3)
            self.assertEqual(result['hosted'],[])
            self.assertEqual(result['local_arches'],['arm64'])
            restore.assert_called_once()

    def test_explicit_server_unavailable_is_immediate_even_within_grace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def download(url,path,maximum,deadline):
                path.write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'servers':{ARM:{'status':'unavailable'}}}))
            with patch.object(h,'download',side_effect=download), patch.object(s.time,'sleep') as sleep:
                result = s.resolve(root,SOURCE,'arm64','https://trusted.example/builds',root/'out',h)
            self.assertEqual(len(result['hosted']),1)
            sleep.assert_not_called()

    def test_missing_server_announcement_expires_to_hosted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); clock = [0]
            def download(url,path,maximum,deadline):
                path.write_text(json.dumps({'schema_version':1,'source_revision':SOURCE,'targets':{}}))
            def sleep(seconds): clock[0] += seconds
            with patch.object(h,'download',side_effect=download), patch.object(s.time,'monotonic',side_effect=lambda:clock[0]), patch.object(s.time,'sleep',side_effect=sleep):
                result = s.resolve(root,SOURCE,'arm64','https://trusted.example/builds',root/'out',h,initial_wait=30)
            self.assertEqual(clock[0],30)
            self.assertEqual(len(result['hosted']),1)

    def test_archive_source_change_during_verification_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root/'input.zip'; output = root/'verified'
            with zipfile.ZipFile(archive,'w') as stream: stream.writestr('file',b'input')
            with patch.object(s,'expected',side_effect=[{'tree':'old'},{'tree':'new'}]), patch.object(s,'verify_tree',return_value={}):
                with self.assertRaises(ValueError): s.verify_archive(root,SOURCE,ARM,archive,output)
            self.assertFalse(output.exists())

    def test_archive_bytes_changed_during_verification_fail_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root/'input.zip'; output = root/'verified'
            with zipfile.ZipFile(archive,'w') as stream: stream.writestr('file',b'input')
            def mutate(*args): archive.write_bytes(b'changed'); return {}
            with patch.object(s,'expected',return_value={'tree':'same'}), patch.object(s,'verify_tree',side_effect=mutate):
                with self.assertRaises(ValueError): s.verify_archive(root,SOURCE,ARM,archive,output)
            self.assertFalse(output.exists())

    def test_workflow_reuses_configured_depot_and_keeps_all_final_gates(self):
        text = Path(__file__).parents[1].joinpath('.github/workflows/server-platforms.yml').read_text()
        self.assertIn('vars.PORTHUB_TRUSTED_NATIVE_DEPOT', text)
        self.assertNotIn('vars.PORTHUB_NATIVE_BUILD_DEPOT_URL', text)
        self.assertIn("needs.server-plan.outputs.hosted_count == '0'", text)
        self.assertIn("needs.ui.result == 'success'", text)
        self.assertIn("needs.terminal-measurements.result == 'success'", text)
        self.assertIn('fromJSON(needs.server-plan.outputs.hosted)', text)
        self.assertIn('fromJSON(needs.server-plan.outputs.matrix)', text)
        self.assertIn('--source-revision "$SOURCE"', text)


if __name__ == '__main__': unittest.main()
