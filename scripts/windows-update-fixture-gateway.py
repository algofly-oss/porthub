"""Private loopback-only authenticated gateway for the disposable native updater gate.
Importing creates no listener or subprocess. This is never a production gateway.
"""
import hashlib
import json
from pathlib import Path
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Gateway:
    def __init__(self, artifacts, enrollments, journal):
        self.artifacts = artifacts
        self.enrollments = enrollments
        self.journal = journal
        self.lock = threading.Lock()
        self.events = []
        self.overflow = False
        self.active_connections = 0
        self.request = None
        self.fail_version = None
        self.hold_download = False
        self.download_started = threading.Event()
        self.release_download = threading.Event()
        self.release_download.set()
        self.candidate_sync_seen = threading.Event()
        self.rollback_sync_pulsed = False
        self.server = None

    def advertise(self, machine, version):
        if machine not in self.enrollments or version not in self.artifacts:
            raise ValueError('Unknown fixture enrollment/artifact')
        with self.lock:
            self.request = (machine, version, 'native-gate-' + uuid.uuid4().hex)
            return self.request[2]

    def headers(self, machine):
        with self.lock:
            request = self.request
        if request and request[0] == machine:
            return {'x-porthub-client-update-requested': 'true',
                    'x-porthub-client-update-request-id': request[2],
                    'x-porthub-client-target-version': request[1]}
        return {}

    def authorize(self, machine, token):
        return machine in self.enrollments and token == self.enrollments[machine]

    def record(self, value):
        with self.lock:
            if value.get('kind') == 'request-observed' and any(e.get('kind') == value['kind'] and e.get('machine') == value.get('machine') and e.get('request_id') == value.get('request_id') for e in self.events):
                return
            if len(self.events) >= 4096:
                self.overflow = True
                return
            self.events.append(dict(value, sequence=len(self.events) + 1, monotonic=time.monotonic()))

    def start(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(10)
                with owner.lock:
                    owner.active_connections += 1

            def finish(self):
                try:
                    super().finish()
                finally:
                    with owner.lock:
                        owner.active_connections -= 1

            def log_message(self, *_):
                pass  # Enrollment tokens are present in release URLs.

            def reply(self, status, value=None, headers=None):
                body = b'' if value is None else json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Content-Type', 'application/json')
                for key, val in (headers or {}).items():
                    self.send_header(key, val)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_POST(self):
                if urlsplit(self.path).path != '/api/machines/client/sync':
                    return self.reply(404)
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 65536:
                        return self.reply(413)
                    value = json.loads(self.rfile.read(length))
                except (ValueError, UnicodeError):
                    return self.reply(400)
                machine = value.get('machine_id')
                if not owner.authorize(machine, value.get('token')):
                    return self.reply(403)
                version = value.get('client_version')
                handled = value.get('client_update_last_handled_request_id')
                record = owner.journal(machine)
                if handled:
                    artifact = owner.artifacts.get(version)
                    if (not artifact or not record or record.get('phase') != 'committed'
                            or record.get('request', {}).get('id') != handled
                            or record.get('release', {}).get('version') != version
                            or record.get('release', {}).get('sha256') != artifact['sha256']
                            or record.get('source_revision') != artifact.get('source')):
                        owner.record({'kind': 'invalid-ack', 'machine': machine})
                        return self.reply(409)
                owner.record({'kind': 'sync', 'machine': machine,
                              'version': version, 'handled': handled or '',
                              'journal_phase': record.get('phase') if record else None})
                if version == owner.fail_version:
                    owner.candidate_sync_seen.set()
                    return self.reply(503)
                config = {'machine_id': machine, 'version': 'native-update-gate',
                          'files': {'client.toml': "[client]\nremote_addr='ws://127.0.0.1:9'\n"}}
                headers = owner.headers(machine)
                if headers:
                    owner.record({'kind': 'request-observed', 'machine': machine,
                                  'request_id': headers['x-porthub-client-update-request-id'],
                                  'target_version': headers['x-porthub-client-target-version']})
                return self.reply(200, {'data': {'config': config}}, headers)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == '/api/machines/client/changes.toml':
                    query = parse_qs(parsed.query)
                    machine = query.get('machine_id', [''])[0]
                    if not owner.authorize(machine, query.get('token', [''])[0]):
                        return self.reply(403)
                    time.sleep(.1)  # Bound fixture polling CPU; never a timing proof.
                    headers = owner.headers(machine)
                    if headers:
                        owner.record({'kind': 'request-observed', 'machine': machine,
                                  'request_id': headers['x-porthub-client-update-request-id'],
                                  'target_version': headers['x-porthub-client-target-version']})
                    headers.update({'x-porthub-machine-id': machine,
                                    'x-porthub-config-version': 'native-update-gate'})
                    record = owner.journal(machine)
                    if (record and record.get('phase') == 'rolled-back' and headers.get('x-porthub-client-update-request-id')
                            and not owner.rollback_sync_pulsed):
                        owner.rollback_sync_pulsed = True
                        owner.record({'kind': 'rollback-sync-pulse', 'machine': machine})
                        return self.reply(503)  # Exercise ordinary retry→sync, not a faster client default.
                    self.reply(204, headers=headers)
                    owner.record({'kind': 'changes-cycle', 'machine': machine,
                                  'request_id': headers.get('x-porthub-client-update-request-id'),
                                  'target_version': headers.get('x-porthub-client-target-version'),
                                  'journal_phase': record.get('phase') if record else None})
                    return
                parts = parsed.path.strip('/').split('/')
                if len(parts) < 6 or parts[:2] != ['api', 'machines'] or parts[4] != 'downloads':
                    return self.reply(404)
                machine, token = parts[2:4]
                if not owner.authorize(machine, token):
                    return self.reply(403)
                with owner.lock:
                    request = owner.request
                if not request or request[0] != machine:
                    return self.reply(404)
                artifact = owner.artifacts[request[1]]
                if parts[5:] == ['releases']:
                    release = {key: artifact[key] for key in
                               ('target', 'os', 'arch', 'asset', 'version', 'sha256', 'size')}
                    return self.reply(200, {'format_version': 1, 'machine_id': machine,
                                            'releases': [release]})
                if parts[5:] != ['agent', artifact['target']]:
                    return self.reply(404)
                path = Path(artifact['path'])
                with path.open('rb') as check:
                    digest = hashlib.file_digest(check, 'sha256').hexdigest()
                if path.stat().st_size != artifact['size'] or digest != artifact['sha256']:
                    owner.record({'kind': 'artifact-changed'})
                    return self.reply(409)
                owner.record({'kind': 'download', 'machine': machine, 'version': request[1]})
                self.send_response(200)
                for key, val in {'Content-Length': str(artifact['size']),
                                 'x-porthub-agent-target': artifact['target'],
                                 'x-porthub-agent-release': artifact['version'],
                                 'x-porthub-agent-sha256': artifact['sha256']}.items():
                    self.send_header(key, val)
                self.end_headers()
                try:
                    with path.open('rb') as stream:
                        first = True
                        while block := stream.read(65536):
                            self.wfile.write(block)
                            if first and owner.hold_download:
                                self.wfile.flush()
                                owner.download_started.set()
                                if not owner.release_download.wait(60):
                                    owner.record({'kind': 'download-barrier-timeout'})
                                    return
                            first = False
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Cancellation is a tested expected outcome.

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.server.timeout = 1
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.release_download.set()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError('Fixture gateway did not stop')
            deadline = time.monotonic() + 11
            while self.active_connections and time.monotonic() < deadline:
                time.sleep(.02)
            if self.active_connections:
                raise RuntimeError('Fixture HTTP handlers did not drain')
