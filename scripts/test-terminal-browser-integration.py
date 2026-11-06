#!/usr/bin/env python3
"""Exercise exported UI -> real API -> broker -> bundled PTY with isolated state."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import subprocess
import threading
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def run(environment, command=None):
    command = command or ['cargo', 'test', '--locked', '-p', 'porthub-api', '--test',
               'terminal_browser',
               'ordinary_ssh_and_https_share_one_tls_port_with_real_terminal_participants',
               '--', '--include-ignored', '--nocapture']
    process = subprocess.Popen(command, cwd=ROOT, env=environment, start_new_session=True)
    try:
        code = process.wait(timeout=180)
        if code:
            raise subprocess.CalledProcessError(code, command)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ui-root', type=Path, required=True)
    parser.add_argument('--browser', choices=['chromium', 'webkit', 'all'], default='all')
    parser.add_argument('--transport', choices=['direct', 'blocked', 'all'], default='all')
    args = parser.parse_args()
    ui = args.ui_root.resolve()
    if not (ui / 'terminal.html').is_file():
        parser.error('Exported terminal.html is required')
    mongo = urlsplit(os.environ.get('PORTHUB_TEST_MONGO_URI', ''))
    if mongo.scheme != 'mongodb' or mongo.hostname not in ('127.0.0.1', '::1', 'localhost'):
        parser.error('An isolated loopback PORTHUB_TEST_MONGO_URI is required')
    for name in ['PORTHUB_TEST_AGENT_EXECUTABLE', 'PORTHUB_TEST_TERMINAL_BUNDLE']:
        if not Path(os.environ.get(name, '')).is_file():
            parser.error(f'{name} must point to a built local artifact')
    if not os.environ.get('PORTHUB_TEST_TERMINAL_TARGET'):
        parser.error('PORTHUB_TEST_TERMINAL_TARGET is required')

    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            if (ui / (path.lstrip('/') + '.html')).is_file():
                self.path = path + '.html'
            super().do_GET()

        def log_message(self, *_args):
            pass

    browsers = ['chromium', 'webkit'] if args.browser == 'all' else [args.browser]
    transports = ['direct', 'blocked'] if args.transport == 'all' else [args.transport]
    with ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(ui))) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for browser in browsers:
                preview = dict(os.environ, REVIEW_ORIGIN=f'http://127.0.0.1:{server.server_port}', REVIEW_BROWSER=browser)
                print(f'Verify terminal dashboard: {browser}', flush=True)
                run(preview, ['node', str(ROOT / 'ui/tests/terminal-dashboard.cjs')])
                run(preview, ['node', str(ROOT / 'ui/tests/terminal-connectivity.cjs')])
                for transport in transports:
                    print(f'Verify terminal sharing: {browser}, {transport}', flush=True)
                    environment = dict(os.environ,
                                       # The enrolled control fixture uses loopback
                                       # HTTP explicitly. Software stays in its
                                       # seeded verified cache with HTTPS-only
                                       # download authorities, as in production.
                                       PORTHUB_COMPONENT_GATEWAY='https://components-fixture.invalid',
                                       PORTHUB_TEST_UI_ORIGIN=f'http://127.0.0.1:{server.server_port}',
                                       PORTHUB_TEST_NATIVE_HOST='1',
                                       PORTHUB_TEST_TERMINAL_DIRECT='1' if transport == 'direct' else 'blocked',
                                       REVIEW_BROWSER=browser)
                    run(environment)
        finally:
            server.shutdown()
            worker.join(timeout=5)


if __name__ == '__main__':
    main()
