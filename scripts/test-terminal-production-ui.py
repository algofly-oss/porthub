#!/usr/bin/env python3
"""Load the actual exported terminal page with Chrome, without an API/account."""
import argparse
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit


class TerminalDOM(HTMLParser):
    def __init__(self):
        super().__init__()
        self.screen = False
        self.terminal = False

    def handle_starttag(self, tag, attrs):
        classes = dict(attrs).get('class', '').split()
        self.screen |= 'xterm-screen' in classes
        self.terminal |= 'xterm' in classes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--chrome', default=shutil.which('google-chrome') or shutil.which('chromium'))
    args = parser.parse_args()
    root = args.root.resolve()
    if not args.chrome or not (root/'terminal.html').is_file():
        parser.error('A Chrome executable and exported terminal.html are required')
    failures = []

    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if urlsplit(self.path).path == '/terminal':
                self.path = '/terminal.html'
            super().do_GET()

        def send_response(self, code, message=None):
            if code >= 400 and self.path.startswith(('/_next/', '/terminal')):
                failures.append((self.path, code))
            super().send_response(code, message)

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(root))) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='porthub-terminal-browser-') as profile:
                result = subprocess.run([
                    args.chrome, '--headless', '--no-sandbox', '--disable-gpu',
                    '--no-first-run', '--disable-background-networking',
                    '--user-data-dir='+profile, '--virtual-time-budget=8000',
                    '--dump-dom', f'http://127.0.0.1:{server.server_port}/terminal',
                ], capture_output=True, text=True, timeout=45)
            dom = TerminalDOM()
            dom.feed(result.stdout)
            if result.returncode or failures or not (dom.terminal and dom.screen):
                raise RuntimeError('Exported terminal failed browser initialization: '+
                                   repr({'exit': result.returncode, 'asset_failures': failures,
                                         'terminal': dom.terminal, 'screen': dom.screen}))
            if 'The terminal could not load.' in result.stdout:
                raise RuntimeError('Exported terminal displays its initialization error')
            print('PASS production terminal: exported assets initialize xterm and its screen in Chrome')
        finally:
            server.shutdown()
            worker.join(timeout=5)


if __name__ == '__main__':
    main()
