#!/usr/bin/env python3
"""Check the exported portal at phone and desktop sizes in both browser engines."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import threading


class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        candidate = super().translate_path(path)
        return candidate + '.html' if not Path(candidate).exists() and Path(candidate + '.html').is_file() else candidate

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if not (root / 'home.html').is_file():
        parser.error('Exported home.html is required')
    repository = Path(__file__).resolve().parents[1]
    scripts = ('layout-settling.cjs', 'iphone-layout.cjs', 'iphone-safe-area.cjs',
               'iphone-native-media.cjs', 'native-media-browser.cjs',
               'private-network-growth.cjs')
    with ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(root))) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for engine in ('chromium', 'webkit'):
                env = {**os.environ, 'REVIEW_BROWSER': engine,
                       'REVIEW_ORIGIN': 'http://127.0.0.1:' + str(server.server_port)}
                for script in scripts:
                    print(engine + ': ' + script, flush=True)
                    subprocess.run(['node', str(repository / 'ui/tests' / script)],
                                   cwd=repository, env=env, check=True, timeout=180)
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
