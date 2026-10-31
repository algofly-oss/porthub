#!/usr/bin/env python3
"""Exercise a packaged CLI and its embedded helper without agent registration."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='porthub-packaged-terminal-') as temporary:
        environment = {**os.environ, 'XDG_DATA_HOME': temporary, 'TERM': 'xterm-256color'}
        environment.pop('TMUX', None)
        environment.pop('TMUX_PANE', None)
        def call(*arguments):
            result = subprocess.run([executable, *arguments], env=environment,
                                    capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise RuntimeError('Packaged terminal command failed: '+result.stderr[-1500:])
            return result.stdout
        try:
            call('version')
            job = json.loads(call('terminal', 'crosssmoke', '--detach', '--json', '--shell', '/bin/sh'))
            assert job['shared'] is False
            reopened = json.loads(call('terminal', 'crosssmoke', '--detach', '--json'))
            assert reopened['id'] == job['id'], 'reopening must preserve the workspace identity'
            call('terminal', 'tmux', 'crosssmoke', '--', 'send-keys', '-t', '%0',
                 "persistvalue=packagedstate; printf 'PACKAGED%s\\n' 'READY'", 'Enter')
            def wait_capture(marker):
                deadline = time.monotonic()+15
                while marker not in call('terminal', 'tmux', 'crosssmoke', '--', 'capture-pane', '-p', '-t', '%0'):
                    assert time.monotonic()<deadline, 'packaged terminal did not produce the expected shell output'
                    time.sleep(.1)
            wait_capture('PACKAGEDREADY')
            call('terminal', 'tmux', 'crosssmoke', '--', 'send-keys', '-t', '%0',
                 "printf 'PERSIST%s\\n' \"$persistvalue\"", 'Enter')
            wait_capture('PERSISTpackagedstate')
            call('terminal', 'tmux', 'crosssmoke', '--', 'send-keys', '-t', '%0', 'C-d')
            deadline = time.monotonic()+15
            while next(row for row in json.loads(call('terminal', 'list', '--json')) if row['id']==job['id'])['state'] != 'ended':
                assert time.monotonic()<deadline, 'explicit Ctrl+D must end the final shell'
                time.sleep(.1)
        finally:
            with contextlib.suppress(Exception):
                call('terminal', 'stop', 'crosssmoke')
    print('PASS packaged CLI/helper: no registration, detached workspace, named reopen, shared shell state and explicit Ctrl+D teardown')


if __name__ == '__main__':
    main()
