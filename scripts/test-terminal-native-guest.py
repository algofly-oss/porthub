#!/usr/bin/env python3
"""Scoped native CLI guest smoke. Credentials arrive on stdin; never print them."""
import json
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import struct
import time


def main():
    data = json.load(sys.stdin)
    executable = str(Path(data['nativeGuest']).resolve(strict=True))
    invitation = data['invitation']
    host = data['host']
    owner = shlex.split(data['ownerPrefix'])
    name = data['name']
    marker = data['marker']
    children = {}
    with tempfile.TemporaryDirectory(prefix='porthub-native-guest-') as directory:
        def start(url):
            pid, fd = pty.fork()
            if pid == 0:
                env = dict(os.environ, TERM='xterm-256color',
                           XDG_DATA_HOME=directory+'/data', XDG_CONFIG_HOME=directory+'/config')
                try:
                    fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack('HHHH',40,120,0,0))
                    os.execve(executable, [executable, 'terminal', 'join', url, '--transport', 'relay'], env)
                except Exception:
                    os._exit(127)
            children[pid] = fd
            return pid, fd

        def expect(fd, needle, timeout=20):
            deadline = time.monotonic()+timeout
            output = b''
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], min(1, max(0, deadline-time.monotonic())))
                if not ready:
                    continue
                try:
                    chunk = os.read(fd, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                output = (output+chunk)[-262144:]
                if needle in output:
                    return
            diagnostic=output.decode('utf-8',errors='replace')
            for key in ('interactive_url','read_only_url'):
                diagnostic=diagnostic.replace(invitation[key].rsplit('#',1)[-1],'[invitation]')
            raise RuntimeError('Native guest did not render '+repr(needle.decode('utf-8',errors='replace'))+': '+repr(diagnostic[-1000:]))

        def detach(pid):
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    os.close(children.pop(pid))
                    if os.waitstatus_to_exitcode(status) != 0:
                        raise RuntimeError('Native guest did not detach cleanly on SIGTERM')
                    return
                time.sleep(.05)
            raise RuntimeError('Native guest detach timed out')

        def remote(args):
            result = subprocess.run(['ssh', '-oBatchMode=yes', host, shlex.join([*owner, *args])],
                                    capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Owned native guest workspace verification failed')
            return result.stdout
        try:
            pid, fd = start(invitation['interactive_url'])
            expect(fd, b'porthub-live$')
            os.write(fd, ("printf '\\r\\nNATIVE_SUCCESS_%s\\r\\n' "+shlex.quote(marker)+"\r").encode())
            expect(fd, ('NATIVE_SUCCESS_'+marker).encode())
            detach(pid)
            jobs = json.loads(remote(['list', '--json']))
            if not any(job.get('name') == name and job.get('state') == 'running' for job in jobs):
                raise RuntimeError('Native guest detach ended the shared workspace')
            pid, fd = start(invitation['read_only_url'])
            expect(fd, b'porthub-live$')
            forbidden = 'NATIVE_READONLY_'+marker
            os.write(fd, ('echo '+forbidden+'\r').encode()+b'\x1b[18~')
            expect(fd, b'Scrollback')
            # Snapshot response is generated after navigation; verify against the
            # host history so an input leak cannot hide behind the guest display.
            capture = remote(['tmux', name, '--', 'capture-pane', '-p', '-S', '-1000'])
            if forbidden.encode() in capture:
                raise RuntimeError('Read-only native navigation leaked shell input')
            detach(pid)
            print('PASS native CLI relay: shared shell I/O, read-only F7 history, clean detach and workspace persistence')
        finally:
            for pid, fd in list(children.items()):
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(fd)


if __name__ == '__main__':
    main()
