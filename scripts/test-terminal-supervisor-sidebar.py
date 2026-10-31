#!/usr/bin/env python3
"""Real CLI sidebar against the sharing supervisor's private owner control socket."""
import json
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from terminal_pty_fixture import TERMINAL_KEEPER, assert_terminal_restored


def main():
    executable, identity = sys.argv[1:3]
    target=int(sys.argv[3]) if len(sys.argv)>3 else 2
    remote=len(sys.argv)>3
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
    report_read, report_write = os.pipe()
    def terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    child = subprocess.Popen([sys.executable, '-c', TERMINAL_KEEPER, str(report_write),
        executable, 'terminal', 'attach', identity, '--sidebar', 'on'],
        stdin=slave, stdout=slave, stderr=slave, pass_fds=(report_write,), preexec_fn=terminal)
    os.close(report_write)
    pending = bytearray()
    def wait(text, timeout=8):
        deadline = time.monotonic()+timeout
        while text not in pending:
            assert time.monotonic()<deadline and child.poll() is None, f'sidebar missing {text!r}: {bytes(pending[-1200:])!r}'
            if select.select([master], [], [], .05)[0]:
                pending.extend(os.read(master, 65536))
        pending.clear()
    try:
        wait(f'{target} read'.encode())
        listing=subprocess.run([executable,'terminal','participants',identity,'--json'],capture_output=True,check=True)
        members=json.loads(listing.stdout)['members']
        index=next(i for i,member in enumerate(members) if member['id']==target)
        os.write(master, b'\x1b[19~')  # Focus private sidebar.
        time.sleep(.1)
        os.write(master, b'\x1b[B'*index+b'k')
        wait(f'Remove {target}?'.encode())
        os.write(master, b'n')
        wait(b'Removing a guest leaves')
        os.write(master, b'k')
        wait(f'Remove {target}?'.encode())
        os.write(master, b'y')
        wait(b'Guest removed')
        os.write(master, b'q')
        time.sleep(.1)
        variable=b"$OWNVAR" if remote else b"$PORTSTATE"
        os.write(master,b'printf \'SIDEBAR%s:%s\\n\' \'OWNER\' "'+variable+b'"\r')
        wait(b'SIDEBAROWNER:preserved')
        os.write(master, b'\x01d')
        deadline=time.monotonic()+5
        while child.poll() is None:
            assert time.monotonic()<deadline, 'sidebar detach stalled'
            if select.select([master], [], [], .05)[0]: os.read(master,65536)
        assert child.returncode == 0, 'normal sidebar detach must succeed'
        assert_terminal_restored(report_read)
        print('PASS native sidebar through real sharing supervisor: presence, cancel/confirm removal, shared shell state, clean detach and terminal restoration', flush=True)
    finally:
        if child.poll() is None:
            try: os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=3)
        os.close(master)
        os.close(slave)
        os.close(report_read)


if __name__ == '__main__': main()
