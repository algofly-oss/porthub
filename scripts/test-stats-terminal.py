#!/usr/bin/env python3
"""Exercise the real stats screen on an isolated Unix PTY and local broker."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time


def wait_text(master, child, expected, timeout=5):
    data = bytearray()
    deadline = time.monotonic() + timeout
    while expected not in data:
        if time.monotonic() >= deadline or child.poll() is not None:
            raise AssertionError(f"stats screen did not show {expected!r}: {bytes(data[-1000:])!r}")
        if select.select([master], [], [], 0.05)[0]:
            data.extend(os.read(master, 65536))
    return data


def screen(executable, config, stalled=False, accepted=None):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    def own_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    child = subprocess.Popen([executable, "stats", "--user"], stdin=slave, stdout=slave, stderr=slave,
        env={**os.environ, "XDG_CONFIG_HOME": str(config), "TERM": "xterm-256color"}, preexec_fn=own_terminal)
    try:
        wait_text(master, child, b"PortHub stats")
        if stalled:
            assert accepted.wait(3), "stats must start a local broker request"
        if not stalled:
            os.write(master, b" ")
            wait_text(master, child, b"PAUSED")
            os.write(master, b" ")
            wait_text(master, child, b"LIVE")
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 100, 0, 0))
            os.write(master, b"cmtn\r\x1b[B\x1b[A")
        # Quit must remain responsive even when a trusted agent accepts the
        # broker socket but never responds. Collection cannot block key input.
        started = time.monotonic()
        os.write(master, b"q")
        output = bytearray()
        while child.poll() is None and time.monotonic() - started < 1.5:
            if select.select([master], [], [], 0.02)[0]:
                output.extend(os.read(master, 65536))
        assert child.poll() == 0, f"stats quit must not wait for background collection: {bytes(output[-1200:])!r}"
        assert time.monotonic() - started < 1.5
        assert termios.tcgetattr(slave) == before, "stats must restore terminal settings"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        os.close(master)
        os.close(slave)


def main():
    executable = str(Path(sys.argv[1]).resolve())
    # /tmp also keeps the broker socket short enough on macOS's long TMPDIR.
    with tempfile.TemporaryDirectory(prefix="phstats-", dir="/tmp") as directory:
        config = Path(directory) / "config"
        config.mkdir()
        screen(executable, config)
        single = subprocess.run([executable, "stats", "--user", "--once", "--json"],
            env={**os.environ, "XDG_CONFIG_HOME": str(config)}, capture_output=True, check=True, timeout=5)
        assert json.loads(single.stdout)["agents"] == []
        status = config / "porthub/status"
        status.mkdir(parents=True, mode=0o755)
        identity = "a" * 64
        record = {"format_version": 1, "id": identity, "machine_id": "b" * 24,
            "email": "fixture@example.test", "gateway": "https://example.test", "private": False,
            "enabled": True, "active": True, "state": "running", "agent_version": "test", "ports": 1,
            "route": "direct", "updated_at": int(time.time()), "strategy": "auto", "strategy_override": False}
        path = status / f"{identity}.json"
        path.write_text(json.dumps(record))
        path.chmod(0o644)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(status / f"{identity[:24]}.sock"))
        listener.listen(2)
        stop = threading.Event()
        accepted = threading.Event()
        def stuck_agent():
            listener.settimeout(4)
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    assert b"agent_stats" in connection.recv(1024)
                    accepted.set()
                    stop.wait(4)
            except (TimeoutError, OSError):
                pass
        thread = threading.Thread(target=stuck_agent, daemon=True)
        thread.start()
        try:
            screen(executable, config, stalled=True, accepted=accepted)
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=1)
    print("PASS stats PTY: raw-mode restoration, pause/resume, resize, sort keys, JSON, responsive quit with stalled agent")


if __name__ == "__main__":
    main()
