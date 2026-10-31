#!/usr/bin/env python3
"""Real PTY checks of owner selection/removal against an isolated private socket."""
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
    output = bytearray()
    deadline = time.monotonic() + timeout
    while expected not in output:
        assert time.monotonic() < deadline and child.poll() is None, f"participant view did not show {expected!r}: {bytes(output[-1200:])!r}"
        if select.select([master], [], [], .05)[0]:
            output.extend(os.read(master, 65536))
    return output


def exercise(executable, environment, job, stalled=False):
    path = Path(job["workspace"]) / "owner.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(4)
    listener.settimeout(.2)
    stop, accepted = threading.Event(), threading.Event()
    members = [{"id": 100, "read_only": False, "joined_at": int(time.time()), "last_active_at": int(time.time())},
               {"id": 200, "read_only": True, "joined_at": int(time.time()), "last_active_at": int(time.time())}]
    removals = []

    def server():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(2)
                data = bytearray()
                while not data.endswith(b"\n") and len(data) < 256:
                    chunk = connection.recv(256)
                    if not chunk:
                        break
                    data.extend(chunk)
                if not data:
                    continue
                request = json.loads(data)
                accepted.set()
                if stalled:
                    stop.wait(4)
                    continue
                if request["operation"] == "kick":
                    removals.append(request["client"])
                    members[:] = [member for member in members if member["id"] != request["client"]]
                try:
                    connection.sendall(json.dumps({"connected": True, "members": members}).encode() + b"\n")
                except OSError:
                    pass
    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    before = termios.tcgetattr(slave)
    def own_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    child = subprocess.Popen([executable, "terminal", "participants", job["id"], "--watch"],
                             stdin=slave, stdout=slave, stderr=slave, env=environment, preexec_fn=own_terminal)
    try:
        wait_text(master, child, b"Participants")
        if stalled:
            assert accepted.wait(3), "owner query must start"
        else:
            wait_text(master, child, b"200 read")
            os.write(master, b"\x1b[Bk")
            wait_text(master, child, b"Remove 200? y / n")
            os.write(master, b"n")
            wait_text(master, child, b"Removing a guest leaves")
            assert removals == [], "cancel must not remove a guest"
            os.write(master, b"k")
            wait_text(master, child, b"Remove 200? y / n")
            os.write(master, b"y")
            wait_text(master, child, b"Guest removed")
            assert removals == [200], "only the selected guest must be removed"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 18, 40, 0, 0))
            os.write(master, b"\x1b[A")
        started = time.monotonic()
        os.write(master, b"q")
        while child.poll() is None and time.monotonic() - started < 1.5:
            if select.select([master], [], [], .02)[0]:
                os.read(master, 65536)
        assert child.poll() == 0, "quit must not wait for a stalled owner socket"
        assert termios.tcgetattr(slave) == before, "terminal mode must be restored"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        stop.set()
        listener.close()
        thread.join(timeout=1)
        path.unlink(missing_ok=True)
        os.close(master)
        os.close(slave)


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="phparticipants-", dir="/tmp") as temporary:
        data = Path(temporary) / "data"
        environment = {**os.environ, "XDG_DATA_HOME": str(data), "TERM": "xterm-256color"}
        created = subprocess.run([executable, "terminal", "paneltest", "--detach", "--json", "--shell", "/bin/sh"],
                                 env=environment, capture_output=True, check=True)
        identity = json.loads(created.stdout)["id"]
        job = json.loads((data / "porthub/terminal" / f"{identity}.json").read_text())
        try:
            exercise(executable, environment, job)
            exercise(executable, environment, job, stalled=True)
            listed = subprocess.run([executable, "terminal", "list", "--json"], env=environment, capture_output=True, check=True)
            assert any(row["id"] == identity and row["state"] == "running" for row in json.loads(listed.stdout)), "closing the owner view must preserve its workspace"
        finally:
            subprocess.run([executable, "terminal", "stop", identity], env=environment, capture_output=True, check=True)
    print("PASS owner participants PTY: selection, cancellation, targeted removal, resize, terminal restoration, responsive stalled-socket quit and workspace persistence")


if __name__ == "__main__":
    main()
