#!/usr/bin/env python3
"""Real PTY checks of owner selection/removal against an isolated private socket."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
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


def terminal_state(fd):
    state = termios.tcgetattr(fd)
    state[6] = [value[0] if isinstance(value, bytes) else value for value in state[6]]
    return state


# Retain a controlling session leader until the app exits and its mode is read.
# Darwin invalidates slave ioctls after the controlling session ends; checking
# before that end verifies restoration without weakening the assertion.
TERMINAL_KEEPER = r"""
import json, os, subprocess, sys, termios
report = int(sys.argv[1])
result = subprocess.run(sys.argv[2:])
state = termios.tcgetattr(0)
state[6] = [value[0] if isinstance(value, bytes) else value for value in state[6]]
os.write(report, json.dumps(state).encode())
os.close(report)
raise SystemExit(result.returncode)
"""

def exercise(executable, environment, job, stalled=False, sidebar=False, columns=100):
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
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, columns, 0, 0))
    before = terminal_state(slave)
    def own_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    arguments = [executable, "terminal", "attach", job["id"]] if sidebar else [executable, "terminal", "participants", job["id"], "--watch"]
    report_read, report_write = os.pipe()
    child = subprocess.Popen([sys.executable, "-c", TERMINAL_KEEPER, str(report_write), *arguments],
                             stdin=slave, stdout=slave, stderr=slave, env=environment,
                             pass_fds=(report_write,), preexec_fn=own_terminal)
    os.close(report_write)
    try:
        if sidebar:
            wait_text(master, child, b"$" if columns < 60 else b"PortHub")
            root = Path(environment["XDG_DATA_HOME"]) / "porthub/terminal"
            arguments = [executable,"terminal","__participants-popup",str(root),job["id"],str(child.pid)]
            denied = subprocess.run(arguments,env=environment,capture_output=True,timeout=2)
            assert denied.returncode != 0, "unregistered clients cannot open owner controls"
            stale = Path(job["workspace"]) / f"owner-client-{child.pid}.lock"
            stale.touch(mode=0o600)
            try:
                denied = subprocess.run(arguments,env=environment,capture_output=True,timeout=2)
                assert denied.returncode != 0, "an unlocked stale lease cannot grant controls"
            finally:
                stale.unlink()
            os.write(master, b"\x01P")
        try:
            wait_text(master, child, b"Participants")
        except AssertionError:
            if sidebar:
                leases = list(Path(job["workspace"]).glob("owner-client-*.lock"))
                assert leases, "owner attachment must hold a private lease"
                client = leases[0].stem.split("-")[-1]
                root = Path(environment["XDG_DATA_HOME"]) / "porthub/terminal"
                probe = subprocess.run([executable,"terminal","__participants-popup",str(root),job["id"],client],env=environment,capture_output=True,timeout=2)
                raise AssertionError(f"popup failed: {probe.stderr!r} {probe.stdout!r}")
            raise
        if sidebar:
            panes = subprocess.run([executable,"terminal","tmux",job["id"],"--","list-panes","-a","-F","#{pane_id}"],env=environment,capture_output=True,check=True)
            assert len(panes.stdout.splitlines()) == 1, "participant popup must not create a shell pane"
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
        if sidebar:
            wait_text(master, child, b"$", timeout=1.5)
            assert child.poll() is None, "closing the popup must keep the owner attached"
            started = time.monotonic()
            os.write(master, b"\x01d")
        while child.poll() is None and time.monotonic() - started < 1.5:
            if select.select([master], [], [], .02)[0]:
                os.read(master, 65536)
        assert child.poll() == 0, "quit must not wait for a stalled owner socket"
        assert json.loads(os.read(report_read, 8192)) == before, "terminal mode must be restored before the controlling session exits"
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        stop.set()
        listener.close()
        thread.join(timeout=1)
        path.unlink(missing_ok=True)
        os.close(master)
        os.close(slave)
        os.close(report_read)


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
            exercise(executable, environment, job, sidebar=True)
            exercise(executable, environment, job, sidebar=True, columns=36)
            listed = subprocess.run([executable, "terminal", "list", "--json"], env=environment, capture_output=True, check=True)
            assert any(row["id"] == identity and row["state"] == "running" for row in json.loads(listed.stdout)), "closing the owner view must preserve its workspace"
        finally:
            subprocess.run([executable, "terminal", "stop", identity], env=environment, capture_output=True, check=True)
    print("PASS owner participants PTY: selection, cancellation, targeted removal, resize, terminal restoration, responsive stalled-socket quit, owner-targeted right popup and workspace persistence")


if __name__ == "__main__":
    main()
