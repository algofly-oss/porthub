#!/usr/bin/env python3
"""Real PTY checks of owner selection/removal against an isolated private socket."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from terminal_pty_fixture import TERMINAL_KEEPER, assert_terminal_restored


def wait_text(master, child, expected, timeout=5):
    output = bytearray()
    deadline = time.monotonic() + timeout
    while expected not in output:
        assert time.monotonic() < deadline and child.poll() is None, f"participant view did not show {expected!r}: {bytes(output[-1200:])!r}"
        if select.select([master], [], [], .05)[0]:
            output.extend(os.read(master, 65536))
    return output



def exercise(executable, environment, job, stalled=False, sidebar=False, columns=100):
    native = sidebar == "native"
    root = Path(environment["XDG_DATA_HOME"]) / "porthub/terminal"
    shared_marker = root / f"{job['id']}.share"
    if native:
        shared_marker.write_text("{}")
        shared_marker.chmod(0o600)
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
    def own_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    arguments = [executable, "terminal", "attach", job["id"]] if sidebar else [executable, "terminal", "participants", job["id"], "--watch"]
    if native: arguments += ["--sidebar", "on"]
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
            os.write(master, b"\x1b[19~" if native else b"\x01P")
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
            wait_text(master, child, b"Remove 200?")
            os.write(master, b"n")
            wait_text(master, child, b"Removing a guest leaves")
            assert removals == [], "cancel must not remove a guest"
            os.write(master, b"k")
            wait_text(master, child, b"Remove 200?")
            os.write(master, b"y")
            wait_text(master, child, b"Guest removed")
            assert removals == [200], "only the selected guest must be removed"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 18, 40, 0, 0))
            if native:
                time.sleep(.1)
                os.write(master,b"printf 'RESIZE%s\\n' 'SHELL'\r")
                wait_text(master,child,b"RESIZESHELL")
                fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",24,120,0,0))
                time.sleep(.1)
                os.write(master,b"\x1b[19~")
                wait_text(master,child,b"Participants")
            else:
                os.write(master,b"\x1b[A")
        started = time.monotonic()
        os.write(master, b"q")
        if sidebar:
            if native:
                time.sleep(.1)
                os.write(master,b"printf 'NATIVE%s\\n' 'FOCUS'\r")
                wait_text(master, child, b"NATIVEFOCUS", timeout=1.5)
            else:
                wait_text(master, child, b"$", timeout=1.5)
            assert child.poll() is None, "closing the popup must keep the owner attached"
            started = time.monotonic()
            os.write(master, b"\x01d")
        exit_output=bytearray()
        while child.poll() is None and time.monotonic() - started < 1.5:
            if select.select([master], [], [], .02)[0]:
                exit_output.extend(os.read(master, 65536))
        assert child.poll() == 0, f"quit must not wait for a stalled owner socket: status={child.poll()}, output={bytes(exit_output[-1500:])!r}"
        assert_terminal_restored(report_read)
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
        if native: shared_marker.unlink(missing_ok=True)
        os.close(master)
        os.close(slave)
        os.close(report_read)


def exercise_hangup(executable, environment, job):
    """A lost controlling terminal must not kill tasks in the private server."""
    marker = Path(environment["XDG_DATA_HOME"]) / "hangup-released"
    def attach():
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        def own_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        child = subprocess.Popen([executable, "terminal", "attach", job["id"], "--sidebar", "on"],
                                 stdin=slave, stdout=slave, stderr=slave,
                                 env=environment, preexec_fn=own_terminal)
        os.close(slave)
        return master, child
    def call(*arguments):
        return subprocess.run([executable, "terminal", *arguments], env=environment,
                              capture_output=True, check=True, timeout=3).stdout
    master, child = attach()
    try:
        wait_text(master, child, b"$")
        command = ("persistvalue=porthublifetime; printf 'LIFETIME%s\\n' 'READY'; "
                   f"(while [ ! -f {shlex.quote(str(marker))} ]; do sleep .05; done; "
                   "printf 'TASK%s\\n' 'SURVIVED') &\n")
        os.write(master, command.encode())
        wait_text(master, child, b"LIFETIMEREADY")
        os.close(master)
        master = None
        child.wait(timeout=3)
        # Release the task only after the host terminal is gone, so scheduler
        # timing cannot let it finish before the disconnect under test.
        marker.touch()
        deadline = time.monotonic() + 4
        while b"TASKSURVIVED" not in call("tmux", job["id"], "--", "capture-pane", "-p", "-t", "%0"):
            assert time.monotonic() < deadline, "background task must finish after the host terminal hangs up"
            time.sleep(.05)
        master, child = attach()
        wait_text(master, child, b"$")
        os.write(master, b"printf 'PERSIST%s\\n' \"$persistvalue\"\n")
        wait_text(master, child, b"PERSISTporthublifetime")
        os.write(master, b"\x04")
        child.wait(timeout=3)
        assert child.returncode == 0, "explicit Ctrl+D must close the final shell cleanly"
        rows = json.loads(call("list", "--json"))
        assert next(row for row in rows if row["id"] == job["id"])["state"] == "ended", "Ctrl+D must end the workspace"
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        if master is not None:
            os.close(master)
        marker.unlink(missing_ok=True)


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
            exercise(executable, environment, job, sidebar="native", columns=120)
            listed = subprocess.run([executable, "terminal", "list", "--json"], env=environment, capture_output=True, check=True)
            assert any(row["id"] == identity and row["state"] == "running" for row in json.loads(listed.stdout)), "closing the owner view must preserve its workspace"
            exercise_hangup(executable, environment, job)
        finally:
            subprocess.run([executable, "terminal", "stop", identity], env=environment, capture_output=True, check=True)
    print("PASS owner participants PTY: selection, cancellation, targeted removal, resize, terminal restoration, responsive stalled-socket quit, owner-targeted right popup and nonmodal private sidebar, abrupt PTY hangup, background-task/shell-state persistence and explicit Ctrl+D teardown")


if __name__ == "__main__":
    main()
