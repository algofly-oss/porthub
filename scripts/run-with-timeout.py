#!/usr/bin/env python3
"""Bound a compiled CI check and retain its live output on a stalled process."""
import os
import signal
import subprocess
import sys


def main():
    seconds = int(sys.argv[1])
    command = sys.argv[2:]
    if seconds <= 0 or not command:
        raise SystemExit("usage: run-with-timeout.py SECONDS COMMAND [ARG ...]")
    child = subprocess.Popen(command, start_new_session=os.name != "nt")
    try:
        return child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        print(f"CI check exceeded {seconds} seconds; terminating its process tree", file=sys.stderr, flush=True)
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], check=False)
        else:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
