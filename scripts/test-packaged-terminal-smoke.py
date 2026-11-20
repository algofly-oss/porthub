#!/usr/bin/env python3
"""Check that the shipped agent refuses shell access and retains port forwarding."""
from pathlib import Path
import subprocess
import sys

agent = str(Path(sys.argv[1]).resolve())
subprocess.run([agent, "forward", "--help"], check=True, stdout=subprocess.DEVNULL)
for args in (["share", "workspace"], ["join", "unused"], ["dashboard", "run"]):
    result = subprocess.run([agent, "terminal", *args], capture_output=True, timeout=10)
    if result.returncode == 0 or b"unrecognized subcommand" not in result.stderr:
        raise SystemExit(f"unexpected terminal command result for {args[0]}")

# Old login services use Restart=on-failure or launchd SuccessfulExit=false.
old_service = subprocess.run(
    [agent, "terminal", "dashboard", "run", "--owner", "old-owner", "--registration", "old-registration"],
    capture_output=True, timeout=10, check=True,
)
assert b"retired" in old_service.stderr
