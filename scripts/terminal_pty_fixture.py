"""Shared controlling-session guard for real terminal restoration tests."""
import json
import os
import sys
import termios

# Retain a controlling session leader until the app exits and its mode is read.
# Darwin invalidates slave ioctls after the controlling session ends; checking
# before that end verifies restoration without weakening the assertion.
TERMINAL_KEEPER = r"""
import json, os, subprocess, sys, termios
report = int(sys.argv[1])
def state():
    value = termios.tcgetattr(0)
    value[6] = [item[0] if isinstance(item, bytes) else item for item in value[6]]
    return value
before = state()
result = subprocess.run(sys.argv[2:])
os.write(report, json.dumps({"before":before,"after":state()}).encode())
os.close(report)
raise SystemExit(result.returncode)
"""

def assert_terminal_restored(report_read):
    state = json.loads(os.read(report_read, 8192))
    # Darwin sets PENDIN while restoring ICANON and preserves it in tcsetattr;
    # it is queued-input state, not an application-controlled mode setting.
    if sys.platform == "darwin":
        for value in state.values():
            value[3] &= ~termios.PENDIN
    assert state["after"] == state["before"], f"terminal mode must be restored before the controlling session exits: {state!r}"
