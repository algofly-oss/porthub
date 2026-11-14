#!/usr/bin/env python3
"""Reject optional worker implementations in the core's production dependency graph."""
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parent.parent
FORBIDDEN={
    'portable-pty','porthub-tor','arti-client','porthub-stats','porthub-sync','porthub-terminal-cli',
}


def main():
    tree=subprocess.check_output(['cargo','tree','--locked','-p','porthub-agent','-e','normal,build','--prefix','none'],cwd=ROOT,text=True)
    packages={line.split()[0] for line in tree.splitlines() if line.strip()}
    found=sorted(packages&FORBIDDEN)
    if found:
        raise SystemExit('Optional implementations linked into core: '+', '.join(found))
    # Native keyboard and USB forwarding share the RTC data channel engine.
    # Terminal hosting stays optional: portable-pty and terminal-cli remain forbidden.
    print('PASS core production graph excludes optional workers and terminal hosting implementations')


if __name__=='__main__':main()
