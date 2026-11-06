#!/usr/bin/env python3
"""Verify caller context and workspace identity through an exact seeded helper."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    core=Path(sys.argv[1]).resolve()
    if not os.environ.get('PORTHUB_COMPONENT_CACHE'):
        raise RuntimeError('Seed the verified terminal helper fixture first')
    with tempfile.TemporaryDirectory(prefix='porthub-workspace-caller-') as temporary:
        root=Path(temporary)
        environment=dict(os.environ,XDG_DATA_HOME=str(root/'data'),XDG_CONFIG_HOME=str(root/'config'))
        created=[]
        def call(arguments,extra=None):
            result=subprocess.run([str(core),*arguments],env=dict(environment,**(extra or {})),capture_output=True,text=True,timeout=40)
            if result.returncode:
                raise RuntimeError('Workspace command failed: '+result.stderr[-1000:])
            return result.stdout
        try:
            for index in range(2):
                name=f'caller-{index}';output=root/f'caller-{index}.txt';cwd=root/f'cwd-{index}';cwd.mkdir()
                job=json.loads(call(['terminal','new','--name',name,'--cwd',str(cwd),'--detach','--json','--','/bin/sh','-c',
                    'printf "%s\\n%s" "$PORTHUB_WORKSPACE_FIXTURE" "$PWD" > "$1"; sleep 30','fixture',str(output)],
                    {'PORTHUB_WORKSPACE_FIXTURE':f'value-{index}'}))
                created.append(name)
                deadline=time.monotonic()+5
                while not output.exists() and time.monotonic()<deadline:
                    time.sleep(.02)
                assert output.read_text()==f'value-{index}\n{cwd}', 'Caller environment or cwd was lost'
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    results=list(pool.map(lambda _:json.loads(call(['terminal',name,'--detach','--json'])),range(6)))
                assert all(row['id']==job['id'] for row in results), 'Concurrent reopen changed workspace identity'
                renamed=f'renamed-{index}'
                call(['terminal','rename',name,renamed]);created[-1]=renamed
                rows=json.loads(call(['terminal','ls','--json']))
                assert any(row['id']==job['id'] and row['name']==renamed for row in rows), 'Rename lost workspace identity'
                assert call(['terminal','tmux',renamed,'--','display-message','-p','#{session_name}']).strip()=='workspace'

        finally:
            for name in created:
                call(['terminal','stop',name])
        assert json.loads(call(['terminal','ls','--json']))==[], 'Ended workspaces leaked into default list'
        archived=json.loads(call(['terminal','ls','--json','--all']))
        assert len(archived)==2 and all(row['state']=='ended' for row in archived), 'History lost ended workspace metadata'
    print('PASS helper-owned workspaces: caller environment/cwd preserved and concurrent reopen retains identity')


if __name__=='__main__':main()
