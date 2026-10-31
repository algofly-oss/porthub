#!/usr/bin/env python3
"""Explicit scoped live smoke test. Never installs or restarts an agent service."""
import argparse
import json
from pathlib import Path
import re
import secrets
import shlex
import string
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True,help='Existing SSH host/config alias for an upgraded machine')
    parser.add_argument('--version',required=True)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--known-hosts',required=True,type=Path,help='Previously verified terminal-gateway SSH host keys')
    parser.add_argument('--binary',default='porthub')
    parser.add_argument('--registration')
    args=parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_@.:-]+',args.host) or args.host.startswith('-') or not re.fullmatch('[a-f0-9]{40}',args.revision):
        parser.error('Use an explicit SSH host and complete build revision')
    known=args.known_hosts.resolve(strict=True)
    if not known.is_file() or not known.read_text().strip():parser.error('A verified gateway known-hosts file is required')
    def remote(arguments,check=True,timeout=45):
        result=subprocess.run(['ssh','-oBatchMode=yes',args.host,shlex.join(arguments)],capture_output=True,text=True,timeout=timeout)
        if check and result.returncode:raise RuntimeError('Scoped remote terminal operation failed')
        return result
    version=remote([args.binary,'version','--verbose']).stdout
    if ('porthub '+args.version) not in version or args.revision not in version:
        raise RuntimeError('Host CLI has not reached the expected version and source; no workspace created')
    fixture=remote(['mktemp','-d','/tmp/porthub-terminal-live-XXXXXXXX']).stdout.strip()
    if not re.fullmatch(r'/tmp/porthub-terminal-live-[a-zA-Z0-9]+',fixture):raise RuntimeError('Unexpected private fixture directory')
    prefix=['env','XDG_DATA_HOME='+fixture+'/data','XDG_CONFIG_HOME='+fixture+'/config',args.binary,'terminal']
    name='rollout'+''.join(secrets.choice(string.ascii_lowercase) for _ in range(12))
    sensitive=[]
    cleanup_error=None
    try:
        command=[*prefix,'share','--name',name,'--detach','--json','--shell','/bin/sh',
                 '--env','ENV=','--env','BASH_ENV=','--env','PS1=porthub-live$ ',
                 '--link-expires','180','--session-timeout','300','--max-viewers','6']
        if args.registration:command.extend(['--registration',args.registration])
        command.extend(['--','/bin/sh','-i'])
        invitation=json.loads(remote(command).stdout)
        for setting, expected in [('history-limit','100000'),('mouse','on'),('prefix','C-a')]:
            actual=remote([*prefix,'tmux',name,'--','show-options','-gv',setting]).stdout.strip()
            if actual!=expected:raise RuntimeError('Bundled terminal option was not applied: '+setting)
        if 'copy-mode' not in remote([*prefix,'tmux',name,'--','list-keys','-T','root','F7']).stdout:
            raise RuntimeError('Bundled terminal F7 history binding is missing')
        for key in ('interactive_url','read_only_url'):
            value=invitation.get(key,'');token=value.rsplit('#',1)[-1]
            if not value.startswith('https://') or not re.fullmatch('[a-f0-9]{64}',token):raise RuntimeError('Invalid live invitation metadata')
            sensitive.append(token)
        ssh=shlex.split(invitation['interactive_ssh'])
        if not ssh or ssh.pop(0)!='ssh':raise RuntimeError('Unexpected gateway SSH command')
        payload=dict(host=args.host,name=name,invitation=invitation,ownerPrefix=shlex.join(prefix),marker=secrets.token_hex(8),
                     sshArguments=ssh,sshOptions=['-F','/dev/null','-oBatchMode=yes','-oStrictHostKeyChecking=yes',
                         '-oUserKnownHostsFile='+str(known),'-oLogLevel=ERROR','-tt'])
        result=subprocess.run(['node',str(Path(__file__).with_name('test-terminal-live-browser.cjs'))],
                              input=json.dumps(payload),text=True,capture_output=True,timeout=180)
        output=result.stdout+result.stderr
        for token in sensitive:output=output.replace(token,'[invitation]')
        if result.returncode:raise RuntimeError('Live terminal fixture failed: '+output[-2000:])
        print(output.strip())
    finally:
        # Scope every cleanup command to our random name inside the private XDG root.
        remote([*prefix,'stop',name],check=False)
        ended=remote([*prefix,'list','--json'])
        if any(job.get('name')==name and job.get('state')=='running' for job in json.loads(ended.stdout)):
            raise RuntimeError('Owned fixture is still running; retained at '+fixture)
        cleanup=r'''import fcntl,os,pathlib,shutil,sys,time
p=pathlib.Path(sys.argv[1]);assert p.parent==pathlib.Path('/tmp') and p.name.startswith('porthub-terminal-live-')
assert p.is_dir() and not p.is_symlink() and p.stat().st_uid==os.getuid() and p.stat().st_mode&0o077==0
for attempt in range(300):
 files=[]
 try:
  for lock in p.glob('data/porthub/terminal/*.share.lock'):
   fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);files.append(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  shutil.rmtree(p);break
 except BlockingIOError:
  time.sleep(.1)
 finally:
  for fd in files:os.close(fd)
else:raise RuntimeError('Owned sharing supervisor still exiting; fixture retained')
'''
        try:
            remote(['python3','-c',cleanup,fixture],timeout=35)
            print('PASS cleanup: owned workspace stopped and private fixture directory removed; services unchanged')
        except Exception as error:
            cleanup_error=error
        if cleanup_error:raise RuntimeError('Live smoke cleanup needs review for '+fixture) from cleanup_error


if __name__=='__main__':
    main()
