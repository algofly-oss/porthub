#!/usr/bin/env python3
"""Fast disposable-hosted Windows PS5/Scheduler gate, no whole-agent compilation."""
import argparse,base64,hashlib,json,os,pathlib,subprocess,sys,tempfile,uuid,threading,time,re

def main():
    p=argparse.ArgumentParser();p.add_argument('--receipt',required=True);args=p.parse_args()
    if sys.platform!='win32' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise RuntimeError('Disposable GitHub-hosted Windows runner required')
    repo=pathlib.Path(__file__).resolve().parents[1]
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    expected=os.environ.get('PORTHUB_SOURCE_REVISION') or os.environ.get('GITHUB_SHA')
    if not expected or not re.fullmatch('[a-f0-9]{40}',expected) or expected!=revision:raise RuntimeError('Exact checked-out CI source required')
    source=repo/'scripts/test-windows-refresh-native.ps1';raw=source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    root=pathlib.Path(tempfile.gettempdir())/('porthub-refresh-native-'+uuid.uuid4().hex)
    receipt=pathlib.Path(args.receipt)
    if receipt.exists() or receipt.resolve().parent!=pathlib.Path(os.environ['RUNNER_TEMP']).resolve():raise RuntimeError('Fresh own RUNNER_TEMP proof receipt required')
    def quote(s):return "'"+str(s).replace("'","''")+"'"
    env={k:v for k,v in os.environ.items() if k.lower() not in ('psmodulepath','psmoduleanalysiscachepath')}
    executable=pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    def phase(name):
        text="$ErrorActionPreference='Stop';$p="+quote(source)+";$b=[IO.File]::ReadAllBytes($p);$h=[Security.Cryptography.SHA256]::Create();try{$s=[BitConverter]::ToString($h.ComputeHash($b)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($s -cne "+quote(digest)+"){throw 'Fixture source hash changed'};& ([scriptblock]::Create((New-Object Text.UTF8Encoding($false,$true)).GetString($b))) -Phase "+name+" -Root "+quote(root)+" -Repository "+quote(repo)
        encoded=base64.b64encode(text.encode('utf-16le')).decode()
        if len(encoded)>8192:raise RuntimeError('Fixture loader argv bound')
        child=subprocess.Popen([str(executable),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
        buffers=[bytearray(),bytearray()];overflow=threading.Event()
        def drain(stream,buffer):
            while True:
                chunk=stream.read1(2048)
                if not chunk:return
                if len(buffer)+len(chunk)>32768:overflow.set();return
                buffer.extend(chunk)
        threads=[threading.Thread(target=drain,args=(stream,buffer),daemon=True) for stream,buffer in zip((child.stdout,child.stderr),buffers)]
        for thread in threads:thread.start()
        deadline=time.monotonic()+(110 if name=='Run' else 30)
        try:
            while child.poll() is None or any(t.is_alive() for t in threads):
                if overflow.is_set() or time.monotonic()>deadline:raise RuntimeError('Fixture deadline/output bound')
                time.sleep(.02)
            out,err=map(bytes,buffers)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            for stream in (child.stdout,child.stderr):stream.close()
            for thread in threads:thread.join(timeout=1)
        if child.returncode:raise RuntimeError('Native fixture '+name+' failed: '+err.decode('utf-8',errors='replace')[:32768])
        return json.loads(out.decode('utf-8-sig'))
    result={'source_sha256':digest,'revision':revision,'rust_source_sha256':hashlib.sha256((repo/'crates/porthub-agent/src/keyboard/windows_refresh.rs').read_bytes()).hexdigest(),'physical_capture':False};failure=None
    try:result['run']=phase('Run')
    except BaseException as error:failure=error;result['failure']=str(error)
    finally:
        try:result['independent_cleanup']=phase('Cleanup')
        except BaseException as error:result['cleanup_failure']=str(error);failure=failure or error
        receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if failure:raise failure
    print('HOSTED_PS5_SCHEDULER_ACTIVE_INACTIVE_EXACT_SECURITY_PASS')
if __name__=='__main__':main()
