#!/usr/bin/env python3
"""Source-pinned native core-only validation. Never establishes full-release proof."""
import argparse
from contextlib import contextmanager
import shutil
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import tomllib

SUPPORTED = {'aarch64-apple-darwin'}
PACKAGES = ['porthub-agent','porthub-transfer','porthub-tunnel','porthub-identity','porthub-mesh','porthub-network','porthub-io']


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def plan(target):
    if target not in SUPPORTED: raise ValueError('Local validation equivalence is implemented for Mac ARM core-only')
    rows=[]
    def add(name,argv,timeout=90,env=None): rows.append(dict(name=name,argv=argv,timeout_seconds=timeout,env=env or {}))
    cargo=['cargo']; tail=['--target',target]
    for package in ('porthub-sync','porthub-stats','porthub-terminal-cli'):
        add('build-'+package,cargo+['build','--locked','-p',package]+tail,900)
    add('seed-components',['{python}','scripts/seed-component-fixture.py','--cache','{fixture_cache}','--target',target,'--core','{version}','--revision','{source}','--input','stats','{debug}/porthub-stats','--input','terminal','{debug}/porthub-terminal','--input','sync','{debug}/porthub-sync'])
    group=sum((['-p',p] for p in PACKAGES),[])
    add('compile-complete-platform',cargo+['test','--locked']+group+tail+['--no-run'],900)
    add('test-complete-platform',cargo+['test','--locked']+group+tail,240)
    add('terminal-packaged-ssh',cargo+['test','--locked','-p','porthub-terminal','--features','ssh']+tail+['--','--include-ignored'],900)
    add('terminal-viewer',cargo+['test','--locked','-p','porthub-terminal','--features','direct,viewer-history','--lib','direct::viewer']+tail)
    add('terminal-native-direct',cargo+['test','--locked','-p','porthub-terminal','--features','direct,viewer-history','--test','native_direct']+tail+['--','--include-ignored'])
    add('agent-terminal-direct',cargo+['test','--locked','-p','porthub-agent','--features','terminal-direct','--lib','terminal_']+tail)
    add('agent-terminal-policy',cargo+['test','--locked','-p','porthub-agent','--no-default-features','--lib','terminal_policy']+tail)
    add('agent-terminal-join',cargo+['test','--locked','-p','porthub-agent','--features','terminal-direct','--bin','porthub','cli_tests::native_terminal_join_is_opt_in_and_does_not_require_system_privileges']+tail)
    add('native-launchd',cargo+['test','--locked','-p','porthub-agent','--test','launchd_live']+tail+['--','--include-ignored'],240,{'PORTHUB_TEST_LAUNCHD':'1'})
    return rows


def plan_hash(root,target):
    # A workflow change invalidates an old local proof, even when a maintainer
    # has not yet updated the portable command plan to match the new gate.
    return hashlib.sha256(canonical({'schema_version':1,'mode':'core_only','target':target,
        'steps':plan(target),'workflow_sha256':sha(root/'.github/workflows/agent-platforms.yml'),
        'runner_sha256':sha(root/'scripts/native-core-validation.py')})).hexdigest()


def verify(root,directory,target,source):
    if target not in SUPPORTED: raise ValueError('Unsupported local native validation target')
    path=directory/'native-validation.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size>128*1024: raise ValueError('Native validation receipt missing/oversized')
    receipt=json.loads(path.read_text())
    if (receipt.get('schema_version')!=1 or receipt.get('mode')!='core_only' or receipt.get('source_revision')!=source
        or receipt.get('target')!=target or receipt.get('plan_sha256')!=plan_hash(root,target)
        or receipt.get('system')!='Darwin' or receipt.get('machine') not in ('arm64','aarch64')
        or receipt.get('status')!='passed'):
        raise ValueError('Native validation identity/plan mismatch')
    expected=['terminal-runtime']+[row['name'] for row in plan(target)]+['core-build','core-startup']
    steps=receipt.get('steps',[])
    if [row.get('name') for row in steps]!=expected or any(type(row.get('exit_code')) is not int or row['exit_code']!=0 or not isinstance(row.get('elapsed_seconds'),(int,float)) or not math.isfinite(row['elapsed_seconds']) or row['elapsed_seconds']<0 for row in steps):
        raise ValueError('Incomplete native validation steps')
    builds=load('hybrid-native-build').verify(root,directory,target,source,controller=True)
    if len(builds)!=1 or next(iter(builds))[0]!='core': raise ValueError('Core-only proof must bind exactly one core')
    binary=next(iter(builds.values()))[1]
    if receipt.get('binary_sha256')!=sha(binary): raise ValueError('Validated native core differs from artifact')
    return receipt


def execute(argv,root,env,log,timeout):
    with log.open('wb') as stream:
        process=subprocess.Popen(argv,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        started=time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic()-started>timeout or log.stat().st_size>8*1024**2:
                    raise TimeoutError('Owned validation step exceeded bound')
                time.sleep(.2)
            if process.returncode: raise ValueError('Native validation step failed: '+log.stem)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
            raise
    return {'name':log.stem,'exit_code':0,'elapsed_seconds':round(time.monotonic()-started,3),'log_sha256':sha(log)}


def launchd_labels():
    rows=subprocess.run(['launchctl','list'],check=True,capture_output=True,text=True,timeout=5).stdout
    return {line.split()[-1] for line in rows.splitlines()[1:] if line.split()}


def cleanup_launchd(before,program):
    # Only labels created during this fixture and pointing at its exact nonce-
    # owned executable can be retired. Never unload a pre-existing registration.
    domain='gui/'+str(os.getuid())
    for label in launchd_labels()-before:
        if not label.startswith('porthub-'): continue
        result=subprocess.run(['launchctl','print',domain+'/'+label],capture_output=True,text=True,timeout=5)
        if result.returncode: continue
        observed=[line.strip().split(' = ',1)[1].strip().strip(chr(34)) for line in result.stdout.splitlines() if line.strip().startswith('program = ')]
        if observed != [str(program)]: continue
        subprocess.run(['launchctl','bootout',domain+'/'+label],check=True,capture_output=True,timeout=10)
        if label in launchd_labels(): raise ValueError('Owned fixture launchd cleanup incomplete')


@contextmanager
def validation_stage(parent):
    with tempfile.TemporaryDirectory(prefix='native-core-validation-',dir=parent) as raw:
        stage=Path(raw);stage.chmod(0o700)
        try:
            yield stage
        except BaseException as error:
            # Retain only bounded fixture logs, never profiles/component stores.
            # This directory belongs to the enclosing nonce stage and survives
            # removal of the working source/target after a failed validation.
            destination=parent/('native-validation-failure-'+stage.name)
            destination.mkdir(mode=0o700)
            retained=[];total=0
            logs=stage/'logs'
            for path in sorted(logs.glob('*.log'),key=lambda p:p.stat().st_mtime,reverse=True) if logs.exists() else []:
                if path.is_symlink() or not path.is_file(): continue
                size=path.stat().st_size
                if size>8*1024**2 or total+size>64*1024**2: continue
                shutil.copy2(path,destination/path.name);total+=size
                retained.append({'name':path.name,'size':size,'sha256':sha(path)})
            (destination/'failure.json').write_text(json.dumps({'status':'failed','error_type':type(error).__name__,'error':str(error)[:16384],'logs':retained},sort_keys=True))
            raise


def run(root,source,output,budget):
    root=root.resolve();hybrid=load('hybrid-native-build');hybrid.load('component-build-plan').require_clean_source(root,source)
    target=load('build-local-native').native_target(platform.system(),platform.machine())
    if target not in SUPPORTED or platform.system()!='Darwin': raise ValueError('Native Mac ARM host required')
    if output.exists() or output.is_symlink(): raise ValueError('New output path required')
    env=os.environ.copy();env.update(RUST_MIN_STACK='33554432',CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
    # All fixture profiles and optional component stores are private test roots;
    # never use installed enrollment profiles or mutate the machine service.
    started=time.monotonic();output.parent.mkdir(parents=True,exist_ok=True)
    with validation_stage(output.parent) as stage:
        logs=stage/'logs';logs.mkdir()
        fixtures=stage/'fixture-tmp';fixtures.mkdir(mode=0o700);env['TMPDIR']=str(fixtures)
        cache=stage/'components-cache';debug=Path(env.get('CARGO_TARGET_DIR',root/'target'))/target/'debug'
        env.update(PORTHUB_TEST_SYNC_EXECUTABLE=str(debug/'porthub-sync'),PORTHUB_COMPONENT_CACHE=str(cache),PORTHUB_COMPONENT_SHARED_CACHE='off',PORTHUB_COMPONENT_SOURCE='github',PORTHUB_TERMINAL_HELPER_CACHE_ROOT=str(stage/'terminal-cache'))
        steps=[]
        def step(name,argv,limit,extra=None):
            remaining=budget-(time.monotonic()-started)
            if remaining<=1: raise TimeoutError('Native validation total budget exhausted')
            item=execute(argv,root,dict(env,**(extra or {})),logs/(name+'.log'),min(limit,remaining));steps.append(item)
        step('terminal-runtime',[sys.executable,str(root/'scripts/build-terminal-helper.py'),'--target',target],900)
        bundle=(logs/'terminal-runtime.log').read_text().strip().splitlines()[-1]
        if not Path(bundle).is_file(): raise ValueError('Terminal runtime builder omitted bundle')
        env.update(PORTHUB_TERMINAL_BUNDLE=bundle,PORTHUB_TEST_TERMINAL_BUNDLE=bundle,PORTHUB_TEST_TERMINAL_TARGET=target)
        version=tomllib.loads((root/'crates/porthub-agent/Cargo.toml').read_text())['package']['version']
        values={'python':sys.executable,'fixture_cache':str(cache),'debug':str(debug),'source':source,'version':version}
        for row in plan(target):
            before=launchd_labels() if row['name']=='native-launchd' else None
            try: step(row['name'],[arg.format(**values) for arg in row['argv']],row['timeout_seconds'],row['env'])
            finally:
                if before is not None: cleanup_launchd(before,debug/'porthub')
        built=stage/'core.zip'
        step('core-build',[sys.executable,str(root/'scripts/hybrid-native-build.py'),'worker','--root',str(root),'--source-revision',source,'--output',str(built),'--tool','core','--timeout-seconds',str(max(1,min(1700,int(budget-(time.monotonic()-started)-15))))],1700)
        components=stage/'components';hybrid.unpack(built,components)
        builds=hybrid.verify(root,components,target,source,controller=True);binary=next(iter(builds.values()))[1];binary.chmod(0o755)
        step('core-startup',[str(binary),'--version'],10)
        receipt={'schema_version':1,'mode':'core_only','source_revision':source,'target':target,'plan_sha256':plan_hash(root,target),'system':platform.system(),'machine':platform.machine(),'kernel':platform.release(),'status':'passed','binary_sha256':sha(binary),'steps':steps}
        (components/'native-validation.json').write_text(json.dumps(receipt,sort_keys=True))
        verify(root,components,target,source)
        # Successful bounded logs accompany proof; failed stages never publish.
        import shutil
        shutil.copytree(logs,components/'native-validation-logs')
        hybrid.pack(components,output)
    return {'status':'passed','mode':'core_only','target':target,'sha256':sha(output),'size':output.stat().st_size}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--source-revision',required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--budget-seconds',type=int,default=1640)
    args=parser.parse_args()
    if not 60<=args.budget_seconds<=1640: parser.error('Bounded validation budget required')
    print(json.dumps(run(args.root,args.source_revision,args.output,args.budget_seconds),sort_keys=True))
if __name__=='__main__':main()
