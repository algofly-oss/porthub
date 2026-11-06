#!/usr/bin/env python3
"""Exercise dashboard auto/forced transports under process-local Unix-bind denial."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    executable=Path(sys.argv[1]).resolve()
    headers=subprocess.run(['readelf','--program-headers',str(executable)],capture_output=True,text=True,check=True).stdout
    if 'INTERP' not in headers:
        raise RuntimeError('This fault-injection check requires the native dynamically linked debug CLI')
    if not os.environ.get('PORTHUB_COMPONENT_CACHE'):
        raise RuntimeError('Seed the exact stats helper fixture before this check')
    with tempfile.TemporaryDirectory(prefix='porthub-stats-bind-denial-') as temporary:
        root=Path(temporary)
        source=root/'deny-bind.c';library=root/'deny-bind.so'
        source.write_text('''#define _GNU_SOURCE
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>
int bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (address && address->sa_family == AF_UNIX) { errno=EACCES; return -1; }
    int (*next)(int,const struct sockaddr*,socklen_t)=dlsym(RTLD_NEXT,"bind");
    return next(fd,address,length);
}
''')
        subprocess.run(['cc','-shared','-fPIC',str(source),'-ldl','-o',str(library)],check=True,capture_output=True)
        config=root/'config';config.mkdir(mode=0o700)
        environment=dict(os.environ,LD_PRELOAD=str(library),XDG_CONFIG_HOME=str(config))
        for mode in ['auto','cli','rpc']:
            result=subprocess.run([str(executable),'stats','--user','--once','--json'],
                env=dict(environment,PORTHUB_COMPONENT_TRANSPORT=mode),capture_output=True,text=True,timeout=15)
            if mode == 'rpc':
                assert result.returncode != 0, 'forced RPC must fail when binding is denied'
            else:
                assert result.returncode == 0, 'dashboard handoff failed: '+result.stderr[-1000:]
                assert json.loads(result.stdout)['agents'] == []
    print('PASS dashboard fallback: bind denial triggers private file mode; forced CLI succeeds and forced RPC fails')


if __name__=='__main__': main()
