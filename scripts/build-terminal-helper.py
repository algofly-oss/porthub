#!/usr/bin/env python3
"""Build/cache PortHub's private tmux runtime from checksum-pinned sources.

Only build hosts need a C compiler, make, yacc and tic. Distributed CLI artifacts
embed the resulting static runtime, terminfo and license notices.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent

def build(args):
    lock_path = ROOT / 'vendor/terminal/sources.json'
    lock = json.loads(lock_path.read_text())
    identity = hashlib.sha256(lock_path.read_bytes() + Path(__file__).read_bytes() + args.target.encode() + args.cc.encode()).hexdigest()[:20]
    cache = ROOT / 'target/terminal-helper' / args.target / identity
    output = cache / 'bundle.tar.gz'
    if output.is_file():
        print(output)
        return
    cache.mkdir(parents=True, exist_ok=True)
    prefix = cache / 'prefix'
    prefix.mkdir(exist_ok=True)
    env = dict(os.environ, CC=args.cc, AR=args.ar, RANLIB=args.ar[:-2]+'ranlib' if args.ar.endswith('ar') else 'ranlib', CFLAGS='-O2 -fPIC', PKG_CONFIG_PATH=str(prefix/'lib/pkgconfig'))
    env['PKG_CONFIG_LIBDIR'] = str(prefix/'lib/pkgconfig')
    sources = {}
    for item in lock['sources']:
        archive = cache / (item['name'] + '.tar.gz')
        if not archive.is_file():
            # Sources use canonical HTTPS release locations; subsequent builds
            # verify the committed SHA256 before touching the build tree.
            with urllib.request.urlopen(item['url'], timeout=60) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != item['sha256']:
            raise RuntimeError('Source checksum mismatch: ' + item['name'])
        destination = cache / item['name']
        if not destination.exists():
            extraction = cache / ('unpack-' + item['name'])
            extraction.mkdir(exist_ok=True)
            with tarfile.open(archive) as tar:
                tar.extractall(extraction, filter='data')
            entries = list(extraction.iterdir())
            if len(entries) != 1 or not entries[0].is_dir():
                raise RuntimeError('Unexpected source archive structure')
            entries[0].rename(destination)
            extraction.rmdir()
        sources[item['name']] = destination
    def run(command, directory, extra=None):
        merged = dict(env)
        merged.update(extra or {})
        subprocess.run(command, cwd=directory, env=merged, check=True, stdout=log, stderr=subprocess.STDOUT)
    configure = ['--prefix=' + str(prefix), '--host=' + args.target]
    jobs = '-j' + str(args.jobs)
    with (cache/'build.log').open('w') as log:
        if 'linux' in args.target:
            # Build the private helper against musl too: static glibc can still
            # load host NSS modules, which would defeat self-contained delivery.
            musl_prefix = cache / 'musl-runtime'
            run(['./configure','--prefix='+str(musl_prefix),'--host='+args.target,'--disable-shared','--enable-wrapper=gcc'],sources['musl'])
            run(['make',jobs],sources['musl']);run(['make','install'],sources['musl'])
            env['CC'] = str(musl_prefix/'bin/musl-gcc')
        run(['./configure', *configure, '--disable-shared','--enable-static','--disable-openssl','--disable-thread-support','--disable-samples','--disable-libevent-regress'],sources['libevent'])
        run(['make',jobs],sources['libevent']);run(['make','install'],sources['libevent'])
        run(['./configure', *configure, '--without-shared','--with-normal','--enable-widec','--with-termlib','--without-cxx','--without-cxx-binding','--without-ada','--without-tests','--without-progs','--without-manpages','--without-debug','--with-build-cc=cc','--enable-pc-files','--with-pkg-config-libdir='+str(prefix/'lib/pkgconfig')],sources['ncurses'])
        run(['make',jobs],sources['ncurses']);run(['make','install.libs'],sources['ncurses'])
        libraries = [prefix/'lib/libncursesw.a',prefix/'lib/libtinfow.a']
        if not all(path.is_file() for path in libraries):
            raise RuntimeError('Static terminal libraries missing; see '+str(cache/'build.log'))
        flags = {'LIBEVENT_CFLAGS':'-I'+str(prefix/'include'),'LIBEVENT_LIBS':str(prefix/'lib/libevent_core.a'),'NCURSES_CFLAGS':'-I'+str(prefix/'include/ncursesw'),'NCURSES_LIBS':' '.join(map(str,libraries)),'LDFLAGS':'-static' if 'linux' in args.target else ''}
        run(['./configure', *configure,'--disable-utf8proc','--disable-systemd','--disable-utempter'],sources['tmux'],flags)
        run(['make',jobs],sources['tmux'],flags)
    stage = cache/'package';stage.mkdir(exist_ok=True)
    shutil.copy2(sources['tmux']/'tmux',stage/'tmux')
    if 'linux' in args.target:
        result = subprocess.check_output(['readelf','-l',stage/'tmux'],text=True)
        if 'INTERP' in result:
            raise RuntimeError('Terminal helper must not require a dynamic loader')
    terminfo=stage/'terminfo';terminfo.mkdir(exist_ok=True)
    tic=shutil.which('tic')
    if not tic:raise RuntimeError('Build host requires tic to package terminal definitions')
    subprocess.run([tic,'-x','-e','xterm,xterm-256color,screen,screen-256color,tmux,tmux-256color,vt100','-o',str(terminfo),str(sources['ncurses']/'misc/terminfo.src')],check=True)
    licenses=stage/'licenses';licenses.mkdir(exist_ok=True)
    for name, source in [('tmux',sources['tmux']/'COPYING'),('libevent',sources['libevent']/'LICENSE'),('ncurses',sources['ncurses']/'COPYING')] + ([('musl',sources['musl']/'COPYRIGHT')] if 'linux' in args.target else []):
        if not source.is_file():raise RuntimeError('License notice missing: '+name)
        shutil.copyfile(source,licenses/(name+'.txt'))
    manifest={'version':next(item['version'] for item in lock['sources'] if item['name']=='tmux'),'target':args.target,'files':{str(path.relative_to(stage)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(stage.rglob('*')) if path.is_file()}}
    (stage/'manifest.json').write_text(json.dumps(manifest,sort_keys=True)+'\n')
    temporary=output.with_suffix('.tmp')
    with temporary.open('wb') as raw, gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as zipped, tarfile.open(fileobj=zipped,mode='w',dereference=True) as tar:
        for path in sorted(stage.rglob('*')):
            info=tar.gettarinfo(str(path),arcname=str(path.relative_to(stage)))
            info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
            info.mode=0o755 if path.is_dir() or path.name=='tmux' else 0o444
            if path.is_file():
                with path.open('rb') as source:tar.addfile(info,source)
            else:tar.addfile(info)
    temporary.rename(output)
    print(output)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True)
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--ar',default='ar')
    parser.add_argument('--jobs',type=int,default=2)
    args=parser.parse_args()
    if not 1<=args.jobs<=8:parser.error('--jobs must be 1–8')
    build(args)
