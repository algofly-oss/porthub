#!/usr/bin/env python3
"""Build/cache PortHub's private tmux runtime from checksum-pinned sources.

Only build hosts need a C compiler, make, yacc and tic. Distributed CLI artifacts
embed the resulting static runtime, terminfo and license notices.
"""
import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import time
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent

MAX_SOURCE_BYTES = 64 * 1024 * 1024

def download_source(item, archive):
    """Retry transient transport failures; publish only checksum-pinned bytes."""
    if archive.is_file():
        if archive.stat().st_size <= MAX_SOURCE_BYTES and hashlib.sha256(archive.read_bytes()).hexdigest() == item['sha256']:
            return
        archive.unlink()  # A corrupt cache must not poison all later builds.
    deadline = time.monotonic() + 180
    for attempt in range(3):
        temporary = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('pinned source download deadline exceeded')
            request = urllib.request.Request(item['url'], headers={'User-Agent': 'PortHub terminal builder', 'Cache-Control': 'no-cache'})
            print('Downloading pinned ' + item['name'] + ' (attempt ' + str(attempt + 1) + '/3)', file=sys.stderr, flush=True)
            with urllib.request.urlopen(request, timeout=min(60, remaining)) as response:
                if not response.geturl().startswith('https://'):
                    raise RuntimeError('Pinned source redirected away from HTTPS: ' + item['name'])
                with tempfile.NamedTemporaryFile(prefix='.source-', dir=archive.parent, delete=False) as output:
                    temporary = Path(output.name)
                    size = 0
                    digest = hashlib.sha256()
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('pinned source download deadline exceeded')
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_SOURCE_BYTES:
                            raise RuntimeError('Pinned source exceeds size limit: ' + item['name'])
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            if digest.hexdigest() != item['sha256']:
                raise RuntimeError('Source checksum mismatch: ' + item['name'])
            temporary.replace(archive)
            return
        except urllib.error.HTTPError as error:
            if error.code not in (408, 429, 500, 502, 503, 504):
                raise RuntimeError('Pinned source request rejected (HTTP ' + str(error.code) + '): ' + item['name']) from None
        except (OSError, urllib.error.URLError, http.client.IncompleteRead):
            pass
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if attempt < 2 and time.monotonic() + 2 ** (attempt + 1) < deadline:
            time.sleep(2 ** (attempt + 1))
    raise RuntimeError('Could not download pinned source after bounded retries: ' + item['name']) from None

def patch_terminal_spawn(source):
    path = source / 'spawn.c'
    text = path.read_text()
    anchor = '\tenviron_push(child);\n'
    patch = '''\t/* PortHub panes must not redirect an ordinary host tmux client. */
\tif (getenv("PORTHUB_TERMINAL_ISOLATED") != NULL &&
\t    strcmp(getenv("PORTHUB_TERMINAL_ISOLATED"), "1") == 0) {
\t\tenviron_unset(child, "TMUX");
\t\tenviron_unset(child, "TMUX_PANE");
\t\tenviron_unset(child, "PORTHUB_TERMINAL_ISOLATED");
\t\tenviron_set(child, "PORTHUB_TERMINAL_SOCKET", 0, "%s", socket_path);
\t}
'''
    if patch + anchor in text:
        return
    if 'PORTHUB_TERMINAL_ISOLATED' in text or text.count(anchor) != 1:
        raise RuntimeError('Pinned tmux pane environment does not match the PortHub patch')
    path.write_text(text.replace(anchor, patch + anchor))

def validate_linux_binary(binary, target):
    environment = dict(os.environ, LC_ALL='C')
    headers = subprocess.check_output(['readelf', '-h', str(binary)], text=True, env=environment)
    architecture = target.split('-')[0]
    expected = {
        'x86_64': ('ELF64', 'Advanced Micro Devices X86-64'),
        'aarch64': ('ELF64', 'AArch64'),
        'i686': ('ELF32', 'Intel 80386'),
        'i586': ('ELF32', 'Intel 80386'),
        'arm': ('ELF32', 'ARM'),
        'armv7': ('ELF32', 'ARM'),
    }.get(architecture)
    if expected is None or not all(value in headers for value in expected):
        raise RuntimeError('Terminal helper ELF architecture does not match ' + target)
    segments = subprocess.check_output(['readelf', '-l', str(binary)], text=True, env=environment)
    if 'INTERP' in segments:
        raise RuntimeError('Terminal helper must not require a dynamic loader')

def build(args):
    lock_path = ROOT / 'vendor/terminal/sources.json'
    lock = json.loads(lock_path.read_text())
    identity = hashlib.sha256(lock_path.read_bytes() + Path(__file__).read_bytes() + args.target.encode() + args.cc.encode()).hexdigest()[:20]
    cache_root = Path(os.environ.get('PORTHUB_TERMINAL_HELPER_CACHE_ROOT', ROOT / 'target/terminal-helper'))
    if not cache_root.is_absolute():
        raise ValueError('Terminal helper cache root must be absolute')
    cache = cache_root / args.target / identity
    output = cache / 'bundle.tar.gz'
    if output.is_file():
        print(output)
        return
    cache.mkdir(parents=True, exist_ok=True)
    prefix = cache / 'prefix'
    prefix.mkdir(exist_ok=True)
    env = dict(os.environ, CC=args.cc, AR=args.ar, RANLIB=args.ar[:-2]+'ranlib' if args.ar.endswith('ar') else 'ranlib', CFLAGS='-O2 -fPIC', PKG_CONFIG_PATH=str(prefix/'lib/pkgconfig'))
    env['PKG_CONFIG_LIBDIR'] = str(prefix/'lib/pkgconfig')
    # The i686 CI target uses the multilib host compiler, whose default is x86_64.
    # Carry -m32 through musl and every dependent compile/link invocation.
    if args.target.startswith(('i686-', 'i586-', 'i386-')):
        env['CFLAGS'] += ' -m32'

    sources = {}
    for item in lock['sources']:
        if item.get('platforms') and not any(platform in args.target for platform in item['platforms']):
            continue
        archive = cache / (item['name'] + ('.tar.bz2' if item['url'].endswith('.tar.bz2') else '.tar.gz'))
        download_source(item, archive)
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
    patch_terminal_spawn(sources['tmux'])
    def run(command, directory, extra=None):
        merged = dict(env)
        merged.update(extra or {})
        try:
            subprocess.run(command, cwd=directory, env=merged, check=True, stdout=log, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            log.flush()
            with (cache/'build.log').open('rb') as failure_log:
                failure_log.seek(max(0, failure_log.seek(0, 2) - 65536))
                tail = failure_log.read().decode('utf-8', errors='replace').splitlines()[-80:]
            print('Terminal helper build failed; final build log lines:', file=sys.stderr)
            print('\n'.join(tail), file=sys.stderr)
            raise
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
            env['LDFLAGS'] = '-static'
            # Fail early with the actual linker diagnostic rather than allowing
            # configure to quietly mark required environment functions absent.
            probe = cache/'libc-link-probe.c'
            probe.write_text('#include <stdlib.h>\nint main(void) { setenv("PORTHUB_BUILD_PROBE", "1", 1); return putenv("PORTHUB_BUILD_PROBE=1"); }\n')
            run([env['CC'], *shlex.split(env['CFLAGS']), '-static', str(probe), '-o', str(cache/'libc-link-probe')], cache)

        run(['./configure', *configure, '--disable-shared','--enable-static','--disable-openssl','--disable-thread-support','--disable-samples','--disable-libevent-regress'],sources['libevent'])
        run(['make',jobs],sources['libevent']);run(['make','install'],sources['libevent'])
        run(['./configure', *configure, '--without-shared','--with-normal','--enable-widec','--with-termlib','--without-cxx','--without-cxx-binding','--without-ada','--without-tests',('--with-progs' if 'darwin' in args.target else '--without-progs'),'--without-manpages','--without-debug','--with-build-cc=cc','--enable-pc-files','--with-pkg-config-libdir='+str(prefix/'lib/pkgconfig')],sources['ncurses'])
        run(['make',jobs],sources['ncurses']);run(['make','install.libs'],sources['ncurses'])
        libraries = [prefix/'lib/libncursesw.a',prefix/'lib/libtinfow.a']
        if not all(path.is_file() for path in libraries):
            raise RuntimeError('Static terminal libraries missing; see '+str(cache/'build.log'))
        flags = {'LIBEVENT_CORE_CFLAGS':'-I'+str(prefix/'include'),
                 'LIBEVENT_CORE_LIBS':str(prefix/'lib/libevent_core.a'),
                 'LIBTINFOW_CFLAGS':'-I'+str(prefix/'include/ncursesw'),
                 'LIBTINFOW_LIBS':str(prefix/'lib/libtinfow.a'),
                 'LDFLAGS':'-static' if 'linux' in args.target else ''}
        allocator = '--disable-jemalloc'
        if 'jemalloc' in sources:
            run(['./configure', *configure, '--disable-shared', '--enable-static', '--disable-cxx', '--disable-doc'],sources['jemalloc'])
            run(['make',jobs],sources['jemalloc']);run(['make','install'],sources['jemalloc'])
            # Darwin's default jemalloc zone initializer must be retained even
            # when linking the archive instead of loading a shared library.
            flags['JEMALLOC_CFLAGS'] = '-I'+str(prefix/'include')
            flags['JEMALLOC_LIBS'] = '-Wl,-force_load,'+str(prefix/'lib/libjemalloc.a')
            allocator = '--enable-jemalloc'
        run(['./configure', *configure,'--disable-utf8proc','--disable-systemd','--disable-utempter',allocator],sources['tmux'],flags)
        run(['make',jobs],sources['tmux'],flags)
    stage = cache/'package';stage.mkdir(exist_ok=True)
    shutil.copy2(sources['tmux']/'tmux',stage/'tmux')
    if 'linux' in args.target:
        validate_linux_binary(stage/'tmux', args.target)
    elif 'darwin' in args.target:
        linked = subprocess.check_output(['otool', '-L', str(stage/'tmux')], text=True)
        for line in linked.splitlines()[1:]:
            dependency = line.strip().split(' (', 1)[0]
            if not dependency.startswith(('/usr/lib/', '/System/Library/')):
                raise RuntimeError('Terminal helper requires an unbundled library: '+dependency)
    terminfo=stage/'terminfo';terminfo.mkdir(exist_ok=True)
    # Apple's system tic cannot write some current extended terminfo entries.
    # Native Darwin builds use the compiler from the same pinned ncurses source.
    tic=str(sources['ncurses']/'progs/tic') if 'darwin' in args.target else shutil.which('tic')
    if not tic:raise RuntimeError('Build host requires tic to package terminal definitions')
    subprocess.run([tic,'-x','-e','xterm,xterm-256color,screen,screen-256color,tmux,tmux-256color,vt100','-o',str(terminfo),str(sources['ncurses']/'misc/terminfo.src')],check=True)
    licenses=stage/'licenses';licenses.mkdir(exist_ok=True)
    for name, source in [('tmux',sources['tmux']/'COPYING'),('libevent',sources['libevent']/'LICENSE'),('ncurses',sources['ncurses']/'COPYING')] + ([('musl',sources['musl']/'COPYRIGHT')] if 'linux' in args.target else []) + ([('jemalloc',sources['jemalloc']/'COPYING')] if 'jemalloc' in sources else []):
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
