#!/usr/bin/env bash
# Build infrastructure only. Does not install a daemon or touch client devices.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: bootstrap-media-pipewire.sh PRIVATE_BUILD_DIRECTORY PRIVATE_PREFIX' >&2
  exit 2
fi
media_script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
media_build=$1
media_prefix=$2
python3 - "$media_script_root/vendor/media/build-inputs.json" "$media_build" "$media_prefix" <<'PY'
import hashlib,json,pathlib,sys,tarfile,urllib.request
lock=json.loads(pathlib.Path(sys.argv[1]).read_text())['pipewire_build']
build=pathlib.Path(sys.argv[2]);prefix=pathlib.Path(sys.argv[3])
for path in [build,prefix]:
 if not path.is_absolute() or path.is_symlink() or path.exists():raise SystemExit('Use two new absolute private build paths')
 if any(p.is_symlink() for p in path.parents):raise SystemExit('Build path parents must not be symlinks')
build.mkdir(parents=True,mode=0o700);prefix.mkdir(parents=True,mode=0o700)
request=urllib.request.Request(lock['url'],headers={'User-Agent':'PortHub-media-build'})
with urllib.request.urlopen(request,timeout=60) as reply:
 if not reply.url.startswith('https://'):raise SystemExit('PipeWire archive must use HTTPS')
 data=reply.read(lock['size']+1)
if len(data)!=lock['size'] or hashlib.sha256(data).hexdigest()!=lock['sha256']:raise SystemExit('Pinned PipeWire archive digest mismatch')
archive=build/'pipewire.tar.gz';archive.write_bytes(data)
with tarfile.open(archive,'r:gz') as tar:
 members=tar.getmembers()
 if len(members)>20000 or sum(m.size for m in members)>128*1024*1024:raise SystemExit('PipeWire source archive exceeds bounds')
 for member in members:
  rel=pathlib.PurePosixPath(member.name)
  if rel.is_absolute() or '..' in rel.parts or not(member.isfile() or member.isdir()):raise SystemExit('Unsafe PipeWire archive entry')
  dest=build.joinpath(*rel.parts)
  if member.isdir():dest.mkdir(parents=True,exist_ok=True)
  else:
   dest.parent.mkdir(parents=True,exist_ok=True)
   with tar.extractfile(member) as source:dest.write_bytes(source.read())
   dest.chmod(0o755 if member.mode&0o111 else 0o644)
(build/'meson-arguments.json').write_text(json.dumps(lock['meson']))
PY
media_source="$media_build/pipewire-0.3.68"
mapfile -t media_meson_arguments < <(python3 - "$media_build/meson-arguments.json" <<'PY'
import json,sys
for value in json.load(open(sys.argv[1])):print(value)
PY
)
meson setup "$media_build/compiled" "$media_source" --prefix="$media_prefix" "${media_meson_arguments[@]}"
meson compile -C "$media_build/compiled" -j "${PORTHUB_MEDIA_BUILD_JOBS:-2}"
meson install -C "$media_build/compiled" --no-rebuild
PKG_CONFIG_PATH="$media_prefix/lib/pkgconfig" pkg-config --exact-version=0.3.68 libpipewire-0.3
