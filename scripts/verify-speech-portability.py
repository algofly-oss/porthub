#!/usr/bin/env python3
"""Verify the exact ARM native build and stage its isolated, static FFI probe."""
import hashlib, json, pathlib, re, shutil, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
target = 'aarch64-unknown-linux-musl'
release = root / 'target' / target / 'release'
rows = [json.loads(line) for line in (release / 'speech-probe-build.jsonl').read_text().splitlines() if line.startswith('{')]
def local(path):
    value = pathlib.Path(path)
    assert str(value).startswith('/src/target/' + target + '/release/'), 'unexpected cargo output path'
    value = root / str(value).removeprefix('/src/')
    assert value.resolve().is_relative_to(release.resolve()), 'escaped release directory'
    return value
artifacts = [r for r in rows if r.get('reason') == 'compiler-artifact' and r.get('target', {}).get('name') == 'speech_portability' and r.get('profile', {}).get('test') and r.get('executable')]
assert len(artifacts) == 1, 'missing or ambiguous probe'
exe = local(artifacts[0]['executable'])
builds = [r for r in rows if r.get('reason') == 'build-script-executed' and 'transcribe-cpp-sys' in r.get('package_id', '')]
assert len(builds) == 1, 'missing or ambiguous native build'
build = local(builds[0]['out_dir']) / 'build'
cache = build / 'CMakeCache.txt'
values = dict(re.findall(r'^([^#/:][^:=]*):[^=]+=([^\n]*)$', cache.read_text(), re.M))
assert values.get('GGML_NATIVE') == 'OFF'
assert values.get('GGML_CPU_ARM_ARCH') == 'armv8-a'
flags = list(build.rglob('ggml-cpu.dir/flags.make'))
assert len(flags) == 1
text = flags[0].read_text()
isa = sorted(set(re.findall(r'-(?:march|mcpu|mtune)=[^\s]+', text)))
assert '-march=armv8-a' in isa
assert all(flag in ('-march=armv8-a',) for flag in isa), 'unexpected CPU architecture tuning'
assert not re.search(r'\+(?:sve|sme|i8mm|bf16)', text)
assert exe.is_file() and not exe.is_symlink() and exe.stat().st_size < 150_000_000
result = subprocess.run([str(exe), '--ignored', '--exact', 'speech_backend_devices_enumerate_without_model_or_application', '--nocapture'], capture_output=True, timeout=15)
assert len(result.stdout) + len(result.stderr) < 16384
assert result.returncode == 0, 'native enumeration probe failed'
assert b'SPEECH_NATIVE_DEVICE_PROBE cpu_present=true' in result.stdout
out = root / 'server-speech-probe'
out.mkdir(exist_ok=False)
shutil.copyfile(exe, out / 'porthub-speech-probe-arm64')
(out / 'porthub-speech-probe-arm64').chmod(0o755)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
proof = dict(source_revision=revision, target=target, ggml_native=values['GGML_NATIVE'], ggml_cpu_arm_arch=values['GGML_CPU_ARM_ARCH'], cpu_isa_flags=isa, cmake_cache_sha256=sha(cache), cpu_flags_sha256=sha(flags[0]), executable_sha256=sha(exe), executable_size=exe.stat().st_size, enumeration_passed=True, model_loaded=False, app_created=False, inference_test_requires_explicit_pinned_fixtures=True)
(out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
(out / 'source-revision').write_text(revision + '\n')
(out / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(out.iterdir()) if p.is_file()))
print(json.dumps(proof))
