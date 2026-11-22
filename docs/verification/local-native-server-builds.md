# Local native server build inputs

The optional trusted native controller can produce the four static server roles
on deployment hardware, without installing a host compiler or a permanent runner.
The release workflow consumes only exact-source verified inputs; image packaging,
UI/account tests, OCI identity checks and image smoke tests still run in CI.
There is no deployment operation in this lane.

Configure the existing private operator `builders.json` with `server_builders`
(maximum two). Each entry has the same `target`, `probe`, `build`, `fetch` argv
structure as client builders. Supported targets are `aarch64-unknown-linux-musl`
and `x86_64-unknown-linux-musl`. Commands may invoke
`scripts/ssh-server-builder.py` with an operator-owned host configuration:

```json
{"schema_version":1,"hosts":{"urm2-server":{
  "platform":"posix","destination":"urm2",
  "target":"aarch64-unknown-linux-musl","python":"python3",
  "ssh_options":[],"scp_options":[],
  "server_cache":"/home/ubuntu/.cache/porthub-server-native-v1"
}}}
```

For each command pass `--config PRIVATE_HOSTS --host urm2-server --target
{target} --state PRIVATE_STATE/urm2-server-{revision}.json`. Build additionally
requires `--root {root} --revision {revision} --timeout 2700`; fetch requires
`--revision {revision} --archive {archive}`. Set `build_timeout_seconds: 2700`
and `minimum_source_revision` to the commit introducing these scripts. Commands
are trusted local operator configuration, never workflow-supplied shell text.
The existing controller lock protects both producer maps and depot publication.

The deployment host needs Python 3.10+, Git, Docker, readelf, findmnt and lsblk.
Host Rust/C++ and a preinstalled SDK image are unnecessary. The pinned Rust
Alpine image is pulled if absent; package and Rust component bootstrap execute
inside the same limited, transient container as compilation. Network/package
availability failures fall back to hosted builds. No extra production container
or public listener is installed.

A two-CPU host uses one CPU and one Cargo job. Larger hosts use at most two CPUs
and half their detected CPU count. The compiler container has 6 GiB RAM, no extra
swap, 384 PIDs, 40 MiB/s cache-device read/write caps, low CPU/IO weights and an
OOM score preference. Its actual cgroup limits must match before bootstrap.
Admission requires a healthy existing core, at least 8 GiB available RAM and
20 GiB free disk, a supported pinned cache block device and no concurrent server
worker. The build stops on its deadline, a 10 GiB disk reserve, or the dedicated
32 GiB cache cap. Cache contents are not automatically deleted: this avoids
pruning another active build or unrelated files. Capacity failures select hosted
fallback.

A worker executes the existing role builds, static checks, role help checks,
edge fixture suite and portable speech probe including the x86 baseline emulator.
It records exact Git tree, recipe hashes, toolchain, validation log digest,
actual resource limits, artifact hashes and source. The consumer verifies those
receipts, archive bounds, every static ELF architecture, probe evidence and
before/after source/archive identity before making outputs available to the
existing image packager. A verified cached archive retries upload without a new
build. Failed remote stages retain their private nonce/state for investigation;
never remove a stage while its worker is active.

The same immutable depot URL/key scheme carries server ZIPs. The source manifest
has separate `servers` and `targets` maps. Each publisher replaces only its own
map while preserving the other, and serializes local replacement and upload.
The repository variable is the existing `PORTHUB_TRUSTED_NATIVE_DEPOT`.
Unconfigured depots immediately retain hosted builds. A configured endpoint gets
a bounded initial pickup grace, then waits only for bounded active producer
records. Missing, invalid, failed or expired entries choose the hosted target.
Only the missing targets run on hosted native builders; packaging still covers
all requested targets. A skipped hosted job is accepted only when the verified
plan reports zero missing targets. Failure/cancellation of planning, UI, account
checks or any required hosted target prevents packaging.

Local cold bootstrap can be slower than hosted hardware and the planning runner
wait consumes hosted minutes. This lane makes available hardware usable and
avoids duplicate native builds when valid local artifacts arrive; it does not
claim universally lower wall time or GitHub minutes. Full native execution of
this new server lane must be recorded separately from its contract tests.
