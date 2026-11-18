# Local native release builds

The controller records the prepared release commit before probing builders.
An interrupted first probe can resume against that commit on the next check.

For builds on another machine, configure an SSH host entry and its readiness
probe. The adapter checks the native toolchain before it accepts work.
[SSH builder setup](../../scripts/ssh-native-builder.README.md)

The PortHub core can serve verified artifacts from a read-only mount.
[Artifact endpoint configuration](../native-build-depot.md)


Run this on each explicitly authorized build host, in a clean checkout at the
same full commit. It does not provision hosts, register runners, deploy, install
services, or publish. SSH/staging remains a separate explicit operator action.

```
python3 scripts/build-local-native.py --source-revision FULL40SHA --output /owned/new/component-builds --tool core
```

The default prints a plan without invoking Cargo or downloading terminal sources.
Add `--execute` to build. On Windows use `python` and a Windows-owned output path.
Omit `--tool core` to build all configured independent components. Each component
gets a separate Cargo invocation, preventing optional-helper feature unification.
`--previous` accepts an existing verified component-build index for safe reuse.

Prerequisites are the existing shipping workflow's native toolchain/dependencies:
Rust from rust-toolchain.toml, Python 3.11+, Git; Linux matching musl-gcc, terminal
builder prerequisites and readelf; Windows MSVC/Windows SDK; macOS Xcode command
line tools and target SDK. Media helper native dependencies still apply when
selecting all tools. This entry point installs none of them and does not elevate.

Linux x86_64/arm64 chooses the shipping musl target and builds the existing pinned
terminal bundle. macOS/Windows select the matching architecture only. Unsupported
hosts fail closed. Shipping compiler inputs come from component-platforms.toml;
conflicting inherited settings are rejected, not erased. Full source pin and
clean-tree checks bracket the existing build orchestration. Cargo uses --locked
and the configured release recipe. index.json references build-receipt.json files
with actual dependency/input closure and raw binary SHA/size; all emitted binaries
are verified again through previous_builds/verify_reuse before success.

This establishes artifact/input integrity, not native service, audio, network,
signing/notarization, or all-platform release acceptance. Existing hosted native
checks, prepare-release/assemble-client-release and publication verification remain
separate. On nitin-mbp, the arm64 core build at commit
`e33e3e5f179c7dd5113384cde2f13ae307ca831e` completed in 92 seconds.
The local build command verified the artifact receipt and the executable
reported `porthub 1.11.42` when run on the Mac.

## Hybrid native builders and hosted fallback

`scripts/hybrid-native-build.py controller` is the trusted local invocation:

```
python3 scripts/hybrid-native-build.py controller --root /owned/clean/checkout --source-revision FULL40SHA --config /private/builders.json --output /owned/controller-FULL40SHA
```

The private configuration has schema_version 1, builders (at most ten), and depot.
Each builder has target and nonempty argv arrays probe/build/fetch. Templates are
`{revision}`, `{target}`, `{root}`, `{output}`, `{archive}`; no shell is invoked.
Probe is limited to 8s, build to 900s by default (configurable up to 1800), fetch to
120s. Authentication stays in an existing SSH agent/control socket or transport
credential store, never the configuration's command arguments or output URLs.
Use explicit pinned checkout paths and strict SSH host-key checking. The worker
command executes only an owned child tree, with an 840s default bound, in a new
private output stage; it does not alter checkout refs or install dependencies:

```
python3 scripts/hybrid-native-build.py worker --root /owned/pinned/repo --source-revision FULL40SHA --tool core --output /owned/new/core-FULL40SHA.zip
```

Example private builder entry (a trusted controller can use its existing SSH
configuration/keys; no credentials or host names are committed):

```
{"target":"aarch64-apple-darwin",
 "probe":["ssh","-oBatchMode=yes","-oStrictHostKeyChecking=yes","-oConnectTimeout=5","native-mac","true"],
 "build":["ssh","-oBatchMode=yes","-oStrictHostKeyChecking=yes","native-mac","python3","/owned/pinned/repo/scripts/hybrid-native-build.py","worker","--root","/owned/pinned/repo","--source-revision","{revision}","--tool","core","--output","/owned/new/core-{revision}.zip"],
 "fetch":["scp","-oBatchMode=yes","-oStrictHostKeyChecking=yes","native-mac:/owned/new/core-{revision}.zip","{archive}"]}
```

Paths/SSH command tokens are trusted operator configuration. Keep them free of
shell metacharacters/spaces for remote SSH invocation; SSH itself interprets its
remote command through the remote shell. The controller never invents credentials,
changes a host's release/feature policy, or registers a self-hosted public runner.
On a repeated source attempt use a fresh owned remote output path, or configure a
trusted remote wrapper to return the already verified immutable ZIP.

`depot` contains an HTTPS `base_url` and upload argv with `{file}` and `{key}`.
For example an installed authenticated object-store CLI can copy `{file}` to an
operator-controlled bucket prefix plus `{key}`. Storage access policy must prevent
untrusted writers. Upload is bounded; source-keyed manifest is uploaded *after*
each verified target's content-addressed ZIP, so faster targets are available
without waiting for slow builders. A new exact source revision gets a new key.
Controller resume re-verifies successful local archives and skips probe/build for
those targets. Failed/unavailable targets remain absent; they never block others.

Configure repository Actions variable `PORTHUB_TRUSTED_NATIVE_DEPOT` to this trusted
HTTPS base. Ordinary agent-platforms builds automatically read
`BASE/FULL40SHA/manifest.json`; no manual run input, embedded credentials, exposed
local service, or public self-hosted runner is needed. There is no caller-supplied
depot override. Only exact source-keyed manifest and content-addressed artifact
paths in this depot are accepted. HTTPS redirects cannot cross origins. Manifest
reads have a 15s budget; archive download has a 150s aggregate budget and an outer
170s workflow process cap. Sizes, ZIP paths/types, raw binary SHA/size, exact source,
locked inputs and release recipe are verified. Executable mode is restored after
ZIP extraction. Any missing/stale/unreachable/invalid local artifact falls back
to the normal hosted builder, rather than failing the release or waiting forever.

Local archives may contain just core or any configured subset. They become a
verified `--previous` input, merged with retained prior artifacts; the existing
component planner reuses unchanged successful tools and builds only missing ones.
All existing hosted platform/runtime/package gates remain in place. This saves
compilation, not acceptance checks. Local availability is sampled once per target
when its normal hosted build reaches the build step: if a builder finishes later,
the already-started hosted fallback is not cancelled. Its next attempt can reuse
the local result. No polling, distributed locks, or cancellation of valid builds
is added. Publication remains the existing separately gated release operation.

For an SSH depot on the existing core host, use the checked-in helper, installed
at a fixed operator-owned path, and a dedicated existing directory (owner-only
write; no symlink parents):

```
"depot": {"base_url":"https://trusted-core.example/api/native-builds",
  "upload":["python3","scripts/native-build-depot.py","upload",
    "--host","trusted-core","--remote-script","/owned/tools/native-build-depot.py",
    "--remote-root","/owned/native-builds","--file","{file}","--key","{key}"]}
```

The uploader streams stdin over strict, noninteractive SSH, not scp-to-an-arbitrary
path. The remote helper accepts only exact revision/manifest.json or
revision/target/SHA.zip keys, checks content addressing, and replaces files
atomically. It creates no HTTP listener: the existing core's read-only route must
serve that dedicated directory. It installs no service/container/database. Depot
install/prune locking uses POSIX flock, so this narrow storage helper is for the
Linux core host; Windows/macOS builders still use their native build worker.

Depot cap defaults to 4GiB final artifacts and 12 source revisions; incoming files
are independently limited to 512MiB and removed on failure. Reaching a cap rejects
new uploads, leaving existing active data intact and allowing GitHub fallback.
There is no background or automatic deletion. Review a cleanup plan with *all*
currently active source SHAs protected, then repeat with --execute only once the
operator has confirmed those sources (including ongoing workflow downloads):

```
python3 /owned/tools/native-build-depot.py prune --root /owned/native-builds --protected-source ACTIVE40SHA --keep 4
```

Protected source arguments may repeat. Cleanup preserves protected and newest
retained revisions, ignores foreign top-level names, and refuses symlinks in
managed revisions. Source snapshots and content-addressed archives are immutable;
manifest replacement is atomic. A file already open for an HTTP download remains
consistent across a new manifest. Never prune a revision in use by a workflow;
explicit protection is necessary for future archive requests, not just open FDs.

At most three builder jobs run concurrently. Slow/offline builders do not delay
another host's publication. Probe commands are operator-configured capability
checks, not a permanent availability flag. A staged toolchain can be provided in
that build job's PATH; no temporary musl compiler location is hard-coded here.

## Triggering at the prepared release commit

The normal continuous-release prepare job publishes a tiny `native-build-request`
artifact containing its *final prepared* revision and run identity. The trusted
controller's one-shot entry point consumes only active main-branch
continuous-release runs from the configured repository, checks the artifact digest
and request identity, fetches trusted main, and proves prepared source ancestry
before opening an owned detached checkout. This avoids compiling the pre-push
version when CI subsequently advances the release version.

```
python3 scripts/hybrid-native-release.py --root /owned/repository --repository algofly-oss/porthub --config /owned/private/builders.json --state /owned/private/native-state
```

Run this directly for one check, or review/copy the optional user unit templates
in `deploy/native-build-controller/`. Replace their `/owned` paths, then explicitly
install/enable them using normal operator systemd user-unit management. The
repository does **not** install or activate those units. The timer invokes one
bounded oneshot per minute, not a persistent polling process. Quiet checks make
one small GitHub runs request and exit. Only active trusted main runs get artifact
lookups; PRs/forks/arbitrary workflows are ignored before local credentials or
builders are used. `gh` uses the operator's existing read-only repository access;
no GitHub token is sent to a builder. SSH/depot configuration remains outside the
checkout and must be operator-owned without group/world write.

The atomic JSON checkpoint records source/run/target outcomes. Completed sources
are skipped, verified target outputs survive retries without rebuilding or
re-uploading, and unavailable targets can retry on later checks while that release
is active. Maximum 12 owned source checkouts and 32 checkpoint records bound state
cardinality; reaching the source cap chooses hosted fallback rather than deleting
active work. Archive bytes also consume local controller disk: monitor/prune
explicitly with active source protection, just as for the capped depot. No state
cleanup is installed or run automatically. The user timer cannot overlap itself;
a controller lock also prevents duplicate concurrent invocations.

The existing server/browser gate normally runs between release preparation and
client build, giving configured local hosts time to finish. There is no promise
that a slow local build beats the hosted lookup; late local results remain useful
for a later attempt. Unavailable controllers/depot simply leave the original
GitHub builds in place. This source ships the orchestration and unit templates;
actual activation of a controller, its host adapters, timer and trusted HTTP depot
is separate operator work and is not claimed by the orchestration unit tests.

Actual local native evidence supplied during integration (separate from shipped
orchestration tests):

- Mac arm64 core 1.11.42, source e33e3e5f179c7dd5113384cde2f13ae307ca831e,
  binary SHA256 391c47f370bdce68de5ba5978141e942a9597a9b8c17cfdb034b68fab9232ffe,
  35,670,256 bytes. The controller/restore verifier accepted the real core-only
  artifact, restored executable mode, and the release planner selected core reuse
  plus builds for the four missing helpers; no missing helper was compiled in
  that verification. Receipt `/tmp/porthub-hybrid-actual-mac-partial-proof.json`.
- Linux x86_64 static core, source 6f32c763ebaa927d9cfb08d3cbf32af367b85b8b,
  binary SHA256 8318ef7ddad9857460b8c6d3830d5d549b80eb078d29537b8a704d4c9c0e5fc3,
  49,298,528 bytes, native Cargo duration 3m13s. Static verification and --version
  passed. The exact retained terminal bundle and shipping environment permitted
  core reuse after target deletion, with four missing helpers left to build.
  Operator receipt pointer `/tmp/porthub-luna-native-current`.

These prove real native build artifacts and partial reuse, not an activated
unattended host fleet, live HTTP depot, successful SSH adapter on every host, or
an end-to-end published hybrid release. Those activation/integration observations
must be recorded separately when performed.
