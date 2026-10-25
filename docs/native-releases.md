# Native agent release distribution

Release versions use `major.minor.patch`, defined in the root Cargo workspace.
`porthub version`, `porthub --version`, agent heartbeats and release catalogs
report this numeric version. Major releases cover incompatible changes, minor
releases add compatible features, and patch releases contain compatible fixes.
Once published, a version must not be reused for different release contents.

`porthub version --verbose` separately reports the source revision and target.
CI passes the commit through `PORTHUB_SOURCE_REVISION`; container OCI labels also
retain it independently of `org.opencontainers.image.version`. Normally assemble
from one verified CI run and promote matching images from that same revision.
Build-only version overrides remain available for isolated updater fixtures.

CI assembles `porthub-release-bundle` only after every platform job succeeds.
All ten targets must have the same workspace version and valid checksums; a
missing target or mixed version fails the release. Prefer the aggregate artifact
from a single CI run. A targeted recovery build may reuse successful artifacts
when the production source, dependencies and build recipe are unchanged; only
tests or workflow orchestration may differ. Verify that equivalence with Git,
validate the complete bundle again, and record the recovery commits and runs in
the release notes. Do not combine different feature sets under one version.
The shared version identifies the same source release; operating-system-specific
capabilities and limitations still apply.

Deployment keeps the stable current-release tags `porthub:core`, `porthub:edge`
and `porthub:firewall`. It also tags the same images with the release, for example
`porthub:core-1.2.0`, and records that version in their OCI labels. All three
labels must match before deployment starts any containers.

The Rust API serves release metadata and binaries from a read-only bundle. It
does not run a downloader, shell script or Go handler to deliver these assets.
The production core image embeds exactly the latest release for all ten
platforms in `/app/client-bin`, including version and SHA256 sidecars. No client
artifact volume or runtime download is required. Historical releases are kept
outside the active image for operator rollback.

Generated binaries are not tracked in the source repository. They remain in
GitHub Releases and are embedded in the production image. Stage the verified
bundle before a production build:

```sh
PORTHUB_RELEASE_BUNDLE=/path/to/verified/bundle ./deploy.sh
```

The build stages only one release and rejects missing platforms, mixed versions,
unexpected history directories, and checksum mismatches. `porthub-api
--check-artifacts /app/client-bin VERSION` verifies an image offline. Development
images may build the host agent locally; production consumes the complete
prebuilt bundle instead of recompiling an agent during deployment.

All routes require the current enabled machine's ID and token; account cookies
cannot substitute for the machine credential. Retirement returns the existing
410 response, and disabled machines receive 403.

| Route | Behavior |
| --- | --- |
| `/api/machines/{id}/{token}/downloads/releases` | Versioned JSON catalog with actual bundled assets and missing targets |
| `/api/machines/{id}/{token}/downloads/agent/{target}` | Native binary with attachment filename, SHA256 and release headers |
| `/api/machines/{id}/{token}/downloads/rathole/{target}` | Compatibility URL serving the native binary with existing Rathole headers |
| `/api/machines/{id}/{token}/downloads/porthub` and `/client.sh` | Transitional CLI for old self-updaters; invokes native bootstrap while preserving a legacy rollback CLI |

The catalog has `format_version: 1`, `machine_id`, `releases` and
`missing_targets`. Each release supplies `target`, `os`, `arch`, `asset`,
`version`, `sha256`, `size` and an authenticated download `url`. Generated URLs
retain the machine's configured public authority and path prefix. The API
advertises only files it actually finds; accepted target names do not establish
that a platform build or installed lifecycle has been verified.

| OS | Native target names | Asset names |
| --- | --- | --- |
| Linux | `x86_64`, `x86`, `arm64`, `armhf`, `armv7` | `porthub-{target}` |
| macOS | `darwin_x86_64`, `darwin_arm64` | `porthub-{target}` |
| Windows | `windows_x86_64`, `windows_x86`, `windows_arm64` | `porthub-{target}.exe` |

Native `x86` selects the 32-bit Linux asset. The old Rathole URL deliberately
retains its existing `x86` → `x86_64` alias; use `i686` or the native endpoint for
32-bit Linux. Common aliases such as `amd64`, `aarch64`, `darwin_amd64` and
`windows_amd64` resolve to the corresponding native target.

`PORTHUB_CLIENT_BINARY_DIR` defaults to `/app/client-bin`; `CLIENT_BINARY_DIR` is
accepted as a fallback setting. Each asset requires an adjacent `.version` file
with a nonempty version of at most 128 ASCII letters, digits, dots, underscores,
pluses or dashes. An optional `.sha256` file is checked against the actual bytes
and, if present, its filename must match the asset. The Docker build now creates
both sidecars for its own architecture. Missing or inconsistent metadata returns
503 instead of publishing an unverified release description.

Binary and sidecar files must be regular files. Leaf symlinks, oversized
metadata, malformed versions and nonregular binary files are rejected. Hashing
uses a 64 KiB buffer and a bounded cache keyed by the opened file's identity,
size and timestamps. A download streams from that same descriptor, so atomic
replacement does not change an already opened response. Publish immutable
release directories atomically; in-place writes during an active response are
not a supported publication mechanism. Production image roots are read-only.

Downloads support GET, HEAD, single byte ranges, suffix/open-ended ranges,
SHA256 ETags, Last-Modified and conditional requests. Unsatisfiable ranges return
416; multi-range and unknown range units fall back to a full response. A changed
If-Range validator also returns the full file, preventing an accidental append
to a different release. Responses use `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. Native headers use `X-PortHub-Agent-*`; the
compatibility URL additionally preserves `X-PortHub-Rathole-*` fields.

## Agent release verification

The native agent's update module selects the compilation target, verifies the
catalog's enrolled machine identity, and checks platform, asset name, version,
size and digest. ARMv7 is selected from Cargo's compilation target rather than
being confused with the ARM baseline. Catalog download URLs never introduce a
credential authority: requests are reconstructed from the saved gateway and its
configured fallbacks. Redirects and server/network failures may try another
configured gateway; authentication rejection stops the attempt.

Downloads stream into a private temporary file with a 256 MiB maximum and a
ten-minute total deadline. Header identity, exact length and SHA256 must match
before an executable is staged in an immutable hash directory. Cancellation or
failed verification removes temporary files. Verification rechecks ownership
and the staged digest, then runs only the binary's `version` command, requiring
the published version. The child has a five-second lifetime limit and bounded
output. This preparation does not stop services, publish the CLI or acknowledge
an update request.

Local checks cover corrupted/truncated/oversized bodies, stale headers, wrong
identity/platform metadata, duplicate targets, configured fallbacks, redirect
handling, cancellation and unsafe staging directories. An isolated native API
test publishes the actual agent executable, downloads and verifies it, checks
its version, and rejects subsequent version/digest mismatches.

## Updating an installed Linux agent

The CLI can inspect and update an existing public registration and its matching
private service. A stopped service stays stopped, and its boot enablement is
preserved. Other local registrations are excluded. Select the public registration
ID shown by `porthub ls`; `--profile` also accepts its enrollment file.

```sh
sudo porthub update PUBLIC_REGISTRATION_ID --check
sudo porthub update PUBLIC_REGISTRATION_ID
# For user services, use --user; --bin-dir retains a custom CLI directory.
porthub update PUBLIC_REGISTRATION_ID --user --bin-dir /absolute/bin/directory
```

After download and verification, the CLI queues a separate systemd service
through D-Bus. Typed arguments retain literal spaces, dollar signs and percent
signs. The worker runs from the immutable release, so restarting the registered
service cannot kill its updater. User workers retain the caller's XDG config/data
locations. Queueing reports a unit name; completion requires its journal to reach
`committed`, not merely acceptance by systemd.

Before activation, a private `upgrade-*` receipt retains the original profiles,
units, manifests, executable paths, CLI target and service states. The normal
installation lock serializes other native service edits. Active registrations
must report `running` with the worker's version and exact executable identity;
stale status from another PID does not satisfy readiness. Only then is the shared
CLI published and the transaction committed. An unchanged executable is not
restarted. Activation/readiness failure restores the prior service files and
states. Backups and immutable releases remain for interrupted recovery:

```sh
sudo /path/to/retained/native/porthub update --rollback /etc/porthub/native/upgrade-EXAMPLE
```

Recovery accepts interrupted unit/manifest writes, leaves untouched services
running, and refuses later credential, unit or CLI changes. Completed rollback
is idempotent. Library fixtures cover paired activation, deliberate stopped and
disabled state, failed second readiness and interrupted activation. Real systemd
user-service checks exercise queued CLI activation, data forwarding and rollback;
these checks change only their disposable registrations.

Installed Linux public services also handle authenticated API update requests.
The controller accepts an explicit pending flag, request identity and target
version only after validating the configuration's machine identity. It discovers
the registration's owned manifest, executable and service cgroup; foreground
profiles do not perform automatic service updates. A saved CLI binding preserves
custom installation directories and user workers retain their XDG locations.

One dormant task waits for requests. Download preparation runs outside the
forwarding loop, with one child using the same native executable. Its attempt
timestamp survives restarts and delays network/preparation retries for five
minutes. A rolled-back request waits for a new request identity instead of
restarting the device repeatedly. Owner requests can be repeated from the UI;
each gets a fresh identity. Revocation or cancellation stops preparation.

The worker's private receipt binds the request and target to the public
enrollment. The agent reports a handled request only when that receipt is
committed and its installed public/private executable paths match the running
release. Merely observing the new version during readiness does not acknowledge
it. Rollback invalidates the proof. The API's ordinary sync acknowledgement then
clears the request target. No credentials or origin addresses are included in
routine update diagnostics.

Local verification includes the real native API and MongoDB requesting an
installed user-service update, observing the new version without acknowledgement,
and clearing the request only after commit. Service fixtures also reject a
foreign-machine configuration before download, preserve forwarding, verify one
download per request, and keep rejected/rolled-back requests unacknowledged.
Interrupted worker recovery remains available through the explicit rollback
command above.

The legacy updater compatibility bridge is implemented and locally tested;
complete automatic production adoption remains a rollout gate. Linux ticket
enrollment and legacy adoption are described in their native documents; complete non-Linux lifecycle
and all required platform builds remain unfinished. The production isolation
check exercises its packaged Linux architecture; other platform entries are
catalog/transport fixtures, not executed platform releases. Final remote client
upgrades and physical bandwidth tests have not occurred.
