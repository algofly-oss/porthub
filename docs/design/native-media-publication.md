# Optional native media helper publication contract

Status: strict optional-set, gateway archive-cache and assembly support is implemented
in the current development tree. Helper build-job/reuse wiring and final release
review remain required. No external release assets have been uploaded by these scripts. Native source and
receiver hardware validation remains separate from packaging validation.

The normal core release may contain three additional optional GNU assets:

- `porthub-media-components.json` (namespace `porthub-media`, schema 1).
- `porthub-media-helper-x86_64-unknown-linux-gnu.tar.gz`.
- `porthub-media-helper-aarch64-unknown-linux-gnu.tar.gz`.

A separately verified Windows x86-64 helper may add the fourth known optional
asset, `porthub-media-helper-x86_64-pc-windows-msvc.tar.gz`; its archive member ends
in `.exe` and its PE/MSVC validation is separate from GNU ELF validation. An
initial GNU-only release does not claim Windows native-source availability.

The legacy `porthub-components.json` schema, its `Component` enum, and its 21
ordinary assets remain unchanged. A media-aware complete release has 24 assets;
a release with no media assets remains valid. A complete media set including
Windows has 25 assets. A partial optional set, an unknown
extra asset, a duplicate target, or a mismatched digest must fail verification.
Do not create a separate stable helper tag that becomes GitHub's latest release.
Do not accept arbitrary extra assets merely because the core release is valid.

## Source and runtime baseline

The helper is a separate on-demand GNU executable. The static agent, API, edge,
and runtime retain their current linking strategy and gain no PipeWire runtime
dependency. The helper is launched in the authenticated desktop user session
only. There is no new daemon, container, audio file, default-device change, or
idle capture in the product.

Use native x86-64 and ARM64 GNU build hosts with GLIBC no newer than 2.35. A build
container is optional build infrastructure, never a client runtime requirement.
The runtime explicitly requires both the PipeWire library and desktop daemon to
be at least 0.3.68. Missing/incompatible PipeWire is reported as unavailable.
An actual baseline build showed that Rust pipewire/libspa 0.10.1 fails against
0.3.49 headers: the wrapper requires newer SPA metadata/video definitions.
An actual 0.3.65 build then identified the unconditional `SPA_MEDIA_SUBTYPE_opus`
reference, [documented upstream as introduced in 0.3.68](https://github.com/PipeWire/pipewire/blob/0.3.68/spa/include/spa/param/format.h#L51). The supported build/runtime
minimum is therefore 0.3.68; neither older baseline is claimed. The Rust feature
remains `v0_3_65`, its highest available feature tier below `v0_3_77`.
Ubuntu 22.04's original development package is 0.3.48, so it is not a
valid build input for this helper's selected 0.3.68 API. Bootstrap the exact
source pinned in `vendor/media/build-inputs.json` into an isolated prefix; do not
replace the host's PipeWire service or install a daemon as part of the build.

The upstream [build instructions](https://github.com/PipeWire/pipewire/blob/0.3.68/INSTALL.md)
and [Meson options](https://github.com/PipeWire/pipewire/blob/0.3.68/meson_options.txt)
are the primary sources for that bootstrap. The pinned archive is the official
PipeWire project's GitHub mirror, checksum
`fdcf7f2ee881cdc91ef54b3a558e431bdb3395f7a1e9044753c7a89346fafd91`,
2,055,909 bytes. Verify its size and SHA before unpacking; reject paths outside
the private build directory and reject links. The pinned archive has no links.
The optional build-only image recipe `vendor/media/Dockerfile.glibc235` pins
Ubuntu 22.04 by digest and installs build tools, bindgen's `libclang-14-dev`,
and `libdbus-1-dev`; the exact
PipeWire Meson configuration requires DBus development headers even with other
auto features disabled. Neither the builder nor bootstrap starts a daemon or
changes host services; generated PipeWire files stay in the private prefix.
`scripts/bootstrap-media-pipewire.sh` downloads, verifies and safely extracts the
pinned source, then installs solely into two explicitly supplied new private
build/prefix paths. Run this in the ephemeral builder, not as a client installer.
Record the image digest, `dpkg-query -W`, Rust version and actual ELF baseline in
the private build receipt.

Run Meson using the exact argument list in the input lock, an explicit private
`--prefix`, and `--libdir=lib`; build/install only into that prefix. Export its
`lib/pkgconfig` directory in `PKG_CONFIG_PATH`. The helper links against the
ordinary host `libpipewire-0.3.so.0` at runtime, without private RPATH/RUNPATH.

Run `scripts/build-media-helper.sh TARGET RELEASE MIN_AGENT_VERSION REVISION OUT`
from a frozen checkout. The script checks native architecture, GLIBC baseline,
exact PipeWire build version and clean committed build inputs before building.
`REVISION` is the actual 40-character source commit. `MIN_AGENT_VERSION` is the
compatible **agent** version, not the independent server workspace version.
Production packages require agent >=1.11.34; stable agents through 1.11.33 do
not include this media feature. The earlier private >=1.11.32 fixture catalog
is isolated test data and must never be published.
`RELEASE` is the enclosing normal core release version. Both GNU builds must use
the same reviewed source revision. No Windows or macOS helper archive is
advertised in this initial media catalog.

## Artifact identity and packaging

`scripts/package-media-helper.py` checks real ELF architecture, dynamic-loader
presence, required library allowlist, GLIBC version requirements <=2.35, and
absence of RPATH/RUNPATH. Its input digest covers Cargo manifests/lockfile, helper
and component source, Rust toolchain, input lock, and build/package scripts.
Production packaging rejects uncommitted/changed source. It never uploads.

Each GNU archive contains exactly one regular executable:
`media-helper/HELPER_VERSION/porthub-media-helper`. Archive owner, group,
timestamp, mode and gzip timestamp are deterministic. The artifact entry carries
helper version, target, compatible agent requirement, protocol 1, exact source
revision, build-input digest and executable/archive byte sizes and SHA-256 hashes.
The two single-platform artifact records must be merged into one typed manifest,
not published as competing manifests. Build receipts are review/provenance data;
they are not extra public release assets in the strict three-asset extension.

## Release integration and remaining build-job wiring

The current tree provides these verification hooks. Enable helper build/reuse jobs
only from the reviewed immutable media release, independently of ordinary static
component builds:

1. `prepare-release.py` and component build planning: optionally request the two
   GNU helpers from the reviewed immutable media snapshot, without invalidating
   or relinking unchanged core components.
2. `publish-release.py`: accept either zero optional media assets or the exact
   complete three-asset set; parse/validate the typed media manifest and both
   archives before upload. Preserve existing monotonic publication/history and
   per-artifact source provenance checks.
3. `stage-verified-release.py`: stage the exact optional set, verify every hash,
   target/member and ELF baseline, reject partial sets and unknown assets.
4. `fetch-component-release.py` reuse: include and verify all optional assets
   when present; never drop their manifest or silently reuse different bytes
   under one immutable version. A legacy release remains usable unchanged.
5. `verify-static-components.py`: keep static checks for all ordinary components;
   separately apply the GNU media ELF checks. Do not call a GNU helper static.
6. Rust release-directory verification: recognize only the same exact optional
   set and call `media_store::Manifest::parse`; enforce archive/executable hashes,
   member/target identity, compatible protocol, core/agent version and provenance.
7. Add publisher/stage/reuse/directory tests for legacy releases, complete valid
   media releases, partial sets, unknown assets, wrong namespace/target/protocol,
   downgrade/immutable-version changes, corrupt archives, executable mismatch,
   excessive GLIBC requirements and reused-release provenance.

The existing release cache's bounded asset count permits the additional files,
but its core-only allowlist does not constitute media catalog verification. Add
the optional gateway catalog route only after the same typed verification.
An approved official GitHub HTTPS manifest plus digest/provenance validation is
the current trust model; no detached signature verification is claimed.

## Private native validation

A private fixture may use a SHA-verified helper placed in its own explicitly
approved user cache/catalog. It must use a separate test registration/profile,
explicit device identity and test VID/PID, never weaken production HTTPS/catalog
checks or rewrite an installed registration. The real next transport proof must
exercise new media API authorization, report/plan worker, negotiated PortHub
carrier, exact selected source and receiver-local UAC followed by an ordinary
application capture. An SSH audio pipeline is only an OS-adapter test.

Receiver USB identity is configured locally and advertised by the receiver. A
plan must match it; absent identity disables media receiving with a clear reason.
`1209:0001` is confined to authorized private in-house fixtures. There is no
borrowed/default production identity, and no third-party PID application has
been submitted. Source microphone, camera, media receiving, keyboard and raw USB
permissions remain separate. Native camera and Windows desktop source-host
integration are not yet complete and must not be advertised as available.


`prepare-release.py --media-target TARGET` validates an explicit build plan,
requiring both GNU targets, an optional known Windows target, helper source, and
agent >=1.11.34. It reports `media_targets` and `media_min_core`; it does not build
or publish a helper. `merge-media-release.py` merges platform manifests/archives
into a new verified directory and may rewrap unchanged reviewed artifact metadata
for a later enclosing release. `assemble-client-release.py --media-assets DIR`
accepts one or more such platform or merged inputs, copies only the exact known
optional files, and invokes complete Rust verification. Without this flag the
ordinary 21-asset behavior remains unchanged.

The dedicated `/api/downloads/media/catalog` route serves the verified namespace;
`/api/downloads/media/{version}/{target}/{executable_digest}` returns the verified
**archive**, with archive length and archive-digest ETag. The cache uses a separate
media index, preserves the legacy release-index schema, rejects mutable published
identities/downgrades, bounds downloads and extraction, and never executes the
helper. Absent optional assets return media unavailable without affecting core
release startup. The ordinary components route continues to serve executables.

## Native CI build and reuse

The reusable `media-helpers.yml` workflow plans optional assets before the full
agent release bundle is assembled. A checkout without the helper remains a
legacy release. A checkout containing it requires agent >=1.11.34. New helpers
build on native x86-64 GNU, ARM64 GNU and Windows runners; the GNU jobs use the
pinned GLIBC 2.35/PipeWire 0.3.68 build environment. These builds do not open
capture devices or prove native device operation.

For an unchanged helper, `media-helper-plan.py` verifies the prior manifest's
source input digest against its Git tree, then compares semantic build inputs.
Only the unrelated workspace release version and locked dependencies outside
the helper dependency closure are ignored. Reuse retains the old artifact's
version, source revision, input digest and archive bytes. A changed helper
requires an explicit helper version increase; it cannot overwrite the old
identity. Recovery uses exact HTTPS archive URLs, rejects redirects, and checks
archive and executable digests before exposing the recovered directory.

The bundle job requires the helper workflow to succeed, restores the complete
verified optional set, and passes it to `assemble-client-release.py`. Assembly
merges and verifies the entire bundle in a temporary directory before making
the destination visible. A missing or corrupt optional archive fails the
release; it does not silently fall back to a helper-free bundle.
