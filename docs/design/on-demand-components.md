# Independently usable PortHub components

Status: agreed requirements and implementation design; not shipped. The current
agent still bundles these features. This document does not change the published
installer, updater, or release format.

## Ownership and package boundaries

The `porthub` executable remains the user interface and contains enrollment,
public and private networking, OTA, component management, basic status, logs,
diagnosis, HTTP serving, and ordinary file upload/download. Core starts serving
immediately; optional downloads must never gate enrollment or healthy tunnels.

Optional executables provide Tor, terminal sharing/local workspaces, directory
sync/watch, and the live stats dashboard. They have their own CLI entry points
and can be downloaded independently. Local operations must work without an
installed core or a PortHub server. Operations inherently requiring a gateway,
such as public exposure or remote sharing, still require one. A standalone
transfer executable can reuse the core transfer library without making that
library optional in core.

The server tracks only core version and core update status. Component inventory,
update retries, and compatibility decisions belong to core locally. Failure to
update an optional tool must not mark a healthy core update as failed.

## Compatibility and discovery

Core selects the newest stable component release compatible with its supported
IPC protocol, core version, operating system, architecture, and declared host
capabilities. “Latest” never means blindly running the latest executable.
Versions are independent: a core release does not require relinking unchanged
components or changing their component versions.

Use one versioned catalog schema containing, for each component artifact:

- Component identity, numeric version, OS/architecture, minimum/maximum core
  compatibility, and supported IPC protocol versions.
- Immutable source revision, build-input digest, executable size and SHA256.
- Official release tag, platform archive name, archive size/SHA256, and exact
  executable member name for GitHub fallback.
- Required capabilities and whether this platform supports the component.

Prefer catalog and binary downloads through the enrolled gateway using its
existing verified transport. Fall back to official GitHub release metadata and
direct release asset URLs if that service is unavailable. A gateway outage
must not prevent use of an already verified compatible local tool. Do not send
gateway credentials to GitHub or forwarded download origins. Download clients
must enforce HTTPS, bounded redirects, response-size limits, and timeouts.

Validate the catalog before selecting an artifact. Only permit known component
identities, supported targets, and official repository release locations; never
accept arbitrary executable locations from a command argument or catalog.
Reject conflicting entries for the same component/version/target. Verify both
the platform archive and extracted executable against the trusted catalog.
Checksums detect corruption but do not protect against a compromised publisher;
the catalog is trusted through the configured gateway or official GitHub TLS
origin, matching the current release trust model.

Release retention must preserve a compatible downloadable component for every
supported core version. In particular, the current latest-only release pruning
cannot delete the only fallback artifact still required by a supported core.
Either carry forward compatible component artifacts/catalog entries into the
retained release or retain the referenced immutable release. Never fabricate a
GitHub URL for a release already removed by pruning.

## Background installation and updates

After core becomes ready, a supervised maintenance worker fetches the catalog
and prefetches the supported optional tools with bounded concurrency. Continue
normal core operation throughout. Interactive commands join the same pending
download, display useful progress, and run once it completes; do not launch a
second installer. Unsupported tools fail with an actionable platform message.

Refresh on startup and periodically with jitter, bounded retries, and backoff.
Recheck compatibility after a core update. An administrator can restrict network
sources, background prefetch, component availability, and explicit version pins;
automatic updates respect those restrictions. Offline operation uses the last
verified compatible version and reports any unavailable tool clearly.

Cache by component/version/target/digest in a private, ownership-checked
directory. Use a cross-process install lock, bounded temporary files, checksum
verification, executable permissions, and atomic publication. Archive extraction
accepts only the exact regular executable member: reject links, traversal,
duplicates, unexpected executables, and oversized output. Never run unverified
downloads. Keep a last-known-good version and do not delete in-use binaries.

Start and validate a replacement worker before switching new work to it. Existing
sessions retain their worker until they drain where possible. If a protocol
cannot hand off safely, defer its update until idle or reconnect with explicit
session recovery. A failed replacement leaves the working version active.
Component crashes have bounded restart backoff; they cannot restart the whole
agent or silently weaken networking, authorization, or Tor privacy policy.

## Process communication and independence

Use a small shared protocol crate rather than linking helper implementations
back into the agent. Typed, versioned IPC uses Unix sockets on Unix and named
pipes on Windows with owner/ACL checks, peer verification, bounded frames,
request IDs, cancellation, deadlines, and protocol negotiation. Reject an
incompatible handshake before dispatching work.

Persistent workers handle streaming and long-lived operations. Core supervises
their lifecycle; IPC carries structured requests/results/events and streams,
not parsed human CLI output. Invoking a standalone CLI directly remains valid;
it starts its own local backend when core is absent. Shared libraries provide
code reuse, while process isolation gives independently replaceable tools.

Core retains machine credentials, server authorization, routing policy, and the
authenticated exposure broker. Give helpers narrowly scoped session capabilities
rather than machine tokens. Endpoint paths and credentials must not be logged.
Standalone local functions do not need those capabilities. Extract the terminal
runtime and tmux build into its component; core keeps only the broker/protocol
pieces needed to authorize terminal sharing. Tor moves its heavyweight Arti
runtime into its worker while core retains private-network policy enforcement.

## Builds and release presentation

Compute component build inputs from its transitive workspace dependencies,
Cargo.lock dependency closure, feature set, toolchain, target, build scripts,
embedded assets, and build recipe. A source-path-only filter is insufficient.
Core changes rebuild core; shared protocol/dependency changes rebuild affected
tools too. Reuse unchanged artifacts only after verifying their input digest,
provenance, size, and checksum. Missing or uncertain provenance triggers a build.

Keep one coherent GitHub release. Publish core platform binaries, one tools
archive per supported platform containing the independent executables, and one
shared catalog. The gateway caches/extracts archives and offers individual tool
downloads. GitHub fallback downloads the platform archive directly and extracts
only the requested tool. Standalone users can also download that archive without
core. Avoid a separate public release for each tool or intermediate build.

The current gateway release reader and publisher require `.version`/`.sha256`
sidecars for every core platform. Deploy a reader supporting both old sidecars
and the new catalog before switching the publisher to the compact layout.
Preserve existing bootstrap/OTA endpoints and supported old clients. Complete
platform coverage, artifact verification, draft promotion, and immutable release
rules still apply. Verification-only builds never publish releases.

## Implementation and verification sequence

1. Add the shared catalog/compatibility and IPC contracts with no heavyweight
   terminal/Tor dependencies. Test selection, malformed catalogs, and protocol
   negotiation.
2. Add the verified component store and downloader. Test gateway failure,
   GitHub fallback, offline cache, wrong checksums, unsafe archives, concurrent
   requests, interrupted downloads, authorization failures, and source limits.
3. Extract optional tools behind stable core commands and worker APIs. Test
   independent local use with no core/server installed, plus authenticated
   sharing and policy enforcement through core.
4. Wire background prefetch/update and worker replacement. Test that slow or
   failing downloads do not delay core startup, active tunnels survive, retries
   back off, and incompatible upgrades remain unapplied.
5. Add gateway component downloads and dual-format release reading. Test old
   bootstrap/OTA clients before publishing the compact release format.
6. Update dependency-aware CI, artifact reuse, assembly, and retention. Verify
   core-only changes skip unchanged tool builds, shared changes rebuild them,
   and every published catalog resolves to verified downloadable artifacts.

Record native Windows, Linux, macOS, and supported architecture results before
release. Windows named-pipe ACLs and executable replacement require native
coverage; Unix-only tests cannot establish their correctness.
