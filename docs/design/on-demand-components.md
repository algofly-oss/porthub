# Independently usable PortHub components

Status: implementation in progress; not shipped. The current published agent
still bundles these features. The `porthub-components` crate implements catalog
validation, compatibility selection, verified downloads/cache, gateway/GitHub
fallback, installed-version receipts, IPC framing, and background maintenance.
`porthub-sync` provides independently usable directory watching and an HTTP
receiver, so neither end needs core or a PortHub gateway. Core sync/watch
commands now use its persistent worker; core transfer builds exclude watch code.
Background maintenance begins after the first authenticated configuration is
applied. Core also exposes local `components list`, `fetch`, and `update` commands.
Tor, terminal and live stats extraction, gateway delivery, release packaging,
and installed rollout verification remain incomplete.
No modules have been published or deployed. This document does not change the
published updater or release format.

## Ownership and package boundaries

Normal users interact exclusively with the existing `porthub` commands. Core
uses worker IPC and manages downloads/updates automatically; users never need
to invoke a component executable to use a PortHub feature. Standalone CLI
arguments exist for deliberate reuse of one tool on another system.

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
Worker startup locks and retry state are scoped to the endpoint identity, which
includes the account, cache, state context, tool version, and executable hash. A
failed candidate cannot impose its backoff on an older binary or another state
context. Repacking an unchanged tool preserves its identity. After a successful version handshake, the core records a private activation
receipt for that identity. If a later candidate fails before receiving a tool
request, it can try up to four previously activated older compatible versions.
Each executable is verified again, and administrator pins and disabled-component
policy still apply. A download receipt alone never qualifies a version for this
startup recovery. This does not yet provide transactional staging of Tor pool
bootstrap or pin existing consumers to a worker version; those remain required.

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

CLI invocation is an allowed fallback when a module's IPC/RPC transport is
unavailable. It is internal to core: normal user commands do not change. Core
must use the same verified compatible executable, invoke it directly without a
shell, and use versioned machine-readable output or inherit the terminal for
interactive frontends. It must not parse human status text. Sensitive arguments
use protected handoff files or standard input; never put machine credentials in
process arguments or logs. Do not replay a mutating operation after an ambiguous
RPC result; fall back before sending it, or reconcile its outcome first. A
module policy/authentication rejection remains a rejection. Native tests must
exercise forced CLI mode and automatic transport failure/recovery. Sync now supports `PORTHUB_COMPONENT_TRANSPORT=auto|rpc|cli` (default auto).
Its CLI fallback invokes `__porthub-stdio` directly and carries the same typed
contract through inherited pipes, including foreground streams. Automatic
fallback is limited to pre-dispatch worker startup failures. Remaining extracted
tools must support this contract before release.

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

## Configuration implemented so far

`PORTHUB_COMPONENT_SOURCE=auto|gateway|github` selects the permitted download
sources; `auto` prefers the gateway. `PORTHUB_COMPONENT_GATEWAY` explicitly sets
an HTTPS gateway; otherwise core uses its enrolled gateway for background work
and discovers an installed gateway for interactive commands. Tool downloads do
not contain enrollment credentials.

`PORTHUB_COMPONENT_DISABLED` is a comma-separated list of prohibited tool names.
`PORTHUB_COMPONENT_PINS` accepts comma-separated `name=major.minor.patch` pins;
pins still require compatible core/platform/IPC metadata. Set
`PORTHUB_COMPONENT_PREFETCH=false` to update already installed tools without
prefetching unused ones. The default is true.

`PORTHUB_COMPONENT_CACHE` can override the private absolute cache path. Executable
caches must not be writable through another account or an untrusted ancestor.
`PORTHUB_STATE_DIR` retains the existing per-user transfer/job state convention.
The system service mirrors verified software into `/var/cache/porthub-components`
on Linux, `/Library/Caches/PortHubComponents` on macOS, or
`%ProgramData%/PortHubComponents` on Windows. Core automatically reuses those
bytes in a user's private execution cache without another network request.
Catalogs are remembered privately, so subsequent shared-cache cleanup does not
break offline use. Profiles, credentials and worker state are never mirrored.
`PORTHUB_COMPONENT_SHARED_CACHE=off` disables this reuse; an absolute path selects
an administrator-managed shared cache location. Existing unmarked directories
are not adopted, and shared files must not grant mutation to other accounts.
Module HTTP clients still need integration with core's outbound routing/source
selection policy before rollout.

Worker startup uses a verified executable and the private endpoint argument
only; requests and credentials travel over typed IPC. A readiness ping precedes
use. Concurrent starts share a lock, failed starts back off, and idle workers
exit after five minutes. Foreground sync watches follow connection lifetime;
detached jobs survive caller exit and remain manageable through the same core
commands. Native core watch tests first build `porthub-sync` beside the core
binary, or use `PORTHUB_TEST_SYNC_EXECUTABLE` to locate that fixture explicitly.

Before rollout, native Windows must also pass a complete isolated SCM install,
service start/stop, CLI publication and PATH check against a mock enrollment
server. Shell command smoke tests and credential-file ACL checks alone do not
prove that complete installation works. Current fixes remove the protected
Windows profile-save stub, open the PATH registry key with write access, register
PATH for private installations too, and refresh the invoking PowerShell session.
Native CLI startup and detached worker pipe-lifetime checks gate the Windows
main-stack reserve and handle-inheritance fixes.

### Tor extraction implementation status

`porthub-tor` now owns the Arti implementation. Core's `local-tor` feature keeps
its user commands, mesh policy and source watcher but links only lightweight
egress contracts/websocket support. Local Tor exits and `porthub proxy --via tor`
call the verified worker's typed bootstrap/resolve/stream contract. A configured
empty underlay remains restricted rather than enabling OS route fallback. Stream
leases retain their original pool; inactive profiles expire after five minutes.
The independent `porthub-tor proxy` command starts an authenticated localhost
HTTP/SOCKS5 proxy without core, enrollment, or a PortHub server.

Managed Tor deliberately requires persistent worker transport for now. A one-shot
CLI cannot update an already-running stream's source restrictions through its raw
stream channel. `cli` mode therefore fails explicitly for managed Tor, and auto
mode does not fall back to a fresh unrestricted process. The supervised Tor CLI
fallback remains required before final release. Ordinary sync supports CLI
fallback already. Live Tor-network bootstrap/stream verification and component
publication are also still required; current Tor tests run without Tor-network
access and cover source policy, profile lifetime and the real standalone frontend.

### Dependency-aware build receipts

`deploy/components.toml` declares separate Cargo invocations for core, sync and
Tor. `scripts/component-build-plan.py` records each target's actual Cargo dependency
tree and merged dependency file after its build. Receipts include compiled local
sources, effective inherited manifests, selected lockfile identities/edges,
relevant patch overrides, profile/compiler inputs and an immutable binary digest.
The selection phase re-hashes those recorded inputs without running Cargo or
fetching registry manifests. Unrelated agent edits, unrelated locked packages,
workspace membership and fixed helpers' unrelated core-version bumps do not
invalidate a helper. Changed helper inputs advance its independent patch version;
changed core inputs require a fresh core release version. Ambiguous versions of
an active dependency name are conservatively fingerprinted.

A reuse decision is a candidate, not authorization to publish arbitrary cached
bytes. `verify-reuse` must verify the previous binary against the receipt after
its official archive/provenance has been verified. `build` invokes the selected package/profile directly and captures Cargo's
reported executable and merged dependency file. It requires a clean checkout of
the stated immutable source before and after compilation, and checks that source
inputs are tracked. Generated outputs under `target` are excluded;
their source/build-script inputs and explicitly declared external build recipes
must be included. Native compiler/linker flags must be consistent between the
selection and build phases. The build planner is tested on native platforms;
release workflow selection, archive repacking and publication integration remain
required before the agent release. Terminal/stats recipes will be added with their
extracted packages.

The build-selection tests now pass on Linux, macOS, Windows x64 and Windows ARM64.
A real optimized sync build produced a receipt with 38 local inputs and 176 active
dependencies; the next plan selected reuse and verified the executable digest
without Cargo. The contract workflow now distinguishes script-only changes from
native Rust inputs, while conservatively testing all Rust inputs when the prior
revision cannot be inspected. This conditional workflow change is awaiting its
native run. Stable server image/environment promotion must also be automated in
the upgrade tool before the next gateway rollout.

### Shared compact manifest reader

The shared `porthub-components.json` document can now use schema 2, containing
`repository`, `release`, exactly ten `core_assets` (`target`, `asset`,
`executable: {size, sha256}`), and a nested schema-1 `components` catalog. Core
asset names are fixed for their platforms; the nested catalog must have the same
repository and release. The existing schema-1 tool-only document remains readable
by the component manager.

The gateway's release reader accepts both existing GitHub releases with version
and checksum sidecars and compact releases whose core metadata is in that shared
document. It verifies the document against GitHub's asset digest and size, then
checks every core asset against GitHub metadata. A malformed compact document
cannot fall back to ignoring the document. Previously accepted component metadata
cannot be discarded or changed incompatibly by a later release. The persistent
index retains validated tool metadata for subsequent delivery work.

The reader still generates the existing local core sidecars, preserving the
current OTA and bootstrap download contracts. Component delivery routes now serve the verified tool-only catalog and
individual executables. Compact publication and deployment of this reader remain pending; the current production release continues using the original format.


The gateway exposes public `GET /api/downloads/components/catalog` and
`GET /api/downloads/components/{component}/{version}/{target}/{sha256}` routes,
matching the core manager's URL contract. The latter accepts only exact entries
from the verified catalog. It fetches the declared GitHub platform archive,
verifies its size/hash, rejects unlisted or unsafe archive members, and verifies
the selected executable before atomic publication. Concurrent requests share
one extraction. Cached binaries are checked again before serving and repaired
when damaged; transfers retain their open descriptor. Responses provide an
immutable hash ETag and exact length. These are public software artifacts and
carry no enrollment credentials. Existing legacy-only releases report component
metadata unavailable, allowing the manager's configured fallback behavior.


Gateway platform archives are cached by SHA-256 alongside extracted tools. Each
reuse rechecks the archive size/hash. The archive is published only after safe
extraction and the requested executable's hash check succeed. Multiple tools
from the same platform archive therefore share one upstream download; a missing
or damaged executable can be restored from the cached archive even when GitHub
is unavailable. Damaged archives are replaced only by verified downloads.


### Compact packaging implementation

`scripts/package-components.py` takes repeated `--input RECEIPT BINARY` pairs,
a coherent `--release`, and a new `--output` directory. Each receipt and executable
are verified using the build planner before packaging. The default requires all
ten core targets from one source revision and a tool archive for each. Linux
inputs must use the musl build triples; catalog names retain the established GNU
platform identifiers. `--verify-only` permits unpublished platform-subset fixtures.

Archives use fixed gzip/tar metadata, regular files, stable member ordering,
versioned tool paths, and protocol size limits. Packaged bytes are checked again
before atomic publication of the directory. Older compatible helper receipts can
be included alongside new ones: their executable hashes, original source revisions,
build fingerprints, compatibility requirements, and protocol lists stay intact,
while the new archive is carried by the current coherent release. Thus release
retention need not remove the only download location of an older compatible tool.

The ten-platform fixture produces exactly 21 files. This packager is not yet
wired into production build selection/publication; legacy release verification
and the publication workflow must be adapted before switching formats. Real
platform executable/ABI checks remain required in addition to packaging tests.


The existing offline `porthub-api --check-artifacts DIRECTORY VERSION` verifier
now accepts either the legacy 30-file release or the compact 21-file release.
For compact releases it validates the shared Rust manifest contracts, every core
hash, all declared tool archives and extracted executable hashes, safe members,
and the exact asset set. Retained helpers must be repacked into this release's
archives. The check needs no database, gateway, credentials, or tool execution.
A Rust integration test consumes the Python packager's full ten-platform fixture
and rejects wrong versions, damaged core/archive bytes, and unexpected files.
This validates distribution integrity; native executable/ABI checks remain
separate release gates. Packaging sets explicit permissions independent of umask.


### Compact publication guard

The publisher accepts compact packages only with an explicit absolute
`--artifact-verifier /path/to/porthub-api` and
`--compact-gateway https://gateway.example`. It invokes the Rust offline verifier
and hashes all 21 files before and after verification. Missing verification,
changed inputs, or failed checks abort before GitHub mutations.

The gateway exposes `GET /api/downloads/components/capabilities` independently
of whichever client release is currently latest. The publisher requires schema 2,
component protocol 1, and core-sidecar compatibility over verified HTTPS, with a
bounded response, no redirects, and no credentials or TLS/proxy bypasses. It
checks again immediately before promoting the uploaded draft. This permits the
new gateway reader to be deployed while the old client release is still current,
and prevents switching formats before that deployment. The existing legacy
publication path remains available. The build workflow still needs to supply
these arguments and assemble the verified compact inputs; no compact release has
been published by this change.

Standalone private-network enrollments start optional-tool maintenance after the
first authenticated policy has been applied and the network device is ready.
Embedded private networking shares its parent registration's maintenance worker.
Neither path awaits downloads during forwarding startup. The standalone worker
uses the private enrollment's gateway and lifetime cancellation token; shutdown
cancels and drops it with the private runtime. Failure to initialize optional
maintenance leaves private forwarding running and emits a credential-free warning.
This hook has compile and maintenance-lifetime regression coverage; a live
private-only installed-agent prefetch check remains part of rollout verification.

### Proxy-aware outbound selection prerequisite

The agent now provides `outbound::http_connection_target` using the same
hyper-util proxy matcher as reqwest, with system-proxy support enabled. It returns
the actual socket host/port: the proxy when intercepted, or the origin when
`NO_PROXY` applies. Proxy credentials are never part of the returned authority.
Direct IPv6 authorities are normalized for socket resolution. A redirect must
invoke this decision again because the new host can have different proxy rules.
Tests cover credential-bearing proxies, bypass rules, IPv6, and GitHub-to-asset
redirect authorities. The component HTTP transport now calls this selector through the core-owned
routing adapter described below. Live multi-address and VPN behavior still need
installed-agent verification.


Component download routing is supplied by the core through the lightweight
`Routing` interface. It resolves the actual proxy/origin socket authority, performs
bounded DNS and policy-aware route discovery, and binds the client to a permitted
source (and its interface on macOS). IPv4/IPv6 candidates use the existing sticky
selection and failure cooldown logic. Each new request rechecks system proxy
configuration and routes, without changing host routes, firewall rules, or DNS.
Explicit system mode delegates sockets to the operating system; explicit source
and interface preferences remain enforced. Ordinary local gateways can use
loopback in automatic mode.

The HTTP transport retries at most eight source attempts before response headers.
It reports failed connections and interrupted bodies to the selector. Access
denials stop immediately. GitHub redirects are followed explicitly, at most four
times and only to the existing official HTTPS host allowlist; each hop obtains a
fresh route. Gateway redirects remain refused. TLS verification and configured
system proxies remain enabled. The adapter sends no enrollment credentials.
The full component suite and agent compile check cover this integration, including
a real local HTTP test with a failing bound source, successful alternative,
access denial, and denied routing policy. Live multi-interface/VPN/TLS recovery
checks remain rollout gates.

Managed worker sessions now pin an artifact for a consumer's lifetime. Creation
completes a version handshake before the session is retained, with the same
activation-qualified compatible fallback used for startup recovery. Reconnecting
an existing session preserves its version even after the catalog advances. A new
worker process rechecks executable integrity before spawning; an already connected
verified worker does not require repeatedly hashing the executable.

Tor's readiness monitor, bootstrap, resolver, source updates, and new streams now
share one such session. This prevents readiness from an older pool being applied
to a newly downloaded, unbootstrapped worker. The sync process fixture verifies
stable worker identity across a catalog update and session recovery after a failed
candidate. Automatic Tor candidate bootstrap-and-switch, retained-stream source
updates during that transition, version-specific state directories, and supervised
persistent CLI fallback are still required. Prefetch updates files in the
background; this change does not yet hot-activate a new Tor worker version.
