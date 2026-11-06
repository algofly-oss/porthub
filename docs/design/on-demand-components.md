# Independently usable PortHub components

Status: implementation in progress; the modular agent is not released. Production
serves agent 1.10.1. The gateway/UI reader for compact components is deployed at
1.11.0, but optional component assets and the new agent have not been published.

The component SDK implements compatibility selection, verified gateway/GitHub
downloads, private/shared caches, versioned RPC and CLI pipe transports,
activation receipts, and background maintenance. Core delegates sync/watch,
live stats, Tor, terminal runtime provisioning, workspace creation, and owner
attachment UI and sharing supervision. The terminal helper supports independent `new`, `attach`, `tmux`
and `runtime` commands. Terminal execution is delegated to the helper; full-platform and installed
rollout validation remain pending. Live managed Tor generation handover has
passed through both RPC and CLI pipe transports; final platform checks, compact
publication, and installed rollout verification remain pending.
Background maintenance begins after authenticated configuration; core also
exposes `components list`, `fetch`, and `update`.

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
individual executables. This reader is deployed in gateway 1.11.0; compact agent
publication remains pending, so the current published agent release continues
using the original format.


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
updates during that transition and supervised persistent CLI fallback are still
required. Version-specific worker state directories are implemented below. Prefetch updates files in the
background; this change does not yet hot-activate a new Tor worker version.

Tor RPC workers place Arti state/cache under a directory specific to the immutable
tool version, circuit group count, connection limit, and restricted/system routing
mode. Different versions or pool configurations can therefore prepare alongside
an older pool without selecting its Arti lock directory. Updating the allowed
source addresses, including revoking all addresses, retains the same pool and
storage identity. Standalone `proxy --directory` behavior remains explicit to that
standalone command. Unit checks cover namespace separation, unchanged source
update identity, source revocation, leased pool retention, and invalid requests;
live simultaneous Arti bootstrap and version handover remain rollout gates.

### Independent stats dashboard frontend

`porthub-stats` is a fixed-version helper crate with no dependency on the agent,
server, or gateway. It contains the interactive renderer, rate baseline logic,
pause/sort/selection controls, and bounded asynchronous collection interface.
`porthub-console` provides shared terminal restoration and cancellable input;
the core currently reuses that small library for its remaining terminal flows.

Standalone examples:

```sh
porthub-stats --pid 1234
porthub-stats --once --json
porthub-stats --input snapshot.json
```

Without an input file the tool samples local processes, bounded to 128 rows by
memory use. Snapshot files use `{"agents":[...]}`, with unique bounded registration
identities, at most 128 rows and 32 KiB per row. They can be refreshed atomically
by another project. The frontend has no authority to query enrolled agents.

The core's authenticated stats broker and basic status remain in core.
`porthub stats` now delegates to this frontend through typed private IPC; the
duplicated renderer, rate baseline, and interactive loop have been removed from
core. The helper is in the component build recipe and native contract test
matrix; it has not been released or deployed.


The managed dashboard runs as a verified foreground executable with inherited
terminal handles. Core creates an invocation-specific, account-protected local
endpoint and serves only `Collect` for the command's selected registrations.
The helper validates the component/protocol/version handshake, receives a bounded
row count, and reads individually framed rows (at most 48 KiB each, 128 rows).
Aggregate snapshots can exceed the 64 KiB frame limit without truncation. No
machine tokens, profile contents, or arbitrary broker operations are supplied to
the helper. Core retains the existing authenticated whitelist collector.

Core owns terminal-mode restoration while the helper controls rendering and input.
It cancels the invocation broker and owns the child lifetime, including failed
startup and cancellation. The scoped broker stays available during long pauses;
general idle workers still self-exit normally. Independent invocation retains its
own terminal guard and local process/file providers. Integration tests cover the
standalone provider, private managed snapshot streaming beyond one frame, and the
core broker's exclusion of credentials. Live installed CLI/TTY checks remain
required before rollout. A file-input fallback exists for standalone use; automatic
managed handoff fallback when local IPC is unavailable remains unimplemented.

### Independent terminal runtime component

`porthub-terminal-cli` builds the `porthub-terminal` executable independently of
core. It owns a terminal bundle build script, the verified runtime installer,
versioned `Install` IPC operation, persistent worker, and private stdio frontend.
It has no agent or gateway dependency. Linux/macOS release builds require the
existing checksum-pinned C runtime bundle; Windows hosting remains unsupported
and uses WSL. Development builds can expose help/contracts without embedding it.

Standalone use forwards normal tmux commands to the bundled runtime, for example:

```sh
porthub-terminal tmux -- new-session -s work
porthub-terminal tmux -- list-sessions
porthub-terminal tmux -- attach-session -t work
```

`--directory` selects a private runtime cache. The tool sets its bundled terminfo
and invokes the executable directly; projects can use it without PortHub core or
a gateway. A real bundled Linux test creates/lists an isolated workspace using
its own socket and removes only that test server. Debug native contract runs
without a bundle test help and invalid-directory handling; bundled workspace
coverage requires the release/native build environment.

Core now delegates runtime installation to this component through typed IPC,
with the verified CLI transport available as startup fallback. The embedded bundle
and its build-script requirement have been removed from core, and core's build
recipe no longer includes the C helper build inputs. Workspace preparation happens
outside the workspace lock and is rechecked under the lock before creation.
Opening a live workspace uses its existing recorded runtime without initializing
or fetching a component. The remaining workspace/sharing implementation is still
linked into core and must move behind the scoped broker before full extraction.
These changes have not been released or deployed.


Native agent checks build terminal and stats fixtures in separate Cargo invocations
and seed an isolated cache with their exact executable hashes. The fixture catalog
is test-only and cannot be used as publication provenance. Normal users do not
need to seed caches or invoke helpers. Local Linux verification with this setup
passed the real core workspace lifecycle (including reattach with an unavailable
component source), the sharing supervisor/sidebar integration, and the delegated
stats PTY suite (restoration, pause/resume, resize, sorting, JSON, and prompt quit
with a stalled source). Native CI and production canary checks remain required.


Release staging now accepts both the existing 30-file bundle and the compact
21-file bundle. It still requires a successful original ten-platform CI run and
complete release gate, verifies the outer GitHub artifact size/digest, rejects
unexpected/duplicate/traversal/link entries, and applies per-file plus aggregate
expansion limits. Compact staging requires the explicit trusted Rust artifact
verifier before creating the destination. Extracted bytes are verified using the
publisher's immutable snapshot checks. Promotion workflows still need to supply
the verifier and gateway arguments when compact production assembly is enabled;
this does not yet switch publication format.


Pinned sessions expose `newer()` to prepare a compatible candidate without changing
the active consumer. Unchanged catalogs do not start a candidate; unsuccessful
startup recovery cannot accidentally replace the active session with an older
artifact. A process-level test builds actual 0.1.0 and 0.1.1 sync helpers, keeps a
foreground watch stream active, prepares the newer worker, verifies distinct
worker identities, and confirms the old stream continues transferring changes.
Native component checks run this test on their supported runner platforms.
Application-specific Tor bootstrap, source-update leases, and atomic handover
still need to use this API before automatic runtime activation is complete.

Publication rejects legacy-only bundles for version 1.11.0 and later, the first
modular core release. This prevents the old assembly workflow from publishing a
core that requires helpers while omitting its catalog and archives. The compact
assembly workflow must be finished and the compatible gateway deployed before
these releases can pass publication. Earlier complete legacy releases remain
supported for verification and recovery.

Tor readiness, bootstrap, new connections and resolution now require a live,
nonempty allowed-source authority even when Arti already has cached clients or
circuits. In-flight operations observe source revocation and cancel; a closed
source authority fails closed. Revocation puts cached clients into soft dormancy
and prevents a warm client from bypassing the source check through circuit reuse.
The managed core adapter checks its authority before provisioning/requests and
again before exposing asynchronous results. On monitor exit it makes a bounded,
best-effort revocation request through an existing connection and never starts a
new worker for cleanup.

Local offline checks passed for operation cancellation, closed/empty authority,
no unauthorized bootstrap/state writes, and worker profile/source lifecycle. The
opt-in live library test also passed: real Tor bootstrap, verified HTTPS to the
Tor Project identifying a Tor exit, then immediate rejection of new connections
and DNS after revoking the warm client's sources. This does not prove module
hot-handover or managed fallback; those remain pending.

The full ten-platform native agent run at source `cacab4d` passed:
https://github.com/algofly-oss/porthub/actions/runs/42106863593 . It verifies the
runtime extraction, independent fixtures, existing installer/connectivity gates,
and Unix CLI/PTY integration at that source. Subsequent routing, candidate-session,
publication and source-revocation changes require updated native validation.

The shared release manifest separates the GitHub release carrier (`release`) from
the executable core version (`core_version`, defaulting to `release` for older
manifests). A helper-only release may reuse all ten unchanged core executables.
The gateway reports the executable core version to OTA clients and generates
matching `.version` sidecars, while downloads and cache pruning use the carrier
release. It rejects core downgrades and changed executable bytes under the same
core version. Helper versions use their own independent semantic version domain.
Publication requires the gateway capability `independent_core_version: true`.
Build selection and receipt reuse must preserve these identities before this
format is published; this metadata support alone does not enable production reuse.

Each platform archive retains `.porthub-build-receipts.json`, a deterministic
schema-1 envelope containing the original core receipt and each packaged helper
receipt. This preserves input hashes and executable provenance beyond CI artifact
retention without adding release-page assets. The envelope is limited to 8 MiB;
it counts toward the 128-member and 1-GiB expanded archive limits. Runtime
extraction permits only this exact metadata name alongside catalog-authorized
executables and discards the metadata without writing it to the cache. Future CI
reuse must validate receipt checksums, current inputs, and binary hashes again;
an archived receipt alone does not authorize reuse.

`scripts/recover-component-builds.py --input RELEASE_DIR --output NEW_DIR
--target RUST_TARGET --release CARRIER --artifact-verifier /absolute/porthub-api`
recovers platform build inputs from a locally staged full compact release. It
first invokes the trusted Rust verifier through the publisher's immutable-file
checks. It then validates receipt checksums, platform, optimized executable names,
core version, helper provenance, and executable hashes against the shared manifest.
Recovered files appear atomically with an `index.json`; errors leave no output.
The index paths are relative to the recovery directory and may be passed to the
build planner and packager. Recovery verifies the previous build, not that its
inputs match current source: `component-build-plan.py plan` must still make that
decision. Legacy releases without archived receipts require fresh builds.

`scripts/build-component-platform.py --target TARGET --source-revision SHA
--previous RECOVERED_DIR` reports a plan for all configured tools without compiling.
Adding `--output NEW_DIR` executes that plan, one Cargo invocation per changed
tool, and atomically publishes verified binaries, receipts, and a relative-path
index. `--tool TOOL` may be repeated to select a subset. Reused binaries are
checked before selection and after copying. Changed core inputs still require a
new committed core package version; helper versions advance independently.
Older verified helper versions are retained for compatible consumers and startup
fallback. The coordinator does not itself download releases or mutate versions.
Production workflow integration and independent core version preparation remain
required before release publication.

Compact assembly accepts repeated `--build-index PLATFORM_BUILD_DIR` arguments,
so the coordinator's output can feed the packager without constructing long
receipt/binary argument lists. Index loading verifies relative paths, target,
receipt identity, and binary contents again. Production packaging and the Rust
offline verifier require all four optional tool families on all ten platforms;
`--verify-only` permits incomplete, unpublished fixtures only. The public release
still consists of ten core binaries, ten platform tool archives, and one manifest.

Core executable versioning is independent of the workspace/server release. The
agent manifest now records its own version. During release preparation, repeated
`--previous-core-build PLATFORM_BUILD_DIR` options supply recovered, verified
build inputs for all ten platforms. If all core fingerprints remain unchanged,
the core version stays fixed while the server/carrier advances. Missing proof
forces a conservative core patch increment; incomplete or corrupt supplied proof
fails preparation. A changed platform also forces a new core version. Manifest
and lockfile changes are validated together and committed before builds; explicit
tags must already contain the required core version. The production workflow
still needs to fetch verified prior-release inputs and pass these options before
it can benefit from core reuse automatically.

Continuous release preparation now inspects the published release format. For a
compact release, it builds a trusted Rust verifier from the checked-out source,
then runs `fetch-component-release.py` to stage exactly 21 expected assets from
the official immutable GitHub URLs. Downloads honor system proxies and verified
TLS, restrict redirect hosts, and enforce per-file size, SHA-256, and deadline
bounds. The complete staged release must pass Rust verification before it becomes
visible. `--recover-output` atomically recovers all ten platform build indexes;
release preparation consumes those indexes as core reuse proof automatically.
A complete legacy release authorizes no reuse and causes fresh builds; malformed
compact metadata or failed verification stops preparation. The build/publish jobs
still require their separate compact coordinator integration.

Core version reservations also survive failed drafts: release preparation reads
the immutable source of stable release reservations and skips core versions used
by different source, even when their carrier tags differ. Exact-source draft
retries may retain their version. Reuse of a published core version is permitted
only with the complete unchanged-input proof described above. Unreadable or
ambiguous reserved source fails before changing manifests.

Normal client publication and verified-run promotion now build the trusted
`porthub-api` artifact verifier from the checked-out source and pass its absolute
path to compact staging/publication. Both publication paths require the gateway
capability check, using repository variable `PORTHUB_RELEASE_GATEWAY` or
`https://porthub.algofly.in` by default. This verifies TLS and independent core
version support before release writes and again before draft promotion. These
workflow guards do not enable compact production builds by themselves; the
platform build and release-bundle producer integration is still pending.

The agent workflow's complete-bundle job now runs
`assemble-client-release.py` on the downloaded platform artifacts, builds the
trusted Rust verifier, and uploads only the verified assembled release. Assembly
requires ten indexed platforms for modular releases, rejects mixed legacy/indexed
inputs, and publishes its output directory atomically after verification. Legacy
collection remains available only for releases before 1.11.0. A ten-platform
assembly fixture passes the actual Rust verifier with exactly 21 output assets.
Native and cross-compilation jobs still need to emit the coordinator indexes;
the bundle gate deliberately rejects their old legacy-only modular outputs.

Native macOS and Windows production builds now invoke the component coordinator
for core and all four optional tools, in separate optimized Cargo invocations.
They upload the indexed binaries and original receipts rather than legacy flat
core files. Packaged lifecycle checks use a fresh private fixture cache seeded
from those exact packaged helpers, with shared-cache reuse disabled; packaged
core startup is checked explicitly too. Linux production job conversion and
prior-build input delivery to native jobs remain pending, so full publication
continues to be blocked until every platform emits the required indexes.

Native Linux x64 and ARM64 production jobs now emit coordinator indexes too.
They build all five Rust executables for musl, provision the terminal bundle with
that exact shipping target, and maintain a separate shipping-runtime cache.
`verify-static-components.py` verifies indexed binary checksums, requires a musl
target, and rejects ELF interpreter or shared-library dependencies for every
packaged version. Exact packaged helper fixtures and core startup checks then
run on the native host. Local verifier tests compile static/dynamic ELF examples
and reject invalid payloads. Three 32-bit Linux production jobs still need their
musl toolchain conversion before complete release publication can proceed.

The three 32-bit Linux production jobs now build shipping-target musl terminal
runtimes and use their pinned private musl compiler wrappers for separate Cargo
component builds. Indexed executables must pass static ELF verification. ARM
smoke checks run through the disposable runner's binfmt/QEMU setup; all packaged
helpers seed the private check cache before exercising core terminal commands.
The production artifact upload is the indexed component directory for every
platform. Actual cross-platform build/run verification remains required.

Generated terminal bundles are recorded as bounded, SHA-256-identified derived
inputs alongside the tracked C builder and pinned source list. Only the exact
configured bundle is excluded from Cargo's source depfile list; other untracked
inputs remain subject to the existing rejection. Changed bundle bytes invalidate
helper reuse, and changes during compilation fail receipt creation. This avoids
mistaking `.cache/terminal-helper/.../bundle.tar.gz` for a tracked source file.

Continuous release preparation retains each verified recovered platform as a
one-day CI artifact named `component-reuse-PLATFORM` (these are not GitHub release
assets). The reusable agent workflow restores only its platform's inputs and
passes them to the coordinator for native and cross builds. Missing requested
artifacts fail the workflow; corrupt binaries fail receipt verification before
reuse. Initial legacy-to-compact builds run without previous inputs. The
complete-bundle download pattern excludes these prior-build artifacts.

Offline compact verification now also requires a core-compatible, protocol-1
version of every required helper on every platform, allowing older retained
versions to coexist. Merely including all component names cannot authorize a
release whose core cannot use them. Fixture checks reject incompatible core
requirements and unsupported helper protocols before publication.

`deploy/component-platforms.toml` declares shipping compiler settings for all ten
targets. Release preparation compares prior core receipts using those target
settings, rather than its Linux host environment. Actual shipping builds require
their compiler environment to match the declaration before invoking Cargo.
Unexpected flags or compiler wrappers fail without logging their values. Changes
to a target's declared settings invalidate that target's build proof. Terminal
compiler cache paths use a portable placeholder; their target/source identity
still matches the actual pinned C builder cache key. Empty flag variables are
normalized as unset. Local targets outside this shipping catalog retain normal
recorded-environment planning. Real multi-platform build verification of this
recipe remains required before publication.

Whole-platform CI reuse fingerprints now include the component recipes and
coordinator/check scripts, preventing reuse across changed packaging/compiler
policies. Component-level reuse still uses each tool's actual compiled inputs.

Managed Tor worker profiles now require continuing source authorization. Any
validated managed operation renews a monotonic 30-second lease; core already sends
`Ready` heartbeats every two seconds. A weak supervisor checks the lease every two
seconds. If control traffic stops, it clears the permitted sources and requests
soft dormancy, without terminating existing stream objects. Expired profiles
reject subsequent connection and DNS work through the existing underlay guard.
Explicit empty source updates request dormancy immediately. A later authorized
operation may renew sources but cannot bootstrap Tor merely by reconfiguring it.
Standalone profiles with OS routing (`sources: None`) are unaffected. The
supervisor does not keep a discarded profile alive. Paused-clock tests exercise
expiry, renewal, and denial of post-expiry operations; standalone CLI/pipe checks
still pass. Generation handover and persistent CLI fallback remain unfinished.

Embedded terminal runtime manifests now use the exact Rust build target. Linux
musl-to-GNU aliases remain a catalog naming convention and are not applied to
private runtime manifests. The terminal build script checks the bounded archive's
manifest target before embedding it, so an ABI label mismatch fails during build
instead of after installation. Tests reject catalog-alias substitutions and
malformed/oversized manifests; the independent CLI still creates and lists an
isolated real tmux workspace. Cargo receipt capture now includes local build-script
depfiles too, ensuring changes in imported build support modules invalidate reuse.

The managed stats frontend now honors `PORTHUB_COMPONENT_TRANSPORT=auto|rpc|cli`.
Core binds its reverse broker before launching the helper. Auto uses a private
snapshot file if binding fails before admission; rpc fails without switching;
cli uses the file handoff directly. Collection stays in core with the same
registration scope. Only bounded snapshot data and a private temporary path cross
the handoff, never enrollment credentials. The invocation directory is explicitly
private on Unix and protected with the native Windows DACL. Snapshot writes are
atomic, limited to 128 rows with the RPC row bound, and owned by the invocation.
The frontend waits for the first capture asynchronously and consumes each sequence
once, avoiding false zero-rate samples when a capture has not advanced. Core owns
terminal restoration in both modes. Standalone `--input` retains its existing
smaller bound and works independently. Live PTY checks pass in rpc and cli modes;
a process-local bind-denial test proves auto fallback without changing host policy.

Gateway core 1.11.0 is consumed by deployed source
`63e4afce3efb5cfe8fec28db1035b5bc944f73a8`. The next server/carrier version is
1.11.1; the unreleased core agent remains independently versioned 1.11.0. This
avoids reusing an immutable server image version while client implementation
continues. Production's raw agent endpoint still serves 1.10.1 until publication.

Managed Tor now checks for a newer compatible worker every 60 seconds after a
session exists. It stages the candidate separately, supplies current permitted
sources, and bootstraps it before atomically selecting it for new operations.
A routing-policy change interrupts candidate preparation. Failed preparation
retains the active generation and best-effort revokes the candidate's sources.
All current, preparing, and stream-leased retiring generations receive source
heartbeats; routing changes cancel the previous heartbeat batch. Each returned
stream retains its generation until drop. Maintenance keeps only weak references
to retired generations, so it stops renewing their authorization after their last
operation/stream closes. The worker's existing 30-second source authorization
expiry remains the fallback when the core or its cleanup connection disappears.
At most 16 generations may be maintained concurrently; further updates wait for
old streams to close. Cleanup uses an existing-worker-only connection and cannot
start another helper merely to revoke it.

Four core adapter tests pass, including duplex stream I/O after generation
promotion, release of the retired generation after stream drop, rejected-candidate
isolation, generation bounds, and empty/closed routing authority. These tests
verify adapter lifetime behavior; an actual managed Tor worker upgrade with live
network traffic is still required before release. Persistent Tor CLI fallback
and full terminal implementation extraction remain outstanding.

A persistent CLI carrier is now implemented in the component SDK and exposed by
Tor's hidden `__porthub-multiplex` entry point. It runs the existing typed RPC
handshake and explicit stream upgrades on independent HTTP/2 channels over one
inherited stdin/stdout pair. It opens no socket or network listener and carries
no machine credentials in argv. Each channel has a 64 KiB receive window, with
bounded aggregate connection capacity so a backpressured stream cannot consume
the control channel's flow capacity. There are at most 128 concurrent channels;
headers and send buffers are bounded. Upgraded streams retain the carrier driver
until they close. Carrier failure fails outstanding operations; the transport
never retries a dispatched request.

Four SDK transport tests pass, covering shared handler state, a 2 MiB stream,
control access while another stream is unread, interrupted-request isolation,
and retention after the original carrier owner drops. Both real Tor standalone
process tests pass, including two channels reporting the same helper PID,
configure/ready through different channels, and process exit when inherited pipes
close. They use empty authorized sources and require no network, enrollment,
core executable, or gateway. The core session manager still needs to select and
supervise this carrier for persistent automatic/forced CLI fallback; the new
helper entry point alone does not complete that requirement.

Core-managed Tor sessions now select the persistent pipe carrier. With
`PORTHUB_COMPONENT_TRANSPORT=auto`, local RPC is attempted first; startup failure
can select the verified multiplexed CLI before any Tor operation is dispatched.
`rpc` forbids this fallback, while `cli` selects pipes directly. The selected
transport stays fixed for that session; candidate generations inherit the
administrator's selection policy. Session clones coalesce pipe startup and share
one child. Existing streams retain that child through their carrier leases.
A channel admission failure on a healthy carrier never replaces its process or
splits its live pool. A terminated carrier may reconnect before a new operation,
with in-memory retry delays and private, locked startup-failure records persisting
across new session objects. Delays are bounded at 300 seconds. Each new spawn
rechecks the verified executable hash. Cleanup only opens an existing carrier or
local worker and never launches a replacement for revocation.

All six real Tor standalone/process tests pass on native Linux, including 16
concurrent managed connections sharing one PID, safe reconnection after explicit
worker shutdown, automatic fallback after fixture-injected worker startup
failure, forced-RPC refusal to fall back, and failed-start backoff surviving
fresh sessions. The full component SDK test suite and the core compile check
also pass. These process tests use empty authorized sources and do not establish
Tor circuits. Live managed network traffic, generation handover with active Tor
streams, and platform validation remain required; full terminal extraction is
also still pending.

Local workspace creation and its registry write have moved into the terminal
component. Core sends a typed `Create` request with explicit cwd, shell, command,
overrides and the invoking process's native environment. The helper starts tmux
with that environment after removing inherited tmux attachment markers; an
already-running helper cannot substitute its earlier caller's environment. The
registry lock covers selecting/reopening a name, archiving ended identities and
creating the replacement. Active workspaces keep their recorded verified runtime
paths. Core still owns command parsing and presentation during this extraction.

The independent helper also exposes `porthub-terminal new --directory PATH`,
with name/cwd/shell/env/prefix/history/mouse options and literal command argv.
It creates persistent workspaces and prints their registry record without core,
enrollment or a gateway. Three bundled-runtime standalone process tests pass,
including multiple workspace creation in one directory with different caller
environments. The new `test-terminal-workspace-helper.py` passes against the
rebuilt core and seeded helper: both cwd/environment snapshots survive reuse,
and six concurrent reopen calls retain the original identity. Native and packaged
Unix platform jobs now run this check. Sharing supervision, attachment UI and
native guest/direct transport are still in core and must finish moving before
the terminal extraction is complete.


Owner attachment, participant popup and sidebar implementations now reside in
the terminal helper; their previous core source files have been removed. Core
resolves the verified helper and launches its foreground `attach` or hidden owner
view command with inherited terminal handles. Workspace directory, identity and
sidebar selection are the only arguments; no invitations, machine credentials
or gateway configuration are transferred. Helper-owned shortcuts invoke the
same content-addressed helper executable, preserving old attached workspaces
when a newer helper is downloaded. The sharing-control server remains in core
until the sharing supervisor itself is extracted.

The rebuilt core and exact seeded helper passed the complete owner PTY suite:
selection/cancel, targeted guest removal, resize, terminal restoration, quit
while the private control socket stalls, owner-only popup, nonmodal sidebar,
mouse copy, abrupt hangup, persistent shell/background state and explicit Ctrl+D
teardown. All three standalone bundled-runtime process tests also pass. Sharing
supervision, native guest/direct transport and remaining local workspace commands
still require extraction before terminal code can be excluded from core.


The sharing supervisor, attachment host, owner-control server and traffic emitter
now execute inside the terminal helper. Core keeps registration selection,
launching, invitation display and the credential-injecting local broker. Saved
shares include only a credential-free broker endpoint, expected OS owner and
capability flag. The helper rejects non-sockets and mismatched peer identities.
Old share files without that context are upgraded by the core launch wrapper;
missing display metadata disables extension advertisement but does not prevent
reconnecting to the authenticated broker. Gateway/machine credentials are never
copied into helper arguments or configuration.

Foreground launches identify their core parent. The asynchronous terminal sharing
entry point stops its supervisor when that parent disappears, preserving the
independent tmux shell. A bounded two-second lock handoff handles immediate
restarts. This was necessary because killing the launcher otherwise orphaned the
new helper and prevented the replacement from acquiring the supervisor lock.

The real sharing process/PTY test passes against the rebuilt core and exact
seeded helper, covering forced launcher death and recovery to the existing shell,
sidebar/presence controls, invitation acknowledgement/rotation/revocation and
explicit stop/end notification. Four helper unit tests and three standalone
bundled-runtime tests also pass. Native guest transport and remaining local
workspace operations still need extraction; this is not an agent release.


Native terminal guest WebSocket/recovery/TTY/direct code and its permission
subscriber now live in the terminal helper. Core retains unambiguous registration
selection and the authenticated policy server. It sends the helper a private,
owner-only request file containing the invitation and optional credential-free
broker context; invitation data is absent from internal helper argv. The helper
also exposes independent `join --transport ssh|relay|auto`; without an explicitly
supplied core policy broker, auto uses relay and cannot authorize a direct path.
Parent disappearance cancels managed asynchronous joining so its TTY guard can
restore the terminal. Invalid/public request-file tests confirm rejection without
echoing invitation contents.

The rebuilt standalone helper passed 21 library tests covering TLS/guest framing,
raw TTY input/resize/restoration, recovery without replay or offline keystrokes,
direct-to-relay fallback and permission expiry/revocation, plus four standalone
process tests. Core passed 20 terminal broker/privacy/registration tests. The new
production dependency check rejects optional worker implementations and terminal
RTC engine/media/datachannel packages in core; core's required private-network
ICE/DTLS dependencies are explicitly retained. Core alone compiles without the
terminal RTC feature linkage. Remaining local workspace operations and registry
presentation still need extraction before the terminal boundary is complete.


Remaining workspace execution now runs in the helper: list/status, stop, rename
and workspace-scoped tmux commands. Listing uses bounded 64-row pages with
creation-time/identity ordering, validates names, and omits ended workspaces
unless explicitly requested. Core keeps its existing command parsing, output,
registration selection and credential-free registry/broker metadata. The helper
exposes independent list/stop/rename/workspace-tmux commands alongside new/attach.
The shared terminal library has an explicit hosting feature; core disables it,
so portable PTYs, bundled runtime installation and local shell hosting are absent
from its production dependency graph. Other consumers retain their previous
hosting defaults. The unused core runtime wrapper was removed.

The helper passed 22 library tests, including pagination over 130 registry jobs,
rename identity, native guest recovery and privacy revocation, plus four real
standalone process tests. The rebuilt core and exact seeded helper passed caller
cwd/environment, six concurrent reopen calls, rename/tmux, ended-session history,
the full owner PTY suite and the sharing reconnect/invitation/stop suite. These
runtime suites were rerun sequentially after concurrent debug-process hashing
caused observation deadlines and a short-lived fixture shell to expire.
Progress-message decisions now inspect receipts rather than hashing helpers a
second time; actual resolution still verifies bytes. Unauthorized legacy popup
invocations fail a local lease precheck before resolving optional code, and the
helper repeats the full owner check. Release-platform checks, live managed Tor
upgrade verification and installed agent rollout remain outstanding.


Managed Tor upgrades now have an explicit opt-in live network test. It builds and
seeds two locally compiled helper versions, runs core's real periodic candidate
selection/bootstrap/handover, holds one verified HTTPS connection to the gateway
through activation, independently checks old/new Tor exits using the Tor Project
API, denies new streams and DNS after source revocation, and verifies recovery
when sources return. Both persistent CLI pipes (87.84 s) and local socket RPC
(86.23 s) passed. Tests use isolated private state and synthetic fixture catalog
provenance; those binaries/catalogs are not release assets. Normal CI skips this
network test. To run it deliberately, build distinct helper versions with
`PORTHUB_COMPONENT_VERSION`, provide their paths using
`PORTHUB_TEST_OLD_TOR_EXECUTABLE` and `PORTHUB_TEST_NEW_TOR_EXECUTABLE`, select
`PORTHUB_COMPONENT_TRANSPORT=cli` or `rpc`, and run the single ignored
`tor_component::live::managed_upgrade_preserves_old_https_connection_and_revokes_new_flows`
test with `--test-threads=1`.

The first live run exposed asynchronous readiness propagation after Arti
bootstrap. The library now explicitly wakes a cached dormant client and waits
up to 15 seconds for its published traffic readiness within the existing source
revocation guard. It still fails when readiness or source authorization is
unavailable. Regular Tor worker/process tests pass as well. The original
verification peer closes HTTP connections, so exit identification and long-lived
gateway connection continuity are checked separately. Full-platform run
42137007532 validates source 4e4991c with publishing disabled; its source predates
this readiness fix, so it cannot alone certify the final release.


Full-platform run 42137007532 exposed the same offline-workspace regression on
Linux x64/ARM64 and macOS ARM64: reopening a running saved name attempted to
provision the optional helper despite having an existing verified tmux runtime.
Core now performs a bounded read-only saved-runtime probe before provisioning.
It requires absolute paths, a private owned workspace, an owned regular executable
with no writable group/other bits, a single link, a 16 MiB limit matching runtime
extraction, and the recorded checksum. The probe sets the saved TERMINFO path.
A running name can be reused without initializing a component cache. Basic
attachment also works through the saved external runtime when the helper catalog
is absent; rich owner views still require the optional helper. No PTY hosting or
runtime bundle has been restored to core.

The original failing native lifecycle test passes locally. Extended process/PTY
checks pass for cached helper operations, offline attachment, shell input,
detach, exact terminal restoration and no cache creation with downloads
unavailable. A separate security test confirms relative, modified and writable
runtime files are rejected before execution. Core's production boundary check
continues to exclude portable-pty and terminal RTC implementation packages.
These fixes require a new platform validation run; successful older jobs do not
certify the changed source.

Windows packaging now includes a real installation gate on disposable hosted
x64 and Windows 11 ARM64 runners. It serves the actual PowerShell installer and
exact packaged core over loopback, using the existing explicit test-only HTTP
opt-in. Copied Command Prompt, PowerShell 5.1, PowerShell 7 and downloaded batch
commands must install the same enrollment without duplicates. The gate checks
an automatic LocalSystem service, authenticated control syncs reporting the
packaged version, current PowerShell session and persistent machine PATH, and
the published CLI's stop/start/restart/remove operations. It refuses existing
PortHub installations, restores machine PATH and removes only its fixture
service and newly created directories. This does not test UAC consent or
non-administrator execution. The x86 binary retains its separate startup and
ACL tests: an installer on an x64 OS selects x64, so substituting an x86 binary
in that download would not represent a real installation. Native execution of
the new lifecycle gate is still pending; syntax validation alone is insufficient.
