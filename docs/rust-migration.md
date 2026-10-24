# Native Rust migration

Resumed at the user's request. See `../RUST_MIGRATION_HANDOFF.txt` for the pause
snapshot; current verification and implementation may be newer.

This migration is in progress. Production still runs the existing Go server
and agents. Do not deploy the Rust binaries until the parity and rollout gates
below pass. The user authorized committing, pushing and deploying the completed
migration, including agent upgrades; unrelated URM2 services must remain intact.
The user has now renewed permission to deploy on URM2 after resuming this work.
Deployment remains gated on verification of the completed native replacement.
The user subsequently authorized testing, committing, pushing and deploying,
followed by Luna–Condor and Luna–Miro verification. Keep URM2 changes confined
to PortHub. Native file serving and segmented/resumable downloads must be part
of the agent binary, with no apt/lighttpd/aria2c runtime dependency.

## Current rollout gates

Local native implementation and test milestones below do not establish a
completed migration. Public tunnel endpoint recovery now runs in a scheduled
worker, and endpoint changes retain TCP streams while preserving revocation
across generations; see `native-agent.md` for timing and UDP limitations.
The remaining end-state checks include:

- Legacy Go/shell automatic updater migration to the native lifecycle.
- Complete Windows/macOS service, credential, interface and DNS lifecycle, with
  verified artifacts for the supported operating systems and architectures.
- Private route bandwidth/latency decisions, network-change and credential
  refresh behavior, and discovery scaling beyond the current proactive peer cap.
- Gateway cutover with existing data, identities, certificates and firewall
  policies preserved; unrelated URM2 services must remain untouched.
- Upgrade and route checks for every enabled registered client, including the
  machines whose current SSH access is unavailable.
- Actual 10 GiB Luna–Condor public/private transfers and Luna–Miro LAN route
  evidence, sustained rates and integrity checks.
- Final source cleanup, commit/push and verification of the deployed release.

Production cutover, client upgrades and these physical benchmarks remain
pending. Earlier numbered test reports are historical evidence for their stated
scope, not claims that these rollout gates passed.

The public failover milestone passes 218 workspace tests with integration
opt-ins and no ignored tests, Clippy with warnings denied, and 23 disposable
production-image checks. Exact source and image identities and the limits of
that verification are recorded in
[`verification/2026-10-24-public-failover.json`](verification/2026-10-24-public-failover.json).

Native updates now include authenticated release preparation and an explicit
Linux `porthub update` command. Its independent systemd worker preserves the
installed state in a private receipt, checks readiness before CLI publication,
and restores the prior state on failure. Local user-service checks cover an
unchanged binary, a distinct version/PID, explicit rollback and rejected-version
readiness failure. The latest regression passes 229 tests with integration
opt-ins and no ignored tests, Clippy with warnings denied, and 23 rebuilt image
checks. This manual-update milestone preceded API-request handling below.
Scope and limitations are in
[`verification/2026-10-24-update-activation.json`](verification/2026-10-24-update-activation.json).

Installed Linux agents now handle API-requested updates in a dormant background
controller and acknowledge only matching committed receipts. The native API/Mongo
test observes the new process version before acknowledgement and verifies the
request target clears after commit. Foreign identity, deduplicated preparation
and rejected-version rollback are exercised with actual disposable user
services. Legacy updater migration, platform lifecycle, private-route work and
all production/fleet/performance rollout gates above remain.
The final run passes 233 workspace tests with integration opt-ins and no ignored
tests, Clippy with warnings denied, and 23 rebuilt production-image checks. See
[`verification/2026-10-24-native-auto-update.json`](verification/2026-10-24-native-auto-update.json)
for exact scope, source/image identities and recovery limits.

## Source layout

- `crates/porthub-api`: native HTTP API, MongoDB access and account sessions.
- `crates/porthub-agent`: the installed `porthub` executable.
- `crates/porthub-identity`: shared certificate-key identity verification.
- `crates/porthub-mesh`: native ICE, DTLS, STUN and TURN peer transports.
- `crates/porthub-edge`: public HTTP ingress and service listeners.
- `crates/porthub-tunnel`: integration of Rathole with PortHub's shared listener.
- `crates/porthub-transfer`: native HTTP file serving, managed instances and downloads.
- `crates/porthub-runtime`: supervision, IPC, streaming proxy and static UI support.
- `crates/porthub-firewall`: isolated netlink rules and persistent traffic accounting.
- `vendor/rathole`: pinned upstream source and license; local changes are listed
  in `vendor/rathole/PORTHUB.md`.

Use the root Cargo workspace and lockfile. Do not add an alternative backend
inside the UI, shell wrappers, or protocol adapters. Go code remains the behavior
reference during translation and must be removed when the native replacements
cover it; it is not the intended final runtime.

## Implemented and checked so far

- Rathole client linked into the Rust agent, not launched as a subprocess.
- The agent's file-based tunnel command now uses `EmbeddedClient` directly with
  a bounded filesystem event channel and directory watches for atomic saves.
  No timer scans files while idle. Invalid edits preserve current services;
  unchanged services survive reloads. Native tests verify removal, transport
  validation before replacement, drop/explicit shutdown and backoff cancellation.
  TCP target sockets and UDP forwarders close with their owner. Complete UDP
  datagrams are flushed immediately through framed transports.
- Embedded Rathole server accepts byte streams from `/api/tunnel`, with no
  standalone Rathole communication listener.
- Native WebSocket adapter, configurable client request path, rustls TLS, and
  incremental gateway-config reload.
- Service removal closes public listeners and active TCP forwards. Authentication
  cannot register a service that was removed/changed during its handshake.
- Native API sign-in/sign-out, current account, session listing/revocation,
  settings, JSON errors, MongoDB serialization and sliding session renewal.
- Integration test against an isolated MongoDB proves existing BSON binary
  bcrypt hashes and Go-issued sessions work, expired/revoked sessions are
  rejected, renewal does not repeat within a day, and another account's sessions
  are excluded.
- Integration test with the actual upstream Rathole client transfers two 2 MiB
  payloads over the shared HTTP path, including an unchanged reload, and verifies
  service removal terminates the listener and active stream.
- UI keeps account-scoped data in memory between tab mounts, revalidates active
  views, cancels supported requests on unmount and displays explicit listener
  addresses separately from access URLs. Browser checks cover a delayed
  background response and rendering a supplied custom listener IP.
- Native machine creation validates owned group membership and aliases, generates
  credentials and enrolls into the owner's private network. Allocation matches
  the original stable-address algorithm. Existing invited/disabled enrollments
  and revoked ownership are preserved; exhausted ranges roll back new machines.
- Native startup reconciles private enrollment and rebuilds embedded-gateway
  configuration from active database records. Atomic, deterministic replacement
  includes custom listener IPs, safely quoted tokens and no control listener;
  unchanged output is not rewritten. Invalid snapshots retain the published file.
  Tests cover token changes and removal of deleted machines from public services.
- Native web routing now restores enabled database routes, with manual-target
  Host behavior, HTTP/HTTPS entry handling and authenticated HTTPS upstreams.
  Routing occurs before the gateway API dispatcher, so an application can use
  `/api/tunnel` or other paths on its own host. Shared bounded connection pools
  stream uploads/responses/upgrades and preserve encoded paths, target queries,
  configured upstream credentials and independent half-close. Certificate and
  hostname failures are rejected. Bounded filesystem events replace the edge's
  idle config scans; atomic route snapshots preserve previous valid routes on
  bad edits. Canonical/fallback gateway hosts cannot be claimed by web routes.
- Traffic-route add/update/list/delete APIs are now native. All 606 original
  model fixtures match normalized output and validation errors. Integration
  checks cover ownership of linked connections, cross-owner host reservations,
  reserved gateway aliases, disabled-route claims and concurrent creates.
  Failed config publication rolls back create/update/delete; edits retain
  existing creation metadata and unknown stored fields. Unsupported HTTP
  upstreams are rejected before persistence instead of poisoning edge reloads.
- Machine client auth/sync, JSON/TOML configuration, JSON/TOML change waits,
  deletion acknowledgement and owner-requested updates now run natively. Tests
  cover original Unicode/date configuration digests, endpoint overrides, update
  acknowledgements, deleted/disabled headers and owner isolation. Per-machine
  request-owned notifications wake idle change waits; no database polling timer
  or worker is created for each connected machine. Timeout rechecks still catch
  changes made outside the native API. An actual existing Go client consumed
  configuration through the native edge/API Unix proxy and returned 2 MiB intact
  with request half-close, without another tunnel communication listener.
- Authenticated Socket.IO status/configuration/log events and legacy sync are
  native. Scheduled native status/history, instant-alert and digest workers run
  in core; notification delivery cannot block presence monitoring. Their bounded
  cursor batches and transition cache avoid loading all machine documents or
  querying unchanged history on every poll.
- Saved-profile agents capture bounded, redacted diagnostics and stream them
  natively when requested by the UI. Console and retained output share the same
  redaction writer; background upload does not block forwarding or control sync.
- Native release distribution serves authenticated platform catalogs and
  resumable binaries, including the existing Rathole download URL. Only actual
  bundled assets are advertised; this does not establish platform lifecycle or
  bootstrap/update completion. See `native-releases.md`.

## Required work before rollout

### Private path selection requirements

The gateway coordinates authorized peer discovery and signaling. Private paths
must be selected by sustained measured performance and observed traffic demand.
Direct peer paths avoid gateway payload bandwidth and are preferred for light
traffic when healthy. A gateway relay remains eligible, including on a LAN, when
it offers materially better sustained throughput or latency for the workload.
Gateway load is a tiebreaker when performance is comparable, not an absolute
prohibition on relay traffic. Direct connections still need lightweight control
traffic and keepalives.

Agents must advertise usable local interface endpoints to authorized peers and
actively check candidate pairs, including LAN candidates when STUN or TURN is
unavailable. Exclude PortHub's own virtual interface and irrelevant container
bridges. A matching private subnet is only a hint: overlapping subnets, client
isolation and firewalls mean reachability and enrolled peer identity must be
verified before selecting a path. Do not trust a private address as identity.
The user explicitly requires collision handling across unrelated networks:
candidate IP/subnet matches never establish peer identity. Bind each probe and
transport handshake to the authorized enrolled peer ID, expected certificate
fingerprint and fresh session. Verify the actual DTLS certificate against that
pin before application payload; a responder claiming the expected ID with a
different certificate must be rejected. Tests must include two reachable peers
at overlapping RFC1918 addresses, wrong peer IDs, wrong certificate fingerprints,
replayed discovery replies, certificate rotation and stale candidate caches.

Applications continue using the same private virtual IP or private domain while
the underlying transport changes. With multiple viable interfaces, compare
measured RTT, loss and bounded capacity probes; ICE candidate priority alone is
not evidence of the fastest link. Avoid disruptive probing and route flapping.
Refresh candidates when interfaces or routes change, retry direct paths while
relaying, and reselect when a better stable path becomes available. Share one
bounded discovery task and byte-counter sample per peer across all transfers;
prefer interface/route events, slow scheduled refresh, jitter and failure backoff.
Cache prevalidated alternatives. Transfers read the ready path snapshot, without
synchronous probes or endpoint discovery. Pin each public control session and
its data channels to the same endpoint; do not move healthy streams for marginal
gains. Use sustained traffic windows, hysteresis and minimum dwell times to avoid
switching for brief bursts. Normal logs show path labels; explicit debug/status
details may include addresses. Traceroute routers are not peer endpoints.
Expose the selected direct/relay path and reason so operators can verify it.

The existing Go agent gathers host candidates, monitors network changes and
supports ICE renomination. The Luna–Miro baseline verified direct LAN UDP using
both private IP and private domain, at approximately 109 MB/s; see
`benchmarks/2026-10-23-luna-miro-baseline.json`. This does not establish fastest
multi-interface selection, recovery after a physical network move, or parity
in the Rust agent. Required checks include LAN discovery without STUN/TURN,
multiple interfaces, unreachable/overlapping LAN addresses, authenticated peer
selection, relay fallback, and direct-path recovery without changing the
application's private address.

### Remaining implementation

1. Translate every remaining API operation and its validation/authorization,
   Socket.IO event contract, workers, policy generation, operator tooling and
   artifact/install endpoints. The complete existing route manifest is
   `api/cmd/porthub-api/testdata/legacy_routes.json`; registering placeholder
   routes or forwarding requests back to Go does not satisfy parity.
   Mapped-port CRUD, availability/random selection, firewall policy/activity/traffic
   endpoints and manual/scheduled refresh are implemented natively. Machine
   creation, editing, group membership, token refresh, journaled deletion and
   native startup configuration are implemented. Install/artifact/private-install
   operations still need translation and end-to-end verification. Binary artifact
   distribution is native; install/bootstrap handling remains. Log routes,
   realtime events and status/alert workers are native. HTTP client sync
   and configuration reads are implemented. A saved-profile Rust foreground agent
   now synchronizes them and reloads embedded tunnels natively. Linux service
   installation/management is implemented and user-service tested; privileged
   activation, Windows/macOS controllers, crash-safe updates/retirement and background
   origin/cache/failover integration remain.
   See `native-agent.md` for the implemented profile commands and remaining gates.
2. Translate the full installed agent lifecycle: configuration sync, public
   tunnel endpoint/pin handling, file serving/downloads, service installation,
   updates, installed-service retirement, private enrollment, TUN, DNS, ICE/DTLS signaling, relay
   authentication, policy enforcement and network-change/path reselection.
   Native file serving, cross-terminal server management and resumable parallel
   downloads are implemented; full enrollment and private networking remain.
3. Support existing `porthub.tcp.v1` framed WebSocket and HTTP-upgrade clients
   during staged upgrades. Verify half-close, bidirectional traffic, wrong
   credentials, token rotation, concurrent transfers, reconnects and backpressure.
   Framed WebSocket and HTTP Upgrade now pass half-close and multi-MiB round trips
   between the native client/edge and current Go client/gateway in both directions.
   Adapter tests cover backpressure, malformed/truncated frames and cancelled
   reads. Raw WebSocket remains available for upstream compatibility; it does
   not preserve TCP half-close. Framed native clients send idle heartbeats while
   waiting for commands, including pooled channels, without a separate task.
   Reconnect/concurrency/credential-rotation cases still need broader checks.
4. Complete native edge TLS termination, API/UI proxying over a Unix socket,
   configured web routes and private relay; supervise failures and shutdowns.
   Native TLS termination, streamed API proxying over Unix sockets and configured
   host-based web forwarding are implemented and tested. Private relay remains;
   native traffic-route activity collection/API now preserves existing totals through
   an edge-owned aggregate journal.
5. Finish production migration of the native firewall worker and three-container
   topology in `deployment-isolation.md`. The replacement manifests, native
   worker, static UI and supervision pass isolated local production/dev checks;
   existing production data/ownership/firewall adoption still require verification.
6. Build all required Linux/macOS agent targets; use immutable release versions
   and authenticated downloads. Test lifecycle/rollback before queueing updates.
7. Preserve a fresh production DB backup, configuration audit and rollback image;
   deploy only PortHub on URM2, then compare records/routes and perform real
   public/private connectivity and performance checks from registered machines.
8. Upgrade every registered client and verify reported versions, private names,
   paths, routes and intended public listeners. Offline clients must reconnect
   before their installation and connectivity can be declared verified.
   The user renewed deployment/commit/push authorization and requires final native
   `porthub http.server`/`porthub get` transfers from Luna to Condor through both
   private and public mappings, followed by Luna to `miro.phub` through the private
   domain. Record sustained MB/s, checksum integrity and the selected transport;
   verify actual direct-LAN versus gateway payload traffic rather than inferring
   a route from the hostname or a matching private subnet.
9. Remove retired Go source/build/runtime dependencies, update the main docs,
   complete checks, then commit and push the final migration and finish rollout.

## Local verification

```sh
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# Use a dedicated MongoDB, never production: tests create/drop their own DB.
PORTHUB_TEST_MONGO_URI=mongodb://127.0.0.1:47117 \
  cargo test -p porthub-api -- --ignored
# Optional real Linux user-service test: creates and removes one test unit.
cargo build --release -p porthub-agent
PORTHUB_TEST_USER_SERVICE=1 \
  PORTHUB_TEST_AGENT_EXECUTABLE="$PWD/target/release/porthub" \
  cargo test -p porthub-agent --test service_live -- --ignored
# Optional staged-upgrade check also runs an existing Go agent executable.
PORTHUB_TEST_MONGO_URI=mongodb://127.0.0.1:47117 \
  PORTHUB_TEST_GO_CLIENT_BINARY=/path/to/existing/porthub \
  cargo test -p porthub-api --test machine_client -- --include-ignored
cd ui
node --test tests/workspace.test.mjs
# Requires Playwright, Chrome, and a development server at REVIEW_ORIGIN.
REVIEW_ORIGIN=http://127.0.0.1:47130 node tests/tab-data-cache.cjs
```

The first read-only URM2 audit is saved locally at
`/tmp/porthub-before-rust-audit.json`; it reported no problems or warnings.
Read-only client inventory found offline registrations, which still require
revalidation during rollout. These observations are baselines, not evidence
that the Rust rollout or performance objective has been achieved.

## Authenticated gateway-origin discovery

`POST /api/gateway/origin` accepts `machine_id` and `token` in its JSON body.
Only live enabled machine credentials can read the result, even if a previous
caller warmed the cache. The response is `Cache-Control: private, no-store` and
contains `data.public_ip`, `observed_at`, `refresh_after_seconds` and `stale`.
The gateway queries HTTPS IP-echo services without forwarding client credentials.
The IP is an origin candidate: outbound NAT discovery does not prove inbound
reachability. Clients must authenticate TLS and prevalidate it in the background.
DNS for an orange-cloud domain gives Cloudflare addresses, not its origin.

`PORTHUB_GATEWAY_PUBLIC_IP` overrides discovery. `PORTHUB_GATEWAY_IP_SOURCES`
accepts at most four comma-separated HTTPS endpoints; defaults are api.ipify.org
and checkip.amazonaws.com. A shared cache refreshes after five minutes, retries
failure after 30 seconds, and expires stale results after one hour. The native
API has one sleeping refresh task; concurrent calls do not duplicate lookups.
Unit/integration checks cover rejected private/malformed/oversized responses,
cache reuse, concurrent callers, retry backoff, stale expiry and credential
rotation/disable/deletion. Native tunnel candidates now verify authenticated
SPKI key pins and preserve canonical SNI/Host when dialing a direct origin.
Initial concurrent transport checks select a session endpoint. Agent-side origin
cache/discovery, background readiness and live failover remain unintegrated; the
native API still needs to advertise the edge's public certificate key pin.
Public mapped ports retain Rathole forwarding; private route scoring is separate.

## Isolation implementation and local verification

`porthub-runtime` now provides Unix socket ownership/permissions, streaming HTTP
proxying and structured native process supervision. `PORTHUB_API_SOCKET` makes
the API listen exclusively on its internal socket; the edge can proxy that
socket using `--api-socket` or the same environment setting. The core API can
forward non-API UI requests to `PORTHUB_UI_UPSTREAM`, a loopback HTTP origin.
Unknown API paths remain JSON 404s. Proxy checks cover streamed responses,
forwarded Host/authentication, hop-header removal, upgraded streams including
pipelined data and half-close, and clean upstream failures. Unix socket checks
cover one owner, 0660 permissions, stale recovery and file/symlink protection.
Native supervisor checks cover restart/backoff and process-group shutdown.
Production serves exported/precompressed Next.js assets from Rust, without Node.
Development runs Next.js behind the same Unix proxy and supports Compose Watch
source sync and live updates. TLS identity initialization and interrupted-write
recovery preserve existing private keys. The firewall uses native netlink and
SQLite; namespace tests verify allowlists, accounting, persistence and preservation
of foreign tables. Configured web forwarding and route management are now
native. Request activity now uses bounded edge-side aggregation and a read-only
core journal reader with revision-guarded Mongo checkpoints. Private relay remains
unimplemented.

The root deployment uses one Compose file with dev/prod mode, clean container
names (`porthub-core`, `porthub-edge`, `porthub-firewall`), explicit `:latest`
image tags, and separate slim runtime targets without build tools/source trees.
`scripts/verify-isolation.py` renders that file into a uniquely named disposable
project: no host networking, published ports only on loopback and an isolated
shared edge/firewall namespace. It checks simultaneous startup, authenticated
IPC, inaccessible internal TCP ports, capability separation, static UI and
account/session/TLS persistence after restart. It removes only its own resources.
This is evidence for the container boundary, not full API/agent migration parity.

## Canonical identity and optional raw direct transport

The user identifies `porthub.algofly.in` as the permanent server address, including
after moving the gateway. Saved profiles must retain that domain; discovered
origin IPs are expiring, authenticated, prechecked alternatives, never replacement
enrollment authorities. `algofly.duckdns.org` and the configured URM2 hostname are
fallback gateway routes. Verify their gateway identity before use, refresh the
origin in the background and recover through the canonical domain on stale-cache
or direct-path failure. Preserve TLS SNI/Host checks even when connecting to an IP.
Public mapped-port access can use the verified origin plus its mapped port.

The user permits an optional raw transport after authenticated discovery. Every
raw connection must still prove the exact enrolled peer and fresh session; an
IP/subnet match alone never authorizes payload. Reuse persistent/prewarmed
transports so discovery does not delay parallel application connections. Raw mode
removes payload encryption/integrity, remains opt-in, and must be benchmarked
against TLS/DTLS before selecting it for performance. End-to-end identity checks
and collision/replay tests remain required with either transport.

Native web activity is now implemented locally. Targeted tests cover bounded
per-route/month aggregation, partial journal tails, rotation, writer exclusion,
unclean shutdown markers, malformed/symlink input, legacy totals, owner filtering,
concurrent revision-guarded ingestion and replay suppression. A real proxy HTTP
request reaches the activity API without recording its query or payload. The
full workspace suite (including isolated Mongo tests) and Clippy pass. Rebuilt
production core/edge images pass the actual disposable Compose startup/restart
check with the edge journal writable and the core journal read-only. No URM2
deployment, final benchmark, commit or push has occurred.

Native mapped-port operations now implement the complete legacy connections route
set: create/update/delete/list, port discovery and availability, deprecated script
response, manual refresh, firewall policy read/update/delete, active ports, traffic
snapshots and recent hits. Validation passes 536 original connection cases, 256
policy cases and seven snapshot cases. External port reservations remain global,
including disabled entries. Owner checks apply to linked machines and all returned
firewall data. Requests cannot provide their own owner ID. A numeric unique Mongo
index prevents competing owners from assigning the same external port.

Mutation tasks finish after browser disconnects. Failed configuration publication
or firewall application restores previous records and policies. Agent configuration
long polls are notified for both machines when a mapping moves. Firewall IPC has
a dedicated authenticated Unix-socket HTTP client, redirect/proxy suppression,
bounded response size and request timeout; core needs no network capability.
Initial or failed-policy reconciliation retries with bounded backoff and sleeps
until recovery is requested after success, rather than scanning on every edit.
Scheduled refresh retains the legacy 30-second bounded queue and five-second
reconnect interval. Persisted refresh leases recover interrupted operations;
concurrent user edits invalidate a lease so deliberate disables are preserved.

All 81 Rust workspace tests, including isolated Mongo integration tests, and
Clippy pass. The rebuilt production core passes the expanded disposable Compose
verifier with existing native edge/firewall images: an API-created mapped port
transfers a 32 MiB file through embedded Rathole using the native file server and
parallel downloader with matching SHA256. Authenticated firewall updates block an
unlisted source and permit the configured source. The verifier uses the legacy
firewall contract: an empty allowlist is unrestricted, even with private metadata.
These are local functional checks, not the required 10 GiB remote performance
benchmarks. No commit, push or URM2 deployment has occurred.

Live listener revocation ordering now uses the native edge's scoped apply socket,
as described below. Production migration must still revalidate this ordering in
the target environment; atomic file publication alone is insufficient evidence.

The native foreground profile runtime is now implemented and checked locally.
It uses private saved machine credentials, native hostname collection, authenticated
sync/long polling, cancellation, bounded retries and incremental embedded tunnel
reloads. Wrong-machine configurations cannot replace live services; disable/re-enable
and service deletion work. URL-based legacy configs, pinned TLS and normal CA
validation are accepted by the Rust runner. The actual disposable three-container
Compose verifier now uses this profile runtime rather than a hand-written tunnel
config: real API sync, 32 MiB native transfer integrity, firewall enforcement and
live mapping deletion all pass. This does not complete the OS service/update,
background path-selection or private-network lifecycle. Windows GNU cross-check
is still stopped in a dependency build by the missing MinGW compiler; no native
Windows/macOS release-matrix result is claimed.

Latest local verification for this profile/identity milestone: 92 Rust workspace
tests pass, including isolated Mongo workflows, with Clippy warnings denied. The
11-check production Compose report and exact tested image IDs are recorded in
`verification/2026-10-24-production-isolation.json`. The final remote 10 GiB
benchmarks, full supported-agent release matrix, commit/push and URM2 rollout
remain outstanding.

The subsequent Linux service milestone passes 97 workspace tests, including the
opt-in real user-service lifecycle and isolated Mongo workflows, plus formatting
and Clippy with warnings denied. Installation uses an immutable binary release,
private copied profile and scoped native systemd D-Bus operations. The real CLI
test verifies authenticated sync, 4 MiB forwarding before and after stop/start,
status and complete test-unit removal. Its artifact hash and limits are recorded
in `verification/2026-10-24-native-service.json`. Privileged system activation,
Windows/macOS controllers and crash-safe updates remain unverified or incomplete.
The production-isolation image report above belongs to the preceding milestone;
those images have not been rebuilt with the service changes.

Machine group add/remove and token refresh are now native Rust endpoints.
Membership preserves legacy scalar groups, rejects foreign ownership and
serializes with group deletion and machine creation. Token refresh publishes
new gateway credentials, wakes waiting configuration requests and preserves the
existing bounded log-token history. A failed publication restores only rotation
fields, preserving concurrent runtime sync and client-update requests. Old
credentials retain the legacy `410`/machine-deleted response contract.

Local verification now covers 99 workspace tests, including isolated Mongo
workflows and the real Linux user-service test. The extended rotation test also
forces concurrent sync/update writes during a failed publication and verifies
that recovery retains those writes. Native realtime machine disconnect/status
events, machine update/delete, install/artifact/log APIs and the remaining
private-network lifecycle are still required. No commit, push or URM2 deployment
has occurred, and production isolation images have not been rebuilt for these
API changes.
The route coverage and remaining gates for this milestone are recorded in
`verification/2026-10-24-machine-management.json`.

Machine editing (`PUT /api/machines/update`) is now native. Add and update share
the same nullable request model. Editing preserves optional-field presence,
legacy `is_active` precedence, hostname overrides/runtime fallback, alias and
group normalization, setup URL/text limits and Telegram exclusion settings.
Only the authenticated owner can edit a machine; extra credential/owner/private
revocation fields cannot change registrations. Explicit null groups/setup values
clear their fields; omitted fields retain the saved values.

Enable changes synchronize mapped-port policies. Restrictions are installed
before newly enabled listeners are published, including recovery from a failed
disable. Failed edits use a conditional Mongo update pipeline to restore only
values still owned by the edit, preserving concurrent runtime sync and update
requests. Token rotation now shares this atomic recovery implementation.
Dedicated tests cover actual Mongo persistence, authenticated runtime sync,
firewall IPC with partial failures, unrelated-port isolation and publication
ordering. These checks do not yet prove live edge listener closure before
policy removal, recovery after multiple simultaneous external failures, or
native realtime event parity; those remain rollout gates. Machine deletion,
install/artifact/log routes, private networking, supported-platform release
verification and the final production migration remain incomplete.

This machine-editing milestone passes 103 workspace tests, formatting and Clippy
with warnings denied. The test scope and limitations are recorded in
`verification/2026-10-24-machine-update.json`. Production images, URM2 and installed
clients remain unchanged; no commit or push has occurred.

Native listener application now has an explicit acknowledgement protocol. Core
publishes a snapshot and submits its exact SHA256 over a role-scoped Unix socket.
Edge serializes file reads with reloads, waits for revoked control/pool/listener
and forwarding tasks, then returns the digest. TCP/UDP sockets can be rebound
immediately on completion. Interrupted cleanup remains owned by the embedded
server and is awaited on retry, even for an otherwise unchanged configuration.
No additional TCP listener, container, public endpoint or credential is required.

Policy removal and reconciliation require a successful apply when the edge
socket is configured. Restrictions are retained on unavailable or rejected
acknowledgement, and failed rollback keeps candidate restrictions until successful
reconciliation. Startup primes active policies before publishing listener config;
the production Compose dependency order is firewall, core, then edge. The
three-container topology adds only a scoped socket volume, read-only in core.

New integration checks use real native API, edge, client, live TCP forwarding,
MongoDB and firewall IPC: failed acknowledgement retains the rule and registration;
successful disable/delete closes the listener before the firewall delete handler
runs. Protocol checks reject wrong digests, malformed snapshots and invalid config,
and verify that the apply endpoint is absent from public ingress. Existing TCP
tests now force cancellation during closure and require synchronous port rebinding;
UDP tests also revoke live server forwarding and immediately rebind its port.
Broader crash/restart and multiple-failure recovery, full API/realtime/private
network parity, cross-platform releases, remote benchmarks, commit/push and the
actual URM2 migration remain outstanding.

The listener-acknowledgement milestone passes 106 workspace tests, formatting and
Clippy with warnings denied. Rebuilt local production images pass all 12 checks
in `verification/2026-10-24-listener-ack-isolation.json`, which records exact image
IDs. The disposable test includes native profile sync, 32 MiB file integrity,
firewall enforcement, immediate listener deletion, private socket mount scope
and restart persistence. Its containers, volumes and user-service test unit have
been removed. This is local functional evidence; final remote 10 GiB benchmarks
and the production/client migration have not occurred. No commit or push yet.
The explicit local Go compatibility executable also passes all five machine
client checks against the native API/edge after the ownership changes. Test
scope and its executable hash are in `verification/2026-10-24-listener-ack.json`.

Machine deletion (`POST /api/machines/delete`) is now native. It preserves the
owner-only request and legacy pre-deletion response contracts. A temporary
disabled state returns 403 while listeners close, avoiding premature client
uninstallation if closure or firewall cleanup fails. Edge acknowledgement
precedes policy cleanup; failures before the commit phase restore registration
fields and restrictions before republishing enabled listeners.

After closure, a persistent committing phase precedes connection cleanup and the
410 deletion response. A single indexed worker resumes interrupted work in
batches of at most 25, with per-job retry deadlines capped at 30 seconds. It
releases the mutation lock between jobs and has no timer/scans when idle. Client
ACKs can be recorded immediately during committing, without waiting for cleanup's
lock. Conditional finalization prevents concurrent ACKs from losing their removal
request; unacknowledged tombstones remain for offline clients. A client disconnect
does not cancel the authorized deletion task. Pending jobs reject edits/token
rotation, and startup avoids allocating new private enrollments for retiring
machines. Legacy private-peer/history records are retained; native private-route
revocation and installed-service/profile retirement remain separate lifecycle work.

The deletion tests cover authorization, ordinary and early ACKs, concurrent
finalization, reversible failure, request cancellation, journal recovery, notified
jobs, bounded retry scheduling and misconfigured edge snapshot paths. The live
native API/edge/client test now also verifies whole-machine deletion and rollback
after a rejected firewall delete. Remaining install/artifact/log/realtime/private
APIs, platform lifecycle, final remote benchmarks and the URM2 rollout are still
required. Nothing has been committed or pushed.

This milestone passes 112 workspace tests with the explicit Go compatibility
executable enabled, formatting and Clippy with warnings denied. Rebuilt local
images pass all 13 checks in `verification/2026-10-24-machine-deletion-isolation.json`.
The new whole-machine check observes normal native-agent exit, deleted status
and acknowledged record removal while another profile and its HTTP server remain
running. Active restrictions are now installed as a batch before inactive mapping
cleanup can publish an enabled snapshot. Scope and remaining gates are recorded
in `verification/2026-10-24-machine-deletion.json`. URM2 and registered clients
remain unchanged, and the overall migration goal is still active.

The API now serves authenticated Socket.IO status, configuration and live log
events on the existing `/socket.io` ingress. Its bounded connection registry and
ordered event queues scope user events to the owning account and machine events
to that machine. Session expiry, revocation and token rotation are rechecked
before delivery. Log subscriptions are reference counted and removed on
disconnect; slow consumers have bounded queues. The implementation uses
[socketioxide](https://docs.rs/socketioxide/0.18.7/socketioxide/) with the
frontend's existing Socket.IO event names, websocket transport and heartbeat
settings. It requires no extra container or communication port.

The UI connects after authentication and keeps its connection while switching
workspace tabs. Native log upload and stream-status routes preserve line/source
bounds and historical-token diagnostics. Deliberate security changes reject
anonymous sockets, prevent machine sockets from reading account-wide status,
and reject unknown log credentials without updating presence. Retained historical
tokens can report diagnostic logs with `auth_required` set. The legacy machine
sync route preserves its top-level response and disabled-machine configuration;
retiring machines return 410 to complete deletion.

Seven new integration checks cover event scopes, subscription cleanup, token and
session revocation, Unicode log bounds, legacy sync and the UI's actual
`socket.io-client` against the native API. The production isolation verifier also
exercises that client through HTTPS edge ingress and the Unix API socket. These
changes do not implement the offline status/history monitor, Telegram alert and
digest workers, or the native agent's log uploader. Those remain parity gates
alongside private networking, platform lifecycle and the final remote benchmarks.

The realtime milestone passes 119 workspace tests (including the explicit Go
compatibility executable, actual user-service lifecycle and official frontend
client), formatting and Clippy with warnings denied. All 13 UI unit checks and
both tab-data/bootstrap-cache browser checks pass. Rebuilt local `:latest`
images pass all 14 checks in `verification/2026-10-24-realtime-isolation.json`,
including HTTPS websocket ingress and the existing native 32 MiB transfer,
firewall, machine-retirement and restart-persistence checks. The report records
the exact image IDs; the disposable project was removed. These checks are local,
and do not replace the required Luna/Condor/Miro benchmarks or production rollout.
Scope is recorded in `verification/2026-10-24-realtime.json`. No commit or push.

Status/history monitoring and Telegram instant/digest workers are now native and
supervised with the API. Presence/history scans use cursor batches of 100 and a
small per-machine transition cache. Unchanged history is checked again near its
370-day retention deadline; failed writes retry without requiring another status
transition. Idle expiry and recovery push owner-scoped Socket.IO changes. The
poll interval remains half the online TTL, bounded to 5–30 seconds.

Instant alerts run independently of presence monitoring and query only eligible
transitions using an alert-state/last-seen index. Conditional updates reject stale
heartbeat, exclusion, disable and retirement snapshots. Startup suppresses alerts
for machines already offline beyond the grace period. Digest scans run every ten
minutes and honor each account's interval, recipients and exclusions. HTML names
are escaped and bounded, and large digests are split into messages bounded by
4096 UTF-16 code units. Delivery failures log counts without bot tokens, chat IDs
or URLs. Both workers cancel in-flight requests on shutdown; no global mutation
lock is held during notification I/O.

As with existing instant alerts, delivery is an attempt rather than a durable
outbox. The digest period is claimed before network I/O, so failures are not
replayed every scan and a process crash after claiming can skip that period.
This ordering differs from the old digest checkpoint after delivery and avoids
concurrent duplicate digests; durable notification retries are not implemented.
Tests use a loopback mock endpoint and do not send messages to actual recipients.

This milestone passes 128 workspace tests, formatting and Clippy with warnings
denied, including history retry/retention repair, stalled-delivery isolation,
startup indexes, alert grace/exclusions, scoped digests and websocket expiry.
Rebuilt local production images pass all 15 checks in
`verification/2026-10-24-status-isolation.json`. The new check observes online
history followed by idle expiry using the actual production API worker. Existing
HTTPS realtime, native 32 MiB file integrity, firewall, retirement and persistence
checks also pass; all disposable containers are removed. Scope is recorded in
`verification/2026-10-24-status.json`.

Install/artifact/private APIs, native agent log/update lifecycle, private path
selection/relay, full platform support, production adoption and the required
remote bandwidth tests remain incomplete. No commit, push, URM2 deployment or
registered-agent upgrade has occurred; the overall migration goal remains active.

Native saved-profile agents now replace the shell log supervisor. One
profile-scoped tracing writer redacts enrolled credentials, endpoint URLs and
addresses before console output and retention. The ring is bounded to 256 lines
and 128 KiB, each line to 4000 characters, and each raw event to 16 KiB. Partial
writes are assembled before redaction; oversized events are omitted whole rather
than exposing a credential split by truncation. Normal tracing defaults to info.

A single cancellable task checks authenticated demand every five seconds, then
sends the most recent three lines and batches of up to 100 new lines every two
seconds while demand remains active. Demand and upload failures have separate
backoff capped at sixty seconds. Successful demand checks do not reset failed
upload backoff; a pending batch retains its cursor until acknowledged. Inactive
or failed demand checks stop uploads and reset recent context; deletion ends the
task. The worker is owned by the runtime guard and never blocks forwarding.
The stream is not an archive: memory pressure can evict older lines, reconnection
can repeat recent context and process exit loses buffered history. No shell,
tail process, log file or additional runtime package is needed.

Seven new checks cover redaction/partial writes, memory and cursor bounds,
demand/subscription changes, wrong-machine responses, independent retry backoff,
deletion and cancellation. A real CLI process also proves configuration diagnostics
reach the upload endpoint, debug console output omits the enrolled token and
endpoint address, and SIGTERM completes normally. The rebuilt native release was
used by the actual systemd user-service check.

This milestone passes all 135 workspace tests, formatting and Clippy with
warnings denied. The rebuilt local production images pass all 16 checks in
`verification/2026-10-24-agent-logs-isolation.json`: the packaged native agent
streams its own diagnostics to the UI's official Socket.IO client over HTTPS,
alongside the existing native 32 MiB integrity, policy, retirement and persistence
checks. All disposable containers are removed. Scope and local agent identity
are recorded in `verification/2026-10-24-agent-logs.json`.

The remaining install/artifact APIs, private networking and route selection,
cross-platform lifecycle and crash-safe updates, production adoption, final
remote benchmarks, commit/push, URM2 deployment and registered-agent upgrades are
still required. URM2 and registered clients remain unchanged; the goal is active.

Release artifact distribution is now native. Enabled machine credentials protect
the JSON catalog and streaming binary endpoints. The catalog reports per-file
platform, version, size and computed SHA256, with missing targets listed
separately. Native URLs preserve the configured public authority and path prefix;
Windows attachments retain `.exe`. The compatibility Rathole URL preserves its
existing headers and `x86` alias, while the native URL selects actual 32-bit x86.

Version metadata is required; optional SHA sidecars are verified against the
opened bytes. Docker now produces both version and SHA metadata. Invalid
versions, hash mismatches, symlink leaves and nonregular files fail closed.
Hashing is bounded and cached by file identity, and responses retain the opened
descriptor across atomic publication. Active files must not be rewritten in
place. GET/HEAD, single byte ranges, ETags, Last-Modified and conditional requests
support native parallel/resumable downloads. Details and target mapping are in
`native-releases.md`.

Six new checks cover platform aliases, immutable opened responses, hash-cache
invalidation, bad metadata/special files, HTTP resume/conditionals, machine
authorization and real native `get` integrity through the authenticated API.
All 141 workspace tests pass with the explicit Go compatibility executable,
actual user-service lifecycle, formatting and Clippy with warnings denied.
Rebuilt local images pass all 17 checks in
`verification/2026-10-24-artifacts-isolation.json`, including catalog lookup,
range/legacy headers and the packaged agent downloading its own release with a
matching SHA256. Existing diagnostics, 32 MiB transfer, firewall, deletion and
restart checks pass; all disposable containers are removed. Scope is recorded
in `verification/2026-10-24-artifacts.json`.

Catalog fixtures cover other platform names and bytes; they do not execute those
platform releases. Native ticket enrollment and installer replacement remain,
as do crash-safe updates, private APIs/transports/path selection, supported-platform
lifecycle/build verification and production adoption. Commit/push, URM2 rollout,
all registered-agent upgrades and the final remote benchmarks remain outstanding.

Native bootstrap enrollment now issues owner-scoped, 24-hour capabilities and
serves versioned profiles or a minimal first-download launcher. Current-token,
enabled-state and retirement checks protect profile and asset access; existing
valid public Go-issued codes remain readable. The CLI fetches without redirects,
requires HTTPS unless explicitly testing, checks response identity/size and
stores private credentials. Linux service activation uses the existing native
manager, with source rollback on failure and protection of other enrollments.
Typed setup overrides persist into later configuration requests.

Each effective setup now has its own stable, immutable code. This fixes a
discovered interaction with the UI cache: Go's mutable per-credential ticket
could change the settings behind a previously cached command after another
draft was previewed. Identical settings reuse a code, different settings get
separate codes, and reverting can reuse the original cached command safely.
Native contexts use a separate key space from Go-issued tickets.

All 149 workspace tests pass, including eight new bootstrap/rollback checks and
the updated actual systemd user-service test. The latter enrolls through native
`setup`, synchronizes, forwards 4 MiB and proves stop/start and scoped removal.
Formatting, Clippy with warnings denied and the existing bootstrap-cache browser
check pass. Rebuilt production images pass all 18 checks in
`verification/2026-10-24-bootstrap-isolation.json`: the packaged agent enrolls
through a real owner-issued ticket before native 32 MiB file integrity, policy,
diagnostics and retirement checks. Disposable containers and test units are
removed. Scope and local release identity are recorded in
`verification/2026-10-24-bootstrap.json`.

This does not complete first-install distribution. Interactive CLI publication
into a bin directory, safe existing-CLI/tenant adoption, native tenant-management
aliases and full legacy installer-route compatibility remain. The small Unix
first-download launcher uses OS tools only for downloading/launching the native
binary; it has not been fully exercised over HTTPS with privileged activation.
See `native-bootstrap.md` for these limits and the next installation work.
Private networking, crash-safe updates, all required platforms, production
adoption, final remote benchmarks, commit/push, URM2 deployment and every
registered-agent upgrade remain outstanding. The overall goal stays active.

Native setup now publishes the interactive CLI into `/usr/local/bin`, or
`~/.local/bin` for user installations, with an explicit bin-directory override.
Publication selects a verified immutable release and rolls back if service
activation fails. Unknown executables and links are refused; an identical native
executable can be adopted with its original inode preserved for rollback.
Native list/status/start/stop/restart/remove commands select owned registrations
by unambiguous identifiers. Removal preserves the shared executable.

All 153 workspace tests, formatting and Clippy with warnings denied pass. The
actual user-service test drives its lifecycle through the published CLI. Local
production images pass all 18 isolation checks, and their disposable containers
are removed. Evidence and exact image/release identities are recorded in
`verification/2026-10-24-cli-publication.json` and its isolation report. An initial
optimized compiler crash was followed by a successful build with a larger
compiler stack; this build-only setting does not change runtime configuration.

Legacy CLI/tenant adoption remains necessary before replacing existing client
installations. Private networking, background route selection, crash-safe
updates, platform lifecycle support, remaining API compatibility, production
adoption and remote benchmarks remain outstanding. No commit, push, URM2
deployment or registered-agent upgrade has occurred at this milestone.

The native CLI can now stage credentials from an existing Unix `client.env`
without executing shell code or changing its running installation. Import
preserves authority/machine ID/token, removes the legacy `/api` suffix, accepts
explicit same-gateway fallback URLs and writes only a new private profile.
Bounded source reads reject unsafe ownership, writable-by-others files,
symlink leaves, shell expressions and duplicate assignments. Errors omit values.
Legacy service takeover and private runtime-state migration are still required;
credential staging alone is not an agent upgrade.

Five new importer tests pass, including invocation of the compiled CLI, immutable
source/output checks, permissions and malicious-input rejection. All 158
workspace tests pass with integration opt-ins enabled, along with formatting,
Clippy with warnings denied and patch whitespace checks. The existing lifecycle
integration still executes the previously built CLI-publication release; the
import-specific test executes the newly compiled test binary. No production
images were rebuilt for this source change. Scope is recorded in
`verification/2026-10-24-legacy-import.json`.

Native private-access browser inventory, network preferences and private peer
enable/disable/revocation now use the existing MongoDB records. Workspace roles
and origin checks protect writes; explicit projections exclude credentials and
unexpected stored fields from inventory. Settings retain enrolled addresses,
and revocation invalidates private authentication before clearing tickets and
signaling without changing public credentials. Native private naming retains
legacy unambiguous names and resolves collisions in the old short-ID suffix.
ObjectId/string joins preserve the actual identifier type. See
`native-private-access.md` for supported endpoints and remaining transport work.

All 162 workspace tests pass with integration opt-ins enabled, including four
new private-access tests; formatting, Clippy with warnings denied and patch
whitespace checks pass. Rebuilt local production images pass all 19 isolation
checks, including the new browser controls and the retained native 32 MiB file
transfer, diagnostics, policy enforcement, deletion and restart checks. The
disposable containers are removed. Exact image identities and scope are in
`verification/2026-10-24-private-access-isolation.json` and
`verification/2026-10-24-private-access.json`. URM2 was inspected read-only and
still runs its existing PortHub container. No commit, push, production rollout,
client upgrade or final remote benchmark has occurred.

Native private sync now authenticates existing private credentials and publishes
only policy-reachable peers and incident grants. Machine ownership/state and
workspace membership checks protect presence and response publication. Signaling
validates sender fingerprints and negotiation direction, deduplicates retries,
binds both process/certificate contexts, restricts acknowledgements to recipients
and explicitly filters expired messages. Native configuration parses existing
ICE/relay settings once and issues compatible peer-scoped TURN REST credentials.
Snapshot expiry uses UTC RFC3339 rather than the public inventory's legacy
naive-date format, preserving the Go client's timestamp contract. Protocol and
remaining transport gates are described in `native-private-sync.md`.

All 172 workspace tests pass with integration opt-ins, including five new
private sync/settings/security tests. Formatting, Clippy with warnings denied
and patch whitespace checks pass. Rebuilt production images pass all 21 checks;
the new production assertion rejects public machine credentials at private
signaling ingress. Positive sync/signaling cases exercise the native router
against isolated MongoDB, rather than a private agent transport. Disposable
containers are removed. Scope and exact image identities are recorded in
`verification/2026-10-24-private-sync.json` and its isolation report. Private
enrollment/relay/native-agent transport and the remaining migration gates still
prevent rollout. No commit, push, URM2 deployment, client upgrade or final
physical-machine benchmark has occurred.

Native private enrollment, one-time bootstrap and hostname changes now preserve
existing peer IDs/addresses and check workspace/machine ownership. Native ticket
generations prevent stale issuance from publishing into a later reenrollment;
legacy Go-issued pending tickets remain supported without generation fields.
Short installer links distinguish private metadata and native `enroll` from
public `setup`. The agent validates identity and file permissions before ticket
consumption and saves a new private profile in the existing Go wire format.
Existing files, redirects and unsafe metadata are rejected. This stages private
credentials; private packet runtime and service activation remain required.
See `native-private-enrollment.md` for lifecycle and recovery limits.

All 178 workspace tests pass with integration opt-ins, including six new
enrollment/model/file-security/CLI tests. Formatting, Clippy with warnings denied
and patch whitespace checks pass. Rebuilt production images pass all 22 checks:
the packaged CLI stages two private identities through owner-issued short
capabilities, then the API exchanges and acknowledges a policy-scoped offer.
This proves positive production enrollment/sync/signaling, not a peer packet
handshake. Existing public transfer, diagnostics, firewall, deletion and restart
checks remain passing, and disposable containers are removed. Scope and exact
image identities are in `verification/2026-10-24-private-enrollment.json` and its
isolation report. Private packet transport/activation, relay and the other
migration gates remain. No commit, push, URM2 rollout, registered-agent upgrade
or final physical-machine benchmark has occurred.

The private policy model, access evaluator and explicit grant compiler now run
in Rust. Retained reference fixtures cover 69 model cases, 21 port expressions,
1,536 access decisions and ten grants. Per-client compilation restricts pair
selection before expansion, retaining only the requested machine's grants.
Browser rule-book create/update/delete and policy previews use workspace roles,
selector ownership validation and atomic revision predicates. Concurrent edits
at one revision admit exactly one update; stale deletes fail. Nested validation
retains original error ordering, and JSON integer/string coercion preserves
large identifiers and Python exponent formatting. See
`native-private-policy.md` for behavior and the remaining transport gates.

All 167 workspace tests pass with integration opt-ins enabled, including five
new policy/reference/database tests. Formatting, Clippy with warnings denied
and patch whitespace checks pass. Rebuilt production images pass all 20 checks,
including rule-book creation, stale-revision rejection, deletion and policy
previews through ingress. The final run also verifies retained creator metadata
in the inventory projection. Disposable containers are removed. Scope and exact
image identities are in `verification/2026-10-24-private-policy.json` and its
isolation report. Native private signaling/relay/agent transport and the other
production migration gates remain; no commit, push, URM2 rollout, registered
client upgrade or final remote benchmark has occurred.
