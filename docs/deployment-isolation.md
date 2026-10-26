# Native deployment boundaries

The root Dockerfile and single `docker-compose.yml` define three native server
roles. Native release 1.4.6 is deployed on URM2. Persistent PortHub state is
host-bound under `/home/ubuntu/algofly/porthub/volumes/porthub-native`; the
original named volumes remain intact for rollback.

| Container / image | Components | Network | Added capability | Shared access |
| --- | --- | --- | --- | --- |
| `porthub-core` / `porthub:core` | Rust API, static UI, MongoDB, Rust supervision | Bridge; no published ports | None | Database volume, API socket, routing config, firewall socket; edge control socket and request journal read-only |
| `porthub-edge` / `porthub:edge` | Rust HTTP/HTTPS ingress and embedded Rathole | Host; intentional web and assigned service listeners | `NET_BIND_SERVICE` | API socket and routing config read-only; own control socket, TLS and request journal volumes |
| `porthub-firewall` / `porthub:firewall` | Rust netlink firewall and SQLite traffic accounting | Host | `NET_ADMIN` | Own state volume and dedicated firewall socket |

Core runs as UID/GID 10001. Edge and firewall run as UID 0/GID 10001 with every
capability dropped except the one listed. A local kernel test confirmed Docker
removes effective `NET_ADMIN` when starting the worker as non-root. Neither role
is privileged. Production root filesystems are read-only; `/tmp` is a bounded tmpfs,
and `no-new-privileges` is enabled. No role mounts the Docker socket.

MongoDB binds only to core loopback, outside the host network. The API binds
exclusively to `/run/porthub-api/api.sock` in this deployment. The static Next.js
export is served by Rust; production contains no Node runtime or UI server
modules. Any future Redis service must also stay inside core's namespace.

Edge connects to the API through the restricted shared Unix socket and proxies
streams/upgrades without buffering complete bodies. Core reaches the firewall
through `/run/porthub-firewall/api.sock`, authenticated with `FW_API_KEY`.
The native mapped-port API uses a dedicated bounded HTTP client over this socket;
it applies configured restrictions before publishing a new listener. Initial or
failed-policy reconciliation retries in the background, then sleeps until needed.
The API and firewall sockets live in different volumes. Edge receives neither
database credentials/storage nor firewall credentials/storage/socket access.
The firewall controls only PortHub's own nftables table; it never flushes the
host ruleset. It communicates with netfilter directly in Rust, without `nft`.

The post-deployment live audit on 2026-10-26 verified all 17 configured public
ports against sockets owned by the edge process. Requests through all 25 proxy
routes reached HTTP responses: 15 reached upstream responses, while 10 returned
502 because their existing mapped targets were disabled (eight disabled port
mappings and two mappings on the disabled Clearsight machine). Those settings
were preserved. Both builtin PortHub gateway aliases returned 200. All nine
enabled machines reported agent 1.4.6 with no pending update target.

Core requests exact-snapshot application over `/run/porthub-edge/control.sock`.
This is a separate Unix socket volume: edge mounts it writable, core read-only,
and firewall has no mount. No control endpoint is mounted on public ingress.
Requests contain only a SHA256 of the generated config. Edge reads under its
reload lock and acknowledges the same digest after revoked listeners and
forwarding tasks have released their sockets. The API requires that acknowledgement
before policy removal; missing/rejected acknowledgements retain restrictions.
Interrupted reloads retain cleanup ownership so retries cannot acknowledge early.

Production starts the firewall before core, then edge. Core primes active
restrictions before publishing its initial listener snapshot, without waiting
for an edge that cannot start until core is healthy. Reconciliation removes stale
restrictions only after live edge acknowledgement. The disposable verifier places
firewall inside edge's test namespace, so its empty edge starts before firewall
and core; all resources are still created together to test volume initialization.

Machine retirement journals unfinished cleanup in MongoDB. Its one native worker
uses the same role-scoped sockets, processes at most 25 due records per batch,
releases the mutation lock between jobs and sleeps until a retry deadline or
notification. It adds no listener, container or helper executable. Early client
ACKs are preserved until connection cleanup can safely remove the registration.
Core also publishes `web-routes.json` beside the Rathole configuration. Edge
validates and atomically swaps host routes after native filesystem notifications;
it does not scan files on an idle timer. HTTP/HTTPS upstreams use shared bounded
pools, verified TLS, streaming bodies and upgraded connections. Canonical and
fallback gateway names are reserved for gateway ingress.

Edge aggregates web requests by stable route ID and UTC month in bounded memory.
A background worker writes at most 512 aggregate rows per batch, normally every
five seconds while requests are pending. The rotating journal is bounded to
roughly 30 MiB and contains configured hosts, counts and timestamps; request
addresses, URLs, credentials and payloads are excluded. Core mounts this journal
read-only and follows native filesystem notifications without idle scans. Batch
IDs, read checkpoints and totals commit atomically in the existing Mongo activity
document, preserving previous totals and avoiding duplicates after retries.
An unclean edge exit, corruption or missing journal history sets a coverage
warning. Graceful shutdown flushes pending counters. This adds one scoped volume
and no container, port or runtime CLI dependency.

Public clients share the existing API/HTTPS listeners for tunnel control and
data at `/api/tunnel`. Mapped public service ports are additional listeners by
design. There is no standalone Rathole communication port. Public forwarding
retains Rathole behavior; private-peer route selection is a separate concern.

Linux TCP sockets prefer BBR individually, including accepted mapped-port
connections. URM2 loads its installed `tcp_bbr` module through
`/etc/modules-load.d/porthub-bbr.conf`; this enables the algorithm without changing
the host's CUBIC default or granting containers module-loading capabilities.
On another gateway, load `tcp_bbr` on the host if its kernel provides the module.
Unsupported kernels retain their existing TCP policy. The application does not
change global TCP sysctls.

## Development and production

Both modes use the same Compose file and the `porthub:core`, `porthub:edge`
and `porthub:firewall` image tags:

```sh
# Build/validate production images without changing running services.
docker compose config --quiet
docker compose build core edge firewall

# Development, on a host with the intended PortHub listener ports available.
PORTHUB_MODE=dev ./deploy.sh

# Production after the native migration's rollout gates have passed.
PORTHUB_MODE=prod ./deploy.sh
```

Development images include Rust and Node toolchains and source. Compose Watch
syncs UI and Rust source into the containers. Production copies
only compiled Rust executables, MongoDB and exported/precompressed UI assets;
compilers, Go, Node, npm, Yarn and source trees are absent. Version labels and
embedded executable versions identify a release even though tags remain latest.
The helper sets the core filesystem writable only in development: Docker's
archive API used by Compose Watch cannot sync into a read-only container root.
The other roles remain read-only. Production explicitly restores read-only core
and rebuilds its production target, preventing reuse of a development-tagged image.

`PORTHUB_EDGE_HTTP_LISTEN` and `PORTHUB_EDGE_TLS_LISTEN` are comma-separated
listener addresses. Empty TLS configuration disables HTTPS for local tests.
The default ports retain web 80/443 and app 8345/8346. TLS identity files persist
in the edge-only certificates volume. An explicitly permitted first-start
self-signed identity is generated in Rust; an existing identity is preserved,
and an interrupted certificate write can recover using the same private key.
Supplied CA-issued identities use the same files. Listener-derived forwarding
headers let the API set Secure cookies for HTTPS.

## Verified locally

- Native core starts an authenticated new MongoDB and uses existing authenticated
  data after restart. Account/session state survived a container restart.
- Machine creation, automatic private enrollment and gateway-config publication
  work with the read-only production root and writable scoped volumes. Private
  addresses survive restart; startup preserves existing enrollments.
- HTTP/HTTPS ingress serves API and static UI through the Unix socket. Static
  HTML and JavaScript have valid precompressed gzip; hashed assets are immutable.
- Core's database/API/UI TCP ports cannot be reached through the bridge address.
  Firewall has no TCP API listener; no Rathole control port exists.
- Native edge request counts reach the authenticated activity API through the
  read-only core journal mount. Counts and checkpoint survive a three-role restart.
- A saved-profile native agent receives configuration from the real API and
  applies live mapped-port deletion without a shell client. API-created mappings
  carry 32 MiB native file-server/parallel-download transfers
  through embedded Rathole with matching SHA256. API firewall updates block an
  unlisted source and permit the configured source in the disposable namespace.
- Core can authenticate to the firewall over IPC; edge cannot access that socket.
- Real netlink tests inside disposable namespaces permit/block sources, preserve
  counters across unchanged reloads, and leave an unrelated table intact.
- Edge and firewall were also tested in the same disposable namespace: native
  `http.server`, embedded Rathole HTTP Upgrade and four-connection native `get`
  transferred 32 MiB with matching SHA256; firewall policy changes blocked and
  restored public-port access and traffic samples recorded the forwarded bytes.
- SQLite migration, policy deletion/restart, Unix socket ownership and stale
  recovery, proxy streaming/upgrades, and supervisor restart/shutdown have tests.
- Development startup, actual Compose Watch source sync and browser live updates
  through the edge/API Unix proxy passed using the same Compose topology.
- `python3 scripts/verify-isolation.py` checks the actual production Compose
  startup and restart in a fresh disposable project. Set
  `PORTHUB_VERIFICATION_REPORT=/path/report.json` to save a sanitized report.
  A local result with tested image IDs is recorded in
  `verification/2026-10-24-production-isolation.json`.

These tests use private namespaces, not the existing host firewall. They do not
prove that all remaining API routes, private relay/agent features or registered
production clients have been migrated. The full supported-agent release matrix
still requires verification.

## Existing deployment migration

Before rollout, preserve a production database backup, original images, listener
inventory and rollback instructions. Target only PortHub services. Reuse the
existing MongoDB data, with a scoped ownership migration for UID 10001 if needed;
do not reset credentials or registrations. Copy the legacy firewall SQLite data
into its new dedicated volume before stopping the old worker permanently.
Audit/adopt or remove only PortHub's legacy `inet rathole` table after its worker
is stopped, so stale rules do not conflict with the native `inet porthub` table.
Do not flush unrelated rules, remove unrelated containers or prune networks.
The old monolithic container must stop before the replacement takes its ports.
