# Sparse private-network prototype — not a release capability

This isolated prototype is based on `dcc9aed45d8800d177c9338fa44d910f82b25d0f`.
The `private-sparse` Cargo feature is deliberately absent from both API and agent
default/release feature sets. Pool growth is a separate implemented feature; this
prototype does not establish unlimited devices, full-mesh throughput, or automatic
range migration.

Implemented contracts:

- A negotiated base identity plus independently expiring, exact-direction pair
  grants. Local authority epochs, remote identity revisions, certificate/process
  pins, cache capacity and packet/stream authorization remain distinct.
- Indexed current peer/address, machine, workspace-membership and user checks.
  No positive credential, membership, address or pair decision is cached by the API.
  Immutable rule selector indexes are keyed by a freshly read book revision
  manifest and rechecked before publication. Covered group queries return only
  relevant IDs, not entire user-membership arrays.
- A separate DNS directory materializes existing name-assignment semantics on
  bootstrap, name changes and periodic refresh. Directory names never authorize
  a machine: current metadata, membership, assignment and rules are checked again.
- Bounded client intent batches, demand wakeup with at most one control cycle per
  second, asynchronous private-name misses, lease-bounded DNS answers and local
  SERVFAIL on unresolved private names instead of public DNS fallback.
- Cold incoming pair discovery and expiring reciprocal gateway eligibility bound
  to both peers' credentials, instances and separate local policy epochs. Idle
  sparse registrations allocate no datagram-relay connection seats.
- Exact-pair denial retires only that pair; overload and malformed replies do not
  masquerade as authoritative denial. Source HTTP 401/403 cancels the entire
  private work scope. Credential/process-bound Hub admission generations fence older
  in-flight publication after a source denial, without evicting a newer incarnation
  or quarantining later freshly authorized recovery. Established QUIC copies have their own deadline/renewal
  guard rather than relying on a periodic base-policy tick.
- Shared collision planning and Linux/Windows/macOS owned capture-prefix adapters.
  A private prefix routes packets to the ACL engine; it never grants permission.
  A newly conflicting prefix cannot force itself over an existing LAN/VPN route.

Evidence so far:

- An actual isolated MongoDB 7 test inserts 4,097 registered peers, including the
  unique workspace/address index that normal enrollment already creates. A sparse base
  and exact pair lease stay below 16 KiB of response JSON; a legacy oversized
  snapshot fails with an upgrade/narrow-rule explanation.
- A warm broad lookup examined 17 documents / 20 keys with 7,852 bytes of Mongo
  responses. A representative explicit-group case with 4,097 distinct users
  examined 18 documents / 23 keys with 8,590 bytes. Rule-manifest and group queries
  examined zero documents through covered indexes. These are 2–3 API callers,
  not 4,097 running agents or a full-mesh throughput benchmark.
- Actual target-only group removal leaves the source epoch unchanged but retires
  its installed target pair and preserves an unrelated pair/base. Book revocation
  changes the epoch and removes remaining grants. Removing source workspace
  membership returns HTTP 403; the client rejection regression begins with an
  unexpired installed pair and verifies immediate cache/DNS/work cancellation.
- Portable engine, resolver, DNS, rule-index parity, stream-deadline and HTTP
  rejection regressions pass. Windows x64/ARM64 and macOS x64/ARM64 adapter metadata compile
  against the actual platform source; metadata compilation is not native route
  execution.

Remaining release blockers include coherent sparse exit/LAN-exit/Tor/proxy paths,
automatic server/client range migration when required, lifecycle/native route
proofs on all three OSes, directory mutation/concurrency tests, complex-policy
resource-status handling, measured admission/fairness under load, and final
standalone-Mongo mutation/identity-race audit. Existing known-host /32 routes must
also be reconciled safely when physical networks change; refusing a broad route
alone does not make a stale raw IP unambiguous. Stable enrolled IDs/names can move
to new addresses, but stale raw-IP bookmarks cannot safely identify a peer once
that same address belongs to a LAN without an explicit quarantine/migration
contract. No forced foreign-route replacement is permitted.

No prototype source was pushed, deployed, installed on a client, or enabled in
production during this checkpoint. All disposable Mongo containers and their
unique test databases were independently confirmed removed after each batch.
