# Sparse private-network prototype — not a release capability

This isolated prototype is based on `dcc9aed45d8800d177c9338fa44d910f82b25d0f`.
The `private-sparse` Cargo feature is deliberately absent from both API and agent
default/release feature sets. Pool growth is a separate implemented feature; this
prototype does not establish unlimited devices, full-mesh throughput, or automatic
range migration.

Implemented contracts:

- A negotiated base identity plus independently expiring, exact-direction pair
  grants. Fixed-size directional protocol/port masks preserve complex unions
  without transmitting/truncating a growing grant list. Four worst-case masks
  occupy under 45 KiB of JSON and at most 32 KiB of decoded bitmap storage per
  pair. Canonical encoding and exact two-identity validation are independent of
  the API; legacy grant snapshots retain their existing format. Local authority epochs, remote identity revisions, certificate/process
  pins, cache capacity and packet/stream authorization remain distinct.
- Indexed current peer/address, machine, workspace-membership and user checks.
  No positive credential, membership, address or pair decision is cached by the API.
  Immutable rule selector indexes are keyed by a freshly read book revision
  manifest and rechecked before publication. Covered group queries return only
  relevant IDs, not entire user-membership arrays.
- A separate DNS directory materializes existing name-assignment semantics on
  bootstrap, name changes and periodic refresh. Directory names never authorize
  a machine: current metadata, membership, assignment and rules are checked again.
- One shared 65,536-private-flow admission budget covers all child pair engines;
  their count cannot multiply that map limit. Revocation, expiration cleanup and
  drop release permits. The existing separate exit-flow budget is unchanged.
  Live packet/QUIC flows remain eligible for fresh gateway renewal, without any
  local deadline extension or revival after source revocation.
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
  or quarantining later freshly authorized recovery. Tickets are per request,
  including overlapping reads from the same process. Credential rejection pins the
  ticket before its database read. Pair publication checks that ticket and the
  target credential/process/address/policy binding. Negative decisions retire only
  the incident pair generation observed before target authorization reads, rather
  than confusing its old authority epoch with the newly denied policy epoch.
  Retirement invalidates target-side uncommitted reads so they must revalidate;
  already committed unrelated pair/base leases are preserved. Established QUIC copies have their own deadline/renewal
  guard rather than relying on a periodic base-policy tick.
- Cold custom private suffixes are published as bounded namespace-only metadata,
  independently of selected pair identities. The actual private-domain mutation
  path invalidates that materialization under its publication lock before the
  write; failed writes/recovery still require a complete rebuild. No partial
  namespace is published when its explicit suffix/byte budget is exceeded.
- A changed local address cannot be applied to an already-configured TUN/DNS
  listener. It ends the private worker; the existing supervisor closes its old
  resources before restarting with the new address and unchanged registration.
- Shared collision planning and Linux/Windows/macOS owned capture-prefix adapters.
  A private prefix routes packets to the ACL engine; it never grants permission.
  A newly conflicting prefix cannot force itself over an existing LAN/VPN route.

Evidence so far:

- An actual isolated MongoDB 7 test inserts 4,097 registered peers, including the
  unique workspace/address index that normal enrollment already creates. A sparse base
  and exact pair lease stay below 16 KiB of response JSON; a legacy oversized
  snapshot fails with an upgrade/narrow-rule explanation.
- With the custom-namespace fixture, a warm broad lookup examined 18 documents /
  21 keys with 8,821 bytes of Mongo responses. A representative explicit-group
  case with 4,097 distinct users examined 18 documents / 23 keys with 8,908 bytes. Rule-manifest and group queries
  examined zero documents through covered indexes. These are 2–3 API callers,
  not 4,097 running agents or a full-mesh throughput benchmark.
- Actual target-only group removal leaves the source epoch unchanged but retires
  its installed target pair and preserves an unrelated pair/base. Book revocation
  changes the epoch and removes remaining grants. Removing source workspace
  membership returns HTTP 403; the client rejection regression begins with an
  unexpired installed pair and verifies immediate cache/DNS/work cancellation.
- The same Mongo fixture calls the real machine-update route to add a custom
  suffix to a cold peer, immediately receives that suffix without exposing the
  cold identity in the base snapshot, then resolves its exact authorized name.
  Local DNS proxy regressions prevent both default and custom private misses from
  falling through even when public queries are forwarded. Native OS resolver
  registration and dynamic configuration propagation are not established by these
  portable/API tests.
- Portable engine, resolver, DNS, rule-index parity, stream-deadline and HTTP
  rejection regressions pass. Windows x64/ARM64 and macOS x64/ARM64 adapter metadata compile
  against the actual platform source; metadata compilation is not native route
  execution.

Remaining release blockers include coherent sparse exit/LAN-exit/Tor/proxy paths,
automatic server/client range migration when required, lifecycle/native route
proofs on all three OSes, directory mutation/concurrency tests, definition/index/compilation resource admission, measured renewal/admission
fairness under load, and final
standalone-Mongo mutation/identity-race audit. Existing known-host /32 routes must
also be reconciled safely when physical networks change; refusing a broad route
alone does not make a stale raw IP unambiguous. Stable enrolled IDs/names can move
to new addresses, but stale raw-IP bookmarks cannot safely identify a peer once
that same address belongs to a LAN without an explicit quarantine/migration
contract. No forced foreign-route replacement is permitted.

No prototype source was pushed, deployed, installed on a client, or enabled in
production during this checkpoint. All disposable Mongo containers and their
unique test databases were independently confirmed removed after each batch.

The sparse reply reserves a separate 2 MiB pair budget and enforces the existing
4 MiB full control-response bound. A byte-budget rejection is `busy`, retains the
exact query, and does not renew the Hub pair authority. Compilation still has
explicit definition/index/input budgets; this is not arbitrary rule-book scale.
A 256-entry cache and a bounded 16-intent RPC are not proof that 256 active pairs
can be renewed fairly under every WAN latency. That scheduling/admission work and
whole-process RSS measurements remain open. No total-transport RAM claim is made
from the bitmap or flow-count limits alone.

The read/publication fences above do not establish transactional atomicity for all
MongoDB policy mutations. Group/member/address/credential mutation journaling,
concurrent mutation tests and the complete writer audit remain required. The Hub's
current incident-pair discovery also scans its bounded global 8,192-pair table;
the 4,097-record/2-pair fixture is not evidence of constant work with 8,192 active
pairs or many simultaneous policy editors.


### Native route revalidation checkpoint (still private)

The next checkpoint connects the planner to the real route readers on Linux,
Windows and macOS. Route-only notifications wake a separate audit without
restarting ICE when the underlay address list is unchanged. A five-second audit
also covers missed notifications. Before publishing a new pair to the local DNS
cache or stream router, the packet owner checks retained peer `/32` routes and
pool captures against the fresh native table. Conflicting peer authority is
retired individually; an unrelated pair and the base lease remain intact. Known
hosts outside a conflicting subnetwork can retain unambiguous `/32` routes;
ambiguous addresses are not forced over the LAN. An own-address collision stops
the private worker with a range-migration error.

A macOS resolver expansion now retains its existing byte-verified owned suffix
files until every addition succeeds. Failed additions remove only their own
new files. Successful updates transfer ownership before retiring obsolete
suffixes, and externally edited files are neither adopted nor removed. The
same-interface Windows DNS guard no longer clears settings just installed by
its replacement. These lifecycle improvements do not establish Windows private
namespace routing: explicit NRPT ownership/rollback remains required, because
an interface search list is not a suffix-routing policy.

Portable planner, route-notification and selective pair-retirement tests and
extracted actual macOS resolver-file transaction tests are distinct from actual
OS execution. Native platform metadata compilation is also not a route fixture.
The prototype has not changed any host network state.

Windows Wintun ownership remains an explicit blocker. The pinned tun-rs layer-3
builder may reopen a same-named adapter; its `reuse_dev(false)` setting applies
only to TAP. No arbitrary existing adapter may be configured or deleted. Safe
recovery must use a protected profile-bound pre-creation GUID journal under the
profile lease, verify the actual adapter and recorded configuration before
mutation, and recover legitimate stale owned instances rather than permanently
rejecting all unclean restarts. Linux policy-routing/VPN rules and macOS local
address routes also require native lifecycle verification. Server renumbering,
three-OS resolver ownership, sparse exits/Tor and load fairness remain open.


### Windows ownership and NRPT source checkpoint (native proof pending)

The isolated source now writes a privileged, profile/path/identity-bound Wintun
intent before creation, opens without assigning an address, and verifies the
actual GUID/name before configuration. A separate ownership lease prevents a
live owned adapter from being mistaken for a stale instance. Protected records
retain the baseline and acknowledged explicit routes. Pending route intents are
not confirmed ownership: an ambiguous live row after an interrupted add is
preserved and fails actionably. Missing rows can be repaired; normal stale owned
configuration can be recovered. A freshly proven absent adapter can rebind its
address with the same identity. Unknown legacy/name-only adapters, renamed GUIDs,
foreign addresses/metrics and unexpected route rows are not adopted or deleted.
Cleanup removes only verified own rows/address and stops the own session; an
opened stale adapter keeps its protected recovery record.

Windows private namespace routing now has a source implementation using exact
local NRPT apex/suffix rules, not only an interface search list. One hidden,
bounded one-shot PowerShell process reads a protected journal, checks local and
effective policy conflicts, records each addition's exact marker before mutation,
then checkpoints returned rule GUIDs. Failed updates restore the committed set;
a killed transaction is recovered from its recorded intents. Obsolete entries
are removed only after additions become effective. No GPO or global DNS setting
is written. A journal hash fences concurrent record changes. Explicit async
shutdown and a bounded cancellation fallback clear exact owned rules; failures
retain the journal and are not reported as cleanup success. Endpoint changes
first clear the exact old owned policy. The listener binds an exclusive deterministic 127/8 loopback endpoint derived
from the private address. A stale rule therefore cannot send private names onto
a LAN after the TUN disappears. Alias bind/routing support remains a required
Windows native test; collisions fail rather than reusing another listener.

These are source and portable-contract results. They do not prove actual Wintun
or NRPT lifecycle on Windows, PowerShell 5.1 provider behavior, complete detection
of changes to native route flags, or absence of OS-level parallel public DNS
queries. The disposable opt-in native validation design is recorded in
`sparse-windows-native-validation.md`; it has not been dispatched or run. The
feature remains default-off and unmerged; the broader registration/range goal
still requires the previously listed migration, exit/Tor and fairness work.


Independent review of frozen `6bae7f0` found a missing broad-route journal
retirement and a non-exclusive Windows DNS bind. Follow-up source retires route
claims before native removal, retains non-authorizing diagnostic tombstones,
uses removal permits, and fences the unshipped old record format. It explicitly
sets/readbacks Winsock `SO_EXCLUSIVEADDRUSE` before UDP/TCP bind. The retained red
recovery test reproduces old stale-prefix adoption; the new failure/restart
contracts pass. Ignored native adversarial socket cases compile but are not
native execution proof. At that checkpoint, the 320-row ownership journal's legacy-4096 compatibility
remained a blocker; the later common-budget source checkpoint below addresses
its scalar admission without implying native scale validation.


A second independent review of `15d12d3` found that observing an externally
missing route could prune memory without retiring its journal claim. Follow-up
verified-inventory processing now checkpoints that absence before memory changes
or early return. Repair requires a new pending intent plus native add
acknowledgement; diagnostic expiry cannot reauthorize a row. The frozen-source
red and five portable failure/repair/restart regressions are retained. These
remain source/contract checks, not Windows native lifecycle proof, and did not yet
resolve the legacy ledger-capacity blocker addressed by the next source checkpoint.


The common ownership budget now derives from the unchanged 4096-identity legacy
limit (4095 remote host rows), the unchanged 256 sparse-pair limit, 32 capture
prefixes and the prior maximum 320-row baseline allowance. It admits 4447 total
ownership rows in a bounded 512 KiB record, with disjoint phases and one pending
add. No persisted mode or arbitrary budget field is trusted. Actual current-mode
host admission is checked before native writes; obsolete hosts retire before
new additions, so replacement and legacy/sparse handover do not need two full
route generations. Max-shape codec, overflow and handover contracts pass; the
network Engine still rejects 4097 legacy identities. This removes the scalar
320-row journal mismatch in source. Native full-size I/O/latency, lifecycle,
range migration, sparse exit/Tor and fairness remain unverified/open; it is not
proof of thousands of running agents or full-mesh reachability.
