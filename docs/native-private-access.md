# Native private-access control plane

The Rust API implements these browser endpoints against the existing MongoDB
collections:

| Endpoint | Behavior |
| --- | --- |
| `GET /api/access/snapshot` | Workspace machines, members, groups, rule books, private peers, network preferences and administrator-visible invitations |
| `PUT /api/access/network` | Administrator-only validated CIDR and DNS suffix settings |
| `PUT /api/access/private/peers/{id}` | Administrator-only private enable/disable |
| `DELETE /api/access/private/peers/{id}` | Owner/admin revocation, or a member revoking their own private peer |
| `POST /api/access/groups` | Administrator-only named group creation with workspace duplicate detection |
| `PUT /api/access/groups/{id}/members` | Administrator-only machine/user membership with selector ownership checks and legacy group preservation |
| `POST /api/access/books` | Administrator-only rule-book creation with workspace selector validation |
| `PUT /api/access/books/{id}` | Administrator-only update requiring the current revision |
| `DELETE /api/access/books/{id}` | Administrator-only deletion requiring the current revision |
| `POST /api/access/test` | Authorized workspace policy preview using the native evaluator |
| `POST /api/access/private/sync` | Private-credential authentication, scoped peer/policy snapshot and fingerprint/instance-bound signaling |
| `POST /api/access/private/peers` | Enroll an authorized machine while preserving its assigned private identity/address |
| `POST /api/access/private/bootstrap` | Exchange a live one-time ticket for a private credential |
| `PUT /api/access/private/peers/{id}/hostname` | Set or clear an authorized peer's unique private name |

Workspace membership is read for each request. Writes check browser origin.
Inventory queries select the fields they need and responses exclude machine
tokens, password hashes, private credential hashes and fingerprints. Rule-book
and invitation projections also exclude unexpected stored fields. Members see
no pending invitations. Peer path reports are deduplicated and sorted.

Network settings preserve existing peer addresses and credentials. Disabling a
peer retains its credential for a later enable; revocation disables it and
removes its credential hash, fingerprint and process instance before consuming
its installer tickets and deleting incoming/outgoing signaling records. Cleanup
can be retried. Public machine credentials and forwarding configuration are not
modified by these operations.

Private names retain the original enrollment ordering, custom-name priority,
machine-name reservations and alias ownership. BSON ObjectIds and equal-looking
string identifiers remain distinct when joining machines. Existing unambiguous
names retain their legacy spelling. If the old four-character machine-ID suffix
also collides, a deterministic numeric suffix makes subsequent peer names
distinct. Names and addresses remain routing hints; transport authentication
must verify the enrolled peer ID and certificate fingerprint.

These endpoints report `transport_ready: false` where that field exists.
Private group mutation and both native and legacy-compatible relay endpoints
are implemented. Linux TUN/DNS/ICE/DTLS packet transport and bounded background
host/STUN/TURN discovery have local integration coverage. Windows/macOS private
runtimes, sustained route selection/failure recovery, service adoption and fleet
rollout remain unfinished. Inventory/control responses alone do not establish
that a registered machine is running the replacement agent.

Rule parsing, grant compilation, preview semantics and validation evidence are
described in [native-private-policy.md](native-private-policy.md).
Private sync protocol and verification scope are described in
[native-private-sync.md](native-private-sync.md).
Credential staging and its remaining lifecycle gates are described in
[native-private-enrollment.md](native-private-enrollment.md).

## Exit selection

Access rules → Routes lets an administrator select routing peers, consuming
machines, and a selection mode. Selections can include machines or groups.

- **Sticky** (default) uses a stable client-identity hash to choose the same
  available exit for that client’s new connections. Peer order does not affect
  the result.
- **Round robin** alternates new connections across available exits. It balances
  connection counts, not bytes; one large transfer can still dominate an exit.
- **Random** independently selects an available exit for each new connection.

A flow retains its exit identity when the selection mode changes. An offline
exit is excluded from new assignments after its presence lease expires. Existing
flows are not moved to a different exit NAT address: loss of their assigned exit
can interrupt them. This does not promise transparent TCP failover between public
source IPs.

Assignments are bounded to 65,536 flows. Authenticated replies refresh existing
assignments but cannot create them or change their exit identity. Established TCP
flows have a five-day idle lifetime; incomplete handshakes expire after five
minutes. Policy leases, revocation, and peer identity changes are enforced
independently of idle lifetimes.

The current exit data plane is Linux IPv4. IPv6 routing and other operating
systems remain rollout gates. While an exit is active, an owned IPv6 output
filter rejects new internet traffic so applications can fall back to IPv4. It
preserves conntrack-established traffic, loopback, link-local/multicast and
directly attached LAN prefixes. Explicit source binding cannot bypass this
filter. Disabling the exit or recovering its stale journal removes only the
owned filter. The disposable network test verifies blocked new sockets, blocked
source-bound sockets, an established UDP round trip, LAN access and restoration.
Do not describe this implementation as an IPv6 full tunnel. Local verification uses `scripts/verify-exit-network.py` with an
isolated test MongoDB: three native agent processes, two separate exit interfaces,
round-robin/sticky/random connections, a persistent TCP stream across mode
changes, and removal of an unused exit. These fixtures do not prove fleet
rollout or real Luna/Miro/Condor throughput.

## Device DNS policy verification

The private resolver handles both UDP and TCP queries on the same endpoint.
TCP clients are bounded, have a timeout, and close when the resolver shuts down.
Domain blocks return NXDOMAIN; address overrides return configured A/AAAA records.
These policies operate through the OS resolver. Applications using their own
DoH resolvers can bypass them, and DNS address overrides do not replace HTTPS
certificate validation or rewrite a URL path.

On 2026-10-27, the current native test binary passed on Miro against its actual
systemd-resolved service. An owned temporary interface registered test-only
suffixes. The test verified a private name, an address override, and an NXDOMAIN
block. Override and block queries used ordinary resolver selection (interface
index zero). Main routes and policy rules matched their pre-test snapshots;
the temporary interface and copied test binary were removed. This verification
did not replace Miro’s running registration or change its normal default route.

On 2026-10-27, `scripts/verify-exit-remote.py` ran native agents on the actual
Luna, Miro, and Condor hosts in disposable network namespaces. Miro consumed two
exits: Luna and Condor. Fresh HTTPS requests observed both hosts’ public egress
addresses. Round robin distributed eight connections 4/4; sticky used one exit
for all eight; random distributed sixteen connections 8/8 in that run (random
does not guarantee an even split). Production registrations were not replaced.
Test containers, networks, copied files, and control proxies were removed; host
policy-routing rules remained at their original defaults. This establishes
real-host exit selection, not bandwidth or seamless failover of an established
connection whose exit disappears.

The follow-up run with the IPv6 output guard passed on the same three hosts:
round robin 4/4, sticky 8/0, and random 11/5. The fixture now waits for the actual
consumer selection mode and two available exits before measuring a phase. A
fixed five-second sleep could race the five-second background sync and briefly
measure the previous strategy. Received policies now update selection immediately;
the periodic tick refreshes availability without moving existing assignments.
The isolated native-agent test also passed with a persistent TCP connection
across all three mode changes and removal of an unused exit.
