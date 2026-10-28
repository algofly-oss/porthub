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
minutes. A single FIN preserves the half-closed stream. Both FIN directions cap
the remaining lifetime at two minutes, so completed connections release capacity
without later ACKs extending it. RST removes policy state and retires the exit
assignment after the same grace period. A new SYN sequence on a reused tuple
starts a new selection; retransmissions retain their original exit. Policy
leases, revocation, and peer identity changes are enforced
independently of idle lifetimes.

Linux agents provide exit egress. Linux and macOS consumers route IPv4 TCP,
UDP, and ICMP echo at the IP layer, independently of the originating application.
The transport to an exit uses the same cached quality decisions and flow pinning
as private peer traffic. Parallel application connections benefit independently;
the agent does not turn a single TCP stream into multiple application connections.
HTTP keep-alive and HTTP/2 requests sharing a connection retain that connection's
exit, even with round robin selected.

Standard Linux Docker bridges (`docker*` and `br-*`) follow the host policy.
Owned forwarding and source translation bind container packets to the enrolled
host identity. Conntrack pins established container flows during fallback and
recovery, and incoming published-port replies keep their original route.
Explicit packet marks used by other routers are preserved. Custom bridge names,
container VPNs, and custom routing remain separate configurations. Docker Desktop
on macOS/Windows runs inside a VM and is not covered by the Linux bridge tests.

IPv6 exit forwarding is not implemented. While an exit is active, Linux rejects
new IPv6 internet traffic while preserving established connections and attached
LAN prefixes. macOS preserves local IPv6 and established TCP, but restricts
non-TCP internet IPv6, including existing UDP, for the active policy's duration.
Neither implementation is an IPv6 full tunnel. Cleanup removes only the owned
filter and routes. The macOS consumer keeps the ordinary default route and adds
an owned interface-scoped physical route so gateway heartbeats and peer sockets
continue outside the exit. A root-only journal recovers owned changes after a
crash. Local verification uses `scripts/verify-exit-network.py` with an
isolated test MongoDB: three native agent processes, two separate exit interfaces,
round-robin/sticky/random connections, a persistent TCP stream across mode
changes, final responses after a client half-close, and removal of an unused exit. These fixtures do not prove fleet
rollout or real Luna/Miro/Condor throughput.

## Embedded Tor state lifecycle

Tor runs inside the agent and opens no local listener for exit routing. Circuit
state and directory caches belong to the registration's dedicated `.tor`
directory. Stopping Tor retains these files for the next bootstrap. Removing a
registration with credential purge also removes its Tor directory after its
runtime has stopped. Cleanup rejects a symlink in place of that directory and
does not follow nested symlinks into other application data.

Explicit `porthub proxy start --via tor` jobs use their own per-user proxy-state
cache, shared between that user's jobs. Stopping a job removes its credentials,
curl configuration and job files; it retains the Tor cache for later jobs.

`porthub tor start --system-wide` is a separate, administrator-authorized local
override. The registered private agent applies an Internet-only Tor exit while
leaving local and private destinations direct; traffic Tor cannot carry is
blocked. It does not change the gateway policy. `porthub tor reset` removes the
override and resumes the UI policy. The standalone proxy and system-wide mode
use separate Tor pools, so both can run at the same time.

macOS preference notifications retain one directory vnode and one kqueue per
watcher, without enumerating sibling Tor caches or upgrade backup directories.
General application and transfer watches explicitly use FSEvents. This selection
is independent of Arti's additive `notify` backend features. A native regression
exercise populated 1,280 cache files and repeatedly replaced preferences while
running all three application watches; descriptor count returned to its baseline
after cancellation. The small `vendor/notify` patch exposes both macOS backends
without changing the upstream default selection; see its patch notes.

## Device DNS policy verification

The private resolver handles both UDP and TCP queries on the same endpoint.
TCP clients are bounded, have a timeout, and close when the resolver shuts down.
Domain blocks return NXDOMAIN. DNS address replacement is not supported.
These policies operate through the OS resolver. Applications using their own
DoH resolvers can bypass them.

On 2026-10-27, the current native test binary passed on Miro against its actual
systemd-resolved service. An owned temporary interface registered test-only
suffixes. The test verified private name resolution and an NXDOMAIN
block. Block queries used ordinary resolver selection (interface
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

The 1.5.2 connection-lifetime fix passed 139 native agent tests, including
authorized tuple reuse and bounded cleanup without expiring half-closed streams.
The isolated three-agent test verified final responses and orderly shutdown
after a client half-close in every selection mode. A further Miro test through
Luna and Condor exits produced round robin 4/4, sticky 0/8, and random 3/13.
These are functional connection-distribution checks, not throughput benchmarks.

## All exits unavailable

Each route defaults to blocking internet traffic when no exit is available.
`allow_direct_fallback: true` permits new connections to use the client's normal
internet connection after five seconds of continuous unavailability, following
peer presence/transport availability detection. Five seconds of stable recovery
returns new connections to exit routing. Withdrawing permission or losing the
policy lease ends bypass immediately. Existing overlay-source flows keep their
exit route; connections opened through the normal interface retain that path.
This does not repair a TCP connection whose exit disappeared. The owned IPv6
filter permits normal IPv6 during bypass while retaining connection tracking,
then blocks new IPv6 internet flows after exit routing resumes. Private-network
ACLs and DNS controls remain enforced. Only the PortHub-owned catch-all rule and
IPv6 filter mode change; host default routes and management connections remain.

## DNS scopes and native macOS handover

Machine DNS settings offer an exact name, a name with all subdomains, or a
`*.example.com` wildcard that excludes the apex. Only unmatched queries inside
those configured resolver domains are forwarded to the machine's existing DNS
servers. Private identity zones remain authoritative and are never forwarded.
Forwarding has bounded concurrency and timeouts, supports UDP and TCP, validates
response identity, and refreshes upstream settings lazily without idle polling.
System stubs and PortHub's own resolvers are excluded to prevent recursion.

The native macOS public service can adopt its matching generated private service.
It checks machine/gateway identity, journals the original resolver configuration,
and restores the legacy service if native readiness fails. Operator-stopped
private services remain stopped. Installing a healthy candidate on the Mac
verified both native services, private SSH access to Luna and Miro, Instagram
blocking in Chrome with its default DNS settings, and unrelated HTTPS access.
The DNS wildcard apex/child check also passed against the Mac's actual upstream.

`porthub status` reports the paired private agent, policy lease, rule counts,
configured exit peers, selection mode, and applied routing/fallback state.
On Linux, gateway HTTP and public tunnel sockets bind to the physical source;
source changes affect future channels while established streams are retained.
Disposable-network tests verified new heartbeat and tunnel SYN packets escaping
a dead exit while application packets still follow the configured exit policy.


## macOS and container qualification for 1.6.0

A native Mac candidate passed a guarded full-route test: four HTTPS requests used
both configured exits, gateway access remained available, and LAN, private-peer,
and external SSH connections succeeded. A separate native consumer test verified
normal-internet fallback, reactivation, and removal of owned routes and PF state.
The installed release and ordinary internet route were restored after testing.
The Mac has no Docker installation, so container tests run on Linux.

The disposable Linux full-agent test additionally verifies UDP egress identity,
ICMP echo, and an established UDP flow across selection changes. Its existing TCP
checks cover round robin, sticky/random selection, half-close, an offline exit,
blocked all-exit outage, opt-in normal fallback, and stable direct flows on
recovery. An isolated forwarding test injects container-source traffic through
the actual kernel NAT/conntrack path, reproduces Docker's forwarding policy,
verifies return translation and preservation of incoming service replies, pins
flows across fallback/recovery, and checks exact cleanup of owned Docker rules.
These checks establish functionality; they do not establish new exit-route
throughput measurements or Docker Desktop coverage.
