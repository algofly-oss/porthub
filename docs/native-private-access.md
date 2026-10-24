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
