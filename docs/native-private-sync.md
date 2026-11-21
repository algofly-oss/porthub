# Native private-peer sync and signaling

`POST /api/access/private/sync` authenticates against an enabled peer's private
credential hash. A public machine token cannot authenticate this endpoint.
Active inventory checks workspace membership, machine ownership, enabled state,
pending deletion and revoked private ownership. Authentication precedes index
initialization and presence updates. The current credential, process instance,
certificate fingerprint, machine state and workspace membership are checked
again before returning the response.

The endpoint compiles only the caller's incident policy grants and returns the
corresponding peers, enrolled IDs, fingerprints, instances and assigned DNS
names/aliases. Other workspace peers and credentials are excluded. The snapshot
has a 15-second lease and a UTC RFC3339 expiry, as required by the existing Go
client's timestamp decoder. Peer advertisements are not a substitute for the
agent validating the actual remote certificate during its transport handshake.

Signaling accepts the existing offer, answer and trickle-candidate messages.
Offers follow the deterministic peer-ID ordering; candidates require exactly
one candidate line and a bounded payload. All fingerprint lines must match the
authenticated sender's advertised SHA-256 fingerprint. Message IDs deduplicate
retries while binding both peers' IDs, process instances and certificate
fingerprints. Recipient restarts or certificate rotations produce a new
context, and stale source/target contexts are not delivered. An address in a
candidate never establishes peer identity.

Acknowledgements delete only messages addressed to the authenticated peer.
Incoming delivery is limited to 128 records and excludes expired messages even
before MongoDB TTL cleanup. Signal records expire after 45 seconds. Input has
limits of 16 signals, 128 acknowledgements and 1,000 path reports, in addition to
the API body limit. The expiry/recipient lookup indexes initialize once per
application instance. No new background worker or listening port is introduced.

The API parses `PORTHUB_PRIVATE_ICE_SERVERS`, `PORTHUB_RELAY_ROUTES` and
`PORTHUB_RELAY_SECRET` once during configuration loading. Configured ICE entries
and relay routes have count/size limits. When the relay secret meets the existing
length requirement, the response can issue peer-scoped, 12-hour TURN REST
credentials using the existing HMAC-SHA1 format. This compatibility metadata
does not implement a TURN or gateway relay service. Explicit configured gateway
fallbacks are returned without replacing the saved primary authority.

Ten retained ClientSync model fixtures cover field validation and error ordering.
The old Python fixture's one offer/answer enum-error expectation is expanded to
include the current Go implementation's existing trickle-candidate extension.
Native tests additionally cover certificate/candidate validation, a reference
TURN credential, credential separation, policy-scoped discovery, deduplication,
acknowledgement ownership, source/target restarts and certificate rotation,
expired messages, disabled/deleting machines and revoked membership.

These tests exercise the native router and isolated MongoDB. Subsequent native
transport tests also exercise real UDP certificate possession, Go reference
interoperability, native API signaling followed by gateway-independent payload
transfer, and the native authenticated gateway WebSocket fallback. See
`native-private-transport.md` for the implemented Linux packet/DNS runtime and
remaining STUN/TURN, route measurement, fleet scheduling, platform and physical
benchmark gates. A physical sustained-bandwidth acceptance result is still
required before this migration can be called complete.

### Reauthorizing an established TCP connection

An updated Linux or macOS agent can preserve an ordinary private TCP connection across a brief gateway outage. It discards packet queues and grants at expiry. Both endpoints must obtain fresh base and peer authorization and confirm the same original TCP handshake. The agent retains at most 256 openings across 32 peers for 35 seconds. After a new pair is installed, the confirmation window is six seconds. A policy edit, host sleep, agent restart, loss of identity, or failed confirmation returns the connection to normal application reconnection. UDP, exit routing, and offloaded streams use their existing recovery behavior.

The gateway issues continuity witnesses only after every writer uses the deployed fencing protocol, PORTHUB_PRIVATE_CONTINUITY_FENCED_WRITERS=all-v1 is set on the issuing gateway, and the shared fleet epoch is explicitly enabled. This setting attests that **every** process writing private policy or enrolled identities in the shared database runs the matching write-fence protocol. Finish upgrading and draining all older writers before enabling it. Disable the setting on every gateway before running an older writer, restoring the database, or editing policy outside the application. An older gateway or agent automatically uses the ordinary reconnect path.

The durable fence covers the beginning and end of authorization. Concurrent or ambiguous policy writes withhold the witness from the affected scope. Normal fresh DNS and private connections continue. For automatic recovery after a gateway process terminates, persist its exclusive writer slots under /data/private-policy-writers (override with PORTHUB_PRIVATE_CONTINUITY_WRITER_DIR). On standalone MongoDB the gateway verifies that the former process released its slot and that Mongo has drained all connections and operations bearing its writer tag. This verification requires permission for the $currentOp aggregation with allUsers enabled. If either proof is unavailable, the gateway continues using fresh connections.

During bilateral reauthorization, a new worker may quarantine one newly read local TCP segment per matching connection. It checks the original TCP opening and observed sender sequence window. On Linux a newly attached, read-only TUN queue can see retries before base recovery. On macOS the worker first proves the owned utun receive queue is empty and then accepts newly written local retries. The agent uses ordinary reconnection if it cannot prove the queue or source owner. The worker discards unconfirmed segments after eight seconds and reserves at most 32 segments total. The validated sending window after fresh pair admission is two seconds. Delivery requires the receiving peer to confirm it has installed the exact TCP opening, a live local flow owner, and both the original and current base and pair grants. The worker discards its buffer on exit. An unconfirmed peer or an expired window leaves retransmission to the native TCP stack.

A warm proof uses one fresh indexed MongoDB read after admission. The earlier observation may come from a preceding request. A changed or busy scope fails the comparison. The cache is capped at 4,096 workspaces and optional proof reads have a 200 ms deadline. Each scope admits up to 128 concurrent policy writes, with excess writers receiving a retryable 503.

#### Activating a deployed fleet

The Compose core reads `PORTHUB_PRIVATE_CONTINUITY_FENCED_WRITERS` and persists its writer slots under the existing `/data` volume. The installation default is `off`. Agents negotiate automatically using their existing private enrollment.

1. Inventory every gateway, job and administrative process that can mutate enrolled identities, private ACLs, groups, DNS, virtual hosts or network assignments in this database. Record their image digests and the last healthy deployment. Keep the existing renumbering setting throughout this procedure.
2. Upgrade every writer to the same verified fence-capable release. Set `PORTHUB_PRIVATE_CONTINUITY_FENCED_WRITERS=staged-v1` in each deployment's environment. Recreate the core using its normal release procedure. Staged writers record every relevant mutation and continue ordinary admission without issuing a witness.
3. Drain or stop every previous writer and verify the running image digests against the inventory, including other replicas and out-of-band jobs. Keep direct database editing paused. Check each core's existing startup and HTTP health, existing private DNS and a fresh authorized connection. From the deployment's Compose directory, `docker compose exec -T core porthub-api --private-continuity status` reports the process mode and persistent fleet state. A status command on one gateway cannot inventory other writers.
4. Change every staged writer to `all-v1` and recreate it. Confirm each has `process_mode=all-v1`. For an initial activation, the shared database must still report `fleet_enabled=false`. Execute `docker compose exec -T core porthub-api --private-continuity enable` once, then read status through every replica. Verify the same generation and `issues_witnesses=true` everywhere. This command creates a new durable generation and preserves all outstanding writer tickets.
5. In a designated test workspace, verify an ordinary private connection and repeat the short-outage test on the same existing application connection. Verify a deny followed by a regrant during the outage rejects the original operation and a newly authorized connection succeeds. Exercise an older client to verify fresh reconnection. Review gateway health and latency during the test.

For rollback, run `docker compose exec -T core porthub-api --private-continuity disable` from a capable image while the writers still use the fencing protocol. Verify `fleet_enabled=false` through every replica and use ordinary private connections for health checks. Wait 35 seconds for previously issued lease and continuity evidence to drain before downgrading a writer, permitting direct database writes, or restoring storage. Restore the recorded image and environment through the deployment's normal rollback, preserving the renumbering hold. Repeat the complete staging and inventory procedure before enabling a new fleet generation. Every enable and disable rotates the stored generation, including a reactivation with unchanged final ACLs. Missing activation state disables the optimization.
