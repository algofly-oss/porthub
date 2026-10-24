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
