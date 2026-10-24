# Upstream provenance

Rathole v0.5.0, commit `ebb764ae53d7ffe4fcb45f83f7563bec5c74199d`,
from https://github.com/rathole-org/rathole. Apache-2.0; see LICENSE.

PortHub links this crate into its agent and edge. It does not launch a Rathole
subprocess. The upstream protocol, authentication, connection pools, and
forwarding implementation remain in use.

Local changes:

- Generate CLI build metadata using only Rust's standard library. Embedded
  builds no longer compile libgit2 or probe the enclosing repository; PortHub's
  own release identity remains supplied through PORTHUB_VERSION.
- Expose the validated configuration parser.
- Add `EmbeddedServer` and an injected-stream transport so an existing HTTP
  listener can supply connections without opening another communication port.
- Keep service reloads incremental, revoking removed/changed credentials.
- Cancel active TCP forwards on service revocation and reject handshakes that
  race service removal or credential rotation.
- Use rustls for TLS, including trusted-root and hostname validation. TLS server
  identities use PEM `certificate` and `private_key`; old PKCS12 identities must
  be converted before migration.
- Make the WebSocket request path configurable (default `/`) and return failed
  connection handshakes as errors instead of panicking.
- Propagate instance startup/task failures to the owning process and await
  instance shutdown instead of leaving a failed instance hidden in a task.

- Add optional `porthub_framing` and `http_upgrade` transport settings. Shared
  framing preserves TCP half-close and validates frame sizes; HTTP Upgrade
  retains buffered handshake bytes and bounds header memory. Upstream raw
  WebSocket mode remains the default. Flush authentication rejection packets
  before closing buffered transports.
- Framed client transports send 15-second idle heartbeats while their read is
  pending, keeping pooled channels alive through HTTP proxies. No additional
  timer task is spawned. Writes postpone idle heartbeats; partial heartbeats
  preserve frame boundaries, cancellation safety and bidirectional backpressure.
- Add an in-memory `EmbeddedClient` with incremental service reload, validated
  transport replacement and awaited shutdown. An unchanged service retains its
  control session and active forwards. Control actors own their pooled/active
  data tasks; UDP data tasks own their writer and per-source forwarders. Dropping
  ownership cancels descendants, including connection attempts and retry sleeps.
- Flush complete UDP datagrams and the initial UDP forwarding command so framed
  transports do not leave a lone packet buffered until another packet arrives.
- Closing a client configuration-update channel stops its runner rather than
  spinning on an immediately ready closed receiver. Normal control failure logs
  use labels; endpoint/error details are emitted at debug level.

- Add an authenticated SPKI SHA256 trust-anchor option to rustls transports.
  Full TLS 1.2/1.3 handshake signature verification remains enabled. Canonical
  hostname/SNI and HTTP Host can be preserved when dialing an origin address;
  unpinned endpoints retain standard public-CA/name verification.
- Expose a transport reachability probe that completes TLS and WebSocket/Upgrade
  negotiation without starting or authenticating a control channel. The agent
  can check configured alternatives independently of forwarded payload traffic.

Production rollout remains gated on compatibility, revocation, performance,
and client lifecycle verification. Vendoring is not proof of deployment parity.

- Server control handles now own their pool/control tasks. TCP pools own and
  drain their listener and copy tasks; UDP/control shutdown cancels blocked I/O.
  Embedded reloads await socket release, including active visitors and queued
  channels. Pending cleanup stays owned across cancellation, and a retried or
  unchanged reload waits for interrupted cleanup before reporting success.
  Replacement handshakes likewise retain the old handle until cleanup completes.
  This makes native edge snapshot acknowledgement reflect actual closure.

- Endpoint-only client rerouting retires control sessions while keeping their
  established TCP data tasks owned until completion. Retrying a broken control
  connection also retains active copies; retirement interrupts retry backoff.
  Service edits/removal and explicit shutdown still cancel retired copies.
- Gateway reconnects release the old TCP listener and idle channels before
  binding a replacement, then drain active copies under the replacement
  service's ownership. Failed replacement acknowledgements retain the previous
  generation in the service map. Token rotation, service deletion and shutdown
  cancel and join all generations. UDP pools retain their immediate replacement
  behavior. This change does not alter the Rathole wire protocol.
