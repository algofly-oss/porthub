# Public forwarding gateway

Public forwarding runs inside `porthub-api`. Agents connect to `/api/tunnel` on
an existing HTTP(S) API listener, using the `porthub.tcp.v1` WebSocket subprotocol.
There is no Rathole executable or dedicated agent port in the server image.
Public services still listen on their individually configured forwarding ports.
Private networking keeps its existing encrypted peer connections and access rules.

`api/internal/gateway` implements authentication, control channels, pooled data
channels, configuration reloads, and bidirectional TCP forwarding. Its protocol
is compatible with Rathole v0.5.0's TCP protocol, reviewed from
[`src/server.rs`](https://github.com/rathole-org/rathole/blob/v0.5.0/src/server.rs)
and [`src/protocol.rs`](https://github.com/rathole-org/rathole/blob/v0.5.0/src/protocol.rs)
(Apache-2.0). PortHub implements the gateway in Go and does not embed Rust code.
The shared framing code lives in `client/transport`; it preserves TCP half-close.

Payloads stream directly between sockets. They do not pass through MongoDB,
Redis, or a queue. Compression is disabled. Frame buffers are reused, and pooled
connections avoid a TLS handshake for each visitor. Stream and handshake limits
bound resource use. Removing a service or rotating its token closes its active
and queued streams without restarting other services.

## Addresses and fallback

`PORT_HUB_PUBLIC_BASE_URL` selects the canonical endpoint. HTTPS is preferred.
`PORT_HUB_FALLBACK_BASE_URLS` accepts comma-separated alternate base URLs of the
same server, including HTTP addresses and explicit ports. A matching HTTP URL of
the canonical hostname is also offered when the primary uses standard HTTPS.
Fallback addresses apply to tunnel connections, tenant CLI API requests, and
private-agent control requests. HTTP fallback is unencrypted; configure only
addresses you intend the agents to trust. Authentication failures and private
revocations do not trigger another endpoint attempt.

Private agents persist fallback addresses learned from an authenticated sync in
their existing mode-0600 profile. A working alternate control endpoint is reused
for 30 seconds before probing the primary again. Tunnel data channels stay on
the endpoint selected by their authenticated control connection.

For a CDN-backed domain, `PORT_HUB_DIRECT_HTTPS_BASE_URL` can name the origin
on the existing HTTPS listener (`443` or the app HTTPS port). The API advertises
its certificate key pin and canonical Host. Agents prefer this pinned TLS path
for payloads, with the canonical domain and configured HTTP addresses available
as fallbacks. The pin is checked on every handshake; unexpected certificate keys
are rejected. The API refreshes the advertised pin after an origin restart.

Gateway configuration lives at `/runtime/porthub/gateway.toml` by default.
`PORTHUB_GATEWAY_CONFIG_PATH` overrides it. Historical `RATHOLE_*` address/config
settings and download routes remain compatibility aliases for old installations;
they do not select or download a Rathole executable. The firewall retains its
existing nftables table name so an upgrade preserves access policies.

## Tests and performance

```sh
cd api
go test -race ./internal/gateway
# Optional reference interoperability test, using the official v0.5.0 binary:
PORTHUB_TEST_CLIENT_BINARY=/path/to/rathole go test ./internal/gateway \
  -run 'TestPortHubAgentRoundTrip/websocket=false' -count=1
# Same backend and PortHub agent for gateway comparisons:
PORTHUB_TEST_RATHOLE_BINARY=/path/to/rathole go test ./internal/gateway \
  -run '^$' -bench 'Benchmark(Stream)?(Gateway|Rathole)$' -benchtime=2s
```

Tests cover HTTPS, large transfers, TCP half-close, concurrent visitors,
authentication failure, revocation, and unchanged configuration reloads. Client
suites cover HTTP fallback and private-control profile persistence.

Use `BenchmarkStream*` for continuous transfers.
The request/response benchmark counts both directions and includes one round
trip per block; it is not a WAN bandwidth guarantee. HTTPS framing and encryption
have CPU cost relative to raw TCP. Validate actual throughput in both directions
and application response times on the deployment's network before retiring a
previous gateway. Keep the previous image available for rollback.

For an upgrade, first distribute agents that understand WebSocket URLs while
keeping their existing tunnel addresses. Then switch gateway ownership, keep the temporary TCP listener during
configuration delivery, and publish the new configuration. Verify the temporary
listener has no established connections before removing it. `PORTHUB_TUNNEL_GATEWAY_ENABLED=false` and
`PORTHUB_TUNNEL_WEBSOCKET=false` support that temporary distribution phase.
`PORTHUB_TUNNEL_LEGACY_LISTEN` enables an explicit temporary TCP compatibility
listener; it is unset during normal operation.

Local operator commands:

```sh
docker exec porthub porthub-api clients
docker exec porthub porthub-api clients --request-updates
docker exec porthub porthub-api audit
```

## Operator-controlled origin advertisement

Set `PORTHUB_GATEWAY_PUBLIC_IP` in `.env` to the exact IPv4 address authenticated
clients should receive. A configured address is authoritative: the gateway does
not query external IP-discovery services while it is set. An explicitly routed
private address is accepted too. The value is an address, not a CIDR or hostname.
Leave it empty to use the existing cached public-IP discovery sources.

The edge publishes its TLS listener port and public certificate-key pin through
its role-scoped volume; core mounts that directory read-only. Authenticated
origin responses include that metadata. Public tunnel configuration can advertise
an IP candidate with the same key pin and canonical Host/SNI. Clients check the
candidate outside packet forwarding and retain their domain fallback. Selecting
an advertised address does not guarantee that the address is reachable.

### External endpoint and TLS termination

Prefer `PORTHUB_GATEWAY_ADVERTISED_URL` when the external port differs from the
listener, for example `https://origin.example:18446` or
`http://203.0.113.10:18345`. This single URL overrides the older IP-only setting
and disables external IP discovery. The authenticated response includes its
exact scheme, host and public port; the tunnel URL uses that same endpoint.
The configured endpoint must belong to this gateway.

For example, an HTTPS domain with a forwarded HTTP origin can use:

```dotenv
PORT_HUB_PUBLIC_BASE_URL=https://porthub.algofly.in
PORTHUB_GATEWAY_ADVERTISED_URL=http://origin.example.com:18345
```

In this example the firewall forwards external TCP port `18345` to the edge's
HTTP listener (default `8345`). The HTTPS listener defaults to `8346`, with
`443` also available. API requests and tunnel communication share these edge
listeners; there is no separate Rathole control port. The advertised external
port must match the firewall mapping, rather than the internal listener port.

The public API URL remains independently configured through
`PORT_HUB_PUBLIC_BASE_URL`. Thus the API/domain can use HTTPS at a reverse proxy
while the origin serves HTTP. The HTTPS primary authority tells the HTTP edge
which external scheme to pass to core; arbitrary incoming forwarding headers
remain untrusted. Plain HTTP data transport is used only when explicitly
advertised. HTTPS origins validate either their authenticated key pin or, for an
operator-configured TLS-terminating proxy, a normal CA certificate for the
canonical authority. Manually supplied strict key pins do not automatically
permit a CA fallback.
