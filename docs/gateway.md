# Public forwarding gateway

Public forwarding runs in the Rust `porthub-edge` process. Agents connect to
`/api/tunnel` on an existing HTTP(S) API listener using the
`porthub.tcp.v1` WebSocket subprotocol. It needs no dedicated Rathole control
port. Published services still use their individually configured external
ports.

The edge role streams payloads directly between sockets. It does not send
payloads through MongoDB, Redis, or a queue. Compression is disabled, buffers
are reused, and pooled data connections avoid a TLS handshake for each visitor.
Configuration reloads close removed services and revoked tokens without
restarting unrelated services. The Rathole-compatible forwarding implementation
is embedded in the Rust gateway; no separate Rathole executable is required.

## Addresses and fallback

`PORT_HUB_PUBLIC_BASE_URL` selects the canonical endpoint.
`PORT_HUB_FALLBACK_BASE_URLS` accepts comma-separated alternate base URLs for
the same gateway, including HTTP addresses and explicit ports. HTTPS is
preferred. Configure only HTTP endpoints agents are intended to trust because
HTTP does not encrypt credentials or payloads. Authentication failures and
private revocations do not trigger endpoint fallback.

Private agents persist authenticated fallback addresses in their mode-0600
profile. A working alternate control endpoint is reused briefly before the
primary endpoint is probed again. Tunnel data channels stay on the endpoint
selected by their authenticated control connection.

For a CDN-backed domain, `PORT_HUB_DIRECT_HTTPS_BASE_URL` can advertise the
origin on an existing HTTPS listener. The API advertises its certificate key
pin and canonical Host; agents validate the pin on every handshake and retain
the canonical domain as a fallback. Alternatively,
`PORTHUB_GATEWAY_ADVERTISED_URL` sets the exact externally reachable scheme,
host and port. It takes precedence over `PORTHUB_GATEWAY_PUBLIC_IP` and disables
external IP discovery. These authenticated advertisements describe candidates;
they do not guarantee reachability.

Gateway configuration is shared through the scoped routing-config mount and is
overridable with `PORTHUB_GATEWAY_CONFIG_PATH`. Historical `RATHOLE_*` settings
and download routes remain compatibility aliases; they do not launch or fetch
an external Rathole binary. The firewall retains its existing nftables table
name so upgrades preserve access policies.

## Performance checks

Use the recorded comparisons under `docs/benchmarks/` for tested workloads.
They distinguish local transport microbenchmarks from WAN throughput and
application-level response times. Validate both transfer directions and the
actual deployment network before treating a result as a capacity guarantee.
