# Firewall source observations

The native firewall keeps connection-attempt/security telemetry in `incoming_ips`
unchanged. It can include sources later blocked by a port policy and refreshes on
new connections. Do not use it as a list of accepted clients.

New samples separately expose `accepted_incoming_ips` and its
`accepted_incoming_ips_window_seconds` / `accepted_incoming_ips_address_families`
provenance. These are source addresses of TCP packets allowed by PortHub's own
port policy during that observation window. Every matching packet refreshes its
source, including packets on long-lived connections. IPv4 and IPv6 are supported;
restricted IPv4 allowlists continue to deny IPv6 as before.

The window is explicitly reported, normally the sampling interval plus one
second, with a two-second minimum and a 300-second maximum. The kernel retains
addresses for up to 300 seconds; each snapshot filters their remaining expiry to
the reported, narrower window. Missing expiry cannot substantiate an observation.
The retention timeout is not the reported observation window.

`null`/missing provenance means unavailable or older telemetry. An empty array
with valid provenance means no sources were observed in the window. Storage
migration preserves older samples as unavailable; it never relabels attempted
sources as accepted ones.

Observation sets hold at most 4,096 addresses per port and address family, so
these are bounded observed sources, not an exhaustive audit log. Tracking runs
in separate rules from authorization and byte accounting: a full tracking set
cannot drop an otherwise allowed packet or suppress its byte counter. PortHub's
allow decision does not prove application delivery, successful authentication,
or acceptance by another firewall's later base chain. It does not provide
per-source byte counts.

Kernel integration tests run only in disposable network namespaces with
`NET_ADMIN`, isolated networking, a read-only test executable and no host nftables
access. They cover established-flow refresh, blocked attempts, expiry windows,
IPv6, full-set forwarding, port isolation, and preservation of foreign tables.
