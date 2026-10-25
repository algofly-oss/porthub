# PortHub transfer benchmark summary

These runs describe the specific machines, releases, routes and workloads
tested at the time; they are not general performance guarantees. The 1.4.1
historical runs used a 10 GiB sparse, zero-filled payload served by
`porthub http.server`, downloaded with `porthub get` using 16 connections, and
SHA256-checked. The 1.4.3 candidate runs below use the same 1 GiB file and
SHA256 on every path.

| Test | Route and workload | Result | Interpretation |
| --- | --- | ---: | --- |
| Luna → Condor, PortHub 1.4.1 | Private `luna.phub`, 10 GiB, 16 connections | 38.37 MB/s; ~280 s | SHA256 verified. Live peer status selected gateway relay. |
| Luna → Condor, PortHub 1.4.1 | Public mapping `algofly.duckdns.org:13367`, 10 GiB, 16 connections | 49.15 MB/s; ~218 s | SHA256 verified; about 393 Mbps, near Luna's stated 400 Mbps ISP limit. |
| Miro → Luna, PortHub 1.4.1 | Private `miro.phub`, 10 GiB, 16 connections | 111.73 MB/s; ~96 s | SHA256 verified; live peer status selected direct transport. |
| Luna → Condor, PortHub 1.3.4 | Private `luna.phub`, 10 GiB, 16 connections | 44.38 MB/s; 242 s | Hash verified. Peer status selected gateway relay, so this is not a direct-path result. |
| Luna → Condor, PortHub 1.3.4 | Public mapping `algofly.duckdns.org:13367`, 10 GiB, 16 connections | 49.12 MB/s; 219 s | Hash verified; about 393 Mbps, near Luna's stated 400 Mbps ISP limit. |
| Miro → Luna, PortHub 1.3.4 | Private `miro.phub`, 10 GiB, 16 connections | 111.76 MB/s; 96 s | Hash verified; peer status selected direct. Gateway TX increased by under 35 MB during the transfer, confirming payload bypass. |
| Luna → Condor, prior Go agent | Private domain / public mapping, 10 GiB | 24.6 / 48.3 MB/s | Public reached about 387 Mbps, near Luna's stated 400 Mbps ISP. |
| Luna → Condor, Rust transfer tools over prior Go agents | Private / public, 10 GiB | 14.4 / 48.8 MB/s | Public near 390 Mbps; private regressed in this candidate. |
| Luna → Miro, prior Go agents | LAN / private IP / private domain, 10 GiB | 111.0 / 108.8 / 109.2 MB/s | About 0.28 ms ping; direct LAN UDP observed. |
| Miro → Luna, native Rust agents | Direct private path, 10 GiB | 109.8 MB/s (879 Mbps) | Hash verified; concurrent gateway traffic was about 0.8 MB/s versus 112 MB/s payload, confirming payload bypassed the gateway. |
| Luna → Condor, native Rust agents | Private IP, 10 GiB | 41.8 MB/s | Hash verified, but gateway traffic indicated relay; this did not establish direct-path performance. |
| Luna → Condor, native Rust agents before flow-tracking fix | Private domain, 10 GiB | 29.6 MB/s | Relay selected; peer adoption disrupted flow tracking. A clean post-fix Condor repeat was still required. |
| Luna → Condor, native Rust public mapping | Public, 10 GiB | 45.4 MB/s (363 Mbps) | Hash verified; below the stated 400 Mbps ISP ceiling. |
| Luna → Condor, isolated staging gateway | Public, 10 GiB | 44.7 MB/s (358 Mbps) | Hash verified; temporary staging setup, not production cutover. |
| Miro → Luna, native Rust public mapping | Public, 10 GiB | 10.2 MB/s | Hash verified. Both endpoints shared a 400 Mbps WAN; bottleneck was not isolated. |
| Miro → Condor, native Rust public mapping | Public, 1 GiB | 48.5 MB/s | Hash verified; shows this route can outperform the Miro–Luna shared-WAN result. |
| Luna ↔ Miro, iperf3 | Private/public TCP and private UDP | 894 / 105 / 100 Mbps | UDP loss 0%, jitter 0.017 ms; TCP retransmits occurred. Independent network test, not PortHub transfer throughput. |
| Luna → Condor, PortHub 1.4.3 | Private `luna.phub`, 1 GiB, 1 connection | 7.79 and 8.42 MB/s | Both repeated downloads passed SHA256; live route was gateway relay. |
| Luna → Condor, PortHub 1.4.3 | Public mapping `algofly.duckdns.org:13367`, 1 GiB, 1 connection | 20.44 MB/s | SHA256 verified; about 2.4× the private single-flow result. |
| Luna → Condor, PortHub 1.4.3 | Private `luna.phub`, 1 GiB, 16 connections | 34.17 MB/s | SHA256 verified; relay route. |
| Luna → Condor, PortHub 1.4.3 | Public mapping `algofly.duckdns.org:13367`, 1 GiB, 16 connections | 49.60 MB/s | SHA256 verified; about 45% faster than private. |
| Miro → Luna, PortHub 1.4.3 | Private direct, 64 MiB HTTP range | 111.2 MB/s | 64 MiB completed in 0.60 s; route status was direct. |
| Luna → Condor, earlier private legacy-agent attempt | Private, 10 GiB | Incomplete | Stalled and retried; stopped before completion at 883 MiB. Not a valid completed throughput result. |

## What these runs show

- Direct same-LAN private transfer reached roughly 110 MB/s and kept the
  payload off the gateway in the verified Miro–Luna run.
- Public forwarding reached roughly 45–49 MB/s in the Luna–Condor tests,
  close to Luna's stated 400 Mbps service limit.
- Private Luna–Condor results varied from 14 to 42 MB/s, and one run was
  confirmed to use the gateway relay. They do not demonstrate a consistently
  selected direct path between those machines.
- Public Miro–Luna throughput was substantially lower than Miro–Condor; the
  available measurements did not isolate whether the shared WAN, router, or
  another link caused it.
- The current 1.4.1 run confirms direct Luna–Miro transfer at about 112 MB/s.
  Luna–Condor private access works, but the peer status selects relay; it
  delivered 38.37 MB/s. The public mapped route delivered 49.15 MB/s, close to
  Luna's stated WAN limit. The direct Condor path is not available in this
  network configuration, so the private result is a relay benchmark.

## Luna–Condor private relay investigation

The 1.4.1 private relay stayed on the configured `https://porthub.algofly.in`
WebSocket endpoint, which is Cloudflare proxied. URM2 also advertises its
operator-configured direct HTTP API origin on port 8345, but that origin was
not included in private relay candidates: enrollment filtered relay fallbacks
to HTTPS, and a healthy primary connection was never replaced with a direct
one. The relay also sent each IP packet as a separate WebSocket message over
TCP. Public Rathole forwarding uses a TCP stream, so the two routes did not
have equivalent proxy hops or per-packet overhead.

Release 1.4.3 carries the configured direct origin and short-lived relay
credential in authenticated private sync, tries that origin before the TLS
fallback, batches up to 32 packet records, and raises bounded relay queues to
reduce packet loss during bursts. The peer payload remains DTLS protected.
All nine enabled clients now report 1.4.3. The live route inventory has 30
peer reports and no `connecting` routes; Luna–Condor uses gateway relay and
Luna–Miro uses direct transport.

The 1.4.3 same-file benchmark still shows a material single-flow gap. While the
private transfer was active, Luna's HTTP socket reported 90–135 ms RTT, CUBIC,
roughly 590–717 packets in its congestion window, and a send queue near 3 MiB.
Retransmitted bytes were small relative to bytes sent, and neither endpoint
logged relay queue overflow. Increasing packet queue capacity therefore did
not remove the limiting factor: a private relay carries the application's
end-to-end TCP packets over a long-RTT path, while the public Rathole route
forwards a TCP stream and splits TCP near the gateway and service. The 1.4.3
private route averaged 8.1 MB/s across two single-connection runs, versus
20.44 MB/s publicly; with 16 connections it reached 34.17 MB/s versus
49.60 MB/s publicly.

The queue change is not a throughput-parity fix. Matching the public single
flow requires a stream path that terminates TCP near each endpoint (or an
equivalent transport-level change); it cannot be achieved by increasing the
packet queues alone. Keep the next release decision pending until that design
is implemented and measured locally.

Raw per-run JSON, progress logs, and temporary payloads were removed to keep
this directory concise. Condor–Miro private transfer was not attempted because
the current private access rules do not authorize that machine pair.
