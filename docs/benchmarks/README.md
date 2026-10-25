# PortHub transfer benchmarks

Measurements describe these hosts and routes, not general performance guarantees.
Luna has a stated 400 Mbps ISP connection; Condor has 1 Gbps. Luna–Miro LAN is
1 Gbps. Rates below use decimal MB/s. Test payloads are sparse zero-filled files;
downloads use fresh destinations and verify SHA256. No raw benchmark artifacts
are retained in this directory.

## Latest local candidate

The native Linux candidate identifies itself as 1.4.4. Release packaging is pending. The working tree enables private TCP streams by default. URM2's test
API images retain all ten production 1.4.3 agent artifacts, so these experiments
do not publish an agent update. No GitHub workflow builds were used.

The built-in `porthub http.server` on Luna serves files through `luna.phub` and
the existing public mapping. Condor uses `porthub get -x 1 --sha256 …`.

| Route / candidate | Payload | Result | Validation |
| --- | ---: | ---: | --- |
| Public gateway, current comparison | 10,000,000,000 bytes | **48.84 MB/s** | SHA256 matched. |
| Private gateway, before receive-backpressure fixes | 10 GB | **45.42 MB/s** | SHA256 matched; completed without reset. |
| Private gateway, client backpressure only | 1 GB | **45.81 MB/s** | SHA256 matched; client ingress drops eliminated, but gateway dropped over 14,000 packets. |
| Private gateway, client and gateway backpressure | 1 GB | **48.81 MB/s** | SHA256 matched; no gateway queue-overflow warnings. |
| Private gateway, client and gateway backpressure | 10 GB | **45.29 MB/s** | SHA256 matched; one gateway queue timeout. |
| Private gateway, compact framing and larger bounded datagrams | 10 GB | **48.16 MB/s** | SHA256 matched; no queue-overflow warnings; 1.4% below the public comparison. |
| Private, Auto strategy, compact framing | 1 GB | **52.75 MB/s** | SHA256 matched; short run includes possible ISP burst allowance. |
| Private, Auto strategy, compact framing | 10 GB | **48.16 MB/s** | SHA256 matched; sustained result matches the gateway-preference run. |
| Miro → Luna, `miro.phub`, Auto, one connection | 10 GB | **92.67 MB/s; 107.91 s** | SHA256 matched. Gateway-wide TX increased by only 83,496,247 bytes, confirming payload bypass. |

The 10 GB SHA256 is
`1a0a850851f333647936c0a1b4576e7ab90398b9e1ae2faf4bb66ca6b72cf724`.

## Bottlenecks and fixes

- The 1.4.3 packet relay carried application TCP over another long-lived TCP
  connection. Public Rathole forwarding splits TCP close to the endpoints.
  Same-file 1 GiB tests measured private single-connection rates of 7.79/8.42
  MB/s versus 20.44 MB/s publicly; 16 connections reached 34.17/49.60 MB/s.
- The new private path terminates admitted TCP beside each endpoint with
  smoltcp and carries ordered bytes through Quinn over existing transports.
  It preserves the application's private source identity and requires no
  additional listening port. LAN packet transport remains available.
- `get -x 1` previously requested each 8 MiB checkpoint separately. Adjacent
  checkpoints now share a continuous HTTP response without losing safe resume.
- Client/gateway WebSocket reads continue independently of blocked writes.
  Bounded transmit and receive queues propagate pressure instead of creating
  avoidable loss. The gateway waits outside its global hub lock and rechecks
  credentials, leases, IPs, ACLs and target generation before sending.
- Negotiated prefix batches remove repeated headers within each frame. Decoding
  restores exact records before ordinary admission checks; old clients retain
  the existing framing. Datagrams fit the existing 1,380-byte transport bound.
- Linux connections prefer per-socket BBR when available; unsupported kernels
  retain their default. Host-wide TCP settings are not changed. Local adapter
  sockets disable Nagle and delayed ACKs; edge HTTP acceptors use TCP_NODELAY.
- Operator-advertised direct HTTP origins precede the HTTPS proxy fallback.
  Peer/stream payload authentication and encryption remain independent of
  the outer HTTP carrier. Relay QoS probes use validated IPv4 control envelopes.

Brief record coalescing and a second carrier did not improve throughput and
were removed. Packet-by-packet striping exceeded Quinn's bounded reassembly-gap
limit; later burst striping completed but wasted bandwidth on recovery.

## Correctness and resources

- Mutual certificate fingerprints and current per-port grants bind streams to
  exact peer identities. Revocation closes admitted streams. Tests cover wrong
  identities at the same virtual address, changed instances, packet loss,
  carrier changes, bounded queues and revocation while waiting for capacity.
- The compact-framing candidate completed a standard `curl --retry 0` transfer
  of 3 GB with matching SHA256 while gateway/peer/gateway preferences changed.
  Its application TCP source port stayed 38168 across all three snapshots.
  The transfer completed in 63.146 seconds without an application retry.
  A previous candidate also confirmed actual carrier changes with socket byte
  counters while preserving the same application TCP tuple.
- Workspace checks passed 244 tests (78 ignored); targeted MongoDB integration
  checks passed 17 tests; UI checks passed 14 tests. Gateway backpressure unit
  and private-sync integration tests passed separately. Clippy passed.
- An idle sample over 149.8 seconds measured private-agent CPU/RSS at
  **0.174% of one core / 20.2 MiB** on Luna and **0.093% / 18.4 MiB** on Condor.
  These are private processes, not all PortHub services combined.
- Earlier release-mode local tests measured 189.71 MB/s through simulated TCP
  endpoints and 832.35 MB/s through an owned Linux network namespace. They
  validate adapter behavior and are not WAN throughput results.

Only PortHub test images and the two selected temporary private agents were
changed. Existing volume mounts and unrelated URM2 applications remain intact.
Rollback images and automatic agent rollback timers are retained while testing.
Completed downloads are removed after verification; 60 GB was reclaimed on
Condor and 13 GB of incremental build cache was reclaimed on Luna.
