# PortHub transfer benchmarks

These results describe the tested routes, not general performance guarantees.
Luna has a stated 400 Mbps ISP connection; Condor has 1 Gbps. Luna–Miro LAN is
1 Gbps. Rates use decimal MB/s. Sparse zero-filled payloads use fresh download
destinations and SHA256 verification. This directory retains only this summary.

## Current deployment

URM2 runs release 1.4.6 in the isolated Rust core, edge and firewall images.
All nine enabled machines, including the MacBook, report agent 1.4.6. All ten
platform binaries in the production image and GitHub release are 1.4.6.

An additional 1.4.6 Luna → Miro public gateway test sustained only about
0.72 MB/s before cancellation. The gateway's accepted public socket used CUBIC
and showed retransmissions and a small congestion window. Applying the existing
per-socket policy to accepted visitors and loading the installed `tcp_bbr` kernel
module improved a fresh single-connection 1 GB transfer to **40.76 MB/s**, with
matching SHA256. Socket inspection confirmed BBR; the host default remained
CUBIC. The initial tuning-only test still used CUBIC and remained slow before
the module was loaded. The subsequent single-connection 10 GB transfer completed
at **37.32 MB/s**, with matching SHA256. Both public runs used fresh destinations
and the existing gateway mapping; no Cloudflare proxy carried their payloads.
This route did not saturate the stated 400 Mbps ISP capacity, so these results
do not establish that every public route achieves the same throughput.

## Release 1.4.5 throughput qualification

The built-in `porthub http.server` and `porthub get -x 1 --sha256 …` ran on
release 1.4.5. Each result below transfers 10,000,000,000 bytes on one connection.
Runs were sequential, without concurrent release uploads or other benchmark
transfers. All completed successfully with matching SHA256.

| Route | Result |
| --- | ---: |
| Luna → Condor, private `luna.phub`, Auto | **46.99 MB/s** |
| Luna → Condor, public gateway mapping | **49.72 MB/s** |
| Miro → Luna, private `miro.phub`, Auto | **90.52 MB/s** |

Private WAN throughput was 5.5% below the public comparison. These sequential
measurements do not prove identical path capacity. The earlier qualified local
candidate measured private WAN 48.16 MB/s against public 48.84 MB/s.

During the deployed LAN qualification interval, gateway-wide TX increased by
126,167,675 bytes and RX by 7,143,090 bytes, including unrelated traffic. The
10 GB payload therefore bypassed the gateway. No forced-direct override was used.

The 10 GB SHA256 is
`1a0a850851f333647936c0a1b4576e7ab90398b9e1ae2faf4bb66ca6b72cf724`.

## Bottlenecks and fixes

- The old packet relay carried application TCP over another long-lived TCP
  connection. Public Rathole forwarding splits TCP close to each endpoint.
  Earlier 1 GiB tests measured private single-connection rates of 7.79/8.42
  MB/s versus 20.44 MB/s publicly; 16 connections reached 34.17/49.60 MB/s.
- Private TCP now terminates beside each endpoint with smoltcp and carries
  ordered bytes through Quinn over existing transports. Source identity and
  per-port authorization are preserved without another listening port.
- A single `get` response now spans adjacent durable resume checkpoints,
  eliminating a separate round trip for each 8 MiB piece.
- Independent WebSocket readers/writers and bounded client/gateway queues
  propagate pressure instead of dropping reliable traffic. Gateway waits stay
  outside the global hub lock and revalidate admission before sending.
- Negotiated prefix batches remove repeated headers within each frame; records
  are restored before admission checks. Existing peers retain compatible framing.
  Datagrams remain within the existing transport bound.
- With both LAN clients on 1.4.4, Auto stalled after about 5.3 MB while forced
  direct completed 1 GB at 90.19 MB/s. Batched reads distorted probe estimates.
  A 1 ms measurement floor prevents sub-millisecond dispatch spacing from
  masquerading as link capacity. Auto now selects the low-latency LAN path.
- Linux private and public carrier sockets prefer BBR when available. Unsupported
  kernels retain their defaults; host-wide TCP settings remain unchanged.
  Nagle/delayed ACK tuning and HTTP TCP_NODELAY reduce local adapter delays.
- Operator-advertised direct HTTP origins precede HTTPS proxy fallback. Peer
  authentication/encryption remains independent of the outer HTTP carrier.

Brief coalescing and multiple striped carriers did not improve the comparison
and were removed. The current transport uses one bounded carrier per route.

## Validation and resources

- Workspace checks passed 245 tests (78 ignored); targeted MongoDB integration
  checks passed 17 tests; UI checks passed 14 tests. Clippy passed before release.
- All ten release platform builds passed. Intel macOS required a test-only
  recovery build: a pending response now guarantees cancellation before EOF,
  replacing a throughput-dependent sleep. Production source, dependencies and
  binary build recipe matched the release tag. All 30 published asset digests
  matched GitHub SHA256 metadata. Provenance is recorded in the release notes.
- All 17 configured public service ports were verified against sockets owned by
  the deployed edge process. Configuration retained 27 web routes, 10 private
  registrations, 65 connections and 20 enabled connections.
- Mutual certificate fingerprints and current per-port grants bind streams to
  exact peers. Tests cover changed identities, loss, carrier changes, bounded
  queues and revocation while waiting for capacity.
- The earlier 1.4.4 qualification completed a standard `curl --retry 0` 3 GB
  transfer across gateway/peer/gateway preference changes. SHA256 matched and
  its application TCP source port remained 38168 throughout; no retry occurred.
- A prior 149.8-second idle sample measured private-agent CPU/RSS at 0.174% of
  one core / 20.2 MiB on Luna and 0.093% / 18.4 MiB on Condor.
- Verified qualification downloads were removed and test HTTP servers stopped
  after recording results. No unrelated URM2 application was changed.

Release 1.4.6 passed 251 workspace tests (78 ignored), including the new
credential-free unprivileged status checks. All ten platform builds passed;
the three Windows targets used a Windows-only recovery for transient status-file
sharing conflicts. All 30 published asset digests matched GitHub SHA256 metadata.
Idle private-agent samples measured 0.178% of one CPU / 19.6 MiB RSS over
280.4 seconds on Luna and 0.092% / 18.4 MiB over 368.3 seconds on Condor.
