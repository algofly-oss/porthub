# PortHub transfer benchmarks

These results describe the tested routes, not general performance guarantees.
Luna has a stated 400 Mbps ISP connection; Condor has 1 Gbps. Luna–Miro LAN is
1 Gbps. Rates use decimal MB/s. Sparse zero-filled payloads use fresh download
destinations and SHA256 verification. This directory retains only this summary.

## Current deployment

URM2 runs release 1.4.8 in the isolated Rust core, edge and firewall images.
All nine enabled machines, including the MacBook, report agent 1.4.8. All ten
platform binaries in the production image and GitHub release are 1.4.8.

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

## HTTP interoperability and uploads (1.4.6, gateway patch ea96fa6)

The Luna–Condor matrix completed 42 byte-transfer cases, each with a fresh
256 MiB destination and a matching SHA256. Transfers ran sequentially. Download
direction is Luna → Condor; upload direction is Condor → Luna. Private requests
used `luna.phub:5201`; public requests used the existing gateway mapping. These
short runs include connection startup and can exceed stated ISP rates during
bursts; they are not substitutes for the sustained 10 GB results above. Download
checks span the gateway tuning change; all upload numbers below use the patch.

Download rates, decimal MB/s:

| Listener | Route | `get -x 1` | curl | wget |
| --- | --- | ---: | ---: | ---: |
| http.server | public | 53.56 | 51.88 | 52.69 |
| http.server | private | 49.64 | 57.19 | 57.10 |
| http.server --upload | public | 59.19 | 55.78 | 56.82 |
| http.server --upload | private | 56.05 | 57.38 | 57.10 |
| http.receive | public | 55.09 | 50.10 | 52.15 |
| http.receive | private | 59.80 | 57.32 | 62.54 |

Upload rates, decimal MB/s:

| Listener | Route | `push -x 1` | `push -x 8` | curl PUT | curl POST | wget PUT | wget POST |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| http.server --upload | public | 23.12 | 55.66 | 33.33 | 36.23 | 37.37 | 34.28 |
| http.server --upload | private | 20.60 | 31.99 | 24.95 | 27.94 | 30.07 | 26.49 |
| http.receive | public | 23.89 | 55.32 | 32.89 | 34.65 | 37.06 | 33.91 |
| http.receive | private | 21.15 | 27.50 | 27.41 | 27.88 | 35.19 | 30.17 |

Plain `http.server` rejected upload requests with 405 on both routes. Standard
uploads used `/.porthub/raw/<filename>` with curl PUT/POST or wget
`--method=PUT|POST --body-file=...`. These are ordinary HTTP clients; no extra
PortHub client protocol was required for raw uploads.

Both upload-enabled listener modes, on both routes, passed live checks for:

- Nested directory push and directory get with matching file hashes.
- Repeating an unchanged push: sent 0 files, skipped 3.
- Changing one file: sent 1 file, skipped 2.
- Killing an upload after durable chunks arrived, then resuming to a matching
  whole-file hash. The incomplete destination was not published before commit.
- Interrupted curl and wget downloads resumed from partial files and matched
  the complete hash.
- Two simultaneous managed servers, list visibility, and stopping one while
  the other remained accessible (local management check).

Directory sync is PortHub-specific, not the native rsync wire protocol. Changed
files are resent as files; this does not implement rsync block deltas. Raw HTTP
PUT/POST uploads do not gain PortHub checkpoint resume automatically.

The first upload checks exposed CUBIC on the gateway shared HTTP carriers:
embedded Rathole cannot tune a socket after HTTP upgrade. Edge now applies
the same per-socket BBR policy before HTTP or TLS upgrade. Socket inspection
confirmed BBR, with the host default still CUBIC. A public parallel push improved
from 7.03 MB/s before this fix to 55.66 MB/s afterward. No agent rebuild or
GitHub release was required.

Private upload parity remained unproven in the 1.4.6 matrix. The follow-up
1.4.8 checks below confirm a parallel-upload gap. Source inspection shows that
the private TCP flows to one peer are multiplexed over one QUIC connection and
share its congestion controller; public forwarding uses separate TCP
connections. This is a plausible explanation for the different scaling, but
the measurements do not isolate the cause. Single-connection `push` also does
8 MiB chunk acknowledgements, hashing and durable receiver writes.

Directory bandwidth used three files totaling 256 MiB and the default worker
counts. Changing one 64 MiB file resent that file, retaining the other two.
All initial and incremental trees matched their source hashes.

| Route | Initial push MB/s | Unchanged push seconds | Changed-file push MB/s | Directory get MB/s |
| --- | ---: | ---: | ---: | ---: |
| public | 49.50 | 0.090 | 44.19 | 57.41 |
| private | 21.79 | 0.050 | 27.16 | 57.79 |

## Default upload concurrency: 8 versus 16

On the current Luna–Condor hardware (roughly 64 GiB RAM each), eight sequential
1 GiB upload comparisons alternated connection counts in the order 8,16,16,8
on each route. Every received file matched SHA256. The same deployed agent
executed explicit `-x` values; no GitHub build was used for this comparison.

| Route | 8 connections, mean MB/s | 16 connections, mean MB/s | Sender peak RSS, 8 / 16 MiB |
| --- | ---: | ---: | ---: |
| public | 45.05 | 44.91 | 90.5 / 170.9 |
| private | 29.84 | 30.16 | 90.6 / 170.9 |

Throughput was effectively unchanged in this small sample. Sixteen connections
fit this hardware and become the CLI default for both push and get in 1.4.7;
`-x` / `--connections` retains explicit lower or higher overrides. Receiver RSS
peaked at 66.7 MiB during a 169.4-second sample of the comparison. This is not
a slow-disk qualification: concurrency does not automatically adapt to disk
speed, and the receiver stages chunks before assembling the final file.

A native 1.4.7 receiver was isolated in a temporary systemd unit with cgroup
`io.max` limiting only that process to **100,000 write bytes/s**. A 4 MiB
upload using the default connection setting completed in **83.9 seconds**,
with matching SHA256. The receiver physically wrote 8,396,800 bytes, consistent
with staging plus assembly. Other processes were not throttled. This qualifies
a long slow-write wait with one small chunk, not 16 simultaneously saturated
writers or every weak-client hardware configuration. The unit was stopped
after verification.

### 1.4.8 watch-mode validation (2026-10-26)

The locally built Linux candidate synchronized a 64 MiB directory from Condor
to Luna through both `luna.phub:5201` and the existing public mapping. SHA256
matched on both routes. Each detached job survived its SSH launcher exiting,
created multi-level destination and empty source directories, propagated edits
and newly created files, and supported list/status/stop. The idle jobs recorded
zero CPU ticks over five seconds and about 14–15 MiB RSS. These small functional
transfers include startup and do not replace the sustained bandwidth results
above. Temporary receivers, jobs, binaries, payloads, and checkpoints were
removed after validation.

The published, gateway-installed 1.4.8 CLIs repeated the checks after deployment:
64 MiB Condor-to-Luna transfers on private and public mapped routes, and a
16 MiB Luna-to-Condor private transfer, all with matching contents/SHA256,
nested directories, subsequent watched edits, and successful stop/cleanup.
The installed detached senders used about 12 MiB RSS and recorded zero CPU
ticks over five idle seconds. These remain functional checks rather than
sustained capacity measurements.

### 1.4.8 private upload follow-up (2026-10-26)

Condor pushed the same sparse 512 MiB file to a manually started Luna
`http.receive` listener on port 5201. The receiver was on the same host and
filesystem for every case. Every completed file matched SHA256
`9acca8e8c22201155389f65abbf6bc9723edc7384ead80503839f49dcc56d767`.
Times include the remote SSH command startup. Runs were sequential; the
variation between the two 32-connection public/private results shows why these
single samples are diagnostic rather than a final capacity qualification.

| Condor → Luna route | Connections | MB/s |
| --- | ---: | ---: |
| Private domain, Auto | 1 | 17.56 |
| Public gateway mapping | 1 | 15.29 |
| Private domain, Auto | 16 | 30.35 |
| Public gateway mapping | 16 | 42.55 |
| Private domain, Auto | 32 | 23.80 |
| Public gateway mapping | 32 | 35.91 |
| Private domain, `prefer-gateway` override | 16 | 22.33 |

The 16-connection Auto private run reached about 71% of the public result;
the single-connection results were similar in this sample. Raising concurrency
to 32 did not help. Forcing the private overlay's gateway relay was slower than
Auto, and Condor's strategy was reset to Auto after the run. No transfer
completed during that temporary override. Temporary files and the receiver
were removed after each case.

### Local four-lane candidate follow-up (2026-10-26)

A temporary, native-built 1.4.8 candidate added a bounded pool of up to four
authenticated QUIC connections per private peer. It was run on Luna and Condor
only; the public origin services and gateway were left on their installed
builds. The clients' path strategy remained Auto and the original private
services were restored after the comparison.

Condor downloaded from a Luna `http.server` using `porthub get -x 16`, first
over `luna.phub:5201`, then over the existing public mapping at
`algofly.duckdns.org:13367`. The source was a 10 GiB sparse file and both
destinations matched SHA256
`732377e7f4a2abdc13ddfa1eb4c9c497fd2a2b294674d056cf51581b47dd586d`.

| Route | Size | Connections | Elapsed | Average MB/s |
| --- | ---: | ---: | ---: | ---: |
| Private domain, Auto (private first) | 10 GiB | 16 | 255.92 s | 43.20 |
| Public gateway mapping (private first) | 10 GiB | 16 | 223.98 s | 49.58 |
| Public gateway mapping (public first) | 10 GiB | 16 | 225.82 s | 49.30 |
| Private domain, Auto (public first) | 10 GiB | 16 | 241.82 s | 46.11 |

The reversed-order check puts private at about 93.5% of public throughput, a
smaller gap than the first run's 87%. Public-first then private reduces the
transfer-order bias, though a single pair is not a full storage-cache
qualification. The 512 MiB single-connection samples were 50.46 MB/s private
and 55.96 MB/s public; the 16-connection samples were 56.68 and 56.55 MB/s.
The remaining sustained difference is still unexplained; transport RTT,
congestion window, loss and per-lane byte counters during the same transfer
are needed before selecting another tuning change. Nothing from this candidate
was deployed or committed.

### 1.4.8 upload carrier diagnosis (2026-10-26)

A matched 512 MiB `porthub push -x 16` to the same Luna `http.receive`
listener measured 29.0 MB/s over the private domain and 41.9 MB/s over the
public Rathole mapping on the installed build. Both files matched the same
SHA256. A native-built eight-lane candidate reached 31.1 MB/s in Auto; the
public result remained 41.9 MB/s. A diagnostic build that sent QUIC stream
datagrams over the peer ICE session while the saved strategy remained Auto
reached 26.4 MB/s.

Counters identified the active carriers. The private-domain route sent the
payload through the PortHub tunnel. QUIC stream counters totaled about 550 MB
across eight lanes, while one private-agent TCP WebSocket to the gateway
carried about 557 MB. The ICE session carried little data in normal Auto mode.
When the diagnostic build forced stream datagrams onto that ICE session, the
ICE byte counter rose to about 558 MB and the WebSocket carried only control
traffic. This shows that Auto correctly preferred the WebSocket relay over the
slower available ICE relay in this test; it does not indicate a direct peer
path.

The current private upload therefore multiplexes its QUIC lanes over one
gateway WebSocket/TCP connection. The public Rathole upload uses independent
TCP flows and was faster. More QUIC lanes alone did not remove that shared
carrier limit. Both clients were restored to their installed services with
Auto selected. The diagnostic override, listener, benchmark data, and local
temporary service units were removed. No change was committed or deployed.

### Native relay-lane qualification (2026-10-26)

The final native Linux candidate uses four independently written, bounded
WebSocket relay lanes on the existing API port. QUIC destination-CID affinity
keeps each connection's packets on one lane, including under queue pressure.
Up to eight QUIC connections are prepared only when authenticated TLS ALPN
negotiation confirms peer support. Older peers retain one connection. Prepared
lanes require no keepalive traffic and remain available after idle periods.
Peer certificate pinning, private port authorization and revocation remain in
place; lane headers do not replace authentication.

The controlled Condor-to-Luna comparison used one manually started installed
`http.receive` on Luna port 5201, the private domain with **Auto** preserved on
both machines, and the existing public Rathole mapping. No GitHub build was
used. The gateway API was built natively on URM2 in its existing builder image
and temporarily staged only in the PortHub core container. Client candidates
ran through temporary service units without replacing installed releases.

Final Linux candidate SHA256:
`02527c96d473a45d53582a703022031aa56ec26a9a9bb87f08b83a5ad794f4af`.

Every final run below transferred **10,000,000,000 bytes** to a fresh destination.
Each completed output independently matched SHA256
`1a0a850851f333647936c0a1b4576e7ab90398b9e1ae2faf4bb66ca6b72cf724`.

| Upload method | Public seconds | Public MB/s | Private seconds | Private MB/s |
| --- | ---: | ---: | ---: | ---: |
| Continuous curl PUT, one HTTP connection | 303.841 | 32.91 | 287.304 | 34.81 |
| `porthub push -x 16`, including commit/assembly | 227.30 | 44.00 | 230.65 | 43.36 |

The final private parallel run was 1.45% below public end-to-end throughput.
Its chunk-upload phase took 212.812 s, approximately **46.99 MB/s**, measured
from receiver manifest creation to the last completed chunk. This excludes
final file assembly/checksum work and is not interchangeable with end-to-end
rates. Single-connection uploads completed without retries or application
reconnection. An earlier CID-affinity build also completed the private 10 GB
single-connection upload at 35.29 MB/s with matching SHA256.

These sequential measurements establish comparable throughput in this tested
setup, not identical capacity on every route. 400 Mbps is 50 MB/s before protocol
and application overhead. The public end-to-end parallel baseline itself was
44.00 MB/s; private did not introduce a material deficit in this pair.

Diagnostic evidence behind the change:

- A fresh installed-build 512 MiB parallel comparison measured 28.54 MB/s
  privately versus 44.11 MB/s publicly. The native candidate against the old
  one-lane gateway reached 31.64 MB/s. With CID affinity and four relay lanes,
  private short samples reached 40.28–44.44 MB/s, versus a 44.74 MB/s public
  recheck. The final large-file comparison above reduces startup bias.
- Packet-by-packet round-robin striping was rejected: one upload timed out and
  a warmed retry achieved only 8.56 MB/s. Sender QUIC counters reported 77,131
  packets lost out of 243,108 sent on the busy connection. Keeping packets on
  the same carrier removed that regression.
- Idle checks after several minutes showed eight prepared lanes for Condor
  and one for each of six older peers. Luna's idle diagnostic agent used about
  25 MiB RSS and 0.1% average CPU. The private domain still resolved through the
  PortHub tunnel interface; no path override was used.
- Targeted tests covered independent lane backpressure, older gateway framing,
  peer protocol negotiation, certificate identity, port ACLs, revocation,
  packet loss and carrier changes. A test-harness shutdown race was fixed so
  a deliberately closed carrier is accepted only after explicit cancellation.
  The privileged disposable-network-namespace test remained skipped; real
  Luna/Condor transfers exercised the installed Linux TUN environment.

After qualification, both installed private services were restored with Auto
selected. URM2 was restored to the exact original healthy `porthub:core` image;
edge, firewall and unrelated applications were not restarted. Temporary
receivers, agent units, rollback timers, candidate image, source staging,
upload checkpoints and payloads were cleaned up. Luna returned to approximately
119 GiB free. No source change was committed and no production client upgraded.
