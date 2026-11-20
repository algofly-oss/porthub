# Private WAN and LAN qualification, November 19, 2026

Luna and Condor used separate WANs and full-duplex Ethernet links at 1 and
2.5 Gbit/s respectively. PortHub selected its encrypted relay for this WAN
pair. Luna and Miro selected the local UDP path when addressed through PortHub
DNS. The 32 MiB transfers in both directions produced 36.8–37.1 MB of UDP
traffic between their LAN addresses on Luna's wired interface. On repeat
Luna-to-Miro tests, private DNS delivered 73.33–77.37 MiB/s and direct LAN
HTTP delivered 99.33–101.89 MiB/s with one or eight connections.

## What limited Linux throughput

The gateway's public TCP mapping splits the connection. On the private packet
path the application sender waits for TCP acknowledgements from the far host.
With approximately 100 ms of round-trip time, Condor's Linux send-buffer
autotuning ceiling of 4 MiB constrained a single connection. BBR socket
samples showed time spent waiting for send-buffer space. An independent
issue on the Linux TUN transmit side caused bursts to drop packets before
the agent could read them.

| Condor to Luna, 512 MiB, one connection | Private MiB/s | Public TCP MiB/s |
| --- | ---: | ---: |
| Original 4 MiB send ceiling | 23.20 | 30.30 |
| 32 MiB automatic ceiling | 33.96, 35.39 | 33.59 |
| Original ceiling restored | 24.62 | 36.17 |

Each trial used
a fresh download destination and PortHub's SHA-256 verification. The
minimum and initial send buffers stayed at 4 KiB and 16 KiB throughout.
Twenty checks of the Jupyter login page returned HTTP 200 during the
automatic-ceiling test.

The Linux agent changes are in PRs #44 and #45. The agent requests a
4,096-packet transmit queue on the PortHub TUN. On hosts with the standard
unmanaged send-buffer settings it allows the kernel to grow individual TCP
send buffers to 32 MiB. The ceiling applies to the network namespace.
Administrator policy, custom runtime values and the service opt-out are
covered in the [native transport documentation](../native-private-transport.md).

## File transfer comparisons

The tests used installed 1.11.50 agents with gateway 1.11.73 and applied the
tested Linux settings directly on the two benchmark hosts. Each rate includes
CLI startup and transfer completion. Downloads used `porthub http.server`
and `porthub get`. For uploads, `porthub push` sent to a Condor
`porthub http.receive` listener, and the file hash was checked on Condor.
SSH carried administrative commands only.

| 512 MiB transfer | Connections | Private MiB/s | Public TCP MiB/s |
| --- | ---: | ---: | ---: |
| Condor to Luna | 8 | 31.78 | 36.53 |
| Luna to Condor | 1 | 18.78 | 17.64 |
| Luna to Condor | 8 | 30.14 | 32.63 |
| Condor to MacBook | 1 | 23.03 | 22.99 |
| Condor to MacBook | 8 | 22.69 | 27.09 |

Before the sender changes, Luna's 512 MiB single-connection upload reached
5.52 MiB/s on private and 24.17 MiB/s on public. Sequential WAN measurements
vary with conditions. MacBook uploads also varied. One eight-connection
512 MiB private upload failed on the installed Mac agent. A later 128 MiB
comparison on that same agent measured 8.08 versus 10.05 MiB/s with one
connection and 11.72 versus 10.25 MiB/s with eight. Neither a larger macOS
send-buffer ceiling nor a larger utun control-socket queue produced a
consistent gain across comparisons. The Mac retained its original settings.

The public HTTPS path used fresh URLs on a temporary web mapping. These
512 MiB comparisons used an 8 MiB checkpoint size and SHA-256 verification.

| Condor sender | Connections | Private MiB/s | Public HTTPS MiB/s |
| --- | ---: | ---: | ---: |
| Luna receiver | 1 | 35.00 | 38.19 |
| Luna receiver | 8 | 27.65 | 38.33 |
| MacBook receiver | 1 | 16.09 | 23.91 |
| MacBook receiver | 8 | 21.88 | 26.53 |

## Sustained MacBook downloads

Condor served the same 2 GiB file for four eight-connection downloads. The
MacBook ran the installed 1.11.50 agent and verified the SHA-256 with
`porthub get` in a fresh directory each time. The public comparison used a
temporary TCP mapping. The trials ran in the order shown.

| Run | Route | Seconds | MiB/s |
| ---: | --- | ---: | ---: |
| 1 | Private DNS | 115.198 | 17.78 |
| 2 | Public TCP | 90.897 | 22.53 |
| 3 | Public TCP | 89.978 | 22.76 |
| 4 | Private DNS | 113.711 | 18.01 |

Average private throughput was 79.0% of the public average on this path.
The wired Condor-to-Luna results below were measured separately.

## Sustained wired transfers

Condor served a 10 GiB file to Luna over a private PortHub hostname and a
public TCP mapping. The private path used the encrypted relay. Ethernet byte
counters increased on both hosts and the downloaded SHA-256 matched the
source. The release 1.8.2 qualification used the opposite transfer direction.

| Connections | Private MiB/s | Public TCP MiB/s | Private / public |
| ---: | ---: | ---: | ---: |
| 1 | 33.15 | 33.28 | 99.6% |
| 16 | 33.07 | 34.57 | 95.7% |

During sustained testing, six Jupyter login-page checks on Luna and six on
the MacBook each loaded all ten referenced assets. Checks took 1.78–2.63
seconds on Luna and 1.82–1.95 seconds on the MacBook.

The [hosted verification run](https://github.com/algofly-oss/porthub/actions/runs/44495981744) passed on Linux x86-64, Linux ARM64 and Apple Silicon.

## Direct LAN follow-up

Luna served a 1 GiB file over Ethernet. Miro downloaded it into a fresh
directory using `porthub get --sha256`. With one connection, alternating
the order of direct LAN IP and private DNS downloads produced these results.

| Receiver measurement | Direct LAN IP | Private DNS |
| --- | ---: | ---: |
| Application throughput (MiB/s) | 92.20, 103.56 | 82.81, 83.75 |
| Ethernet receive bytes per download (GB, decimal) | 1.123 | 1.183 |

Interface counters include other host traffic. The application data was
identical. The receiver counted approximately 5.3% more Ethernet bytes on
the private path. In a separate ten-second sample, the agents averaged 1.05
CPU cores on Luna and 1.47 on Miro during a private transfer. A single
aggregate CPU sample cannot identify which thread limits throughput.

### Loss and socket buffers

At a 500-packet tunnel queue length, the sender reported 177 tunnel transmit
drops during one private transfer. At 4,096 packets, both hosts reported zero
tunnel drops in the repeat. With the larger tunnel queues, a separate run
still recorded 1,819 drops on the receiving PortHub UDP socket and 2,984
host-wide UDP send-buffer errors on Luna. Enlarging the sender's UDP send
buffer and receiver's UDP receive buffer from 212,992 to 4,194,304 bytes
(kernel-reported sizes) cleared those two counters' increments on the next
run. The reverse direction still lost 310 datagrams at Luna. Private
throughput moved from 83.59 to 73.15 MiB/s while the direct comparison moved
from 103.89 to 93.80 MiB/s. Both endpoints returned to their original UDP
buffer settings after the experiment.

### Candidate changes

Each trial used the same PortHub HTTP transfer and verified the full file.
A sender-side change deferred a timer registration for immediately ready UDP
writes. Across two runs per mode, one connection delivered 78.88–83.73 MiB/s
with the original build and 72.97–77.69 with the candidate. Eight connections
delivered 87.30–90.39 and 86.56–90.39 MiB/s respectively.

A receiver-side experiment enabled Linux TUN polling (`IFF_NAPI`) with a
switch in the same binary. Two sequences with opposite test orders produced
four measurements per cell. The table gives medians in MiB/s.

| Connections | Polling off | Polling on |
| ---: | ---: | ---: |
| 1 | 73.51 | 77.84 |
| 8 | 91.23 | 90.00 |

The single-connection gain in the first sequence did not repeat when polling
ran first. Both experiments ended with the installed agents restored. Neither
candidate was included in the release.

### Released agent 1.11.51

Both endpoints reported the published agent version. Each transfer used a
1 GiB file served by `porthub http.server`. The receiver used `porthub get`
with SHA-256 verification. SSH was used for test administration.

| Sender → receiver | Connections | Private (MiB/s) | Comparison (MiB/s) | Private / comparison |
| --- | ---: | ---: | ---: | ---: |
| Condor → Luna | 1 | 34.18 | 35.08 | 97.4% |
| Condor → Luna | 16 | 32.93 | 34.28 | 96.1% |
| Luna → Miro | 1 | 75.96 | 97.80 | 77.7% |
| Luna → Miro | 8 | 84.72 | 101.76 | 83.3% |
| Miro → Luna | 1 | 75.56 | 101.15 | 74.7% |
| Miro → Luna | 8 | 89.26 | 94.47 | 94.5% |

For Condor the comparison used a temporary PortHub public gateway mapping,
with one transfer per cell. For Luna and Miro the comparison used the
sender's Ethernet IP. Each LAN cell is the mean of two transfers, with the
private and direct trials interleaved. The private trials addressed the
sender by its PortHub DNS name. During a Miro → Luna private download, a
two-second capture on Luna's Ethernet interface counted 151,663 UDP packets
from Miro's Ethernet IP to Luna's Ethernet IP.

Single-connection LAN throughput was 22–25% below the direct-IP baseline
in both directions. Miro's sending TCP sockets showed different feedback
patterns across the paths. For sockets with more than 5 MB sent, the median
ratio of inbound TCP segments to outbound data segments was 0.456 across
46 private observations and 0.041 across 33 direct-IP observations. These
are repeated snapshots of active sockets and include multiple connection
counts. They identify a difference worth isolating in a controlled trial
before attributing the throughput gap to acknowledgement processing.
