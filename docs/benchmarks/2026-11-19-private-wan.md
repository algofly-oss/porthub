# Private WAN and LAN qualification, November 19, 2026

Luna and Condor used separate WANs and full-duplex Ethernet links at 1 and
2.5 Gbit/s respectively. PortHub selected its encrypted relay for this WAN
pair. Luna and Miro selected the local UDP path when addressed through PortHub
DNS. The 32 MiB transfers in both directions produced 36.8–37.1 MB of UDP
traffic between their LAN addresses on Luna's wired interface.

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

## Sustained wired transfers

Condor served a 10 GiB file to Luna over a private PortHub hostname and a
public TCP mapping. The private path used the encrypted relay. Ethernet byte
counters increased on both hosts and the downloaded SHA-256 matched the
source. The release 1.8.2 qualification used the opposite transfer direction.

| Connections | Private MiB/s | Public TCP MiB/s | Private / public |
| ---: | ---: | ---: | ---: |
| 1 | 33.15 | 33.28 | 99.6% |

During sustained testing, all six Jupyter login-page checks loaded the ten
referenced assets, taking 1.78–2.63 seconds per check.
