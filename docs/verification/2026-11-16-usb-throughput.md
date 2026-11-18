# Retained USB storage throughput evidence

Native Linux agent 24's authenticated bulk-TCP USB path was physically tested with the JMicron external SSD, USB serial `DD56419883914`, between Luna and Miro. Both machines used their 1 Gbps Ethernet links. These are retained measurements from that candidate, not a fresh benchmark of the final media build or a claim of maximum drive performance.

| Measurement | Result | Local receipt |
| --- | --- | --- |
| Forwarded raw read, 256 MiB | 83.9 MB/s; 3.19992 s | `/tmp/porthub-usb-luna-miro-read-after.log` |
| Forwarded file write, 64 MiB, including fsync | 41.867 MB/s; 1.602896 s | `/tmp/porthub-usb-luna-miro-write-after.log` |
| Re-read of the same test file, SHA verified | 83.911 MB/s | `/tmp/porthub-usb-luna-miro-write-after.log` |
| Source-local raw read, 1 GiB | 355 MB/s | `/tmp/porthub-usb-luna-local-read.log` |
| Source-local bounded file write, including fsync | 336.118 MB/s | `/tmp/porthub-usb-luna-local-write.log` |

The forwarded write used a unique, owned test file on the existing ext4 filesystem; no raw block write or formatting was performed. The owned file was removed and forwarding/mount state restored before the later storage-protection constraints. The file re-read and small local-file measurements remain sensitive to caching and test size; they are not sustained workload or physical-media limits.

The earlier forwarded read stalled at roughly 0.6–0.8 MB/s (`/tmp/porthub-usb-luna-miro-read-before3.log`). The replacement transport reused the agent's HTTP/file source and interface policy, authenticated TLS peer binding and direct-path discovery. It did not bypass VPN/interface policy or expose unauthenticated USB/IP TCP port 3240.

Independent Ethernet diagnostics subsequently found asymmetric throughput and increasing receive errors on Luna. They constrain conclusions about the slower write direction; the software result does not establish that the underlying link fault was repaired.

## SanDisk NTFS test on Aero and Miro

The 128 GB SanDisk (`0781:55a9`) negotiated USB high speed on Luna. On 2026-11-18
the same stick used a clean NTFS volume on each path. Aero ran the native core
1.11.40 package from `251f7657707b300078fd45729430b2e718513dc2`. Miro and Luna
ran core 1.11.39 for their comparison.

| Path | Read | Write |
| --- | ---: | ---: |
| Attached directly to Luna, direct I/O | 40.4 MiB/s | 14.2 MiB/s |
| Luna to Miro over direct LAN forwarding | 27.4 MiB/s | 11.7 MiB/s |
| Luna to Aero over direct LAN forwarding | 6.0 MiB/s | 5.46 MiB/s |

Aero mounted the forwarded volume and copied a 64 MiB test file in both
directions with unbuffered `robocopy /J`. Its SHA-256 matched after the readback.
A separate memory-to-memory TCP test between Luna and Aero measured 47.36 and
52.94 MiB/s. Those figures distinguish the end-to-end Windows USB path from
available TCP throughput, without locating the bottleneck in a specific driver
or PortHub component. Test forwarding rules and files were removed, and the
device returned to Luna.

## Coverage limits

- A historical Linux agent 17 Luna→Condor WAN read completed 16 MiB in 51.4908 seconds, approximately 326 kB/s (`/tmp/porthub-usb-ssd-native-condor-full-test.log`). The optimized bulk-TCP candidate was not re-benchmarked over that WAN, and no WAN write result is claimed.
- The Windows SanDisk source→Linux test covered local typed storage preparation and a read-only NTFS mount. The Linux→Windows test above covered the same removable stick. SSD throughput on either Windows path remains unmeasured.
- macOS source capture could seize the selected device but interface initialization failed; Mac→Linux storage mounting was not proved. Mac virtual-host receiving remains a separate platform limitation.
- No later benchmark wrote to the sensitive Samsung T7, and these historical tests do not authorize further drive changes.
