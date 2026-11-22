# Paired RAM-stream direct transport benchmark (private verification)

This ignored test measures the production `usb::negotiate(Control)` → authenticated bulk TLS → `bridge_bulk` path. It does not attach a USB device or emulate storage. There is no block device, mount, filesystem payload, driver installation, permanent process, enrollment, or production registry claim. Both endpoints verify 128 MiB in 64 KiB pattern/offset chunks plus streaming SHA256. Small application completion barriers precede source-side in-memory USB-policy revocation and owned connection shutdown. Each receiver reports its actual elapsed throughput; compare the two receipts to establish both directions. Do not call the enqueue-side number storage write throughput.

The only gateway is an explicitly labeled fixture. It authenticates two roles using a random, protected per-run capability and listens **only on loopback**. A temporary, separately owned SSH remote-forward carries signaling between hosts; bulk bytes must use the exact nonloopback LAN endpoints and normal `Control` interface/source/VPN discovery. No plaintext signaling listener is exposed on the LAN. The source receipt asserts zero binary payload in signaling; the destination receipt explicitly requires that source proof.

## Exact two-host invocation for Root review

Do not run these until Root reviews the exact source/test-binary SHA and live network/USB-job baselines. No spare drive is required; no physical drive will be opened. The example uses the currently documented Luna `192.168.0.3` ↔ Miro `192.168.0.166` link. If routing/addresses differ, stop and review a fresh configuration. No firewall/VPN/NIC setting change is authorized by this recipe.

Build locally from this exact worktree (no version edits). This uses the existing target cache and tests the same TCP path without unrelated optional Tor/private-stream features:

```sh
CARGO_TARGET_DIR=/home/nitin/nitin/algofly-oss/porthub/target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
CARGO_BUILD_JOBS=2 cargo test --locked -p porthub-agent --lib \
  usb::memory_benchmark:: --no-default-features --no-run --message-format=json
```

Select the unique `compiler-artifact` test executable for `porthub_agent`, record its SHA256/size/source commit, and stage **that same executable** on both hosts. Never use a wildcard choosing an older `deps` binary. The selected exact test is:

`usb::memory_benchmark::paired_lan_memory_transport_ceiling`

Root's owned staging directory must be newly created, mode0700, e.g. `/tmp/porthub-memory-<32hex>`. Specs are mode0600, contain no production credentials, and share one new `secrets.token_hex(32)` fixture capability. They contain exactly:

```json
{"role":"source","nonce":"<64 lowercase random hex>","local":"192.168.0.3","peer":"192.168.0.166","control_port":49231}
{"role":"destination","nonce":"<same capability>","local":"192.168.0.166","peer":"192.168.0.3","control_port":49231}
```

The source and destination specs must remain on their respective hosts; do not print them. All paths below refer only to that exact new owned staging directory. Check both selected binaries against the recorded hash before starting either actor.

On Luna, create a NEW SSH master dedicated only to this control tunnel (never reuse or exit an existing user master):

```sh
ssh -M -S "$BENCH_ROOT/control.sock" -fnNT \
  -o BatchMode=yes -o ControlPersist=no -o ExitOnForwardFailure=yes \
  -R 127.0.0.1:49231:127.0.0.1:49231 nitin@miro.phub
```

If the remote loopback port is occupied or forwarding is denied, stop. Do not change sshd or substitute an exposed LAN signaling port.

Before starting, capture simultaneous per-host fresh interface counters using the reviewed `/tmp/porthub-usb-memory-link-counters.py --interface enp6s0` to owned `link-before.json`. This includes sysfs and read-only `ethtool -S` whitelisted hardware counters, with no MAC/credentials. Root's existing route/link metadata probe should confirm the exact peer/source/interface. Existing cumulative Luna `rx_errors=10759807` is **not evidence of new loss**; compare fresh before/after deltas.

Start source on Luna, keeping its exact shell child handle in Root's supervisor:

```sh
PORTHUB_USB_MEMORY_BENCH_AUTHORIZED=root-reviewed-memory-bulk-v1 \
PORTHUB_USB_MEMORY_BENCH_SPEC="$BENCH_ROOT/source.json" \
timeout 190s "$BENCH_ROOT/fixture" --exact \
 usb::memory_benchmark::paired_lan_memory_transport_ceiling \
 --ignored --nocapture >"$BENCH_ROOT/source.log" 2>&1
```

Use one automated supervisor to watch for `PORTHUB_MEMORY_SIGNAL_READY loopback-only` and immediately launch the destination SSH command. The production hello deadline is eight seconds; separate manual tool turns can consume that budget before the peer starts. Keep the deadline unchanged. Run destination on Miro with the bounded supervisor, environment and protected remote staging:

```sh
PORTHUB_USB_MEMORY_BENCH_AUTHORIZED=root-reviewed-memory-bulk-v1 \
PORTHUB_USB_MEMORY_BENCH_SPEC="$BENCH_ROOT/destination.json" \
timeout 190s "$BENCH_ROOT/fixture" --exact \
 usb::memory_benchmark::paired_lan_memory_transport_ceiling \
 --ignored --nocapture >"$BENCH_ROOT/destination.log" 2>&1
```

The actor reads normal outbound environment; do not silently override an existing source/interface/VPN policy to make it pass. Each endpoint must select the exact expected nonloopback local/peer IP, or the actor fails. It refuses SCTP/gateway fallback. Internal overall bound180s, source revocation3s, peer-stop5s; no retries.

Capture fresh `link-after.json` on each host, compute `--before link-before.json --after link-after.json` deltas, and retain the bounded numerical results. Counter reset or unavailable hardware data remains unknown; never convert it into zero. Link throughput must be considered alongside active `rx_errors`, drops and missed-packet deltas. No `ethtool` setting operation is used.

Require both actor exits0, same session SHA, exact opposite endpoints, each received/sent payload134217728 bytes, source send SHA=destination receive SHA and reverse, source gateway payload0, source local USB revocation true, both bridge-stopped true. Destination may classify only a typed `std::io::ErrorKind::UnexpectedEof` after all payload/SHA and application COMMIT barriers as `expected-post-commit-revoke-tls-eof`; source intentional policy revocation drops TLS without close_notify. EOF during payload/barriers, string-only errors and other I/O errors still fail. Retain the terminal class in the receipt. Retain failures and counter deltas without inferring a device or driver cause.

Finally stop ONLY the dedicated tunnel using `ssh -S "$BENCH_ROOT/control.sock" -O exit nitin@miro.phub`; verify that owned control socket/master and both exact actor children are absent. Do not broadly kill processes. Preserve both proof lines/logs and fresh counter snapshots; remove only exact owned binaries/spec files after an ownership/hash manifest check. No physical USB, mounts, services or client policies should have changed. Retain separate receipts for each actual LAN execution.

## Recorded wired LAN run — 2026-11-17

The optimized `agent-dev` build (opt-level3, no LTO) from benchmark commit `8c8385d572d22a166a8cff63f1294a9547cf7bb8` completed on Luna and Miro. Both hosts used their 1,000Mb/s full-duplex Ethernet interfaces. The observed simultaneous rates were 109.44MiB/s from Luna to Miro and 98.20MiB/s in reverse. Each side received and checked 128MiB, including pattern offsets, SHA256 and mutual completion acknowledgements. Selected TLS endpoints were the expected nonloopback LAN addresses; signaling carried zero binary payload. The source's in-memory USB-policy revocation stopped both bridges.

The first attempt exposed the manual launch race described above. The second completed the payload checks but rejected the expected TLS EOF after intentional revocation. A test-only classifier now accepts typed `UnexpectedEof` only after all payload and commit barriers; earlier and other failures remain errors. The third attempt passed at both endpoints. No production transport behavior was changed for that classifier.

Fresh counter snapshots recorded a Luna vendor RX-error-counter increase while Linux CRC/error counters remained zero. This counter difference does not identify a cause for storage performance. No NIC settings changed. Both actors and the owned signaling tunnel stopped; private specs and remote staging were removed, and numerical proofs and failure logs were retained. No USB device or block device was opened by the benchmark, and no payload was written to a filesystem. Physical storage performance still requires its own device test.

## Recorded core36 transport verification

Source `5b0c5265f0a69f0f6559df5eb00a3c2376b13d1b` passed the same paired wired-LAN workload: each endpoint verified 134,217,728 bytes, with 108.638 MiB/s Luna→Miro and 102.900 MiB/s Miro→Luna. The exact 30,870,848-byte `agent-dev` no-default-features test executable had SHA256 `5c0380d6f53a77e2890d19cc66f0db85fbef065e8a44e1e3e66ee056f2685d57`. Both directional SHA checks and completion barriers passed; signaling payload was zero, policy revocation stopped both bridges, actors/tunnel stopped, private specs and remote staging were removed, and block inventories stayed unchanged. Receipt: `/tmp/porthub-memory36-lan-verified.json`.

The same executable also passed seven USB TCP tests plus the bounded-family selection test, including preferred-path selection and stalled-preferred fallback. Production selection caps eight approved paths, giving the final candidate a maximum 1.4 s launch delay within the 4 s connection budget. The paired LAN run verifies carrier throughput on its selected route; it does not independently compare competing physical routes or establish SSD write throughput.

During the benchmark Luna's legacy hardware `rx_errors` tally increased 6,160 while kernel RX/CRC errors stayed zero. A separate 2.02 s passive window received 530 packets with no tally increase; reported MAC receive/alignment/length errors and pause counts were zero. These observations do not explain the earlier delta or establish TCP drops, a cable fault, or an SSD bottleneck. Missing PHY/RMON/FCS-specific fields remain unknown. Qualified receipt: `/tmp/porthub-luna-passive-nic-interpretation.json`. No NIC settings or physical storage changed.

## Wired retest on 2026-11-22

On the 1 Gbit/s full-duplex Luna–Miro Ethernet link, the destination received
**111.51 MiB/s from Luna** and the source received **111.76 MiB/s from Miro**
simultaneously. Each receiver verified 128 MiB. Both actors exited successfully.
PortHub selected the wired LAN addresses while Miro's Wi-Fi interface was also
up. The test used the optimized agent fixture built from `e44fb03`, SHA-256
`b40481228e43707854c92a18bfbd935419e98caa8f5b0edb116493947b422df7`.

The signaling gateway carried zero payload bytes. Kernel receive-drop counters
increased by two on each host, while kernel CRC counters did not increase.
The observed result measures the in-memory USB transport. For physical SanDisk and JMicron
reads and writes, see [the USB storage results](2026-11-16-usb-throughput.md).
