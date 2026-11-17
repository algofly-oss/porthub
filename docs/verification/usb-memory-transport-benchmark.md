# Paired RAM-stream direct transport benchmark (private, not executed)

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

Wait at most10s for the fixed `PORTHUB_MEMORY_SIGNAL_READY loopback-only` line in the owned source log, then run destination on Miro (Root's bounded SSH supervisor, environment and protected remote staging):

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

Finally stop ONLY the dedicated tunnel using `ssh -S "$BENCH_ROOT/control.sock" -O exit nitin@miro.phub`; verify that owned control socket/master and both exact actor children are absent. Do not broadly kill processes. Preserve both proof lines/logs and fresh counter snapshots; remove only exact owned binaries/spec files after an ownership/hash manifest check. No physical USB, mounts, services or client policies should have changed. Actual LAN execution remains a separate Root-authorized gate.
