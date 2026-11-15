# Native USB relay through a Linux machine

Linux `usbip-host` deliberately rejects devices attached to `vhci_hcd` in
`drivers/usb/usbip/stub_dev.c`. Removing the inventory filter cannot enable
re-export. PortHub will relay its existing authenticated USB/IP data stream
instead; no kernel patch, userspace USB driver, isochronous translation, public
raw USB socket, extra daemon, or container is needed.

The receiving agent owns a profile-scoped import registry. Each entry binds its
upstream forwarding ID, original device identity and USB/IP descriptor bytes to
the lifetime of that authenticated session. Inventory exposes one stable imported
alias (`0-<numeric digest of upstream ID>`), distinct from physical bus IDs and
unchanged if the local virtual controller assigns a different port later. The
local CLI obtains these entries through the existing OS-authenticated broker.
Physical inventory remains unchanged.

A downstream source acquires the import's sole exclusive lease before opening
its downstream signaling socket. The lease requests a controlled restart of the
upstream session. Dropping the old local VHCI handoff detaches the local virtual
device and closes that old stream normally. The original source reconnects using
its existing forwarding plan and performs a fresh native handoff. This new
upstream connection terminates in a private, ownership-checked TCP pair owned by
the downstream lease instead of VHCI. The downstream source waits for fresh
original descriptors, then opens its ordinary authenticated peer session. Thus
only one consumer exists, no outstanding URBs or sequence numbers are replayed,
and opaque isochronous requests follow the existing transport unchanged.

Both sides retain normal gateway authorization, pinned TLS/capability direct
transport, path policy and gateway fallback. The original USB/IP device ID and
wire descriptors are retained across the relay. The stable local alias identifies
the configured device; it never becomes a kernel device ID. No microphone samples
are inspected or logged.

Stopping the downstream lease closes that stream and restarts the original
upstream plan in local VHCI mode. Stopping/losing the upstream session or disabling
USB revokes downstream access. Cleanup always removes the alias/lease when the
upstream plan ceases to exist. A child lease must not survive a replaced upstream
epoch. Application connections and active recordings are interrupted during these
explicit ownership transfers, just as when moving a physical USB device.

The gateway accepts optional import metadata (`busid`, `upstream_id`) only from
the authenticated reporting machine. Creating a child checks that the current,
same-owner upstream plan terminates at its source and describes the same original
device. Private ancestry is stored in a separate owner-bound `usb_relay_lineage`
collection. Existing `usb_forwards` documents and the `Forward` contract gain no
unknown fields, so an older gateway sharing the database can still decode ordinary
plans. A new relay source must positively authorize its current parent through the
new machine-authenticated relay endpoint before claiming a local stream. An old
gateway returning 404 cannot authorize a relay. The gateway rejects repeated machines, returns to any ancestor, more than
four hops, absent/expired parents and ambiguous lineage. Existing atomic source
reservations plus the local lease enforce one downstream destination.

A capability on the report response gates imported aliases. Older gateways never
receive imported aliases or new report fields after compatibility fallback. Their
local CLI can explain that a gateway upgrade is required. Existing agents and
single-hop plans retain their wire format. Serial-bearing legacy Windows imports
can have ancestry inferred only when exactly one current upstream matches;
ambiguous cases fail closed.

Verification must include lifecycle and failure-injection tests for lease races,
revocation, upstream replacement, cycle/hop rejection, restoration and compatibility,
then actual Luna → Miro → Aero microphone enumeration and a bounded capture to
`/dev/null`/discarded memory. Windows-middle Luna → Aero → Miro enumeration and
three-second 48 kHz mono S16 capture already passed after fixing owned Windows
firewall rule reconciliation; the independent Linux-middle result is recorded below.

Initial onward support is deliberately limited to imported devices whose every
interface is positively identified as USB Audio or HID. Imported mass storage
gets an explicit unsupported reason, even if currently unmounted: a mount-state
check cannot prevent a competing mount before the parent VHCI consumer stops.
Transactional held exclusive block-device leases, validated first with an owned
loop-device fixture, are required before storage onward support can be enabled.
Ordinary physical storage exports and their existing preparation remain unchanged.

## Actual Linux-middle microphone validation, 2026-11-15

Luna agent 1.11.30 → Miro agent 1.11.30 → Aero agent 1.11.28 passed an actual
Windows microphone capture through the ordinary USB Audio class driver. The
Linux agents and gateway 1.11.47 used frozen source
`5e5c5945b8824292428c8c2bd07a48d88c263cd4`; Aero was the existing ordinary
Windows USB receiver. This test did not use the unfinished native media adapter,
change client policies, access drives, or publish a synthetic microphone.

The selected source was Sennheiser Profile `1377:1100`, serial `0214024304`,
Luna bus `1-5`. The upstream temporary job `7a4f8de91727` first imported it as
Miro `5-1`, VHCI port 0, with all three `snd-usb-audio` interfaces. Miro's native
CLI exposed its authenticated alias `0-1148601517668033298`; onward temporary job
`33bbf3b58109` selected that alias for Aero. Miro's local VHCI port became free
while forwarding onward, confirming that this used the native stream relay rather
than binding the imported device to `usbip-host`. Aero enumerated the exact USB
serial and its MEDIA/audio endpoint with healthy native device status.

Both hops reported `active-direct` at both endpoints. Recorded LAN TCP sockets
were `192.168.0.3:32843 ↔ 192.168.0.166:55951` for Luna–Miro and
`192.168.0.166:37795 ↔ 192.168.0.169:51063` for Miro–Aero. Luna and Miro routed
through their Ethernet `enp6s0` interfaces. Aero used its Intel AX201 Wi-Fi adapter
(reporting a 432 Mbps link at inspection). The second hop is a Wi-Fi result, not
an Ethernet throughput baseline.

An owned, limited InteractiveToken task in Windows session 1 selected the exact
active IMMDevice endpoint through its present PnP USB-serial ancestry. It captured
144,000 mono frames at 48,000 Hz: 576,000 bytes, 300 packets, over 3,015 ms. Buffers
were discarded; no audio file or playback was produced and no default endpoint
was selected for capture. The recorded mix format was 32-bit
WAVEFORMATEXTENSIBLE with four bytes per frame; this first diagnostic did not
record the subformat GUID and therefore does not distinguish integer PCM from
floating point in the persisted proof.

The capture reported two data-discontinuity flags, including **one after the
first packet**, and zero timestamp-error flags. This proves native capture and
delivery, not flawless audio quality or measured end-to-end latency. The initial
check recorded totals only. A future separately authorized, bounded diagnostic
must record packet device positions, QPC timestamps, elapsed time and flags to
locate startup gaps versus later transport/clock effects before any tuning or
repeat-quality claim.

Cleanup stopped the child first: Aero's microphone disappeared and Miro's original
local VHCI microphone and all three sound interfaces returned. Stopping the
parent then restored Luna's original USB driver and all three `snd-usb-audio`
interfaces. Miro's VHCI ports were all free and its alias disappeared. All three
clients reported no saved USB forwards. All six Windows capture/render default
role IDs matched their values from before attachment; Luna and Miro PipeWire
default metadata matched byte for byte. The owned Windows diagnostic task, runner
and metadata output were removed. The shared diagnostic source remained for the
separately coordinated synthetic-device test.

Local receipts: `/tmp/porthub-relay30-aero-capture-proof.json`,
`/tmp/porthub-relay30-actual-api-states.json`,
`/tmp/porthub-relay30-miro-vhci-onward.txt`, and
`/tmp/porthub-relay30-complete-restoration.json`. These contain device/transport
metadata and counts, not microphone audio.
