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
firewall rule reconciliation; that does not prove this new Linux relay.

Initial onward support is deliberately limited to imported devices whose every
interface is positively identified as USB Audio or HID. Imported mass storage
gets an explicit unsupported reason, even if currently unmounted: a mount-state
check cannot prevent a competing mount before the parent VHCI consumer stops.
Transactional held exclusive block-device leases, validated first with an owned
loop-device fixture, are required before storage onward support can be enabled.
Ordinary physical storage exports and their existing preparation remain unchanged.
