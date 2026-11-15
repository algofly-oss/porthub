# Windows-middle USB microphone validation — 2026-11-15

A physical Sennheiser Profile microphone (USB `1377:1100`, serial `0214024304`)
was forwarded **Luna → Aero (Windows) → Miro (Linux)**. Both hops reported
`active-direct` on both endpoints. Miro enumerated the same microphone on its
virtual USB controller, bound all three interfaces to `snd-usb-audio`, and exposed
ALSA card `Profile` (card 2 during this test).

A bounded capture on Miro completed successfully: **three seconds, 48 kHz,
mono S16_LE**, exit status zero, with no reported overruns or USB/audio errors.
The capture went directly to `/dev/null`; no audio file was created, played back,
or retained. The ordinary Miro SSH account lacked audio-device permissions, so
the test used a temporary root bridge limited to the microphone's control and
capture device nodes. It did not expose its playback node, change audio defaults,
or change account groups.

## Runtime and prerequisite correction

This was an **agent 1.11.27 runtime** test, with the corrected prerequisite script
from commit `6404352` applied to the existing, verified PortHub-owned Windows
firewall rule. No Windows agent/helper/service restart or replacement occurred.
The active Windows executable's SHA-256 was
`f3d6ccf95a765bbc1fc156c02ede06cf435766098e788b2351c215fc0c04490b`.
This distinguishes the tested runtime from the future agent release that embeds
the correction automatically.

Before correction, the owned inbound USB rule still targeted an older immutable
executable (`1505190680d5a5ef8a4ed611944a1a01009ec85522c1ff11ffbb48b5ee8528bd`).
Read-only native command metadata confirmed the cause:
`Set-NetFirewallApplicationFilter` does **not** have an
`AssociatedNetFirewallRule` parameter. That parameter belongs to its `Get`
counterpart. Updating an existing rule therefore failed, leaving new agent
executables without their intended inbound local-subnet TCP exception.

The corrected script retrieves the owned application filter and pipes it into
`Set-NetFirewallApplicationFilter`, reconciles the TCP port filter, and verifies
the resulting program/ownership/action/address settings. The actual owned rule
was updated only after verifying the active enrolled service executable and its
immutable checksum. Raw USB/IP TCP 3240 was not opened. A separate unpredictable,
owned temporary-rule fixture passed creation, idempotent reapplication, migration
from a previous executable path, and foreign-owner refusal. Its temporary rules
were removed afterward. The same production script and regression fixture are
wired into Windows CI; the owning script group is checked before modification.

## Physical restoration

The downstream Aero → Miro session was stopped first, then Luna → Aero. Both
CLI jobs had restart recovery disabled and Aero reported no saved USB forwards.
Final checks verified:

- Luna serial `0214024304` returned to the ordinary `usb` driver, with all three
  interfaces restored to `snd-usb-audio`.
- Miro no longer enumerated the microphone or its ALSA card, and its occupied
  VHCI port returned to the free state.
- Aero no longer had the imported microphone present.
- Aero's existing keyboard helper and mapping supervisor remained running;
  their processes were neither restarted nor replaced.

Stop commands return before asynchronous kernel/PnP cleanup completes, so these
checks were repeated until the physical state was restored. No drive, filesystem,
firmware, audio contents, or unrelated forwarding job was modified.

## Scope and remaining work

This proves the Windows-middle microphone path for this bounded LAN test, with
Luna/Miro on Ethernet and Aero on Wi-Fi. It is not a general WAN/audio-latency or
all-device compatibility guarantee.

It does **not** prove Linux-middle re-export. Linux `usbip-host` explicitly rejects
`vhci_hcd` devices, so simply listing imported devices is insufficient. The separate
agent29 design in [native-usb-relay.md](../design/native-usb-relay.md) uses the
existing authenticated upstream stream, exclusive ownership and cycle-safe
lineage; it requires its own implementation and Luna → Miro → Aero audio test.
