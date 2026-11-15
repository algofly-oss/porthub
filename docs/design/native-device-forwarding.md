# Native device forwarding and desktop sharing

User requirements captured 2026-11-15, extending the active VKeyboard goal.

USB forwarding is current work: native Rust inside the existing agent/API; no extra containers; persistent host-popup rules and temporary foreground/background CLI sessions with restart recovery; immediate client-side disable; authenticated intelligent local/direct path selection with gateway fallback. One destination per physical device, stable device identity, cleanup and restoration. Never detach mounted disks or active network adapters.

Physical tests authorized: forward Luna's Sennheiser Profile microphone and USB external SSD to Miro (SSH alias `miro`, user said Myro), then Condor. Benchmark direct LAN transport and validate the remote route. The SSD partition is mounted at `/media/nitin/ssd469`; check users before safe unmount, never format or overwrite existing data, and restore its original mount afterward. Miro and Condor both have Docker administrator access and installed Linux USB/IP modules; passwordless sudo is unavailable.

The next desktop-sharing feature must also be implemented natively in Rust. Do not wrap, bundle or launch Deskflow. Use https://github.com/deskflow/deskflow only as a reference for behavior and useful ideas.

Desktop-sharing requirements:

- Share physical keyboard, mouse/trackpad and clipboard across adjacent screens, with seamless pointer edge transitions.
- Persistent server/client roles, multiple groups/servers/clients and arbitrary machine assignments.
- Screen arrangement configurable from CLI (screen names, coordinates/directional links) and PortHub UI.
- Survive agent and system restarts and reconnect automatically.
- Reuse PortHub identity, intelligent transport, local feature policies and native input/clipboard APIs.
- Capture input through native OS APIs, including required desktop/Wayland consent, rather than browser events or external desktop-sharing programs.
- Prevent routing and clipboard loops, arbitrate input ownership, release held input on transitions and disconnect, and provide a local escape shortcut.
- Keep USB forwarding, desktop sharing, and browser VKeyboard as separate modules within the same binary.

All PortHub dropdowns must use custom searchable controls, including machine, device, model, settings and topology selectors. Do not introduce native HTML select or datalist menus. Machine pickers must support typing to find registered machines quickly.

## Hardware validation status

Validated on 2026-11-15:

- Luna → Miro, Sennheiser Profile (1377:1100): authenticated direct transport and two seconds of actual 48 kHz mono audio captured successfully. The source microphone was restored afterward.
- Luna → Condor, same microphone: enumeration succeeded, but audio capture returned an I/O error. The approximately 60 ms measured network RTT exceeds the upstream Linux 6.8 capture queue of 12 URBs at no more than 1 ms each. This supports a timing limitation on this route, not a claim that generic USB audio works over WAN. See [capture scheduling](https://github.com/torvalds/linux/blob/v6.8/sound/usb/endpoint.c) and [queue limit](https://github.com/torvalds/linux/blob/v6.8/sound/usb/card.h). Use a low-latency LAN for this microphone; a larger ALSA userspace buffer does not enlarge that kernel capture queue.
- Luna → Miro, JMicron external SSD (152d:a583): native Rust storage preparation passed a 16 MiB read in 0.532441 seconds (31.5 MB/s). USB request tracing isolated the earlier stall to the first physical bulk request; resetting the detached UAS device and selecting its descriptor-confirmed bulk alternate mode resolved it.
- Luna → Condor, same SSD: its older virtual USB controller rejected SuperSpeedPlus. Agent 1.11.17 adds an EINVAL-only retry at SuperSpeed; physical testing confirmed successful attachment and descriptor enumeration with that retry. With source-side storage preparation, the full 16 MiB read passed in 51.4908 seconds (326 kB/s). Measured network round-trip latency was approximately 60 ms.

SSD checks used normal unmounts and bounded read-only probes, with the original mount restored after each test. Both destination reads completed without writes to the SSD. Device attachment and transport connection status must not be reported as proof that a device's application workload works. Keep the hardware forwarding work open until storage and remote audio tests pass or their supported constraints are established with evidence.

### Explicit Windows removable-drive preparation

Windows removable media may reject disk-level offline operations. An administrator
can instead run `porthub usb prepare BUSID` locally before forwarding it. This
operation checks the local USB permission, confirms one directly attached USB disk
with a stable native serial, enumerates all its volume extents, and locks every
volume before dismounting or offlining any volume. Open files, system/page-file
volumes, incomplete metadata, multi-LUN devices and spanned volumes block preparation.
Close applications using the drive and retry; there is no force option.

Preparation records a private identity-bound recovery journal and leaves the
volumes offline. It does not format, repair, read or write user files; Windows
flushes its existing filesystem cache when obtaining the volume lock. Start the
usual USB forward afterward. After stopping forwarding and waiting for the device
to return, run `porthub usb restore BUSID` on its source. Restoration checks the
same physical serial, size, device instance and volume extents before bringing
only PortHub-prepared volumes online. It remains available when local USB access
is disabled so recovery is still possible. A failed rollback retains its journal
and reports the restore command. Mount points and disk read-only settings are not
changed, and no remote request automatically dismounts local storage.
