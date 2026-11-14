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
- Luna → Condor, same microphone: enumeration succeeded, but audio capture returned an I/O error. This remains unresolved.
- Luna → Miro, JMicron external SSD (152d:a583): descriptors enumerate over both direct and relay transport, then storage initialization times out. Switching the source interface to alternate setting 0 did not resolve it. During forwarding the source interface has no local driver, ruling out local driver reclamation in that test.
- Luna → Condor, same SSD: its older virtual USB controller rejected SuperSpeedPlus. Agent 1.11.17 adds an EINVAL-only retry at SuperSpeed; physical testing confirmed successful attachment and descriptor enumeration with that retry. Disk initialization still times out afterward.

SSD checks used normal unmounts and bounded read-only probes, with the original mount restored after each test. No successful remote SSD throughput result exists yet. Device attachment and transport connection status must not be reported as proof that a device's application workload works. Keep the hardware forwarding work open until storage and remote audio tests pass or their supported constraints are established with evidence.
