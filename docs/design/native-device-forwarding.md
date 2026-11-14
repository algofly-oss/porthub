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
