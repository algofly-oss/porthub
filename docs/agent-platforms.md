# Native agent platform requirements

The agent must be self-contained on Windows, macOS and Linux. HTTP serving,
server management and parallel/resumable downloads cannot depend on apt,
lighttpd, aria2c, Python or a shell helper at runtime. Build-time compilers are
separate from this runtime requirement.

| OS | Architectures / release names |
| --- | --- |
| Linux | x86_64, arm64, x86 (i686), armv7, armhf (ARMv6 hard float) |
| macOS | darwin_x86_64, darwin_arm64 |
| Windows | windows_x86_64, windows_arm64, windows_x86 (32-bit), with `.exe` |

`.github/workflows/agent-platforms.yml` builds these targets. Native 64-bit OS
runners and Windows x86 run transfer, management and tunnel-adapter checks.
32-bit Linux targets currently have build jobs; ARM hardware/emulator runtime
checks are still required. The workflow has not run until it is pushed: its
existence is not evidence that a target passes. Runner labels come from the
[GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Foreground profile storage/control is implemented in the portable agent. Unix
end-to-end gateway tests are restricted to Unix dev-dependencies, so server
runtime crates do not enter Windows agent builds. Linux service installation
and management use native systemd D-Bus, with a real user-service lifecycle test.
Privileged system-service activation remains unverified. The macOS launchd
controller now generates owned plists and supports install, start, stop,
restart and removal through the OS-provided `/bin/launchctl`, without a shell
or an additional installed helper. Readiness checks the actual process
executable through `proc_pidpath`. Its disposable user-service test is gated by
`PORTHUB_TEST_LAUNCHD=1`; runtime verification is still pending. An ARM Mac
compiled the earlier agent baseline, but disconnected before the new lifecycle
implementation could be synced and tested. This is not evidence that the
current macOS implementation passes. Windows service control, non-Linux
updates, private-network lifecycle and Windows credential ACL verification
remain.

The server runtime, nftables worker and container deployment are Linux-specific
crates and must not become dependencies of the portable agent. TUN, DNS, service
installation, updates and policy enforcement need platform implementations
behind shared interfaces. Those lifecycle/private-network features are not yet
fully migrated, so the new transfer CLI is not a verified replacement for every
installed agent. Windows private networking also needs a bundled and licensed
native driver strategy; it must not require users to assemble external tools.

Release builds embed the commit version and produce a version marker and SHA256
beside each binary. Packaging must gather matching-version artifacts for every
supported target before a server release advertises or queues agent updates.
The local Docker build currently includes only the agent matching its server
architecture; complete artifact gathering/download routes remain rollout gates.
