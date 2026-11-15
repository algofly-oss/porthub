# WSL local-network names

PortHub preserves private `.phub` DNS and its access controls while allowing ordinary Windows LAN names such as `luna.local` to resolve inside WSL.

## The regression

On the tested Windows/Ubuntu WSL2 machine, Windows resolved `luna.local` to its LAN address and WSL could connect directly to that address on TCP 8888. WSL's normal hostname lookup failed, despite a direct DNS query to its existing Windows NAT resolver returning the correct answer.

PortHub's private DNS integration inserts `resolve [!UNAVAIL=return]` before NSS `dns`. With WSL NAT, `systemd-resolved` had mDNS disabled and refused `.local` with “No appropriate name servers or networks,” stopping lookup before the working Windows NAT DNS path. This was a resolver-routing failure, rather than lost LAN connectivity. Microsoft documents the [WSL `.local` networking limitations](https://learn.microsoft.com/en-us/windows/wsl/troubleshooting#resolve-local-names-in-wsl).

## Native reconciliation

The Linux agent enables this repair only when all of the following hold:

- It runs as root inside WSL and the trusted OS `wslinfo` reports NAT mode.
- PortHub's system-resolver integration is present.
- The existing `eth0` default gateway is already a configured DNS server.
- That DNS server answers a bounded probe.
- The link has no conflicting DNS configuration, enabled mDNS, or administrator-owned `.local` route.

It adds only the routing domain `~local` on the existing NAT link, using the existing Windows resolver. It preserves the link's default-route setting and other domains. It does not add public DNS servers, static host entries, a general NSS fallback, mirrored networking, Avahi, or another resident service.

The separate `.phub` interface and its DNS policies are unchanged. In particular, successful `.local` resolution does not grant private-network access.

## Ownership and lifecycle

`/run/porthub-wsl-local-dns/state.json` records the original and managed link settings. The root-only directory and private receipt are protected by a process lock. A later agent adopts an intact receipt instead of treating its own settings as the administrator's original configuration.

Public and private native runtimes reconcile every 30 seconds. `/run` is recreated after a WSL restart, so the current gateway and original link settings are discovered again. The ordinary-DNS route is retained during an agent process shutdown, matching the persistent NSS integration and avoiding a DNS interruption during upgrades.

If NAT mode or resolver integration disappears, or an administrator enables mDNS or supplies another `.local` route, reconciliation restores the saved settings only when current values still match the owned configuration or a recognizable interrupted transaction. Concurrent administrator edits are preserved. Failed initial activation attempts an owned rollback. No WSL shutdown, agent restart, NIC reconfiguration, DNS-service restart, firewall change, or access-control change is needed to apply the repair.

## Validation

The live Windows/WSL check confirmed:

- Before repair: Windows and direct NAT DNS resolved the LAN name; WSL libc lookup failed; direct LAN TCP connectivity worked.
- After repair: WSL resolved `luna.local` and connected on TCP 8888.
- `luna.phub` still resolved to its private overlay address, while its existing unauthorized TCP connection continued to time out.
- Other resolver domain routes were unchanged, and Windows SSH stayed reachable throughout.

Source tests cover NAT-gateway qualification, preserving private suffix/default policy, refusing conflicting administrator DNS/mDNS/routes, and retaining the original snapshot across upgrade/partial rollback:

```sh
cargo test -p porthub-agent --lib wsl_local_dns
```
