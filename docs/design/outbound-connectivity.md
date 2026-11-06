# Agent outbound connectivity

The machine inventory's **All** filter includes enabled and disabled machines.
**Disabled** is a separate filter; Online and Offline describe enabled machines.

## Problem and design

Previously, control requests, private-policy sync, and public transport selected
`interfaces.current().first()` independently. Expiring the HTTP cache discovered
the same first address again. A working homepage or DNS answer did not prove that
the enrolled agent could reach its authenticated control service or relay.

The outbound selector maintains source/destination candidates, failure cooldowns,
and a preferred authenticated path per enrolled gateway authority. Linux discovers UP interfaces, usable IPv4
and IPv6 addresses, and destination-specific routes including gateway and metric.
Read-only source-aware FIB lookups exclude prohibited sources and sources whose
egress differs from the kernel's unbound destination route. A VPN wins when the
kernel routes the gateway through it; physical interfaces receive no special
preference. PortHub's own exit is the sole exception: its root-owned, validated
ownership journal can authorize the physical sources for which that exit already
installed management bypass rules. The selector does not add such rules.
An explicit preference restricts discovery and may select another egress when
the source-aware kernel lookup permits it, rather than bypassing the
kernel's routing policy. No routes, addresses, firewall rules, or DNS configuration
are changed by the selector.

DNS answers are bounded to 16; discovery yields at most 32 source/destination
pairs. Each operation tries at most eight eligible pairs. DNS and inventory have
3- and 2-second limits, TCP connect has a 3-second limit, and authenticated control
operations have a 45-second retry budget (individual requests at most 40 seconds,
including existing long polls). Failures cool down exponentially from 2 to 60
seconds. A successful authenticated response retains its path despite candidate
ordering or metric changes. A removed address invalidates it; route changes are
rechecked against the source-aware kernel policy. Idle agents
perform no discovery work: the next control operation refreshes the snapshot at
most 30 seconds after its previous discovery; a network failure invalidates the
cache immediately. Rebuilding the bound client discards its stale connection pool.

Control clients pin each DNS answer while retaining the original hostname for
certificate verification. Certificate verification and configured proxy behavior
remain enabled. HTTP authorization rejection stops authority/path failover.
Network failures before connection establishment can retry; reads and the two
idempotent heartbeat/signal sync endpoints may retry after interrupted responses.
Other mutations are not replayed after ambiguous failures. Redirects never send
credentials to a new authority. Only already enrolled fallback authorities are used.

Public transport adopts the selected control source during normal configuration
refreshes. Its existing reroute operation retains established streams while
replacing the control connection and the source for future channels. Private
policy sync uses the same selector implementation, with its own identity/state.
Private relay connections use independent authenticated WebSocket attempts and
sticky source selection; additional lanes use the selected source. Healthy relay
sockets and peer sessions are preserved across discovery changes. New private
negotiations are restricted to policy-permitted source addresses.

## Configuration

Set these in the agent service environment, then restart that agent:

| Variable | Values and behavior |
| --- | --- |
| `PORTHUB_OUTBOUND_MODE` | `auto` (default), `system`, or `interface` |
| `PORTHUB_OUTBOUND_INTERFACE` | Exact local interface name; required for `interface` mode; also restricts `auto` |
| `PORTHUB_OUTBOUND_SOURCE` | Optional local IPv4 or IPv6 address; never assigned automatically |

`system` delegates source selection to the OS and rejects explicit interface or
source settings. It is appropriate for administrator-managed proxies or routing
that requires platform-specific socket marks. Preferences apply to the process,
including public and private modules; they do not change enrollment credentials.
An unavailable explicitly selected interface fails closed instead of silently
using another one. A service restart intentionally replaces existing connections.

Example systemd drop-in (`systemctl edit <porthub-service>`):

```ini
[Service]
Environment=PORTHUB_OUTBOUND_MODE=interface
Environment=PORTHUB_OUTBOUND_INTERFACE=ens33
Environment=PORTHUB_OUTBOUND_SOURCE=192.0.2.20
```

## Diagnosis

```sh
porthub diagnose --profile /path/to/registration.json
```

This read-only command prints JSON with separate DNS, per-path TCP, verified TLS,
authenticated control, saved public-tunnel, private-policy and authenticated relay
statuses, plus local interface and Linux route inventories. Homepage HEAD responses only establish TLS reachability; they never
establish control authorization. HTTP status errors contain no request URLs,
credentials, or response bodies. Transport details include local IP/interface and
gateway, which administrators should treat as network inventory.

Private status also identifies missing system DNS integration separately from
working private IP connectivity. Saved tunnel/relay state is an observation from the running agent, not a new
end-to-end peer connection test. The authenticated control check is live and
verifies the response's enrolled identity. A relay marked ready means its
WebSocket carrier authenticated; it does not prove that a particular peer's SSH
service is listening or permitted. Unknown/unobserved is reported explicitly.

A missing `systemd-resolved` service and unconfirmed clock synchronization produce
separate advice. Expired private-policy leases remain rejected and explicitly
suggest checking the host clock and gateway. Runtime retry loops never install
packages or alter clock synchronization.

During privileged Linux enrollment/install and upgrades with an existing private
module, dependency preparation installs `systemd-resolved` from configured DNF/APT
repositories, starts its service, and integrates system hostname resolution.
On authselect-managed hosts it clones the selected profile with the same enabled
features, links its existing PAM templates, changes the hosts lookup order to use
`resolve` before `dns`, takes an authselect backup and verifies PAM contents are
unchanged. On unmanaged hosts it backs up and atomically updates only the hosts
entry in `/etc/nsswitch.conf`. Before package preparation, the installer snapshots the existing resolver file
or symlink. Known package hooks that replace it with a systemd stub are restored,
including ownership, permissions and SELinux label. NetworkManager-managed
symlinks retain live DHCP updates; unrelated administrator changes are not
overwritten. Debian/Ubuntu NSS integration also prepares `libnss-resolve` when
needed. Existing stub-based setups are verified through their DNS backend. Real `getent -s resolve` resolution is checked; failure rolls back the
hostname lookup change. Invalid administrator-managed profiles are never forced.
A background monitor then verifies the enrolled private hostname using normal
`getent` lookups. This runs outside packet forwarding, and private-service
readiness waits for verification rather than assuming resolver registration is
sufficient. Explicit NSS action policies that cannot be safely preserved fail
with an administrator-facing error.

Set `PORTHUB_PRIVATE_DEPENDENCIES=check` for administrator-managed installations:
setup then reports missing/inactive dependencies or missing DNS integration without
installing, starting, or editing them. Package transactions are allowed to complete
rather than killed mid-update. No package manager, NSS configuration repair or
clock changes run in a packet forwarding loop. The outbound path selector never
changes host DNS configuration; this preparation belongs to privileged install.

The release workflow explicitly gates dependency preparation, DNS integration,
unified private activation/public upgrades, and fail-closed clock diagnostics.
Tests cover missing packages, unavailable privilege/package managers, failed
installations, masked services, idempotence, default RHEL NSS lookup order, and
preserving public forwarding when private preparation fails.

## Limitations and boundaries

* Gateway choice is owned by the kernel. Binding a source cannot force an
  arbitrary next hop. Multiple API DNS answers and enrolled gateways are tried;
  equally ranked host next hops are not rewritten. A dead preferred host route
  may require an administrator to correct routing before another interface is
  eligible. This boundary prevents automatic escape from VPN/policy routing.
* Linux has source-policy validation. macOS/Windows automatic discovery retains
  only the OS-selected source; explicit local interface/source choices are
  administrator-directed. Full cross-interface automatic failover is deliberately
  not implemented on those platforms. Unsupported address families are skipped.
* Configured HTTP proxies can choose their own upstream path; socket binding does
  not select the proxy's source address. Use `system` mode for such environments.
  A direct TCP probe and a proxy-mediated HTTP result can therefore differ.
* Private ICE discovery still uses the existing platform watcher. Candidate
  restrictions affect new negotiations; source preferences do not migrate an
  established UDP session. Public transport currently shares the control source,
  rather than selecting a different source independently for each tunnel origin.
* Discovery is lazy with a 30-second cache, plus failure invalidation. It does not
  run an additional permanent network monitor, and cannot preserve a connection
  whose bound address was removed or whose remote endpoint stopped responding.

## Verification

`ui/tests/disabled-machines.cjs` checks All/Disabled/Online/Offline and configuration
access at desktop and mobile sizes. Selector tests cover address removal, IPv6,
per-remote backoff, bounded attempts, retention and cooldown. Control tests make
real socket connections from alternate loopback sources after a failed local
binding and ensure rejection does not retry or promote a path.

The `netns-tests` feature includes
`outbound::namespace_tests::source_policy_interface_changes_and_gateway_metrics_are_respected`.
Run it only in an owned disposable container namespace via
`scripts/verify-private-tun.py`. It creates two source addresses and two default
gateways, verifies lowest-metric selection, applies a source-specific prohibition,
and removes an address. No host namespace or writable host mount is used.

## Windows installer and WSL exposure

The Windows command explicitly launches `powershell.exe`, so it works from
Command Prompt, Windows PowerShell, and PowerShell tabs in Windows Terminal.
The served installer requests UAC elevation when needed and preserves certificate
verification and execution policy. Shell-specific URL expansion is prevented.
Hosted Windows checks execute the copied UI command in cmd.exe, Windows
PowerShell 5.1 and PowerShell 7; desktop/mobile browser checks verify the copied
value matches the displayed command.

WSL uses its Linux registration and local Unix broker. A Windows registration or
another distribution is not implicitly a local Linux registration. Exposure
preflight now explains missing WSL registration and stopped-agent conditions,
including detached starts. Local broker connection establishment is bounded.
The original incident machine was unavailable, so no claim is made that its
specific failure was reproduced.

`porthub get` reports human-readable transferred/total bytes, speed, remaining
bytes and ETA. Terminal output updates in place; redirected output is throttled
and has no terminal control characters. Resumed data does not inflate throughput,
and unknown file lengths never display a fabricated percentage or ETA.

On macOS and Windows, automatic mode conservatively retains the kernel-selected
source for each destination. The read-only UDP route lookup runs once per
address, sends no datagram, and records only successful results. A missing IPv6
route is skipped independently and cannot discard a working IPv4 candidate (or
vice versa). Interface inventory and administrator source/interface preferences
still constrain the candidates. Linux continues using its source-aware FIB
queries and route priorities. Tests cover mixed-family lookup failure, no probe
packet emission, sticky failover, and independent address backoff. Native checks
on the target operating systems remain required before rollout.
