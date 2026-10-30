# Multiple bindings for public web proxies

One hostname and access policy route to an ordered list of owned machine-port
mappings or standalone HTTP(S) URLs. Existing single-target documents remain
readable without a database migration.

The two routing modes are deliberately separate:

- Priority / manual: use the first available binding by user-defined priority.
- Priority / health: choose among healthy bindings by consecutive failures and
  smoothed health-probe response time. Manual priorities are ignored.
- Load balance: distribute requests across all healthy, enabled bindings using
  round robin, weighted round robin, or least active connections. Manual
  priorities are ignored. Optional cookie affinity retains a healthy target.

Availability uses bounded active HTTP checks, passive transport failures,
unhealthy/recovery thresholds, and cooldowns. Only empty-body GET/HEAD requests
may retry across targets; writes, uploads, and upgrades are never replayed.
Once a response starts, it cannot move to another binding. WebSockets remain on
the selected target until they close and reconnect. Application state is the
operator's responsibility when balancing distinct application instances.

Bindings have stable IDs, labels, enable switches, priority, weight, optional
health path, and automatic/original/target Host header selection. Owner checks
resolve managed target URLs from authoritative mapping records; disabled,
deleted, or transferred mappings cannot retain their old gateway port.

A single edge health worker bounds checks across pools. Core reads a fresh,
credential-free status snapshot from the existing read-only activity mount and
returns only the requesting owner's route/binding IDs. No per-request database
access or per-binding detached polling task is introduced.

The UI exposes routing mode and bindings together, with separate Health and
Options tabs. Up to 128 bindings are supported per proxy. Advanced controls
include a 1–128 attempt budget, response-header timeout, expected health status
range, and Host-header behavior. The default attempt budget is four. Only
502/503/504 responses and transport failures cause safe GET/HEAD failover;
application 4xx and ordinary 500 responses are returned to the client.

Existing proxies are represented as one binding when edited. Their active health
checks remain off until explicitly enabled or a mode requiring checks is chosen.
Machine bindings are resolved from current owned mapping records, including
specific IPv4/IPv6 listener addresses. All-disabled or unavailable pools return
503. Health/counter state is in memory and survives unchanged configuration
reloads, but resets after an edge restart or a changed pool configuration.

Server-only builds use `server-platforms.yml` to compile API, edge and runtime
without rebuilding or publishing agent binaries. Roll out edge before API/UI so
it can read the new snapshot fields. Both roles retain the same persistent
mounts. Runtime health snapshots use the existing activity volume; no new host
ports or external health service is needed.

Verification and the scoped 1.8.6 deployment are recorded in
`docs/verification/2026-10-30-proxy-bindings.json`. The published cross-platform
agent release remains 1.8.5; the server feature needs no agent upgrade.
