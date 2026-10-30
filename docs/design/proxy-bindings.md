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
