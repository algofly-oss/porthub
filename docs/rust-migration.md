# Native Rust implementation

The production gateway, firewall worker, API, and distributed client are Rust
applications. Public forwarding embeds the Rathole-compatible protocol in the
Rust edge process. The retired Go client source and compatibility fixtures have
been removed; native Rust implementations and tests are maintained in this
repository.

The server is split into three containers by privilege and data access:

- `porthub-core` hosts the API, MongoDB and static UI. It has no host network
  and publishes no host ports.
- `porthub-edge` owns public listeners and forwarding. It has no database or
  firewall state access.
- `porthub-firewall` owns PortHub firewall state and receives only
  `NET_ADMIN`.

The roles communicate through scoped Unix socket mounts. See
[`deployment-isolation.md`](deployment-isolation.md) for the container
boundaries and [`gateway.md`](gateway.md) for the public data path.

## Deployment and release status

Native release `1.3.3` is deployed on URM2. Images use stable `porthub:core`,
`porthub:edge`, and `porthub:firewall` tags, with version and source revision
labels. Client binaries are released together for the supported OS and CPU
targets; the API serves the staged release bundle to installers.

The release workflow builds client platforms only when agent source or its
build inputs change. Server, documentation, and UI-only changes do not consume
the platform matrix. A completed agent release is published as a GitHub
Release.

## Operational follow-ups

- GitHub Releases are the source of client artifacts. Gateway-side automatic
  fetch and persistent caching of a newer GitHub release is not implemented;
  deployment currently stages the complete artifact bundle into the image.
- The active URM2 deployment still uses Docker named volumes. The repository's
  new compose configuration uses host bind mounts under `./volumes/porthub`;
  migrating the active database and runtime state requires a controlled
  volume copy before replacing the deployment.
- Benchmark records under `benchmarks/` identify the tested endpoints and
  workload. Treat each result as specific to that setup, not as a general
  network capacity claim.
