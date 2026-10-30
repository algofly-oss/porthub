# PortHub

Self-hosted private networking, public port forwarding and a web dashboard. The
API, gateway, firewall worker and host agent are Rust; the dashboard is Next.js.

![PortHub dashboard](docs/screenshots/dashboard-overview.jpg)

## Architecture

One Compose file runs three isolated roles:

- `porthub-core`: API, MongoDB and UI; no host networking or published ports.
- `porthub-edge`: public listeners and streaming gateway; no database access.
- `porthub-firewall`: network policy; only this role receives `NET_ADMIN`.

The roles communicate through scoped Unix sockets. Rathole-compatible forwarding
uses the existing API listeners, so it needs no extra control port. Production
images use slim runtime layers; development images also include Rust and Node
toolchains and the source needed to build inside the containers.

## Configure and run

Copy `env.example` to `.env`, set strong database and firewall credentials, and
configure the gateway URL. Runtime state is stored on the host under
`./volumes/porthub` by default; set `PORTHUB_VOLUME_ROOT` to a stable host path
when deploying from versioned source directories.

```sh
docker compose config --quiet
# Download the matching GitHub release bundle before building production images.
PORTHUB_RELEASE_BUNDLE=/path/to/verified/bundle ./deploy.sh

# Development: builds toolchains into dev-only images and syncs source into them.
PORTHUB_MODE=dev ./deploy.sh
```

Development dependencies stay in the containers; the host needs Docker Compose,
not Rust, Go or Node. Run Rust commands in a development container, for example:

```sh
docker exec -it porthub-core cargo test --workspace
```

Production keeps read-only roots and excludes build toolchains and source trees.
The default images are `porthub:core`, `porthub:edge` and `porthub:firewall`,
with the release version recorded in image labels.

## Agent development builds

The `porthub` CLI links the transfer, tunnel, mesh, egress, packet-network and
stream-lifetime libraries into one executable. `porthub-network` owns portable
packet policy/TCP termination; `porthub-io` owns tunnel cleanup. CLI and service
changes can reuse those library artifacts. Internal library versions
are independent of the CLI release; bump them when their interfaces require it.

```sh
# Fast optimized iteration, with incremental compilation and no cross-crate LTO.
cargo build --locked -p porthub-agent --profile agent-dev --timings
./target/agent-dev/porthub --help

# Shipping build retains release optimization.
cargo build --locked -p porthub-agent --release --timings
```

The first build of each profile/target is cold. Later builds still relink the
executable; edits to a dependency also rebuild its consumers. Adding Rust `mod`
files alone does not establish a separate compilation/cache boundary. Existing
libraries should be reused before introducing helper processes or embedded
executables with their own installation/update lifecycle.

GitHub platform jobs restore Cargo artifacts (including workspace libraries)
per target/toolchain. Native Linux jobs build the static musl binary in that
cached target directory through `scripts/build-agent-linux.sh`; they verify
that it has no dynamic loader and keep the existing release/checksum format.
The Docker `agent-artifacts` target remains available for local packaging.

Start releases from the default branch so later versions can restore the same
build caches. GitHub isolates caches written on one version tag from other tags;
merely caching a tag-only workflow does not solve reuse across releases.
After committing the new workspace release version to `main`, run:

```sh
gh workflow run agent-platforms.yml --ref main -f platform=all -F publish_release=true
```

This builds and validates the full platform bundle before creating the release
tag, then retains only the latest verified stable release and older version
releases/tags are removed. Git history remains available for rebuilding an older
commit. Non-version tags and newer in-flight versions are preserved. Dispatch
without `publish_release` for checks or cache warming. Tag-push builds remain
supported, but the default-branch entry point is preferred for cache reuse.
CI staging artifacts expire after three days; build caches remain available for
subsequent builds, while the latest published release stays downloadable.

## Agent transfer tools

The Rust `porthub` binary includes HTTP serving, receiving, parallel downloads
and resumable directory sync:

```sh
porthub http.server 8000 ./files
porthub http.server list
porthub http.server stop 8000
porthub http.receive 8001 ./drop
porthub get https://example.com/archive.bin --connections 16 --sha256 <digest>
porthub get http://machine:8000/dataset/ --dir ./downloads
porthub push ./dataset http://machine:8001/
```

See [native transfers](docs/native-transfers.md) and the [agent platform
matrix](docs/agent-platforms.md) for details.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/` | Rust API, agent, edge, firewall, mesh, tunnel, transfer and runtime crates |
| `ui/` | Dashboard source and UI checks |
| `deploy/` | Compose runtime configuration and deployment preflight tools |
| `vendor/` | Pinned upstream Rust dependencies and documented local patches |
| `docs/` | Architecture, operations, platform support and verification records |

## Tunnel lifetime and edge health

The edge replaces closed idle data carriers automatically. Framed carriers that
stop delivering bytes expire after 60 seconds (agents send 15-second transport
heartbeats). TCP sessions stay open while both sides remain open, including
quiet SSH sessions. Once one side sends EOF, two minutes without application
reads or writes releases the connection; progressing responses can run longer.
`PORTHUB_TUNNEL_HALF_CLOSE_IDLE_SECONDS` selects 1..86400 seconds, or 0 to disable
that cleanup policy. Set it in the edge/agent process environment as needed.

Compose preserves the edge's descriptor limits (soft 65536, hard 524288).
Its real HTTP `/healthz` response reports `x-porthub-fd-used` and
`x-porthub-fd-limit`; on Linux it returns 503 at 90% of the soft limit or if
sampling fails. Applying Compose limits requires a planned container recreation.

## Checks

```sh
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --test ui/tests/workspace.test.mjs
python3 -m unittest discover -s deploy/native -p 'test_*.py'
```

MongoDB integration checks require a dedicated disposable database. Network
benchmarks and registered-client rollout checks are recorded separately under
`docs/benchmarks/` and `docs/verification/`.
