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
./deploy.sh

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
