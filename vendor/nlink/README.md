# nlink

[![Crates.io](https://img.shields.io/crates/v/nlink.svg)](https://crates.io/crates/nlink)
[![Documentation](https://docs.rs/nlink/badge.svg)](https://docs.rs/nlink)
[![License](https://img.shields.io/crates/l/nlink.svg)](https://github.com/p13marc/nlink#license)

A Rust library for Linux network configuration via netlink. Async/tokio-native,
type-safe, owns its wire format end-to-end (no `rtnetlink` / `netlink-packet-*`
dependency). CLI binaries (`nlink-ip`, `nlink-tc`, `nlink-ss`, `nlink-nft`,
`nlink-wg`, `nlink-bridge`, `nlink-devlink`, `nlink-ethtool`, `nlink-wifi`,
`nlink-config`) ship as proof-of-concept demonstrations of the library —
each `nlink-` prefixed so it never shadows the system tool it mirrors.

## Install

```toml
nlink = "0.33"
```

Feature flags: `sockdiag`, `tuntap`, `output`, `namespace_watcher`,
`syscall_batch` (recvmmsg/sendmmsg batching), `serde`, `schemars` (JSON Schema for
`NetworkConfig`), `lab` (test harness), `wireguard-keys` (WireGuard key
generation), `full` (all of them but `lab`). Full list in the
[docs.rs feature table](https://docs.rs/crate/nlink/latest/features).

MSRV: Rust 1.88, edition 2024: the oldest stable that builds every target with
every feature. It is raised only in a minor release, for a language or library
feature worth it, and the CHANGELOG says so.

## Quick start

```rust,no_run
use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // Query
    for link in conn.get_links().await? {
        println!("{}: {} (up={})", link.ifindex(), link.name_or("?"), link.is_up());
    }

    // Modify
    conn.set_link_up("eth0").await?;
    conn.set_link_mtu("eth0", 9000).await?;

    // Observe
    conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;
    while let Some(event) = events.try_next().await? {
        if let NetworkEvent::NewLink(link) = event {
            println!("link added: {}", link.name_or("?"));
        }
    }
    Ok(())
}
```

## What's in the box

**Networking core** — links (20+ types: dummy, veth, bridge, bond, VLAN, VXLAN,
GRE, IPIP, SIT, VTI, Geneve, netkit, IFB, VRF, MACsec, MACVLAN, IPVLAN, GTP,
tun/tap), addresses, routes, neighbors, routing rules, nexthop objects + ECMP
groups, MPLS, SRv6, bridge FDB + VLAN filtering, network namespaces.

**Traffic control** — 35 typed qdisc kinds, typed classes (HTB, HFSC, DRR, QFQ),
11 typed filter kinds, 19 typed action kinds, filter chains, BPF program attachment.
Every typed config has a `parse_params(&[&str])` so `tc` CLI syntax round-trips
through the typed API. Strongly-typed units: `Rate` (bytes/sec internally,
parses `100mbit` / `1gbit`), `Bytes`, `Percent`, `TcHandle`, `FilterPriority`.

**Generic Netlink families** — WireGuard, MACsec, MPTCP, ethtool, nl80211 (WiFi:
PHY/wiphy band capabilities, scan/BSS, station-info, channel survey), devlink,
DPLL (clock synchronization — SyncE/PTP/GNSS, kernel 6.7+), net_shaper (TX
hardware shaping incl. hierarchical groups, kernel 6.13+), OpenVPN DCO.

**Firewall** — nftables tables/chains/rules/NAT/match expressions, named sets
(imperative + declarative `DeclaredSet` with element-level diff), flowtables
(`Expr::FlowOffload`), multicast event subscription, atomic single-batch commits
via `Transaction`, declarative `NftablesConfig` reconcile, typed decoding of
dumped rule expressions (`RuleInfo::expressions()` / per-rule hit counters
via `RuleInfo::counter()`).

**Diagnostics & observability** — socket diagnostics (`SockDiag`) with
kernel-side `ss`-expression filtering (compiled `INET_DIAG_REQ_BYTECODE`
programs: ports, addresses, or/not, state hoisting), socket→process/cgroup
attribution (`SocketOwnerMap`/`CgroupPathMap`), per-socket TCP goodput
tracking (`SocketRateTracker`), typed congestion-control internals
(BBR/DCTCP/vegas `CcInfo`); connection tracking (`Netfilter`/ctnetlink),
Linux audit, SELinux events, FIB lookups, ethtool statistics + monitor,
kobject uevent (device hotplug), process connector lifecycle events.

**Cross-cutting** — XFRM IPsec SA/SP management + hardware offload
(`XFRMA_OFFLOAD_DEV`) + monitor event stream (`Connection<Xfrm>: EventSource`),
ENOBUFS-resync event streams with a kube-rs-style `Store` watch-cache
(`ReflectExt::reflect`), opt-in per-`nlmsg_seq` dispatcher mode
(`Connection::with_dispatcher`) so events and requests coexist on one
connection, 30-second default per-Connection timeout (override or opt out),
`NETLINK_EXT_ACK` TLV parsing (kernel error messages with offset + attribute
name), `NETLINK_GET_STRICT_CHK` opt-in.

## High-level APIs

The lower-level imperative API is the foundation; these declarative layers
collapse common configuration patterns.

```rust,no_run
use std::{sync::Arc, time::Duration};
use nlink::netlink::{Connection, Nftables, Route, diagnostics::Diagnostics};

async fn tour(conn: Connection<Route>) -> Result<(), Box<dyn std::error::Error>> {
    // Declarative network state — diff against kernel, apply changes idempotently.
    // With the `serde` feature it also round-trips through JSON/YAML: the typed
    // config validates as it parses (CIDR addresses, MAC strings), so a bad value
    // is a deserialize error, not a silently-wrong config.
    use nlink::netlink::config::NetworkConfig;
    NetworkConfig::new()
        .link("br0", |l| l.bridge().up())
        .link("dummy0", |l| l.dummy().mtu(9000).up().master("br0"))
        .address("br0", "192.168.100.1/24")?
        .apply(&conn).await?;
    let cfg = NetworkConfig::from_json_str(r#"{ "links": [{ "name": "br0", "link-type": "bridge" }] }"#)?;

    // Declarative nftables ruleset — atomic batch commit.
    use nlink::netlink::nftables::config::NftablesConfig;
    use nlink::netlink::nftables::types::{BaseChain, Family, FilterHook, Policy, Priority};
    let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
        t.chain("input", |c| c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop)))
            .rule("input", |r| r.match_iif("lo").accept())
            .rule("input", |r| r.match_tcp_dport(22).accept())
    });
    let fw = Connection::<Nftables>::new()?;
    cfg.diff(&fw).await?.apply(&fw).await?;

    // Rate limiting — typed Rate, no bits-vs-bytes confusion.
    use nlink::{Rate, netlink::ratelimit::RateLimiter};
    RateLimiter::new("eth0").egress(Rate::mbit(100)).ingress(Rate::mbit(50))
        .apply(&conn).await?;

    // Per-peer impairment — netem per destination on shared L2.
    use nlink::netlink::{impair::PerPeerImpairer, tc::NetemConfig};
    let wan = NetemConfig::new().delay(Duration::from_millis(40)).build();
    PerPeerImpairer::new("vethA-br")
        .impair_dst_ip("172.100.3.18".parse()?, wan)
        .apply(&conn).await?;

    // Network diagnostics — find issues, score bottlenecks.
    let report = Diagnostics::new(Connection::<Route>::new()?).scan().await?;

    // Reflector / watch-cache — keep an in-memory Store up to date from a
    // resync-aware event stream (kube-rs style), then read it from anywhere.
    use nlink::{NetworkEvent, Store, StoreOp};
    use nlink::netlink::{reflector::ReflectExt, resync::ConnectionFactory};
    let factory: ConnectionFactory<Route> = Arc::new(|| Box::pin(async { Connection::<Route>::new() }));
    let store: Store<u32, NetworkEvent> = Store::new();
    let watch = conn.into_events_with_resync(factory).await?.reflect(store.clone(), |ev| match ev {
        NetworkEvent::NewLink(l) => StoreOp::Upsert(l.ifindex()),
        NetworkEvent::DelLink(l) => StoreOp::Remove(l.ifindex()),
        _ => StoreOp::Ignore,
    });
    // drive `watch` in a task; `store.len()` / `store.get(&idx)` read the cache.

    // JSON Schema for config files (feature `schemars`) — editor/CI validation.
    let schema = NetworkConfig::json_schema();
    Ok(())
}
```

## Building blocks for downstream code

- **`ConnectionPool<P>`** — bounded async pool of typed connections; each lease
  gets its own kernel-side socket, so the kernel processes them in parallel.
- **`DumpStream<T>`** — `Stream` adapter over netlink dumps; O(1) memory on
  BGP/conntrack/IPsec-scale tables instead of buffering the full response.
- **`ResyncStream<T>`** — wraps multicast subscriptions with ENOBUFS recovery
  (`ResyncedEvent::Marker(ResyncStart)` → snapshot replay → `ResyncEnd`).
- **`nlink-macros`** — declare a custom Generic Netlink family in ~30 lines via
  `#[genl_family]` + `#[derive(GenlMessage)]`; consume through
  `conn.send_typed(req).await?` / `dump_typed_stream`. The in-tree DPLL and
  net_shaper families are the canonical dogfoods.

## Documentation

- [Library guide](docs/library.md) — detailed examples: namespaces, TC, WireGuard,
  error handling, concurrency.
- [Cookbook recipes](docs/recipes/README.md) — end-to-end walkthroughs
  (per-peer impairment, VLAN-aware bridges, bidirectional rate limiting,
  WireGuard mesh in namespaces, ENOBUFS-resync loops, define-your-own-GENL-family).
- [CLI reference](docs/cli.md) — command coverage for all ten demo
  binaries (`nlink-ip`, `nlink-tc`, `nlink-ss`, `nlink-nft`,
  `nlink-bridge`, `nlink-wg`, `nlink-config`, `nlink-devlink`,
  `nlink-ethtool`, `nlink-wifi`).
- [Migration guides](docs/migration_guide/README.md) — per-release upgrade notes.
- [Examples](crates/nlink/examples/README.md) — 40+ runnable demos.
- [docs.rs/nlink](https://docs.rs/nlink) — full API reference.

## Project status

API stable and used in production. Wire format pinned by build-time
`sizeof(struct …)` CI gates; concurrent shared-`Arc<Connection>` use is safe
(serialized via internal mutex — use `ConnectionPool` for parallel throughput).
19 CI gates on every push (build × 2 feature sets, tests × 2, clippy
`--deny warnings`, doc with strict intra-doc links, semver-checks, public-api
diff, machete, msrv, s390x big-endian cross-check, README/manifest sync, plus
8 nlink-specific audit scripts) + a privileged integration job that runs the
root-gated kernel round-trip suite.

## Building from source

```bash
cargo build --release
cargo run --release -p nlink-ip -- link show
cargo run --release -p nlink-tc -- qdisc show
```

## License

Apache 2.0 OR MIT, at your option.
