//! Async netlink library for Linux network configuration.
//!
//! This crate provides a complete netlink implementation for programmatic
//! network management on Linux. It supports RTNetlink (routing), traffic
//! control, socket diagnostics, and TUN/TAP device management.
//!
//! # Features
//!
//! - `sockdiag` - Socket diagnostics via NETLINK_SOCK_DIAG
//! - `tuntap` - TUN/TAP device management
//! - `tc` - Traffic control utilities
//! - `output` - JSON/text output formatting
//! - `full` - All features enabled
//!
//! # Example
//!
//! ```no_run
//! use nlink::netlink::{Connection, Route};
//!
//! #[tokio::main]
//! async fn main() -> nlink::netlink::Result<()> {
//!     let conn = Connection::<Route>::new()?;
//!
//!     // Query interfaces
//!     let links = conn.get_links().await?;
//!     for link in &links {
//!         // Use name_or() helper for cleaner code
//!         println!("{}: {}", link.ifindex(), link.name_or("?"));
//!     }
//!
//!     // Build ifindex -> name map for resolving routes/addresses
//!     let names = conn.get_interface_names().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Link State Management
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Bring an interface up
//! conn.set_link_up("eth0").await?;
//!
//! // Bring it down
//! conn.set_link_down("eth0").await?;
//!
//! // Set MTU
//! conn.set_link_mtu("eth0", 9000).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Network Namespace Support
//!
//! Operations can be performed in specific network namespaces:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, Generic};
//! use nlink::netlink::namespace;
//!
//! // Connect to a named namespace (created via `ip netns add myns`)
//! // Functions are generic over protocol type
//! let conn: Connection<Route> = Connection::new_in("myns")?;
//! let links = conn.get_links().await?;
//!
//! // Or connect to a container's namespace
//! # let container_pid = 1234;
//! let conn: Connection<Route> = Connection::new_in(namespace::NetnsRef::Pid(container_pid))?;
//! let links = conn.get_links().await?;
//!
//! // Or use a path directly
//! let conn: Connection<Route> = Connection::new_in(std::path::Path::new("/proc/1234/ns/net"))?;
//!
//! // Generic connections work too (e.g., for WireGuard in a namespace)
//! let genl: Connection<Generic> = Connection::new_in("myns")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Namespace safety — `_by_index` vs `_by_name`
//!
//! Every resource lookup that takes an interface comes in two
//! flavors: `*_by_index(ifindex: u32)` and `*_by_name(name: &str)`.
//! The `_by_index` form takes a kernel ifindex, which is **always**
//! relative to the connection's netns — safe to call from any
//! process mount namespace. The `_by_name` form goes through
//! `Connection::get_link_by_name(...)` which resolves via
//! `RTM_GETLINK` over the same socket (Plan 192 D4 corrected an
//! earlier `_by_name reads /sys/class/net/` design — both variants
//! are now netlink-correct; the difference is ergonomic, not a
//! namespace-safety footgun).
//!
//! For namespace-aware code, the canonical pattern is:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::{Connection, Route};
//! let conn = Connection::<Route>::new()?;
//! // One name resolution at startup, then ifindex everywhere:
//! let eth0_idx = conn.get_link_by_name("eth0").await?
//!     .ok_or(nlink::Error::interface_not_found("eth0"))?
//!     .ifindex();
//! conn.set_link_mtu_by_index(eth0_idx, 9000).await?;
//! # Ok(())
//! # }
//! ```
//!
//! This is a deliberate design choice. `neli` and
//! `vishvananda/netlink` both leave namespace handling to the
//! caller — a documented footgun in
//! [Cilium issue #40280](https://github.com/cilium/cilium/issues/40280).
//! nlink's typed `InterfaceRef::Index(u32)` plus the per-method
//! `_by_index` variants make namespace-correct code natural to
//! write, while `_by_name` stays available as the deliberate
//! convenience choice.
//!
//! # Event Monitoring
//!
//! Use `Connection::subscribe()` to select event types, then `events()` to get a stream:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
//!
//! let mut events = conn.events().await;
//! while let Some(event) = events.next().await {
//!     match event? {
//!         NetworkEvent::NewLink(link) => println!("New link: {:?}", link.name()),
//!         NetworkEvent::NewAddress(addr) => println!("New address: {:?}", addr.address()),
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Multi-Namespace Event Monitoring
//!
//! Use `tokio_stream::StreamMap` to monitor multiple namespaces:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, namespace};
//! use tokio_stream::{StreamExt, StreamMap};
//!
//! let mut streams = StreamMap::new();
//!
//! let conn1 = Connection::<Route>::new()?;
//! conn1.subscribe_all()?;
//! streams.insert("default", conn1.into_events().await);
//!
//! let conn2: Connection<Route> = Connection::new_in("ns1")?;
//! conn2.subscribe_all()?;
//! streams.insert("ns1", conn2.into_events().await);
//!
//! while let Some((ns, event)) = streams.next().await {
//!     println!("[{}] {:?}", ns, event?);
//! }
//! # Ok(())
//! # }
//! ```

// The Plan 154 derive macros generate code referencing
// `::nlink::macros::__rt::*` so the same expansion works
// uniformly from any downstream crate. Inside `nlink` itself
// that path would fail to resolve (no external crate named
// `nlink` from our own perspective); this `extern crate self as
// nlink` aliases the crate to its own external name so generated
// paths work here too. Required for the in-tree derive tests in
// `crate::macros::tests`.
extern crate self as nlink;

// Core modules (always available)
pub mod blocking;
pub mod facade;
pub mod macros;
pub mod netlink;
pub mod prelude;
pub mod util;

// Feature-gated modules
#[cfg(feature = "sockdiag")]
pub mod sockdiag;

#[cfg(feature = "tuntap")]
pub mod tuntap;

#[cfg(feature = "output")]
pub mod output;

#[cfg(feature = "lab")]
pub mod lab;

#[cfg(feature = "replay")]
pub mod replay;

// Re-export common types at crate root for convenience
// Namespace types
// Event types
// Route protocol multicast groups
// Bridge VLAN types
pub use netlink::bridge_vlan::{
    BridgeVlanBuilder, BridgeVlanEntry, BridgeVlanEntryOptions, BridgeVlanEntryOptionsBuilder,
    BridgeVlanFlags, BridgeVlanGlobalOptions, BridgeVlanGlobalOptionsBuilder, BridgeVlanState,
};
// Diagnostics types
pub use netlink::diagnostics::{
    Bottleneck, BottleneckType, ConnectivityReport, DiagnosticReport, Diagnostics,
    DiagnosticsConfig, InterfaceDiag, Issue, IssueCategory, IssueStream, RouteDiag, RouteInfo,
    Severity, TcDiag,
};
// Statistics: one `LinkRates` for the crate since 0.32 (#525); the root
// re-exported diagnostics' before.
pub use netlink::stats::{LinkRates, RateSampler, StatsSnapshot};
// FDB types
pub use netlink::fdb::{FdbEntry, FdbEntryBuilder};
// Per-peer impairment helper
pub use netlink::impair::{PeerImpairment, PeerMatch, PerPeerImpairer};
// Message types (commonly used)
pub use netlink::messages::{
    AddressMessage,
    // Type aliases for TcMessage
    ClassMessage,
    FilterMessage,
    LinkMessage,
    NeighborMessage,
    QdiscMessage,
    RouteMessage,
    RuleMessage,
    TcMessage,
};
// Sealed trait formalizing the `parse_params` contract on every typed TC
// config. Inherent methods stay; the trait is for generic dispatch.
pub use netlink::parse_params::ParseParams;
// Strongly-typed TC handle and filter priority — use these in new code at
// public boundaries instead of raw &str / u16.
pub use netlink::eth_proto::EthProto;
pub use netlink::tc_handle::{FilterPriority, TcHandle, TcHandleParseError};
// One reconcile vocabulary for every layer and recipe (#532), and how an
// apply executes (#519): `nlink::reconcile::*`, and the common names here.
pub use netlink::reconcile;
pub use netlink::reconcile::{
    ExecOptions, ReconcileOptions, ReconcileReport, StaleObject, UnmanagedObject,
};
pub use netlink::{
    Connection, Error, ErrorDetail, ErrorKind, ErrorObject, LinkCond, NamespaceSpec, NetworkEvent, Protocol, Result,
    ResultExt, RtnetlinkGroup,
    // `Error::validation` takes `impl IntoIterator<Item = ValidationErrorInfo>`
    // and this lived in a private module, so the public constructor was
    // uncallable from outside the crate (#280).
    ValidationErrorInfo,
};
// Default named-netns directory (`/var/run/netns`) — where
// `NamespaceSpec::Named` / `namespace::connection_for` resolve names
// (#169).
pub use netlink::namespace::NETNS_RUN_DIR;
// Plan 187 §2.2 — chain-walk iterator + convenience over the
// `&dyn Error` source chain that handles `Box<nlink::Error>`
// transparently.
pub use netlink::ChainWalk;
// Stream-based event API
pub use netlink::{EventMeta, EventSource, EventSubscription, OwnedEventStream, WithMeta};
// Protocol state types
pub use netlink::{Generic, Nftables, Route, Wireguard};
// Strongly-typed unit types (rate, byte, percent values used at TC API
// boundaries). Use these in new code; the kernel's unit confusion (bits/sec
// vs bytes/sec, decimal vs binary) is handled at type construction.
pub use util::{AddressFamily, Bytes, Packets, Percent, Rate};

// ---- Plan 148 §4.3 re-export hygiene ----------------------------------
// The route / address / rule builders and the extension traits users
// implement to add custom link/addr/route/neighbor types. Previously
// reachable only via deep `nlink::netlink::route::Ipv4Route`-style
// paths; surface them at the crate root for shorter imports.

// Route builders + nested types.
pub use netlink::route::{Ipv4Route, Ipv6Route, NextHop, RouteConfig, RouteMetrics};
// Address builders + extension trait.
pub use netlink::addr::{AddressConfig, Ipv4Address, Ipv6Address};
// Rule builder.
pub use netlink::rule::RuleBuilder;
// Link + neighbor extension traits for custom impl.
pub use netlink::link::LinkConfig;
pub use netlink::neigh::NeighborConfig;

// Connection pool (Plan 159) — bounded mpsc-channel-backed pool
// for high-fanout consumers.
pub use netlink::pool::{ConnectionPool, ConnectionPoolBuilder, PooledConnection};

// ENOBUFS resync helper types (Plan 151) — sum type yielded by a
// resync-aware event consumer, plus boundary markers, plus the
// pre-baked Stream wrapper (Plan 151 closeout). Plan 185 added
// the generic `ConnectionFactory<P>` / `ConnectionFuture<P>` —
// the boxed closure shape protocol-specific resync wrappers
// (e.g. `Connection<Nftables>::into_events_with_resync`) consume
// to materialise a fresh unicast connection on every ENOBUFS.
pub use netlink::resync::{
    ConnectionFactory, ConnectionFuture, ResyncMarker, ResyncStream, ResyncedEvent,
    events_with_resync,
};
// Reflector / watch-cache (Plan 195) — keep an in-memory `Store`
// up to date from a resync-aware event stream (`kube-rs`-style).
// `ReflectExt` (the stream combinator) lives at
// `netlink::reflector::ReflectExt`, mirroring `ResyncStreamExt`.
pub use netlink::reflector::{Store, StoreOp};

// Streaming dump API (Plan 149) — yield typed netlink dump
// messages one at a time.
pub use netlink::dump_stream::DumpStream;

// nftables flowtable (Plan 150) — flow-table fast path for the
// netfilter conntrack-cached forwarding bypass.
pub use netlink::nftables::Flowtable;

// Declarative nftables config (Plan 157) — diff + apply for
// tables/chains/rules/flowtables, mirroring NetworkConfig's shape.
pub use netlink::nftables::config::{
    DeclaredChain, DeclaredFlowtable, DeclaredRule, DeclaredTable, NftablesConfig,
    NftablesDiff,
};

// XFRM IPsec hardware offload (Plan 153.1) — request kernel push
// SA crypto/packet path onto NIC hardware.
pub use netlink::xfrm::{XfrmOffloadFlag, XfrmUserOffload};


// Plan 189 — `serde` feature flag JSON-shape tests.
// Verifies the kebab-case (struct) / snake_case (enum) JSON
// shape commitments of the gated `Serialize` impls. Gated on
// `cfg(feature = "serde")` so the non-serde build skips them.
#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use crate::netlink::config::{ConfigDiff, NetworkConfig};
    use crate::netlink::nftables::config::NftablesDiff;
    use crate::netlink::nftables::types::Family;

    #[test]
    fn types_implement_serialize() {
        fn assert_serialize<T: serde::Serialize>() {}
        assert_serialize::<ConfigDiff>();
        assert_serialize::<NftablesDiff>();
        assert_serialize::<crate::netlink::config::ApplyResult>();
        assert_serialize::<crate::ReconcileReport>();
    }

    #[test]
    fn config_diff_empty_serializes_to_known_shape() {
        let diff = ConfigDiff::default();
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&diff).unwrap()).unwrap();
        assert!(parsed["links-to-add"].is_array());
        assert!(parsed["links-to-modify"].is_array());
        assert!(parsed["addresses-to-add"].is_array());
        assert!(parsed["routes-to-add"].is_array());
        assert!(parsed["qdiscs-to-add"].is_array());
        // No snake_case bleed-through.
        let json = serde_json::to_string(&diff).unwrap();
        assert!(!json.contains(r#""links_to_add""#));
    }

    #[test]
    fn nftables_diff_empty_serializes_kebab_case_shape() {
        let diff = NftablesDiff::default();
        let json = serde_json::to_string(&diff).unwrap();
        // Spot-check the kebab-case is applied at the outer
        // diff level (precise field names vary by NftablesDiff
        // shape; we assert the no-underscore convention).
        assert!(!json.contains("_to_"), "expected kebab-case throughout: {json}");
    }

    #[test]
    fn family_enum_serializes_to_lowercase_string() {
        // Plan 189 §2.4 — enums are snake_case-renamed, so
        // unit variants emit bare strings instead of
        // `{"Inet": null}`-shape.
        assert_eq!(serde_json::to_string(&Family::Inet).unwrap(), r#""inet""#);
        assert_eq!(serde_json::to_string(&Family::Ip).unwrap(), r#""ip""#);
        assert_eq!(serde_json::to_string(&Family::Ip6).unwrap(), r#""ip6""#);
    }

    #[test]
    fn config_diff_with_link_carries_kebab_payload() {
        let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
        let mut diff = ConfigDiff::default();
        diff.links_to_add.push(cfg.links()[0].clone());
        let parsed: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&diff).unwrap()).unwrap();
        // The link object itself carries kebab-cased field names.
        assert_eq!(parsed["links-to-add"].as_array().unwrap().len(), 1);
        let link = &parsed["links-to-add"][0];
        assert_eq!(link["name"].as_str(), Some("eth0"));
        // DeclaredLinkType::Dummy serializes as bare string "dummy".
        assert_eq!(link["link-type"].as_str(), Some("dummy"));
    }
}

// #319 — the recipes under `docs/recipes/` are compiled as doctests. See
// `recipe_doctests.rs`; `cfg(doctest)` keeps it out of every normal build.
#[cfg(doctest)]
mod recipe_doctests;
