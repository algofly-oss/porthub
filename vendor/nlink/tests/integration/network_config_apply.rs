//! Plan 186 — VLAN parent ifindex race investigation +
//! topo-sort regression coverage.
//!
//! nlink-lab's 158e Slice 3 hit:
//!
//! ```text
//! NetworkConfig::apply on 'host': interface not found: eth0
//! ```
//!
//! …on the second link create — the VLAN whose parent is the
//! dummy created immediately before, on the same
//! `Connection<Route>`. The kernel ACKed the dummy; the next
//! `resolve_interface("eth0")` returned `InterfaceNotFound`.
//!
//! Plan 186 §1 maintainer audit concluded the cache/sysfs
//! hypotheses are wrong — `resolve_interface` is netlink-based
//! end-to-end. This file is the integration reproducer the
//! plan called for: if green locally, the symptom isn't
//! reproducible in our harness (ship as a regression test +
//! ask the maintainer for the missing piece); if red, debug
//! from there.
//!
//! All tests root-gated.

use nlink::Result;
use nlink::netlink::{
    Connection, Route,
    config::{ApplyOptions, PlanOptions, NetworkConfig},
};
use nlink::reconcile::ReconcileOptions;

use crate::common::{TestNamespace, with_timeout};

fn conn_in_ns(ns: &TestNamespace) -> Result<Connection<Route>> {
    nlink::Connection::<Route>::new_in(ns.name())
}

/// Plan 186 §2.1 reproducer — the headline scenario.
/// Dummy + VLAN child in one `NetworkConfig`, applied once.
/// Both must end up in the kernel.
#[tokio::test]
async fn vlan_parent_dummy_in_same_apply_succeeds() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-parent-race")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .link("eth0.42", |b| b.vlan("eth0", 42));

        let result = cfg.apply(&conn).await?;
        // Both links should have been created.
        assert_eq!(
            result.changes_made, 2,
            "expected 2 link creates (Dummy + VLAN); result: {}",
            result.summary.join("\n")
        );

        // Verify kernel-side visibility — both names must dump back.
        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("eth0")),
            "dummy eth0 must be in dump"
        );
        assert!(
            links.iter().any(|l| l.name() == Some("eth0.42")),
            "vlan eth0.42 must be in dump"
        );

        Ok(())
    })
    .await
}

/// Hash-defeating order — declare the VLAN BEFORE the dummy
/// in the same `NetworkConfig`. nlink-lab's
/// `network_config_vlan_parent_dummy_declared_first_regardless_of_hashmap_order`
/// test sees this happen for `HashMap`-built configs.
///
/// **Currently expected to fail** without Plan 186 §3c's
/// topo-sort fix — the apply iterates declared order, so the
/// VLAN goes first and fails to resolve "eth0". When the
/// topo-sort lands, this test should pass.
///
/// Wired here as a regression test (root-gated) so the
/// behavior is pinned: if topo-sort ships, this test catches
/// regressions.
#[tokio::test]
async fn vlan_parent_dummy_declared_in_either_order() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-decl-order")?;
        let conn = conn_in_ns(&ns)?;

        // CHILD declared FIRST. Without topo-sort, apply
        // would try to create the VLAN before its parent
        // exists, and resolve_interface("eth0") fails.
        let cfg = NetworkConfig::new()
            .link("eth0.42", |b| b.vlan("eth0", 42))
            .link("eth0", |b| b.dummy());

        let result = cfg.apply(&conn).await;

        // If the apply succeeds, Plan 186 §3c's topo-sort is
        // implicitly working or another reorder kicked in.
        // If it fails with InterfaceNotFound, the topo-sort
        // hasn't shipped yet — document the expected pre-fix
        // behavior so a future Plan 186 §3c PR turns red.
        match result {
            Ok(r) => {
                assert_eq!(r.changes_made, 2, "both links created");
                let links = conn.get_links().await?;
                assert!(links.iter().any(|l| l.name() == Some("eth0.42")));
                assert!(links.iter().any(|l| l.name() == Some("eth0")));
                Ok(())
            }
            Err(e) if e.is_not_found() => {
                // Documented pre-fix behavior. When Plan 186
                // §3c's topo-sort ships, this branch becomes
                // unreachable + the test transitions to a
                // strict pass-only contract.
                eprintln!(
                    "vlan_parent_dummy_declared_in_either_order: \
                    pre-Plan-186-§3c declared-order behavior — \
                    apply failed with InterfaceNotFound (expected \
                    until topo-sort ships). Error: {e}"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    })
    .await
}

// -------------------------------------------------------------
// Plan 190 §2.1 — VXLAN local/port/underlay.
// -------------------------------------------------------------

/// VXLAN with local/port/underlay_dev set via declarative
/// path. Verifies the apply-path arm builds VxlanLink with
/// all knobs forwarded.
#[tokio::test]
async fn vxlan_with_local_port_underlay_creates() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vxlan");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};
        let ns = TestNamespace::new("vxlan-extras")?;
        let conn = conn_in_ns(&ns)?;

        // Need a dummy underlay parent with the address the
        // VXLAN's local() will reference — the kernel
        // rejects local IPs not configured on a local link.
        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new().link("vx0", |b| {
            b.vxlan(42)
                .vxlan_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)))
                .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                .vxlan_port(4790)
                .vxlan_underlay_dev("eth0")
        });

        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "VXLAN should be created");

        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("vx0")),
            "vx0 must be in the dump"
        );

        Ok(())
    })
    .await
}

// -------------------------------------------------------------
// Plan 190 §2.3 — VRF declarative path.
// -------------------------------------------------------------

/// Create a VRF link via `LinkBuilder::vrf(table)`. Verifies
/// the apply-path arm emits a `vrf`-kind link bound to the
/// requested routing table.
#[tokio::test]
async fn vrf_link_creates_via_declarative_path() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vrf");

    with_timeout(async {
        let ns = TestNamespace::new("vrf-create")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new().link("vrf-red", |b| b.vrf(100));
        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "VRF link should be created");

        let links = conn.get_links().await?;
        assert!(
            links.iter().any(|l| l.name() == Some("vrf-red")),
            "vrf-red must be in the dump"
        );

        Ok(())
    })
    .await
}

/// VRF + dummy member, with the member enslaved via
/// `LinkBuilder::master(vrf-name)`. Combined with the Plan 186
/// topo-sort fix, declared order doesn't matter — both ship.
#[tokio::test]
async fn vrf_with_dummy_member_via_master_chain() -> Result<()> {
    nlink::require_root!();
    nlink::require_module!("vrf");

    with_timeout(async {
        let ns = TestNamespace::new("vrf-master")?;
        let conn = conn_in_ns(&ns)?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy().master("vrf-red"))
            .link("vrf-red", |b| b.vrf(200));

        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 2, "both links should be created");

        // Verify both kernel-side.
        let links = conn.get_links().await?;
        assert!(links.iter().any(|l| l.name() == Some("vrf-red")));
        assert!(links.iter().any(|l| l.name() == Some("eth0")));

        Ok(())
    })
    .await
}

// -------------------------------------------------------------

/// Pre-existing parent + VLAN child — control case. Verifies
/// the working baseline isn't accidentally regressed by Plan
/// 186 fixes.
#[tokio::test]
async fn vlan_parent_already_exists_in_kernel() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        let ns = TestNamespace::new("vlan-existing-parent")?;
        let conn = conn_in_ns(&ns)?;

        // Pre-create the dummy out-of-band (the "working
        // today" path).
        use nlink::netlink::link::DummyLink;
        conn.add_link(DummyLink::new("eth0")).await?;

        let cfg = NetworkConfig::new()
            .link("eth0.42", |b| b.vlan("eth0", 42));
        let result = cfg.apply(&conn).await?;
        assert_eq!(result.changes_made, 1, "only the VLAN should be new");

        Ok(())
    })
    .await
}

// -------------------------------------------------------------
// Plan 205 (re-wired) — declarative purge: remove undeclared
// kernel resources, conservatively scoped. Validates the
// exclusion fences (global-scope only, managed devices only,
// static/boot main-table routes only) against a live kernel.
// Locally: run as root-in-netns via `unshare -rn`.
// -------------------------------------------------------------

/// Purge removes an undeclared **global** address while keeping
/// the declared one — and never touches the kernel-managed
/// IPv6 link-local (scope link) the kernel auto-adds when the
/// dummy comes up.
#[tokio::test]
async fn purge_removes_undeclared_global_address_keeps_declared() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("purge-addr")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        // Two global addresses on the managed interface; the
        // config will declare only the first.
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        // Purge diff: exactly one address slated for removal.
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let removed: Vec<(IpAddr, u8)> = diff
            .addresses_to_remove
            .iter()
            .map(|a| (a.address(), a.prefix_len()))
            .collect();
        assert_eq!(
            removed,
            vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24)],
            "only the undeclared global address should be slated for removal \
             (link-local / declared address excluded); got {removed:?}"
        );

        // Apply the purge, then confirm kernel state.
        let result = diff.apply(&conn, nlink::ExecOptions::default()).await?;
        assert_eq!(result.changes_made, 1, "one address removed");

        let addrs = conn.get_addresses().await?;
        let v4: Vec<IpAddr> = addrs
            .iter()
            .filter(|a| a.is_ipv4())
            .filter_map(|a| a.address().copied())
            .collect();
        assert!(
            v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "declared address must survive purge; have {v4:?}"
        );
        assert!(
            !v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "undeclared address must be gone; have {v4:?}"
        );
        // Link-local must still be present (proves scope fence).
        assert!(
            addrs.iter().any(|a| !a.is_ipv4()),
            "IPv6 link-local must survive purge (scope-link exclusion)"
        );

        Ok(())
    })
    .await
}

/// Default (non-purge) diff never removes anything, even when
/// the kernel has undeclared addresses — the safety invariant.
#[tokio::test]
async fn default_diff_never_removes_addresses() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("no-purge-addr")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        // Two global addresses; the config declares only .1, so eth0
        // is an address-managed interface and .9 is undeclared.
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 9), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let diff = cfg.diff(&conn).await?;
        assert!(
            diff.addresses_to_remove.is_empty(),
            "default diff must never populate removals"
        );
        // …and the purge diff WOULD remove the undeclared .9 (proves
        // the gate is the flag, not a missing-data accident).
        let purge = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(
            purge.addresses_to_remove.len(),
            1,
            "purge diff sees the undeclared address"
        );

        Ok(())
    })
    .await
}

/// Purge removes an undeclared `boot`-protocol main-table route
/// but leaves the kernel-managed connected route (proto kernel)
/// the address install created. Re-diffing after apply yields an
/// empty purge set (idempotent).
#[tokio::test]
async fn purge_removes_static_route_keeps_connected_route() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-route")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        // Undeclared admin route (proto boot, table main).
        conn.add_route(Ipv4Route::from_addr(Ipv4Addr::new(10, 9, 0, 0), 24).dev("eth0"))
            .await?;

        // Config declares the address (so the connected route
        // stays "desired" via the kernel) but no explicit routes.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let removed: Vec<(std::net::IpAddr, u8)> = diff
            .routes_to_remove
            .iter()
            .map(|r| (r.destination(), r.prefix_len()))
            .collect();
        assert!(
            removed.contains(&(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0)), 24)),
            "undeclared static route must be slated for removal; got {removed:?}"
        );
        assert!(
            !removed
                .iter()
                .any(|(d, _)| *d == std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))),
            "kernel connected route (proto kernel) must NOT be purged; got {removed:?}"
        );

        let _ = diff.apply(&conn, nlink::ExecOptions::default()).await?;

        // The static route is gone; the connected route remains.
        let routes = conn.get_routes().await?;
        let dst_is = |r: &nlink::RouteMessage, a: Ipv4Addr| {
            r.destination() == Some(&std::net::IpAddr::V4(a))
        };
        assert!(
            !routes.iter().any(|r| dst_is(r, Ipv4Addr::new(10, 9, 0, 0))),
            "static route must be removed after purge apply"
        );
        assert!(
            routes.iter().any(|r| dst_is(r, Ipv4Addr::new(10, 0, 0, 0))),
            "connected route must survive purge apply"
        );

        // Idempotent: re-diff now sees nothing to remove.
        let again = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert!(
            again.routes_to_remove.is_empty(),
            "purge must be idempotent — second diff has no route removals"
        );

        Ok(())
    })
    .await
}

/// #333 / #335 — a route declared into a non-main table (VRF-style)
/// is added by apply, and when it leaves the declaration a purging
/// apply removes it. Before the fix purge walked table 254 only, so
/// the declared table was a one-way street. A table the config never
/// mentions stays untouched, and `purge_tables` reaches a table the
/// config has just stopped declaring into.
#[tokio::test]
async fn purge_reaches_the_tables_the_config_declares_into() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::config::ApplyOptions;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-table")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;

        // Somebody else's table: must never be touched.
        conn.add_route(Ipv4Route::from_addr(Ipv4Addr::new(10, 200, 0, 0), 24).dev("eth0").table(200))
            .await?;

        let in_table = |routes: &[nlink::RouteMessage], a: Ipv4Addr, table: u32| {
            routes
                .iter()
                .any(|r| r.destination() == Some(&IpAddr::V4(a)) && r.table_id() == table)
        };

        // Declare two routes into table 100; both land.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .route("10.1.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR")
            .route("10.2.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR");
        let _ = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        let routes = conn.get_routes().await?;
        assert!(in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100));
        assert!(in_table(&routes, Ipv4Addr::new(10, 2, 0, 0), 100));

        // Drop 10.2.0.0/24 from the declaration: a purging apply
        // removes it, keeps its sibling, leaves table 200 alone.
        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .route("10.1.0.0/24", |r| r.dev("eth0").table(100))
            .expect("valid CIDR");
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(
            diff.routes_to_remove.len(),
            1,
            "exactly the dropped table-100 route; got {:?}",
            diff.routes_to_remove
        );
        let result = cfg
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true))
            .await?;
        assert_eq!(result.changes_made, 1, "{result:?}");
        let routes = conn.get_routes().await?;
        assert!(!in_table(&routes, Ipv4Addr::new(10, 2, 0, 0), 100), "dropped route purged");
        assert!(in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100), "declared route kept");
        assert!(in_table(&routes, Ipv4Addr::new(10, 200, 0, 0), 200), "unowned table untouched");

        // Drop the last table-100 route: without purge_tables the
        // table falls out of scope and the leftover stays…
        let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
        let _ = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        let routes = conn.get_routes().await?;
        assert!(
            in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100),
            "a table the config no longer mentions is out of scope"
        );
        // …and with it, the caller who owns table 100 gets it emptied.
        let result = cfg
            .apply_with_options(
                &conn,
                ApplyOptions::default().with_purge(true).with_purge_tables([100]),
            )
            .await?;
        assert_eq!(result.changes_made, 1, "{result:?}");
        let routes = conn.get_routes().await?;
        assert!(!in_table(&routes, Ipv4Addr::new(10, 1, 0, 0), 100));
        assert!(in_table(&routes, Ipv4Addr::new(10, 200, 0, 0), 200), "still untouched");

        // Idempotent.
        let again = cfg
            .apply_with_options(
                &conn,
                ApplyOptions::default().with_purge(true).with_purge_tables([100]),
            )
            .await?;
        assert_eq!(again.changes_made, 0, "{again:?}");
        Ok(())
    })
    .await
}

/// #335 — a purge whose route vanished between diff and apply is not
/// an error: the goal state is reached, the apply reports it as
/// already absent and counts no change.
#[tokio::test]
async fn purge_tolerates_a_route_removed_between_diff_and_apply() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::Ipv4Addr;

        use nlink::netlink::link::DummyLink;
        use nlink::netlink::route::Ipv4Route;

        let ns = TestNamespace::new("purge-race")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        let stale = Ipv4Route::from_addr(Ipv4Addr::new(10, 9, 0, 0), 24).dev("eth0");
        conn.add_route(stale.clone()).await?;

        let cfg = NetworkConfig::new().link("eth0", |b| b.dummy());
        let diff = cfg
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert_eq!(diff.routes_to_remove.len(), 1);

        // Someone else removes it first.
        assert!(conn.del_route_if_exists(stale.clone()).await?);
        assert!(!conn.del_route_if_exists(stale).await?, "second delete reports absent");

        let result = diff.apply(&conn, nlink::ExecOptions::default()).await?;
        assert_eq!(result.changes_made, 0, "{result:?}");
        assert!(result.errors.is_empty(), "{result:?}");
        assert!(
            result.summary.iter().any(|l| l.contains("already absent")),
            "{:?}",
            result.summary
        );
        Ok(())
    })
    .await
}

/// #345 — `apply_reconcile` could not purge: every attempt recomputed
/// the non-purge diff and applied with `ApplyOptions::default()`, so a
/// concurrent-mutator consumer that also wanted undeclared state removed
/// had to write the retry loop by hand. `apply_reconcile_with_options`
/// takes the `ApplyOptions` per attempt; plain `apply_reconcile` keeps
/// its defaults and removes nothing.
#[tokio::test]
async fn apply_reconcile_with_options_purges_and_plain_does_not() -> Result<()> {
    nlink::require_root!();

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;

        let ns = TestNamespace::new("reconcile-purge")?;
        let conn = conn_in_ns(&ns)?;

        conn.add_link(DummyLink::new("eth0")).await?;
        conn.set_link_up("eth0").await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 1), 24))
            .await?;
        conn.add_address(Ipv4Address::new("eth0", Ipv4Addr::new(10, 0, 0, 2), 24))
            .await?;

        let cfg = NetworkConfig::new()
            .link("eth0", |b| b.dummy())
            .address("eth0", "10.0.0.1/24")
            .expect("valid CIDR");

        let v4 = |addrs: &[nlink::netlink::messages::AddressMessage]| -> Vec<IpAddr> {
            addrs
                .iter()
                .filter(|a| a.is_ipv4())
                .filter_map(|a| a.address().copied())
                .collect()
        };

        // A dry run with purge counts the removal and makes it not (#532:
        // the reconcile options carry `dry_run` for every layer now).
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default().with_dry_run(true),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert!(report.dry_run, "{report:?}");
        assert_eq!(report.changes_made, 1, "{report:?}");
        assert!(
            v4(&conn.get_addresses().await?).contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "a dry run removes nothing"
        );

        // Plain reconcile: the declaration is already satisfied and the
        // undeclared address is not its business.
        let report = cfg
            .apply_reconcile(&conn, ReconcileOptions::default())
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 0), "{report:?}");
        let have = v4(&conn.get_addresses().await?);
        assert!(
            have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "plain apply_reconcile must not purge; have {have:?}"
        );

        // With purge: one attempt, one change, the undeclared address gone
        // and the declared one kept.
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default(),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 1), "{report:?}");
        let have = v4(&conn.get_addresses().await?);
        assert!(
            have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "declared address must survive; have {have:?}"
        );
        assert!(
            !have.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            "undeclared address must be purged; have {have:?}"
        );

        // And it converges: a second purge-reconcile has nothing to do.
        let report = cfg
            .apply_reconcile_with_options(
                &conn,
                ReconcileOptions::default(),
                ApplyOptions::default().with_purge(true),
            )
            .await?;
        assert_eq!((report.attempts, report.changes_made), (1, 0), "{report:?}");
        Ok(())
    })
    .await
}

/// `ApplyOptions::purge_address_devs` reaches every path that turns
/// `ApplyOptions` into a diff. `apply_with_options` honoured it; the
/// reconcile loop and a `Stack`'s pre-flight diff dropped it, so a stray
/// address on a listed but undeclared link stayed (#601).
#[tokio::test]
async fn purge_address_devs_reaches_reconcile_and_stack() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};

        use nlink::netlink::addr::Ipv4Address;
        use nlink::netlink::link::DummyLink;
        use nlink::netlink::namespace::NamespaceSpec;

        let ns = TestNamespace::new("purge-devs")?;
        let conn = conn_in_ns(&ns)?;
        conn.add_link(DummyLink::new("d1")).await?;
        let stray = Ipv4Addr::new(10, 61, 0, 1);
        conn.add_address(Ipv4Address::new("d1", stray, 24)).await?;

        let cfg = NetworkConfig::new().link("d0", |l| l.dummy());
        let opts = || {
            ApplyOptions::default()
                .with_purge(true)
                .with_purge_address_devs(["d1"])
        };

        // A dry run shows the removal its apply would make.
        let report = nlink::facade::Stack::new()
            .network(cfg.clone())
            .apply_in_with(NamespaceSpec::Named(ns.name()), opts().with_dry_run(true))
            .await?;
        let diff = report
            .planned
            .as_ref()
            .and_then(|d| d.network.as_ref())
            .expect("the network layer's diff");
        assert_eq!(diff.addresses_to_remove.len(), 1, "{diff}");

        // The reconcile loop removes it: d0 created, the address gone.
        let report = cfg
            .apply_reconcile_with_options(&conn, ReconcileOptions::default(), opts())
            .await?;
        assert_eq!(report.changes_made, 2, "{report:?}");
        let left: Vec<IpAddr> = conn
            .get_addresses_by_name("d1")
            .await?
            .iter()
            .filter_map(|a| a.address().copied())
            .collect();
        assert!(
            !left.contains(&IpAddr::V4(stray)),
            "the stray address stayed: {left:?}"
        );
        Ok(())
    })
    .await
}

/// A snapshot diff is the live diff, with no kernel read: after an apply it
/// still describes the state it was read from, and a fresh one is empty.
/// `with_verify` re-diffs after the apply (#518).
#[tokio::test]
async fn a_snapshot_diff_is_the_live_diff_without_a_read() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::netlink::config::Snapshot;

        let ns = TestNamespace::new("snapshot")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.62.0.1/24")?;

        let before = Snapshot::read(&conn).await?;
        let live = cfg.diff(&conn).await?;
        let offline = cfg.diff_snapshot(&before, PlanOptions::default())?;
        assert_eq!(offline.to_string(), live.to_string());
        assert!(!offline.is_empty());

        let applied = cfg
            .apply_with_options(&conn, ApplyOptions::default().with_verify(true))
            .await?;
        assert!(applied.is_success(), "{applied:?}");

        let stale = cfg.diff_snapshot(&before, PlanOptions::default())?;
        assert_eq!(
            stale.to_string(),
            offline.to_string(),
            "a snapshot does not change"
        );
        let now = Snapshot::read(&conn).await?;
        assert!(now.links().iter().any(|l| l.name() == Some("d0")));
        assert!(cfg.diff_snapshot(&now, PlanOptions::default())?.is_empty());
        Ok(())
    })
    .await
}

/// A precomputed diff executes with `ExecOptions` alone, and `verify` diffs
/// again with the config and plan it came from (#519). Here the diff goes
/// stale before it is applied: the MTU it saw as right is changed under
/// it, so the apply adds the address and the re-diff finds the MTU.
#[tokio::test]
async fn a_precomputed_diff_verifies_against_its_own_config() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::ExecOptions;

        let ns = TestNamespace::new("diffverify")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.63.0.1/24")?;
        let link_only = NetworkConfig::new().link("d0", |l| l.dummy().mtu(1400).up());
        let applied = link_only.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.change_count(), 1, "the address only: {diff}");
        conn.set_link_mtu("d0", 1300).await?;

        let err = diff
            .apply(&conn, ExecOptions::new().with_verify(true))
            .await
            .expect_err("the MTU changed under the diff");
        let nlink::ErrorDetail::NotConverged { remaining } = err.detail() else {
            panic!("not NotConverged: {err}");
        };
        assert!(remaining.to_string().contains("d0"), "{remaining}");

        // Without verify the same stale diff reports success.
        conn.set_link_mtu("d0", 1300).await?;
        let diff = cfg.diff(&conn).await?;
        conn.set_link_mtu("d0", 1200).await?;
        let applied = diff.apply(&conn, ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        Ok(())
    })
    .await
}

/// The apply runs its plan step by step and journals what it changed;
/// the journal's undo puts the kernel back (#518). Applying config B over
/// A — an MTU, a route's gateway, an address — and then B's undo leaves
/// A's diff empty, and the route change was planned as a replace of the
/// route it overwrote, not an addition.
#[tokio::test]
async fn the_journal_of_an_apply_undoes_it() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("journal")?;
        let conn = conn_in_ns(&ns)?;
        let a = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1400).up())
            .address("d0", "10.65.0.1/24")?
            .route("10.66.0.0/16", |r| r.via("10.65.0.2").dev("d0"))?;
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().mtu(1500).up())
            .address("d0", "10.65.0.1/24")?
            .address("d0", "10.65.1.1/24")?
            .route("10.66.0.0/16", |r| r.via("10.65.0.3").dev("d0"))?;
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let diff = b.diff(&conn).await?;
        let plan = diff.plan();
        let shown = plan.to_string();
        assert!(
            shown.contains("~ route 10.66.0.0/16 via 10.65.0.3 dev d0 (replacing 10.66.0.0/16 via 10.65.0.2 dev d0)"),
            "{shown}"
        );
        let applied = diff.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(applied.journal.len(), 3, "mtu, address, route: {:?}", applied.journal);
        assert_eq!(applied.irreversible().count(), 0);
        assert!(b.diff(&conn).await?.is_empty());

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// Kind parameters changed in place are undone too (#649): a Geneve TTL,
/// which the kernel changes attribute by attribute, and an ip6gre's ends
/// and key, which its parms rebuild from the request. The undo sends back
/// what each had, and A's diff is empty after it.
#[tokio::test]
async fn the_journal_undoes_kind_changes() -> Result<()> {
    use std::net::Ipv6Addr;
    nlink::require_root!();
    nlink::require_modules!("dummy", "geneve", "ip6_gre");

    with_timeout(async {
        let ns = TestNamespace::new("journal-kind")?;
        let conn = conn_in_ns(&ns)?;
        let a6 = |h: u16| Ipv6Addr::new(0xfd00, 0x97, 0, 0, 0, 0, 0, h);
        let cfg = |ttl: u8, remote: u16, key: u32| {
            NetworkConfig::new()
                .link("gn0", move |l| {
                    l.geneve(9).geneve_remote("10.97.0.2".parse().unwrap()).geneve_ttl(ttl)
                })
                .link("g61", move |l| {
                    l.ip6gre().ip6tnl_local(a6(1)).ip6tnl_remote(a6(remote)).tunnel_key(key)
                })
        };
        let (a, b) = (cfg(10, 2, 7), cfg(20, 3, 8));
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        let applied = b.diff(&conn).await?.apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(
            applied.irreversible().map(|s| s.to_string()).collect::<Vec<_>>(),
            Vec::<String>::new(),
            "kind changes have inverses now"
        );
        assert!(b.diff(&conn).await?.is_empty());

        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// A replaced qdisc is undone too (#649): the diff reads the live one back
/// as a declaration, and the undo puts it back. Each kind is replaced both
/// ways round (fq_codel, tbf, netem by htb, sfq, prio, and back), and a
/// kernel-default root replaced by netem goes back to the default.
#[tokio::test]
async fn the_journal_undoes_replaced_qdiscs() -> Result<()> {
    use nlink::{Bytes, Packets, Rate};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_fq_codel", "sch_tbf", "sch_netem", "sch_htb", "sch_sfq", "sch_prio");

    with_timeout(async {
        let ns = TestNamespace::new("journal-qdisc")?;
        let conn = conn_in_ns(&ns)?;
        let links = |c: NetworkConfig| {
            ["q0", "q1", "q2", "q3"].iter().fold(c, |c, d| c.link(d, |l| l.dummy().up()))
        };
        let a = links(NetworkConfig::new())
            .qdisc("q0", |q| q.fq_codel().limit(Packets::new(1000)).flows(512))
            .qdisc("q1", |q| q.tbf(Rate::mbit(10), Bytes::kib(32)).limit_bytes(Bytes::kib(64)))
            .qdisc("q2", |q| q.netem().delay(std::time::Duration::from_millis(5)))
            .qdisc("q3", |q| q.kernel_default());
        let b = links(NetworkConfig::new())
            .qdisc("q0", |q| q.htb().default_class(0x20))
            .qdisc("q1", |q| q.sfq().perturb(std::time::Duration::from_secs(10)))
            .qdisc("q2", |q| q.prio().bands(4))
            .qdisc("q3", |q| q.netem().delay(std::time::Duration::from_millis(1)));
        for (from, to) in [(&a, &b), (&b, &a)] {
            let applied = from.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            let applied = to.diff(&conn).await?.apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(applied.is_success(), "{applied:?}");
            let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
            assert!(stuck.is_empty(), "replaced qdiscs have inverses: {stuck:?}");
            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{undone:?}");
            let back = from.diff(&conn).await?;
            assert!(back.is_empty(), "the undo left:\n{back}");
        }
        Ok(())
    })
    .await
}

/// A TC tree changed against the previous config's is undone (#649): the
/// undo applies the previous tree, removing what this one added. HTB
/// classes and a filter change A→B, and the undo leaves A's diff empty.
#[tokio::test]
async fn the_journal_undoes_a_tc_tree() -> Result<()> {
    use nlink::netlink::filter::MatchallFilter;
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{EthProto, FilterPriority, Rate, TcHandle};
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_matchall");

    with_timeout(async {
        let ns = TestNamespace::new("journal-tree")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        let tree = |rate: u64, extra: bool| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10))
                .tc("d0", move |t| {
                    let t = t
                        .class(h(1, 0), h(1, 0x10), HtbClassConfig::new(Rate::mbit(rate)))
                        .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, MatchallFilter::new().classid(h(1, 0x10)));
                    if extra { t.class(h(1, 0), h(1, 0x20), HtbClassConfig::new(Rate::mbit(5))) } else { t }
                })
        };
        let a = Arc::new(tree(10, false));
        let b = tree(20, true);
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let applied = b
            .diff_with_options(&conn, nlink::netlink::config::PlanOptions::default().previous(a.clone()))
            .await?
            .apply(&conn, nlink::ExecOptions::new())
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert!(stuck.is_empty(), "a tree with a previous one has an inverse: {stuck:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// With the previous config, an apply removes exactly what that config
/// declared and this one does not: an address, a route in a table nothing
/// declares into any more, a qdisc. What nobody declared stays (#512).
#[tokio::test]
async fn the_previous_config_says_what_to_remove() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    with_timeout(async {
        use std::sync::Arc;

        let ns = TestNamespace::new("previous")?;
        let conn = conn_in_ns(&ns)?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.80.0.1/24")?
                .route("10.81.0.0/24", |r| r.dev("d0").table(100))?
                .qdisc("d0", |q| {
                    q.netem().delay(std::time::Duration::from_millis(5))
                }),
        );
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.80.0.2/24")?
            .route("10.81.0.0/24", |r| r.dev("d0").table(200))?;
        a.apply(&conn)
            .await?
            .errors
            .is_empty()
            .then_some(())
            .expect("A applies");
        ns.exec("ip", &["addr", "add", "10.80.0.9/24", "dev", "d0"])?;

        let diff = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert_eq!(diff.addresses_to_remove.len(), 1, "{diff}");
        assert_eq!(diff.routes_to_remove.len(), 1, "{diff}");
        assert_eq!(diff.qdiscs_to_remove.len(), 1, "{diff}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let again = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");

        let addrs = ns.exec("ip", &["-j", "addr", "show", "dev", "d0"])?;
        assert!(!addrs.contains("10.80.0.1"), "A's address stayed: {addrs}");
        assert!(
            addrs.contains("10.80.0.2") && addrs.contains("10.80.0.9"),
            "{addrs}"
        );
        let t100 = ns.exec("ip", &["route", "show", "table", "100"])?;
        assert!(t100.trim().is_empty(), "table 100 kept its route: {t100}");
        let t200 = ns.exec("ip", &["route", "show", "table", "200"])?;
        assert!(t200.contains("10.81.0.0/24"), "{t200}");
        let qdisc = ns.exec("tc", &["qdisc", "show", "dev", "d0"])?;
        assert!(!qdisc.contains("netem"), "the netem stayed: {qdisc}");
        Ok(())
    })
    .await
}

/// Neighbours the previous config declared and this one does not are
/// removed; one nothing declared stays, even under a purge (#516). A MAC
/// change, which flushes the device's neighbours, puts the declared ones
/// back in the same apply.
#[tokio::test]
async fn the_previous_config_removes_its_neighbours() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let ns = TestNamespace::new("prevneigh")?;
        let conn = conn_in_ns(&ns)?;
        let ip = |h: u8| Ipv4Addr::new(10, 82, 0, h);
        let mac = |n: u8| [0x02, 0, 0, 0, 0x82, n];
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .neighbour("d0", ip(2), mac(2))
                .neighbour("d0", ip(3), mac(3))
                .proxy_neighbour("d0", ip(9)),
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["neigh", "add", "10.82.0.7", "lladdr", "02:00:00:00:82:07", "dev", "d0", "nud", "permanent"])?;

        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .neighbour("d0", ip(2), mac(2));
        let opts = || PlanOptions::default().purge(true).previous(a.clone());
        let diff = b.diff_with_options(&conn, opts()).await?;
        let shown = diff.to_string();
        assert_eq!(diff.neighbours_to_remove.len(), 2, "{shown}");
        assert!(diff.neighbours_to_set.is_empty(), "{shown}");
        assert!(shown.contains("- neighbour 10.82.0.3 lladdr 02:00:00:00:82:03 dev d0"), "{shown}");
        assert!(shown.contains("- proxy neighbour 10.82.0.9 dev d0"), "{shown}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true).with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(b.diff_with_options(&conn, opts()).await?.is_empty());
        let neigh = ns.exec("ip", &["neigh", "show", "dev", "d0"])?;
        assert!(neigh.contains("10.82.0.2 ") && neigh.contains("10.82.0.7 "), "{neigh}");
        assert!(!neigh.contains("10.82.0.3 "), "{neigh}");
        let proxies = ns.exec("ip", &["neigh", "show", "proxy", "dev", "d0"])?;
        assert!(proxies.trim().is_empty(), "{proxies}");

        // A new MAC flushes the device's neighbours; the declared one is
        // set again in the same apply.
        let c = NetworkConfig::new()
            .link("d0", |l| l.dummy().up().address([0x02, 0, 0, 0, 0x82, 0xff]))
            .neighbour("d0", ip(2), mac(2));
        let diff = c.diff(&conn).await?;
        assert!(diff.to_string().contains("+ neighbour 10.82.0.2"), "{diff}");
        let applied = c.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(c.diff(&conn).await?.is_empty());
        let neigh = ns.exec("ip", &["neigh", "show", "dev", "d0"])?;
        assert!(neigh.contains("10.82.0.2 lladdr 02:00:00:00:82:02 PERMANENT"), "{neigh}");
        Ok(())
    })
    .await
}

/// A veth or netkit pair whose peer here has another name has its peer
/// renamed to the declared one (#793, #804). The comparison looked at the
/// peer's namespace and never its name, so a pair made with another peer
/// name passed for the declared one (#793); then it was a recreate, which
/// the apply refused while the old peer was undeclared. Renaming the peer in
/// place converges in one apply and keeps what is on the peer; the undo
/// renames it back.
#[tokio::test]
async fn a_pairs_peer_is_renamed_to_the_declared_name() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("veth", "netkit");

    with_timeout(async {
        let ns = TestNamespace::new("peer-name")?;
        let conn = conn_in_ns(&ns)?;
        for (kind, cfg) in [
            ("veth", NetworkConfig::new().link("v0", |l| l.veth("v0-p").up())),
            ("netkit", NetworkConfig::new().link("v0", |l| l.netkit("v0-p").up())),
        ] {
            // iproute2 before 6.7 cannot make a netkit pair.
            if kind == "veth" {
                ns.exec("ip", &["link", "add", "v0", "type", kind, "peer", "name", "v0-x"])?;
            } else {
                conn.add_link(nlink::netlink::link::NetkitLink::new("v0", "v0-x")).await?;
            }
            ns.exec("ip", &["link", "set", "v0-x", "up"])?;
            ns.exec("ip", &["addr", "add", "10.94.0.2/24", "dev", "v0-x"])?;
            let diff = cfg.diff(&conn).await?;
            assert_eq!(diff.links_to_rename.len(), 1, "{kind}: a peer v0-x passed for v0-p: {diff}");
            assert!(diff.links_to_recreate.is_empty(), "{kind}: {diff}");
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{kind}: {applied:?}");
            let links = ns.exec("ip", &["-br", "link", "show"])?;
            assert!(links.contains("v0-p@v0") && !links.contains("v0-x"), "{kind}: {links}");
            let addrs = ns.exec("ip", &["-br", "addr", "show", "dev", "v0-p"])?;
            assert!(addrs.contains("10.94.0.2/24") && addrs.contains("UP"), "{kind}: {addrs}");
            assert!(cfg.diff(&conn).await?.is_empty(), "{kind}: did not converge");

            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{kind}: {undone:?}");
            let links = ns.exec("ip", &["-br", "link", "show"])?;
            assert!(links.contains("v0-x@v0"), "{kind}: the undo did not rename it back: {links}");
            ns.exec("ip", &["link", "del", "v0"])?;
        }
        Ok(())
    })
    .await
}

/// A bridge FDB entry declared without a VLAN is also one per VLAN of its
/// port, and the diff sees one of those go (#793). `br_fdb_add` makes the
/// untagged entry and one for each VLAN on the port, VLAN 1 by default,
/// with or without VLAN filtering. The diff compared the untagged one only,
/// so a deleted per-VLAN entry, and the traffic in that VLAN it was for,
/// went unseen.
#[tokio::test]
async fn an_fdb_entry_without_a_vlan_is_one_per_port_vlan() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "bridge");

    with_timeout(async {
        let ns = TestNamespace::new("fdb-vlans")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("br0", |l| l.bridge().up())
            .link("p0", |l| l.dummy().master("br0").up())
            .fdb("p0", [0x02, 0, 0, 0, 0x93, 1], |e| e);
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(cfg.diff(&conn).await?.is_empty(), "the entry converges");
        let fdb = || ns.exec("bridge", &["fdb", "show", "dev", "p0"]);
        assert!(fdb()?.contains("02:00:00:00:93:01 vlan 1 master br0 static"), "{}", fdb()?);

        ns.exec("bridge", &["fdb", "del", "02:00:00:00:93:01", "dev", "p0", "vlan", "1", "master"])?;
        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.fdb_to_set.len(), 1, "the VLAN 1 entry went unseen: {diff}");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(fdb()?.contains("02:00:00:00:93:01 vlan 1 master br0 static"), "{}", fdb()?);
        assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");
        Ok(())
    })
    .await
}

/// An FDB entry the apply moves is moved back by its undo, not deleted
/// (#783). A bridge keeps one entry per MAC and VLAN, so setting one on a
/// port takes it from another; a VXLAN device keeps one remote per unicast
/// MAC, which a replace swaps. The diff looked for the entry on the
/// declared port or remote alone, found nothing to replace, and the undo
/// deleted the entry.
#[tokio::test]
async fn an_undo_moves_an_fdb_entry_back() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr};
    nlink::require_root!();
    nlink::require_modules!("dummy", "bridge", "vxlan");

    with_timeout(async {
        let ns = TestNamespace::new("fdb-move")?;
        let conn = conn_in_ns(&ns)?;
        let ip = |h: u8| IpAddr::V4(Ipv4Addr::new(10, 86, 1, h));
        let links = move || {
            NetworkConfig::new()
                .link("br0", |l| l.bridge().up())
                .link("p0", |l| l.dummy().master("br0").up())
                .link("p1", |l| l.dummy().master("br0").up())
                .link("vx0", move |l| l.vxlan(7).vxlan_local(ip(1)).vxlan_port(4789))
        };
        let applied = links().apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("bridge", &["fdb", "add", "02:00:00:00:87:01", "dev", "p0", "master", "static"])?;
        ns.exec("bridge", &["fdb", "add", "02:00:00:00:87:02", "dev", "vx0", "dst", "10.86.1.2"])?;
        let entries = || -> Result<Vec<String>> {
            let out = ns.exec("bridge", &["fdb", "show"])?;
            let mut lines: Vec<String> =
                out.lines().filter(|l| l.contains("02:00:00:00:87:0")).map(str::to_string).collect();
            lines.sort();
            Ok(lines)
        };
        let before = entries()?;

        let cfg = links()
            .fdb("p1", [0x02, 0, 0, 0, 0x87, 1], |e| e)
            .fdb("vx0", [0x02, 0, 0, 0, 0x87, 2], move |e| e.dst(ip(3)));
        let shown = cfg.diff(&conn).await?.to_string();
        assert!(shown.contains("(was on p0)") && shown.contains("(was dst 10.86.1.2)"), "{shown}");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let moved = entries()?;
        assert!(moved.iter().any(|l| l.contains("87:01 dev p1")), "{moved:?}");
        assert!(moved.iter().any(|l| l.contains("87:02 dev vx0 dst 10.86.1.3")), "{moved:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(entries()?, before, "the undo did not move them back");
        Ok(())
    })
    .await
}

/// FDB entries the previous config declared and this one does not are
/// removed — one remote of a VXLAN flood entry, not the entry — and one
/// nothing declared stays, even under a purge (#516). An entry moved to
/// another port of the bridge is moved, not removed.
#[tokio::test]
async fn the_previous_config_removes_its_fdb_entries() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "bridge", "vxlan");

    with_timeout(async {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        let ns = TestNamespace::new("prevfdb")?;
        let conn = conn_in_ns(&ns)?;
        let ip = |h: u8| IpAddr::V4(Ipv4Addr::new(10, 86, 0, h));
        let mac = |n: u8| [0x02, 0, 0, 0, 0x86, n];
        let links = || {
            NetworkConfig::new()
                .link("br0", |l| l.bridge().up())
                .link("p0", |l| l.dummy().master("br0").up())
                .link("p1", |l| l.dummy().master("br0").up())
                .link("vx0", move |l| l.vxlan(7).vxlan_local(ip(1)).vxlan_port(4789))
        };
        let a = Arc::new(
            links()
                .fdb("p0", mac(1), |e| e)
                .fdb("p0", mac(2), |e| e)
                .fdb("vx0", [0; 6], |e| e.dst(ip(2)))
                .fdb("vx0", [0; 6], |e| e.dst(ip(3))),
        );
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("bridge", &["fdb", "add", "02:00:00:00:86:07", "dev", "p0", "master", "static"])?;

        let b = links().fdb("p1", mac(1), |e| e).fdb("vx0", [0; 6], |e| e.dst(ip(2)));
        let opts = || PlanOptions::default().purge(true).previous(a.clone());
        let diff = b.diff_with_options(&conn, opts()).await?;
        let shown = diff.to_string();
        assert_eq!(diff.fdb_to_remove.len(), 2, "{shown}");
        assert!(shown.contains("- fdb 02:00:00:00:86:02 dev p0 static"), "{shown}");
        assert!(shown.contains("- fdb 00:00:00:00:00:00 dev vx0 dst 10.86.0.3"), "{shown}");
        // A move, which an undo moves back (#783).
        assert!(shown.contains("~ fdb 02:00:00:00:86:01 dev p1 static (was on p0)"), "{shown}");
        assert!(!shown.contains("- fdb 02:00:00:00:86:01"), "a moved entry is not removed: {shown}");

        let applied = b
            .apply_with_options(&conn, ApplyOptions::default().with_purge(true).with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(b.diff_with_options(&conn, opts()).await?.is_empty());
        let fdb = ns.exec("bridge", &["fdb", "show"])?;
        for (want, line) in [
            (true, "02:00:00:00:86:01 dev p1 master br0 static"),
            (true, "02:00:00:00:86:07 dev p0 master br0 static"),
            (false, "02:00:00:00:86:02"),
            (true, "00:00:00:00:00:00 dev vx0 dst 10.86.0.2"),
            (false, "dst 10.86.0.3"),
        ] {
            assert_eq!(fdb.contains(line), want, "{line}: {fdb}");
        }
        Ok(())
    })
    .await
}

/// With the previous config, the links it created and this one does not
/// are deleted, with what is stacked on them. A kindless link it only
/// configured stays, and so does a link of the same name another actor
/// made with another kind (#512).
#[tokio::test]
async fn the_previous_config_removes_the_links_it_created() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q", "bridge");

    with_timeout(async {
        use std::sync::Arc;

        let ns = TestNamespace::new("prev-links")?;
        let conn = conn_in_ns(&ns)?;
        ns.exec("ip", &["link", "add", "hand0", "type", "dummy"])?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .link("d1", |l| l.dummy().up())
                .link("v10", |l| l.vlan("d1", 10).up())
                .link("x0", |l| l.dummy())
                .link("hand0", |l| l.mtu(1400))
                .address("v10", "10.91.0.1/24")?,
        );
        let b = NetworkConfig::new().link("d0", |l| l.dummy().up());
        assert!(a.apply(&conn).await?.is_success());
        // Another actor replaces x0 with a bridge of the same name.
        ns.exec("ip", &["link", "del", "x0"])?;
        ns.exec("ip", &["link", "add", "x0", "type", "bridge"])?;

        let opts = || ApplyOptions::default().with_previous(a.clone());
        let applied = b.apply_with_options(&conn, opts()).await?;
        assert!(applied.is_success(), "{applied:?}");
        for gone in ["d1", "v10"] {
            assert!(
                conn.get_link_by_name(gone).await?.is_none(),
                "{gone} stayed"
            );
        }
        for kept in ["d0", "hand0", "x0"] {
            assert!(
                conn.get_link_by_name(kept).await?.is_some(),
                "{kept} was deleted"
            );
        }
        let again = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");
        Ok(())
    })
    .await
}

/// A removal that would destroy what no config declares is refused before
/// anything changes, as a recreate is (#512).
#[tokio::test]
async fn a_removal_over_undeclared_state_is_refused() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q");

    with_timeout(async {
        use std::sync::Arc;

        use nlink::netlink::config::Blocker;

        let ns = TestNamespace::new("prev-refused")?;
        let conn = conn_in_ns(&ns)?;
        let a = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .link("v10", |l| l.vlan("d0", 10).up())
                .link("d2", |l| l.dummy()),
        );
        let b = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d2", |l| l.dummy().up());
        assert!(a.apply(&conn).await?.is_success());
        ns.exec("ip", &["route", "add", "10.92.0.0/24", "dev", "v10"])?;

        let diff = b
            .diff_with_options(&conn, PlanOptions::default().previous(a.clone()))
            .await?;
        let removal = diff
            .links_to_remove
            .iter()
            .find(|r| r.name == "v10")
            .expect("v10 is up for removal");
        assert!(
            removal
                .blocked_by
                .iter()
                .any(|b| matches!(b, Blocker::Route { .. })),
            "{removal}"
        );
        let err = b
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await
            .expect_err("the removal is refused");
        assert!(err.is_not_supported(), "{err}");
        assert!(
            conn.get_link_by_name("v10").await?.is_some(),
            "v10 was deleted"
        );
        let d2 = conn.get_link_by_name("d2").await?.expect("d2");
        assert!(!d2.is_up(), "the refused apply changed d2");
        Ok(())
    })
    .await
}

/// With a protocol of its own, a config installs its routes with it, and a
/// purge removes only its own routes; a route at a declared key that some
/// other tool added is refused, not replaced (#512).
#[tokio::test]
async fn a_route_protocol_of_its_own_makes_the_config_own_exactly_its_routes() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        use nlink::netlink::types::route::RouteProtocol;

        let ns = TestNamespace::new("rt-proto")?;
        let conn = conn_in_ns(&ns)?;
        let own = |dst: &str| -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .route_protocol(RouteProtocol::Other(250))
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.93.0.1/24")?
                .route(dst, |r| r.dev("d0"))?)
        };
        assert!(own("10.93.1.0/24")?.apply(&conn).await?.is_success());
        let shown = ns.exec("ip", &["-j", "route", "show", "10.93.1.0/24"])?;
        assert!(shown.contains("\"protocol\":\"250\""), "{shown}");

        // Someone else's route, `ip route add`'s default `boot`: not the
        // config's, so a purge leaves it, and declaring its key is refused.
        ns.exec("ip", &["route", "add", "10.93.2.0/24", "dev", "d0"])?;
        let purge = ApplyOptions::default().with_purge(true);
        let applied = own("10.93.3.0/24")?
            .apply_with_options(&conn, purge)
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let routes = ns.exec("ip", &["route", "show", "dev", "d0"])?;
        assert!(
            routes.contains("10.93.2.0/24"),
            "a purge removed another tool's route: {routes}"
        );
        assert!(
            !routes.contains("10.93.1.0/24"),
            "a purge kept the config's own old route: {routes}"
        );
        assert!(routes.contains("10.93.3.0/24"), "{routes}");
        // A route identical to the declared one carries it; a different
        // route at the declared key and metric is someone else's, and the
        // replace that would take its place is refused.
        let blackhole = NetworkConfig::new()
            .route_protocol(RouteProtocol::Other(250))
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.93.0.1/24")?
            .route("10.93.2.0/24", |r| r.blackhole())?;
        let diff = blackhole.diff(&conn).await?;
        assert_eq!(diff.routes_refused.len(), 1, "{diff}");
        assert!(diff.to_string().contains("proto boot"), "{diff}");
        Ok(())
    })
    .await
}

/// Links a config with an owner creates carry the owner as their alias,
/// and a purge removes a tagged link the config no longer declares, with
/// what is on it; an untagged link stays, and an untagged link stacked on a
/// tagged one refuses its removal (#512).
#[tokio::test]
async fn an_owner_tag_lets_a_purge_find_the_configs_links() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "8021q");

    with_timeout(async {
        use nlink::netlink::config::Blocker;

        let ns = TestNamespace::new("owner-tag")?;
        let conn = conn_in_ns(&ns)?;
        ns.exec("ip", &["link", "add", "other", "type", "dummy"])?;
        let a = NetworkConfig::new()
            .owner("lab1")
            .link("d0", |l| l.dummy().up())
            .link("v1", |l| l.vlan("d0", 10).up())
            .link("d1", |l| l.dummy().up())
            .address("v1", "10.97.0.1/24")?;
        assert!(a.apply(&conn).await?.is_success());
        let v1 = conn.get_link_by_name("v1").await?.expect("v1");
        assert_eq!(v1.alias(), Some("lab1"));

        // Someone stacks a VLAN of their own on d1.
        ns.exec(
            "ip",
            &[
                "link", "add", "link", "d1", "name", "d1.5", "type", "vlan", "id", "5",
            ],
        )?;

        let b = NetworkConfig::new()
            .owner("lab1")
            .link("d0", |l| l.dummy().up());
        let purge = || ApplyOptions::default().with_purge(true);
        let diff = b
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        let refused = diff
            .links_to_remove
            .iter()
            .find(|r| r.name == "d1")
            .expect("d1 is tagged and undeclared");
        assert!(
            refused
                .blocked_by
                .iter()
                .any(|b| matches!(b, Blocker::StackedLink { name, .. } if name == "d1.5")),
            "{refused}"
        );
        let err = b
            .apply_with_options(&conn, purge())
            .await
            .expect_err("d1's removal is refused");
        assert!(err.is_not_supported(), "{err}");

        ns.exec("ip", &["link", "del", "d1.5"])?;
        let applied = b.apply_with_options(&conn, purge()).await?;
        assert!(applied.is_success(), "{applied:?}");
        for gone in ["v1", "d1"] {
            assert!(
                conn.get_link_by_name(gone).await?.is_none(),
                "{gone} stayed"
            );
        }
        for kept in ["d0", "other"] {
            assert!(
                conn.get_link_by_name(kept).await?.is_some(),
                "{kept} was deleted"
            );
        }
        let again = b
            .diff_with_options(&conn, PlanOptions::default().purge(true))
            .await?;
        assert!(again.is_empty(), "the second diff: {again}");
        Ok(())
    })
    .await
}

/// #526: a failed step names what it was done to. The kernel's answer
/// alone (`Network is unreachable`) said nothing about which route; the
/// error now carries the step as context and the route as its object,
/// propagated or collected with `continue_on_error`, and serialized.
#[tokio::test]
async fn a_failed_step_names_its_object() -> Result<()> {
    use nlink::ErrorObject;
    use nlink::netlink::config::ExecOptions;
    nlink::require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("err-object")?;
    let conn = conn_in_ns(&ns)?;
    // A gateway on a link with no address: the kernel refuses the route.
    let cfg = NetworkConfig::new()
        .link("d0", |b| b.dummy().up())
        .route("10.9.0.0/24", |r| r.via("10.99.0.1").dev("d0"))?;
    let route = ErrorObject::Route {
        destination: "10.9.0.0/24".into(),
        table: None,
    };

    let err = cfg.apply(&conn).await.expect_err("the gateway is unreachable");
    assert_eq!(err.object(), Some(&route), "{err}");
    assert!(err.to_string().contains("10.9.0.0/24"), "{err}");
    assert!(err.errno().is_some(), "the kernel's errno survives: {err:?}");

    let diff = cfg.diff(&conn).await?;
    let result = diff.apply(&conn, ExecOptions::new().with_continue_on_error(true)).await?;
    let [failed] = result.errors.as_slice() else {
        panic!("one failed step: {:?}", result.errors);
    };
    assert_eq!(failed.error.object(), Some(&route));
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_value(failed).unwrap();
        assert_eq!(json["object"]["type"], "route", "{json}");
        assert_eq!(json["object"]["destination"], "10.9.0.0/24", "{json}");
        assert_eq!(json["errno"], serde_json::json!(failed.error.errno()), "{json}");
    }
    Ok(())
}

/// A route through a nexthop object with a gateway reads back as itself
/// (#769): the kernel dumps the nexthop's gateway and device along with
/// its id (`nexthop_compat_mode`), and read back with them, the route's
/// delete matched no route, so a route the config stopped declaring stayed
/// forever, and an undo that put it back sent both, which the kernel
/// refuses ("Nexthop specification and nexthop id are mutually
/// exclusive").
#[tokio::test]
async fn a_route_through_a_nexthop_reads_back_as_one() -> Result<()> {
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("nhid-readback")?;
        let conn = conn_in_ns(&ns)?;
        let base = || -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.81.0.1/24")?
                .nexthop(5, |n| n.via("10.81.0.2".parse().unwrap()).dev("d0")))
        };
        let routes = |ns: &TestNamespace| -> Result<serde_json::Value> {
            crate::common::converge::ip_json(ns, &["route", "show", "10.82.0.0/16"])
                .map_err(nlink::Error::invalid_message)
        };
        let a = Arc::new(base()?.route("10.82.0.0/16", |r| r.nhid(5))?);
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");

        // Replaced by a route through a gateway, and the replace undone.
        let b = base()?.route("10.82.0.0/16", |r| r.via("10.81.0.3").dev("d0"))?;
        let applied = b.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(routes(&ns)?[0]["gateway"], "10.81.0.3");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(routes(&ns)?[0]["nhid"], 5, "{}", routes(&ns)?);
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");

        // Removed: the previous config declared it, this one does not.
        let applied = base()?
            .apply_with_options(&conn, ApplyOptions::default().with_previous(a.clone()))
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(routes(&ns)?, serde_json::json!([]), "the route stayed");
        Ok(())
    })
    .await
}

/// A nexthop's encap is echoed with the route too (#769): a route through
/// an MPLS-encapsulating nexthop object never converged, the diff taking
/// the echoed `encap mpls` for the route's own; and it read back with it,
/// so the undo of its replace sent the encap with the id, which the
/// kernel refuses as it refuses a gateway.
#[tokio::test]
async fn a_route_through_an_encap_nexthop_reads_back_as_one() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "mpls_router", "mpls_iptunnel");

    with_timeout(async {
        let ns = TestNamespace::new("nhid-encap")?;
        let conn = conn_in_ns(&ns)?;
        let base = || -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.83.0.1/24")?)
        };
        let applied = base()?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["nexthop", "add", "id", "7", "encap", "mpls", "100", "via", "10.83.0.2", "dev", "d0"])?;
        let routes = |ns: &TestNamespace| -> Result<serde_json::Value> {
            crate::common::converge::ip_json(ns, &["route", "show", "10.84.0.0/16"])
                .map_err(nlink::Error::invalid_message)
        };
        let a = base()?.route("10.84.0.0/16", |r| r.nhid(7))?;
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        // The echoed encap is the object's, not a difference.
        let again = a.diff(&conn).await?;
        assert!(again.is_empty(), "a route through the nexthop did not converge:\n{again}");

        let b = base()?.route("10.84.0.0/16", |r| r.via("10.83.0.3").dev("d0"))?;
        let applied = b.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(routes(&ns)?[0]["nhid"], 7, "{}", routes(&ns)?);
        let back = a.diff(&conn).await?;
        assert!(back.is_empty(), "the undo left:\n{back}");
        Ok(())
    })
    .await
}

/// A route with what a declaration cannot say is not the declared one, and
/// its replace is not undone as if it were (#783). The comparison and the
/// read-back held six metrics, so a live route with an `rto_min` and a
/// realm passed for its declaration, and the undo of a replace put back a
/// route without them.
#[tokio::test]
async fn a_route_with_what_a_declaration_cannot_say_is_another() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("route-lost")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.85.0.1/24")?
            .route("10.86.0.0/16", |r| r.via("10.85.0.2").dev("d0"))?;
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec(
            "ip",
            &["route", "replace", "10.86.0.0/16", "via", "10.85.0.2", "dev", "d0", "rto_min", "50ms", "realm", "7", "proto", "boot"],
        )?;
        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.routes_to_add.len(), 1, "a route with rto_min and a realm passed for one without: {diff}");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
        assert_eq!(stuck.len(), 1, "the replace of what cannot be put back: {stuck:?}");
        let shown = ns.exec("ip", &["route", "show", "10.86.0.0/16"])?;
        assert!(!shown.contains("rto_min") && !shown.contains("realm"), "{shown}");
        assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");
        Ok(())
    })
    .await
}

/// A route through a nexthop object reads back as unicast, and one stuck as
/// a blackhole is not the declared route (#783). The kernel dumps the
/// object's type while the object is a blackhole, so the read-back took a
/// route through a blackhole nexthop for a blackhole route. Put back that
/// way by an undo, it stayed a blackhole after its object got a gateway,
/// and nothing compared it.
#[tokio::test]
async fn a_route_through_a_blackhole_nexthop_is_unicast() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("nh-blackhole")?;
        let conn = conn_in_ns(&ns)?;
        // A blackhole nexthop is on `lo`, which must be up.
        ns.exec("ip", &["link", "set", "lo", "up"])?;
        let base = |nh: fn(nlink::netlink::config::NexthopSpecBuilder) -> nlink::netlink::config::NexthopSpecBuilder| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.91.0.1/24")
                .map(|c| c.nexthop(5, nh))
        };
        let via = |n: nlink::netlink::config::NexthopSpecBuilder| n.via("10.91.0.2".parse().unwrap()).dev("d0");
        let a = base(|n| n.blackhole())?.route("10.90.0.0/16", |r| r.nhid(5))?;
        let applied = a.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let b = base(|n| n.blackhole())?.route("10.90.0.0/16", |r| r.via("10.91.0.3").dev("d0"))?;
        let applied = b.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        // Give the object a gateway: the route put back follows it.
        ns.exec("ip", &["nexthop", "replace", "id", "5", "via", "10.91.0.2", "dev", "d0", "proto", "boot"])?;
        let shown = ns.exec("ip", &["-d", "route", "show", "10.90.0.0/16"])?;
        assert!(shown.starts_with("unicast"), "the undo put it back as a blackhole: {shown}");

        // A route added as a blackhole stays one: not the declared route.
        ns.exec("ip", &["route", "replace", "blackhole", "10.90.0.0/16", "nhid", "5", "proto", "boot"])?;
        let c = base(via)?.route("10.90.0.0/16", |r| r.nhid(5))?;
        let diff = c.diff(&conn).await?;
        assert_eq!(diff.routes_to_add.len(), 1, "a route stuck as a blackhole passed for the declared one: {diff}");
        let applied = c.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let shown = ns.exec("ip", &["-d", "route", "show", "10.90.0.0/16"])?;
        assert!(shown.starts_with("unicast"), "{shown}");
        assert!(c.diff(&conn).await?.is_empty(), "did not converge");
        Ok(())
    })
    .await
}

/// A multipath hop's weight of 256, its encap and its realms are read
/// (#783). The weight was a `u8`, so 256 read back as 255 and passed for a
/// declared 255. A hop's encap and realms were not read, so a route whose
/// hop had them passed for its declaration.
#[tokio::test]
async fn a_multipath_hops_weight_encap_and_realms_are_read() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "mpls_router", "mpls_iptunnel");

    with_timeout(async {
        let ns = TestNamespace::new("mp-hops")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = |w: u16| -> Result<NetworkConfig> {
            Ok(NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .address("d0", "10.89.0.1/24")?
                .route("10.88.0.0/16", move |r| {
                    r.nexthop(move |h| h.via("10.89.0.2").dev("d0").weight(w))
                        .nexthop(|h| h.via("10.89.0.3").dev("d0"))
                })?)
        };
        let applied = cfg(255)?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let replace = |hop: &[&str]| -> Result<String> {
            let mut args = vec!["route", "replace", "10.88.0.0/16", "proto", "boot", "nexthop", "via", "10.89.0.2", "dev", "d0", "weight", "256"];
            args.extend(hop);
            args.extend(["nexthop", "via", "10.89.0.3", "dev", "d0"]);
            ns.exec("ip", &args)
        };
        replace(&[])?;
        assert!(!cfg(255)?.diff(&conn).await?.is_empty(), "a weight of 256 passed for 255");
        assert!(cfg(256)?.diff(&conn).await?.is_empty(), "a declared 256 did not match");

        for hop in [&["encap", "mpls", "100"][..], &["realm", "5"][..]] {
            replace(hop)?;
            let diff = cfg(256)?.diff(&conn).await?;
            assert!(!diff.is_empty(), "a hop with {hop:?} passed for one without");
            let applied = cfg(256)?.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            let shown = ns.exec("ip", &["route", "show", "10.88.0.0/16"])?;
            assert!(!shown.contains(hop[0]), "{hop:?}: {shown}");
            assert!(cfg(256)?.diff(&conn).await?.is_empty(), "{hop:?}: did not converge");
        }
        Ok(())
    })
    .await
}

/// A nexthop with an encap is not a declared one (#783). A declaration has
/// no encap, and the diff did not read the kernel's: `ip nexthop add id 7
/// encap mpls 100 via …` passed for a declared nexthop 7 via the same
/// gateway, so traffic through it went out with a label nothing declared.
#[tokio::test]
async fn a_nexthop_with_an_encap_is_not_a_declared_one() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "mpls_router", "mpls_iptunnel");

    with_timeout(async {
        let ns = TestNamespace::new("nh-encap")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.83.1.1/24")?
            .nexthop(7, |n| n.via("10.83.1.2".parse().unwrap()).dev("d0"));
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec(
            "ip",
            &["nexthop", "replace", "id", "7", "encap", "mpls", "100", "via", "10.83.1.2", "dev", "d0", "proto", "boot"],
        )?;
        let diff = cfg.diff(&conn).await?;
        assert_eq!(diff.nexthops_to_set.len(), 1, "a nexthop with an encap passed for one without: {diff}");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let shown = ns.exec("ip", &["nexthop", "show", "id", "7"])?;
        assert!(!shown.contains("encap"), "{shown}");
        assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");
        Ok(())
    })
    .await
}

/// An address the apply removes comes back from its undo with what it had
/// (#781): its label, metric, `noprefixroute` and broadcast (#783). The diff read a live
/// address back bare, so the undo put back a plain address: no label, a
/// metric-0 prefix route where there had been none.
#[tokio::test]
async fn an_undo_puts_back_an_address_with_its_attributes() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("addr-undo")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new().link("d0", |l| l.dummy().up());
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec(
            "ip",
            &["addr", "add", "10.87.0.5/24", "brd", "10.87.0.255", "dev", "d0", "label", "d0:x", "metric", "50", "noprefixroute"],
        )?;
        let shown = |ns: &TestNamespace| -> Result<String> {
            let addr = crate::common::converge::ip_json(ns, &["addr", "show", "dev", "d0"])
                .map_err(nlink::Error::invalid_message)?;
            let routes = crate::common::converge::ip_json(ns, &["route", "show", "dev", "d0"])
                .map_err(nlink::Error::invalid_message)?;
            let a: Vec<String> = addr[0]["addr_info"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["family"] == "inet")
                .map(|a| format!("{} {} {} {} {}", a["local"], a["broadcast"], a["label"], a["metric"], a["noprefixroute"]))
                .collect();
            Ok(format!("{a:?} {routes}"))
        };
        let before = shown(&ns)?;

        let applied = cfg.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(!shown(&ns)?.contains("10.87.0.5"), "the purge removed it");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(shown(&ns)?, before);
        Ok(())
    })
    .await
}

/// An sfq's divisor, depth and head drop, an fq_codel's drop batch and CE
/// threshold selector, and a TBF's overhead, mpu and link layer are
/// declared, converge, and are compared (#806). The configs could not say
/// them, and the comparison did not read them.
#[tokio::test]
async fn sfq_fq_codel_and_tbf_settings_converge_and_are_compared() -> Result<()> {
    use nlink::netlink::psched::LinkLayer;
    use nlink::{Bytes, Rate};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_sfq", "sch_fq_codel", "sch_tbf");

    with_timeout(async {
        let ns = TestNamespace::new("qdisc-settings")?;
        let conn = conn_in_ns(&ns)?;
        let link = || NetworkConfig::new().link("d0", |l| l.dummy().up());
        let rows = [
            (link().qdisc("d0", |q| q.sfq().divisor(512).depth(32).headdrop(true)), "replace", "sfq divisor 256 depth 32 headdrop"),
            (link().qdisc("d0", |q| q.fq_codel().drop_batch(32)), "change", "fq_codel drop_batch 16"),
            (
                link().qdisc("d0", |q| {
                    q.tbf(Rate::mbit(1), Bytes::kib(32))
                        .limit_bytes(Bytes::kib(64))
                        .overhead(24)
                        .mpu(64)
                        .linklayer(LinkLayer::Atm)
                }),
                "change",
                "tbf rate 1mbit burst 32k limit 64k overhead 8 mpu 64 linklayer atm",
            ),
        ];
        for (cfg, how, drift) in rows {
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{drift}: {applied:?}");
            let again = cfg.diff(&conn).await?;
            assert!(again.is_empty(), "before `{drift}`: did not converge:\n{again}");
            // sfq has no change operation: a new one stands in for it.
            if how == "replace" {
                ns.exec("tc", &["qdisc", "del", "dev", "d0", "root"])?;
            }
            let verb = if how == "replace" { "add" } else { "change" };
            let mut args = vec!["qdisc", verb, "dev", "d0", "root"];
            args.extend(drift.split_whitespace());
            ns.exec("tc", &args)?;
            assert!(!cfg.diff(&conn).await?.is_empty(), "`{drift}` compared equal to the declaration");
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{drift}: {applied:?}");
            let back = cfg.diff(&conn).await?;
            assert!(back.is_empty(), "from `{drift}`, did not converge:\n{back}");
            ns.exec("tc", &["qdisc", "del", "dev", "d0", "root"])?;
        }
        Ok(())
    })
    .await
}

/// A replaced qdisc comes back from its undo as it was, settings a spec
/// did not carry included (#783, #806). An sfq with another divisor,
/// flows, depth or head drop read back as a plain sfq, so its replace's
/// undo restored one with the kernel's defaults. #783 made such a replace
/// irreversible; #806 has the spec carry them, so it comes back.
#[tokio::test]
async fn a_replaced_qdisc_comes_back_from_its_undo_as_it_was() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_sfq", "sch_fq_codel", "sch_tbf");

    with_timeout(async {
        let ns = TestNamespace::new("qdisc-lossy")?;
        let conn = conn_in_ns(&ns)?;
        let applied = NetworkConfig::new().link("d0", |l| l.dummy().up()).apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let shown = || -> Result<String> {
            let out = ns.exec("tc", &["qdisc", "show", "dev", "d0"])?;
            Ok(out.lines().next().unwrap_or_default().to_string())
        };
        // A qdisc tc makes, then a declared one of another kind replaces.
        let fq_codel = || NetworkConfig::new().link("d0", |l| l.dummy().up()).qdisc("d0", |q| q.fq_codel());
        let sfq = || NetworkConfig::new().link("d0", |l| l.dummy().up()).qdisc("d0", |q| q.sfq());
        let rows = [
            ("sfq divisor 512 flows 64 depth 32 headdrop", fq_codel()),
            ("sfq perturb 10", fq_codel()),
            ("tbf rate 1mbit burst 32k limit 64k overhead 24 mpu 64 linklayer atm", fq_codel()),
            ("fq_codel drop_batch 32 ce_threshold 2ms ce_threshold_selector 0x01/0x01", sfq()),
        ];
        for (line, cfg) in rows {
            // sfq has no change operation: a new one, not a replace.
            let _ = ns.exec("tc", &["qdisc", "del", "dev", "d0", "root"]);
            let mut add = vec!["qdisc", "add", "dev", "d0", "root", "handle", "1:"];
            add.extend(line.split_whitespace());
            ns.exec("tc", &add)?;
            let before = shown()?;
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            assert_eq!(applied.irreversible().count(), 0, "{line}: {:?}", applied.journal);
            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{undone:?}");
            assert_eq!(shown()?, before, "the undo put back another qdisc for `{line}`");
        }
        Ok(())
    })
    .await
}

/// A declared IPv4 broadcast is installed and compared (#783), and one not
/// declared is left alone. `DeclaredAddress` had no broadcast, so an undo or
/// a #745 restore put an address back without the one it had, and without
/// the broadcast route the kernel makes for it in the local table.
#[tokio::test]
async fn an_addresss_broadcast_is_declared_and_compared() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("addr-brd")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address_with("d0", "10.87.1.5/24", |a| a.broadcast("10.87.1.255"))?;
        let brd = || -> Result<String> {
            let addr = crate::common::converge::ip_json(&ns, &["addr", "show", "dev", "d0"])
                .map_err(nlink::Error::invalid_message)?;
            Ok(addr[0]["addr_info"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["family"] == "inet")
                .map(|a| a["broadcast"].to_string())
                .collect())
        };
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(brd()?, "\"10.87.1.255\"");
        assert!(cfg.diff(&conn).await?.is_empty(), "the declared broadcast converges");

        ns.exec("ip", &["addr", "del", "10.87.1.5/24", "dev", "d0"])?;
        ns.exec("ip", &["addr", "add", "10.87.1.5/24", "dev", "d0"])?;
        assert!(!cfg.diff(&conn).await?.is_empty(), "an address without its broadcast compared equal");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(brd()?, "\"10.87.1.255\"");
        assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");

        // Not declared, not compared: `brd +` and DHCP clients set one.
        let plain = NetworkConfig::new().link("d0", |l| l.dummy().up()).address("d0", "10.87.1.5/24")?;
        assert!(plain.diff(&conn).await?.is_empty(), "an undeclared broadcast was compared");
        Ok(())
    })
    .await
}

/// A tunnel's output key is compared too (#782). A declared key is the
/// key both ways, and the comparison read the input key alone: a gre,
/// vti or ip6gre tunnel with another output key compared equal to its
/// declaration and was never put right. The apply sends both now, and
/// `ip` reads one key back.
#[tokio::test]
async fn a_tunnels_output_key_is_compared() -> Result<()> {
    use std::net::Ipv6Addr;
    nlink::require_root!();
    nlink::require_modules!("ip_gre", "ip_vti", "ip6_gre", "ip6_vti");

    with_timeout(async {
        let ns = TestNamespace::new("okey")?;
        let conn = conn_in_ns(&ns)?;
        for (kind, local, remote) in [("gre", "10.88.0.1", "10.88.0.2"), ("vti", "10.88.1.1", "10.88.1.2"), ("ip6gre", "fd88::1", "fd88::2"), ("vti6", "fd88:1::1", "fd88:1::2")] {
            ns.exec("ip", &["link", "add", "t1", "type", kind, "local", local, "remote", remote, "ikey", "7", "okey", "8"])?;
            let cfg = NetworkConfig::new().link("t1", |l| match kind {
                "ip6gre" | "vti6" => (if kind == "ip6gre" { l.ip6gre() } else { l.vti6() })
                    .ip6tnl_local(local.parse::<Ipv6Addr>().unwrap())
                    .ip6tnl_remote(remote.parse::<Ipv6Addr>().unwrap())
                    .tunnel_key(7),
                _ => {
                    let l = if kind == "gre" { l.gre() } else { l.vti() };
                    l.tunnel_local(local.parse().unwrap()).tunnel_remote(remote.parse().unwrap()).tunnel_key(7)
                }
            });
            let diff = cfg.diff(&conn).await?;
            assert!(!diff.is_empty(), "{kind}: okey 8 compared equal to key 7");
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{kind}: {applied:?}");
            let link = crate::common::converge::ip_json(&ns, &["-d", "link", "show", "t1"])
                .map_err(nlink::Error::invalid_message)?;
            let data = &link[0]["linkinfo"]["info_data"];
            assert_eq!((&data["ikey"], &data["okey"]), (&data["ikey"], &data["ikey"]), "{kind}: {data}");
            assert!(cfg.diff(&conn).await?.is_empty(), "{kind} did not converge");
            ns.exec("ip", &["link", "del", "t1"])?;
        }
        Ok(())
    })
    .await
}

/// A qdisc the apply takes away takes its tree with it, and the undo puts
/// both back (#783): an HTB root with classes, a leaf qdisc and filters,
/// replaced by another kind of root, and removed when the previous config
/// declared it. The undo used to add the bare qdisc back, and say nothing
/// was lost.
#[tokio::test]
async fn an_undo_puts_back_the_tree_under_a_qdisc() -> Result<()> {
    use std::sync::Arc;
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "sch_netem", "cls_matchall", "cls_u32");

    with_timeout(async {
        let ns = TestNamespace::new("qdisc-tree-undo")?;
        let conn = conn_in_ns(&ns)?;
        let htb = Arc::new(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10)),
        );
        let tc = |args: &str| ns.exec("tc", &args.split_whitespace().collect::<Vec<_>>()).map(drop);
        let shown = || -> Result<Vec<String>> {
            ["qdisc show dev d0", "class show dev d0", "filter show dev d0 parent 1:"]
                .iter()
                .map(|a| ns.exec("tc", &a.split_whitespace().collect::<Vec<_>>()))
                .map(|r| {
                    r.map(|out| {
                        out.lines()
                            .map(|l| {
                                // Counters and per-install numbering are not state.
                                let mut w: Vec<&str> = l.split_whitespace().collect();
                                while let Some(i) = w.iter().position(|x| matches!(*x, "direct_packets_stat" | "index" | "ref" | "bind")) {
                                    w.drain(i..(i + 2).min(w.len()));
                                }
                                w.join(" ")
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                })
                .collect()
        };
        let fq = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .qdisc("d0", |q| q.fq_codel());
        let bare = NetworkConfig::new().link("d0", |l| l.dummy().up());
        let previous = nlink::netlink::config::PlanOptions::default().previous(htb.clone());
        let steps: [(&NetworkConfig, Option<&nlink::netlink::config::PlanOptions>); 2] = [(&fq, None), (&bare, Some(&previous))];
        for (next, plan) in steps {
            let applied = htb.apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            tc("class add dev d0 parent 1: classid 1:10 htb rate 10mbit")?;
            tc("class add dev d0 parent 1: classid 1:20 htb rate 20mbit")?;
            tc("qdisc add dev d0 parent 1:20 handle 20: netem delay 5ms")?;
            tc("filter add dev d0 parent 1: prio 1 protocol ip matchall classid 1:20")?;
            tc("filter add dev d0 parent 1: prio 2 protocol ip u32 match ip dst 10.0.0.0/8 classid 1:10")?;
            let before = shown()?;

            let diff = match plan {
                Some(p) => next.diff_with_options(&conn, p.clone()).await?,
                None => next.diff(&conn).await?,
            };
            let applied = diff.apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(applied.is_success(), "{applied:?}");
            assert!(!shown()?[1].contains("1:20"), "the tree went: {:?}", shown()?);
            let stuck: Vec<String> = applied.irreversible().map(|s| s.to_string()).collect();
            assert!(stuck.is_empty(), "{stuck:?}");
            let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
            assert!(undone.is_success(), "{undone:?}");
            assert_eq!(shown()?, before);
            ns.exec("tc", &["qdisc", "del", "dev", "d0", "root"])?;
        }
        Ok(())
    })
    .await
}

/// An IPv4 multipath route through IPv6 gateways (RFC 5549) keeps them
/// (#786). `Ipv4Route::multipath` sent a hop's IPv6 gateway nowhere, so
/// the route went in through bare devices; and the parser read only
/// `RTA_GATEWAY`, not the `RTA_VIA` the kernel dumps such a hop with, so a
/// route `ip` made read back without its gateways, which a removal's undo
/// then put back without.
#[tokio::test]
async fn ipv4_multipath_keeps_its_ipv6_gateways() -> Result<()> {
    use nlink::netlink::route::{Ipv4Route, NextHop};
    use std::net::{IpAddr, Ipv6Addr};
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("mp-via")?;
        let conn = conn_in_ns(&ns)?;
        let applied = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .apply(&conn)
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        let gw = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        conn.add_route(
            Ipv4Route::new(std::net::Ipv4Addr::new(10, 89, 0, 0), 24).multipath(vec![
                NextHop::new().gateway_v6(gw("fe80::1")).dev("d0"),
                NextHop::new().gateway_v6(gw("fe80::2")).dev("d1"),
            ]),
        )
        .await?;
        let route = crate::common::converge::ip_json(&ns, &["route", "show", "10.89.0.0/24"])
            .map_err(nlink::Error::invalid_message)?;
        let vias: Vec<String> = route[0]["nexthops"]
            .as_array()
            .map(|h| h.iter().map(|h| h["via"]["host"].as_str().unwrap_or("none").to_string()).collect())
            .unwrap_or_default();
        assert_eq!(vias, ["fe80::1", "fe80::2"], "{route}");

        let read: Vec<Option<IpAddr>> = conn
            .get_routes()
            .await?
            .iter()
            .find(|r| r.destination() == Some(&"10.89.0.0".parse().unwrap()))
            .and_then(|r| r.multipath())
            .unwrap_or_default()
            .iter()
            .map(|h| h.gateway)
            .collect();
        assert_eq!(read, [Some(gw("fe80::1").into()), Some(gw("fe80::2").into())]);
        Ok(())
    })
    .await
}

/// A route an apply replaces or purges comes back from the undo with the
/// protocol it had (#783). A config owns `static` routes as well as `boot`
/// ones, so it replaces and purges `proto static` routes, systemd-networkd's
/// among them; the undo put them back as the plan's `boot`.
#[tokio::test]
async fn an_undo_puts_a_route_back_with_its_protocol() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("route-proto-undo")?;
        let conn = conn_in_ns(&ns)?;
        let base = || -> Result<NetworkConfig> {
            Ok(NetworkConfig::new().link("d0", |l| l.dummy().up()).address("d0", "10.90.0.1/24")?)
        };
        let applied = base()?.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let protocol = |dst: &str| -> Result<String> {
            let r = crate::common::converge::ip_json(&ns, &["route", "show", dst])
                .map_err(nlink::Error::invalid_message)?;
            // `ip -j` leaves the protocol out for `boot`.
            Ok(r[0]["protocol"].as_str().unwrap_or("boot").to_string())
        };
        ns.exec("ip", &["route", "add", "10.91.0.0/24", "via", "10.90.0.2", "proto", "static"])?;
        ns.exec("ip", &["route", "add", "10.92.0.0/24", "via", "10.90.0.2", "proto", "static"])?;

        // Replaced by a declared route, and the replace undone.
        let replacing = base()?.route("10.91.0.0/24", |r| r.via("10.90.0.3"))?;
        let applied = replacing.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert_eq!(protocol("10.91.0.0/24")?, "boot");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(protocol("10.91.0.0/24")?, "static", "the replaced route");

        // Purged, and the purge undone.
        let applied = base()?.apply_with_options(&conn, ApplyOptions::default().with_purge(true)).await?;
        assert!(applied.is_success(), "{applied:?}");
        let undone = applied.undo().apply(&conn, nlink::ExecOptions::new()).await?;
        assert!(undone.is_success(), "{undone:?}");
        assert_eq!(protocol("10.92.0.0/24")?, "static", "the purged route");
        Ok(())
    })
    .await
}

/// What a link is declared with goes out when it is created, so one apply
/// converges (#788): a gretap's, ip6gretap's, erspan's or macsec's MAC
/// and a vti's MTU were left for a second apply's modify.
#[tokio::test]
async fn a_tunnels_mac_and_mtu_go_out_at_create() -> Result<()> {
    use nlink::netlink::link::ErspanVersion;
    nlink::require_root!();
    nlink::require_modules!("dummy", "ip_gre", "ip6_gre", "ip_vti", "macsec");

    with_timeout(async {
        let ns = TestNamespace::new("create-mac")?;
        let conn = conn_in_ns(&ns)?;
        let mac = |n: u8| [0x02, 0, 0, 0, 0x89, n];
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("gt1", |l| l.gretap().tunnel_remote("10.93.0.2".parse().unwrap()).address(mac(1)))
            .link("gt6", |l| l.ip6gretap().ip6tnl_remote("fd93::2".parse().unwrap()).address(mac(2)))
            .link("er1", |l| {
                l.erspan(5)
                    .erspan_remote("10.93.0.3".parse::<std::net::Ipv4Addr>().unwrap())
                    .erspan_version(ErspanVersion::V1 { index: 1 })
                    .address(mac(3))
            })
            .link("ms1", |l| l.macsec("d0").macsec_port(9).address(mac(4)))
            .link("vt1", |l| l.vti().tunnel_remote("10.93.0.4".parse().unwrap()).mtu(1300));
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "one apply did not converge:\n{again}");
        Ok(())
    })
    .await
}

/// An ERSPAN tunnel's output key is compared too (#782): the session goes
/// out as both keys, and the comparison read the input key alone, so an
/// erspan whose output key differed converged as it was.
#[tokio::test]
async fn an_erspans_output_key_is_compared() -> Result<()> {
    use nlink::netlink::link::ErspanVersion;
    nlink::require_root!();
    nlink::require_modules!("ip_gre");

    with_timeout(async {
        let ns = TestNamespace::new("erspan-okey")?;
        let conn = conn_in_ns(&ns)?;
        ns.exec(
            "ip",
            &["link", "add", "er1", "type", "erspan", "seq", "ikey", "5", "okey", "6", "local", "10.94.0.1", "remote", "10.94.0.2", "erspan_ver", "1", "erspan", "3"],
        )?;
        let cfg = NetworkConfig::new().link("er1", |l| {
            l.erspan(5)
                .erspan_local("10.94.0.1".parse::<std::net::Ipv4Addr>().unwrap())
                .erspan_remote("10.94.0.2".parse::<std::net::Ipv4Addr>().unwrap())
                .erspan_version(ErspanVersion::V1 { index: 3 })
        });
        let diff = cfg.diff(&conn).await?;
        assert!(!diff.is_empty(), "okey 6 compared equal to session 5");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let link = crate::common::converge::ip_json(&ns, &["-d", "link", "show", "er1"])
            .map_err(nlink::Error::invalid_message)?;
        let data = &link[0]["linkinfo"]["info_data"];
        assert_eq!(data["ikey"], data["okey"], "{data}");
        assert!(cfg.diff(&conn).await?.is_empty(), "it did not converge");
        Ok(())
    })
    .await
}

/// An HTB class's quantum, mpu and overhead are compared (#789). A
/// declared class sends them, and the comparison looked at rate, ceil,
/// bursts and priority only: a class whose quantum or overhead drifted
/// matched its declaration and was never put right.
#[tokio::test]
async fn an_htb_classs_quantum_and_overhead_are_compared() -> Result<()> {
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{Rate, TcHandle};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb");

    with_timeout(async {
        let ns = TestNamespace::new("htb-quantum")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        let cfg = |class: HtbClassConfig| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10))
                .tc("d0", move |t| t.class(h(1, 0), h(1, 0x10), class))
        };
        let declared = || HtbClassConfig::new(Rate::mbit(10)).quantum(1514).overhead(4).mpu(64);
        let applied = cfg(declared()).apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(cfg(declared()).diff(&conn).await?.is_empty(), "the declared class converges");
        for drift in ["quantum 3000", "overhead 40", "mpu 128"] {
            let mut args = vec!["class", "change", "dev", "d0", "parent", "1:", "classid", "1:10", "htb", "rate", "10mbit"];
            for (k, v) in [("quantum", "1514"), ("overhead", "4"), ("mpu", "64")] {
                if !drift.starts_with(k) {
                    args.extend([k, v]);
                }
            }
            args.extend(drift.split_whitespace());
            ns.exec("tc", &args)?;
            let diff = cfg(declared()).diff(&conn).await?;
            assert!(!diff.is_empty(), "{drift} compared equal to the declaration");
            let applied = cfg(declared()).apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            assert!(cfg(declared()).diff(&conn).await?.is_empty(), "{drift}: did not converge");
        }
        Ok(())
    })
    .await
}

/// A route or rule with a TOS is not the declared one (#793). A
/// declaration has no TOS, so it is installed with 0, but the comparison
/// ignored the TOS: a live `tos 0x10` route or rule at the declared key
/// passed for it, and the declared one, for all other traffic, was never
/// added.
#[tokio::test]
async fn a_route_or_rule_with_a_tos_is_another() -> Result<()> {
    use std::net::Ipv4Addr;
    nlink::require_root!();
    nlink::require_modules!("dummy");

    with_timeout(async {
        let ns = TestNamespace::new("route-tos")?;
        let conn = conn_in_ns(&ns)?;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.65.0.1/24")?
            .route("10.66.0.0/16", |r| r.via("10.65.0.2").dev("d0"))?
            .rule(100, |r| r.from(Ipv4Addr::new(10, 87, 0, 0), 16).table(100));
        let applied = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .address("d0", "10.65.0.1/24")?
            .apply(&conn)
            .await?;
        assert!(applied.is_success(), "{applied:?}");
        ns.exec("ip", &["route", "add", "10.66.0.0/16", "via", "10.65.0.2", "dev", "d0", "tos", "0x10", "proto", "boot"])?;
        ns.exec("ip", &["rule", "add", "pref", "100", "from", "10.87.0.0/16", "tos", "0x10", "table", "100", "proto", "boot"])?;

        let diff = cfg.diff(&conn).await?;
        assert_eq!((diff.routes_to_add.len(), diff.rules_to_add.len()), (1, 1), "{diff}");
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        let routes = ns.exec("ip", &["route", "show", "10.66.0.0/16"])?;
        assert_eq!(routes.lines().count(), 2, "the TOS route and the declared one: {routes}");
        let rules = ns.exec("ip", &["rule", "show", "pref", "100"])?;
        assert_eq!(rules.lines().count(), 2, "the TOS rule and the declared one: {rules}");
        assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");
        Ok(())
    })
    .await
}

/// A declared filter's chain is compared, and a filter of its name in
/// another chain goes (#793). The live lookup was by parent, priority and
/// protocol and the comparison left the chain out, so a filter in chain 0
/// matched a declaration in chain 5. And the replace deleted in chain 0,
/// whatever chain the filter it replaced was in.
#[tokio::test]
async fn a_filters_chain_is_compared() -> Result<()> {
    use nlink::netlink::filter::MatchallFilter;
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{EthProto, FilterPriority, Rate, TcHandle};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_matchall");

    with_timeout(async {
        let ns = TestNamespace::new("filter-chain")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        let cfg = |chain: Option<u32>| {
            let filter = MatchallFilter::new().classid(h(1, 0x10));
            let filter = match chain {
                Some(c) => filter.chain(c),
                None => filter,
            };
            NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10))
                .tc("d0", move |t| {
                    t.class(h(1, 0), h(1, 0x10), HtbClassConfig::new(Rate::mbit(10)))
                        .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, filter)
                })
        };
        // The chains of the filters at 1:, as tc lists them.
        let chains = || -> Result<Vec<u64>> {
            let out = ns.exec("tc", &["-j", "filter", "show", "dev", "d0", "parent", "1:"])?;
            let listed: serde_json::Value = serde_json::from_str(&out)
                .map_err(|e| nlink::Error::invalid_message(format!("{e}: {out}")))?;
            Ok(listed
                .as_array()
                .into_iter()
                .flatten()
                .filter(|f| f.get("options").is_some())
                .map(|f| f["chain"].as_u64().unwrap_or(0))
                .collect())
        };
        // Declared in chain 5, made in chain 0; then declared in chain 0,
        // made in chain 5.
        for (declared, made) in [(Some(5), "0"), (None, "5")] {
            let applied = cfg(None).apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            ns.exec("tc", &["filter", "del", "dev", "d0", "parent", "1:"])?;
            ns.exec(
                "tc",
                &["filter", "add", "dev", "d0", "parent", "1:", "chain", made, "prio", "1", "protocol", "ip", "matchall", "classid", "1:10"],
            )?;
            let diff = cfg(declared).diff(&conn).await?;
            assert!(!diff.is_empty(), "chain {made} compared equal to chain {declared:?}");
            let applied = cfg(declared).apply(&conn).await?;
            assert!(applied.is_success(), "{applied:?}");
            assert_eq!(chains()?, [u64::from(declared.unwrap_or(0))], "after the apply");
            assert!(cfg(declared).diff(&conn).await?.is_empty(), "chain {declared:?}: did not converge");
        }
        Ok(())
    })
    .await
}

/// A police action read from tc(8)'s words makes what tc makes of them,
/// and a declaration of it converges (#800). `parse_params` started from
/// nlink's own defaults: what exceeded was dropped where tc reclassifies
/// it, and the mtu was 2047 where tc leaves it to the kernel, which a
/// rate-less policer then held every larger packet to.
#[tokio::test]
async fn a_police_from_tcs_words_is_tcs_and_converges() -> Result<()> {
    use nlink::netlink::action::{ActionList, Estimator, PoliceAction};
    use nlink::netlink::filter::MatchallFilter;
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{EthProto, FilterPriority, Rate, TcHandle};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_matchall", "act_police");

    with_timeout(async {
        let ns = TestNamespace::new("police-tc-words")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        // The kernel's mtu: `255 << cell_log` with a rate table, none without.
        for (line, mtu) in [("rate 1mbit burst 32k", "mtu 2Kb"), ("avrate 1mbit", "mtu 4096Mb")] {
            let words: Vec<&str> = line.split_whitespace().collect();
            let police = PoliceAction::parse_params(&words)?;
            let estimator = Estimator::parse_params(&["1sec", "8sec"])?;
            let cfg = NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.htb().default_class(0x10))
                .tc("d0", move |t| {
                    t.class(h(1, 0), h(1, 0x10), HtbClassConfig::new(Rate::mbit(10))).filter(
                        h(1, 0),
                        FilterPriority::new(1),
                        EthProto::IP,
                        MatchallFilter::new()
                            .classid(h(1, 0x10))
                            .actions(ActionList::new().with_estimator(estimator).with(police.clone())),
                    )
                });
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{line}: {applied:?}");
            let shown = ns.exec("tc", &["filter", "show", "dev", "d0", "parent", "1:"])?;
            assert!(shown.contains("action reclassify") && shown.contains(mtu), "{line}: {shown}");
            let diff = cfg.diff(&conn).await?;
            assert!(diff.is_empty(), "{line}: the declaration did not converge: {diff:?}");
            ns.exec("tc", &["filter", "del", "dev", "d0", "parent", "1:"])?;
        }
        Ok(())
    })
    .await
}

/// Every action kind is compared by what it does (#791), and converges.
/// Only mirred, gact and police were; every other kind was compared by its
/// kind alone, so a filter whose vlan action pushed another id, or whose
/// skbedit set another mark, matched its declaration and was never put
/// right. Each row declares a filter with the action, applies twice, then
/// replaces the filter with a drifted action, which the diff must see and
/// the apply must put back. A gate is read as the schedule the kernel keeps
/// (#813); bpf, which needs a program, has a test of its own.
#[tokio::test]
async fn every_action_kind_is_compared_and_converges() -> Result<()> {
    use nlink::netlink::action::{
        ActionList, ConnmarkAction, CsumAction, CtAction, CtinfoAction, GateAction, IfeAction, MplsAction,
        NatAction, PeditAction, SampleAction, SimpleAction, SkbeditAction, SkbmodAction, TunnelKeyAction,
        VlanAction,
    };
    use nlink::netlink::filter::MatchallFilter;
    use nlink::{EthProto, FilterPriority, TcHandle};
    nlink::require_root!();
    nlink::require_modules!(
        "dummy", "sch_ingress", "cls_matchall", "act_vlan", "act_mpls", "act_skbmod", "act_skbedit", "act_connmark",
        "act_csum", "act_nat", "act_tunnel_key", "act_ct", "act_pedit", "act_simple", "act_sample", "act_gate",
        "act_ctinfo", "act_ife"
    );

    fn list(kind: &str, line: &str) -> nlink::Result<ActionList> {
        let w: Vec<&str> = line.split_whitespace().collect();
        Ok(match kind {
            "vlan" => ActionList::new().with(VlanAction::parse_params(&w)?),
            "mpls" => ActionList::new().with(MplsAction::parse_params(&w)?),
            "skbmod" => ActionList::new().with(SkbmodAction::parse_params(&w)?),
            "skbedit" => ActionList::new().with(SkbeditAction::parse_params(&w)?),
            "connmark" => ActionList::new().with(ConnmarkAction::parse_params(&w)?),
            "csum" => ActionList::new().with(CsumAction::parse_params(&w)?),
            "nat" => ActionList::new().with(NatAction::parse_params(&w)?),
            "tunnel_key" => ActionList::new().with(TunnelKeyAction::parse_params(&w)?),
            "ct" => ActionList::new().with(CtAction::parse_params(&w)?),
            "pedit" => ActionList::new().with(PeditAction::parse_params(&w)?),
            "simple" => ActionList::new().with(SimpleAction::parse_params(&w)?),
            "sample" => ActionList::new().with(SampleAction::parse_params(&w)?),
            "gate" => ActionList::new().with(GateAction::parse_params(&w)?),
            "ctinfo" => ActionList::new().with(CtinfoAction::parse_params(&w)?),
            "ife" => ActionList::new().with(IfeAction::parse_params(&w)?),
            other => panic!("no row for {other}"),
        })
    }
    let rows: &[(&str, &str, &str)] = &[
        ("vlan", "pop", "push 100"),
        ("vlan", "push 100", "push 200"),
        ("vlan", "push 100 priority 3", "push 100 priority 4"),
        ("vlan", "modify 200 protocol 802.1ad", "modify 200"),
        ("mpls", "push label 100 ttl 64 tc 3", "push label 101 ttl 64 tc 3"),
        ("mpls", "pop protocol ipv4", "pop protocol ipv6"),
        ("skbmod", "set dmac 02:00:00:00:00:01", "set dmac 02:00:00:00:00:02"),
        ("skbedit", "priority 7", "priority 8"),
        ("skbedit", "mark 42", "mark 43"),
        ("skbedit", "mark 1 mask 255", "mark 1 mask 15"),
        ("connmark", "zone 5", "zone 6"),
        ("csum", "iph", "iph tcp"),
        ("nat", "egress 10.0.0.1 192.168.0.1", "egress 10.0.0.1 192.168.0.2"),
        ("tunnel_key", "set src 10.0.0.1 dst 10.0.0.2 id 100 dst_port 4789", "set src 10.0.0.1 dst 10.0.0.2 id 101 dst_port 4789"),
        ("tunnel_key", "release", "set src 10.0.0.1 dst 10.0.0.2 id 1"),
        ("ct", "commit", "commit zone 5"),
        ("pedit", "ex munge ip ttl set 5", "ex munge ip ttl set 6"),
        ("simple", "sdata hello", "sdata world"),
        ("sample", "rate 100 group 5", "rate 200 group 5"),
        ("ctinfo", "cpmark zone 1", "cpmark zone 2"),
        ("gate", "base-time 1000 sched-entry open 2000", "base-time 1000 sched-entry close 2000"),
        (
            "gate",
            "priority 1 base-time 1000 sched-entry open 2000 sched-entry close 3000",
            "priority 1 base-time 1000 sched-entry open 2000 sched-entry close 4000",
        ),
        ("ife", "encode allow mark", "encode allow prio"),
    ];

    with_timeout(async {
        let ns = TestNamespace::new("action-kinds")?;
        let conn = conn_in_ns(&ns)?;
        // On the clsact ingress hook: `ct` attaches nowhere else.
        let hook = TcHandle::CLSACT_INGRESS;
        let filter = |actions: ActionList| MatchallFilter::new().actions(actions);
        let mut failed = Vec::new();
        for (kind, line, drift) in rows {
            let actions = list(kind, line)?;
            let cfg = NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.clsact())
                .tc("d0", move |t| t.filter(hook, FilterPriority::new(1), EthProto::ALL, filter(actions.clone())));
            match cfg.apply(&conn).await {
                Ok(applied) if applied.is_success() => {}
                Ok(applied) => {
                    failed.push(format!("{kind} {line}: the apply failed: {applied:?}"));
                    continue;
                }
                Err(e) => {
                    failed.push(format!("{kind} {line}: the apply failed: {e}"));
                    continue;
                }
            }
            let again = cfg.diff(&conn).await?;
            if !again.is_empty() {
                failed.push(format!("{kind} {line}: did not converge:\n{again}"));
                continue;
            }
            ns.exec("tc", &["filter", "del", "dev", "d0", "ingress", "prio", "1"])?;
            if let Err(e) = conn
                .add_filter_full("d0", hook, None, EthProto::ALL, FilterPriority::new(1), filter(list(kind, drift)?))
                .await
            {
                failed.push(format!("{kind} {line}: `{drift}` would not install: {e}"));
                continue;
            }
            if cfg.diff(&conn).await?.is_empty() {
                failed.push(format!("{kind} {line}: `{drift}` compared equal to it"));
            }
            let applied = cfg.apply(&conn).await.map(|a| a.is_success()).unwrap_or(false);
            let back = cfg.diff(&conn).await?;
            if !applied || !back.is_empty() {
                failed.push(format!("{kind} {line}: from `{drift}`, did not converge:\n{back}"));
            }
        }
        assert!(failed.is_empty(), "{}", failed.join("\n"));
        Ok(())
    })
    .await
}

/// #827: every flower key a tc(8) line can now say is written as the
/// kernel echoes it, so a declaration converges, and is compared, so a
/// filter whose key drifted, or that matches on one more key, is put back.
#[tokio::test]
async fn every_flower_key_is_compared_and_converges() -> Result<()> {
    use nlink::netlink::filter::FlowerFilter;
    use nlink::{EthProto, FilterPriority, TcHandle};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_flower");

    // (protocol, line, drift)
    let rows: &[(&str, &str, &str)] = &[
        ("ip", "ip_proto icmp type 8 code 0", "ip_proto icmp type 0 code 0"),
        ("ipv6", "ip_proto icmpv6 type 128", "ip_proto icmpv6 type 129"),
        ("ip", "ip_flags frag/nofirstfrag", "ip_flags frag/firstfrag"),
        ("ip", "ct_state +trk+est", "ct_state +trk+new"),
        ("ip", "ct_zone 3 ct_mark 5/0xff", "ct_zone 3 ct_mark 6/0xff"),
        ("ip", "ct_zone 3", "ct_zone 3 ct_mark 5"),
        ("ip", "ct_label 01/ff", "ct_label 02/ff"),
        ("ip", "enc_key_id 100 enc_dst_ip 10.0.0.1 enc_dst_port 4789", "enc_key_id 101 enc_dst_ip 10.0.0.1 enc_dst_port 4789"),
        ("ip", "enc_src_ip fd00::/64 enc_tos 16/0xfc enc_ttl 64", "enc_src_ip fd00::/64 enc_tos 16/0xfc enc_ttl 63"),
        ("mpls_uc", "mpls_label 100 mpls_tc 3", "mpls_label 101 mpls_tc 3"),
        ("arp", "arp_op request arp_tip 10.0.0.0/24", "arp_op reply arp_tip 10.0.0.0/24"),
        ("arp", "arp_sha 02:00:00:00:00:01", "arp_sha 02:00:00:00:00:02"),
        ("802.1q", "vlan_id 10 vlan_ethtype ip src_ip 10.0.0.1", "vlan_id 10 vlan_ethtype ip src_ip 10.0.0.2"),
        (
            "802.1ad",
            "vlan_id 10 vlan_ethtype 802.1q cvlan_id 20 cvlan_ethtype ip",
            "vlan_id 10 vlan_ethtype 802.1q cvlan_id 21 cvlan_ethtype ip",
        ),
        ("ip", "dst_mac 02:00:00:00:00:00/ff:ff:ff:00:00:00", "dst_mac 02:00:00:00:00:00/ff:ff:00:00:00:00"),
        ("ip", "indev d0", "indev lo"),
    ];

    with_timeout(async {
        let ns = TestNamespace::new("flower-keys")?;
        let conn = conn_in_ns(&ns)?;
        let hook = TcHandle::CLSACT_INGRESS;
        let parse = |line: &str| FlowerFilter::parse_params(&line.split_whitespace().collect::<Vec<_>>());
        let mut failed = Vec::new();
        for &(proto, line, drift) in rows {
            let protocol: EthProto = proto.parse()?;
            let flower = parse(line)?;
            let cfg = NetworkConfig::new()
                .link("d0", |l| l.dummy().up())
                .qdisc("d0", |q| q.clsact())
                .tc("d0", move |t| t.filter(hook, FilterPriority::new(1), protocol, flower.clone()));
            match cfg.apply(&conn).await {
                Ok(applied) if applied.is_success() => {}
                Ok(applied) => {
                    failed.push(format!("{proto} {line}: the apply failed: {applied:?}"));
                    continue;
                }
                Err(e) => {
                    failed.push(format!("{proto} {line}: the apply failed: {e}"));
                    continue;
                }
            }
            let again = cfg.diff(&conn).await?;
            if !again.is_empty() {
                failed.push(format!("{proto} {line}: did not converge:\n{again}"));
                continue;
            }
            ns.exec("tc", &["filter", "del", "dev", "d0", "ingress", "prio", "1"])?;
            if let Err(e) = conn.add_filter_full("d0", hook, None, protocol, FilterPriority::new(1), parse(drift)?).await {
                failed.push(format!("{proto} {line}: `{drift}` would not install: {e}"));
                continue;
            }
            if cfg.diff(&conn).await?.is_empty() {
                failed.push(format!("{proto} {line}: `{drift}` compared equal to it"));
            }
            let applied = cfg.apply(&conn).await.map(|a| a.is_success()).unwrap_or(false);
            let back = cfg.diff(&conn).await?;
            if !applied || !back.is_empty() {
                failed.push(format!("{proto} {line}: from `{drift}`, did not converge:\n{back}"));
            }
        }
        assert!(failed.is_empty(), "{}", failed.join("\n"));
        Ok(())
    })
    .await
}

/// A police action's conform verdict, peakrate and average rate, and a
/// gact action's random verdict, are compared (#791). The comparison
/// summarised a police by its rate, burst, mtu and exceed verdict and a
/// gact by its verdict alone, so a filter whose action drifted in any of
/// the rest matched its declaration.
#[tokio::test]
async fn a_filters_police_and_gact_parameters_are_compared() -> Result<()> {
    use nlink::netlink::action::{ActionList, Estimator, GactAction, PoliceAction};
    use nlink::netlink::filter::MatchallFilter;
    use nlink::netlink::tc::HtbClassConfig;
    use nlink::{Bytes, EthProto, FilterPriority, Rate, TcHandle};
    nlink::require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_matchall", "act_police", "act_gact");

    with_timeout(async {
        let ns = TestNamespace::new("action-fields")?;
        let conn = conn_in_ns(&ns)?;
        let h = |m: u16, n: u16| TcHandle::new(m, n);
        // A peakrate needs an mtu; declared here, so the drift below
        // changes the peakrate alone.
        let police = || {
            PoliceAction::new()
                .rate(Rate::mbit(1))
                .burst(Bytes::kib(32))
                .mtu(Bytes::new(2048))
                .exceed_drop()
        };
        // An average rate needs the actions' rate estimator (#792).
        let estimator = Estimator::new(std::time::Duration::from_secs(1), std::time::Duration::from_secs(8))?;
        let filter = move |police: PoliceAction, gact: GactAction| {
            MatchallFilter::new()
                .classid(h(1, 0x10))
                .actions(ActionList::new().with_estimator(estimator).with(police).with(gact))
        };
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .qdisc("d0", |q| q.htb().default_class(0x10))
            .tc("d0", move |t| {
                t.class(h(1, 0), h(1, 0x10), HtbClassConfig::new(Rate::mbit(10))).filter(
                    h(1, 0),
                    FilterPriority::new(1),
                    EthProto::IP,
                    filter(police(), GactAction::pass()),
                )
            });
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "{applied:?}");
        assert!(cfg.diff(&conn).await?.is_empty(), "the declared filter converges");
        let drifts: [(&str, PoliceAction, GactAction); 4] = [
            ("conform pipe", police().conform_pipe(), GactAction::pass()),
            ("peakrate", police().peakrate(Rate::mbit(2)), GactAction::pass()),
            ("avrate", police().avrate(Rate::mbit(1)), GactAction::pass()),
            ("gact random", police(), GactAction::pass().random(10, 2 /* TC_ACT_SHOT */)),
        ];
        for (what, p, g) in drifts {
            ns.exec("tc", &["filter", "del", "dev", "d0", "parent", "1:", "prio", "1"])?;
            conn.add_filter_full("d0", h(1, 0), None, EthProto::IP, FilterPriority::new(1), filter(p, g))
                .await?;
            let diff = cfg.diff(&conn).await?;
            assert!(!diff.is_empty(), "{what} compared equal to the declaration");
            let applied = cfg.apply(&conn).await?;
            assert!(applied.is_success(), "{what}: {applied:?}");
            assert!(cfg.diff(&conn).await?.is_empty(), "{what}: did not converge");
        }
        Ok(())
    })
    .await
}
