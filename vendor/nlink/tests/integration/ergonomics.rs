//! Plan 148 ergonomics — `wait_link_up` + `get_link_stats`.
//!
//! Mirrors §5.1 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! Each test gates on root + the `dummy` module; on a regular-user
//! invocation `require_root!()` early-returns so the suite is no-op.

use std::time::Duration;

use nlink::netlink::link::DummyLink;

use crate::common::TestNamespace;

#[tokio::test]
async fn wait_link_up_returns_when_link_comes_up() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("wait-link-up")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    // Stagger: spawn the wait, then bring up after 100ms. The wait
    // should observe operstate change within its 5s deadline.
    let ns_name = ns.name().to_string();
    let wait_task = tokio::spawn(async move {
        let conn = nlink::Connection::<nlink::Route>::new_in(&ns_name)?;
        conn.wait_link_up("d0", Duration::from_secs(5)).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.set_link_up("d0").await?;

    wait_task
        .await
        .expect("wait task must complete")
        .expect("wait_link_up must return Ok when the link comes up");
    Ok(())
}

#[tokio::test]
async fn wait_link_up_times_out_when_link_stays_down() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("wait-link-timeout")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    let result = conn
        .wait_link_up("d0", Duration::from_millis(200))
        .await;
    let err = result.expect_err("wait_link_up must time out when link stays down");
    assert!(err.is_timeout(), "expected timeout, got {err:?}");
    Ok(())
}

#[tokio::test]
async fn get_link_stats_returns_zero_on_unused_dummy() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("link-stats")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;

    let stats = conn.get_link_stats("d0").await?;
    assert_eq!(stats.tx_packets(), 0, "fresh dummy has no tx traffic");
    assert_eq!(stats.rx_packets(), 0, "fresh dummy has no rx traffic");
    Ok(())
}

// ============================================================================
// #169 — del_*_if_exists family + WireGuard device bootstrap
// ============================================================================

#[tokio::test]
async fn del_if_exists_family_swallows_absence_and_reports_deletion() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb");

    let ns = TestNamespace::new("if-exists")?;
    let conn = ns.connection()?;

    // Absent everything → Ok(false), never an error.
    assert!(!conn.del_link_if_exists("ghost0").await?);
    assert!(
        !conn
            .del_route_v4_if_exists(std::net::Ipv4Addr::new(10, 99, 99, 0), 24)
            .await?
    );
    assert!(
        !conn
            .del_address_if_exists("lo", "10.99.99.1".parse().unwrap(), 32)
            .await?
    );
    assert!(
        !conn
            .del_qdisc_if_exists("lo", nlink::TcHandle::ROOT)
            .await?
    );
    assert!(
        !conn
            .del_filter_if_exists(
                "lo",
                nlink::TcHandle::ROOT,
                nlink::EthProto::new(0x0800),
                nlink::FilterPriority::new(100)
            )
            .await?
    );

    // Present → deleted, Ok(true); second call → Ok(false).
    conn.add_link(DummyLink::new("d0")).await?;
    assert!(conn.del_link_if_exists("d0").await?);
    assert!(!conn.del_link_if_exists("d0").await?);

    Ok(())
}

/// #718: the deletes that had no `_if_exists` form. Each deletes what is
/// there (`Ok(true)`), then answers `Ok(false)` for what is not, which the
/// kernel reports as `ENOENT`.
#[tokio::test]
async fn neighbours_rules_and_nexthops_delete_if_they_exist() -> nlink::Result<()> {
    use nlink::netlink::neigh::Neighbor;
    use nlink::netlink::nexthop::NexthopBuilder;
    use nlink::netlink::rule::RuleBuilder;
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("del-if-exists")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.set_link_up("d0").await?;
    let ifindex = conn.get_link_by_name("d0").await?.expect("d0").ifindex();

    let target: std::net::Ipv4Addr = "10.98.0.9".parse().unwrap();
    let neighbour = || Neighbor::with_index_v4(ifindex, target);
    conn.add_neighbor(neighbour().lladdr([2, 0, 0, 0, 0, 9]).permanent())
        .await?;
    assert!(conn.del_neighbor_if_exists(neighbour()).await?);
    assert!(!conn.del_neighbor_if_exists(neighbour()).await?);

    let rule = || RuleBuilder::v4().priority(4321).table(100);
    conn.add_rule(rule()).await?;
    assert!(conn.del_rule_if_exists(rule()).await?);
    assert!(!conn.del_rule_if_exists(rule()).await?);

    // A blackhole nexthop hangs off `lo`, which has to be up.
    conn.set_link_up("lo").await?;
    conn.add_nexthop(NexthopBuilder::new(77).blackhole()).await?;
    assert!(conn.del_nexthop_if_exists(77).await?);
    assert!(!conn.del_nexthop_if_exists(77).await?);
    Ok(())
}

#[tokio::test]
async fn wireguard_diff_reports_missing_device_and_ensure_creates_it() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("wireguard");

    use nlink::netlink::genl::wireguard::WireguardConfig;

    let ns = TestNamespace::new("wg-bootstrap")?;
    let conn = ns.connection()?;
    let wg: nlink::Connection<nlink::Wireguard> =
        nlink::Connection::new_in_async(ns.name()).await?;

    let cfg = WireguardConfig::new().device("wg-boot0", |d| d.listen_port(51999));

    // Absent device → devices_to_add, not an error (#169).
    let diff = cfg.diff(&wg).await?;
    assert_eq!(diff.devices_to_add, vec!["wg-boot0".to_string()]);
    assert!(!diff.is_empty());
    assert!(diff.change_count() >= 1);

    // apply() refuses with a descriptive error while missing.
    let err = cfg.apply(&wg).await.expect_err("apply must name the missing device");
    assert!(err.to_string().contains("wg-boot0"), "got: {err}");

    // ensure_devices creates it; idempotent second run creates none.
    let created = cfg.ensure_devices(&conn).await?;
    assert_eq!(created, vec!["wg-boot0".to_string()]);
    assert!(cfg.ensure_devices(&conn).await?.is_empty());

    // …and leaves it UP (#329): the documented follow-on is a
    // NetworkConfig that routes via the tunnel, and the kernel refuses
    // a nexthop on a down device with ENETDOWN.
    let link = conn
        .get_link_by_name("wg-boot0")
        .await?
        .expect("wg-boot0 exists after ensure_devices");
    assert!(link.is_up(), "ensure_devices must bring the link up");
    ns.add_addr("wg-boot0", "10.100.0.1/24")?;
    conn.add_route(
        nlink::netlink::route::Ipv4Route::new(std::net::Ipv4Addr::new(10, 2, 0, 0), 24)
            .gateway(std::net::Ipv4Addr::new(10, 100, 0, 2)),
    )
    .await
    .expect("a route via the tunnel address must not fail with ENETDOWN");

    // A device someone downed by hand comes back up on the next call:
    // desired state, not create-time state.
    conn.set_link_down("wg-boot0").await?;
    assert!(cfg.ensure_devices(&conn).await?.is_empty());
    assert!(
        conn.get_link_by_name("wg-boot0").await?.unwrap().is_up(),
        "ensure_devices must re-raise a declared device that was downed"
    );

    // Now the config applies cleanly end-to-end.
    let report = cfg.apply(&wg).await?;
    assert!(report.total_writes() >= 1, "apply configured the fresh device");
    let dev = wg.get_device_by_name("wg-boot0").await?;
    assert_eq!(dev.listen_port, Some(51999));

    Ok(())
}
