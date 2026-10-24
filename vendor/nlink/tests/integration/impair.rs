//! Integration tests for the per-peer impairment helper.
//!
//! These require root + a kernel with `cls_flower` and `sch_netem` loaded.

use std::{net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    impair::{PeerImpairment, PerPeerImpairer},
    link::DummyLink,
    tc::NetemConfig,
};

use crate::common::TestNamespace;

fn netem_50ms() -> NetemConfig {
    NetemConfig::new().delay(Duration::from_millis(50)).build()
}

#[tokio::test]
async fn test_apply_creates_full_tree() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_apply")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 3).into(), netem_50ms())
        .apply(&conn)
        .await?;

    // Root HTB present.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root()),
        "root HTB should exist"
    );

    // 4 netem leaves: one per rule + one default (since no default
    // impairment specified, we don't add a netem leaf for the default
    // class — adjust: exactly 3 netem leaves expected)
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 3,
        "expected 3 netem leaves (one per rule, no default impairment)"
    );

    // 5 classes total: 1:1 root + 1:2..1:4 per rule + 1:5 default.
    let classes = conn.get_classes_by_index(ifindex).await?;
    let htb_classes = classes.iter().filter(|c| c.kind() == Some("htb")).count();
    assert_eq!(
        htb_classes, 5,
        "expected 5 HTB classes (1 parent + 3 rules + 1 default)"
    );

    // 3 flower filters at parent 1:.
    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    let flower_filters = filters
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();
    assert_eq!(flower_filters, 3, "expected 3 flower filters at parent 1:");

    Ok(())
}

#[tokio::test]
async fn test_apply_with_default_impairment_adds_default_leaf() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_default")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .default_impairment(NetemConfig::new().delay(Duration::from_millis(20)).build())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 2,
        "expected 2 netem leaves (1 rule + 1 default impairment)"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_no_default_means_no_default_leaf() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_no_default")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(
        netem_count, 1,
        "expected 1 netem leaf (rule only, no default impairment)"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_idempotent")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let imp = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms());

    imp.apply(&conn).await?;
    let first_filter_count = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();

    // Apply again — should give the same shape.
    imp.apply(&conn).await?;
    let second_filter_count = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .count();

    assert_eq!(first_filter_count, second_filter_count);
    assert_eq!(first_filter_count, 2);

    Ok(())
}

#[tokio::test]
async fn test_clear_removes_all() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_clear")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let imp = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms());

    imp.apply(&conn).await?;
    assert!(
        conn.get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("htb")),
        "HTB should exist after apply"
    );

    imp.clear(&conn).await?;
    assert!(
        !conn
            .get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("htb")),
        "HTB should be removed after clear"
    );

    // clear() is idempotent — second call is a no-op.
    imp.clear(&conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_apply_with_ipv6_match() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_v6")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_subnet("2001:db8::/32", netem_50ms())?
        .apply(&conn)
        .await?;

    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    let flower_filters: Vec<_> = filters
        .iter()
        .filter(|f| f.kind() == Some("flower"))
        .collect();
    assert_eq!(flower_filters.len(), 1, "one flower filter expected");

    Ok(())
}

#[tokio::test]
async fn test_apply_with_dst_mac_match() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_mac")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], netem_50ms())
        .apply(&conn)
        .await?;

    let filters = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    assert!(
        filters.iter().any(|f| f.kind() == Some("flower")),
        "flower filter for MAC match should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_apply_by_index_constructor() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_byidx")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new_by_index(ifindex)
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs.iter().any(|q| q.kind() == Some("htb")),
        "tree should be created when constructed by ifindex"
    );

    Ok(())
}

#[tokio::test]
async fn test_rate_cap_per_rule() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_ratecap")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            PeerImpairment::new(netem_50ms()).rate_cap(nlink::Rate::mbit(100)),
        )
        .apply(&conn)
        .await?;

    let classes = conn.get_classes_by_index(ifindex).await?;
    let htb_classes: Vec<_> = classes.iter().filter(|c| c.kind() == Some("htb")).collect();
    // 1 parent + 1 rule + 1 default = 3 HTB classes
    assert_eq!(htb_classes.len(), 3, "expected 3 HTB classes with rate cap");

    Ok(())
}

// ============================================================================
// Reconcile tests
// ============================================================================

#[tokio::test]
async fn test_reconcile_first_call_creates_tree() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_reconcile_first")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let report = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .reconcile(&conn)
        .await?;

    assert!(report.changes_made > 0, "first reconcile must mutate");
    assert_eq!(report.rules_added, 2);
    assert!(report.root_modified);

    // Tree exists.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root())
    );
    assert_eq!(
        qdiscs.iter().filter(|q| q.kind() == Some("netem")).count(),
        2,
    );
    Ok(())
}

#[tokio::test]
async fn test_reconcile_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_reconcile_idem")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let imp = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms());

    let r1 = imp.reconcile(&conn).await?;
    assert!(r1.changes_made > 0);

    let r2 = imp.reconcile(&conn).await?;
    assert!(
        r2.is_noop(),
        "second reconcile should be a no-op (got {} changes: {:?})",
        r2.changes_made,
        r2,
    );
    Ok(())
}

#[tokio::test]
async fn test_reconcile_modify_netem() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_reconcile_mod")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let imp_a = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms());
    let _ = imp_a.reconcile(&conn).await?;

    // Now bump the delay and reconcile.
    let imp_b = PerPeerImpairer::new("test0").impair_dst_ip(
        Ipv4Addr::new(10, 0, 0, 1).into(),
        NetemConfig::new().delay(Duration::from_millis(120)).build(),
    );
    let r = imp_b.reconcile(&conn).await?;
    assert_eq!(
        r.rules_modified, 1,
        "rule should be modified, not added/removed (report: {:?})",
        r,
    );
    assert_eq!(r.rules_added, 0);
    assert_eq!(r.rules_removed, 0);
    Ok(())
}

#[tokio::test]
async fn test_reconcile_remove_rule() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_reconcile_rm")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let _ = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 3).into(), netem_50ms())
        .reconcile(&conn)
        .await?;

    // Reconcile a 2-rule version — should remove the third.
    let r = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .reconcile(&conn)
        .await?;
    assert!(
        r.rules_removed >= 1,
        "expected at least 1 rule removed: {r:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_reconcile_dry_run_makes_no_changes() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_reconcile_dry")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    let report = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .reconcile_dry_run(&conn)
        .await?;

    assert!(report.dry_run);
    assert!(report.changes_made > 0, "would-do count should be > 0");

    // No qdisc was actually installed.
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs.iter().all(|q| q.kind() != Some("htb")),
        "dry-run installed an HTB qdisc",
    );
    Ok(())
}

#[tokio::test]
async fn test_reconcile_wrong_root_kind_errors() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");
    use nlink::netlink::tc::PrioConfig;

    let ns = TestNamespace::new("impair_reconcile_wrongroot")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    // Install a non-HTB qdisc at root manually.
    conn.add_qdisc_full(
        "test0",
        nlink::TcHandle::ROOT,
        Some(nlink::TcHandle::major_only(1)),
        PrioConfig::new().build(),
    )
    .await?;

    let r = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .reconcile(&conn)
        .await;
    assert!(r.is_err(), "expected error for wrong root kind, got {r:?}");
    Ok(())
}

#[tokio::test]
async fn test_reconcile_with_fallback_to_apply() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");
    use nlink::ReconcileOptions;
    use nlink::netlink::tc::PrioConfig;

    let ns = TestNamespace::new("impair_reconcile_fallback")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    // Wrong root.
    conn.add_qdisc_full(
        "test0",
        nlink::TcHandle::ROOT,
        Some(nlink::TcHandle::major_only(1)),
        PrioConfig::new().build(),
    )
    .await?;

    let _ = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .reconcile_with_options(&conn, ReconcileOptions::new().with_fallback_to_apply(true))
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root()),
        "fallback should have rebuilt the HTB tree",
    );
    Ok(())
}

#[tokio::test]
async fn test_get_filters_by_parent_filters_correctly() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_byparent")?;
    let conn = ns.connection()?;

    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let link = conn.get_link_by_name("test0").await?.expect("dummy exists");
    let ifindex = link.ifindex();

    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
        .apply(&conn)
        .await?;

    // All filters at parent 1: should be the helper's flower filters.
    let at_root = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
        .await?;
    assert_eq!(at_root.len(), 2, "expected 2 filters at parent 1:");
    assert!(at_root.iter().all(|f| f.kind() == Some("flower")));

    // No filters at parent 2: (a parent that doesn't exist).
    let at_other = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(2))
        .await?;
    assert!(at_other.is_empty(), "no filters expected at parent 2:");

    Ok(())
}

/// Shrinking more than 100 rules. Rule `i` sits at priority `100 + i`, so
/// rules 100 and up are above the recipe band. Reconcile told its filters
/// by the band, left those behind, and deleting the classes they were
/// bound to was EBUSY (#491).
#[tokio::test]
async fn test_reconcile_shrinks_past_the_recipe_band() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("impair_shrink_band")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy")
        .ifindex();

    let peers = |n: u8| {
        (0..n).fold(PerPeerImpairer::new("test0"), |p, i| {
            p.impair_dst_ip(Ipv4Addr::new(10, 0, 1, i).into(), netem_50ms())
        })
    };
    let built = peers(105).reconcile(&conn).await?;
    assert_eq!(built.rules_added, 105, "{built:?}");
    let shrunk = peers(2).reconcile(&conn).await?;
    assert!(shrunk.rules_removed >= 103, "{shrunk:?}");
    let again = peers(2).reconcile(&conn).await?;
    assert_eq!(again.changes_made, 0, "{again:?}");
    let filters = conn.get_filters_by_index(ifindex).await?;
    let left: Vec<u16> = filters
        .iter()
        .map(|f| f.priority().as_u16())
        .filter(|p| *p > 101)
        .collect();
    assert!(left.is_empty(), "filters left behind at {left:?}");
    Ok(())
}

/// An HTB `1:` with another default class — another recipe's tree, or one
/// from before 0.26 — cannot be changed in place: HTB has no change
/// operation, so the change reconcile sent was EINVAL every time. Without
/// fallback it now says what is in the way; with it, it rebuilds (#491).
#[tokio::test]
async fn test_reconcile_over_an_htb_with_another_default() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");
    use nlink::ReconcileOptions;
    use nlink::netlink::tc::HtbQdiscConfig;

    let ns = TestNamespace::new("impair_other_default")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    conn.add_qdisc_full(
        "test0",
        nlink::TcHandle::ROOT,
        Some(nlink::TcHandle::major_only(1)),
        HtbQdiscConfig::new().default_class(0x10).build(),
    )
    .await?;

    let impairer = PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms());
    let err = impairer
        .reconcile(&conn)
        .await
        .expect_err("another default class");
    assert!(err.to_string().contains("default class 0x10"), "{err}");

    let rebuilt = impairer
        .reconcile_with_options(&conn, ReconcileOptions::new().with_fallback_to_apply(true))
        .await?;
    assert!(rebuilt.root_modified, "{rebuilt:?}");
    let again = impairer.reconcile(&conn).await?;
    assert_eq!(again.changes_made, 0, "{again:?}");
    Ok(())
}
