//! Integration tests for the rate limiting DSL.
//!
//! These tests require root privileges and network namespace support.

use std::time::Duration;

use nlink::{
    Bytes, Rate,
    netlink::ratelimit::{PerHostLimiter, RateLimit, RateLimiter},
};

use crate::common::TestNamespace;

// ============================================================================
// Unit tests (no root required)
// ============================================================================

#[test]
fn test_rate_limit_new() {
    let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000));
    assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
    assert!(limit.ceil.is_none());
    assert!(limit.burst.is_none());
    assert!(limit.latency.is_none());
}

#[test]
fn test_rate_limit_typed_units() {
    // 100 Mbps -> 12.5 MB/s, 1 Gbps -> 125 MB/s.
    let limit = RateLimit::new(Rate::mbit(100));
    assert_eq!(limit.rate.as_bytes_per_sec(), 12_500_000);

    let limit = RateLimit::new(Rate::gbit(1));
    assert_eq!(limit.rate.as_bytes_per_sec(), 125_000_000);

    let limit = RateLimit::new(Rate::mbit(10));
    assert_eq!(limit.rate.as_bytes_per_sec(), 1_250_000);
}

#[test]
fn test_rate_limit_with_options() {
    let limit = RateLimit::new(Rate::bytes_per_sec(1_000_000))
        .ceil(Rate::bytes_per_sec(2_000_000))
        .burst(Bytes::new(32000))
        .latency(Duration::from_millis(20));

    assert_eq!(limit.rate, Rate::bytes_per_sec(1_000_000));
    assert_eq!(limit.ceil, Some(Rate::bytes_per_sec(2_000_000)));
    assert_eq!(limit.burst, Some(Bytes::new(32000)));
    assert_eq!(limit.latency, Some(Duration::from_millis(20)));
}

#[test]
fn test_rate_limiter_builder() {
    // Just verify builder pattern works without errors
    let _limiter = RateLimiter::new("eth0")
        .egress(Rate::bytes_per_sec(1_000_000))
        .ingress(Rate::bytes_per_sec(2_000_000))
        .burst_to(Rate::bytes_per_sec(3_000_000))
        .latency(Duration::from_millis(20));
}

#[test]
fn test_rate_limiter_with_typed_rates() {
    let _limiter = RateLimiter::new("eth0")
        .egress(Rate::mbit(100))
        .ingress(Rate::gbit(1))
        .burst_to(Rate::mbit(150));
}

#[test]
fn test_per_host_limiter_builder() {
    let _limiter = PerHostLimiter::new("eth0", Rate::mbit(10));
}

#[test]
fn test_per_host_limiter_with_rules() {
    let _limiter = PerHostLimiter::new("eth0", Rate::mbit(10))
        .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))
        .unwrap()
        .limit_port(80, Rate::mbit(500))
        .latency(Duration::from_millis(5));
}

// ============================================================================
// Integration tests (require root)
// ============================================================================

#[tokio::test]
async fn test_egress_rate_limiting() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_egress")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .egress(Rate::bytes_per_sec(1_000_000))
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_qdisc = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb_qdisc.is_some(), "HTB qdisc should exist");

    let fq_codel = qdiscs.iter().find(|q| q.kind() == Some("fq_codel"));
    assert!(fq_codel.is_some(), "fq_codel leaf qdisc should exist");

    RateLimiter::new("test0").remove(&conn).await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_qdisc = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb_qdisc.is_none(), "HTB qdisc should be removed");

    Ok(())
}

/// #169 — RateLimiter::reconcile converges from scratch, is
/// idempotent (second run = zero changes), and picks up a
/// rate drift in place.
#[tokio::test]
async fn test_rate_limiter_reconcile_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "ifb");

    let ns = TestNamespace::new("rl_reconcile")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = RateLimiter::new("test0")
        .egress(Rate::bytes_per_sec(1_000_000))
        .ingress(Rate::bytes_per_sec(2_000_000))
        .latency(Duration::from_millis(20));

    // From scratch: converges (several changes).
    let first = limiter.reconcile(&conn).await?;
    assert!(first.changes_made > 0, "first reconcile must build the tree");

    // Idempotence: nothing to do.
    let second = limiter.reconcile(&conn).await?;
    assert_eq!(
        second.changes_made, 0,
        "second reconcile must be a no-op, got {second:?}"
    );

    // Dry-run reports drift without mutating.
    let drifted = RateLimiter::new("test0")
        .egress(Rate::bytes_per_sec(5_000_000))
        .ingress(Rate::bytes_per_sec(2_000_000))
        .latency(Duration::from_millis(20));
    let plan = drifted.reconcile_dry_run(&conn).await?;
    assert!(plan.changes_made > 0, "dry run must report the rate drift");
    let after_dry = limiter.reconcile(&conn).await?;
    assert_eq!(
        after_dry.changes_made, 0,
        "dry run must not have mutated anything"
    );

    // Real drift fix converges and is idempotent again.
    let fixed = drifted.reconcile(&conn).await?;
    assert!(fixed.changes_made > 0);
    assert_eq!(drifted.reconcile(&conn).await?.changes_made, 0);

    Ok(())
}

#[tokio::test]
async fn test_ingress_rate_limiting() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_ingress",
        "cls_matchall",
        "act_mirred",
        "ifb"
    );

    let ns = TestNamespace::new("rl_ingress")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .ingress(Rate::bytes_per_sec(2_000_000))
        .latency(Duration::from_millis(10))
        .apply(&conn)
        .await?;

    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_some(), "IFB device should be created");

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(
        ingress.is_some(),
        "Ingress qdisc should exist on main interface"
    );

    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist on IFB device");

    RateLimiter::new("test0").remove(&conn).await?;

    let ifb_link = conn.get_link_by_name("ifb_test0").await?;
    assert!(ifb_link.is_none(), "IFB device should be removed");

    Ok(())
}

#[tokio::test]
async fn test_bidirectional_rate_limiting() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_ingress",
        "cls_matchall",
        "act_mirred",
        "ifb"
    );

    let ns = TestNamespace::new("rl_bidir")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0")
        .egress(Rate::mbit(100))
        .ingress(Rate::gbit(1))
        .burst_to(Rate::mbit(150))
        .latency(Duration::from_millis(20))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "Egress HTB should exist");

    let ingress = qdiscs.iter().find(|q| q.is_ingress());
    assert!(ingress.is_some(), "Ingress qdisc should exist");

    let ifb_qdiscs = conn.get_qdiscs_by_name("ifb_test0").await?;
    let ifb_htb = ifb_qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(ifb_htb.is_some(), "HTB on IFB should exist");

    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_per_host_rate_limiting() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_perhost")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("192.168.1.100".parse().unwrap(), Rate::mbit(100))
        .limit_subnet("10.0.0.0/8", Rate::mbit(50))?
        .latency(Duration::from_millis(5))
        .apply(&conn)
        .await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "HTB qdisc should exist");

    let fq_codel_count = qdiscs
        .iter()
        .filter(|q| q.kind() == Some("fq_codel"))
        .count();
    assert!(
        fq_codel_count >= 3,
        "Should have at least 3 fq_codel qdiscs (2 rules + default)"
    );

    let filters = conn.get_filters_by_name("test0").await?;
    assert!(!filters.is_empty(), "Flower filters should exist");

    PerHostLimiter::new("test0", Rate::mbit(10))
        .remove(&conn)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_idempotency() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_idemp")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = RateLimiter::new("test0").egress(Rate::bytes_per_sec(1_000_000));

    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;
    limiter.apply(&conn).await?;

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    let htb_count = qdiscs.iter().filter(|q| q.kind() == Some("htb")).count();
    assert_eq!(htb_count, 1, "Should have exactly one HTB qdisc");

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_remove_nonexistent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_remove")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    RateLimiter::new("test0").remove(&conn).await?;

    Ok(())
}

// ============================================================================
// Reconcile tests
// ============================================================================

#[tokio::test]
async fn test_per_host_reconcile_first_call_creates_tree() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_reconcile_first")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let report = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100))
        .limit_ip("10.0.0.2".parse().unwrap(), Rate::mbit(50))
        .reconcile(&conn)
        .await?;

    assert!(report.changes_made > 0);
    assert_eq!(report.rules_added, 2);
    assert!(report.root_modified);

    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("htb") && q.is_root())
    );
    Ok(())
}

#[tokio::test]
async fn test_per_host_reconcile_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_reconcile_idem")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let limiter = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100));

    let r1 = limiter.reconcile(&conn).await?;
    assert!(r1.changes_made > 0);
    let r2 = limiter.reconcile(&conn).await?;
    assert!(
        r2.is_noop(),
        "second reconcile should be a no-op (got {} changes)",
        r2.changes_made,
    );
    Ok(())
}

#[tokio::test]
async fn test_per_host_reconcile_dry_run() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("rl_reconcile_dry")?;
    let conn = ns.connection()?;

    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;

    let report = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), Rate::mbit(100))
        .reconcile_dry_run(&conn)
        .await?;

    assert!(report.dry_run);
    assert!(report.changes_made > 0);

    // Nothing actually installed.
    let qdiscs = conn.get_qdiscs_by_name("test0").await?;
    assert!(qdiscs.iter().all(|q| q.kind() != Some("htb")));
    Ok(())
}

/// A `RateLimiter` meeting an HTB `1:` another recipe built (here a
/// `PerPeerImpairer`'s, default class `0xffff`) says so, instead of adding
/// its classes into that tree (#491).
#[tokio::test]
async fn test_rate_limiter_refuses_another_recipes_htb() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "sch_fq_codel", "cls_flower", "sch_netem");
    use nlink::netlink::impair::PerPeerImpairer;
    use nlink::netlink::tc::NetemConfig;

    let ns = TestNamespace::new("rl_other_htb")?;
    let conn = ns.connection()?;
    conn.add_link(nlink::netlink::link::DummyLink::new("test0"))
        .await?;
    conn.set_link_up("test0").await?;
    PerPeerImpairer::new("test0")
        .impair_dst_ip(
            std::net::Ipv4Addr::new(10, 0, 0, 1).into(),
            NetemConfig::new().delay(Duration::from_millis(5)).build(),
        )
        .apply(&conn)
        .await?;

    let err = RateLimiter::new("test0")
        .egress(Rate::mbit(10))
        .reconcile(&conn)
        .await
        .expect_err("another recipe's HTB");
    assert!(err.to_string().contains("default class 0xffff"), "{err}");
    Ok(())
}

// ============================================================================
// #490 — a RateLimiter touches what it owns
// ============================================================================

async fn dummy(
    conn: &nlink::netlink::Connection<nlink::netlink::Route>,
    name: &str,
) -> nlink::Result<u32> {
    conn.add_link(nlink::netlink::link::DummyLink::new(name))
        .await?;
    conn.set_link_up(name).await?;
    Ok(conn
        .get_link_by_name(name)
        .await?
        .expect("dummy exists")
        .ifindex())
}

/// A `clsact` hook with a filter of its own on it — what a BPF program
/// looks like to tc.
async fn clsact_with_a_filter(
    conn: &nlink::netlink::Connection<nlink::netlink::Route>,
    ifindex: u32,
) -> nlink::Result<()> {
    use nlink::netlink::action::{ActionList, GactAction};
    use nlink::netlink::filter::MatchallFilter;
    conn.add_qdisc_by_index(ifindex, nlink::netlink::tc::ClsactConfig::new())
        .await?;
    conn.add_filter_by_index_full(
        ifindex,
        nlink::TcHandle::CLSACT_INGRESS,
        None,
        nlink::EthProto::new(0x0003),
        nlink::FilterPriority::new(7),
        MatchallFilter::new().actions(ActionList::new().with(GactAction::pass())),
    )
    .await
}

/// `remove()` takes only what the limiter built. It deleted whatever root
/// and ingress qdiscs were there — a netem, a clsact with its programs —
/// and threw away every error (#490).
#[tokio::test]
async fn remove_leaves_what_the_limiter_did_not_build() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_netem",
        "sch_ingress",
        "cls_matchall",
        "act_gact",
        "dummy"
    );

    let ns = TestNamespace::new("rl_rm_own")?;
    let conn = ns.connection()?;
    let ifindex = dummy(&conn, "test0").await?;
    conn.add_qdisc_by_index(ifindex, nlink::netlink::tc::NetemConfig::new().build())
        .await?;
    clsact_with_a_filter(&conn, ifindex).await?;

    RateLimiter::new("test0").remove(&conn).await?;
    let kinds: Vec<String> = conn
        .get_qdiscs_by_index(ifindex)
        .await?
        .iter()
        .filter_map(|q| q.kind().map(str::to_string))
        .collect();
    assert!(kinds.contains(&"netem".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"clsact".to_string()), "{kinds:?}");
    let on_hook = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::CLSACT_INGRESS)
        .await?;
    assert_eq!(on_hook.len(), 1, "the clsact's own filter is gone");
    Ok(())
}

/// The ingress half hangs its redirect off a clsact that is there, instead
/// of deleting it (a clsact sits at `ffff:` too) and its programs with it,
/// and converges; removing it leaves the clsact as it found it (#490).
#[tokio::test]
async fn ingress_shaping_keeps_a_clsact() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_fq_codel",
        "sch_ingress",
        "ifb",
        "act_mirred",
        "cls_matchall",
        "act_gact",
        "dummy"
    );

    let ns = TestNamespace::new("rl_clsact")?;
    let conn = ns.connection()?;
    let ifindex = dummy(&conn, "test0").await?;
    clsact_with_a_filter(&conn, ifindex).await?;

    let limiter = RateLimiter::new("test0").ingress(Rate::mbit(10));
    limiter.apply(&conn).await?;
    let again = limiter.reconcile(&conn).await?;
    assert_eq!(again.changes_made, 0, "{again:?}");
    let on_hook = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::CLSACT_INGRESS)
        .await?;
    assert_eq!(on_hook.len(), 2, "the clsact's own filter and the redirect");

    limiter.remove(&conn).await?;
    let kinds: Vec<String> = conn
        .get_qdiscs_by_index(ifindex)
        .await?
        .iter()
        .filter_map(|q| q.kind().map(str::to_string))
        .collect();
    assert!(kinds.contains(&"clsact".to_string()), "{kinds:?}");
    let on_hook = conn
        .get_filters_by_parent_index(ifindex, nlink::TcHandle::CLSACT_INGRESS)
        .await?;
    assert_eq!(
        on_hook.len(),
        1,
        "the redirect is gone, the clsact's own filter stays"
    );
    assert!(conn.get_link_by_name("ifb_test0").await?.is_none());
    Ok(())
}

/// A direction the limiter no longer declares is taken down by reconcile.
/// It stayed: only the declared halves were looked at (#490).
#[tokio::test]
async fn reconcile_takes_down_a_half_that_left() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_fq_codel",
        "sch_ingress",
        "ifb",
        "act_mirred",
        "cls_matchall",
        "dummy"
    );

    let ns = TestNamespace::new("rl_half")?;
    let conn = ns.connection()?;
    let ifindex = dummy(&conn, "test0").await?;

    let both = RateLimiter::new("test0")
        .egress(Rate::mbit(10))
        .ingress(Rate::mbit(20));
    let built = both.reconcile(&conn).await?;
    assert!(built.changes_made > 0);

    let egress_only = RateLimiter::new("test0").egress(Rate::mbit(10));
    let r = egress_only.reconcile(&conn).await?;
    assert!(r.changes_made > 0, "{r:?}");
    assert!(
        conn.get_link_by_name("ifb_test0").await?.is_none(),
        "the IFB stayed"
    );
    assert!(
        !conn
            .get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("ingress")),
        "the ingress hook stayed"
    );
    assert_eq!(egress_only.reconcile(&conn).await?.changes_made, 0);

    let ingress_only = RateLimiter::new("test0").ingress(Rate::mbit(20));
    let swapped = ingress_only.reconcile(&conn).await?;
    assert!(swapped.changes_made > 0, "{swapped:?}");
    assert!(
        !conn
            .get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("htb")),
        "the egress HTB stayed"
    );
    assert_eq!(ingress_only.reconcile(&conn).await?.changes_made, 0);
    Ok(())
}

/// The IFB is used, and deleted, only when it is this limiter's: an IFB
/// by kind, carrying its tag. A dummy that happens to have the name was
/// reused (#490).
#[tokio::test]
async fn an_ifb_name_taken_by_something_else_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_fq_codel",
        "sch_ingress",
        "ifb",
        "act_mirred",
        "cls_matchall",
        "dummy"
    );

    let ns = TestNamespace::new("rl_ifb_own")?;
    let conn = ns.connection()?;
    dummy(&conn, "test0").await?;
    dummy(&conn, "ifb_test0").await?;

    let limiter = RateLimiter::new("test0").ingress(Rate::mbit(10));
    let err = limiter
        .apply(&conn)
        .await
        .expect_err("ifb_test0 is a dummy");
    assert!(err.to_string().contains("not an IFB"), "{err}");
    limiter.remove(&conn).await?;
    let still = conn
        .get_link_by_name("ifb_test0")
        .await?
        .expect("the dummy is left alone");
    assert_eq!(still.kind(), Some("dummy"));
    Ok(())
}

/// A burst or a latency dropped from the declaration is reset. Reconcile
/// compared rate and ceiling only, and any AQM target passed (#490).
#[tokio::test]
async fn reconcile_resets_a_dropped_burst_and_latency() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "sch_fq_codel", "dummy");

    let ns = TestNamespace::new("rl_drift")?;
    let conn = ns.connection()?;
    dummy(&conn, "test0").await?;

    let tuned = RateLimiter::new("test0")
        .egress(Rate::mbit(10))
        .burst_size(Bytes::kib(64))
        .latency(Duration::from_millis(20));
    let built = tuned.reconcile(&conn).await?;
    assert!(built.changes_made > 0, "{built:?}");
    assert_eq!(tuned.reconcile(&conn).await?.changes_made, 0);

    let plain = RateLimiter::new("test0").egress(Rate::mbit(10));
    let reset = plain.reconcile(&conn).await?;
    assert!(
        reset.changes_made >= 3,
        "two classes and the leaf: {reset:?}"
    );
    assert_eq!(plain.reconcile(&conn).await?.changes_made, 0);
    Ok(())
}

/// `burst_to` lets the limiter reach its ceiling. Class `1:1` sits straight
/// under the qdisc, with no parent to borrow from, so with `rate 1mbit,
/// ceil 8mbit` there the leaf never passed 1 Mbit/s — measured, 1.1 Mbit/s
/// (#490). Two seconds of datagrams now arrive at about 8 Mbit/s.
#[tokio::test]
async fn burst_to_reaches_the_ceiling() -> nlink::Result<()> {
    use std::net::{SocketAddr, UdpSocket};
    require_root!();
    nlink::require_modules!("sch_htb", "sch_fq_codel", "veth");

    let pair = crate::common::topo::NsPair::new("rl-ceil", 91).await?;
    RateLimiter::new(pair.a_if)
        .egress(Rate::mbit(1))
        .burst_to(Rate::mbit(8))
        .apply(&pair.a.connection()?)
        .await?;

    let dst = SocketAddr::from((pair.b_addr, 9100));
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    let b_name = pair.b.name().to_string();
    let receiver = std::thread::spawn(move || {
        let _ns = nlink::netlink::namespace::enter(&b_name).expect("enter b");
        let socket = UdpSocket::bind(dst).expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        bound_tx.send(()).expect("bound");
        let mut buf = [0u8; 2048];
        let mut bytes = 0usize;
        while let Ok(n) = socket.recv(&mut buf) {
            bytes += n;
        }
        bytes
    });
    bound_rx.recv().expect("receiver bound");
    crate::common::traffic::in_ns(&pair.a, move || {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind sender");
        let payload = [0u8; 1200];
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < until {
            if socket.send_to(&payload, dst).is_err() {
                std::thread::sleep(Duration::from_micros(500));
            }
        }
    });
    let bytes = receiver.join().expect("receiver");
    // 1 Mbit/s for 2 s is 250 kB; 8 Mbit/s is 2 MB.
    assert!(
        bytes > 1_000_000,
        "{bytes} bytes in 2 s: the ceiling is out of reach"
    );
    Ok(())
}
