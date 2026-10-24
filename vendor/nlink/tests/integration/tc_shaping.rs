//! Regression tests for the TC shaping recipes — #258, #268, #269, #270.
//!
//! Three independent "the HTB `default` names a class that does not
//! exist" bugs shipped in `RateLimiter`, `PerHostLimiter` and (as a
//! near miss) `PerPeerImpairer`. All three were invisible to the
//! existing suite, which asserted that qdiscs and classes *exist* and
//! never that the `defcls` and the created classes agree. When
//! `htb_classify` cannot resolve `defcls` it returns `HTB_DIRECT`: the
//! packet leaves the interface completely unshaped, with no error, no
//! log and no dropped counter to notice.
//!
//! So the first group of tests here reads the live `defcls` back off
//! the wire and demands a class at that handle. The second group goes
//! one better and pushes real traffic through a veth pair, asserting
//! the *class counters* moved — which tests the behaviour rather than
//! the plumbing, and would catch the next bug of this shape too.
//!
//! The third group covers #268: `ingress`/`clsact` are parent-fixed
//! hooks (`TC_H_CLSACT` is an alias of `TC_H_INGRESS`), and installing
//! them under `TC_H_ROOT` made `apply` delete the interface's real root
//! qdisc and then fail.

use std::{net::Ipv4Addr, time::Duration};

use nlink::{
    Rate, TcHandle,
    netlink::{
        config::{NetworkConfig, QdiscParent},
        impair::PerPeerImpairer,
        link::DummyLink,
        ratelimit::{PerHostLimiter, RateLimiter},
        tc::{FqCodelConfig, NetemConfig},
        tc_options::QdiscOptions,
    },
};

use crate::common::counters::class_stats;
use crate::common::topo::NsPair;
use crate::common::traffic::deliver_udp;
use crate::common::TestNamespace;

// ============================================================================
// Helpers
// ============================================================================

/// The `default` class minor the live root HTB qdisc is configured with.
async fn live_defcls(
    conn: &nlink::Connection<nlink::Route>,
    ifindex: u32,
) -> nlink::Result<Option<u32>> {
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let root = qdiscs
        .iter()
        .find(|q| q.kind() == Some("htb") && q.is_root());
    Ok(root.and_then(|q| match q.options() {
        Some(QdiscOptions::Htb(o)) => o.default_class(),
        _ => None,
    }))
}

/// Assert the class named by the root HTB's `defcls` actually exists.
///
/// This is the assertion whose absence let #258 and #269 ship.
async fn assert_default_class_exists(
    conn: &nlink::Connection<nlink::Route>,
    ifindex: u32,
    who: &str,
) -> nlink::Result<TcHandle> {
    let defcls = live_defcls(conn, ifindex)
        .await?
        .unwrap_or_else(|| panic!("{who}: root HTB has no default class configured"));

    let classes = conn.get_classes_by_index(ifindex).await?;
    let want = TcHandle::new(1, defcls as u16);
    let found = classes.iter().any(|c| c.handle() == want);
    assert!(
        found,
        "{who}: HTB default is {defcls:#x} but no class exists at {want}. \
         htb_classify would fall through to HTB_DIRECT and send every \
         unmatched packet unshaped. Live classes: {:?}",
        classes.iter().map(|c| c.handle()).collect::<Vec<_>>()
    );
    Ok(want)
}

// ============================================================================
// #258 / #269 — the HTB default must name a class that exists
// ============================================================================

/// #258 — `RateLimiter` wrote `default_class(0x10)` (16) while creating
/// its single leaf class at `1:10` (10). Every packet on a
/// rate-limited interface bypassed the shaper.
#[tokio::test]
async fn ratelimiter_default_class_exists() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let ns = TestNamespace::new("tcs_rl_def")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    RateLimiter::new("test0")
        .egress(Rate::mbit(10))
        .apply(&conn)
        .await?;

    assert_default_class_exists(&conn, ifindex, "RateLimiter::apply").await?;
    Ok(())
}

/// The same for the reconcile verb, which builds the tree by a
/// different code path.
#[tokio::test]
async fn ratelimiter_reconcile_default_class_exists() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let ns = TestNamespace::new("tcs_rl_rec")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    let _ = RateLimiter::new("test0")
        .egress(Rate::mbit(10))
        .reconcile(&conn)
        .await?;

    assert_default_class_exists(&conn, ifindex, "RateLimiter::reconcile").await?;
    Ok(())
}

/// #269 — `PerHostLimiter::apply` set the HTB `default` to `n+1`, the
/// *last rule's* class, while creating the real default at `n+2`.
/// Unmatched traffic was shaped at the last rule's rate; with zero
/// rules the `default` named the inner class `1:1` and fell through to
/// `HTB_DIRECT`.
///
/// Parameterised over the rule count because the two failure modes are
/// different: `n = 0` produced a nonexistent target, `n >= 1` produced
/// an existing but *wrong* one.
#[tokio::test]
async fn per_host_default_class_exists_for_every_rule_count() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    for n in 0..3usize {
        let ns = TestNamespace::new(&format!("tcs_ph_{n}"))?;
        let conn = ns.connection()?;
        conn.add_link(DummyLink::new("test0")).await?;
        conn.set_link_up("test0").await?;
        let ifindex = conn
            .get_link_by_name("test0")
            .await?
            .expect("dummy exists")
            .ifindex();

        let mut limiter = PerHostLimiter::new("test0", Rate::mbit(10));
        for i in 0..n {
            limiter = limiter.limit_ip(
                Ipv4Addr::new(10, 0, 0, (i + 1) as u8).into(),
                Rate::mbit(100),
            );
        }
        limiter.apply(&conn).await?;

        let default = assert_default_class_exists(
            &conn,
            ifindex,
            &format!("PerHostLimiter::apply with {n} rules"),
        )
        .await?;

        // …and it must not be a rule's own class, which is what `n+1`
        // resolved to for n >= 1: unmatched traffic then inherited the
        // last rule's rate instead of `default_rate`.
        let rule_handles: Vec<TcHandle> =
            (0..n).map(|i| TcHandle::new(1, (i + 2) as u16)).collect();
        assert!(
            !rule_handles.contains(&default),
            "n={n}: HTB default {default} is a rule's class, not the default class"
        );
    }
    Ok(())
}

/// `apply` and `reconcile` must build the *same* tree — the #269 split
/// (`n+1` vs `n+2`) meant an `apply` followed by a `reconcile` always
/// reported changes, so the idempotence contract never held across the
/// two verbs.
#[tokio::test]
async fn per_host_apply_then_reconcile_is_a_noop() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("tcs_ph_verbs")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let limiter = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip(Ipv4Addr::new(10, 0, 0, 1).into(), Rate::mbit(100))
        .limit_ip(Ipv4Addr::new(10, 0, 0, 2).into(), Rate::mbit(50));

    limiter.apply(&conn).await?;
    let report = limiter.reconcile(&conn).await?;
    assert!(
        report.is_noop(),
        "reconcile after apply must have nothing to do, got {} changes: {report:?}",
        report.changes_made
    );
    Ok(())
}

/// `PerPeerImpairer` derives its default minor from one expression
/// already; this pins that it stays that way.
#[tokio::test]
async fn per_peer_impairer_default_class_exists() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("tcs_ppi_def")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    let netem = NetemConfig::new().delay(Duration::from_millis(20)).build();
    PerPeerImpairer::new("test0")
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem.clone())
        .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem)
        .apply(&conn)
        .await?;

    assert_default_class_exists(&conn, ifindex, "PerPeerImpairer::apply").await?;
    Ok(())
}

// ============================================================================
// Traffic actually lands in the class
// ============================================================================

/// The behavioural version of the assertion above: push real packets
/// and check the class counters moved.
///
/// A class-exists assertion catches the three bugs that shipped. This
/// one also catches the next one — a `defcls` that resolves but names
/// the wrong class, a filter that never matches, a leaf that is not
/// attached — because it tests what the recipe is *for*.
#[tokio::test]
async fn per_host_traffic_lands_in_the_declared_classes() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "veth");

    let pair = NsPair::new("tcs_traf", 9).await?;
    let left = &pair.a;
    let conn = left.connection()?;
    let ifindex = pair.a_ifindex;

    // 10.9.0.2 gets its own class; everything else falls to the
    // default class.
    let limiter = PerHostLimiter::new(pair.a_if, Rate::mbit(10))
        .limit_ip(Ipv4Addr::new(10, 9, 0, 2).into(), Rate::mbit(100));
    limiter.apply(&conn).await?;

    let rule_class = TcHandle::new(1, 2);
    let default_class = assert_default_class_exists(&conn, ifindex, "PerHostLimiter").await?;

    let before = class_stats(&conn, ifindex, rule_class)
        .await?
        .expect("rule class exists")
        .1;

    // 20 pings is enough to move a byte counter well past any noise.
    left.exec("ping", &["-c", "20", "-i", "0.05", "-W", "1", "10.9.0.2"])?;

    let after = class_stats(&conn, ifindex, rule_class)
        .await?
        .expect("rule class exists")
        .1;

    assert!(
        after > before,
        "traffic to 10.9.0.2 did not land in its class {rule_class}: \
         {before} -> {after} bytes. The flower filter or the classid is wrong."
    );

    // The default class must be reachable too — this is the half that
    // #258/#269 broke. Ping the network broadcast address, which no
    // rule matches.
    let default_before = class_stats(&conn, ifindex, default_class)
        .await?
        .expect("default class exists")
        .1;
    left.exec_ignore("ping", &["-c", "5", "-i", "0.05", "-W", "1", "-b", "10.9.0.255"]);
    // ARP for an unclaimed address also leaves via the default class.
    left.exec_ignore("ping", &["-c", "3", "-i", "0.05", "-W", "1", "10.9.0.77"]);
    let default_after = class_stats(&conn, ifindex, default_class)
        .await?
        .expect("default class exists")
        .1;

    assert!(
        default_after > default_before,
        "unmatched traffic did not land in the HTB default class \
         {default_class}: {default_before} -> {default_after} bytes. \
         htb_classify fell through to HTB_DIRECT and the shaper is a no-op."
    );
    Ok(())
}

/// `RateLimiter` installs no filters at all, so its default class is
/// the *only* thing between traffic and the wire — the reason #258 was
/// a total bypass rather than a partial one.
#[tokio::test]
async fn ratelimiter_traffic_lands_in_the_default_class() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "veth");

    let pair = NsPair::new("tcs_rltr", 19).await?;
    let left = &pair.a;
    let conn = left.connection()?;
    let ifindex = pair.a_ifindex;

    RateLimiter::new(pair.a_if)
        .egress(Rate::mbit(50))
        .apply(&conn)
        .await?;

    let default_class = assert_default_class_exists(&conn, ifindex, "RateLimiter").await?;
    let before = class_stats(&conn, ifindex, default_class)
        .await?
        .expect("default class exists")
        .1;

    left.exec("ping", &["-c", "20", "-i", "0.05", "-W", "1", "10.19.0.2"])?;

    let after = class_stats(&conn, ifindex, default_class)
        .await?
        .expect("default class exists")
        .1;
    assert!(
        after > before,
        "RateLimiter shaped nothing: default class {default_class} stayed at \
         {before} bytes. This is #258 — every packet took HTB_DIRECT."
    );
    Ok(())
}

// ============================================================================
// #270 — reconcile must notice an edited match criterion
// ============================================================================

/// Editing a rule in place kept its index, so it kept its priority and
/// its classid — and the old comparison looked at nothing else.
/// `reconcile()` reported "no changes" and left the previous address
/// being classified.
#[tokio::test]
async fn per_host_reconcile_notices_an_edited_address() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("tcs_ph_edit")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let before = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip(Ipv4Addr::new(10, 0, 0, 1).into(), Rate::mbit(100));
    let _ = before.reconcile(&conn).await?;
    assert!(before.reconcile(&conn).await?.is_noop());

    // Same rate, same rule index, different address.
    let after = PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_ip(Ipv4Addr::new(10, 0, 0, 2).into(), Rate::mbit(100));
    let report = after.reconcile(&conn).await?;
    assert!(
        report.changes_made > 0,
        "reconcile ignored an edited match address (#270): {report:?}"
    );

    // …and converges: a second pass has nothing left to do.
    assert!(
        after.reconcile(&conn).await?.is_noop(),
        "reconcile did not converge after rewriting the filter"
    );
    Ok(())
}

/// The same for a port rule turned into a different port.
#[tokio::test]
async fn per_host_reconcile_notices_an_edited_port() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("tcs_ph_port")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let before = PerHostLimiter::new("test0", Rate::mbit(10)).limit_port(80, Rate::mbit(100));
    let _ = before.reconcile(&conn).await?;
    let settled = before.reconcile(&conn).await?;
    assert!(settled.is_noop(), "port rule never settles: {settled:?}");

    let after = PerHostLimiter::new("test0", Rate::mbit(10)).limit_port(8080, Rate::mbit(100));
    let report = after.reconcile(&conn).await?;
    assert!(
        report.changes_made > 0,
        "reconcile ignored an edited match port (#270): {report:?}"
    );
    assert!(after.reconcile(&conn).await?.is_noop());
    Ok(())
}

/// `PerPeerImpairer` carried the identical comparison.
#[tokio::test]
async fn per_peer_reconcile_notices_an_edited_address() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem");

    let ns = TestNamespace::new("tcs_ppi_edit")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;

    let netem = NetemConfig::new().delay(Duration::from_millis(20)).build();
    let before =
        PerPeerImpairer::new("test0").impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem.clone());
    let _ = before.reconcile(&conn).await?;
    assert!(before.reconcile(&conn).await?.is_noop());

    let after =
        PerPeerImpairer::new("test0").impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem);
    let report = after.reconcile(&conn).await?;
    assert!(
        report.changes_made > 0,
        "reconcile ignored an edited peer address (#270): {report:?}"
    );
    assert!(after.reconcile(&conn).await?.is_noop());
    Ok(())
}

// ============================================================================
// #268 — ingress/clsact are parent-fixed hooks
// ============================================================================

/// The destructive half of #268.
///
/// `QdiscBuilder::clsact()` left the parent at the `Root` default, so
/// `apply` ran `del_qdisc(dev, TC_H_ROOT)` — removing the interface's
/// real root qdisc — and then asked the kernel to install clsact at
/// `TC_H_ROOT`, which `clsact_init` refuses with `EOPNOTSUPP`. Net
/// effect: the declared clsact was never installed *and* the
/// pre-existing shaping was gone.
#[tokio::test]
async fn declaring_a_clsact_does_not_destroy_the_root_qdisc() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_ingress");

    let ns = TestNamespace::new("tcs_clsact")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    // Pre-existing root shaping, installed out of band.
    conn.add_qdisc_by_index(ifindex, FqCodelConfig::new().build())
        .await?;
    assert!(
        conn.get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .any(|q| q.kind() == Some("fq_codel") && q.is_root()),
        "precondition: fq_codel is the root qdisc"
    );

    let cfg = NetworkConfig::new().qdisc("test0", |q| q.clsact());
    let result = cfg.apply(&conn).await?;
    assert!(
        result.is_success(),
        "applying a clsact declaration failed: {}",
        result.summary_text()
    );

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.kind() == Some("fq_codel") && q.is_root()),
        "declaring a clsact destroyed the root qdisc. Live: {:?}",
        qdiscs.iter().map(|q| q.kind()).collect::<Vec<_>>()
    );
    assert!(
        qdiscs.iter().any(|q| q.kind() == Some("clsact")),
        "the declared clsact was not installed. Live: {:?}",
        qdiscs.iter().map(|q| q.kind()).collect::<Vec<_>>()
    );
    Ok(())
}

/// `clsact()` must resolve to the ingress slot regardless of what the
/// declaration's `parent` field says — a deserialized document can set
/// it freely.
#[tokio::test]
async fn clsact_declaration_resolves_to_the_ingress_slot() -> nlink::Result<()> {
    let cfg = NetworkConfig::new().qdisc("test0", |q| q.clsact());
    let declared = cfg.qdiscs().first().expect("one qdisc declared");
    assert_eq!(declared.effective_parent(), QdiscParent::Ingress);
    Ok(())
}

/// The convenience constructor `add_qdisc` defaults the parent to
/// `TC_H_ROOT`, which the kernel can only refuse for these two kinds.
/// It now asks the config where it belongs.
#[tokio::test]
async fn add_qdisc_installs_a_hook_qdisc_at_the_hook() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_ingress");

    let ns = TestNamespace::new("tcs_hook")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    conn.add_qdisc_by_index(ifindex, nlink::netlink::tc::ClsactConfig::new())
        .await?;

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let clsact = qdiscs
        .iter()
        .find(|q| q.kind() == Some("clsact"))
        .expect("clsact installed");
    assert_eq!(
        clsact.parent(),
        TcHandle::INGRESS,
        "clsact must sit at TC_H_INGRESS (== TC_H_CLSACT), not TC_H_ROOT"
    );
    Ok(())
}

/// A BPF filter's parent is the *hook*, `0xFFFFFFF2` / `0xFFFFFFF3` —
/// not the qdisc parent. `TcHandle::CLSACT` used to hold the ingress
/// hook's value by mistake, so `attach_bpf` happened to name the right
/// filter parent while naming the wrong qdisc parent.
#[tokio::test]
async fn clsact_hook_handles_are_the_filter_parents() -> nlink::Result<()> {
    assert_eq!(TcHandle::CLSACT, TcHandle::INGRESS);
    assert_eq!(TcHandle::CLSACT_INGRESS.as_raw(), 0xFFFF_FFF2);
    assert_eq!(TcHandle::CLSACT_EGRESS.as_raw(), 0xFFFF_FFF3);
    Ok(())
}

// ============================================================================
// #288 — an L4 flower key without an ethertype installs as a match-all
// ============================================================================

/// `cls_flower` reads `ip_proto` and the port keys only when
/// `TCA_FLOWER_KEY_ETH_TYPE` says IPv4 or IPv6 — the filter's `tcm_info`
/// protocol does not feed it. A port filter without the attribute gets a
/// clean ACK and matches *everything*, so `PerHostLimiter::limit_port`
/// was sending all IPv4 traffic to the first port rule's class.
///
/// Asserting the install returned `Ok` cannot catch that. This reads the
/// filter back and demands its keys are there.
#[tokio::test]
async fn port_rules_install_with_their_match_keys() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let ns = TestNamespace::new("tcs_ethtype")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("test0")).await?;
    conn.set_link_up("test0").await?;
    let ifindex = conn
        .get_link_by_name("test0")
        .await?
        .expect("dummy exists")
        .ifindex();

    PerHostLimiter::new("test0", Rate::mbit(10))
        .limit_port(80, Rate::mbit(100))
        .apply(&conn)
        .await?;

    let filters = conn
        .get_filters_by_parent_index(ifindex, TcHandle::major_only(1))
        .await?;
    let installed: Vec<&nlink::netlink::messages::TcMessage> = filters
        .iter()
        .filter(|f| f.handle_raw() != 0 && f.kind() == Some("flower"))
        .collect();
    // TCP and UDP, for IPv4 and for IPv6 (#425).
    assert_eq!(
        installed.len(),
        4,
        "expected TCP and UDP filters for both families"
    );

    for f in installed {
        let raw = f
            .raw_options()
            .unwrap_or_else(|| panic!("filter at prio {} has no options", f.priority()));
        let mut has_eth_type = false;
        let mut has_ip_proto = false;
        let mut has_port = false;
        let mut input = raw;
        while input.len() >= 4 {
            let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
            if len < 4 || input.len() < len {
                break;
            }
            match ty {
                8 => has_eth_type = true,   // TCA_FLOWER_KEY_ETH_TYPE
                9 => has_ip_proto = true,   // TCA_FLOWER_KEY_IP_PROTO
                19 | 21 => has_port = true, // TCA_FLOWER_KEY_{TCP,UDP}_DST
                _ => {}
            }
            let aligned = (len + 3) & !3;
            if input.len() <= aligned {
                break;
            }
            input = &input[aligned..];
        }
        let prio = f.priority();
        assert!(has_eth_type, "prio {prio}: kernel kept no eth_type");
        assert!(
            has_ip_proto,
            "prio {prio}: kernel discarded ip_proto — this filter matches everything (#288)"
        );
        assert!(
            has_port,
            "prio {prio}: kernel discarded the port key — this filter matches everything (#288)"
        );
    }
    Ok(())
}

// ============================================================================
// #458 — RateLimiter ingress must deliver
// ============================================================================

/// `RateLimiter`'s ingress half sends what arrives through the IFB's HTB,
/// and delivers it. The redirect was a mirred *ingress* redirect: the
/// packet went to the IFB's receive path, never met the HTB, and the IFB
/// (`IFF_NOARP`) dropped ARP, so nothing arrived at all (#458).
/// `reconcile()` read that filter as converged; it now replaces it.
#[tokio::test]
async fn ratelimiter_ingress_delivers_through_the_ifb() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_ingress",
        "cls_matchall",
        "cls_u32",
        "act_mirred",
        "ifb",
        "veth"
    );

    let pair = NsPair::new("tcs_rlin", 29).await?;
    let b = pair.b.connection()?;
    let dst = std::net::SocketAddr::new(pair.b_addr.into(), 9000);
    let limiter = RateLimiter::new(pair.b_if).ingress(Rate::mbit(50));
    limiter.apply(&b).await?;

    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 20),
        20,
        "ingress shaping delivers"
    );
    let ifb = b
        .get_link_by_name("ifb_veth-b")
        .await?
        .expect("the IFB exists")
        .ifindex();
    let (_, bytes) = class_stats(&b, ifb, TcHandle::new(1, 10))
        .await?
        .expect("the IFB's default class exists");
    assert!(bytes > 0, "the traffic passed the IFB's HTB");

    // What every release before 0.31 installed: u32 at priority 1 with a
    // mirred *ingress* redirect.
    for f in b
        .get_filters_by_parent_index(pair.b_ifindex, TcHandle::INGRESS)
        .await?
    {
        b.del_filter_by_index(
            pair.b_ifindex,
            TcHandle::INGRESS,
            f.protocol(),
            f.priority(),
        )
        .await
        .or_else(|e| if e.is_not_found() { Ok(()) } else { Err(e) })?;
    }
    pair.b.exec(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            pair.b_if,
            "parent",
            "ffff:",
            "prio",
            "1",
            "protocol",
            "all",
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "mirred",
            "ingress",
            "redirect",
            "dev",
            "ifb_veth-b",
        ],
    )?;
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 20),
        0,
        "the old redirect drops it all"
    );

    let report = limiter.reconcile(&b).await?;
    assert!(report.changes_made > 0, "{report:?}");
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 20),
        20,
        "reconcile fixed the redirect"
    );
    let filters = b
        .get_filters_by_parent_index(pair.b_ifindex, TcHandle::INGRESS)
        .await?;
    assert!(
        filters.iter().all(|f| f.kind() == Some("matchall")),
        "the u32 redirect is gone: {:?}",
        filters
            .iter()
            .map(|f| (f.kind(), f.priority()))
            .collect::<Vec<_>>()
    );
    let again = limiter.reconcile(&b).await?;
    assert_eq!(again.changes_made, 0, "{again:?}");
    Ok(())
}
