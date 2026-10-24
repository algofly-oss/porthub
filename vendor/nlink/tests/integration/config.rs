//! Integration tests for declarative network configuration.

use std::time::Duration;

use nlink::{
    Result,
    netlink::{
        config::{ApplyOptions, DeclaredLinkType, LinkState, NetworkConfig},
        link::DummyLink,
        tc_options::QdiscOptions,
    },
    util::{Percent, Rate},
};

use crate::common::TestNamespace;

// ============================================================================
// Unit Tests (no namespace required)
// ============================================================================

#[test]
fn test_network_config_builder() {
    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .link("br0", |l| l.bridge().up().mtu(9000));

    assert_eq!(config.links().len(), 2);
    assert_eq!(config.links()[0].name(), "dummy0");
    assert_eq!(config.links()[0].link_type(), &DeclaredLinkType::Dummy);
    assert_eq!(config.links()[0].state(), LinkState::Up);

    assert_eq!(config.links()[1].name(), "br0");
    assert_eq!(config.links()[1].link_type(), &DeclaredLinkType::Bridge);
    assert_eq!(config.links()[1].mtu(), Some(9000));
}

#[test]
fn test_address_parsing() {
    let config = NetworkConfig::new()
        .address("eth0", "192.168.1.1/24")
        .unwrap()
        .address("eth0", "2001:db8::1/64")
        .unwrap();

    assert_eq!(config.addresses().len(), 2);

    let addr1 = &config.addresses()[0];
    assert_eq!(addr1.dev(), "eth0");
    assert!(addr1.is_ipv4());
    assert_eq!(addr1.prefix_len(), 24);

    let addr2 = &config.addresses()[1];
    assert!(addr2.is_ipv6());
    assert_eq!(addr2.prefix_len(), 64);
}

#[test]
fn test_address_parsing_errors() {
    // Missing prefix
    let result = NetworkConfig::new().address("eth0", "192.168.1.1");
    assert!(result.is_err());

    // Invalid address
    let result = NetworkConfig::new().address("eth0", "invalid/24");
    assert!(result.is_err());

    // Invalid prefix
    let result = NetworkConfig::new().address("eth0", "192.168.1.1/abc");
    assert!(result.is_err());

    // Prefix too large for IPv4
    let result = NetworkConfig::new().address("eth0", "192.168.1.1/33");
    assert!(result.is_err());
}

#[test]
fn test_route_parsing() {
    let config = NetworkConfig::new()
        .route("10.0.0.0/8", |r| r.via("192.168.1.1").dev("eth0"))
        .unwrap()
        .route("0.0.0.0/0", |r| r.via("192.168.1.254"))
        .unwrap();

    assert_eq!(config.routes().len(), 2);

    let route1 = &config.routes()[0];
    assert!(route1.is_ipv4());
    assert_eq!(route1.prefix_len(), 8);
    assert!(route1.gateway().is_some());
    assert_eq!(route1.dev(), Some("eth0"));

    let route2 = &config.routes()[1];
    assert_eq!(route2.prefix_len(), 0); // default route
}

#[test]
fn test_route_parsing_errors() {
    // Missing prefix
    let result = NetworkConfig::new().route("10.0.0.0", |r| r);
    assert!(result.is_err());

    // Invalid destination
    let result = NetworkConfig::new().route("invalid/8", |r| r);
    assert!(result.is_err());
}

#[test]
fn test_qdisc_builder() {
    let config = NetworkConfig::new()
        .qdisc("eth0", |q| {
            q.netem()
                .delay_ms(100)
                .loss_pct(nlink::Percent::new(1.0))
        })
        .qdisc("eth1", |q| q.htb().default_class(0x30));

    assert_eq!(config.qdiscs().len(), 2);
    assert_eq!(config.qdiscs()[0].dev(), "eth0");
    assert_eq!(config.qdiscs()[0].qdisc_type().kind(), "netem");
    assert_eq!(config.qdiscs()[1].qdisc_type().kind(), "htb");
}

#[test]
fn test_veth_link_builder() {
    let config = NetworkConfig::new().link("veth0", |l| l.veth("veth1").master("br0").up());

    let link = &config.links()[0];
    assert_eq!(link.name(), "veth0");
    assert!(matches!(
        link.link_type(),
        DeclaredLinkType::Veth { peer, .. } if peer == "veth1"
    ));
    assert_eq!(link.master(), Some("br0"));
    assert_eq!(link.state(), LinkState::Up);
}

#[test]
fn test_vlan_link_builder() {
    let config = NetworkConfig::new().link("eth0.100", |l| l.vlan("eth0", 100).up());

    let link = &config.links()[0];
    assert!(matches!(
        link.link_type(),
        DeclaredLinkType::Vlan { parent, vlan_id, .. } if parent == "eth0" && *vlan_id == 100
    ));
}

// ============================================================================
// Integration Tests (require namespace)
// ============================================================================

#[tokio::test]
async fn test_config_diff_empty_namespace() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-diff")?;
    let conn = ns.connection()?;

    // Empty config against empty namespace should have no changes
    let config = NetworkConfig::new();
    let diff = config.diff(&conn).await?;

    assert!(diff.is_empty());
    assert_eq!(diff.change_count(), 0);
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_missing_link() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-diff-link")?;
    let conn = ns.connection()?;

    // Config wants a dummy interface that doesn't exist
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let diff = config.diff(&conn).await?;

    assert!(!diff.is_empty());
    assert_eq!(diff.links_to_add.len(), 1);
    assert_eq!(diff.links_to_add[0].name(), "dummy0");
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_existing_link() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-diff-existing")?;
    let conn = ns.connection()?;

    // Create the interface first
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Config wants the same interface
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy());

    let diff = config.diff(&conn).await?;

    // Interface already exists, no creation needed
    assert!(diff.links_to_add.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_config_diff_detects_state_change() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-diff-state")?;
    let conn = ns.connection()?;

    // Create interface in down state
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Config wants it up
    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let diff = config.diff(&conn).await?;

    // Should detect need to bring interface up
    assert_eq!(diff.links_to_modify.len(), 1);
    assert_eq!(diff.links_to_modify[0].0, "dummy0");
    assert!(diff.links_to_modify[0].1.set_up);
    Ok(())
}

#[tokio::test]
async fn test_config_apply_creates_link() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-apply-link")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new().link("dummy0", |l| l.dummy().up());

    let result = config.apply(&conn).await?;

    assert!(result.is_success());
    assert!(result.changes_made > 0);

    // Verify the interface was created
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_some());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_creates_address() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-apply-addr")?;
    let conn = ns.connection()?;

    // Create interface first
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let config = NetworkConfig::new()
        .address("dummy0", "192.168.100.1/24")
        .unwrap();

    let result = config.apply(&conn).await?;

    assert!(result.is_success());

    // Verify address was added
    let addrs = conn.get_addresses_by_name("dummy0").await?;
    assert!(!addrs.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_idempotent() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-idempotent")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .address("dummy0", "10.0.0.1/24")
        .unwrap();

    // First apply
    let result1 = config.apply(&conn).await?;
    assert!(result1.changes_made > 0);

    // Second apply should be a no-op
    let result2 = config.apply(&conn).await?;
    assert_eq!(result2.changes_made, 0);
    Ok(())
}

#[tokio::test]
async fn test_config_dry_run() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-dryrun")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new().link("dummy0", |l| l.dummy());

    let result = config
        .apply_with_options(
            &conn,
            // Plan 188 §2.2 — ApplyOptions is `#[non_exhaustive]`;
            // builder methods replace struct-literal construction.
            ApplyOptions::default().with_dry_run(true),
        )
        .await?;

    // Should report changes but not apply them
    assert!(result.changes_made > 0);

    // Interface should NOT exist
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_none());
    Ok(())
}

#[tokio::test]
async fn test_config_apply_bridge_with_port() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-bridge")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("br0", |l| l.bridge().up())
        .link("dummy0", |l| l.dummy().master("br0").up());

    let result = config.apply(&conn).await?;
    assert!(result.is_success());

    // Verify bridge was created
    let br = conn.get_link_by_name("br0").await?;
    assert!(br.is_some());

    // Verify dummy was created and attached to bridge
    let dummy = conn.get_link_by_name("dummy0").await?;
    assert!(dummy.is_some());
    assert!(dummy.unwrap().master().is_some());
    Ok(())
}

#[tokio::test]
async fn test_config_diff_summary() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-summary")?;
    let conn = ns.connection()?;

    let config = NetworkConfig::new()
        .link("dummy0", |l| l.dummy().up())
        .address("dummy0", "10.0.0.1/24")
        .unwrap();

    let diff = config.diff(&conn).await?;
    // Plan 188 §2.6 — `summary()` deprecated in favor of Display.
    let summary = diff.to_string();

    assert!(summary.contains("dummy0"));
    assert!(summary.contains("10.0.0.1/24"));
    Ok(())
}

#[tokio::test]
async fn test_config_apply_qdisc() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("config-qdisc")?;
    let conn = ns.connection()?;

    // Create interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let config = NetworkConfig::new().qdisc("dummy0", |q| q.netem().delay_ms(50));

    let result = config.apply(&conn).await?;
    assert!(result.is_success());

    // Verify qdisc was added, with the delay that was declared.
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs
        .iter()
        .find(|q| q.kind() == Some("netem"))
        .expect("netem qdisc installed");
    let Some(QdiscOptions::Netem(opts)) = netem.options() else {
        panic!("netem options parse");
    };
    assert_eq!(opts.delay(), Some(Duration::from_millis(50)));
    Ok(())
}

/// #332 — the declarative netem can now say `rate` and sub-millisecond
/// delay/jitter, and what the kernel installs is what was declared:
/// the readback goes through the parsed `QdiscOptions::Netem`, not a
/// kind check.
#[tokio::test]
async fn declarative_netem_rate_and_sub_ms_jitter_reach_the_kernel() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    let ns = TestNamespace::new("config-netem-rate")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let config = NetworkConfig::new().qdisc("dummy0", |q| {
        q.netem()
            .delay(Duration::from_micros(1_500))
            .jitter(Duration::from_micros(250))
            .rate(Rate::mbit(100))
            .reorder_pct(Percent::new(3.0))
            .reorder_correlation_pct(Percent::new(50.0))
            .gap(5)
    });
    let result = config.apply(&conn).await?;
    assert!(result.is_success(), "{result:?}");

    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs
        .iter()
        .find(|q| q.kind() == Some("netem"))
        .expect("netem qdisc installed");
    let Some(QdiscOptions::Netem(opts)) = netem.options() else {
        panic!("netem options parse");
    };
    assert_eq!(opts.delay(), Some(Duration::from_micros(1_500)));
    assert_eq!(opts.jitter(), Some(Duration::from_micros(250)));
    assert_eq!(
        opts.rate_bps(),
        Some(Rate::mbit(100).as_bytes_per_sec()),
        "netem rate is bytes/sec"
    );
    assert_eq!(opts.gap(), Some(5));
    assert_eq!(
        opts.reorder().map(|p| Percent::new(p).as_kernel_probability()),
        Some(Percent::new(3.0).as_kernel_probability())
    );
    assert_eq!(
        opts.reorder_correlation().map(|p| Percent::new(p).as_kernel_probability()),
        Some(Percent::new(50.0).as_kernel_probability())
    );
    Ok(())
}

/// #366 — an IPv6 route diffed as missing on every reconcile.
///
/// A route added without an explicit metric does not come back as 0 for
/// both families: IPv4 leaves it 0, IPv6 substitutes `IP6_RT_PRIO_USER`
/// (1024). The diff compared a declared `None` against 0, so it never
/// matched its own IPv6 routes and put every one of them in
/// `routes_to_add`, forever.
///
/// It hid the same way #362 did: `apply` does not go through
/// `diff_routes`, so it reported no changes at the same moment
/// `diff()` reported one. A downstream `apply --check` gate on any
/// IPv6 topology could never go green.
///
/// The v4 leg is here to pin that the fix did not loosen the common
/// case into "any metric matches".
#[tokio::test]
async fn ipv6_routes_without_a_metric_diff_clean_after_apply() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("config-v6-metric")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // `NetworkConfig` is not `Clone`, so build each one from scratch.
    let addressed = || -> Result<NetworkConfig> {
        Ok(NetworkConfig::new()
            .address("dummy0", "fd00::1/64")?
            .address("dummy0", "10.9.0.1/24")?)
    };
    let cfg = addressed()?
        .route("::/0", |r| r.via("fd00::2"))?
        .route("0.0.0.0/0", |r| r.via("10.9.0.2"))?;

    let applied = cfg.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");

    let again = cfg.diff(&conn).await?;
    assert!(
        again.is_empty(),
        "a route declared with no metric must match the one the kernel \
         installed — IPv6 stamps 1024 on it, not 0. Second diff:\n{again}"
    );

    // And an apply of that empty diff is genuinely zero ops.
    let second = cfg.apply(&conn).await?;
    assert_eq!(second.changes_made, 0, "{second:?}");

    // A metric that really does differ is still drift, both families.
    let moved = addressed()?
        .route("::/0", |r| r.via("fd00::2").metric(700))?
        .route("0.0.0.0/0", |r| r.via("10.9.0.2").metric(700))?;
    let drift = moved.diff(&conn).await?;
    assert_eq!(
        drift.routes_to_add.len(),
        2,
        "an explicitly different metric is a change, not a match:\n{drift}"
    );
    Ok(())
}

/// #361 — the fq_codel / sfq / prio / tbf knobs reach the kernel.
///
/// `DeclaredQdiscType` carried `FqCodel { limit, target_us,
/// interval_us }`, `Sfq { perturb_secs }` and `Prio { bands }` since
/// they were added, and the lowering and the diff honoured them — but
/// `QdiscBuilder` had no setter for any of them and `fq_codel()` /
/// `sfq()` / `prio()` hardcoded `None`, so through the builder those
/// kinds were "kernel defaults or nothing". TBF was missing `peakrate`
/// and `mtu` on the variant as well.
///
/// Read back through the parsed `QdiscOptions`, so this asserts what
/// the kernel stored rather than what we sent.
#[tokio::test]
async fn declarative_qdisc_knobs_reach_the_kernel() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_fq_codel", "sch_sfq", "sch_prio", "sch_tbf");

    let ns = TestNamespace::new("config-qdisc-knobs")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let live = |kind: &'static str| {
        let conn = &conn;
        async move {
            let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
            let q = qdiscs
                .iter()
                .find(|q| q.kind() == Some(kind))
                .unwrap_or_else(|| panic!("{kind} qdisc installed"))
                .clone();
            Ok::<_, nlink::Error>(q)
        }
    };

    // ---- fq_codel ----
    NetworkConfig::new()
        .qdisc("dummy0", |q| {
            q.fq_codel()
                .limit(nlink::Packets::new(1200))
                .target(Duration::from_millis(5))
                .interval(Duration::from_millis(100))
                .flows(1024)
                .quantum(300)
                .ecn(true)
        })
        .apply(&conn)
        .await
        .map(|r| assert!(r.is_success(), "{r:?}"))?;
    let Some(QdiscOptions::FqCodel(opts)) = live("fq_codel").await?.options() else {
        panic!("fq_codel options parse");
    };
    assert_eq!(opts.limit, 1200);
    assert_eq!(opts.flows, 1024);
    assert_eq!(opts.quantum, 300);
    assert!(opts.ecn, "ecn must be on");
    // codel times are psched ticks, so the echo is the round-trip of
    // what we sent rather than the exact microsecond count.
    assert!(
        (4_900..=5_100).contains(&opts.target_us),
        "target ~5ms, got {}us",
        opts.target_us
    );
    assert!(
        (99_000..=101_000).contains(&opts.interval_us),
        "interval ~100ms, got {}us",
        opts.interval_us
    );

    // ---- sfq ----
    NetworkConfig::new()
        .qdisc("dummy0", |q| {
            q.sfq()
                .perturb(Duration::from_secs(10))
                .limit(nlink::Packets::new(200))
                .quantum(1514)
        })
        .apply(&conn)
        .await
        .map(|r| assert!(r.is_success(), "{r:?}"))?;
    let Some(QdiscOptions::Sfq(opts)) = live("sfq").await?.options() else {
        panic!("sfq options parse");
    };
    assert_eq!(opts.perturb_period, 10);
    assert_eq!(opts.limit, 200);
    assert_eq!(opts.quantum, 1514);

    // ---- prio ----
    NetworkConfig::new()
        .qdisc("dummy0", |q| q.prio().bands(4))
        .apply(&conn)
        .await
        .map(|r| assert!(r.is_success(), "{r:?}"))?;
    let Some(QdiscOptions::Prio(opts)) = live("prio").await?.options() else {
        panic!("prio options parse");
    };
    assert_eq!(opts.bands, 4, "prio() could only ever install the default 3 before");

    // ---- tbf ----
    NetworkConfig::new()
        .qdisc("dummy0", |q| {
            q.tbf(Rate::mbit(1), nlink::Bytes::kib(32))
                .limit_bytes(nlink::Bytes::kib(64))
                .peakrate(Rate::mbit(2))
                .mtu(1600)
        })
        .apply(&conn)
        .await
        .map(|r| assert!(r.is_success(), "{r:?}"))?;
    let Some(QdiscOptions::Tbf(opts)) = live("tbf").await?.options() else {
        panic!("tbf options parse");
    };
    assert_eq!(opts.rate, Rate::mbit(1).as_bytes_per_sec());
    assert_eq!(opts.peakrate, Rate::mbit(2).as_bytes_per_sec(), "peakrate is bytes/sec");
    assert_eq!(opts.mtu, 1600, "mtu comes back through TCA_TBF_PBURST, in bytes");
    Ok(())
}

/// #346 — a second `apply` of an unchanged declaration is a no-op for
/// every kind the diff can compare field by field. The diff used to
/// byte-compare the declared `TCA_OPTIONS` against the kernel's echo,
/// which never matched for netem (the kernel adds `CORR`/`RATE`/`ECN`/
/// `LATENCY64`/`JITTER64` and reorders), so every reconcile replaced the
/// qdisc: `changes_made == 1` forever, statistics reset, traffic
/// disturbed. The maintainer's repro was netem with delay/jitter/rate/
/// reorder on a dummy; the other kinds are here so the property holds
/// for the whole declarative surface.
#[tokio::test]
async fn unchanged_declared_qdiscs_are_not_replaced_on_reapply() -> Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy",
        "sch_netem",
        "sch_tbf",
        "sch_htb",
        "sch_fq_codel",
        "sch_sfq",
        "sch_prio"
    );

    let ns = TestNamespace::new("config-qdisc-idem")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    let cases: Vec<(&str, NetworkConfig)> = vec![
        // #368: a declared Markov loss model must diff clean against the
        // kernel's echo, which arrives as u32 probabilities read back as
        // f64 — a float compare would replace it on every reconcile (#346).
        (
            "netem-gemodel",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.netem().delay(Duration::from_millis(20)).loss_model(
                    nlink::netlink::tc::NetemLossModel::gilbert_elliot(nlink::Percent::new(1.0))
                        .r(nlink::Percent::new(30.0))
                        .loss_in_bad(nlink::Percent::new(50.0))
                        .loss_in_good(nlink::Percent::new(0.1)),
                )
            }),
        ),
        (
            "netem-4state",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.netem().loss_model(
                    nlink::netlink::tc::NetemLossModel::gilbert_intuitive(nlink::Percent::new(1.0))
                        .p31(nlink::Percent::new(2.0))
                        .p32(nlink::Percent::new(3.0))
                        .p23(nlink::Percent::new(4.0))
                        .p14(nlink::Percent::new(5.0)),
                )
            }),
        ),
        (
            "netem",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.netem()
                    .delay(Duration::from_millis(20))
                    .jitter(Duration::from_millis(2))
                    .rate(nlink::Rate::mbit(100))
                    .loss_pct(nlink::Percent::new(0.5))
                    .reorder_pct(nlink::Percent::new(3.0))
                    .reorder_correlation_pct(nlink::Percent::new(50.0))
                    .gap(5)
            }),
        ),
        // #370: the same device, the "netem" case above replaced by one that
        // sets none of rate / reorder / gap / loss. A replace is
        // `netem_change()`, which keeps what it is not sent, so before the
        // writer sent explicit off states this never converged: diff
        // reported the stale rate, and every apply replaced the qdisc.
        (
            "netem-attributes-removed",
            NetworkConfig::new().qdisc("dummy0", |q| q.netem().delay(Duration::from_millis(20))),
        ),
        (
            "tbf",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.tbf(nlink::Rate::mbit(1), nlink::Bytes::kib(32))
                    .limit_bytes(nlink::Bytes::kib(64))
            }),
        ),
        (
            "tbf-peaked",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.tbf(nlink::Rate::mbit(1), nlink::Bytes::kib(32))
                    .limit_bytes(nlink::Bytes::kib(64))
                    .peakrate(nlink::Rate::mbit(2))
                    .mtu(1600)
            }),
        ),
        (
            "htb",
            NetworkConfig::new().qdisc("dummy0", |q| q.htb().default_class(0x10)),
        ),
        ("fq_codel", NetworkConfig::new().qdisc("dummy0", |q| q.fq_codel())),
        // #361: the same property, but with every knob actually set.
        // Before 0.28 these kinds had no setters at all, so the cases
        // above could only ever exercise kernel defaults — a diff that
        // mishandled a declared value had nothing to fail on.
        (
            "fq_codel-tuned",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.fq_codel()
                    .limit(nlink::Packets::new(1200))
                    .target(Duration::from_millis(5))
                    .interval(Duration::from_millis(100))
                    .flows(1024)
                    .quantum(300)
                    .ecn(true)
            }),
        ),
        ("sfq", NetworkConfig::new().qdisc("dummy0", |q| q.sfq())),
        (
            "sfq-tuned",
            NetworkConfig::new().qdisc("dummy0", |q| {
                q.sfq()
                    .perturb(Duration::from_secs(10))
                    .limit(nlink::Packets::new(200))
                    .quantum(1514)
            }),
        ),
        ("prio", NetworkConfig::new().qdisc("dummy0", |q| q.prio())),
        (
            "prio-bands",
            NetworkConfig::new().qdisc("dummy0", |q| q.prio().bands(4)),
        ),
    ];

    for (kind, config) in &cases {
        // Name the case in the failure: a bare `?` here reports only
        // "replace_qdisc: Invalid argument" with no clue which of the
        // eleven declarations the kernel rejected.
        let first = config
            .apply(&conn)
            .await
            .unwrap_or_else(|e| panic!("{kind}: first apply failed: {e}"));
        assert!(first.is_success(), "{kind}: first apply: {first:?}");
        assert_eq!(first.changes_made, 1, "{kind}: first apply installs (or replaces) the root qdisc");

        let diff = config
            .diff(&conn)
            .await
            .unwrap_or_else(|e| panic!("{kind}: diff failed: {e}"));
        assert!(diff.is_empty(), "{kind}: unchanged declaration diffs as:\n{diff}");

        let second = config
            .apply(&conn)
            .await
            .unwrap_or_else(|e| panic!("{kind}: second apply failed: {e}"));
        assert!(second.is_success(), "{kind}: second apply: {second:?}");
        assert_eq!(second.changes_made, 0, "{kind}: second apply must be a no-op: {second:?}");
    }
    Ok(())
}
