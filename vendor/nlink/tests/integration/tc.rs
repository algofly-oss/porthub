//! Traffic Control (TC) integration tests.
//!
//! Tests for qdisc, class, and filter management using network namespaces.

use std::time::Duration;

use nlink::{
    Connection, Result, Route, TcHandle,
    netlink::{
        filter::{FlowerFilter, MatchallFilter, U32Filter},
        link::{DummyLink, IfbLink},
        tc::{
            FqCodelConfig, HtbClassConfig, HtbQdiscConfig, IngressConfig, NetemConfig,
            NetemLossModel, PlugConfig, PrioConfig, SfqConfig, TbfConfig,
        },
        tc_options::QdiscOptions,
    },
};

use crate::common::TestNamespace;

/// Set up a namespace with a dummy interface.
async fn setup_tc_ns(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    Ok((ns, conn))
}

// ============================================================================
// Qdisc Tests
// ============================================================================

#[tokio::test]
async fn test_add_netem_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (_ns, conn) = setup_tc_ns("netem").await?;

    // Add netem qdisc with delay
    let netem = NetemConfig::new()
        .delay(Duration::from_millis(100))
        .jitter(Duration::from_millis(10))
        .build();

    conn.add_qdisc("dummy0", netem).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some(), "netem qdisc should exist");

    Ok(())
}

/// `PlugConfig::new().build()` — no limit — could not install a plug at
/// all: the request carried an empty `TCA_OPTIONS` nest, and `plug_init`
/// refuses one shorter than `tc_plug_qopt` with `EINVAL`. The form the
/// kernel wants for "use the device default" is *no* `TCA_OPTIONS`
/// (#327). This installs the plug as the leaf of a netem, the shape the
/// issue reproduced with, then sends traffic through it and checks the
/// property that distinguishes a working plug from a `limit(0)`
/// blackhole: packets are **held**, not dropped.
#[tokio::test]
async fn plug_without_limit_installs_and_buffers() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem", "sch_plug", "veth");

    let left = TestNamespace::new("plug_l")?;
    let right = TestNamespace::new("plug_r")?;
    left.connect_to(&right, "veth0", "veth1")?;
    left.add_addr("veth0", "10.27.0.1/24")?;
    left.link_up("veth0")?;
    right.add_addr("veth1", "10.27.0.2/24")?;
    right.link_up("veth1")?;

    let conn = left.connection()?;
    let ifindex = conn
        .get_link_by_name("veth0")
        .await?
        .expect("veth0 exists")
        .ifindex();

    conn.add_qdisc_by_index_full(
        ifindex,
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        NetemConfig::new().build(),
    )
    .await?;
    let parent = TcHandle::new(1, 1);

    // The form that returned EINVAL.
    conn.add_qdisc_by_index_full(ifindex, parent, None, PlugConfig::new().build())
        .await
        .expect("PlugConfig::new().build() must install (no TCA_OPTIONS → kernel default limit)");

    // Ping into the plug: nothing comes back (that is the point of a
    // plug), so let ping time out and look at the qdisc instead.
    left.exec_ignore("ping", &["-c", "3", "-i", "0.2", "-W", "1", "10.27.0.2"]);

    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let plug = qdiscs
        .iter()
        .find(|q| q.kind() == Some("plug"))
        .expect("plug qdisc is installed");
    let stats = plug.stats_queue().expect("plug reports queue stats");
    assert!(
        stats.backlog > 0 && stats.qlen > 0,
        "a plug with the kernel-default limit must hold packets; \
         backlog {}b {}p — a zero limit would show 0b 0p and drops instead",
        stats.backlog,
        stats.qlen
    );
    assert_eq!(
        stats.drops, 0,
        "a plug with the kernel-default limit dropped {} packets — that is \
         the `limit 0` blackhole, not the default",
        stats.drops
    );

    // An explicit limit keeps working: replace with one and the qdisc
    // still stands.
    conn.replace_qdisc_by_index_full(
        ifindex,
        parent,
        None,
        PlugConfig::new().limit(nlink::Bytes::new(65536)).build(),
    )
    .await?;
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    assert!(qdiscs.iter().any(|q| q.kind() == Some("plug")));

    // Let the buffered packets out so the namespace tears down cleanly.
    conn.plug_release_indefinite(ifindex, parent).await.ok();
    Ok(())
}

#[tokio::test]
async fn test_netem_with_loss() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (_ns, conn) = setup_tc_ns("netemloss").await?;

    // Add netem with packet loss
    let netem = NetemConfig::new().loss(nlink::Percent::new(1.0)).build();

    conn.add_qdisc("dummy0", netem).await?;

    // Verify netem exists
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem"));
    assert!(netem.is_some());

    Ok(())
}

/// The Markov loss models go into the kernel and come back as written
/// (#368). The kernel echoes `TCA_NETEM_LOSS` only after `get_loss_clg`
/// accepted it, so a model read back is a model the kernel parsed — the
/// nested attribute, its `NLA_F_NESTED` flag and the struct layout all
/// included. A plain `loss` replace must then clear it.
#[tokio::test]
async fn netem_loss_models_round_trip_through_the_kernel() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");
    use nlink::Percent;

    let (_ns, conn) = setup_tc_ns("netem-lossmodel").await?;
    let models = [
        NetemLossModel::gilbert_elliot(Percent::new(1.0))
            .r(Percent::new(30.0))
            .loss_in_bad(Percent::new(50.0))
            .loss_in_good(Percent::new(0.1)),
        NetemLossModel::gilbert_intuitive(Percent::new(1.0))
            .p31(Percent::new(2.0))
            .p32(Percent::new(3.0))
            .p23(Percent::new(4.0))
            .p14(Percent::new(5.0)),
    ];
    for model in models {
        conn.replace_qdisc("dummy0", NetemConfig::new().loss_model(model).build())
            .await?;
        let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
        let netem = qdiscs
            .iter()
            .find(|q| q.kind() == Some("netem"))
            .expect("netem installed");
        let Some(QdiscOptions::Netem(opts)) = netem.options() else {
            panic!("netem options did not parse");
        };
        let echoed = opts
            .loss_model()
            .unwrap_or_else(|| panic!("the kernel echoed no loss model for {model:?}"));
        assert_eq!(
            format!("{echoed:.3?}"),
            format!("{model:.3?}"),
            "kernel stored a different model"
        );
        assert_eq!(opts.loss(), Some(0.0), "a model must not also set random loss");
    }

    conn.replace_qdisc("dummy0", NetemConfig::new().loss(Percent::new(2.0)).build())
        .await?;
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
    let Some(QdiscOptions::Netem(opts)) = netem.options() else {
        panic!("netem options did not parse");
    };
    assert!(opts.loss_model().is_none(), "random loss must replace the model");
    Ok(())
}

/// A configured model must actually *drop* — the property nlink-lab#153
/// asks to pin, because `loss <p>% <corr>%` went quiet for a year without
/// anything noticing (#369). Deterministic models, so the counts are
/// exact: Gilbert-Elliot that never enters the bad state drops nothing;
/// one that loses everything in the good state drops every packet, and so
/// does a 4-state model with p13 = 100% (it never leaves "burst losses").
#[tokio::test]
async fn netem_loss_models_drop_what_they_describe() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem", "dummy");
    use nlink::Percent;

    let cases = [
        ("ge-never-bad", NetemLossModel::gilbert_elliot(Percent::ZERO), false),
        (
            "ge-lose-in-good",
            NetemLossModel::gilbert_elliot(Percent::ZERO).loss_in_good(Percent::HUNDRED),
            true,
        ),
        ("gi-always-burst", NetemLossModel::gilbert_intuitive(Percent::HUNDRED), true),
    ];
    for (name, model, drops_all) in cases {
        let ns = crate::common::TestNamespace::new(&format!("netem-drop-{name}"))?;
        let conn = ns.connection()?;
        conn.add_link(DummyLink::new("dummy0")).await?;
        conn.set_link_up("dummy0").await?;
        ns.add_addr("dummy0", "10.31.0.1/24")?;
        conn.add_qdisc("dummy0", NetemConfig::new().loss_model(model).build())
            .await?;

        // dummy is NOARP: every ping goes straight through the qdisc.
        ns.exec_ignore("ping", &["-c", "5", "-i", "0.2", "-W", "1", "10.31.0.2"]);

        let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
        let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
        let stats = netem.stats_queue().expect("netem reports queue stats");
        if drops_all {
            assert!(stats.drops >= 5, "{name}: dropped {} of 5 pings", stats.drops);
        } else {
            assert_eq!(stats.drops, 0, "{name}: must drop nothing, dropped {}", stats.drops);
        }
    }
    Ok(())
}

/// #370: replacing a netem with one that sets fewer attributes must clear
/// the rest. A replace is `netem_change()`, which keeps whatever it is not
/// sent; `rate`, `reorder` and `corrupt` used to survive this.
#[tokio::test]
async fn netem_replace_clears_what_the_new_config_does_not_set() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");
    use nlink::Percent;

    let (_ns, conn) = setup_tc_ns("netem-replace-clears").await?;
    conn.add_qdisc(
        "dummy0",
        NetemConfig::new()
            .delay(Duration::from_millis(20))
            .jitter(Duration::from_millis(2))
            .delay_correlation(Percent::new(30.0))
            .rate(nlink::Rate::mbit(100))
            .loss(Percent::new(1.0))
            .loss_correlation(Percent::new(25.0))
            .duplicate(Percent::new(2.0))
            .duplicate_correlation(Percent::new(10.0))
            .corrupt(Percent::new(1.0))
            .corrupt_correlation(Percent::new(5.0))
            .reorder(Percent::new(3.0))
            .reorder_correlation(Percent::new(50.0))
            .gap(5)
            .build(),
    )
    .await?;
    let bare = NetemConfig::new().delay(Duration::from_millis(20)).build();
    conn.replace_qdisc("dummy0", bare).await?;

    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();
    let Some(QdiscOptions::Netem(o)) = netem.options() else {
        panic!("netem options did not parse");
    };
    let left: Vec<String> = [
        ("rate", o.rate_bps().unwrap_or(0) as f64),
        ("reorder", o.reorder().unwrap_or(0.0)),
        ("reorder correlation", o.reorder_correlation().unwrap_or(0.0)),
        ("corrupt", o.corrupt().unwrap_or(0.0)),
        ("corrupt correlation", o.corrupt_correlation().unwrap_or(0.0)),
        ("delay correlation", o.delay_correlation().unwrap_or(0.0)),
        ("loss correlation", o.loss_correlation().unwrap_or(0.0)),
        ("duplicate correlation", o.duplicate_correlation().unwrap_or(0.0)),
        ("loss", o.loss().unwrap_or(0.0)),
        ("duplicate", o.duplicate().unwrap_or(0.0)),
    ]
    .into_iter()
    .filter(|(_, v)| *v != 0.0)
    .map(|(k, v)| format!("{k}={v}"))
    .collect();
    assert!(left.is_empty(), "survived the replace: {left:?}");
    assert_eq!(o.jitter(), None);
    Ok(())
}

/// The live netem on `dummy0`, parsed.
async fn dummy0_netem(
    conn: &Connection<Route>,
) -> Result<nlink::netlink::tc_options::NetemOptions> {
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs
        .iter()
        .find(|q| q.kind() == Some("netem"))
        .expect("a netem");
    match netem.options() {
        Some(QdiscOptions::Netem(o)) => Ok(o),
        other => panic!("netem options did not parse: {other:?}"),
    }
}

/// #493: `NetemConfig` does not model ECN or a slot, so `write_options`
/// never sent them, and a replace — `netem_change()`, which keeps what it
/// is not sent — left ones set by `tc` in place, where `tc qdisc show`
/// still listed them. A rate past `u32::MAX` B/s read back as the capped
/// `TCA_NETEM_RATE` the kernel dumps after `RATE64`.
#[tokio::test]
async fn netem_replace_clears_an_external_slot_and_ecn() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (ns, conn) = setup_tc_ns("netem-slot-ecn").await?;
    ns.exec(
        "tc",
        &[
            "qdisc", "add", "dev", "dummy0", "root", "netem", "delay", "10ms", "slot", "1ms",
            "2ms", "ecn", "loss", "1%",
        ],
    )?;
    let before = dummy0_netem(&conn).await?;
    assert!(before.ecn(), "nlink reads the ECN tc set");
    assert!(before.slot().is_some(), "nlink reads the slot tc set");

    let fast = nlink::Rate::bytes_per_sec(5_000_000_000);
    let cfg = NetemConfig::new()
        .delay(Duration::from_millis(20))
        .rate(fast)
        .build();
    conn.replace_qdisc("dummy0", cfg).await?;

    let after = dummy0_netem(&conn).await?;
    assert!(!after.ecn(), "ECN survived the replace");
    assert!(
        after.slot().is_none(),
        "the slot survived the replace: {:?}",
        after.slot()
    );
    assert_eq!(
        after.rate_bps(),
        Some(5_000_000_000),
        "RATE64, not the capped RATE"
    );
    assert_eq!(after.delay(), Some(Duration::from_millis(20)));
    let shown = ns.exec("tc", &["qdisc", "show", "dev", "dummy0"])?;
    assert!(
        !shown.contains("slot") && !shown.contains("ecn"),
        "tc still shows them: {shown}"
    );
    Ok(())
}

/// `tc -d qdisc show dev <dev> root` with the handle and a netem seed cut
/// out, so two devices given the same qdisc print the same line. A seed is
/// random unless set, and only iproute2 6.3+ prints one.
fn root_qdisc_line(ns: &TestNamespace, dev: &str) -> Result<String> {
    let shown = ns.exec("tc", &["-d", "qdisc", "show", "dev", dev, "root"])?;
    let line = shown
        .lines()
        .find(|l| l.starts_with("qdisc "))
        .unwrap_or_else(|| panic!("no root qdisc on {dev}: {shown}"));
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match words[i] {
            "seed" => i += 2,
            _ if i == 2 => i += 1,
            w => {
                out.push(w);
                i += 1;
            }
        }
    }
    Ok(out.join(" "))
}

/// A netem options dump without `TCA_NETEM_PRNG_SEED` (and the pad that
/// can precede it): the fixed `tc_netem_qopt`, then the attributes.
fn without_netem_seed(blob: &[u8]) -> Vec<u8> {
    const TCA_NETEM_PAD: u16 = 9;
    const TCA_NETEM_PRNG_SEED: u16 = 14;
    let mut out = blob[..24].to_vec();
    let mut rest = &blob[24..];
    while rest.len() >= 4 {
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        let ty = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff;
        let end = len.next_multiple_of(4).min(rest.len());
        if ty != TCA_NETEM_PAD && ty != TCA_NETEM_PRNG_SEED {
            out.extend_from_slice(&rest[..end]);
        }
        rest = &rest[end..];
    }
    out
}

/// #633: nlink truncated a percentage where tc rounds, so the same netem
/// put a value one unit lower in the kernel. Each set of tokens goes
/// through `tc` on one dummy and through `NetemConfig::parse_params` on
/// another, and the kernel's dumps of the two must be the same bytes, the
/// seed aside: it is random unless set, and iproute2 6.1, the CI image's,
/// cannot set one.
#[tokio::test]
async fn netem_percentages_land_where_tc_puts_them() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (ns, conn) = setup_tc_ns("netem-pct").await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    for pct in ["1%", "1.2%", "0.3%", "33.333333%", "50%", "99.99%"] {
        let tokens = [
            "delay",
            "1ms",
            "1ms",
            pct,
            "loss",
            pct,
            pct,
            "duplicate",
            pct,
            pct,
            "corrupt",
            pct,
            pct,
            "reorder",
            pct,
            pct,
        ];
        let mut args = vec!["qdisc", "replace", "dev", "dummy1", "root", "netem"];
        args.extend(tokens);
        ns.exec("tc", &args)?;
        conn.replace_qdisc("dummy0", NetemConfig::parse_params(&tokens)?)
            .await?;
        let raw = |dev: &'static str| {
            let conn = &conn;
            async move {
                let q = conn.get_root_qdisc_by_name(dev).await?.expect("a root");
                Result::Ok(without_netem_seed(q.raw_options().expect("options")))
            }
        };
        assert_eq!(raw("dummy0").await?, raw("dummy1").await?, "{pct}");
    }
    Ok(())
}

/// #515: the slot, ECN, the PRNG seed, the rate overheads and a delay
/// distribution, which `parse_params` refused and `NetemConfig` could not
/// carry. The same tokens go through `tc` on one device and through
/// `NetemConfig::parse_params` on another, and the kernel shows the same
/// netem on both; the table is not dumped, so it is checked by the kernel
/// accepting it. A replace without them then clears what it should and
/// keeps the seed, which the kernel holds across a change.
#[tokio::test]
async fn netem_slot_ecn_seed_overhead_and_distribution_match_tc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (ns, conn) = setup_tc_ns("netem-515").await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    conn.set_link_up("dummy1").await?;
    let tokens = [
        "delay",
        "10ms",
        "2ms",
        "distribution",
        "normal",
        "loss",
        "1%",
        "rate",
        "1mbit",
        "20",
        "53",
        "5",
        "slot",
        "1ms",
        "2ms",
        "packets",
        "5",
        "bytes",
        "3000",
        "ecn",
        "limit",
        "500",
    ];
    let mut args = vec!["qdisc", "add", "dev", "dummy1", "root", "netem"];
    args.extend(tokens);
    ns.exec("tc", &args)?;
    // The seed through nlink only: iproute2 learnt `seed` in 6.3, after
    // the CI image's 6.1. `root_qdisc_line` drops the one tc prints, which is
    // random where none was set.
    let mut seeded = tokens.to_vec();
    seeded.extend(["seed", "42"]);
    conn.add_qdisc("dummy0", NetemConfig::parse_params(&seeded)?)
        .await?;

    let ours = root_qdisc_line(&ns, "dummy0")?;
    assert_eq!(
        ours,
        root_qdisc_line(&ns, "dummy1")?,
        "nlink and tc installed different netems"
    );
    for word in [
        "ecn",
        "slot 1ms 2ms packets 5 bytes 3000",
        "packetoverhead 20",
    ] {
        assert!(ours.contains(word), "`{word}` missing: {ours}");
    }

    let opts = dummy0_netem(&conn).await?;
    assert_eq!(opts.seed(), Some(42));
    assert!(opts.ecn());
    assert_eq!(
        (
            opts.packet_overhead(),
            opts.cell_size(),
            opts.cell_overhead()
        ),
        (20, 53, 5)
    );
    let slot = opts.slot().expect("the slot");
    assert_eq!(
        (slot.min_delay_ns, slot.max_delay_ns),
        (1_000_000, 2_000_000)
    );
    assert_eq!((slot.max_packets, slot.max_bytes), (5, 3000));

    conn.replace_qdisc(
        "dummy0",
        NetemConfig::new().delay(Duration::from_millis(10)),
    )
    .await?;
    let opts = dummy0_netem(&conn).await?;
    assert!(!opts.ecn(), "ECN survived the replace");
    assert!(
        opts.slot().is_none(),
        "the slot survived: {:?}",
        opts.slot()
    );
    assert_eq!(
        (
            opts.packet_overhead(),
            opts.cell_size(),
            opts.cell_overhead()
        ),
        (0, 0, 0)
    );
    assert_eq!(
        opts.seed(),
        Some(42),
        "the kernel keeps a seed a change does not send"
    );
    Ok(())
}

/// #515: a seeded netem drops the same packets of the same traffic. Five
/// batches of 40 datagrams through a 50 % loss on `lo`, counted as they
/// arrive: the same seed twice gives the same five counts, another seed
/// gives others (two random seeds would match by chance about once in
/// 10^5). A fresh namespace's `lo` carries nothing but the test's
/// datagrams — no neighbour discovery, no MLD — and the receiver is bound,
/// so no ICMP draws from netem's generator either.
#[tokio::test]
async fn netem_seed_reproduces_the_same_losses() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let ns = TestNamespace::new("netem-seed")?;
    let conn = ns.connection()?;
    crate::common::traffic::lo_up(&ns).await?;
    let lo = conn.get_link_by_name("lo").await?.expect("lo").ifindex();

    let mut runs = Vec::new();
    for seed in [7, 7, 8] {
        let cfg = NetemConfig::new()
            .loss(nlink::Percent::new(50.0))
            .seed(seed);
        conn.add_qdisc_by_index(lo, cfg).await?;
        let arrived = crate::common::traffic::in_ns(&ns, || {
            let rx = std::net::UdpSocket::bind("127.0.0.1:9999").expect("bind rx");
            rx.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let tx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind tx");
            let mut buf = [0u8; 16];
            let mut arrived = Vec::new();
            for _ in 0..5 {
                for _ in 0..40 {
                    tx.send_to(b"nlink", "127.0.0.1:9999").expect("send");
                }
                let mut n = 0;
                while rx.recv(&mut buf).is_ok() {
                    n += 1;
                }
                arrived.push(n);
            }
            arrived
        });
        conn.del_qdisc_by_index(lo, TcHandle::ROOT).await?;
        runs.push(arrived);
    }
    let total: u32 = runs[0].iter().sum();
    assert!(
        (50..150).contains(&total),
        "50 % loss of 200 delivered {total}: {:?}",
        runs[0]
    );
    assert_eq!(runs[1], runs[0], "the same seed dropped different packets");
    assert_ne!(runs[2], runs[0], "another seed dropped the same packets");
    Ok(())
}

#[tokio::test]
async fn test_del_netem() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_netem");

    let (_ns, conn) = setup_tc_ns("netemrm").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(50)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Remove it
    conn.del_netem("dummy0").await?;

    // Verify it's gone (default qdisc should be back)
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(
        !qdiscs.iter().any(|q| q.kind() == Some("netem")),
        "netem should be removed"
    );

    Ok(())
}

#[tokio::test]
async fn test_add_htb_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htb").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let htb = qdiscs.iter().find(|q| q.kind() == Some("htb"));
    assert!(htb.is_some(), "htb qdisc should exist");
    assert!(htb.unwrap().is_root());

    Ok(())
}

#[tokio::test]
async fn test_add_tbf_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_tbf");

    let (_ns, conn) = setup_tc_ns("tbf").await?;

    // Add TBF qdisc (token bucket filter)
    let tbf = TbfConfig::new()
        .rate(nlink::Rate::bytes_per_sec(1_000_000)) // 8 Mbps
        .burst(nlink::Bytes::new(10000))
        .limit(nlink::Bytes::new(100000))
        .build();
    conn.add_qdisc("dummy0", tbf).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let tbf = qdiscs.iter().find(|q| q.kind() == Some("tbf"));
    assert!(tbf.is_some(), "tbf qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_fq_codel_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_fq_codel");

    let (_ns, conn) = setup_tc_ns("fqcodel").await?;

    // Add fq_codel qdisc
    let fqcodel = FqCodelConfig::new()
        .target(Duration::from_micros(5000)) // 5ms
        .interval(Duration::from_micros(100000)) // 100ms
        .limit(nlink::Packets::new(10240))
        .build();
    conn.add_qdisc("dummy0", fqcodel).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let fq = qdiscs.iter().find(|q| q.kind() == Some("fq_codel"));
    assert!(fq.is_some(), "fq_codel qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_prio_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_prio");

    let (_ns, conn) = setup_tc_ns("prio").await?;

    // Add prio qdisc
    let prio = PrioConfig::new().bands(3).build();
    conn.add_qdisc_full(
        "dummy0",
        TcHandle::ROOT,
        Some(TcHandle::major_only(1)),
        prio,
    )
    .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let prio = qdiscs.iter().find(|q| q.kind() == Some("prio"));
    assert!(prio.is_some(), "prio qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_sfq_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_sfq");

    let (_ns, conn) = setup_tc_ns("sfq").await?;

    // Add SFQ qdisc
    let sfq = SfqConfig::new().perturb(10).quantum(1500).build();
    conn.add_qdisc("dummy0", sfq).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let sfq = qdiscs.iter().find(|q| q.kind() == Some("sfq"));
    assert!(sfq.is_some(), "sfq qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_ingress_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_ingress");

    let (_ns, conn) = setup_tc_ns("ingress").await?;

    // Add ingress qdisc. The ingress qdisc is not a root qdisc — it must
    // attach to the special ingress parent (TC_H_INGRESS, ffff:fff1).
    // Adding it at the root parent makes the kernel return EOPNOTSUPP.
    conn.add_qdisc_full("dummy0", TcHandle::INGRESS, None, IngressConfig::new())
        .await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let ingress = qdiscs.iter().find(|q| q.kind() == Some("ingress"));
    assert!(ingress.is_some(), "ingress qdisc should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("qdiscdel").await?;

    // Add netem
    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Delete it
    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;

    // Verify
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(!qdiscs.iter().any(|q| q.kind() == Some("netem")));

    Ok(())
}

#[tokio::test]
async fn test_replace_qdisc() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "sch_netem");

    let (_ns, conn) = setup_tc_ns("qdiscrep").await?;

    // Add netem with 100ms delay
    let netem1 = NetemConfig::new().delay(Duration::from_millis(100)).build();
    conn.add_qdisc("dummy0", netem1).await?;

    // Replace with 50ms delay
    let netem2 = NetemConfig::new().delay(Duration::from_millis(50)).build();
    conn.replace_qdisc("dummy0", netem2).await?;

    // Verify there's still just one netem
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem_count = qdiscs.iter().filter(|q| q.kind() == Some("netem")).count();
    assert_eq!(netem_count, 1);

    Ok(())
}

/// `replace_qdisc` looks at the slot (#486). Each of these was EINVAL:
/// fq_codel carrying `flows` into a change, sfq (no change operation), a
/// different kind at the live qdisc's own handle. And `add_qdisc` over a
/// live qdisc of its kind is EEXIST, where it used to change it quietly.
#[tokio::test]
async fn replace_qdisc_handles_whatever_is_in_the_slot() -> Result<()> {
    use nlink::netlink::tc::{HtbQdiscConfig, PrioConfig, SfqConfig, TbfConfig};
    use nlink::{Bytes, Rate, TcMessage};
    require_root!();
    nlink::require_modules!("sch_fq_codel", "sch_sfq", "sch_htb", "sch_prio", "sch_tbf");

    let (_ns, conn) = setup_tc_ns("qdiscslot").await?;
    let ifindex = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0")
        .ifindex();

    // fq_codel with flows, replaced twice: the second is a change, which
    // must not carry `flows`.
    let fq = |limit| FqCodelConfig::new().flows(1024).limit(nlink::Packets::new(limit));
    conn.replace_qdisc_by_index(ifindex, fq(1000)).await?;
    conn.replace_qdisc_by_index(ifindex, fq(2000)).await?;
    let opts = |q: Option<TcMessage>| match q.and_then(|q| q.options()) {
        Some(nlink::netlink::tc_options::QdiscOptions::FqCodel(o)) => Some((o.limit, o.flows)),
        _ => None,
    };
    let live = conn.get_qdiscs_by_index(ifindex).await?;
    let fq_live = live.into_iter().find(|q| q.parent() == TcHandle::ROOT);
    assert_eq!(opts(fq_live), Some((2000, 1024)));

    // A different `flows` needs a new qdisc.
    conn.replace_qdisc_by_index(ifindex, FqCodelConfig::new().flows(2048))
        .await?;
    let live = conn.get_qdiscs_by_index(ifindex).await?;
    let fq_live = live.into_iter().find(|q| q.parent() == TcHandle::ROOT);
    assert_eq!(opts(fq_live).map(|(_, flows)| flows), Some(2048));

    // sfq has no change operation.
    conn.replace_qdisc_by_index(ifindex, SfqConfig::new())
        .await?;
    conn.replace_qdisc_by_index(ifindex, SfqConfig::new().limit(nlink::Packets::new(100)))
        .await?;

    // htb at 1:, then prio at 1:.
    let one = Some(TcHandle::major_only(1));
    conn.replace_qdisc_by_index_full(ifindex, TcHandle::ROOT, one, HtbQdiscConfig::new())
        .await?;
    conn.replace_qdisc_by_index_full(ifindex, TcHandle::ROOT, one, PrioConfig::new())
        .await?;
    let live = conn.get_qdiscs_by_index(ifindex).await?;
    let prio = live
        .iter()
        .find(|q| q.parent() == TcHandle::ROOT)
        .expect("a root qdisc");
    assert_eq!(prio.kind(), Some("prio"));
    assert_eq!(prio.handle(), TcHandle::major_only(1));

    // An add over a live qdisc of the same kind, or at a handle in use, is
    // EEXIST. (Over a different kind with no handle the kernel grafts the
    // new one in its place, as `tc qdisc add` does.)
    let err = conn
        .add_qdisc_by_index(ifindex, PrioConfig::new())
        .await
        .unwrap_err();
    assert!(err.is_already_exists(), "{err}");
    let tbf = || {
        TbfConfig::new()
            .rate(Rate::mbit(1))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64))
            .build()
    };
    let err = conn
        .add_qdisc_by_index_full(ifindex, TcHandle::ROOT, one, tbf())
        .await
        .unwrap_err();
    assert!(err.is_already_exists(), "{err}");
    Ok(())
}

/// fq_codel and sfq report every flow with packets queued as a class of
/// their own. The same-kind recreate in `replace_qdisc` refuses to drop
/// classes, which is right for an HTB tree (below) but meant that a
/// `flows` change, or any sfq change (sfq can only be recreated), failed
/// whenever traffic was queued (#596).
#[tokio::test]
async fn replace_qdisc_recreates_flow_queues_under_load() -> Result<()> {
    use std::net::SocketAddr;

    use nlink::Rate;
    use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig, SfqConfig};
    use nlink::netlink::tc_options::QdiscOptions;

    use crate::common::{
        topo::NsPair,
        traffic::{ping, send_udp},
    };
    require_root!();
    nlink::require_modules!("sch_htb", "sch_fq_codel", "sch_sfq", "veth");

    let pair = NsPair::new("flowq", 66).await?;
    assert!(ping(&pair.a, pair.b_addr.into(), 1), "the pair must route");
    let conn = pair.a.connection()?;
    let one = TcHandle::major_only(1);
    let class = TcHandle::new(1, 1);
    let leaf = Some(TcHandle::major_only(0x10));
    conn.add_qdisc_full(
        pair.a_if,
        TcHandle::ROOT,
        Some(one),
        HtbQdiscConfig::new().default_class(1),
    )
    .await?;
    // 8 kbit drains about 20 small datagrams a second, so a burst of 250
    // stays queued for the rest of the test.
    conn.add_class(
        pair.a_if,
        one,
        class,
        HtbClassConfig::new(Rate::kbit(8)).build(),
    )
    .await?;

    let dst = SocketAddr::new(pair.b_addr.into(), 9);
    let queue_traffic = async || -> Result<usize> {
        assert_eq!(send_udp(&pair.a, &[dst], 250), 250);
        let flows = conn
            .get_classes_by_name(pair.a_if)
            .await?
            .iter()
            .filter(|c| c.handle().major() == 0x10)
            .count();
        assert!(flows > 0, "the leaf should hold a queued flow");
        Ok(flows)
    };
    let leaf_options = async || -> Result<Option<QdiscOptions>> {
        Ok(conn
            .get_qdiscs_by_name(pair.a_if)
            .await?
            .into_iter()
            .find(|q| q.parent() == class)
            .and_then(|q| q.options()))
    };

    conn.add_qdisc_full(pair.a_if, class, leaf, FqCodelConfig::new().flows(1024))
        .await?;
    queue_traffic().await?;
    conn.replace_qdisc_full(pair.a_if, class, leaf, FqCodelConfig::new().flows(2048))
        .await?;
    match leaf_options().await? {
        Some(QdiscOptions::FqCodel(o)) => assert_eq!(o.flows, 2048),
        other => panic!("expected the fq_codel leaf, got {other:?}"),
    }

    conn.replace_qdisc_full(pair.a_if, class, leaf, SfqConfig::new())
        .await?;
    queue_traffic().await?;
    conn.replace_qdisc_full(pair.a_if, class, leaf, SfqConfig::new().limit(nlink::Packets::new(100)))
        .await?;
    match leaf_options().await? {
        Some(QdiscOptions::Sfq(o)) => assert_eq!(o.limit, 100),
        other => panic!("expected the sfq leaf, got {other:?}"),
    }
    Ok(())
}

/// A same-kind replace of an HTB that has classes would delete them; it is
/// refused, and the classes stay (#486).
#[tokio::test]
async fn replace_qdisc_refuses_to_drop_an_htb_tree() -> Result<()> {
    use nlink::Rate;
    use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htbtree").await?;
    let one = Some(TcHandle::major_only(1));
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, one, HtbQdiscConfig::new())
        .await?;
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 1),
        HtbClassConfig::new(Rate::mbit(10)).build(),
    )
    .await?;

    let err = conn
        .replace_qdisc_full(
            "dummy0",
            TcHandle::ROOT,
            one,
            HtbQdiscConfig::new().default_class(0x10),
        )
        .await
        .unwrap_err();
    assert!(err.is_not_supported(), "{err}");
    assert!(err.to_string().contains("1 class(es)"), "{err}");
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(classes.iter().any(|c| c.handle() == TcHandle::new(1, 1)));
    Ok(())
}

/// A replace that turns a flag off turns it off. ECN, bytemode and the
/// dequeue-rate estimator were written only when on, and the kernel keeps
/// what a change does not carry, so once on they stayed on (#488).
#[tokio::test]
async fn a_replace_turns_pie_flags_off() -> Result<()> {
    use nlink::netlink::tc::{FqPieConfig, PieConfig};
    require_root!();
    nlink::require_modules!("sch_pie", "sch_fq_pie");

    let (ns, conn) = setup_tc_ns("pieflags").await?;
    let flags = |ns: &TestNamespace| -> Result<serde_json::Value> {
        let out = ns.exec("tc", &["-j", "qdisc", "show", "dev", "dummy0", "root"])?;
        let qdiscs: serde_json::Value = serde_json::from_str(&out).unwrap();
        Ok(qdiscs[0]["options"].clone())
    };

    conn.add_qdisc("dummy0", PieConfig::new().ecn(true).bytemode(true))
        .await?;
    conn.replace_qdisc("dummy0", PieConfig::new()).await?;
    let pie = flags(&ns)?;
    assert_ne!(pie["ecn"], true, "pie ECN stayed on: {pie}");
    assert_ne!(pie["bytemode"], true, "pie bytemode stayed on: {pie}");

    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;
    conn.add_qdisc(
        "dummy0",
        FqPieConfig::new()
            .ecn(true)
            .bytemode(true)
            .dq_rate_estimator(true),
    )
    .await?;
    conn.replace_qdisc("dummy0", FqPieConfig::new()).await?;
    let fq_pie = flags(&ns)?;
    assert_ne!(fq_pie["ecn"], true, "fq_pie ECN stayed on: {fq_pie}");
    assert_ne!(
        fq_pie["bytemode"], true,
        "fq_pie bytemode stayed on: {fq_pie}"
    );
    assert_ne!(
        fq_pie["dq_rate_estimator"], true,
        "fq_pie estimator stayed on: {fq_pie}"
    );
    Ok(())
}

/// #631: `ecn_prob` is a whole percentage. nlink wrote it per-mille and read
/// it back the same way, so its own round trip agreed with itself: through
/// `nlink-tc`, `ecn_prob 20` installed 200, and the kernel default of 10
/// read back as 1 %. The same value through `tc` and through nlink on two
/// devices, then the dumps compared.
#[tokio::test]
async fn fq_pie_ecn_prob_matches_tc() -> Result<()> {
    use nlink::netlink::tc::FqPieConfig;
    require_root!();
    nlink::require_modules!("sch_fq_pie");

    let (ns, conn) = setup_tc_ns("fqpie-ecnprob").await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    let ecn_prob = |opts: Option<QdiscOptions>| match opts {
        Some(QdiscOptions::FqPie(o)) => o.ecn_prob(),
        other => panic!("not fq_pie: {other:?}"),
    };

    ns.exec("tc", &["qdisc", "add", "dev", "dummy1", "root", "fq_pie"])?;
    let root = conn
        .get_root_qdisc_by_name("dummy1")
        .await?
        .expect("a root");
    assert_eq!(
        ecn_prob(root.options()),
        Some(nlink::Percent::new(10.0)),
        "the default"
    );

    ns.exec(
        "tc",
        &[
            "qdisc", "replace", "dev", "dummy1", "root", "fq_pie", "ecn_prob", "20",
        ],
    )?;
    conn.add_qdisc(
        "dummy0",
        FqPieConfig::new().ecn_prob(nlink::Percent::new(20.0)),
    )
    .await?;
    let ours = root_qdisc_line(&ns, "dummy0")?;
    assert!(format!("{ours} ").contains(" ecn_prob 20 "), "{ours}");
    assert_eq!(ours, root_qdisc_line(&ns, "dummy1")?);
    let root = conn
        .get_root_qdisc_by_name("dummy0")
        .await?
        .expect("a root");
    assert_eq!(ecn_prob(root.options()), Some(nlink::Percent::new(20.0)));
    Ok(())
}

/// #635: cake sent its flags only when on and `cake_change` keeps a flag it
/// is not sent, so a replace never turned `nat`, `wash`, `ingress` or
/// autorate off, and `no-split-gso` never reached the kernel. And tc sends
/// a twentieth of the RTT as the target, which nlink did not. A transition
/// that turns everything off, then the same tokens through `tc` and through
/// nlink on two devices.
#[tokio::test]
async fn cake_replace_turns_flags_off_and_matches_tc() -> Result<()> {
    use nlink::netlink::{tc::CakeConfig, tc_options::CakeOptions};
    require_root!();
    nlink::require_modules!("sch_cake");

    let (ns, conn) = setup_tc_ns("cake-635").await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    let cake = |dev: &'static str| {
        let conn = &conn;
        async move {
            let root = conn.get_root_qdisc_by_name(dev).await?.expect("a root");
            Result::Ok(match root.options() {
                Some(QdiscOptions::Cake(o)) => o,
                other => panic!("not cake: {other:?}"),
            })
        }
    };
    let flags = |o: &CakeOptions| (o.nat, o.wash, o.ingress, o.autorate, o.split_gso);

    let on = [
        "bandwidth",
        "10mbit",
        "nat",
        "wash",
        "ingress",
        "autorate-ingress",
    ];
    conn.add_qdisc("dummy0", CakeConfig::parse_params(&on)?)
        .await?;
    assert_eq!(
        flags(&cake("dummy0").await?),
        (true, true, true, true, true)
    );
    let off = ["bandwidth", "10mbit", "no-split-gso"];
    conn.replace_qdisc("dummy0", CakeConfig::parse_params(&off)?)
        .await?;
    let now = cake("dummy0").await?;
    assert_eq!(flags(&now), (false, false, false, false, false), "{now:?}");

    for tokens in [
        &["rtt", "50ms"][..],
        &[
            "bandwidth",
            "10mbit",
            "diffserv4",
            "dual-srchost",
            "nat",
            "wash",
            "ack-filter",
            "overhead",
            "18",
            "mpu",
            "64",
            "no-split-gso",
        ],
        &[],
    ] {
        conn.del_qdisc("dummy0", TcHandle::ROOT).await.ok();
        ns.exec_ignore("tc", &["qdisc", "del", "dev", "dummy1", "root"]);
        let mut args = vec!["qdisc", "add", "dev", "dummy1", "root", "cake"];
        args.extend(tokens);
        ns.exec("tc", &args)?;
        conn.add_qdisc("dummy0", CakeConfig::parse_params(tokens)?)
            .await?;
        assert_eq!(
            root_qdisc_line(&ns, "dummy0")?,
            root_qdisc_line(&ns, "dummy1")?,
            "{tokens:?}"
        );
        // tc does not print the target.
        let (ours, theirs) = (cake("dummy0").await?, cake("dummy1").await?);
        assert_eq!(ours.target_us, theirs.target_us, "{tokens:?}");
        assert_eq!(ours.raw, theirs.raw, "{tokens:?}");
    }
    Ok(())
}

// ============================================================================
// Class Tests
// ============================================================================

#[tokio::test]
async fn test_add_htb_class() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htbclass").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10))
        .ceil(nlink::Rate::mbit(800)) // 800 Mbps (was buggy 100_000_000 bytes/sec = 800 Mbps)
        .build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(
        !classes.is_empty(),
        "at least one class should exist (may include root)"
    );

    Ok(())
}

#[tokio::test]
async fn test_htb_class_hierarchy() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("htbhier").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add root class
    let root_class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 1),
        root_class,
    )
    .await?;

    // Add child classes
    let child1 = HtbClassConfig::new(nlink::Rate::mbit(50))
        .ceil(nlink::Rate::mbit(800))
        .build();
    conn.add_class("dummy0", TcHandle::new(1, 1), TcHandle::new(1, 10), child1)
        .await?;

    let child2 = HtbClassConfig::new(nlink::Rate::mbit(30))
        .ceil(nlink::Rate::mbit(800))
        .build();
    conn.add_class("dummy0", TcHandle::new(1, 1), TcHandle::new(1, 20), child2)
        .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(classes.len() >= 3, "should have at least 3 classes");

    Ok(())
}

#[tokio::test]
async fn test_delete_class() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("classdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Delete it
    conn.del_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 10))
        .await?;

    // Verify
    let classes = conn.get_classes_by_name("dummy0").await?;
    // Check that class 1:10 is gone
    assert!(!classes.iter().any(|c| c.handle() == TcHandle::new(1, 0x10)));

    Ok(())
}

// ============================================================================
// Filter Tests
// ============================================================================

#[tokio::test]
async fn test_add_matchall_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("matchall").await?;

    // Add HTB qdisc first
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add matchall filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let matchall = filters.iter().find(|f| f.kind() == Some("matchall"));
    assert!(matchall.is_some(), "matchall filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_u32_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_u32");

    let (_ns, conn) = setup_tc_ns("u32").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add u32 filter matching destination port 80
    let filter = U32Filter::new()
        .classid(TcHandle::new(1, 0x10))
        .match_dst_port(80)
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let u32 = filters.iter().find(|f| f.kind() == Some("u32"));
    assert!(u32.is_some(), "u32 filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_flower_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let (_ns, conn) = setup_tc_ns("flower").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add flower filter. `.ipv4()` is required, not decorative:
    // cls_flower silently drops ip_proto unless the request carries
    // TCA_FLOWER_KEY_ETH_TYPE, and would install this as a match-all
    // (#288).
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .ipv4()
        .ip_proto_tcp()
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    let flower = filters.iter().find(|f| f.kind() == Some("flower"));
    assert!(flower.is_some(), "flower filter should exist");

    Ok(())
}

/// Regression test for the `tcm_info` protocol/priority packing bug
/// (see `TcMsg::with_filter_info`).
///
/// Adding a filter with an explicit ethernet protocol **and** a non-zero
/// priority must be accepted by the kernel. Before the fix, `tcm_info` packed
/// `(protocol << 16) | priority` (with no byte swap), so the kernel read the
/// two transposed and rejected the add with `EINVAL` — every filter add with
/// an explicit priority failed. A successful add is the regression guard:
/// verified to return `EINVAL` on the pre-fix code and `Ok` after.
///
/// The assertion is on the add, not a dump read-back: `get_filters` issues an
/// `RTM_GETTFILTER` dump with `tcm_ifindex = 0`, which returns nothing on
/// modern kernels (a separate nlink limitation), so a read-back here would be
/// flaky for reasons unrelated to this fix.
#[tokio::test]
async fn test_filter_add_explicit_protocol_priority() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("filterpp").await?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 10), class)
        .await?;

    // Explicit IPv4 protocol + non-zero priority: the exact combination that
    // returned EINVAL before the tcm_info packing fix.
    const ETH_P_IP: u16 = 0x0800;
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(ETH_P_IP),
        nlink::FilterPriority::new(200),
        filter,
    )
    .await
    .expect("filter add with explicit protocol + priority must be accepted (pre-fix: EINVAL)");

    Ok(())
}

#[tokio::test]
async fn test_matchall_on_ingress() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_ingress", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("matchinq").await?;

    // Add ingress qdisc at the special ingress parent (see
    // test_add_ingress_qdisc) — root-parent ingress is EOPNOTSUPP.
    conn.add_qdisc_full("dummy0", TcHandle::INGRESS, None, IngressConfig::new())
        .await?;

    // Add matchall filter on ingress (without actions - just classifying)
    let filter = MatchallFilter::new().build();
    conn.add_filter("dummy0", TcHandle::INGRESS, filter).await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_matchall_goto_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("gotoch").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add chain 10
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 10)
        .await?;

    // Add matchall filter with goto_chain
    let filter = MatchallFilter::new().goto_chain(10).build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_filter_on_ifb() -> Result<()> {
    require_root!();
    nlink::require_modules!("ifb", "sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("ifbfilt").await?;

    // Create IFB interface
    conn.add_link(IfbLink::new("ifb0")).await?;
    conn.set_link_up("ifb0").await?;

    // Add HTB qdisc on IFB
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("ifb0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class("ifb0", TcHandle::major_only(1), TcHandle::new(1, 10), class)
        .await?;

    // Add matchall filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("ifb0", TcHandle::major_only(1), filter)
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("ifb0").await?;
    assert!(!filters.is_empty(), "filter should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("filterdel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add filter
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Flush filters
    conn.flush_filters("dummy0", TcHandle::major_only(1))
        .await?;

    // Verify
    let filters = conn.get_filters_by_name("dummy0").await?;
    assert!(filters.is_empty(), "filters should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_replace_filter() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower");

    let (_ns, conn) = setup_tc_ns("filterrep").await?;
    let ifindex = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0 exists")
        .ifindex();

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add classes
    let class1 = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class1,
    )
    .await?;

    let class2 = HtbClassConfig::new(nlink::Rate::mbit(20)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 20),
        class2,
    )
    .await?;

    // Replace needs a filter kind that supports it, and a pinned
    // priority. Both matter, and neither was true before:
    //
    // 1. `cls_matchall` holds exactly one filter per `tcf_proto` and
    //    `mall_change` returns **EEXIST** when one already exists — it
    //    has no replace path at all. `tc(8)` fails the same way:
    //
    //      # tc filter replace dev d0 parent 1: protocol all pref 100 \
    //            matchall classid 1:20
    //      RTNETLINK answers: File exists
    //
    // 2. Replace identifies its target by (parent, protocol, priority,
    //    handle). Leave the priority unset and the kernel auto-assigns
    //    a different one, so you get a *second* filter — again matching
    //    `tc(8)`.
    //
    // This test used a matchall with no priority, so it was asserting
    // something the kernel cannot do. It could only ever have passed
    // while filter dumps returned nothing at all (#286) — and it had
    // never run anyway, being gated on `require_module!` (#273, #300).
    let prio = 200;
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        Some(TcHandle::from_raw(1)),
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(
            // ETH_P_IP
            prio,
        ),
        FlowerFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .dst_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1), 32)
            .build(),
    )
    .await?;

    conn.replace_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        Some(TcHandle::from_raw(1)),
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(prio),
        FlowerFilter::new()
            .classid(TcHandle::new(1, 0x20))
            .dst_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 2), 32)
            .build(),
    )
    .await?;

    // Replaced, not appended: still exactly one flower filter.
    let filters = conn
        .get_filters_by_parent_index(ifindex, TcHandle::major_only(1))
        .await?;
    let flower: Vec<_> = filters
        .iter()
        .filter(|f| f.kind() == Some("flower") && f.priority() == prio)
        .collect();
    assert_eq!(flower.len(), 1, "replace must not append a second filter");

    Ok(())
}

// ============================================================================
// Statistics Tests
// ============================================================================

#[tokio::test]
async fn test_qdisc_statistics() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("qdiscstats").await?;

    // Add netem qdisc
    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    conn.add_qdisc("dummy0", netem).await?;

    // Get qdiscs and check stats are available
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let netem = qdiscs.iter().find(|q| q.kind() == Some("netem")).unwrap();

    // Check convenience methods work
    let _bytes = netem.bytes();
    let _packets = netem.packets();
    let _drops = netem.drops();

    Ok(())
}

#[tokio::test]
async fn test_class_statistics() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup_tc_ns("classstats").await?;

    // Add HTB qdisc and class
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Get classes and check stats
    let classes = conn.get_classes_by_name("dummy0").await?;
    assert!(!classes.is_empty());

    // Check convenience methods work
    for c in &classes {
        let _bytes = c.bytes();
        let _packets = c.packets();
    }

    Ok(())
}

// ============================================================================
// Chain Tests
// ============================================================================

#[tokio::test]
async fn test_add_tc_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("chain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add a chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 10)
        .await?;

    // Get chains
    let chains = conn
        .get_tc_chains("dummy0", TcHandle::major_only(1))
        .await?;
    assert!(chains.contains(&10), "chain 10 should exist");

    Ok(())
}

#[tokio::test]
async fn test_delete_tc_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("chaindel").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add and delete chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 20)
        .await?;
    conn.del_tc_chain("dummy0", TcHandle::major_only(1), 20)
        .await?;

    // Verify it's gone
    let chains = conn
        .get_tc_chains("dummy0", TcHandle::major_only(1))
        .await?;
    assert!(!chains.contains(&20), "chain 20 should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_filter_with_chain() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_matchall");

    let (_ns, conn) = setup_tc_ns("fchain").await?;

    // Add HTB qdisc
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    // Add class
    let class = HtbClassConfig::new(nlink::Rate::mbit(10)).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 10),
        class,
    )
    .await?;

    // Add chain
    conn.add_tc_chain("dummy0", TcHandle::major_only(1), 5)
        .await?;

    // Add filter in chain 5
    let filter = MatchallFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .chain(5)
        .build();
    conn.add_filter("dummy0", TcHandle::major_only(1), filter)
        .await?;

    // Verify filter is in chain
    let filters = conn.get_filters_by_name("dummy0").await?;
    // At least one filter should exist
    assert!(!filters.is_empty());

    Ok(())
}

// ============================================================================
// #424 — an exact SCTP port is a match, not a match-all
// ============================================================================

/// Send `count` SCTP packets from inside `ns` to `dst` on each of `ports`.
///
/// Through a raw IPv4 socket, so no `sctp` module is needed: the kernel
/// writes the IP header (protocol 132) and this writes the 12-byte SCTP
/// common header — source port, destination port, verification tag,
/// checksum. The flow dissector reads an SCTP packet's ports from its first
/// four bytes, as it does TCP's and UDP's, and nothing on the egress path
/// looks at the rest.
fn send_sctp(ns: &TestNamespace, dst: std::net::Ipv4Addr, ports: &[u16], count: usize) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let name = ns.name().to_string();
    let ports = ports.to_vec();
    std::thread::spawn(move || {
        let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
        // SAFETY: socket(2) with constant arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_SCTP) };
        assert!(
            fd >= 0,
            "raw SCTP socket: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `fd` was just returned by socket(2) and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let to = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst).to_be(),
            },
            sin_zero: [0; 8],
        };
        for port in &ports {
            let mut header = [0u8; 12];
            header[..2].copy_from_slice(&40000u16.to_be_bytes());
            header[2..4].copy_from_slice(&port.to_be_bytes());
            for _ in 0..count {
                // SAFETY: `header` and `to` are live for the call and their
                // lengths are the ones passed.
                let sent = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        header.as_ptr().cast(),
                        header.len(),
                        0,
                        (&to as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                assert_eq!(
                    sent,
                    header.len() as isize,
                    "sendto: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    })
    .join()
    .expect("SCTP thread panicked");
}

/// A flower filter for one SCTP destination port classifies that port and
/// nothing else. `FlowerFilter` wrote an exact port only for TCP and UDP, so
/// an SCTP port filter installed as `ip_proto sctp` alone and claimed every
/// SCTP packet (#424).
///
/// The traffic leaves through a dummy device, so every packet is classified
/// by the HTB root and counted on the class it lands in.
#[tokio::test]
async fn flower_sctp_port_classifies_only_its_port() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");
    use nlink::netlink::types::tc::filter::flower::TCA_FLOWER_KEY_SCTP_DST;

    let (ns, conn) = setup_tc_ns("flower-sctp").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .ipv4()
        .ip_proto(132)
        .dst_port(5001)
        .build();
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        filter,
    )
    .await?;

    // The kernel holds the SCTP port key…
    let mut failures = Vec::new();
    let filters = conn.get_filters_by_name("dummy0").await?;
    let flower = filters
        .iter()
        .find(|f| f.kind() == Some("flower"))
        .expect("flower filter installed");
    let sctp_dst = nlink::netlink::AttrIter::new(flower.raw_options().unwrap_or_default())
        .find(|(ty, _)| *ty == TCA_FLOWER_KEY_SCTP_DST)
        .map(|(_, payload)| payload.to_vec());
    if sctp_dst != Some(5001u16.to_be_bytes().to_vec()) {
        failures.push(format!(
            "the installed filter's TCA_FLOWER_KEY_SCTP_DST is {sctp_dst:?}, want port 5001"
        ));
    }

    // …and classifies by it: port 5001 into 1:10, other SCTP ports and
    // UDP to the same port into the default class.
    const PER_PORT: usize = 5;
    let peer = std::net::Ipv4Addr::new(10, 42, 0, 2);
    send_sctp(&ns, peer, &[5001], PER_PORT);
    send_sctp(&ns, peer, &[5002, 80], PER_PORT);
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for _ in 0..PER_PORT {
                socket.send_to(b"nlink", (peer, 5001)).expect("send");
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (port, default) = (count(0x10), count(0x30));
    let (want_port, want_default) = (PER_PORT as u64, 3 * PER_PORT as u64);
    if port != Some(want_port) || default != Some(want_default) {
        failures.push(format!(
            "port class 1:10 counted {port:?} packets (want {want_port}), default class 1:30 \
             counted {default:?} (want {want_default})"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// A flower filter for one VLAN id classifies that VLAN and nothing else.
/// `FlowerFilter` had no way to set a VLAN ethertype, and `cls_flower` reads
/// `vlan_id` only under one, so `.vlan_id(10)` installed a match-all (#431).
///
/// VLANs 10 and 20 sit on a dummy device with an HTB root; the filter is
/// installed for every protocol, so a match-all would claim VLAN 20 and the
/// untagged traffic too.
#[tokio::test]
async fn flower_vlan_id_classifies_only_its_vlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_htb", "cls_flower");
    use nlink::netlink::link::VlanLink;

    let (ns, conn) = setup_tc_ns("flower-vlan").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;
    for (id, net) in [(10u16, "10.10.0.1/24"), (20, "10.20.0.1/24")] {
        let name = format!("dummy0.{id}");
        conn.add_link(VlanLink::new(&name, "dummy0", id)).await?;
        conn.set_link_up(name.as_str()).await?;
        ns.add_addr(&name, net)?;
    }

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let filter = FlowerFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .vlan_id(10)
        .build();
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x0003),
        nlink::FilterPriority::new(1),
        filter,
    )
    .await?;

    const PER_TARGET: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for peer in ["10.10.0.2:9", "10.20.0.2:9", "10.42.0.2:9"] {
                for _ in 0..PER_TARGET {
                    socket.send_to(b"nlink", peer).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (vlan, default) = (count(0x10), count(0x30));
    let (want_vlan, want_default) = (PER_TARGET as u64, 2 * PER_TARGET as u64);
    assert!(
        vlan == Some(want_vlan) && default == Some(want_default),
        "VLAN class 1:10 counted {vlan:?} packets (want {want_vlan}), default class 1:30 \
         counted {default:?} (want {want_default})"
    );
    Ok(())
}

// ============================================================================
// #433 — the flower ethertype comes from the filter's protocol
// ============================================================================

/// A flower filter installed under `protocol ip` with no ethertype of its own
/// takes the protocol as its TCA_FLOWER_KEY_ETH_TYPE, as tc(8) does. nlink
/// refused it ("needs an ethertype"), so `protocol ip flower ip_proto udp
/// dst_port 5001` — a standard tc(8) filter — could not be installed (#433).
///
/// All three explicit-protocol entry points are exercised: `add_filter_full`
/// puts UDP 5001 into 1:10, `replace_filter_full` puts UDP 5002 into 1:20,
/// and `change_filter_full` moves that filter to UDP 5003, which leaves 5002
/// to the default class.
#[tokio::test]
async fn flower_takes_its_ethertype_from_the_filter_protocol() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");
    use nlink::netlink::types::tc::filter::flower::TCA_FLOWER_KEY_ETH_TYPE;

    let (ns, conn) = setup_tc_ns("flower-proto").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x20, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let udp_port = |minor: u16, port: &str| {
        FlowerFilter::parse_params(&["classid", &format!("1:{minor:x}"), "ip_proto", "udp", "dst_port", port])
            .expect("parses")
    };
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        udp_port(0x10, "5001"),
    )
    .await?;
    conn.replace_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(2),
        udp_port(0x20, "5002"),
    )
    .await?;
    let handle = conn
        .get_filters_by_name("dummy0")
        .await?
        .iter()
        .find(|f| f.kind() == Some("flower") && f.priority() == 2 && f.handle_raw() != 0)
        .map(|f| f.handle())
        .expect("the replaced filter is installed");
    conn.change_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        Some(handle),
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(2),
        udp_port(0x20, "5003"),
    )
    .await?;

    let mut failures = Vec::new();
    for f in conn.get_filters_by_name("dummy0").await? {
        if f.kind() != Some("flower") {
            continue;
        }
        let eth_type = nlink::netlink::AttrIter::new(f.raw_options().unwrap_or_default())
            .find(|(ty, _)| *ty == TCA_FLOWER_KEY_ETH_TYPE)
            .map(|(_, payload)| payload.to_vec());
        if eth_type != Some(0x0800u16.to_be_bytes().to_vec()) {
            failures.push(format!(
                "the flower filter at prio {} carries TCA_FLOWER_KEY_ETH_TYPE {eth_type:?}, want IPv4",
                f.priority()
            ));
        }
    }

    const PER_PORT: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for port in [5001, 5002, 5003] {
                for _ in 0..PER_PORT {
                    socket.send_to(b"nlink", ("10.42.0.2", port)).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let want = Some(PER_PORT as u64);
    for (minor, what) in [(0x10, "UDP 5001"), (0x20, "UDP 5003"), (0x30, "the default (UDP 5002)")] {
        if count(minor) != want {
            failures.push(format!(
                "class 1:{minor:x} for {what} counted {:?} packets, want {want:?}",
                count(minor)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// A flower `vlan_id` filter under `protocol 802.1ad` classifies its 802.1AD
/// VLAN. `.vlan_id()` implied an 802.1Q ethertype even when the filter's
/// protocol named 802.1AD, so the filter asked for a TPID of 0x8100 on frames
/// the protocol had already restricted to 0x88a8, and matched nothing. tc(8)
/// takes the TPID from the protocol (#433). The kernel does not echo the
/// TPID, so only traffic shows the difference.
#[tokio::test]
async fn flower_vlan_id_under_802_1ad_classifies_its_vlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_htb", "cls_flower");
    use nlink::netlink::link::VlanLink;

    let (ns, conn) = setup_tc_ns("flower-qinq").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;
    for (name, link, net) in [
        ("dummy0.10", VlanLink::new("dummy0.10", "dummy0", 10), "10.10.0.1/24"),
        ("dummy0.20", VlanLink::new("dummy0.20", "dummy0", 20).qinq(), "10.20.0.1/24"),
    ] {
        conn.add_link(link).await?;
        conn.set_link_up(name).await?;
        ns.add_addr(name, net)?;
    }

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    // tc(8): `protocol 802.1ad flower vlan_id 20 classid 1:10`.
    let filter = FlowerFilter::parse_params(&["vlan_id", "20", "classid", "1:10"]).expect("parses");
    conn.add_filter_full(
        "dummy0",
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x88A8),
        nlink::FilterPriority::new(1),
        filter,
    )
    .await?;

    const PER_TARGET: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for peer in ["10.20.0.2:9", "10.10.0.2:9", "10.42.0.2:9"] {
                for _ in 0..PER_TARGET {
                    socket.send_to(b"nlink", peer).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let classes = conn.get_classes_by_name("dummy0").await?;
    let count = |minor: u16| {
        classes
            .iter()
            .find(|c| c.handle() == TcHandle::new(1, minor))
            .map(|c| c.packets())
    };
    let (vlan, default) = (count(0x10), count(0x30));
    let (want_vlan, want_default) = (PER_TARGET as u64, 2 * PER_TARGET as u64);
    assert!(
        vlan == Some(want_vlan) && default == Some(want_default),
        "802.1AD VLAN class 1:10 counted {vlan:?} packets (want {want_vlan}), default class 1:30 \
         counted {default:?} (want {want_default})"
    );
    Ok(())
}

// ============================================================================
// #450 — flower carries actions
// ============================================================================

/// A flower filter's actions run on its match, and only there: a
/// `dst_port 5001` filter with a drop drops UDP 5001, and UDP 5002 reaches
/// the default class. `FlowerFilter` could not carry actions (only
/// `goto_chain`), so tc(8)'s `flower … action drop` had no equivalent
/// (#450).
#[tokio::test]
async fn flower_actions_run_on_its_match() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower", "act_gact");
    use nlink::netlink::action::{ActionList, GactAction};

    let (ns, conn) = setup_tc_ns("flower-act").await?;
    ns.add_addr("dummy0", "10.42.0.1/24")?;

    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    // UDP 5002 gets a class of its own: the default class also counts
    // IPv6's own packets on the up link (MLD, router solicitations), so
    // its count is not the test's to assert (#891).
    for minor in [0x20, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(
            "dummy0",
            TcHandle::major_only(1),
            TcHandle::new(1, minor),
            class,
        )
        .await?;
    }
    let drop_5001 = FlowerFilter::new()
        .ipv4()
        .ip_proto_udp()
        .dst_port(5001)
        .actions(ActionList::new().with(GactAction::drop()))
        .build();
    let pass_5002 = FlowerFilter::new()
        .ipv4()
        .ip_proto_udp()
        .dst_port(5002)
        .classid(TcHandle::new(1, 0x20))
        .build();
    for (prio, filter) in [(1, drop_5001), (2, pass_5002)] {
        conn.add_filter_full(
            "dummy0",
            TcHandle::major_only(1),
            None,
            nlink::EthProto::new(0x0800),
            nlink::FilterPriority::new(prio),
            filter,
        )
        .await?;
    }

    const PER_PORT: usize = 5;
    {
        let name = ns.name().to_string();
        std::thread::spawn(move || {
            let _ns = nlink::netlink::namespace::enter(&name).expect("enter test netns");
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
            for port in [5001, 5002] {
                for _ in 0..PER_PORT {
                    // A drop at the qdisc is not an error for UDP without
                    // IP_RECVERR, so every send succeeds.
                    socket.send_to(b"nlink", ("10.42.0.2", port)).expect("send");
                }
            }
        })
        .join()
        .expect("UDP thread panicked");
    }

    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    let drops = qdiscs
        .iter()
        .find(|q| q.kind() == Some("htb"))
        .map(|q| q.drops());
    let classes = conn.get_classes_by_name("dummy0").await?;
    let passed = classes
        .iter()
        .find(|c| c.handle() == TcHandle::new(1, 0x20))
        .map(|c| c.packets());
    let want = Some(PER_PORT as u64);
    assert!(
        drops.map(u64::from) == want && passed == want,
        "the HTB root dropped {drops:?} packets (want {want:?}: UDP 5001, by the flower drop) and \
         class 1:20 passed {passed:?} (want {want:?}: UDP 5002)"
    );
    Ok(())
}

/// HTB on `a`'s end of `pair`: default class 1:30, and 1:10 for what the
/// u32 filters pick.
async fn u32_htb(conn: &Connection<Route>, dev: &str) -> Result<()> {
    let htb = HtbQdiscConfig::new().default_class(0x30).build();
    conn.add_qdisc_full(dev, TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;
    for minor in [0x10, 0x30] {
        let class = HtbClassConfig::new(nlink::Rate::mbit(100)).build();
        conn.add_class(dev, TcHandle::major_only(1), TcHandle::new(1, minor), class)
            .await?;
    }
    Ok(())
}

/// Packets classified into `1:minor` on `a`'s end so far.
async fn u32_class_packets(pair: &crate::common::topo::NsPair, minor: u16) -> Result<u64> {
    let conn = pair.a.connection()?;
    let stats =
        crate::common::counters::class_stats(&conn, pair.a_ifindex, TcHandle::new(1, minor))
            .await?;
    Ok(stats.map_or(0, |(packets, _)| packets))
}

/// #492: `match_dst_port` was a next-header key in host byte order. On
/// little-endian it compared the wrong bytes, and with no linking
/// `offset` the next header is the IP header itself, so it never matched
/// a port. It is now tc's `match ip dport`: bytes 22–23 of an
/// option-less IPv4 packet.
#[tokio::test]
async fn u32_port_matches_classify_traffic() -> Result<()> {
    use std::net::SocketAddr;

    use crate::common::{topo::NsPair, traffic::deliver_udp};
    require_root!();
    nlink::require_modules!("sch_htb", "cls_u32", "veth");

    let pair = NsPair::new("u32ports", 63).await?;
    let conn = pair.a.connection()?;
    u32_htb(&conn, pair.a_if).await?;
    let filter = U32Filter::new()
        .match_ip_proto(17)
        .match_dst_port(5001)
        .classid(TcHandle::new(1, 0x10))
        .build();
    conn.add_filter_full(
        pair.a_if,
        TcHandle::major_only(1),
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        filter,
    )
    .await?;

    let to = |port| SocketAddr::new(pair.b_addr.into(), port);
    assert_eq!(deliver_udp(&pair.a, &pair.b, to(5001), 10), 10);
    assert!(
        u32_class_packets(&pair, 0x10).await? >= 10,
        "port 5001 should land in 1:10"
    );
    let before = u32_class_packets(&pair, 0x10).await?;
    assert_eq!(deliver_udp(&pair.a, &pair.b, to(5002), 10), 10);
    assert_eq!(
        u32_class_packets(&pair, 0x10).await?,
        before,
        "port 5002 is not 5001"
    );
    assert!(
        u32_class_packets(&pair, 0x30).await? >= 10,
        "the rest takes the default"
    );
    Ok(())
}

/// #492: the next-header form, as tc(8) builds it. A filter in the root
/// table finds the header length (`offset at 0 mask 0f00 shift 6`) and
/// links to table 2:, whose key matches the port relative to it. The
/// table handle is a u32 handle, `2:` = 0x00200000, not a qdisc handle.
#[tokio::test]
async fn u32_next_header_port_matches_behind_a_link() -> Result<()> {
    use std::net::SocketAddr;

    use crate::common::{topo::NsPair, traffic::deliver_udp};
    require_root!();
    nlink::require_modules!("sch_htb", "cls_u32", "veth");

    let pair = NsPair::new("u32nexthdr", 64).await?;
    let conn = pair.a.connection()?;
    u32_htb(&conn, pair.a_if).await?;
    let table = U32Filter::handle(2, 0, 0);
    let parent = TcHandle::major_only(1);
    conn.add_filter_full(
        pair.a_if,
        parent,
        Some(TcHandle::from_raw(table)),
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        U32Filter::new().divisor(1).build(),
    )
    .await?;
    // tc(8)'s own line for it.
    let linker = U32Filter::parse_params(&[
        "match", "ip", "protocol", "17", "0xff", "offset", "at", "0", "mask", "0f00", "shift", "6",
        "link", "2:",
    ])?;
    conn.add_filter_full(
        pair.a_if,
        parent,
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        linker,
    )
    .await?;
    let port = U32Filter::parse_params(&["ht", "2:", "match", "udp", "dst", "5003", "0xffff"])?
        .classid(TcHandle::new(1, 0x10));
    conn.add_filter_full(
        pair.a_if,
        parent,
        None,
        nlink::EthProto::new(0x0800),
        nlink::FilterPriority::new(1),
        port,
    )
    .await?;

    let to = |port| SocketAddr::new(pair.b_addr.into(), port);
    assert_eq!(deliver_udp(&pair.a, &pair.b, to(5003), 10), 10);
    assert!(
        u32_class_packets(&pair, 0x10).await? >= 10,
        "port 5003 should land in 1:10 through table 2:"
    );
    let before = u32_class_packets(&pair, 0x10).await?;
    assert_eq!(deliver_udp(&pair.a, &pair.b, to(5004), 10), 10);
    assert_eq!(u32_class_packets(&pair, 0x10).await?, before);
    Ok(())
}

/// #492, the way 0.30 found its flower bugs: install the same u32 lines
/// through `tc` and through nlink's parser at two priorities, and compare
/// what `tc filter show` says about each.
#[tokio::test]
async fn u32_port_filters_match_what_tc_installs() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "cls_u32");

    let (ns, conn) = setup_tc_ns("u32-parity").await?;
    u32_htb(&conn, "dummy0").await?;
    let lines: [&[&str]; 5] = [
        &["match", "ip", "dport", "443", "0xffff", "flowid", "1:10"],
        &["match", "ip", "sport", "53", "0xffff", "flowid", "1:10"],
        &[
            "match",
            "ip",
            "src",
            "10.1.2.0/24",
            "match",
            "ip",
            "dport",
            "80",
            "0xfff0",
            "flowid",
            "1:10",
        ],
        &["match", "tcp", "dst", "22", "0xffff", "flowid", "1:10"],
        &[
            "match", "ip", "protocol", "6", "0xff", "match", "ip", "dport", "22", "0xffff",
            "flowid", "1:10",
        ],
    ];
    let shown = |prio: &str| -> Result<String> {
        let out = ns.exec(
            "tc",
            &[
                "filter", "show", "dev", "dummy0", "parent", "1:", "prio", prio,
            ],
        )?;
        // Drop the per-filter handle lines' numbering; keep the matches.
        Ok(out
            .lines()
            .filter(|l| l.trim_start().starts_with("match"))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n"))
    };
    for (n, tokens) in lines.iter().enumerate() {
        let (tc_prio, nlink_prio) = (10 + 2 * n as u16, 11 + 2 * n as u16);
        let mut args = vec!["filter", "add", "dev", "dummy0", "parent", "1:"];
        let tc_prio_s = tc_prio.to_string();
        args.extend(["prio", &tc_prio_s, "protocol", "ip", "u32"]);
        args.extend(tokens.iter());
        ns.exec("tc", &args)?;
        let filter = U32Filter::parse_params(tokens)?;
        conn.add_filter_full(
            "dummy0",
            TcHandle::major_only(1),
            None,
            nlink::EthProto::new(0x0800),
            nlink::FilterPriority::new(nlink_prio),
            filter,
        )
        .await?;
        let (theirs, ours) = (shown(&tc_prio_s)?, shown(&nlink_prio.to_string())?);
        assert!(
            !theirs.is_empty(),
            "tc showed no match lines for {tokens:?}"
        );
        assert_eq!(ours, theirs, "{tokens:?}");
    }
    Ok(())
}

/// `block` drops a direction's traffic with a matchall on a clsact hook,
/// and leaves the root qdisc alone; `unblock` lets it through again. A
/// boxed qdisc config installs like a typed one (#515).
#[tokio::test]
async fn block_drops_traffic_and_keeps_the_root_qdisc() -> Result<()> {
    use std::net::SocketAddr;

    use nlink::netlink::block::Direction;
    use nlink::netlink::tc::{PrioConfig, QdiscConfig};

    use crate::common::{topo::NsPair, traffic::deliver_udp};
    require_root!();
    nlink::require_modules!(
        "sch_prio",
        "sch_ingress",
        "cls_matchall",
        "act_gact",
        "veth"
    );

    let pair = NsPair::new("block", 67).await?;
    let conn_b = pair.b.connection()?;
    let boxed: Box<dyn QdiscConfig> = Box::new(PrioConfig::new());
    conn_b.replace_qdisc(pair.b_if, boxed).await?;
    let dst = SocketAddr::new(pair.b_addr.into(), 9100);
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 10),
        10,
        "the pair must deliver first"
    );

    conn_b.block(pair.b_if, Direction::Ingress).await?;
    conn_b.block(pair.b_if, Direction::Ingress).await?; // a second time is a no-op
    assert!(conn_b.is_blocked(pair.b_if, Direction::Ingress).await?);
    assert!(!conn_b.is_blocked(pair.b_if, Direction::Egress).await?);
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 10),
        0,
        "blocked ingress delivered"
    );
    let root = conn_b
        .get_qdiscs_by_name(pair.b_if)
        .await?
        .into_iter()
        .find(|q| q.parent() == TcHandle::ROOT)
        .expect("a root qdisc");
    assert_eq!(root.kind(), Some("prio"), "block replaced the root qdisc");

    conn_b.unblock(pair.b_if, Direction::Ingress).await?;
    assert!(!conn_b.is_blocked(pair.b_if, Direction::Ingress).await?);
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 10),
        10,
        "unblocked ingress dropped"
    );

    // Egress, from the sending side.
    let conn_a = pair.a.connection()?;
    conn_a.block(pair.a_if, Direction::Egress).await?;
    assert_eq!(
        deliver_udp(&pair.a, &pair.b, dst, 10),
        0,
        "blocked egress delivered"
    );
    conn_a.unblock(pair.a_if, Direction::Egress).await?;
    assert_eq!(deliver_udp(&pair.a, &pair.b, dst, 10), 10);
    Ok(())
}

/// The handle of dummy0's root qdisc.
async fn dummy0_root_handle(conn: &Connection<Route>) -> Result<TcHandle> {
    let root = conn.get_root_qdisc_by_name("dummy0").await?;
    Ok(root.expect("a root").handle())
}

/// The kind of dummy0's ingress-slot qdisc, if any.
async fn dummy0_hook_kind(conn: &Connection<Route>) -> Result<Option<String>> {
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    Ok(qdiscs
        .iter()
        .find(|q| matches!(q.kind(), Some("ingress" | "clsact")))
        .and_then(|q| q.kind().map(str::to_string)))
}

/// The kind of dummy0's configured root qdisc, if any.
async fn dummy0_root_kind(conn: &Connection<Route>) -> Result<Option<String>> {
    let root = conn.get_root_qdisc_by_name("dummy0").await?;
    Ok(root
        .filter(|q| q.handle().as_raw() != 0)
        .and_then(|q| q.kind().map(str::to_string)))
}

/// #515: a classful qdisc added or replaced at the root without a handle
/// sits at `1:`, so its classes can name it; the kernel picked `8001:`.
/// A live qdisc changed or recreated keeps its handle, and a batch puts an
/// ingress at the hook, which it sent to the root before.
#[tokio::test]
async fn a_classful_root_without_a_handle_sits_at_1() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb", "sch_prio", "sch_netem", "sch_ingress");

    let (_ns, conn) = setup_tc_ns("default-handle").await?;
    conn.add_qdisc("dummy0", HtbQdiscConfig::new().default_class(0x10).build())
        .await?;
    assert_eq!(dummy0_root_handle(&conn).await?, TcHandle::major_only(1));
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 0x10),
        HtbClassConfig::new(nlink::Rate::mbit(10)).build(),
    )
    .await?;

    // Another classful kind replaces it at the same handle, through the
    // graft that never leaves the slot bare.
    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;
    conn.replace_qdisc("dummy0", PrioConfig::new().build())
        .await?;
    assert_eq!(dummy0_root_handle(&conn).await?, TcHandle::major_only(1));
    // A classless kind takes the kernel's choice; a classful one over it
    // grafts at 1:.
    conn.replace_qdisc("dummy0", NetemConfig::new()).await?;
    assert_ne!(dummy0_root_handle(&conn).await?, TcHandle::major_only(1));
    conn.replace_qdisc("dummy0", PrioConfig::new().build())
        .await?;
    assert_eq!(dummy0_root_handle(&conn).await?, TcHandle::major_only(1));
    // An explicit handle wins.
    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;
    conn.add_qdisc_full(
        "dummy0",
        TcHandle::ROOT,
        Some(TcHandle::major_only(7)),
        PrioConfig::new(),
    )
    .await?;
    assert_eq!(dummy0_root_handle(&conn).await?, TcHandle::major_only(7));

    let link = conn.get_link_by_name("dummy0").await?.expect("dummy0");
    conn.del_qdisc("dummy0", TcHandle::ROOT).await?;
    conn.batch()
        .add_qdisc(link.ifindex(), HtbQdiscConfig::new().build())
        .add_qdisc(link.ifindex(), IngressConfig::new())
        .execute()
        .await?;
    assert_eq!(dummy0_root_handle(&conn).await?, TcHandle::major_only(1));
    let qdiscs = conn.get_qdiscs_by_name("dummy0").await?;
    assert!(
        qdiscs.iter().any(|q| q.kind() == Some("ingress")),
        "{qdiscs:?}"
    );
    Ok(())
}

/// #515: the ingress and clsact qdiscs share a slot, and `del_qdisc` at it
/// deleted whichever was there. `del_ingress` and `del_clsact` name the
/// kind, and the kernel refuses the other.
#[tokio::test]
async fn del_ingress_and_del_clsact_delete_only_their_kind() -> Result<()> {
    use nlink::netlink::tc::ClsactConfig;
    require_root!();
    nlink::require_modules!("sch_ingress");

    let (_ns, conn) = setup_tc_ns("del-hook-kind").await?;
    conn.add_qdisc("dummy0", ClsactConfig::new()).await?;
    let err = conn
        .del_ingress("dummy0")
        .await
        .expect_err("a clsact is not an ingress");
    assert!(
        err.to_string().contains("is `clsact`, not `ingress`"),
        "{err}"
    );
    assert_eq!(
        dummy0_hook_kind(&conn).await?.as_deref(),
        Some("clsact"),
        "the clsact stays"
    );
    conn.del_clsact("dummy0").await?;
    assert_eq!(dummy0_hook_kind(&conn).await?, None);

    conn.add_qdisc("dummy0", IngressConfig::new()).await?;
    assert!(conn.del_clsact("dummy0").await.is_err());
    assert_eq!(dummy0_hook_kind(&conn).await?.as_deref(), Some("ingress"));
    conn.del_ingress("dummy0").await?;
    assert_eq!(dummy0_hook_kind(&conn).await?, None);
    assert!(conn.del_ingress("dummy0").await.unwrap_err().is_not_found());
    Ok(())
}

/// #515: `PerHostLimiter::remove` and `PerPeerImpairer::clear` deleted
/// whatever root the device had — a user's TBF, the other recipe's tree.
/// Each removes only a tree it would have built.
#[tokio::test]
async fn recipe_remove_deletes_only_its_own_root() -> Result<()> {
    use nlink::netlink::{impair::PerPeerImpairer, ratelimit::PerHostLimiter};
    require_root!();
    nlink::require_modules!(
        "sch_htb",
        "sch_tbf",
        "sch_fq_codel",
        "sch_netem",
        "cls_flower"
    );

    let (_ns, conn) = setup_tc_ns("recipe-scope").await?;
    let limiter = PerHostLimiter::new("dummy0", nlink::Rate::mbit(10))
        .limit_ip("10.0.0.2".parse().unwrap(), nlink::Rate::mbit(1));
    let impairer = PerPeerImpairer::new("dummy0").impair_dst_ip(
        "10.0.0.3".parse().unwrap(),
        NetemConfig::new().delay(Duration::from_millis(5)),
    );

    // A user's TBF: neither recipe touches it.
    conn.add_qdisc(
        "dummy0",
        TbfConfig::new()
            .rate(nlink::Rate::mbit(10))
            .burst(nlink::Bytes::kib(32))
            .limit(nlink::Bytes::kib(64))
            .build(),
    )
    .await?;
    limiter.remove(&conn).await?;
    impairer.clear(&conn).await?;
    assert_eq!(dummy0_root_kind(&conn).await?.as_deref(), Some("tbf"));

    // The limiter's tree: the impairer leaves it, the limiter removes it.
    limiter.apply(&conn).await?;
    impairer.clear(&conn).await?;
    assert_eq!(
        dummy0_root_kind(&conn).await?.as_deref(),
        Some("htb"),
        "not the impairer's"
    );
    limiter.remove(&conn).await?;
    assert_eq!(dummy0_root_kind(&conn).await?, None);

    // And the other way round.
    impairer.apply(&conn).await?;
    limiter.remove(&conn).await?;
    assert_eq!(
        dummy0_root_kind(&conn).await?.as_deref(),
        Some("htb"),
        "not the limiter's"
    );
    impairer.clear(&conn).await?;
    assert_eq!(dummy0_root_kind(&conn).await?, None);
    Ok(())
}

/// #515: the verbs do what their table says, on a live device: create
/// refuses an occupied slot, change refuses another kind or one only a
/// recreate can change, replace takes anything, apply does nothing when the
/// live qdisc already is the spec, delete_kind names the kind at the hook.
#[tokio::test]
async fn the_tc_verbs_do_what_their_table_says() -> Result<()> {
    use nlink::netlink::tc::ClsactConfig;
    use nlink::netlink::tc_verbs::Parent;
    require_root!();
    nlink::require_modules!("sch_netem", "sch_htb", "sch_ingress");

    let (_ns, conn) = setup_tc_ns("tc-verbs").await?;
    let tc = conn.tc("dummy0");
    let root = tc.qdisc(Parent::Root);
    let netem = |ms| NetemConfig::new().delay(Duration::from_millis(ms));

    assert!(
        root.get().await?.is_none(),
        "the kernel's default root is not configured"
    );
    let missing = root.change(netem(5)).await.unwrap_err();
    assert!(missing.is_not_found(), "change needs something to change");
    // A verb's error names its slot (#718).
    let slot = |kind: Option<&str>| nlink::ErrorObject::Qdisc {
        dev: "dummy0".into(),
        parent: Some("root".into()),
        kind: kind.map(str::to_string),
    };
    assert_eq!(missing.object(), Some(&slot(Some("netem"))), "{missing}");
    root.create(netem(5)).await?;
    let taken = root.create(netem(5)).await.unwrap_err();
    assert!(taken.is_already_exists(), "{taken}");
    assert_eq!(taken.object(), Some(&slot(Some("netem"))), "{taken}");
    root.change(netem(9)).await?;
    let live = root.get().await?.expect("netem");
    assert_eq!(
        dummy0_netem(&conn).await?.delay(),
        Some(Duration::from_millis(9))
    );

    let htb = HtbQdiscConfig::new().default_class(0x10).build();
    let err = root.change(htb.clone()).await.unwrap_err();
    assert!(err.to_string().contains("replace it"), "{err}");
    assert_eq!(
        root.get().await?.expect("netem").handle(),
        live.handle(),
        "untouched"
    );

    // apply: a change when it differs, nothing when it matches.
    assert!(
        root.apply(netem(12)).await?,
        "a different delay is a change"
    );
    assert!(!root.apply(netem(12)).await?, "the same netem is nothing");
    root.replace(htb.clone()).await?;
    assert_eq!(
        root.get().await?.expect("htb").handle(),
        TcHandle::major_only(1)
    );
    let err = root.change(htb).await.unwrap_err();
    assert!(
        err.to_string().contains("cannot be changed in place"),
        "{err}"
    );

    // A leaf in a class.
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 0x10),
        HtbClassConfig::new(nlink::Rate::mbit(10)).build(),
    )
    .await?;
    let leaf = tc.qdisc(Parent::Class(TcHandle::new(1, 0x10))).handle(0x20);
    leaf.create(netem(1)).await?;
    assert_eq!(
        leaf.get().await?.expect("leaf").handle(),
        TcHandle::major_only(0x20)
    );

    root.delete().await?;
    assert!(root.get().await?.is_none());
    let nothing = root.delete().await.unwrap_err();
    assert_eq!(nothing.object(), Some(&slot(None)), "nothing left to delete: {nothing}");

    let hook = tc.qdisc(Parent::Ingress);
    hook.create(ClsactConfig::new()).await?;
    assert!(
        hook.delete_kind("ingress").await.is_err(),
        "a clsact is not an ingress"
    );
    assert_eq!(
        hook.get()
            .await?
            .and_then(|q| q.kind().map(str::to_string))
            .as_deref(),
        Some("clsact")
    );
    hook.delete_kind("clsact").await?;
    assert!(hook.get().await?.is_none());
    Ok(())
}

/// #710: a program pinned in bpffs, attached through `from_pinned` as a
/// filter and as an action. bpffs refuses `open(2)` on a pin (`EIO`); only
/// `bpf(BPF_OBJ_GET)` opens it.
#[tokio::test]
async fn a_pinned_bpf_program_attaches_as_filter_and_action() -> Result<()> {
    use nlink::netlink::{
        action::{ActionList, BpfAction},
        filter::BpfFilter,
        tc::ClsactConfig,
    };
    require_root!();
    // Loading a program needs CAP_BPF in the initial user namespace.
    nlink::require_host_root!();
    nlink::require_modules!("cls_bpf", "act_bpf", "cls_matchall");

    let (ns, conn) = setup_tc_ns("bpf-pin").await?;
    conn.add_qdisc("dummy0", ClsactConfig::new()).await?;
    let classifier = BpfPin::load("cls", BPF_PROG_TYPE_SCHED_CLS)?;
    let act = BpfPin::load("act", BPF_PROG_TYPE_SCHED_ACT)?;

    // The tc(8)-syntax parsers open pins the same way.
    let cls_path = classifier.path.to_str().unwrap();
    let _ = BpfFilter::parse_params(&["pinned", cls_path, "da"])?;
    let _ = BpfAction::parse_params(&["pinned", act.path.to_str().unwrap()])?;

    let filter = BpfFilter::from_pinned(&classifier.path)?.direct_action().build();
    conn.add_filter("dummy0", TcHandle::CLSACT_INGRESS, filter).await?;
    let action = BpfAction::from_pinned(&act.path)?.name("pinned_act").build();
    let matchall = MatchallFilter::new()
        .actions(ActionList::new().with(action))
        .build();
    conn.add_filter("dummy0", TcHandle::CLSACT_EGRESS, matchall).await?;

    let ingress = ns.exec("tc", &["filter", "show", "dev", "dummy0", "ingress"])?;
    assert!(ingress.contains(" bpf ") && ingress.contains("direct-action"), "{ingress}");
    let egress = ns.exec("tc", &["filter", "show", "dev", "dummy0", "egress"])?;
    assert!(egress.contains("bpf pinned_act"), "{egress}");
    Ok(())
}

/// #813: a declared bpf action is compared by its program. A request names
/// the program by fd and a dump by id, so the comparison went by kind
/// alone, and a filter whose action ran another program matched.
#[tokio::test]
async fn a_declared_bpf_action_is_compared_by_its_program() -> Result<()> {
    use nlink::netlink::action::{ActionList, BpfAction};
    use nlink::netlink::config::NetworkConfig;
    use nlink::{EthProto, FilterPriority};
    require_root!();
    // Loading a program needs CAP_BPF in the initial user namespace.
    nlink::require_host_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_bpf");

    let one = BpfPin::load("decl-one", BPF_PROG_TYPE_SCHED_ACT)?;
    let two = BpfPin::load("decl-two", BPF_PROG_TYPE_SCHED_ACT)?;
    let ns = TestNamespace::new("tc-bpf-decl")?;
    let conn = ns.connection()?;
    let actions = |pin: &BpfPin| -> Result<ActionList> {
        Ok(ActionList::new().with(BpfAction::from_pinned(&pin.path)?.name("act").build()))
    };
    let declared = actions(&one)?;
    let cfg = NetworkConfig::new()
        .link("d0", |l| l.dummy().up())
        .qdisc("d0", |q| q.clsact())
        .tc("d0", move |t| {
            t.filter(TcHandle::CLSACT_INGRESS, FilterPriority::new(1), EthProto::ALL, MatchallFilter::new().actions(declared.clone()))
        });
    let applied = cfg.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");
    assert!(cfg.diff(&conn).await?.is_empty(), "the declared action did not converge");

    ns.exec("tc", &["filter", "del", "dev", "d0", "ingress", "prio", "1"])?;
    conn.add_filter_full(
        "d0",
        TcHandle::CLSACT_INGRESS,
        None,
        EthProto::ALL,
        FilterPriority::new(1),
        MatchallFilter::new().actions(actions(&two)?),
    )
    .await?;
    assert!(!cfg.diff(&conn).await?.is_empty(), "another program compared equal");
    let applied = cfg.apply(&conn).await?;
    assert!(applied.is_success(), "{applied:?}");
    assert!(cfg.diff(&conn).await?.is_empty(), "did not converge");
    Ok(())
}

const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;

/// A program that returns 0, of a given type, pinned in bpffs and unpinned
/// on drop.
struct BpfPin {
    path: std::path::PathBuf,
}

impl BpfPin {
    fn load(tag: &str, prog_type: u32) -> Result<Self> {
        use std::os::fd::{FromRawFd, OwnedFd};
        // `union bpf_attr`'s BPF_PROG_LOAD and BPF_OBJ_* members, as far
        // as they are used.
        #[repr(C)]
        struct ProgLoad {
            prog_type: u32,
            insn_cnt: u32,
            insns: u64,
            license: u64,
            log_level: u32,
            log_size: u32,
            log_buf: u64,
            kern_version: u32,
            prog_flags: u32,
        }
        #[repr(C)]
        struct ObjPin {
            pathname: u64,
            bpf_fd: u32,
            file_flags: u32,
            path_fd: i32,
            pad: u32,
        }
        fn bpf<T>(cmd: libc::c_long, attr: &T) -> std::io::Result<i64> {
            // SAFETY: `attr` is a fully initialized `bpf_attr` prefix of
            // the size passed, and every pointer in it outlives the call.
            let ret = unsafe {
                libc::syscall(libc::SYS_bpf, cmd, attr as *const T, std::mem::size_of::<T>())
            };
            if ret < 0 { Err(std::io::Error::last_os_error()) } else { Ok(ret) }
        }
        // r0 = 0; exit. Byte 0 is the opcode on either byte order.
        let insns: [[u8; 8]; 2] = [[0xb7, 0, 0, 0, 0, 0, 0, 0], [0x95, 0, 0, 0, 0, 0, 0, 0]];
        let license = c"GPL";
        let load = ProgLoad {
            prog_type,
            insn_cnt: 2,
            insns: insns.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
        };
        let fd = bpf(5, &load)?;
        // SAFETY: the kernel just returned this fd; the pin keeps the
        // program once it closes.
        let prog = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        // Unique per run, not just per process: two CI containers running
        // the same steps get the same PID, and bpffs may be shared between
        // them, so one run's `remove_file` and `Drop` took the other's pin.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::path::PathBuf::from(format!(
            "/sys/fs/bpf/nlink-test-{}-{nanos}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let pin = ObjPin {
            pathname: cpath.as_ptr() as u64,
            bpf_fd: std::os::fd::AsRawFd::as_raw_fd(&prog) as u32,
            file_flags: 0,
            path_fd: 0,
            pad: 0,
        };
        bpf(6, &pin)?;
        Ok(Self { path })
    }
}

impl Drop for BpfPin {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The actions on each filter at `dev`'s clsact ingress, by priority,
/// without what tells two installs of one action apart (index,
/// references, position).
fn filter_actions(ns: &TestNamespace, dev: &str) -> Result<Vec<(u64, serde_json::Value)>> {
    let out = ns.exec("tc", &["-j", "filter", "show", "dev", dev, "ingress"])?;
    // iproute2 6.1 prints some kinds' options as text inside the JSON
    // (skbmod): read those filters' text instead.
    let Ok(listed) = serde_json::from_str::<serde_json::Value>(&out) else {
        return filter_actions_text(ns, dev);
    };
    let mut by_prio = Vec::new();
    for f in listed.as_array().into_iter().flatten() {
        let Some(actions) = f["options"]["actions"].as_array() else {
            continue;
        };
        let mut actions = actions.clone();
        for a in &mut actions {
            if let Some(o) = a.as_object_mut() {
                for volatile in ["order", "index", "ref", "bind", "not_in_hw", "used_hw_stats"] {
                    o.remove(volatile);
                }
            }
        }
        by_prio.push((f["pref"].as_u64().unwrap_or(0), serde_json::Value::Array(actions)));
    }
    Ok(by_prio)
}

/// [`filter_actions`] from `tc filter show`'s text: each filter's action
/// lines, without the index and reference counts.
fn filter_actions_text(ns: &TestNamespace, dev: &str) -> Result<Vec<(u64, serde_json::Value)>> {
    let out = ns.exec("tc", &["filter", "show", "dev", dev, "ingress"])?;
    let mut by_prio: Vec<(u64, String)> = Vec::new();
    for line in out.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"filter") {
            let pref = words.iter().position(|w| *w == "pref").and_then(|i| words.get(i + 1)?.parse().ok()).unwrap_or(0);
            if by_prio.last().is_none_or(|(p, _)| *p != pref) {
                by_prio.push((pref, String::new()));
            }
            continue;
        }
        let Some((_, text)) = by_prio.last_mut() else { continue };
        let mut rest = words.iter().copied();
        while let Some(w) = rest.next() {
            match w {
                "index" | "ref" | "bind" => {
                    rest.next();
                }
                "not_in_hw" | "in_hw" | "used_hw_stats" => {}
                w => {
                    text.push_str(w);
                    text.push(' ');
                }
            }
        }
    }
    Ok(by_prio
        .into_iter()
        .filter(|(_, text)| !text.is_empty())
        .map(|(pref, text)| (pref, serde_json::Value::String(text)))
        .collect())
}

/// One tc(8) action line installed by `tc` and by nlink's `parse_params`,
/// each on a matchall at `d0`'s clsact ingress, makes the same action: the
/// kernel lists the two alike. On filters rather than standalone: a
/// standalone action needs CAP_NET_ADMIN in the initial user namespace.
async fn same_as_tc(
    ns: &TestNamespace,
    kind: &str,
    line: &str,
    install: impl AsyncFnOnce(nlink::netlink::action::ActionList) -> Result<()>,
    parse: impl FnOnce(&[&str]) -> Result<nlink::netlink::action::ActionList>,
) -> Result<()> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut args = vec!["filter", "add", "dev", "d0", "ingress", "prio", "1", "matchall", "action", kind];
    args.extend(&words);
    ns.exec("tc", &args)?;
    install(parse(&words)?).await?;
    let listed = filter_actions(ns, "d0")?;
    assert_eq!(listed.len(), 2, "{kind} {line}: {listed:?}");
    assert_eq!(listed[0].1, listed[1].1, "{kind} {line}: tc's, then nlink's");
    ns.exec("tc", &["filter", "del", "dev", "d0", "ingress"])?;
    Ok(())
}

/// A namespace with `d0` up and a clsact on it, and a way to put a
/// matchall carrying `actions` at prio 2 on its ingress.
async fn clsact_d0(prefix: &str) -> Result<(TestNamespace, Connection<Route>, u32)> {
    let ns = TestNamespace::new(prefix)?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.set_link_up("d0").await?;
    ns.exec("tc", &["qdisc", "add", "dev", "d0", "clsact"])?;
    let d0 = conn.get_link_by_name("d0").await?.expect("d0").ifindex();
    Ok((ns, conn, d0))
}

async fn matchall_at_prio_2(
    conn: &Connection<Route>,
    d0: u32,
    actions: nlink::netlink::action::ActionList,
) -> Result<()> {
    conn.add_filter_by_index_full(
        d0,
        TcHandle::CLSACT_INGRESS,
        None,
        nlink::EthProto::ALL,
        nlink::FilterPriority::new(2),
        MatchallFilter::new().actions(actions),
    )
    .await
}

/// #792: a police action's average rate installs when the filter gives
/// its actions a rate estimator, and makes what tc(8)'s
/// `estimator 1sec 8sec` makes. The kernel takes `avrate` only with an
/// estimator, which goes on the filter request as `TCA_RATE`; nlink could
/// not send one, so every filter with an `avrate` police failed with a bare
/// `EINVAL`.
#[tokio::test]
async fn a_police_avrate_installs_with_an_estimator() -> Result<()> {
    use nlink::netlink::action::{ActionList, Estimator, PoliceAction};
    use nlink::{Bytes, Rate};
    require_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_police");

    let (ns, conn, d0) = clsact_d0("tc-avrate").await?;
    let shaped = || PoliceAction::new().rate(Rate::mbit(1)).burst(Bytes::kib(32)).avrate(Rate::mbit(2));
    let err = matchall_at_prio_2(&conn, d0, ActionList::new().with(shaped()))
        .await
        .expect_err("the kernel refuses an avrate without an estimator");
    assert!(err.is_invalid_argument(), "{err}");

    // iproute2 6.15 refuses `rate` with `avrate`, so the line tc and nlink
    // both make has the average rate alone. Its mtu and verdict are given:
    // nlink's defaults for them are not tc's (#800).
    let line = "avrate 1mbit mtu 2047 conform-exceed drop";
    let mut args = vec!["filter", "add", "dev", "d0", "ingress", "prio", "1", "estimator", "1sec", "8sec", "matchall", "action", "police"];
    args.extend(line.split_whitespace());
    ns.exec("tc", &args)?;
    let estimator = Estimator::parse_params(&["1sec", "8sec"])?;
    let alone = PoliceAction::parse_params(&line.split_whitespace().collect::<Vec<_>>())?;
    matchall_at_prio_2(&conn, d0, ActionList::new().with_estimator(estimator).with(alone)).await?;
    // The police lines without their index (`police 0x1`).
    let police_lines = || -> Result<Vec<String>> {
        let shown = ns.exec("tc", &["filter", "show", "dev", "d0", "ingress"])?;
        Ok(shown
            .lines()
            .filter_map(|l| l.split_once(" police 0x").map(|(_, rest)| rest.split_once(' ').map_or("", |r| r.1).to_string()))
            .collect())
    };
    let lines = police_lines()?;
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], lines[1], "tc's, then nlink's");
    assert!(lines[0].contains("avrate 1Mbit"), "{lines:?}");

    // The kernel takes a rate with it, which tc does not let it send.
    ns.exec("tc", &["filter", "del", "dev", "d0", "ingress"])?;
    matchall_at_prio_2(&conn, d0, ActionList::new().with_estimator(estimator).with(shaped())).await?;
    let lines = police_lines()?;
    assert!(lines.len() == 1 && lines[0].contains("rate 1Mbit") && lines[0].contains("avrate 2Mbit"), "{lines:?}");
    Ok(())
}

/// #811: a tunnel_key action's key id is the one asked for. nlink sent it as
/// 8 bytes where the kernel reads a `__be32`, so it installed key id 0.
#[tokio::test]
async fn a_tunnel_keys_id_is_installed_as_tc_installs_it() -> Result<()> {
    use nlink::netlink::action::{ActionList, TunnelKeyAction};
    require_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_tunnel_key");

    let (ns, conn, d0) = clsact_d0("tc-tunkey").await?;
    // tc reads `src` as an abbreviation of `src_ip`, its own word (#811).
    for line in ["set src 10.0.0.1 dst 10.0.0.2 id 100 dst_port 4789", "set dst_ip 10.0.0.2 src_ip 10.0.0.1 id 4096"] {
        same_as_tc(&ns, "tunnel_key", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(TunnelKeyAction::parse_params(w)?))
        })
        .await?;
    }
    Ok(())
}

/// One tc(8) qdisc line installed at `dummy0`'s root by `tc` and by nlink
/// makes the same qdisc: `tc -j` reports the same options for both.
async fn qdisc_same_as_tc(
    ns: &TestNamespace,
    conn: &Connection<Route>,
    kind: &str,
    line: &str,
    config: impl nlink::netlink::tc::QdiscConfig,
) -> Result<()> {
    let options = || -> Result<serde_json::Value> {
        let out = ns.exec("tc", &["-j", "qdisc", "show", "dev", "dummy0", "root"])?;
        let listed: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| nlink::Error::invalid_message(format!("{e}: {out}")))?;
        Ok(listed[0]["options"].clone())
    };
    let mut args = vec!["qdisc", "add", "dev", "dummy0", "root", kind];
    args.extend(line.split_whitespace());
    ns.exec("tc", &args)?;
    let theirs = options()?;
    ns.exec("tc", &["qdisc", "del", "dev", "dummy0", "root"])?;
    conn.add_qdisc("dummy0", config).await?;
    let ours = options()?;
    ns.exec("tc", &["qdisc", "del", "dev", "dummy0", "root"])?;
    assert_eq!(theirs, ours, "{kind} {line}: tc's, then nlink's");
    Ok(())
}

/// #806: an sfq's divisor, flows, depth and head drop are what tc(8)
/// makes of the same words. `SfqConfig` could not say them, and sent the
/// v0 struct, from which the kernel takes no depth or head drop.
#[tokio::test]
async fn sfq_divisor_flows_depth_and_headdrop_are_tcs() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_sfq");

    let (ns, conn) = setup_tc_ns("tc-sfq-opts").await?;
    for line in ["divisor 512 flows 64 depth 32 headdrop", "limit 100 depth 10", "flows 200 quantum 3000", "perturb 10"] {
        let words: Vec<&str> = line.split_whitespace().collect();
        qdisc_same_as_tc(&ns, &conn, "sfq", line, SfqConfig::parse_params(&words)?).await?;
    }
    Ok(())
}

/// #806: an fq_codel's drop batch and CE threshold selector, and a TBF's
/// overhead, mpu and link layer, are what tc(8) makes of the same words.
/// The configs could not say them.
#[tokio::test]
async fn fq_codel_and_tbf_framing_are_tcs() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_fq_codel", "sch_tbf");

    let (ns, conn) = setup_tc_ns("tc-qdisc-opts").await?;
    for line in ["drop_batch 32", "ce_threshold 2ms ce_threshold_selector 0x01/0x01", "ce_threshold 2ms ce_threshold_selector 0x04/0xfc"] {
        let words: Vec<&str> = line.split_whitespace().collect();
        qdisc_same_as_tc(&ns, &conn, "fq_codel", line, FqCodelConfig::parse_params(&words)?).await?;
    }
    for line in [
        "rate 1mbit burst 32k limit 64k overhead 24 mpu 64",
        "rate 1mbit burst 32k limit 64k linklayer atm",
        "rate 10mbit burst 64k limit 128k peakrate 20mbit mtu 2k overhead 8",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        qdisc_same_as_tc(&ns, &conn, "tbf", line, TbfConfig::parse_params(&words)?).await?;
    }
    Ok(())
}

/// #816: an skbmod ethertype and an ife type and `use` value are what tc
/// installs. nlink sent them big-endian where the kernel reads host order,
/// so `set etype 0x88b5` installed 0xb588 and `use mark 5` mark 5 << 24.
#[tokio::test]
async fn skbmod_and_ife_values_install_as_tcs() -> Result<()> {
    use nlink::netlink::action::{ActionList, IfeAction, SkbmodAction};
    require_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_skbmod", "act_ife");

    let (ns, conn, d0) = clsact_d0("tc-byteorder").await?;
    for line in ["set smac 02:00:00:00:00:02 set etype 0x88b5", "set etype 0x0800"] {
        same_as_tc(&ns, "skbmod", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(SkbmodAction::parse_params(w)?))
        })
        .await?;
    }
    for line in ["encode type 0xed3e use mark 5", "encode use prio 7", "encode allow mark"] {
        same_as_tc(&ns, "ife", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(IfeAction::parse_params(w)?))
        })
        .await?;
    }
    Ok(())
}

/// Every qdisc kind's tc(8) lines make, through nlink's `parse_params`, the
/// qdisc tc makes of them: `tc -j` lists the same options for both. The
/// qdisc side of the action sweep (#817); kinds were checked one by one as
/// each bug came (#806).
#[tokio::test]
async fn every_qdisc_kinds_lines_install_as_tcs() -> Result<()> {
    use nlink::netlink::tc::*;
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_prio", "sch_multiq", "sch_sfq", "sch_tbf", "sch_htb", "sch_hfsc", "sch_drr", "sch_qfq",
        "sch_red", "sch_choke", "sch_gred", "sch_sfb", "sch_codel", "sch_fq_codel", "sch_fq", "sch_pie",
        "sch_fq_pie", "sch_hhf", "sch_cake", "sch_netem", "sch_etf", "sch_cbs", "sch_skbprio", "sch_plug",
        "sch_ets", "sch_mqprio", "sch_taprio"
    );

    // (device, kind, line): `mq0` has four TX queues, for the kinds that
    // want a multiqueue device.
    let rows: &[(&str, &str, &str)] = &[
        ("dummy0", "pfifo", "limit 100"),
        ("dummy0", "bfifo", "limit 10000"),
        ("dummy0", "bfifo", "limit 10kb"),
        ("dummy0", "pfifo_fast", ""),
        ("dummy0", "prio", "bands 4"),
        ("dummy0", "prio", "bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"),
        ("dummy0", "sfq", ""),
        ("dummy0", "sfq", "limit 100 perturb 10 quantum 1514"),
        ("dummy0", "tbf", "rate 1mbit burst 10kb limit 20kb"),
        ("dummy0", "tbf", "rate 1mbit burst 10kb latency 50ms"),
        ("dummy0", "tbf", "rate 1mbit burst 10kb peakrate 2mbit mtu 2000 latency 50ms"),
        ("dummy0", "htb", "default 10"),
        ("dummy0", "htb", "r2q 5 default 20 direct_qlen 100"),
        ("dummy0", "hfsc", "default 10"),
        ("dummy0", "drr", ""),
        ("dummy0", "qfq", ""),
        // Not `adaptive`: adaptive RED retunes max_P every 500 ms while the
        // queue idles, so a slow dump would differ from a quick one.
        ("dummy0", "red", "limit 400000 min 30000 max 90000 avpkt 1000 burst 55 probability 0.02 bandwidth 10mbit ecn"),
        ("dummy0", "red", "limit 400000 min 30000 max 90000 avpkt 1000 burst 55 bandwidth 10mbit harddrop"),
        ("dummy0", "red", "limit 400000 avpkt 1000"),
        ("dummy0", "red", "limit 1mb avpkt 1500 min 100kb nodrop ecn"),
        ("dummy0", "choke", "limit 1000 min 100 max 300 avpkt 1000 burst 200 bandwidth 10mbit probability 0.1 ecn"),
        ("dummy0", "choke", "limit 1000 bandwidth 10mbit"),
        ("dummy0", "gred", "setup vqs 4 default 1"),
        ("dummy0", "gred", "setup vqs 4 default 1 grio"),
        ("dummy0", "gred", "setup vqs 2 default 0 limit 100000 ecn harddrop"),
        ("dummy0", "sfb", "limit 1000"),
        ("dummy0", "sfb", "target 40"),
        ("dummy0", "sfb", "rehash 600 db 60 limit 1000 max 25 target 20 increment 0.0005 decrement 0.00005 penalty_rate 10 penalty_burst 20"),
        ("dummy0", "codel", "limit 1000 target 5ms interval 100ms ecn"),
        ("dummy0", "codel", "ce_threshold 1ms noecn"),
        ("dummy0", "fq_codel", "limit 1000 flows 2048 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn"),
        ("dummy0", "fq", "limit 1000 flow_limit 50 quantum 3028 initial_quantum 15140 maxrate 100mbit buckets 2048 orphan_mask 1023 nopacing"),
        ("dummy0", "fq", "low_rate_threshold 550kbit horizon 10s horizon_drop ce_threshold 4ms"),
        ("dummy0", "fq", "buckets 1000 horizon 2s horizon_cap timer_slack 20us"),
        ("dummy0", "pie", "limit 1000 target 15ms tupdate 15ms alpha 2 beta 20 ecn bytemode"),
        ("dummy0", "pie", "dq_rate_estimator"),
        ("dummy0", "pie", "limit 500 no_dq_rate_estimator"),
        ("dummy0", "fq_pie", "limit 1000 flows 1024 target 15ms tupdate 15ms alpha 2 beta 20 quantum 1514 memory_limit 32Mb ecn_prob 10 ecn bytemode dq_rate_estimator"),
        ("dummy0", "hhf", "limit 500"),
        ("dummy0", "hhf", "limit 1000 quantum 1514 hh_limit 2048 reset_timeout 40ms admit_bytes 131072 evict_timeout 1s non_hh_weight 2"),
        ("dummy0", "cake", "bandwidth 100mbit"),
        ("dummy0", "cake", "unlimited besteffort"),
        ("dummy0", "cake", "bandwidth 50mbit diffserv4 nat wash ack-filter"),
        ("dummy0", "cake", "rtt 50ms overhead 18 mpu 64 noatm"),
        ("dummy0", "cake", "bandwidth 10mbit ethernet"),
        ("dummy0", "cake", "bandwidth 10mbit docsis ingress"),
        ("dummy0", "cake", "triple-isolate split-gso memlimit 4mb fwmark 0xff"),
        ("dummy0", "cake", "bandwidth 20mbit conservative"),
        ("dummy0", "cake", "bandwidth 20mbit overhead 10 ether-vlan pppoe-ptm"),
        ("dummy0", "cake", "bandwidth 20mbit bridged-llcsnap"),
        ("dummy0", "cake", "bandwidth 20mbit raw"),
        ("dummy0", "netem", "delay 10ms"),
        ("dummy0", "netem", "delay 10ms 2ms 25%"),
        ("dummy0", "netem", "loss 1%"),
        ("dummy0", "netem", "loss 0.5% 25%"),
        ("dummy0", "netem", "duplicate 1% corrupt 0.1%"),
        ("dummy0", "netem", "delay 10ms reorder 25% 50% gap 5"),
        ("dummy0", "netem", "rate 1mbit 20 100 5"),
        ("dummy0", "netem", "slot 10ms 20ms packets 10 bytes 1000"),
        ("dummy0", "netem", "loss state 1% 2% 3% 4% 5%"),
        ("dummy0", "netem", "loss gemodel 1% 10% 70% 0.1%"),
        ("dummy0", "netem", "limit 2000 ecn loss 1%"),
        ("dummy0", "etf", "clockid CLOCK_TAI delta 300000"),
        ("dummy0", "etf", "clockid CLOCK_TAI delta 300000 deadline_mode"),
        ("dummy0", "cbs", "idleslope 1000 sendslope -9000 hicredit 30 locredit -1470"),
        ("dummy0", "skbprio", "limit 100"),
        ("dummy0", "plug", ""),
        ("dummy0", "ets", "bands 3"),
        ("dummy0", "ets", "bands 4 strict 2 quanta 1500 1500 priomap 0 1 2 3"),
        ("mq0", "mq", ""),
        ("mq0", "multiq", ""),
        ("mq0", "mqprio", "num_tc 2 map 0 0 0 0 1 1 1 1 queues 1@0 1@1 hw 0"),
        ("mq0", "mqprio", "num_tc 2 map 1 0 queues 2@0 2@2 hw 0"),
        (
            "mq0",
            "taprio",
            "num_tc 2 map 0 1 queues 1@0 1@1 base-time 1000 sched-entry S 01 300000 sched-entry S 02 300000 clockid CLOCK_TAI",
        ),
    ];

    let (ns, conn) = setup_tc_ns("tc-qdisc-sweep").await?;
    ns.exec("ip", &["link", "add", "mq0", "numtxqueues", "4", "numrxqueues", "4", "type", "dummy"])?;
    ns.exec("ip", &["link", "set", "mq0", "up"])?;
    // Some kinds' `tc -j` is not JSON (hfsc prints its text inside
    // `options`): those compare by tc's text after the handle.
    let options = |dev: &str| -> Result<serde_json::Value> {
        // Details: red's and choke's derived logs show only with -d.
        let out = ns.exec("tc", &["-d", "-j", "qdisc", "show", "dev", dev, "root"])?;
        if let Ok(mut listed) = serde_json::from_str::<serde_json::Value>(&out) {
            // A netem's seed is random unless given.
            if let Some(options) = listed[0]["options"].as_object_mut() {
                options.remove("seed");
            }
            return Ok(listed[0]["options"].take());
        }
        let out = ns.exec("tc", &["-d", "qdisc", "show", "dev", dev, "root"])?;
        Ok(serde_json::Value::String(out.split_once("refcnt").map_or(&*out, |(_, rest)| rest).trim().to_string()))
    };
    let mut failed = Vec::new();
    for &(dev, kind, line) in rows {
        let words: Vec<&str> = line.split_whitespace().collect();
        let mut args = vec!["qdisc", "add", "dev", dev, "root", kind];
        args.extend(&words);
        if let Err(e) = ns.exec("tc", &args) {
            failed.push(format!("{kind} {line}: tc refused it: {e}"));
            continue;
        }
        let theirs = options(dev)?;
        ns.exec("tc", &["qdisc", "del", "dev", dev, "root"])?;
        macro_rules! install {
            ($ty:ty) => {
                match <$ty>::parse_params(&words) {
                    Ok(config) => conn.add_qdisc(dev, config).await,
                    Err(e) => {
                        failed.push(format!("{kind} {line}: nlink refused it: {e}"));
                        continue;
                    }
                }
            };
        }
        let added = match kind {
            "pfifo" => install!(PfifoConfig),
            "bfifo" => install!(BfifoConfig),
            "pfifo_fast" => install!(PfifoFastConfig),
            "prio" => install!(PrioConfig),
            "sfq" => install!(SfqConfig),
            "tbf" => install!(TbfConfig),
            "htb" => install!(HtbQdiscConfig),
            "hfsc" => install!(HfscConfig),
            "drr" => install!(DrrConfig),
            "qfq" => install!(QfqConfig),
            "red" => install!(RedConfig),
            "choke" => install!(ChokeConfig),
            "gred" => install!(GredConfig),
            "sfb" => install!(SfbConfig),
            "codel" => install!(CodelConfig),
            "fq_codel" => install!(FqCodelConfig),
            "fq" => install!(FqConfig),
            "pie" => install!(PieConfig),
            "fq_pie" => install!(FqPieConfig),
            "hhf" => install!(HhfConfig),
            "cake" => install!(CakeConfig),
            "netem" => install!(NetemConfig),
            "etf" => install!(EtfConfig),
            "cbs" => install!(CbsConfig),
            "skbprio" => install!(SkbprioConfig),
            "plug" => install!(PlugConfig),
            "ets" => install!(EtsConfig),
            "mq" => install!(MqConfig),
            "multiq" => install!(MultiqConfig),
            "mqprio" => install!(MqprioConfig),
            "taprio" => install!(TaprioConfig),
            other => panic!("no parser for {other}"),
        };
        if let Err(e) = added {
            failed.push(format!("{kind} {line}: the kernel refused nlink's: {e}"));
            continue;
        }
        let ours = options(dev)?;
        ns.exec("tc", &["qdisc", "del", "dev", dev, "root"])?;
        if theirs != ours {
            failed.push(format!("{kind} {line}:\n  tc:    {theirs}\n  nlink: {ours}"));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// tc(8) arguments from a line: words, but a parenthesised ematch
/// (`cmp(u8 at 9 layer network eq 6)`) stays one, as the shell quotes it.
fn tc_words(line: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut depth = 0usize;
    for w in line.split_whitespace() {
        match words.last_mut() {
            Some(last) if depth > 0 => {
                last.push(' ');
                last.push_str(w);
            }
            _ => words.push(w.to_string()),
        }
        depth = (depth + w.matches('(').count()).saturating_sub(w.matches(')').count());
    }
    words
}

/// Every class kind's tc(8) lines make, through nlink's `parse_params`, the
/// class tc makes of them: `tc -d class show` lists the same. The class
/// side of the qdisc and action sweeps (#817, #820).
#[tokio::test]
async fn every_class_kinds_lines_install_as_tcs() -> Result<()> {
    use nlink::netlink::tc::{DrrClassConfig, HfscClassConfig, HtbClassConfig, QfqClassConfig};
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_hfsc", "sch_drr", "sch_qfq");

    let rows: &[(&str, &str)] = &[
        ("htb", "rate 1mbit"),
        ("htb", "rate 1mbit ceil 2mbit burst 15k cburst 15k prio 1 quantum 1514"),
        ("htb", "rate 1mbit linklayer atm overhead 10 mpu 64"),
        ("htb", "rate 10mbit mtu 9000"),
        ("hfsc", "sc rate 1mbit ul rate 2mbit"),
        ("hfsc", "rt m1 2mbit d 10ms m2 1mbit"),
        ("hfsc", "ls umax 1500b dmax 10ms rate 1mbit"),
        ("hfsc", "sc umax 1500 dmax 50ms rate 10mbit ul m2 20mbit"),
        ("drr", "quantum 1514"),
        ("drr", ""),
        ("qfq", "weight 10 maxpkt 2000"),
        ("qfq", "weight 1"),
    ];

    let (ns, conn) = setup_tc_ns("tc-class-sweep").await?;
    let shown = || ns.exec("tc", &["-d", "class", "show", "dev", "dummy0", "classid", "1:10"]);
    let mut failed = Vec::new();
    for &(kind, line) in rows {
        let words: Vec<&str> = line.split_whitespace().collect();
        // A fresh qdisc each time: htb has no change operation.
        let _ = ns.exec("tc", &["qdisc", "del", "dev", "dummy0", "root"]);
        ns.exec("tc", &["qdisc", "add", "dev", "dummy0", "root", "handle", "1:", kind])?;
        let mut args = vec!["class", "add", "dev", "dummy0", "parent", "1:", "classid", "1:10", kind];
        args.extend(&words);
        if let Err(e) = ns.exec("tc", &args) {
            failed.push(format!("{kind} {line}: tc refused it: {e}"));
            continue;
        }
        let theirs = shown()?;
        ns.exec("tc", &["class", "del", "dev", "dummy0", "classid", "1:10"])?;
        macro_rules! install {
            ($ty:ty) => {
                match <$ty>::parse_params(&words) {
                    Ok(config) => conn.add_class("dummy0", TcHandle::major_only(1), TcHandle::new(1, 0x10), config).await,
                    Err(e) => {
                        failed.push(format!("{kind} {line}: nlink refused it: {e}"));
                        continue;
                    }
                }
            };
        }
        let added = match kind {
            "htb" => install!(HtbClassConfig),
            "hfsc" => install!(HfscClassConfig),
            "drr" => install!(DrrClassConfig),
            "qfq" => install!(QfqClassConfig),
            other => panic!("no parser for {other}"),
        };
        if let Err(e) = added {
            failed.push(format!("{kind} {line}: the kernel refused nlink's: {e}"));
            continue;
        }
        let ours = shown()?;
        ns.exec("tc", &["class", "del", "dev", "dummy0", "classid", "1:10"])?;
        if theirs != ours {
            failed.push(format!("{kind} {line}:\n  tc:    {}\n  nlink: {}", theirs.trim(), ours.trim()));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// Every filter kind's tc(8) lines make, through nlink's `parse_params`,
/// the filter tc makes of them: `tc -d filter show` lists the same. The
/// filter side of the qdisc and action sweeps (#817, #820); flower's
/// ordinary lines are `flower_lines_install_the_same_through_tc_and_nlink`.
#[tokio::test]
async fn every_filter_kinds_lines_install_as_tcs() -> Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_htb", "cls_u32", "cls_fw", "cls_route", "cls_basic", "cls_matchall", "cls_flow", "cls_flower",
        "em_cmp", "em_u32"
    );

    // (kind, protocol, handle, line)
    let rows: &[(&str, &str, Option<&str>, &str)] = &[
        ("u32", "ip", None, "match ip dst 10.0.0.1/32 classid 1:10"),
        ("u32", "ip", None, "match ip src 10.0.0.0/24 match ip dport 80 0xffff classid 1:10"),
        ("u32", "ip", None, "match ip protocol 6 0xff match tcp dst 443 0xffff flowid 1:10"),
        ("u32", "ip", None, "match u32 0x0a000001 0xffffffff at 16 classid 1:10"),
        ("u32", "ip", None, "match u16 0x0050 0xffff at 22 classid 1:10"),
        ("u32", "ip", None, "match u16 80 0xffff at 22 classid 1:10"),
        ("u32", "ip", None, "match mark 16 255 classid 1:10"),
        ("u32", "ip", None, "match ip dst 0.0.0.0/0 classid 1:10"),
        ("u32", "ip", None, "match ip sport 80 0xffff match ip dport 443 0xffff classid 1:10"),
        ("u32", "ip", None, "match ip nofrag match ip df classid 1:10"),
        ("u32", "ip", None, "match ip ihl 5 0xf match ip dsfield 0x20 0xfc classid 1:10"),
        ("u32", "ip", None, "match icmp type 8 0xff match icmp code 0 0xff classid 1:10"),
        ("u32", "ip", None, "match u8 0x06 0xff at 9 classid 1:10"),
        ("u32", "ip", None, "match mark 0x10 0xff classid 1:10"),
        ("u32", "ip", None, "match ip tos 0x10 0xff classid 1:10"),
        ("u32", "ip", None, "match ip icmp_type 8 0xff classid 1:10"),
        ("u32", "ip", None, "match ip sport 1024 0xfc00 classid 1:10"),
        ("u32", "ipv6", None, "match ip6 dst fd00::1/128 classid 1:10"),
        ("u32", "ipv6", None, "match ip6 protocol 17 0xff match ip6 dport 53 0xffff classid 1:10"),
        ("u32", "ipv6", None, "match ip6 src fd00:1::/40 match ip6 priority 0x10 0xff classid 1:10"),
        ("u32", "ipv6", None, "match ip6 flowlabel 0x12345 0xfffff match ip6 icmp_type 128 0xff classid 1:10"),
        ("u32", "all", None, "match ether dst 02:00:00:00:00:01 classid 1:10"),
        // Before the network header: the ethertype (#835).
        ("u32", "all", None, "match u16 0x0800 0xffff at -2 classid 1:10"),
        ("u32", "all", None, "match u8 0x02 0xff at -0xe classid 1:10"),
        ("u32", "all", None, "match ether src 02:00:00:00:00:02 classid 1:10"),
        ("fw", "ip", Some("0x10"), "classid 1:10"),
        ("fw", "ip", Some("0x10"), "indev lo classid 1:10"),
        ("route", "ip", None, "to 10 classid 1:10"),
        ("route", "ip", None, "from 5 classid 1:10"),
        ("route", "ip", None, "to 10 from 5 classid 1:10"),
        ("route", "ip", None, "fromif lo classid 1:10"),
        ("route", "ip", None, "to 10 order 5 classid 1:10"),
        ("basic", "ip", None, "classid 1:10"),
        // tc-ematch(8) expressions (#828).
        ("basic", "ip", None, "match cmp(u8 at 9 layer network eq 6) classid 1:10"),
        ("basic", "ip", None, "match u32(u32 0x0a000001 0xffffffff at 16) classid 1:10"),
        ("basic", "ip", None, "match u32(u16 0x0050 0xffff at 22) classid 1:10"),
        ("basic", "ip", None, "match cmp(u16 at 2 layer transport eq 80) and cmp(u8 at 9 layer network eq 6) classid 1:10"),
        ("basic", "ip", None, "match not cmp(u8 at 9 layer network eq 17) or u32(u8 0x06 0xff at 9) classid 1:10"),
        ("basic", "ip", None, "match cmp(u32 at 12 layer network mask 0xffffff00 trans gt 167772160) classid 1:10"),
        ("matchall", "all", None, "classid 1:10"),
        // flower's keys beyond flower_lines_install_the_same_through_tc_and_nlink's (#827).
        ("flower", "ip", None, "ip_proto icmp type 8 code 0 classid 1:10"),
        ("flower", "ipv6", None, "ip_proto icmpv6 type 128/255 classid 1:10"),
        ("flower", "ip", None, "ip_flags frag/nofirstfrag classid 1:10"),
        ("flower", "ip", None, "ct_state +trk+est-new classid 1:10"),
        ("flower", "ip", None, "ct_mark 5/0xff ct_zone 3 classid 1:10"),
        ("flower", "ip", None, "ct_label 0102030405060708090a0b0c0d0e0f10 classid 1:10"),
        ("flower", "ip", None, "enc_key_id 100 enc_dst_ip 10.0.0.1 enc_src_ip 10.0.0.0/24 enc_dst_port 4789 classid 1:10"),
        ("flower", "ip", None, "enc_dst_ip fd00::1 enc_tos 0x10/0xfc enc_ttl 64 classid 1:10"),
        ("flower", "mpls_uc", None, "mpls_label 100 mpls_tc 3 mpls_bos 1 mpls_ttl 64 classid 1:10"),
        ("flower", "arp", None, "arp_op request arp_sip 10.0.0.1 arp_tip 10.0.0.0/24 classid 1:10"),
        ("flower", "arp", None, "arp_op reply arp_sha 02:00:00:00:00:01 arp_tha 02:00:00:00:00:00/24 classid 1:10"),
        ("flower", "802.1q", None, "vlan_id 10 vlan_ethtype ip src_ip 10.0.0.1 classid 1:10"),
        ("flower", "802.1q", None, "vlan_id 10 vlan_ethtype ipv6 ip_proto tcp dst_port 443 classid 1:10"),
        ("flower", "802.1ad", None, "vlan_id 10 vlan_ethtype 802.1q cvlan_id 20 cvlan_prio 3 cvlan_ethtype ip classid 1:10"),
        ("flower", "ip", None, "dst_mac 02:00:00:00:00:00/ff:ff:ff:00:00:00 classid 1:10"),
        ("flower", "ip", None, "src_mac 02:00:00:00:00:00/24 classid 1:10"),
        ("flower", "ip", None, "indev lo classid 1:10"),
        ("flow", "ip", Some("1"), "map key mark and 0xff baseclass 1:1 divisor 16"),
        ("flow", "ip", Some("1"), "map key priority or 0x10 xor 0x1 rshift 2 addend 3 baseclass 1:1 divisor 64"),
    ];

    filter_lines_same_as_tc("tc-filter-sweep", rows).await
}

/// flow's hash mode, which the kernel refuses in a user namespace other
/// than the initial one (`EOPNOTSUPP`, rootless containers included).
#[tokio::test]
async fn flow_hash_lines_install_as_tcs() -> Result<()> {
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flow");
    let rows: &[(&str, &str, Option<&str>, &str)] = &[
        ("flow", "ip", Some("1"), "hash keys src,dst divisor 1024 baseclass 1:10"),
        ("flow", "ip", Some("1"), "hash keys src,dst,proto,proto-src,proto-dst divisor 256 perturb 10 baseclass 1:1"),
    ];
    filter_lines_same_as_tc("tc-flow-hash", rows).await
}

/// Installs each `(kind, protocol, handle, line)` through `tc` and through
/// nlink's `parse_params` on an HTB root, and fails with every line whose
/// `tc -d filter show` differs.
async fn filter_lines_same_as_tc(label: &str, rows: &[(&str, &str, Option<&str>, &str)]) -> Result<()> {
    use nlink::netlink::filter::{BasicFilter, FlowFilter, FlowerFilter, FwFilter, MatchallFilter, RouteFilter, U32Filter};
    let (ns, conn) = setup_tc_ns(label).await?;
    ns.exec("tc", &["qdisc", "add", "dev", "dummy0", "root", "handle", "1:", "htb"])?;
    for class in ["1:1", "1:10"] {
        ns.exec("tc", &["class", "add", "dev", "dummy0", "parent", "1:", "classid", class, "htb", "rate", "10mbit"])?;
    }
    let shown = || ns.exec("tc", &["-d", "filter", "show", "dev", "dummy0", "parent", "1:"]);
    let mut failed = Vec::new();
    for &(kind, proto, handle, line) in rows {
        let words = tc_words(line);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let mut args = vec!["filter", "add", "dev", "dummy0", "parent", "1:", "protocol", proto, "prio", "1"];
        if let Some(handle) = handle {
            args.extend(["handle", handle]);
        }
        args.push(kind);
        args.extend(&words);
        if let Err(e) = ns.exec("tc", &args) {
            failed.push(format!("{kind} {line}: tc refused it: {e}"));
            continue;
        }
        let theirs = shown()?;
        ns.exec("tc", &["filter", "del", "dev", "dummy0", "parent", "1:"])?;
        let protocol: nlink::EthProto = proto.parse()?;
        let handle = handle.map(|h| TcHandle::from_raw(u32::from_str_radix(h.trim_start_matches("0x"), 16).expect("hex")));
        macro_rules! install {
            ($ty:ty) => {
                match <$ty>::parse_params(&words) {
                    Ok(config) => {
                        conn.add_filter_full(
                            "dummy0",
                            TcHandle::major_only(1),
                            handle,
                            protocol,
                            nlink::FilterPriority::new(1),
                            config,
                        )
                        .await
                    }
                    Err(e) => {
                        failed.push(format!("{kind} {line}: nlink refused it: {e}"));
                        continue;
                    }
                }
            };
        }
        let added = match kind {
            "u32" => install!(U32Filter),
            "fw" => install!(FwFilter),
            "route" => install!(RouteFilter),
            "basic" => install!(BasicFilter),
            "matchall" => install!(MatchallFilter),
            "flow" => install!(FlowFilter),
            "flower" => install!(FlowerFilter),
            other => panic!("no parser for {other}"),
        };
        if let Err(e) = added {
            failed.push(format!("{kind} {line}: the kernel refused nlink's: {e}"));
            continue;
        }
        let ours = shown()?;
        ns.exec("tc", &["filter", "del", "dev", "dummy0", "parent", "1:"])?;
        if theirs != ours {
            failed.push(format!("{kind} {line}:\n  tc:    {}\n  nlink: {}", theirs.trim(), ours.trim()));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}


/// #828: a basic filter with a u32 ematch from the builder installs, and
/// matches what tc's line for it matches. nlink sent the ematch's key as 12
/// bytes, which the kernel refuses for want of the `offmask` that ends a
/// `struct tc_u32_key`, and in host order where the packet's word is
/// big-endian.
#[tokio::test]
async fn a_basic_filters_u32_ematch_installs_as_tcs() -> Result<()> {
    use nlink::netlink::filter::{BasicFilter, Ematch, EmatchU32};
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_basic", "em_u32");

    let (ns, conn) = setup_tc_ns("tc-em-u32").await?;
    ns.exec("tc", &["qdisc", "add", "dev", "dummy0", "root", "handle", "1:", "htb"])?;
    ns.exec("tc", &["class", "add", "dev", "dummy0", "parent", "1:", "classid", "1:10", "htb", "rate", "10mbit"])?;
    let shown = || ns.exec("tc", &["-d", "filter", "show", "dev", "dummy0", "parent", "1:"]);
    ns.exec(
        "tc",
        &["filter", "add", "dev", "dummy0", "parent", "1:", "protocol", "ip", "prio", "1", "basic", "match", "u32(u8 0x06 0xff at 9)", "classid", "1:10"],
    )?;
    let theirs = shown()?;
    ns.exec("tc", &["filter", "del", "dev", "dummy0", "parent", "1:"])?;
    // The IP protocol: byte 9, the second of the word at offset 8.
    let filter = BasicFilter::new()
        .classid(TcHandle::new(1, 0x10))
        .ematch(Ematch::u32(EmatchU32 { mask: 0x00ff_0000, value: 0x0006_0000, offset: 8 }));
    conn.add_filter_full("dummy0", TcHandle::major_only(1), None, nlink::EthProto::IP, nlink::FilterPriority::new(1), filter)
        .await?;
    assert_eq!(shown()?, theirs);
    Ok(())
}

/// #819, #823: a red, a choke and a taprio from nlink's builders install.
/// The kernel refused red and choke without their idle-damping table,
/// which nlink did not send, and a taprio whose entries it skipped as the
/// wrong attribute; no test had installed one of the three.
#[tokio::test]
async fn red_choke_and_taprio_from_the_builders_install() -> Result<()> {
    use nlink::netlink::tc::{ChokeConfig, RedConfig, TaprioConfig};
    use nlink::netlink::types::tc::qdisc::taprio::TaprioSchedEntry;
    use nlink::{Bytes, Packets};
    require_root!();
    nlink::require_modules!("dummy", "sch_red", "sch_choke", "sch_taprio");

    let (ns, conn) = setup_tc_ns("tc-red-builders").await?;
    let shown = |dev: &str| ns.exec("tc", &["-d", "qdisc", "show", "dev", dev, "root"]);

    conn.add_qdisc("dummy0", RedConfig::new().limit(Bytes::new(400_000)).min(Bytes::new(30_000)).max(Bytes::new(90_000)))
        .await?;
    let red = shown("dummy0")?;
    // tc's arithmetic for these thresholds, avpkt 1000 and 10 Mbit.
    assert!(red.contains("min 30000b max 90000b") && red.contains("ewma 5"), "{red}");
    ns.exec("tc", &["qdisc", "del", "dev", "dummy0", "root"])?;

    conn.add_qdisc("dummy0", ChokeConfig::new().limit(Packets::new(1000)).min(Packets::new(100)).max(Packets::new(300)))
        .await?;
    let choke = shown("dummy0")?;
    assert!(choke.contains("limit 1000p min 100p max 300p"), "{choke}");
    ns.exec("tc", &["qdisc", "del", "dev", "dummy0", "root"])?;

    ns.exec("ip", &["link", "add", "mq0", "numtxqueues", "4", "type", "dummy"])?;
    let taprio = TaprioConfig::new()
        .num_tc(2)
        .map(&[0, 1])
        .queues(&[(1, 0), (1, 1)])
        .clockid(libc::CLOCK_TAI)
        .base_time(1000)
        .entry(TaprioSchedEntry::set_gates(0x1, 300_000))
        .entry(TaprioSchedEntry::set_gates(0x2, 300_000));
    conn.add_qdisc("mq0", taprio).await?;
    let taprio = shown("mq0")?;
    assert!(taprio.contains("gatemask 0x1") && taprio.contains("gatemask 0x2"), "{taprio}");
    Ok(())
}

/// Every action kind's tc(8) lines make, through nlink's `parse_params`,
/// the action tc makes of them. A sweep: the kinds were checked one at a
/// time, as each bug came, and a tunnel_key key id was 0 for every
/// release (#811), and seven kinds' parsers did not take tc's own words
/// for what they set (#817).
#[tokio::test]
async fn every_action_kinds_lines_install_as_tcs() -> Result<()> {
    use nlink::netlink::action::*;
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_ingress", "cls_matchall", "act_gact", "act_mirred", "act_vlan", "act_mpls", "act_skbmod",
        "act_skbedit", "act_connmark", "act_csum", "act_nat", "act_tunnel_key", "act_ct", "act_pedit",
        "act_simple", "act_sample", "act_gate", "act_ctinfo", "act_ife"
    );

    fn list(kind: &str, w: &[&str]) -> Result<ActionList> {
        Ok(match kind {
            "gact" => ActionList::new().with(GactAction::parse_params(w)?),
            "vlan" => ActionList::new().with(VlanAction::parse_params(w)?),
            "mpls" => ActionList::new().with(MplsAction::parse_params(w)?),
            "skbmod" => ActionList::new().with(SkbmodAction::parse_params(w)?),
            "skbedit" => ActionList::new().with(SkbeditAction::parse_params(w)?),
            "connmark" => ActionList::new().with(ConnmarkAction::parse_params(w)?),
            "csum" => ActionList::new().with(CsumAction::parse_params(w)?),
            "nat" => ActionList::new().with(NatAction::parse_params(w)?),
            "tunnel_key" => ActionList::new().with(TunnelKeyAction::parse_params(w)?),
            "ct" => ActionList::new().with(CtAction::parse_params(w)?),
            "pedit" => ActionList::new().with(PeditAction::parse_params(w)?),
            "simple" => ActionList::new().with(SimpleAction::parse_params(w)?),
            "sample" => ActionList::new().with(SampleAction::parse_params(w)?),
            "gate" => ActionList::new().with(GateAction::parse_params(w)?),
            "ctinfo" => ActionList::new().with(CtinfoAction::parse_params(w)?),
            "ife" => ActionList::new().with(IfeAction::parse_params(w)?),
            other => panic!("no parser for {other}"),
        })
    }
    let rows: &[(&str, &str)] = &[
        ("gact", "drop"),
        ("gact", "pass random determ drop 10"),
        ("vlan", "pop"),
        ("vlan", "push id 100"),
        ("vlan", "push id 100 protocol 802.1ad priority 3"),
        ("vlan", "modify id 200"),
        ("mpls", "push label 100 ttl 64 tc 3"),
        ("mpls", "pop protocol ipv4"),
        ("mpls", "modify label 200"),
        ("mpls", "dec_ttl"),
        ("skbmod", "set dmac 02:00:00:00:00:01"),
        ("skbmod", "set smac 02:00:00:00:00:02 set etype 0x88b5"),
        ("skbmod", "swap mac"),
        ("skbedit", "priority 7"),
        ("skbedit", "priority 10"),
        ("skbedit", "priority 1:10"),
        ("skbedit", "inheritdsfield"),
        ("skbedit", "mark 42"),
        ("skbedit", "mark 1/0xff"),
        ("skbedit", "ptype host"),
        ("connmark", "zone 5"),
        ("csum", "iph"),
        ("csum", "iph and tcp and udp"),
        ("nat", "egress 10.0.0.1 192.168.0.1"),
        ("nat", "ingress 10.0.0.0/24 192.168.0.0"),
        ("tunnel_key", "set src_ip 10.0.0.1 dst_ip 10.0.0.2 id 100 dst_port 4789 tos 4 ttl 64"),
        ("tunnel_key", "set src_ip fd00::1 dst_ip fd00::2 id 7 nocsum"),
        ("tunnel_key", "set src_ip 10.0.0.1 dst_ip 10.0.0.2 id 9 csum"),
        ("tunnel_key", "unset"),
        ("ct", "commit"),
        ("ct", "commit mark 7"),
        ("ct", "commit zone 5 mark 7/0xff"),
        ("ct", "clear"),
        ("pedit", "ex munge ip ttl set 5"),
        ("pedit", "ex munge ip dst set 10.0.0.9"),
        ("pedit", "ex munge tcp dport set 8080"),
        ("pedit", "ex munge eth dst set 02:00:00:00:00:09"),
        ("simple", "sdata hello"),
        ("sample", "rate 100 group 5"),
        ("sample", "rate 100 group 5 trunc 128"),
        ("gate", "base-time 1000 sched-entry open 2000"),
        ("gate", "priority 1 clockid CLOCK_TAI base-time 1000 sched-entry open 2000 sched-entry close 3000"),
        ("ctinfo", "cpmark zone 1"),
        ("ctinfo", "dscp 0xfc 0x01 zone 5"),
        ("ife", "encode allow mark"),
        ("ife", "encode type 0xed3e use mark 5"),
    ];

    let (ns, conn, d0) = clsact_d0("tc-act-sweep").await?;
    let mut failed = Vec::new();
    for (kind, line) in rows {
        let words: Vec<&str> = line.split_whitespace().collect();
        let parsed = match list(kind, &words) {
            Ok(list) => list,
            Err(e) => {
                failed.push(format!("{kind} {line}: nlink refused it: {e}"));
                continue;
            }
        };
        let mut args = vec!["filter", "add", "dev", "d0", "ingress", "prio", "1", "matchall", "action", kind];
        args.extend(&words);
        if let Err(e) = ns.exec("tc", &args) {
            failed.push(format!("{kind} {line}: tc refused it: {e}"));
            continue;
        }
        if let Err(e) = matchall_at_prio_2(&conn, d0, parsed).await {
            failed.push(format!("{kind} {line}: the kernel refused nlink's: {e}"));
            ns.exec("tc", &["filter", "del", "dev", "d0", "ingress"])?;
            continue;
        }
        let listed = filter_actions(&ns, "d0")?;
        if listed.len() != 2 || listed[0].1 != listed[1].1 {
            failed.push(format!("{kind} {line}:\n  tc:    {}\n  nlink: {}", listed[0].1, listed.get(1).map_or("-".into(), |l| l.1.to_string())));
        }
        ns.exec("tc", &["filter", "del", "dev", "d0", "ingress"])?;
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// #751: a gate's bare times are nanoseconds and a ct `nat` is spelled
/// with `addr`, as tc(8) reads them. nlink read a bare gate time as
/// microseconds, and refused the `addr` keyword.
#[tokio::test]
async fn gate_and_ct_lines_read_as_tc_reads_them() -> Result<()> {
    use nlink::netlink::action::{ActionList, CtAction, GateAction};
    require_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_gate", "act_ct");

    let (ns, conn, d0) = clsact_d0("tc-acts").await?;
    for line in ["base-time 1000 sched-entry open 2000", "base-time 1ms cycle-time 3ms sched-entry close 3ms"] {
        same_as_tc(&ns, "gate", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(GateAction::parse_params(w)?))
        })
        .await?;
    }
    // tc(8) wants a word after the NAT arguments: a verdict.
    for line in ["commit nat src addr 10.0.0.1-10.0.0.9 pipe", "commit nat dst addr 192.0.2.7 pipe", "nat pipe"] {
        same_as_tc(&ns, "ct", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(CtAction::parse_params(w)?))
        })
        .await?;
    }
    Ok(())
}

/// #751: `conform-exceed` is exceed first, as tc-police(8) reads it.
/// nlink read it conform first, so `drop/pipe` dropped the traffic that
/// conformed. #800: what a line leaves out is what tc leaves out. The police rate table needs root in the initial user
/// namespace.
#[tokio::test]
async fn police_conform_exceed_reads_as_tc_reads_it() -> Result<()> {
    use nlink::netlink::action::{ActionList, PoliceAction};
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("dummy", "sch_ingress", "cls_matchall", "act_police");

    let (ns, conn, d0) = clsact_d0("tc-police").await?;
    // The last three leave out what tc fills in: the exceed verdict and the
    // mtu (#800).
    for line in [
        "rate 1mbit burst 32k conform-exceed drop/pipe",
        "rate 2mbit burst 64k conform-exceed reclassify",
        "rate 1mbit burst 32k",
        "rate 1mbit burst 32k conform-exceed pipe",
        "rate 1mbit burst 32k mtu 9000",
    ] {
        same_as_tc(&ns, "police", line, async |a| matchall_at_prio_2(&conn, d0, a).await, |w| {
            Ok(ActionList::new().with(PoliceAction::parse_params(w)?))
        })
        .await?;
    }
    Ok(())
}
