//! Every shape the TC recipes can declare must reconcile to a no-op.
//!
//! `RateLimiter`, `PerHostLimiter` and `PerPeerImpairer` compare the live
//! HTB tree against what they would build, object by object. Anything the
//! kernel stores differently from how it was sent — a rate past 32 bits,
//! a netem field it rounds, a flower key it masks — makes every
//! `reconcile()` rewrite the same object forever. The existing
//! idempotence tests each declare one IPv4 host with defaults; these
//! declare every matcher and knob.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nlink::netlink::impair::{PeerImpairment, PerPeerImpairer};
use nlink::netlink::ratelimit::{PerHostLimiter, RateLimiter};
use nlink::netlink::tc::{NetemConfig, NetemLossModel};
use nlink::netlink::config::NetworkConfig;
use nlink::netlink::{Connection, Route};
use nlink::{Bytes, Percent, Rate, ReconcileReport};

use crate::common::traffic::{send_tcp_syns, send_udp};
use crate::common::TestNamespace;

// A table of test cases, built once each: the size is no concern.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Recipe {
    Rate(RateLimiter),
    Host(PerHostLimiter),
    Peer(PerPeerImpairer),
}

impl Recipe {
    async fn reconcile(&self, conn: &Connection<Route>) -> nlink::Result<ReconcileReport> {
        match self {
            Recipe::Rate(r) => r.reconcile(conn).await,
            Recipe::Host(r) => r.reconcile(conn).await,
            Recipe::Peer(r) => r.reconcile(conn).await,
        }
    }

    async fn reconcile_dry_run(&self, conn: &Connection<Route>) -> nlink::Result<ReconcileReport> {
        match self {
            Recipe::Rate(r) => r.reconcile_dry_run(conn).await,
            Recipe::Host(r) => r.reconcile_dry_run(conn).await,
            Recipe::Peer(r) => r.reconcile_dry_run(conn).await,
        }
    }

    async fn apply(&self, conn: &Connection<Route>) -> nlink::Result<()> {
        match self {
            Recipe::Rate(r) => r.apply(conn).await,
            Recipe::Host(r) => r.apply(conn).await,
            Recipe::Peer(r) => r.apply(conn).await,
        }
    }

    fn to_config(&self) -> nlink::Result<NetworkConfig> {
        match self {
            Recipe::Rate(r) => Ok(r.to_config()),
            Recipe::Host(r) => r.to_config(),
            Recipe::Peer(r) => r.to_config(),
        }
    }
}

struct Case {
    name: String,
    steps: Vec<Recipe>,
}

fn case(name: impl Into<String>, steps: Vec<Recipe>) -> Case {
    Case {
        name: name.into(),
        steps,
    }
}

/// Reconcile, then check that the next two reconciles change nothing.
async fn converges(conn: &Connection<Route>, recipe: &Recipe) -> Result<(), String> {
    let _first = recipe
        .reconcile(conn)
        .await
        .map_err(|e| format!("first reconcile failed: {e}"))?;
    for which in ["second", "third"] {
        let report = recipe
            .reconcile(conn)
            .await
            .map_err(|e| format!("{which} reconcile failed: {e}"))?;
        if !report.is_noop() {
            return Err(format!("{which} reconcile was not a no-op: {report:?}"));
        }
    }
    Ok(())
}

async fn assert_converges(prefix: &str, cases: Vec<Case>) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new(prefix)?;
        let conn = ns.connection()?;
        conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
            .await?;
        conn.set_link_up("d0").await?;
        for (i, step) in case.steps.iter().enumerate() {
            let outcome =
                match tokio::time::timeout(Duration::from_secs(30), converges(&conn, step)).await {
                    Ok(outcome) => outcome,
                    Err(_elapsed) => Err("timed out".to_string()),
                };
            if let Err(why) = outcome {
                failures.push(format!("[{}] step {}: {why}", case.name, i + 1));
                break;
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) did not converge:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    Ok(())
}

/// A recipe and its declaration (#645) install the same tree: installed
/// imperatively, the declaration diffs empty; applied from the
/// declaration, the recipe's reconcile has nothing to do.
async fn agrees_both_ways(prefix: &str, recipe: &Recipe) -> Result<(), String> {
    fn e(what: &'static str) -> impl Fn(nlink::Error) -> String {
        move |err| format!("{what}: {err}")
    }
    let cfg = recipe.to_config().map_err(e("to_config"))?;
    for declared_first in [false, true] {
        let ns = TestNamespace::new(prefix).map_err(e("namespace"))?;
        let conn = ns.connection().map_err(e("connection"))?;
        conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
            .await
            .map_err(e("d0"))?;
        conn.set_link_up("d0").await.map_err(e("d0 up"))?;
        if declared_first {
            let applied = cfg.apply(&conn).await.map_err(e("declarative apply"))?;
            if !applied.is_success() {
                return Err(format!("declarative apply: {:?}", applied.errors));
            }
            let report = recipe.reconcile_dry_run(&conn).await.map_err(e("dry run"))?;
            if !report.is_noop() {
                return Err(format!("applied from the declaration, reconcile would change: {report:?}"));
            }
        } else {
            recipe.apply(&conn).await.map_err(e("imperative apply"))?;
        }
        let diff = cfg.diff(&conn).await.map_err(e("diff"))?;
        if !diff.is_empty() {
            let how = if declared_first { "declaratively" } else { "imperatively" };
            return Err(format!("installed {how}, the declaration differs:\n{diff}"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn recipes_as_declarations_agree_both_ways() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "ifb", "sch_htb", "sch_fq_codel", "sch_netem", "sch_ingress", "cls_flower",
        "cls_matchall", "act_mirred"
    );

    let rl = || RateLimiter::new("d0");
    let ph = || PerHostLimiter::new("d0", Rate::mbit(10));
    let pp = || PerPeerImpairer::new("d0");
    let delay = || NetemConfig::new().delay(Duration::from_millis(20)).build();
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x09];
    let cases = vec![
        ("rate-egress", Recipe::Rate(rl().egress(Rate::mbit(10)))),
        (
            "rate-tuned",
            Recipe::Rate(
                rl().egress(Rate::mbit(10))
                    .ingress(Rate::mbit(20))
                    .burst_to(Rate::mbit(40))
                    .burst_size(Bytes::kib(64))
                    .latency(Duration::from_millis(8)),
            ),
        ),
        ("rate-ingress", Recipe::Rate(rl().ingress(Rate::mbit(20)))),
        (
            "host-rules",
            Recipe::Host(
                ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))
                    .limit_subnet("fd00:5::7/64", Rate::mbit(50))?
                    .limit_port(80, Rate::mbit(5))
                    .limit_port_range(8000, 8100, Rate::mbit(5))
                    .limit_src_ip(v6("fd00::9"), Rate::mbit(7))
                    .latency(Duration::from_millis(3)),
            ),
        ),
        ("host-none", Recipe::Host(ph())),
        (
            "peer-rules",
            Recipe::Peer(
                pp().impair_dst_ip(v4(10, 0, 0, 1), delay())
                    .impair_dst_subnet("fd00:7::9/64", delay())?
                    .impair_dst_mac(mac, delay())
                    .impair_src_ip(v4(10, 0, 0, 2), PeerImpairment::new(delay()).rate_cap(Rate::mbit(10)))
                    .default_impairment(PeerImpairment::new(delay()).rate_cap(Rate::mbit(50))),
            ),
        ),
        ("peer-one", Recipe::Peer(pp().impair_dst_ip(v6("fd00::1"), delay()))),
    ];
    let mut failures = Vec::new();
    for (name, recipe) in &cases {
        if let Err(why) = agrees_both_ways("rce-decl", recipe).await {
            failures.push(format!("[{name}] {why}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));

    // A declaration names its device.
    assert!(PerPeerImpairer::new_by_index(7).to_config().is_err());
    Ok(())
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

// ============================================================================
// RateLimiter
// ============================================================================

#[tokio::test]
async fn rate_limiter_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "sch_htb", "sch_fq_codel", "ifb", "sch_ingress", "cls_u32", "act_mirred"
    );

    let rl = || RateLimiter::new("d0");
    let cases = vec![
        case("egress", vec![Recipe::Rate(rl().egress(Rate::mbit(10)))]),
        case(
            "egress-ceil",
            vec![Recipe::Rate(rl().egress(Rate::mbit(10)).burst_to(Rate::mbit(20)))],
        ),
        case(
            "egress-burst-size",
            vec![Recipe::Rate(rl().egress(Rate::mbit(10)).burst_size(Bytes::kib(64)))],
        ),
        case(
            "egress-latency",
            vec![Recipe::Rate(
                rl().egress(Rate::mbit(10)).latency(Duration::from_millis(5)),
            )],
        ),
        case("egress-10gbit", vec![Recipe::Rate(rl().egress(Rate::gbit(10)))]),
        case(
            "egress-and-ingress",
            vec![Recipe::Rate(
                rl().egress(Rate::mbit(10)).ingress(Rate::mbit(20)),
            )],
        ),
        case(
            "rate-change",
            vec![
                Recipe::Rate(rl().egress(Rate::mbit(10))),
                Recipe::Rate(rl().egress(Rate::mbit(30))),
            ],
        ),
    ];
    assert_converges("rce-rl", cases).await
}

// ============================================================================
// PerHostLimiter
// ============================================================================

#[tokio::test]
async fn per_host_limiter_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");

    let ph = || PerHostLimiter::new("d0", Rate::mbit(10));
    let cases = vec![
        case(
            "ip-v4",
            vec![Recipe::Host(ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100)))],
        ),
        case(
            "ip-v6",
            vec![Recipe::Host(ph().limit_ip(v6("fd00::5"), Rate::mbit(100)))],
        ),
        case(
            "subnet-v4",
            vec![Recipe::Host(ph().limit_subnet("10.5.0.0/16", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v4-host-bits",
            vec![Recipe::Host(ph().limit_subnet("10.5.1.7/16", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v6",
            vec![Recipe::Host(ph().limit_subnet("fd00:5::/64", Rate::mbit(50))?)],
        ),
        case(
            "subnet-v6-host-bits",
            vec![Recipe::Host(ph().limit_subnet("fd00:5::7/64", Rate::mbit(50))?)],
        ),
        case(
            "port",
            vec![Recipe::Host(ph().limit_port(80, Rate::mbit(5)))],
        ),
        case(
            "port-range",
            vec![Recipe::Host(ph().limit_port_range(8000, 8100, Rate::mbit(5)))],
        ),
        case(
            "port-range-narrow",
            vec![Recipe::Host(ph().limit_port_range(8000, 8005, Rate::mbit(5)))],
        ),
        // A one-port range is the port.
        case(
            "port-range-single",
            vec![Recipe::Host(ph().limit_port_range(8000, 8000, Rate::mbit(5)))],
        ),
        case(
            "port-range-edited",
            vec![
                Recipe::Host(ph().limit_port_range(8000, 8100, Rate::mbit(5))),
                Recipe::Host(ph().limit_port_range(9000, 9100, Rate::mbit(5))),
                Recipe::Host(ph().limit_port(9000, Rate::mbit(5))),
                Recipe::Host(ph().limit_port_range(9000, 9100, Rate::mbit(5))),
            ],
        ),
        // A port rule's four filters (#425) come and go with its shape.
        case(
            "port-becomes-address-and-back",
            vec![
                Recipe::Host(ph().limit_port(80, Rate::mbit(5))),
                Recipe::Host(ph().limit_ip(v6("fd00::7"), Rate::mbit(5))),
                Recipe::Host(ph().limit_port_range(8000, 8100, Rate::mbit(5))),
                Recipe::Host(ph().limit_ip(v4(10, 0, 0, 7), Rate::mbit(5))),
            ],
        ),
        case(
            "src-ip-v4",
            vec![Recipe::Host(ph().limit_src_ip(v4(10, 0, 0, 2), Rate::mbit(5)))],
        ),
        case(
            "src-ip-v6",
            vec![Recipe::Host(ph().limit_src_ip(v6("fd00::6"), Rate::mbit(5)))],
        ),
        case(
            "src-subnet",
            vec![Recipe::Host(ph().limit_src_subnet("10.6.0.0/16", Rate::mbit(5))?)],
        ),
        case(
            "ip-with-ceil",
            vec![Recipe::Host(ph().limit_ip_with_ceil(
                v4(10, 0, 0, 3),
                Rate::mbit(10),
                Rate::mbit(40),
            ))],
        ),
        case(
            "latency",
            vec![Recipe::Host(
                ph().limit_ip(v4(10, 0, 0, 4), Rate::mbit(10))
                    .latency(Duration::from_millis(5)),
            )],
        ),
        case(
            "default-10gbit",
            vec![Recipe::Host(
                PerHostLimiter::new("d0", Rate::gbit(10)).limit_ip(v4(10, 0, 0, 5), Rate::gbit(5)),
            )],
        ),
        case(
            "every-matcher",
            vec![Recipe::Host(
                ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))
                    .limit_ip(v6("fd00::5"), Rate::mbit(100))
                    .limit_subnet("10.5.1.7/16", Rate::mbit(50))?
                    .limit_subnet("fd00:5::7/64", Rate::mbit(50))?
                    .limit_port(80, Rate::mbit(5))
                    .limit_port_range(8000, 8100, Rate::mbit(5))
                    .limit_src_ip(v4(10, 0, 0, 2), Rate::mbit(5))
                    .limit_src_subnet("10.6.0.0/16", Rate::mbit(5))?
                    .limit_ip_with_ceil(v4(10, 0, 0, 3), Rate::mbit(10), Rate::mbit(40))
                    .latency(Duration::from_millis(5)),
            )],
        ),
        case(
            "host-rule-removed",
            vec![
                Recipe::Host(
                    ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))
                        .limit_ip(v6("fd00::5"), Rate::mbit(100)),
                ),
                Recipe::Host(ph().limit_ip(v4(10, 0, 0, 1), Rate::mbit(100))),
            ],
        ),
    ];
    assert_converges("rce-ph", cases).await
}

/// A `PerHostLimiter` port range classifies the ports in the range, and
/// only those. `reconcile()` installed no filter for a range at all and
/// `apply()` none for a range wider than 10 ports — and for a narrower
/// one, TCP filters only — so the rule's class existed and nothing was
/// ever classified into it (#416).
///
/// The traffic leaves through a dummy device, so every datagram is
/// classified by the HTB root and counted on the class it lands in.
#[tokio::test]
async fn per_host_port_range_classifies_only_the_range() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");

    let peer = std::net::Ipv4Addr::new(10, 41, 0, 2);
    let at = |port: u16| std::net::SocketAddr::from((peer, port));
    const PER_PORT: usize = 5;

    let mut failures = Vec::new();
    for (start, end) in [(8000u16, 8100u16), (8000, 8005)] {
        let inside = [start, start + 1, (start + end) / 2, end];
        let outside = [start - 1, end + 1, 9000];
        for verb in ["apply", "reconcile"] {
            let case = format!("{verb} {start}-{end}");
            let ns = TestNamespace::new("rce-ph-range")?;
            let conn = ns.connection()?;
            conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
                .await?;
            conn.set_link_up("d0").await?;
            ns.add_addr("d0", "10.41.0.1/24")?;

            let limiter = PerHostLimiter::new("d0", Rate::mbit(100))
                .limit_port_range(start, end, Rate::mbit(50));
            match verb {
                "apply" => limiter.apply(&conn).await?,
                _ => {
                    let _ = limiter.reconcile(&conn).await?;
                }
            }
            // The two verbs build the same tree: a reconcile after
            // either one changes nothing.
            let again = limiter.reconcile(&conn).await?;
            if !again.is_noop() {
                failures.push(format!(
                    "[{case}] reconcile after {verb} was not a no-op: {again:?}"
                ));
            }

            let targets: Vec<_> = inside.iter().chain(&outside).map(|p| at(*p)).collect();
            let sent = send_udp(&ns, &targets, PER_PORT);
            assert_eq!(sent, targets.len() * PER_PORT, "every datagram must go out");

            let classes = conn.get_classes_by_name("d0").await?;
            let count = |minor: u16| {
                classes
                    .iter()
                    .find(|c| c.handle() == nlink::TcHandle::new(1, minor))
                    .map(|c| c.packets())
            };
            let rule = count(2);
            let default = count(0xffff);
            let want_rule = (inside.len() * PER_PORT) as u64;
            let want_default = (outside.len() * PER_PORT) as u64;
            if rule != Some(want_rule) || default != Some(want_default) {
                failures.push(format!(
                    "[{case}] rule class 1:2 counted {rule:?} (want {want_rule}), default class \
                     counted {default:?} (want {want_default})"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// `PerHostLimiter`'s port rules classify IPv6 as well as IPv4. Their
/// flower filters were IPv4-only, so TCP or UDP over IPv6 to a limited
/// port went to the default class, unshaped (#425).
///
/// Both families, both protocols, both verbs: TCP SYNs and UDP datagrams
/// to a `limit_port` port, to ports inside and outside a
/// `limit_port_range`, counted on the class each lands in.
#[tokio::test]
async fn per_host_port_rules_classify_both_families() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");

    const PER_PORT: usize = 3;
    // Rule 0 (class 1:2) is one port, rule 1 (class 1:3) a range.
    let port_rule = [5353u16];
    let range_rule = [8000u16, 8001, 8050, 8100];
    let outside = [7999u16, 8101, 9000];
    let peers = [
        ("IPv4", IpAddr::V4(Ipv4Addr::new(10, 41, 0, 2))),
        ("IPv6", v6("fd41::2")),
    ];

    let mut failures = Vec::new();
    for verb in ["apply", "reconcile"] {
        let ns = TestNamespace::new("rce-ph-v6")?;
        let conn = ns.connection()?;
        conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
            .await?;
        conn.set_link_up("d0").await?;
        ns.add_addr("d0", "10.41.0.1/24")?;
        ns.exec(
            "ip",
            &["-6", "addr", "add", "fd41::1/64", "dev", "d0", "nodad"],
        )?;

        let limiter = PerHostLimiter::new("d0", Rate::mbit(100))
            .limit_port(port_rule[0], Rate::mbit(50))
            .limit_port_range(8000, 8100, Rate::mbit(50));
        match verb {
            "apply" => limiter.apply(&conn).await?,
            _ => {
                let _ = limiter.reconcile(&conn).await?;
            }
        }
        let again = limiter.reconcile(&conn).await?;
        if !again.is_noop() {
            failures.push(format!(
                "[{verb}] reconcile after {verb} was not a no-op: {again:?}"
            ));
        }

        let packets = || async {
            let classes = conn.get_classes_by_name("d0").await?;
            let count = |minor: u16| {
                classes
                    .iter()
                    .find(|c| c.handle() == nlink::TcHandle::new(1, minor))
                    .map_or(0, |c| c.packets())
            };
            nlink::Result::Ok([count(2), count(3), count(0xffff)])
        };
        for (family, peer) in peers {
            let at = |ports: &[u16]| -> Vec<std::net::SocketAddr> {
                ports
                    .iter()
                    .map(|p| std::net::SocketAddr::new(peer, *p))
                    .collect()
            };
            let targets: Vec<_> = [at(&port_rule), at(&range_rule), at(&outside)].concat();

            let before = packets().await?;
            let sent = send_udp(&ns, &targets, PER_PORT);
            assert_eq!(sent, targets.len() * PER_PORT, "every datagram must go out");
            send_tcp_syns(&ns, &targets, PER_PORT, Duration::from_millis(1));
            let after = packets().await?;

            // Each port gets PER_PORT datagrams and PER_PORT SYNs.
            let got: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
            let want: Vec<u64> = [port_rule.len(), range_rule.len(), outside.len()]
                .iter()
                .map(|ports| (2 * ports * PER_PORT) as u64)
                .collect();
            if got != want {
                failures.push(format!(
                    "[{verb}] {family}: (port class 1:2, range class 1:3, default 1:ffff) \
                     counted {got:?} packets, want {want:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// A rule that changes shape keeps no filter of its old one. A port rule
/// turned into an address rule left its other filters — the IPv4 UDP one
/// at `index + 101` and, since #425, the IPv6 ones — classifying that
/// port's traffic into the class the address rule now owns. Removing the
/// rule outright already took them, by the class they point at (#413).
#[tokio::test]
async fn per_host_rule_changing_shape_leaves_no_old_filter() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");

    let ph = || PerHostLimiter::new("d0", Rate::mbit(10));
    let ip = v4(10, 0, 0, 1);
    let cases = [
        (
            "port to address",
            ph().limit_port(80, Rate::mbit(5)),
            ph().limit_ip(ip, Rate::mbit(5)),
        ),
        (
            "range to address",
            ph().limit_port_range(8000, 8100, Rate::mbit(5)),
            ph().limit_ip(ip, Rate::mbit(5)),
        ),
        (
            "port rule removed",
            ph().limit_ip(ip, Rate::mbit(5))
                .limit_port(80, Rate::mbit(5)),
            ph().limit_ip(ip, Rate::mbit(5)),
        ),
    ];

    let mut failures = Vec::new();
    for (name, before, after) in cases {
        let ns = TestNamespace::new("rce-ph-shape")?;
        let conn = ns.connection()?;
        conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
            .await?;
        conn.set_link_up("d0").await?;
        let ifindex = conn
            .get_link_by_name("d0")
            .await?
            .expect("d0 exists")
            .ifindex();

        let _ = before.reconcile(&conn).await?;
        let _ = after.reconcile(&conn).await?;
        let again = after.reconcile(&conn).await?;
        if !again.is_noop() {
            failures.push(format!(
                "[{name}] second reconcile was not a no-op: {again:?}"
            ));
        }
        let left: Vec<u16> = conn
            .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
            .await?
            .iter()
            .map(|f| f.priority().as_u16())
            .collect();
        if left != [100] {
            failures.push(format!(
                "[{name}] filters left at priorities {left:?}; the address rule has one, at 100"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// Upgrading moves `PerHostLimiter` out of the operator band (#434). Its
/// filters used to sit at `index + 1` and, for a port rule, `index +
/// 101/201/301`; they now take `100 + 4 * index` onwards. The first
/// `reconcile()` on a device a 0.29 limiter set up installs the new ones and
/// removes the old ones: every filter that sends traffic into one of the
/// limiter's rule classes from a priority the limiter no longer uses. An
/// operator's own filter in the operator band, aimed elsewhere, stays.
#[tokio::test]
async fn per_host_reconcile_moves_filters_out_of_the_operator_band() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_fq_codel", "cls_flower");
    use nlink::TcHandle;
    use nlink::netlink::filter::FlowerFilter;

    let ns = TestNamespace::new("rce-ph-band")?;
    let conn = ns.connection()?;
    conn.add_link(nlink::netlink::link::DummyLink::new("d0")).await?;
    conn.set_link_up("d0").await?;
    let ifindex = conn.get_link_by_name("d0").await?.expect("d0 exists").ifindex();
    let root = TcHandle::major_only(1);

    let limiter = PerHostLimiter::new("d0", Rate::mbit(10))
        .limit_ip(v4(10, 0, 0, 1), Rate::mbit(5))
        .limit_port(80, Rate::mbit(5));
    let _ = limiter.reconcile(&conn).await?;

    // The (priority, protocol) of every filter under the limiter's root.
    async fn filters(conn: &Connection<Route>, ifindex: u32) -> nlink::Result<Vec<(u16, u16)>> {
        let mut prios: Vec<(u16, u16)> = conn
            .get_filters_by_parent_index(ifindex, nlink::TcHandle::major_only(1))
            .await?
            .iter()
            .map(|f| (f.priority().as_u16(), f.protocol().as_u16()))
            .collect();
        prios.sort();
        prios.dedup();
        Ok(prios)
    }

    // What 0.29 left on the device: the same classes, with the filters at
    // its priorities, and an operator filter of its own in the operator band.
    for (prio, proto) in filters(&conn, ifindex).await? {
        conn.del_filter_by_index(
            ifindex,
            root,
            nlink::EthProto::new(proto),
            nlink::FilterPriority::new(prio),
        )
        .await?;
    }
    let (rule0, rule1) = (TcHandle::new(1, 2), TcHandle::new(1, 3));
    let port80 = |f: FlowerFilter| f.classid(rule1).dst_port(80);
    let old = [
        (0x0800, 1, FlowerFilter::new().classid(rule0).dst_ipv4(Ipv4Addr::new(10, 0, 0, 1), 32)),
        (0x0800, 2, port80(FlowerFilter::new().ipv4().ip_proto_tcp())),
        (0x0800, 102, port80(FlowerFilter::new().ipv4().ip_proto_udp())),
        (0x86DD, 202, port80(FlowerFilter::new().ipv6().ip_proto_tcp())),
        (0x86DD, 302, port80(FlowerFilter::new().ipv6().ip_proto_udp())),
        // The operator's: into the default class, which no rule owns.
        (
            0x0800,
            10,
            FlowerFilter::new()
                .classid(TcHandle::new(1, 0xffff))
                .dst_ipv4(Ipv4Addr::new(10, 9, 9, 9), 32),
        ),
    ];
    for (proto, prio, filter) in old {
        conn.add_filter_by_index_full(
            ifindex,
            root,
            None,
            nlink::EthProto::new(proto),
            nlink::FilterPriority::new(prio),
            filter,
        )
        .await?;
    }

    let mut failures = Vec::new();
    let upgrade = limiter.reconcile(&conn).await?;
    if !upgrade
        .unmanaged
        .iter()
        .any(|u| u.priority.map(|p| p.as_u16()) == Some(10))
    {
        failures.push(format!(
            "the operator's filter at 10 is not reported unmanaged: {:?}",
            upgrade.unmanaged
        ));
    }
    let want = vec![
        (10, 0x0800),
        (100, 0x0800),
        (104, 0x0800),
        (105, 0x0800),
        (106, 0x86DD),
        (107, 0x86DD),
    ];
    let left = filters(&conn, ifindex).await?;
    if left != want {
        failures.push(format!(
            "after the upgrade reconcile the filters are at {left:?} (priority, protocol), \
             want {want:?}"
        ));
    }
    let again = limiter.reconcile(&conn).await?;
    if !again.is_noop() {
        failures.push(format!("the next reconcile was not a no-op: {again:?}"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

// ============================================================================
// PerPeerImpairer
// ============================================================================

#[tokio::test]
async fn per_peer_impairer_shapes_converge() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_netem", "cls_flower");

    let delay = || NetemConfig::new().delay(Duration::from_millis(20)).build();
    let pp = || PerPeerImpairer::new("d0");
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x09];

    let mut cases = vec![
        case("dst-ip-v4", vec![Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 1), delay()))]),
        case("dst-ip-v6", vec![Recipe::Peer(pp().impair_dst_ip(v6("fd00::1"), delay()))]),
        case(
            "dst-subnet-v4",
            vec![Recipe::Peer(pp().impair_dst_subnet("10.7.0.0/16", delay())?)],
        ),
        case(
            "dst-subnet-v4-host-bits",
            vec![Recipe::Peer(pp().impair_dst_subnet("10.7.1.9/16", delay())?)],
        ),
        case(
            "dst-subnet-v6",
            vec![Recipe::Peer(pp().impair_dst_subnet("fd00:7::/64", delay())?)],
        ),
        case(
            "dst-subnet-v6-host-bits",
            vec![Recipe::Peer(pp().impair_dst_subnet("fd00:7::9/64", delay())?)],
        ),
        case("dst-mac", vec![Recipe::Peer(pp().impair_dst_mac(mac, delay()))]),
        case("src-ip-v4", vec![Recipe::Peer(pp().impair_src_ip(v4(10, 0, 0, 2), delay()))]),
        case("src-ip-v6", vec![Recipe::Peer(pp().impair_src_ip(v6("fd00::2"), delay()))]),
        case(
            "src-subnet",
            vec![Recipe::Peer(pp().impair_src_subnet("10.8.0.0/16", delay())?)],
        ),
        case("src-mac", vec![Recipe::Peer(pp().impair_src_mac(mac, delay()))]),
        case(
            "rate-cap",
            vec![Recipe::Peer(pp().impair_dst_ip(
                v4(10, 0, 0, 3),
                PeerImpairment::new(delay()).rate_cap(Rate::mbit(10)),
            ))],
        ),
        case(
            "default-impairment-added-then-removed",
            vec![
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 4), delay())),
                Recipe::Peer(
                    pp().impair_dst_ip(v4(10, 0, 0, 4), delay())
                        .default_impairment(
                            PeerImpairment::new(delay()).rate_cap(Rate::mbit(50)),
                        ),
                ),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 4), delay())),
            ],
        ),
        case(
            "peer-rule-removed",
            vec![
                Recipe::Peer(
                    pp().impair_dst_ip(v4(10, 0, 0, 5), delay())
                        .impair_dst_ip(v6("fd00::5"), delay()),
                ),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 5), delay())),
            ],
        ),
    ];

    // Each netem knob on a rule leaf, added and then removed again.
    type Knob = fn(NetemConfig) -> NetemConfig;
    let knobs: Vec<(&str, Knob)> = vec![
        ("jitter-correlation", |n| {
            n.jitter(Duration::from_millis(2))
                .delay_correlation(Percent::new(25.0))
        }),
        ("loss", |n| n.loss(Percent::new(1.0))),
        ("loss-correlation", |n| {
            n.loss(Percent::new(1.0)).loss_correlation(Percent::new(25.0))
        }),
        ("duplicate", |n| n.duplicate(Percent::new(1.0))),
        ("corrupt", |n| n.corrupt(Percent::new(1.0))),
        ("reorder", |n| n.reorder(Percent::new(5.0))),
        ("rate", |n| n.rate(Rate::mbit(10))),
        ("limit", |n| n.limit(nlink::Packets::new(500))),
        ("loss-model", |n| {
            n.loss_model(NetemLossModel::gilbert_elliot(Percent::new(1.0)).r(Percent::new(30.0)))
        }),
    ];
    for (name, knob) in knobs {
        let with = knob(NetemConfig::new().delay(Duration::from_millis(20))).build();
        cases.push(case(
            format!("netem-{name}"),
            vec![
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), delay())),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), with.clone())),
                Recipe::Peer(pp().impair_dst_ip(v4(10, 0, 0, 6), delay())),
            ],
        ));
    }
    assert_converges("rce-pp", cases).await
}

/// #485: the recipes put their default leaf at `ffff:`, the ingress and
/// clsact qdisc's handle, so neither could be applied next to one —
/// "Cannot move an existing qdisc to a different parent" — and the
/// ingress half of a `RateLimiter`, or a BPF program on clsact, could not
/// be added after them. The leaf is at `8000:` now.
#[tokio::test]
async fn recipes_coexist_with_ingress_and_clsact() -> nlink::Result<()> {
    use nlink::netlink::{
        link::DummyLink,
        tc::{ClsactConfig, IngressConfig},
    };
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_netem", "sch_ingress", "dummy");

    let ns = TestNamespace::new("recipe-ingress")?;
    let conn = ns.connection()?;
    for dev in ["host0", "peer0", "late0"] {
        conn.add_link(DummyLink::new(dev)).await?;
        conn.set_link_up(dev).await?;
    }
    conn.add_qdisc("host0", IngressConfig::new()).await?;
    conn.add_qdisc("peer0", ClsactConfig::new()).await?;

    PerHostLimiter::new("host0", nlink::Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), nlink::Rate::mbit(5))
        .apply(&conn)
        .await?;
    let impairer = PerPeerImpairer::new("peer0")
        .impair_dst_ip("10.0.0.1".parse().unwrap(), NetemConfig::new().build())
        .default_impairment(NetemConfig::new().build());
    impairer.apply(&conn).await?;
    // The other order: the recipe first, then the ingress qdisc.
    PerHostLimiter::new("late0", nlink::Rate::mbit(10))
        .apply(&conn)
        .await?;
    conn.add_qdisc("late0", IngressConfig::new()).await?;

    for dev in ["host0", "peer0", "late0"] {
        let qdiscs = conn.get_qdiscs_by_name(dev).await?;
        let at_ingress: Vec<_> = qdiscs
            .iter()
            .filter(|q| q.handle().major() == 0xffff)
            .collect();
        assert_eq!(
            at_ingress.len(),
            1,
            "{dev}: only the ingress/clsact qdisc at ffff:"
        );
        assert!(
            qdiscs
                .iter()
                .any(|q| q.handle() == nlink::TcHandle::major_only(0x8000)),
            "{dev}: the default leaf at 8000:"
        );
    }
    assert!(impairer.reconcile_dry_run(&conn).await?.is_noop());
    Ok(())
}

/// #485: a recipe applied by an earlier nlink has its default leaf at
/// `ffff:`; `reconcile()` moves it to `8000:` and is then a no-op.
#[tokio::test]
async fn reconcile_moves_a_legacy_default_leaf() -> nlink::Result<()> {
    use nlink::netlink::{link::DummyLink, tc::IngressConfig};
    require_root!();
    nlink::require_modules!("sch_htb", "cls_flower", "sch_ingress", "dummy");

    let ns = TestNamespace::new("recipe-legacy")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("old0")).await?;
    conn.set_link_up("old0").await?;
    let limiter = PerHostLimiter::new("old0", nlink::Rate::mbit(10))
        .limit_ip("10.0.0.1".parse().unwrap(), nlink::Rate::mbit(5));
    limiter.apply(&conn).await?;
    // What 0.30 left: the default class's leaf at ffff:. nlink refuses to
    // write that handle now, so put it there as tc would.
    ns.exec("tc", &["qdisc", "del", "dev", "old0", "parent", "1:ffff"])?;
    ns.exec(
        "tc",
        &[
            "qdisc", "add", "dev", "old0", "parent", "1:ffff", "handle", "ffff:", "fq_codel",
        ],
    )?;

    let report = limiter.reconcile(&conn).await?;
    assert!(report.default_modified, "{report:?}");
    let qdiscs = conn.get_qdiscs_by_name("old0").await?;
    assert!(
        qdiscs
            .iter()
            .any(|q| q.handle() == nlink::TcHandle::major_only(0x8000))
    );
    assert!(!qdiscs.iter().any(|q| q.handle().major() == 0xffff));
    assert!(
        limiter.reconcile(&conn).await?.is_noop(),
        "a second reconcile"
    );
    conn.add_qdisc("old0", IngressConfig::new()).await?;
    Ok(())
}
