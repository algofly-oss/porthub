//! Integration tests for the diagnostics module.

use nlink::netlink::diagnostics::{
    BottleneckType, Diagnostics, DiagnosticsConfig, IssueCategory, LinkRates, Severity,
};

use crate::common::TestNamespace;

// ============================================================================
// Unit Tests (no network namespace required)
// ============================================================================

#[test]
fn test_severity_ordering() {
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Info), "INFO");
    assert_eq!(format!("{}", Severity::Warning), "WARN");
    assert_eq!(format!("{}", Severity::Error), "ERROR");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn test_issue_category_display() {
    assert_eq!(format!("{}", IssueCategory::LinkDown), "LinkDown");
    assert_eq!(format!("{}", IssueCategory::NoCarrier), "NoCarrier");
    assert_eq!(
        format!("{}", IssueCategory::HighPacketLoss),
        "HighPacketLoss"
    );
    assert_eq!(format!("{}", IssueCategory::QdiscDrops), "QdiscDrops");
    assert_eq!(format!("{}", IssueCategory::NoRoute), "NoRoute");
}

#[test]
fn test_link_rates() {
    // `nlink::LinkRates` is the stats module's since 0.32 (#525): bytes and
    // packets per second as f64, bits eight times the bytes (#274).
    let rates = LinkRates {
        rx_bytes_per_sec: 1000.0,
        tx_bytes_per_sec: 2000.0,
        rx_packets_per_sec: 10.0,
        tx_packets_per_sec: 20.0,
        ..LinkRates::default()
    };
    assert_eq!(rates.total_bytes_per_sec(), 3000.0);
    assert_eq!(rates.total_bps(), 24_000.0);
    assert_eq!(rates.total_packets_per_sec(), 30.0);
    assert_eq!(LinkRates::default().total_bps(), 0.0);
}

#[test]
fn test_config_defaults() {
    let config = DiagnosticsConfig::default();
    assert_eq!(config.packet_loss_threshold, 0.01);
    assert_eq!(config.error_rate_threshold, 0.001);
    assert_eq!(config.qdisc_drop_threshold, 0.01);
    assert_eq!(config.backlog_threshold, 100_000);
    assert_eq!(config.qlen_threshold, 1000);
    assert!(config.skip_loopback);
    assert!(!config.skip_down);
    assert_eq!(config.min_bytes_for_rate, 1000);
}

#[test]
fn test_bottleneck_type_display() {
    assert_eq!(format!("{}", BottleneckType::QdiscDrops), "Qdisc Drops");
    assert_eq!(
        format!("{}", BottleneckType::InterfaceDrops),
        "Interface Drops"
    );
    assert_eq!(format!("{}", BottleneckType::BufferFull), "Buffer Full");
    assert_eq!(format!("{}", BottleneckType::RateLimited), "Rate Limited");
    assert_eq!(
        format!("{}", BottleneckType::HardwareErrors),
        "Hardware Errors"
    );
}

// ============================================================================
// Integration Tests (require network namespace — root-gated)
//
// Migrated from `#[ignore]` to `nlink::require_root!()` in 0.17
// (Plan 179) so they run under privileged CI but skip cleanly on
// non-root developer runs.
// ============================================================================

#[tokio::test]
async fn test_diagnostics_scan() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_scan")?;

    // Create a dummy interface
    ns.add_dummy("dummy0")?;
    ns.link_up("dummy0")?;
    ns.add_addr("dummy0", "10.0.0.1/24")?;

    // Create diagnostics runner
    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Run scan
    let report = diag.scan().await?;

    // Verify we got results
    assert!(!report.interfaces.is_empty());

    // Find our dummy interface
    let dummy = report
        .interfaces
        .iter()
        .find(|i| i.name == "dummy0")
        .expect("dummy0 not found in report");

    assert_eq!(dummy.name, "dummy0");
    assert!(dummy.mtu.is_some());
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_scan_interface() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_scan_if")?;

    // Create a dummy interface
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;
    ns.add_addr("eth0", "192.168.1.1/24")?;

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Scan specific interface
    let iface = diag.scan_interface("eth0").await?;

    assert_eq!(iface.name, "eth0");
    assert!(iface.mtu.is_some());
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_scan_interface_not_found() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_notfound")?;

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Try to scan non-existent interface
    let result = diag.scan_interface("nonexistent0").await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(err.is_not_found());
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_check_connectivity_no_route() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_conn")?;

    // Create a dummy interface without any routes
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Check connectivity to external IP - should fail (no route)
    let report = diag
        .check_connectivity("8.8.8.8".parse().unwrap())
        .await?;

    // Should have a NoRoute issue
    assert!(!report.issues.is_empty());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.category == IssueCategory::NoRoute)
    );
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_check_connectivity_with_route() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_route")?;

    // Create interface with address and default route
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;
    ns.add_addr("eth0", "192.168.1.1/24")?;
    // Add a default route (may fail if kernel requires a real gateway)
    let _ = ns.exec("ip", &["route", "add", "default", "via", "192.168.1.254"]);

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Check connectivity to local subnet - should have a route
    let report = diag
        .check_connectivity("192.168.1.100".parse().unwrap())
        .await?;

    // Should find a route (even if not the default)
    assert!(
        report.route.is_some() || report.issues.is_empty(),
        "Expected route or no issues"
    );
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_find_bottleneck() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_bottle")?;

    // Create a dummy interface
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    // Find bottleneck - likely none on a fresh interface
    let bottleneck = diag.find_bottleneck().await?;

    // Fresh interface shouldn't have a bottleneck
    // (unless there's a pre-existing issue)
    if let Some(b) = bottleneck {
        println!("Found bottleneck: {} ({:?})", b.location, b.bottleneck_type);
    }
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_with_tc() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("sch_htb");
    let ns = TestNamespace::new("diag_tc")?;

    // Create a dummy interface with TC
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;

    // Add a qdisc
    ns.exec_ignore(
        "tc",
        &[
            "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb", "default", "10",
        ],
    );

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await?;

    // Find eth0 and check TC info
    let eth0 = report
        .interfaces
        .iter()
        .find(|i| i.name == "eth0")
        .expect("eth0 not found in report");

    if let Some(tc) = &eth0.tc {
        assert_eq!(tc.qdisc, "htb");
    }
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_link_down_detection() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_down")?;

    // Create a dummy interface but leave it down
    ns.add_dummy("eth0")?;
    // Don't bring it up

    let conn = ns.connection()?;

    // Use config that doesn't skip down interfaces
    let config = DiagnosticsConfig {
        skip_down: false,
        ..Default::default()
    };

    let diag = Diagnostics::with_config(conn, config);

    let report = diag.scan().await?;

    // Find eth0
    let eth0 = report
        .interfaces
        .iter()
        .find(|i| i.name == "eth0")
        .expect("eth0 not found in report");

    // Should have LinkDown issue
    assert!(
        eth0.issues
            .iter()
            .any(|i| i.category == IssueCategory::LinkDown)
    );
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_no_address_detection() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_noaddr")?;

    // Create interface without an IPv4 address. After link-up
    // the kernel auto-assigns an IPv6 link-local fe80::/64
    // (SLAAC) on modern kernels, which would count as an
    // address and suppress the `NoAddress` issue the test
    // means to verify. Flush IPv6 addrs post-up. There's no
    // RA source in this isolated namespace, so SLAAC won't
    // re-add anything.
    //
    // Avoid `sysctl(8)` here — the CI container
    // (`rust:bookworm` per integration-tests.yml) installs only
    // `iproute2 kmod conntrack`; `procps` (sysctl) isn't there.
    // `ip` is. (Plan 179.)
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;
    let _ = ns.exec("ip", &["-6", "addr", "flush", "dev", "eth0"]);

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await?;

    let eth0 = report
        .interfaces
        .iter()
        .find(|i| i.name == "eth0")
        .expect("eth0 not found in report");

    assert!(
        eth0.issues
            .iter()
            .any(|i| i.category == IssueCategory::NoAddress),
        "expected NoAddress issue; got issues={:?}",
        eth0.issues.iter().map(|i| &i.category).collect::<Vec<_>>(),
    );
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_route_summary() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_routes")?;

    // Create interface and add routes
    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;
    ns.add_addr("eth0", "10.0.0.1/24")?;
    ns.exec("ip", &["route", "add", "192.168.0.0/16", "dev", "eth0"])?;

    let conn = ns.connection()?;
    let diag = Diagnostics::new(conn);

    let report = diag.scan().await?;

    // Check route diagnostics
    assert!(report.routes.ipv4_route_count >= 1);
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_custom_config() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_config")?;

    ns.add_dummy("eth0")?;
    ns.link_up("eth0")?;

    let conn = ns.connection()?;

    // Custom config with stricter thresholds
    let config = DiagnosticsConfig {
        packet_loss_threshold: 0.001, // 0.1%
        error_rate_threshold: 0.0001, // 0.01%
        skip_loopback: true,
        skip_down: true,
        ..Default::default()
    };

    let diag = Diagnostics::with_config(conn, config);

    assert_eq!(diag.config().packet_loss_threshold, 0.001);
    assert_eq!(diag.config().error_rate_threshold, 0.0001);

    let report = diag.scan().await?;
    assert!(!report.interfaces.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_diagnostics_skip_loopback() -> nlink::Result<()> {
    nlink::require_root!();
    let ns = TestNamespace::new("diag_lo")?;

    let conn = ns.connection()?;

    // Default config skips loopback
    let diag = Diagnostics::new(conn);
    let report = diag.scan().await?;

    // lo should not be in the results
    assert!(!report.interfaces.iter().any(|i| i.name == "lo"));
    Ok(())
}

// ============================================================================
// #497 — lookups in the connection's namespace, not the process's
// ============================================================================

/// A GENL family that names devices (ethtool here; WireGuard does the
/// same) resolved an ifindex with a new `Connection::<Route>` in the
/// *process's* namespace: in a lab, the host's ifindex 2 named the host's
/// `eth0`, which the lab does not have.
#[tokio::test]
async fn a_genl_lookup_by_index_resolves_in_its_own_namespace() -> nlink::Result<()> {
    use nlink::netlink::{Connection, Ethtool, link::DummyLink};
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("ns-ethtool")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    let d0 = conn.get_link_by_name("d0").await?.expect("d0").ifindex();

    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    ethtool.get_link_state(d0).await?;
    Ok(())
}

/// Three ethtool bugs, each silent until a test read a value back:
/// - every getter sent a dump, which ethtool answers for every device, and
///   kept the first: `lo`'s features, rings and link state, whatever the
///   name;
/// - `set_features` failed on every device: FEATURES_SET answers with a
///   reply message unless asked not to, and the request expected only its
///   ACK;
/// - `get_features` read every listed feature as off: the kernel lists a
///   feature bitset's set bits without a value flag.
///
/// `lo` has `loopback` and the veth does not; the veth's tx checksumming
/// goes off and on again, read back each time.
#[tokio::test]
async fn ethtool_reads_and_sets_the_named_devices_features() -> nlink::Result<()> {
    use nlink::netlink::{Connection, Ethtool, link::VethLink};
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("ns-ethfeat")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("ve0", "ve1")).await?;
    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    assert!(ethtool.get_features("lo").await?.active.is_set("loopback"));
    assert!(!ethtool.get_features("ve0").await?.active.is_set("loopback"), "lo's features");

    let feature = "tx-checksum-ip-generic";
    for on in [false, true] {
        ethtool
            .set_features("ve0", |f| if on { f.enable(feature) } else { f.disable(feature) })
            .await?;
        let active = ethtool.get_features("ve0").await?.active;
        assert_eq!(active.is_set(feature), on, "{feature} should be {}", if on { "on" } else { "off" });
    }
    Ok(())
}

/// nlink's ethtool getters read what the ethtool CLI reads, on `lo`, a veth
/// and a dummy: every feature's state and whether it is fixed (`-k`), the
/// speed, duplex, autonegotiation and carrier (`ethtool DEV`), and the
/// channels (`-l`), or both refuse.
#[tokio::test]
async fn ethtool_reads_what_the_ethtool_cli_reads() -> nlink::Result<()> {
    use nlink::netlink::{
        Connection, Ethtool,
        genl::ethtool::Duplex,
        link::{DummyLink, VethLink},
    };
    require_root!();
    nlink::require_modules!("veth", "dummy");

    let ns = TestNamespace::new("ns-ethcli")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("ve0", "ve1")).await?;
    conn.add_link(DummyLink::new("d0")).await?;
    for dev in ["lo", "ve0", "ve1", "d0"] {
        conn.set_link_up(dev).await?;
    }
    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    let mut failed = Vec::new();
    for dev in ["lo", "ve0", "d0"] {
        // Features, as `ethtool --json -k` gives them, without ethtool's
        // legacy group names (its `off_flag_def`), which are not the
        // kernel's features.
        const LEGACY: [&str; 12] = [
            "rx-checksumming", "tx-checksumming", "scatter-gather", "tcp-segmentation-offload",
            "udp-fragmentation-offload", "generic-segmentation-offload", "generic-receive-offload",
            "large-receive-offload", "rx-vlan-offload", "tx-vlan-offload", "ntuple-filters", "receive-hashing",
        ];
        let cli = ns.exec("ethtool", &["--json", "-k", dev])?;
        let cli: serde_json::Value = serde_json::from_str(&cli).map_err(|e| nlink::Error::invalid_message(e.to_string()))?;
        let features = ethtool.get_features(dev).await?;
        for (name, v) in cli[0].as_object().into_iter().flatten() {
            let (Some(on), Some(fixed)) = (v["active"].as_bool(), v["fixed"].as_bool()) else { continue };
            if LEGACY.contains(&name.as_str()) {
                continue;
            }
            if features.is_active(name) != on || features.is_changeable(name) == fixed {
                failed.push(format!(
                    "{dev} {name}: ethtool says active {on} fixed {fixed}, nlink active {} fixed {}",
                    features.is_active(name),
                    !features.is_changeable(name)
                ));
            }
        }

        // Settings and carrier. ethtool fails on a device whose settings
        // it cannot read, after printing what it could (the carrier).
        let mut cmd = std::process::Command::new("ethtool");
        cmd.arg(dev);
        let cli = String::from_utf8_lossy(&ns.spawn_output(cmd)?.stdout).into_owned();
        let field = |key: &str| cli.lines().find_map(|l| l.trim().strip_prefix(key).map(str::trim).map(str::to_string));
        match ethtool.get_link_modes(dev).await {
            Ok(modes) => {
                let speed = modes.speed.map_or("Unknown!".to_string(), |s| format!("{s}Mb/s"));
                if field("Speed:").as_deref() != Some(&*speed) {
                    failed.push(format!("{dev} speed: ethtool says {:?}, nlink {speed}", field("Speed:")));
                }
                let duplex = match modes.duplex {
                    Some(Duplex::Full) => "Full",
                    Some(Duplex::Half) => "Half",
                    _ => "Unknown!",
                };
                if !field("Duplex:").is_some_and(|d| d.starts_with(duplex)) {
                    failed.push(format!("{dev} duplex: ethtool says {:?}, nlink {duplex}", field("Duplex:")));
                }
                let autoneg = if modes.autoneg { "on" } else { "off" };
                if field("Auto-negotiation:").as_deref() != Some(autoneg) {
                    failed.push(format!("{dev} autoneg: ethtool says {:?}, nlink {autoneg}", field("Auto-negotiation:")));
                }
            }
            Err(e) if field("Speed:").is_some() => failed.push(format!("{dev}: ethtool reads its settings, nlink refused: {e}")),
            Err(_) => {}
        }
        // No "Link detected" when the driver cannot tell (#839).
        let link = ethtool.get_link_state(dev).await?.link.map(|l| if l { "yes" } else { "no" });
        if field("Link detected:").as_deref() != link {
            failed.push(format!("{dev} link: ethtool says {:?}, nlink {link:?}", field("Link detected:")));
        }

        // Channels: maximums, then the current values; `n/a` is absent.
        let cli = ns.exec("ethtool", &["-l", dev]);
        let ours = ethtool.get_channels(dev).await;
        match (cli, ours) {
            (Ok(cli), Ok(ch)) => {
                let values: Vec<Option<u32>> = cli
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .filter(|(k, _)| matches!(k.trim(), "RX" | "TX" | "Other" | "Combined"))
                    .map(|(_, v)| v.trim().parse().ok())
                    .collect();
                let mine = vec![
                    ch.rx_max, ch.tx_max, ch.other_max, ch.combined_max, ch.rx_count, ch.tx_count, ch.other_count,
                    ch.combined_count,
                ];
                if values != mine {
                    failed.push(format!("{dev} channels: ethtool says {values:?}, nlink {mine:?}"));
                }
            }
            (Err(_), Err(_)) => {}
            (cli, ours) => failed.push(format!("{dev} channels: ethtool {:?}, nlink {:?}", cli.is_ok(), ours.map(|_| ()))),
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}

/// `get_eth_stats` sent its request as a dump, which ethtool answers for
/// every device in the namespace, ignoring the one it names, and kept the
/// first answer: `lo`'s, whatever the device (#773). The reply's header
/// names the device it is about.
#[tokio::test]
async fn ethtool_reads_the_named_devices_stats() -> nlink::Result<()> {
    use nlink::netlink::{Connection, Ethtool, link::VethLink};
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("ns-ethstats")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("ve0", "ve1")).await?;
    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    let stats = ethtool.get_eth_stats("ve0").await?;
    assert_eq!(stats.ifname.as_deref(), Some("ve0"), "{stats:?}");
    Ok(())
}

/// #166: a veth's timestamping is the kernel's software-only default
/// (`ethtool_op_get_ts_info`): transmit, receive and the system clock in
/// software, no hardware modes or filters, no PTP clock. Where the ethtool
/// CLI is installed, `ethtool -T` lists the same capabilities.
#[tokio::test]
async fn ethtool_reads_a_devices_timestamping() -> nlink::Result<()> {
    use nlink::netlink::{Connection, Ethtool, link::VethLink};
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("ns-tsinfo")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("ve0", "ve1")).await?;
    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    let ts = ethtool.get_tsinfo("ve0").await?;
    let mut caps = ts.timestamping.active_names();
    caps.sort_unstable();
    assert_eq!(caps, ["software-receive", "software-system-clock", "software-transmit"]);
    assert!(ts.tx_types.active_names().is_empty(), "{:?}", ts.tx_types.active_names());
    assert!(ts.rx_filters.active_names().is_empty(), "{:?}", ts.rx_filters.active_names());
    assert_eq!(ts.phc_index, None);
    if let Ok(cli) = ns.exec("ethtool", &["-T", "ve0"]) {
        for cap in &caps {
            assert!(cli.contains(cap), "ethtool -T lists {cap}:\n{cli}");
        }
    }
    Ok(())
}

/// #166: PHY_GET answers for the named link, and a veth, being virtual,
/// has no PHY: the list is empty, not an error, whether asked for the link
/// or for the whole namespace.
#[tokio::test]
async fn ethtool_lists_a_links_phys() -> nlink::Result<()> {
    use nlink::netlink::{Connection, Ethtool, link::VethLink};
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("ns-phys")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("ve0", "ve1")).await?;
    let ethtool: Connection<Ethtool> = nlink::Connection::new_in_async(ns.name()).await?;
    assert_eq!(ethtool.get_phys("ve0").await?, Vec::new());
    assert_eq!(ethtool.dump_phys().await?, Vec::new());
    Ok(())
}

/// `Diagnostics::watch()` subscribed on a new connection in the process's
/// namespace, so `Diagnostics::new(lab_conn).watch()` watched the host. And
/// it named a removed address's interface through the host's sysfs.
#[tokio::test]
async fn watch_follows_its_connections_namespace() -> nlink::Result<()> {
    use std::{net::Ipv4Addr, time::Duration};

    use nlink::netlink::{addr::Ipv4Address, link::DummyLink};
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("diag-watch")?;
    let diag = Diagnostics::new(ns.connection()?);
    let mut issues = diag.watch().await?;

    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("w0")).await?;
    let ip = Ipv4Addr::new(10, 97, 0, 1);
    conn.add_address(Ipv4Address::new("w0", ip, 24)).await?;
    conn.del_address("w0", ip.into(), 24).await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let Ok(Some(issue)) = tokio::time::timeout_at(deadline, issues.next()).await else {
            panic!("no NoAddress issue from the lab namespace within 5 s");
        };
        let issue = issue?;
        if issue.category == IssueCategory::NoAddress {
            assert_eq!(issue.interface.as_deref(), Some("w0"), "{issue:?}");
            return Ok(());
        }
    }
}

/// #509: `check_connectivity` took the first route in the dump that
/// contained the destination — usually the default — and counted a
/// blackhole as a route. It now asks the kernel, as `ip route get` does.
#[tokio::test]
async fn check_connectivity_asks_the_kernel_which_route() -> nlink::Result<()> {
    use std::net::{IpAddr, Ipv4Addr};
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("diag-route")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;
    ns.exec("ip", &["link", "set", "d0", "up"])?;
    ns.exec("ip", &["addr", "add", "10.1.0.1/24", "dev", "d0"])?;
    ns.exec("ip", &["route", "add", "default", "via", "10.1.0.254"])?;
    ns.exec("ip", &["route", "add", "10.50.0.0/16", "via", "10.1.0.2"])?;
    ns.exec("ip", &["route", "add", "blackhole", "10.99.0.0/16"])?;
    let diag = Diagnostics::new(ns.connection()?);

    let specific = diag
        .check_connectivity(IpAddr::V4(Ipv4Addr::new(10, 50, 0, 1)))
        .await?;
    assert_eq!(
        specific.gateway,
        Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))),
        "the /16, not the default route: {specific:?}"
    );
    let blackholed = diag
        .check_connectivity(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)))
        .await?;
    assert!(blackholed.route.is_none(), "{blackholed:?}");
    assert!(
        blackholed
            .issues
            .iter()
            .any(|i| i.category == IssueCategory::NoRoute
                && i.details.as_deref() == Some("a blackhole route matches it")),
        "{blackholed:?}"
    );
    Ok(())
}

/// #509: a lab namespace with no default route on purpose can switch the
/// warning off.
#[tokio::test]
async fn the_no_default_route_warning_can_be_switched_off() -> nlink::Result<()> {
    require_root!();
    let ns = TestNamespace::new("diag-nodefault")?;
    let warned = |report: &nlink::netlink::diagnostics::DiagnosticReport| {
        report
            .issues
            .iter()
            .any(|i| i.category == IssueCategory::NoDefaultRoute)
    };
    let diag = Diagnostics::new(ns.connection()?);
    assert!(warned(&diag.scan().await?), "on by default");
    let config = DiagnosticsConfig {
        warn_no_default_route: false,
        ..Default::default()
    };
    let quiet = Diagnostics::with_config(ns.connection()?, config);
    assert!(!warned(&quiet.scan().await?));
    Ok(())
}

/// Send `n` datagrams over `lo` in `ns`, to a bound receiver so no ICMP
/// follows them.
fn lo_traffic(ns: &TestNamespace, n: usize) {
    crate::common::traffic::in_ns(ns, move || {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind rx");
        let to = rx.local_addr().unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind tx");
        for _ in 0..n {
            tx.send_to(&[0u8; 100], to).expect("send");
        }
    });
}

/// #525: one `RTM_GETSTATS` dump reads every link's counters. An idle
/// link's agree with what the link dump reports, and datagrams over `lo`
/// show up in its.
#[tokio::test]
async fn stats64_dump_agrees_with_the_link_dump_and_counts_traffic() -> nlink::Result<()> {
    use nlink::netlink::link::DummyLink;
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("stats64")?;
    let conn = ns.connection()?;
    crate::common::traffic::lo_up(&ns).await?;
    conn.add_link(DummyLink::new("idle0")).await?;
    let idle = conn.get_link_by_name("idle0").await?.expect("idle0");

    let before = conn.get_stats64_all().await?;
    let mut keys: Vec<u32> = before.keys().copied().collect();
    keys.sort();
    // Every link the link dump has — lo, idle0, and the fallback tunnels a
    // namespace gets where their modules are loaded.
    let mut links: Vec<u32> = conn
        .get_links()
        .await?
        .iter()
        .map(|l| l.ifindex())
        .collect();
    links.sort();
    assert_eq!(keys, links);
    let dumped = idle.stats().copied().unwrap_or_default();
    let read = before[&idle.ifindex()];
    assert_eq!(
        (
            read.rx_packets(),
            read.tx_packets(),
            read.rx_bytes(),
            read.tx_bytes()
        ),
        (
            dumped.rx_packets(),
            dumped.tx_packets(),
            dumped.rx_bytes(),
            dumped.tx_bytes()
        )
    );

    lo_traffic(&ns, 50);
    let after = conn.get_stats64_all().await?;
    let sent = after[&1].tx_packets() - before[&1].tx_packets();
    assert!(sent >= 50, "lo sent {sent}");
    assert!(after[&1].rx_bytes() - before[&1].rx_bytes() >= 50 * 100);
    Ok(())
}

/// #525: `lo` is ifindex 1 in every namespace. A `StatsTracker` keyed by
/// ifindex alone diffed one namespace's counters against another's; a
/// `RateSampler` keeps them apart. Traffic in one namespace only: its
/// `lo` has a rate, the other's has none.
#[tokio::test]
async fn a_rate_sampler_keeps_two_namespaces_lo_apart() -> nlink::Result<()> {
    use nlink::netlink::stats::{RateSampler, StatsSnapshot};
    require_root!();

    let busy = TestNamespace::new("sampler-busy")?;
    let quiet = TestNamespace::new("sampler-quiet")?;
    let (busy_conn, quiet_conn) = (busy.connection()?, quiet.connection()?);
    crate::common::traffic::lo_up(&busy).await?;
    crate::common::traffic::lo_up(&quiet).await?;

    let mut sampler = RateSampler::new();
    assert!(
        sampler
            .sample(&StatsSnapshot::capture(&busy_conn).await?)
            .is_empty()
    );
    assert!(
        sampler
            .sample(&StatsSnapshot::capture(&quiet_conn).await?)
            .is_empty()
    );
    lo_traffic(&busy, 200);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let busy_snap = StatsSnapshot::capture(&busy_conn).await?;
    let quiet_snap = StatsSnapshot::capture(&quiet_conn).await?;
    assert_ne!(busy_snap.netns, quiet_snap.netns);
    assert!(busy_snap.netns.is_some());
    let busy_rates = sampler.sample(&busy_snap);
    let quiet_rates = sampler.sample(&quiet_snap);
    let lo = |rates: &[nlink::netlink::stats::SampledRates]| {
        rates
            .iter()
            .find(|r| r.key.ifindex == 1)
            .map(|r| r.rates)
            .expect("lo")
    };
    assert!(lo(&busy_rates).tx_packets_per_sec > 0.0, "{busy_rates:?}");
    assert_eq!(lo(&quiet_rates).tx_packets_per_sec, 0.0, "{quiet_rates:?}");
    Ok(())
}

/// #525: a fresh `Diagnostics` has no previous sample, so its rates were
/// always 0. `scan_since` takes one from the caller.
#[tokio::test]
async fn scan_since_gives_a_fresh_runner_rates() -> nlink::Result<()> {
    require_root!();
    let ns = TestNamespace::new("diag-since")?;
    crate::common::traffic::lo_up(&ns).await?;
    let config = || DiagnosticsConfig {
        skip_loopback: false,
        ..Default::default()
    };
    let lo = |report: &nlink::netlink::diagnostics::DiagnosticReport| {
        report
            .interfaces
            .iter()
            .find(|i| i.name == "lo")
            .expect("lo")
            .rates
    };

    let first = Diagnostics::with_config(ns.connection()?, config())
        .scan()
        .await?;
    lo_traffic(&ns, 200);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let plain = Diagnostics::with_config(ns.connection()?, config())
        .scan()
        .await?;
    assert_eq!(
        lo(&plain).tx_packets_per_sec,
        0.0,
        "a fresh runner has no sample"
    );
    let since = Diagnostics::with_config(ns.connection()?, config())
        .scan_since(&first)
        .await?;
    assert!(lo(&since).tx_packets_per_sec > 0.0, "{:?}", lo(&since));
    assert!(lo(&since).tx_bytes_per_sec >= 100.0 * lo(&since).tx_packets_per_sec);
    Ok(())
}
