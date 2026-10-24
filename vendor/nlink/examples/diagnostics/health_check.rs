//! Network health check — runs the full `Diagnostics` scan and
//! prints a structured report covering every interface, the
//! routing summary, all detected issues, and the worst
//! bottleneck (if any).
//!
//! Replaces three earlier `println!`-of-doc-string examples
//! (`bottleneck.rs`, `connectivity.rs`, `scan.rs`) catalogued by
//! Plan 160 and deleted in the Plan 168 Phase 2 closeout. The
//! single end-to-end demo is more useful than three separate
//! method walkthroughs: `Diagnostics::scan()` already produces
//! the full report; `find_bottleneck()` is the actionable summary.
//!
//! Run:
//!   cargo run -p nlink --example diagnostics_health_check
//!
//! Sudo isn't required — the diagnostics API only reads netlink
//! dumps (links / addresses / routes / qdiscs). Output without
//! sudo on a regular workstation typically shows the local
//! interfaces in OperState::Up with no detected issues.

use nlink::netlink::{
    Connection, Route,
    diagnostics::{Diagnostics, DiagnosticReport, Severity},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let diag = Diagnostics::new(conn);

    println!("=== Running diagnostic scan ===\n");
    let report = diag.scan().await?;
    print_report(&report);

    println!("\n=== Bottleneck analysis ===\n");
    match diag.find_bottleneck().await? {
        Some(b) => {
            println!("Worst bottleneck:");
            println!("  location:        {}", b.location);
            println!("  type:            {}", b.bottleneck_type);
            println!("  current rate:    {} bytes/sec", b.current_rate);
            println!("  drop rate:       {:.2}%", b.drop_rate * 100.0);
            println!("  total drops:     {}", b.total_drops);
            // Plan 169 Phase 3 (0.17): a 0.0..=1.0 severity score
            // combining drop rate (×0.6), backlog pressure (×0.3),
            // and error rate (×0.1). Backlog and error components
            // are gated on the bottleneck's type, so a pure
            // hardware-error bottleneck scores on the error
            // component alone. Useful for sorting multiple
            // bottlenecks in a controller dashboard.
            println!("  score (0..1):    {:.3}", b.score());
            println!("  recommendation:  {}", b.recommendation);
        }
        None => println!("No bottleneck detected."),
    }

    Ok(())
}

fn print_report(r: &DiagnosticReport) {
    println!(
        "Scanned {} interface(s), {} IPv4 + {} IPv6 routes",
        r.interfaces.len(),
        r.routes.ipv4_route_count,
        r.routes.ipv6_route_count,
    );
    println!(
        "  default IPv4: {}",
        r.routes
            .default_gateway_v4
            .map(|g| g.to_string())
            .unwrap_or_else(|| "(none)".into()),
    );
    println!(
        "  default IPv6: {}",
        r.routes
            .default_gateway_v6
            .map(|g| g.to_string())
            .unwrap_or_else(|| "(none)".into()),
    );

    println!("\nPer-interface summary:");
    for iface in &r.interfaces {
        println!(
            "  {:<16}  state={:<8}  mtu={:<5}  rx={} pkts  tx={} pkts  issues={}",
            iface.name,
            format!("{:?}", iface.state),
            iface
                .mtu
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into()),
            iface.stats.rx_packets(),
            iface.stats.tx_packets(),
            iface.issues.len(),
        );
        if let Some(tc) = &iface.tc {
            println!(
                "      tc: {:<10}  handle={:<6}  drops={}  backlog={}B",
                tc.qdisc, tc.handle, tc.drops, tc.backlog,
            );
        }
    }

    if r.issues.is_empty() {
        println!("\nNo system-level issues detected.");
    } else {
        println!("\nIssues ({} total):", r.issues.len());
        // Sort by severity descending so Critical/Error issues print first.
        let mut sorted: Vec<_> = r.issues.iter().collect();
        sorted.sort_by_key(|i| std::cmp::Reverse(i.severity));
        for issue in sorted {
            let badge = match issue.severity {
                Severity::Critical => "!!",
                Severity::Error => "!",
                Severity::Warning => "?",
                Severity::Info => ".",
                _ => "?",
            };
            println!("  {} {}  {}", badge, issue.severity, issue);
        }
    }
}
