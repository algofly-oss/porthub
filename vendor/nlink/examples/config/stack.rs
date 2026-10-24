//! `Stack` — the unified declarative bundle (network + nftables +
//! WireGuard) applied in dependency order.
//!
//! One type declares all three layers; `diff()` validates every set
//! layer against kernel state before `apply()` mutates anything
//! (pre-flight), and apply order is links → firewall → VPN so later
//! layers can reference earlier ones. Since 0.24 (#169) the
//! namespace-spec variants (`diff_in` / `apply_in` with
//! `NamespaceSpec::{Named, Path, Pid}`) cover containers, the diff
//! and report expose `change_count()`, and a declared-but-absent
//! WireGuard device bootstraps automatically.
//!
//! Run modes:
//!
//! ```bash
//! # Diff-only against the live host (unprivileged; read-only)
//! cargo run -p nlink --example config_stack
//!
//! # Apply + converge + clean up. Requires root (CAP_NET_ADMIN).
//! sudo -E cargo run -p nlink --example config_stack -- --apply
//! ```

use nlink::facade::Stack;
use nlink::netlink::config::NetworkConfig;
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::{BaseChain, Family, FilterHook, Policy, Priority};

fn desired() -> Stack {
    Stack::new()
        .network(
            NetworkConfig::new()
                .link("stack0", |l| l.dummy().mtu(1400).up())
                .address("stack0", "192.0.2.1/24")
                .expect("valid CIDR"),
        )
        .nftables(
            NftablesConfig::new().table("stack_demo", Family::Inet, |t| {
                t.chain("input", |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Input, Priority::Filter)
                            .policy(Policy::Accept),
                    )
                })
                .rule("input", |r| r.match_iif("stack0").counter().accept())
            }),
        )
}

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let apply = std::env::args().any(|a| a == "--apply");
    let stack = desired();

    if !apply {
        // Unprivileged: the network layer diffs read-only. (The
        // nftables layer needs CAP_NET_ADMIN even to dump, so
        // diff-only mode inspects the network half.)
        let net_only = Stack::new().network(desired().network.unwrap());
        let diff = net_only
            .plan(nlink::netlink::config::PlanOptions::default())
            .await?;
        println!(
            "network layer drift: {} pending change(s)",
            diff.change_count()
        );
        if let Some(net) = &diff.network {
            print!("{net}");
        }
        println!("\nRe-run with --apply (as root) to converge all layers.");
        return Ok(());
    }

    // Pre-flight validation runs inside apply(): every set layer's
    // diff must succeed before the first mutation.
    let report = stack.apply().await?;
    println!(
        "applied: {} kernel mutation(s) (noop = {})",
        report.change_count(),
        report.is_noop()
    );

    // Converged: a second apply reports no work.
    let again = stack.apply().await?;
    println!(
        "re-apply: {} mutation(s) (expect 0 → is_noop {})",
        again.change_count(),
        again.is_noop()
    );

    // Cleanup (if_exists shapes — #169 — so re-runs never error).
    let conn = nlink::Connection::<nlink::Route>::new()?;
    conn.del_link_if_exists("stack0").await?;
    let nft = nlink::Connection::<nlink::Nftables>::new()?;
    nft.del_table_if_exists("stack_demo", Family::Inet).await?;
    println!("cleaned up stack0 + stack_demo table");
    Ok(())
}
