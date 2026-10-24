//! Query (and optionally set) ring buffer sizes via ethtool.
//!
//! Mirrors the `ethtool_features` promote pattern: default is a
//! pure query; `--set-rx <N>` / `--set-tx <N>` ask the kernel to
//! resize the rings, re-queries to confirm, and restores the
//! original values so the host is left as we found it.
//!
//! # Usage
//!
//! ```bash
//! # Query mode — ring + channel parameters (no privileges).
//! cargo run --example ethtool_rings -- eth0
//!
//! # Set/verify/restore mode (requires CAP_NET_ADMIN + a real NIC
//! # whose driver supports `ethtool -G`). A dummy/veth will reject
//! # ring resizing at the driver layer — this is not a bug.
//! sudo cargo run --example ethtool_rings -- eth0 --set-rx 4096
//! sudo cargo run --example ethtool_rings -- eth0 --set-rx 4096 --set-tx 4096
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support.
//! - Query mode: no special privileges.
//! - Set mode: CAP_NET_ADMIN + driver that honors `ETHTOOL_SRINGPARAM`.

use nlink::netlink::{Connection, Ethtool, genl::ethtool::Rings};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "eth0".to_string());

    let mut set_rx: Option<u32> = None;
    let mut set_tx: Option<u32> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--set-rx" => {
                set_rx = Some(parse_count("--set-rx", args.next().as_deref()));
            }
            "--set-tx" => {
                set_tx = Some(parse_count("--set-tx", args.next().as_deref()));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let conn = Connection::<Ethtool>::new_async().await?;

    if set_rx.is_none() && set_tx.is_none() {
        return show_rings(&conn, &ifname).await;
    }

    set_rings_cycle(&conn, &ifname, set_rx, set_tx).await
}

fn parse_count(flag: &str, v: Option<&str>) -> u32 {
    match v.map(|s| s.parse::<u32>()) {
        Some(Ok(n)) => n,
        _ => {
            eprintln!("{flag} requires a positive integer (ring depth in slots)");
            std::process::exit(1);
        }
    }
}

async fn show_rings(conn: &Connection<Ethtool>, ifname: &str) -> nlink::Result<()> {
    println!("Querying ring buffer sizes for {ifname}...\n");

    let rings = conn.get_rings(ifname).await?;
    print_rings(ifname, &rings);

    println!();
    println!("Channel parameters for {ifname}:");
    let channels = conn.get_channels(ifname).await?;

    println!();
    println!("Pre-set maximums:");
    if let Some(rx_max) = channels.rx_max {
        println!("  RX:       {rx_max}");
    }
    if let Some(tx_max) = channels.tx_max {
        println!("  TX:       {tx_max}");
    }
    if let Some(other_max) = channels.other_max {
        println!("  Other:    {other_max}");
    }
    if let Some(combined_max) = channels.combined_max {
        println!("  Combined: {combined_max}");
    }

    println!();
    println!("Current hardware settings:");
    if let Some(rx) = channels.rx_count {
        println!("  RX:       {rx}");
    }
    if let Some(tx) = channels.tx_count {
        println!("  TX:       {tx}");
    }
    if let Some(other) = channels.other_count {
        println!("  Other:    {other}");
    }
    if let Some(combined) = channels.combined_count {
        println!("  Combined: {combined}");
    }

    Ok(())
}

async fn set_rings_cycle(
    conn: &Connection<Ethtool>,
    ifname: &str,
    want_rx: Option<u32>,
    want_tx: Option<u32>,
) -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--set-rx / --set-tx require root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    // Snapshot so we can restore after.
    let before = conn.get_rings(ifname).await?;
    let original_rx = before.rx;
    let original_tx = before.tx;

    println!("Current: {ifname} rx={original_rx:?} tx={original_tx:?}");

    if let Some(rx) = want_rx
        && let Some(max) = before.rx_max
        && rx > max
    {
        eprintln!("WARNING: requested rx={rx} exceeds pre-set max {max}; driver may clamp.");
    }
    if let Some(tx) = want_tx
        && let Some(max) = before.tx_max
        && tx > max
    {
        eprintln!("WARNING: requested tx={tx} exceeds pre-set max {max}; driver may clamp.");
    }

    // Apply the requested change.
    println!(
        "Requesting: {}{}{}",
        want_rx.map(|n| format!("rx={n}")).unwrap_or_default(),
        match (want_rx, want_tx) {
            (Some(_), Some(_)) => " ",
            _ => "",
        },
        want_tx.map(|n| format!("tx={n}")).unwrap_or_default(),
    );
    conn.set_rings(ifname, |mut r| {
        if let Some(rx) = want_rx {
            r = r.rx(rx);
        }
        if let Some(tx) = want_tx {
            r = r.tx(tx);
        }
        r
    })
    .await?;

    // Verify.
    let after = conn.get_rings(ifname).await?;
    println!(
        "Kernel echoes: {ifname} rx={:?} tx={:?}",
        after.rx, after.tx
    );
    if let Some(rx) = want_rx
        && after.rx != Some(rx)
    {
        eprintln!(
            "NOTE: kernel set rx={:?} after requesting {rx}. The driver may have clamped, \
             rounded to a supported depth, or silently ignored. Still restoring the \
             original value on the way out.",
            after.rx
        );
    }
    if let Some(tx) = want_tx
        && after.tx != Some(tx)
    {
        eprintln!("NOTE: kernel set tx={:?} after requesting {tx}.", after.tx);
    }

    // Restore.
    println!("Restoring rx={original_rx:?} tx={original_tx:?}...");
    conn.set_rings(ifname, |mut r| {
        if let Some(rx) = original_rx {
            r = r.rx(rx);
        }
        if let Some(tx) = original_tx {
            r = r.tx(tx);
        }
        r
    })
    .await?;

    let final_ = conn.get_rings(ifname).await?;
    println!("Final: {ifname} rx={:?} tx={:?}", final_.rx, final_.tx);

    Ok(())
}

fn print_rings(ifname: &str, rings: &Rings) {
    println!("Ring parameters for {ifname}:");
    println!();
    println!("Pre-set maximums:");
    if let Some(rx_max) = rings.rx_max {
        println!("  RX:         {rx_max}");
    }
    if let Some(rx_mini_max) = rings.rx_mini_max
        && rx_mini_max > 0
    {
        println!("  RX Mini:    {rx_mini_max}");
    }
    if let Some(rx_jumbo_max) = rings.rx_jumbo_max
        && rx_jumbo_max > 0
    {
        println!("  RX Jumbo:   {rx_jumbo_max}");
    }
    if let Some(tx_max) = rings.tx_max {
        println!("  TX:         {tx_max}");
    }

    println!();
    println!("Current hardware settings:");
    if let Some(rx) = rings.rx {
        println!("  RX:         {rx}");
    }
    if let Some(rx_mini) = rings.rx_mini
        && rx_mini > 0
    {
        println!("  RX Mini:    {rx_mini}");
    }
    if let Some(rx_jumbo) = rings.rx_jumbo
        && rx_jumbo > 0
    {
        println!("  RX Jumbo:   {rx_jumbo}");
    }
    if let Some(tx) = rings.tx {
        println!("  TX:         {tx}");
    }

    if let Some(rx_buf_len) = rings.rx_buf_len {
        println!();
        println!("  RX Buf Len: {rx_buf_len}");
    }
    if let Some(cqe_size) = rings.cqe_size {
        println!("  CQE Size:   {cqe_size}");
    }
    if let Some(tx_push) = rings.tx_push {
        println!("  TX Push:    {}", if tx_push { "on" } else { "off" });
    }
    if let Some(rx_push) = rings.rx_push {
        println!("  RX Push:    {}", if rx_push { "on" } else { "off" });
    }
}
