//! DPLL device + pin enumeration via the typed
//! `Connection<Dpll>::dump_devices` / `dump_pins` API.
//!
//! On hosts with DPLL hardware (Intel `ice` ConnectX-7, Mellanox
//! `mlx5` ConnectX-7, NVIDIA BlueField-3, …) this prints every
//! DPLL device the kernel sees plus every pin grouped by parent
//! device. On hosts without DPLL hardware it prints a brief
//! "DPLL not available on this kernel" notice and exits cleanly.
//!
//! Run modes:
//!
//! ```bash
//! # Print overview + API walkthrough (no kernel call)
//! cargo run -p nlink --example genl_dpll
//!
//! # Probe the host and print every DPLL device + its pins.
//! # No root needed for read-only DPLL queries.
//! cargo run -p nlink --example genl_dpll -- show
//! ```
//!
//! See `docs/recipes/dpll-monitor.md` for the canonical
//! "watch lock-status transitions" pattern (multicast monitor
//! support lands in Plan 156 Phase 5).

use std::collections::BTreeMap;

use nlink::netlink::{
    genl::dpll::{DpllPinReply, Dpll},
    Connection,
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("show") => run_show().await,
        _ => {
            print_overview();
            Ok(())
        }
    }
}

fn print_overview() {
    println!("=== DPLL via nlink-macros (Plan 156) ===\n");
    println!("Reads the kernel's DPLL Generic Netlink family — full");
    println!("device + pin enumeration in ~30 lines of consumer code:\n");
    println!("    use nlink::netlink::{{Connection, genl::dpll::Dpll}};");
    println!("    use tokio_stream::StreamExt;");
    println!();
    println!("    let conn = Connection::<Dpll>::new_async().await?;");
    println!("    let mut devices = conn.dump_devices().await?;");
    println!("    while let Some(dev) = devices.next().await {{");
    println!("        let dev = dev?;");
    println!("        println!(\"device {{}}: {{:?}}\", dev.id, dev.lock_status);");
    println!("    }}\n");
    println!("--- What `show` does ---\n");
    println!("    1. Connects to NETLINK_GENERIC + resolves the \"dpll\"");
    println!("       family ID via CTRL_CMD_GETFAMILY.");
    println!("    2. Streams every device through dump_devices().");
    println!("    3. Streams every pin through dump_pins(), grouping");
    println!("       client-side by parent_device.parent_id.");
    println!("    4. Prints the device + pin summary in a hierarchy.\n");
    println!("    No root needed for read-only DPLL queries; the kernel");
    println!("    only requires CAP_NET_ADMIN for *_SET commands.\n");
    println!("    On kernels without DPLL (no CONFIG_DPLL, or no DPLL");
    println!("    driver loaded) this prints a brief notice and exits.");
}

async fn run_show() -> nlink::Result<()> {
    println!("→ Connection::<Dpll>::new_async()");
    let conn = match Connection::<Dpll>::new_async().await {
        Ok(c) => c,
        Err(e) if e.is_not_found() => {
            eprintln!(
                "DPLL family not registered on this kernel — either \
                 CONFIG_DPLL is disabled or no DPLL driver is loaded. \
                 (This is the common case on stock distro kernels.)"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    println!("  family_id resolved\n");

    // Devices first.
    println!("=== DPLL devices ===");
    let mut devices = match conn.dump_devices().await {
        Ok(s) => s,
        Err(e) if e.is_permission_denied() => {
            eprintln!(
                "  EPERM — DPLL queries require CAP_NET_ADMIN on this kernel. \
                 Re-run with sudo."
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut device_count = 0;
    while let Some(dev) = devices.next().await {
        let dev = match dev {
            Ok(d) => d,
            Err(e) if e.is_permission_denied() => {
                eprintln!("  EPERM mid-stream — needs CAP_NET_ADMIN");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        device_count += 1;
        println!(
            "  device id={} module={:?} type={:?} mode={:?} lock={:?}",
            dev.id, dev.module_name, dev.kind, dev.mode, dev.lock_status,
        );
        if let Some(c) = dev.temp_celsius() {
            println!("    temperature: {c:.1} °C");
        }
        if !dev.clock_quality_level.is_empty() {
            println!("    quality:     {:?}", dev.clock_quality_level);
        }
        if let Some(err) = dev.lock_status_error {
            println!("    lock error:  {err:?}");
        }
    }
    if device_count == 0 {
        println!("  (no DPLL devices on this host)");
    }
    println!();

    // Pins, grouped by parent device.
    println!("=== DPLL pins (grouped by parent device) ===");
    let mut pins = match conn.dump_pins().await {
        Ok(s) => s,
        Err(e) if e.is_permission_denied() => {
            eprintln!("  EPERM — DPLL pin queries require CAP_NET_ADMIN");
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut by_device: BTreeMap<u32, Vec<DpllPinReply>> = BTreeMap::new();
    while let Some(pin) = pins.next().await {
        let pin = match pin {
            Ok(p) => p,
            Err(e) if e.is_permission_denied() => break,
            Err(e) => return Err(e),
        };
        let parent_id = pin
            .parent_device
            .as_ref()
            .map(|p| p.parent_id)
            .unwrap_or(u32::MAX);
        by_device.entry(parent_id).or_default().push(pin);
    }
    if by_device.is_empty() {
        println!("  (no DPLL pins on this host)");
    }
    for (parent_id, pins) in by_device {
        if parent_id == u32::MAX {
            println!("  orphan pins (no parent device):");
        } else {
            println!("  parent device {parent_id}:");
        }
        for pin in pins {
            let label = pin
                .board_label
                .as_deref()
                .or(pin.panel_label.as_deref())
                .or(pin.package_label.as_deref())
                .unwrap_or("?");
            println!(
                "    pin id={} label={:?} type={:?} direction={:?} state={:?} prio={:?}",
                pin.id, label, pin.kind, pin.direction, pin.state, pin.prio,
            );
            if let Some(hz) = pin.frequency {
                println!("      frequency:           {hz} Hz");
            }
            if let Some(ns) = pin.phase_offset_ns() {
                println!("      phase offset:        {ns} ns");
            }
            if let Some(hz) = pin.measured_frequency_hz() {
                println!("      measured frequency:  {hz} Hz");
            }
            if !pin.capabilities.is_empty() {
                println!("      capabilities:        {:?}", pin.capabilities);
            }
        }
    }

    Ok(())
}
