//! Devlink device management — info, ports, health, and optional
//! driver reinit.
//!
//! # Usage
//!
//! ```bash
//! # Inventory mode — list devlink devices + firmware info + ports +
//! # health reporters. Safe on any system with devlink-capable HW.
//! cargo run -p nlink --example genl_devlink
//!
//! # Trigger a driver reinit (`ReloadAction::DriverReinit`) on a
//! # specific device. RISKY: the NIC will drop link for the duration
//! # of the reinit. Only use in isolated lab hosts. Requires root.
//! sudo cargo run -p nlink --example genl_devlink -- \
//!     --reload pci/0000:03:00.0
//! ```
//!
//! # Requirements
//!
//! - Devlink-capable NIC driver (mlx5, ice, bnxt, sfc, etc.).
//! - Inventory mode: no privileges.
//! - `--reload`: CAP_NET_ADMIN + a devlink device path like
//!   `pci/0000:03:00.0` (use the inventory mode to find it).

use nlink::netlink::{
    Connection, Devlink,
    genl::devlink::{DevlinkDevice, ReloadAction},
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut reload_target: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--reload" => {
                reload_target = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--reload requires a devlink device path, e.g. `pci/0000:03:00.0`");
                    std::process::exit(1);
                }));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let conn = match Connection::<Devlink>::new_async().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open devlink GENL: {e}");
            eprintln!("Devlink requires a supported NIC driver (mlx5, ice, bnxt, ...).");
            return Ok(());
        }
    };

    match reload_target {
        None => inventory(&conn).await,
        Some(path) => reload_cycle(&conn, &path).await,
    }
}

async fn inventory(conn: &Connection<Devlink>) -> nlink::Result<()> {
    println!("=== Devlink devices ===\n");
    let devices = conn.get_devices().await?;
    if devices.is_empty() {
        println!("  No devlink devices found.");
        println!("  (Devlink is exposed only by drivers that support the devlink interface.)");
        return Ok(());
    }
    for dev in &devices {
        println!("  {}", dev.path());
    }

    for dev in &devices {
        println!("\n=== {} ===", dev.path());
        print_device(conn, dev).await;
    }

    Ok(())
}

async fn print_device(conn: &Connection<Devlink>, dev: &DevlinkDevice) {
    match conn.get_device_info(&dev.bus, &dev.device).await {
        Ok(info) => {
            println!("  driver: {}", info.driver);
            if !info.versions_running.is_empty() {
                println!("  versions:");
                for v in &info.versions_running {
                    println!("    {:<20} {}", v.name, v.value);
                }
            }
            if info.has_pending_update() {
                println!("  *** Pending firmware update! ***");
            }
        }
        Err(e) => eprintln!("  get_device_info failed: {e}"),
    }

    match conn.get_ports().await {
        Ok(ports) => {
            let dev_ports: Vec<_> = ports
                .iter()
                .filter(|p| p.bus == dev.bus && p.device == dev.device)
                .collect();
            if !dev_ports.is_empty() {
                println!("  ports:");
                for port in &dev_ports {
                    println!(
                        "    {:<24} flavour={:?} netdev={:?}",
                        port.path(),
                        port.flavour,
                        port.netdev_name
                    );
                }
            }
        }
        Err(e) => eprintln!("  get_ports failed: {e}"),
    }

    match conn.get_health_reporters(&dev.bus, &dev.device).await {
        Ok(reporters) if !reporters.is_empty() => {
            println!("  health reporters:");
            for r in &reporters {
                println!(
                    "    {:<20} state={:?} errors={}",
                    r.name, r.state, r.error_count
                );
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("  get_health_reporters failed: {e}"),
    }
}

async fn reload_cycle(conn: &Connection<Devlink>, target: &str) -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--reload requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    // Parse "bus/device" (e.g., "pci/0000:03:00.0").
    let (bus, device) = match target.split_once('/') {
        Some((b, d)) => (b, d),
        None => {
            eprintln!("Expected device path like `pci/0000:03:00.0`, got `{target}`");
            std::process::exit(1);
        }
    };

    let devices = conn.get_devices().await?;
    let dev = devices
        .iter()
        .find(|d| d.bus == bus && d.device == device)
        .ok_or_else(|| {
            eprintln!("device `{target}` not present in devlink inventory");
            std::process::exit(1);
        })
        .unwrap();

    // Snapshot pre-reload state to give the user a sense of what they're about to disrupt.
    println!("Pre-reload state for {target}:");
    print_device(conn, dev).await;

    println!();
    println!("Triggering reload(DriverReinit) on {target}...");
    println!("  NOTE: the device's network link will flap for the duration of the reinit.");
    conn.reload(bus, device, ReloadAction::DriverReinit).await?;
    println!("  reload() returned OK.");

    // Re-query to confirm the device reappeared.
    println!();
    println!("Post-reload state for {target}:");
    let devices_after = conn.get_devices().await?;
    match devices_after
        .iter()
        .find(|d| d.bus == bus && d.device == device)
    {
        Some(dev) => print_device(conn, dev).await,
        None => println!("  device not present in inventory — reload may still be in progress"),
    }

    Ok(())
}
