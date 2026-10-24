//! Query (and optionally toggle) device features (offloads) via ethtool.
//!
//! Demonstrates the ethtool genl interface for hardware offloads —
//! `tx-checksumming`, `rx-gro`, `tx-tcp-segmentation`, etc.
//!
//! # Usage
//!
//! ```bash
//! # Query mode: list features for a device (default eth0).
//! cargo run --example ethtool_features -- eth0
//!
//! # Toggle mode: flip one feature to the opposite of its current
//! # state, print the new state, then restore the original value.
//! # Requires CAP_NET_ADMIN.
//! sudo cargo run --example ethtool_features -- eth0 --toggle tx-tcp-segmentation
//! ```
//!
//! # Requirements
//!
//! - Linux kernel 5.6+ with ethtool netlink support
//! - Query mode: no special privileges
//! - `--toggle` mode: CAP_NET_ADMIN
//!
//! # What `--toggle` does
//!
//! 1. Snapshots the feature's current on/off state.
//! 2. Calls `set_features()` to flip it.
//! 3. Re-queries and confirms the kernel applied the change.
//! 4. Restores the original state so the host is left as we found it.
//!
//! If the feature is marked `[fixed]` (the kernel refuses to change
//! it, typically because the driver doesn't support toggling), the
//! `set_features()` call will return an error and the original state
//! is already unchanged.

use nlink::netlink::{Connection, Ethtool};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "eth0".to_string());

    let mut toggle_feature: Option<String> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--toggle" => {
                toggle_feature = Some(
                    args.next()
                        .expect("--toggle requires a feature name, e.g. `tx-tcp-segmentation`"),
                );
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let conn = Connection::<Ethtool>::new_async().await?;

    match toggle_feature {
        None => list_features(&conn, &ifname).await,
        Some(name) => toggle_feature_cycle(&conn, &ifname, &name).await,
    }
}

async fn list_features(conn: &Connection<Ethtool>, ifname: &str) -> nlink::Result<()> {
    println!("Querying features for {ifname}...\n");

    let features = conn.get_features(ifname).await?;

    println!("Features for {ifname}:");
    println!();

    let mut feature_list: Vec<_> = features.iter().collect();
    feature_list.sort_by_key(|(name, _)| *name);

    for (name, enabled) in feature_list {
        let status = if enabled { "on" } else { "off" };
        let changeable = if features.is_changeable(name) {
            ""
        } else {
            " [fixed]"
        };
        let hw = if features.is_hw_supported(name) {
            ""
        } else {
            " [not hw]"
        };
        println!("  {name}: {status}{changeable}{hw}");
    }

    let active_count = features.active_features().len();
    let total = features.active.len();
    println!();
    println!("Summary: {active_count} of {total} features enabled");

    Ok(())
}

async fn toggle_feature_cycle(
    conn: &Connection<Ethtool>,
    ifname: &str,
    feature: &str,
) -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--toggle requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    let before = conn.get_features(ifname).await?;
    let original = before.is_active(feature);

    if !before.is_changeable(feature) {
        eprintln!(
            "Feature `{feature}` on {ifname} is [fixed] — the driver refuses \
             runtime toggling. Aborting before calling set_features()."
        );
        std::process::exit(2);
    }

    println!(
        "Current: {ifname}:{feature} = {}",
        if original { "on" } else { "off" }
    );

    // Flip.
    let target = !original;
    println!("Setting to {}...", if target { "on" } else { "off" });
    conn.set_features(ifname, |fb| {
        if target {
            fb.enable(feature)
        } else {
            fb.disable(feature)
        }
    })
    .await?;

    // Verify kernel accepted the change.
    let after = conn.get_features(ifname).await?;
    let observed = after.is_active(feature);
    println!(
        "Kernel echoes: {ifname}:{feature} = {}",
        if observed { "on" } else { "off" }
    );
    if observed != target {
        eprintln!(
            "WARNING: kernel reported {observed} after set_features({target}); \
             driver may silently reject the change."
        );
    }

    // Restore original state so the host is left as we found it.
    println!(
        "Restoring original state ({})...",
        if original { "on" } else { "off" }
    );
    conn.set_features(ifname, |fb| {
        if original {
            fb.enable(feature)
        } else {
            fb.disable(feature)
        }
    })
    .await?;

    let restored = conn.get_features(ifname).await?;
    println!(
        "Final: {ifname}:{feature} = {}",
        if restored.is_active(feature) {
            "on"
        } else {
            "off"
        }
    );

    Ok(())
}
