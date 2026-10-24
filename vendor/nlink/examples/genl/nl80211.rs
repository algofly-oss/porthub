//! WiFi inspection + scan trigger via nl80211.
//!
//! Demonstrates listing wireless interfaces / phys / stations /
//! regulatory domain, and — with `--scan <iface>` — triggering a
//! scan, waiting for the completion event, and printing the
//! discovered BSSes.
//!
//! # Usage
//!
//! ```bash
//! # Inventory mode — query all the read APIs.
//! cargo run -p nlink --example genl_nl80211
//!
//! # Scan mode — trigger an active scan on an interface and print
//! # results when the kernel completes it. Requires CAP_NET_ADMIN.
//! sudo cargo run -p nlink --example genl_nl80211 -- --scan wlan0
//! ```
//!
//! # Notes
//!
//! Scanning doesn't disconnect you from a connected AP — it's a
//! safe operation to demo on an in-use machine. The trigger returns
//! immediately; actual results arrive asynchronously via the
//! `ScanComplete` multicast event (typically 1-5 seconds later).

use std::time::Duration;

use nlink::netlink::{
    Connection, Nl80211,
    genl::nl80211::{Nl80211Event, ScanRequest, ScanResult},
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut scan_iface: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--scan" => {
                scan_iface = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--scan requires an interface name, e.g. `wlan0`");
                    std::process::exit(1);
                }));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    match scan_iface {
        None => show_inventory().await,
        Some(iface) => scan(&iface).await,
    }
}

async fn show_inventory() -> nlink::Result<()> {
    let conn = match Connection::<Nl80211>::new_async().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open nl80211 GENL: {e}");
            eprintln!("Make sure cfg80211 is loaded (sudo modprobe cfg80211).");
            return Ok(());
        }
    };

    println!("=== Wireless interfaces ===\n");
    let interfaces = conn.get_interfaces().await?;
    if interfaces.is_empty() {
        println!("  No wireless interfaces found.");
        println!();
        println!("  Run `--scan <iface>` on a real interface to exercise the");
        println!("  scan-and-wait flow.");
        return Ok(());
    }
    for iface in &interfaces {
        let name = iface.name.as_deref().unwrap_or("?");
        println!("  {name}: type={:?}", iface.iftype);
        if let Some(mac) = iface.mac_str() {
            println!("    mac:       {mac}");
        }
        if let Some(freq) = iface.frequency {
            println!("    frequency: {freq} MHz");
        }
    }

    println!("\n=== Physical devices ===\n");
    for phy in &conn.get_phys().await? {
        println!(
            "  phy#{}: {} ({} bands)",
            phy.index,
            phy.name,
            phy.bands.len()
        );
    }

    if let Some(iface) = interfaces.first() {
        let name = iface.name.as_deref().unwrap_or("wlan0");
        println!("\n=== Station info ({name}) ===\n");
        match conn.get_stations(name).await {
            Ok(stations) if stations.is_empty() => println!("  Not connected."),
            Ok(stations) => {
                for sta in &stations {
                    if let Some(signal) = sta.signal_dbm {
                        println!("  signal: {signal} dBm");
                    }
                    if let Some(rx) = &sta.rx_bitrate {
                        println!("  rx:     {:?}", rx.mbps());
                    }
                    if let Some(tx) = &sta.tx_bitrate {
                        println!("  tx:     {:?}", tx.mbps());
                    }
                }
            }
            Err(e) => eprintln!("  get_stations failed: {e}"),
        }
    }

    println!("\n=== Regulatory domain ===\n");
    match conn.get_regulatory().await {
        Ok(reg) => println!("  country: {}", reg.country),
        Err(e) => eprintln!("  get_regulatory failed: {e}"),
    }

    Ok(())
}

async fn scan(iface: &str) -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--scan requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    // Two connections: one for the scan command, another subscribed to
    // the scan-complete event. Nl80211's scan results arrive through
    // the multicast group, not as the reply to `trigger_scan`.
    let cmd = Connection::<Nl80211>::new_async().await?;

    let iface_info = cmd
        .get_interfaces()
        .await?
        .into_iter()
        .find(|i| i.name.as_deref() == Some(iface))
        .ok_or_else(|| {
            eprintln!("interface `{iface}` not found in nl80211 inventory");
            std::process::exit(1);
        })
        .unwrap();
    let ifindex = iface_info.ifindex;

    let evt = Connection::<Nl80211>::new_async().await?;
    evt.subscribe()?;

    println!("Triggering scan on {iface} (ifindex {ifindex})...");
    cmd.trigger_scan(iface, &ScanRequest::default()).await?;

    // Wait up to 15s for the scan to complete. Scans are usually 1-5s,
    // but dense environments + many channels can push that out.
    println!("Waiting for ScanComplete...");
    let mut stream = evt.events().await;
    let wait = async {
        while let Some(result) = stream.next().await {
            match result? {
                Nl80211Event::ScanComplete { ifindex: i } if i == ifindex => {
                    println!("  scan completed on ifindex {i}");
                    return Ok(());
                }
                Nl80211Event::ScanAborted { ifindex: i } if i == ifindex => {
                    eprintln!("  scan was aborted on ifindex {i}");
                    return Err(nlink::Error::from(std::io::Error::other("scan aborted")));
                }
                _ => {}
            }
        }
        Err(nlink::Error::from(std::io::Error::other(
            "event stream ended before ScanComplete",
        )))
    };

    match tokio::time::timeout(Duration::from_secs(15), wait).await {
        Ok(res) => res?,
        Err(_) => {
            eprintln!("  timed out after 15s waiting for ScanComplete");
        }
    }

    println!();
    println!("=== Scan results ===\n");
    let results = cmd.get_scan_results(iface).await?;
    if results.is_empty() {
        println!("  (no results — environment may be RF-quiet or scan was partial)");
        return Ok(());
    }
    for r in &results {
        print_result(r);
    }

    Ok(())
}

fn print_result(r: &ScanResult) {
    let ssid = r
        .ssid
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("(hidden)")
        .to_string();
    let secure = if r.is_privacy() { "[secured]" } else { "" };
    println!(
        "  {}  {:>4} MHz  {:>4} dBm  {ssid}  {secure}",
        r.bssid_str(),
        r.frequency,
        r.signal_dbm(),
    );
}
