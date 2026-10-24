//! WireGuard configuration — full device + peer lifecycle.
//!
//! Demonstrates the write-path side of `Connection::<Wireguard>`:
//! creating a `wg0` interface, setting its private key and listen
//! port, adding a peer with an endpoint + allowed-ips, dumping the
//! resulting state, and removing the peer — all inside a temporary
//! namespace.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns and the API overview (no privileges)
//! cargo run -p nlink --example genl_wireguard
//!
//! # Probe a real host for existing wireguard interfaces (read-only)
//! cargo run -p nlink --example genl_wireguard -- show
//!
//! # Create wg0 + configure + add peer + dump + cleanup in a
//! # temporary namespace. Requires root (CAP_NET_ADMIN) and the
//! # `wireguard` kernel module.
//! sudo cargo run -p nlink --example genl_wireguard -- --apply
//! ```
//!
//! See also: `nlink::netlink::genl::wireguard::{WgDevice, WgPeer,
//! AllowedIp}`, and `nlink::netlink::link::WireguardLink` for
//! rtnetlink-side interface creation.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::SystemTime,
};

use nlink::netlink::{
    Connection, Route, Wireguard,
    genl::wireguard::{AllowedIp, WgDevice, WgPeer},
    link::WireguardLink,
    namespace,
};

// Hardcoded 32-byte "keys" for the demo. Real deployments generate
// these with `wg genkey`; we don't run crypto in a throwaway namespace
// and the kernel accepts any 32-byte blob.
const LOCAL_PRIVATE: [u8; 32] = [0x01; 32];
const PEER_PUBLIC: [u8; 32] = [0x02; 32];

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            run_show().await?;
        }
        Some("--apply") => {
            run_apply().await?;
        }
        _ => {
            print_overview();
        }
    }

    Ok(())
}

fn print_overview() {
    println!("=== WireGuard (Generic Netlink) ===\n");
    println!("The `Connection::<Wireguard>` handle sits on top of the WG");
    println!("GENL family. Interface creation is rtnetlink (same as any");
    println!("kind=wireguard link); key and peer config flows through GENL.\n");

    println!("--- What --apply does ---\n");
    println!(
        "    1. Create a temporary namespace.
    2. Add wg0 (kind=wireguard) and bring it up (rtnetlink).
    3. Configure via GENL: private key + listen port.
    4. Add a peer: public key + endpoint + allowed-ip + keepalive.
    5. Dump with get_device() to verify round-trip.
    6. del_peer(), then delete the namespace (wg0 goes with it).
"
    );

    println!("--- Code ---\n");
    println!(
        r#"    use nlink::netlink::{{Connection, Route, Wireguard, namespace}};
    use nlink::netlink::genl::wireguard::AllowedIp;
    use nlink::netlink::link::WireguardLink;
    use std::net::{{Ipv4Addr, SocketAddrV4}};

    // rtnetlink side — create the interface.
    let route: Connection<Route> = nlink::Connection::new_in("lab")?;
    route.add_link(WireguardLink::new("wg0")).await?;
    route.set_link_up("wg0").await?;

    // GENL side — set keys + peer.
    let wg: Connection<Wireguard> = nlink::Connection::new_in_async("lab").await?;

    wg.set_device("wg0", |dev| {{
        dev.private_key(local_private_key)
           .listen_port(51820)
    }}).await?;

    wg.set_peer("wg0", peer_public_key, |peer| {{
        peer.endpoint(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 51820).into())
            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
            .persistent_keepalive(25)
            .replace_allowed_ips()
    }}).await?;

    let device = wg.get_device("wg0").await?;
    for peer in &device.peers {{ /* ... */ }}

    // Remove a peer without tearing down the interface:
    wg.del_peer("wg0", peer_public_key).await?;
"#
    );

    println!("--- Re-run with `--apply` (as root) ---");
    println!("  Runs the lifecycle above in a temporary namespace.");
    println!();
    println!("--- Read-only mode ---");
    println!("  `show` probes common wg* interface names on the current host.");
}

async fn run_show() -> nlink::Result<()> {
    let conn = match Connection::<Wireguard>::new_async().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to connect to WireGuard GENL: {e}");
            eprintln!("Try: sudo modprobe wireguard");
            return Ok(());
        }
    };

    println!("=== WireGuard interfaces (probing wg0..wg2, wg-vpn, wireguard0) ===\n");
    let candidates = ["wg0", "wg1", "wg2", "wg-vpn", "wireguard0"];
    let mut found = false;

    for name in candidates {
        match conn.get_device(name).await {
            Ok(device) => {
                found = true;
                print_device(&device);
            }
            Err(e) if e.is_not_found() || e.is_no_device() => {}
            Err(e) => eprintln!("Error querying {name}: {e}"),
        }
    }

    if !found {
        println!("No WireGuard interfaces found.");
        println!("Build one with: sudo cargo run -p nlink --example genl_wireguard -- --apply");
    }

    Ok(())
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== WireGuard live demo (temporary namespace) ===");

    let ns_name = format!("nlink-wg-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    // rtnetlink side — create wg0 inside the namespace.
    let route: Connection<Route> = nlink::Connection::new_in(ns_name)?;

    route
        .add_link(WireguardLink::new("wg0"))
        .await
        .map_err(|e| {
            eprintln!("\n  add_link(wg0, kind=wireguard) failed: {e}");
            eprintln!("  Is the `wireguard` kernel module loaded? `sudo modprobe wireguard`.");
            e
        })?;
    route.set_link_up("wg0").await?;
    let link = route.get_link_by_name("wg0").await?.expect("just created");
    println!(
        "  Created wg0 (ifindex {}) in namespace `{ns_name}`.",
        link.ifindex()
    );

    // GENL side — configure via set_device + set_peer.
    let wg: Connection<Wireguard> = nlink::Connection::new_in_async(ns_name).await?;
    println!(
        "  Opened WireGuard GENL connection (family_id={}).",
        wg.family_id()
    );

    println!();
    println!("  set_device: private_key + listen_port=51820");
    wg.set_device("wg0", |dev| {
        dev.private_key(LOCAL_PRIVATE).listen_port(51820)
    })
    .await?;

    println!(
        "  set_peer:   pubkey={} endpoint=10.0.0.1:51820 allowed=10.0.0.0/24 keepalive=25s",
        short_key(&PEER_PUBLIC)
    );
    wg.set_peer("wg0", PEER_PUBLIC, |peer| {
        peer.endpoint(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            51820,
        )))
        .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
        .persistent_keepalive(25)
        .replace_allowed_ips()
    })
    .await?;

    println!();
    println!("  --- get_device(wg0) ---");
    let device = wg.get_device("wg0").await?;
    print_device(&device);

    println!("  Removing peer via del_peer()...");
    wg.del_peer("wg0", PEER_PUBLIC).await?;

    let device_after = wg.get_device("wg0").await?;
    println!(
        "  After del_peer: {} peer(s) remaining on wg0.",
        device_after.peers.len()
    );

    Ok(())
}

fn print_device(device: &WgDevice) {
    let ifname = device.ifname.as_deref().unwrap_or("?");
    let ifindex = device.ifindex.unwrap_or(0);

    println!("  interface: {ifname} (index {ifindex})");
    if let Some(key) = &device.public_key {
        println!("    public key: {}", short_key(key));
    }
    if let Some(port) = device.listen_port {
        println!("    listen port: {port}");
    }
    if let Some(fwmark) = device.fwmark
        && fwmark != 0
    {
        println!("    fwmark: 0x{fwmark:x}");
    }
    if device.peers.is_empty() {
        println!("    peers: (none)");
    } else {
        println!("    peers: {}", device.peers.len());
        for peer in &device.peers {
            print_peer(peer);
        }
    }
}

fn print_peer(peer: &WgPeer) {
    println!("      peer:  {}", short_key(&peer.public_key));
    if let Some(ep) = &peer.endpoint {
        println!("        endpoint:    {ep}");
    }
    if !peer.allowed_ips.is_empty() {
        let s: Vec<String> = peer
            .allowed_ips
            .iter()
            .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
            .collect();
        println!("        allowed ips: {}", s.join(", "));
    }
    if let Some(k) = peer.persistent_keepalive
        && k > 0
    {
        println!("        keepalive:   every {k}s");
    }
    if let Some(t) = peer.last_handshake
        && let Ok(d) = SystemTime::now().duration_since(t)
    {
        println!("        handshake:   {} seconds ago", d.as_secs());
    }
    if peer.rx_bytes > 0 || peer.tx_bytes > 0 {
        println!(
            "        transfer:    {} rx, {} tx (bytes)",
            peer.rx_bytes, peer.tx_bytes
        );
    }
}

/// Short hex preview of a 32-byte key — enough to identify it in
/// terminal output without dragging in a base64 encoder.
fn short_key(key: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
        key[0], key[1], key[2], key[3], key[28], key[29], key[30], key[31],
    )
}
