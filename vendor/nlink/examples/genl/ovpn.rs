//! OpenVPN data-channel offload (DCO) demo via the typed
//! `Connection<Ovpn>` + declarative `OvpnConfig` APIs.
//!
//! This example walks every shipping op without requiring an
//! actual OpenVPN userspace handshake. It demonstrates the
//! Rust-side shape; the cipher keys here are zero-fill
//! placeholders (real deployments derive them via TLS).
//!
//! Run modes:
//!
//! ```bash
//! # Print API overview only (no kernel calls).
//! cargo run -p nlink --example genl_ovpn
//!
//! # Probe the host: try to open Connection<Ovpn> + report
//! # whether the family is registered. No root needed.
//! cargo run -p nlink --example genl_ovpn -- probe
//!
//! # Full demo: create an ovpn interface in a lab namespace,
//! # apply a 1-peer OvpnConfig, dump peers, tear down. Requires
//! # root + kernel 6.16+ + the `ovpn` module.
//! sudo cargo run -p nlink --example genl_ovpn --features lab -- apply
//! ```
//!
//! See `docs/recipes/openvpn-dco.md` for the canonical
//! "production-shape OvpnConfig + rekey via key_swap" pattern.

use nlink::netlink::genl::ovpn::{Ovpn, OvpnEvent};
use nlink::netlink::{Connection, Route};
use tokio_stream::StreamExt;
#[cfg(feature = "lab")]
use nlink::netlink::genl::ovpn::{
    OvpnCipherAlg, OvpnConfig, OvpnKeyConfig, OvpnKeySlot, OvpnKeydir,
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("probe") => run_probe().await,
        Some("apply") => run_apply().await,
        Some("monitor") => run_monitor(args.get(2).map(|s| s.as_str())).await,
        _ => {
            print_overview();
            Ok(())
        }
    }
}

fn print_overview() {
    println!(
        "OVPN GENL family — OpenVPN data-channel offload (kernel 6.16+)\n\
         \n\
         Use:\n\
         \n\
         use nlink::netlink::{{Connection, genl::ovpn::*}};\n\
         \n\
         let conn = Connection::<Ovpn>::new_async().await?;\n\
         \n\
         // Imperative — single ops\n\
         conn.peer_new(ifindex, OvpnPeer::identity(42)).await?;\n\
         conn.peer_dump(ifindex).await?;\n\
         conn.key_swap(ifindex, 42).await?;\n\
         \n\
         // Declarative — describe desired state, then diff + apply\n\
         OvpnConfig::new()\n\
             .interface(ifindex, |b| {{\n\
                 b.peer(42, |p| {{\n\
                     p.remote(\"10.0.0.1:1194\".parse().unwrap())\n\
                         .keepalive(20, 60)\n\
                         .key(OvpnKeySlot::Primary, key_config)\n\
                 }})\n\
             }})\n\
             .apply(&conn).await?;\n\
         \n\
         Run modes:\n\
           probe          probe the host's `ovpn` GENL family availability\n\
           monitor <if>   dump per-peer stats on <if>, then stream lifecycle events\n\
           apply          full lab-namespace demo (root + kernel 6.16+ + `ovpn` module)\n",
    );
}

async fn run_probe() -> nlink::Result<()> {
    println!("Probing host for OVPN GENL family…");
    match Connection::<Ovpn>::new_async().await {
        Ok(_conn) => {
            println!("  ovpn family registered (kernel 6.16+ with CONFIG_OVPN).");
            println!("  Connection::<Ovpn> opened successfully.");
            println!("  Next: create an ovpn link via OvpnLink + the rtnetlink connection,");
            println!("  then operate on it via the ifindex with Connection<Ovpn>.");
        }
        Err(e) if e.is_not_found() => {
            println!("  ovpn family NOT registered.");
            println!("  Likely causes:");
            println!("    - kernel < 6.16");
            println!("    - CONFIG_OVPN=n");
            println!("    - `ovpn` module not loaded (try `modprobe ovpn`)");
        }
        Err(e) => {
            println!("  unexpected error: {e}");
            return Err(e);
        }
    }
    Ok(())
}

/// Monitor a DCO server: enumerate peers + their traffic counters
/// (the pull side), then stream lifecycle notifications (the push
/// side). The dump needs an existing `ovpn` interface; the event
/// stream needs the `peers` multicast group (kernel 6.16+).
async fn run_monitor(ifname: Option<&str>) -> nlink::Result<()> {
    let conn = Connection::<Ovpn>::new_async().await?;

    // --- Pull: enumerate connected peers + read their counters. ---
    if let Some(ifname) = ifname {
        let route = Connection::<Route>::new()?;
        let Some(link) = route.get_link_by_name(ifname).await? else {
            println!("interface {ifname} not found");
            return Ok(());
        };
        let ifindex = link.ifindex();
        match conn.peer_dump(ifindex).await {
            Ok(peers) => {
                println!("{} peer(s) on {ifname}:", peers.len());
                for p in &peers {
                    println!(
                        "  peer {:<8} remote={:?}\n      vpn rx={:?}B/{:?}pkt tx={:?}B/{:?}pkt\n      link rx={:?}B tx={:?}B",
                        p.id.unwrap_or(0),
                        p.remote_socket(),
                        p.vpn_rx_bytes,
                        p.vpn_rx_packets,
                        p.vpn_tx_bytes,
                        p.vpn_tx_packets,
                        p.link_rx_bytes,
                        p.link_tx_bytes,
                    );
                }
            }
            Err(e) => println!("peer_dump({ifname}) failed: {e}"),
        }
    } else {
        println!("(no interface given — pass `monitor <ifname>` to dump peer stats)");
    }

    // --- Push: stream peer lifecycle notifications until Ctrl-C. ---
    conn.subscribe_peers()?;
    println!("subscribed to ovpn `peers` group; streaming events (Ctrl-C to stop)…");
    let mut events = conn.events().await;
    while let Some(evt) = events.next().await {
        match evt? {
            OvpnEvent::PeerDeleted(reply) => {
                let peer = reply.peer.as_ref();
                println!(
                    "peer {} removed: {:?}",
                    peer.and_then(|p| p.id).unwrap_or(0),
                    peer.and_then(|p| p.del_reason),
                );
            }
            OvpnEvent::KeySwap(reply) => {
                let kc = reply.keyconf.as_ref();
                println!(
                    "peer {:?} key {:?} needs rekey (IV space exhausting)",
                    kc.and_then(|k| k.peer_id),
                    kc.and_then(|k| k.slot),
                );
            }
            OvpnEvent::PeerFloat(reply) => {
                let peer = reply.peer.as_ref();
                println!(
                    "peer {} floated to {:?}",
                    peer.and_then(|p| p.id).unwrap_or(0),
                    peer.and_then(|p| p.remote_socket()),
                );
            }
            // OvpnEvent is #[non_exhaustive]; ignore kernel additions.
            _ => {}
        }
    }
    Ok(())
}

async fn run_apply() -> nlink::Result<()> {
    #[cfg(not(feature = "lab"))]
    {
        eprintln!(
            "apply mode requires the `lab` feature: \n\
             sudo cargo run -p nlink --example genl_ovpn --features lab -- apply"
        );
        Ok(())
    }
    #[cfg(feature = "lab")]
    {
        use nlink::lab::LabNamespace;
        use nlink::netlink::{link::OvpnLink, Route};

        // SAFETY check.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("apply mode requires root (lab namespace creation + ovpn link setup).");
            return Ok(());
        }
        if !nlink::lab::has_module("ovpn") {
            eprintln!(
                "apply mode requires the kernel `ovpn` module — kernel 6.16+ \
                 (try `modprobe ovpn`)."
            );
            return Ok(());
        }

        let ns_name = format!("ovpn-demo-{}", std::process::id());
        let ns = LabNamespace::new(&ns_name)?;

        // 1. Create the ovpn interface in the namespace.
        let route: Connection<Route> = nlink::Connection::new_in(ns.name())?;
        route.add_link(OvpnLink::new("ovpn0")).await?;

        let link = route
            .get_link_by_name("ovpn0")
            .await?
            .ok_or_else(|| nlink::Error::invalid_message("ovpn0 missing after add_link"))?;
        let ifindex = link.ifindex();

        println!("Created ovpn0 (ifindex={ifindex}) in namespace {ns_name}");

        // 2. Open the OVPN GENL connection in the same namespace.
        let ovpn: Connection<Ovpn> = nlink::Connection::new_in_async(ns.name()).await?;

        // 3. Declarative apply — one peer, one primary key.
        //
        //    These zero-fill key bytes are placeholders; a real
        //    OpenVPN 2.7 deployment derives them via TLS.
        let key = OvpnKeyConfig::new(
            1, // key_id
            OvpnCipherAlg::AesGcm,
            OvpnKeydir::new([0u8; 32], [0u8; 8]),
            OvpnKeydir::new([0u8; 32], [0u8; 8]),
        );

        let cfg = OvpnConfig::new().interface(ifindex, |b| {
            b.peer(42, |p| {
                p.remote("10.0.0.1:1194".parse().unwrap())
                    .keepalive(20, 60)
                    .vpn_ipv4("172.16.0.42".parse().unwrap())
                    .key(OvpnKeySlot::Primary, key)
            })
        });

        let diff = cfg.diff(&ovpn).await?;
        println!("Initial diff: {diff}");

        // Apply.
        diff.apply(&ovpn).await?;

        // 4. Dump peers.
        let peers = ovpn.peer_dump(ifindex).await?;
        println!("Peers after apply: {} found", peers.len());
        for p in &peers {
            println!(
                "  peer {}: remote={:?}, keepalive={:?}/{:?}",
                p.id.unwrap_or(0),
                p.remote_socket(),
                p.keepalive_interval,
                p.keepalive_timeout,
            );
        }

        // 5. Re-diff should be empty (idempotence).
        let post = cfg.diff(&ovpn).await?;
        println!("Post-apply diff (should be empty): {post}");

        // 6. Tear down: drop ns; LabNamespace::Drop removes it.
        drop(ovpn);
        drop(route);
        drop(ns);

        println!("Done.");
        Ok(())
    }
}
