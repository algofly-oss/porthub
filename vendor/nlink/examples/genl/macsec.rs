//! MACsec (IEEE 802.1AE) — full device + SA lifecycle.
//!
//! Demonstrates the write-path of `Connection::<Macsec>`: adding a
//! TX SA, adding an RX SC + RX SA for a peer, dumping, and cleaning
//! up. Runs inside a temporary namespace on a dummy parent
//! interface.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage patterns + API overview (no privileges)
//! cargo run -p nlink --example genl_macsec
//!
//! # Read-only probe of MACsec interfaces on the current host
//! cargo run -p nlink --example genl_macsec -- show
//!
//! # Create dummy + macsec on top + add TX/RX SAs + dump + cleanup.
//! # Requires root (CAP_NET_ADMIN) and `modprobe macsec`.
//! sudo cargo run -p nlink --example genl_macsec -- --apply
//! ```
//!
//! See also: `nlink::netlink::genl::macsec::{MacsecSaBuilder,
//! MacsecDevice}`, `nlink::netlink::link::MacsecLink`.

use nlink::netlink::{
    Connection, Macsec, Route,
    genl::macsec::{MacsecDevice, MacsecSaBuilder},
    link::{DummyLink, MacsecLink},
    namespace,
};

// 128-bit test keys for GCM-AES-128. Real deployments use MKA or a
// key-management daemon; these are for a throwaway namespace demo.
const LOCAL_KEY: [u8; 16] = [0x11; 16];
const PEER_KEY: [u8; 16] = [0x22; 16];
const PEER_SCI: u64 = 0x0011_2233_4455_0001;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => run_show().await?,
        Some("--apply") => run_apply().await?,
        _ => print_overview(),
    }

    Ok(())
}

fn print_overview() {
    println!("=== MACsec (IEEE 802.1AE) ===\n");
    println!("Layer-2 encryption for point-to-point links. The kernel");
    println!("object hierarchy is:\n");
    println!("    macsec0 (TX SC ──> TX SA 0..3)");
    println!("             (RX SC per peer ──> RX SA 0..3)\n");

    println!("--- What --apply does ---\n");
    println!(
        "    1. Create a temporary namespace.
    2. Add dummy0 (nlink), bring up.
    3. Add macsec0 link=dummy0 via MacsecLink rtnetlink builder.
    4. Open Connection::<Macsec>, print device SCI + cipher.
    5. add_tx_sa(AN=0, local key, pn=1, active=true).
    6. add_rx_sc(peer_sci).
    7. add_rx_sa(peer_sci, AN=0, peer key, pn=1, active=true).
    8. get_device() to dump the TX + RX SC/SA state.
    9. del_rx_sa, del_rx_sc, del_tx_sa.
   10. Delete namespace (takes macsec0 + dummy0 with it).
"
    );

    println!("--- Code ---\n");
    println!(
        r#"    use nlink::netlink::{{Connection, Macsec, namespace}};
    use nlink::netlink::genl::macsec::MacsecSaBuilder;

    let conn: Connection<Macsec> =
        nlink::Connection::new_in_async("lab").await?;

    // TX SA (encodes outgoing frames).
    conn.add_tx_sa("macsec0",
        MacsecSaBuilder::new(0, &local_key)   // AN=0, key
            .packet_number(1)
            .active(true),
    ).await?;

    // RX SC (per peer) + RX SA (decodes that peer's frames).
    conn.add_rx_sc("macsec0", peer_sci).await?;
    conn.add_rx_sa("macsec0", peer_sci,
        MacsecSaBuilder::new(0, &peer_key)
            .packet_number(1)
            .active(true),
    ).await?;

    // Inspect current state.
    let dev = conn.get_device("macsec0").await?;

    // Cleanup (caller's responsibility).
    conn.del_rx_sa("macsec0", peer_sci, 0).await?;
    conn.del_rx_sc("macsec0", peer_sci).await?;
    conn.del_tx_sa("macsec0", 0).await?;
"#
    );

    println!("--- Re-run with `--apply` (as root) ---");
    println!("  Runs the lifecycle above in a temporary namespace.");
}

async fn run_show() -> nlink::Result<()> {
    let conn = match Connection::<Macsec>::new_async().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to open MACsec GENL: {e}");
            eprintln!("Load the module with: sudo modprobe macsec");
            return Ok(());
        }
    };

    println!("MACsec family_id={}\n", conn.family_id());

    let route = Connection::<Route>::new()?;
    let links = route.get_links().await?;
    let macsec_links: Vec<_> = links
        .iter()
        .filter(|l| l.kind() == Some("macsec"))
        .collect();

    if macsec_links.is_empty() {
        println!("No MACsec interfaces on this host.");
        println!();
        println!("Build one in a temporary namespace with:");
        println!("  sudo cargo run -p nlink --example genl_macsec -- --apply");
        return Ok(());
    }

    for link in &macsec_links {
        let name = link.name_or("?");
        match conn.get_device(name).await {
            Ok(device) => print_device(name, &device),
            Err(e) => eprintln!("  Error querying {name}: {e}"),
        }
    }
    Ok(())
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== MACsec live demo (temporary namespace) ===");

    let ns_name = format!("nlink-macsec-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    // 1. Dummy parent interface.
    let route: Connection<Route> = nlink::Connection::new_in(ns_name)?;
    route.add_link(DummyLink::new("dummy0")).await?;
    route.set_link_up("dummy0").await?;
    println!("  Created dummy0 in namespace `{ns_name}`.");

    // 2. MACsec interface on top via the typed rtnetlink builder.
    //    If this step fails, the most common cause is a missing
    //    `macsec` kernel module.
    route
        .add_link(MacsecLink::new("macsec0", "dummy0"))
        .await
        .map_err(|e| {
            eprintln!("\n  add_link(MacsecLink) failed: {e}");
            eprintln!("  Load the module with: sudo modprobe macsec");
            e
        })?;
    route.set_link_up("macsec0").await?;
    println!("  Created macsec0 link=dummy0 via MacsecLink and brought it up.");

    // 3. GENL connection for the namespace.
    let macsec: Connection<Macsec> = nlink::Connection::new_in_async(ns_name).await?;
    println!(
        "  Opened MACsec GENL connection (family_id={}).",
        macsec.family_id()
    );

    println!();
    println!("  --- Initial state ---");
    let before = macsec.get_device("macsec0").await?;
    print_device("macsec0", &before);

    // 4. Add a TX SA.
    println!();
    println!("  add_tx_sa(AN=0, key=0x11.., pn=1, active=true)");
    macsec
        .add_tx_sa(
            "macsec0",
            MacsecSaBuilder::new(0, &LOCAL_KEY)
                .packet_number(1)
                .active(true),
        )
        .await?;

    // 5. Add a peer RX SC + RX SA.
    println!("  add_rx_sc(peer_sci=0x{PEER_SCI:016x})");
    macsec.add_rx_sc("macsec0", PEER_SCI).await?;

    println!("  add_rx_sa(peer_sci, AN=0, key=0x22.., pn=1, active=true)");
    macsec
        .add_rx_sa(
            "macsec0",
            PEER_SCI,
            MacsecSaBuilder::new(0, &PEER_KEY)
                .packet_number(1)
                .active(true),
        )
        .await?;

    // 6. Dump to verify round-trip.
    println!();
    println!("  --- After SA configuration ---");
    let after = macsec.get_device("macsec0").await?;
    print_device("macsec0", &after);

    // 7. Cleanup.
    println!();
    println!("  Cleaning up: del_rx_sa, del_rx_sc, del_tx_sa...");
    macsec.del_rx_sa("macsec0", PEER_SCI, 0).await?;
    macsec.del_rx_sc("macsec0", PEER_SCI).await?;
    macsec.del_tx_sa("macsec0", 0).await?;

    Ok(())
}

fn print_device(name: &str, device: &MacsecDevice) {
    println!("  interface: {name} (ifindex {})", device.ifindex);
    println!("    SCI:           0x{:016x}", device.sci);
    println!("    cipher:        {:?}", device.cipher);
    println!("    encoding_sa:   {}", device.encoding_sa);
    println!(
        "    encrypt={}  protect={}  replay_protect={}",
        device.encrypt, device.protect, device.replay_protect
    );

    if let Some(tx_sc) = &device.tx_sc {
        println!("    TX SC (SCI 0x{:016x}):", tx_sc.sci);
        if tx_sc.sas.is_empty() {
            println!("      (no TX SAs)");
        }
        for sa in &tx_sc.sas {
            println!("      TX SA an={} active={} pn={}", sa.an, sa.active, sa.pn);
        }
    } else {
        println!("    TX SC: (none)");
    }

    if device.rx_scs.is_empty() {
        println!("    RX SCs: (none)");
    } else {
        for rx in &device.rx_scs {
            println!("    RX SC 0x{:016x} active={}:", rx.sci, rx.active);
            for sa in &rx.sas {
                println!("      RX SA an={} active={} pn={}", sa.an, sa.active, sa.pn);
            }
        }
    }
}
