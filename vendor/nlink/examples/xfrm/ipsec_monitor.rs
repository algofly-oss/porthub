//! IPsec Security Associations and Policies monitor + lifecycle demo.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage and a code skeleton (no privileges)
//! cargo run -p nlink --example xfrm_ipsec_monitor
//!
//! # Dump the current host SA + SP tables (no privileges beyond
//! # netlink read access)
//! cargo run -p nlink --example xfrm_ipsec_monitor -- show
//!
//! # Watch host XFRM events forever (Ctrl-C to exit). Requires root.
//! sudo cargo run -p nlink --example xfrm_ipsec_monitor -- watch
//!
//! # Run the install/verify/rotate/delete lifecycle inside a
//! # temporary namespace, collecting the multicast events the
//! # mutations emit. Requires root (CAP_NET_ADMIN).
//! sudo cargo run -p nlink --example xfrm_ipsec_monitor -- --apply
//! ```
//!
//! See also: `nlink::netlink::xfrm::{XfrmSaBuilder, XfrmSpBuilder,
//! XfrmEvent, XfrmGroup}`, `docs/recipes/xfrm-ipsec-tunnel.md`.

use std::{env, net::IpAddr, time::Duration};

use nlink::netlink::{
    Connection, Xfrm,
    xfrm::{
        IpsecProtocol, PolicyAction, PolicyDirection, XfrmEvent, XfrmMode, XfrmSaBuilder,
        XfrmSelector, XfrmSpBuilder, XfrmUserTmpl,
    },
};
use tokio_stream::StreamExt;

const SPI_OUT: u32 = 0x0000_AABB;
const SPI_IN: u32 = 0x0000_CCDD;
const REQID: u32 = 42;
const AUTH_KEY: [u8; 32] = [0u8; 32];
const ENCR_KEY: [u8; 16] = [0u8; 16];

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => {
            let conn = Connection::<Xfrm>::new()?;
            show_state(&conn).await?;
        }
        Some("watch") => {
            run_watch().await?;
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
    println!("=== XFRM (IPsec) lifecycle demo ===\n");
    println!("Connection<Xfrm> exposes both the dump path");
    println!("(get_security_associations / get_security_policies) and");
    println!("the typed write path (add/update/del/flush_sa + same for");
    println!("_sp) on the same socket.\n");
    println!("Connection<Xfrm> also implements EventSource: after");
    println!("subscribe()/subscribe_all(), events() streams XfrmEvent");
    println!("(NewSa/DelSa/ExpireSa/NewPolicy/Acquire/...).\n");
    println!("Modes:");
    println!("  show          — Dump host SA + SP tables (no privileges");
    println!("                  beyond netlink read access)");
    println!("  watch         — Stream host XFRM events forever (root)");
    println!("  --apply       — Install + verify + rotate + tear down");
    println!("                  inside a temp namespace, collecting the");
    println!("                  emitted events (root required)");
    println!();
    println!("See `docs/recipes/xfrm-ipsec-tunnel.md` for the");
    println!("two-namespace tunnel walkthrough.");
}

/// Render an `XfrmEvent` as a single human-readable line.
fn format_event(evt: &XfrmEvent) -> String {
    match evt {
        XfrmEvent::NewSa(sa) => format!("NEWSA spi=0x{:08x} proto={:?}", sa.spi, sa.protocol),
        XfrmEvent::DelSa(id) => format!("DELSA spi=0x{:08x} proto={:?}", id.spi, id.protocol),
        XfrmEvent::ExpireSa { sa, hard } => format!(
            "EXPIRE spi=0x{:08x} ({})",
            sa.spi,
            if *hard { "hard" } else { "soft" }
        ),
        XfrmEvent::NewPolicy(sp) => {
            format!("NEWPOLICY dir={:?} index={}", sp.direction, sp.index)
        }
        XfrmEvent::DelPolicy(id) => {
            format!("DELPOLICY dir={:?} index={}", id.direction, id.index)
        }
        XfrmEvent::ExpirePolicy { policy, hard } => format!(
            "POLEXPIRE index={} ({})",
            policy.index,
            if *hard { "hard" } else { "soft" }
        ),
        XfrmEvent::Acquire { policy, .. } => format!("ACQUIRE policy-index={}", policy.index),
        XfrmEvent::Report { protocol, .. } => format!("REPORT proto={protocol:?}"),
        XfrmEvent::FlushSa => "FLUSHSA".to_string(),
        XfrmEvent::FlushPolicy => "FLUSHPOLICY".to_string(),
        XfrmEvent::Other { msg_type } => format!("event (msg type {msg_type})"),
        _ => "event (unrecognized)".to_string(),
    }
}

async fn run_watch() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("watch requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== Watching host XFRM events (Ctrl-C to exit) ===\n");
    let conn = Connection::<Xfrm>::new()?;
    conn.subscribe_all()?;
    let mut events = conn.events().await;
    while let Some(evt) = events.next().await {
        println!("{}", format_event(&evt?));
    }
    Ok(())
}

async fn show_state(conn: &Connection<Xfrm>) -> nlink::Result<()> {
    println!("=== Security Associations ===\n");
    let sas = conn.get_security_associations().await?;
    if sas.is_empty() {
        println!("(none — IPsec SAs are created when VPN tunnels are");
        println!(" established or when --apply runs)");
    } else {
        for sa in &sas {
            print_sa_brief(sa);
        }
    }

    println!("\n=== Security Policies ===\n");
    let policies = conn.get_security_policies().await?;
    if policies.is_empty() {
        println!("(none — IPsec policies steer traffic into the SA");
        println!(" lookup; without them no traffic gets encrypted)");
    } else {
        for pol in &policies {
            print_sp_brief(pol);
        }
    }

    Ok(())
}

fn print_sa_brief(sa: &nlink::netlink::xfrm::SecurityAssociation) {
    let src = sa
        .src_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".into());
    let dst = sa
        .dst_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".into());
    let proto = match sa.protocol {
        IpsecProtocol::Esp => "ESP",
        IpsecProtocol::Ah => "AH",
        IpsecProtocol::Comp => "COMP",
        _ => "?",
    };
    let mode = match sa.mode {
        XfrmMode::Transport => "transport",
        XfrmMode::Tunnel => "tunnel",
        XfrmMode::Beet => "beet",
        _ => "?",
    };
    println!(
        "  {} {src} -> {dst}  spi=0x{:08x} reqid={} mode={mode}",
        proto, sa.spi, sa.reqid
    );
    if let Some(ref enc) = sa.enc_alg {
        println!("    encr: {} ({} bits)", enc.name, enc.key_len);
    }
    if let Some(ref auth) = sa.auth_alg {
        println!("    auth: {} ({} bits)", auth.name, auth.key_len);
    }
    if let Some(ref aead) = sa.aead_alg {
        println!(
            "    aead: {} ({} bits, ICV {} bits)",
            aead.name, aead.key_len, aead.icv_len
        );
    }
}

fn print_sp_brief(pol: &nlink::netlink::xfrm::SecurityPolicy) {
    let dir = match pol.direction {
        PolicyDirection::In => "IN",
        PolicyDirection::Out => "OUT",
        PolicyDirection::Forward => "FWD",
        _ => "?",
    };
    let action = match pol.action {
        PolicyAction::Allow => "allow",
        PolicyAction::Block => "block",
        _ => "?",
    };
    println!(
        "  {dir} prio={} action={action} index={}",
        pol.priority, pol.index
    );
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== XFRM lifecycle apply ===\n");

    // Use the lab namespace so we don't touch host XFRM tables.
    use nlink::lab::with_namespace;
    with_namespace("xfrm-apply", |ns| async move {
        println!("Created namespace: {}", ns.name());
        let conn: Connection<Xfrm> = ns.connection_for()?;

        // Second connection in the same namespace, subscribed to all
        // XFRM groups, owned by a collector task that drains events for
        // the duration of the lifecycle below.
        let sub: Connection<Xfrm> = ns.connection_for()?;
        sub.subscribe_all()?;
        let collector = tokio::spawn(async move {
            let mut stream = sub.into_events().await;
            let mut collected: Vec<XfrmEvent> = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, stream.next()).await {
                    Ok(Some(Ok(evt))) => collected.push(evt),
                    Ok(Some(Err(e))) => return Err(e),
                    Ok(None) => break,
                    Err(_) => break, // deadline reached
                }
            }
            Ok::<_, nlink::Error>(collected)
        });
        // Let the subscribed socket attach before generating activity.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let local: IpAddr = "10.50.0.1".parse().unwrap();
        let peer: IpAddr = "10.50.0.2".parse().unwrap();

        // 1. Install outbound + inbound SA.
        println!(
            "\n[1/6] Installing outbound + inbound SAs (ESP-tunnel + HMAC-SHA256 + AES-CBC)..."
        );
        let sa_out = XfrmSaBuilder::new(local, peer, SPI_OUT, IpsecProtocol::Esp)
            .mode(XfrmMode::Tunnel)
            .reqid(REQID)
            .auth_hmac_sha256(&AUTH_KEY)
            .encr_aes_cbc(&ENCR_KEY);
        conn.add_sa(sa_out).await?;
        let sa_in = XfrmSaBuilder::new(peer, local, SPI_IN, IpsecProtocol::Esp)
            .mode(XfrmMode::Tunnel)
            .reqid(REQID)
            .auth_hmac_sha256(&AUTH_KEY)
            .encr_aes_cbc(&ENCR_KEY);
        conn.add_sa(sa_in).await?;
        println!(
            "  added 2 SAs (spi=0x{:08x}, spi=0x{:08x})",
            SPI_OUT, SPI_IN
        );

        // 2. Install matching SPs.
        println!("\n[2/6] Installing outbound + inbound SPs...");
        let sel = XfrmSelector {
            family: libc::AF_INET as u16,
            ..Default::default()
        };
        let sp_out = XfrmSpBuilder::new(sel, PolicyDirection::Out)
            .priority(100)
            .template(XfrmUserTmpl::match_any(
                local,
                peer,
                IpsecProtocol::Esp,
                XfrmMode::Tunnel,
                REQID,
            ));
        conn.add_sp(sp_out).await?;
        let sp_in = XfrmSpBuilder::new(sel, PolicyDirection::In)
            .priority(100)
            .template(XfrmUserTmpl::match_any(
                peer,
                local,
                IpsecProtocol::Esp,
                XfrmMode::Tunnel,
                REQID,
            ));
        conn.add_sp(sp_in).await?;
        println!("  added 2 SPs (Out, In)");

        // 3. Verify by dumping.
        println!("\n[3/6] Dumping namespace XFRM tables...");
        show_state(&conn).await?;

        // 4. Rotate the outbound SA in place via update_sa.
        println!("\n[4/6] Rotating outbound SA in place (update_sa)...");
        let rotated = XfrmSaBuilder::new(local, peer, SPI_OUT, IpsecProtocol::Esp)
            .mode(XfrmMode::Tunnel)
            .reqid(REQID)
            .auth_hmac_sha256(&[0xAAu8; 32])
            .encr_aes_cbc(&[0xBBu8; 16]);
        conn.update_sa(rotated).await?;
        println!("  rotated (same SPI; keys differ)");

        // 5. Fetch the rotated SA back via get_sa.
        println!("\n[5/6] Fetching rotated SA via get_sa...");
        match conn
            .get_sa(local, peer, SPI_OUT, IpsecProtocol::Esp)
            .await?
        {
            Some(sa) => print_sa_brief(&sa),
            None => println!("  (not found — kernel said ENOENT)"),
        }

        // 6. Tear down.
        println!("\n[6/6] Tearing down (del_sa x2 + flush_sp)...");
        conn.del_sa(local, peer, SPI_OUT, IpsecProtocol::Esp)
            .await?;
        conn.del_sa(peer, local, SPI_IN, IpsecProtocol::Esp).await?;
        conn.flush_sp().await?;
        println!("  done — namespace will be deleted on Drop");

        // Collect the events our own mutations generated.
        println!("\n=== Events captured during the lifecycle ===");
        let events = collector
            .await
            .map_err(|e| nlink::Error::invalid_message(format!("collector task: {e}")))??;
        if events.is_empty() {
            println!("  (none captured — the kernel may not have delivered");
            println!("   notifications within the 3s window)");
        } else {
            for evt in &events {
                println!("  {}", format_event(evt));
            }
        }

        Ok(())
    })
    .await?;

    println!("\nLifecycle complete.");
    Ok(())
}
