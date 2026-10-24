//! Conntrack event subscription — multicast NEW + DESTROY demo.
//!
//! Pairs with `examples/netfilter/conntrack.rs` (the mutation lifecycle
//! demo) to round out Plan 137 PR A + PR B coverage. Subscribes to the
//! NEW + DESTROY ctnetlink groups in a temporary namespace, then
//! injects + deletes a synthetic TCP entry; the resulting events are
//! collected from the stream and printed.
//!
//! Run modes:
//!
//! ```bash
//! # Print usage and a code skeleton (no privileges)
//! cargo run -p nlink --example netfilter_conntrack_events
//!
//! # Subscribe in the host namespace and print events forever (Ctrl-C
//! # to quit). Requires root + nf_conntrack module.
//! sudo cargo run -p nlink --example netfilter_conntrack_events -- watch
//!
//! # Run the inject + delete + assert-events smoke test inside a
//! # temporary namespace. Requires root and the nf_conntrack module.
//! sudo cargo run -p nlink --example netfilter_conntrack_events -- --apply
//! ```
//!
//! See also: `nlink::netlink::netfilter::{ConntrackEvent, ConntrackGroup}`,
//! `docs/recipes/conntrack-programmatic.md`.

use std::{env, net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    Connection, Netfilter, namespace,
    netfilter::{
        ConntrackBuilder, ConntrackEvent, ConntrackGroup, ConntrackStatus, ConntrackTuple,
        IpProtocol, TcpConntrackState,
    },
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("watch") => run_watch().await?,
        Some("--apply") => run_apply().await?,
        _ => print_overview(),
    }

    Ok(())
}

fn print_overview() {
    println!("=== Conntrack event subscription (multicast) ===\n");
    println!("Connection<Netfilter> implements EventSource. After");
    println!("subscribe(), events() / into_events() returns a Stream of");
    println!("ConntrackEvent (New / Destroy).\n");

    println!("--- Code skeleton ---\n");
    println!(
        r#"    use nlink::netlink::{{Connection, Netfilter}};
    use nlink::netlink::netfilter::{{ConntrackGroup, ConntrackEvent}};
    use tokio_stream::StreamExt;

    let mut nf = Connection::<Netfilter>::new()?;
    nf.subscribe(&[ConntrackGroup::New, ConntrackGroup::Destroy])?;

    let mut events = nf.events().await;
    while let Some(evt) = events.next().await {{
        match evt? {{
            ConntrackEvent::New(entry)     => println!("NEW     {{:?}}", entry.orig),
            ConntrackEvent::Destroy(entry) => println!("DESTROY {{:?}}", entry.orig),
        }}
    }}
"#
    );

    println!("--- Modes ---\n");
    println!("  watch     — Subscribe to host events, print indefinitely");
    println!("  --apply   — Inject + delete a synthetic entry in a temp namespace,");
    println!("              collect resulting events, assert NEW + DESTROY arrived");
    println!();
    println!("--- New-vs-Update caveat ---\n");
    println!("  The kernel uses IPCTNL_MSG_CT_NEW for both new entries AND update");
    println!("  notifications. Subscribing to both groups can't distinguish them");
    println!("  from message inspection alone — they all surface as ConntrackEvent::New.");
    println!("  Subscribe to ConntrackGroup::Update alone if you need update isolation.");
}

async fn run_watch() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("watch requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== Watching host conntrack events (Ctrl-C to exit) ===\n");
    let nf = Connection::<Netfilter>::new()?;
    nf.subscribe(&[
        ConntrackGroup::New,
        ConntrackGroup::Update,
        ConntrackGroup::Destroy,
    ])?;
    let mut events = nf.events().await;
    while let Some(evt) = events.next().await {
        print_event(&evt?);
    }
    Ok(())
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }

    println!("=== Conntrack events live demo (temporary namespace) ===");

    let ns_name = format!("nlink-ct-events-demo-{}", std::process::id());
    namespace::create(&ns_name)?;

    let result = run_demo(&ns_name).await;

    let _ = namespace::delete(&ns_name);
    result?;

    println!();
    println!("Done. Namespace `{ns_name}` removed.");
    Ok(())
}

async fn run_demo(ns_name: &str) -> nlink::Result<()> {
    // Two separate connections in the same namespace:
    //   - sub: subscribed to multicast NEW + DESTROY, owned by the
    //     collector task.
    //   - act: used to inject + delete entries (which trigger events).
    let sub: Connection<Netfilter> = nlink::Connection::new_in(ns_name)?;
    sub.subscribe(&[ConntrackGroup::New, ConntrackGroup::Destroy])?;
    let act: Connection<Netfilter> = nlink::Connection::new_in(ns_name)?;

    println!("  Opened sub + act connections in namespace `{ns_name}`.");

    // Spawn a collector that drains events for up to 3s. Using
    // into_events() so we can move the connection into the task.
    let collector = tokio::spawn(async move {
        let mut stream = sub.into_events().await;
        let mut collected: Vec<ConntrackEvent> = Vec::new();
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

    // Give the subscribed socket a moment to attach before we start
    // generating activity (otherwise the NEW for our injection might
    // hit the wire before the kernel has registered our membership).
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Step 1: inject TCP entry → should emit a NEW notification.
    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40000, 80);
    println!();
    println!("  Step 1: inject TCP 10.0.0.1:40000 -> 10.0.0.2:80");
    act.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig.clone())
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(60))
            .tcp_state(TcpConntrackState::Established),
    )
    .await
    .map_err(|e| {
        eprintln!(
            "  ! add_conntrack failed: {e}\n  ! is `nf_conntrack` loaded? modprobe nf_conntrack"
        );
        e
    })?;

    // Find the entry in a dump, to delete exactly that one.
    let entries = act.get_conntrack().await?;
    let entry = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40000)
                && e.orig.dst_port == Some(80)
        })
        .ok_or_else(|| nlink::Error::invalid_message("injected entry not in dump"))?;

    // Step 2: delete it → should emit a DESTROY notification.
    println!("  Step 2: delete the dumped entry — expect a DESTROY event");
    act.del_conntrack_entry(entry).await?;

    // Drain the collector. It will time out 3s after we spawned it.
    let collected = collector
        .await
        .map_err(|e| nlink::Error::invalid_message(format!("collector task: {e}")))??;

    println!();
    println!(
        "  Collected {} event(s) inside the 3s window:",
        collected.len()
    );
    for (i, evt) in collected.iter().enumerate() {
        print!("    [{i}] ");
        print_event(evt);
    }

    let new_count = collected
        .iter()
        .filter(|e| matches!(e, ConntrackEvent::New(_)))
        .count();
    let destroy_count = collected
        .iter()
        .filter(|e| matches!(e, ConntrackEvent::Destroy(_)))
        .count();
    println!();
    println!("  Tally: {new_count} NEW, {destroy_count} DESTROY");
    assert!(new_count >= 1, "expected at least one NEW event");
    assert!(destroy_count >= 1, "expected at least one DESTROY event");

    Ok(())
}

fn print_event(evt: &ConntrackEvent) {
    let (label, entry) = match evt {
        ConntrackEvent::New(entry) => ("NEW    ", entry),
        ConntrackEvent::Destroy(entry) => ("DESTROY", entry),
        // ConntrackEvent is #[non_exhaustive] — newer variants land
        // through Plan 137 PR C (expectations).
        _ => return,
    };
    println!(
        "{label} proto={:?} src={:?}:{:?} dst={:?}:{:?} id={:?}",
        entry.proto,
        entry.orig.src_ip,
        entry.orig.src_port,
        entry.orig.dst_ip,
        entry.orig.dst_port,
        entry.id,
    );
}
