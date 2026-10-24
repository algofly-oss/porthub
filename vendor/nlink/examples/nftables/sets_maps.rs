//! Sets, maps and stateful objects in one declared ruleset — the ipset
//! feature set, in nftables.
//!
//! Run modes:
//!
//! ```bash
//! # Print what the example declares (no privileges)
//! cargo run -p nlink --example nftables_sets_maps
//!
//! # Apply it in a temporary namespace, send traffic through it, show
//! # what the sets and counters saw, and apply again to show that a
//! # second apply changes nothing. Requires root (CAP_NET_ADMIN).
//! sudo cargo run -p nlink --example nftables_sets_maps -- --apply
//! ```
//!
//! The ruleset:
//!   - `allowed_nets`: an interval set of prefixes (ipset `hash:net`);
//!   - `services`: address . port pairs (ipset `hash:ip,port`);
//!   - `seen`: a dynamic set with a timeout, filled by a rule (`update
//!     @seen { ip daddr timeout 60s }`) and kept across applies;
//!   - `per_ip`: an object map giving each address its own counter
//!     (ipset `counters`);
//!   - `by_port`: a verdict map on port ranges (`udp dport vmap @by_port`).

use std::net::Ipv4Addr;
use std::time::Duration;

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    BaseChain, Family, FilterHook, PacketField, Priority, SetDataType, SetElement, SetKeyType,
    Verdict,
};
use nlink::netlink::nftables::{ObjectConfig, ObjectState, ObjectType};
use nlink::netlink::{Connection, Nftables, Route, namespace};

fn ruleset() -> nlink::Result<NftablesConfig> {
    let net = |a, b, c, d, len| SetElement::ipv4_prefix(Ipv4Addr::new(a, b, c, d), len);
    let allowed = vec![net(127, 0, 0, 0, 30)?, net(10, 0, 0, 0, 8)?];
    let services = vec![
        SetElement::concat([SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)), SetElement::port(53)]),
        SetElement::concat([SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 3)), SetElement::port(443)]),
    ];
    Ok(NftablesConfig::new().table("demo", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .chain("high_ports", |c| c)
        .set("allowed_nets", move |s| {
            s.key_type(SetKeyType::Ipv4Addr).interval().elements(allowed)
        })
        .set("services", move |s| {
            s.key_type(SetKeyType::Concat(vec![
                SetKeyType::Ipv4Addr,
                SetKeyType::InetService,
            ]))
            .elements(services)
        })
        .set("seen", |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .dynamic()
                .timeout(Duration::from_secs(60))
        })
        .object("c2", ObjectConfig::Counter)
        .object("c3", ObjectConfig::Counter)
        .set("per_ip", |s| {
            s.map(SetDataType::Object(ObjectType::Counter))
                .element(SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)).object("c2"))
                .element(SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 3)).object("c3"))
        })
        .set("by_port", |s| {
            s.key_type(SetKeyType::InetService)
                .interval()
                .vmap()
                .element(
                    SetElement::port_range(1024, 65535)
                        .verdict(Verdict::JumpTo("high_ports".parse().expect("valid name"))),
                )
        })
        .rule_keyed("out", "track", |r| {
            r.match_l4proto(17)
                .update_in_set(PacketField::Ip4Daddr, "seen", None)
        })
        .rule_keyed("out", "count", |r| {
            r.match_l4proto(17)
                .objref_from_map(PacketField::Ip4Daddr, "per_ip")
        })
        .rule_keyed("out", "services", |r| {
            r.match_concat_in_set(&[PacketField::Ip4Daddr, PacketField::UdpDport], "services")
                .counter()
        })
        .rule_keyed("out", "allowed", |r| {
            r.match_l4proto(17)
                .match_in_set(PacketField::Ip4Daddr, "allowed_nets")
                .counter()
        })
        .rule_keyed("out", "ports", |r| r.vmap(PacketField::UdpDport, "by_port"))
        .rule_keyed("high_ports", "count", |r| r.counter())
    }))
}

#[tokio::main]
async fn main() -> nlink::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--apply") => run_apply().await,
        _ => {
            println!("{:#?}", ruleset()?.tables()[0].sets());
            println!("\nRe-run with `-- --apply` as root to apply it in a temporary namespace.");
            Ok(())
        }
    }
}

async fn run_apply() -> nlink::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("--apply requires root (CAP_NET_ADMIN). Aborting.");
        std::process::exit(1);
    }
    let ns = format!("nlink-sets-maps-{}", std::process::id());
    namespace::create(&ns)?;
    let result = demo(&ns).await;
    let _ = namespace::delete(&ns);
    result
}

async fn demo(ns: &str) -> nlink::Result<()> {
    let route: Connection<Route> = nlink::Connection::new_in(ns)?;
    let lo = route.get_link_by_name("lo").await?.expect("netns has lo");
    route.set_link_up_by_index(lo.ifindex()).await?;
    let conn: Connection<Nftables> = nlink::Connection::new_in(ns)?;

    let cfg = ruleset()?;
    let diff = cfg.diff(&conn).await?;
    println!("first apply:\n{diff}");
    diff.apply(&conn).await?;

    // Traffic from inside the namespace.
    let name = ns.to_string();
    std::thread::spawn(move || {
        let _in = namespace::enter(&name).expect("enter netns");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        for target in ["127.0.0.2:53", "127.0.0.2:53", "127.0.0.3:443", "127.0.0.3:5000"] {
            let _ = socket.send_to(b"nlink", target);
        }
    })
    .join()
    .expect("traffic thread");

    let seen = conn.list_set_elements("demo", "seen", Family::Ip).await?;
    println!("\nseen: {} addresses", seen.len());
    for e in &seen {
        println!("  {:?} expires in {:?}", e.key(), e.expiration());
    }
    for o in conn.list_objects_in("demo", Family::Ip).await? {
        if let ObjectState::Counter { packets, .. } = o.state {
            println!("counter {}: {packets} packets", o.name);
        }
    }
    for r in conn.list_rules("demo", Family::Ip).await? {
        if let (Some(key), Some((packets, _))) = (&r.key, r.counter()) {
            println!("rule {}/{key}: {packets} packets", r.chain);
        }
    }

    let again = cfg.diff(&conn).await?;
    println!(
        "\nsecond apply: {}",
        if again.is_empty() { "nothing to do" } else { "CHANGES (unexpected)" }
    );
    Ok(())
}
