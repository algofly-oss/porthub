//! BPF program attachment to TC hooks.
//!
//! Demonstrates attaching, listing, and detaching BPF programs
//! on TC ingress/egress.
//!
//! Run with: cargo run -p nlink --example route_tc_bpf
//!
//! Requires root privileges and a pinned BPF program.
//!
//! Examples:
//!   sudo cargo run -p nlink --example route_tc_bpf -- attach eth0 /sys/fs/bpf/my_prog
//!   sudo cargo run -p nlink --example route_tc_bpf -- list eth0
//!   sudo cargo run -p nlink --example route_tc_bpf -- detach eth0

use std::env;

use nlink::netlink::{
    Connection, Route,
    filter::{BpfDirection, BpfFilter},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("attach") => {
            let iface = args
                .get(2)
                .expect("usage: attach <iface> <pinned_path> [ingress|egress]");
            let path = args
                .get(3)
                .expect("usage: attach <iface> <pinned_path> [ingress|egress]");
            let direction = match args.get(4).map(|s| s.as_str()) {
                Some("egress") => BpfDirection::Egress,
                _ => BpfDirection::Ingress,
            };

            let filter = BpfFilter::from_pinned(path)?.direct_action();
            conn.attach_bpf(iface, direction, filter).await?;
            println!("Attached BPF from {} to {} {:?}", path, iface, direction);
        }
        Some("list") => {
            let iface = args.get(2).expect("usage: list <iface>");
            let programs = conn.list_bpf_programs(iface).await?;

            if programs.is_empty() {
                println!("No BPF programs attached to {}", iface);
            } else {
                println!("BPF programs on {}:", iface);
                for prog in &programs {
                    println!(
                        "  id={:?} name={:?} tag={:?} direct_action={}",
                        prog.id,
                        prog.name,
                        prog.tag_hex(),
                        prog.direct_action
                    );
                }
            }
        }
        Some("detach") => {
            let iface = args.get(2).expect("usage: detach <iface> [ingress|egress]");
            let direction = match args.get(3).map(|s| s.as_str()) {
                Some("egress") => BpfDirection::Egress,
                _ => BpfDirection::Ingress,
            };

            conn.detach_bpf(iface, direction).await?;
            println!("Detached BPF from {} {:?}", iface, direction);
        }
        _ => {
            println!("Usage:");
            println!("  attach <iface> <pinned_path> [ingress|egress]  - Attach BPF program");
            println!("  list <iface>                                   - List attached programs");
            println!("  detach <iface> [ingress|egress]                - Detach all BPF");
        }
    }

    Ok(())
}
