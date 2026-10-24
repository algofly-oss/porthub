//! Attribute sockets to their owning processes and cgroups (#162).
//!
//! Dumps TCP sockets, then joins each one against a single amortized
//! `/proc` walk (`SocketOwnerMap`) and a single `/sys/fs/cgroup` walk
//! (`CgroupPathMap`). Unprivileged: only your own processes resolve
//! unless run as root — the misses are the documented snapshot
//! semantics, not errors.
//!
//! Run with: cargo run -p nlink --features sockdiag --example sockdiag_socket_owners

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{CgroupPathMap, SocketFilter, SocketInfo, SocketOwnerMap},
};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;
    let sockets = conn.query(&SocketFilter::tcp().build()).await?;

    // One walk each, reused for every socket below.
    let owners = SocketOwnerMap::scan();
    let cgroups = CgroupPathMap::scan();

    println!(
        "{:<28} {:<28} {:<24} CGROUP",
        "LOCAL", "REMOTE", "PROCESS (pid, start)"
    );
    println!("{}", "-".repeat(110));

    for sock in &sockets {
        let SocketInfo::Inet(inet) = sock else {
            continue;
        };
        let process = owners
            .resolve(inet.inode)
            .iter()
            .map(|p| format!("{} (pid {}, {})", p.comm, p.pid, p.start_time))
            .collect::<Vec<_>>()
            .join(", ");
        let cgroup = inet
            .cgroup_id
            .and_then(|id| cgroups.resolve_relative(id))
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        println!(
            "{:<28} {:<28} {:<24} {}",
            inet.local.to_string(),
            inet.remote.to_string(),
            if process.is_empty() { "-".into() } else { process },
            cgroup,
        );
    }

    println!(
        "\n{} sockets, {} inodes attributed, {} cgroups indexed",
        sockets.len(),
        owners.len(),
        cgroups.len()
    );
    Ok(())
}
