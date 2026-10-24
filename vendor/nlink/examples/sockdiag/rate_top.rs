//! Per-process TCP bandwidth "top" from sock_diag polling (#171 + #162).
//!
//! Combines the three sockdiag utilities that ship the unprivileged
//! bmon/nethogs-style fallback:
//!
//! - [`SocketRateTracker`] — cookie-keyed goodput deltas between
//!   consecutive TCP dumps,
//! - [`SocketOwnerMap`] — one amortized `/proc` walk joining inodes
//!   to `(pid, start_time, comm)`,
//! - [`CgroupPathMap`] — cgroup-v2 ID → `system.slice/foo.service`.
//!
//! Unprivileged: rates work for every socket; process attribution
//! resolves only your own processes unless run as root (documented
//! snapshot semantics, not an error). Remember the constraints from
//! the module docs: **TCP-only** (UDP diag has no byte counters),
//! **goodput ≠ wire throughput**, and short flows between polls are
//! invisible.
//!
//! Run with: cargo run -p nlink --features sockdiag --example sockdiag_rate_top

use std::{collections::HashMap, time::Instant};

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{CgroupPathMap, SocketFilter, SocketOwnerMap, SocketRateTracker},
};

const INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const ROUNDS: usize = 3;

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = Connection::<SockDiag>::new()?;
    let mut tracker = SocketRateTracker::new();
    let cgroups = CgroupPathMap::scan();

    println!("sampling TCP goodput over {ROUNDS} x {INTERVAL:?} intervals...\n");

    for round in 0..=ROUNDS {
        // TCP_INFO must be requested — the byte counters ride in it.
        let snapshot = conn
            .query(&SocketFilter::tcp().with_tcp_info().build())
            .await?;
        let inet: Vec<_> = snapshot.iter().filter_map(|s| s.as_inet()).collect();

        // cookie → (inode, cgroup_id) join keys for this snapshot.
        let keys: HashMap<u64, (u32, Option<u64>)> = inet
            .iter()
            .map(|s| (s.cookie, (s.inode, s.cgroup_id)))
            .collect();

        let mut rates = tracker.ingest(inet.iter().copied(), Instant::now());
        if round == 0 {
            // First ingest is the baseline; nothing to report yet.
            tokio::time::sleep(INTERVAL).await;
            continue;
        }

        // Fresh /proc walk per round — sockets come and go.
        let owners = SocketOwnerMap::scan();

        rates.sort_by_key(|r| std::cmp::Reverse(r.tx_goodput_bps + r.rx_goodput_bps));
        println!("--- round {round} ({} active sockets) ---", rates.len());
        println!(
            "{:>12} {:>12} {:>8}  {:<24} CGROUP",
            "TX B/s", "RX B/s", "RETR%", "PROCESS"
        );
        for rate in rates.iter().take(10) {
            let (inode, cgroup_id) = keys.get(&rate.cookie).copied().unwrap_or((0, None));
            let process = owners
                .resolve(inode)
                .first()
                .map(|p| format!("{} (pid {})", p.comm, p.pid))
                .unwrap_or_else(|| "-".into());
            let cgroup = cgroup_id
                .and_then(|id| cgroups.resolve_relative(id))
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            println!(
                "{:>12} {:>12} {:>7.2}%  {:<24} {}",
                rate.tx_goodput_bps,
                rate.rx_goodput_bps,
                rate.retrans_ratio * 100.0,
                process,
                cgroup,
            );
        }
        println!();

        if round < ROUNDS {
            tokio::time::sleep(INTERVAL).await;
        }
    }

    println!("done — {} cookies tracked at exit", tracker.len());
    Ok(())
}
