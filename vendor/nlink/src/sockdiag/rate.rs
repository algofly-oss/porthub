//! Per-socket TCP byte-rate tracking from sock_diag snapshots (#171).
//!
//! [`SocketRateTracker`] turns two consecutive TCP dumps into
//! per-socket **goodput** rates: ingest a snapshot per poll tick,
//! get [`SocketRate`] deltas keyed by the kernel's socket cookie.
//! This is the unprivileged bmon/nethogs-style bandwidth fallback —
//! pair it with [`SocketOwnerMap`](super::SocketOwnerMap) (#162) for
//! per-process attribution.
//!
//! # Constraints (read before building on this)
//!
//! - **TCP only.** `tcp_info` carries cumulative `bytes_acked` /
//!   `bytes_received` (kernel 4.1+) and `bytes_sent` /
//!   `bytes_retrans` (4.19+). **UDP has no per-socket cumulative
//!   byte counters in the kernel** — `udp_diag` fills only
//!   `idiag_rqueue`/`idiag_wqueue`, which are *instantaneous queue
//!   depths*, NOT monotonic counters. Never diff those for a rate;
//!   per-process UDP bandwidth via sock_diag polling is
//!   architecturally impossible (use eBPF).
//! - **Goodput, not wire throughput.** `bytes_acked`/`bytes_received`
//!   count application-layer payload the peer acknowledged /
//!   delivered in order — no headers, no retransmitted bytes. Don't
//!   compare against interface counters; the overhead ratio is
//!   visible separately as [`SocketRate::retrans_ratio`].
//! - **Short flows are invisible.** A socket opened and closed
//!   between two polls never appears in either snapshot. Kernel-6.5+
//!   BPF socket iterators (`tcplife`/`tcptop`) are the event-driven,
//!   race-free successor; this is the polling baseline.
//! - **Delta key is the socket cookie**, not the inode: inodes get
//!   reused across a poll interval and would silently corrupt
//!   deltas. Cookies (`SO_COOKIE`) are monotonic and never reused.
//!
//! Snapshots must be dumped with TCP_INFO requested
//! (`SocketFilter::tcp().with_tcp_info()`); sockets whose snapshot
//! lacks `tcp_info` are skipped.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::{Duration, Instant};
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketFilter, SocketRateTracker};
//!
//! let conn = Connection::<SockDiag>::new()?;
//! let mut tracker = SocketRateTracker::new();
//! loop {
//!     let snapshot = conn
//!         .query(&SocketFilter::tcp().with_tcp_info().build())
//!         .await?;
//!     let inet: Vec<_> = snapshot
//!         .iter()
//!         .filter_map(|s| s.as_inet())
//!         .collect();
//!     for rate in tracker.ingest(inet.iter().copied(), Instant::now()) {
//!         println!(
//!             "cookie {:#x}: tx {} B/s rx {} B/s (retrans {:.2}%)",
//!             rate.cookie,
//!             rate.tx_goodput_bps,
//!             rate.rx_goodput_bps,
//!             rate.retrans_ratio * 100.0,
//!         );
//!     }
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, time::Instant};

use super::socket::InetSocket;

/// One socket's byte-rate over the last ingest interval.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct SocketRate {
    /// Kernel socket cookie (`SO_COOKIE`) — the stable identity to
    /// join back against [`InetSocket::cookie`].
    pub cookie: u64,
    /// Transmit goodput in bytes/second: Δ`bytes_acked` / Δt.
    /// Application payload the peer acknowledged — headers and
    /// retransmissions excluded.
    pub tx_goodput_bps: u64,
    /// Receive goodput in bytes/second: Δ`bytes_received` / Δt.
    pub rx_goodput_bps: u64,
    /// Retransmission overhead over the interval:
    /// Δ`bytes_retrans` / Δ`bytes_sent` (0.0 when nothing was sent,
    /// or on pre-4.19 kernels where those counters read 0).
    pub retrans_ratio: f64,
}

#[derive(Debug, Clone, Copy)]
struct Counters {
    bytes_acked: u64,
    bytes_received: u64,
    bytes_sent: u64,
    bytes_retrans: u64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    counters: Counters,
    at: Instant,
    /// Ingest generation the cookie was last seen in (for eviction).
    last_seen: u64,
}

/// Cookie-keyed delta bookkeeping between TCP snapshots.
///
/// Bounded: cookies absent for
/// [`evict_after`](Self::with_evict_after) consecutive ingests are
/// dropped, so the tracker's memory tracks the live socket set, not
/// everything ever seen. See the [module docs](self) for the
/// TCP-only / goodput / short-flow constraints.
#[derive(Debug)]
pub struct SocketRateTracker {
    entries: HashMap<u64, Entry>,
    generation: u64,
    evict_after: u64,
}

impl Default for SocketRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketRateTracker {
    /// Tracker with the default eviction horizon (3 ingests).
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            generation: 0,
            evict_after: 3,
        }
    }

    /// Drop cookies not seen for `n` consecutive ingests (min 1).
    pub fn with_evict_after(mut self, n: u64) -> Self {
        self.evict_after = n.max(1);
        self
    }

    /// Number of cookies currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no cookies are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ingest one snapshot taken at `at`; returns the rate for every
    /// socket seen in **both** this snapshot and a previous one.
    ///
    /// Sockets without `tcp_info` (dump made without
    /// `with_tcp_info()`, or non-TCP sockets) are skipped. Samples
    /// where any counter went backwards are dropped for that socket
    /// (the baseline resets instead) — cumulative `tcp_info`
    /// counters only regress if the cookie was somehow reused, so a
    /// bad sample must not produce a bogus huge rate. A zero or
    /// negative Δt yields no rates (same-instant double ingest).
    pub fn ingest<'a>(
        &mut self,
        sockets: impl IntoIterator<Item = &'a InetSocket>,
        at: Instant,
    ) -> Vec<SocketRate> {
        self.generation += 1;
        let mut rates = Vec::new();

        for sock in sockets {
            let Some(info) = sock.tcp_info.as_ref() else {
                continue;
            };
            let counters = Counters {
                bytes_acked: info.bytes_acked,
                bytes_received: info.bytes_received,
                bytes_sent: info.bytes_sent,
                bytes_retrans: info.bytes_retrans,
            };
            let entry = Entry {
                counters,
                at,
                last_seen: self.generation,
            };

            let Some(prev) = self.entries.insert(sock.cookie, entry) else {
                continue; // first sighting — baseline only
            };

            let dt = at.saturating_duration_since(prev.at).as_secs_f64();
            if dt <= 0.0 {
                continue;
            }
            let p = prev.counters;
            // Counter regression → cookie reuse or kernel anomaly:
            // skip the sample, keep the fresh baseline.
            if counters.bytes_acked < p.bytes_acked
                || counters.bytes_received < p.bytes_received
                || counters.bytes_sent < p.bytes_sent
                || counters.bytes_retrans < p.bytes_retrans
            {
                continue;
            }

            let d_sent = counters.bytes_sent - p.bytes_sent;
            let d_retrans = counters.bytes_retrans - p.bytes_retrans;
            rates.push(SocketRate {
                cookie: sock.cookie,
                tx_goodput_bps: (((counters.bytes_acked - p.bytes_acked) as f64) / dt) as u64,
                rx_goodput_bps: (((counters.bytes_received - p.bytes_received) as f64) / dt)
                    as u64,
                retrans_ratio: if d_sent == 0 {
                    0.0
                } else {
                    d_retrans as f64 / d_sent as f64
                },
            });
        }

        // Bounded memory: evict cookies not seen for N ingests.
        let horizon = self.generation.saturating_sub(self.evict_after);
        self.entries.retain(|_, e| e.last_seen > horizon);

        rates
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::sockdiag::types::TcpInfo;

    fn sock(cookie: u64, acked: u64, received: u64, sent: u64, retrans: u64) -> InetSocket {
        InetSocket {
            cookie,
            tcp_info: Some(TcpInfo {
                bytes_acked: acked,
                bytes_received: received,
                bytes_sent: sent,
                bytes_retrans: retrans,
                ..TcpInfo::default()
            }),
            ..InetSocket::default()
        }
    }

    #[test]
    fn two_snapshots_yield_goodput_and_retrans_ratio() {
        let mut t = SocketRateTracker::new();
        let t0 = Instant::now();

        // First ingest: baseline only, no rates.
        let s0 = [sock(7, 1_000, 2_000, 1_100, 0)];
        assert!(t.ingest(&s0, t0).is_empty());

        // +2s: 2 MB acked, 4 MB received, 100 KB retrans of 2.1 MB sent.
        let s1 = [sock(7, 2_001_000, 4_002_000, 3_201_100, 100_000)];
        let rates = t.ingest(&s1, t0 + Duration::from_secs(2));
        assert_eq!(rates.len(), 1);
        let r = &rates[0];
        assert_eq!(r.cookie, 7);
        assert_eq!(r.tx_goodput_bps, 1_000_000);
        assert_eq!(r.rx_goodput_bps, 2_000_000);
        assert!((r.retrans_ratio - 100_000.0 / 3_200_000.0).abs() < 1e-9);
    }

    #[test]
    fn new_cookie_needs_a_baseline_first() {
        let mut t = SocketRateTracker::new();
        let t0 = Instant::now();
        t.ingest(&[sock(1, 100, 100, 100, 0)], t0);
        // Second snapshot introduces cookie 2 — only cookie 1 rates.
        let rates = t.ingest(
            &[sock(1, 200, 200, 200, 0), sock(2, 999, 999, 999, 0)],
            t0 + Duration::from_secs(1),
        );
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].cookie, 1);
        assert_eq!(t.len(), 2, "cookie 2 is baselined for next round");
    }

    #[test]
    fn counter_regression_skips_sample_and_rebaselines() {
        let mut t = SocketRateTracker::new();
        let t0 = Instant::now();
        t.ingest(&[sock(1, 10_000, 0, 10_000, 0)], t0);
        // Counters went backwards (cookie reuse) — no rate emitted.
        let rates = t.ingest(&[sock(1, 100, 0, 100, 0)], t0 + Duration::from_secs(1));
        assert!(rates.is_empty());
        // Next interval computes from the fresh baseline.
        let rates = t.ingest(&[sock(1, 1_100, 0, 1_100, 0)], t0 + Duration::from_secs(2));
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].tx_goodput_bps, 1_000);
    }

    #[test]
    fn zero_dt_yields_no_rate() {
        let mut t = SocketRateTracker::new();
        let t0 = Instant::now();
        t.ingest(&[sock(1, 100, 100, 100, 0)], t0);
        assert!(t.ingest(&[sock(1, 200, 200, 200, 0)], t0).is_empty());
    }

    #[test]
    fn sockets_without_tcp_info_are_skipped() {
        let mut t = SocketRateTracker::new();
        let bare = InetSocket {
            cookie: 5,
            ..InetSocket::default()
        };
        assert!(t.ingest(&[bare], Instant::now()).is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn stale_cookies_evict_after_horizon() {
        let mut t = SocketRateTracker::new().with_evict_after(2);
        let t0 = Instant::now();
        t.ingest(&[sock(1, 100, 100, 100, 0)], t0);
        assert_eq!(t.len(), 1);
        // Cookie 1 disappears; two more ingests pass the horizon.
        t.ingest(&[sock(2, 1, 1, 1, 0)], t0 + Duration::from_secs(1));
        assert_eq!(t.len(), 2);
        t.ingest(&[sock(2, 2, 2, 2, 0)], t0 + Duration::from_secs(2));
        t.ingest(&[sock(2, 3, 3, 3, 0)], t0 + Duration::from_secs(3));
        assert_eq!(t.len(), 1, "cookie 1 evicted, cookie 2 retained");
    }

    #[test]
    fn zero_sent_interval_has_zero_retrans_ratio() {
        let mut t = SocketRateTracker::new();
        let t0 = Instant::now();
        t.ingest(&[sock(1, 0, 0, 0, 0)], t0);
        let rates = t.ingest(&[sock(1, 0, 500, 0, 0)], t0 + Duration::from_secs(1));
        assert_eq!(rates[0].retrans_ratio, 0.0);
        assert_eq!(rates[0].rx_goodput_bps, 500);
    }
}
