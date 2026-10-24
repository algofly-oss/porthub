//! WireGuard polling watcher (Plan 199).
//!
//! WireGuard has **no native multicast surface**. The
//! in-tree kernel module's GENL family declares
//! `n_mcgrps = 0` (verified 2026-05-31 via
//! `drivers/net/wireguard/netlink.c`). The UAPI header
//! `include/uapi/linux/wireguard.h` defines only
//! `WG_CMD_GET_DEVICE` + `WG_CMD_SET_DEVICE` — request /
//! response, no notification commands. Userspace cannot
//! subscribe.
//!
//! Every WG monitoring tool (`wg show`, `systemd-networkd`,
//! `cunicu`) therefore **polls** `GET_DEVICE` on a cadence
//! and computes the diff client-side. This module exposes a
//! typed poll-and-diff primitive so consumers don't
//! reimplement that machinery per app.
//!
//! ## What about a future kernel multicast surface?
//!
//! Linus Lotz submitted [`[PATCH v2] wireguard: netlink: add
//! multicast notification for peer changes`][patch] in
//! January 2021. Status as of mainline today: **"Awaiting
//! Upstream"** — never merged. If the kernel grows
//! multicast support, this watcher will be replaced with a
//! multicast subscriber and the polling path will become a
//! compatibility shim. The [`WireguardEvent`] enum shape
//! stays the same either way; consumer code keeps working.
//!
//! [patch]: https://lkml.kernel.org/netdev/20210115195353.11483-1-linus@lotz.li/T/

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use super::types::{AllowedIp, WG_KEY_LEN, WgDevice, WgPeer};
use crate::netlink::protocol::Wireguard;
use crate::{Connection, Error, Result};

/// Synthetic peer-state change event emitted by the polling
/// watcher when a poll cycle observes a difference from the
/// previous snapshot. Plan 199.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WireguardEvent {
    /// A peer not seen in the previous poll appeared. On the
    /// very first poll, every existing peer fires this
    /// variant — initial-inventory semantics, matches Plan
    /// 185 / 191's snapshot shape.
    PeerAdded {
        /// Interface name where the change was observed.
        ifname: String,
        /// Full peer record as the kernel reported it.
        peer: WgPeer,
    },
    /// A peer seen previously is gone in this poll.
    PeerRemoved {
        /// Interface name where the change was observed.
        ifname: String,
        /// Public key of the removed peer.
        public_key: [u8; WG_KEY_LEN],
    },
    /// A peer's endpoint changed — typically a NAT rebind,
    /// roaming client, or operator `wg set ... endpoint ...`.
    PeerEndpointChanged {
        /// Interface name where the change was observed.
        ifname: String,
        /// Public key of the peer.
        public_key: [u8; WG_KEY_LEN],
        /// Previous endpoint (`None` if not previously set).
        from: Option<SocketAddr>,
        /// New endpoint (`None` if cleared).
        to: Option<SocketAddr>,
    },
    /// A peer's `last_handshake` timestamp advanced — fresh
    /// connectivity proof. Emitted whenever the kernel
    /// reports a strictly later timestamp than the previous
    /// poll, OR transitions from `None` to `Some(_)` (first
    /// handshake ever).
    PeerHandshakeRefreshed {
        /// Interface name where the change was observed.
        ifname: String,
        /// Public key of the peer.
        public_key: [u8; WG_KEY_LEN],
        /// New handshake timestamp from the kernel.
        at: SystemTime,
    },
    /// A peer's `allowed_ips` list changed.
    PeerAllowedIpsChanged {
        /// Interface name where the change was observed.
        ifname: String,
        /// Public key of the peer.
        public_key: [u8; WG_KEY_LEN],
        /// `allowed_ips` from the previous poll.
        previous: Vec<AllowedIp>,
        /// `allowed_ips` in this poll.
        current: Vec<AllowedIp>,
    },
}

/// Configuration for the polling watcher.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[must_use = "options do nothing unless passed to WireguardWatcher::new"]
pub struct WireguardWatchOptions {
    /// How often to poll `GET_DEVICE`. Default: 1 second.
    ///
    /// Trade-off: lower values catch handshake-fresh /
    /// endpoint-rebind events sooner at the cost of more
    /// netlink traffic. The kernel re-keys handshakes on a
    /// ~120-second timer, so anything < 30 s is overkill for
    /// handshake tracking; bytes/endpoint changes can fire
    /// at packet rate.
    pub interval: Duration,
    /// Which interfaces to watch. Must be non-empty —
    /// `WireguardWatcher::new` returns an error otherwise.
    /// nlink does NOT auto-enumerate WG-kind interfaces:
    /// that requires an RTNETLINK connection alongside the
    /// WG one, which the caller can do more cheaply.
    pub interfaces: Vec<String>,
}

impl Default for WireguardWatchOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            interfaces: Vec::new(),
        }
    }
}

impl WireguardWatchOptions {
    /// Set the polling interval (builder shape).
    pub fn interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    /// Add an interface to watch (builder shape). Can be
    /// called multiple times to watch several interfaces
    /// from one watcher.
    pub fn interface(mut self, ifname: impl Into<String>) -> Self {
        self.interfaces.push(ifname.into());
        self
    }
}

/// Pure-function diff between two device snapshots,
/// producing one event per observed change. Exposed so
/// callers wiring their own polling cadence can reuse the
/// diff logic.
///
/// `previous` is `None` on the FIRST poll for a given
/// interface — in that case every peer in `current` emits
/// `PeerAdded` (initial inventory, matching Plan 185 / 191
/// snapshot semantics).
pub fn diff_device_states(
    ifname: &str,
    previous: Option<&WgDevice>,
    current: &WgDevice,
) -> Vec<WireguardEvent> {
    let mut out = Vec::new();

    let prev_peers: HashMap<&[u8; WG_KEY_LEN], &WgPeer> = previous
        .map(|d| d.peers.iter().map(|p| (&p.public_key, p)).collect())
        .unwrap_or_default();
    let curr_peers: HashMap<&[u8; WG_KEY_LEN], &WgPeer> =
        current.peers.iter().map(|p| (&p.public_key, p)).collect();

    // Added peers.
    for (pk, peer) in &curr_peers {
        if !prev_peers.contains_key(pk) {
            out.push(WireguardEvent::PeerAdded {
                ifname: ifname.to_string(),
                peer: (*peer).clone(),
            });
        }
    }

    // Removed peers.
    for pk in prev_peers.keys() {
        if !curr_peers.contains_key(pk) {
            out.push(WireguardEvent::PeerRemoved {
                ifname: ifname.to_string(),
                public_key: **pk,
            });
        }
    }

    // Mutated peers — endpoint / handshake / allowed_ips.
    for (pk, curr) in &curr_peers {
        let Some(prev) = prev_peers.get(pk) else {
            continue;
        };

        if prev.endpoint != curr.endpoint {
            out.push(WireguardEvent::PeerEndpointChanged {
                ifname: ifname.to_string(),
                public_key: **pk,
                from: prev.endpoint,
                to: curr.endpoint,
            });
        }

        // Handshake — strictly-later advance, OR first-ever
        // handshake (None → Some).
        match (prev.last_handshake, curr.last_handshake) {
            (Some(p), Some(c)) if c > p => {
                out.push(WireguardEvent::PeerHandshakeRefreshed {
                    ifname: ifname.to_string(),
                    public_key: **pk,
                    at: c,
                });
            }
            (None, Some(c)) => {
                out.push(WireguardEvent::PeerHandshakeRefreshed {
                    ifname: ifname.to_string(),
                    public_key: **pk,
                    at: c,
                });
            }
            _ => {}
        }

        if prev.allowed_ips != curr.allowed_ips {
            out.push(WireguardEvent::PeerAllowedIpsChanged {
                ifname: ifname.to_string(),
                public_key: **pk,
                previous: prev.allowed_ips.clone(),
                current: curr.allowed_ips.clone(),
            });
        }
    }

    out
}

/// Polling-based WireGuard watcher. Holds the GENL
/// connection, the per-interface previous-snapshot table,
/// and the polling cadence. Plan 199.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use std::time::Duration;
/// use nlink::netlink::{Connection, Wireguard};
/// use nlink::netlink::genl::wireguard::watch::{
///     WireguardWatcher, WireguardWatchOptions,
/// };
///
/// let conn = Connection::<Wireguard>::new_async().await?;
/// let mut watcher = WireguardWatcher::new(
///     conn,
///     WireguardWatchOptions::default()
///         .interval(Duration::from_secs(5))
///         .interface("wg0"),
/// )?;
///
/// loop {
///     let events = watcher.next_events().await?;
///     for ev in events {
///         println!("{:?}", ev);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "WireguardWatcher does nothing unless next_events() is called"]
pub struct WireguardWatcher {
    conn: Connection<Wireguard>,
    opts: WireguardWatchOptions,
    /// ifname → previous device snapshot.
    previous: HashMap<String, WgDevice>,
    first_poll: bool,
}

#[nlink_macros::send_futures]
impl WireguardWatcher {
    /// Construct a new watcher. Returns
    /// `Error::invalid_message` if `opts.interfaces` is
    /// empty (the caller must specify at least one
    /// interface to watch).
    pub fn new(conn: Connection<Wireguard>, opts: WireguardWatchOptions) -> Result<Self> {
        if opts.interfaces.is_empty() {
            return Err(Error::invalid_message(
                "WireguardWatchOptions::interfaces is empty — \
                 specify at least one interface to watch"
                    .to_string(),
            ));
        }
        Ok(Self {
            conn,
            opts,
            previous: HashMap::new(),
            first_poll: true,
        })
    }

    /// Sleep until the next poll cycle, then poll every
    /// watched interface and return the diff events.
    ///
    /// The FIRST call does NOT sleep — it polls
    /// immediately and emits `PeerAdded` for every peer
    /// it finds (initial inventory, matching Plan 185 /
    /// 191 snapshot semantics).
    ///
    /// Returns an empty vector if all watched interfaces
    /// report identical state to the previous poll.
    ///
    /// **Per-interface resilience (0.19 N6 fix).** A failure on
    /// one watched interface (the iface was deleted out-of-band,
    /// momentarily unavailable, etc.) no longer aborts the whole
    /// poll cycle. If the previous poll had peers for that iface,
    /// `PeerRemoved` events are emitted for them and the
    /// interface drops out of `self.previous`. Other interfaces
    /// continue to be polled. Pre-0.19 the first iface error
    /// propagated `?` and silently abandoned all unprocessed
    /// interfaces — Plan 199's reliability claim depended on
    /// this fix.
    pub async fn next_events(&mut self) -> Result<Vec<WireguardEvent>> {
        if !self.first_poll {
            tokio::time::sleep(self.opts.interval).await;
        }
        self.first_poll = false;

        let mut all_events = Vec::new();
        for ifname in self.opts.interfaces.clone() {
            match self.conn.get_device_by_name(&ifname).await {
                Ok(device) => {
                    let prev = self.previous.get(&ifname);
                    let events = diff_device_states(&ifname, prev, &device);
                    all_events.extend(events);
                    self.previous.insert(ifname, device);
                }
                Err(e) => {
                    tracing::warn!(
                        ifname = %ifname,
                        error = %e,
                        "WireguardWatcher: failed to poll interface; emitting PeerRemoved for any tracked peers and continuing",
                    );
                    if let Some(prev_device) = self.previous.remove(&ifname) {
                        for peer in &prev_device.peers {
                            all_events.push(WireguardEvent::PeerRemoved {
                                ifname: ifname.clone(),
                                public_key: peer.public_key,
                            });
                        }
                    }
                }
            }
        }
        Ok(all_events)
    }

    /// Borrow the underlying connection — useful for
    /// running ad-hoc queries between polls.
    pub fn connection(&self) -> &Connection<Wireguard> {
        &self.conn
    }

    /// Recover the underlying connection when done watching.
    pub fn into_connection(self) -> Connection<Wireguard> {
        self.conn
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn key(byte: u8) -> [u8; WG_KEY_LEN] {
        [byte; WG_KEY_LEN]
    }

    fn peer(pk: [u8; WG_KEY_LEN]) -> WgPeer {
        WgPeer::new(pk)
    }

    fn device(peers: Vec<WgPeer>) -> WgDevice {
        let mut d = WgDevice::new();
        d.ifname = Some("wg0".to_string());
        d.peers = peers;
        d
    }

    #[test]
    fn first_poll_emits_peer_added_for_every_existing_peer() {
        let current = device(vec![peer(key(1)), peer(key(2))]);
        let events = diff_device_states("wg0", None, &current);
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            WireguardEvent::PeerAdded { .. }
        ));
    }

    #[test]
    fn no_change_emits_empty() {
        let snap = device(vec![peer(key(1))]);
        let events = diff_device_states("wg0", Some(&snap), &snap);
        assert!(events.is_empty());
    }

    #[test]
    fn new_peer_emits_peer_added() {
        let prev = device(vec![peer(key(1))]);
        let curr = device(vec![peer(key(1)), peer(key(2))]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        match &events[0] {
            WireguardEvent::PeerAdded { peer, .. } => assert_eq!(peer.public_key, key(2)),
            other => panic!("expected PeerAdded, got {other:?}"),
        }
    }

    #[test]
    fn removed_peer_emits_peer_removed() {
        let prev = device(vec![peer(key(1)), peer(key(2))]);
        let curr = device(vec![peer(key(1))]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        match &events[0] {
            WireguardEvent::PeerRemoved { public_key, .. } => assert_eq!(*public_key, key(2)),
            other => panic!("expected PeerRemoved, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_change_emits_endpoint_changed() {
        let mut prev_peer = peer(key(1));
        prev_peer.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 51820));
        let mut curr_peer = peer(key(1));
        curr_peer.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 51820));

        let prev = device(vec![prev_peer]);
        let curr = device(vec![curr_peer]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            WireguardEvent::PeerEndpointChanged { .. }
        ));
    }

    #[test]
    fn handshake_advance_emits_refresh() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000);
        let t1 = UNIX_EPOCH + Duration::from_secs(2_000);

        let mut prev_peer = peer(key(1));
        prev_peer.last_handshake = Some(t0);
        let mut curr_peer = peer(key(1));
        curr_peer.last_handshake = Some(t1);

        let prev = device(vec![prev_peer]);
        let curr = device(vec![curr_peer]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        match &events[0] {
            WireguardEvent::PeerHandshakeRefreshed { at, .. } => assert_eq!(*at, t1),
            other => panic!("expected PeerHandshakeRefreshed, got {other:?}"),
        }
    }

    #[test]
    fn handshake_same_emits_nothing() {
        let t = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut p = peer(key(1));
        p.last_handshake = Some(t);
        let snap = device(vec![p]);
        let events = diff_device_states("wg0", Some(&snap), &snap);
        assert!(events.is_empty());
    }

    #[test]
    fn first_ever_handshake_emits_refresh() {
        let t = UNIX_EPOCH + Duration::from_secs(1_000);

        let prev_peer = peer(key(1));
        let mut curr_peer = peer(key(1));
        curr_peer.last_handshake = Some(t);

        let prev = device(vec![prev_peer]);
        let curr = device(vec![curr_peer]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            WireguardEvent::PeerHandshakeRefreshed { .. }
        ));
    }

    #[test]
    fn allowed_ips_change_emits_event() {
        let mut prev_peer = peer(key(1));
        prev_peer.allowed_ips = vec![AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24)];
        let mut curr_peer = peer(key(1));
        curr_peer.allowed_ips = vec![
            AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
            AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24),
        ];

        let prev = device(vec![prev_peer]);
        let curr = device(vec![curr_peer]);
        let events = diff_device_states("wg0", Some(&prev), &curr);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            WireguardEvent::PeerAllowedIpsChanged { .. }
        ));
    }

    #[test]
    fn watch_options_defaults() {
        let opts = WireguardWatchOptions::default();
        assert_eq!(opts.interval, Duration::from_secs(1));
        assert!(opts.interfaces.is_empty());
    }

    #[test]
    fn watch_options_builder() {
        let opts = WireguardWatchOptions::default()
            .interval(Duration::from_secs(30))
            .interface("wg0")
            .interface("wg1");
        assert_eq!(opts.interval, Duration::from_secs(30));
        assert_eq!(opts.interfaces, vec!["wg0", "wg1"]);
    }
}
