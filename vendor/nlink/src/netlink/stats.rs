//! Statistics: link and TC counters, snapshots of them, and rates.
//!
//! [`StatsSnapshot::capture`] reads every link's counters in one
//! `RTM_GETSTATS` dump, with the time they were read and the namespace they
//! were read in; two snapshots give a [`RatesSnapshot`]. [`StatsTracker`]
//! keeps the previous snapshot for you, and [`RateSampler`] does the same
//! for links in many namespaces at once, keyed so that `lo` in one is not
//! `lo` in another (#525).
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::netlink::stats::{StatsSnapshot, StatsTracker};
//! use std::time::Duration;
//!
//! // Two snapshots, and the rates between them.
//! let before = StatsSnapshot::capture(&conn).await?;
//! tokio::time::sleep(Duration::from_secs(1)).await;
//! let after = StatsSnapshot::capture(&conn).await?;
//! for (ifindex, link) in &after.rates(&before).links {
//!     println!("{ifindex}: {:.2} Mbit/s RX, {:.2} Mbit/s TX",
//!         link.rx_bps() / 1e6, link.tx_bps() / 1e6);
//! }
//!
//! // Or a tracker that keeps the previous one.
//! let mut tracker = StatsTracker::new();
//! loop {
//!     if let Some(rates) = tracker.update(StatsSnapshot::capture(&conn).await?) {
//!         println!("Total: {:.2} Mbit/s", rates.total_bytes_per_sec() * 8.0 / 1e6);
//!     }
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # }
//! ```

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::{
    attr::AttrIter,
    connection::{Connection, dump_request},
    error::Result,
    message::{NLMSG_HDRLEN, NlMsgType},
    messages::{LinkMessage, TcMessage},
    namespace::NetnsId,
    protocol::Route,
    types::link::{IFLA_STATS_LINK_64, IfStatsMsg, LinkStats64},
};

/// A link's counters. One type for the whole crate since 0.32: this
/// module had a second `LinkStats`, with the link's name in it (#525). A
/// snapshot keeps the names beside the counters, in
/// [`StatsSnapshot::names`].
pub use super::messages::LinkStats;

/// A link's rates, per second: what [`LinkRates::between`] computes from
/// two samples of its counters. One type for the whole crate since 0.32;
/// `diagnostics` had a second, in whole units (#525).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkRates {
    /// Bytes per second received.
    pub rx_bytes_per_sec: f64,
    /// Bytes per second transmitted.
    pub tx_bytes_per_sec: f64,
    /// Packets per second received.
    pub rx_packets_per_sec: f64,
    /// Packets per second transmitted.
    pub tx_packets_per_sec: f64,
    /// Receive errors per second.
    pub rx_errors_per_sec: f64,
    /// Transmit errors per second.
    pub tx_errors_per_sec: f64,
    /// Receive drops per second.
    pub rx_dropped_per_sec: f64,
    /// Transmit drops per second.
    pub tx_dropped_per_sec: f64,
}

impl LinkRates {
    /// The rates between two samples of one link's counters, `elapsed`
    /// apart.
    ///
    /// `None` when a counter went backwards — the link was recreated, or
    /// its counters reset — or no time passed. A decrease used to be taken
    /// for a 64-bit wrap, which never happens in practice, and reported
    /// about 1.8e19 bytes/s (#506). That the two samples are of the same
    /// link is the caller's to know: [`StatsSnapshot::rates`] and
    /// [`RateSampler`] compare names where they have them.
    pub fn between(prev: &LinkStats, now: &LinkStats, elapsed: Duration) -> Option<Self> {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return None;
        }
        let rate = |now: u64, prev: u64| Some(now.checked_sub(prev)? as f64 / secs);
        Some(Self {
            rx_bytes_per_sec: rate(now.rx_bytes(), prev.rx_bytes())?,
            tx_bytes_per_sec: rate(now.tx_bytes(), prev.tx_bytes())?,
            rx_packets_per_sec: rate(now.rx_packets(), prev.rx_packets())?,
            tx_packets_per_sec: rate(now.tx_packets(), prev.tx_packets())?,
            rx_errors_per_sec: rate(now.rx_errors(), prev.rx_errors())?,
            tx_errors_per_sec: rate(now.tx_errors(), prev.tx_errors())?,
            rx_dropped_per_sec: rate(now.rx_dropped(), prev.rx_dropped())?,
            tx_dropped_per_sec: rate(now.tx_dropped(), prev.tx_dropped())?,
        })
    }

    /// Total bytes per second (RX + TX).
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.rx_bytes_per_sec + self.tx_bytes_per_sec
    }

    /// Total packets per second (RX + TX).
    pub fn total_packets_per_sec(&self) -> f64 {
        self.rx_packets_per_sec + self.tx_packets_per_sec
    }

    /// Receive **bits** per second.
    pub fn rx_bps(&self) -> f64 {
        self.rx_bytes_per_sec * 8.0
    }

    /// Transmit **bits** per second.
    pub fn tx_bps(&self) -> f64 {
        self.tx_bytes_per_sec * 8.0
    }

    /// Total **bits** per second (RX + TX), comparable with a link speed.
    pub fn total_bps(&self) -> f64 {
        self.total_bytes_per_sec() * 8.0
    }
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Every link's counters, by ifindex, in one `RTM_GETSTATS` dump
    /// (Linux 4.7+) (#525).
    ///
    /// Counters only: no names, no attributes, so one dump does what
    /// [`get_links`](Self::get_links) — or a diagnostics scan, which is four
    /// dumps — did to read them. The ifindexes are the connection's
    /// namespace's.
    pub async fn get_stats64_all(&self) -> Result<HashMap<u32, LinkStats>> {
        let mut builder = dump_request(NlMsgType::RTM_GETSTATS);
        builder.append(&IfStatsMsg {
            filter_mask: 1 << (IFLA_STATS_LINK_64 - 1),
            ..IfStatsMsg::default()
        });
        let responses = self.send_dump(builder).await?;
        Ok(responses
            .iter()
            .filter_map(|r| parse_stats_msg(r.get(NLMSG_HDRLEN..)?))
            .collect())
    }
}

/// An `RTM_NEWSTATS` payload's ifindex and 64-bit link counters.
fn parse_stats_msg(payload: &[u8]) -> Option<(u32, LinkStats)> {
    let (hdr, _) = <IfStatsMsg as zerocopy::FromBytes>::read_from_prefix(payload).ok()?;
    AttrIter::new(payload.get(IfStatsMsg::SIZE..)?)
        .find(|(ty, _)| *ty == IFLA_STATS_LINK_64)
        .and_then(|(_, data)| LinkStats64::from_bytes(data))
        .map(|raw| (hdr.ifindex, LinkStats::from(&raw)))
}

/// Statistics for a TC qdisc/class.
#[derive(Debug, Clone, Default)]
pub struct TcStats {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes transmitted.
    pub bytes: u64,
    /// Packets transmitted.
    pub packets: u64,
    /// Packets dropped.
    pub drops: u32,
    /// Packets overlimit.
    pub overlimits: u32,
    /// Packets requeued.
    pub requeues: u32,
    /// Current queue length.
    pub qlen: u32,
    /// Current backlog in bytes.
    pub backlog: u32,
}

impl TcStats {
    /// Create from a TcMessage.
    pub fn from_tc_message(msg: &TcMessage) -> Self {
        Self {
            kind: msg.kind.clone(),
            bytes: msg.bytes(),
            packets: msg.packets(),
            drops: msg.drops(),
            overlimits: msg.overlimits(),
            requeues: msg.requeues(),
            qlen: msg.qlen(),
            backlog: msg.backlog(),
        }
    }
}

/// Rate statistics for a TC qdisc/class (per second).
#[derive(Debug, Clone, Default)]
pub struct TcRates {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes per second.
    pub bytes_per_sec: f64,
    /// Packets per second.
    pub packets_per_sec: f64,
    /// Drops per second.
    pub drops_per_sec: f64,
    /// Overlimits per second.
    pub overlimits_per_sec: f64,
    /// Requeues per second.
    pub requeues_per_sec: f64,
}

impl TcRates {
    /// The rates between two samples of one qdisc or class, `elapsed`
    /// apart; see [`LinkRates::between`].
    ///
    /// `None` when the kind changed (a qdisc replaced by another kind at
    /// the same handle) or bytes or packets went backwards (a recreate)
    /// (#506). Drops, overlimits and requeues are 32-bit in the kernel and
    /// do wrap, so with bytes and packets moving forward a decrease there
    /// is taken as one wrap.
    pub fn between(prev: &TcStats, now: &TcStats, elapsed: Duration) -> Option<Self> {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 || prev.kind != now.kind {
            return None;
        }
        let rate64 = |now: u64, prev: u64| Some(now.checked_sub(prev)? as f64 / secs);
        let rate32 = |now: u32, prev: u32| f64::from(now.wrapping_sub(prev)) / secs;
        Some(Self {
            kind: now.kind.clone(),
            bytes_per_sec: rate64(now.bytes, prev.bytes)?,
            packets_per_sec: rate64(now.packets, prev.packets)?,
            drops_per_sec: rate32(now.drops, prev.drops),
            overlimits_per_sec: rate32(now.overlimits, prev.overlimits),
            requeues_per_sec: rate32(now.requeues, prev.requeues),
        })
    }

    /// Bandwidth in bits per second.
    pub fn bps(&self) -> f64 {
        self.bytes_per_sec * 8.0
    }
}

/// Counters at a point in time: links, qdiscs and classes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StatsSnapshot {
    /// When the counters were read. Rates are taken between two of
    /// these, not between the calls that compared them, which is what
    /// [`StatsTracker`] measured before 0.32 (#525). `new()` and the
    /// `from_*` constructors take the time they are called; a caller that
    /// read the counters earlier sets it.
    pub taken_at: Instant,
    /// The namespace the counters were read in, when known.
    /// [`capture`](Self::capture) records it.
    pub netns: Option<NetnsId>,
    /// Link counters by ifindex.
    pub links: HashMap<u32, LinkStats>,
    /// Link names by ifindex, where the source had them: a link dump does,
    /// `RTM_GETSTATS` does not. Another name at an ifindex is another link,
    /// which has no rate.
    pub names: HashMap<u32, String>,
    /// Qdisc statistics by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcStats>,
    /// Class statistics by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcStats>,
}

impl Default for StatsSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

#[nlink_macros::send_futures]
impl StatsSnapshot {
    /// An empty snapshot, taken now.
    pub fn new() -> Self {
        Self {
            taken_at: Instant::now(),
            netns: None,
            links: HashMap::new(),
            names: HashMap::new(),
            qdiscs: HashMap::new(),
            classes: HashMap::new(),
        }
    }

    /// Every link's counters, read with one `RTM_GETSTATS` dump
    /// ([`Connection::get_stats64_all`]), with the time the dump ended and
    /// the connection's namespace. No names: use
    /// [`from_links`](Self::from_links) for those.
    pub async fn capture(conn: &Connection<Route>) -> Result<Self> {
        let links = conn.get_stats64_all().await?;
        let mut snapshot = Self::new();
        snapshot.links = links;
        snapshot.netns = conn.netns().ok().map(|ns| ns.id());
        Ok(snapshot)
    }

    /// A snapshot of link messages' counters and names.
    pub fn from_links(links: &[LinkMessage]) -> Self {
        let mut snapshot = Self::new();
        snapshot.add_links(links);
        snapshot
    }

    /// Create a snapshot from TC messages.
    pub fn from_tc(qdiscs: &[TcMessage], classes: &[TcMessage]) -> Self {
        let mut snapshot = Self::new();
        snapshot.add_qdiscs(qdiscs);
        snapshot.add_classes(classes);
        snapshot
    }

    /// Add link messages' counters and names to the snapshot.
    pub fn add_links(&mut self, links: &[LinkMessage]) {
        for link in links {
            self.links
                .insert(link.ifindex(), link.stats().copied().unwrap_or_default());
            if let Some(name) = link.name() {
                self.names.insert(link.ifindex(), name.to_string());
            }
        }
    }

    /// Add qdisc statistics to the snapshot.
    pub fn add_qdiscs(&mut self, qdiscs: &[TcMessage]) {
        for qdisc in qdiscs {
            let stats = TcStats::from_tc_message(qdisc);
            self.qdiscs
                .insert((qdisc.ifindex(), qdisc.handle_raw()), stats);
        }
    }

    /// Add class statistics to the snapshot.
    pub fn add_classes(&mut self, classes: &[TcMessage]) {
        for class in classes {
            let stats = TcStats::from_tc_message(class);
            self.classes
                .insert((class.ifindex(), class.handle_raw()), stats);
        }
    }

    /// The rates between `previous` and this snapshot, over the time
    /// between their [`taken_at`](Self::taken_at).
    ///
    /// Every interface and TC object in both that can be compared has an
    /// entry — see [`LinkRates::between`] and [`TcRates::between`]. One
    /// that was recreated, renamed or reset in between has none rather than
    /// a rate of about 1.8e19 (#506), and so has a link whose name differs
    /// between the two, where both have one.
    pub fn rates(&self, previous: &StatsSnapshot) -> RatesSnapshot {
        let elapsed = self.taken_at.saturating_duration_since(previous.taken_at);
        let mut rates = RatesSnapshot::new();
        for (ifindex, current) in &self.links {
            let renamed = matches!(
                (previous.names.get(ifindex), self.names.get(ifindex)),
                (Some(a), Some(b)) if a != b
            );
            if renamed {
                continue;
            }
            if let Some(rate) = previous
                .links
                .get(ifindex)
                .and_then(|prev| LinkRates::between(prev, current, elapsed))
            {
                rates.links.insert(*ifindex, rate);
            }
        }
        for (key, current) in &self.qdiscs {
            if let Some(rate) = previous
                .qdiscs
                .get(key)
                .and_then(|prev| TcRates::between(prev, current, elapsed))
            {
                rates.qdiscs.insert(*key, rate);
            }
        }
        for (key, current) in &self.classes {
            if let Some(rate) = previous
                .classes
                .get(key)
                .and_then(|prev| TcRates::between(prev, current, elapsed))
            {
                rates.classes.insert(*key, rate);
            }
        }
        rates
    }
}

/// A snapshot of rate statistics.
#[derive(Debug, Clone, Default)]
pub struct RatesSnapshot {
    /// Link rates by interface index.
    pub links: HashMap<u32, LinkRates>,
    /// Qdisc rates by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcRates>,
    /// Class rates by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcRates>,
}

impl RatesSnapshot {
    /// Create a new empty rates snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total RX bytes per second across all interfaces.
    pub fn total_rx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.rx_bytes_per_sec).sum()
    }

    /// Get total TX bytes per second across all interfaces.
    pub fn total_tx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.tx_bytes_per_sec).sum()
    }

    /// Get total bytes per second across all interfaces.
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.total_rx_bytes_per_sec() + self.total_tx_bytes_per_sec()
    }
}

/// Helper struct for tracking statistics over time.
///
/// This maintains the previous snapshot and computes rates automatically.
/// It also caches the most recent rates for convenient access.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::netlink::stats::StatsSnapshot;
/// # use std::time::Duration;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::stats::StatsTracker;
///
/// let mut tracker = StatsTracker::new();
///
/// loop {
///     let snapshot = StatsSnapshot::capture(&conn).await?;
///
///     // Update returns rates if we have a previous sample
///     if let Some(rates) = tracker.update(snapshot) {
///         for (ifindex, link_rates) in &rates.links {
///             println!("Interface {}: {:.2} Mbps", ifindex, link_rates.total_bps() / 1_000_000.0);
///         }
///     }
///
///     // Can also access cached rates later
///     if let Some(rate) = tracker.get_link_rate(1) {
///         println!("eth0: {:.2} Mbps RX", rate.rx_bps() / 1_000_000.0);
///     }
///
///     tokio::time::sleep(Duration::from_secs(1)).await;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct StatsTracker {
    previous: Option<StatsSnapshot>,
    last_rates: Option<RatesSnapshot>,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsTracker {
    /// Create a new stats tracker.
    pub fn new() -> Self {
        Self {
            previous: None,
            last_rates: None,
        }
    }

    /// Update with a new snapshot and return the rates since the previous
    /// one, over the time between the two snapshots'
    /// [`taken_at`](StatsSnapshot::taken_at). This timed the calls to
    /// `update` before 0.32, so a snapshot that waited before being handed
    /// over gave a rate over the wrong interval (#525).
    ///
    /// On the first call, returns `None` since there's no previous snapshot.
    /// The computed rates are cached and can be accessed via [`last_rates`](Self::last_rates),
    /// [`get_link_rate`](Self::get_link_rate), etc.
    pub fn update(&mut self, snapshot: StatsSnapshot) -> Option<RatesSnapshot> {
        let rates = self.previous.as_ref().map(|prev| snapshot.rates(prev));
        self.previous = Some(snapshot);
        self.last_rates = rates.clone();
        rates
    }

    /// Reset the tracker, clearing the previous snapshot and cached rates.
    pub fn reset(&mut self) {
        self.previous = None;
        self.last_rates = None;
    }

    /// Get the previous snapshot, if any.
    pub fn previous(&self) -> Option<&StatsSnapshot> {
        self.previous.as_ref()
    }

    /// Get the last computed rates, if any.
    ///
    /// This returns the rates from the most recent [`update`](Self::update) call.
    /// Returns `None` if `update` has been called fewer than 2 times or after [`reset`](Self::reset).
    pub fn last_rates(&self) -> Option<&RatesSnapshot> {
        self.last_rates.as_ref()
    }

    /// Get the cached rate for a specific interface by index.
    ///
    /// Returns `None` if no rates are cached or if the interface wasn't in the last snapshot.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::netlink::stats::StatsTracker;
    /// # let tracker = StatsTracker::new();
    /// # let ifindex = 2;
    /// if let Some(rate) = tracker.get_link_rate(ifindex) {
    ///     println!("RX: {:.2} Mbps, TX: {:.2} Mbps",
    ///         rate.rx_bps() / 1_000_000.0,
    ///         rate.tx_bps() / 1_000_000.0);
    /// }
    /// ```
    pub fn get_link_rate(&self, ifindex: u32) -> Option<&LinkRates> {
        self.last_rates.as_ref()?.links.get(&ifindex)
    }

    /// Get all cached link rates.
    ///
    /// Returns `None` if no rates are cached.
    pub fn get_all_link_rates(&self) -> Option<&HashMap<u32, LinkRates>> {
        self.last_rates.as_ref().map(|r| &r.links)
    }

    /// Get the cached rate for a specific qdisc.
    ///
    /// The key is (ifindex, handle).
    pub fn get_qdisc_rate(&self, ifindex: u32, handle: u32) -> Option<&TcRates> {
        self.last_rates.as_ref()?.qdiscs.get(&(ifindex, handle))
    }

    /// Get the cached rate for a specific class.
    ///
    /// The key is (ifindex, handle).
    pub fn get_class_rate(&self, ifindex: u32, handle: u32) -> Option<&TcRates> {
        self.last_rates.as_ref()?.classes.get(&(ifindex, handle))
    }

    /// Check if rates are available (i.e., update has been called at least twice).
    pub fn has_rates(&self) -> bool {
        self.last_rates.is_some()
    }
}

/// Which link a [`RateSampler`] rate is for: its namespace and ifindex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SampleKey {
    /// The namespace, as the snapshot recorded it.
    pub netns: Option<NetnsId>,
    /// The ifindex within it.
    pub ifindex: u32,
}

/// One link's rates from a [`RateSampler`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SampledRates {
    /// The link.
    pub key: SampleKey,
    /// Its name, when the snapshot had one.
    pub name: Option<String>,
    /// The rates since the previous sample of it.
    pub rates: LinkRates,
}

/// Link rates across many namespaces, sample after sample (#525).
///
/// [`StatsTracker`] follows one stream of snapshots, keyed by ifindex
/// alone, so snapshots from several namespaces overwrote each other — `lo`
/// is ifindex 1 in every one. A sampler keys each link by the namespace its
/// snapshot was read in and its ifindex, and knows a link that is not the
/// one it sampled last: a different name at the ifindex, or counters that
/// went backwards (a recreated link, a reset). Feed it snapshots from
/// [`StatsSnapshot::capture`] in any order.
///
/// ```no_run
/// # async fn example(spaces: Vec<nlink::netlink::namespace::Netns>) -> nlink::Result<()> {
/// use nlink::netlink::stats::{RateSampler, StatsSnapshot};
///
/// let mut sampler = RateSampler::new();
/// loop {
///     for ns in &spaces {
///         let conn = nlink::Connection::<nlink::Route>::new_in(ns)?;
///         for r in sampler.sample(&StatsSnapshot::capture(&conn).await?) {
///             println!("{:?} {}: {:.0} B/s", r.key.netns, r.key.ifindex, r.rates.rx_bytes_per_sec);
///         }
///     }
///     tokio::time::sleep(std::time::Duration::from_secs(1)).await;
/// }
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RateSampler {
    last: HashMap<SampleKey, (Instant, Option<String>, LinkStats)>,
}

impl RateSampler {
    /// A sampler with nothing sampled yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the rates of every link in `snapshot` sampled before, and keep
    /// its counters for the next call.
    ///
    /// A link has a rate when the previous sample is of the same
    /// namespace and ifindex, under the same name where both have one, and
    /// none of its counters went backwards. Links of the snapshot's
    /// namespace that are not in it are forgotten; other namespaces' are
    /// kept.
    pub fn sample(&mut self, snapshot: &StatsSnapshot) -> Vec<SampledRates> {
        let mut out = Vec::new();
        for (&ifindex, now) in &snapshot.links {
            let key = SampleKey {
                netns: snapshot.netns,
                ifindex,
            };
            let name = snapshot.names.get(&ifindex).cloned();
            if let Some((at, prev_name, prev)) = self.last.get(&key) {
                let same = match (prev_name, &name) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                };
                let elapsed = snapshot.taken_at.saturating_duration_since(*at);
                if same && let Some(rates) = LinkRates::between(prev, now, elapsed) {
                    out.push(SampledRates {
                        key,
                        name: name.clone(),
                        rates,
                    });
                }
            }
            self.last.insert(key, (snapshot.taken_at, name, *now));
        }
        self.last.retain(|key, _| {
            key.netns != snapshot.netns || snapshot.links.contains_key(&key.ifindex)
        });
        out.sort_by_key(|r| r.key);
        out
    }

    /// Forget a namespace's links: it was deleted, or is no longer
    /// watched.
    pub fn forget(&mut self, netns: Option<NetnsId>) {
        self.last.retain(|key, _| key.netns != netns);
    }

    /// How many links the sampler holds a previous sample of.
    pub fn len(&self) -> usize {
        self.last.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx(rx_bytes: u64) -> LinkStats {
        LinkStats {
            rx_bytes,
            ..Default::default()
        }
    }

    fn tc(kind: &str, bytes: u64, drops: u32) -> TcStats {
        TcStats {
            kind: Some(kind.to_string()),
            bytes,
            packets: bytes / 100,
            drops,
            ..Default::default()
        }
    }

    /// A snapshot of one link, `secs` after `t0`.
    fn snap(t0: Instant, secs: u64, ifindex: u32, name: Option<&str>, bytes: u64) -> StatsSnapshot {
        let mut s = StatsSnapshot::new();
        s.taken_at = t0 + Duration::from_secs(secs);
        s.links.insert(ifindex, rx(bytes));
        if let Some(name) = name {
            s.names.insert(ifindex, name.to_string());
        }
        s
    }

    /// #506: a counter that goes backwards is a reset — a recreated link,
    /// a replaced qdisc — not a 64-bit wrap. Taken for a wrap it reported
    /// about 1.8e19 bytes/s.
    #[test]
    fn a_counter_that_goes_backwards_is_a_reset_not_a_wrap() {
        let second = Duration::from_secs(1);
        let rates = LinkRates::between(&rx(1000), &rx(3000), second).unwrap();
        assert_eq!(rates.rx_bytes_per_sec, 2000.0);
        assert!(LinkRates::between(&rx(5000), &rx(10), second).is_none());

        let t0 = Instant::now();
        let mut prev = snap(t0, 0, 2, Some("eth0"), 5000);
        prev.qdiscs.insert((2, 0x10000), tc("htb", 9000, 0));
        let mut now = snap(t0, 1, 2, Some("eth0"), 10);
        now.qdiscs.insert((2, 0x10000), tc("htb", 100, 0));
        let rates = now.rates(&prev);
        assert!(rates.links.is_empty(), "{:?}", rates.links);
        assert!(rates.qdiscs.is_empty(), "{:?}", rates.qdiscs);
    }

    /// Another link at the ifindex, or another kind of qdisc at the
    /// handle, is not the object the previous sample was of.
    #[test]
    fn another_object_under_the_same_key_has_no_rate() {
        let t0 = Instant::now();
        let rates = snap(t0, 1, 2, Some("eth1"), 20).rates(&snap(t0, 0, 2, Some("eth0"), 10));
        assert!(rates.links.is_empty());
        // Without names to compare, the counters decide.
        let rates = snap(t0, 1, 2, None, 20).rates(&snap(t0, 0, 2, Some("eth0"), 10));
        assert_eq!(rates.links[&2].rx_bytes_per_sec, 10.0);
        let second = Duration::from_secs(1);
        assert!(TcRates::between(&tc("htb", 10, 0), &tc("prio", 20, 0), second).is_none());
        assert!(LinkRates::between(&rx(10), &rx(20), Duration::ZERO).is_none());
    }

    /// The 32-bit queue counters do wrap; with bytes and packets moving
    /// forward, a smaller drop count is one wrap.
    #[test]
    fn a_32_bit_drop_counter_wraps() {
        let rates = TcRates::between(
            &tc("htb", 1000, u32::MAX - 9),
            &tc("htb", 2000, 10),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(rates.drops_per_sec, 20.0);
        assert_eq!(rates.bytes_per_sec, 1000.0);
    }

    #[test]
    fn test_link_rates_bps() {
        let rates = LinkRates {
            rx_bytes_per_sec: 1000.0,
            tx_bytes_per_sec: 2000.0,
            ..Default::default()
        };

        assert_eq!(rates.rx_bps(), 8000.0);
        assert_eq!(rates.tx_bps(), 16000.0);
        assert_eq!(rates.total_bps(), 24000.0);
    }

    /// #525: rates are over the time between the snapshots, not between
    /// the calls that compared them. Handed over back to back, two
    /// snapshots read 2 s apart give a rate over 2 s; timed by `update`
    /// they gave one over a few nanoseconds.
    #[test]
    fn rates_are_over_the_time_the_snapshots_were_taken() {
        let t0 = Instant::now();
        let mut tracker = StatsTracker::new();
        assert!(tracker.update(snap(t0, 0, 1, Some("eth0"), 1000)).is_none());
        assert!(!tracker.has_rates());
        assert!(tracker.get_link_rate(1).is_none());
        let rates = tracker.update(snap(t0, 2, 1, Some("eth0"), 5000)).unwrap();
        assert_eq!(rates.links[&1].rx_bytes_per_sec, 2000.0);
        assert!(tracker.has_rates());
        assert_eq!(tracker.get_link_rate(1).unwrap().rx_bytes_per_sec, 2000.0);
        assert_eq!(tracker.get_all_link_rates().unwrap().len(), 1);
        assert!(tracker.get_link_rate(999).is_none());

        tracker.reset();
        assert!(!tracker.has_rates());
        assert!(tracker.last_rates().is_none());
        assert!(tracker.previous().is_none());
    }

    /// #525: `lo` is ifindex 1 in every namespace. A sampler keeps each
    /// namespace's apart, forgets a link that left its own namespace's
    /// snapshot, and keeps the others.
    #[test]
    fn a_sampler_keeps_namespaces_apart() {
        let (a, b) = (NetnsId::from_parts(1, 100), NetnsId::from_parts(1, 200));
        let t0 = Instant::now();
        let in_ns = |ns, secs, bytes| {
            let mut s = snap(t0, secs, 1, Some("lo"), bytes);
            s.netns = Some(ns);
            s
        };
        let mut sampler = RateSampler::new();
        assert!(sampler.sample(&in_ns(a, 0, 1000)).is_empty());
        assert!(sampler.sample(&in_ns(b, 0, 9_000_000)).is_empty());
        let rates = sampler.sample(&in_ns(a, 1, 1500));
        assert_eq!(rates.len(), 1);
        assert_eq!(
            rates[0].key,
            SampleKey {
                netns: Some(a),
                ifindex: 1
            }
        );
        assert_eq!(rates[0].name.as_deref(), Some("lo"));
        assert_eq!(
            rates[0].rates.rx_bytes_per_sec, 500.0,
            "not against b's counters"
        );
        let rates = sampler.sample(&in_ns(b, 2, 9_000_400));
        assert_eq!(rates[0].rates.rx_bytes_per_sec, 200.0);

        // A rename at the ifindex is another link: no rate, a new baseline.
        let mut renamed = in_ns(a, 2, 2000);
        renamed.names.insert(1, "other".into());
        assert!(sampler.sample(&renamed).is_empty());
        // An empty snapshot of a forgets a's links, not b's.
        let mut empty = StatsSnapshot::new();
        empty.netns = Some(a);
        sampler.sample(&empty);
        assert_eq!(sampler.len(), 1);
        sampler.forget(Some(b));
        assert!(sampler.is_empty());
    }

    /// An `RTM_NEWSTATS` payload: `if_stats_msg`, then `IFLA_STATS_LINK_64`.
    #[test]
    fn parses_an_rtm_newstats_payload() {
        use zerocopy::IntoBytes;
        let mut payload = IfStatsMsg {
            ifindex: 7,
            filter_mask: 1,
            ..IfStatsMsg::default()
        }
        .as_bytes()
        .to_vec();
        // 24 u64 counters, rx_packets first; one more than this nlink
        // knows, as a newer kernel sends (rx_otherhost_dropped).
        let counters: Vec<u64> = (1..=25).collect();
        let data: Vec<u8> = counters.iter().flat_map(|c| c.to_ne_bytes()).collect();
        payload.extend_from_slice(&(4 + data.len() as u16).to_ne_bytes());
        payload.extend_from_slice(&IFLA_STATS_LINK_64.to_ne_bytes());
        payload.extend_from_slice(&data);
        let (ifindex, stats) = parse_stats_msg(&payload).unwrap();
        assert_eq!(ifindex, 7);
        assert_eq!((stats.rx_packets(), stats.tx_packets()), (1, 2));
        assert_eq!((stats.rx_bytes(), stats.tx_bytes()), (3, 4));
        assert_eq!(stats.collisions(), 10);
        assert!(parse_stats_msg(&payload[..10]).is_none());
    }
}
