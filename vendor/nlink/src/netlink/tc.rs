//! Typed TC (Traffic Control) configuration and builders.
//!
//! This module provides strongly-typed configuration for qdiscs with builder patterns.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use nlink::TcHandle;
//! # use nlink::Percent;
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::netlink::tc::{NetemConfig, QdiscConfig};
//! use std::time::Duration;
//!
//! // Create a netem configuration with delay and loss
//! let netem = NetemConfig::new()
//!     .delay(Duration::from_millis(100))
//!     .jitter(Duration::from_millis(10))
//!     .delay_correlation(Percent::new(25.0))
//!     .loss(Percent::new(1.0))
//!     .loss_correlation(Percent::new(25.0))
//!     .build();
//!
//! // Add the qdisc
//! conn.add_qdisc("eth0", netem).await?;
//!
//! // Later, modify it
//! let updated = NetemConfig::new()
//!     .delay(Duration::from_millis(50))
//!     .build();
//! conn.change_qdisc("eth0", TcHandle::ROOT, updated).await?;
//!
//! // Delete it
//! conn.del_qdisc("eth0", TcHandle::ROOT).await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

// Re-export for convenience
pub use super::tc_options::NetemLossModel;
pub use super::types::tc::qdisc::hfsc::TcServiceCurve;
pub use super::types::tc::qdisc::taprio::TaprioSchedEntry;
use super::{
    Connection,
    builder::MessageBuilder,
    connection::{ack_request, create_request, replace_request},
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NlMsgType},
    messages::TcMessage,
    protocol::Route,
    psched,
    tc_handle::TcHandle,
    types::tc::{
        TcMsg, TcaAttr,
        qdisc::{TcRateSpec, codel, ets, fq, fq_codel, htb, netem::*, prio, sfq, tbf},
    },
};

// ============================================================================
// QdiscConfig trait
// ============================================================================

/// A boxed or borrowed config is a config, so a qdisc kind chosen at run
/// time can be installed: `conn.replace_qdisc(dev, boxed)` with a
/// `Box<dyn QdiscConfig>` (#515).
impl<T: QdiscConfig + ?Sized> QdiscConfig for Box<T> {
    fn kind(&self) -> &'static str {
        (**self).kind()
    }
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        (**self).write_options(builder)
    }
    fn has_options(&self) -> bool {
        (**self).has_options()
    }
    fn default_handle(&self) -> Option<TcHandle> {
        (**self).default_handle()
    }
    fn in_place(&self, live: &TcMessage) -> InPlace {
        (**self).in_place(live)
    }
    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        (**self).write_change_options(builder)
    }
    fn fixed_parent(&self) -> Option<TcHandle> {
        (**self).fixed_parent()
    }
}

impl<T: QdiscConfig + ?Sized> QdiscConfig for &T {
    fn kind(&self) -> &'static str {
        (**self).kind()
    }
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        (**self).write_options(builder)
    }
    fn has_options(&self) -> bool {
        (**self).has_options()
    }
    fn default_handle(&self) -> Option<TcHandle> {
        (**self).default_handle()
    }
    fn in_place(&self, live: &TcMessage) -> InPlace {
        (**self).in_place(live)
    }
    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        (**self).write_change_options(builder)
    }
    fn fixed_parent(&self) -> Option<TcHandle> {
        (**self).fixed_parent()
    }
}

/// How a live qdisc takes a replace by one of the same kind; see
/// [`QdiscConfig::in_place`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InPlace {
    /// The kernel changes the live qdisc's parameters (`qdisc_change`).
    Change,
    /// The live qdisc is replaced by a new one, grafted into the slot in
    /// the same request, so the slot is never bare: the kind has no change
    /// operation, or a parameter only creation honours differs.
    Recreate,
}

/// The handle a classful qdisc gets at the root when none is given:
/// `1:` (#515).
pub const CLASSFUL_ROOT_HANDLE: TcHandle = TcHandle::major_only(1);

/// `config`'s default handle, when it goes at the root.
fn root_default_handle(parent: TcHandle, config: &impl QdiscConfig) -> Option<TcHandle> {
    parent.is_root().then(|| config.default_handle()).flatten()
}

/// Trait for qdisc configurations that can be applied.
pub trait QdiscConfig: Send + Sync {
    /// Get the qdisc kind (e.g., "netem", "htb", "fq_codel").
    fn kind(&self) -> &'static str;

    /// Write the qdisc options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Whether the request should carry a `TCA_OPTIONS` attribute at all.
    ///
    /// The kernel distinguishes an **absent** `TCA_OPTIONS` (`opt == NULL`
    /// in the qdisc's `init`) from a **present but empty** one, and the two
    /// are not interchangeable — the answer differs per kind. `plug_init`
    /// takes `opt == NULL` as "use the device's `txqueuelen × MTU`" and
    /// rejects an empty nest with `EINVAL`, because the nest is shorter
    /// than `struct tc_plug_qopt`. `drr_change_class` and
    /// `qfq_change_class` go the other way: they refuse `NULL` and read
    /// their defaults from an empty nest. So this is per-config and
    /// opt-in, not a blanket "skip empty nests" (#327).
    ///
    /// Default `true`: the nest is always written, and
    /// [`write_options`](Self::write_options) decides what goes in it.
    /// Return `false` when the kernel must see no `TCA_OPTIONS` — the
    /// connection then skips the nest entirely and never calls
    /// `write_options` for that request.
    fn has_options(&self) -> bool {
        true
    }

    /// The handle a qdisc of this kind gets at the root when none is
    /// given (#515): `1:` for a classful kind, so its classes and filters
    /// can name it, where the kernel — and tc(8) — would pick `8001:`.
    /// `None`, the default, leaves the choice to the kernel.
    ///
    /// Only an add or replace at the root with no handle uses it; a
    /// replace that changes or recreates a live qdisc keeps that qdisc's
    /// handle. This was declared, returned `None` for every kind, and was
    /// read by nothing that mattered, before 0.32.
    fn default_handle(&self) -> Option<TcHandle> {
        None
    }

    /// How [`Connection::replace_qdisc`] has to treat `live`, a qdisc of
    /// this kind already in the slot (#486).
    ///
    /// Default [`InPlace::Change`]: the kernel's `qdisc_change` takes the
    /// new parameters. Kinds without a change operation (`htb`, `sfq`)
    /// return [`InPlace::Recreate`], as does `fq_codel` when the declared
    /// `flows` — which only `init` honours — differs from the live one.
    fn in_place(&self, live: &TcMessage) -> InPlace {
        let _ = live;
        InPlace::Change
    }

    /// The options of an in-place change of a live qdisc of this kind.
    ///
    /// Default: [`write_options`](Self::write_options). `fq_codel`
    /// overrides it to leave out `flows`, which `fq_codel_change` refuses
    /// on a live qdisc even when the value is unchanged (#486).
    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        self.write_options(builder)
    }

    /// The one parent this qdisc kind can live under, if it is
    /// parent-fixed.
    ///
    /// `ingress` and `clsact` are not schedulers — they are the two
    /// spellings of a fixed hook slot, and `ingress_init`/`clsact_init`
    /// reject anything but `TC_H_INGRESS` with `EOPNOTSUPP`. The
    /// convenience constructors [`Connection::add_qdisc`] and
    /// [`Connection::add_qdisc_by_index`] default the parent to
    /// `TC_H_ROOT`, so every caller that reached for them — the
    /// declarative `apply` path and `attach_bpf` among them — sent a
    /// request the kernel could only refuse. Honouring this makes the
    /// short form correct instead of merely convenient.
    ///
    /// [`Connection::add_qdisc`]: crate::Connection::add_qdisc
    /// [`Connection::add_qdisc_by_index`]: crate::Connection::add_qdisc_by_index
    fn fixed_parent(&self) -> Option<TcHandle> {
        None
    }
}

// ============================================================================
// NetemConfig
// ============================================================================

/// Network emulator (netem) qdisc configuration.
///
/// Netem allows adding delay, packet loss, duplication, corruption, and reordering
/// to outgoing packets on an interface.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Percent;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::NetemConfig;
/// use nlink::Packets;
/// use std::time::Duration;
///
/// // Simulate a lossy satellite link
/// let config = NetemConfig::new()
///     .delay(Duration::from_millis(500))
///     .jitter(Duration::from_millis(50))
///     .loss(Percent::new(0.1))  // 0.1% packet loss
///     .limit(Packets::new(10000))
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
///
/// Jitter without a [`rate`](Self::rate) reorders packets: netem sends
/// each at its own delayed time from a time-sorted queue (tfifo), so a
/// packet given less jitter overtakes one given more. tc(8) behaves the
/// same; set a rate, or no jitter, to keep the order.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct NetemConfig {
    /// Added delay.
    pub delay: Option<Duration>,
    /// Delay jitter (variation).
    pub jitter: Option<Duration>,
    /// Delay correlation.
    pub delay_correlation: crate::util::Percent,
    /// Packet loss percentage.
    pub loss: crate::util::Percent,
    /// Loss correlation. **Lowers the loss rate, it does not make loss
    /// bursty** — see [`loss_correlation`](Self::loss_correlation).
    pub loss_correlation: crate::util::Percent,
    /// Packet duplication percentage.
    pub duplicate: crate::util::Percent,
    /// Duplication correlation.
    pub duplicate_correlation: crate::util::Percent,
    /// Packet corruption percentage.
    pub corrupt: crate::util::Percent,
    /// Corruption correlation.
    pub corrupt_correlation: crate::util::Percent,
    /// Packet reordering percentage.
    pub reorder: crate::util::Percent,
    /// Reordering correlation.
    pub reorder_correlation: crate::util::Percent,
    /// Reorder gap.
    pub gap: u32,
    /// Rate limit.
    pub rate: Option<crate::util::Rate>,
    /// Queue limit in packets.
    pub limit: crate::util::Packets,
    /// A Markov loss model (`loss state …` / `loss gemodel …`) in place
    /// of random [`loss`](Self::loss). Added in 0.29 (#368).
    pub loss_model: Option<NetemLossModel>,
    /// Mark packets with ECN instead of dropping them, where `loss` would
    /// (`tc … ecn`). Added in 0.32 (#515).
    pub ecn: bool,
    /// Release packets in slots (`tc … slot`). Added in 0.32 (#515).
    pub slot: Option<NetemSlot>,
    /// The seed of netem's random numbers (`tc … seed N`, Linux 6.3+): the
    /// same seed drops, duplicates and reorders the same packets of the
    /// same traffic, run after run. Added in 0.32 (#515).
    pub seed: Option<u64>,
    /// The delay distribution jitter is drawn from (`tc … distribution
    /// normal`); uniform when `None`. Added in 0.32 (#515).
    pub distribution: Option<NetemDistribution>,
    /// The link-layer overhead the [`rate`](Self::rate) accounts for, in
    /// bytes per packet (`tc … rate R OVERHEAD`). Added in 0.32 (#515).
    pub rate_packet_overhead: i32,
    /// The cell size the rate rounds each packet up to (ATM: 53).
    /// Added in 0.32 (#515).
    pub rate_cell_size: u32,
    /// The overhead added to each cell. Added in 0.32 (#515).
    pub rate_cell_overhead: i32,
}

/// A netem slot (`tc … slot MIN MAX [packets N] [bytes N]`): packets are
/// held and released in bursts, each slot between `min_delay` and
/// `max_delay` after the last, as a Wi-Fi or DOCSIS link schedules them
/// (#515).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetemSlot {
    /// The shortest time between slots.
    pub min_delay: Duration,
    /// The longest time between slots; each is uniformly between the two.
    pub max_delay: Duration,
    /// The most packets one slot releases; unlimited when `None`.
    pub max_packets: Option<crate::util::Packets>,
    /// The most bytes one slot releases; unlimited when `None`.
    pub max_bytes: Option<u32>,
}

impl NetemSlot {
    /// Slots `min_delay` to `max_delay` apart, with no limit on what one
    /// releases.
    pub fn new(min_delay: Duration, max_delay: Duration) -> Self {
        Self {
            min_delay,
            max_delay,
            max_packets: None,
            max_bytes: None,
        }
    }

    /// Release at most `n` packets per slot.
    pub fn packets(mut self, n: crate::util::Packets) -> Self {
        self.max_packets = Some(n);
        self
    }

    /// Release at most `n` bytes per slot.
    pub fn bytes(mut self, n: u32) -> Self {
        self.max_bytes = Some(n);
        self
    }
}

/// A netem delay distribution table (`tc … distribution NAME`): the shape
/// of the jitter added to each packet's delay (#515).
///
/// tc(8) loads tables from iproute2's generated `.dist` files (`normal`,
/// `pareto`, `paretonormal`); [`named`](Self::named) reads the same files
/// from the same places, so a table matches `tc`'s exactly.
///
/// The kernel keeps a table across a change and never dumps it: to remove
/// one, delete the qdisc and add it again. For the same reason a reconcile
/// cannot see one — [`PerPeerImpairer`](crate::netlink::impair::PerPeerImpairer)
/// leaves a netem in place when everything else about it matches, whatever
/// table it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetemDistribution {
    table: Vec<i16>,
}

impl NetemDistribution {
    /// The most entries a table may have (`NETEM_DIST_MAX`).
    pub const MAX_LEN: usize = 16384;

    /// A table iproute2 installs, by name (`normal`, `pareto`,
    /// `paretonormal`, …), found where tc(8) looks: `$TC_LIB_DIR`,
    /// `/usr/lib/tc`, `/usr/lib64/tc`, and the multiarch
    /// `/usr/lib/<triplet>/tc`.
    pub fn named(name: &str) -> Result<Self> {
        if name.is_empty() || name.contains('/') {
            return Err(Error::invalid_message(format!(
                "netem: distribution `{name}` is not a table name"
            )));
        }
        let file = format!("{name}.dist");
        let mut dirs: Vec<std::path::PathBuf> = Vec::new();
        if let Some(dir) = std::env::var_os("TC_LIB_DIR") {
            dirs.push(dir.into());
        }
        dirs.extend(["/usr/lib/tc", "/usr/lib64/tc"].map(std::path::PathBuf::from));
        if let Ok(entries) = std::fs::read_dir("/usr/lib") {
            dirs.extend(entries.flatten().map(|e| e.path().join("tc")));
        }
        for dir in dirs {
            let path = dir.join(&file);
            if path.is_file() {
                return Self::from_file(path);
            }
        }
        Err(Error::invalid_message(format!(
            "netem: no distribution table `{file}` (is iproute2 installed? set TC_LIB_DIR to \
             where its .dist files are)"
        )))
    }

    /// A table from an iproute2 `.dist` file: whitespace-separated integers,
    /// `#` comments.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(Error::from)?;
        let mut table = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            for word in line.split_whitespace() {
                let v: i16 = word.parse().map_err(|_| {
                    Error::invalid_message(format!(
                        "netem: {}: `{word}` is not a table entry",
                        path.display()
                    ))
                })?;
                table.push(v);
            }
        }
        Self::from_table(table)
    }

    /// A table of your own: entries scaled by `NETEM_DIST_SCALE` (8192),
    /// at most [`MAX_LEN`](Self::MAX_LEN).
    pub fn from_table(table: Vec<i16>) -> Result<Self> {
        if table.is_empty() || table.len() > Self::MAX_LEN {
            return Err(Error::invalid_message(format!(
                "netem: a distribution table has 1 to {} entries, not {}",
                Self::MAX_LEN,
                table.len()
            )));
        }
        Ok(Self { table })
    }

    /// The entries.
    pub fn table(&self) -> &[i16] {
        &self.table
    }
}

impl NetemConfig {
    /// Create a new netem configuration builder.
    pub fn new() -> Self {
        Self {
            limit: crate::util::Packets::new(1000), // Default limit
            ..Default::default()
        }
    }

    /// Set the added delay.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Set the delay jitter (variation).
    pub fn jitter(mut self, jitter: Duration) -> Self {
        self.jitter = Some(jitter);
        self
    }

    /// Set the delay correlation.
    pub fn delay_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.delay_correlation = corr;
        self
    }

    /// Set the packet loss percentage.
    pub fn loss(mut self, percent: crate::util::Percent) -> Self {
        self.loss = percent;
        self
    }

    /// Set the loss correlation (`loss <p>% <corr>%`).
    ///
    /// **This does not produce bursty loss; it lowers the loss rate.**
    /// netem's correlation is not a statistical correlation (`tc-netem(8)`
    /// calls it "an approximation"): each random draw is averaged with the
    /// previous one, `value = (1 - corr)·rand + corr·last`, and a packet is
    /// lost when that value falls below the loss probability. Averaging pulls
    /// the value towards the middle of its range, so a small probability
    /// almost never triggers. Effective loss, simulated from the formula (#369):
    ///
    /// | `loss` | corr 0 % | 10 % | 25 % | 50 % |
    /// |---|---|---|---|---|
    /// | 0.5 % | 0.50 % | **0.00 %** | 0.00 % | 0.00 % |
    /// | 2 % | 2.00 % | 0.14 % | 0.01 % | 0.00 % |
    /// | 10 % | 9.99 % | 5.58 % | 1.77 % | 0.10 % |
    ///
    /// Measured on Linux 6.12 with plain `tc`, `loss 0.5% 25%` dropped 0 of
    /// 40 000 paced packets where `loss 0.5%` dropped 0.48 %. For loss that
    /// arrives in bursts, use a Markov model:
    /// [`loss_model`](Self::loss_model).
    ///
    /// The duplicate, corrupt and reorder correlations use the same
    /// generator, with the same effect on small probabilities.
    pub fn loss_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.loss_correlation = corr;
        self
    }

    /// Use a Markov loss model instead of random loss: Gilbert-Elliot
    /// (`loss gemodel …`) or the 4-state Gilbert-Intuitive model
    /// (`loss state …`). These are netem's generators for **bursty** loss;
    /// see [`NetemLossModel`].
    ///
    /// Exclusive with [`loss`](Self::loss) and
    /// [`loss_correlation`](Self::loss_correlation): the kernel would
    /// accept both and silently ignore the random-loss values, so
    /// installing a config that sets both is an error.
    pub fn loss_model(mut self, model: NetemLossModel) -> Self {
        self.loss_model = Some(model);
        self
    }

    /// Mark packets with ECN instead of dropping them where `loss` would.
    /// See [`ecn`](Self::ecn).
    pub fn ecn(mut self, on: bool) -> Self {
        self.ecn = on;
        self
    }

    /// Release packets in slots. See [`NetemSlot`].
    pub fn slot(mut self, slot: NetemSlot) -> Self {
        self.slot = Some(slot);
        self
    }

    /// Seed netem's random numbers, for runs that drop the same packets.
    /// See [`seed`](Self::seed).
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Draw the jitter from this distribution. It needs a delay and a
    /// jitter. See [`NetemDistribution`].
    pub fn distribution(mut self, distribution: NetemDistribution) -> Self {
        self.distribution = Some(distribution);
        self
    }

    /// The link-layer overhead the rate accounts for: bytes per packet,
    /// and a cell size and per-cell overhead (0 for none), as tc(8)'s
    /// `rate R PACKETOVERHEAD CELLSIZE CELLOVERHEAD`.
    pub fn rate_overhead(
        mut self,
        packet_overhead: i32,
        cell_size: u32,
        cell_overhead: i32,
    ) -> Self {
        self.rate_packet_overhead = packet_overhead;
        self.rate_cell_size = cell_size;
        self.rate_cell_overhead = cell_overhead;
        self
    }

    /// Set the packet duplication percentage.
    pub fn duplicate(mut self, percent: crate::util::Percent) -> Self {
        self.duplicate = percent;
        self
    }

    /// Set the duplication correlation. Like
    /// [`loss_correlation`](Self::loss_correlation), it lowers a small
    /// probability rather than grouping events.
    pub fn duplicate_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.duplicate_correlation = corr;
        self
    }

    /// Set the packet corruption percentage.
    pub fn corrupt(mut self, percent: crate::util::Percent) -> Self {
        self.corrupt = percent;
        self
    }

    /// Set the corruption correlation. Like
    /// [`loss_correlation`](Self::loss_correlation), it lowers a small
    /// probability rather than grouping events.
    pub fn corrupt_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.corrupt_correlation = corr;
        self
    }

    /// Set the packet reordering percentage.
    ///
    /// Note: Reordering requires delay to be set.
    pub fn reorder(mut self, percent: crate::util::Percent) -> Self {
        self.reorder = percent;
        self
    }

    /// Set the reordering correlation. Like
    /// [`loss_correlation`](Self::loss_correlation), it lowers a small
    /// probability rather than grouping events.
    pub fn reorder_correlation(mut self, corr: crate::util::Percent) -> Self {
        self.reorder_correlation = corr;
        self
    }

    /// Set the reorder gap.
    pub fn gap(mut self, gap: u32) -> Self {
        self.gap = gap;
        self
    }

    /// Set the rate limit.
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = packets;
        self
    }

    /// Build the configuration (returns self, for API consistency).
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style params slice into a typed `NetemConfig`.
    ///
    /// Recognised tokens (positional optionals are consumed greedily
    /// up to the next keyword):
    ///
    /// - `delay <time> [<jitter> [<corr>]]` (alias `latency`)
    /// - `loss [random] <pct> [<corr>]` (alias `drop`) — the correlation
    ///   lowers the loss rate; see [`loss_correlation`](Self::loss_correlation)
    /// - `loss state <p13> [<p31> [<p32> [<p23> [<p14>]]]]` and
    ///   `loss gemodel <p> [<r> [<1-h> [<1-k>]]]` (alias `drop`), with
    ///   `tc(8)`'s defaults for the omitted values — see
    ///   [`NetemLossModel`]
    /// - `duplicate <pct> [<corr>]`
    /// - `corrupt <pct> [<corr>]`
    /// - `reorder <pct> [<corr>]`
    /// - `gap <n>`
    /// - `rate <rate> [<packet_overhead> [<cell_size> [<cell_overhead>]]]`
    /// - `limit <packets>`
    /// - `ecn`
    /// - `slot <min> [<max>] [packets <n>] [bytes <n>]`
    /// - `distribution <name>` — an iproute2 table, see
    ///   [`NetemDistribution::named`]
    /// - `seed <n>`
    ///
    /// **Not modelled** (returns `Error::invalid_message`): `slot
    /// distribution …`, a slot whose spacing is drawn from a table.
    ///
    /// Strict: unknown keywords, missing values, and unparseable
    /// time/rate/percent/integer values all return an error rather
    /// than silently being skipped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::NetemConfig;
    /// # use std::time::Duration;
    /// let cfg = NetemConfig::parse_params(&[
    ///     "delay", "100ms", "10ms",
    ///     "loss", "1%",
    ///     "limit", "5000",
    /// ])?;
    /// assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "delay" | "latency" => {
                    let time_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message(format!("netem: `{key}` requires a value"))
                    })?;
                    cfg.delay = Some(crate::util::parse::get_time(time_str).map_err(|_| {
                        Error::invalid_message(format!(
                            "netem: invalid {key} `{time_str}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                    if let Some(j) = params.get(i)
                        && !is_netem_keyword(j)
                    {
                        cfg.jitter = Some(crate::util::parse::get_time(j).map_err(|_| {
                            Error::invalid_message(format!(
                                "netem: invalid jitter `{j}` (expected tc-style time)"
                            ))
                        })?);
                        i += 1;
                        if let Some(c) = params.get(i)
                            && !is_netem_keyword(c)
                        {
                            cfg.delay_correlation = parse_netem_percent(c, "delay correlation")?;
                            i += 1;
                        }
                    }
                }
                "loss" | "drop" => {
                    i += 1;
                    // Optional `random` qualifier on `loss`.
                    let random = key == "loss" && params.get(i) == Some(&"random");
                    if random {
                        i += 1;
                    }
                    // The Markov models: positional percents, greedy up
                    // to the next keyword, tc(8)'s defaults for the rest.
                    if let Some(model) = params.get(i).copied()
                        && (model == "state" || model == "gemodel")
                    {
                        if random {
                            return Err(Error::invalid_message(format!(
                                "netem: `loss random {model}` mixes two loss generators; use `loss {model} …`"
                            )));
                        }
                        i += 1;
                        let mut values = Vec::new();
                        while let Some(v) = params.get(i)
                            && !is_netem_keyword(v)
                        {
                            values.push(parse_netem_percent(v, &format!("loss {model} value"))?);
                            i += 1;
                        }
                        cfg.loss_model = Some(netem_loss_model(model, &values)?);
                        continue;
                    }
                    let pct_str = params.get(i).copied().ok_or_else(|| {
                        Error::invalid_message(format!("netem: `{key}` requires a percent value"))
                    })?;
                    cfg.loss = parse_netem_percent(pct_str, key)?;
                    i += 1;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.loss_correlation = parse_netem_percent(c, "loss correlation")?;
                        i += 1;
                    }
                }
                "duplicate" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `duplicate` requires a percent value")
                    })?;
                    cfg.duplicate = parse_netem_percent(pct_str, "duplicate")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.duplicate_correlation =
                            parse_netem_percent(c, "duplicate correlation")?;
                        i += 1;
                    }
                }
                "corrupt" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `corrupt` requires a percent value")
                    })?;
                    cfg.corrupt = parse_netem_percent(pct_str, "corrupt")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.corrupt_correlation = parse_netem_percent(c, "corrupt correlation")?;
                        i += 1;
                    }
                }
                "reorder" => {
                    let pct_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `reorder` requires a percent value")
                    })?;
                    cfg.reorder = parse_netem_percent(pct_str, "reorder")?;
                    i += 2;
                    if let Some(c) = params.get(i)
                        && !is_netem_keyword(c)
                    {
                        cfg.reorder_correlation = parse_netem_percent(c, "reorder correlation")?;
                        i += 1;
                    }
                }
                "gap" => {
                    let n_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `gap` requires a value")
                    })?;
                    cfg.gap = n_str.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "netem: invalid gap `{n_str}` (expected unsigned integer)"
                        ))
                    })?;
                    i += 2;
                }
                "rate" => {
                    let rate_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `rate` requires a value")
                    })?;
                    cfg.rate = Some(crate::util::Rate::parse(rate_str).map_err(|_| {
                        Error::invalid_message(format!(
                            "netem: invalid rate `{rate_str}` (expected tc-style rate like `100mbit`)"
                        ))
                    })?);
                    i += 2;
                    // Positional packet_overhead, cell_size, cell_overhead.
                    let mut extras = 0;
                    while let Some(v) = params.get(i).copied()
                        && !is_netem_keyword(v)
                    {
                        let bad = |what: &str| {
                            Error::invalid_message(format!(
                                "netem: invalid rate {what} `{v}` (expected integer)"
                            ))
                        };
                        match extras {
                            0 => {
                                cfg.rate_packet_overhead =
                                    v.parse().map_err(|_| bad("packet overhead"))?
                            }
                            1 => cfg.rate_cell_size = v.parse().map_err(|_| bad("cell size"))?,
                            2 => {
                                cfg.rate_cell_overhead =
                                    v.parse().map_err(|_| bad("cell overhead"))?
                            }
                            _ => {
                                return Err(Error::invalid_message(format!(
                                    "netem: `rate` takes <rate> [<packet_overhead> [<cell_size> [<cell_overhead>]]], got an extra `{v}`"
                                )));
                            }
                        }
                        extras += 1;
                        i += 1;
                    }
                }
                "limit" => {
                    let n_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `limit` requires a value")
                    })?;
                    cfg.limit = n_str.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "netem: invalid limit `{n_str}` (expected unsigned integer)"
                        ))
                    })?;
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "seed" => {
                    let n_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `seed` requires a value")
                    })?;
                    cfg.seed = Some(n_str.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "netem: invalid seed `{n_str}` (expected unsigned 64-bit integer)"
                        ))
                    })?);
                    i += 2;
                }
                "distribution" => {
                    let name = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `distribution` requires a table name")
                    })?;
                    cfg.distribution = Some(NetemDistribution::named(name)?);
                    i += 2;
                }
                "slot" => {
                    let time = |what: &str, v: &str| {
                        crate::util::parse::get_time(v).map_err(|_| {
                            Error::invalid_message(format!(
                                "netem: invalid slot {what} `{v}` (expected tc-style time)"
                            ))
                        })
                    };
                    let min_str = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("netem: `slot` requires a minimum delay")
                    })?;
                    if min_str == "distribution" {
                        return Err(Error::invalid_message(
                            "netem: `slot distribution …` is not modelled by NetemConfig; use `slot <min> <max>` (NetemSlot::new)",
                        ));
                    }
                    let min = time("minimum delay", min_str)?;
                    i += 2;
                    let mut max = min;
                    if let Some(v) = params.get(i).copied()
                        && !is_netem_keyword(v)
                        && v != "packets"
                        && v != "bytes"
                    {
                        max = time("maximum delay", v)?;
                        i += 1;
                    }
                    let mut slot = NetemSlot::new(min, max);
                    while let Some(sub) = params.get(i).copied()
                        && (sub == "packets" || sub == "bytes")
                    {
                        let n_str = params.get(i + 1).copied().ok_or_else(|| {
                            Error::invalid_message(format!("netem: slot `{sub}` requires a value"))
                        })?;
                        let n: u32 = n_str.parse().map_err(|_| {
                            Error::invalid_message(format!(
                                "netem: invalid slot {sub} `{n_str}` (expected unsigned integer)"
                            ))
                        })?;
                        slot = if sub == "packets" {
                            slot.packets(crate::util::Packets::new(n))
                        } else {
                            slot.bytes(n)
                        };
                        i += 2;
                    }
                    cfg.slot = Some(slot);
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "netem: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl From<&super::tc_options::NetemOptions> for NetemConfig {
    /// The netem the kernel reports, as a config that installs it again
    /// (#515): read a qdisc, change one thing, apply it.
    ///
    /// Two things the kernel holds cannot come back. A delay distribution
    /// table is never reported, so the config has none — installing it
    /// replaces the qdisc's jitter shape with the uniform one — and a slot
    /// drawn from a table (`slot distribution …`, which nlink does not
    /// write) becomes no slot. The seed is kept, so the config draws the
    /// same random numbers; a kernel before 6.3 reports none.
    fn from(o: &super::tc_options::NetemOptions) -> Self {
        use crate::util::{Percent, Rate};
        let nanos = |ns: i64| Duration::from_nanos(u64::try_from(ns).unwrap_or(0));
        let limit = |n: i32| (n > 0 && n != i32::MAX).then(|| n.unsigned_abs());
        let mut cfg = Self::new();
        cfg.delay = (o.delay_ns > 0).then(|| Duration::from_nanos(o.delay_ns));
        cfg.jitter = (o.jitter_ns > 0).then(|| Duration::from_nanos(o.jitter_ns));
        cfg.delay_correlation = Percent::new(o.delay_corr);
        // The kernel ignores random loss under a model, and `write_options`
        // refuses the two together.
        if o.loss_model.is_none() {
            cfg.loss = Percent::new(o.loss_percent);
            cfg.loss_correlation = Percent::new(o.loss_corr);
        }
        cfg.loss_model = o.loss_model;
        cfg.duplicate = Percent::new(o.duplicate_percent);
        cfg.duplicate_correlation = Percent::new(o.duplicate_corr);
        cfg.corrupt = Percent::new(o.corrupt_percent);
        cfg.corrupt_correlation = Percent::new(o.corrupt_corr);
        cfg.reorder = Percent::new(o.reorder_percent);
        cfg.reorder_correlation = Percent::new(o.reorder_corr);
        cfg.gap = o.gap;
        cfg.rate = (o.rate > 0).then(|| Rate::bytes_per_sec(o.rate));
        cfg.rate_packet_overhead = o.packet_overhead;
        cfg.rate_cell_size = o.cell_size;
        cfg.rate_cell_overhead = o.cell_overhead;
        cfg.limit = crate::util::Packets::new(o.limit);
        cfg.ecn = o.ecn;
        cfg.slot = o
            .slot
            .as_ref()
            .filter(|s| s.dist_delay_ns == 0 && s.dist_jitter_ns == 0)
            .map(|s| NetemSlot {
                min_delay: nanos(s.min_delay_ns),
                max_delay: nanos(s.max_delay_ns),
                max_packets: limit(s.max_packets).map(crate::util::Packets::new),
                max_bytes: limit(s.max_bytes),
            });
        cfg.seed = o.seed;
        cfg
    }
}

/// Tokens that begin a new netem option group — used by
/// `NetemConfig::parse_params` to decide where greedy positional
/// optionals (jitter / correlation) end.
fn is_netem_keyword(s: &str) -> bool {
    matches!(
        s,
        "delay"
            | "latency"
            | "loss"
            | "drop"
            | "duplicate"
            | "corrupt"
            | "reorder"
            | "gap"
            | "rate"
            | "limit"
            | "slot"
            | "ecn"
            | "distribution"
            | "seed"
            | "random"
    )
}

/// Build a `loss state …` / `loss gemodel …` model from its positional
/// values, in `tc(8)`'s order, defaulting the omitted ones as iproute2
/// does.
fn netem_loss_model(model: &str, v: &[crate::util::Percent]) -> Result<NetemLossModel> {
    let (max, args) = if model == "state" {
        (5, "<p13> [<p31> [<p32> [<p23> [<p14>]]]]")
    } else {
        (4, "<p> [<r> [<1-h> [<1-k>]]]")
    };
    if v.is_empty() || v.len() > max {
        return Err(Error::invalid_message(format!(
            "netem: `loss {model}` takes {args}, got {} value(s)",
            v.len()
        )));
    }
    Ok(if model == "state" {
        let mut m = NetemLossModel::gilbert_intuitive(v[0]);
        // tc's order is p13 p31 p32 p23 p14 — not the struct's.
        for (j, p) in v.iter().enumerate().skip(1) {
            m = match j {
                1 => m.p31(*p),
                2 => m.p32(*p),
                3 => m.p23(*p),
                _ => m.p14(*p),
            };
        }
        m
    } else {
        let mut m = NetemLossModel::gilbert_elliot(v[0]);
        for (j, p) in v.iter().enumerate().skip(1) {
            m = match j {
                1 => m.r(*p),
                2 => m.loss_in_bad(*p),
                _ => m.loss_in_good(*p),
            };
        }
        m
    })
}

/// Parse a netem percent value (`"1.5"`, `"1.5%"`) with a context
/// label folded into the error so the user knows which field failed.
fn parse_netem_percent(s: &str, label: &str) -> Result<crate::util::Percent> {
    s.parse::<crate::util::Percent>()
        .map_err(|_| Error::invalid_message(format!("netem: invalid {label} `{s}`")))
}

impl QdiscConfig for NetemConfig {
    fn kind(&self) -> &'static str {
        "netem"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Validate: reorder requires delay
        if !self.reorder.is_zero() && self.delay.is_none() {
            return Err(Error::invalid_message(
                "netem: reorder requires delay to be set",
            ));
        }
        // A distribution shapes the jitter, which netem only adds to a
        // delay; tc(8) refuses one without both.
        if self.distribution.is_some()
            && (self.delay.is_none() || self.jitter.is_none_or(|j| j.is_zero()))
        {
            return Err(Error::invalid_message(
                "netem: a distribution needs a delay and a jitter to shape",
            ));
        }
        if let Some(slot) = &self.slot
            && slot.min_delay > slot.max_delay
        {
            return Err(Error::invalid_message(format!(
                "netem: slot min_delay {:?} is above its max_delay {:?}",
                slot.min_delay, slot.max_delay
            )));
        }
        // A loss model replaces random loss in the kernel, which would
        // accept `loss` / its correlation alongside one and ignore them.
        if self.loss_model.is_some()
            && (!self.loss.is_zero() || !self.loss_correlation.is_zero())
        {
            return Err(Error::invalid_message(
                "netem: a loss model (`loss state`/`loss gemodel`) excludes random `loss` and its correlation",
            ));
        }

        // Build TcNetemQopt
        let mut qopt = TcNetemQopt::new();
        qopt.limit = self.limit.as_u32();

        // `latency`/`jitter` are psched ticks (64 ns), not µs (#493). The
        // LATENCY64/JITTER64 attributes below override them on 4.15+; a
        // kernel without those read µs as ticks, 15.6 times too short.
        let ticks = |d: Duration| {
            u32::try_from(d.as_nanos() >> super::psched::PSCHED_SHIFT).unwrap_or(u32::MAX)
        };
        if let Some(delay) = self.delay {
            qopt.latency = ticks(delay);
        }
        if let Some(jitter) = self.jitter {
            qopt.jitter = ticks(jitter);
        }
        if !self.loss.is_zero() {
            qopt.loss = self.loss.as_kernel_probability();
        }
        if !self.duplicate.is_zero() {
            qopt.duplicate = self.duplicate.as_kernel_probability();
        }
        if !self.reorder.is_zero() && self.gap == 0 {
            qopt.gap = 1; // Default gap if reorder is set
        } else {
            qopt.gap = self.gap;
        }

        // Write the base options
        builder.append(&qopt);

        // Add 64-bit latency for precision (nanoseconds)
        if let Some(delay) = self.delay {
            let latency_ns = delay.as_nanos() as i64;
            builder.append_attr(TCA_NETEM_LATENCY64, &latency_ns.to_ne_bytes());
        }

        // Add 64-bit jitter for precision (nanoseconds)
        if let Some(jitter) = self.jitter {
            let jitter_ns = jitter.as_nanos() as i64;
            builder.append_attr(TCA_NETEM_JITTER64, &jitter_ns.to_ne_bytes());
        }

        // CORR, REORDER, CORRUPT and RATE are written even when unset, as
        // zeros — the kernel's "off" for each. A replace of an existing
        // netem is `netem_change()`, which updates only the attributes it is
        // sent: omit one and the old value survives, so a declaration that
        // drops `rate`, `reorder` or `corrupt` could never converge, and
        // `apply()` replaced it on every run (#370). `tc_netem_qopt` above
        // is always sent, which is why latency, loss, duplicate, gap and
        // limit never had this problem; a loss model is reset by the kernel
        // itself when `TCA_NETEM_LOSS` is absent.
        let corr = TcNetemCorr {
            delay_corr: self.delay_correlation.as_kernel_probability(),
            loss_corr: self.loss_correlation.as_kernel_probability(),
            dup_corr: self.duplicate_correlation.as_kernel_probability(),
        };
        builder.append_attr(TCA_NETEM_CORR, corr.as_bytes());

        let reorder = TcNetemReorder {
            probability: self.reorder.as_kernel_probability(),
            correlation: self.reorder_correlation.as_kernel_probability(),
        };
        builder.append_attr(TCA_NETEM_REORDER, reorder.as_bytes());

        let corrupt = TcNetemCorrupt {
            probability: self.corrupt.as_kernel_probability(),
            correlation: self.corrupt_correlation.as_kernel_probability(),
        };
        builder.append_attr(TCA_NETEM_CORRUPT, corrupt.as_bytes());

        // Rate: 0 is "no rate limit". RATE64 only when the rate needs it;
        // the kernel assigns `q->rate` from TCA_NETEM_RATE first, so a stale
        // 64-bit rate cannot survive a replace that omits RATE64.
        let bytes_per_sec = self.rate.map_or(0, |r| r.as_bytes_per_sec());
        let mut rate_struct = TcNetemRate {
            packet_overhead: self.rate_packet_overhead,
            cell_size: self.rate_cell_size,
            cell_overhead: self.rate_cell_overhead,
            ..TcNetemRate::default()
        };
        if bytes_per_sec > u32::MAX as u64 {
            rate_struct.rate = u32::MAX;
            builder.append_attr(TCA_NETEM_RATE, rate_struct.as_bytes());
            builder.append_attr(TCA_NETEM_RATE64, &bytes_per_sec.to_ne_bytes());
        } else {
            rate_struct.rate = bytes_per_sec as u32;
            builder.append_attr(TCA_NETEM_RATE, rate_struct.as_bytes());
        }

        // Markov loss model, nested TCA_NETEM_LOSS
        if let Some(model) = &self.loss_model {
            model.write_attr(builder);
        }

        // ECN and the slot are always sent, off when unset: a replace is
        // `netem_change()`, which keeps both when they are not sent, so one
        // set outside nlink (`tc … ecn`, `slot 1ms 2ms`) would otherwise
        // survive every replace, unseen (#493). A zero slot is the kernel's
        // "no slot" (`get_slot` clears `slot_next`), and a zero packet or
        // byte limit its "unlimited".
        builder.append_attr_u32(TCA_NETEM_ECN, u32::from(self.ecn));
        let slot = self
            .slot
            .map_or_else(TcNetemSlot::default, |s| TcNetemSlot {
                min_delay: i64::try_from(s.min_delay.as_nanos()).unwrap_or(i64::MAX),
                max_delay: i64::try_from(s.max_delay.as_nanos()).unwrap_or(i64::MAX),
                max_packets: s
                    .max_packets
                    .map_or(0, |n| i32::try_from(n.as_u32()).unwrap_or(i32::MAX)),
                max_bytes: s
                    .max_bytes
                    .map_or(0, |n| i32::try_from(n).unwrap_or(i32::MAX)),
                ..TcNetemSlot::default()
            });
        builder.append_attr(TCA_NETEM_SLOT, slot.as_bytes());
        // The seed is sent only when set: the kernel picks a random one
        // otherwise, and keeps the old one across a change (Linux 6.3+;
        // older kernels ignore the attribute).
        if let Some(seed) = self.seed {
            builder.append_attr(TCA_NETEM_PRNG_SEED, &seed.to_ne_bytes());
        }
        // The delay distribution table cannot be cleared by a change —
        // `netem_change` keeps it, and `netem_dump` never shows it — so it
        // is sent when set, and only a delete and add removes one.
        if let Some(dist) = &self.distribution {
            let bytes: Vec<u8> = dist.table().iter().flat_map(|v| v.to_ne_bytes()).collect();
            builder.append_attr(TCA_NETEM_DELAY_DIST, &bytes);
        }

        Ok(())
    }
}

// ============================================================================
// FqCodelConfig
// ============================================================================

/// Fair Queue CoDel (fq_codel) qdisc configuration.
///
/// FQ-CoDel combines fair queuing with the CoDel AQM algorithm to provide
/// good latency under load while maintaining fairness between flows.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::FqCodelConfig;
/// use nlink::Packets;
/// use std::time::Duration;
///
/// let config = FqCodelConfig::new()
///     .target(Duration::from_millis(5))
///     .interval(Duration::from_millis(100))
///     .limit(Packets::new(10000))
///     .flows(1024)
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct FqCodelConfig {
    /// Target delay.
    pub target: Option<Duration>,
    /// Interval for CoDel algorithm.
    pub interval: Option<Duration>,
    /// Queue limit in packets.
    pub limit: Option<crate::util::Packets>,
    /// Number of flows.
    pub flows: Option<u32>,
    /// Quantum (bytes per round).
    pub quantum: Option<u32>,
    /// ECN marking: `Some(true)` marks, `Some(false)` drops, `None` sends
    /// nothing. The kernel turns ECN **on** when it creates an fq_codel and
    /// keeps whatever it has when a change does not carry the attribute, so
    /// turning it off has to be said (#488).
    pub ecn: Option<bool>,
    /// CE threshold.
    pub ce_threshold: Option<Duration>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u32>,
    /// The most packets dropped at once when the queue is full; the
    /// kernel's is 64. tc(8) `drop_batch` (#806).
    pub drop_batch: Option<u32>,
    /// Which packets the CE threshold applies to: those whose DS field
    /// (the TOS byte), masked with the second, equals the first. tc(8)
    /// `ce_threshold_selector V/M` (#806).
    pub ce_threshold_selector: Option<(u8, u8)>,
}

impl Default for FqCodelConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FqCodelConfig {
    /// Create a new fq_codel configuration builder.
    pub fn new() -> Self {
        Self {
            target: None,
            interval: None,
            limit: None,
            flows: None,
            quantum: None,
            ecn: None,
            ce_threshold: None,
            memory_limit: None,
            drop_batch: None,
            ce_threshold_selector: None,
        }
    }

    /// Set the most packets dropped at once when the queue is full
    /// (#806).
    pub fn drop_batch(mut self, packets: u32) -> Self {
        self.drop_batch = Some(packets);
        self
    }

    /// Apply the CE threshold to the packets whose DS field, masked with
    /// `mask`, equals `value` (#806).
    pub fn ce_threshold_selector(mut self, value: u8, mask: u8) -> Self {
        self.ce_threshold_selector = Some((value, mask));
        self
    }

    /// Set the target delay (default: 5ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the interval (default: 100ms).
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the number of flows.
    pub fn flows(mut self, flows: u32) -> Self {
        self.flows = Some(flows);
        self
    }

    /// Set the quantum (bytes per round).
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Enable or disable ECN marking. The kernel's default is on.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = Some(enable);
        self
    }

    /// Set the CE threshold for ECN marking.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Set the memory limit in bytes.
    pub fn memory_limit(mut self, bytes: crate::util::Bytes) -> Self {
        self.memory_limit = Some(bytes.as_u32_saturating());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fq_codel params slice into a typed
    /// `FqCodelConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <packets>` — hard limit on queue size.
    /// - `target <time>` — target delay (e.g. `5ms`).
    /// - `interval <time>` — moving-time-window width (e.g. `100ms`).
    /// - `flows <n>` — number of flows.
    /// - `quantum <bytes>` — bytes served per round.
    /// - `ce_threshold <time>` — ECN CE marking threshold.
    /// - `memory_limit <bytes>` — memory limit (tc-style size).
    /// - `ecn` / `noecn` — flag tokens, no value.
    ///
    /// Stricter than the legacy parser: unknown tokens, missing
    /// values, and unparseable time/size/integer values all return
    /// `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("fq_codel: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("fq_codel: invalid limit `{s}`"))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "interval" => {
                    let s = need_value()?;
                    cfg.interval = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid interval `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "flows" => {
                    let s = need_value()?;
                    cfg.flows = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("fq_codel: invalid flows `{s}`"))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let s = need_value()?;
                    cfg.quantum = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid quantum `{s}` (expected unsigned integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "ce_threshold" => {
                    let s = need_value()?;
                    cfg.ce_threshold = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid ce_threshold `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "memory_limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid memory_limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("fq_codel: memory_limit `{s}` exceeds u32"))
                    })?);
                    i += 2;
                }
                "drop_batch" => {
                    let s = need_value()?;
                    cfg.drop_batch = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_codel: invalid drop_batch `{s}` (expected unsigned integer packets)"
                        ))
                    })?);
                    i += 2;
                }
                "ce_threshold_selector" => {
                    let s = need_value()?;
                    let byte = |v: &str| {
                        match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                            Some(hex) => u8::from_str_radix(hex, 16),
                            None => v.parse(),
                        }
                        .ok()
                    };
                    let (value, mask) = s
                        .split_once('/')
                        .and_then(|(v, m)| Some((byte(v)?, byte(m)?)))
                        .ok_or_else(|| {
                            Error::invalid_message(format!(
                                "fq_codel: invalid ce_threshold_selector `{s}` (expected VALUE/MASK, bytes)"
                            ))
                        })?;
                    cfg.ce_threshold_selector = Some((value, mask));
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = Some(true);
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = Some(false);
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "fq_codel: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for FqCodelConfig {
    fn kind(&self) -> &'static str {
        "fq_codel"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        self.write_fq_codel(builder, true)
    }

    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        self.write_fq_codel(builder, false)
    }

    /// `flows` sizes the flow table, which only `fq_codel_init` allocates:
    /// a different value needs a new qdisc.
    fn in_place(&self, live: &TcMessage) -> InPlace {
        let live_flows = match live.options() {
            Some(crate::netlink::tc_options::QdiscOptions::FqCodel(o)) => Some(o.flows),
            _ => None,
        };
        match self.flows {
            Some(want) if live_flows != Some(want) => InPlace::Recreate,
            _ => InPlace::Change,
        }
    }
}

impl FqCodelConfig {
    /// `with_flows`: `false` for a change to a live fq_codel, whose
    /// `fq_codel_change` refuses `TCA_FQ_CODEL_FLOWS` outright, even with
    /// the live value (#361, #486).
    fn write_fq_codel(&self, builder: &mut MessageBuilder, with_flows: bool) -> Result<()> {
        if let Some(target) = self.target {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_TARGET, target.as_micros() as u32);
        }
        if let Some(interval) = self.interval {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_INTERVAL, interval.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_LIMIT, limit.as_u32());
        }
        if let Some(flows) = self.flows
            && with_flows
        {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_FLOWS, flows);
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_QUANTUM, quantum);
        }
        if let Some(ecn) = self.ecn {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_ECN, u32::from(ecn));
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
        }
        if let Some(mem) = self.memory_limit {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_MEMORY_LIMIT, mem);
        }
        if let Some(batch) = self.drop_batch {
            builder.append_attr_u32(fq_codel::TCA_FQ_CODEL_DROP_BATCH_SIZE, batch);
        }
        // The kernel takes the selector only with its mask.
        if let Some((value, mask)) = self.ce_threshold_selector {
            builder.append_attr_u8(fq_codel::TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR, value);
            builder.append_attr_u8(fq_codel::TCA_FQ_CODEL_CE_THRESHOLD_MASK, mask);
        }
        Ok(())
    }
}

// ============================================================================
// CodelConfig
// ============================================================================

/// Controlled Delay (codel) qdisc configuration.
///
/// Plain CoDel — a single-queue AQM. For per-flow fairness use
/// [`FqCodelConfig`] instead.
///
/// ```no_run
/// use nlink::netlink::tc::CodelConfig;
/// use std::time::Duration;
///
/// let cfg = CodelConfig::new()
///     .target(Duration::from_millis(5))
///     .interval(Duration::from_millis(100))
///     .ecn(true)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CodelConfig {
    /// Target queue delay.
    pub target: Option<Duration>,
    /// Sliding-window interval.
    pub interval: Option<Duration>,
    /// Hard queue limit in packets.
    pub limit: Option<crate::util::Packets>,
    /// ECN marking instead of dropping (`Some(false)` = explicit noecn).
    pub ecn: Option<bool>,
    /// CE threshold for ECN marking.
    pub ce_threshold: Option<Duration>,
}

impl CodelConfig {
    /// Create a new codel configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target queue delay (default: 5ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the sliding-window interval (default: 100ms).
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Set the hard queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = Some(enable);
        self
    }

    /// Set the CE threshold for ECN marking.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style codel params slice.
    ///
    /// Recognised tokens: `limit <packets>`, `target <time>`,
    /// `interval <time>`, `ce_threshold <time>`, `ecn`/`noecn`.
    /// Strict: unknown tokens, missing values, and unparseable
    /// values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("codel: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("codel: invalid limit `{s}`"))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "codel: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "interval" => {
                    let s = need_value()?;
                    cfg.interval = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "codel: invalid interval `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "ce_threshold" => {
                    let s = need_value()?;
                    cfg.ce_threshold = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "codel: invalid ce_threshold `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = Some(true);
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = Some(false);
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!("codel: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CodelConfig {
    fn kind(&self) -> &'static str {
        "codel"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(target) = self.target {
            builder.append_attr_u32(codel::TCA_CODEL_TARGET, target.as_micros() as u32);
        }
        if let Some(interval) = self.interval {
            builder.append_attr_u32(codel::TCA_CODEL_INTERVAL, interval.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(codel::TCA_CODEL_LIMIT, limit.as_u32());
        }
        if let Some(ecn) = self.ecn {
            builder.append_attr_u32(codel::TCA_CODEL_ECN, u32::from(ecn));
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(codel::TCA_CODEL_CE_THRESHOLD, ce.as_micros() as u32);
        }
        Ok(())
    }
}

// ============================================================================
// FqConfig
// ============================================================================

/// Fair Queue (fq) qdisc configuration — the pacing-aware scheduler
/// used with BBR. Distinct from [`FqCodelConfig`] (which is an AQM).
///
/// ```no_run
/// use nlink::netlink::tc::FqConfig;
/// use nlink::Packets;
/// use nlink::Rate;
///
/// let cfg = FqConfig::new()
///     .limit(Packets::new(10_000))
///     .flow_limit(Packets::new(100))
///     .maxrate(Rate::mbit(100))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct FqConfig {
    /// Total packet limit across the queue.
    pub limit: Option<crate::util::Packets>,
    /// Per-flow packet limit.
    pub flow_limit: Option<crate::util::Packets>,
    /// Round-robin quantum in bytes.
    pub quantum: Option<u32>,
    /// Initial quantum for a new flow, in bytes.
    pub initial_quantum: Option<u32>,
    /// Per-flow maximum rate.
    pub maxrate: Option<crate::util::Rate>,
    /// Low-rate threshold below which flows are not throttled.
    pub low_rate_threshold: Option<crate::util::Rate>,
    /// Flow credit refill delay.
    pub refill_delay: Option<Duration>,
    /// Mask applied to the orphaned-skb hash.
    pub orphan_mask: Option<u32>,
    /// ECN CE marking threshold.
    pub ce_threshold: Option<Duration>,
    /// Enable/disable pacing (`Some(false)` = explicit nopacing).
    pub pacing: Option<bool>,
    /// The flow table's size in buckets; the kernel takes its log2, rounded
    /// up, as tc(8) does (#821).
    pub buckets: Option<u32>,
    /// How far ahead of now a packet's departure time may be (#821).
    pub horizon: Option<Duration>,
    /// Beyond the horizon, drop (`Some(true)`, tc's `horizon_drop`) or cap
    /// the time to it (`Some(false)`, `horizon_cap`) (#821).
    pub horizon_drop: Option<bool>,
    /// The pacing timer's slack (#821).
    pub timer_slack: Option<Duration>,
}

impl FqConfig {
    /// Create a new fq configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total packet limit.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the per-flow packet limit.
    pub fn flow_limit(mut self, packets: crate::util::Packets) -> Self {
        self.flow_limit = Some(packets);
        self
    }

    /// Set the round-robin quantum in bytes.
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Set the initial quantum for new flows, in bytes.
    pub fn initial_quantum(mut self, bytes: u32) -> Self {
        self.initial_quantum = Some(bytes);
        self
    }

    /// Set the per-flow maximum rate.
    pub fn maxrate(mut self, rate: crate::util::Rate) -> Self {
        self.maxrate = Some(rate);
        self
    }

    /// Set the low-rate threshold.
    pub fn low_rate_threshold(mut self, rate: crate::util::Rate) -> Self {
        self.low_rate_threshold = Some(rate);
        self
    }

    /// Set the flow credit refill delay.
    pub fn refill_delay(mut self, delay: Duration) -> Self {
        self.refill_delay = Some(delay);
        self
    }

    /// Set the orphan mask.
    pub fn orphan_mask(mut self, mask: u32) -> Self {
        self.orphan_mask = Some(mask);
        self
    }

    /// Set the ECN CE marking threshold.
    pub fn ce_threshold(mut self, threshold: Duration) -> Self {
        self.ce_threshold = Some(threshold);
        self
    }

    /// Enable or disable pacing.
    pub fn pacing(mut self, enable: bool) -> Self {
        self.pacing = Some(enable);
        self
    }

    /// Set the flow table's size in buckets.
    pub fn buckets(mut self, buckets: u32) -> Self {
        self.buckets = Some(buckets);
        self
    }

    /// Set the horizon.
    pub fn horizon(mut self, horizon: Duration) -> Self {
        self.horizon = Some(horizon);
        self
    }

    /// Drop packets beyond the horizon (`true`), or cap their time to it.
    pub fn horizon_drop(mut self, drop: bool) -> Self {
        self.horizon_drop = Some(drop);
        self
    }

    /// Set the pacing timer's slack.
    pub fn timer_slack(mut self, slack: Duration) -> Self {
        self.timer_slack = Some(slack);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fq params slice.
    ///
    /// Recognised tokens: `limit <packets>`, `flow_limit <packets>`,
    /// `quantum <bytes>`, `initial_quantum <bytes>`, `maxrate <rate>`,
    /// `low_rate_threshold <rate>`, `refill_delay <time>`,
    /// `orphan_mask <n>`, `ce_threshold <time>`, `pacing`/`nopacing`,
    /// `buckets <n>`, `horizon <time>`, `horizon_drop`/`horizon_cap`,
    /// `timer_slack <time>` (#821). Strict: unknown tokens, missing values,
    /// and unparseable values all error. `defrate` is refused: the kernel
    /// ignores it; the newer `bands`, `priomap`, `weights` and
    /// `offload_horizon` are not modelled.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("fq: `{key}` requires a value")))
            };
            let parse_u32 = |s: &str, what: &str| {
                s.parse::<u32>().map_err(|_| {
                    Error::invalid_message(format!("fq: invalid {what} `{s}` (expected integer)"))
                })
            };
            let parse_rate = |s: &str, what: &str| {
                crate::util::Rate::parse(s).map_err(|_| {
                    Error::invalid_message(format!("fq: invalid {what} `{s}` (expected tc-style rate)"))
                })
            };
            let parse_time = |s: &str, what: &str| {
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::invalid_message(format!("fq: invalid {what} `{s}` (expected tc-style time)"))
                })
            };
            match key {
                "limit" => {
                    cfg.limit = Some(crate::util::Packets::new(parse_u32(need_value()?, "limit")?));
                    i += 2;
                }
                "flow_limit" => {
                    cfg.flow_limit = Some(crate::util::Packets::new(parse_u32(need_value()?, "flow_limit")?));
                    i += 2;
                }
                "quantum" => {
                    cfg.quantum = Some(parse_u32(need_value()?, "quantum")?);
                    i += 2;
                }
                "initial_quantum" => {
                    cfg.initial_quantum = Some(parse_u32(need_value()?, "initial_quantum")?);
                    i += 2;
                }
                "maxrate" => {
                    cfg.maxrate = Some(parse_rate(need_value()?, "maxrate")?);
                    i += 2;
                }
                "low_rate_threshold" => {
                    cfg.low_rate_threshold = Some(parse_rate(need_value()?, "low_rate_threshold")?);
                    i += 2;
                }
                "refill_delay" => {
                    cfg.refill_delay = Some(parse_time(need_value()?, "refill_delay")?);
                    i += 2;
                }
                "orphan_mask" => {
                    cfg.orphan_mask = Some(parse_u32(need_value()?, "orphan_mask")?);
                    i += 2;
                }
                "ce_threshold" => {
                    cfg.ce_threshold = Some(parse_time(need_value()?, "ce_threshold")?);
                    i += 2;
                }
                "pacing" => {
                    cfg.pacing = Some(true);
                    i += 1;
                }
                "nopacing" => {
                    cfg.pacing = Some(false);
                    i += 1;
                }
                "buckets" => {
                    cfg.buckets = Some(parse_u32(need_value()?, "buckets")?);
                    i += 2;
                }
                "horizon" => {
                    cfg.horizon = Some(parse_time(need_value()?, "horizon")?);
                    i += 2;
                }
                "horizon_drop" | "horizon_cap" => {
                    cfg.horizon_drop = Some(key == "horizon_drop");
                    i += 1;
                }
                "timer_slack" => {
                    cfg.timer_slack = Some(parse_time(need_value()?, "timer_slack")?);
                    i += 2;
                }
                "defrate" => {
                    return Err(Error::invalid_message(
                        "fq: `defrate` is obsolete: the kernel ignores TCA_FQ_FLOW_DEFAULT_RATE".to_string(),
                    ));
                }
                "bands" | "priomap" | "weights" | "offload_horizon" => {
                    return Err(Error::invalid_message(format!("fq: `{key}` is not modelled by FqConfig")));
                }
                other => {
                    return Err(Error::invalid_message(format!("fq: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for FqConfig {
    fn kind(&self) -> &'static str {
        "fq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq::TCA_FQ_PLIMIT, limit.as_u32());
        }
        if let Some(flow_limit) = self.flow_limit {
            builder.append_attr_u32(fq::TCA_FQ_FLOW_PLIMIT, flow_limit.as_u32());
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq::TCA_FQ_QUANTUM, quantum);
        }
        if let Some(iq) = self.initial_quantum {
            builder.append_attr_u32(fq::TCA_FQ_INITIAL_QUANTUM, iq);
        }
        if let Some(maxrate) = self.maxrate {
            builder.append_attr_u32(
                fq::TCA_FQ_FLOW_MAX_RATE,
                maxrate.as_u32_bytes_per_sec_saturating(),
            );
        }
        if let Some(lrt) = self.low_rate_threshold {
            builder.append_attr_u32(
                fq::TCA_FQ_LOW_RATE_THRESHOLD,
                lrt.as_u32_bytes_per_sec_saturating(),
            );
        }
        if let Some(rd) = self.refill_delay {
            builder.append_attr_u32(fq::TCA_FQ_FLOW_REFILL_DELAY, rd.as_micros() as u32);
        }
        if let Some(mask) = self.orphan_mask {
            builder.append_attr_u32(fq::TCA_FQ_ORPHAN_MASK, mask);
        }
        if let Some(ce) = self.ce_threshold {
            builder.append_attr_u32(fq::TCA_FQ_CE_THRESHOLD, ce.as_micros() as u32);
        }
        if let Some(pacing) = self.pacing {
            builder.append_attr_u32(fq::TCA_FQ_RATE_ENABLE, u32::from(pacing));
        }
        // log2 of the buckets, rounded up: tc's ilog2().
        if let Some(buckets) = self.buckets.filter(|b| *b != 0) {
            builder.append_attr_u32(fq::TCA_FQ_BUCKETS_LOG, u32::BITS - (buckets - 1).leading_zeros());
        }
        if let Some(slack) = self.timer_slack {
            builder.append_attr_u32(fq::TCA_FQ_TIMER_SLACK, u32::try_from(slack.as_nanos()).unwrap_or(u32::MAX));
        }
        if let Some(horizon) = self.horizon {
            builder.append_attr_u32(fq::TCA_FQ_HORIZON, u32::try_from(horizon.as_micros()).unwrap_or(u32::MAX));
        }
        if let Some(drop) = self.horizon_drop {
            builder.append_attr(fq::TCA_FQ_HORIZON_DROP, &[u8::from(drop)]);
        }
        Ok(())
    }
}

// ============================================================================
// MqConfig
// ============================================================================

/// Multiqueue (mq) qdisc configuration.
///
/// `mq` is a classful dummy scheduler the kernel attaches as the root
/// qdisc of a multi-queue NIC: it exposes one child class per hardware
/// TX queue so a real qdisc (fq_codel, pfifo_fast, …) can be installed
/// per queue. The qdisc itself carries **no options** — like
/// [`DrrConfig`], this type exists for symmetry so `mq` can be created
/// through the same typed `add_qdisc` path as every other kind.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::MqConfig;
/// conn.add_qdisc("eth0", MqConfig::new()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct MqConfig {}

impl MqConfig {
    /// Create a new mq configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style mq params slice. `mq` takes no parameters; an
    /// empty slice succeeds, anything else errors (strict contract —
    /// per-queue tuning belongs on the child qdiscs).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::invalid_message(format!(
                "mq: qdisc takes no parameters (got `{token}`); install per-queue qdiscs on the child classes"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for MqConfig {
    fn kind(&self) -> &'static str {
        "mq"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // mq has no options; the kernel materializes one child class
        // per hardware TX queue automatically.
        Ok(())
    }
}

// ============================================================================
// EtsConfig
// ============================================================================

/// Enhanced Transmission Selection (ets) qdisc configuration.
///
/// `ets` (IEEE 802.1Qaz) combines strict-priority and weighted
/// (deficit round-robin) bands in a single qdisc. The first `nstrict`
/// bands are served in strict priority order; the remaining
/// `nbands - nstrict` bands share bandwidth by their DRR `quanta`. A
/// `priomap` maps each of the 16 skb priorities to a band.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::tc::EtsConfig;
/// // 4 bands, 1 strict; the 3 DWRR bands get 3000/2000/1000 byte quanta.
/// let cfg = EtsConfig::new()
///     .bands(4)
///     .strict(1)
///     .quanta(vec![3000, 2000, 1000])
///     .priomap(vec![0, 0, 0, 1, 2, 3, 3, 3])
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct EtsConfig {
    /// Total number of bands (`nbands`, 1..=16).
    pub bands: Option<u8>,
    /// Number of leading strict-priority bands (`nstrict`).
    pub strict: Option<u8>,
    /// Per-band DRR quanta in bytes, for the non-strict bands.
    pub quanta: Vec<u32>,
    /// Priority → band map (one entry per skb priority, up to 16).
    pub priomap: Vec<u8>,
}

impl EtsConfig {
    /// Create a new ets configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total number of bands.
    pub fn bands(mut self, nbands: u8) -> Self {
        self.bands = Some(nbands);
        self
    }

    /// Set the number of leading strict-priority bands.
    pub fn strict(mut self, nstrict: u8) -> Self {
        self.strict = Some(nstrict);
        self
    }

    /// Set the per-band DRR quanta (bytes) for the non-strict bands.
    pub fn quanta(mut self, quanta: Vec<u32>) -> Self {
        self.quanta = quanta;
        self
    }

    /// Set the priority → band map.
    pub fn priomap(mut self, priomap: Vec<u8>) -> Self {
        self.priomap = priomap;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style ets params slice.
    ///
    /// Recognised tokens: `bands <n>`, `strict <n>`,
    /// `quanta <q1> <q2> …` (greedy until the next keyword),
    /// `priomap <p0> <p1> …` (greedy until the next keyword). Strict:
    /// unknown tokens, missing values, and unparseable values error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        fn is_keyword(s: &str) -> bool {
            matches!(s, "bands" | "strict" | "quanta" | "priomap")
        }
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "bands" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("ets: `bands` requires a value".to_string())
                    })?;
                    cfg.bands = Some(v.parse::<u8>().map_err(|_| {
                        Error::invalid_message(format!(
                            "ets: invalid bands `{v}` (expected integer 1..=16)"
                        ))
                    })?);
                    i += 2;
                }
                "strict" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("ets: `strict` requires a value".to_string())
                    })?;
                    cfg.strict = Some(v.parse::<u8>().map_err(|_| {
                        Error::invalid_message(format!(
                            "ets: invalid strict `{v}` (expected integer)"
                        ))
                    })?);
                    i += 2;
                }
                "quanta" => {
                    i += 1;
                    let start = i;
                    while i < params.len() && !is_keyword(params[i]) {
                        let v = params[i];
                        cfg.quanta.push(v.parse::<u32>().map_err(|_| {
                            Error::invalid_message(format!(
                                "ets: invalid quantum `{v}` (expected integer bytes)"
                            ))
                        })?);
                        i += 1;
                    }
                    if i == start {
                        return Err(Error::invalid_message(
                            "ets: `quanta` requires at least one value".to_string(),
                        ));
                    }
                }
                "priomap" => {
                    i += 1;
                    let start = i;
                    while i < params.len() && !is_keyword(params[i]) {
                        let v = params[i];
                        cfg.priomap.push(v.parse::<u8>().map_err(|_| {
                            Error::invalid_message(format!(
                                "ets: invalid priomap entry `{v}` (expected band index)"
                            ))
                        })?);
                        i += 1;
                    }
                    if i == start {
                        return Err(Error::invalid_message(
                            "ets: `priomap` requires at least one value".to_string(),
                        ));
                    }
                }
                other => {
                    return Err(Error::invalid_message(format!("ets: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for EtsConfig {
    fn kind(&self) -> &'static str {
        "ets"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(nbands) = self.bands {
            builder.append_attr(ets::TCA_ETS_NBANDS, &[nbands]);
        }
        if let Some(nstrict) = self.strict {
            builder.append_attr(ets::TCA_ETS_NSTRICT, &[nstrict]);
        }
        if !self.quanta.is_empty() {
            let token = builder.nest_start(ets::TCA_ETS_QUANTA);
            for q in &self.quanta {
                builder.append_attr(ets::TCA_ETS_QUANTA_BAND, &q.to_ne_bytes());
            }
            builder.nest_end(token);
        }
        if !self.priomap.is_empty() {
            let token = builder.nest_start(ets::TCA_ETS_PRIOMAP);
            for band in &self.priomap {
                builder.append_attr(ets::TCA_ETS_PRIOMAP_BAND, &[*band]);
            }
            builder.nest_end(token);
        }
        Ok(())
    }
}

// ============================================================================
// TbfConfig
// ============================================================================

/// Token Bucket Filter (tbf) qdisc configuration.
///
/// TBF is a simple rate limiter that allows bursts up to a configured size.
///
/// # Example
///
/// ```no_run
/// use nlink::{Bytes, Rate, netlink::tc::TbfConfig};
/// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
/// let config = TbfConfig::new()
///     .rate(Rate::bytes_per_sec(1_000_000))  // 1 MB/s
///     .burst(Bytes::kib(32))                 // 32 KiB burst
///     .limit(Bytes::kib(100))                // 100 KiB buffer
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TbfConfig {
    /// Rate.
    pub rate: crate::util::Rate,
    /// Peak rate (optional).
    pub peakrate: Option<crate::util::Rate>,
    /// Burst size.
    pub burst: crate::util::Bytes,
    /// MTU / peak burst.
    pub mtu: u32,
    /// Queue limit in bytes. **Required**: 0 (the default) is refused when
    /// the qdisc is written, because the kernel installs a TBF with no
    /// limit with no queue at all and drops every packet.
    pub limit: crate::util::Bytes,
    /// Bytes the kernel adds to each packet's size when it charges the
    /// rates, for framing the device does not count. tc(8) `overhead`
    /// (#806).
    pub overhead: u16,
    /// The least size a packet is charged as. tc(8) `mpu` (#806).
    pub mpu: u16,
    /// The link layer the rate tables are for: ATM rounds each packet up
    /// to whole cells. tc(8) `linklayer` (#806).
    pub linklayer: super::psched::LinkLayer,
}

impl Default for TbfConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TbfConfig {
    /// Create a new tbf configuration builder.
    pub fn new() -> Self {
        Self {
            rate: crate::util::Rate::ZERO,
            peakrate: None,
            burst: crate::util::Bytes::ZERO,
            mtu: 1514,
            limit: crate::util::Bytes::ZERO,
            overhead: 0,
            mpu: 0,
            linklayer: super::psched::LinkLayer::Ethernet,
        }
    }

    /// Set the per-packet overhead the rates charge (#806).
    pub fn overhead(mut self, bytes: u16) -> Self {
        self.overhead = bytes;
        self
    }

    /// Set the least size a packet is charged as (#806).
    pub fn mpu(mut self, bytes: u16) -> Self {
        self.mpu = bytes;
        self
    }

    /// Set the link layer the rate tables are for (#806).
    pub fn linklayer(mut self, linklayer: super::psched::LinkLayer) -> Self {
        self.linklayer = linklayer;
        self
    }

    /// Set the rate.
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        self.rate = rate;
        self
    }

    /// Set the peak rate.
    pub fn peakrate(mut self, rate: crate::util::Rate) -> Self {
        self.peakrate = Some(rate);
        self
    }

    /// Set the burst size.
    pub fn burst(mut self, b: crate::util::Bytes) -> Self {
        self.burst = b;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the queue limit in bytes — how much may wait for tokens.
    ///
    /// Required. `tbf_change()` only gives the qdisc a queue when the limit
    /// is non-zero, so without one every packet is dropped; `add_qdisc` /
    /// `replace_qdisc` refuse a zero limit rather than install that, as
    /// tc(8) refuses a tbf with neither `limit` nor `latency`. A common
    /// choice is the burst plus what the rate drains in the latency you
    /// accept: `burst + rate * latency`.
    pub fn limit(mut self, b: crate::util::Bytes) -> Self {
        self.limit = b;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style tbf params slice into a typed `TbfConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `rate <rate>` — required; the shaping rate.
    /// - `burst <bytes>` (alias `buffer`, `maxburst`) — required by
    ///   the kernel; the token-bucket size.
    /// - `limit <bytes>` — buffer size in bytes.
    /// - `peakrate <rate>` — optional secondary rate cap.
    /// - `mtu <bytes>` (alias `minburst`) — peak-burst MTU.
    ///
    /// - `latency <time>` — instead of `limit`: the limit is computed as
    ///   tc(8) computes it, `rate * latency + burst`, or with a
    ///   `peakrate` the smaller of that and `peakrate * latency + mtu`
    ///   (#820).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rate/size values all return `Error::invalid_message`. Note:
    /// this parser does NOT enforce the kernel's "rate and burst
    /// are required" rule — that's left to `add_qdisc` / the kernel
    /// itself, mirroring how `parse_params` behaves on every other
    /// config.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::TbfConfig;
    /// let cfg = TbfConfig::parse_params(&[
    ///     "rate", "1mbit",
    ///     "burst", "32kb",
    ///     "limit", "10kb",
    /// ])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        // tc(8) takes one of `limit` and `latency`, once.
        let (mut limit_given, mut latency) = (false, None);
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("tbf: `{key}` requires a value")))
            };
            match key {
                "rate" => {
                    let s = need_value()?;
                    cfg.rate = crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "tbf: invalid rate `{s}` (expected tc-style rate like `1mbit`)"
                        ))
                    })?;
                    i += 2;
                }
                "peakrate" => {
                    let s = need_value()?;
                    cfg.peakrate = Some(crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "tbf: invalid peakrate `{s}` (expected tc-style rate)"
                        ))
                    })?);
                    i += 2;
                }
                "burst" | "buffer" | "maxburst" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "tbf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.burst = crate::util::Bytes::new(bytes);
                    i += 2;
                }
                "limit" => {
                    if limit_given || latency.is_some() {
                        return Err(Error::invalid_message("tbf: one `limit` or `latency`, once".to_string()));
                    }
                    limit_given = true;
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "tbf: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = crate::util::Bytes::new(bytes);
                    i += 2;
                }
                "mtu" | "minburst" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "tbf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.mtu = bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("tbf: {key} `{s}` exceeds u32 (max ~4GB)"))
                    })?;
                    i += 2;
                }
                "latency" => {
                    if limit_given || latency.is_some() {
                        return Err(Error::invalid_message("tbf: one `limit` or `latency`, once".to_string()));
                    }
                    let s = need_value()?;
                    latency = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!("tbf: invalid latency `{s}` (expected tc-style time)"))
                    })?);
                    i += 2;
                }
                "overhead" | "mpu" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).ok().and_then(|b| u16::try_from(b).ok()).ok_or_else(|| {
                        Error::invalid_message(format!(
                            "tbf: invalid {key} `{s}` (expected a size up to 65535 bytes)"
                        ))
                    })?;
                    if key == "overhead" {
                        cfg.overhead = bytes;
                    } else {
                        cfg.mpu = bytes;
                    }
                    i += 2;
                }
                "linklayer" => {
                    let s = need_value()?;
                    cfg.linklayer = match s {
                        "ethernet" => super::psched::LinkLayer::Ethernet,
                        "atm" | "adsl" => super::psched::LinkLayer::Atm,
                        _ => {
                            return Err(Error::invalid_message(format!(
                                "tbf: invalid linklayer `{s}` (expected ethernet, atm or adsl)"
                            )));
                        }
                    };
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "tbf: unknown token `{other}`"
                    )));
                }
            }
        }
        if let Some(latency) = latency {
            // tc's arithmetic, in microseconds and bytes.
            let us = latency.as_micros() as f64;
            let mut limit = cfg.rate.as_bytes_per_sec() as f64 * us / 1e6 + cfg.burst.as_u64() as f64;
            if let Some(peak) = cfg.peakrate {
                limit = limit.min(peak.as_bytes_per_sec() as f64 * us / 1e6 + f64::from(cfg.mtu));
            }
            cfg.limit = crate::util::Bytes::new(u64::from(limit as u32));
        }
        Ok(cfg)
    }
}

impl QdiscConfig for TbfConfig {
    fn kind(&self) -> &'static str {
        "tbf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // `tbf_change()` only creates the child bfifo when
        // `qopt->limit > 0`, so a TBF created with limit 0 keeps
        // `noop_qdisc` as its queue and drops every packet; on an existing
        // TBF, limit 0 shrinks its bfifo to nothing, with the same result.
        // tc(8) refuses it ("either \"limit\" or \"latency\" are
        // required"). `TbfConfig::new()` defaults the limit to 0, so a TBF
        // built with only a rate and a burst — the shape most callers
        // reach for — used to install as a black hole.
        if self.limit.as_u32_saturating() == 0 {
            return Err(Error::invalid_message(
                "tbf: a queue limit is required — with limit 0 the kernel gives the qdisc no \
                 queue and it drops every packet (tc(8): \"either limit or latency are \
                 required\"); set TbfConfig::limit (QdiscBuilder::limit_bytes when declared)"
                    ,
            ));
        }
        let rate_bps = self.rate.as_bytes_per_sec();
        let peakrate_bps = self.peakrate.map(|p| p.as_bytes_per_sec());
        let burst = self.burst.as_u32_saturating();

        // `tc_tbf_qopt.buffer` and `.mtu` are psched TICKS, not bytes —
        // tbf_change() runs both through PSCHED_TICKS2NS(). Writing the raw
        // byte count made the bucket drain ~125x too fast at 1 mbit, so
        // tbf_enqueue() dropped every packet over ~262 bytes (#192).
        // The overhead, mpu and link layer go on both rates, as tc(8) puts
        // them (#806).
        let spec = |rate: u32| TcRateSpec {
            rate,
            overhead: self.overhead,
            mpu: self.mpu,
            ..Default::default()
        };
        let mut rate = spec(rate_bps.min(u32::MAX as u64) as u32);
        let rtab = psched::tc_calc_rtable(&mut rate, rate_bps, self.mtu, self.linklayer);

        let mut peakrate = TcRateSpec::default();
        let ptab = peakrate_bps.map(|pr| {
            peakrate = spec(pr.min(u32::MAX as u64) as u32);
            psched::tc_calc_rtable(&mut peakrate, pr, self.mtu, self.linklayer)
        });

        let qopt = tbf::TcTbfQopt {
            rate,
            peakrate,
            limit: self.limit.as_u32_saturating(),
            buffer: psched::tc_calc_xmittime(rate_bps, burst),
            // The peak-rate bucket is sized in ticks against the peak rate;
            // with no peakrate configured the kernel ignores the field.
            mtu: psched::tc_calc_xmittime(peakrate_bps.unwrap_or(rate_bps), self.mtu),
        };

        builder.append_attr(tbf::TCA_TBF_PARMS, qopt.as_bytes());

        // The rate tables are mandatory: qdisc_get_rtab() rejects the qdisc
        // outright without them (and silently discards a table whose spec
        // carries cell_log == 0, which is why tc_calc_rtable stamps it).
        builder.append_attr(tbf::TCA_TBF_RTAB, &rtab);
        if let Some(ptab) = &ptab {
            builder.append_attr(tbf::TCA_TBF_PTAB, ptab);
        }

        // Add 64-bit rate if needed
        if rate_bps > u32::MAX as u64 {
            builder.append_attr(tbf::TCA_TBF_RATE64, &rate_bps.to_ne_bytes());
        }
        if let Some(pr) = peakrate_bps
            && pr > u32::MAX as u64
        {
            builder.append_attr(tbf::TCA_TBF_PRATE64, &pr.to_ne_bytes());
        }

        // The byte-valued escape hatches. Modern kernels prefer these over the
        // tick-valued qopt fields and recompute the bucket from them, so they
        // sidestep the tick quantization entirely. iproute2 emits both.
        builder.append_attr_u32(tbf::TCA_TBF_BURST, burst);
        if peakrate_bps.is_some() {
            builder.append_attr_u32(tbf::TCA_TBF_PBURST, self.mtu);
        }

        Ok(())
    }
}

// ============================================================================
// HtbConfig (qdisc level)
// ============================================================================

/// HTB (Hierarchical Token Bucket) qdisc configuration.
///
/// HTB is used for hierarchical bandwidth shaping with classes.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::HtbQdiscConfig;
///
/// let config = HtbQdiscConfig::new()
///     .default_class(0x10)
///     .r2q(10)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HtbQdiscConfig {
    /// Default class ID for unclassified traffic.
    pub default_class: u32,
    /// Rate to quantum divisor.
    pub r2q: u32,
    /// Direct queue length.
    pub direct_qlen: Option<crate::util::Packets>,
}

impl Default for HtbQdiscConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HtbQdiscConfig {
    /// Create a new HTB qdisc configuration builder.
    pub fn new() -> Self {
        Self {
            default_class: 0,
            r2q: 10,
            direct_qlen: None,
        }
    }

    /// Set the default class ID.
    pub fn default_class(mut self, classid: u32) -> Self {
        self.default_class = classid;
        self
    }

    /// Set the rate to quantum divisor.
    pub fn r2q(mut self, r2q: u32) -> Self {
        self.r2q = r2q;
        self
    }

    /// Set the direct queue length.
    pub fn direct_qlen(mut self, qlen: crate::util::Packets) -> Self {
        self.direct_qlen = Some(qlen);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style params slice into a typed `HtbQdiscConfig`.
    ///
    /// Recognised tokens (each followed by a value):
    ///
    /// - `default <class>` — default class for unclassified traffic.
    ///   Accepts a tc handle (`1:10`) or a bare hex minor (`10`,
    ///   matching iproute2's `tc qdisc add ... htb default 10`).
    /// - `r2q <n>` — rate-to-quantum divisor (default 10).
    /// - `direct_qlen <n>` — direct queue length.
    ///
    /// Strict: unknown tokens, keys missing their value, and
    /// unparseable numbers all return `Error::invalid_message`
    /// instead of being silently skipped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::HtbQdiscConfig;
    /// let cfg = HtbQdiscConfig::parse_params(&["default", "1:10", "r2q", "5"])?;
    /// assert_eq!(cfg.r2q, 5);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("htb: `{key}` requires a value")))
            };
            match key {
                "default" => {
                    cfg.default_class = parse_default_class(value()?)?;
                    i += 2;
                }
                "r2q" => {
                    cfg.r2q = value()?.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "htb: invalid r2q `{}` (expected unsigned integer)",
                            params[i + 1]
                        ))
                    })?;
                    i += 2;
                }
                "direct_qlen" => {
                    cfg.direct_qlen = Some(value()?.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "htb: invalid direct_qlen `{}` (expected unsigned integer)",
                            params[i + 1]
                        ))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "htb: unknown token `{other}` (expected default, r2q, or direct_qlen)"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Parse the `default` class identifier in an HTB params slice.
///
/// Accepts a tc handle (`1:10` → raw u32 of `TcHandle::new(1, 0x10)`)
/// or a bare hex minor (`10` → `0x10`). The bare-hex form mirrors
/// `tc(8)`'s convention where `tc qdisc add ... htb default 10`
/// means "minor 0x10 under the qdisc's own major".
fn parse_default_class(s: &str) -> Result<u32> {
    if s.contains(':') {
        s.parse::<crate::netlink::tc_handle::TcHandle>()
            .map(|h| h.as_raw())
            .map_err(|e| Error::invalid_message(format!("htb: invalid default class `{s}`: {e}")))
    } else {
        u32::from_str_radix(s, 16).map_err(|_| {
            Error::invalid_message(format!(
                "htb: invalid default class `{s}` (expected hex minor or tc handle)"
            ))
        })
    }
}

impl QdiscConfig for HtbQdiscConfig {
    fn kind(&self) -> &'static str {
        "htb"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    /// `sch_htb` has no change operation: "Change operation not supported
    /// by specified qdisc".
    fn in_place(&self, _live: &TcMessage) -> InPlace {
        InPlace::Recreate
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let glob = htb::TcHtbGlob::new()
            .with_default(self.default_class)
            .with_r2q(self.r2q);
        builder.append_attr(htb::TCA_HTB_INIT, glob.as_bytes());

        if let Some(qlen) = self.direct_qlen {
            builder.append_attr_u32(htb::TCA_HTB_DIRECT_QLEN, qlen.as_u32());
        }

        Ok(())
    }
}

// ============================================================================
// PrioConfig
// ============================================================================

/// Priority (prio) qdisc configuration.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::PrioConfig;
///
/// let config = PrioConfig::new()
///     .bands(3)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PrioConfig {
    /// Number of priority bands.
    pub bands: i32,
    /// Priority map (16 entries).
    pub priomap: [u8; 16],
}

impl Default for PrioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PrioConfig {
    /// The kernel's (and `tc`'s) priomap for three bands.
    pub const DEFAULT_PRIOMAP: [u8; 16] = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];

    /// Create a new prio configuration builder with defaults.
    pub fn new() -> Self {
        Self {
            bands: 3,
            priomap: Self::DEFAULT_PRIOMAP,
        }
    }

    /// The priomap that is sent: the one set, except that the default
    /// map is fitted to fewer than three bands (every entry capped at the
    /// last band), so `bands(2)` works without a priomap. The kernel
    /// refuses an entry that names a band past the last (#487).
    pub fn effective_priomap(&self) -> [u8; 16] {
        let last = u8::try_from(self.bands.clamp(1, 16) - 1).unwrap_or(0);
        if self.priomap == Self::DEFAULT_PRIOMAP && self.bands < 3 {
            Self::DEFAULT_PRIOMAP.map(|band| band.min(last))
        } else {
            self.priomap
        }
    }

    /// Set the number of bands.
    pub fn bands(mut self, bands: i32) -> Self {
        self.bands = bands;
        self
    }

    /// Set the priority map.
    pub fn priomap(mut self, map: [u8; 16]) -> Self {
        self.priomap = map;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style prio params slice into a typed `PrioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `bands <n>` — number of priority bands (signed i32 to match
    ///   the kernel's wire type).
    /// - `priomap <P0> <P1> ... <P15>` — exactly 16 priority-to-band
    ///   mappings. Stricter than the legacy parser, which silently
    ///   ignored the token if there weren't 16 values; here a short
    ///   priomap is an explicit error.
    ///
    /// Unknown tokens, missing values, and unparseable numbers all
    /// return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "bands" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("prio: `bands` requires a value")
                    })?;
                    cfg.bands = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "prio: invalid bands `{s}` (expected signed integer)"
                        ))
                    })?;
                    i += 2;
                }
                "priomap" => {
                    if params.len() < i + 1 + 16 {
                        return Err(Error::invalid_message(format!(
                            "prio: `priomap` requires exactly 16 values, got {}",
                            params.len().saturating_sub(i + 1)
                        )));
                    }
                    for j in 0..16 {
                        let s = params[i + 1 + j];
                        cfg.priomap[j] = s.parse().map_err(|_| {
                            Error::invalid_message(format!(
                                "prio: invalid priomap[{j}] `{s}` (expected 0-255)"
                            ))
                        })?;
                    }
                    i += 17;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "prio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for PrioConfig {
    fn kind(&self) -> &'static str {
        "prio"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // prio_tune: TCQ_MIN_PRIO_BANDS (2) ..= TCQ_PRIO_BANDS (16), and
        // every priomap entry below `bands`. Say so here rather than relay
        // a bare EINVAL.
        if !(2..=16).contains(&self.bands) {
            return Err(Error::invalid_message(format!(
                "prio: bands {} out of range (2..=16)",
                self.bands
            )));
        }
        let priomap = self.effective_priomap();
        if let Some((tos, band)) = priomap
            .iter()
            .enumerate()
            .find(|(_, band)| i32::from(**band) >= self.bands)
        {
            return Err(Error::invalid_message(format!(
                "prio: priomap[{tos}] names band {band}, but there are only {} bands",
                self.bands
            )));
        }
        let qopt = prio::TcPrioQopt {
            bands: self.bands,
            priomap,
        };
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// SfqConfig
// ============================================================================

/// Stochastic Fairness Queuing (sfq) qdisc configuration.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::SfqConfig;
/// use nlink::Packets;
///
/// let config = SfqConfig::new()
///     .perturb(10)
///     .limit(Packets::new(127))
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SfqConfig {
    /// Perturbation period in seconds.
    pub perturb: i32,
    /// Queue limit in packets; 0, the default, leaves the kernel's (127).
    /// A limit also caps the number of flows (`sfq_change`), so `limit(100)`
    /// has 100 flows where the default has 128. This was 127 and always
    /// sent before 0.32, which gave the default sfq 127 flows where tc(8)'s
    /// has 128 (#637).
    pub limit: crate::util::Packets,
    /// Quantum (bytes per round).
    pub quantum: u32,
    /// The hash table's buckets, a power of two up to 65536; 0, the
    /// default, leaves the kernel's (1024). tc(8) `divisor` (#806).
    pub divisor: u32,
    /// The most flows; 0 leaves the kernel's (128). A limit caps it.
    /// tc(8) `flows` (#806).
    pub flows: u32,
    /// The most packets a flow queues, up to 127; 0 leaves the kernel's
    /// (127). tc(8) `depth` (#806).
    pub depth: u32,
    /// Drop from the head of a full flow's queue, not its tail. tc(8)
    /// `headdrop` (#806).
    pub headdrop: bool,
}

impl Default for SfqConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SfqConfig {
    /// Create a new sfq configuration builder.
    pub fn new() -> Self {
        Self {
            perturb: 0,
            limit: crate::util::Packets::ZERO,
            quantum: 0,
            divisor: 0,
            flows: 0,
            depth: 0,
            headdrop: false,
        }
    }

    /// Set the hash table's buckets, a power of two up to 65536 (#806).
    pub fn divisor(mut self, buckets: u32) -> Self {
        self.divisor = buckets;
        self
    }

    /// Set the most flows (#806).
    pub fn flows(mut self, flows: u32) -> Self {
        self.flows = flows;
        self
    }

    /// Set the most packets a flow queues, up to 127 (#806).
    pub fn depth(mut self, packets: u32) -> Self {
        self.depth = packets;
        self
    }

    /// Drop from the head of a full flow's queue (#806).
    pub fn headdrop(mut self, on: bool) -> Self {
        self.headdrop = on;
        self
    }

    /// Set the perturbation period in seconds.
    pub fn perturb(mut self, seconds: i32) -> Self {
        self.perturb = seconds;
        self
    }

    /// Set the queue limit.
    pub fn limit(mut self, limit: crate::util::Packets) -> Self {
        self.limit = limit;
        self
    }

    /// Set the quantum (bytes per round).
    pub fn quantum(mut self, bytes: u32) -> Self {
        self.quantum = bytes;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style sfq params slice into a typed `SfqConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `quantum <bytes>` — bytes dequeued per round (tc-style size).
    /// - `perturb <seconds>` — hash perturbation interval.
    /// - `limit <packets>` — queue limit in packets.
    /// - `divisor <buckets>`, `flows <n>`, `depth <packets>`, `headdrop`
    ///   (#806).
    ///
    /// **Not typed-modelled** (returns `Error::invalid_message`): the
    /// SFQRED words (`redflowlimit`, `min`, `max`, `avpkt`, `burst`,
    /// `probability`, `ecn`, `harddrop`).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// numbers all return an error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("sfq: `{key}` requires a value")))
            };
            match key {
                "quantum" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "sfq: invalid quantum `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.quantum = bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("sfq: quantum `{s}` exceeds u32"))
                    })?;
                    i += 2;
                }
                "perturb" => {
                    let s = need_value()?;
                    cfg.perturb = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "sfq: invalid perturb `{s}` (expected signed integer seconds)"
                        ))
                    })?;
                    i += 2;
                }
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "sfq: invalid limit `{s}` (expected unsigned integer packets)"
                        ))
                    })?;
                    i += 2;
                }
                key @ ("divisor" | "flows" | "depth") => {
                    let s = need_value()?;
                    let v: u32 = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "sfq: invalid {key} `{s}` (expected unsigned integer)"
                        ))
                    })?;
                    cfg = match key {
                        "divisor" => cfg.divisor(v),
                        "flows" => cfg.flows(v),
                        _ => cfg.depth(v),
                    };
                    i += 2;
                }
                "headdrop" => {
                    cfg.headdrop = true;
                    i += 1;
                }
                red @ ("redflowlimit" | "min" | "max" | "avpkt" | "burst" | "probability" | "ecn"
                | "harddrop") => {
                    return Err(Error::invalid_message(format!(
                        "sfq: `{red}` (SFQRED) is not modelled by SfqConfig"
                    )));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "sfq: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for SfqConfig {
    fn kind(&self) -> &'static str {
        "sfq"
    }

    /// `sch_sfq` has no change operation: "Change operation not supported
    /// by specified qdisc".
    fn in_place(&self, _live: &TcMessage) -> InPlace {
        InPlace::Recreate
    }

    /// The v1 struct whole, as tc(8) sends it: `sfq_change()` takes depth
    /// and head drop only from one of its full size (#806). Zero is the
    /// kernel's default for each field, and no SFQRED.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let qopt = sfq::TcSfqQoptV1 {
            v0: sfq::TcSfqQopt {
                quantum: self.quantum,
                perturb_period: self.perturb,
                limit: self.limit.as_u32(),
                divisor: self.divisor,
                flows: self.flows,
            },
            depth: self.depth,
            headdrop: u32::from(self.headdrop),
            ..Default::default()
        };
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// RedConfig
// ============================================================================

/// RED (Random Early Detection) qdisc configuration.
///
/// RED is an Active Queue Management (AQM) algorithm that probabilistically
/// drops packets before the queue is full to signal congestion.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::Bytes;
/// use nlink::netlink::tc::RedConfig;
///
/// let config = RedConfig::new()
///     .limit(Bytes::kib(100))
///     .min(Bytes::kib(30))
///     .max(Bytes::kib(90))
///     .ecn(true)            // Enable ECN marking
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RedConfig {
    /// Queue limit in bytes.
    pub limit: u32,
    /// Minimum threshold in bytes. 0 is a third of `max`, as tc(8) makes it.
    pub min: u32,
    /// Maximum threshold in bytes. 0 is three times `min`, or a quarter of
    /// `limit` without one, as tc(8) makes it.
    pub max: u32,
    /// The average packet size in bytes (`avpkt`), 1000 by default (#819).
    pub avpkt: u32,
    /// The burst in packets. 0 derives it as tc(8) does:
    /// `(2 * min + max) / (3 * avpkt)` (#819).
    pub burst: u32,
    /// The link's bandwidth, for the idle-time damping table; 10 Mbit by
    /// default, as tc(8)'s (#819).
    pub bandwidth: crate::util::Rate,
    /// The maximum marking probability, a fraction from 0.0 to 1.0 (tc(8)'s
    /// `probability`); 0.02 by default (#819).
    pub probability: f64,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Enable hard drop (drop all above max).
    pub harddrop: bool,
    /// Enable adaptive RED.
    pub adaptive: bool,
    /// Never drop: mark what is ECN-capable, queue the rest (#819).
    pub nodrop: bool,
}

impl Default for RedConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl RedConfig {
    /// Create a new RED configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 0,
            min: 0,
            max: 0,
            avpkt: 1000,
            burst: 0,
            bandwidth: crate::util::Rate::mbit(10),
            probability: 0.02,
            ecn: false,
            harddrop: false,
            adaptive: false,
            nodrop: false,
        }
    }

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: crate::util::Bytes) -> Self {
        self.limit = bytes.as_u32_saturating();
        self
    }

    /// Set the minimum threshold in bytes.
    pub fn min(mut self, bytes: crate::util::Bytes) -> Self {
        self.min = bytes.as_u32_saturating();
        self
    }

    /// Set the maximum threshold in bytes.
    pub fn max(mut self, bytes: crate::util::Bytes) -> Self {
        self.max = bytes.as_u32_saturating();
        self
    }

    /// Set the average packet size.
    pub fn avpkt(mut self, bytes: crate::util::Bytes) -> Self {
        self.avpkt = bytes.as_u32_saturating();
        self
    }

    /// Set the burst, in packets. 0 derives it.
    pub fn burst(mut self, packets: u32) -> Self {
        self.burst = packets;
        self
    }

    /// Set the link's bandwidth.
    pub fn bandwidth(mut self, rate: crate::util::Rate) -> Self {
        self.bandwidth = rate;
        self
    }

    /// Set the maximum probability (0-100%).
    pub fn max_probability(mut self, percent: f64) -> Self {
        self.probability = (percent / 100.0).clamp(0.0, 1.0);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable hard drop.
    pub fn harddrop(mut self, enable: bool) -> Self {
        self.harddrop = enable;
        self
    }

    /// Enable or disable adaptive RED.
    pub fn adaptive(mut self, enable: bool) -> Self {
        self.adaptive = enable;
        self
    }

    /// Enable or disable `nodrop`.
    pub fn nodrop(mut self, enable: bool) -> Self {
        self.nodrop = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style red params slice into a typed `RedConfig`.
    ///
    /// Recognised tokens, as tc-red(8) reads them (#819):
    ///
    /// - `limit <bytes>`, `min <bytes>`, `max <bytes>`, `avpkt <bytes>` —
    ///   tc-style sizes.
    /// - `burst <packets>`.
    /// - `bandwidth <rate>`.
    /// - `probability <fraction>` — 0.0 to 1.0: `0.02` is 2%.
    /// - `ecn`, `harddrop`, `adaptive` (or `adaptative`), `nodrop`, and
    ///   nlink's `noecn`, `noharddrop`, `noadaptive`.
    ///
    /// A bandwidth in percent of the device's speed and `qevent` blocks
    /// are not modelled.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("red: `{key}` requires a value")))
            };
            match key {
                "limit" | "min" | "max" | "avpkt" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "red: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })?;
                    let val: u32 = bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("red: {key} `{s}` exceeds u32"))
                    })?;
                    match key {
                        "limit" => cfg.limit = val,
                        "min" => cfg.min = val,
                        "max" => cfg.max = val,
                        _ => cfg.avpkt = val,
                    }
                    i += 2;
                }
                "burst" => {
                    cfg.burst = tc_unsigned("red", key, need_value()?)?;
                    i += 2;
                }
                "bandwidth" => {
                    cfg.bandwidth = red_parse_bandwidth("red", need_value()?)?;
                    i += 2;
                }
                "probability" => {
                    cfg.probability = red_parse_probability("red", need_value()?)?;
                    i += 2;
                }
                "ecn" | "noecn" => {
                    cfg.ecn = key == "ecn";
                    i += 1;
                }
                "harddrop" | "noharddrop" => {
                    cfg.harddrop = key == "harddrop";
                    i += 1;
                }
                "adaptive" | "adaptative" | "noadaptive" => {
                    cfg.adaptive = key != "noadaptive";
                    i += 1;
                }
                "nodrop" => {
                    cfg.nodrop = true;
                    i += 1;
                }
                "qevent" => {
                    return Err(Error::invalid_message(
                        "red: `qevent` is not modelled by RedConfig".to_string(),
                    ));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "red: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// An unsigned value as tc(8)'s `get_unsigned(.., 0)` reads it: decimal,
/// `0x` hex or `0` octal.
fn tc_unsigned(kind: &str, key: &str, s: &str) -> Result<u32> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8)
    } else {
        s.parse::<u32>()
    };
    parsed.map_err(|_| Error::invalid_message(format!("{kind}: invalid {key} `{s}` (expected unsigned integer)")))
}

fn red_parse_bandwidth(kind: &str, s: &str) -> Result<crate::util::Rate> {
    if s.ends_with('%') {
        return Err(Error::invalid_message(format!(
            "{kind}: a bandwidth in percent of the device's speed is not modelled; give a rate"
        )));
    }
    s.parse::<crate::util::Rate>()
        .map_err(|_| Error::invalid_message(format!("{kind}: invalid bandwidth `{s}` (expected a rate)")))
}

fn red_parse_probability(kind: &str, s: &str) -> Result<f64> {
    match s.parse::<f64>() {
        Ok(p) if (0.0..=1.0).contains(&p) => Ok(p),
        _ => Err(Error::invalid_message(format!(
            "{kind}: invalid probability `{s}` (expected a fraction from 0.0 to 1.0)"
        ))),
    }
}

/// What a red or choke qdisc derives from its parameters, as tc(8)
/// computes it (`tc_red.c`): the EWMA weight's log, the probability's log,
/// and the idle-time damping table with its cell log. The kernel refuses
/// either kind without the table (#819).
struct RedDerived {
    wlog: u8,
    plog: u8,
    scell_log: u8,
    stab: [u8; 256],
    max_p: u32,
}

/// `qmin` and `qmax` are in bytes: choke's packets times `avpkt`.
#[allow(clippy::too_many_arguments)]
fn red_derive(
    kind: &str,
    psched: &super::psched::Psched,
    qmin: u32,
    qmax: u32,
    burst: u32,
    avpkt: u32,
    bandwidth: crate::util::Rate,
    probability: f64,
) -> Result<RedDerived> {
    let fail = |what: &str| Error::invalid_message(format!("{kind}: failed to calculate {what}"));
    if avpkt == 0 {
        return Err(Error::invalid_message(format!("{kind}: avpkt must not be 0")));
    }
    // tc_red_eval_ewma: the smallest Wlog with
    // burst + 1 - qmin/avpkt <= (1 - (1 - W)^burst) / W.
    let a = f64::from(burst) + 1.0 - f64::from(qmin) / f64::from(avpkt);
    if a < 1.0 {
        return Err(Error::invalid_message(format!(
            "{kind}: burst {burst} is too small (try {})",
            1 + qmin / avpkt
        )));
    }
    let mut w: f64 = 0.5;
    let mut wlog = None;
    for log in 1..32u8 {
        if a <= (1.0 - (1.0 - w).powf(f64::from(burst))) / w {
            wlog = Some(log);
            break;
        }
        w /= 2.0;
    }
    let wlog = wlog.ok_or_else(|| fail("the EWMA constant"))?;
    // tc_red_eval_P: Plog = log2(1 / (prob / (qmax - qmin))).
    let plog = match i64::from(qmax) - i64::from(qmin) {
        0 => 0,
        d if d < 0 => return Err(fail("the probability (max is below min)")),
        d => {
            let mut p = probability / d as f64;
            (0..32u8)
                .find(|_| {
                    let above = p > 1.0;
                    p *= 2.0;
                    above
                })
                .ok_or_else(|| fail("the probability"))?
        }
    };
    // tc_red_eval_idle_damping: Stab[t >> Scell_log] = -log(1 - W) * t / xmit_time.
    let rate = bandwidth.as_bytes_per_sec().min(u64::from(u32::MAX));
    let xmit_time = f64::from(psched.calc_xmittime(rate, avpkt));
    let lw = -(1.0 - 1.0 / f64::from(1u32 << wlog)).ln() / xmit_time;
    let maxtime = 31.0 / lw;
    let scell_log = (0..32u8)
        .find(|c| maxtime / ((1u64 << c) as f64) < 512.0)
        .ok_or_else(|| fail("the idle damping table"))?;
    let mut stab = [0u8; 256];
    for (i, slot) in stab.iter_mut().enumerate().take(255).skip(1) {
        *slot = (((i as u64) << scell_log) as f64 * lw).min(31.0) as u8;
    }
    stab[255] = 31;
    Ok(RedDerived { wlog, plog, scell_log, stab, max_p: (probability * 4_294_967_296.0) as u32 })
}

impl QdiscConfig for RedConfig {
    fn kind(&self) -> &'static str {
        "red"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::red;

        // tc(8)'s defaults, from Sally Floyd's recommendations.
        let qmax = match (self.max, self.min) {
            (0, 0) => self.limit / 4,
            (0, min) => min.saturating_mul(3),
            (max, _) => max,
        };
        let qmin = if self.min == 0 { qmax / 3 } else { self.min };
        let burst = match self.burst {
            0 => (2 * u64::from(qmin) + u64::from(qmax)) / (3 * u64::from(self.avpkt.max(1))),
            b => u64::from(b),
        } as u32;
        let derived = red_derive(
            "red",
            &super::psched::psched(),
            qmin,
            qmax,
            burst,
            self.avpkt,
            self.bandwidth,
            self.probability,
        )?;

        let mut flags = 0;
        for (on, flag) in [
            (self.ecn, red::TC_RED_ECN),
            (self.harddrop, red::TC_RED_HARDDROP),
            (self.adaptive, red::TC_RED_ADAPTATIVE),
            (self.nodrop, red::TC_RED_NODROP),
        ] {
            if on {
                flags |= flag;
            }
        }

        // The flags go in TCA_RED_FLAGS, as tc sends them: the kernel
        // refuses them in both places.
        let qopt = red::TcRedQopt {
            limit: self.limit,
            qth_min: qmin,
            qth_max: qmax,
            wlog: derived.wlog,
            plog: derived.plog,
            scell_log: derived.scell_log,
            flags: 0,
        };
        builder.append_attr(red::TCA_RED_PARMS, qopt.as_bytes());
        builder.append_attr(red::TCA_RED_STAB, &derived.stab);
        builder.append_attr_u32(red::TCA_RED_MAX_P, derived.max_p);
        // struct nla_bitfield32 { value, selector }.
        let supported = red::TC_RED_ECN | red::TC_RED_HARDDROP | red::TC_RED_ADAPTATIVE | red::TC_RED_NODROP;
        let mut bitfield = [0u8; 8];
        bitfield[..4].copy_from_slice(&flags.to_ne_bytes());
        bitfield[4..].copy_from_slice(&supported.to_ne_bytes());
        builder.append_attr(red::TCA_RED_FLAGS, &bitfield);

        Ok(())
    }
}

// ============================================================================
// ChokeConfig
// ============================================================================

/// CHOKe qdisc configuration.
///
/// CHOKe ("CHOose and Keep for responsive flows, CHOose and Kill for
/// unresponsive flows") is a stateless AQM in the RED family. On each
/// enqueue it compares the arriving packet against a randomly-chosen
/// packet already in the queue; if they belong to the same flow it
/// drops both, penalising unresponsive (high-rate) flows without
/// per-flow state. Parameters mirror RED (it shares
/// `struct tc_red_qopt`).
///
/// ```no_run
/// use nlink::netlink::tc::ChokeConfig;
/// use nlink::Packets;
///
/// let cfg = ChokeConfig::new()
///     .limit(Packets::new(1000))
///     .min(Packets::new(50))
///     .max(Packets::new(150))
///     .ecn(true)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct ChokeConfig {
    /// Queue limit in packets: `sch_choke` counts packets (#723).
    pub limit: crate::util::Packets,
    /// Minimum threshold in packets. 0 is a third of `max`, as tc(8)
    /// makes it.
    pub min: crate::util::Packets,
    /// Maximum threshold in packets. 0 is a quarter of `limit`, as tc(8)
    /// makes it.
    pub max: crate::util::Packets,
    /// The average packet size in bytes (`avpkt`), 1000 by default (#819).
    pub avpkt: u32,
    /// The burst in packets. 0 derives it as tc(8) does:
    /// `(2 * min + max) / 3` (#819).
    pub burst: u32,
    /// The link's bandwidth, for the idle-time damping table; 10 Mbit by
    /// default (#819).
    pub bandwidth: crate::util::Rate,
    /// The maximum marking probability, a fraction from 0.0 to 1.0 (tc(8)'s
    /// `probability`); 0.02 by default (#819).
    pub probability: f64,
    /// Mark rather than drop ECN-capable packets.
    pub ecn: bool,
    /// Drop everything above `max`, ECN-capable or not.
    pub harddrop: bool,
}

impl Default for ChokeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ChokeConfig {
    pub fn new() -> Self {
        Self {
            limit: crate::util::Packets::ZERO,
            min: crate::util::Packets::ZERO,
            max: crate::util::Packets::ZERO,
            avpkt: 1000,
            burst: 0,
            bandwidth: crate::util::Rate::mbit(10),
            probability: 0.02,
            ecn: false,
            harddrop: false,
        }
    }

    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = packets;
        self
    }

    pub fn min(mut self, packets: crate::util::Packets) -> Self {
        self.min = packets;
        self
    }

    pub fn max(mut self, packets: crate::util::Packets) -> Self {
        self.max = packets;
        self
    }

    /// Set the average packet size.
    pub fn avpkt(mut self, bytes: crate::util::Bytes) -> Self {
        self.avpkt = bytes.as_u32_saturating();
        self
    }

    /// Set the burst, in packets. 0 derives it.
    pub fn burst(mut self, packets: u32) -> Self {
        self.burst = packets;
        self
    }

    /// Set the link's bandwidth.
    pub fn bandwidth(mut self, rate: crate::util::Rate) -> Self {
        self.bandwidth = rate;
        self
    }

    pub fn max_probability(mut self, percent: f64) -> Self {
        self.probability = (percent / 100.0).clamp(0.0, 1.0);
        self
    }

    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    pub fn harddrop(mut self, enable: bool) -> Self {
        self.harddrop = enable;
        self
    }

    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style choke params slice, as tc(8) reads it (#819):
    /// `limit`, `min`, `max` and `burst` in packets; `avpkt <size>`;
    /// `bandwidth <rate>`; `probability <fraction>`; `ecn`. nlink also
    /// takes `noecn`, `harddrop` and `noharddrop`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("choke: `{key}` requires a value"))
                })
            };
            match key {
                "limit" | "min" | "max" | "burst" => {
                    let val = tc_unsigned("choke", key, need_value()?)?;
                    match key {
                        "limit" => cfg.limit = crate::util::Packets::new(val),
                        "min" => cfg.min = crate::util::Packets::new(val),
                        "max" => cfg.max = crate::util::Packets::new(val),
                        _ => cfg.burst = val,
                    }
                    i += 2;
                }
                "avpkt" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s)
                        .ok()
                        .and_then(|b| u32::try_from(b).ok())
                        .ok_or_else(|| {
                            Error::invalid_message(format!("choke: invalid avpkt `{s}` (expected tc-style size)"))
                        })?;
                    cfg.avpkt = bytes;
                    i += 2;
                }
                "bandwidth" => {
                    cfg.bandwidth = red_parse_bandwidth("choke", need_value()?)?;
                    i += 2;
                }
                "probability" => {
                    cfg.probability = red_parse_probability("choke", need_value()?)?;
                    i += 2;
                }
                "ecn" | "noecn" => {
                    cfg.ecn = key == "ecn";
                    i += 1;
                }
                "harddrop" | "noharddrop" => {
                    cfg.harddrop = key == "harddrop";
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "choke: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for ChokeConfig {
    fn kind(&self) -> &'static str {
        "choke"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::{choke, red};

        // tc(8)'s defaults, in packets.
        let limit = self.limit.as_u32();
        let qmax = if self.max.as_u32() == 0 { limit / 4 } else { self.max.as_u32() };
        let qmin = if self.min.as_u32() == 0 { qmax / 3 } else { self.min.as_u32() };
        let burst = if self.burst == 0 { (2 * qmin + qmax) / 3 } else { self.burst };
        // tc derives choke's logs from the thresholds in bytes.
        let derived = red_derive(
            "choke",
            &super::psched::psched(),
            qmin.saturating_mul(self.avpkt),
            qmax.saturating_mul(self.avpkt),
            burst,
            self.avpkt,
            self.bandwidth,
            self.probability,
        )?;

        let mut flags: u8 = 0;
        if self.ecn {
            flags |= red::TC_RED_ECN as u8;
        }
        if self.harddrop {
            flags |= red::TC_RED_HARDDROP as u8;
        }

        let qopt = choke::TcRedQopt {
            limit,
            qth_min: qmin,
            qth_max: qmax,
            wlog: derived.wlog,
            plog: derived.plog,
            scell_log: derived.scell_log,
            flags,
        };
        builder.append_attr(choke::TCA_CHOKE_PARMS, qopt.as_bytes());
        builder.append_attr(choke::TCA_CHOKE_STAB, &derived.stab);
        builder.append_attr_u32(choke::TCA_CHOKE_MAX_P, derived.max_p);

        Ok(())
    }
}

// ============================================================================
// PfifoFastConfig
// ============================================================================

/// pfifo_fast qdisc configuration.
///
/// `pfifo_fast` is the classic three-band priority FIFO that the kernel
/// installs as the default qdisc on a freshly-created device. Its
/// band count and priomap (`prio2band`) are hardcoded kernel-side, so
/// unlike most qdiscs it accepts **no** options — this config is a unit
/// type. Adding it explicitly is mostly useful for restoring the
/// default behaviour after replacing the root qdisc.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::PfifoFastConfig;
///
/// conn.add_qdisc("eth0", PfifoFastConfig::new()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct PfifoFastConfig;

impl PfifoFastConfig {
    /// Create a new pfifo_fast configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style pfifo_fast params slice. pfifo_fast takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::invalid_message(format!(
                "pfifo_fast: unexpected token `{tok}` (pfifo_fast takes no parameters)"
            )));
        }
        Ok(Self)
    }
}

impl QdiscConfig for PfifoFastConfig {
    fn kind(&self) -> &'static str {
        "pfifo_fast"
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // pfifo_fast ignores TCA_OPTIONS — bands and priomap are
        // hardcoded kernel-side. Send no options.
        Ok(())
    }
}

// ============================================================================
// AtmConfig
// ============================================================================

/// ATM (`sch_atm`) qdisc configuration.
///
/// **Deprecated: the kernel retired `sch_atm` in Linux 6.8** (together
/// with CBQ and dsmark — "net/sched: Retire ATM qdisc"). On 6.8 and later
/// every add fails with `ENOENT` / `EOPNOTSUPP` whatever the arguments;
/// the type remains for callers on older kernels and will be removed in
/// a later release (#347).
///
/// The ATM qdisc is classful: it maps classified flows onto ATM virtual
/// circuits. The **qdisc itself takes no options** — `tc qdisc add dev X
/// root atm` simply instantiates the classful qdisc, so this is a unit
/// config (like [`PfifoFastConfig`] / `MultiqConfig`).
///
/// ```no_run
/// # #![allow(deprecated)]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::AtmConfig;
///
/// conn.add_qdisc("eth0", AtmConfig::new()).await?;
/// # Ok(())
/// # }
/// ```
///
/// # VC binding is out of scope
///
/// The useful part of `sch_atm` lives in its **classes**, which bind a
/// flow to an ATM virtual circuit via the file descriptor of an *open
/// ATM socket* (`TCA_ATM_FD`, plus `TCA_ATM_HDR`/`TCA_ATM_EXCESS`/
/// `TCA_ATM_ADDR`). That requires live ATM hardware and an
/// application-owned socket fd, so nlink does not model an ATM class
/// config — there is no portable, testable surface for it. Use a
/// hand-rolled `MessageBuilder` with your own socket fd if you target
/// ATM hardware.
#[derive(Debug, Clone, Default)]
#[deprecated(
    since = "0.27.0",
    note = "sch_atm was removed from the kernel in Linux 6.8; the type will be dropped in a later release — #347"
)]
pub struct AtmConfig;

#[allow(deprecated)]
impl AtmConfig {
    /// Create a new ATM qdisc configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style atm params slice. The ATM qdisc takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::invalid_message(format!(
                "atm: unexpected token `{tok}` (the atm qdisc takes no parameters; \
                 VC binding is a class-level concern not modelled by nlink)"
            )));
        }
        Ok(Self)
    }
}

#[allow(deprecated)]
impl QdiscConfig for AtmConfig {
    fn kind(&self) -> &'static str {
        "atm"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // The atm qdisc accepts no TCA_OPTIONS; classes carry the VC
        // binding. Send no options.
        Ok(())
    }
}

// ============================================================================
// GredConfig
// ============================================================================

/// GRED (Generic RED) qdisc configuration — **setup phase**.
///
/// GRED multiplexes up to 16 virtual queues (drop precedences) over one
/// qdisc, each with independent RED parameters. Configuration is
/// two-phase in the kernel:
///
/// 1. **Setup** (this config) — declare the number of virtual queues
///    (`DPs`), the default VQ, and whether GRIO (RIO-like priority
///    dropping) is enabled. Sent as `struct tc_gred_sopt` under
///    `TCA_GRED_DPS`, plus an optional global byte `limit`.
/// 2. **Per-VQ RED params** — `min`/`max`/`avpkt`/`bandwidth`/`prio` for
///    an individual VQ. This requires the kernel's 256-byte RED stab
///    probability table (computed from avpkt + bandwidth), which
///    `GredConfig` does **not** model — see the note below.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::GredConfig;
///
/// // 8 virtual queues, VQ 2 is the default, GRIO on.
/// let cfg = GredConfig::new()
///     .virtual_queues(8)
///     .default_vq(2)
///     .grio(true)
///     .build();
/// conn.add_qdisc("eth0", cfg).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Per-VQ parameterization is not modelled
///
/// Setting an individual VQ's RED thresholds (the
/// `tc qdisc change … gred limit … min … max … avpkt … bandwidth … DP …`
/// form) requires computing the RED stab table the kernel demands under
/// `TCA_GRED_STAB`. The library does not currently model that table (the
/// plain [`RedConfig`] sidesteps it too). `parse_params` therefore
/// rejects per-VQ tokens with a clear not-modelled error rather than
/// emitting a message the kernel would refuse. Tracked as a follow-up
/// under the #115 coverage epic.
#[derive(Debug, Clone, Default)]
pub struct GredConfig {
    /// Number of virtual queues / drop precedences (`DPs`, 1..=16).
    pub virtual_queues: Option<u32>,
    /// Default virtual queue (`def_DP`).
    pub default_vq: Option<u32>,
    /// Enable GRIO (RIO-like priority dropping).
    pub grio: bool,
    /// Global queue limit in bytes (`TCA_GRED_LIMIT`).
    pub limit: Option<u32>,
    /// Mark rather than drop ECN-capable packets (#820).
    pub ecn: bool,
    /// Drop above the maximum threshold, ECN-capable or not (#820).
    pub harddrop: bool,
}

impl GredConfig {
    /// Create a new GRED setup configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of virtual queues / drop precedences (1..=16).
    pub fn virtual_queues(mut self, dps: u32) -> Self {
        self.virtual_queues = Some(dps);
        self
    }

    /// Set the default virtual queue.
    pub fn default_vq(mut self, dp: u32) -> Self {
        self.default_vq = Some(dp);
        self
    }

    /// Enable or disable GRIO (RIO-like priority dropping).
    pub fn grio(mut self, enable: bool) -> Self {
        self.grio = enable;
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable hard drop.
    pub fn harddrop(mut self, enable: bool) -> Self {
        self.harddrop = enable;
        self
    }

    /// Set the global queue limit in bytes.
    pub fn limit(mut self, bytes: crate::util::Bytes) -> Self {
        self.limit = Some(bytes.as_u32_saturating());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style gred params slice into a typed `GredConfig`.
    ///
    /// Recognised tokens (setup phase):
    ///
    /// - `setup` — optional leading keyword (tc(8) accepts it; ignored).
    /// - `vqs <n>` (or `DPs`) — number of virtual queues (1..=16).
    /// - `default <dp>` — default virtual queue.
    /// - `grio` / `nogrio` — GRIO flag pair.
    /// - `limit <bytes>` — global queue limit (tc-style size).
    /// - `ecn`, `harddrop` — the setup's flags (#820).
    ///
    /// **Not modelled by `GredConfig`** (returns `Error::invalid_message`):
    /// the per-VQ RED tokens `min`/`max`/`avpkt`/`burst`/`bandwidth`/`DP`/
    /// `probability`/`prio`. Per-VQ parameterization needs
    /// the RED stab probability table the kernel requires under
    /// `TCA_GRED_STAB`; configure VQs via a hand-rolled `MessageBuilder`
    /// until that lands.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("gred: `{key}` requires a value")))
            };
            match key {
                "setup" => {
                    // tc(8) leading keyword; the setup fields follow.
                    i += 1;
                }
                // tc-gred(8) says `vqs`; `DPs` is its older word (#820).
                "vqs" | "DPs" | "dps" => {
                    let s = need_value()?;
                    let n: u32 = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "gred: invalid DPs `{s}` (expected 1..=16)"
                        ))
                    })?;
                    if n == 0 || n > super::types::tc::qdisc::gred::MAX_DPS {
                        return Err(Error::invalid_message(format!(
                            "gred: DPs `{n}` out of range (1..=16)"
                        )));
                    }
                    cfg.virtual_queues = Some(n);
                    i += 2;
                }
                "default" => {
                    let s = need_value()?;
                    let dp: u32 = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "gred: invalid default `{s}` (expected unsigned integer)"
                        ))
                    })?;
                    cfg.default_vq = Some(dp);
                    i += 2;
                }
                "grio" => {
                    cfg.grio = true;
                    i += 1;
                }
                "nogrio" => {
                    cfg.grio = false;
                    i += 1;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "harddrop" => {
                    cfg.harddrop = true;
                    i += 1;
                }
                "limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "gred: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    let val: u32 = bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("gred: limit `{s}` exceeds u32"))
                    })?;
                    cfg.limit = Some(val);
                    i += 2;
                }
                "min" | "max" | "avpkt" | "burst" | "bandwidth" | "DP" | "probability" | "prio" => {
                    return Err(Error::invalid_message(format!(
                        "gred: per-VQ token `{key}` is not modelled by GredConfig — \
                         per-VQ RED parameterization needs the TCA_GRED_STAB table; \
                         use setup mode (DPs/default/grio) or a hand-rolled MessageBuilder"
                    )));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "gred: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for GredConfig {
    fn kind(&self) -> &'static str {
        "gred"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::gred;

        // Setup message: tc_gred_sopt under TCA_GRED_DPS. The kernel
        // requires DPs to install the virtual-queue table; default to a
        // single VQ if the caller only set a limit.
        let sopt = gred::TcGredSopt {
            dps: self.virtual_queues.unwrap_or(1),
            def_dp: self.default_vq.unwrap_or(0),
            grio: u8::from(self.grio),
            flags: (u8::from(self.ecn) * super::types::tc::qdisc::red::TC_RED_ECN as u8)
                | (u8::from(self.harddrop) * super::types::tc::qdisc::red::TC_RED_HARDDROP as u8),
            pad1: 0,
        };
        builder.append_attr(gred::TCA_GRED_DPS, sopt.as_bytes());

        if let Some(limit) = self.limit {
            builder.append_attr_u32(gred::TCA_GRED_LIMIT, limit);
        }

        Ok(())
    }
}

// ============================================================================
// PieConfig
// ============================================================================

/// PIE (Proportional Integral controller-Enhanced) qdisc configuration.
///
/// PIE is an AQM algorithm that achieves low latency and high throughput.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::PieConfig;
/// use nlink::Packets;
/// use std::time::Duration;
///
/// let config = PieConfig::new()
///     .target(Duration::from_millis(15))
///     .limit(Packets::new(1000))
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PieConfig {
    /// Target delay.
    pub target: Option<Duration>,
    /// Queue limit in packets.
    pub limit: Option<crate::util::Packets>,
    /// Probability update interval.
    pub tupdate: Option<Duration>,
    /// Alpha parameter (P controller).
    pub alpha: Option<u32>,
    /// Beta parameter (I controller).
    pub beta: Option<u32>,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Estimate the drop probability from the dequeue rate, not from
    /// timestamps (#820).
    pub dq_rate_estimator: bool,
    /// Use byte mode instead of packet mode.
    pub bytemode: bool,
}

impl Default for PieConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PieConfig {
    /// Create a new PIE configuration builder.
    pub fn new() -> Self {
        Self {
            target: None,
            limit: None,
            tupdate: None,
            alpha: None,
            beta: None,
            ecn: false,
            bytemode: false,
            dq_rate_estimator: false,
        }
    }

    /// Set the target delay (default: 15ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the probability update interval.
    pub fn tupdate(mut self, interval: Duration) -> Self {
        self.tupdate = Some(interval);
        self
    }

    /// Set the alpha parameter.
    pub fn alpha(mut self, alpha: u32) -> Self {
        self.alpha = Some(alpha);
        self
    }

    /// Set the beta parameter.
    pub fn beta(mut self, beta: u32) -> Self {
        self.beta = Some(beta);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable byte mode.
    pub fn bytemode(mut self, enable: bool) -> Self {
        self.bytemode = enable;
        self
    }

    /// Enable or disable the dequeue-rate estimator.
    pub fn dq_rate_estimator(mut self, enable: bool) -> Self {
        self.dq_rate_estimator = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style pie params slice into a typed `PieConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `target <time>` — target delay (e.g. `15ms`).
    /// - `limit <packets>` — queue limit.
    /// - `tupdate <time>` — probability update interval.
    /// - `alpha <n>` — P-controller alpha parameter.
    /// - `beta <n>` — I-controller beta parameter.
    /// - `ecn` / `noecn` — ECN marking flag pair.
    /// - `bytemode` / `nobytemode` — byte-vs-packet mode pair.
    /// - `dq_rate_estimator` / `no_dq_rate_estimator` (#820).
    ///
    /// Stricter than the legacy parser (which doesn't recognise pie
    /// at all): unknown tokens, missing values, and unparseable
    /// time/integer values return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("pie: `{key}` requires a value")))
            };
            match key {
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "pie: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "limit" => {
                    let s = need_value()?;
                    cfg.limit =
                        Some(s.parse().map_err(|_| {
                            Error::invalid_message(format!("pie: invalid limit `{s}`"))
                        })?);
                    i += 2;
                }
                "tupdate" => {
                    let s = need_value()?;
                    cfg.tupdate = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "pie: invalid tupdate `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "alpha" => {
                    let s = need_value()?;
                    cfg.alpha =
                        Some(s.parse().map_err(|_| {
                            Error::invalid_message(format!("pie: invalid alpha `{s}`"))
                        })?);
                    i += 2;
                }
                "beta" => {
                    let s = need_value()?;
                    cfg.beta =
                        Some(s.parse().map_err(|_| {
                            Error::invalid_message(format!("pie: invalid beta `{s}`"))
                        })?);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "bytemode" => {
                    cfg.bytemode = true;
                    i += 1;
                }
                "nobytemode" => {
                    cfg.bytemode = false;
                    i += 1;
                }
                "dq_rate_estimator" | "no_dq_rate_estimator" => {
                    cfg.dq_rate_estimator = key == "dq_rate_estimator";
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "pie: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for PieConfig {
    fn kind(&self) -> &'static str {
        "pie"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::pie;

        if let Some(target) = self.target {
            builder.append_attr_u32(pie::TCA_PIE_TARGET, target.as_micros() as u32);
        }
        if let Some(limit) = self.limit {
            builder.append_attr_u32(pie::TCA_PIE_LIMIT, limit.as_u32());
        }
        if let Some(tupdate) = self.tupdate {
            builder.append_attr_u32(pie::TCA_PIE_TUPDATE, tupdate.as_micros() as u32);
        }
        if let Some(alpha) = self.alpha {
            builder.append_attr_u32(pie::TCA_PIE_ALPHA, alpha);
        }
        if let Some(beta) = self.beta {
            builder.append_attr_u32(pie::TCA_PIE_BETA, beta);
        }
        // Written whether on or off: both default off, and `pie_change`
        // keeps what it has when the attribute is absent, so a replace that
        // only ever sent "on" could never turn either off (#488).
        builder.append_attr_u32(pie::TCA_PIE_ECN, u32::from(self.ecn));
        builder.append_attr_u32(pie::TCA_PIE_BYTEMODE, u32::from(self.bytemode));
        builder.append_attr_u32(pie::TCA_PIE_DQ_RATE_ESTIMATOR, u32::from(self.dq_rate_estimator));

        Ok(())
    }
}

// ============================================================================
// FqPieConfig
// ============================================================================

/// FQ-PIE (Flow Queue PIE) qdisc configuration.
///
/// Mainline since Linux 5.6 (Mar 2020). Combines `fq_codel`'s per-flow
/// hashing with PIE's proportional-integral AQM: each flow gets its
/// own queue, and PIE controls the per-queue drop probability based on
/// queueing delay.
///
/// Practically: a fairer alternative to `pie` for shared links where
/// elephant flows would otherwise crowd out interactive ones.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::FqPieConfig;
/// use nlink::Packets;
/// use nlink::{Bytes, Percent};
/// use std::time::Duration;
///
/// let config = FqPieConfig::new()
///     .target(Duration::from_millis(15))
///     .tupdate(Duration::from_millis(15))
///     .limit(Packets::new(10240))
///     .flows(1024)
///     .quantum(Bytes::new(1514))
///     .ecn(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FqPieConfig {
    /// Queue limit in packets.
    pub limit: Option<crate::util::Packets>,
    /// Number of flow buckets (default 1024).
    pub flows: Option<u32>,
    /// Target queueing delay.
    pub target: Option<Duration>,
    /// Drop-probability update interval.
    pub tupdate: Option<Duration>,
    /// Alpha parameter (P controller, weighted scaled).
    pub alpha: Option<u32>,
    /// Beta parameter (I controller, weighted scaled).
    pub beta: Option<u32>,
    /// DRR quantum (bytes per scheduling round).
    pub quantum: Option<crate::util::Bytes>,
    /// Per-qdisc memory limit.
    pub memory_limit: Option<crate::util::Bytes>,
    /// The drop probability up to which a packet is ECN-marked instead of
    /// dropped (kernel default 10 %). A whole percentage: the kernel holds
    /// no fraction of one.
    pub ecn_prob: Option<crate::util::Percent>,
    /// Enable ECN marking.
    pub ecn: bool,
    /// Use byte mode instead of packet mode.
    pub bytemode: bool,
    /// Enable dequeue rate estimator.
    pub dq_rate_estimator: bool,
}

impl Default for FqPieConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FqPieConfig {
    /// Create a new FQ-PIE configuration builder with all options unset.
    pub fn new() -> Self {
        Self {
            limit: None,
            flows: None,
            target: None,
            tupdate: None,
            alpha: None,
            beta: None,
            quantum: None,
            memory_limit: None,
            ecn_prob: None,
            ecn: false,
            bytemode: false,
            dq_rate_estimator: false,
        }
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the number of flow buckets.
    pub fn flows(mut self, n: u32) -> Self {
        self.flows = Some(n);
        self
    }

    /// Set the target queueing delay (default: 15ms).
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the drop-probability update interval.
    pub fn tupdate(mut self, interval: Duration) -> Self {
        self.tupdate = Some(interval);
        self
    }

    /// Set the alpha parameter (P controller).
    pub fn alpha(mut self, alpha: u32) -> Self {
        self.alpha = Some(alpha);
        self
    }

    /// Set the beta parameter (I controller).
    pub fn beta(mut self, beta: u32) -> Self {
        self.beta = Some(beta);
        self
    }

    /// Set the DRR quantum (bytes per scheduling round).
    pub fn quantum(mut self, quantum: crate::util::Bytes) -> Self {
        self.quantum = Some(quantum);
        self
    }

    /// Set the per-qdisc memory limit.
    pub fn memory_limit(mut self, limit: crate::util::Bytes) -> Self {
        self.memory_limit = Some(limit);
        self
    }

    /// Set the drop probability up to which packets are ECN-marked
    /// instead of dropped. A whole percentage; `write_options` refuses a
    /// fraction, which the kernel cannot hold.
    pub fn ecn_prob(mut self, prob: crate::util::Percent) -> Self {
        self.ecn_prob = Some(prob);
        self
    }

    /// Enable or disable ECN marking.
    pub fn ecn(mut self, enable: bool) -> Self {
        self.ecn = enable;
        self
    }

    /// Enable or disable byte mode.
    pub fn bytemode(mut self, enable: bool) -> Self {
        self.bytemode = enable;
        self
    }

    /// Enable or disable the dequeue rate estimator.
    pub fn dq_rate_estimator(mut self, enable: bool) -> Self {
        self.dq_rate_estimator = enable;
        self
    }

    /// Build the configuration (returns self, for API consistency).
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fq_pie params slice into a typed `FqPieConfig`.
    ///
    /// Recognised tokens (any order):
    ///
    /// - `limit <packets>`, `flows <n>`, `alpha <n>`, `beta <n>`
    /// - `target <time>`, `tupdate <time>` — tc-style times (`15ms`)
    /// - `quantum <size>`, `memory_limit <size>` — tc-style sizes
    /// - `ecnprob <percent>` (alias `ecn_prob`) — a whole percentage
    /// - bare toggles: `ecn` / `noecn`, `bytemode` / `nobytemode`,
    ///   `dq_rate_estimator` / `no_dq_rate_estimator`
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// values all return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("fq_pie: `{key}` requires a value"))
                })
            };
            match key {
                "limit" => {
                    let s = need_value()?;
                    cfg.limit = Some(crate::util::Packets::new(
                        crate::util::parse::get_u32(s).map_err(|_| {
                            Error::invalid_message(format!(
                                "fq_pie: invalid limit `{s}` (expected packet count)"
                            ))
                        })?,
                    ));
                    i += 2;
                }
                "flows" => {
                    let s = need_value()?;
                    cfg.flows = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid flows `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "alpha" => {
                    let s = need_value()?;
                    cfg.alpha = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid alpha `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "beta" => {
                    let s = need_value()?;
                    cfg.beta = Some(crate::util::parse::get_u32(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid beta `{s}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid target `{s}` (expected tc-style time like `15ms`)"
                        ))
                    })?);
                    i += 2;
                }
                "tupdate" => {
                    let s = need_value()?;
                    cfg.tupdate = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid tupdate `{s}` (expected tc-style time like `15ms`)"
                        ))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid quantum `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.quantum = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "memory_limit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid memory_limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "ecnprob" | "ecn_prob" => {
                    let s = need_value()?;
                    let prob = s.parse::<crate::util::Percent>().map_err(|_| {
                        Error::invalid_message(format!(
                            "fq_pie: invalid ecnprob `{s}` (expected percent 0-100)"
                        ))
                    })?;
                    if prob.as_percent().fract() != 0.0 {
                        return Err(Error::invalid_message(format!(
                            "fq_pie: ecnprob `{s}` is not a whole percentage"
                        )));
                    }
                    cfg.ecn_prob = Some(prob);
                    i += 2;
                }
                "ecn" => {
                    cfg.ecn = true;
                    i += 1;
                }
                "noecn" => {
                    cfg.ecn = false;
                    i += 1;
                }
                "bytemode" => {
                    cfg.bytemode = true;
                    i += 1;
                }
                "nobytemode" => {
                    cfg.bytemode = false;
                    i += 1;
                }
                "dq_rate_estimator" => {
                    cfg.dq_rate_estimator = true;
                    i += 1;
                }
                "no_dq_rate_estimator" => {
                    cfg.dq_rate_estimator = false;
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "fq_pie: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for FqPieConfig {
    fn kind(&self) -> &'static str {
        "fq_pie"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fq_pie;

        if let Some(limit) = self.limit {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_LIMIT, limit.as_u32());
        }
        if let Some(flows) = self.flows {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_FLOWS, flows);
        }
        if let Some(target) = self.target {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_TARGET, target.as_micros() as u32);
        }
        if let Some(tupdate) = self.tupdate {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_TUPDATE, tupdate.as_micros() as u32);
        }
        if let Some(alpha) = self.alpha {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ALPHA, alpha);
        }
        if let Some(beta) = self.beta {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_BETA, beta);
        }
        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_QUANTUM, quantum.as_u32_saturating());
        }
        if let Some(memory_limit) = self.memory_limit {
            builder.append_attr_u32(
                fq_pie::TCA_FQ_PIE_MEMORY_LIMIT,
                memory_limit.as_u32_saturating(),
            );
        }
        if let Some(prob) = self.ecn_prob {
            // A whole percentage, as tc(8) sends it. This was written as
            // per-mille: 20 % installed 200, which marks at any drop
            // probability (#631).
            let pct = prob.as_percent();
            if pct.fract() != 0.0 {
                return Err(Error::invalid_message(format!(
                    "fq_pie: ecn_prob {prob} is not a whole percentage"
                )));
            }
            builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ECN_PROB, pct as u32);
        }
        // Written whether on or off: all three default off, and
        // `fq_pie_change` keeps what it has when an attribute is absent, so
        // a replace could never turn one off (#488).
        builder.append_attr_u32(fq_pie::TCA_FQ_PIE_ECN, u32::from(self.ecn));
        builder.append_attr_u32(fq_pie::TCA_FQ_PIE_BYTEMODE, u32::from(self.bytemode));
        builder.append_attr_u32(
            fq_pie::TCA_FQ_PIE_DQ_RATE_ESTIMATOR,
            u32::from(self.dq_rate_estimator),
        );

        Ok(())
    }
}

// ============================================================================
// IngressConfig
// ============================================================================

/// Ingress qdisc configuration.
///
/// The ingress qdisc is used for ingress traffic processing and filtering.
/// It's typically used with filters to classify/police incoming traffic.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::IngressConfig;
///
/// // Add ingress qdisc for filtering incoming traffic
/// conn.add_qdisc("eth0", IngressConfig::new()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct IngressConfig;

impl IngressConfig {
    /// Create a new ingress configuration.
    pub fn new() -> Self {
        Self
    }

    /// Parse a tc-style ingress params slice. Ingress takes no
    /// parameters; this method is for symmetry with the typed-units
    /// rollout — empty slice succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::invalid_message(format!(
                "ingress: takes no parameters (got `{token}`)"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for IngressConfig {
    fn kind(&self) -> &'static str {
        "ingress"
    }

    /// `TC_H_INGRESS` — the only parent the kernel accepts here.
    /// `TC_H_CLSACT` is an alias of it.
    fn fixed_parent(&self) -> Option<TcHandle> {
        Some(TcHandle::INGRESS)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // Ingress qdisc has no options
        Ok(())
    }
}

// ============================================================================
// ClsactConfig
// ============================================================================

/// Clsact qdisc configuration.
///
/// The clsact qdisc is similar to ingress but provides both ingress and
/// egress traffic processing. It's commonly used with BPF programs.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::ClsactConfig;
///
/// // Add clsact qdisc for BPF program attachment
/// conn.add_qdisc("eth0", ClsactConfig::new()).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ClsactConfig;

impl ClsactConfig {
    /// Create a new clsact configuration.
    pub fn new() -> Self {
        Self
    }

    /// Parse a tc-style clsact params slice. Clsact takes no
    /// parameters; this method is for symmetry — empty slice
    /// succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::invalid_message(format!(
                "clsact: takes no parameters (got `{token}`)"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for ClsactConfig {
    fn kind(&self) -> &'static str {
        "clsact"
    }

    /// `TC_H_INGRESS` — the only parent the kernel accepts here.
    /// `TC_H_CLSACT` is an alias of it.
    fn fixed_parent(&self) -> Option<TcHandle> {
        Some(TcHandle::INGRESS)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // Clsact qdisc has no options
        Ok(())
    }
}

// ============================================================================
// PfifoConfig
// ============================================================================

/// Pfifo (packet FIFO) qdisc configuration.
///
/// Simple FIFO queueing with a packet-based limit.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::PfifoConfig;
/// use nlink::Packets;
///
/// let config = PfifoConfig::new()
///     .limit(Packets::new(1000))  // 1000 packets
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PfifoConfig {
    /// Queue limit in packets.
    pub limit: crate::util::Packets,
}

impl Default for PfifoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PfifoConfig {
    /// Create a new pfifo configuration builder.
    pub fn new() -> Self {
        Self { limit: crate::util::Packets::new(1000) }
    }

    /// Set the queue limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = packets;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style pfifo params slice into a typed `PfifoConfig`.
    ///
    /// Recognised token:
    ///
    /// - `limit <packets>` — queue limit in packets.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// numbers all return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("pfifo: `limit` requires a value")
                    })?;
                    cfg.limit = crate::util::Packets::new(crate::util::parse::get_u32(s).map_err(
                        |_| {
                            Error::invalid_message(format!(
                                "pfifo: invalid limit `{s}` (expected packet count)"
                            ))
                        },
                    )?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "pfifo: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for PfifoConfig {
    fn kind(&self) -> &'static str {
        "pfifo"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fifo::TcFifoQopt;

        let qopt = TcFifoQopt::new(self.limit.as_u32());
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// BfifoConfig
// ============================================================================

/// Bfifo (byte FIFO) qdisc configuration.
///
/// Simple FIFO queueing with a byte-based limit.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::Bytes;
/// use nlink::netlink::tc::BfifoConfig;
///
/// let config = BfifoConfig::new()
///     .limit(Bytes::kib(100))
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BfifoConfig {
    /// Queue limit in bytes.
    pub limit: u32,
}

impl Default for BfifoConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BfifoConfig {
    /// Create a new bfifo configuration builder.
    pub fn new() -> Self {
        Self {
            limit: 100 * 1024, // 100KB default
        }
    }

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: crate::util::Bytes) -> Self {
        self.limit = bytes.as_u32_saturating();
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style bfifo params slice into a typed `BfifoConfig`.
    ///
    /// Recognised token:
    ///
    /// - `limit <size>` — queue limit as a tc-style size (bytes,
    ///   accepts suffixes like `kb`/`mb`).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// sizes all return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("bfifo: `limit` requires a value")
                    })?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "bfifo: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("bfifo: limit `{s}` exceeds u32 (max ~4GB)"))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "bfifo: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for BfifoConfig {
    fn kind(&self) -> &'static str {
        "bfifo"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::fifo::TcFifoQopt;

        let qopt = TcFifoQopt::new(self.limit);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// CbsConfig (Credit-Based Shaper, IEEE 802.1Qav / AVB / TSN)
// ============================================================================

/// CBS (Credit-Based Shaper) qdisc configuration.
///
/// CBS implements the IEEE 802.1Qav forwarding-and-queuing rules used by
/// AVB / TSN, shaping a traffic class to a reserved bandwidth. It is
/// typically installed as a leaf under `mqprio` on a multi-queue NIC.
///
/// `idleslope`/`sendslope` are in kbit/s; `hicredit`/`locredit` are in
/// bytes (matching tc(8) and the kernel's `struct tc_cbs_qopt`). Set
/// `offload` to hand the shaping to a NIC that implements the Qav
/// shaper in hardware.
///
/// ```no_run
/// use nlink::netlink::tc::CbsConfig;
///
/// // Class A reservation on a 1Gbit link (tc(8) example values).
/// let cfg = CbsConfig::new()
///     .idleslope(98_688)
///     .sendslope(-901_312)
///     .hicredit(153)
///     .locredit(-1_389)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CbsConfig {
    /// Hardware offload flag.
    pub offload: bool,
    /// High credit, in bytes.
    pub hicredit: i32,
    /// Low credit, in bytes.
    pub locredit: i32,
    /// Idle slope, in kbit/s.
    pub idleslope: i32,
    /// Send slope, in kbit/s (typically negative).
    pub sendslope: i32,
}

impl CbsConfig {
    /// Create a new CBS configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable hardware offload.
    pub fn offload(mut self, offload: bool) -> Self {
        self.offload = offload;
        self
    }

    /// Set the high credit (bytes).
    pub fn hicredit(mut self, hicredit: i32) -> Self {
        self.hicredit = hicredit;
        self
    }

    /// Set the low credit (bytes).
    pub fn locredit(mut self, locredit: i32) -> Self {
        self.locredit = locredit;
        self
    }

    /// Set the idle slope (kbit/s).
    pub fn idleslope(mut self, idleslope: i32) -> Self {
        self.idleslope = idleslope;
        self
    }

    /// Set the send slope (kbit/s).
    pub fn sendslope(mut self, sendslope: i32) -> Self {
        self.sendslope = sendslope;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cbs params slice into a typed `CbsConfig`.
    ///
    /// Recognised tokens: `idleslope <kbit>`, `sendslope <kbit>`,
    /// `hicredit <bytes>`, `locredit <bytes>`, `offload <0|1>`.
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("cbs: `{key}` requires a value"))
                })
            };
            let parse_i32 = |s: &str| -> Result<i32> {
                s.parse::<i32>().map_err(|_| {
                    Error::invalid_message(format!(
                        "cbs: invalid {key} `{s}` (expected signed integer)"
                    ))
                })
            };
            match key {
                "idleslope" => {
                    cfg.idleslope = parse_i32(need_value()?)?;
                    i += 2;
                }
                "sendslope" => {
                    cfg.sendslope = parse_i32(need_value()?)?;
                    i += 2;
                }
                "hicredit" => {
                    cfg.hicredit = parse_i32(need_value()?)?;
                    i += 2;
                }
                "locredit" => {
                    cfg.locredit = parse_i32(need_value()?)?;
                    i += 2;
                }
                "offload" => {
                    let s = need_value()?;
                    cfg.offload = match s {
                        "0" | "off" | "false" => false,
                        "1" | "on" | "true" => true,
                        other => {
                            return Err(Error::invalid_message(format!(
                                "cbs: invalid offload `{other}` (expected 0|1)"
                            )));
                        }
                    };
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!("cbs: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CbsConfig {
    fn kind(&self) -> &'static str {
        "cbs"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::cbs::{TCA_CBS_PARMS, TcCbsQopt};

        let qopt = TcCbsQopt {
            offload: u8::from(self.offload),
            _pad: [0; 3],
            hicredit: self.hicredit,
            locredit: self.locredit,
            idleslope: self.idleslope,
            sendslope: self.sendslope,
        };
        builder.append_attr(TCA_CBS_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// SkbprioConfig (SKB priority queue)
// ============================================================================

/// skbprio (SKB priority) qdisc configuration.
///
/// A priority queue that uses the packet's `skb->priority` to drop the
/// lowest-priority packets first when the queue is full. The only knob
/// is the queue-length `limit` (packets).
///
/// ```no_run
/// use nlink::netlink::tc::SkbprioConfig;
/// use nlink::Packets;
///
/// let cfg = SkbprioConfig::new().limit(Packets::new(64)).build();
/// ```
#[derive(Debug, Clone)]
pub struct SkbprioConfig {
    /// Queue length limit in packets.
    pub limit: crate::util::Packets,
}

impl Default for SkbprioConfig {
    fn default() -> Self {
        // Kernel default is 64 packets.
        Self { limit: crate::util::Packets::new(64) }
    }
}

impl SkbprioConfig {
    /// Create a new skbprio configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the queue length limit in packets.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = packets;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style skbprio params slice into a typed
    /// `SkbprioConfig`.
    ///
    /// Recognised tokens: `limit <packets>`. Strict: unknown tokens,
    /// missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("skbprio: `limit` requires a value".to_string())
                    })?;
                    cfg.limit = s.parse().map_err(|_| {
                        Error::invalid_message(format!("skbprio: invalid limit `{s}`"))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "skbprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for SkbprioConfig {
    fn kind(&self) -> &'static str {
        "skbprio"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::skbprio::TcSkbprioQopt;

        let qopt = TcSkbprioQopt::new(self.limit.as_u32());
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// SfbConfig (Stochastic Fair Blue)
// ============================================================================

/// `SFB_MAX_PROB`: an SFB probability's full scale, 1.0.
const SFB_MAX_PROB: u32 = 0xFFFF;

/// SFB (Stochastic Fair Blue) qdisc configuration.
///
/// SFB is a rate-control AQM that uses Bloom-filter accounting to keep
/// per-flow marking/dropping probabilities and rate-limit non-responsive
/// ("inelastic") flows. All fields map directly to `struct tc_sfb_qopt`;
/// `rehash`/`db` are durations (sent as milliseconds).
///
/// ```no_run
/// use nlink::netlink::tc::SfbConfig;
/// use nlink::Packets;
///
/// let cfg = SfbConfig::new().limit(Packets::new(1000)).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SfbConfig {
    /// Max SFB queue length (packets).
    pub limit: Option<crate::util::Packets>,
    /// Rehash interval.
    pub rehash: Option<Duration>,
    /// Double-buffering warmup time (must be < rehash).
    pub db: Option<Duration>,
    /// Max length of qlen_min.
    pub max: Option<u32>,
    /// Target queue length per bin.
    pub target: Option<u32>,
    /// Probability increment (d1).
    pub increment: Option<u32>,
    /// Probability decrement (d2).
    pub decrement: Option<u32>,
    /// Inelastic-flow penalty rate (packets/s).
    pub penalty_rate: Option<u32>,
    /// Inelastic-flow penalty burst.
    pub penalty_burst: Option<u32>,
}

impl SfbConfig {
    /// Create a new SFB configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the max SFB queue length (packets).
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the rehash interval.
    pub fn rehash(mut self, interval: Duration) -> Self {
        self.rehash = Some(interval);
        self
    }

    /// Set the double-buffering warmup time.
    pub fn db(mut self, warmup: Duration) -> Self {
        self.db = Some(warmup);
        self
    }

    /// Set the max length of qlen_min.
    pub fn max(mut self, max: u32) -> Self {
        self.max = Some(max);
        self
    }

    /// Set the target queue length per bin.
    pub fn target(mut self, target: u32) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the probability increment (d1).
    pub fn increment(mut self, increment: u32) -> Self {
        self.increment = Some(increment);
        self
    }

    /// Set the probability decrement (d2).
    pub fn decrement(mut self, decrement: u32) -> Self {
        self.decrement = Some(decrement);
        self
    }

    /// Set the inelastic-flow penalty rate (packets/s).
    pub fn penalty_rate(mut self, rate: u32) -> Self {
        self.penalty_rate = Some(rate);
        self
    }

    /// Set the inelastic-flow penalty burst.
    pub fn penalty_burst(mut self, burst: u32) -> Self {
        self.penalty_burst = Some(burst);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style sfb params slice into a typed `SfbConfig`, as
    /// tc-sfb(8) reads it (#820).
    ///
    /// Recognised tokens: `limit <packets>`, `rehash <ms>`, `db <ms>`,
    /// `max <packets>`, `target <packets>`, `increment <probability>`,
    /// `decrement <probability>`, `penalty_rate <pps>`,
    /// `penalty_burst <n>`. `rehash` and `db` are milliseconds, as tc reads
    /// them; a time with a unit (`10s`) reads too. `increment` and
    /// `decrement` are fractions from 0.0 to 1.0. Strict: unknown tokens,
    /// missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("sfb: `{key}` requires a value"))
                })
            };
            let parse_u32 = |s: &str| tc_unsigned("sfb", key, s);
            // tc reads a bare number as milliseconds (#820).
            let parse_time = |s: &str| -> Result<Duration> {
                if let Ok(ms) = tc_unsigned("sfb", key, s) {
                    return Ok(Duration::from_millis(ms.into()));
                }
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::invalid_message(format!(
                        "sfb: invalid {key} `{s}` (expected milliseconds or a tc-style time)"
                    ))
                })
            };
            // A probability, scaled to SFB_MAX_PROB as tc's get_prob() does.
            let parse_prob = |s: &str| -> Result<u32> {
                match s.parse::<f64>() {
                    Ok(p) if (0.0..=1.0).contains(&p) => Ok((p * f64::from(SFB_MAX_PROB) + 0.5) as u32),
                    _ => Err(Error::invalid_message(format!(
                        "sfb: invalid {key} `{s}` (expected a probability from 0.0 to 1.0)"
                    ))),
                }
            };
            match key {
                "limit" => {
                    cfg.limit = Some(crate::util::Packets::new(parse_u32(need_value()?)?));
                    i += 2;
                }
                "rehash" => {
                    cfg.rehash = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "db" => {
                    cfg.db = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "max" => {
                    cfg.max = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "target" => {
                    cfg.target = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "increment" => {
                    cfg.increment = Some(parse_prob(need_value()?)?);
                    i += 2;
                }
                "decrement" => {
                    cfg.decrement = Some(parse_prob(need_value()?)?);
                    i += 2;
                }
                "penalty_rate" => {
                    cfg.penalty_rate = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "penalty_burst" => {
                    cfg.penalty_burst = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!("sfb: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for SfbConfig {
    fn kind(&self) -> &'static str {
        "sfb"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::sfb::{TCA_SFB_PARMS, TcSfbQopt};

        // What is not set is tc(8)'s default, not 0: the kernel takes the
        // struct as it comes, so a 0 increment never marks and a 0 rehash
        // rehashes on every packet (#820).
        let ms = |d: Duration| d.as_millis() as u32;
        let target = self.target.unwrap_or(0);
        let max = match self.max.unwrap_or(0) {
            0 if target >= 1 => (target * 5 + 1) / 4,
            0 => 25,
            max => max,
        };
        let bin_size = if target == 0 { (max * 4 + 3) / 5 } else { target };
        let qopt = TcSfbQopt {
            rehash_interval: self.rehash.map_or(600 * 1000, ms),
            warmup_time: self.db.map_or(60 * 1000, ms),
            max,
            bin_size,
            increment: self.increment.unwrap_or((SFB_MAX_PROB + 1000) / 2000),
            decrement: self.decrement.unwrap_or((SFB_MAX_PROB + 10000) / 20000),
            limit: self.limit.map_or(0, crate::util::Packets::as_u32),
            penalty_rate: self.penalty_rate.unwrap_or(10),
            penalty_burst: self.penalty_burst.unwrap_or(20),
        };
        builder.append_attr(TCA_SFB_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// MultiqConfig (band-per-tx-queue)
// ============================================================================

/// multiq qdisc configuration.
///
/// multiq creates one band per device tx queue, mapping `skb->priority`
/// to a band so a multi-queue NIC can be driven directly. It is
/// parameterless: the kernel derives the band count from the device's
/// real tx-queue count, so the config writes a zeroed
/// `struct tc_multiq_qopt`.
///
/// ```no_run
/// use nlink::netlink::tc::MultiqConfig;
///
/// let cfg = MultiqConfig::new().build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct MultiqConfig;

impl MultiqConfig {
    /// Create a new multiq configuration.
    pub fn new() -> Self {
        Self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style multiq params slice. multiq takes no
    /// parameters; any token is rejected (strict-parse contract).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(tok) = params.first() {
            return Err(Error::invalid_message(format!(
                "multiq: unexpected token `{tok}` (multiq takes no parameters)"
            )));
        }
        Ok(Self)
    }
}

impl QdiscConfig for MultiqConfig {
    fn kind(&self) -> &'static str {
        "multiq"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::multiq::TcMultiqQopt;

        // Zeroed — the kernel fills bands from the device tx-queue count.
        let qopt = TcMultiqQopt::default();
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// HhfConfig (Heavy-Hitter Filter)
// ============================================================================

/// HHF (Heavy-Hitter Filter) qdisc configuration.
///
/// HHF isolates "heavy-hitter" flows (those sending disproportionately)
/// from the rest, scheduling the two bands with WDRR. Timeouts are
/// durations (sent as microseconds, matching the kernel's
/// `usecs_to_jiffies`).
///
/// ```no_run
/// # use nlink::Bytes;
/// use nlink::netlink::tc::HhfConfig;
/// use nlink::Packets;
///
/// let cfg = HhfConfig::new().limit(Packets::new(1000)).quantum(Bytes::new(1514)).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct HhfConfig {
    /// Backlog limit, in packets.
    pub limit: Option<crate::util::Packets>,
    /// Quantum, in bytes.
    pub quantum: Option<crate::util::Bytes>,
    /// Heavy-hitter flow-table size.
    pub hh_limit: Option<u32>,
    /// Reset timeout.
    pub reset_timeout: Option<Duration>,
    /// Admit bytes threshold.
    pub admit_bytes: Option<crate::util::Bytes>,
    /// Evict timeout.
    pub evict_timeout: Option<Duration>,
    /// Weight of the non-heavy-hitter band.
    pub non_hh_weight: Option<u32>,
}

impl HhfConfig {
    /// Create a new HHF configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the backlog limit (packets).
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Set the quantum (bytes).
    pub fn quantum(mut self, bytes: crate::util::Bytes) -> Self {
        self.quantum = Some(bytes);
        self
    }

    /// Set the heavy-hitter flow-table size.
    pub fn hh_limit(mut self, limit: u32) -> Self {
        self.hh_limit = Some(limit);
        self
    }

    /// Set the reset timeout.
    pub fn reset_timeout(mut self, timeout: Duration) -> Self {
        self.reset_timeout = Some(timeout);
        self
    }

    /// Set the admit-bytes threshold.
    pub fn admit_bytes(mut self, bytes: crate::util::Bytes) -> Self {
        self.admit_bytes = Some(bytes);
        self
    }

    /// Set the evict timeout.
    pub fn evict_timeout(mut self, timeout: Duration) -> Self {
        self.evict_timeout = Some(timeout);
        self
    }

    /// Set the non-heavy-hitter band weight.
    pub fn non_hh_weight(mut self, weight: u32) -> Self {
        self.non_hh_weight = Some(weight);
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style hhf params slice into a typed `HhfConfig`.
    ///
    /// Recognised tokens: `limit <packets>`, `quantum <bytes>`,
    /// `hh_limit <n>`, `reset_timeout <time>`, `admit_bytes <bytes>`,
    /// `evict_timeout <time>`, `non_hh_weight <n>` (or `nonhh_weight`). Strict: unknown
    /// tokens, missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("hhf: `{key}` requires a value"))
                })
            };
            let parse_u32 = |s: &str| -> Result<u32> {
                s.parse::<u32>().map_err(|_| {
                    Error::invalid_message(format!(
                        "hhf: invalid {key} `{s}` (expected unsigned integer)"
                    ))
                })
            };
            let parse_bytes = |s: &str| -> Result<crate::util::Bytes> {
                crate::util::parse::get_size(s)
                    .map(crate::util::Bytes::new)
                    .map_err(|_| {
                        Error::invalid_message(format!(
                            "hhf: invalid {key} `{s}` (expected tc-style size)"
                        ))
                    })
            };
            let parse_time = |s: &str| -> Result<Duration> {
                crate::util::parse::get_time(s).map_err(|_| {
                    Error::invalid_message(format!(
                        "hhf: invalid {key} `{s}` (expected tc-style time)"
                    ))
                })
            };
            match key {
                "limit" => {
                    cfg.limit = Some(crate::util::Packets::new(parse_u32(need_value()?)?));
                    i += 2;
                }
                "quantum" => {
                    cfg.quantum = Some(parse_bytes(need_value()?)?);
                    i += 2;
                }
                "hh_limit" => {
                    cfg.hh_limit = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                "reset_timeout" => {
                    cfg.reset_timeout = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                "admit_bytes" => {
                    cfg.admit_bytes = Some(parse_bytes(need_value()?)?);
                    i += 2;
                }
                "evict_timeout" => {
                    cfg.evict_timeout = Some(parse_time(need_value()?)?);
                    i += 2;
                }
                // tc(8)'s word is non_hh_weight (#820).
                "non_hh_weight" | "nonhh_weight" => {
                    cfg.non_hh_weight = Some(parse_u32(need_value()?)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!("hhf: unknown token `{other}`")));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for HhfConfig {
    fn kind(&self) -> &'static str {
        "hhf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hhf::*;

        if let Some(limit) = self.limit {
            builder.append_attr_u32(TCA_HHF_BACKLOG_LIMIT, limit.as_u32());
        }
        if let Some(q) = self.quantum {
            builder.append_attr_u32(TCA_HHF_QUANTUM, q.as_u32_saturating());
        }
        if let Some(hh) = self.hh_limit {
            builder.append_attr_u32(TCA_HHF_HH_FLOWS_LIMIT, hh);
        }
        if let Some(t) = self.reset_timeout {
            builder.append_attr_u32(TCA_HHF_RESET_TIMEOUT, t.as_micros() as u32);
        }
        if let Some(a) = self.admit_bytes {
            builder.append_attr_u32(TCA_HHF_ADMIT_BYTES, a.as_u32_saturating());
        }
        if let Some(t) = self.evict_timeout {
            builder.append_attr_u32(TCA_HHF_EVICT_TIMEOUT, t.as_micros() as u32);
        }
        if let Some(w) = self.non_hh_weight {
            builder.append_attr_u32(TCA_HHF_NON_HH_WEIGHT, w);
        }
        Ok(())
    }
}

// ============================================================================
// DsmarkConfig (DiffServ marking)
// ============================================================================

/// dsmark (DiffServ marking) qdisc configuration.
///
/// **Deprecated: the kernel retired `sch_dsmark` in Linux 6.8** (together
/// with CBQ and ATM — "net/sched: Retire dsmark qdisc"; its companion
/// classifier `cls_tcindex` went in 6.3). On 6.8 and later every add
/// fails with `ENOENT` / `EOPNOTSUPP` whatever the arguments; the type
/// remains for callers on older kernels and will be removed in a later
/// release (#347).
///
/// dsmark classifies packets into a table of indices, each carrying a
/// DiffServ mask/value applied to the DS field. This config covers the
/// qdisc-level knobs; the per-index `mask`/`value` are class-level
/// (`TCA_DSMARK_MASK`/`VALUE`).
///
/// `indices` is **required**: `dsmark_init` rejects a `TCA_OPTIONS` nest
/// without `TCA_DSMARK_INDICES` with `EINVAL`, and there is no kernel
/// default. A config without it fails in `write_options` with a readable
/// error instead of sending the request the kernel refuses (#347).
///
/// ```no_run
/// # #![allow(deprecated)]
/// use nlink::netlink::tc::DsmarkConfig;
///
/// let cfg = DsmarkConfig::new().indices(64).set_tc_index().build();
/// ```
#[derive(Debug, Clone, Default)]
#[deprecated(
    since = "0.27.0",
    note = "sch_dsmark was removed from the kernel in Linux 6.8; the type will be dropped in a later release — #347"
)]
pub struct DsmarkConfig {
    /// Number of indices (power of two).
    pub indices: Option<u16>,
    /// Default index for unclassified packets.
    pub default_index: Option<u16>,
    /// Derive the class from `skb->tc_index`.
    pub set_tc_index: bool,
}

#[allow(deprecated)]
impl DsmarkConfig {
    /// Create a new dsmark configuration builder. `indices` must be set
    /// before the config can install — see the type docs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of indices (power of two). Required.
    pub fn indices(mut self, indices: u16) -> Self {
        self.indices = Some(indices);
        self
    }

    /// Set the default index.
    pub fn default_index(mut self, index: u16) -> Self {
        self.default_index = Some(index);
        self
    }

    /// Derive the class from `skb->tc_index`.
    pub fn set_tc_index(mut self) -> Self {
        self.set_tc_index = true;
        self
    }

    /// Terminal no-op for builder symmetry.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style dsmark params slice into a typed
    /// `DsmarkConfig`.
    ///
    /// Recognised tokens: `indices <n>` (required), `default_index <n>`,
    /// `set_tc_index`. Strict: unknown tokens, missing values, and
    /// unparseable values all error, as does a missing `indices`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("dsmark: `{key}` requires a value"))
                })
            };
            let parse_u16 = |s: &str| -> Result<u16> {
                s.parse::<u16>().map_err(|_| {
                    Error::invalid_message(format!(
                        "dsmark: invalid {key} `{s}` (expected unsigned integer)"
                    ))
                })
            };
            match key {
                "indices" => {
                    cfg.indices = Some(parse_u16(need_value()?)?);
                    i += 2;
                }
                "default_index" => {
                    cfg.default_index = Some(parse_u16(need_value()?)?);
                    i += 2;
                }
                "set_tc_index" => {
                    cfg.set_tc_index = true;
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "dsmark: unknown token `{other}`"
                    )));
                }
            }
        }
        if cfg.indices.is_none() {
            return Err(Error::invalid_message(
                "dsmark: `indices <n>` is required (dsmark_init rejects options without TCA_DSMARK_INDICES)"
                    .to_string(),
            ));
        }
        Ok(cfg)
    }
}

#[allow(deprecated)]
impl QdiscConfig for DsmarkConfig {
    fn kind(&self) -> &'static str {
        "dsmark"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::dsmark::*;

        // `dsmark_init`: `if (!tb[TCA_DSMARK_INDICES]) goto errout;` —
        // there is no default, so an empty nest is a request the kernel
        // refuses with EINVAL. Say so here instead (#347).
        let Some(indices) = self.indices else {
            return Err(Error::invalid_message(
                "dsmark: indices is required (dsmark_init rejects TCA_OPTIONS without \
                 TCA_DSMARK_INDICES); use DsmarkConfig::new().indices(n)"
                    .to_string(),
            ));
        };
        builder.append_attr_u16(TCA_DSMARK_INDICES, indices);
        if let Some(default_index) = self.default_index {
            builder.append_attr_u16(TCA_DSMARK_DEFAULT_INDEX, default_index);
        }
        if self.set_tc_index {
            builder.append_attr_empty(TCA_DSMARK_SET_TC_INDEX);
        }
        Ok(())
    }
}

// ============================================================================
// DrrConfig (Deficit Round Robin)
// ============================================================================

/// DRR (Deficit Round Robin) qdisc configuration.
///
/// DRR is a classful qdisc that implements the Deficit Round Robin algorithm
/// for fair bandwidth distribution among classes. Each class gets a quantum
/// of bytes to send per round.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::DrrConfig;
///
/// // Create DRR qdisc
/// let config = DrrConfig::new().build();
///
/// // DRR carries no options of its own, so the handle goes on the request.
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), config)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrrConfig {}

impl Default for DrrConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DrrConfig {
    /// Create a new DRR configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style drr params slice. DRR's *qdisc* level takes
    /// no parameters (the per-class `quantum` lives on `DrrClassConfig`,
    /// not here); this method is for symmetry — empty slice succeeds,
    /// anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::invalid_message(format!(
                "drr: qdisc takes no parameters (got `{token}`); per-class quantum belongs on DrrClassConfig"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for DrrConfig {
    fn kind(&self) -> &'static str {
        "drr"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // DRR qdisc has no options, only classes have options
        Ok(())
    }
}

// ============================================================================
// QfqConfig (Quick Fair Queueing)
// ============================================================================

/// QFQ (Quick Fair Queueing) qdisc configuration.
///
/// QFQ is a classful qdisc that provides O(1) fair scheduling with weights.
/// It is faster than DRR for large numbers of classes.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::QfqConfig;
///
/// // Create QFQ qdisc
/// let config = QfqConfig::new().build();
///
/// // QFQ carries no options of its own, so the handle goes on the request.
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), config)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QfqConfig {}

impl Default for QfqConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl QfqConfig {
    /// Create a new QFQ configuration builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style qfq params slice. QFQ's *qdisc* level takes
    /// no parameters (the per-class `weight` and `lmax` live on
    /// `QfqClassConfig`); empty slice succeeds, anything else errors.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if let Some(token) = params.first() {
            return Err(Error::invalid_message(format!(
                "qfq: qdisc takes no parameters (got `{token}`); per-class weight/lmax belongs on QfqClassConfig"
            )));
        }
        Ok(Self::new())
    }
}

impl QdiscConfig for QfqConfig {
    fn kind(&self) -> &'static str {
        "qfq"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // QFQ qdisc has no options, only classes have options
        Ok(())
    }
}

// ============================================================================
// CakeConfig
// ============================================================================

/// CAKE diffserv mode (priority bands by DSCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeDiffserv {
    /// 3 tins (default for typical home gateways).
    Diffserv3,
    /// 4 tins.
    Diffserv4,
    /// 8 tins (maximum granularity).
    Diffserv8,
    /// 1 tin (no DSCP differentiation).
    Besteffort,
    /// Per-IP-precedence prioritization.
    Precedence,
}

/// CAKE flow isolation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeFlowMode {
    /// No flow isolation.
    Flowblind,
    /// Per source-IP.
    Srchost,
    /// Per destination-IP.
    Dsthost,
    /// Per host pair (src+dst combined).
    Hosts,
    /// Per 5-tuple flow.
    Flows,
    /// Hierarchical: dual-isolate on src host, then per-flow.
    DualSrchost,
    /// Hierarchical: dual-isolate on dst host, then per-flow.
    DualDsthost,
    /// Triple isolation: src-host + dst-host + flow.
    Triple,
}

/// tc-cake(8)'s link framing keywords: the ATM mode each sets, the bytes it
/// adds to the overhead, and the mpu it sets (`q_cake.c`).
const CAKE_FRAMINGS: [(&str, Option<CakeAtmMode>, i32, Option<u32>); 13] = [
    ("ipoa-vcmux", Some(CakeAtmMode::Atm), 8, None),
    ("ipoa-llcsnap", Some(CakeAtmMode::Atm), 16, None),
    ("bridged-vcmux", Some(CakeAtmMode::Atm), 24, None),
    ("bridged-llcsnap", Some(CakeAtmMode::Atm), 32, None),
    ("pppoa-vcmux", Some(CakeAtmMode::Atm), 10, None),
    ("pppoa-llc", Some(CakeAtmMode::Atm), 14, None),
    ("pppoe-vcmux", Some(CakeAtmMode::Atm), 32, None),
    ("pppoe-llcsnap", Some(CakeAtmMode::Atm), 40, None),
    ("pppoe-ptm", Some(CakeAtmMode::Ptm), 30, None),
    ("bridged-ptm", Some(CakeAtmMode::Ptm), 22, None),
    ("ethernet", None, 38, Some(84)),
    ("ether-vlan", None, 4, None),
    ("docsis", Some(CakeAtmMode::None), 18, Some(64)),
];

/// CAKE ATM/PTM overhead compensation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeAtmMode {
    /// No overhead compensation.
    None,
    /// ATM (53-byte cells, 5-byte header).
    Atm,
    /// PTM (G.992.3-style).
    Ptm,
}

/// CAKE ACK filtering mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CakeAckFilter {
    /// No ACK filtering.
    Disabled,
    /// Conservative ACK filtering.
    Filter,
    /// Aggressive ACK filtering (drops more redundant ACKs).
    Aggressive,
}

/// CAKE (Common Applications Kept Enhanced) qdisc configuration.
///
/// The most-used modern AQM qdisc on real-world deployments —
/// OpenWrt's default and the bufferbloat.net community recommendation.
/// Combines a token-bucket shaper, fair queueing, and CoDel-style AQM
/// in a single self-tuning qdisc.
///
/// This is the typed builder mirroring the rest of the qdisc lineup.
/// (The legacy string-args `tc/options/cake.rs` interface was
/// removed in 0.15.0; the typed builder is the only public API.
/// Construct it via `CakeConfig::new()` + fluent setters, or via
/// `CakeConfig::parse_params(&["bandwidth", "100mbit", ...])`
/// per the [`ParseParams`](crate::ParseParams) contract.)
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::{CakeConfig, CakeFlowMode, CakeDiffserv};
/// use nlink::Rate;
/// use std::time::Duration;
///
/// let config = CakeConfig::new()
///     .bandwidth(Rate::mbit(100))
///     .rtt(Duration::from_millis(80))
///     .flow_mode(CakeFlowMode::Triple)
///     .diffserv_mode(CakeDiffserv::Diffserv4)
///     .nat(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CakeConfig {
    /// Bandwidth shaping limit. `None` = unlimited (let cake autorate).
    pub bandwidth: Option<crate::util::Rate>,
    /// Estimated round-trip time. Unless [`target`](Self::target) is set,
    /// a twentieth of it is sent as the target too, as tc(8) does (#635).
    pub rtt: Option<Duration>,
    /// Explicit CoDel target delay (overrides RTT-derived default).
    pub target: Option<Duration>,
    /// Per-packet overhead compensation in bytes (can be negative).
    pub overhead: Option<i32>,
    /// Minimum packet unit (size to charge for sub-MPU packets).
    pub mpu: Option<u32>,
    /// Per-qdisc memory limit.
    pub memory_limit: Option<crate::util::Bytes>,
    /// fwmark mask used for tin classification.
    pub fwmark: Option<u32>,
    /// Diffserv tin layout.
    pub diffserv_mode: Option<CakeDiffserv>,
    /// Flow isolation mode.
    pub flow_mode: Option<CakeFlowMode>,
    /// ATM/PTM cell-overhead compensation.
    pub atm_mode: Option<CakeAtmMode>,
    /// ACK filtering mode.
    pub ack_filter: Option<CakeAckFilter>,
    /// Enable autorate-ingress (estimate bandwidth from observed flow).
    /// This flag and the four below are sent whether on or off, so a replace
    /// turns one off; the kernel keeps a flag it is not sent (#635).
    pub autorate: bool,
    /// Enable NAT mode (rewrite addresses for hash classification).
    pub nat: bool,
    /// Disable overhead compensation entirely (raw mode).
    pub raw: bool,
    /// Enable DSCP washing (clear DSCP on egress).
    pub wash: bool,
    /// Treat as ingress qdisc (use IFB for inbound shaping).
    pub ingress: bool,
    /// Split GSO super-segments before queueing. On by default, as in the
    /// kernel; it was off here and never sent, so `no-split-gso` had no
    /// effect (#635).
    pub split_gso: bool,
}

impl Default for CakeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl CakeConfig {
    /// Create a new CAKE configuration builder with all options unset.
    pub fn new() -> Self {
        Self {
            bandwidth: None,
            rtt: None,
            target: None,
            overhead: None,
            mpu: None,
            memory_limit: None,
            fwmark: None,
            diffserv_mode: None,
            flow_mode: None,
            atm_mode: None,
            ack_filter: None,
            autorate: false,
            nat: false,
            raw: false,
            wash: false,
            ingress: false,
            split_gso: true,
        }
    }

    /// Set the bandwidth shaping limit.
    pub fn bandwidth(mut self, rate: crate::util::Rate) -> Self {
        self.bandwidth = Some(rate);
        self
    }

    /// Mark the qdisc as unlimited (no shaping).
    ///
    /// Equivalent to `bandwidth(Rate::ZERO)` — the kernel encodes
    /// bandwidth=0 as the unlimited sentinel.
    pub fn unlimited(mut self) -> Self {
        self.bandwidth = Some(crate::util::Rate::ZERO);
        self
    }

    /// Set the estimated round-trip time.
    pub fn rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    /// Set the explicit CoDel target delay.
    pub fn target(mut self, target: Duration) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the per-packet overhead in bytes (can be negative).
    pub fn overhead(mut self, overhead: i32) -> Self {
        self.overhead = Some(overhead);
        self
    }

    /// Set the minimum packet unit.
    pub fn mpu(mut self, mpu: u32) -> Self {
        self.mpu = Some(mpu);
        self
    }

    /// Set the per-qdisc memory limit.
    pub fn memory_limit(mut self, mem: crate::util::Bytes) -> Self {
        self.memory_limit = Some(mem);
        self
    }

    /// Set the fwmark mask used for tin classification.
    pub fn fwmark(mut self, mask: u32) -> Self {
        self.fwmark = Some(mask);
        self
    }

    /// Set the diffserv tin layout.
    pub fn diffserv_mode(mut self, mode: CakeDiffserv) -> Self {
        self.diffserv_mode = Some(mode);
        self
    }

    /// Set the flow isolation mode.
    pub fn flow_mode(mut self, mode: CakeFlowMode) -> Self {
        self.flow_mode = Some(mode);
        self
    }

    /// Set the ATM/PTM overhead compensation mode.
    pub fn atm_mode(mut self, mode: CakeAtmMode) -> Self {
        self.atm_mode = Some(mode);
        self
    }

    /// Set the ACK filtering mode.
    pub fn ack_filter(mut self, mode: CakeAckFilter) -> Self {
        self.ack_filter = Some(mode);
        self
    }

    /// Enable autorate-ingress.
    pub fn autorate(mut self, enable: bool) -> Self {
        self.autorate = enable;
        self
    }

    /// Enable NAT mode.
    pub fn nat(mut self, enable: bool) -> Self {
        self.nat = enable;
        self
    }

    /// Disable overhead compensation (raw mode).
    pub fn raw(mut self, enable: bool) -> Self {
        self.raw = enable;
        self
    }

    /// Enable DSCP washing.
    pub fn wash(mut self, enable: bool) -> Self {
        self.wash = enable;
        self
    }

    /// Mark this as an ingress shaper.
    pub fn ingress(mut self, enable: bool) -> Self {
        self.ingress = enable;
        self
    }

    /// Enable or disable GSO super-segment splitting (on by default).
    pub fn split_gso(mut self, enable: bool) -> Self {
        self.split_gso = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cake params slice into a typed `CakeConfig`.
    ///
    /// The link framing keywords (`ethernet`, `docsis`, `ether-vlan`,
    /// `conservative`, `pppoe-ptm`, `bridged-llcsnap`, …) set the overhead,
    /// mpu and ATM mode as tc-cake(8) does: each adds its bytes to the
    /// overhead given so far (#820).
    ///
    /// Recognised tokens with values:
    ///
    /// - `bandwidth <rate>` — set the shaping limit (also: `unlimited`
    ///   as a flag token, equivalent to `bandwidth 0`).
    /// - `rtt <time>` — RTT estimate.
    /// - `target <time>` — explicit CoDel target delay.
    /// - `overhead <bytes>` — per-packet overhead (signed i32).
    /// - `mpu <bytes>` — minimum packet unit.
    /// - `memlimit <bytes>` — per-qdisc memory limit.
    /// - `fwmark <hex>` — fwmark mask for tin classification.
    ///
    /// Flag tokens for diffserv mode: `diffserv3`, `diffserv4`,
    /// `diffserv8`, `besteffort`, `precedence`.
    ///
    /// Flag tokens for flow isolation: `flowblind`, `srchost`,
    /// `dsthost`, `hosts`, `flows`, `dual-srchost`, `dual-dsthost`,
    /// `triple-isolate`.
    ///
    /// Flag tokens for ATM mode: `noatm`, `atm`, `ptm`.
    ///
    /// Flag tokens for ACK filter: `no-ack-filter`, `ack-filter`,
    /// `ack-filter-aggressive`.
    ///
    /// Boolean flag tokens (with their negations where applicable):
    /// `raw`, `nat` / `nonat`, `wash` / `nowash`, `ingress` /
    /// `egress`, `split-gso` / `no-split-gso`, `autorate-ingress`,
    /// `unlimited`.
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rate / time / size / integer values all return
    /// `Error::invalid_message`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::CakeConfig;
    /// let cfg = CakeConfig::parse_params(&[
    ///     "bandwidth", "100mbit",
    ///     "rtt", "20ms",
    ///     "diffserv4", "triple-isolate",
    ///     "ack-filter", "wash",
    /// ])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("cake: `{key}` requires a value")))
            };
            // tc-cake(8)'s link framings (#820): each adds its bytes to the
            // overhead so far, and may set the ATM mode and the mpu.
            if let Some(&(_, atm, add, mpu)) = CAKE_FRAMINGS.iter().find(|(name, ..)| *name == key) {
                if let Some(atm) = atm {
                    cfg.atm_mode = Some(atm);
                }
                cfg.overhead = Some(cfg.overhead.unwrap_or(0) + add);
                if let Some(mpu) = mpu {
                    cfg.mpu = Some(mpu);
                }
                i += 1;
                continue;
            }
            match key {
                // A whole ATM cell plus its framing: a safe overestimate.
                "conservative" => {
                    cfg.atm_mode = Some(CakeAtmMode::Atm);
                    cfg.overhead = Some(48);
                    i += 1;
                }
                // Deprecated in tc; it does nothing there either.
                "via-ethernet" => i += 1,
                // Value tokens.
                "bandwidth" => {
                    let s = need_value()?;
                    cfg.bandwidth = Some(crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid bandwidth `{s}` (expected tc-style rate like `100mbit`)"
                        ))
                    })?);
                    i += 2;
                }
                "rtt" => {
                    let s = need_value()?;
                    cfg.rtt = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid rtt `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "target" => {
                    let s = need_value()?;
                    cfg.target = Some(crate::util::parse::get_time(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid target `{s}` (expected tc-style time)"
                        ))
                    })?);
                    i += 2;
                }
                "overhead" => {
                    let s = need_value()?;
                    cfg.overhead = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid overhead `{s}` (expected signed integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "mpu" => {
                    let s = need_value()?;
                    cfg.mpu = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid mpu `{s}` (expected unsigned integer bytes)"
                        ))
                    })?);
                    i += 2;
                }
                "memlimit" => {
                    let s = need_value()?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid memlimit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.memory_limit = Some(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "fwmark" => {
                    let s = need_value()?;
                    let trimmed = s.strip_prefix("0x").unwrap_or(s);
                    cfg.fwmark = Some(u32::from_str_radix(trimmed, 16).map_err(|_| {
                        Error::invalid_message(format!(
                            "cake: invalid fwmark `{s}` (expected hex u32)"
                        ))
                    })?);
                    i += 2;
                }
                // Diffserv flag tokens.
                "diffserv3" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv3);
                    i += 1;
                }
                "diffserv4" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv4);
                    i += 1;
                }
                "diffserv8" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Diffserv8);
                    i += 1;
                }
                "besteffort" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Besteffort);
                    i += 1;
                }
                "precedence" => {
                    cfg.diffserv_mode = Some(CakeDiffserv::Precedence);
                    i += 1;
                }
                // Flow-mode flag tokens.
                "flowblind" => {
                    cfg.flow_mode = Some(CakeFlowMode::Flowblind);
                    i += 1;
                }
                "srchost" => {
                    cfg.flow_mode = Some(CakeFlowMode::Srchost);
                    i += 1;
                }
                "dsthost" => {
                    cfg.flow_mode = Some(CakeFlowMode::Dsthost);
                    i += 1;
                }
                "hosts" => {
                    cfg.flow_mode = Some(CakeFlowMode::Hosts);
                    i += 1;
                }
                "flows" => {
                    cfg.flow_mode = Some(CakeFlowMode::Flows);
                    i += 1;
                }
                "dual-srchost" => {
                    cfg.flow_mode = Some(CakeFlowMode::DualSrchost);
                    i += 1;
                }
                "dual-dsthost" => {
                    cfg.flow_mode = Some(CakeFlowMode::DualDsthost);
                    i += 1;
                }
                "triple-isolate" => {
                    cfg.flow_mode = Some(CakeFlowMode::Triple);
                    i += 1;
                }
                // ATM mode flag tokens.
                "noatm" => {
                    cfg.atm_mode = Some(CakeAtmMode::None);
                    i += 1;
                }
                "atm" => {
                    cfg.atm_mode = Some(CakeAtmMode::Atm);
                    i += 1;
                }
                "ptm" => {
                    cfg.atm_mode = Some(CakeAtmMode::Ptm);
                    i += 1;
                }
                // ACK filter flag tokens.
                "no-ack-filter" => {
                    cfg.ack_filter = Some(CakeAckFilter::Disabled);
                    i += 1;
                }
                "ack-filter" => {
                    cfg.ack_filter = Some(CakeAckFilter::Filter);
                    i += 1;
                }
                "ack-filter-aggressive" => {
                    cfg.ack_filter = Some(CakeAckFilter::Aggressive);
                    i += 1;
                }
                // Boolean flag tokens.
                // As tc(8): no overhead and no ATM framing, and the
                // kernel told to ignore what a link layer would add (#820).
                "raw" => {
                    cfg.raw = true;
                    cfg.overhead = Some(0);
                    cfg.atm_mode = Some(CakeAtmMode::None);
                    i += 1;
                }
                "nat" => {
                    cfg.nat = true;
                    i += 1;
                }
                "nonat" => {
                    cfg.nat = false;
                    i += 1;
                }
                "wash" => {
                    cfg.wash = true;
                    i += 1;
                }
                "nowash" => {
                    cfg.wash = false;
                    i += 1;
                }
                "ingress" => {
                    cfg.ingress = true;
                    i += 1;
                }
                "egress" => {
                    cfg.ingress = false;
                    i += 1;
                }
                "split-gso" => {
                    cfg.split_gso = true;
                    i += 1;
                }
                "no-split-gso" => {
                    cfg.split_gso = false;
                    i += 1;
                }
                "autorate-ingress" => {
                    cfg.autorate = true;
                    i += 1;
                }
                "unlimited" => {
                    cfg.bandwidth = Some(crate::util::Rate::ZERO);
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "cake: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for CakeConfig {
    fn kind(&self) -> &'static str {
        "cake"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::cake::*;

        if let Some(bw) = self.bandwidth {
            builder.append_attr_u64(TCA_CAKE_BASE_RATE64, bw.as_bytes_per_sec());
        }
        let us = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
        if let Some(rtt) = self.rtt {
            builder.append_attr_u32(TCA_CAKE_RTT, us(rtt));
        }
        // tc(8) sends a twentieth of the RTT as the target with every
        // `rtt`, and has no `target` of its own; without it the kernel
        // kept 5 ms whatever the RTT (#635).
        let target = self
            .target
            .map(us)
            .or_else(|| self.rtt.map(|rtt| (us(rtt) / 20).max(1)));
        if let Some(target) = target {
            builder.append_attr_u32(TCA_CAKE_TARGET, target);
        }
        if let Some(overhead) = self.overhead {
            builder.append_attr(TCA_CAKE_OVERHEAD, &overhead.to_ne_bytes());
        }
        if let Some(mpu) = self.mpu {
            builder.append_attr_u32(TCA_CAKE_MPU, mpu);
        }
        if let Some(mem) = self.memory_limit {
            builder.append_attr_u32(TCA_CAKE_MEMORY, mem.as_u32_saturating());
        }
        if let Some(mask) = self.fwmark {
            builder.append_attr_u32(TCA_CAKE_FWMARK, mask);
        }
        if let Some(mode) = self.diffserv_mode {
            let v = match mode {
                CakeDiffserv::Diffserv3 => CAKE_DIFFSERV_DIFFSERV3,
                CakeDiffserv::Diffserv4 => CAKE_DIFFSERV_DIFFSERV4,
                CakeDiffserv::Diffserv8 => CAKE_DIFFSERV_DIFFSERV8,
                CakeDiffserv::Besteffort => CAKE_DIFFSERV_BESTEFFORT,
                CakeDiffserv::Precedence => CAKE_DIFFSERV_PRECEDENCE,
            };
            builder.append_attr_u32(TCA_CAKE_DIFFSERV_MODE, v);
        }
        if let Some(mode) = self.flow_mode {
            let v = match mode {
                CakeFlowMode::Flowblind => CAKE_FLOW_NONE,
                CakeFlowMode::Srchost => CAKE_FLOW_SRC_IP,
                CakeFlowMode::Dsthost => CAKE_FLOW_DST_IP,
                CakeFlowMode::Hosts => CAKE_FLOW_HOSTS,
                CakeFlowMode::Flows => CAKE_FLOW_FLOWS,
                CakeFlowMode::DualSrchost => CAKE_FLOW_DUAL_SRC,
                CakeFlowMode::DualDsthost => CAKE_FLOW_DUAL_DST,
                CakeFlowMode::Triple => CAKE_FLOW_TRIPLE,
            };
            builder.append_attr_u32(TCA_CAKE_FLOW_MODE, v);
        }
        if let Some(mode) = self.atm_mode {
            let v = match mode {
                CakeAtmMode::None => CAKE_ATM_NONE,
                CakeAtmMode::Atm => CAKE_ATM_ATM,
                CakeAtmMode::Ptm => CAKE_ATM_PTM,
            };
            builder.append_attr_u32(TCA_CAKE_ATM, v);
        }
        if let Some(mode) = self.ack_filter {
            let v = match mode {
                CakeAckFilter::Disabled => CAKE_ACK_NONE,
                CakeAckFilter::Filter => CAKE_ACK_FILTER,
                CakeAckFilter::Aggressive => CAKE_ACK_AGGRESSIVE,
            };
            builder.append_attr_u32(TCA_CAKE_ACK_FILTER, v);
        }
        // The flags are sent whether on or off: `cake_change` keeps one it
        // is not sent, so a replace could never turn one off, and
        // `split_gso`, on in the kernel by default, could not be turned off
        // at all (#635). `raw` is the exception: the kernel reads only the
        // attribute's presence, and turns raw mode off with an overhead.
        builder.append_attr_u32(TCA_CAKE_AUTORATE, u32::from(self.autorate));
        builder.append_attr_u32(TCA_CAKE_NAT, u32::from(self.nat));
        if self.raw {
            builder.append_attr_u32(TCA_CAKE_RAW, 1);
        }
        builder.append_attr_u32(TCA_CAKE_WASH, u32::from(self.wash));
        builder.append_attr_u32(TCA_CAKE_INGRESS, u32::from(self.ingress));
        builder.append_attr_u32(TCA_CAKE_SPLIT_GSO, u32::from(self.split_gso));
        Ok(())
    }
}

// ============================================================================
// PlugConfig (Plug/Unplug qdisc)
// ============================================================================

/// Plug qdisc configuration.
///
/// The plug qdisc allows buffering packets and releasing them on demand.
/// This is useful for checkpoint/restore, debugging, or controlled packet release.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::PlugConfig;
///
/// // Create plug qdisc with a 10000-byte limit
/// let config = PlugConfig::new()
///     .limit(nlink::Bytes::new(10000))
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
///
/// // Installing the qdisc starts buffering immediately.
/// conn.plug_release_one("eth0", TcHandle::ROOT).await?;        // let this epoch out
/// conn.plug_buffer("eth0", TcHandle::ROOT).await?;             // start a new one
/// conn.plug_release_indefinite("eth0", TcHandle::ROOT).await?; // stop buffering
/// # Ok(())
/// # }
/// ```
///
/// Those three methods did not exist. The doc example named
/// `plug_buffer` and `plug_release_one` and neither appeared anywhere in
/// the workspace, while `write_options` emitted only `TCQ_PLUG_LIMIT` —
/// so there was no way to send `BUFFER`, `RELEASE_ONE` or
/// `RELEASE_INDEFINITE` at all. Since installing a plug qdisc **starts
/// buffering immediately**, the library let you stall an interface with
/// no library-side way to unstall it (#276).
#[derive(Debug, Clone)]
pub struct PlugConfig {
    /// Initial limit in bytes.
    ///
    /// `None` leaves the choice to the kernel: `plug_init` sizes the
    /// buffer as the device's `txqueuelen × MTU` when the request carries
    /// no `TCA_OPTIONS` at all — which is what `None` sends (#327). That
    /// is the `tc qdisc add ... plug` default.
    ///
    /// **`limit(0)` is not "kernel default"; it is a blackhole.**
    /// `plug_enqueue` admits a packet only while `backlog + len <= limit`,
    /// so a zero limit drops every packet while the qdisc looks installed
    /// and healthy (measured: 3 pings, `0b 0p` backlog, 4 dropped).
    pub limit: Option<u32>,
}

impl Default for PlugConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PlugConfig {
    /// Create a new plug configuration builder.
    pub fn new() -> Self {
        Self { limit: None }
    }

    /// Set the queue limit in bytes.
    pub fn limit(mut self, bytes: crate::util::Bytes) -> Self {
        self.limit = Some(bytes.as_u32_saturating());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style plug params slice into a typed `PlugConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `limit <bytes>` — initial buffer limit.
    ///
    /// Unknown tokens, missing values, and unparseable sizes return
    /// `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "limit" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("plug: `limit` requires a value")
                    })?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "plug: invalid limit `{s}` (expected tc-style size)"
                        ))
                    })?;
                    cfg.limit = Some(bytes.try_into().map_err(|_| {
                        Error::invalid_message(format!("plug: limit `{s}` exceeds u32"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "plug: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// A plug action, as a `QdiscConfig` so it can ride the ordinary
/// `change_qdisc` path. `tc qdisc change ... plug release_one` is the
/// same request: `RTM_NEWQDISC` on the existing handle with a
/// `tc_plug_qopt` carrying the action.
#[derive(Debug, Clone, Copy)]
struct PlugAction(i32, u32);

impl QdiscConfig for PlugAction {
    fn kind(&self) -> &'static str {
        "plug"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::plug::TcPlugQopt;

        builder.append(&TcPlugQopt::new(self.0, self.1));
        Ok(())
    }
}

impl QdiscConfig for PlugConfig {
    fn kind(&self) -> &'static str {
        "plug"
    }

    /// No limit, no `TCA_OPTIONS`. An empty nest is not the same thing:
    /// `plug_init` checks `nla_len(opt) < sizeof(struct tc_plug_qopt)`
    /// and returns `EINVAL`, so `PlugConfig::new().build()` could not
    /// install a plug at all until the nest was omitted (#327).
    fn has_options(&self) -> bool {
        self.limit.is_some()
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::plug::TcPlugQopt;

        if let Some(limit) = self.limit {
            let qopt = TcPlugQopt::limit(limit);
            builder.append(&qopt);
        }
        Ok(())
    }
}

/// `queues` as tc(8)'s mqprio and taprio read it (#820): up to 16
/// `count@offset` pairs, to the first word that is not one. `i` is at
/// `queues` and is left past what was read.
fn read_queues(kind: &str, params: &[&str], i: &mut usize) -> Result<Vec<(u16, u16)>> {
    let mut queues = Vec::new();
    while queues.len() < 16 {
        let Some((count, offset)) = params.get(*i + 1 + queues.len()).and_then(|s| s.split_once('@')) else {
            break;
        };
        let pair = count.parse::<u16>().ok().zip(offset.parse::<u16>().ok()).ok_or_else(|| {
            Error::invalid_message(format!("{kind}: invalid queues `{count}@{offset}` (expected count@offset)"))
        })?;
        queues.push(pair);
    }
    if queues.is_empty() {
        return Err(Error::invalid_message(format!("{kind}: `queues` requires at least one count@offset")));
    }
    *i += 1 + queues.len();
    Ok(queues)
}

/// A `map` as tc(8)'s mqprio and taprio read it: up to 16 traffic classes,
/// to the first word that is not one, the rest 0. `i` is at `map` and is
/// left past what was read.
fn read_prio_tc_map(kind: &str, params: &[&str], i: &mut usize) -> Result<[u8; 16]> {
    let mut map = [0u8; 16];
    let mut n = 0;
    while n < 16 {
        let Some(tc) = params.get(*i + 1 + n).and_then(|s| s.parse::<u8>().ok()) else { break };
        map[n] = tc;
        n += 1;
    }
    if n == 0 {
        return Err(Error::invalid_message(format!("{kind}: `map` requires at least one traffic class")));
    }
    *i += 1 + n;
    Ok(map)
}

// ============================================================================
// MqprioConfig (Multi-Queue Priority)
// ============================================================================

/// MQPRIO (Multi-Queue Priority) qdisc configuration.
///
/// MQPRIO is a qdisc for multi-queue network devices that maps traffic classes
/// to hardware queues. It supports hardware offload for NICs that support it.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::MqprioConfig;
///
/// // Create mqprio with 4 traffic classes and hardware offload
/// let config = MqprioConfig::new()
///     .num_tc(4)
///     .map(&[0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3])
///     .hw_offload(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MqprioConfig {
    /// Number of traffic classes.
    pub num_tc: u8,
    /// Priority to traffic class mapping.
    pub prio_tc_map: [u8; 16],
    /// Enable hardware offload.
    pub hw: bool,
    /// Queue count for each traffic class.
    pub count: [u16; 16],
    /// Queue offset for each traffic class.
    pub offset: [u16; 16],
}

impl Default for MqprioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MqprioConfig {
    /// Create a new mqprio configuration builder.
    pub fn new() -> Self {
        Self {
            num_tc: 8,
            prio_tc_map: [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 1, 1, 3, 3, 3, 3],
            hw: true,
            count: [0; 16],
            offset: [0; 16],
        }
    }

    /// Set the number of traffic classes (1-16).
    pub fn num_tc(mut self, num_tc: u8) -> Self {
        self.num_tc = num_tc.min(16);
        self
    }

    /// Set the priority to traffic class mapping.
    ///
    /// The array maps Linux priority (0-15) to traffic class (0-num_tc-1).
    pub fn map(mut self, map: &[u8]) -> Self {
        for (i, &tc) in map.iter().enumerate().take(16) {
            self.prio_tc_map[i] = tc;
        }
        self
    }

    /// Enable or disable hardware offload.
    pub fn hw_offload(mut self, enable: bool) -> Self {
        self.hw = enable;
        self
    }

    /// Set queue configuration for traffic classes.
    ///
    /// Each entry is (count, offset) specifying number of queues and starting queue.
    pub fn queues(mut self, queues: &[(u16, u16)]) -> Self {
        for (i, &(c, o)) in queues.iter().enumerate().take(16) {
            self.count[i] = c;
            self.offset[i] = o;
        }
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style mqprio params slice into a typed `MqprioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `num_tc <n>` — number of traffic classes (1-16).
    /// - `map <P0> <P1> ...` — up to 16 priority-to-tc mappings, the
    ///   rest 0, as tc(8) reads them (#820).
    /// - `queues <count@offset> ...` — up to 16 queue ranges (#820).
    /// - `hw 1` / `hw 0` (tc(8)'s form), or `hw` / `nohw` — hardware offload.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "num_tc" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("mqprio: `num_tc` requires a value")
                    })?;
                    let n: u8 = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "mqprio: invalid num_tc `{s}` (expected 1-16)"
                        ))
                    })?;
                    if !(1..=16).contains(&n) {
                        return Err(Error::invalid_message(format!(
                            "mqprio: num_tc `{n}` out of range (1-16)"
                        )));
                    }
                    cfg = cfg.num_tc(n);
                    i += 2;
                }
                "map" => {
                    // As tc(8) reads it (#820): up to 16 classes, to the
                    // first word that is not one; the rest are 0.
                    cfg.prio_tc_map = read_prio_tc_map("mqprio", params, &mut i)?;
                }
                // tc(8) writes `hw 1` or `hw 0` (#820); a bare `hw` is on.
                "hw" => match params.get(i + 1) {
                    Some(&("0" | "1")) => {
                        cfg.hw = params[i + 1] == "1";
                        i += 2;
                    }
                    _ => {
                        cfg.hw = true;
                        i += 1;
                    }
                },
                "nohw" => {
                    cfg.hw = false;
                    i += 1;
                }
                "queues" => {
                    let queues = read_queues("mqprio", params, &mut i)?;
                    cfg = cfg.queues(&queues);
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "mqprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for MqprioConfig {
    fn kind(&self) -> &'static str {
        "mqprio"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::mqprio::TcMqprioQopt;

        let mut qopt = TcMqprioQopt::new()
            .with_num_tc(self.num_tc)
            .with_hw(self.hw);

        qopt.prio_tc_map = self.prio_tc_map;
        qopt.count = self.count;
        qopt.offset = self.offset;

        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// TaprioConfig (Time Aware Priority)
// ============================================================================

/// TAPRIO (Time Aware Priority) qdisc configuration.
///
/// TAPRIO implements IEEE 802.1Qbv Time-Aware Shaping for Time-Sensitive
/// Networking (TSN). It uses a time-based gate control list to schedule
/// traffic classes.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::{TaprioConfig, TaprioSchedEntry};
///
/// // Create TAPRIO with a simple schedule
/// let config = TaprioConfig::new()
///     .num_tc(2)
///     .map(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
///     .queues(&[(1, 0), (1, 1)])
///     .clockid(libc::CLOCK_TAI)
///     .base_time(0)
///     .cycle_time(1_000_000) // 1ms cycle
///     .entry(TaprioSchedEntry::set_gates(0x1, 500_000))  // TC0 open 500us
///     .entry(TaprioSchedEntry::set_gates(0x2, 500_000))  // TC1 open 500us
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TaprioConfig {
    /// Number of traffic classes.
    pub num_tc: u8,
    /// Priority to traffic class mapping.
    pub prio_tc_map: [u8; 16],
    /// Queue count for each traffic class.
    pub count: [u16; 16],
    /// Queue offset for each traffic class.
    pub offset: [u16; 16],
    /// Clock ID (e.g., CLOCK_TAI).
    pub clockid: i32,
    /// Base time for schedule (nanoseconds since epoch).
    pub base_time: i64,
    /// Cycle time in nanoseconds.
    pub cycle_time: i64,
    /// Cycle time extension in nanoseconds.
    pub cycle_time_extension: i64,
    /// Schedule entries.
    pub entries: Vec<super::types::tc::qdisc::taprio::TaprioSchedEntry>,
    /// Flags (TXTIME_ASSIST, FULL_OFFLOAD).
    pub flags: u32,
    /// TX time delay in nanoseconds.
    pub txtime_delay: u32,
}

impl Default for TaprioConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TaprioConfig {
    /// Create a new TAPRIO configuration builder.
    pub fn new() -> Self {
        Self {
            num_tc: 0,
            prio_tc_map: [0; 16],
            count: [0; 16],
            offset: [0; 16],
            clockid: -1,
            base_time: 0,
            cycle_time: 0,
            cycle_time_extension: 0,
            entries: Vec::new(),
            flags: 0,
            txtime_delay: 0,
        }
    }

    /// Set the number of traffic classes.
    pub fn num_tc(mut self, num_tc: u8) -> Self {
        self.num_tc = num_tc.min(16);
        self
    }

    /// Set the priority to traffic class mapping.
    pub fn map(mut self, map: &[u8]) -> Self {
        for (i, &tc) in map.iter().enumerate().take(16) {
            self.prio_tc_map[i] = tc;
        }
        self
    }

    /// Set queue configuration for traffic classes.
    pub fn queues(mut self, queues: &[(u16, u16)]) -> Self {
        for (i, &(c, o)) in queues.iter().enumerate().take(16) {
            self.count[i] = c;
            self.offset[i] = o;
        }
        self
    }

    /// Set the clock ID (e.g., libc::CLOCK_TAI).
    pub fn clockid(mut self, clockid: i32) -> Self {
        self.clockid = clockid;
        self
    }

    /// Set the base time in nanoseconds since epoch.
    pub fn base_time(mut self, base_time: i64) -> Self {
        self.base_time = base_time;
        self
    }

    /// Set the cycle time in nanoseconds.
    pub fn cycle_time(mut self, cycle_time: i64) -> Self {
        self.cycle_time = cycle_time;
        self
    }

    /// Set the cycle time extension in nanoseconds.
    pub fn cycle_time_extension(mut self, extension: i64) -> Self {
        self.cycle_time_extension = extension;
        self
    }

    /// Add a schedule entry.
    pub fn entry(mut self, entry: super::types::tc::qdisc::taprio::TaprioSchedEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Enable TXTIME assist mode.
    pub fn txtime_assist(mut self, enable: bool) -> Self {
        use super::types::tc::qdisc::taprio::TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        if enable {
            self.flags |= TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        } else {
            self.flags &= !TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
        }
        self
    }

    /// Enable full offload mode.
    pub fn full_offload(mut self, enable: bool) -> Self {
        use super::types::tc::qdisc::taprio::TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        if enable {
            self.flags |= TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        } else {
            self.flags &= !TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
        }
        self
    }

    /// Set the TX time delay in nanoseconds.
    pub fn txtime_delay(mut self, delay: u32) -> Self {
        self.txtime_delay = delay;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style taprio params slice into a typed
    /// `TaprioConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `num_tc <n>` — number of traffic classes (1-16).
    /// - `map <P0> ...` — up to 16 priority-to-tc mappings, the rest 0.
    /// - `clockid <id>` — clock ID (named like `CLOCK_TAI` or bare
    ///   integer).
    /// - `base-time <ns>` — base time, ns since epoch (i64).
    /// - `cycle-time <ns>` — cycle time (i64).
    /// - `cycle-time-extension <ns>` — cycle time extension (i64).
    /// - `txtime-delay <ns>` — TX time delay (u32).
    /// - `txtime-assist` / `notxtime-assist` — flag pair.
    /// - `full-offload` / `nofull-offload` — flag pair.
    /// - `flags <hex>` — raw flags u32 (alternative to the named
    ///   flag pairs above; replaces, doesn't OR).
    /// - `sched-entry <CMD> <gate-mask-hex> <interval-ns>` —
    ///   schedule entry. CMD is `SET` (alias `S`),
    ///   `SET_AND_HOLD` (`HOLD`/`H`), or `SET_AND_RELEASE`
    ///   (`RELEASE`/`R`). Multiple `sched-entry` tokens append.
    ///
    /// - `map`, `queues` — as [`MqprioConfig::parse_params`] reads them
    ///   (#820).
    ///
    /// **Net new CLI capability**: the legacy qdisc dispatcher
    /// silently swallowed `taprio`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::netlink::types::tc::qdisc::taprio::{
            TAPRIO_ATTR_FLAG_FULL_OFFLOAD, TAPRIO_ATTR_FLAG_TXTIME_ASSIST,
        };
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("taprio: `{key}` requires a value"))
                })
            };
            match key {
                "num_tc" => {
                    let s = need_value()?;
                    let n: u8 = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "taprio: invalid num_tc `{s}` (expected 1-16)"
                        ))
                    })?;
                    if !(1..=16).contains(&n) {
                        return Err(Error::invalid_message(format!(
                            "taprio: num_tc `{n}` out of range (1-16)"
                        )));
                    }
                    cfg = cfg.num_tc(n);
                    i += 2;
                }
                "map" => {
                    // As tc(8) reads it (#820): up to 16 classes, to the
                    // first word that is not one; the rest are 0.
                    cfg.prio_tc_map = read_prio_tc_map("taprio", params, &mut i)?;
                }
                "clockid" => {
                    let s = need_value()?;
                    cfg.clockid = parse_etf_clockid(s).map_err(|e| {
                        // Re-label the error from the etf helper to taprio context.
                        Error::invalid_message(format!("taprio: invalid clockid `{s}` ({e})"))
                    })?;
                    i += 2;
                }
                "base-time" => {
                    let s = need_value()?;
                    cfg.base_time = s.parse().map_err(|_| {
                        Error::invalid_message(format!("taprio: invalid base-time `{s}`"))
                    })?;
                    i += 2;
                }
                "cycle-time" => {
                    let s = need_value()?;
                    cfg.cycle_time = s.parse().map_err(|_| {
                        Error::invalid_message(format!("taprio: invalid cycle-time `{s}`"))
                    })?;
                    i += 2;
                }
                "cycle-time-extension" => {
                    let s = need_value()?;
                    cfg.cycle_time_extension = s.parse().map_err(|_| {
                        Error::invalid_message(format!("taprio: invalid cycle-time-extension `{s}`"))
                    })?;
                    i += 2;
                }
                "txtime-delay" => {
                    let s = need_value()?;
                    cfg.txtime_delay = s.parse().map_err(|_| {
                        Error::invalid_message(format!("taprio: invalid txtime-delay `{s}`"))
                    })?;
                    i += 2;
                }
                "txtime-assist" => {
                    cfg.flags |= TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
                    i += 1;
                }
                "notxtime-assist" => {
                    cfg.flags &= !TAPRIO_ATTR_FLAG_TXTIME_ASSIST;
                    i += 1;
                }
                "full-offload" => {
                    cfg.flags |= TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
                    i += 1;
                }
                "nofull-offload" => {
                    cfg.flags &= !TAPRIO_ATTR_FLAG_FULL_OFFLOAD;
                    i += 1;
                }
                "flags" => {
                    let s = need_value()?;
                    let trimmed = s.strip_prefix("0x").unwrap_or(s);
                    cfg.flags = u32::from_str_radix(trimmed, 16)
                        .or_else(|_| s.parse::<u32>())
                        .map_err(|_| {
                            Error::invalid_message(format!(
                                "taprio: invalid flags `{s}` (expected hex u32 or decimal)"
                            ))
                        })?;
                    i += 2;
                }
                "sched-entry" => {
                    let cmd_s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                ,
                        )
                    })?;
                    let mask_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                ,
                        )
                    })?;
                    let interval_s = params.get(i + 3).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "taprio: `sched-entry` needs <cmd> <gate-mask-hex> <interval-ns>"
                                ,
                        )
                    })?;
                    let entry = parse_taprio_sched_entry(cmd_s, mask_s, interval_s)?;
                    cfg.entries.push(entry);
                    i += 4;
                }
                "queues" => {
                    let queues = read_queues("taprio", params, &mut i)?;
                    cfg = cfg.queues(&queues);
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "taprio: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Parse a single taprio sched-entry triple (cmd, gate-mask-hex,
/// interval-ns).
fn parse_taprio_sched_entry(
    cmd_s: &str,
    mask_s: &str,
    interval_s: &str,
) -> Result<super::types::tc::qdisc::taprio::TaprioSchedEntry> {
    use super::types::tc::qdisc::taprio::{
        TC_TAPRIO_CMD_SET_AND_HOLD, TC_TAPRIO_CMD_SET_AND_RELEASE, TC_TAPRIO_CMD_SET_GATES,
        TaprioSchedEntry,
    };
    let cmd = match cmd_s {
        "SET" | "S" | "set" | "s" => TC_TAPRIO_CMD_SET_GATES,
        "SET_AND_HOLD" | "HOLD" | "H" | "hold" | "h" => TC_TAPRIO_CMD_SET_AND_HOLD,
        "SET_AND_RELEASE" | "RELEASE" | "R" | "release" | "r" => TC_TAPRIO_CMD_SET_AND_RELEASE,
        other => {
            return Err(Error::invalid_message(format!(
                "taprio: invalid sched-entry cmd `{other}` (expected SET / HOLD / RELEASE)"
            )));
        }
    };
    let mask_trimmed = mask_s.strip_prefix("0x").unwrap_or(mask_s);
    let mask = u32::from_str_radix(mask_trimmed, 16).map_err(|_| {
        Error::invalid_message(format!(
            "taprio: invalid sched-entry gate mask `{mask_s}` (expected hex)"
        ))
    })?;
    let interval = interval_s.parse::<u32>().map_err(|_| {
        Error::invalid_message(format!(
            "taprio: invalid sched-entry interval `{interval_s}` (expected u32 ns)"
        ))
    })?;
    Ok(TaprioSchedEntry::new(cmd, mask, interval))
}

impl QdiscConfig for TaprioConfig {
    fn kind(&self) -> &'static str {
        "taprio"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::{mqprio::TcMqprioQopt, taprio::*};

        // Write the mqprio-style priomap
        let mut qopt = TcMqprioQopt::new().with_num_tc(self.num_tc).with_hw(false);
        qopt.prio_tc_map = self.prio_tc_map;
        qopt.count = self.count;
        qopt.offset = self.offset;
        builder.append_attr(TCA_TAPRIO_ATTR_PRIOMAP, qopt.as_bytes());

        // Clock ID
        if self.clockid >= 0 {
            builder.append_attr(TCA_TAPRIO_ATTR_SCHED_CLOCKID, &self.clockid.to_ne_bytes());
        }

        // Base time
        if self.base_time != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_BASE_TIME,
                &self.base_time.to_ne_bytes(),
            );
        }

        // Cycle time
        if self.cycle_time != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME,
                &self.cycle_time.to_ne_bytes(),
            );
        }

        // Cycle time extension
        if self.cycle_time_extension != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION,
                &self.cycle_time_extension.to_ne_bytes(),
            );
        }

        // Flags
        if self.flags != 0 {
            builder.append_attr(TCA_TAPRIO_ATTR_FLAGS, &self.flags.to_ne_bytes());
        }

        // TX time delay
        if self.txtime_delay != 0 {
            builder.append_attr(
                TCA_TAPRIO_ATTR_TXTIME_DELAY,
                &self.txtime_delay.to_ne_bytes(),
            );
        }

        // Schedule entries
        if !self.entries.is_empty() {
            let list_token = builder.nest_start(TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST);
            for (idx, entry) in self.entries.iter().enumerate() {
                // TCA_TAPRIO_SCHED_ENTRY, not the top-level
                // TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY: the kernel skips
                // that, and refuses an empty schedule (#823).
                let entry_token = builder.nest_start(TCA_TAPRIO_SCHED_ENTRY);
                builder.append_attr(TCA_TAPRIO_SCHED_ENTRY_INDEX, &(idx as u32).to_ne_bytes());
                builder.append_attr(TCA_TAPRIO_SCHED_ENTRY_CMD, &[entry.cmd]);
                builder.append_attr(
                    TCA_TAPRIO_SCHED_ENTRY_GATE_MASK,
                    &entry.gate_mask.to_ne_bytes(),
                );
                builder.append_attr(
                    TCA_TAPRIO_SCHED_ENTRY_INTERVAL,
                    &entry.interval.to_ne_bytes(),
                );
                builder.nest_end(entry_token);
            }
            builder.nest_end(list_token);
        }

        Ok(())
    }
}

// ============================================================================
// HfscConfig (Hierarchical Fair Service Curve)
// ============================================================================

/// HFSC (Hierarchical Fair Service Curve) qdisc configuration.
///
/// HFSC is a hierarchical packet scheduler that provides guaranteed bandwidth
/// and delay bounds. It uses service curves to define bandwidth allocations.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::HfscConfig;
///
/// // Create HFSC qdisc with default class 0x10
/// let config = HfscConfig::new()
///     .default_class(0x10)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfscConfig {
    /// Default class for unclassified packets.
    pub default_class: u16,
}

impl Default for HfscConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HfscConfig {
    /// Create a new HFSC configuration builder.
    pub fn new() -> Self {
        Self { default_class: 0 }
    }

    /// Set the default class for unclassified packets.
    pub fn default_class(mut self, classid: u16) -> Self {
        self.default_class = classid;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style hfsc params slice into a typed `HfscConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `default <classid>` — default class for unclassified
    ///   packets. Accepts a tc handle's minor (`10` → `0x10`,
    ///   matching `tc(8)`'s `tc qdisc add ... hfsc default 10`
    ///   convention).
    ///
    /// Unknown tokens, missing values, and unparseable values
    /// return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "default" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("hfsc: `default` requires a value")
                    })?;
                    cfg.default_class = u16::from_str_radix(s, 16).map_err(|_| {
                        Error::invalid_message(format!(
                            "hfsc: invalid default `{s}` (expected hex minor like `10`)"
                        ))
                    })?;
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "hfsc: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

impl QdiscConfig for HfscConfig {
    fn kind(&self) -> &'static str {
        "hfsc"
    }

    /// Classful: `1:` at the root unless a handle is given.
    fn default_handle(&self) -> Option<TcHandle> {
        Some(CLASSFUL_ROOT_HANDLE)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hfsc::TcHfscQopt;

        let qopt = TcHfscQopt::new(self.default_class);
        builder.append(&qopt);
        Ok(())
    }
}

// ============================================================================
// EtfConfig (Earliest TxTime First)
// ============================================================================

/// ETF (Earliest TxTime First) qdisc configuration.
///
/// ETF is a qdisc for time-based transmission scheduling. Packets are
/// transmitted at the exact time specified in the SO_TXTIME socket option.
/// This is useful for Time-Sensitive Networking (TSN) applications.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::EtfConfig;
///
/// // Create ETF with CLOCK_TAI and hardware offload
/// let config = EtfConfig::new()
///     .clockid(libc::CLOCK_TAI)
///     .delta_ns(300000)  // 300us
///     .offload(true)
///     .deadline_mode(true)
///     .build();
///
/// conn.add_qdisc("eth0", config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EtfConfig {
    /// Delta time in nanoseconds.
    pub delta: i32,
    /// Clock ID (e.g., CLOCK_TAI, CLOCK_MONOTONIC).
    pub clockid: i32,
    /// Enable deadline mode.
    pub deadline_mode: bool,
    /// Enable hardware offload.
    pub offload: bool,
    /// Skip socket check.
    pub skip_sock_check: bool,
}

impl Default for EtfConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EtfConfig {
    /// Create a new ETF configuration builder.
    pub fn new() -> Self {
        Self {
            delta: 0,
            clockid: -1, // CLOCKID_INVALID
            deadline_mode: false,
            offload: false,
            skip_sock_check: false,
        }
    }

    /// Set the clock ID (e.g., libc::CLOCK_TAI, libc::CLOCK_MONOTONIC).
    pub fn clockid(mut self, clockid: i32) -> Self {
        self.clockid = clockid;
        self
    }

    /// Set the delta time in nanoseconds.
    ///
    /// This is the time offset from the scheduled transmission time.
    pub fn delta_ns(mut self, delta: i32) -> Self {
        self.delta = delta;
        self
    }

    /// Enable or disable deadline mode.
    ///
    /// In deadline mode, the transmission time is treated as a deadline
    /// rather than an exact time.
    pub fn deadline_mode(mut self, enable: bool) -> Self {
        self.deadline_mode = enable;
        self
    }

    /// Enable or disable hardware offload.
    ///
    /// When enabled, the NIC handles the time-based transmission scheduling.
    pub fn offload(mut self, enable: bool) -> Self {
        self.offload = enable;
        self
    }

    /// Enable or disable socket capability check skip.
    pub fn skip_sock_check(mut self, enable: bool) -> Self {
        self.skip_sock_check = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style etf params slice into a typed `EtfConfig`.
    ///
    /// Recognised tokens:
    ///
    /// - `delta <ns>` — transmission-time delta in nanoseconds
    ///   (signed i32).
    /// - `clockid <id>` — clock ID. Accepts the common names
    ///   `CLOCK_TAI`, `CLOCK_REALTIME`, `CLOCK_MONOTONIC`,
    ///   `CLOCK_BOOTTIME`, `CLOCK_PROCESS_CPUTIME_ID`,
    ///   `CLOCK_THREAD_CPUTIME_ID`, or a bare integer.
    /// - `deadline_mode` / `nodeadline_mode` — flag pair.
    /// - `offload` / `nooffload` — hardware-offload flag pair.
    /// - `skip_sock_check` / `noskip_sock_check` — flag pair.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("etf: `{key}` requires a value")))
            };
            match key {
                "delta" => {
                    let s = need_value()?;
                    cfg.delta = s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "etf: invalid delta `{s}` (expected signed integer ns)"
                        ))
                    })?;
                    i += 2;
                }
                "clockid" => {
                    let s = need_value()?;
                    cfg.clockid = parse_etf_clockid(s)?;
                    i += 2;
                }
                "deadline_mode" => {
                    cfg.deadline_mode = true;
                    i += 1;
                }
                "nodeadline_mode" => {
                    cfg.deadline_mode = false;
                    i += 1;
                }
                "offload" => {
                    cfg.offload = true;
                    i += 1;
                }
                "nooffload" => {
                    cfg.offload = false;
                    i += 1;
                }
                "skip_sock_check" => {
                    cfg.skip_sock_check = true;
                    i += 1;
                }
                "noskip_sock_check" => {
                    cfg.skip_sock_check = false;
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "etf: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

/// Map a clock-ID name to its libc constant; otherwise parse as a
/// bare integer. The named constants come from `<time.h>` and match
/// what `tc(8)` accepts.
fn parse_etf_clockid(s: &str) -> Result<i32> {
    Ok(match s {
        "CLOCK_REALTIME" => libc::CLOCK_REALTIME,
        "CLOCK_MONOTONIC" => libc::CLOCK_MONOTONIC,
        "CLOCK_PROCESS_CPUTIME_ID" => libc::CLOCK_PROCESS_CPUTIME_ID,
        "CLOCK_THREAD_CPUTIME_ID" => libc::CLOCK_THREAD_CPUTIME_ID,
        "CLOCK_BOOTTIME" => libc::CLOCK_BOOTTIME,
        "CLOCK_TAI" => libc::CLOCK_TAI,
        other => other.parse::<i32>().map_err(|_| {
            Error::invalid_message(format!(
                "etf: invalid clockid `{other}` (expected name like CLOCK_TAI or bare integer)"
            ))
        })?,
    })
}

impl QdiscConfig for EtfConfig {
    fn kind(&self) -> &'static str {
        "etf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::etf::{
            TC_ETF_DEADLINE_MODE_ON, TC_ETF_OFFLOAD_ON, TC_ETF_SKIP_SOCK_CHECK, TCA_ETF_PARMS,
            TcEtfQopt,
        };

        let mut flags = 0i32;
        if self.deadline_mode {
            flags |= TC_ETF_DEADLINE_MODE_ON;
        }
        if self.offload {
            flags |= TC_ETF_OFFLOAD_ON;
        }
        if self.skip_sock_check {
            flags |= TC_ETF_SKIP_SOCK_CHECK;
        }

        let qopt = TcEtfQopt {
            delta: self.delta,
            clockid: self.clockid,
            flags,
        };

        builder.append_attr(TCA_ETF_PARMS, qopt.as_bytes());
        Ok(())
    }
}

// ============================================================================
// ClassConfig trait
// ============================================================================

/// Trait for TC class configurations.
///
/// This trait is analogous to `QdiscConfig` but for traffic control classes.
/// Classes are used with classful qdiscs like HTB, HFSC, and DRR.
pub trait ClassConfig: Send + Sync {
    /// Get the class type (e.g., "htb", "hfsc", "drr").
    fn kind(&self) -> &'static str;

    /// Write the class options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}

// ============================================================================
// HtbClassConfig
// ============================================================================

/// HTB class configuration builder.
///
/// Provides a type-safe way to configure HTB classes with compile-time
/// validation and IDE autocompletion.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};
/// use nlink::Rate;
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add HTB qdisc
/// let htb = HtbQdiscConfig::new().default_class(0x30).build();
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb).await?;
///
/// // Add root class (total bandwidth)
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 1),
///     HtbClassConfig::new(Rate::gbit(1))
///         .ceil(Rate::gbit(1))
///         .build()
/// ).await?;
///
/// // Add child class with guaranteed and ceiling rates
/// conn.add_class("eth0", TcHandle::new(1, 1), TcHandle::new(1, 0x10),
///     HtbClassConfig::new(Rate::mbit(100))
///         .ceil(Rate::mbit(500))
///         .prio(1)
///         .build()
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct HtbClassConfig {
    /// Guaranteed rate.
    rate: crate::util::Rate,
    /// Maximum rate (ceil).
    ceil: Option<crate::util::Rate>,
    /// Burst size.
    burst: Option<crate::util::Bytes>,
    /// Ceil burst size.
    cburst: Option<crate::util::Bytes>,
    /// Priority (0-7, lower is higher priority).
    prio: Option<u32>,
    /// Quantum for round-robin.
    quantum: Option<u32>,
    /// MTU for rate calculations.
    mtu: u32,
    /// Minimum packet unit.
    mpu: u16,
    /// Per-packet overhead.
    overhead: u16,
    /// The link layer the rate tables account for (tc(8)'s `linklayer`,
    /// #826).
    linklayer: psched::LinkLayer,
}

impl HtbClassConfig {
    /// Create a new HTB class configuration with the given rate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::HtbClassConfig;
    /// use nlink::Rate;
    /// let config = HtbClassConfig::new(Rate::mbit(100));
    /// // Or parse a tc-style string:
    /// let config = HtbClassConfig::new("100mbit".parse()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(rate: crate::util::Rate) -> Self {
        Self {
            rate,
            ceil: None,
            burst: None,
            cburst: None,
            prio: None,
            quantum: None,
            mtu: 1600,
            mpu: 0,
            overhead: 0,
            linklayer: psched::LinkLayer::Ethernet,
        }
    }

    /// Set the ceiling rate.
    ///
    /// The ceiling rate is the maximum rate the class can use when borrowing
    /// from parent classes.
    pub fn ceil(mut self, ceil: crate::util::Rate) -> Self {
        self.ceil = Some(ceil);
        self
    }

    /// Set the burst size.
    ///
    /// The burst is the amount of data that can be sent at hardware speed
    /// before rate limiting kicks in.
    pub fn burst(mut self, burst: crate::util::Bytes) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set the ceil burst size.
    ///
    /// The cburst is the burst for the ceiling rate.
    pub fn cburst(mut self, cburst: crate::util::Bytes) -> Self {
        self.cburst = Some(cburst);
        self
    }

    /// Set the priority (0-7, lower = higher priority).
    ///
    /// Classes with lower priority values are served first.
    pub fn prio(mut self, prio: u32) -> Self {
        self.prio = Some(prio.min(7));
        self
    }

    /// Set the quantum for round-robin scheduling.
    ///
    /// The quantum determines how many bytes a class can send before
    /// yielding to siblings.
    pub fn quantum(mut self, quantum: u32) -> Self {
        self.quantum = Some(quantum);
        self
    }

    /// Set the MTU for rate table calculations.
    ///
    /// Default is 1600 bytes.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the minimum packet unit.
    ///
    /// Packets smaller than this are treated as this size for rate calculations.
    pub fn mpu(mut self, mpu: u16) -> Self {
        self.mpu = mpu;
        self
    }

    /// Set the per-packet overhead.
    ///
    /// Added to each packet for rate calculations (e.g., for ATM or Ethernet framing).
    pub fn overhead(mut self, overhead: u16) -> Self {
        self.overhead = overhead;
        self
    }

    /// Set the link layer: ATM rounds each packet up to whole 53-byte cells.
    pub fn linklayer(mut self, linklayer: psched::LinkLayer) -> Self {
        self.linklayer = linklayer;
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style HTB class param token slice.
    ///
    /// Accepts the same keywords as `tc class add ... htb`: `rate`,
    /// `ceil`, `burst`/`buffer`/`maxburst`, `cburst`/`cbuffer`/`cmaxburst`,
    /// `prio`, `quantum`, `mtu`, `mpu`, `overhead`. `rate` is required
    /// (matches the kernel and `HtbClassConfig::new`'s contract).
    ///
    /// Strict: unknown tokens, missing values, and unparseable
    /// rates/sizes/integers all return `Error::invalid_message` —
    /// the legacy stringly-typed dispatcher used to silently swallow
    /// unknown tokens, which this replaces.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::util::Rate;
        let mut rate: Option<Rate> = None;
        let mut ceil: Option<Rate> = None;
        let mut burst: Option<crate::util::Bytes> = None;
        let mut cburst: Option<crate::util::Bytes> = None;
        let mut prio: Option<u32> = None;
        let mut quantum: Option<u32> = None;
        let mut mtu: Option<u32> = None;
        let mut mpu: Option<u16> = None;
        let mut overhead: Option<u16> = None;
        let mut linklayer: Option<psched::LinkLayer> = None;

        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            let val = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("htb: `{tok}` requires a value")))
            };
            match tok {
                "rate" => {
                    let v = val()?;
                    rate = Some(v.parse::<Rate>().map_err(|e| {
                        Error::invalid_message(format!("htb: invalid rate `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "ceil" => {
                    let v = val()?;
                    ceil = Some(v.parse::<Rate>().map_err(|e| {
                        Error::invalid_message(format!("htb: invalid ceil `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "burst" | "buffer" | "maxburst" => {
                    let v = val()?;
                    burst = Some(v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::invalid_message(format!("htb: invalid burst `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "cburst" | "cbuffer" | "cmaxburst" => {
                    let v = val()?;
                    cburst = Some(v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::invalid_message(format!("htb: invalid cburst `{v}`: {e}"))
                    })?);
                    i += 2;
                }
                "prio" => {
                    let v = val()?;
                    prio = Some(v.parse::<u32>().map_err(|_| {
                        Error::invalid_message(format!(
                            "htb: invalid prio `{v}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "quantum" => {
                    let v = val()?;
                    let bytes = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::invalid_message(format!("htb: invalid quantum `{v}`: {e}"))
                    })?;
                    quantum = Some(bytes.as_u32_saturating());
                    i += 2;
                }
                "mtu" => {
                    let v = val()?;
                    mtu = Some(v.parse::<u32>().map_err(|_| {
                        Error::invalid_message(format!(
                            "htb: invalid mtu `{v}` (expected unsigned integer)"
                        ))
                    })?);
                    i += 2;
                }
                "mpu" => {
                    let v = val()?;
                    mpu = Some(v.parse::<u16>().map_err(|_| {
                        Error::invalid_message(format!("htb: invalid mpu `{v}` (expected u16)"))
                    })?);
                    i += 2;
                }
                "overhead" => {
                    let v = val()?;
                    overhead = Some(v.parse::<u16>().map_err(|_| {
                        Error::invalid_message(format!("htb: invalid overhead `{v}` (expected u16)"))
                    })?);
                    i += 2;
                }
                "linklayer" => {
                    let v = val()?;
                    linklayer = Some(match v {
                        "ethernet" => psched::LinkLayer::Ethernet,
                        "atm" | "adsl" => psched::LinkLayer::Atm,
                        _ => {
                            return Err(Error::invalid_message(format!(
                                "htb: invalid linklayer `{v}` (expected ethernet, atm or adsl)"
                            )));
                        }
                    });
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "htb: unknown token `{other}` (recognised: rate, ceil, burst, cburst, prio, quantum, mtu, mpu, overhead, linklayer)"
                    )));
                }
            }
        }

        let rate = rate.ok_or_else(|| Error::invalid_message("htb: `rate` is required"))?;
        let mut cfg = HtbClassConfig::new(rate);
        if let Some(c) = ceil {
            cfg = cfg.ceil(c);
        }
        if let Some(b) = burst {
            cfg = cfg.burst(b);
        }
        if let Some(c) = cburst {
            cfg = cfg.cburst(c);
        }
        if let Some(p) = prio {
            cfg = cfg.prio(p);
        }
        if let Some(q) = quantum {
            cfg = cfg.quantum(q);
        }
        if let Some(m) = mtu {
            cfg = cfg.mtu(m);
        }
        if let Some(m) = mpu {
            cfg = cfg.mpu(m);
        }
        if let Some(o) = overhead {
            cfg = cfg.overhead(o);
        }
        if let Some(l) = linklayer {
            cfg = cfg.linklayer(l);
        }
        Ok(cfg)
    }

    /// The class as the tokens [`parse_params`](Self::parse_params)
    /// reads, its inverse (#645). Values left at their defaults are not
    /// written.
    pub fn to_params(&self) -> Result<Vec<String>> {
        let default = Self::new(self.rate);
        let mut out = vec!["rate".to_string(), self.rate.to_string()];
        let mut put = |k: &str, v: String| {
            out.push(k.to_string());
            out.push(v);
        };
        if let Some(c) = self.ceil {
            put("ceil", c.to_string());
        }
        if let Some(b) = self.burst {
            put("burst", b.to_string());
        }
        if let Some(b) = self.cburst {
            put("cburst", b.to_string());
        }
        if let Some(p) = self.prio {
            put("prio", p.to_string());
        }
        if let Some(q) = self.quantum {
            put("quantum", crate::util::Bytes::new(u64::from(q)).to_string());
        }
        if self.mtu != default.mtu {
            put("mtu", self.mtu.to_string());
        }
        if self.mpu != default.mpu {
            put("mpu", self.mpu.to_string());
        }
        if self.overhead != default.overhead {
            put("overhead", self.overhead.to_string());
        }
        match self.linklayer {
            psched::LinkLayer::Ethernet => {}
            psched::LinkLayer::Atm => put("linklayer", "atm".to_string()),
            other => return Err(Error::not_supported(format!("htb: linklayer {other:?} has no token"))),
        }
        Ok(out)
    }
}

impl HtbClassConfig {
    /// The burst this class reads back as, in bytes: the declared one or
    /// the default [`write_options`](ClassConfig::write_options) picks,
    /// through the kernel's tick round trip — what a dump's
    /// [`HtbClassOptions::burst`](super::tc_options::HtbClassOptions::burst)
    /// holds for it.
    /// Rate and ceiling, in bytes per second, as written.
    pub(crate) fn rates_bps(&self) -> (u64, u64) {
        let rate = self.rate.as_bytes_per_sec();
        (rate, self.ceil.map_or(rate, |c| c.as_bytes_per_sec()))
    }

    /// The declared priority, if any.
    pub(crate) fn priority(&self) -> Option<u32> {
        self.prio
    }

    /// The declared quantum, if any; the kernel's (rate / r2q) otherwise,
    /// and not compared (#789).
    pub(crate) fn quantum_declared(&self) -> Option<u32> {
        self.quantum
    }

    /// The mpu and overhead both rate specs carry (#789).
    pub(crate) fn mpu_and_overhead(&self) -> (u16, u16) {
        (self.mpu, self.overhead)
    }

    /// The link layer, as the rate specs carry it.
    pub(crate) fn linklayer_wire(&self) -> u8 {
        self.linklayer as u8
    }

    /// The declared ceil burst as a dump reads it back (through the tick
    /// round trip at the ceil rate), if one is declared; the default the
    /// kernel derives is not compared.
    pub(crate) fn cburst_as_dumped(&self) -> Option<u32> {
        let (_, ceil) = self.rates_bps();
        let cburst = self.cburst?.as_u32_saturating();
        Some(psched::tc_calc_xmitsize(ceil, psched::tc_calc_xmittime(ceil, cburst)))
    }

    pub(crate) fn burst_as_dumped(&self) -> u32 {
        let rate = self.rate.as_bytes_per_sec();
        let burst = self
            .burst
            .map(|b| b.as_u32_saturating())
            .unwrap_or_else(|| (rate / psched::hz()) as u32 + self.mtu);
        psched::tc_calc_xmitsize(rate, psched::tc_calc_xmittime(rate, burst))
    }
}

impl ClassConfig for HtbClassConfig {
    fn kind(&self) -> &'static str {
        "htb"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let cfg = self;
        let rate = cfg.rate.as_bytes_per_sec();
        let ceil = cfg.ceil.unwrap_or(cfg.rate).as_bytes_per_sec();

        // iproute2's get_hz() reads /proc/net/psched and returns 1e9 on any
        // modern kernel — so q_htb.c's `buffer = rate64 / get_hz() + mtu`
        // reduces to `mtu` for every rate below 8 Gbit/s. The old hardcoded
        // hz = 1000 inflated the default burst by rate/1000 bytes (12,500
        // extra at 100 mbit). Keep the formula, source hz correctly (#193).
        let hz = psched::hz();

        let burst = cfg
            .burst
            .map(|b| b.as_u32_saturating())
            .unwrap_or_else(|| (rate / hz) as u32 + cfg.mtu);
        let cburst = cfg
            .cburst
            .map(|b| b.as_u32_saturating())
            .unwrap_or_else(|| (ceil / hz) as u32 + cfg.mtu);

        // sch_htb.c: `cl->buffer = PSCHED_TICKS2NS(hopt->buffer)`. The old
        // code computed microseconds (burst * 1e6 / rate) and labelled them
        // ticks, losing the 15.625 factor — the token bucket landed below one
        // MTU, so no class could ever burst a full-size packet (#193).
        let mut rate_spec = TcRateSpec {
            rate: rate.min(u32::MAX as u64) as u32,
            mpu: cfg.mpu,
            overhead: cfg.overhead,
            ..Default::default()
        };
        let mut ceil_spec = TcRateSpec {
            rate: ceil.min(u32::MAX as u64) as u32,
            mpu: cfg.mpu,
            overhead: cfg.overhead,
            ..Default::default()
        };
        let linklayer = cfg.linklayer;
        let rtab = psched::tc_calc_rtable(&mut rate_spec, rate, cfg.mtu, linklayer);
        let ctab = psched::tc_calc_rtable(&mut ceil_spec, ceil, cfg.mtu, linklayer);

        let opt = htb::TcHtbOpt {
            rate: rate_spec,
            ceil: ceil_spec,
            buffer: psched::tc_calc_xmittime(rate, burst),
            cbuffer: psched::tc_calc_xmittime(ceil, cburst),
            quantum: cfg.quantum.unwrap_or(0),
            prio: cfg.prio.unwrap_or(0),
            ..Default::default()
        };

        // Add 64-bit rate if needed (for rates >= 4 Gbps)
        if rate >= (1u64 << 32) {
            builder.append_attr(htb::TCA_HTB_RATE64, &rate.to_ne_bytes());
        }

        if ceil >= (1u64 << 32) {
            builder.append_attr(htb::TCA_HTB_CEIL64, &ceil.to_ne_bytes());
        }

        // Add the main parameters structure
        builder.append_attr(htb::TCA_HTB_PARMS, opt.as_bytes());

        builder.append_attr(htb::TCA_HTB_RTAB, &rtab);
        builder.append_attr(htb::TCA_HTB_CTAB, &ctab);

        Ok(())
    }
}

// ============================================================================
// HfscClassConfig
// ============================================================================

/// HFSC class configuration builder.
///
/// HFSC (Hierarchical Fair Service Curve) uses three service curves to provide
/// both bandwidth guarantees and latency bounds:
///
/// - **RSC (Real-time Service Curve)**: Guaranteed minimum latency service
/// - **FSC (Fair Service Curve)**: Guaranteed bandwidth over time
/// - **USC (Upper-limit Service Curve)**: Maximum bandwidth limit
///
/// Each curve can be a simple rate or a two-slope curve with an initial burst.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// # use nlink::Rate;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{HfscConfig, HfscClassConfig, TcServiceCurve};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add HFSC qdisc
/// let hfsc = HfscConfig::new().default_class(0x10).build();
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), hfsc).await?;
///
/// // Add root class with link-share curve
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 1),
///     HfscClassConfig::new()
///         .ls_rate(Rate::gbit(1))  // 1 Gbps link-share
///         .build()
/// ).await?;
///
/// // Add real-time class with latency guarantee
/// conn.add_class("eth0", TcHandle::new(1, 1), TcHandle::new(1, 0x10),
///     HfscClassConfig::new()
///         .rt_curve(TcServiceCurve::two_slope(10_000_000, 5000, 1_000_000))
///         .ls_rate(Rate::mbit(100))
///         .build()
/// ).await?;
///
/// // Add best-effort class with upper limit
/// conn.add_class("eth0", TcHandle::new(1, 1), TcHandle::new(1, 0x20),
///     HfscClassConfig::new()
///         .ls_rate(Rate::mbit(50))
///         .ul_rate(Rate::mbit(100))  // Cap at 100 Mbps
///         .build()
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct HfscClassConfig {
    /// Real-time service curve (latency guarantee).
    rsc: Option<TcServiceCurve>,
    /// Fair service curve (bandwidth share).
    fsc: Option<TcServiceCurve>,
    /// Upper-limit service curve (maximum bandwidth).
    usc: Option<TcServiceCurve>,
}

impl HfscClassConfig {
    /// Create a new HFSC class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the real-time service curve (latency guarantee).
    ///
    /// The RSC provides a guaranteed minimum latency service. Packets are
    /// scheduled to meet the delay bound specified by this curve.
    pub fn rt_curve(mut self, curve: TcServiceCurve) -> Self {
        self.rsc = Some(curve);
        self
    }

    /// Set the real-time curve as a simple rate.
    ///
    /// HFSC's `tc_service_curve.m1`/`.m2` are 32-bit fields in the kernel
    /// UAPI. The `Rate` is saturating-cast to `u32` (max ≈4 GB/s ≈ 32 Gbps).
    pub fn rt_rate(mut self, rate: crate::util::Rate) -> Self {
        self.rsc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Set the link-share (fair) service curve.
    ///
    /// The FSC determines the bandwidth share among sibling classes.
    /// This is the most commonly used curve.
    pub fn ls_curve(mut self, curve: TcServiceCurve) -> Self {
        self.fsc = Some(curve);
        self
    }

    /// Set the link-share curve as a simple rate. See [`Self::rt_rate`] for
    /// the 32-bit saturating-cast caveat.
    pub fn ls_rate(mut self, rate: crate::util::Rate) -> Self {
        self.fsc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Set the upper-limit service curve.
    ///
    /// The USC caps the maximum bandwidth a class can use, even when
    /// there's spare bandwidth available.
    pub fn ul_curve(mut self, curve: TcServiceCurve) -> Self {
        self.usc = Some(curve);
        self
    }

    /// Set the upper-limit curve as a simple rate. See [`Self::rt_rate`] for
    /// the 32-bit saturating-cast caveat.
    pub fn ul_rate(mut self, rate: crate::util::Rate) -> Self {
        self.usc = Some(TcServiceCurve::rate(rate.as_u32_bytes_per_sec_saturating()));
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// The real-time, link-sharing and upper-limit curves, as declared.
    pub(crate) fn curves(&self) -> [Option<TcServiceCurve>; 3] {
        [self.rsc, self.fsc, self.usc]
    }

    /// Parse a `tc(8)`-style HFSC class param token slice.
    ///
    /// Each curve is `rt`, `ls`, `ul`, or `sc` (real-time and link-sharing
    /// both), followed by `[m1 <rate> d <time>] m2 <rate>`, or by
    /// `rate <rate>`, which is `m2` alone. `d` is a time (`5ms`, `100us`).
    /// tc(8)'s other form, `[umax <size>] [dmax <time>] rate <rate>`, is
    /// turned into `m1`, `d` and `m2` as tc turns it (#826).
    /// Strict rejection on unknown tokens.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        use crate::util::Rate;
        let mut cfg = HfscClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let kind = params[i];
            if !matches!(kind, "rt" | "ls" | "ul" | "sc") {
                return Err(Error::invalid_message(format!(
                    "hfsc: unknown token `{kind}` (recognised: rt, ls, ul, sc; each followed by \
                     `[m1 <rate> d <time>] m2 <rate>`, `[umax <size>] [dmax <time>] rate <rate>` or `rate <rate>`)"
                )));
            }
            let rate = |key: &str, v: &str| -> Result<u32> {
                v.parse::<Rate>()
                    .map(|r| r.as_u32_bytes_per_sec_saturating())
                    .map_err(|e| Error::invalid_message(format!("hfsc: invalid {key} `{v}`: {e}")))
            };
            let (mut m1, mut d, mut m2) = (None, None, None);
            let (mut umax, mut dmax) = (None, None);
            i += 1;
            while let Some(&key) = params.get(i) {
                if !matches!(key, "m1" | "d" | "m2" | "rate" | "umax" | "dmax") {
                    break;
                }
                let v = params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("hfsc: `{kind} {key}` requires a value"))
                })?;
                match key {
                    "m1" => m1 = Some(rate(key, v)?),
                    "d" | "dmax" => {
                        let t = crate::util::parse::get_time(v).map_err(|e| {
                            Error::invalid_message(format!("hfsc: invalid {key} `{v}`: {e}"))
                        })?;
                        let us = (t.as_nanos() + 500) / 1000;
                        let us = u32::try_from(us).map_err(|_| {
                            Error::invalid_message(format!("hfsc: {key} `{v}` is past u32 microseconds"))
                        })?;
                        if key == "d" {
                            d = Some(us);
                        } else {
                            dmax = Some(us);
                        }
                    }
                    "umax" => {
                        let bytes = crate::util::parse::get_size(v).ok().and_then(|b| u32::try_from(b).ok()).ok_or_else(|| {
                            Error::invalid_message(format!("hfsc: invalid umax `{v}` (expected a size)"))
                        })?;
                        umax = Some(bytes);
                    }
                    _ => m2 = Some(rate(key, v)?),
                }
                i += 2;
            }
            if umax.is_some() || dmax.is_some() {
                if m1.is_some() || d.is_some() {
                    return Err(Error::invalid_message(format!(
                        "hfsc: `{kind}` takes `m1`/`d` or `umax`/`dmax`, not both"
                    )));
                }
                let rate = m2.ok_or_else(|| {
                    Error::invalid_message(format!("hfsc: `{kind} umax`/`dmax` requires `rate <rate>`"))
                })?;
                let (umax, dmax) = (umax.unwrap_or(0), dmax.unwrap_or(0));
                if umax != 0 && dmax == 0 {
                    return Err(Error::invalid_message(format!("hfsc: `{kind} umax` requires `dmax`")));
                }
                // tc's hfsc_get_sc2(): concave when umax/dmax beats the
                // rate, with that slope up to dmax; convex otherwise, flat
                // until dmax - umax/rate.
                let slope = (f64::from(umax) * 1e6 / f64::from(dmax)).ceil();
                if dmax != 0 && slope > f64::from(rate) {
                    m1 = Some(slope as u32);
                    d = Some(dmax);
                } else {
                    m1 = Some(0);
                    let flat = (f64::from(dmax) - f64::from(umax) * 1e6 / f64::from(rate.max(1))).ceil();
                    d = Some(flat.max(0.0) as u32);
                }
            }
            let m2 = m2.ok_or_else(|| {
                Error::invalid_message(format!(
                    "hfsc: `{kind}` requires `m2 <rate>` or `rate <rate>`"
                ))
            })?;
            let curve = TcServiceCurve::new(m1.unwrap_or(0), d.unwrap_or(0), m2);
            cfg = match kind {
                "rt" => cfg.rt_curve(curve),
                "ls" => cfg.ls_curve(curve),
                "ul" => cfg.ul_curve(curve),
                _ => cfg.rt_curve(curve).ls_curve(curve),
            };
        }
        Ok(cfg)
    }

    /// The class as the tokens [`parse_params`](Self::parse_params)
    /// reads, its inverse (#645): `sc` when the real-time and
    /// link-sharing curves are one.
    pub fn to_params(&self) -> Result<Vec<String>> {
        use crate::util::Rate;
        let curve = |kind: &str, c: &TcServiceCurve| {
            let rate = |m: u32| Rate::bytes_per_sec(u64::from(m)).to_string();
            let mut out = vec![kind.to_string()];
            if c.m1 == 0 && c.d == 0 {
                out.extend(["rate".to_string(), rate(c.m2)]);
            } else {
                out.extend([
                    "m1".to_string(),
                    rate(c.m1),
                    "d".to_string(),
                    format!("{}us", c.d),
                    "m2".to_string(),
                    rate(c.m2),
                ]);
            }
            out
        };
        let same = |a: &TcServiceCurve, b: &TcServiceCurve| (a.m1, a.d, a.m2) == (b.m1, b.d, b.m2);
        let mut out = Vec::new();
        match (&self.rsc, &self.fsc) {
            (Some(r), Some(f)) if same(r, f) => out.extend(curve("sc", r)),
            (r, f) => {
                if let Some(r) = r {
                    out.extend(curve("rt", r));
                }
                if let Some(f) = f {
                    out.extend(curve("ls", f));
                }
            }
        }
        if let Some(u) = &self.usc {
            out.extend(curve("ul", u));
        }
        Ok(out)
    }
}

impl ClassConfig for HfscClassConfig {
    fn kind(&self) -> &'static str {
        "hfsc"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::hfsc::{TCA_HFSC_FSC, TCA_HFSC_RSC, TCA_HFSC_USC};

        let cfg = self;

        if let Some(ref rsc) = cfg.rsc {
            builder.append_attr(TCA_HFSC_RSC, rsc.as_bytes());
        }

        if let Some(ref fsc) = cfg.fsc {
            builder.append_attr(TCA_HFSC_FSC, fsc.as_bytes());
        }

        if let Some(ref usc) = cfg.usc {
            builder.append_attr(TCA_HFSC_USC, usc.as_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// DrrClassConfig
// ============================================================================

/// DRR class configuration builder.
///
/// DRR (Deficit Round Robin) is a simple fair queuing algorithm where each
/// class gets a quantum of bytes to send per round. Classes with larger
/// quanta get proportionally more bandwidth.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::Bytes;
/// # use nlink::TcHandle;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{DrrConfig, DrrClassConfig};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add DRR qdisc
/// let drr = DrrConfig::new().build();
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), drr).await?;
///
/// // Add classes with different quanta (bandwidth proportions)
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 1),
///     DrrClassConfig::new()
///         .quantum(Bytes::new(1500))  // 1 packet worth
///         .build()
/// ).await?;
///
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 2),
///     DrrClassConfig::new()
///         .quantum(Bytes::new(3000))  // 2x bandwidth of class 1:1
///         .build()
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct DrrClassConfig {
    /// Quantum in bytes (bandwidth share).
    quantum: Option<crate::util::Bytes>,
}

impl DrrClassConfig {
    /// Create a new DRR class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the quantum.
    ///
    /// The quantum determines how many bytes this class can send per round.
    /// Classes with larger quanta get proportionally more bandwidth.
    /// If not set, defaults to the interface MTU. Saturates at u32::MAX
    /// because the kernel field is 32 bits.
    pub fn quantum(mut self, q: crate::util::Bytes) -> Self {
        self.quantum = Some(q);
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// The declared quantum.
    pub(crate) fn quantum_bytes(&self) -> Option<crate::util::Bytes> {
        self.quantum
    }

    /// Parse a `tc(8)`-style DRR class param token slice.
    ///
    /// DRR class accepts a single optional keyword: `quantum <bytes>`.
    /// Unknown tokens, missing values, and unparseable sizes return
    /// `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = DrrClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            match tok {
                "quantum" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("drr: `quantum` requires a value")
                    })?;
                    let q = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::invalid_message(format!("drr: invalid quantum `{v}`: {e}"))
                    })?;
                    cfg = cfg.quantum(q);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "drr: unknown token `{other}` (recognised: quantum)"
                    )));
                }
            }
        }
        Ok(cfg)
    }

    /// The class as the tokens [`parse_params`](Self::parse_params)
    /// reads, its inverse (#645).
    pub fn to_params(&self) -> Result<Vec<String>> {
        Ok(self
            .quantum
            .map(|q| vec!["quantum".to_string(), q.to_string()])
            .unwrap_or_default())
    }
}

impl ClassConfig for DrrClassConfig {
    fn kind(&self) -> &'static str {
        "drr"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::drr::TCA_DRR_QUANTUM;

        if let Some(quantum) = self.quantum {
            builder.append_attr_u32(TCA_DRR_QUANTUM, quantum.as_u32_saturating());
        }

        Ok(())
    }
}

// ============================================================================
// QfqClassConfig
// ============================================================================

/// QFQ class configuration builder.
///
/// QFQ (Quick Fair Queueing) is similar to DRR but with O(1) complexity
/// for scheduling. Each class has a weight and an optional maximum packet
/// size limit.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::TcHandle;
/// # use nlink::Bytes;
/// use nlink::netlink::{Connection, Route};
/// use nlink::netlink::tc::{QfqConfig, QfqClassConfig};
///
/// let conn = Connection::<Route>::new()?;
///
/// // First add QFQ qdisc
/// let qfq = QfqConfig::new().build();
/// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), qfq).await?;
///
/// // Add classes with different weights
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 1),
///     QfqClassConfig::new()
///         .weight(1)
///         .build()
/// ).await?;
///
/// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 2),
///     QfqClassConfig::new()
///         .weight(2)  // 2x bandwidth of class 1:1
///         .lmax(Bytes::new(9000)) // Max packet size (for jumbo frames)
///         .build()
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct QfqClassConfig {
    /// Weight (bandwidth share).
    weight: Option<u32>,
    /// Maximum packet length.
    lmax: Option<crate::util::Bytes>,
}

impl QfqClassConfig {
    /// Create a new QFQ class configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the weight.
    ///
    /// The weight determines the relative bandwidth share. A class with
    /// weight 2 gets twice the bandwidth of a class with weight 1.
    /// Valid range is 1-1023.
    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight.clamp(1, 1023));
        self
    }

    /// Set the maximum packet length.
    ///
    /// This is used for internal scheduling calculations. Should be at
    /// least the interface MTU. Default is typically 2048. Saturates at
    /// u32::MAX because the kernel field is 32 bits.
    pub fn lmax(mut self, b: crate::util::Bytes) -> Self {
        self.lmax = Some(b);
        self
    }

    /// Build the configuration. No-op marker for "I'm done"; the
    /// builder is already usable as a `ClassConfig` without it.
    pub fn build(self) -> Self {
        self
    }

    /// The declared weight and maximum packet length.
    pub(crate) fn weight_lmax(&self) -> (Option<u32>, Option<crate::util::Bytes>) {
        (self.weight, self.lmax)
    }

    /// Parse a `tc(8)`-style QFQ class param token slice.
    ///
    /// QFQ class accepts: `weight <u32>` (1..=1023, clamped) and
    /// `lmax <bytes>`. Unknown tokens and unparseable values return
    /// `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut cfg = QfqClassConfig::new();
        let mut i = 0;
        while i < params.len() {
            let tok = params[i];
            match tok {
                "weight" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("qfq: `weight` requires a value")
                    })?;
                    let w = v.parse::<u32>().map_err(|_| {
                        Error::invalid_message(format!(
                            "qfq: invalid weight `{v}` (expected unsigned integer)"
                        ))
                    })?;
                    cfg = cfg.weight(w);
                    i += 2;
                }
                // tc(8) says `maxpkt` (#826); `lmax` is the kernel's name.
                "maxpkt" | "lmax" => {
                    let v = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message(format!("qfq: `{}` requires a value", params[i]))
                    })?;
                    let b = v.parse::<crate::util::Bytes>().map_err(|e| {
                        Error::invalid_message(format!("qfq: invalid {} `{v}`: {e}", params[i]))
                    })?;
                    cfg = cfg.lmax(b);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "qfq: unknown token `{other}` (recognised: weight, maxpkt, lmax)"
                    )));
                }
            }
        }
        Ok(cfg)
    }

    /// The class as the tokens [`parse_params`](Self::parse_params)
    /// reads, its inverse (#645).
    pub fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if let Some(w) = self.weight {
            out.extend(["weight".to_string(), w.to_string()]);
        }
        // tc's word, and the plain byte count tc reads.
        if let Some(l) = self.lmax {
            out.extend(["maxpkt".to_string(), l.as_u64().to_string()]);
        }
        Ok(out)
    }
}

impl ClassConfig for QfqClassConfig {
    fn kind(&self) -> &'static str {
        "qfq"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::qfq::{TCA_QFQ_LMAX, TCA_QFQ_WEIGHT};

        if let Some(weight) = self.weight {
            builder.append_attr_u32(TCA_QFQ_WEIGHT, weight);
        }

        if let Some(lmax) = self.lmax {
            builder.append_attr_u32(TCA_QFQ_LMAX, lmax.as_u32_saturating());
        }

        Ok(())
    }
}


// ============================================================================
// Connection extension methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Add a qdisc to an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use nlink::{Percent, netlink::tc::NetemConfig};
    /// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .loss(Percent::new(1.0))
    ///     .build();
    ///
    /// conn.add_qdisc("eth0", netem).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc"))]
    pub async fn add_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let parent = config.fixed_parent().unwrap_or(TcHandle::ROOT);
        self.add_qdisc_full(dev, parent, None, config).await
    }

    /// Add a qdisc with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_full"))]
    pub async fn add_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Add a qdisc by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Route, namespace, tc::NetemConfig};
    /// use std::time::Duration;
    ///
    /// let conn: Connection<Route> = Connection::new_in("myns")?;
    /// let link = conn
    ///     .get_link_by_name("eth0")
    ///     .await?
    ///     .expect("eth0 exists in this namespace");
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .build();
    ///
    /// conn.add_qdisc_by_index(link.ifindex(), netem).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_by_index"))]
    pub async fn add_qdisc_by_index(&self, ifindex: u32, config: impl QdiscConfig) -> Result<()> {
        let parent = config.fixed_parent().unwrap_or(TcHandle::ROOT);
        self.add_qdisc_by_index_full(ifindex, parent, None, config)
            .await
    }

    /// Add a qdisc by interface index with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_qdisc_by_index_full"))]
    pub async fn add_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        // NLM_F_EXCL, as `tc qdisc add` sends: an add over a live qdisc of
        // the same kind, or at a handle in use, is EEXIST. Without it the
        // kernel quietly *changed* a same-kind qdisc, and refused a
        // different kind with EINVAL (#486). Over a different kind with no
        // handle, the kernel grafts the new qdisc in its place, for `tc`
        // and for this. `replace_qdisc` is the verb for "whatever is there".
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        let handle = handle.or_else(|| root_default_handle(parent, &config));
        self.send_qdisc(
            ifindex,
            parent,
            handle.map_or(0, |h| h.as_raw()),
            flags,
            &config,
            false,
        )
        .await
        .map_err(|e| e.with_context("add_qdisc"))
    }

    /// Delete a qdisc from an interface: whatever is at `parent`.
    ///
    /// At `TcHandle::INGRESS` that is the ingress *or* the clsact qdisc —
    /// the two share the slot, and the constants are one value. Use
    /// [`del_ingress`](Self::del_ingress) or [`del_clsact`](Self::del_clsact)
    /// to delete only the one you mean.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_qdisc("eth0", TcHandle::ROOT).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc"))]
    pub async fn del_qdisc(&self, dev: impl Into<InterfaceRef>, parent: TcHandle) -> Result<()> {
        self.del_qdisc_full(dev, parent, None).await
    }

    /// Delete a qdisc if it exists. Returns `Ok(true)` if the qdisc
    /// was deleted, `Ok(false)` if there was none (also covers a
    /// missing interface). Unlike [`Self::del_qdisc`], does NOT
    /// error when there's nothing to delete (#169; mirrors the
    /// nftables `del_*_if_exists` family).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_if_exists"))]
    pub async fn del_qdisc_if_exists(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<bool> {
        match self.del_qdisc(dev, parent).await {
            Ok(()) => Ok(true),
            // The kernel answers "no qdisc there" with ENOENT (or
            // the typed QdiscNotFound), but EINVAL when only the
            // never-deletable default qdisc sits at that position.
            Err(e) if e.is_not_found() || e.is_invalid_argument() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete a qdisc with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_full"))]
    pub async fn del_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_qdisc_by_index_full(ifindex, parent, handle).await
    }

    /// Delete a qdisc by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_by_index"))]
    pub async fn del_qdisc_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<()> {
        self.del_qdisc_by_index_full(ifindex, parent, None).await
    }

    /// Delete a qdisc by interface index with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_qdisc_by_index_full"))]
    pub async fn del_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
    ) -> Result<()> {
        self.del_qdisc_inner(ifindex, parent, handle, None).await
    }

    /// Delete the `ingress` qdisc, and nothing else (#515).
    ///
    /// The ingress and clsact qdiscs share one slot, and
    /// `TcHandle::INGRESS` and `TcHandle::CLSACT` are the same value, so
    /// [`del_qdisc`](Self::del_qdisc) at it deletes whichever is there — a
    /// clsact, with every BPF program on it, when the caller meant an
    /// ingress. This names the kind, and the kernel refuses (`EINVAL`,
    /// "Invalid qdisc name") when the slot holds a clsact.
    pub async fn del_ingress(&self, dev: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_ingress_by_index(ifindex).await
    }

    /// [`del_ingress`](Self::del_ingress) by interface index.
    pub async fn del_ingress_by_index(&self, ifindex: u32) -> Result<()> {
        self.del_qdisc_inner(ifindex, TcHandle::INGRESS, None, Some("ingress"))
            .await
    }

    /// Delete the `clsact` qdisc, and nothing else; the kernel refuses
    /// when the slot holds an `ingress`. See [`del_ingress`](Self::del_ingress).
    pub async fn del_clsact(&self, dev: impl Into<InterfaceRef>) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_clsact_by_index(ifindex).await
    }

    /// [`del_clsact`](Self::del_clsact) by interface index.
    pub async fn del_clsact_by_index(&self, ifindex: u32) -> Result<()> {
        self.del_qdisc_inner(ifindex, TcHandle::CLSACT, None, Some("clsact"))
            .await
    }

    /// Delete the qdisc at `parent` (and `handle`) only if it is a `kind`;
    /// the kernel refuses another (`tc_get_qdisc` compares `TCA_KIND`). The
    /// error says what is there, and an empty slot is
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound).
    pub async fn del_qdisc_kind_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        kind: &str,
    ) -> Result<()> {
        self.del_qdisc_inner(ifindex, parent, handle, Some(kind))
            .await
    }

    /// One `RTM_DELQDISC`; with `kind`, the kernel deletes only a qdisc of
    /// that kind (`tc_get_qdisc` compares `TCA_KIND`).
    async fn del_qdisc_inner(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        kind: Option<&str>,
    ) -> Result<()> {
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw())
            .with_handle(handle.map_or(0, |h| h.as_raw()));

        let mut builder = ack_request(NlMsgType::RTM_DELQDISC);
        builder.append(&tcmsg);
        if let Some(kind) = kind {
            builder.append_attr_str(TcaAttr::Kind as u16, kind);
        }

        let not_found = || {
            Error::not_found(crate::ErrorObject::Qdisc {
                dev: format!("ifindex {ifindex}"),
                parent: Some(parent.to_string()),
                kind: kind.map(str::to_string),
            })
        };
        let Err(e) = self.send_ack(builder).await else {
            return Ok(());
        };
        if e.is_not_found() {
            return Err(not_found());
        }
        // A kind that does not match is "Invalid qdisc name", and so is an
        // empty slot, which holds the kernel's placeholder; look to say
        // which.
        if let Some(kind) = kind
            && e.is_invalid_argument()
        {
            let live = self.get_qdiscs_by_index(ifindex).await?;
            let there = live
                .iter()
                .find(|q| q.parent() == parent && q.handle().as_raw() != 0);
            return Err(match there.and_then(|q| q.kind()) {
                None => not_found(),
                Some(other) => Error::invalid_message(format!(
                    "del_qdisc(ifindex {ifindex}, parent={parent}): the qdisc there is \
                     `{other}`, not `{kind}`; left in place"
                )),
            });
        }
        let kind = kind.map_or_else(String::new, |k| format!(", kind={k}"));
        Err(e.with_context(format!(
            "del_qdisc(ifindex {ifindex}, parent={parent}{kind})"
        )))
    }

    /// Replace a qdisc (add or update) — whatever is in the root slot.
    ///
    /// The kernel's answer to a replace depends on the live qdisc, so this
    /// looks first (#486):
    /// - nothing there, or a different kind under its own handle: created
    ///   and grafted in;
    /// - the same kind: changed in place ([`QdiscConfig::in_place`]), with
    ///   the options in change mode (fq_codel without `flows`);
    /// - the same kind that cannot change in place (`htb`, `sfq`, fq_codel
    ///   with a different `flows`), or a different kind at the live
    ///   qdisc's own handle: a new qdisc is grafted over the live one, so
    ///   the slot is never bare. A same-kind qdisc with classes is refused
    ///   instead (`is_not_supported`), because the new one would not have
    ///   them. fq_codel and sfq are not refused: their classes are the
    ///   flows that have packets queued, which a recreate drops along with
    ///   the queue (#596).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::tc::NetemConfig;
    /// # use std::time::Duration;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(50))
    ///     .build();
    ///
    /// conn.replace_qdisc("eth0", netem).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc"))]
    pub async fn replace_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.replace_qdisc_full(dev, TcHandle::ROOT, None, config)
            .await
    }

    /// Replace a qdisc with explicit parent and handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc_full"))]
    pub async fn replace_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Replace a qdisc by interface index (add or update).
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_qdisc_by_index"))]
    pub async fn replace_qdisc_by_index(
        &self,
        ifindex: u32,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.replace_qdisc_by_index_full(ifindex, TcHandle::ROOT, None, config)
            .await
    }

    /// Replace a qdisc by interface index with explicit parent and handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_qdisc_by_index_full")
    )]
    pub async fn replace_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        // What the kernel does with NLM_F_REPLACE depends on what is in the
        // slot, and some of its answers are EINVAL (#486): a same-kind
        // replace is `qdisc_change`, which `htb` and `sfq` do not have and
        // which `fq_codel` refuses when `flows` is present; a different kind
        // at the live qdisc's own handle is "Invalid qdisc name". So look at
        // the slot first.
        let live = self
            .get_qdiscs_by_index(ifindex)
            .await?
            .into_iter()
            // A handle of 0 is the device's default qdisc; the kernel
            // ignores it here too.
            .find(|q| q.parent() == parent && q.handle().as_raw() != 0);
        let replace = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let raw = |h: Option<TcHandle>| h.map_or(0, |h| h.as_raw());
        // A new qdisc in the slot takes the kind's default handle at the
        // root (#515); a live one changed or recreated keeps its own.
        let new_handle = handle.or_else(|| root_default_handle(parent, &config));

        let Some(live) = live else {
            return self
                .send_qdisc(ifindex, parent, raw(new_handle), replace, &config, false)
                .await
                .map_err(|e| e.with_context("replace_qdisc"));
        };
        let same_kind = live.kind() == Some(config.kind());
        let at_live_handle = new_handle.is_some_and(|h| h == live.handle());

        if same_kind && config.in_place(&live) == InPlace::Change {
            // `qdisc_change`, encoded for a change.
            return self
                .send_qdisc(ifindex, parent, raw(handle), replace, &config, true)
                .await
                .map_err(|e| e.with_context("replace_qdisc"));
        }
        if !same_kind && !at_live_handle {
            // A different kind under its own handle: the kernel creates it
            // and grafts it over the live one.
            return self
                .send_qdisc(ifindex, parent, raw(new_handle), replace, &config, false)
                .await
                .map_err(|e| e.with_context("replace_qdisc"));
        }

        // Recreate: a new qdisc grafted over the live one. A same-kind
        // recreate would take the live qdisc's classes with it, which a
        // caller asking to change parameters does not expect; refuse that.
        // fq_codel's and sfq's classes are not a tree anyone built: their
        // `walk` reports each flow that has packets queued, so a busy one
        // always has some. Recreating them drops the queue, as any graft
        // does (#596).
        if same_kind && !matches!(config.kind(), "fq_codel" | "sfq") {
            let classes = self
                .get_classes_by_index(ifindex)
                .await?
                .into_iter()
                .filter(|c| c.handle().major() == live.handle().major())
                .count();
            if classes > 0 {
                return Err(Error::not_supported(format!(
                    "replace_qdisc: a {} cannot be changed in place, and replacing it would \
                     delete its {classes} class(es); delete the qdisc and add the new one if \
                     that is what you want",
                    config.kind()
                )));
            }
        }
        // Graft a new qdisc over the live one at a handle nothing uses — a
        // handle the kernel cannot look up is always "create and graft" —
        // then graft again at the handle asked for (the live one when none
        // was), which by then is free. The slot is never bare (#486).
        let in_use: Vec<u16> = self
            .get_qdiscs_by_index(ifindex)
            .await?
            .iter()
            .map(|q| q.handle().major())
            .collect();
        let temporary = (0x7000..=0x7fffu16)
            .rev()
            .find(|major| !in_use.contains(major))
            .map(TcHandle::major_only)
            .ok_or_else(|| {
                Error::not_supported("replace_qdisc: no free qdisc handle to graft through")
            })?;
        let fin = if same_kind {
            handle.unwrap_or(live.handle())
        } else {
            new_handle.unwrap_or(live.handle())
        };
        for step in [temporary, fin] {
            self.send_qdisc(ifindex, parent, step.as_raw(), replace, &config, false)
                .await
                .map_err(|e| e.with_context("replace_qdisc"))?;
        }
        Ok(())
    }

    /// Send one `RTM_NEWQDISC` with `flags`, writing `config`'s options in
    /// change mode when `change` is set.
    async fn send_qdisc(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: u32,
        flags: u16,
        config: &impl QdiscConfig,
        change: bool,
    ) -> Result<()> {
        // `ffff:` is the ingress/clsact qdisc's. The kernel takes it for a
        // classful qdisc's leaf while no ingress exists, and then refuses
        // the ingress — or, the other way round, the leaf (#485).
        if TcHandle::from_raw(handle).is_reserved_major() && !parent.is_ingress() {
            return Err(Error::invalid_message(format!(
                "tc: qdisc handle {} is reserved for the ingress/clsact qdisc",
                TcHandle::from_raw(handle)
            )));
        }
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw())
            .with_handle(handle);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_NEWQDISC, flags);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());
        if config.has_options() {
            let options_token = builder.nest_start(TcaAttr::Options as u16);
            if change {
                config.write_change_options(&mut builder)?;
            } else {
                config.write_options(&mut builder)?;
            }
            builder.nest_end(options_token);
        }
        self.send_ack(builder).await
    }

    /// Change a qdisc's parameters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # use nlink::netlink::tc::NetemConfig;
    /// # use std::time::Duration;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(200))
    ///     .build();
    ///
    /// conn.change_qdisc("eth0", TcHandle::ROOT, netem).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc"))]
    pub async fn change_qdisc(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_full(dev, parent, None, config).await
    }

    /// Change a qdisc with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc_full"))]
    pub async fn change_qdisc_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_qdisc_by_index_full(ifindex, parent, handle, config)
            .await
    }

    /// Change a qdisc's parameters by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_qdisc_by_index"))]
    pub async fn change_qdisc_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl QdiscConfig,
    ) -> Result<()> {
        self.change_qdisc_by_index_full(ifindex, parent, None, config)
            .await
    }

    /// Change a qdisc by interface index with explicit handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "change_qdisc_by_index_full")
    )]
    pub async fn change_qdisc_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        config: impl QdiscConfig,
    ) -> Result<()> {
        // A change is `qdisc_change` on the live qdisc, so the options go in
        // change mode (fq_codel without `flows`, #486).
        let kind = config.kind().to_string();
        self.send_qdisc(
            ifindex,
            parent,
            handle.map_or(0, |h| h.as_raw()),
            NLM_F_REQUEST | NLM_F_ACK,
            &config,
            true,
        )
        .await
        .map_err(|e| {
            if e.is_not_found() {
                Error::not_found(crate::ErrorObject::Qdisc {
                    dev: format!("ifindex {ifindex}"),
                    parent: Some(parent.to_string()),
                    kind: Some(kind),
                })
            } else {
                e.with_context(format!(
                    "change_qdisc(ifindex {ifindex}, parent={})",
                    parent
                ))
            }
        })
    }

    /// Start buffering on a plug qdisc (`TCQ_PLUG_BUFFER`).
    ///
    /// Packets queued from now on are held until a release. Installing
    /// the qdisc already buffers, so this is for starting a *new* epoch
    /// after a release.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::TcHandle;
    /// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
    /// conn.plug_buffer("eth0", TcHandle::ROOT).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "plug_buffer"))]
    pub async fn plug_buffer(&self, dev: impl Into<InterfaceRef>, parent: TcHandle) -> Result<()> {
        use super::types::tc::qdisc::plug::TCQ_PLUG_BUFFER;

        self.change_qdisc(dev, parent, PlugAction(TCQ_PLUG_BUFFER, 0))
            .await
    }

    /// Release the packets buffered so far (`TCQ_PLUG_RELEASE_ONE`),
    /// and keep buffering what arrives next.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "plug_release_one"))]
    pub async fn plug_release_one(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<()> {
        use super::types::tc::qdisc::plug::TCQ_PLUG_RELEASE_ONE;

        self.change_qdisc(dev, parent, PlugAction(TCQ_PLUG_RELEASE_ONE, 0))
            .await
    }

    /// Stop buffering and let everything through
    /// (`TCQ_PLUG_RELEASE_INDEFINITE`).
    ///
    /// The way out of a plug: without it, installing the qdisc stalls
    /// the interface with nothing in the library to unstall it (#276).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "plug_release_indefinite"))]
    pub async fn plug_release_indefinite(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<()> {
        use super::types::tc::qdisc::plug::TCQ_PLUG_RELEASE_INDEFINITE;

        self.change_qdisc(dev, parent, PlugAction(TCQ_PLUG_RELEASE_INDEFINITE, 0))
            .await
    }

    /// Change a plug qdisc's buffer limit in bytes (`TCQ_PLUG_LIMIT`).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "plug_set_limit"))]
    pub async fn plug_set_limit(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        bytes: crate::util::Bytes,
    ) -> Result<()> {
        use super::types::tc::qdisc::plug::TCQ_PLUG_LIMIT;

        let limit = PlugAction(TCQ_PLUG_LIMIT, bytes.as_u32_saturating());
        self.change_qdisc(dev, parent, limit).await
    }

    /// Apply a netem configuration to an interface.
    ///
    /// This is a convenience method that replaces any existing root qdisc
    /// with a netem qdisc. If no root qdisc exists, it creates one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use nlink::{Percent, netlink::tc::NetemConfig};
    /// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .jitter(Duration::from_millis(10))
    ///     .loss(Percent::new(1.0))
    ///     .build();
    ///
    /// conn.apply_netem("eth0", netem).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "apply_netem"))]
    pub async fn apply_netem(
        &self,
        dev: impl Into<InterfaceRef>,
        config: NetemConfig,
    ) -> Result<()> {
        // `replace_qdisc` creates the qdisc when the slot is empty; there
        // was an ENOENT → add fallback here, which a CREATE request never
        // reached (#486).
        self.replace_qdisc(dev, config).await
    }

    /// Apply a netem configuration by interface index.
    ///
    /// This is useful for namespace-aware operations where you've already
    /// resolved the interface index via `conn.get_link_by_name()`.
    /// If no root qdisc exists, it creates one.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "apply_netem_by_index"))]
    pub async fn apply_netem_by_index(&self, ifindex: u32, config: NetemConfig) -> Result<()> {
        self.replace_qdisc_by_index(ifindex, config).await
    }

    /// Remove netem configuration from an interface.
    ///
    /// This deletes the root qdisc, which restores the default qdisc.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
    /// conn.del_netem("eth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_netem"))]
    pub async fn del_netem(&self, dev: impl Into<InterfaceRef>) -> Result<()> {
        self.del_qdisc(dev, TcHandle::ROOT).await
    }

    /// Remove netem configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_netem_by_index"))]
    pub async fn del_netem_by_index(&self, ifindex: u32) -> Result<()> {
        self.del_qdisc_by_index(ifindex, TcHandle::ROOT).await
    }

    // ========================================================================
    // TC Class Operations
    // ========================================================================

    /// Delete a TC class.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 0x10)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_class"))]
    pub async fn del_class(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_class_by_index(ifindex, parent, classid).await
    }

    /// Delete a TC class by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_class_by_index"))]
    pub async fn del_class_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_DELTCLASS);
        builder.append(&tcmsg);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_class"))
    }

    /// Add a TC class with typed configuration.
    ///
    /// Mirrors `add_qdisc` / `add_filter` / `add_action`: takes the
    /// typed `ClassConfig` (`HtbClassConfig`, `HfscClassConfig`,
    /// `DrrClassConfig`, `QfqClassConfig`) and submits a single
    /// `RTM_NEWTCLASS` request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # use nlink::Rate;
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::tc::{HtbQdiscConfig, HtbClassConfig};
    ///
    /// let conn = Connection::<Route>::new()?;
    ///
    /// // First add HTB qdisc
    /// let htb = HtbQdiscConfig::new().default_class(0x30).build();
    /// conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb).await?;
    ///
    /// // Add a class with guaranteed 100mbit, ceiling 500mbit
    /// conn.add_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 0x10),
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .prio(1)
    ///         .build()
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class", kind = %config.kind()))]
    pub async fn add_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Add a TC class with typed configuration by interface index.
    ///
    /// Useful for namespace-aware operations where the interface
    /// index has already been resolved via `conn.get_link_by_name()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_class_by_index", kind = %config.kind()))]
    pub async fn add_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = create_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_class"))
    }

    /// Change a TC class with typed configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # use nlink::Rate;
    /// # use nlink::netlink::tc::HtbClassConfig;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Update an existing class's rate
    /// conn.change_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 0x10),
    ///     HtbClassConfig::new(Rate::mbit(200))
    ///         .ceil(Rate::mbit(800))
    ///         .build()
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class", kind = %config.kind()))]
    pub async fn change_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Change a TC class with typed configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_class_by_index", kind = %config.kind()))]
    pub async fn change_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = ack_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("change_class"))
    }

    /// Replace a TC class with typed configuration (add or update).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # use nlink::Rate;
    /// # use nlink::netlink::tc::HtbClassConfig;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Create or update a class
    /// conn.replace_class("eth0", TcHandle::major_only(1), TcHandle::new(1, 0x10),
    ///     HtbClassConfig::new(Rate::mbit(100))
    ///         .ceil(Rate::mbit(500))
    ///         .build()
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class", kind = %config.kind()))]
    pub async fn replace_class<C: ClassConfig>(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_class_by_index(ifindex, parent, classid, config)
            .await
    }

    /// Replace a TC class with typed configuration by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_class_by_index", kind = %config.kind()))]
    pub async fn replace_class_by_index<C: ClassConfig>(
        &self,
        ifindex: u32,
        parent: TcHandle,
        classid: TcHandle,
        config: C,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let class_handle = classid.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(class_handle);

        let mut builder = replace_request(NlMsgType::RTM_NEWTCLASS);
        builder.append(&tcmsg);
        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_class"))
    }
}

/// Wire-byte assertions for the psched-tick encoders (#191-#194, #218).
///
/// These deliberately do **not** round-trip through nlink's own decoder: a
/// writer and reader that are wrong in the same direction agree with each
/// other, which is exactly how the tick bugs survived for so long. Every
/// expected value here is computed by hand from iproute2's algorithm and
/// shown in the comment above it.
#[cfg(test)]
mod psched_wire_tests {
    use super::*;
    use crate::netlink::{
        psched::Psched,
        test_support::{class_attrs, qdisc_attrs, u32_at},
    };
    use crate::util::{Bytes, Rate};

    /// The psched clock every modern kernel reports. The library reads the
    /// real `/proc/net/psched`, which on any supported kernel yields exactly
    /// this — asserting it here means the expected values below are stable.
    #[test]
    fn the_host_clock_is_the_modern_clock() {
        assert_eq!(crate::netlink::psched::psched(), Psched::MODERN);
        assert_eq!(crate::netlink::psched::tick_in_usec(), 15.625);
    }

    /// TBF at 1 mbit with a 32 KiB burst (#192).
    ///
    ///   rate  = 1 mbit           = 125_000 bytes/sec
    ///   burst = 32 KiB           = 32_768 bytes
    ///   xmit  = 32768 / 125000   = 0.262144 s = 262_144 us
    ///   ticks = 262_144 * 15.625 = 4_096_000
    ///
    /// The old encoder put the raw 32_768 here. The kernel read that as
    /// ticks (~2.1 ms), computed max_size = 125_000 * 2.1ms ~= 262 bytes, and
    /// tbf_enqueue() then dropped every packet larger than that.
    #[test]
    fn tbf_buffer_is_psched_ticks_not_bytes() {
        let cfg = TbfConfig::new()
            .rate(Rate::mbit(1))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64));
        let attrs = qdisc_attrs(&cfg);

        let parms = &attrs[&tbf::TCA_TBF_PARMS];
        assert_eq!(parms.len(), 36, "sizeof(tc_tbf_qopt)");

        assert_eq!(u32_at(&attrs, tbf::TCA_TBF_PARMS, 8), 125_000, "rate.rate");
        assert_eq!(
            u32_at(&attrs, tbf::TCA_TBF_PARMS, 28),
            4_096_000,
            "tc_tbf_qopt.buffer must be psched ticks",
        );
        assert_ne!(
            u32_at(&attrs, tbf::TCA_TBF_PARMS, 28),
            32_768,
            "regression: buffer is the raw byte count again",
        );
    }

    /// A rate table whose spec carries cell_log == 0 is silently discarded by
    /// the kernel's qdisc_get_rtab(). The table and the cell_log must be
    /// produced together or the qdisc is rejected (TBF) / the linklayer
    /// handling never works (HTB).
    #[test]
    fn tbf_emits_a_rate_table_with_a_matching_cell_log() {
        let cfg = TbfConfig::new()
            .rate(Rate::mbit(1))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64));
        let attrs = qdisc_attrs(&cfg);

        let rtab = &attrs[&tbf::TCA_TBF_RTAB];
        assert_eq!(rtab.len(), 1024, "TC_RTAB_SIZE");

        let parms = &attrs[&tbf::TCA_TBF_PARMS];
        // Default mtu 1514: 1514 >> 3 == 189 fits 256 entries, 1514 >> 2 does not.
        assert_eq!(parms[0], 3, "rate.cell_log");
        assert_ne!(parms[0], 0, "cell_log == 0 makes the kernel drop the rtab");
        assert_eq!(parms[1], 1, "rate.linklayer = TC_LINKLAYER_ETHERNET");
        assert_eq!(&parms[4..6], (-1i16).to_ne_bytes(), "rate.cell_align");

        // Entry 0 covers one 8-byte cell: 8/125000 s = 64 us -> 1000 ticks.
        assert_eq!(u32::from_ne_bytes(rtab[0..4].try_into().unwrap()), 1_000);
    }

    /// iproute2 sends the byte-valued burst alongside the tick-valued one;
    /// modern kernels prefer it and recompute the bucket from it exactly.
    #[test]
    fn tbf_emits_the_byte_valued_burst_escape_hatch() {
        let cfg = TbfConfig::new()
            .rate(Rate::mbit(1))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64));
        let attrs = qdisc_attrs(&cfg);

        assert_eq!(u32_at(&attrs, tbf::TCA_TBF_BURST, 0), 32_768);
        // No peakrate configured -> no peak-side attributes.
        assert!(!attrs.contains_key(&tbf::TCA_TBF_PTAB));
        assert!(!attrs.contains_key(&tbf::TCA_TBF_PBURST));
    }

    #[test]
    fn tbf_peakrate_emits_the_peak_table_and_burst() {
        let cfg = TbfConfig::new()
            .rate(Rate::mbit(1))
            .peakrate(Rate::mbit(2))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64));
        let attrs = qdisc_attrs(&cfg);

        assert_eq!(attrs[&tbf::TCA_TBF_PTAB].len(), 1024);
        assert!(attrs.contains_key(&tbf::TCA_TBF_PBURST));
        // peakrate.rate lives at offset 20 of tc_tbf_qopt.
        assert_eq!(u32_at(&attrs, tbf::TCA_TBF_PARMS, 20), 250_000);
    }

    /// A TBF with limit 0 has no queue in the kernel — its child stays
    /// noop_qdisc — and drops every packet. `new()` defaults the limit to
    /// 0, so this is what a rate-and-burst-only TBF used to install.
    #[test]
    fn tbf_without_a_limit_is_refused() {
        let cfg = TbfConfig::new().rate(Rate::mbit(10)).burst(Bytes::kib(32));
        let mut builder = MessageBuilder::new(0, 0);
        let err = cfg
            .write_options(&mut builder)
            .expect_err("a zero limit is a black hole, not a qdisc");
        let msg = err.to_string();
        assert!(msg.contains("tbf: "), "{msg}");
        assert!(msg.contains("limit"), "{msg}");

        let mut builder = MessageBuilder::new(0, 0);
        cfg.limit(Bytes::kib(64))
            .write_options(&mut builder)
            .expect("with a limit it is fine");
    }

    /// HTB class at 100 mbit with an explicit 15 KiB burst (#193).
    ///
    ///   rate  = 100 mbit        = 12_500_000 bytes/sec
    ///   burst = 15 KiB          = 15_360 bytes
    ///   xmit  = 15360/12500000  = 1228.8 us
    ///   ticks = 1228.8 * 15.625 = 19_200
    ///
    /// The old encoder wrote the microsecond value (1228), which the kernel
    /// read as ticks = 78 us — a token bucket of ~980 bytes, below one MTU,
    /// so the class could never burst a full-size packet.
    #[test]
    fn htb_class_buffer_is_psched_ticks_not_microseconds() {
        let cfg = HtbClassConfig::new(Rate::mbit(100)).burst(Bytes::kib(15));
        let attrs = class_attrs(&cfg);

        // tc_htb_opt: rate(12) ceil(12) buffer@24 cbuffer@28 quantum@32 ...
        assert_eq!(
            u32_at(&attrs, htb::TCA_HTB_PARMS, 24),
            19_200,
            "tc_htb_opt.buffer must be psched ticks",
        );
        assert_ne!(
            u32_at(&attrs, htb::TCA_HTB_PARMS, 24),
            1_228,
            "regression: buffer is back in microseconds",
        );

        let parms = &attrs[&htb::TCA_HTB_PARMS];
        assert_eq!(parms[0], 3, "rate.cell_log");
        assert_eq!(parms[12], 3, "ceil.cell_log");
        assert_eq!(attrs[&htb::TCA_HTB_RTAB].len(), 1024);
        assert_eq!(attrs[&htb::TCA_HTB_CTAB].len(), 1024);
    }

    /// iproute2's get_hz() is 1e9 on modern kernels, so q_htb.c's
    /// `buffer = rate64 / get_hz() + mtu` is just `mtu` below 8 Gbit/s.
    /// The old hardcoded hz = 1000 added rate/1000 bytes on top — 12_500
    /// extra at 100 mbit, a >8x too-large default burst.
    #[test]
    fn htb_class_default_burst_is_one_mtu() {
        let cfg = HtbClassConfig::new(Rate::mbit(100)); // no explicit burst
        let attrs = class_attrs(&cfg);

        // Default mtu is 1600 bytes: 1600/12_500_000 s = 128 us -> 2000 ticks.
        assert_eq!(u32_at(&attrs, htb::TCA_HTB_PARMS, 24), 2_000);
    }

    /// `HtbQdiscConfig` had an `r2q` field, a public `.r2q()` setter, and a
    /// `parse_params` token for it — and `write_options` read none of them,
    /// because `TcHtbGlob::new()` hardcoded `rate2quantum: 10` with no way to
    /// override it. This is CLAUDE.md's "silent skipping is a bug" contract
    /// violated one layer *below* the parser: the parser dutifully accepted
    /// the token and the encoder threw it away (#213).
    /// #635: cake's flags go out whether on or off, `split_gso` on by
    /// default, and an RTT without a target brings a twentieth of itself
    /// as the target, as tc(8) sends it.
    #[test]
    fn cake_sends_its_flags_off_and_a_target_with_the_rtt() {
        use crate::netlink::types::tc::qdisc::cake::*;
        let attrs = qdisc_attrs(&CakeConfig::new());
        for (ty, want) in [
            (TCA_CAKE_AUTORATE, 0),
            (TCA_CAKE_NAT, 0),
            (TCA_CAKE_WASH, 0),
            (TCA_CAKE_INGRESS, 0),
            (TCA_CAKE_SPLIT_GSO, 1),
        ] {
            assert_eq!(u32_at(&attrs, ty, 0), want, "attribute {ty}");
        }
        assert!(!attrs.contains_key(&TCA_CAKE_RAW));
        assert!(!attrs.contains_key(&TCA_CAKE_TARGET), "no RTT, no target");

        let cfg = CakeConfig::new().rtt(std::time::Duration::from_millis(50));
        let attrs = qdisc_attrs(&cfg);
        assert_eq!(u32_at(&attrs, TCA_CAKE_RTT, 0), 50_000);
        assert_eq!(u32_at(&attrs, TCA_CAKE_TARGET, 0), 2_500);
        let cfg = cfg.target(std::time::Duration::from_millis(4));
        assert_eq!(u32_at(&qdisc_attrs(&cfg), TCA_CAKE_TARGET, 0), 4_000);
        let cfg = CakeConfig::parse_params(&["no-split-gso", "rtt", "10us"]).unwrap();
        let attrs = qdisc_attrs(&cfg);
        assert_eq!(u32_at(&attrs, TCA_CAKE_SPLIT_GSO, 0), 0);
        assert_eq!(u32_at(&attrs, TCA_CAKE_TARGET, 0), 1, "tc's floor of 1 µs");
    }

    /// #631: `TCA_FQ_PIE_ECN_PROB` is a whole percentage, as tc(8) sends
    /// it; it was written per-mille, so 20 % went out as 200.
    #[test]
    fn fq_pie_ecn_prob_is_a_percentage_on_the_wire() {
        use crate::netlink::types::tc::qdisc::fq_pie::TCA_FQ_PIE_ECN_PROB;
        let cfg = FqPieConfig::new().ecn_prob(crate::util::Percent::new(20.0));
        assert_eq!(u32_at(&qdisc_attrs(&cfg), TCA_FQ_PIE_ECN_PROB, 0), 20);

        let cfg = FqPieConfig::new().ecn_prob(crate::util::Percent::new(1.5));
        let mut b = MessageBuilder::new(0, 0);
        let err = cfg.write_options(&mut b).unwrap_err().to_string();
        assert!(err.contains("not a whole percentage"), "got: {err}");
        let err = FqPieConfig::parse_params(&["ecn_prob", "1.5"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("fq_pie: ecnprob `1.5` is not a whole percentage"),
            "got: {err}"
        );
    }

    #[test]
    fn htb_qdisc_r2q_reaches_the_wire() {
        // struct tc_htb_glob: version@0 rate2quantum@4 defcls@8 debug@12 ...
        let attrs = qdisc_attrs(&HtbQdiscConfig::new().r2q(100).default_class(0x30));
        assert_eq!(u32_at(&attrs, htb::TCA_HTB_INIT, 4), 100, "rate2quantum");
        assert_eq!(u32_at(&attrs, htb::TCA_HTB_INIT, 8), 0x30, "defcls");

        // The tc(8) token must land in the same place.
        let cfg = HtbQdiscConfig::parse_params(&["r2q", "100"]).unwrap();
        assert_eq!(u32_at(&qdisc_attrs(&cfg), htb::TCA_HTB_INIT, 4), 100);

        // And the default is still 10.
        let attrs = qdisc_attrs(&HtbQdiscConfig::new());
        assert_eq!(u32_at(&attrs, htb::TCA_HTB_INIT, 4), 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Percent;

    #[test]
    fn test_pfifo_parse_params() {
        let cfg = PfifoConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, crate::util::Packets::new(1000)); // default

        let cfg = PfifoConfig::parse_params(&["limit", "500"]).unwrap();
        assert_eq!(cfg.limit, crate::util::Packets::new(500));

        // missing value, unparseable value, and unknown token all error
        assert!(PfifoConfig::parse_params(&["limit"]).is_err());
        assert!(PfifoConfig::parse_params(&["limit", "abc"]).is_err());
        assert!(PfifoConfig::parse_params(&["bogus"]).is_err());
    }

    #[test]
    fn test_bfifo_parse_params() {
        let cfg = BfifoConfig::parse_params(&["limit", "100kb"]).unwrap();
        assert_eq!(cfg.limit, 100 * 1024); // tc size suffixes are binary

        let cfg = BfifoConfig::parse_params(&["limit", "4096"]).unwrap();
        assert_eq!(cfg.limit, 4096);

        assert!(BfifoConfig::parse_params(&["limit"]).is_err());
        assert!(BfifoConfig::parse_params(&["limit", "nope"]).is_err());
        assert!(BfifoConfig::parse_params(&["divisor", "1"]).is_err());
    }

    #[test]
    fn test_fq_pie_parse_params() {
        use crate::util::{Bytes, Percent};

        let cfg = FqPieConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.limit, None);
        assert!(!cfg.ecn);

        let cfg = FqPieConfig::parse_params(&[
            "limit", "10000", "flows", "1024", "target", "15ms", "tupdate", "16ms", "alpha", "2",
            "beta", "20", "quantum", "1514", "memory_limit", "32mb", "ecnprob", "10", "ecn",
            "bytemode", "dq_rate_estimator",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(10000)));
        assert_eq!(cfg.flows, Some(1024));
        assert_eq!(cfg.target, Some(Duration::from_millis(15)));
        assert_eq!(cfg.tupdate, Some(Duration::from_millis(16)));
        assert_eq!(cfg.alpha, Some(2));
        assert_eq!(cfg.beta, Some(20));
        assert_eq!(cfg.quantum, Some(Bytes::new(1514)));
        assert_eq!(cfg.memory_limit, Some(Bytes::new(32 * 1024 * 1024)));
        assert_eq!(cfg.ecn_prob, Some(Percent::new(10.0)));
        assert!(cfg.ecn);
        assert!(cfg.bytemode);
        assert!(cfg.dq_rate_estimator);

        // toggles can be cleared, alias accepted
        let cfg =
            FqPieConfig::parse_params(&["noecn", "nobytemode", "ecn_prob", "5"]).unwrap();
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
        assert_eq!(cfg.ecn_prob, Some(Percent::new(5.0)));

        // strict: missing value, bad value, unknown token
        assert!(FqPieConfig::parse_params(&["limit"]).is_err());
        assert!(FqPieConfig::parse_params(&["target", "fast"]).is_err());
        assert!(FqPieConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_cbs_parse_and_write() {
        // tc(8) Class-A example values.
        let cfg = CbsConfig::parse_params(&[
            "idleslope", "98688", "sendslope", "-901312", "hicredit", "153", "locredit", "-1389",
            "offload", "1",
        ])
        .unwrap();
        assert_eq!(cfg.idleslope, 98688);
        assert_eq!(cfg.sendslope, -901312);
        assert_eq!(cfg.hicredit, 153);
        assert_eq!(cfg.locredit, -1389);
        assert!(cfg.offload);

        // write_options emits the PARMS attribute without error; the
        // fixed struct is 20 bytes (offload + 3 pad + 4×i32).
        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();
        use crate::netlink::types::tc::qdisc::cbs::TcCbsQopt;
        assert_eq!(TcCbsQopt::SIZE, 20);

        // offload alias + default-zero fields.
        let cfg = CbsConfig::parse_params(&["offload", "off"]).unwrap();
        assert!(!cfg.offload);
        assert_eq!(cfg.idleslope, 0);

        // strict: missing value, bad value, bad offload, unknown token.
        assert!(CbsConfig::parse_params(&["idleslope"]).is_err());
        assert!(CbsConfig::parse_params(&["idleslope", "fast"]).is_err());
        assert!(CbsConfig::parse_params(&["offload", "2"]).is_err());
        assert!(CbsConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_skbprio_parse() {
        let cfg = SkbprioConfig::parse_params(&["limit", "128"]).unwrap();
        assert_eq!(cfg.limit, crate::util::Packets::new(128));
        // kernel default when unspecified.
        assert_eq!(SkbprioConfig::parse_params(&[]).unwrap().limit, crate::util::Packets::new(64));
        // strict: missing value, bad value, unknown token.
        assert!(SkbprioConfig::parse_params(&["limit"]).is_err());
        assert!(SkbprioConfig::parse_params(&["limit", "x"]).is_err());
        assert!(SkbprioConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_sfb_parse_and_write() {
        let cfg = SfbConfig::parse_params(&[
            "limit", "1000", "rehash", "600ms", "db", "60ms", "max", "25", "target", "20",
            "increment", "0.0005", "decrement", "0.00005", "penalty_rate", "10", "penalty_burst", "20",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(1000)));
        assert_eq!(cfg.rehash, Some(Duration::from_millis(600)));
        assert_eq!(cfg.db, Some(Duration::from_millis(60)));
        assert_eq!(cfg.max, Some(25));
        assert_eq!(cfg.target, Some(20));
        assert_eq!(cfg.penalty_rate, Some(10));
        // Probabilities, scaled to 0xFFFF as tc does (#820).
        assert_eq!((cfg.increment, cfg.decrement), (Some(33), Some(3)));
        assert!(SfbConfig::parse_params(&["increment", "5"]).is_err());
        // tc reads a bare rehash or db as milliseconds.
        let cfg = SfbConfig::parse_params(&["rehash", "600", "db", "0x3c"]).unwrap();
        assert_eq!((cfg.rehash, cfg.db), (Some(Duration::from_secs(600) / 1000), Some(Duration::from_millis(60))));

        // What is unset is tc's default, not 0.
        use crate::netlink::types::tc::qdisc::sfb::TCA_SFB_PARMS;
        let attrs = qdisc_option_attrs(&SfbConfig::new());
        let parms = &attrs[&TCA_SFB_PARMS];
        let words: Vec<u32> = parms.chunks(4).map(|w| u32::from_ne_bytes(w.try_into().unwrap())).collect();
        // rehash, db, max, bin_size, increment, decrement, limit, penalty rate and burst.
        assert_eq!(words, [600_000, 60_000, 25, 20, 33, 3, 0, 10, 20]);
        let attrs = qdisc_option_attrs(&SfbConfig::new().target(40));
        assert_eq!(attrs[&TCA_SFB_PARMS][8..12], 50u32.to_ne_bytes());

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();
        use crate::netlink::types::tc::qdisc::sfb::TcSfbQopt;
        assert_eq!(TcSfbQopt::SIZE, 36);

        // strict: missing value, bad time, unknown token.
        assert!(SfbConfig::parse_params(&["limit"]).is_err());
        assert!(SfbConfig::parse_params(&["rehash", "soon"]).is_err());
        assert!(SfbConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn test_multiq_parse() {
        // Parameterless: empty parses, any token errors.
        assert!(MultiqConfig::parse_params(&[]).is_ok());
        assert!(MultiqConfig::parse_params(&["bands", "4"]).is_err());
        let mut b = MessageBuilder::new(0, 0);
        MultiqConfig::new().write_options(&mut b).unwrap();
    }

    #[test]
    fn test_hhf_parse_and_write() {
        use crate::util::Bytes;

        let cfg = HhfConfig::parse_params(&[
            "limit", "1000", "quantum", "1514", "hh_limit", "2048", "reset_timeout", "40ms",
            "admit_bytes", "131072", "evict_timeout", "1s", "nonhh_weight", "2",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(1000)));
        assert_eq!(cfg.quantum, Some(Bytes::new(1514)));
        assert_eq!(cfg.hh_limit, Some(2048));
        assert_eq!(cfg.reset_timeout, Some(Duration::from_millis(40)));
        assert_eq!(cfg.admit_bytes, Some(Bytes::new(131072)));
        assert_eq!(cfg.evict_timeout, Some(Duration::from_secs(1)));
        assert_eq!(cfg.non_hh_weight, Some(2));

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();

        // strict: missing value, bad size, bad time, unknown token.
        assert!(HhfConfig::parse_params(&["limit"]).is_err());
        assert!(HhfConfig::parse_params(&["quantum", "big"]).is_err());
        assert!(HhfConfig::parse_params(&["reset_timeout", "soon"]).is_err());
        assert!(HhfConfig::parse_params(&["unknown"]).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_dsmark_parse() {
        let cfg =
            DsmarkConfig::parse_params(&["indices", "64", "default_index", "0", "set_tc_index"])
                .unwrap();
        assert_eq!(cfg.indices, Some(64));
        assert_eq!(cfg.default_index, Some(0));
        assert!(cfg.set_tc_index);

        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();

        // strict: missing value, bad value, unknown token.
        assert!(DsmarkConfig::parse_params(&["indices"]).is_err());
        assert!(DsmarkConfig::parse_params(&["indices", "x"]).is_err());
        assert!(DsmarkConfig::parse_params(&["unknown"]).is_err());
        // and a missing `indices`, which the kernel would refuse (#347).
        let err = DsmarkConfig::parse_params(&["set_tc_index"]).unwrap_err();
        assert!(err.to_string().contains("dsmark: `indices <n>` is required"), "{err}");
    }

    /// `DsmarkConfig::new().build()` used to send an empty `TCA_OPTIONS`
    /// nest, which `dsmark_init` refuses with EINVAL because
    /// `TCA_DSMARK_INDICES` has no default. The request the kernel cannot
    /// accept is now a readable error before it is sent; with `indices`
    /// the nest carries exactly that attribute (#347).
    #[test]
    #[allow(deprecated)]
    fn dsmark_without_indices_is_an_error_not_an_empty_nest() {
        use crate::netlink::test_support::qdisc_attrs;
        use crate::netlink::types::tc::qdisc::dsmark::*;

        let mut b = MessageBuilder::new(0, 0);
        let err = DsmarkConfig::new().build().write_options(&mut b).unwrap_err();
        assert!(err.to_string().contains("dsmark: indices is required"), "{err}");
        assert_eq!(b.len(), MessageBuilder::new(0, 0).len(), "nothing written on error");

        let attrs = qdisc_attrs(&DsmarkConfig::new().indices(64).build());
        assert_eq!(attrs.get(&TCA_DSMARK_INDICES).map(Vec::as_slice), Some(&64u16.to_ne_bytes()[..]));
        assert!(!attrs.contains_key(&TCA_DSMARK_DEFAULT_INDEX));
        assert!(!attrs.contains_key(&TCA_DSMARK_SET_TC_INDEX));

        let attrs = qdisc_attrs(&DsmarkConfig::new().indices(16).default_index(3).set_tc_index().build());
        assert_eq!(attrs.get(&TCA_DSMARK_DEFAULT_INDEX).map(Vec::as_slice), Some(&3u16.to_ne_bytes()[..]));
        assert_eq!(attrs.get(&TCA_DSMARK_SET_TC_INDEX).map(Vec::len), Some(0));
    }

    #[test]
    fn test_netem_builder() {
        use crate::util::Percent;
        let config = NetemConfig::new()
            .delay(Duration::from_millis(100))
            .jitter(Duration::from_millis(10))
            .delay_correlation(Percent::new(25.0))
            .loss(Percent::new(1.0))
            .build();

        assert_eq!(config.delay, Some(Duration::from_millis(100)));
        assert_eq!(config.jitter, Some(Duration::from_millis(10)));
        assert_eq!(config.delay_correlation.as_percent(), 25.0);
        assert_eq!(config.loss.as_percent(), 1.0);
        assert_eq!(config.kind(), "netem");
    }

    #[test]
    fn test_fq_codel_builder() {
        let config = FqCodelConfig::new()
            .target(Duration::from_millis(5))
            .interval(Duration::from_millis(100))
            .limit(crate::util::Packets::new(10000))
            .ecn(true)
            .build();

        assert_eq!(config.target, Some(Duration::from_millis(5)));
        assert_eq!(config.interval, Some(Duration::from_millis(100)));
        assert_eq!(config.limit, Some(crate::util::Packets::new(10000)));
        assert_eq!(config.ecn, Some(true));
        assert_eq!(config.kind(), "fq_codel");
    }

    #[test]
    fn test_tbf_builder() {
        use crate::util::{Bytes, Rate};
        let config = TbfConfig::new()
            .rate(Rate::bytes_per_sec(1_000_000))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(100))
            .build();

        assert_eq!(config.rate, Rate::bytes_per_sec(1_000_000));
        assert_eq!(config.burst, Bytes::kib(32));
        assert_eq!(config.limit, Bytes::kib(100));
        assert_eq!(config.kind(), "tbf");
    }

    #[test]
    fn test_netem_clamp() {
        use crate::util::Percent;
        let config = NetemConfig::new()
            .loss(Percent::new(150.0)) // Should clamp to 100
            .delay_correlation(Percent::new(-10.0)) // Should clamp to 0
            .build();

        assert_eq!(config.loss.as_percent(), 100.0);
        assert_eq!(config.delay_correlation.as_percent(), 0.0);
    }

    #[test]
    fn test_drr_builder() {
        let config = DrrConfig::new().build();

        assert_eq!(config.kind(), "drr");
    }

    #[test]
    fn test_qfq_builder() {
        let config = QfqConfig::new().build();

        assert_eq!(config.kind(), "qfq");
    }

    #[test]
    fn test_plug_builder() {
        let config = PlugConfig::new()
            .limit(crate::util::Bytes::new(10000))
            .build();

        assert_eq!(config.limit, Some(10000));
        assert_eq!(config.kind(), "plug");
    }

    /// `PlugConfig::new()` must send **no** `TCA_OPTIONS`, not an empty
    /// one: `plug_init` takes the absent nest as "kernel default limit"
    /// and refuses an empty nest as shorter than `tc_plug_qopt` (#327).
    /// With a limit, the nest carries exactly the 8-byte struct.
    #[test]
    fn plug_without_limit_sends_no_options_at_all() {
        use crate::netlink::types::tc::qdisc::plug::TcPlugQopt;

        let bare = PlugConfig::new().build();
        assert!(!bare.has_options(), "no limit → no TCA_OPTIONS nest");
        let mut b = MessageBuilder::new(0, 0);
        let header = b.len();
        bare.write_options(&mut b).unwrap();
        assert_eq!(b.len(), header, "nothing to write without a limit");

        let limited = PlugConfig::new()
            .limit(crate::util::Bytes::new(65536))
            .build();
        assert!(limited.has_options());
        let mut b = MessageBuilder::new(0, 0);
        limited.write_options(&mut b).unwrap();
        assert_eq!(b.len() - header, TcPlugQopt::SIZE);
        assert_eq!(TcPlugQopt::SIZE, 8);

        // Every other qdisc keeps the nest — the default is not
        // "skip empty nests", which would break kinds that read their
        // defaults from one.
        assert!(NetemConfig::new().build().has_options());
        assert!(IngressConfig::new().has_options());
    }

    #[test]
    fn test_mqprio_builder() {
        let config = MqprioConfig::new()
            .num_tc(4)
            .map(&[0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3])
            .hw_offload(true)
            .queues(&[(2, 0), (2, 2), (2, 4), (2, 6)])
            .build();

        assert_eq!(config.num_tc, 4);
        assert!(config.hw);
        assert_eq!(config.prio_tc_map[0], 0);
        assert_eq!(config.prio_tc_map[3], 3);
        assert_eq!(config.count[0], 2);
        assert_eq!(config.offset[1], 2);
        assert_eq!(config.kind(), "mqprio");
    }

    #[test]
    fn test_etf_builder() {
        let config = EtfConfig::new()
            .clockid(1) // CLOCK_MONOTONIC on most systems
            .delta_ns(300000)
            .deadline_mode(true)
            .offload(true)
            .skip_sock_check(false)
            .build();

        assert_eq!(config.clockid, 1);
        assert_eq!(config.delta, 300000);
        assert!(config.deadline_mode);
        assert!(config.offload);
        assert!(!config.skip_sock_check);
        assert_eq!(config.kind(), "etf");
    }

    #[test]
    fn test_hfsc_builder() {
        let config = HfscConfig::new().default_class(0x10).build();

        assert_eq!(config.default_class, 0x10);
        assert_eq!(config.kind(), "hfsc");
    }

    #[test]
    fn test_taprio_builder() {
        let config = TaprioConfig::new()
            .num_tc(2)
            .map(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .queues(&[(1, 0), (1, 1)])
            .clockid(11) // CLOCK_TAI
            .base_time(1000000000)
            .cycle_time(1000000)
            .entry(TaprioSchedEntry::set_gates(0x1, 500000))
            .entry(TaprioSchedEntry::set_gates(0x2, 500000))
            .full_offload(true)
            .build();

        assert_eq!(config.num_tc, 2);
        assert_eq!(config.clockid, 11);
        assert_eq!(config.base_time, 1000000000);
        assert_eq!(config.cycle_time, 1000000);
        assert_eq!(config.entries.len(), 2);
        assert_eq!(config.entries[0].gate_mask, 0x1);
        assert_eq!(config.entries[0].interval, 500000);
        assert_eq!(config.entries[1].gate_mask, 0x2);
        assert!(config.flags & 2 != 0); // FULL_OFFLOAD flag
        assert_eq!(config.kind(), "taprio");
    }

    #[test]
    fn test_htb_class_config_typed() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::mbit(100))
            .ceil(Rate::mbit(500))
            .prio(1)
            .quantum(1500)
            .build();

        assert_eq!(config.rate, Rate::mbit(100));
        assert_eq!(config.ceil, Some(Rate::mbit(500)));
        assert_eq!(config.prio, Some(1));
        assert_eq!(config.quantum, Some(1500));
        assert_eq!(config.kind(), "htb");
    }

    #[test]
    fn test_htb_class_config_from_string() {
        use crate::util::Rate;
        // Parse via FromStr first, then construct.
        let config = HtbClassConfig::new("100mbit".parse::<Rate>().unwrap())
            .ceil("500mbit".parse::<Rate>().unwrap())
            .prio(2)
            .build();

        assert_eq!(config.rate, Rate::mbit(100));
        assert_eq!(config.ceil, Some(Rate::mbit(500)));
        assert_eq!(config.prio, Some(2));
        assert_eq!(config.kind(), "htb");
    }

    #[test]
    fn test_htb_class_config_burst() {
        use crate::util::{Bytes, Rate};
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000))
            .burst(Bytes::new(16384))
            .cburst(Bytes::new(32768))
            .mtu(9000)
            .mpu(64)
            .overhead(14)
            .build();

        assert_eq!(config.burst, Some(Bytes::new(16384)));
        assert_eq!(config.cburst, Some(Bytes::new(32768)));
        assert_eq!(config.mtu, 9000);
        assert_eq!(config.mpu, 64);
        assert_eq!(config.overhead, 14);
    }

    #[test]
    fn test_htb_class_config_prio_clamp() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000))
            .prio(100) // Should clamp to 7
            .build();

        assert_eq!(config.prio, Some(7));
    }

    #[test]
    fn test_htb_class_config_defaults() {
        use crate::util::Rate;
        let config = HtbClassConfig::new(Rate::bytes_per_sec(1_000_000)).build();

        // ceil defaults to rate
        assert_eq!(config.ceil, None);
        // Other defaults
        assert_eq!(config.burst, None);
        assert_eq!(config.cburst, None);
        assert_eq!(config.prio, None);
        assert_eq!(config.quantum, None);
        assert_eq!(config.mtu, 1600);
        assert_eq!(config.mpu, 0);
        assert_eq!(config.overhead, 0);
    }

    #[test]
    fn htb_qdisc_parse_params_empty_yields_defaults() {
        let cfg = HtbQdiscConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.default_class, 0);
        assert_eq!(cfg.r2q, 10);
        assert_eq!(cfg.direct_qlen, None);
    }

    #[test]
    fn htb_qdisc_parse_params_default_as_handle() {
        // tc handle form: "1:10" -> raw u32 of TcHandle::new(1, 0x10)
        let cfg = HtbQdiscConfig::parse_params(&["default", "1:10"]).unwrap();
        assert_eq!(
            cfg.default_class,
            crate::netlink::tc_handle::TcHandle::new(1, 0x10).as_raw(),
        );
    }

    #[test]
    fn htb_qdisc_parse_params_default_as_bare_hex() {
        // bare-hex form mirrors `tc(8)`: "default 10" means minor 0x10.
        let cfg = HtbQdiscConfig::parse_params(&["default", "10"]).unwrap();
        assert_eq!(cfg.default_class, 0x10);
        let cfg = HtbQdiscConfig::parse_params(&["default", "ff"]).unwrap();
        assert_eq!(cfg.default_class, 0xff);
    }

    #[test]
    fn htb_qdisc_parse_params_all_three() {
        let cfg =
            HtbQdiscConfig::parse_params(&["default", "1:10", "r2q", "5", "direct_qlen", "1000"])
                .unwrap();
        assert_eq!(
            cfg.default_class,
            crate::netlink::tc_handle::TcHandle::new(1, 0x10).as_raw(),
        );
        assert_eq!(cfg.r2q, 5);
        assert_eq!(cfg.direct_qlen, Some(crate::util::Packets::new(1000)));
    }

    #[test]
    fn htb_qdisc_parse_params_unknown_token_errors() {
        // Legacy parser silently swallowed `default_class` (a typo for
        // `default`); the typed parser rejects it so callers see the
        // mistake immediately.
        let err = HtbQdiscConfig::parse_params(&["default_class", "1:10"]).unwrap_err();
        assert!(
            err.to_string().contains("unknown token"),
            "expected unknown-token error, got: {err}"
        );
    }

    #[test]
    fn htb_qdisc_parse_params_missing_value_errors() {
        let err = HtbQdiscConfig::parse_params(&["default"]).unwrap_err();
        assert!(
            err.to_string().contains("requires a value"),
            "expected missing-value error, got: {err}"
        );
        let err = HtbQdiscConfig::parse_params(&["r2q"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn htb_qdisc_parse_params_invalid_number_errors() {
        let err = HtbQdiscConfig::parse_params(&["r2q", "not-a-number"]).unwrap_err();
        assert!(
            err.to_string().contains("invalid r2q"),
            "expected invalid-r2q error, got: {err}"
        );
        let err = HtbQdiscConfig::parse_params(&["direct_qlen", "x"]).unwrap_err();
        assert!(err.to_string().contains("invalid direct_qlen"));
    }

    #[test]
    fn htb_qdisc_parse_params_invalid_default_errors() {
        // Bare "abcdefg" is not a valid hex u32.
        let err = HtbQdiscConfig::parse_params(&["default", "zzzz"]).unwrap_err();
        assert!(
            err.to_string().contains("invalid default class"),
            "got: {err}"
        );
    }

    #[test]
    fn netem_parse_params_empty_yields_defaults() {
        let cfg = NetemConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.delay, None);
        assert_eq!(cfg.jitter, None);
        assert!(cfg.loss.is_zero());
        assert_eq!(cfg.limit, crate::util::Packets::new(1000));
    }

    #[test]
    fn netem_parse_params_delay_only() {
        let cfg = NetemConfig::parse_params(&["delay", "100ms"]).unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, None);
    }

    #[test]
    fn netem_parse_params_delay_with_jitter_and_corr() {
        let cfg = NetemConfig::parse_params(&["delay", "100ms", "10ms", "25%"]).unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, Some(Duration::from_millis(10)));
        // Percent::new(25.0) produces 25% (kernel probability ~ 25/100 * u32::MAX).
        assert!(!cfg.delay_correlation.is_zero());
    }

    #[test]
    fn netem_parse_params_loss_with_random_qualifier() {
        let cfg = NetemConfig::parse_params(&["loss", "random", "1.5%"]).unwrap();
        assert!(!cfg.loss.is_zero());
    }

    #[test]
    fn netem_parse_params_drop_alias() {
        // `drop` is the legacy alias for `loss`.
        let cfg = NetemConfig::parse_params(&["drop", "0.5%"]).unwrap();
        assert!(!cfg.loss.is_zero());
    }

    #[test]
    fn netem_parse_params_multiple_groups() {
        let cfg = NetemConfig::parse_params(&[
            "delay",
            "100ms",
            "10ms",
            "loss",
            "1%",
            "duplicate",
            "0.1%",
            "limit",
            "5000",
        ])
        .unwrap();
        assert_eq!(cfg.delay, Some(Duration::from_millis(100)));
        assert_eq!(cfg.jitter, Some(Duration::from_millis(10)));
        assert!(!cfg.loss.is_zero());
        assert!(!cfg.duplicate.is_zero());
        assert_eq!(cfg.limit, crate::util::Packets::new(5000));
    }

    #[test]
    fn netem_parse_params_rate_no_extras() {
        let cfg = NetemConfig::parse_params(&["rate", "100mbit"]).unwrap();
        // 100mbit = 12_500_000 bytes/sec. The previous implementation
        // mis-routed get_rate (which returns bits) through
        // Rate::bytes_per_sec, ending up at 100_000_000 (= 800mbit).
        // Switching to Rate::parse fixed the units bug.
        assert_eq!(
            cfg.rate.map(|r| r.as_bytes_per_sec()),
            Some(12_500_000),
            "100mbit should round-trip to 12.5 MB/sec"
        );
    }

    #[test]
    fn netem_parse_params_rate_extras() {
        // tc(8)'s `rate R PACKETOVERHEAD CELLSIZE CELLOVERHEAD`, greedy up
        // to the next keyword; the overheads are signed.
        let cfg =
            NetemConfig::parse_params(&["rate", "1mbit", "-4", "53", "5", "limit", "9"]).unwrap();
        assert_eq!(
            (
                cfg.rate_packet_overhead,
                cfg.rate_cell_size,
                cfg.rate_cell_overhead
            ),
            (-4, 53, 5)
        );
        assert_eq!(cfg.limit, crate::util::Packets::new(9));
        let cfg = NetemConfig::parse_params(&["rate", "1mbit", "20"]).unwrap();
        assert_eq!((cfg.rate_packet_overhead, cfg.rate_cell_size), (20, 0));
        for bad in [
            &["rate", "1mbit", "1", "2", "3", "4"][..],
            &["rate", "1mbit", "x"],
        ] {
            let err = NetemConfig::parse_params(bad).unwrap_err();
            assert!(err.to_string().contains("netem: "), "got: {err}");
        }
    }

    #[test]
    fn netem_parse_params_unknown_token_errors() {
        let err = NetemConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_ecn_seed_slot() {
        let cfg = NetemConfig::parse_params(&[
            "delay",
            "10ms",
            "ecn",
            "seed",
            "18446744073709551615",
            "slot",
            "1ms",
            "2ms",
            "packets",
            "5",
            "bytes",
            "3000",
            "loss",
            "1%",
        ])
        .unwrap();
        assert!(cfg.ecn);
        assert_eq!(cfg.seed, Some(u64::MAX));
        assert_eq!(
            cfg.slot,
            Some(
                NetemSlot::new(Duration::from_millis(1), Duration::from_millis(2))
                    .packets(crate::util::Packets::new(5))
                    .bytes(3000)
            )
        );
        assert_eq!(cfg.loss, Percent::new(1.0));

        // tc(8): an omitted maximum is the minimum.
        let cfg = NetemConfig::parse_params(&["slot", "3ms", "packets", "2"]).unwrap();
        assert_eq!(
            cfg.slot,
            Some(NetemSlot::new(Duration::from_millis(3), Duration::from_millis(3)).packets(crate::util::Packets::new(2)))
        );
    }

    #[test]
    fn netem_parse_params_new_tokens_are_strict() {
        for (params, needle) in [
            (&["seed"][..], "`seed` requires a value"),
            (&["seed", "-1"], "invalid seed"),
            (&["slot"], "`slot` requires"),
            (&["slot", "x"], "invalid slot minimum delay"),
            (&["slot", "1ms", "packets"], "slot `packets` requires"),
            (&["slot", "1ms", "bytes", "lots"], "invalid slot bytes"),
            (
                &["slot", "distribution", "normal", "1ms", "1ms"],
                "not modelled",
            ),
            (&["distribution"], "requires a table name"),
            (&["distribution", "../normal"], "not a table name"),
            (&["distribution", "no-such-table"], "no distribution table"),
        ] {
            let err = NetemConfig::parse_params(params).unwrap_err().to_string();
            assert!(
                err.contains(needle),
                "{params:?}: expected `{needle}`, got: {err}"
            );
            assert!(err.contains("netem: "), "{params:?}: {err}");
        }
    }

    /// The attributes after `tc_netem_qopt`, which netem writes bare,
    /// ahead of its attribute stream.
    fn netem_attrs(cfg: &NetemConfig) -> crate::netlink::test_support::AttrMap {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write_options(&mut b).unwrap();
        crate::netlink::test_support::parse_attrs(&b.as_bytes()[start + TcNetemQopt::SIZE..])
    }

    /// The new fields on the wire (#515), against `struct tc_netem_rate`,
    /// `struct tc_netem_slot` and the attribute types in `pkt_sched.h`.
    #[test]
    fn netem_writes_ecn_slot_seed_and_rate_overhead() {
        let cfg = NetemConfig::new()
            .rate(crate::util::Rate::bytes_per_sec(125_000))
            .rate_overhead(-4, 53, 5)
            .ecn(true)
            .seed(0x0102_0304_0506_0708)
            .slot(NetemSlot::new(Duration::from_millis(1), Duration::from_millis(2)).packets(crate::util::Packets::new(5)));
        let attrs = netem_attrs(&cfg);
        let rate = &attrs[&TCA_NETEM_RATE];
        assert_eq!(rate.len(), 16);
        assert_eq!(u32::from_ne_bytes(rate[0..4].try_into().unwrap()), 125_000);
        assert_eq!(i32::from_ne_bytes(rate[4..8].try_into().unwrap()), -4);
        assert_eq!(u32::from_ne_bytes(rate[8..12].try_into().unwrap()), 53);
        assert_eq!(i32::from_ne_bytes(rate[12..16].try_into().unwrap()), 5);
        assert_eq!(attrs[&TCA_NETEM_ECN], 1u32.to_ne_bytes());
        assert_eq!(
            attrs[&TCA_NETEM_PRNG_SEED],
            0x0102_0304_0506_0708u64.to_ne_bytes()
        );
        let slot = &attrs[&TCA_NETEM_SLOT];
        assert_eq!(slot.len(), 40);
        assert_eq!(
            i64::from_ne_bytes(slot[0..8].try_into().unwrap()),
            1_000_000
        );
        assert_eq!(
            i64::from_ne_bytes(slot[8..16].try_into().unwrap()),
            2_000_000
        );
        assert_eq!(i32::from_ne_bytes(slot[16..20].try_into().unwrap()), 5);
        // 0 is the kernel's "unlimited" for the byte limit not set.
        assert_eq!(i32::from_ne_bytes(slot[20..24].try_into().unwrap()), 0);
        assert!(slot[24..].iter().all(|&b| b == 0), "no slot distribution");
        assert!(!attrs.contains_key(&TCA_NETEM_DELAY_DIST));

        // Unset: ECN and the slot are written off, so a replace clears
        // them; the seed is left for the kernel to pick.
        let attrs = netem_attrs(&NetemConfig::new());
        assert_eq!(attrs[&TCA_NETEM_ECN], 0u32.to_ne_bytes());
        assert!(attrs[&TCA_NETEM_SLOT].iter().all(|&b| b == 0));
        assert!(!attrs.contains_key(&TCA_NETEM_PRNG_SEED));
    }

    #[test]
    fn netem_distribution_table_on_the_wire() {
        let dist = NetemDistribution::from_table(vec![-32768, -1, 0, 1, 32767]).unwrap();
        let cfg = NetemConfig::new()
            .delay(Duration::from_millis(10))
            .jitter(Duration::from_millis(2))
            .distribution(dist);
        let attrs = netem_attrs(&cfg);
        let want: Vec<u8> = [-32768i16, -1, 0, 1, 32767]
            .iter()
            .flat_map(|v| v.to_ne_bytes())
            .collect();
        assert_eq!(attrs[&TCA_NETEM_DELAY_DIST], want);
    }

    #[test]
    fn netem_distribution_needs_delay_and_jitter() {
        let dist = || NetemDistribution::from_table(vec![0]).unwrap();
        for cfg in [
            NetemConfig::new().distribution(dist()),
            NetemConfig::new()
                .delay(Duration::from_millis(10))
                .distribution(dist()),
            NetemConfig::new()
                .delay(Duration::from_millis(10))
                .jitter(Duration::ZERO)
                .distribution(dist()),
        ] {
            let mut b = MessageBuilder::new(0, 0);
            let err = cfg.write_options(&mut b).unwrap_err();
            assert!(
                err.to_string().contains("needs a delay and a jitter"),
                "got: {err}"
            );
        }
        let mut b = MessageBuilder::new(0, 0);
        let err = NetemConfig::new()
            .slot(NetemSlot::new(
                Duration::from_millis(2),
                Duration::from_millis(1),
            ))
            .write_options(&mut b)
            .unwrap_err();
        assert!(
            err.to_string().contains("above its max_delay"),
            "got: {err}"
        );
    }

    #[test]
    fn netem_distribution_table_limits() {
        assert!(NetemDistribution::from_table(Vec::new()).is_err());
        assert!(NetemDistribution::from_table(vec![0; NetemDistribution::MAX_LEN]).is_ok());
        assert!(NetemDistribution::from_table(vec![0; NetemDistribution::MAX_LEN + 1]).is_err());
    }

    #[test]
    fn netem_distribution_reads_an_iproute2_file() {
        let dir = std::env::temp_dir().join(format!("nlink-dist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiny.dist");
        std::fs::write(&path, "# comment\n -3 4\n\t5 # trailing\n").unwrap();
        assert_eq!(
            NetemDistribution::from_file(&path).unwrap().table(),
            [-3, 4, 5]
        );
        std::fs::write(&path, "1 40000\n").unwrap();
        let err = NetemDistribution::from_file(&path).unwrap_err().to_string();
        assert!(err.contains("`40000` is not a table entry"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();

        // iproute2's own table, when it is installed: 4096 entries, from
        // the most negative i16.
        if let Ok(normal) = NetemDistribution::named("normal") {
            assert_eq!(normal.table().len(), 4096);
            assert_eq!(normal.table()[0], -32768);
        }
    }

    // The Markov loss models (#368). Every expected value below is what
    // iproute2 6.15 put in the kernel for the same `tc` arguments, read back
    // through `parse_netem_loss_model` — so these pin tc(8)'s semantics,
    // not this parser's opinion of them.

    fn ge(m: &NetemLossModel) -> (f64, f64, f64, f64) {
        match *m {
            NetemLossModel::GilbertElliot { p, r, h, k1 } => (p, r, h, k1),
            other => panic!("expected Gilbert-Elliot, got {other:?}"),
        }
    }

    fn gi(m: &NetemLossModel) -> (f64, f64, f64, f64, f64) {
        match *m {
            NetemLossModel::GilbertIntuitive {
                p13,
                p31,
                p32,
                p14,
                p23,
            } => (p13, p31, p32, p14, p23),
            other => panic!("expected Gilbert-Intuitive, got {other:?}"),
        }
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn netem_parse_params_gemodel_full() {
        // tc: `loss gemodel 1% 10% 70% 0.1%` -> kernel p=1 r=10 h=30 k1=0.1.
        // `1-h` is converted (70 -> h 30); `1-k` is sent as given.
        let cfg = NetemConfig::parse_params(&["loss", "gemodel", "1%", "10%", "70%", "0.1%"]).unwrap();
        let (p, r, h, k1) = ge(cfg.loss_model.as_ref().unwrap());
        assert!(close(p, 1.0) && close(r, 10.0) && close(h, 30.0) && close(k1, 0.1), "{p} {r} {h} {k1}");
        assert!(cfg.loss.is_zero(), "a model must not also set random loss");
    }

    #[test]
    fn netem_parse_params_gemodel_tc_defaults() {
        // tc: `loss gemodel 1%` -> r = 100 - p, 1-h = 100% (h 0), 1-k = 0.
        let cfg = NetemConfig::parse_params(&["loss", "gemodel", "1%"]).unwrap();
        let (p, r, h, k1) = ge(cfg.loss_model.as_ref().unwrap());
        assert!(close(p, 1.0) && close(r, 99.0) && close(h, 0.0) && close(k1, 0.0), "{p} {r} {h} {k1}");
        // and the partial forms keep the defaults for what they omit
        let cfg = NetemConfig::parse_params(&["loss", "gemodel", "1%", "10%", "70%"]).unwrap();
        let (_, r, h, k1) = ge(cfg.loss_model.as_ref().unwrap());
        assert!(close(r, 10.0) && close(h, 30.0) && close(k1, 0.0), "{r} {h} {k1}");
    }

    #[test]
    fn netem_parse_params_state_takes_p23_before_p14() {
        // tc: `loss state 1% 2% 3% 4% 5%` is p13 p31 p32 *p23 p14*; the
        // kernel struct stores p14 before p23. Read back: p14 5, p23 4.
        let cfg = NetemConfig::parse_params(&["loss", "state", "1%", "2%", "3%", "4%", "5%"]).unwrap();
        let (p13, p31, p32, p14, p23) = gi(cfg.loss_model.as_ref().unwrap());
        assert!(close(p13, 1.0) && close(p31, 2.0) && close(p32, 3.0), "{p13} {p31} {p32}");
        assert!(close(p23, 4.0) && close(p14, 5.0), "p23 {p23} p14 {p14} — swapped?");
    }

    #[test]
    fn netem_parse_params_state_tc_defaults() {
        // tc: `loss state 1%` -> p31 = 100 - p13, p32 0, p23 100, p14 0.
        let cfg = NetemConfig::parse_params(&["loss", "state", "1%"]).unwrap();
        let (p13, p31, p32, p14, p23) = gi(cfg.loss_model.as_ref().unwrap());
        assert!(close(p13, 1.0) && close(p31, 99.0) && close(p32, 0.0), "{p13} {p31} {p32}");
        assert!(close(p23, 100.0) && close(p14, 0.0), "{p23} {p14}");
    }

    #[test]
    fn netem_parse_params_loss_model_then_more_groups() {
        let cfg = NetemConfig::parse_params(&["drop", "gemodel", "2%", "delay", "10ms", "limit", "50"]).unwrap();
        assert!(matches!(cfg.loss_model, Some(NetemLossModel::GilbertElliot { .. })));
        assert_eq!(cfg.delay, Some(Duration::from_millis(10)));
        assert_eq!(cfg.limit, crate::util::Packets::new(50));
    }

    #[test]
    fn netem_parse_params_loss_model_arity_errors() {
        let err = NetemConfig::parse_params(&["loss", "gemodel"]).unwrap_err();
        assert!(err.to_string().contains("takes <p>"), "got: {err}");
        let err = NetemConfig::parse_params(&["loss", "gemodel", "1", "2", "3", "4", "5"]).unwrap_err();
        assert!(err.to_string().contains("got 5"), "got: {err}");
        let err = NetemConfig::parse_params(&["loss", "state", "1", "2", "3", "4", "5", "6"]).unwrap_err();
        assert!(err.to_string().contains("got 6"), "got: {err}");
        let err = NetemConfig::parse_params(&["loss", "state", "lots"]).unwrap_err();
        assert!(err.to_string().contains("invalid loss state value"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_random_with_a_model_rejected() {
        let err = NetemConfig::parse_params(&["loss", "random", "gemodel", "1%"]).unwrap_err();
        assert!(err.to_string().contains("mixes two loss generators"), "got: {err}");
    }

    #[test]
    fn netem_loss_model_excludes_random_loss_at_write() {
        let model = NetemLossModel::gilbert_elliot(Percent::new(1.0));
        for cfg in [
            NetemConfig::new().loss(Percent::new(1.0)).loss_model(model),
            NetemConfig::new().loss_correlation(Percent::new(25.0)).loss_model(model),
        ] {
            let mut b = MessageBuilder::new(0, 0);
            let err = cfg.write_options(&mut b).unwrap_err();
            assert!(err.to_string().contains("excludes random `loss`"), "got: {err}");
        }
    }

    /// #370: a replace is `netem_change()`, which keeps every attribute
    /// it is not sent, so the "off" state must be written explicitly —
    /// otherwise a declaration that drops `rate`/`reorder`/`corrupt` can
    /// never reach the kernel.
    #[test]
    fn netem_writes_off_states_so_a_replace_can_clear_them() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        NetemConfig::new().build().write_options(&mut b).unwrap();
        let blob = &b.as_bytes()[start..];
        // Walk the attributes after the fixed tc_netem_qopt.
        let mut attrs = std::collections::HashMap::new();
        let mut rest = &blob[TcNetemQopt::SIZE..];
        while rest.len() >= 4 {
            let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
            let ty = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3FFF;
            attrs.insert(ty, rest[4..len].to_vec());
            rest = &rest[((len + 3) & !3).min(rest.len())..];
        }
        for (ty, name) in [
            (TCA_NETEM_CORR, "CORR"),
            (TCA_NETEM_REORDER, "REORDER"),
            (TCA_NETEM_CORRUPT, "CORRUPT"),
            (TCA_NETEM_RATE, "RATE"),
        ] {
            let payload = attrs.get(&ty).unwrap_or_else(|| panic!("TCA_NETEM_{name} not written"));
            assert!(payload.iter().all(|&x| x == 0), "TCA_NETEM_{name} is not the off state: {payload:?}");
        }
        assert!(!attrs.contains_key(&TCA_NETEM_RATE64), "RATE64 only when the rate needs it");
        assert!(!attrs.contains_key(&TCA_NETEM_LOSS), "no loss model unless one is set");
    }

    #[test]
    fn netem_loss_model_builders_match_tc_semantics() {
        // The named setters do tc's `1-h` conversion; the variant stores
        // the kernel's `h`.
        let m = NetemLossModel::gilbert_elliot(Percent::new(1.0))
            .r(Percent::new(30.0))
            .loss_in_bad(Percent::new(50.0))
            .loss_in_good(Percent::new(0.1));
        let (p, r, h, k1) = ge(&m);
        assert!(close(p, 1.0) && close(r, 30.0) && close(h, 50.0) && close(k1, 0.1));
        // A setter for the other model is a no-op, not a panic.
        assert_eq!(m.p14(Percent::new(9.0)), m);
        let s = NetemLossModel::gilbert_intuitive(Percent::new(1.0)).r(Percent::new(9.0));
        assert_eq!(s, NetemLossModel::gilbert_intuitive(Percent::new(1.0)));
    }

    #[test]
    fn netem_parse_params_missing_value_errors() {
        let err = NetemConfig::parse_params(&["delay"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got: {err}");
        let err = NetemConfig::parse_params(&["loss"]).unwrap_err();
        assert!(err.to_string().contains("percent value"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_invalid_time_errors() {
        let err = NetemConfig::parse_params(&["delay", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid delay"), "got: {err}");
    }

    #[test]
    fn netem_parse_params_invalid_percent_errors() {
        let err = NetemConfig::parse_params(&["loss", "lots"]).unwrap_err();
        assert!(err.to_string().contains("invalid loss"), "got: {err}");
    }

    #[test]
    fn cake_parse_params_empty_yields_default() {
        let cfg = CakeConfig::parse_params(&[]).unwrap();
        assert!(cfg.bandwidth.is_none());
        assert!(cfg.rtt.is_none());
        assert!(cfg.diffserv_mode.is_none());
        assert!(cfg.flow_mode.is_none());
        assert!(!cfg.nat);
        assert!(!cfg.wash);
    }

    #[test]
    fn cake_parse_params_bandwidth_and_rtt() {
        let cfg = CakeConfig::parse_params(&["bandwidth", "100mbit", "rtt", "20ms"]).unwrap();
        assert_eq!(
            cfg.bandwidth.map(|r| r.as_bytes_per_sec()),
            Some(12_500_000)
        );
        assert_eq!(cfg.rtt, Some(Duration::from_millis(20)));
    }

    #[test]
    fn cake_parse_params_unlimited_flag() {
        let cfg = CakeConfig::parse_params(&["unlimited"]).unwrap();
        assert_eq!(cfg.bandwidth, Some(crate::util::Rate::ZERO));
    }

    #[test]
    fn cake_parse_params_diffserv_modes() {
        for (token, expected) in [
            ("diffserv3", CakeDiffserv::Diffserv3),
            ("diffserv4", CakeDiffserv::Diffserv4),
            ("diffserv8", CakeDiffserv::Diffserv8),
            ("besteffort", CakeDiffserv::Besteffort),
            ("precedence", CakeDiffserv::Precedence),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.diffserv_mode, Some(expected), "diffserv {token}");
        }
    }

    #[test]
    fn cake_parse_params_flow_modes() {
        for (token, expected) in [
            ("flowblind", CakeFlowMode::Flowblind),
            ("srchost", CakeFlowMode::Srchost),
            ("dsthost", CakeFlowMode::Dsthost),
            ("hosts", CakeFlowMode::Hosts),
            ("flows", CakeFlowMode::Flows),
            ("dual-srchost", CakeFlowMode::DualSrchost),
            ("dual-dsthost", CakeFlowMode::DualDsthost),
            ("triple-isolate", CakeFlowMode::Triple),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.flow_mode, Some(expected), "flow {token}");
        }
    }

    #[test]
    fn cake_parse_params_atm_modes() {
        for (token, expected) in [
            ("noatm", CakeAtmMode::None),
            ("atm", CakeAtmMode::Atm),
            ("ptm", CakeAtmMode::Ptm),
        ] {
            let cfg = CakeConfig::parse_params(&[token]).unwrap();
            assert_eq!(cfg.atm_mode, Some(expected), "atm {token}");
        }
    }

    #[test]
    fn cake_parse_params_ack_filter() {
        let cfg = CakeConfig::parse_params(&["ack-filter"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Filter));
        let cfg = CakeConfig::parse_params(&["ack-filter-aggressive"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Aggressive));
        let cfg = CakeConfig::parse_params(&["no-ack-filter"]).unwrap();
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Disabled));
    }

    #[test]
    fn cake_parse_params_boolean_flags_with_negations() {
        let cfg =
            CakeConfig::parse_params(&["nat", "wash", "ingress", "split-gso", "raw"]).unwrap();
        assert!(cfg.nat);
        assert!(cfg.wash);
        assert!(cfg.ingress);
        assert!(cfg.split_gso);
        assert!(cfg.raw);

        // Negations override.
        let cfg =
            CakeConfig::parse_params(&["nat", "nonat", "wash", "nowash", "ingress", "egress"])
                .unwrap();
        assert!(!cfg.nat);
        assert!(!cfg.wash);
        assert!(!cfg.ingress);
    }

    #[test]
    fn cake_parse_params_overhead_signed() {
        let cfg = CakeConfig::parse_params(&["overhead", "-4"]).unwrap();
        assert_eq!(cfg.overhead, Some(-4));
        let cfg = CakeConfig::parse_params(&["overhead", "38"]).unwrap();
        assert_eq!(cfg.overhead, Some(38));
    }

    #[test]
    fn cake_parse_params_memlimit_size() {
        let cfg = CakeConfig::parse_params(&["memlimit", "32k"]).unwrap();
        assert_eq!(cfg.memory_limit.map(|b| b.as_u64()), Some(32 * 1024));
    }

    #[test]
    fn cake_parse_params_fwmark_hex() {
        let cfg = CakeConfig::parse_params(&["fwmark", "0xff"]).unwrap();
        assert_eq!(cfg.fwmark, Some(0xff));
        // Bare hex without 0x prefix.
        let cfg = CakeConfig::parse_params(&["fwmark", "ff"]).unwrap();
        assert_eq!(cfg.fwmark, Some(0xff));
    }

    #[test]
    fn cake_parse_params_realistic_combo() {
        // A typical bufferbloat-mitigation config.
        let cfg = CakeConfig::parse_params(&[
            "bandwidth",
            "100mbit",
            "rtt",
            "20ms",
            "diffserv4",
            "triple-isolate",
            "ack-filter",
            "nat",
            "wash",
        ])
        .unwrap();
        assert!(cfg.bandwidth.is_some());
        assert_eq!(cfg.rtt, Some(Duration::from_millis(20)));
        assert_eq!(cfg.diffserv_mode, Some(CakeDiffserv::Diffserv4));
        assert_eq!(cfg.flow_mode, Some(CakeFlowMode::Triple));
        assert_eq!(cfg.ack_filter, Some(CakeAckFilter::Filter));
        assert!(cfg.nat);
        assert!(cfg.wash);
    }

    #[test]
    fn cake_parse_params_unknown_token_errors() {
        let err = CakeConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
        // Common typo: dual_srchost vs dual-srchost. Legacy parser
        // silently ignored — typed parser flags it.
        let err = CakeConfig::parse_params(&["dual_srchost"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn cake_parse_params_missing_value_errors() {
        let err = CakeConfig::parse_params(&["bandwidth"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
        let err = CakeConfig::parse_params(&["rtt"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn cake_parse_params_invalid_value_errors() {
        let err = CakeConfig::parse_params(&["bandwidth", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid bandwidth"));
        let err = CakeConfig::parse_params(&["overhead", "lots"]).unwrap_err();
        assert!(err.to_string().contains("invalid overhead"));
        let err = CakeConfig::parse_params(&["fwmark", "zzzz"]).unwrap_err();
        assert!(err.to_string().contains("invalid fwmark"));
    }

    #[test]
    fn tbf_parse_params_empty_yields_default() {
        let cfg = TbfConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.rate, crate::util::Rate::ZERO);
        assert!(cfg.peakrate.is_none());
        assert_eq!(cfg.burst, crate::util::Bytes::ZERO);
        assert_eq!(cfg.mtu, 1514);
    }

    #[test]
    fn tbf_parse_params_typical_set() {
        let cfg =
            TbfConfig::parse_params(&["rate", "1mbit", "burst", "32kb", "limit", "10kb"]).unwrap();
        // 1mbit = 125_000 bytes/sec
        assert_eq!(cfg.rate.as_bytes_per_sec(), 125_000);
        // 32kb = 32 * 1024 bytes (binary, per tc(8) convention)
        assert_eq!(cfg.burst.as_u64(), 32 * 1024);
        assert_eq!(cfg.limit.as_u64(), 10 * 1024);
    }

    #[test]
    fn tbf_parse_params_burst_aliases() {
        for alias in ["burst", "buffer", "maxburst"] {
            let cfg = TbfConfig::parse_params(&[alias, "16kb"]).unwrap();
            assert_eq!(cfg.burst.as_u64(), 16 * 1024, "alias {alias}");
        }
    }

    #[test]
    fn tbf_parse_params_mtu_alias() {
        for alias in ["mtu", "minburst"] {
            let cfg = TbfConfig::parse_params(&[alias, "9000"]).unwrap();
            assert_eq!(cfg.mtu, 9000, "alias {alias}");
        }
    }

    #[test]
    fn tbf_parse_params_peakrate() {
        let cfg = TbfConfig::parse_params(&["rate", "1mbit", "peakrate", "2mbit"]).unwrap();
        assert_eq!(cfg.rate.as_bytes_per_sec(), 125_000);
        assert_eq!(cfg.peakrate.unwrap().as_bytes_per_sec(), 250_000);
    }

    #[test]
    fn tbf_parse_params_latency_is_tcs_limit() {
        // rate * latency + burst: 125000 B/s * 50 ms + 10 KiB (#820).
        let cfg = TbfConfig::parse_params(&["rate", "1mbit", "burst", "10kb", "latency", "50ms"]).unwrap();
        assert_eq!(cfg.limit.as_u64(), 6250 + 10240);
        // With a peak rate, the smaller of that and peakrate * latency + mtu.
        let cfg = TbfConfig::parse_params(&[
            "rate", "1mbit", "burst", "10kb", "peakrate", "2mbit", "mtu", "2000", "latency", "50ms",
        ])
        .unwrap();
        assert_eq!(cfg.limit.as_u64(), 12500 + 2000);
        // One of limit and latency, once, as tc takes them.
        let err = TbfConfig::parse_params(&["limit", "10kb", "latency", "50ms"]).unwrap_err();
        assert!(err.to_string().contains("once"), "{err}");
    }

    #[test]
    fn tbf_parse_params_unknown_token_errors() {
        let err = TbfConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn tbf_parse_params_missing_value_errors() {
        let err = TbfConfig::parse_params(&["rate"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn tbf_parse_params_invalid_rate_errors() {
        let err = TbfConfig::parse_params(&["rate", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid rate"));
    }

    #[test]
    fn sfq_parse_params_empty_yields_default() {
        let cfg = SfqConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.perturb, 0);
        assert_eq!(cfg.limit, crate::util::Packets::new(0), "the kernel's, as tc leaves it (#637)");
        assert_eq!(cfg.quantum, 0);
    }

    #[test]
    fn sfq_parse_params_typical_set() {
        let cfg = SfqConfig::parse_params(&["perturb", "10", "limit", "1000", "quantum", "1500"])
            .unwrap();
        assert_eq!(cfg.perturb, 10);
        assert_eq!(cfg.limit, crate::util::Packets::new(1000));
        assert_eq!(cfg.quantum, 1500);
    }

    #[test]
    fn sfq_parse_params_quantum_with_size_suffix() {
        let cfg = SfqConfig::parse_params(&["quantum", "1k"]).unwrap();
        assert_eq!(cfg.quantum, 1024);
    }

    /// #806: divisor, flows, depth and head drop are modelled; SFQRED is
    /// not, and says so.
    #[test]
    fn sfq_parse_params_divisor_flows_depth_headdrop() {
        let cfg = SfqConfig::parse_params(&["divisor", "512", "flows", "64", "depth", "32", "headdrop"]).unwrap();
        assert_eq!((cfg.divisor, cfg.flows, cfg.depth, cfg.headdrop), (512, 64, 32, true));
        let err = SfqConfig::parse_params(&["redflowlimit", "100000"]).unwrap_err();
        assert!(err.to_string().contains("not modelled"), "got: {err}");
    }

    #[test]
    fn sfq_parse_params_unknown_token_errors() {
        let err = SfqConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn sfq_parse_params_missing_value_errors() {
        let err = SfqConfig::parse_params(&["perturb"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn prio_parse_params_empty_yields_default() {
        let cfg = PrioConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.bands, 3);
        assert_eq!(
            cfg.priomap,
            [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
        );
    }

    #[test]
    fn prio_parse_params_bands() {
        let cfg = PrioConfig::parse_params(&["bands", "5"]).unwrap();
        assert_eq!(cfg.bands, 5);
    }

    #[test]
    fn prio_parse_params_priomap_full() {
        // 16 explicit values
        let mut params = vec!["priomap"];
        for n in 0u8..16 {
            params.push(if n < 8 { "0" } else { "1" });
        }
        let cfg = PrioConfig::parse_params(&params).unwrap();
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(cfg.priomap, expected);
    }

    #[test]
    fn prio_parse_params_priomap_short_errors() {
        // Only 5 values supplied — strict, unlike the legacy parser.
        let err = PrioConfig::parse_params(&["priomap", "1", "2", "3", "4", "5"]).unwrap_err();
        assert!(
            err.to_string().contains("requires exactly 16 values"),
            "got: {err}"
        );
    }

    #[test]
    fn prio_parse_params_unknown_token_errors() {
        let err = PrioConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fq_codel_parse_params_empty_yields_default() {
        let cfg = FqCodelConfig::parse_params(&[]).unwrap();
        assert!(cfg.target.is_none());
        assert!(cfg.interval.is_none());
        assert!(cfg.limit.is_none());
        assert_eq!(cfg.ecn, None);
    }

    #[test]
    fn fq_codel_parse_params_typical_set() {
        let cfg = FqCodelConfig::parse_params(&[
            "limit",
            "10240",
            "target",
            "5ms",
            "interval",
            "100ms",
            "flows",
            "1024",
            "quantum",
            "1500",
            "memory_limit",
            "32m",
            "ecn",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(10240)));
        assert_eq!(cfg.target, Some(Duration::from_millis(5)));
        assert_eq!(cfg.interval, Some(Duration::from_millis(100)));
        assert_eq!(cfg.flows, Some(1024));
        assert_eq!(cfg.quantum, Some(1500));
        // 32m via tc-style size = 32 * 1024 * 1024
        assert_eq!(cfg.memory_limit, Some(32 * 1024 * 1024));
        assert_eq!(cfg.ecn, Some(true));
    }

    #[test]
    fn fq_codel_parse_params_ecn_noecn_toggle() {
        let cfg = FqCodelConfig::parse_params(&["ecn"]).unwrap();
        assert_eq!(cfg.ecn, Some(true));
        let cfg = FqCodelConfig::parse_params(&["ecn", "noecn"]).unwrap();
        assert_eq!(cfg.ecn, Some(false));
    }

    /// `ecn(false)` writes ECN=0 — the kernel's default is on — and an
    /// unset ECN writes nothing (#488).
    #[test]
    fn fq_codel_writes_ecn_off_and_omits_it_unset() {
        let ecn_attr = |cfg: FqCodelConfig| {
            let attrs = crate::netlink::test_support::qdisc_attrs(&cfg);
            attrs
                .get(&fq_codel::TCA_FQ_CODEL_ECN)
                .map(|v| u32::from_ne_bytes(v[..4].try_into().unwrap()))
        };
        assert_eq!(ecn_attr(FqCodelConfig::new().ecn(false)), Some(0));
        assert_eq!(ecn_attr(FqCodelConfig::new().ecn(true)), Some(1));
        assert_eq!(ecn_attr(FqCodelConfig::new()), None);
    }

    /// A change of a live fq_codel leaves `flows` out, and a different
    /// `flows` asks for a new qdisc (#486).
    #[test]
    fn fq_codel_change_mode_leaves_flows_out() {
        use crate::netlink::test_support::encode;
        let cfg = FqCodelConfig::new().flows(1024).limit(crate::util::Packets::new(1000));
        let create = encode(|b| cfg.write_options(b));
        let change = encode(|b| cfg.write_change_options(b));
        assert!(create.contains_key(&fq_codel::TCA_FQ_CODEL_FLOWS));
        assert!(!change.contains_key(&fq_codel::TCA_FQ_CODEL_FLOWS));
        assert!(change.contains_key(&fq_codel::TCA_FQ_CODEL_LIMIT));
    }

    /// Fewer than three bands fit the default priomap to them; a custom
    /// map that names a band past the last is refused before the kernel
    /// sees it (#487).
    #[test]
    fn prio_fits_the_default_priomap_and_refuses_a_bad_one() {
        let two = PrioConfig::new().bands(2);
        assert!(two.effective_priomap().iter().all(|band| *band <= 1));
        let mut b = MessageBuilder::new(0, 0);
        two.write_options(&mut b)
            .expect("bands(2) with the default map");

        let parsed = PrioConfig::parse_params(&["bands", "2"]).unwrap();
        assert_eq!(parsed.effective_priomap(), two.effective_priomap());

        let bad = PrioConfig::new().bands(2).priomap([2; 16]);
        let err = bad
            .write_options(&mut MessageBuilder::new(0, 0))
            .unwrap_err();
        assert!(err.to_string().contains("priomap[0] names band 2"), "{err}");
        let err = PrioConfig::new()
            .bands(1)
            .write_options(&mut MessageBuilder::new(0, 0))
            .unwrap_err();
        assert!(err.to_string().contains("bands 1 out of range"), "{err}");
        assert_eq!(
            PrioConfig::new().effective_priomap(),
            PrioConfig::DEFAULT_PRIOMAP
        );
    }

    #[test]
    fn fq_codel_parse_params_ce_threshold() {
        let cfg = FqCodelConfig::parse_params(&["ce_threshold", "20ms"]).unwrap();
        assert_eq!(cfg.ce_threshold, Some(Duration::from_millis(20)));
    }

    #[test]
    fn fq_codel_parse_params_unknown_token_errors() {
        let err = FqCodelConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fq_codel_parse_params_invalid_time_errors() {
        let err = FqCodelConfig::parse_params(&["target", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid target"));
    }

    /// What tc(8)'s own `tc_red.c` computes (built and run against this
    /// clock as an oracle, #819): the STAB as the indices where its value
    /// steps up by one, then 31 at 255.
    fn stab_from_steps(steps: &[usize]) -> [u8; 256] {
        let mut stab = [0u8; 256];
        for (i, slot) in stab.iter_mut().enumerate().take(255) {
            *slot = steps.iter().filter(|s| **s <= i).count() as u8;
        }
        stab[255] = 31;
        stab
    }

    #[test]
    fn red_derives_what_tc_derives() {
        use crate::netlink::psched::Psched;
        use crate::util::Rate;
        // limit 400000 min 30000 max 90000 avpkt 1000 burst 55
        // probability 0.02 bandwidth 10mbit
        let d = red_derive("red", &Psched::MODERN, 30000, 90000, 55, 1000, Rate::mbit(10), 0.02).unwrap();
        assert_eq!((d.wlog, d.plog, d.scell_log, d.max_p), (5, 22, 15, 85_899_345));
        let steps = [13, 25, 37, 49, 61, 73, 85, 97, 109, 121, 133, 145, 157, 169, 181, 193, 205, 217, 229, 241, 253];
        assert_eq!(d.stab, stab_from_steps(&steps));
        // choke: limit 1000 min 100 max 300 avpkt 1000 burst 200
        // bandwidth 10mbit probability 0.1, thresholds times avpkt.
        let d = red_derive("choke", &Psched::MODERN, 100_000, 300_000, 200, 1000, Rate::mbit(10), 0.1).unwrap();
        assert_eq!((d.wlog, d.plog, d.scell_log, d.max_p), (7, 21, 17, 429_496_729));
        let steps = [13, 25, 37, 49, 61, 73, 86, 98, 110, 122, 134, 146, 159, 171, 183, 195, 207, 219, 232, 244];
        assert_eq!(d.stab, stab_from_steps(&steps));
        // A burst too small for the minimum, and a max below the min.
        assert!(red_derive("red", &Psched::MODERN, 30000, 90000, 1, 1000, Rate::mbit(10), 0.02).is_err());
        assert!(red_derive("red", &Psched::MODERN, 90000, 30000, 55, 1000, Rate::mbit(10), 0.02).is_err());
    }

    /// The options a qdisc config writes, by attribute type.
    fn qdisc_option_attrs(cfg: &impl QdiscConfig) -> std::collections::HashMap<u16, Vec<u8>> {
        let mut b = MessageBuilder::new(0, 0);
        cfg.write_options(&mut b).unwrap();
        let bytes = b.finish();
        let mut attrs = std::collections::HashMap::new();
        let mut rest = &bytes[16..];
        while rest.len() >= 4 {
            let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
            // Without NLA_F_NESTED and NLA_F_NET_BYTEORDER.
            let ty = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff;
            attrs.insert(ty, rest[4..len].to_vec());
            rest = &rest[len.next_multiple_of(4).min(rest.len())..];
        }
        attrs
    }

    #[test]
    fn red_writes_a_stab_and_tcs_defaults() {
        use crate::netlink::types::tc::qdisc::red;
        // The kernel refuses a red without TCA_RED_STAB (#819).
        let cfg = RedConfig::parse_params(&["limit", "400000", "avpkt", "1000"]).unwrap();
        let attrs = qdisc_option_attrs(&cfg);
        assert_eq!(attrs[&red::TCA_RED_STAB].len(), 256);
        // tc's defaults: max a quarter of the limit, min a third of max.
        let parms = &attrs[&red::TCA_RED_PARMS];
        let word = |i: usize| u32::from_ne_bytes(parms[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!((word(0), word(1), word(2)), (400_000, 33_333, 100_000));
        assert_eq!(attrs[&red::TCA_RED_MAX_P], 85_899_345u32.to_ne_bytes());
        // The flags go in TCA_RED_FLAGS only: value, then selector.
        let cfg = RedConfig::parse_params(&["limit", "400000", "avpkt", "1000", "ecn", "nodrop"]).unwrap();
        let attrs = qdisc_option_attrs(&cfg);
        assert_eq!(attrs[&red::TCA_RED_PARMS][15], 0);
        let flags = &attrs[&red::TCA_RED_FLAGS];
        assert_eq!(u32::from_ne_bytes(flags[..4].try_into().unwrap()), red::TC_RED_ECN | red::TC_RED_NODROP);
        assert_eq!(u32::from_ne_bytes(flags[4..].try_into().unwrap()), 0xf);
    }

    #[test]
    fn red_parse_params_reads_tcs_words() {
        use crate::util::Rate;
        let cfg = RedConfig::parse_params(&[
            "limit", "100k", "min", "10k", "max", "30k", "avpkt", "1500", "burst", "20", "bandwidth", "100mbit",
            "probability", "0.05",
        ])
        .unwrap();
        assert_eq!((cfg.limit, cfg.min, cfg.max, cfg.avpkt, cfg.burst), (100 * 1024, 10 * 1024, 30 * 1024, 1500, 20));
        assert_eq!(cfg.bandwidth, Rate::mbit(100));
        // tc-red(8)'s probability is a fraction: 0.05 is 5%.
        assert_eq!(cfg.probability, 0.05);
        assert!(RedConfig::parse_params(&["probability", "50"]).is_err());
        assert!(RedConfig::parse_params(&["bandwidth", "10%"]).unwrap_err().to_string().contains("not modelled"));
        let cfg = RedConfig::parse_params(&["ecn", "harddrop", "adaptative", "nodrop"]).unwrap();
        assert!(cfg.ecn && cfg.harddrop && cfg.adaptive && cfg.nodrop);
        let cfg = RedConfig::parse_params(&["ecn", "noecn", "harddrop", "noharddrop", "adaptive", "noadaptive"]).unwrap();
        assert!(!cfg.ecn && !cfg.harddrop && !cfg.adaptive);
        let cfg = RedConfig::parse_params(&[]).unwrap();
        assert_eq!((cfg.avpkt, cfg.burst, cfg.probability), (1000, 0, 0.02));
        assert_eq!(cfg.bandwidth, Rate::mbit(10));
        assert!(RedConfig::parse_params(&["nonsense"]).unwrap_err().to_string().contains("unknown token"));
        assert!(RedConfig::parse_params(&["qevent", "mark"]).unwrap_err().to_string().contains("not modelled"));
    }

    #[test]
    fn choke_writes_a_stab_and_reads_tcs_words() {
        use crate::netlink::types::tc::qdisc::choke;
        let cfg = ChokeConfig::parse_params(&[
            "limit", "1000", "min", "100", "max", "300", "avpkt", "1000", "burst", "200", "bandwidth", "10mbit",
            "probability", "0.1", "ecn",
        ])
        .unwrap();
        assert_eq!(cfg.limit, crate::util::Packets::new(1000));
        assert_eq!((cfg.burst, cfg.probability), (200, 0.1));
        assert!(cfg.ecn);
        let attrs = qdisc_option_attrs(&cfg);
        assert_eq!(attrs[&choke::TCA_CHOKE_STAB].len(), 256);
        assert_eq!(attrs[&choke::TCA_CHOKE_MAX_P], 429_496_729u32.to_ne_bytes());
        // Packets, as tc reads them: no size suffix, any base.
        assert!(ChokeConfig::parse_params(&["limit", "100k"]).is_err());
        let cfg = ChokeConfig::parse_params(&["limit", "0x10"]).unwrap();
        assert_eq!(cfg.limit, crate::util::Packets::new(16));
        // tc's defaults: max a quarter of the limit, min a third of max.
        let attrs = qdisc_option_attrs(&ChokeConfig::parse_params(&["limit", "1000"]).unwrap());
        let parms = &attrs[&choke::TCA_CHOKE_PARMS];
        let word = |i: usize| u32::from_ne_bytes(parms[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!((word(0), word(1), word(2)), (1000, 83, 250));
        assert!(ChokeConfig::parse_params(&["nonsense"]).unwrap_err().to_string().contains("unknown token"));
        assert!(ChokeConfig::parse_params(&["limit"]).unwrap_err().to_string().contains("requires a value"));
    }

    #[test]
    fn pfifo_fast_parse_params_takes_no_args() {
        assert!(PfifoFastConfig::parse_params(&[]).is_ok());
        let err = PfifoFastConfig::parse_params(&["bands", "3"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn pfifo_fast_writes_no_options() {
        // pfifo_fast ignores TCA_OPTIONS; write_options must be a no-op
        // (no panic, no bytes appended beyond the empty builder).
        let cfg = PfifoFastConfig::new();
        assert_eq!(cfg.kind(), "pfifo_fast");
    }

    #[test]
    #[allow(deprecated)]
    fn atm_parse_params_takes_no_args() {
        assert!(AtmConfig::parse_params(&[]).is_ok());
        assert_eq!(AtmConfig::new().kind(), "atm");
        let err = AtmConfig::parse_params(&["vpi", "0"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn gred_parse_params_setup() {
        let cfg =
            GredConfig::parse_params(&["setup", "DPs", "8", "default", "2", "grio", "limit", "60k"])
                .unwrap();
        assert_eq!(cfg.virtual_queues, Some(8));
        assert_eq!(cfg.default_vq, Some(2));
        assert!(cfg.grio);
        assert_eq!(cfg.limit, Some(60 * 1024));
    }

    #[test]
    fn gred_parse_params_empty_yields_default() {
        let cfg = GredConfig::parse_params(&[]).unwrap();
        assert!(cfg.virtual_queues.is_none());
        assert!(cfg.default_vq.is_none());
        assert!(!cfg.grio);
        assert!(cfg.limit.is_none());
    }

    #[test]
    fn gred_parse_params_dps_range_checked() {
        assert!(GredConfig::parse_params(&["DPs", "0"]).is_err());
        assert!(GredConfig::parse_params(&["DPs", "17"]).is_err());
        assert!(GredConfig::parse_params(&["DPs", "16"]).is_ok());
        let err = GredConfig::parse_params(&["DPs", "notanum"]).unwrap_err();
        assert!(err.to_string().contains("invalid DPs"));
    }

    #[test]
    fn gred_parse_params_per_vq_tokens_not_modelled() {
        for tok in ["min", "max", "avpkt", "bandwidth", "DP", "probability", "prio"] {
            let err = GredConfig::parse_params(&[tok, "1"]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled for per-VQ `{tok}`, got: {err}"
            );
        }
    }

    #[test]
    fn gred_parse_params_unknown_token_errors() {
        let err = GredConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
        let err = GredConfig::parse_params(&["DPs"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn pie_parse_params_empty_yields_default() {
        let cfg = PieConfig::parse_params(&[]).unwrap();
        assert!(cfg.target.is_none());
        assert!(cfg.limit.is_none());
        assert!(cfg.alpha.is_none());
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
    }

    #[test]
    fn pie_parse_params_typical_set() {
        let cfg = PieConfig::parse_params(&[
            "target", "15ms", "limit", "1000", "tupdate", "30ms", "alpha", "2", "beta", "20",
        ])
        .unwrap();
        assert_eq!(cfg.target, Some(Duration::from_millis(15)));
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(1000)));
        assert_eq!(cfg.tupdate, Some(Duration::from_millis(30)));
        assert_eq!(cfg.alpha, Some(2));
        assert_eq!(cfg.beta, Some(20));
    }

    #[test]
    fn pie_parse_params_flags_with_negations() {
        let cfg = PieConfig::parse_params(&["ecn", "bytemode"]).unwrap();
        assert!(cfg.ecn);
        assert!(cfg.bytemode);
        let cfg = PieConfig::parse_params(&["ecn", "noecn", "bytemode", "nobytemode"]).unwrap();
        assert!(!cfg.ecn);
        assert!(!cfg.bytemode);
    }

    #[test]
    fn pie_parse_params_unknown_token_errors() {
        let err = PieConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn pie_parse_params_invalid_time_errors() {
        let err = PieConfig::parse_params(&["target", "fast"]).unwrap_err();
        assert!(err.to_string().contains("invalid target"));
    }

    #[test]
    fn hfsc_parse_params_empty_yields_default() {
        let cfg = HfscConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.default_class, 0);
    }

    #[test]
    fn hfsc_parse_params_default_hex() {
        let cfg = HfscConfig::parse_params(&["default", "10"]).unwrap();
        assert_eq!(cfg.default_class, 0x10);
        let cfg = HfscConfig::parse_params(&["default", "ff"]).unwrap();
        assert_eq!(cfg.default_class, 0xff);
    }

    #[test]
    fn hfsc_parse_params_unknown_token_errors() {
        let err = HfscConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn hfsc_parse_params_missing_value_errors() {
        let err = HfscConfig::parse_params(&["default"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn ingress_clsact_parse_params_empty_succeeds() {
        IngressConfig::parse_params(&[]).unwrap();
        ClsactConfig::parse_params(&[]).unwrap();
    }

    #[test]
    fn ingress_clsact_parse_params_reject_any_token() {
        let err = IngressConfig::parse_params(&["foo"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
        let err = ClsactConfig::parse_params(&["bar"]).unwrap_err();
        assert!(err.to_string().contains("takes no parameters"));
    }

    #[test]
    fn drr_qfq_parse_params_empty_succeeds() {
        DrrConfig::parse_params(&[]).unwrap();
        QfqConfig::parse_params(&[]).unwrap();
    }

    #[test]
    fn drr_qfq_parse_params_reject_any_token() {
        let err = DrrConfig::parse_params(&["quantum", "1500"]).unwrap_err();
        assert!(
            err.to_string().contains("DrrClassConfig"),
            "expected per-class hint, got: {err}"
        );
        let err = QfqConfig::parse_params(&["weight", "10"]).unwrap_err();
        assert!(err.to_string().contains("QfqClassConfig"), "got: {err}");
    }

    #[test]
    fn plug_parse_params_empty_yields_default() {
        let cfg = PlugConfig::parse_params(&[]).unwrap();
        assert!(cfg.limit.is_none());
    }

    #[test]
    fn plug_parse_params_limit_with_size_suffix() {
        let cfg = PlugConfig::parse_params(&["limit", "10k"]).unwrap();
        assert_eq!(cfg.limit, Some(10 * 1024));
    }

    #[test]
    fn plug_parse_params_unknown_token_errors() {
        let err = PlugConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn mqprio_parse_params_num_tc_and_hw_flag() {
        let cfg = MqprioConfig::parse_params(&["num_tc", "4", "nohw"]).unwrap();
        assert_eq!(cfg.num_tc, 4);
        assert!(!cfg.hw);
        let cfg = MqprioConfig::parse_params(&["num_tc", "8", "hw"]).unwrap();
        assert!(cfg.hw);
    }

    #[test]
    fn mqprio_parse_params_map_full() {
        let mut params = vec!["map"];
        for n in 0u8..16 {
            params.push(if n < 8 { "0" } else { "1" });
        }
        let cfg = MqprioConfig::parse_params(&params).unwrap();
        let expected: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(cfg.prio_tc_map, expected);
    }

    #[test]
    fn mqprio_and_taprio_maps_read_as_tcs() {
        // Up to 16 classes, to the first word that is not one; the rest
        // are 0 (#820).
        let cfg = MqprioConfig::parse_params(&["map", "1", "2", "3"]).unwrap();
        assert_eq!(cfg.prio_tc_map, [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let cfg = MqprioConfig::parse_params(&["num_tc", "2", "map", "0", "1", "queues", "1@0", "1@1", "hw", "0"]).unwrap();
        assert_eq!(cfg.prio_tc_map[..3], [0, 1, 0]);
        assert_eq!((cfg.count[1], cfg.offset[1]), (1, 1));
        let cfg = TaprioConfig::parse_params(&["num_tc", "2", "map", "0", "1", "queues", "1@0", "1@1"]).unwrap();
        assert_eq!(cfg.prio_tc_map[..3], [0, 1, 0]);
        assert!(MqprioConfig::parse_params(&["map", "queues"]).unwrap_err().to_string().contains("at least one"));
        assert!(TaprioConfig::parse_params(&["map"]).is_err());
    }

    #[test]
    fn mqprio_parse_params_num_tc_out_of_range() {
        let err = MqprioConfig::parse_params(&["num_tc", "20"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn mqprio_parse_params_reads_queues() {
        // tc(8)'s count@offset pairs, to the first word that is not one (#820).
        let cfg = MqprioConfig::parse_params(&["queues", "1@0", "2@1", "hw", "0"]).unwrap();
        assert_eq!((&cfg.count[..3], &cfg.offset[..3]), (&[1, 2, 0][..], &[0, 1, 0][..]));
        assert!(!cfg.hw);
        assert!(MqprioConfig::parse_params(&["queues", "1@x"]).is_err());
        assert!(MqprioConfig::parse_params(&["queues", "hw"]).is_err());
    }

    #[test]
    fn etf_parse_params_empty_yields_default() {
        let cfg = EtfConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.delta, 0);
        assert_eq!(cfg.clockid, -1);
        assert!(!cfg.deadline_mode);
        assert!(!cfg.offload);
    }

    #[test]
    fn etf_parse_params_typical() {
        let cfg = EtfConfig::parse_params(&[
            "delta",
            "300000",
            "clockid",
            "CLOCK_TAI",
            "deadline_mode",
            "offload",
        ])
        .unwrap();
        assert_eq!(cfg.delta, 300_000);
        assert_eq!(cfg.clockid, libc::CLOCK_TAI);
        assert!(cfg.deadline_mode);
        assert!(cfg.offload);
    }

    #[test]
    fn etf_parse_params_clockid_named_and_integer() {
        for (name, expected) in [
            ("CLOCK_REALTIME", libc::CLOCK_REALTIME),
            ("CLOCK_MONOTONIC", libc::CLOCK_MONOTONIC),
            ("CLOCK_BOOTTIME", libc::CLOCK_BOOTTIME),
            ("CLOCK_TAI", libc::CLOCK_TAI),
        ] {
            let cfg = EtfConfig::parse_params(&["clockid", name]).unwrap();
            assert_eq!(cfg.clockid, expected, "name {name}");
        }
        let cfg = EtfConfig::parse_params(&["clockid", "11"]).unwrap();
        assert_eq!(cfg.clockid, 11);
    }

    #[test]
    fn etf_parse_params_unknown_clockid_errors() {
        let err = EtfConfig::parse_params(&["clockid", "CLOCK_NONSENSE"]).unwrap_err();
        assert!(err.to_string().contains("invalid clockid"));
    }

    #[test]
    fn etf_parse_params_unknown_token_errors() {
        let err = EtfConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn taprio_parse_params_empty_yields_default() {
        let cfg = TaprioConfig::parse_params(&[]).unwrap();
        assert_eq!(cfg.entries.len(), 0);
        assert_eq!(cfg.cycle_time, 0);
    }

    #[test]
    fn taprio_parse_params_typical() {
        let cfg = TaprioConfig::parse_params(&[
            "num_tc",
            "2",
            "clockid",
            "CLOCK_TAI",
            "base-time",
            "0",
            "cycle-time",
            "1000000",
            "sched-entry",
            "SET",
            "0x1",
            "500000",
            "sched-entry",
            "SET",
            "0x2",
            "500000",
        ])
        .unwrap();
        assert_eq!(cfg.num_tc, 2);
        assert_eq!(cfg.clockid, libc::CLOCK_TAI);
        assert_eq!(cfg.cycle_time, 1_000_000);
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].gate_mask, 0x1);
        assert_eq!(cfg.entries[0].interval, 500_000);
        assert_eq!(cfg.entries[1].gate_mask, 0x2);
    }

    #[test]
    fn taprio_parse_params_sched_entry_cmd_aliases() {
        use crate::netlink::types::tc::qdisc::taprio::{
            TC_TAPRIO_CMD_SET_AND_HOLD, TC_TAPRIO_CMD_SET_AND_RELEASE, TC_TAPRIO_CMD_SET_GATES,
        };
        for (cmd, expected) in [
            ("SET", TC_TAPRIO_CMD_SET_GATES),
            ("S", TC_TAPRIO_CMD_SET_GATES),
            ("set", TC_TAPRIO_CMD_SET_GATES),
            ("HOLD", TC_TAPRIO_CMD_SET_AND_HOLD),
            ("H", TC_TAPRIO_CMD_SET_AND_HOLD),
            ("RELEASE", TC_TAPRIO_CMD_SET_AND_RELEASE),
            ("R", TC_TAPRIO_CMD_SET_AND_RELEASE),
        ] {
            let cfg = TaprioConfig::parse_params(&["sched-entry", cmd, "0x1", "100"]).unwrap();
            assert_eq!(cfg.entries[0].cmd, expected, "cmd alias `{cmd}`");
        }
    }

    #[test]
    fn taprio_parse_params_sched_entry_short_errors() {
        let err = TaprioConfig::parse_params(&["sched-entry", "SET", "0x1"]).unwrap_err();
        assert!(err.to_string().contains("sched-entry"));
    }

    #[test]
    fn taprio_parse_params_flags_and_named() {
        use crate::netlink::types::tc::qdisc::taprio::{
            TAPRIO_ATTR_FLAG_FULL_OFFLOAD, TAPRIO_ATTR_FLAG_TXTIME_ASSIST,
        };
        let cfg = TaprioConfig::parse_params(&["txtime-assist", "full-offload"]).unwrap();
        assert_eq!(
            cfg.flags,
            TAPRIO_ATTR_FLAG_TXTIME_ASSIST | TAPRIO_ATTR_FLAG_FULL_OFFLOAD
        );
        let cfg = TaprioConfig::parse_params(&["flags", "0x3"]).unwrap();
        assert_eq!(cfg.flags, 0x3);
    }

    #[test]
    fn taprio_parse_params_reads_queues() {
        let cfg = TaprioConfig::parse_params(&["queues", "1@0", "1@1", "clockid", "CLOCK_TAI"]).unwrap();
        assert_eq!((&cfg.count[..2], &cfg.offset[..2]), (&[1, 1][..], &[0, 1][..]));
        assert!(TaprioConfig::parse_params(&["queues"]).is_err());
    }

    #[test]
    fn taprio_parse_params_unknown_token_errors() {
        let err = TaprioConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn taprio_parse_params_invalid_sched_entry_cmd() {
        let err = TaprioConfig::parse_params(&["sched-entry", "BOGUS", "0x1", "100"]).unwrap_err();
        assert!(err.to_string().contains("invalid sched-entry cmd"));
    }

    // ============================================================================
    // Class-config parse_params tests (HtbClassConfig / HfscClassConfig /
    // DrrClassConfig / QfqClassConfig — added in 0.15.0 to close the class
    // side at typed-first parity with qdisc/filter/action).
    // ============================================================================

    #[test]
    fn htb_class_parse_params_rate_only() {
        let cfg = HtbClassConfig::parse_params(&["rate", "100mbit"]).unwrap();
        assert_eq!(
            cfg.rate.as_bytes_per_sec(),
            crate::util::Rate::mbit(100).as_bytes_per_sec()
        );
        assert!(cfg.ceil.is_none());
    }

    #[test]
    fn htb_class_parse_params_full_aliases() {
        // Cover the alias set: buffer / cbuffer = burst / cburst.
        let cfg = HtbClassConfig::parse_params(&[
            "rate", "10mbit", "ceil", "100mbit", "buffer", "32kb", "cbuffer", "64kb", "prio", "1",
            "quantum", "1500", "mtu", "1500", "mpu", "64", "overhead", "14",
        ])
        .unwrap();
        assert!(cfg.ceil.is_some());
        assert!(cfg.burst.is_some());
        assert!(cfg.cburst.is_some());
        assert_eq!(cfg.prio, Some(1));
        assert_eq!(cfg.quantum, Some(1500));
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.mpu, 64);
        assert_eq!(cfg.overhead, 14);
    }

    #[test]
    fn htb_class_parse_params_missing_rate_errors() {
        let err = HtbClassConfig::parse_params(&[]).unwrap_err();
        assert!(err.to_string().contains("htb:"), "kind-prefixed: {err}");
        assert!(err.to_string().contains("`rate` is required"), "got: {err}");
    }

    #[test]
    fn htb_class_parse_params_unknown_token_errors() {
        let err = HtbClassConfig::parse_params(&["rate", "100mbit", "nonsense"]).unwrap_err();
        assert!(
            err.to_string().contains("htb: unknown token `nonsense`"),
            "got: {err}"
        );
    }

    #[test]
    fn htb_class_parse_params_missing_value_errors() {
        let err = HtbClassConfig::parse_params(&["rate"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got: {err}");
    }

    #[test]
    fn htb_class_parse_params_invalid_rate_errors() {
        let err = HtbClassConfig::parse_params(&["rate", "fast"]).unwrap_err();
        assert!(err.to_string().contains("htb: invalid rate"), "got: {err}");
    }

    #[test]
    fn hfsc_class_parse_params_empty_yields_empty_config() {
        let cfg = HfscClassConfig::parse_params(&[]).unwrap();
        assert!(cfg.rsc.is_none() && cfg.fsc.is_none() && cfg.usc.is_none());
    }

    #[test]
    fn hfsc_class_parse_params_three_curves() {
        let cfg = HfscClassConfig::parse_params(&[
            "rt", "rate", "10mbit", "ls", "rate", "100mbit", "ul", "rate", "200mbit",
        ])
        .unwrap();
        assert!(cfg.rsc.is_some());
        assert!(cfg.fsc.is_some());
        assert!(cfg.usc.is_some());
    }

    #[test]
    fn hfsc_class_parse_params_unknown_curve_errors() {
        let err = HfscClassConfig::parse_params(&["xt", "rate", "10mbit"]).unwrap_err();
        assert!(
            err.to_string().contains("hfsc: unknown token `xt`"),
            "got: {err}"
        );
    }

    /// A curve with an `m1` and no `m2` says what it lacks (#645 reads
    /// the `m1`/`d`/`m2` form; it used to refuse everything but `rate`).
    #[test]
    fn hfsc_class_parse_params_curve_without_m2_errors() {
        let err = HfscClassConfig::parse_params(&["rt", "rate", "10mbit", "ls", "m1", "100"])
            .unwrap_err();
        assert!(err.to_string().contains("hfsc:"), "kind-prefixed: {err}");
        assert!(
            err.to_string().contains("`ls` requires `m2 <rate>` or `rate <rate>`"),
            "got: {err}"
        );
    }

    #[test]
    fn drr_class_parse_params_empty_and_quantum() {
        let cfg = DrrClassConfig::parse_params(&[]).unwrap();
        assert!(cfg.quantum.is_none());
        let cfg = DrrClassConfig::parse_params(&["quantum", "1500"]).unwrap();
        assert!(cfg.quantum.is_some());
    }

    #[test]
    fn drr_class_parse_params_unknown_token_errors() {
        let err = DrrClassConfig::parse_params(&["rate", "100mbit"]).unwrap_err();
        assert!(
            err.to_string().contains("drr: unknown token `rate`"),
            "got: {err}"
        );
    }

    #[test]
    fn qfq_class_parse_params_weight_and_lmax() {
        let cfg = QfqClassConfig::parse_params(&["weight", "5", "lmax", "9000"]).unwrap();
        assert_eq!(cfg.weight, Some(5));
        assert!(cfg.lmax.is_some());
    }

    #[test]
    fn qfq_class_parse_params_weight_clamped() {
        let cfg = QfqClassConfig::parse_params(&["weight", "9999"]).unwrap();
        assert_eq!(cfg.weight, Some(1023));
    }

    #[test]
    fn qfq_class_parse_params_unknown_token_errors() {
        let err = QfqClassConfig::parse_params(&["nonsense"]).unwrap_err();
        assert!(
            err.to_string().contains("qfq: unknown token `nonsense`"),
            "got: {err}"
        );
    }

    /// Generic dispatch through the sealed `ParseParams` trait —
    /// proves the new class-config impls are wired into the trait
    /// alongside qdisc/filter/action, not just inherent methods.
    #[test]
    fn class_configs_dispatch_through_parse_params_trait() {
        use crate::ParseParams;
        let _: HtbClassConfig =
            <HtbClassConfig as ParseParams>::parse_params(&["rate", "100mbit"]).unwrap();
        let _: HfscClassConfig = <HfscClassConfig as ParseParams>::parse_params(&[]).unwrap();
        let _: DrrClassConfig = <DrrClassConfig as ParseParams>::parse_params(&[]).unwrap();
        let _: QfqClassConfig = <QfqClassConfig as ParseParams>::parse_params(&[]).unwrap();
    }

    #[test]
    fn codel_parse_params() {
        let cfg = CodelConfig::parse_params(&[
            "limit", "1000", "target", "5ms", "interval", "100ms", "ecn",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(1000)));
        assert_eq!(cfg.target, Some(Duration::from_millis(5)));
        assert_eq!(cfg.interval, Some(Duration::from_millis(100)));
        assert_eq!(cfg.ecn, Some(true));
        assert_eq!(cfg.kind(), "codel");

        // noecn distinct from unset
        assert_eq!(CodelConfig::parse_params(&["noecn"]).unwrap().ecn, Some(false));
        assert_eq!(CodelConfig::parse_params(&[]).unwrap().ecn, None);

        // strict
        assert!(CodelConfig::parse_params(&["bogus"]).is_err());
        assert!(CodelConfig::parse_params(&["limit"]).is_err()); // missing value
        assert!(CodelConfig::parse_params(&["target", "notatime"]).is_err());
    }

    #[test]
    fn fq_reads_buckets_horizon_and_timer_slack() {
        use crate::netlink::types::tc::qdisc::fq;
        let cfg = FqConfig::parse_params(&["buckets", "1000", "horizon", "10s", "horizon_drop", "timer_slack", "20us"]).unwrap();
        let attrs = qdisc_option_attrs(&cfg);
        // log2 rounded up, as tc's ilog2(): 1000 buckets is 2^10 (#821).
        assert_eq!(attrs[&fq::TCA_FQ_BUCKETS_LOG], 10u32.to_ne_bytes());
        assert_eq!(attrs[&fq::TCA_FQ_HORIZON], 10_000_000u32.to_ne_bytes());
        assert_eq!(attrs[&fq::TCA_FQ_HORIZON_DROP], [1]);
        assert_eq!(attrs[&fq::TCA_FQ_TIMER_SLACK], 20_000u32.to_ne_bytes());
        let attrs = qdisc_option_attrs(&FqConfig::parse_params(&["buckets", "2048", "horizon_cap"]).unwrap());
        assert_eq!(attrs[&fq::TCA_FQ_BUCKETS_LOG], 11u32.to_ne_bytes());
        assert_eq!(attrs[&fq::TCA_FQ_HORIZON_DROP], [0]);
        assert!(FqConfig::parse_params(&["defrate", "1mbit"]).unwrap_err().to_string().contains("obsolete"));
        assert!(FqConfig::parse_params(&["weights", "1"]).unwrap_err().to_string().contains("not modelled"));
    }

    #[test]
    fn cake_framings_add_as_tcs() {
        // Each adds to the overhead so far, as tc-cake(8)'s do (#820).
        let cfg = CakeConfig::parse_params(&["ethernet"]).unwrap();
        assert_eq!((cfg.overhead, cfg.mpu, cfg.atm_mode), (Some(38), Some(84), None));
        let cfg = CakeConfig::parse_params(&["overhead", "10", "ether-vlan", "pppoe-ptm"]).unwrap();
        assert_eq!((cfg.overhead, cfg.atm_mode), (Some(44), Some(CakeAtmMode::Ptm)));
        let cfg = CakeConfig::parse_params(&["docsis"]).unwrap();
        assert_eq!((cfg.overhead, cfg.mpu, cfg.atm_mode), (Some(18), Some(64), Some(CakeAtmMode::None)));
        let cfg = CakeConfig::parse_params(&["bridged-llcsnap", "conservative"]).unwrap();
        assert_eq!((cfg.overhead, cfg.atm_mode), (Some(48), Some(CakeAtmMode::Atm)));
        let cfg = CakeConfig::parse_params(&["overhead", "20", "raw"]).unwrap();
        assert_eq!((cfg.overhead, cfg.atm_mode, cfg.raw), (Some(0), Some(CakeAtmMode::None), true));
        assert!(CakeConfig::parse_params(&["via-ethernet"]).is_ok());
    }

    #[test]
    fn gred_and_pie_read_tcs_words() {
        use crate::netlink::types::tc::qdisc::{gred, pie};
        // tc-gred(8)'s `vqs`, and the setup's ecn and harddrop (#820).
        let cfg = GredConfig::parse_params(&["setup", "vqs", "4", "default", "1", "ecn", "harddrop"]).unwrap();
        assert_eq!((cfg.virtual_queues, cfg.default_vq, cfg.ecn, cfg.harddrop), (Some(4), Some(1), true, true));
        let attrs = qdisc_option_attrs(&cfg);
        assert_eq!(attrs[&gred::TCA_GRED_DPS][9], 3, "TC_RED_ECN | TC_RED_HARDDROP");
        let cfg = PieConfig::parse_params(&["dq_rate_estimator"]).unwrap();
        assert!(cfg.dq_rate_estimator);
        assert_eq!(qdisc_option_attrs(&cfg)[&pie::TCA_PIE_DQ_RATE_ESTIMATOR], 1u32.to_ne_bytes());
        assert!(!PieConfig::parse_params(&["dq_rate_estimator", "no_dq_rate_estimator"]).unwrap().dq_rate_estimator);
        assert!(HhfConfig::parse_params(&["non_hh_weight", "2"]).is_ok());
    }

    #[test]
    fn taprio_entries_nest_as_the_kernel_reads_them() {
        use crate::netlink::types::tc::qdisc::taprio;
        let cfg = TaprioConfig::parse_params(&["sched-entry", "S", "01", "300000", "sched-entry", "S", "02", "300000"]).unwrap();
        let list = &qdisc_option_attrs(&cfg)[&taprio::TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST];
        // Each entry is a TCA_TAPRIO_SCHED_ENTRY nest: the kernel skips any
        // other type and then refuses the empty schedule (#823).
        let mut rest = &list[..];
        let mut types = Vec::new();
        while rest.len() >= 4 {
            let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
            types.push(u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff);
            rest = &rest[len.next_multiple_of(4).min(rest.len())..];
        }
        assert_eq!(types, [taprio::TCA_TAPRIO_SCHED_ENTRY; 2]);
    }

    #[test]
    fn fq_parse_params() {
        let cfg = FqConfig::parse_params(&[
            "limit", "10000", "flow_limit", "100", "quantum", "3028", "maxrate", "100mbit",
            "nopacing",
        ])
        .unwrap();
        assert_eq!(cfg.limit, Some(crate::util::Packets::new(10000)));
        assert_eq!(cfg.flow_limit, Some(crate::util::Packets::new(100)));
        assert_eq!(cfg.quantum, Some(3028));
        // 100 mbit = 12_500_000 bytes/sec
        assert_eq!(
            cfg.maxrate.unwrap().as_u32_bytes_per_sec_saturating(),
            12_500_000
        );
        assert_eq!(cfg.pacing, Some(false));
        assert_eq!(cfg.kind(), "fq");

        // strict
        assert!(FqConfig::parse_params(&["bogus"]).is_err());
        assert!(FqConfig::parse_params(&["maxrate"]).is_err()); // missing value
        assert!(FqConfig::parse_params(&["maxrate", "notarate"]).is_err());
        assert!(FqConfig::parse_params(&["limit", "notanumber"]).is_err());
    }

    #[test]
    fn mq_parse_params() {
        assert_eq!(MqConfig::parse_params(&[]).unwrap().kind(), "mq");
        // strict: any token errors
        assert!(MqConfig::parse_params(&["bands", "4"]).is_err());
        assert!(MqConfig::parse_params(&["anything"]).is_err());
    }

    #[test]
    fn ets_parse_params() {
        let cfg = EtsConfig::parse_params(&[
            "bands", "4", "strict", "1", "quanta", "3000", "2000", "1000", "priomap", "0", "0", "1",
            "2", "3",
        ])
        .unwrap();
        assert_eq!(cfg.bands, Some(4));
        assert_eq!(cfg.strict, Some(1));
        assert_eq!(cfg.quanta, vec![3000, 2000, 1000]);
        assert_eq!(cfg.priomap, vec![0, 0, 1, 2, 3]);
        assert_eq!(cfg.kind(), "ets");

        // any-order keywords
        let cfg = EtsConfig::parse_params(&["quanta", "1500", "bands", "2"]).unwrap();
        assert_eq!(cfg.quanta, vec![1500]);
        assert_eq!(cfg.bands, Some(2));

        // strict
        assert!(EtsConfig::parse_params(&["bogus"]).is_err());
        assert!(EtsConfig::parse_params(&["bands"]).is_err()); // missing value
        assert!(EtsConfig::parse_params(&["bands", "notanumber"]).is_err());
        assert!(EtsConfig::parse_params(&["quanta"]).is_err()); // empty list
        assert!(EtsConfig::parse_params(&["quanta", "notanumber"]).is_err());
        assert!(EtsConfig::parse_params(&["priomap", "notanumber"]).is_err());
    }

    #[test]
    fn ets_write_options_nests_quanta_and_priomap() {
        // Smoke-test that nested encoding produces bytes without panic
        // and includes the band-level attrs.
        let cfg = EtsConfig::new()
            .bands(3)
            .strict(1)
            .quanta(vec![2000, 1000])
            .priomap(vec![0, 1, 2]);
        let mut builder = MessageBuilder::new(0, 0);
        cfg.write_options(&mut builder).unwrap();
        // Non-empty payload — at minimum NBANDS + NSTRICT + 2 nests.
        assert!(!builder.as_bytes().is_empty());
    }

    /// #485: `ffff:` is the ingress/clsact qdisc's handle. Refused anywhere
    /// else, before the kernel is asked — which would accept it until an
    /// ingress qdisc came along, and refuse one of them then.
    #[tokio::test]
    async fn a_qdisc_handle_with_the_ingress_major_is_refused_off_ingress() {
        let conn = Connection::<Route>::new().expect("socket open");
        let err = conn
            .add_qdisc_by_index_full(
                1,
                TcHandle::new(1, 2),
                Some(TcHandle::major_only(0xffff)),
                FqCodelConfig::new().build(),
            )
            .await
            .expect_err("reserved");
        assert!(err.to_string().contains("reserved"), "{err}");
        assert!(TcHandle::major_only(0xffff).is_reserved_major());
        assert!(TcHandle::INGRESS.is_reserved_major());
        assert!(!TcHandle::major_only(0x8000).is_reserved_major());
    }
}

/// `to_params` is `parse_params`' inverse for the class kinds a declared
/// tree holds (#645): the tokens parse back to a class that writes the
/// same request, and the same tokens.
#[cfg(test)]
mod class_params_tests {
    use super::*;
    use crate::util::{Bytes, Rate};

    fn bytes(c: &impl ClassConfig) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        c.write_options(&mut b).unwrap();
        b.as_bytes()[start..].to_vec()
    }

    macro_rules! round_trips {
        ($ty:ident, $c:expr) => {{
            let c: $ty = $c;
            let tokens = c.to_params().unwrap_or_else(|e| panic!("{e}"));
            let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let back = $ty::parse_params(&refs).unwrap_or_else(|e| panic!("{tokens:?}: {e}"));
            assert_eq!(back.to_params().unwrap(), tokens);
            assert_eq!(bytes(&back), bytes(&c), "{tokens:?}");
            tokens
        }};
    }

    #[test]
    fn htb_round_trips() {
        assert_eq!(
            round_trips!(HtbClassConfig, HtbClassConfig::new(Rate::mbit(60)).ceil(Rate::mbit(100))),
            ["rate", "60mbit", "ceil", "100mbit"]
        );
        round_trips!(
            HtbClassConfig,
            HtbClassConfig::new(Rate::bytes_per_sec(1_250_001))
                .burst(Bytes::kib(32))
                .cburst(Bytes::new(3000))
                .prio(2)
                .quantum(1514)
                .mtu(9000)
                .mpu(64)
                .overhead(4)
        );
    }

    #[test]
    fn hfsc_round_trips_and_reads_curves() {
        let two = TcServiceCurve::two_slope(2_500_000, 5000, 1_250_000);
        assert_eq!(
            round_trips!(HfscClassConfig, HfscClassConfig::new().rt_curve(two).ls_rate(Rate::mbit(60))),
            ["rt", "m1", "20mbit", "d", "5000us", "m2", "10mbit", "ls", "rate", "60mbit"]
        );
        // One curve for both is `sc`.
        assert_eq!(
            round_trips!(HfscClassConfig, HfscClassConfig::new().rt_curve(two).ls_curve(two)),
            ["sc", "m1", "20mbit", "d", "5000us", "m2", "10mbit"]
        );
        round_trips!(HfscClassConfig, HfscClassConfig::new().ls_rate(Rate::mbit(40)).ul_rate(Rate::mbit(80)));
        // tc(8)'s spellings read as the same curve.
        let parsed = HfscClassConfig::parse_params(&[
            "rt", "m1", "20mbit", "d", "5ms", "m2", "10mbit", "ls", "m2", "60mbit",
        ])
        .unwrap();
        assert_eq!(
            bytes(&parsed),
            bytes(&HfscClassConfig::new().rt_curve(two).ls_rate(Rate::mbit(60)))
        );
        for bad in [&["rt"][..], &["rt", "m1", "1mbit"], &["xx", "rate", "1mbit"], &["ls", "d", "1x", "m2", "1mbit"]] {
            let err = HfscClassConfig::parse_params(bad).unwrap_err().to_string();
            assert!(err.contains("hfsc: "), "{bad:?}: {err}");
        }
    }

    #[test]
    fn drr_and_qfq_round_trip() {
        assert_eq!(
            round_trips!(DrrClassConfig, DrrClassConfig::new().quantum(Bytes::new(3000))),
            ["quantum", "3000b"]
        );
        assert!(round_trips!(DrrClassConfig, DrrClassConfig::new()).is_empty());
        assert_eq!(
            round_trips!(QfqClassConfig, QfqClassConfig::new().weight(10).lmax(Bytes::kib(2))),
            ["weight", "10", "maxpkt", "2048"]
        );
    }
}
