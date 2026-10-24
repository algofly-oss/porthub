//! Typed TC options parsing.
//!
//! This module provides strongly-typed access to qdisc-specific options
//! that are stored in the raw `TcMessage.options` field.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::netlink::tc_options::{QdiscOptions, parse_qdisc_options};
//!
//! let qdiscs = conn.get_qdiscs().await?;
//! for qdisc in &qdiscs {
//!     if let Some(opts) = parse_qdisc_options(qdisc) {
//!         match opts {
//!             QdiscOptions::FqCodel(fq) => {
//!                 println!("fq_codel: target={}us, interval={}us, limit={}",
//!                     fq.target_us, fq.interval_us, fq.limit);
//!             }
//!             QdiscOptions::Htb(htb) => {
//!                 println!("htb: default={:x}", htb.default_class);
//!             }
//!             // ... handle other types
//!             _ => {}
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use super::{messages::TcMessage, psched};

/// Parsed qdisc options, strongly typed by qdisc kind.
///
/// `Display` prints them in tc(8) syntax, as they follow the kind on a `tc
/// qdisc add` line, and the text is an input: given to tc, or split on
/// whitespace and given to the kind's `parse_params`, it installs a qdisc
/// the kernel reports as this one (#515).
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::tc::NetemConfig;
/// use nlink::netlink::tc_options::QdiscOptions;
///
/// let root = conn.get_root_qdisc_by_name("eth0").await?.expect("a root qdisc");
/// if let Some(QdiscOptions::Netem(netem)) = root.options() {
///     println!("{netem}"); // limit 1000 delay 100ms 10ms loss 1%
///     // The same netem, one thing changed.
///     let cfg = NetemConfig::from(&netem).limit(nlink::Packets::new(5000));
///     conn.replace_qdisc("eth0", cfg).await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QdiscOptions {
    /// fq_codel - Fair Queue Controlled Delay
    FqCodel(FqCodelOptions),
    /// htb - Hierarchical Token Bucket
    Htb(HtbOptions),
    /// tbf - Token Bucket Filter
    Tbf(TbfOptions),
    /// netem - Network Emulator
    Netem(NetemOptions),
    /// prio - Priority Scheduler
    Prio(PrioOptions),
    /// sfq - Stochastic Fairness Queuing
    Sfq(SfqOptions),
    /// fq_pie - Flow Queue PIE
    FqPie(FqPieOptions),
    /// cake - Common Applications Kept Enhanced
    Cake(CakeOptions),
    /// Unknown qdisc type (contains raw options)
    Unknown(Vec<u8>),
}

/// fq_codel qdisc options.
#[derive(Debug, Clone, Default)]
pub struct FqCodelOptions {
    /// Target delay in microseconds.
    pub target_us: u32,
    /// Interval in microseconds.
    pub interval_us: u32,
    /// Queue limit in packets.
    pub limit: u32,
    /// Number of flows.
    pub flows: u32,
    /// Quantum (bytes to dequeue per round).
    pub quantum: u32,
    /// ECN marking enabled.
    pub ecn: bool,
    /// CE threshold in microseconds.
    pub ce_threshold_us: Option<u32>,
    /// Memory limit in bytes.
    pub memory_limit: Option<u32>,
    /// Drop batch size.
    pub drop_batch_size: Option<u32>,
    /// The CE threshold's selector and mask, when it has them (#806).
    pub ce_threshold_selector: Option<(u8, u8)>,
}

impl FqCodelOptions {
    /// Get the target delay as a Duration, or None if not set.
    #[inline]
    pub fn target(&self) -> Option<std::time::Duration> {
        if self.target_us > 0 {
            Some(std::time::Duration::from_micros(self.target_us as u64))
        } else {
            None
        }
    }

    /// Get the interval as a Duration, or None if not set.
    #[inline]
    pub fn interval(&self) -> Option<std::time::Duration> {
        if self.interval_us > 0 {
            Some(std::time::Duration::from_micros(self.interval_us as u64))
        } else {
            None
        }
    }

    /// Get the queue limit in packets, or None if not set.
    #[inline]
    pub fn limit(&self) -> Option<u32> {
        if self.limit > 0 {
            Some(self.limit)
        } else {
            None
        }
    }

    /// Get the number of flows, or None if not set.
    #[inline]
    pub fn flows(&self) -> Option<u32> {
        if self.flows > 0 {
            Some(self.flows)
        } else {
            None
        }
    }

    /// Get the quantum (bytes per round), or None if not set.
    #[inline]
    pub fn quantum(&self) -> Option<u32> {
        if self.quantum > 0 {
            Some(self.quantum)
        } else {
            None
        }
    }

    /// Check if ECN marking is enabled.
    #[inline]
    pub fn ecn(&self) -> bool {
        self.ecn
    }

    /// Get the CE threshold as a Duration, if configured.
    #[inline]
    pub fn ce_threshold(&self) -> Option<std::time::Duration> {
        self.ce_threshold_us
            .map(|us| std::time::Duration::from_micros(us as u64))
    }

    /// Get the memory limit in bytes, if configured.
    #[inline]
    pub fn memory_limit(&self) -> Option<u32> {
        self.memory_limit
    }

    /// Get the drop batch size, if configured.
    #[inline]
    pub fn drop_batch_size(&self) -> Option<u32> {
        self.drop_batch_size
    }
}

/// htb qdisc options.
#[derive(Debug, Clone, Default)]
pub struct HtbOptions {
    /// Default class ID.
    pub default_class: u32,
    /// Rate to quantum divisor.
    pub rate2quantum: u32,
    /// Direct queue length.
    pub direct_qlen: Option<u32>,
    /// HTB version.
    pub version: u32,
}

impl HtbOptions {
    /// Get the default class ID, or None if not set (0).
    #[inline]
    pub fn default_class(&self) -> Option<u32> {
        if self.default_class != 0 {
            Some(self.default_class)
        } else {
            None
        }
    }

    /// Get the rate to quantum divisor, or None if not set (0).
    #[inline]
    pub fn rate2quantum(&self) -> Option<u32> {
        if self.rate2quantum != 0 {
            Some(self.rate2quantum)
        } else {
            None
        }
    }

    /// Get the direct queue length, if configured.
    #[inline]
    pub fn direct_qlen(&self) -> Option<u32> {
        self.direct_qlen
    }

    /// Get the HTB version.
    #[inline]
    pub fn version(&self) -> u32 {
        self.version
    }
}

/// tbf qdisc options.
#[derive(Debug, Clone, Default)]
pub struct TbfOptions {
    /// Rate in bytes/sec.
    pub rate: u64,
    /// Peak rate in bytes/sec (0 if not set).
    pub peakrate: u64,
    /// Bucket size (burst) in bytes.
    pub burst: u32,
    /// Maximum packet size (MTU).
    pub mtu: u32,
    /// Queue limit in bytes.
    pub limit: u32,
}

impl TbfOptions {
    /// Get the rate in bytes/sec, or None if not set.
    #[inline]
    pub fn rate(&self) -> Option<u64> {
        if self.rate > 0 { Some(self.rate) } else { None }
    }

    /// Get the peak rate in bytes/sec, or None if not set.
    #[inline]
    pub fn peakrate(&self) -> Option<u64> {
        if self.peakrate > 0 {
            Some(self.peakrate)
        } else {
            None
        }
    }

    /// Get the bucket size (burst) in bytes, or None if not set.
    #[inline]
    pub fn burst(&self) -> Option<u32> {
        if self.burst > 0 {
            Some(self.burst)
        } else {
            None
        }
    }

    /// Get the MTU (maximum packet size) in bytes, or None if not set.
    #[inline]
    pub fn mtu(&self) -> Option<u32> {
        if self.mtu > 0 { Some(self.mtu) } else { None }
    }

    /// Get the queue limit in bytes, or None if not set.
    #[inline]
    pub fn limit(&self) -> Option<u32> {
        if self.limit > 0 {
            Some(self.limit)
        } else {
            None
        }
    }
}

/// netem qdisc options.
///
/// All fields are private; use accessor methods to retrieve values.
/// For example, use `delay()` to get the delay as a `Duration`, or
/// `loss()` to get the loss percentage.
#[derive(Debug, Clone, Default)]
pub struct NetemOptions {
    /// Added delay in nanoseconds.
    pub(crate) delay_ns: u64,
    /// Delay jitter in nanoseconds.
    pub(crate) jitter_ns: u64,
    /// Delay correlation (0-100%).
    pub(crate) delay_corr: f64,
    /// Packet loss probability (0-100%).
    pub(crate) loss_percent: f64,
    /// Loss correlation (0-100%).
    pub(crate) loss_corr: f64,
    /// Duplicate probability (0-100%).
    pub(crate) duplicate_percent: f64,
    /// Duplicate correlation (0-100%).
    pub(crate) duplicate_corr: f64,
    /// Reorder probability (0-100%).
    pub(crate) reorder_percent: f64,
    /// Reorder correlation (0-100%).
    pub(crate) reorder_corr: f64,
    /// Corruption probability (0-100%).
    pub(crate) corrupt_percent: f64,
    /// Corruption correlation (0-100%).
    pub(crate) corrupt_corr: f64,
    /// Rate limit in bytes/sec (0 if not set).
    pub(crate) rate: u64,
    /// Per-packet overhead in bytes for rate limiting.
    pub(crate) packet_overhead: i32,
    /// ATM cell size for rate limiting overhead calculation.
    pub(crate) cell_size: u32,
    /// Per-cell overhead for rate limiting.
    pub(crate) cell_overhead: i32,
    /// Queue limit in packets.
    pub(crate) limit: u32,
    /// Reorder gap.
    pub(crate) gap: u32,
    /// ECN marking enabled.
    pub(crate) ecn: bool,
    /// Slot-based transmission configuration (if present).
    pub(crate) slot: Option<NetemSlotOptions>,
    /// Loss model (if using state-based loss instead of random).
    pub(crate) loss_model: Option<NetemLossModel>,
    /// The PRNG seed (Linux 6.3+ dumps one always, random unless set).
    pub(crate) seed: Option<u64>,
}

/// A netem Markov loss model — `tc`'s `loss state …` and `loss gemodel …`.
///
/// These are netem's two **bursty** loss generators. `loss <p>% <corr>%`
/// is not one: its correlation lowers the loss rate instead of grouping
/// losses (#369). Read back from the kernel in
/// [`NetemOptions::loss_model`], and set through
/// [`NetemConfig::loss_model`](crate::netlink::tc::NetemConfig::loss_model)
/// or the declarative `QdiscBuilder::loss_model`.
///
/// Every field holds a probability in **percent** (`0.0..=100.0`), exactly
/// as the kernel stores it, so a model read back from the kernel and one
/// built here compare field for field. Build one with
/// [`gilbert_elliot`](Self::gilbert_elliot) or
/// [`gilbert_intuitive`](Self::gilbert_intuitive), which apply `tc(8)`'s
/// defaults and take each parameter by its meaning, rather than writing the
/// variants directly: Gilbert-Elliot's `h` in particular is the probability
/// of *delivering* in the bad state, the complement of what `tc` takes.
///
/// Field semantics follow `tc-netem(8)` and iproute2's `q_netem.c`, and were
/// checked against what iproute2 6.15 installs in the kernel.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::Percent;
/// use nlink::netlink::tc::{NetemConfig, NetemLossModel};
///
/// // tc qdisc add dev eth0 root netem loss gemodel 1% 30% 50% 0.1%
/// let model = NetemLossModel::gilbert_elliot(Percent::new(1.0)) // enter the bad state
///     .r(Percent::new(30.0))                                     // leave it
///     .loss_in_bad(Percent::new(50.0))                           // tc's `1-h`
///     .loss_in_good(Percent::new(0.1));                          // tc's `1-k`
/// conn.add_qdisc("eth0", NetemConfig::new().loss_model(model)).await?;
/// # Ok(())
/// # }
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum NetemLossModel {
    /// Gilbert-Intuitive 4-state Markov model (`loss state p13 [p31 [p32
    /// [p23 [p14]]]]`). The states, per `tc-netem(8)`:
    ///
    /// 1. good packet reception (no loss);
    /// 2. good reception within a burst;
    /// 3. burst losses;
    /// 4. independent losses.
    ///
    /// `tc` takes `p23` *before* `p14` on its command line, while the
    /// kernel struct (and this variant) stores `p14` first.
    GilbertIntuitive {
        /// 1 → 3: from good reception into a loss burst. `tc`'s first,
        /// mandatory value.
        p13: f64,
        /// 3 → 1: from a loss burst back to good reception.
        p31: f64,
        /// 3 → 2: from a loss burst to good reception within the burst.
        p32: f64,
        /// 1 → 4: an independent (isolated) loss.
        p14: f64,
        /// 2 → 3: from good reception within a burst back to losing.
        p23: f64,
    },
    /// Gilbert-Elliot 2-state model (`loss gemodel p [r [1-h [1-k]]]`): a
    /// good state and a bad (lossy) state, each with its own loss
    /// probability.
    GilbertElliot {
        /// Good → bad: the probability of entering the bad state.
        p: f64,
        /// Bad → good: the probability of leaving the bad state.
        r: f64,
        /// The probability of **delivering** a packet in the bad state.
        /// The loss probability there is `100 - h`: `tc`'s `1-h` argument,
        /// which iproute2 converts before sending.
        h: f64,
        /// The **loss** probability in the good state: `tc`'s `1-k`
        /// argument, which is sent as given.
        k1: f64,
    },
}

impl NetemLossModel {
    /// A Gilbert-Elliot model entering the bad state with probability `p`,
    /// with `tc(8)`'s defaults for the rest, i.e. `loss gemodel p`: leave
    /// the bad state with `r = 100% - p`, lose everything while in it, and
    /// nothing in the good state (the "simple Gilbert" model).
    ///
    /// Refine with [`r`](Self::r), [`loss_in_bad`](Self::loss_in_bad) and
    /// [`loss_in_good`](Self::loss_in_good).
    #[doc(alias = "gemodel")]
    pub fn gilbert_elliot(p: crate::util::Percent) -> Self {
        Self::GilbertElliot {
            p: p.as_percent(),
            r: 100.0 - p.as_percent(),
            h: 0.0,
            k1: 0.0,
        }
    }

    /// A Gilbert-Intuitive 4-state model entering a loss burst with
    /// probability `p13`, with `tc(8)`'s defaults for the rest, i.e.
    /// `loss state p13`: `p31 = 100% - p13`, `p32 = 0`, `p23 = 100%`,
    /// `p14 = 0`.
    ///
    /// Refine with [`p31`](Self::p31), [`p32`](Self::p32),
    /// [`p23`](Self::p23) and [`p14`](Self::p14).
    #[doc(alias = "state")]
    pub fn gilbert_intuitive(p13: crate::util::Percent) -> Self {
        Self::GilbertIntuitive {
            p13: p13.as_percent(),
            p31: 100.0 - p13.as_percent(),
            p32: 0.0,
            p14: 0.0,
            p23: 100.0,
        }
    }

    /// Gilbert-Elliot: the probability of leaving the bad state (`r`).
    /// No-op on a 4-state model.
    pub fn r(mut self, r: crate::util::Percent) -> Self {
        if let Self::GilbertElliot { r: v, .. } = &mut self {
            *v = r.as_percent();
        }
        self
    }

    /// Gilbert-Elliot: the loss probability in the bad state, `tc`'s
    /// `1-h`. Stored as the kernel's `h`, its complement. No-op on a
    /// 4-state model.
    pub fn loss_in_bad(mut self, loss: crate::util::Percent) -> Self {
        if let Self::GilbertElliot { h, .. } = &mut self {
            *h = 100.0 - loss.as_percent();
        }
        self
    }

    /// Gilbert-Elliot: the loss probability in the good state, `tc`'s
    /// `1-k` and the kernel's `k1`. No-op on a 4-state model.
    pub fn loss_in_good(mut self, loss: crate::util::Percent) -> Self {
        if let Self::GilbertElliot { k1, .. } = &mut self {
            *k1 = loss.as_percent();
        }
        self
    }

    /// 4-state: loss burst → good reception (`p31`). No-op on
    /// Gilbert-Elliot.
    pub fn p31(mut self, p: crate::util::Percent) -> Self {
        if let Self::GilbertIntuitive { p31, .. } = &mut self {
            *p31 = p.as_percent();
        }
        self
    }

    /// 4-state: loss burst → good reception within the burst (`p32`).
    /// No-op on Gilbert-Elliot.
    pub fn p32(mut self, p: crate::util::Percent) -> Self {
        if let Self::GilbertIntuitive { p32, .. } = &mut self {
            *p32 = p.as_percent();
        }
        self
    }

    /// 4-state: good reception within a burst → loss burst (`p23`).
    /// No-op on Gilbert-Elliot.
    pub fn p23(mut self, p: crate::util::Percent) -> Self {
        if let Self::GilbertIntuitive { p23, .. } = &mut self {
            *p23 = p.as_percent();
        }
        self
    }

    /// 4-state: good reception → independent loss (`p14`). No-op on
    /// Gilbert-Elliot.
    pub fn p14(mut self, p: crate::util::Percent) -> Self {
        if let Self::GilbertIntuitive { p14, .. } = &mut self {
            *p14 = p.as_percent();
        }
        self
    }

    /// The model as the kernel stores it: its `NETEM_LOSS_*` type and its
    /// fields in struct order, each as a `u32` probability.
    pub(crate) fn kernel_fields(&self) -> (u16, Vec<u32>) {
        use super::types::tc::qdisc::netem::{NETEM_LOSS_GE, NETEM_LOSS_GI};
        let k = |v: f64| crate::util::Percent::new(v).as_kernel_probability();
        match *self {
            Self::GilbertIntuitive {
                p13,
                p31,
                p32,
                p14,
                p23,
            } => (NETEM_LOSS_GI, vec![k(p13), k(p31), k(p32), k(p14), k(p23)]),
            Self::GilbertElliot { p, r, h, k1 } => (NETEM_LOSS_GE, vec![k(p), k(r), k(h), k(k1)]),
        }
    }

    /// Whether two models are the same in the kernel's own units. This is
    /// the comparison the declarative diff needs, since a model read back
    /// carries `u32 → f64` rounding that a built one does not.
    pub(crate) fn kernel_eq(&self, other: &Self) -> bool {
        self.kernel_fields() == other.kernel_fields()
    }

    /// Append the nested `TCA_NETEM_LOSS` attribute that selects this
    /// model.
    pub(crate) fn write_attr(&self, builder: &mut super::builder::MessageBuilder) {
        use super::types::tc::qdisc::netem::{
            NETEM_LOSS_GE, NETEM_LOSS_GI, TCA_NETEM_LOSS, TcNetemGeModel, TcNetemGiModel,
        };
        let (kind, f) = self.kernel_fields();
        let nest = builder.nest_start(TCA_NETEM_LOSS);
        if kind == NETEM_LOSS_GI {
            let gi = TcNetemGiModel {
                p13: f[0],
                p31: f[1],
                p32: f[2],
                p14: f[3],
                p23: f[4],
            };
            builder.append_attr(NETEM_LOSS_GI, gi.as_bytes());
        } else {
            debug_assert_eq!(kind, NETEM_LOSS_GE);
            let ge = TcNetemGeModel {
                p: f[0],
                r: f[1],
                h: f[2],
                k1: f[3],
            };
            builder.append_attr(NETEM_LOSS_GE, ge.as_bytes());
        }
        builder.nest_end(nest);
    }
}

/// Netem slot-based transmission options.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetemSlotOptions {
    /// Minimum delay between packets in nanoseconds.
    pub min_delay_ns: i64,
    /// Maximum delay between packets in nanoseconds.
    pub max_delay_ns: i64,
    /// Maximum packets per slot (0 = unlimited).
    pub max_packets: i32,
    /// Maximum bytes per slot (0 = unlimited).
    pub max_bytes: i32,
    /// Distribution delay in nanoseconds.
    pub dist_delay_ns: i64,
    /// Distribution jitter in nanoseconds.
    pub dist_jitter_ns: i64,
}

/// Netem parameters that can be configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetemParameter {
    /// Delay is configured (delay_ns > 0).
    Delay,
    /// Jitter is configured (jitter_ns > 0).
    Jitter,
    /// Packet loss is configured.
    Loss,
    /// Packet duplication is configured.
    Duplicate,
    /// Packet reordering is configured.
    Reorder,
    /// Packet corruption is configured.
    Corrupt,
    /// Rate limiting is configured.
    Rate,
}

impl NetemOptions {
    /// Get the configured delay as a Duration, or None if not set.
    #[inline]
    pub fn delay(&self) -> Option<std::time::Duration> {
        if self.delay_ns > 0 {
            Some(std::time::Duration::from_nanos(self.delay_ns))
        } else {
            None
        }
    }

    /// Get the configured jitter as a Duration, or None if not set.
    #[inline]
    pub fn jitter(&self) -> Option<std::time::Duration> {
        if self.jitter_ns > 0 {
            Some(std::time::Duration::from_nanos(self.jitter_ns))
        } else {
            None
        }
    }

    /// Get the configured loss percentage, or None if not set.
    #[inline]
    pub fn loss(&self) -> Option<f64> {
        if self.loss_percent > 0.0 || self.loss_model.is_some() {
            Some(self.loss_percent)
        } else {
            None
        }
    }

    /// Get the configured duplicate percentage, or None if not set.
    #[inline]
    pub fn duplicate(&self) -> Option<f64> {
        if self.duplicate_percent > 0.0 {
            Some(self.duplicate_percent)
        } else {
            None
        }
    }

    /// Get the configured reorder percentage, or None if not set.
    #[inline]
    pub fn reorder(&self) -> Option<f64> {
        if self.reorder_percent > 0.0 || self.gap > 0 {
            Some(self.reorder_percent)
        } else {
            None
        }
    }

    /// Get the configured corrupt percentage, or None if not set.
    #[inline]
    pub fn corrupt(&self) -> Option<f64> {
        if self.corrupt_percent > 0.0 {
            Some(self.corrupt_percent)
        } else {
            None
        }
    }

    /// Get the configured rate limit in bytes/sec, or None if not set.
    #[inline]
    pub fn rate_bps(&self) -> Option<u64> {
        if self.rate > 0 { Some(self.rate) } else { None }
    }

    /// Get the per-packet overhead in bytes for rate limiting.
    ///
    /// This is added to each packet's size when calculating rate limiting.
    /// Common values: 14 for Ethernet header, 38 for PPPoE+Ethernet.
    #[inline]
    pub fn packet_overhead(&self) -> i32 {
        self.packet_overhead
    }

    /// Get the ATM cell size for rate limiting overhead calculation.
    ///
    /// When set, packets are rounded up to multiples of this cell size.
    /// Typically 53 for ATM networks.
    #[inline]
    pub fn cell_size(&self) -> u32 {
        self.cell_size
    }

    /// Get the per-cell overhead for rate limiting.
    ///
    /// This overhead is added for each ATM cell.
    #[inline]
    pub fn cell_overhead(&self) -> i32 {
        self.cell_overhead
    }

    /// Get the delay correlation percentage (0-100%), or None if not set.
    #[inline]
    pub fn delay_correlation(&self) -> Option<f64> {
        if self.delay_corr > 0.0 {
            Some(self.delay_corr)
        } else {
            None
        }
    }

    /// Get the loss correlation percentage (0-100%), or None if not set.
    #[inline]
    pub fn loss_correlation(&self) -> Option<f64> {
        if self.loss_corr > 0.0 {
            Some(self.loss_corr)
        } else {
            None
        }
    }

    /// Get the duplicate correlation percentage (0-100%), or None if not set.
    #[inline]
    pub fn duplicate_correlation(&self) -> Option<f64> {
        if self.duplicate_corr > 0.0 {
            Some(self.duplicate_corr)
        } else {
            None
        }
    }

    /// Get the reorder correlation percentage (0-100%), or None if not set.
    #[inline]
    pub fn reorder_correlation(&self) -> Option<f64> {
        if self.reorder_corr > 0.0 {
            Some(self.reorder_corr)
        } else {
            None
        }
    }

    /// Get the corrupt correlation percentage (0-100%), or None if not set.
    #[inline]
    pub fn corrupt_correlation(&self) -> Option<f64> {
        if self.corrupt_corr > 0.0 {
            Some(self.corrupt_corr)
        } else {
            None
        }
    }

    /// Get the raw delay in nanoseconds.
    ///
    /// Prefer using `delay()` which returns an `Option<Duration>`.
    #[inline]
    pub fn delay_ns(&self) -> u64 {
        self.delay_ns
    }

    /// Get the raw jitter in nanoseconds.
    ///
    /// Prefer using `jitter()` which returns an `Option<Duration>`.
    #[inline]
    pub fn jitter_ns(&self) -> u64 {
        self.jitter_ns
    }

    /// Get the raw loss percentage (0.0-100.0).
    ///
    /// Prefer using `loss()` which returns `None` if not configured.
    #[inline]
    pub fn loss_percent(&self) -> f64 {
        self.loss_percent
    }

    /// Get the raw duplicate percentage (0.0-100.0).
    ///
    /// Prefer using `duplicate()` which returns `None` if not configured.
    #[inline]
    pub fn duplicate_percent(&self) -> f64 {
        self.duplicate_percent
    }

    /// Get the raw reorder percentage (0.0-100.0).
    ///
    /// Prefer using `reorder()` which returns `None` if not configured.
    #[inline]
    pub fn reorder_percent(&self) -> f64 {
        self.reorder_percent
    }

    /// Get the raw corrupt percentage (0.0-100.0).
    ///
    /// Prefer using `corrupt()` which returns `None` if not configured.
    #[inline]
    pub fn corrupt_percent(&self) -> f64 {
        self.corrupt_percent
    }

    /// Check if ECN marking is enabled.
    #[inline]
    pub fn ecn(&self) -> bool {
        self.ecn
    }

    /// Get the reorder gap, or None if not set.
    ///
    /// The gap specifies how many packets can be reordered. A gap of N means
    /// that packet N can be reordered with packets 1 through N-1.
    #[inline]
    pub fn gap(&self) -> Option<u32> {
        if self.gap > 0 { Some(self.gap) } else { None }
    }

    /// Get the queue limit in packets, or None if not set.
    #[inline]
    pub fn limit(&self) -> Option<u32> {
        if self.limit > 0 {
            Some(self.limit)
        } else {
            None
        }
    }

    /// Get the slot-based transmission configuration, if present.
    #[inline]
    pub fn slot(&self) -> Option<&NetemSlotOptions> {
        self.slot.as_ref()
    }

    /// The Markov loss model, when the qdisc uses one instead of
    /// random loss (`loss state …` / `loss gemodel …`).
    #[inline]
    pub fn loss_model(&self) -> Option<&NetemLossModel> {
        self.loss_model.as_ref()
    }

    /// The seed of netem's random numbers. Linux 6.3+ reports one whether
    /// or not it was set — a random one when it was not — and keeps it
    /// across a change that does not send one; older kernels report none.
    #[inline]
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Returns the set of configured parameters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::tc_options::QdiscOptions;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// if let Some(QdiscOptions::Netem(opts)) = qdisc.options() {
    ///     for param in opts.configured_parameters() {
    ///         println!("Configured: {:?}", param);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn configured_parameters(&self) -> Vec<NetemParameter> {
        let mut params = Vec::new();
        if self.delay().is_some() {
            params.push(NetemParameter::Delay);
        }
        if self.jitter().is_some() {
            params.push(NetemParameter::Jitter);
        }
        if self.loss().is_some() {
            params.push(NetemParameter::Loss);
        }
        if self.duplicate().is_some() {
            params.push(NetemParameter::Duplicate);
        }
        if self.reorder().is_some() {
            params.push(NetemParameter::Reorder);
        }
        if self.corrupt().is_some() {
            params.push(NetemParameter::Corrupt);
        }
        if self.rate_bps().is_some() {
            params.push(NetemParameter::Rate);
        }
        params
    }

    /// Whether moving this live netem to `new_config` needs the qdisc
    /// deleted and re-added, rather than replaced.
    ///
    /// Since 0.29 (#370), a replace clears every parameter
    /// [`NetemConfig`](super::tc::NetemConfig) can set. The base
    /// `tc_netem_qopt` always carried latency, jitter, loss, duplicate, gap
    /// and limit; the writer now also sends the *off* state of the
    /// correlations, reorder, corrupt and rate, which `netem_change()` would
    /// otherwise keep; and the kernel resets a loss model itself when none
    /// is sent. What a replace still cannot clear is what `NetemConfig`
    /// cannot express — a `slot` configuration and ECN marking, which
    /// `netem_change()` keeps when they are absent — so this is `true` only
    /// when the live qdisc carries one of those, whatever `new_config` is.
    /// (Delay/jitter distribution tables are not decoded, so they cannot be
    /// detected here either.)
    ///
    /// Before 0.29 this returned `true` whenever `new_config` dropped a
    /// parameter the live qdisc had. For delay, jitter, loss and duplicate
    /// that was never necessary, and for reorder, corrupt and rate it was
    /// the workaround for #370; a delete-and-add disturbs traffic and drops
    /// whatever the qdisc was holding.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// use nlink::netlink::tc::NetemConfig;
    /// use nlink::netlink::tc_options::QdiscOptions;
    /// use std::time::Duration;
    ///
    /// let current = match qdisc.options() {
    ///     Some(QdiscOptions::Netem(opts)) => opts,
    ///     _ => return Ok(()),
    /// };
    /// let new_config = NetemConfig::new()
    ///     .delay(Duration::from_millis(100))
    ///     .build();
    ///
    /// if current.requires_recreation_for(&new_config) {
    ///     // Need to delete and recreate
    ///     conn.del_qdisc("eth0", TcHandle::ROOT).await?;
    ///     conn.add_qdisc("eth0", new_config).await?;
    /// } else {
    ///     // Can use replace
    ///     conn.replace_qdisc("eth0", new_config).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn requires_recreation_for(&self, new_config: &super::tc::NetemConfig) -> bool {
        // Kept for the signature: no NetemConfig can clear these.
        let _ = new_config;
        self.slot.is_some() || self.ecn
    }
}

/// prio qdisc options.
#[derive(Debug, Clone)]
pub struct PrioOptions {
    /// Number of priority bands.
    pub bands: i32,
    /// Priority map (16 entries, maps TOS to band).
    pub priomap: [u8; 16],
}

impl Default for PrioOptions {
    fn default() -> Self {
        Self {
            bands: 3,
            priomap: [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
        }
    }
}

/// sfq qdisc options.
#[derive(Debug, Clone, Default)]
pub struct SfqOptions {
    /// Quantum (bytes to send per round).
    pub quantum: u32,
    /// Perturbation period in seconds.
    pub perturb_period: i32,
    /// Queue limit.
    pub limit: u32,
    /// Number of hash buckets.
    pub divisor: u32,
    /// Number of flows.
    pub flows: u32,
    /// Depth (packets per flow).
    pub depth: Option<u32>,
    /// Enable head drop.
    pub headdrop: Option<bool>,
}

/// fq_pie qdisc options.
///
/// Mirrors the kernel's `TCA_FQ_PIE_*` attribute set (Linux 5.6+).
#[derive(Debug, Clone, Default)]
pub struct FqPieOptions {
    /// Queue limit in packets.
    pub limit: u32,
    /// Number of flow buckets.
    pub flows: u32,
    /// Target queueing delay in microseconds.
    pub target_us: u32,
    /// Drop-probability update interval in microseconds.
    pub tupdate_us: u32,
    /// Alpha parameter (P controller).
    pub alpha: u32,
    /// Beta parameter (I controller).
    pub beta: u32,
    /// DRR quantum in bytes.
    pub quantum: u32,
    /// Per-qdisc memory limit in bytes.
    pub memory_limit: u32,
    /// The drop probability up to which packets are ECN-marked, in whole
    /// percent. Named `ecn_prob_permille` and divided by 10 before 0.32
    /// (#631).
    pub ecn_prob_percent: u32,
    /// ECN marking enabled.
    pub ecn: bool,
    /// Byte mode enabled.
    pub bytemode: bool,
    /// Dequeue rate estimator enabled.
    pub dq_rate_estimator: bool,
}

impl FqPieOptions {
    /// Get the target queueing delay as a `Duration`, or `None` if zero.
    pub fn target(&self) -> Option<std::time::Duration> {
        if self.target_us > 0 {
            Some(std::time::Duration::from_micros(self.target_us as u64))
        } else {
            None
        }
    }

    /// Get the update interval as a `Duration`, or `None` if zero.
    pub fn tupdate(&self) -> Option<std::time::Duration> {
        if self.tupdate_us > 0 {
            Some(std::time::Duration::from_micros(self.tupdate_us as u64))
        } else {
            None
        }
    }

    /// Get the ECN probability as a `Percent`, or `None` if zero.
    pub fn ecn_prob(&self) -> Option<crate::util::Percent> {
        if self.ecn_prob_percent > 0 {
            Some(crate::util::Percent::new(f64::from(self.ecn_prob_percent)))
        } else {
            None
        }
    }
}

/// CAKE qdisc options.
///
/// Mirrors the kernel's `TCA_CAKE_*` attribute set as echoed back on
/// a qdisc dump.
#[derive(Debug, Clone, Default)]
pub struct CakeOptions {
    /// Bandwidth shaping limit in bytes/sec (0 = unlimited).
    pub bandwidth_bps: u64,
    /// Estimated round-trip time in microseconds (0 = unset).
    pub rtt_us: u32,
    /// Explicit CoDel target delay in microseconds (0 = unset).
    pub target_us: u32,
    /// Per-packet overhead in bytes (signed; can be negative).
    pub overhead: i32,
    /// Minimum packet unit (bytes).
    pub mpu: u32,
    /// Memory limit in bytes (0 = unset).
    pub memory_limit: u32,
    /// fwmark mask used for tin classification (0 = unset).
    pub fwmark: u32,
    /// Diffserv mode (kernel value, see `CAKE_DIFFSERV_*`).
    pub diffserv_mode: u32,
    /// Flow isolation mode (kernel value, see `CAKE_FLOW_*`).
    pub flow_mode: u32,
    /// ATM/PTM mode (kernel value, see `CAKE_ATM_*`).
    pub atm_mode: u32,
    /// ACK filter mode (kernel value, see `CAKE_ACK_*`).
    pub ack_filter: u32,
    pub autorate: bool,
    pub nat: bool,
    pub raw: bool,
    pub wash: bool,
    pub ingress: bool,
    pub split_gso: bool,
}

impl CakeOptions {
    /// Get the bandwidth as a typed `Rate`, or `None` if unlimited (0).
    pub fn bandwidth(&self) -> Option<crate::util::Rate> {
        if self.bandwidth_bps > 0 {
            Some(crate::util::Rate::bytes_per_sec(self.bandwidth_bps))
        } else {
            None
        }
    }

    /// Get the RTT as a `Duration`, or `None` if unset.
    pub fn rtt(&self) -> Option<std::time::Duration> {
        if self.rtt_us > 0 {
            Some(std::time::Duration::from_micros(self.rtt_us as u64))
        } else {
            None
        }
    }

    /// Get the target delay as a `Duration`, or `None` if unset.
    pub fn target(&self) -> Option<std::time::Duration> {
        if self.target_us > 0 {
            Some(std::time::Duration::from_micros(self.target_us as u64))
        } else {
            None
        }
    }
}

/// Parse qdisc options from a TcMessage.
///
/// Returns `None` if the message has no kind or no options.
pub fn parse_qdisc_options(msg: &TcMessage) -> Option<QdiscOptions> {
    let kind = msg.kind()?;
    let data = msg.options.as_ref()?;

    Some(match kind {
        "fq_codel" => QdiscOptions::FqCodel(parse_fq_codel_options(data)),
        "htb" => QdiscOptions::Htb(parse_htb_options(data)),
        "tbf" => QdiscOptions::Tbf(parse_tbf_options(data)),
        "netem" => QdiscOptions::Netem(parse_netem_options(data)),
        "prio" => QdiscOptions::Prio(parse_prio_options(data)),
        "sfq" => QdiscOptions::Sfq(parse_sfq_options(data)),
        "fq_pie" => QdiscOptions::FqPie(parse_fq_pie_options(data)),
        "cake" => QdiscOptions::Cake(parse_cake_options(data)),
        _ => QdiscOptions::Unknown(data.clone()),
    })
}

/// HTB class options.
#[derive(Debug, Clone, Default)]
pub struct HtbClassOptions {
    /// Guaranteed rate in bytes/sec.
    pub rate: u64,
    /// Ceiling rate in bytes/sec.
    pub ceil: u64,
    /// Burst size in bytes.
    pub burst: u32,
    /// Ceil burst size in bytes.
    pub cburst: u32,
    /// Priority (lower = higher priority).
    pub priority: u32,
    /// Quantum for borrowing.
    pub quantum: u32,
    /// Class level in hierarchy.
    pub level: u32,
}

/// Parse HTB class options from TcMessage options data.
pub fn parse_htb_class_options(data: &[u8]) -> Option<HtbClassOptions> {
    use super::types::tc::qdisc::htb::*;

    let mut opts = HtbClassOptions::default();
    let mut rate64: Option<u64> = None;
    let mut ceil64: Option<u64> = None;
    let mut buffer_ticks: u32 = 0;
    let mut cbuffer_ticks: u32 = 0;
    let mut input = data;

    while input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().ok()?) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().ok()?);

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_HTB_PARMS if payload.len() >= std::mem::size_of::<TcHtbOpt>() => {
                // Parse TcHtbOpt structure
                // Rate spec starts at offset 0, ceil at offset 12
                let rate = u32::from_ne_bytes(payload[8..12].try_into().ok()?);
                let ceil = u32::from_ne_bytes(payload[20..24].try_into().ok()?);
                opts.rate = rate as u64;
                opts.ceil = ceil as u64;

                if payload.len() >= 44 {
                    // tc_htb_opt.buffer/.cbuffer are psched TICKS. Convert to
                    // bytes below, once the 64-bit rates (which may override
                    // the 32-bit ones) are known (#218).
                    buffer_ticks = u32::from_ne_bytes(payload[24..28].try_into().ok()?);
                    cbuffer_ticks = u32::from_ne_bytes(payload[28..32].try_into().ok()?);
                    opts.quantum = u32::from_ne_bytes(payload[32..36].try_into().ok()?);
                    opts.level = u32::from_ne_bytes(payload[36..40].try_into().ok()?);
                    opts.priority = u32::from_ne_bytes(payload[40..44].try_into().ok()?);
                }
            }
            TCA_HTB_RATE64 if payload.len() >= 8 => {
                rate64 = Some(u64::from_ne_bytes(payload[..8].try_into().ok()?));
            }
            TCA_HTB_CEIL64 if payload.len() >= 8 => {
                ceil64 = Some(u64::from_ne_bytes(payload[..8].try_into().ok()?));
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    // Use 64-bit rates if available
    if let Some(r) = rate64 {
        opts.rate = r;
    }
    if let Some(c) = ceil64 {
        opts.ceil = c;
    }

    // The kernel reports the token bucket in psched ticks; `burst`/`cburst`
    // are byte counts. iproute2 converts back with tc_calc_xmitsize() before
    // printing, and so must we — without this, reading back a class created by
    // real `tc` yielded a burst off by 15.625/rate, and `reconcile` considered
    // a wildly wrong burst to be in sync (#218).
    opts.burst = psched::tc_calc_xmitsize(opts.rate, buffer_ticks);
    opts.cburst = psched::tc_calc_xmitsize(opts.ceil, cbuffer_ticks);

    Some(opts)
}

// ============================================================================
// Internal parsing functions
// ============================================================================

/// fq_codel attribute constants.
mod fq_codel_attrs {
    pub const TCA_FQ_CODEL_TARGET: u16 = 1;
    pub const TCA_FQ_CODEL_LIMIT: u16 = 2;
    pub const TCA_FQ_CODEL_INTERVAL: u16 = 3;
    pub const TCA_FQ_CODEL_ECN: u16 = 4;
    pub const TCA_FQ_CODEL_FLOWS: u16 = 5;
    pub const TCA_FQ_CODEL_QUANTUM: u16 = 6;
    pub const TCA_FQ_CODEL_CE_THRESHOLD: u16 = 7;
    pub const TCA_FQ_CODEL_DROP_BATCH_SIZE: u16 = 8;
    pub const TCA_FQ_CODEL_MEMORY_LIMIT: u16 = 9;
    pub const TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR: u16 = 10;
    pub const TCA_FQ_CODEL_CE_THRESHOLD_MASK: u16 = 11;
}

fn parse_fq_codel_options(data: &[u8]) -> FqCodelOptions {
    use fq_codel_attrs::*;

    let mut opts = FqCodelOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_FQ_CODEL_TARGET if payload.len() >= 4 => {
                opts.target_us = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            TCA_FQ_CODEL_LIMIT if payload.len() >= 4 => {
                opts.limit = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            TCA_FQ_CODEL_INTERVAL if payload.len() >= 4 => {
                opts.interval_us = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            TCA_FQ_CODEL_ECN if payload.len() >= 4 => {
                opts.ecn = u32::from_ne_bytes(payload[..4].try_into().unwrap()) != 0;
            }
            TCA_FQ_CODEL_FLOWS if payload.len() >= 4 => {
                opts.flows = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            TCA_FQ_CODEL_QUANTUM if payload.len() >= 4 => {
                opts.quantum = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            TCA_FQ_CODEL_CE_THRESHOLD if payload.len() >= 4 => {
                opts.ce_threshold_us = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            TCA_FQ_CODEL_DROP_BATCH_SIZE if payload.len() >= 4 => {
                opts.drop_batch_size = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR if !payload.is_empty() => {
                let mask = opts.ce_threshold_selector.map_or(0, |(_, m)| m);
                opts.ce_threshold_selector = Some((payload[0], mask));
            }
            TCA_FQ_CODEL_CE_THRESHOLD_MASK if !payload.is_empty() => {
                let value = opts.ce_threshold_selector.map_or(0, |(v, _)| v);
                opts.ce_threshold_selector = Some((value, payload[0]));
            }
            TCA_FQ_CODEL_MEMORY_LIMIT if payload.len() >= 4 => {
                opts.memory_limit = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_htb_options(data: &[u8]) -> HtbOptions {
    use super::types::tc::qdisc::htb::*;

    let mut opts = HtbOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_HTB_INIT if payload.len() >= TcHtbGlob::SIZE => {
                opts.version = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                opts.rate2quantum = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                opts.default_class = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
            }
            TCA_HTB_DIRECT_QLEN if payload.len() >= 4 => {
                opts.direct_qlen = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_tbf_options(data: &[u8]) -> TbfOptions {
    use super::types::tc::qdisc::tbf::*;

    let mut opts = TbfOptions::default();
    let mut rate64: Option<u64> = None;
    let mut prate64: Option<u64> = None;
    let mut buffer_ticks: u32 = 0;
    let mut mtu_ticks: u32 = 0;
    let mut burst_bytes: Option<u32> = None;
    let mut pburst_bytes: Option<u32> = None;
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_TBF_PARMS
                // TcTbfQopt: rate (TcRateSpec), peakrate (TcRateSpec), limit, buffer, mtu
                // TcRateSpec is 12 bytes
                if payload.len() >= 36 => {
                    // rate.rate is at offset 8
                    opts.rate = u32::from_ne_bytes(payload[8..12].try_into().unwrap()) as u64;
                    // peakrate.rate is at offset 20
                    opts.peakrate = u32::from_ne_bytes(payload[20..24].try_into().unwrap()) as u64;
                    // limit at offset 24
                    opts.limit = u32::from_ne_bytes(payload[24..28].try_into().unwrap());
                    // buffer at offset 28 and mtu at offset 32 are psched
                    // TICKS, not bytes — converted below once the rates are
                    // final (#218).
                    buffer_ticks = u32::from_ne_bytes(payload[28..32].try_into().unwrap());
                    mtu_ticks = u32::from_ne_bytes(payload[32..36].try_into().unwrap());
                }
            TCA_TBF_RATE64
                if payload.len() >= 8 => {
                    rate64 = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            TCA_TBF_PRATE64
                if payload.len() >= 8 => {
                    prate64 = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            // BURST/PBURST carry the true byte counts. When the kernel sends
            // them they are authoritative and sidestep the tick quantization
            // entirely, so they win over the converted PARMS values —
            // regardless of the order the attributes arrive in.
            TCA_TBF_BURST
                if payload.len() >= 4 => {
                    burst_bytes = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            TCA_TBF_PBURST
                if payload.len() >= 4 => {
                    pburst_bytes = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    // Use 64-bit rates if available
    if let Some(r) = rate64 {
        opts.rate = r;
    }
    if let Some(r) = prate64 {
        opts.peakrate = r;
    }

    // Byte counts, from the authoritative attribute if the kernel sent one,
    // else converted back from the tick-valued qopt fields.
    opts.burst =
        burst_bytes.unwrap_or_else(|| psched::tc_calc_xmitsize(opts.rate, buffer_ticks));
    // The peak bucket is sized against the peak rate; with no peakrate the
    // kernel sizes it against the main rate.
    let peak = if opts.peakrate > 0 {
        opts.peakrate
    } else {
        opts.rate
    };
    opts.mtu = pburst_bytes.unwrap_or_else(|| psched::tc_calc_xmitsize(peak, mtu_ticks));

    opts
}

fn parse_netem_options(data: &[u8]) -> NetemOptions {
    use super::types::tc::qdisc::netem::*;

    let mut opts = NetemOptions::default();

    // First 24 bytes are TcNetemQopt
    if data.len() >= TcNetemQopt::SIZE {
        // `latency` and `jitter` are psched ticks (64 ns), capped at
        // u32::MAX; TCA_NETEM_LATENCY64/JITTER64 below carry the exact
        // values on 4.15+. They were read as µs (#493).
        let delay_ticks = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        opts.delay_ns = u64::from(delay_ticks) << super::psched::PSCHED_SHIFT;
        opts.limit = u32::from_ne_bytes(data[4..8].try_into().unwrap());
        let loss_raw = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        opts.loss_percent = prob_to_percent(loss_raw);
        opts.gap = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let dup_raw = u32::from_ne_bytes(data[16..20].try_into().unwrap());
        opts.duplicate_percent = prob_to_percent(dup_raw);
        let jitter_ticks = u32::from_ne_bytes(data[20..24].try_into().unwrap());
        opts.jitter_ns = u64::from(jitter_ticks) << super::psched::PSCHED_SHIFT;
    }

    // Parse nested attributes after TcNetemQopt
    let mut input = if data.len() > TcNetemQopt::SIZE {
        &data[TcNetemQopt::SIZE..]
    } else {
        return opts;
    };

    // `netem_dump` puts RATE64 *before* RATE, whose u32 then reads
    // `u32::MAX`; read in order, a rate of 4 GB/s or more came back as
    // 4294967295 (#493). RATE64 wins whichever comes first.
    let mut rate64 = None;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            TCA_NETEM_CORR
                if payload.len() >= TcNetemCorr::SIZE => {
                    let delay_corr = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let loss_corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let dup_corr = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    opts.delay_corr = prob_to_percent(delay_corr);
                    opts.loss_corr = prob_to_percent(loss_corr);
                    opts.duplicate_corr = prob_to_percent(dup_corr);
                }
            TCA_NETEM_REORDER
                if payload.len() >= TcNetemReorder::SIZE => {
                    let prob = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.reorder_percent = prob_to_percent(prob);
                    opts.reorder_corr = prob_to_percent(corr);
                }
            TCA_NETEM_CORRUPT
                if payload.len() >= TcNetemCorrupt::SIZE => {
                    let prob = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let corr = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.corrupt_percent = prob_to_percent(prob);
                    opts.corrupt_corr = prob_to_percent(corr);
                }
            TCA_NETEM_RATE => {
                // TcNetemRate: rate (u32), packet_overhead (i32), cell_size (u32), cell_overhead (i32)
                if payload.len() >= 4 {
                    opts.rate = u32::from_ne_bytes(payload[0..4].try_into().unwrap()) as u64;
                }
                if payload.len() >= TcNetemRate::SIZE {
                    opts.packet_overhead = i32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    opts.cell_size = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    opts.cell_overhead = i32::from_ne_bytes(payload[12..16].try_into().unwrap());
                }
            }
            TCA_NETEM_RATE64
                if payload.len() >= 8 => {
                    rate64 = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
                }
            TCA_NETEM_ECN => {
                // A u32. The kernel dumps it only when set, but nlink sends
                // 0 to clear it, so read the value; a bare flag is "on".
                opts.ecn = payload
                    .get(..4)
                    .is_none_or(|b| u32::from_ne_bytes(b.try_into().unwrap()) != 0);
            }
            TCA_NETEM_LATENCY64
                // 64-bit latency in nanoseconds
                if payload.len() >= 8 => {
                    opts.delay_ns = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            TCA_NETEM_JITTER64
                // 64-bit jitter in nanoseconds
                if payload.len() >= 8 => {
                    opts.jitter_ns = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                }
            TCA_NETEM_SLOT
                // TcNetemSlot structure
                if payload.len() >= TcNetemSlot::SIZE => {
                    let slot = NetemSlotOptions {
                        min_delay_ns: i64::from_ne_bytes(payload[0..8].try_into().unwrap()),
                        max_delay_ns: i64::from_ne_bytes(payload[8..16].try_into().unwrap()),
                        max_packets: i32::from_ne_bytes(payload[16..20].try_into().unwrap()),
                        max_bytes: i32::from_ne_bytes(payload[20..24].try_into().unwrap()),
                        dist_delay_ns: i64::from_ne_bytes(payload[24..32].try_into().unwrap()),
                        dist_jitter_ns: i64::from_ne_bytes(payload[32..40].try_into().unwrap()),
                    };
                    // The kernel's own test for a slot that does anything
                    // (`get_slot`, `netem_dump`); the zero slot nlink sends
                    // to clear one is no slot (#493).
                    if slot.min_delay_ns | slot.max_delay_ns | slot.dist_jitter_ns != 0 {
                        opts.slot = Some(slot);
                    }
                }
            TCA_NETEM_LOSS => {
                // Loss model is a nested attribute containing the model type and parameters
                parse_netem_loss_model(payload, &mut opts);
            }
            TCA_NETEM_PRNG_SEED if payload.len() >= 8 => {
                opts.seed = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    if let Some(rate) = rate64 {
        opts.rate = rate;
    }
    opts
}

/// Parse TCA_NETEM_LOSS nested attribute for loss model.
fn parse_netem_loss_model(data: &[u8], opts: &mut NetemOptions) {
    use super::types::tc::qdisc::netem::*;

    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            NETEM_LOSS_GI
                // Gilbert-Intuitive 4-state model
                if payload.len() >= TcNetemGiModel::SIZE => {
                    let p13 = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let p31 = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let p32 = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    let p14 = u32::from_ne_bytes(payload[12..16].try_into().unwrap());
                    let p23 = u32::from_ne_bytes(payload[16..20].try_into().unwrap());
                    opts.loss_model = Some(NetemLossModel::GilbertIntuitive {
                        p13: prob_to_percent(p13),
                        p31: prob_to_percent(p31),
                        p32: prob_to_percent(p32),
                        p14: prob_to_percent(p14),
                        p23: prob_to_percent(p23),
                    });
                }
            NETEM_LOSS_GE
                // Gilbert-Elliot 2-state model
                if payload.len() >= TcNetemGeModel::SIZE => {
                    let p = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    let r = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
                    let h = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    let k1 = u32::from_ne_bytes(payload[12..16].try_into().unwrap());
                    opts.loss_model = Some(NetemLossModel::GilbertElliot {
                        p: prob_to_percent(p),
                        r: prob_to_percent(r),
                        h: prob_to_percent(h),
                        k1: prob_to_percent(k1),
                    });
                }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
}

fn parse_prio_options(data: &[u8]) -> PrioOptions {
    // TcPrioQopt: i32 bands + [u8; 16] priomap = 20 bytes
    if data.len() >= 20 {
        let bands = i32::from_ne_bytes(data[0..4].try_into().unwrap());
        let mut priomap = [0u8; 16];
        priomap.copy_from_slice(&data[4..20]);
        PrioOptions { bands, priomap }
    } else {
        PrioOptions::default()
    }
}

fn parse_fq_pie_options(data: &[u8]) -> FqPieOptions {
    use super::types::tc::qdisc::fq_pie::*;

    let mut opts = FqPieOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }
        let payload = &input[4..len];

        let read_u32 = |p: &[u8]| -> Option<u32> {
            p.get(..4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes)
        };

        match attr_type & 0x3FFF {
            TCA_FQ_PIE_LIMIT => {
                if let Some(v) = read_u32(payload) {
                    opts.limit = v;
                }
            }
            TCA_FQ_PIE_FLOWS => {
                if let Some(v) = read_u32(payload) {
                    opts.flows = v;
                }
            }
            TCA_FQ_PIE_TARGET => {
                if let Some(v) = read_u32(payload) {
                    opts.target_us = v;
                }
            }
            TCA_FQ_PIE_TUPDATE => {
                if let Some(v) = read_u32(payload) {
                    opts.tupdate_us = v;
                }
            }
            TCA_FQ_PIE_ALPHA => {
                if let Some(v) = read_u32(payload) {
                    opts.alpha = v;
                }
            }
            TCA_FQ_PIE_BETA => {
                if let Some(v) = read_u32(payload) {
                    opts.beta = v;
                }
            }
            TCA_FQ_PIE_QUANTUM => {
                if let Some(v) = read_u32(payload) {
                    opts.quantum = v;
                }
            }
            TCA_FQ_PIE_MEMORY_LIMIT => {
                if let Some(v) = read_u32(payload) {
                    opts.memory_limit = v;
                }
            }
            TCA_FQ_PIE_ECN_PROB => {
                if let Some(v) = read_u32(payload) {
                    opts.ecn_prob_percent = v;
                }
            }
            TCA_FQ_PIE_ECN => {
                if let Some(v) = read_u32(payload) {
                    opts.ecn = v != 0;
                }
            }
            TCA_FQ_PIE_BYTEMODE => {
                if let Some(v) = read_u32(payload) {
                    opts.bytemode = v != 0;
                }
            }
            TCA_FQ_PIE_DQ_RATE_ESTIMATOR => {
                if let Some(v) = read_u32(payload) {
                    opts.dq_rate_estimator = v != 0;
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_cake_options(data: &[u8]) -> CakeOptions {
    use super::types::tc::qdisc::cake::*;

    let mut opts = CakeOptions::default();
    let mut input = data;

    while input.len() >= 4 {
        let Some(len) = input
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };
        let len = len as usize;
        let Some(attr_type) = input
            .get(2..4)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            break;
        };

        if len < 4 || input.len() < len {
            break;
        }
        let payload = &input[4..len];

        let read_u32 = |p: &[u8]| -> Option<u32> {
            p.get(..4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes)
        };
        let read_i32 = |p: &[u8]| -> Option<i32> {
            p.get(..4)
                .and_then(|b| b.try_into().ok())
                .map(i32::from_ne_bytes)
        };
        let read_u64 = |p: &[u8]| -> Option<u64> {
            p.get(..8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_ne_bytes)
        };

        match attr_type & 0x3FFF {
            TCA_CAKE_BASE_RATE64 => {
                if let Some(v) = read_u64(payload) {
                    opts.bandwidth_bps = v;
                }
            }
            TCA_CAKE_RTT => {
                if let Some(v) = read_u32(payload) {
                    opts.rtt_us = v;
                }
            }
            TCA_CAKE_TARGET => {
                if let Some(v) = read_u32(payload) {
                    opts.target_us = v;
                }
            }
            TCA_CAKE_OVERHEAD => {
                if let Some(v) = read_i32(payload) {
                    opts.overhead = v;
                }
            }
            TCA_CAKE_MPU => {
                if let Some(v) = read_u32(payload) {
                    opts.mpu = v;
                }
            }
            TCA_CAKE_MEMORY => {
                if let Some(v) = read_u32(payload) {
                    opts.memory_limit = v;
                }
            }
            TCA_CAKE_FWMARK => {
                if let Some(v) = read_u32(payload) {
                    opts.fwmark = v;
                }
            }
            TCA_CAKE_DIFFSERV_MODE => {
                if let Some(v) = read_u32(payload) {
                    opts.diffserv_mode = v;
                }
            }
            TCA_CAKE_FLOW_MODE => {
                if let Some(v) = read_u32(payload) {
                    opts.flow_mode = v;
                }
            }
            TCA_CAKE_ATM => {
                if let Some(v) = read_u32(payload) {
                    opts.atm_mode = v;
                }
            }
            TCA_CAKE_ACK_FILTER => {
                if let Some(v) = read_u32(payload) {
                    opts.ack_filter = v;
                }
            }
            TCA_CAKE_AUTORATE => {
                if let Some(v) = read_u32(payload) {
                    opts.autorate = v != 0;
                }
            }
            TCA_CAKE_NAT => {
                if let Some(v) = read_u32(payload) {
                    opts.nat = v != 0;
                }
            }
            // Raw mode is the attribute's presence: `cake_dump` puts it with
            // the value 0 (#635).
            TCA_CAKE_RAW => opts.raw = true,
            TCA_CAKE_WASH => {
                if let Some(v) = read_u32(payload) {
                    opts.wash = v != 0;
                }
            }
            TCA_CAKE_INGRESS => {
                if let Some(v) = read_u32(payload) {
                    opts.ingress = v != 0;
                }
            }
            TCA_CAKE_SPLIT_GSO => {
                if let Some(v) = read_u32(payload) {
                    opts.split_gso = v != 0;
                }
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    opts
}

fn parse_sfq_options(data: &[u8]) -> SfqOptions {
    // TcSfqQopt: quantum (4), perturb_period (4), limit (4), divisor (4), flows (4) = 20 bytes
    if data.len() >= 20 {
        let quantum = u32::from_ne_bytes(data[0..4].try_into().unwrap());
        let perturb_period = i32::from_ne_bytes(data[4..8].try_into().unwrap());
        let limit = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let divisor = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let flows = u32::from_ne_bytes(data[16..20].try_into().unwrap());

        let mut opts = SfqOptions {
            quantum,
            perturb_period,
            limit,
            divisor,
            flows,
            ..Default::default()
        };

        // Check for extended SFQ options (TcSfqQoptV1)
        if data.len() >= 32 {
            opts.depth = Some(u32::from_ne_bytes(data[20..24].try_into().unwrap()));
            let headdrop = u32::from_ne_bytes(data[24..28].try_into().unwrap());
            opts.headdrop = Some(headdrop != 0);
        }

        opts
    } else {
        SfqOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fq_codel_defaults() {
        let opts = FqCodelOptions::default();
        assert_eq!(opts.target_us, 0);
        assert_eq!(opts.interval_us, 0);
        assert!(!opts.ecn);
    }

    #[test]
    fn test_prio_defaults() {
        let opts = PrioOptions::default();
        assert_eq!(opts.bands, 3);
        assert_eq!(opts.priomap[0], 1);
        assert_eq!(opts.priomap[6], 0);
    }

    #[test]
    fn test_netem_defaults() {
        let opts = NetemOptions::default();
        assert_eq!(opts.delay_ns, 0);
        assert!(opts.delay().is_none());
        assert_eq!(opts.jitter_ns, 0);
        assert!(opts.jitter().is_none());
        assert!(opts.loss().is_none());
        assert!(opts.duplicate().is_none());
        assert!(opts.reorder().is_none());
        assert!(opts.corrupt().is_none());
        assert!(opts.rate_bps().is_none());
        assert_eq!(opts.limit, 0);
        assert_eq!(opts.gap, 0);
        assert!(!opts.ecn);
        assert!(opts.slot.is_none());
    }

    #[test]
    fn test_netem_delay() {
        let mut opts = NetemOptions::default();
        assert!(opts.delay().is_none());

        opts.delay_ns = 100_000_000; // 100ms
        assert_eq!(opts.delay(), Some(std::time::Duration::from_millis(100)));
    }

    #[test]
    fn test_netem_jitter() {
        let mut opts = NetemOptions::default();
        assert!(opts.jitter().is_none());

        opts.jitter_ns = 10_000_000; // 10ms
        assert_eq!(opts.jitter(), Some(std::time::Duration::from_millis(10)));
    }

    #[test]
    fn test_netem_loss() {
        let mut opts = NetemOptions::default();
        assert!(opts.loss().is_none());

        // Test with loss_percent
        opts.loss_percent = 1.0;
        assert_eq!(opts.loss(), Some(1.0));

        // Test with loss_model
        opts.loss_percent = 0.0;
        opts.loss_model = Some(NetemLossModel::GilbertElliot {
            p: 1.0,
            r: 10.0,
            h: 50.0,
            k1: 0.0,
        });
        assert!(opts.loss().is_some());
    }

    #[test]
    fn test_netem_duplicate() {
        let mut opts = NetemOptions::default();
        assert!(opts.duplicate().is_none());

        opts.duplicate_percent = 0.5;
        assert_eq!(opts.duplicate(), Some(0.5));
    }

    #[test]
    fn test_netem_reorder() {
        let mut opts = NetemOptions::default();
        assert!(opts.reorder().is_none());

        // Test with reorder_percent
        opts.reorder_percent = 5.0;
        assert_eq!(opts.reorder(), Some(5.0));

        // Test with gap only
        opts.reorder_percent = 0.0;
        opts.gap = 5;
        assert_eq!(opts.reorder(), Some(0.0));
    }

    #[test]
    fn test_netem_corrupt() {
        let mut opts = NetemOptions::default();
        assert!(opts.corrupt().is_none());

        opts.corrupt_percent = 0.1;
        assert_eq!(opts.corrupt(), Some(0.1));
    }

    #[test]
    fn test_netem_rate_bps() {
        let mut opts = NetemOptions::default();
        assert!(opts.rate_bps().is_none());

        opts.rate = 1_000_000;
        assert_eq!(opts.rate_bps(), Some(1_000_000));
    }

    #[test]
    fn test_netem_configured_parameters() {
        let opts = NetemOptions::default();
        assert!(opts.configured_parameters().is_empty());

        let opts = NetemOptions {
            delay_ns: 100_000_000,
            jitter_ns: 10_000_000,
            loss_percent: 1.0,
            rate: 1_000_000,
            ..Default::default()
        };

        let params = opts.configured_parameters();
        assert_eq!(params.len(), 4);
        assert!(params.contains(&NetemParameter::Delay));
        assert!(params.contains(&NetemParameter::Jitter));
        assert!(params.contains(&NetemParameter::Loss));
        assert!(params.contains(&NetemParameter::Rate));
        assert!(!params.contains(&NetemParameter::Duplicate));
        assert!(!params.contains(&NetemParameter::Reorder));
        assert!(!params.contains(&NetemParameter::Corrupt));
    }

    /// #493: `netem_dump` sends RATE64 first, then RATE carrying `~0U`.
    /// Read in order, a 5 GB/s rate came back as 4294967295.
    #[test]
    fn netem_rate64_wins_over_the_capped_rate_after_it() {
        use super::super::types::tc::qdisc::netem::*;
        let mut data = TcNetemQopt::new().as_bytes().to_vec();
        let mut rate64 = Vec::new();
        rate64.extend_from_slice(&12u16.to_ne_bytes());
        rate64.extend_from_slice(&TCA_NETEM_RATE64.to_ne_bytes());
        rate64.extend_from_slice(&5_000_000_000u64.to_ne_bytes());
        data.extend(rate64);
        let capped = TcNetemRate {
            rate: u32::MAX,
            ..Default::default()
        };
        data.extend_from_slice(&(4 + TcNetemRate::SIZE as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE.to_ne_bytes());
        data.extend_from_slice(capped.as_bytes());

        assert_eq!(parse_netem_options(&data).rate, 5_000_000_000);
    }

    /// #493: with no LATENCY64 (pre-4.15), the delay is `qopt.latency`, in
    /// 64 ns psched ticks. It was read as µs, 15.6 times too long.
    #[test]
    fn netem_qopt_latency_is_in_psched_ticks() {
        use std::time::Duration;

        use super::super::types::tc::qdisc::netem::*;
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 1_562_500;
        let opts = parse_netem_options(qopt.as_bytes());
        assert_eq!(opts.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_netem_parse_basic() {
        use std::time::Duration;

        use super::super::types::tc::qdisc::netem::*;

        // Build TcNetemQopt with 100ms delay, 1000 packet limit, 1% loss
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 1_562_500; // 100ms in 64 ns psched ticks
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(1.0); // 1% loss
        qopt.gap = 0;
        qopt.duplicate = 0;
        qopt.jitter = 156_250; // 10ms jitter, in ticks

        let data = qopt.as_bytes().to_vec();
        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay(), Some(Duration::from_millis(100)));
        assert_eq!(opts.jitter(), Some(Duration::from_millis(10)));
        assert_eq!(opts.limit, 1000);
        assert!((opts.loss_percent - 1.0).abs() < 0.01);
        assert_eq!(opts.duplicate_percent, 0.0);
        assert_eq!(opts.gap, 0);
    }

    #[test]
    fn test_netem_parse_with_correlation() {
        use std::time::Duration;

        use super::super::types::tc::qdisc::netem::*;

        // Build base options
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 781_250; // 50ms, in ticks
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(5.0); // 5% loss
        qopt.duplicate = percent_to_prob(2.0); // 2% duplicate
        qopt.jitter = 78_125; // 5ms jitter, in ticks

        // Build correlation attributes
        let corr = TcNetemCorr {
            delay_corr: percent_to_prob(25.0),
            loss_corr: percent_to_prob(50.0),
            dup_corr: percent_to_prob(10.0),
        };

        // Construct full data with nested attribute
        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_CORR attribute (type 1)
        let corr_bytes = corr.as_bytes();
        let attr_len = 4 + corr_bytes.len(); // header + payload
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORR.to_ne_bytes());
        data.extend_from_slice(corr_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay(), Some(Duration::from_micros(50_000)));
        assert_eq!(opts.jitter(), Some(Duration::from_micros(5_000)));
        assert!((opts.loss_percent - 5.0).abs() < 0.1);
        assert!((opts.duplicate_percent - 2.0).abs() < 0.1);
        assert!((opts.delay_corr - 25.0).abs() < 0.1);
        assert!((opts.loss_corr - 50.0).abs() < 0.1);
        assert!((opts.duplicate_corr - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_reorder() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 1_562_500; // 100ms, in ticks
        qopt.limit = 1000;
        qopt.gap = 5; // reorder gap

        let reorder = TcNetemReorder {
            probability: percent_to_prob(10.0),
            correlation: percent_to_prob(25.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_REORDER attribute (type 3)
        let reorder_bytes = reorder.as_bytes();
        let attr_len = 4 + reorder_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_REORDER.to_ne_bytes());
        data.extend_from_slice(reorder_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.gap, 5);
        assert!((opts.reorder_percent - 10.0).abs() < 0.1);
        assert!((opts.reorder_corr - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_corrupt() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 0;
        qopt.limit = 1000;

        let corrupt = TcNetemCorrupt {
            probability: percent_to_prob(0.5),
            correlation: percent_to_prob(10.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_CORRUPT attribute (type 4)
        let corrupt_bytes = corrupt.as_bytes();
        let attr_len = 4 + corrupt_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORRUPT.to_ne_bytes());
        data.extend_from_slice(corrupt_bytes);

        let opts = parse_netem_options(&data);

        assert!((opts.corrupt_percent - 0.5).abs() < 0.1);
        assert!((opts.corrupt_corr - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_rate() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let rate = TcNetemRate {
            rate: 1_000_000, // 1 MB/s
            ..Default::default()
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_RATE attribute (type 6)
        let rate_bytes = rate.as_bytes();
        let attr_len = 4 + rate_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE.to_ne_bytes());
        data.extend_from_slice(rate_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 1_000_000);
    }

    #[test]
    fn test_netem_parse_with_rate64() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Use a rate larger than u32::MAX
        let rate64: u64 = 10_000_000_000; // 10 GB/s

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_RATE64 attribute (type 8)
        let attr_len = 4 + 8; // header + u64
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE64.to_ne_bytes());
        data.extend_from_slice(&rate64.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 10_000_000_000);
    }

    #[test]
    fn test_netem_parse_multiple_attrs() {
        use std::time::Duration;

        use super::super::types::tc::qdisc::netem::*;

        // Build a complete netem config with multiple attributes
        let mut qopt = TcNetemQopt::new();
        qopt.latency = 1_562_500; // 100ms, in ticks
        qopt.limit = 1000;
        qopt.loss = percent_to_prob(1.0);
        qopt.jitter = 156_250; // 10ms, in ticks

        let corr = TcNetemCorr {
            delay_corr: percent_to_prob(25.0),
            loss_corr: percent_to_prob(50.0),
            ..Default::default()
        };

        let corrupt = TcNetemCorrupt {
            probability: percent_to_prob(0.1),
            ..Default::default()
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add correlation (with padding to 4-byte alignment)
        let corr_bytes = corr.as_bytes();
        let attr_len = 4 + corr_bytes.len();
        let aligned_len = (attr_len + 3) & !3;
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORR.to_ne_bytes());
        data.extend_from_slice(corr_bytes);
        // Add padding if needed
        data.resize(data.len() + aligned_len - attr_len, 0);

        // Add corruption
        let corrupt_bytes = corrupt.as_bytes();
        let attr_len = 4 + corrupt_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_CORRUPT.to_ne_bytes());
        data.extend_from_slice(corrupt_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay(), Some(Duration::from_millis(100)));
        assert_eq!(opts.jitter(), Some(Duration::from_millis(10)));
        assert!((opts.loss_percent - 1.0).abs() < 0.1);
        assert!((opts.delay_corr - 25.0).abs() < 0.1);
        assert!((opts.loss_corr - 50.0).abs() < 0.1);
        assert!((opts.corrupt_percent - 0.1).abs() < 0.1);
    }

    #[test]
    fn test_netem_parse_with_64bit_delay() {
        use std::time::Duration;

        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.latency = 100_000; // Will be overridden by 64-bit value
        qopt.limit = 1000;

        // 5 seconds in nanoseconds (exceeds u32 microseconds)
        let delay64_ns: u64 = 5_000_000_000;
        let jitter64_ns: u64 = 500_000_000; // 0.5 seconds

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_LATENCY64 attribute
        let attr_len = 4 + 8;
        let aligned_len = (attr_len + 3) & !3;
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LATENCY64.to_ne_bytes());
        data.extend_from_slice(&delay64_ns.to_ne_bytes());
        data.resize(data.len() + aligned_len - attr_len, 0);

        // Add TCA_NETEM_JITTER64 attribute
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_JITTER64.to_ne_bytes());
        data.extend_from_slice(&jitter64_ns.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert_eq!(opts.delay_ns, 5_000_000_000);
        assert_eq!(opts.jitter_ns, 500_000_000);
        assert_eq!(opts.delay(), Some(Duration::from_secs(5)));
        assert_eq!(opts.jitter(), Some(Duration::from_millis(500)));
    }

    #[test]
    fn test_netem_parse_with_ecn() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_ECN attribute (flag, just presence matters)
        let attr_len = 4 + 4; // header + u32 (some kernels send a value)
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_ECN.to_ne_bytes());
        data.extend_from_slice(&1u32.to_ne_bytes());

        let opts = parse_netem_options(&data);

        assert!(opts.ecn);
    }

    #[test]
    fn test_netem_parse_with_slot() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let slot = TcNetemSlot {
            min_delay: 1_000_000,  // 1ms in ns
            max_delay: 10_000_000, // 10ms in ns
            max_packets: 10,
            max_bytes: 15000,
            dist_delay: 0,
            dist_jitter: 0,
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_SLOT attribute
        let slot_bytes = slot.as_bytes();
        let attr_len = 4 + slot_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_SLOT.to_ne_bytes());
        data.extend_from_slice(slot_bytes);

        let opts = parse_netem_options(&data);

        assert!(opts.slot.is_some());
        let slot_opts = opts.slot.unwrap();
        assert_eq!(slot_opts.min_delay_ns, 1_000_000);
        assert_eq!(slot_opts.max_delay_ns, 10_000_000);
        assert_eq!(slot_opts.max_packets, 10);
        assert_eq!(slot_opts.max_bytes, 15000);
    }

    #[test]
    fn test_netem_parse_with_rate_overhead() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        let rate = TcNetemRate {
            rate: 1_000_000,     // 1 MB/s
            packet_overhead: 14, // Ethernet header
            cell_size: 53,       // ATM cell size
            cell_overhead: 5,    // ATM cell overhead
        };

        let mut data = qopt.as_bytes().to_vec();

        let rate_bytes = rate.as_bytes();
        let attr_len = 4 + rate_bytes.len();
        data.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_RATE.to_ne_bytes());
        data.extend_from_slice(rate_bytes);

        let opts = parse_netem_options(&data);

        assert_eq!(opts.rate, 1_000_000);
        assert_eq!(opts.packet_overhead, 14);
        assert_eq!(opts.cell_size, 53);
        assert_eq!(opts.cell_overhead, 5);
    }

    #[test]
    fn test_netem_prob_conversion_roundtrip() {
        use super::super::types::tc::qdisc::netem::*;

        // Test that percent -> prob -> percent roundtrips correctly
        let test_values = [0.0, 0.1, 1.0, 10.0, 50.0, 99.9, 100.0];

        for &percent in &test_values {
            let prob = percent_to_prob(percent);
            let back = prob_to_percent(prob);
            assert!(
                (percent - back).abs() < 0.01,
                "Roundtrip failed for {}: got {}",
                percent,
                back
            );
        }
    }

    #[test]
    fn test_netem_parse_with_loss_model_gi() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Gilbert-Intuitive model
        let gi_model = TcNetemGiModel {
            p13: percent_to_prob(5.0),
            p31: percent_to_prob(95.0),
            p32: percent_to_prob(3.0),
            p14: percent_to_prob(1.0),
            p23: percent_to_prob(10.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Add TCA_NETEM_LOSS attribute (nested)
        // First the outer TCA_NETEM_LOSS, then nested NETEM_LOSS_GI
        let gi_bytes = gi_model.as_bytes();
        let inner_len = 4 + gi_bytes.len();
        let inner_aligned = (inner_len + 3) & !3;

        // Build nested attribute
        let mut nested = Vec::new();
        nested.extend_from_slice(&(inner_len as u16).to_ne_bytes());
        nested.extend_from_slice(&NETEM_LOSS_GI.to_ne_bytes());
        nested.extend_from_slice(gi_bytes);
        nested.resize(nested.len() + inner_aligned - inner_len, 0);

        let outer_len = 4 + nested.len();
        data.extend_from_slice(&(outer_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LOSS.to_ne_bytes());
        data.extend_from_slice(&nested);

        let opts = parse_netem_options(&data);

        assert!(opts.loss_model.is_some());
        match opts.loss_model.unwrap() {
            NetemLossModel::GilbertIntuitive {
                p13,
                p31,
                p32,
                p14,
                p23,
            } => {
                assert!((p13 - 5.0).abs() < 0.1);
                assert!((p31 - 95.0).abs() < 0.1);
                assert!((p32 - 3.0).abs() < 0.1);
                assert!((p14 - 1.0).abs() < 0.1);
                assert!((p23 - 10.0).abs() < 0.1);
            }
            _ => panic!("Expected GilbertIntuitive model"),
        }
    }

    #[test]
    fn test_netem_parse_with_loss_model_ge() {
        use super::super::types::tc::qdisc::netem::*;

        let mut qopt = TcNetemQopt::new();
        qopt.limit = 1000;

        // Gilbert-Elliot model
        let ge_model = TcNetemGeModel {
            p: percent_to_prob(1.0),
            r: percent_to_prob(10.0),
            h: percent_to_prob(50.0),
            k1: percent_to_prob(0.0),
        };

        let mut data = qopt.as_bytes().to_vec();

        // Build nested attribute
        let ge_bytes = ge_model.as_bytes();
        let inner_len = 4 + ge_bytes.len();
        let inner_aligned = (inner_len + 3) & !3;

        let mut nested = Vec::new();
        nested.extend_from_slice(&(inner_len as u16).to_ne_bytes());
        nested.extend_from_slice(&NETEM_LOSS_GE.to_ne_bytes());
        nested.extend_from_slice(ge_bytes);
        nested.resize(nested.len() + inner_aligned - inner_len, 0);

        let outer_len = 4 + nested.len();
        data.extend_from_slice(&(outer_len as u16).to_ne_bytes());
        data.extend_from_slice(&TCA_NETEM_LOSS.to_ne_bytes());
        data.extend_from_slice(&nested);

        let opts = parse_netem_options(&data);

        assert!(opts.loss_model.is_some());
        match opts.loss_model.unwrap() {
            NetemLossModel::GilbertElliot { p, r, h, k1 } => {
                assert!((p - 1.0).abs() < 0.1);
                assert!((r - 10.0).abs() < 0.1);
                assert!((h - 50.0).abs() < 0.1);
                assert!((k1 - 0.0).abs() < 0.1);
            }
            _ => panic!("Expected GilbertElliot model"),
        }
    }

    /// #370: a replace now clears every parameter NetemConfig models, so
    /// removing any of them — or a loss model — needs no recreation.
    #[test]
    fn test_requires_recreation_not_needed_for_modelled_parameters() {
        use super::super::tc::NetemConfig;

        let current = NetemOptions {
            delay_ns: 100_000_000,
            jitter_ns: 10_000_000,
            loss_percent: 1.0,
            duplicate_percent: 1.0,
            reorder_percent: 3.0,
            corrupt_percent: 1.0,
            rate: 1_000_000,
            gap: 5,
            loss_model: Some(NetemLossModel::GilbertElliot {
                p: 1.0,
                r: 10.0,
                h: 50.0,
                k1: 0.0,
            }),
            ..Default::default()
        };
        assert!(!current.requires_recreation_for(&NetemConfig::new().build()));
    }

    /// What NetemConfig cannot express, a replace cannot clear.
    #[test]
    fn test_requires_recreation_for_slot_and_ecn() {
        use super::super::tc::NetemConfig;

        let bare = NetemConfig::new().build();
        let slot = NetemOptions {
            slot: Some(NetemSlotOptions::default()),
            ..Default::default()
        };
        assert!(slot.requires_recreation_for(&bare));
        let ecn = NetemOptions {
            ecn: true,
            ..Default::default()
        };
        assert!(ecn.requires_recreation_for(&bare));
        assert!(!NetemOptions::default().requires_recreation_for(&bare));
    }

    #[test]
    fn test_fq_pie_options_default() {
        let opts = FqPieOptions::default();
        assert_eq!(opts.limit, 0);
        assert_eq!(opts.flows, 0);
        assert!(opts.target().is_none());
        assert!(opts.tupdate().is_none());
        assert!(opts.ecn_prob().is_none());
        assert!(!opts.ecn);
    }

    #[test]
    fn test_fq_pie_options_target_accessor() {
        let opts = FqPieOptions {
            target_us: 15_000,
            ..Default::default()
        };
        assert_eq!(opts.target(), Some(std::time::Duration::from_millis(15)));
    }

    #[test]
    fn test_fq_pie_options_ecn_prob_accessor() {
        let opts = FqPieOptions {
            ecn_prob_percent: 20,
            ..Default::default()
        };
        let p = opts.ecn_prob().unwrap();
        assert!((p.as_percent() - 20.0).abs() < 1e-6);
    }

    #[test]
    fn test_fq_pie_round_trip_via_writer() {
        use std::time::Duration;

        use super::super::tc::FqPieConfig;
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::tc::QdiscConfig;

        let cfg = FqPieConfig::new()
            .limit(crate::util::Packets::new(10240))
            .flows(2048)
            .target(Duration::from_millis(15))
            .tupdate(Duration::from_millis(20))
            .alpha(2)
            .beta(20)
            .ecn(true)
            .build();

        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).unwrap();
        let end = builder.len();
        let blob = builder.as_bytes()[start..end].to_vec();

        let opts = parse_fq_pie_options(&blob);
        assert_eq!(opts.limit, 10240);
        assert_eq!(opts.flows, 2048);
        assert_eq!(opts.target_us, 15_000);
        assert_eq!(opts.tupdate_us, 20_000);
        assert_eq!(opts.alpha, 2);
        assert_eq!(opts.beta, 20);
        assert!(opts.ecn);
    }

    /// #635: `cake_dump` signals raw mode by `TCA_CAKE_RAW`'s presence,
    /// with the value 0.
    #[test]
    fn cake_raw_is_the_attributes_presence() {
        use super::super::types::tc::qdisc::cake::TCA_CAKE_RAW;
        let mut blob = Vec::new();
        blob.extend_from_slice(&8u16.to_ne_bytes());
        blob.extend_from_slice(&TCA_CAKE_RAW.to_ne_bytes());
        blob.extend_from_slice(&0u32.to_ne_bytes());
        assert!(parse_cake_options(&blob).raw);
        assert!(!parse_cake_options(&[]).raw);
    }

    #[test]
    fn test_cake_options_default() {
        let opts = CakeOptions::default();
        assert!(opts.bandwidth().is_none());
        assert!(opts.rtt().is_none());
        assert!(opts.target().is_none());
        assert_eq!(opts.diffserv_mode, 0);
        assert!(!opts.nat);
    }

    #[test]
    fn test_cake_options_bandwidth_accessor() {
        use crate::util::Rate;
        let opts = CakeOptions {
            bandwidth_bps: 12_500_000, // 100 Mbps
            ..Default::default()
        };
        assert_eq!(opts.bandwidth(), Some(Rate::mbit(100)));
    }

    #[test]
    fn test_cake_round_trip_via_writer() {
        use std::time::Duration;

        use super::super::tc::{CakeConfig, CakeDiffserv, CakeFlowMode};
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::tc::QdiscConfig;
        use crate::util::Rate;

        let cfg = CakeConfig::new()
            .bandwidth(Rate::mbit(100))
            .rtt(Duration::from_millis(80))
            .target(Duration::from_millis(5))
            .flow_mode(CakeFlowMode::Triple)
            .diffserv_mode(CakeDiffserv::Diffserv4)
            .nat(true)
            .wash(true)
            .build();

        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).unwrap();
        let end = builder.len();
        let blob = builder.as_bytes()[start..end].to_vec();

        let opts = parse_cake_options(&blob);
        assert_eq!(opts.bandwidth_bps, 12_500_000);
        assert_eq!(opts.rtt_us, 80_000);
        assert_eq!(opts.target_us, 5_000);
        assert_eq!(
            opts.flow_mode,
            super::super::types::tc::qdisc::cake::CAKE_FLOW_TRIPLE,
        );
        assert_eq!(
            opts.diffserv_mode,
            super::super::types::tc::qdisc::cake::CAKE_DIFFSERV_DIFFSERV4,
        );
        assert!(opts.nat);
        assert!(opts.wash);
        // Round-trip Rate accessor.
        assert_eq!(opts.bandwidth(), Some(Rate::mbit(100)));
    }

    #[test]
    fn test_cake_unlimited_writes_zero_rate() {
        use super::super::tc::CakeConfig;
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::tc::QdiscConfig;

        let cfg = CakeConfig::new().unlimited().build();
        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).unwrap();
        let blob = builder.as_bytes()[start..].to_vec();

        let opts = parse_cake_options(&blob);
        assert_eq!(opts.bandwidth_bps, 0);
        assert!(opts.bandwidth().is_none());
    }
}
