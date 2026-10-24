//! One qdisc spec for both paths (#515).
//!
//! [`QdiscSpec`] holds the imperative configs themselves — a netem is a
//! [`NetemConfig`], a TBF a [`TbfConfig`] — so the declarative
//! [`NetworkConfig`](crate::netlink::config::NetworkConfig) and the
//! imperative `Connection` take the same type, with the same defaults and
//! the same bugs fixed once. Before 0.32 the declarative side had its own
//! `DeclaredQdiscType`, with its own field types, a lowering per kind, and
//! its own comparison, and fixes reached one side or the other (#361 fixed
//! fq_codel's `flows` on one).
//!
//! A spec installs like any config (`conn.add_qdisc(dev, spec)`), says
//! whether a live qdisc already is it ([`QdiscSpec::matches`]), and checks
//! itself without a kernel ([`QdiscSpec::validate`]). With the `serde`
//! feature it reads and writes in the units tc(8) writes: `"10ms"`,
//! `"100mbit"`, `"1.5%"`, `"32kib"`.

use std::time::Duration;

use super::{
    builder::MessageBuilder,
    error::{Error, Result},
    messages::TcMessage,
    psched,
    tc::{
        ClsactConfig, DrrConfig, FqCodelConfig, HfscConfig, HtbQdiscConfig, InPlace,
        IngressConfig, NetemConfig, PrioConfig, QdiscConfig, QfqConfig, SfqConfig, TbfConfig,
    },
    tc_handle::TcHandle,
};

/// A qdisc, for the declarative and the imperative path alike (#515).
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use std::time::Duration;
/// use nlink::netlink::{config::NetworkConfig, tc::NetemConfig, tc_spec::QdiscSpec};
///
/// let spec = QdiscSpec::from(NetemConfig::new().delay(Duration::from_millis(10)).seed(7));
/// conn.replace_qdisc("eth0", spec.clone()).await?;
/// let config = NetworkConfig::new().qdisc("eth0", |q| q.spec(spec));
/// # let _ = config;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum QdiscSpec {
    /// netem.
    Netem(NetemConfig),
    /// HTB.
    Htb(HtbQdiscConfig),
    /// fq_codel.
    FqCodel(FqCodelConfig),
    /// TBF.
    Tbf(TbfConfig),
    /// sfq.
    Sfq(SfqConfig),
    /// prio.
    Prio(PrioConfig),
    /// HFSC: its classes are declared with
    /// [`NetworkConfig::tc`](crate::netlink::config::NetworkConfig::tc).
    Hfsc(HfscConfig),
    /// DRR, which has no parameters of its own.
    Drr(DrrConfig),
    /// QFQ, which has no parameters of its own.
    Qfq(QfqConfig),
    /// The ingress hook.
    Ingress,
    /// The clsact hooks.
    Clsact,
    /// The kernel's own root qdisc: declared, the installed root is
    /// deleted and the kernel puts its default back (#514). Not something
    /// to install.
    KernelDefault,
}

macro_rules! from_config {
    ($($cfg:ident => $variant:ident),*) => {$(
        impl From<$cfg> for QdiscSpec {
            fn from(cfg: $cfg) -> Self {
                Self::$variant(cfg)
            }
        }
    )*};
}
from_config!(
    NetemConfig => Netem,
    HtbQdiscConfig => Htb,
    FqCodelConfig => FqCodel,
    TbfConfig => Tbf,
    SfqConfig => Sfq,
    PrioConfig => Prio,
    HfscConfig => Hfsc,
    DrrConfig => Drr,
    QfqConfig => Qfq
);

/// A live HFSC qdisc's default class: `hfsc_dump_qdisc()` reports its
/// `tc_hfsc_qopt` as the bare `TCA_OPTIONS` payload.
fn hfsc_defcls(live: &TcMessage) -> Option<u16> {
    let b = live.raw_options()?.get(..2)?;
    Some(u16::from_ne_bytes([b[0], b[1]]))
}

/// fq_codel's smallest quantum: `fq_codel_change()` stores
/// `max(256, quantum)`.
const FQ_CODEL_MIN_QUANTUM: u32 = 256;

/// sfq's defaults and caps (`sch_sfq.c`): `SFQ_DEFAULT_FLOWS`,
/// `SFQ_MAX_DEPTH` (the default depth too) and `SFQ_MAX_FLOWS`.
const SFQ_DEFAULT_FLOWS: u32 = 128;
const SFQ_MAX_DEPTH: u32 = 127;
const SFQ_MAX_FLOWS: u32 = 0x10000 - SFQ_MAX_DEPTH - 1;

/// A live TBF's overhead, mpu and link layer (#806), from its rate; `None`
/// when its peak rate has others, which no `TbfConfig` sends (#783).
fn tbf_framing(live: &TcMessage) -> Option<(u16, u16, psched::LinkLayer)> {
    use crate::netlink::types::tc::qdisc::tbf::{TCA_TBF_PARMS, TcTbfQopt};
    use zerocopy::FromBytes;
    let (q, _) = crate::netlink::attr::AttrIter::new(live.raw_options().unwrap_or(&[]))
        .find(|(t, _)| t & 0x7FFF == TCA_TBF_PARMS)
        .and_then(|(_, p)| TcTbfQopt::read_from_prefix(p).ok())?;
    let layer = |r: &crate::netlink::types::tc::qdisc::TcRateSpec| match r.linklayer & 0x0F {
        0 => Some(psched::LinkLayer::Unaware),
        1 => Some(psched::LinkLayer::Ethernet),
        2 => Some(psched::LinkLayer::Atm),
        _ => None,
    };
    let framing = (q.rate.overhead, q.rate.mpu, layer(&q.rate)?);
    let peak_agrees = q.peakrate.rate == 0
        || (q.peakrate.overhead, q.peakrate.mpu, layer(&q.peakrate)) == (framing.0, framing.1, Some(framing.2));
    peak_agrees.then_some(framing)
}

impl QdiscSpec {
    /// The config to install, or `None` for the kernel default.
    fn config(&self) -> Option<&dyn QdiscConfig> {
        match self {
            Self::Netem(c) => Some(c),
            Self::Htb(c) => Some(c),
            Self::FqCodel(c) => Some(c),
            Self::Tbf(c) => Some(c),
            Self::Sfq(c) => Some(c),
            Self::Prio(c) => Some(c),
            Self::Hfsc(c) => Some(c),
            Self::Drr(c) => Some(c),
            Self::Qfq(c) => Some(c),
            Self::Ingress => Some(&IngressConfig),
            Self::Clsact => Some(&ClsactConfig),
            Self::KernelDefault => None,
        }
    }

    /// The kind: `"netem"`, `"htb"`, …, and `"default"` for the kernel's
    /// default.
    pub fn kind(&self) -> &'static str {
        self.config().map_or("default", |c| c.kind())
    }

    /// The spec a live qdisc is, for putting it back (#649): the kinds
    /// [`matches`](Self::matches) reads, from their parsed options, and the
    /// kernel's default root. `None` for another kind; the spec read back
    /// [`matches`](Self::matches) the qdisc it came from.
    ///
    /// `None` too for a TBF whose peak rate is framed unlike its rate,
    /// which no `TbfConfig` sends (#783). An sfq's divisor, flows, depth
    /// and head drop, an fq_codel's drop batch and CE selector, and a TBF's
    /// overhead, mpu and link layer are their specs' (#806).
    pub(crate) fn from_live(live: &TcMessage) -> Option<Self> {
        use crate::netlink::tc_options::QdiscOptions as O;
        use crate::util::{Bytes, Packets, Rate};
        if live.handle().as_raw() == 0 {
            return Some(Self::KernelDefault);
        }
        let us = |v: u32| Duration::from_micros(u64::from(v));
        Some(match (live.kind()?, live.options()) {
            ("ingress", _) => Self::Ingress,
            ("clsact", _) => Self::Clsact,
            ("hfsc", _) => Self::Hfsc(HfscConfig::new().default_class(hfsc_defcls(live)?)),
            ("drr", _) => Self::Drr(DrrConfig::new()),
            ("qfq", _) => Self::Qfq(QfqConfig::new()),
            (_, Some(O::Netem(o))) => Self::Netem(NetemConfig::from(&o)),
            (_, Some(O::FqCodel(o))) => {
                Self::FqCodel(FqCodelConfig {
                target: Some(us(o.target_us)),
                interval: Some(us(o.interval_us)),
                limit: Some(Packets::new(o.limit)),
                flows: Some(o.flows),
                quantum: Some(o.quantum),
                ecn: Some(o.ecn),
                ce_threshold: o.ce_threshold_us.map(us),
                memory_limit: o.memory_limit,
                drop_batch: o.drop_batch_size,
                ce_threshold_selector: o.ce_threshold_selector,
            })
            }
            (_, Some(O::Htb(o))) => Self::Htb(HtbQdiscConfig {
                default_class: o.default_class,
                r2q: o.rate2quantum,
                direct_qlen: o.direct_qlen.map(Packets::new),
            }),
            (_, Some(O::Tbf(o))) => {
                let framing @ (overhead, mpu, linklayer) = tbf_framing(live)?;
                // The dumped buckets are framed sizes; what to send for them
                // is not, unless there is no framing (#806).
                let mtu = if o.peakrate != 0 { psched::tbf_bucket_declared(o.peakrate, o.mtu, framing) } else { o.mtu };
                Self::Tbf(TbfConfig {
                    rate: Rate::bytes_per_sec(o.rate),
                    peakrate: (o.peakrate != 0).then(|| Rate::bytes_per_sec(o.peakrate)),
                    burst: Bytes::new(u64::from(psched::tbf_bucket_declared(o.rate, o.burst, framing))),
                    mtu,
                    limit: Bytes::new(u64::from(o.limit)),
                    overhead,
                    mpu,
                    linklayer,
                })
            }
            (_, Some(O::Sfq(o))) => Self::Sfq(SfqConfig {
                perturb: o.perturb_period,
                limit: Packets::new(o.limit),
                quantum: o.quantum,
                divisor: o.divisor,
                flows: o.flows,
                depth: o.depth.unwrap_or(0),
                headdrop: o.headdrop.unwrap_or(false),
            }),
            (_, Some(O::Prio(o))) => Self::Prio(PrioConfig {
                bands: o.bands,
                priomap: o.priomap,
            }),
            _ => return None,
        })
    }

    /// Whether `live` already is this qdisc: the same kind, with every
    /// parameter the spec sets as the kernel keeps it.
    ///
    /// The comparison is in the kernel's own units and quantisation:
    /// probabilities as 32-bit fractions, codel times in 1.024 µs units (a
    /// 20 ms target reads back as 19999 µs), TBF buckets as the transmission
    /// time the kernel stores. A kind that has no parser here compares the
    /// options' bytes, which errs towards "differs". The kernel's default
    /// matches a root with handle 0, which is what the kernel installs.
    pub fn matches(&self, live: &TcMessage) -> bool {
        use crate::netlink::{
            tc_options::QdiscOptions,
            tc_recipe_internals::{codel_round_trip_us, netem_matches},
        };

        if let Self::KernelDefault = self {
            return live.handle().as_raw() == 0;
        }
        if live.kind() != Some(self.kind()) {
            return false;
        }
        // The message, which some arms read beside its parsed options.
        let live_msg = live;
        match (self, live.options()) {
            (Self::Netem(cfg), _) => netem_matches(cfg, live),
            (Self::Tbf(cfg), Some(QdiscOptions::Tbf(live))) => {
                // Rate, peakrate and limit come back exact. Burst and mtu
                // do not: the kernel keeps both buckets as nanoseconds and
                // reports them only as psched ticks, so the bytes read back
                // are a tick round trip of what was sent (32768 at 10 gbit
                // reads as 32719); compare against the same trip. The mtu
                // goes as TCA_TBF_PBURST only with a peak rate; otherwise
                // the kernel keeps the tick count written into `qopt.mtu`.
                let rate = cfg.rate.as_bytes_per_sec();
                let peak = cfg.peakrate.map(|r| r.as_bytes_per_sec());
                // The kernel charges the buckets with the rate's framing (#806).
                let framing = (cfg.overhead, cfg.mpu, cfg.linklayer);
                let burst = psched::tbf_bucket_round_trip_framed(rate, cfg.burst.as_u32_saturating(), framing);
                let mtu = match peak {
                    Some(peak) => psched::tbf_bucket_round_trip_framed(peak, cfg.mtu, framing),
                    None => psched::tc_calc_xmitsize(rate, psched::tc_calc_xmittime(rate, cfg.mtu)),
                };
                // Without a limit there is no match, so an apply gets to
                // refuse the spec (`TbfConfig::write_options`) even where
                // an older apply installed it: the kernel's limit-0 TBF has
                // no queue and drops everything.
                cfg.limit.as_u32_saturating() != 0
                    && live.rate == rate
                    && live.burst == burst
                    && live.limit == cfg.limit.as_u32_saturating()
                    && live.peakrate == peak.unwrap_or(0)
                    && live.mtu == mtu
                    && tbf_framing(live_msg) == Some((cfg.overhead, cfg.mpu, cfg.linklayer))
            }
            (Self::Htb(cfg), Some(QdiscOptions::Htb(live))) => {
                live.default_class == cfg.default_class
                    && live.rate2quantum == cfg.r2q
                    && cfg.direct_qlen.is_none_or(|q| live.direct_qlen == Some(q.as_u32()))
            }
            (Self::FqCodel(cfg), Some(QdiscOptions::FqCodel(live))) => {
                // Only what the spec sets is written; the kernel chooses
                // the rest. `quantum` is kept as `max(256, quantum)`.
                let us = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
                cfg.limit.is_none_or(|l| live.limit == l.as_u32())
                    && cfg.flows.is_none_or(|f| live.flows == f)
                    && cfg
                        .target
                        .is_none_or(|t| codel_round_trip_us(us(t)) == live.target_us)
                    && cfg
                        .interval
                        .is_none_or(|i| codel_round_trip_us(us(i)) == live.interval_us)
                    && cfg
                        .quantum
                        .is_none_or(|q| live.quantum == q.max(FQ_CODEL_MIN_QUANTUM))
                    && cfg.ecn.is_none_or(|e| live.ecn == e)
                    && cfg
                        .ce_threshold
                        .is_none_or(|t| live.ce_threshold_us == Some(codel_round_trip_us(us(t))))
                    && cfg
                        .memory_limit
                        .is_none_or(|m| live.memory_limit == Some(m))
                    && cfg.drop_batch.is_none_or(|b| live.drop_batch_size == Some(b))
                    && cfg
                        .ce_threshold_selector
                        .is_none_or(|s| live.ce_threshold_selector == Some(s))
            }
            (Self::Sfq(cfg), Some(QdiscOptions::Sfq(live))) => {
                // A limit, quantum, divisor, flow count or depth of 0
                // leaves the kernel its default, so is not compared; the
                // perturbation period and head drop always are, 0 and off
                // being the kernel's. As `sfq_change()` has it, the depth is
                // capped at 127, the limit at `maxdepth * maxflows`, and a
                // limit caps the flows in turn (#806).
                let flows = if cfg.flows == 0 { SFQ_DEFAULT_FLOWS } else { cfg.flows.min(SFQ_MAX_FLOWS) };
                let depth = if cfg.depth == 0 { SFQ_MAX_DEPTH } else { cfg.depth.min(SFQ_MAX_DEPTH) };
                let limit = cfg.limit.as_u32().min(depth * flows);
                let live_flows = if cfg.limit == crate::util::Packets::ZERO { flows } else { flows.min(limit) };
                live.perturb_period == cfg.perturb
                    && (cfg.limit == crate::util::Packets::ZERO || live.limit == limit)
                    && (cfg.quantum == 0 || live.quantum == cfg.quantum)
                    && (cfg.divisor == 0 || live.divisor == cfg.divisor)
                    && (cfg.flows == 0 || live.flows == live_flows)
                    && (cfg.depth == 0 || live.depth == Some(depth))
                    && live.headdrop.unwrap_or(false) == cfg.headdrop
            }
            (Self::Prio(cfg), Some(QdiscOptions::Prio(live))) => {
                live.bands == cfg.bands && live.priomap == cfg.effective_priomap()
            }
            (Self::Hfsc(cfg), _) => hfsc_defcls(live) == Some(cfg.default_class),
            (Self::Drr(_) | Self::Qfq(_) | Self::Ingress | Self::Clsact, _) => true,
            // No parser for this kind, or no options reported: compare the
            // bytes, which errs towards "differs".
            _ => self
                .options_bytes()
                .is_some_and(|b| b.as_slice() == live.raw_options().unwrap_or(&[])),
        }
    }

    /// The `TCA_OPTIONS` payload, when the spec writes one.
    fn options_bytes(&self) -> Option<Vec<u8>> {
        let cfg = self.config()?;
        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).ok()?;
        Some(builder.as_bytes()[start..].to_vec())
    }

    /// Check the spec without a kernel: what installing it would refuse
    /// before sending anything (a netem distribution with no jitter, a TBF
    /// without a limit, a loss model beside random loss, …).
    pub fn validate(&self) -> Result<()> {
        match self.config() {
            Some(cfg) => {
                let mut scratch = MessageBuilder::new(0, 0);
                cfg.write_options(&mut scratch)
            }
            None => Ok(()),
        }
    }

    /// Whether the kind has classes, and so `1:` as its default handle.
    pub fn is_classful(&self) -> bool {
        self.default_handle().is_some()
    }
}

impl QdiscConfig for QdiscSpec {
    fn kind(&self) -> &'static str {
        QdiscSpec::kind(self)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        match self.config() {
            Some(cfg) => cfg.write_options(builder),
            None => Err(Error::invalid_message(
                "the kernel's default qdisc is not installed: delete the root qdisc, and the \
                 kernel puts it back"
                    ,
            )),
        }
    }

    fn has_options(&self) -> bool {
        self.config().is_some_and(|c| c.has_options())
    }

    fn default_handle(&self) -> Option<TcHandle> {
        self.config().and_then(|c| c.default_handle())
    }

    fn in_place(&self, live: &TcMessage) -> InPlace {
        self.config().map_or(InPlace::Change, |c| c.in_place(live))
    }

    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        match self.config() {
            Some(cfg) => cfg.write_change_options(builder),
            None => self.write_options(builder),
        }
    }

    fn fixed_parent(&self) -> Option<TcHandle> {
        self.config().and_then(|c| c.fixed_parent())
    }
}

#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{Bytes, Percent, Rate};

    /// A live qdisc as a dump would report it: kind + raw `TCA_OPTIONS`.
    fn live(kind: &str, options: Option<Vec<u8>>) -> TcMessage {
        TcMessage {
            kind: Some(kind.to_string()),
            options,
            ..TcMessage::default()
        }
    }

    /// One native-endian `u32` attribute, the way the kernel writes it.
    fn attr_u32(attr_type: u16, value: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&8u16.to_ne_bytes());
        out.extend_from_slice(&attr_type.to_ne_bytes());
        out.extend_from_slice(&value.to_ne_bytes());
        out
    }

    fn bytes(spec: &QdiscSpec) -> Vec<u8> {
        spec.options_bytes().unwrap_or_default()
    }

    fn netem(delay_ms: u64) -> QdiscSpec {
        NetemConfig::new()
            .delay(Duration::from_millis(delay_ms))
            .jitter(Duration::from_millis(10))
            .loss(Percent::new(0.5))
            .reorder(Percent::new(3.0))
            .reorder_correlation(Percent::new(50.0))
            .rate(Rate::mbit(100))
            .gap(5)
            .into()
    }

    #[test]
    fn options_differ_when_a_parameter_does() {
        let htb = |class| QdiscSpec::from(HtbQdiscConfig::new().default_class(class));
        assert_ne!(bytes(&htb(0x10)), bytes(&htb(0x20)));
        assert_eq!(bytes(&netem(100)), bytes(&netem(100)));
        assert_ne!(bytes(&netem(100)), bytes(&netem(200)));
    }

    #[test]
    fn a_kind_without_options_matches_and_one_with_needs_them() {
        let htb = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x10));
        assert!(!htb.matches(&live("htb", None)));
        assert!(!htb.matches(&live("htb", Some(Vec::new()))));
        assert!(QdiscSpec::Clsact.matches(&live("clsact", Some(Vec::new()))));
        assert!(QdiscSpec::Clsact.matches(&live("clsact", None)));
        assert!(
            !QdiscSpec::Clsact.matches(&live("ingress", None)),
            "another kind"
        );
    }

    /// The kernel reports attributes netem was never sent (`ECN`, `CORR`,
    /// …). A spec must still match its own qdisc (#346).
    #[test]
    fn netem_matches_the_kernels_echo_with_extra_attributes() {
        use crate::netlink::types::tc::qdisc::netem::TCA_NETEM_ECN;
        let spec = netem(100);
        let mut echo = bytes(&spec);
        echo.extend(attr_u32(TCA_NETEM_ECN, 0));
        assert!(spec.matches(&live("netem", Some(echo.clone()))));
        assert!(!netem(200).matches(&live("netem", Some(echo))));
    }

    /// codel stores time in 2^-10 s units: a 20 ms target is echoed as
    /// 19999 µs. Compare in the kernel's quantisation, and only the fields
    /// the spec sets.
    #[test]
    fn fq_codel_compares_in_codel_ticks_and_only_set_fields() {
        use crate::netlink::types::tc::qdisc::fq_codel::{
            TCA_FQ_CODEL_ECN, TCA_FQ_CODEL_FLOWS, TCA_FQ_CODEL_QUANTUM, TCA_FQ_CODEL_TARGET,
        };
        let target = |ms| QdiscSpec::from(FqCodelConfig::new().target(Duration::from_millis(ms)));
        let echo = live("fq_codel", Some(attr_u32(TCA_FQ_CODEL_TARGET, 19_999)));
        assert!(target(20).matches(&echo));
        assert!(!target(18).matches(&echo));
        assert!(QdiscSpec::from(FqCodelConfig::new()).matches(&echo));

        let fq = |flows: Option<u32>, quantum: Option<u32>, ecn: Option<bool>| {
            let mut c = FqCodelConfig::new();
            c.flows = flows;
            c.quantum = quantum;
            c.ecn = ecn;
            QdiscSpec::from(c)
        };
        let mut opts = attr_u32(TCA_FQ_CODEL_FLOWS, 1024);
        opts.extend(attr_u32(TCA_FQ_CODEL_QUANTUM, 300));
        opts.extend(attr_u32(TCA_FQ_CODEL_ECN, 1));
        let echo = live("fq_codel", Some(opts));
        assert!(fq(Some(1024), Some(300), Some(true)).matches(&echo));
        assert!(
            fq(None, None, None).matches(&echo),
            "unset knobs are not compared"
        );
        assert!(
            !fq(Some(512), None, None).matches(&echo),
            "flows recreates, so it is seen (#596)"
        );
        assert!(!fq(None, Some(1514), None).matches(&echo));
        assert!(!fq(None, None, Some(false)).matches(&echo));
        // The kernel stores quantum as max(256, quantum).
        let echo = live("fq_codel", Some(attr_u32(TCA_FQ_CODEL_QUANTUM, 256)));
        assert!(fq(None, Some(128), None).matches(&echo));
        assert!(!fq(None, Some(300), None).matches(&echo));
    }

    #[test]
    fn htb_default_class_is_compared_as_a_field() {
        use crate::netlink::types::tc::qdisc::htb::TCA_HTB_DIRECT_QLEN;
        let spec = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x10));
        let mut echo = bytes(&spec);
        echo.extend(attr_u32(TCA_HTB_DIRECT_QLEN, 1000));
        assert!(spec.matches(&live("htb", Some(echo.clone()))));
        let other = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x20));
        assert!(!other.matches(&live("htb", Some(echo))));
    }

    fn tbf(rate: u64, burst: u64, limit: u64, peak: Option<u64>, mtu: Option<u32>) -> QdiscSpec {
        let mut c = TbfConfig::new()
            .rate(Rate::bytes_per_sec(rate))
            .burst(Bytes::new(burst))
            .limit(Bytes::new(limit));
        c.peakrate = peak.map(Rate::bytes_per_sec);
        if let Some(mtu) = mtu {
            c.mtu = mtu;
        }
        c.into()
    }

    #[test]
    fn tbf_rate_burst_limit_peakrate_and_mtu_are_compared() {
        let spec = tbf(125_000, 32_768, 65_536, None, None);
        let echo = live("tbf", Some(bytes(&spec)));
        assert!(spec.matches(&echo));
        assert!(!tbf(250_000, 32_768, 65_536, None, None).matches(&echo));
        assert!(!tbf(125_000, 65_536, 65_536, None, None).matches(&echo));

        let peaked = tbf(125_000, 32_768, 65_536, Some(250_000), Some(1600));
        let peaked_echo = live("tbf", Some(bytes(&peaked)));
        assert!(peaked.matches(&peaked_echo));
        assert!(!tbf(125_000, 32_768, 65_536, Some(500_000), Some(1600)).matches(&peaked_echo));
        assert!(!tbf(125_000, 32_768, 65_536, Some(250_000), Some(9000)).matches(&peaked_echo));
        assert!(!spec.matches(&peaked_echo), "dropping the peakrate is seen");
    }

    /// What `tbf_dump()` sends back: `tc_tbf_qopt` alone, with `buffer`
    /// and `mtu` as psched ticks and no TCA_TBF_BURST/PBURST.
    fn kernel_tbf_echo(rate: u32, limit: u32, buffer_ticks: u32, mtu_ticks: u32) -> Vec<u8> {
        use crate::netlink::types::tc::qdisc::{TcRateSpec, tbf};
        // The kernel reports the link layer sent, Ethernet's 1 (#806).
        let qopt = tbf::TcTbfQopt {
            rate: TcRateSpec { linklayer: 1, ..TcRateSpec::new(rate) },
            peakrate: TcRateSpec::default(),
            limit,
            buffer: buffer_ticks,
            mtu: mtu_ticks,
        };
        let mut out = Vec::new();
        out.extend_from_slice(&((4 + tbf::TcTbfQopt::SIZE) as u16).to_ne_bytes());
        out.extend_from_slice(&tbf::TCA_TBF_PARMS.to_ne_bytes());
        out.extend_from_slice(qopt.as_bytes());
        out
    }

    /// 10 gbit, a 32 KiB burst, the default mtu: a 6.12 kernel dumps
    /// `buffer` 409 ticks and `mtu` 18, which read back as 32719 and 1440
    /// bytes; the comparison goes through the same round trip.
    #[test]
    fn tbf_buckets_are_compared_after_the_kernels_tick_round_trip() {
        let echo = live("tbf", Some(kernel_tbf_echo(1_250_000_000, 65_536, 409, 18)));
        assert!(tbf(1_250_000_000, 32_768, 65_536, None, None).matches(&echo));
        assert!(!tbf(1_250_000_000, 65_536, 65_536, None, None).matches(&echo));
        // Without a limit nothing matches, so an apply refuses it (the
        // kernel's limit-0 TBF drops everything).
        let black_hole = live("tbf", Some(kernel_tbf_echo(1_250_000_000, 0, 409, 18)));
        assert!(!tbf(1_250_000_000, 32_768, 0, None, None).matches(&black_hole));
        assert!(
            tbf(1_250_000_000, 32_768, 0, None, None)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn sfq_and_prio_compare_their_fields() {
        let sfq = |perturb: i32, limit: u32, quantum: u32| {
            let mut c = SfqConfig::new();
            c.perturb = perturb;
            c.limit = crate::util::Packets::new(limit);
            c.quantum = quantum;
            QdiscSpec::from(c)
        };
        let tuned = sfq(10, 200, 1514);
        let echo = live("sfq", Some(bytes(&tuned)));
        assert!(tuned.matches(&echo));
        assert!(!sfq(20, 200, 1514).matches(&echo));
        // A limit or quantum of 0 leaves the kernel its default and is not
        // compared; the perturbation period is, 0 being "off".
        assert!(sfq(10, 0, 0).matches(&echo));
        assert!(
            !sfq(0, 0, 0).matches(&echo),
            "an unset perturb is the kernel's 0, not 10"
        );
        assert!(!sfq(10, 64, 0).matches(&echo));
        assert!(!sfq(10, 0, 300).matches(&echo));
        // The limit is capped at maxdepth * maxflows.
        let echo = live("sfq", Some(bytes(&sfq(0, 16_256, 0))));
        assert!(sfq(0, 20_000, 0).matches(&echo));
        assert!(!sfq(0, 16_000, 0).matches(&echo));

        let prio = |bands| QdiscSpec::from(PrioConfig::new().bands(bands));
        let echo = live("prio", Some(bytes(&prio(3))));
        assert!(prio(3).matches(&echo));
        assert!(!prio(4).matches(&echo));
    }

    #[test]
    fn hfsc_drr_and_qfq_roots_compare_and_read_back() {
        let at_1 = |mut m: TcMessage| {
            m.header.tcm_handle = TcHandle::major_only(1).as_raw();
            m
        };
        let hfsc = |class| QdiscSpec::from(HfscConfig::new().default_class(class));
        let echo = at_1(live("hfsc", Some(bytes(&hfsc(0x20)))));
        assert!(hfsc(0x20).matches(&echo));
        assert!(!hfsc(0x10).matches(&echo));
        assert_eq!(QdiscSpec::from_live(&echo), Some(hfsc(0x20)));
        for spec in [QdiscSpec::from(DrrConfig::new()), QdiscSpec::from(QfqConfig::new())] {
            let echo = at_1(live(spec.kind(), None));
            assert!(spec.matches(&echo), "{}", spec.kind());
            assert_eq!(QdiscSpec::from_live(&echo).as_ref(), Some(&spec));
        }
        assert!(!QdiscSpec::from(DrrConfig::new()).matches(&live("qfq", None)));
    }

    #[test]
    fn a_spec_installs_as_its_config_does() {
        let spec = netem(100);
        let QdiscSpec::Netem(cfg) = &spec else {
            unreachable!()
        };
        assert_eq!(QdiscConfig::kind(&spec), "netem");
        assert_eq!(bytes(&spec), {
            let mut b = MessageBuilder::new(0, 0);
            let start = b.len();
            cfg.write_options(&mut b).unwrap();
            b.as_bytes()[start..].to_vec()
        });
        assert_eq!(QdiscSpec::Clsact.fixed_parent(), Some(TcHandle::INGRESS));
        assert_eq!(
            QdiscSpec::from(HtbQdiscConfig::new()).default_handle(),
            Some(TcHandle::major_only(1))
        );
        assert!(QdiscSpec::from(HtbQdiscConfig::new()).is_classful());
        assert!(!spec.is_classful());
        assert!(QdiscSpec::KernelDefault.validate().is_ok());
        let mut b = MessageBuilder::new(0, 0);
        assert!(QdiscSpec::KernelDefault.write_options(&mut b).is_err());
    }
}
