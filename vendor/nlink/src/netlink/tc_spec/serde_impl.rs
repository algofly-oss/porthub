//! `QdiscSpec` in JSON and YAML, in the units tc(8) writes (#515).
//!
//! Each kind goes through a shadow representation: the fields as a
//! document names them, optional, in human units — `{"netem": {"delay":
//! "10ms", "loss": "1%", "rate": "100mbit"}}`. A spec writes only what
//! differs from its kind's defaults, and reads back as the same spec.
//!
//! A document written by nlink 0.31 or before still reads: the fields the
//! declarative qdisc type had in raw units (`delay_us`, `loss_percent`,
//! `rate_bps` in bytes per second, `burst_bytes`, `perturb_secs`, …) are
//! accepted beside the new ones, never written, and a document that sets
//! a value both ways is refused. Unknown fields are refused: a misspelt
//! parameter used to be ignored.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::QdiscSpec;
use crate::{
    netlink::{
        tc::{
            DrrConfig, FqCodelConfig, HfscConfig, HtbQdiscConfig, NetemConfig, NetemSlot,
            PrioConfig, QfqConfig, SfqConfig, TbfConfig,
        },
        tc_options::NetemLossModel,
    },
    util::{
        Bytes, Packets, Percent, Rate,
        serde_units::{duration, option_duration},
    },
};

/// The document form of a [`QdiscSpec`]: one key per kind.
// Built for one (de)serialization and dropped: its size does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schemars", schemars(rename = "QdiscSpec"))]
pub(super) enum Repr {
    Netem(NetemRepr),
    Htb(HtbRepr),
    FqCodel(FqCodelRepr),
    Tbf(TbfRepr),
    Sfq(SfqRepr),
    Prio(PrioRepr),
    Hfsc(HfscRepr),
    Drr,
    Qfq,
    Ingress,
    Clsact,
    KernelDefault,
}

/// One value set two ways — the 0.31 field and its replacement.
fn either<T>(
    new: Option<T>,
    old: Option<T>,
    field: &str,
    legacy: &str,
) -> Result<Option<T>, String> {
    match (new, old) {
        (Some(_), Some(_)) => Err(format!(
            "`{field}` and `{legacy}` say the same thing twice; keep `{field}`"
        )),
        (new, old) => Ok(new.or(old)),
    }
}

/// A 0.31 percentage, a bare `f64`, checked as a `Percent` field is.
fn legacy_percent(v: Option<f64>, field: &str) -> Result<Option<Percent>, String> {
    v.map(|v| {
        if v.is_finite() && (0.0..=100.0).contains(&v) {
            Ok(Percent::new(v))
        } else {
            Err(format!("`{field}` is a percentage from 0 to 100, not {v}"))
        }
    })
    .transpose()
}

macro_rules! human_duration {
    () => {
        Option<Duration>
    };
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct NetemRepr {
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    delay: human_duration!(),
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    jitter: human_duration!(),
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_correlation: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    loss: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    loss_correlation: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    loss_model: Option<NetemLossModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_correlation: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    corrupt: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    corrupt_correlation: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reorder: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reorder_correlation: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gap: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<Rate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_packet_overhead: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_cell_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_cell_overhead: Option<i32>,
    /// Packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Packets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<SlotRepr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    // 0.31: read, never written.
    #[serde(skip_serializing)]
    delay_us: Option<u32>,
    #[serde(skip_serializing)]
    jitter_us: Option<u32>,
    #[serde(skip_serializing)]
    loss_percent: Option<f64>,
    #[serde(skip_serializing)]
    duplicate_percent: Option<f64>,
    #[serde(skip_serializing)]
    corrupt_percent: Option<f64>,
    #[serde(skip_serializing)]
    reorder_percent: Option<f64>,
    /// Bytes per second, as 0.31 had it.
    #[serde(skip_serializing)]
    rate_bps: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct SlotRepr {
    #[serde(with = "duration")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "crate::util::serde_units::HumanDuration")
    )]
    min_delay: Duration,
    #[serde(with = "duration")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "crate::util::serde_units::HumanDuration")
    )]
    max_delay: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packets: Option<Packets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytes: Option<u32>,
}

fn nonzero<T: PartialEq + Default>(v: T) -> Option<T> {
    (v != T::default()).then_some(v)
}

impl From<&NetemConfig> for NetemRepr {
    fn from(c: &NetemConfig) -> Self {
        let pct = |p: Percent| (!p.is_zero()).then_some(p);
        let default = NetemConfig::new();
        NetemRepr {
            delay: c.delay,
            jitter: c.jitter,
            delay_correlation: pct(c.delay_correlation),
            loss: pct(c.loss),
            loss_correlation: pct(c.loss_correlation),
            loss_model: c.loss_model,
            duplicate: pct(c.duplicate),
            duplicate_correlation: pct(c.duplicate_correlation),
            corrupt: pct(c.corrupt),
            corrupt_correlation: pct(c.corrupt_correlation),
            reorder: pct(c.reorder),
            reorder_correlation: pct(c.reorder_correlation),
            gap: nonzero(c.gap),
            rate: c.rate,
            rate_packet_overhead: nonzero(c.rate_packet_overhead),
            rate_cell_size: nonzero(c.rate_cell_size),
            rate_cell_overhead: nonzero(c.rate_cell_overhead),
            limit: (c.limit != default.limit).then_some(c.limit),
            ecn: c.ecn.then_some(true),
            slot: c.slot.map(|s| SlotRepr {
                min_delay: s.min_delay,
                max_delay: s.max_delay,
                packets: s.max_packets,
                bytes: s.max_bytes,
            }),
            seed: c.seed,
            ..NetemRepr::default()
        }
    }
}

impl TryFrom<NetemRepr> for NetemConfig {
    type Error = String;
    fn try_from(r: NetemRepr) -> Result<Self, String> {
        let us = |v: Option<u32>| v.map(|v| Duration::from_micros(u64::from(v)));
        let mut c = NetemConfig::new();
        c.delay = either(r.delay, us(r.delay_us), "delay", "delay_us")?;
        c.jitter = either(r.jitter, us(r.jitter_us), "jitter", "jitter_us")?;
        let pick = |new: Option<Percent>, old: Option<f64>, field: &str, legacy: &str| {
            either(new, legacy_percent(old, legacy)?, field, legacy).map(Option::unwrap_or_default)
        };
        c.loss = pick(r.loss, r.loss_percent, "loss", "loss_percent")?;
        c.duplicate = pick(
            r.duplicate,
            r.duplicate_percent,
            "duplicate",
            "duplicate_percent",
        )?;
        c.corrupt = pick(r.corrupt, r.corrupt_percent, "corrupt", "corrupt_percent")?;
        c.reorder = pick(r.reorder, r.reorder_percent, "reorder", "reorder_percent")?;
        c.delay_correlation = r.delay_correlation.unwrap_or_default();
        c.loss_correlation = r.loss_correlation.unwrap_or_default();
        c.duplicate_correlation = r.duplicate_correlation.unwrap_or_default();
        c.corrupt_correlation = r.corrupt_correlation.unwrap_or_default();
        c.reorder_correlation = r.reorder_correlation.unwrap_or_default();
        c.loss_model = r.loss_model;
        c.gap = r.gap.unwrap_or(0);
        c.rate = either(
            r.rate,
            r.rate_bps.map(Rate::bytes_per_sec),
            "rate",
            "rate_bps",
        )?;
        c.rate_packet_overhead = r.rate_packet_overhead.unwrap_or(0);
        c.rate_cell_size = r.rate_cell_size.unwrap_or(0);
        c.rate_cell_overhead = r.rate_cell_overhead.unwrap_or(0);
        if let Some(limit) = r.limit {
            c.limit = limit;
        }
        c.ecn = r.ecn.unwrap_or(false);
        c.slot = r.slot.map(|s| {
            let mut slot = NetemSlot::new(s.min_delay, s.max_delay);
            slot.max_packets = s.packets;
            slot.max_bytes = s.bytes;
            slot
        });
        c.seed = r.seed;
        Ok(c)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct HtbRepr {
    /// The minor of the class unclassified traffic goes to.
    #[serde(skip_serializing_if = "Option::is_none")]
    default_class: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    r2q: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_qlen: Option<Packets>,
}

impl From<&HtbQdiscConfig> for HtbRepr {
    fn from(c: &HtbQdiscConfig) -> Self {
        let default = HtbQdiscConfig::new();
        HtbRepr {
            default_class: Some(c.default_class),
            r2q: (c.r2q != default.r2q).then_some(c.r2q),
            direct_qlen: c.direct_qlen,
        }
    }
}

impl From<HtbRepr> for HtbQdiscConfig {
    fn from(r: HtbRepr) -> Self {
        let mut c = HtbQdiscConfig::new();
        c.default_class = r.default_class.unwrap_or(0);
        if let Some(r2q) = r.r2q {
            c.r2q = r2q;
        }
        c.direct_qlen = r.direct_qlen;
        c
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct FqCodelRepr {
    /// Packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Packets>,
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    target: Option<Duration>,
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    interval: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flows: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quantum: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecn: Option<bool>,
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    ce_threshold: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_limit: Option<Bytes>,
    /// Packets (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    drop_batch: Option<u32>,
    /// `[value, mask]` (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    ce_threshold_selector: Option<[u8; 2]>,
    #[serde(skip_serializing)]
    target_us: Option<u32>,
    #[serde(skip_serializing)]
    interval_us: Option<u32>,
}

impl From<&FqCodelConfig> for FqCodelRepr {
    fn from(c: &FqCodelConfig) -> Self {
        FqCodelRepr {
            limit: c.limit,
            target: c.target,
            interval: c.interval,
            flows: c.flows,
            quantum: c.quantum.map(|q| Bytes::new(u64::from(q))),
            ecn: c.ecn,
            ce_threshold: c.ce_threshold,
            memory_limit: c.memory_limit.map(|m| Bytes::new(u64::from(m))),
            drop_batch: c.drop_batch,
            ce_threshold_selector: c.ce_threshold_selector.map(|(v, m)| [v, m]),
            ..FqCodelRepr::default()
        }
    }
}

impl TryFrom<FqCodelRepr> for FqCodelConfig {
    type Error = String;
    fn try_from(r: FqCodelRepr) -> Result<Self, String> {
        let us = |v: Option<u32>| v.map(|v| Duration::from_micros(u64::from(v)));
        let mut c = FqCodelConfig::new();
        c.limit = r.limit;
        c.target = either(r.target, us(r.target_us), "target", "target_us")?;
        c.interval = either(r.interval, us(r.interval_us), "interval", "interval_us")?;
        c.flows = r.flows;
        c.quantum = r.quantum.map(Bytes::as_u32_saturating);
        c.ecn = r.ecn;
        c.ce_threshold = r.ce_threshold;
        c.memory_limit = r.memory_limit.map(Bytes::as_u32_saturating);
        c.drop_batch = r.drop_batch;
        c.ce_threshold_selector = r.ce_threshold_selector.map(|[v, m]| (v, m));
        Ok(c)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct TbfRepr {
    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<Rate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    burst: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peakrate: Option<Rate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<Bytes>,
    /// Bytes added to each packet's size (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    overhead: Option<u16>,
    /// The least size a packet is charged as (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    mpu: Option<u16>,
    /// `ethernet` (the default) or `atm` (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    linklayer: Option<String>,
    /// Bytes per second, as 0.31 had it.
    #[serde(skip_serializing)]
    rate_bps: Option<u64>,
    #[serde(skip_serializing)]
    burst_bytes: Option<u32>,
    #[serde(skip_serializing)]
    limit_bytes: Option<u32>,
    #[serde(skip_serializing)]
    peakrate_bps: Option<u64>,
}

impl From<&TbfConfig> for TbfRepr {
    fn from(c: &TbfConfig) -> Self {
        TbfRepr {
            rate: Some(c.rate),
            burst: Some(c.burst),
            limit: (c.limit != Bytes::ZERO).then_some(c.limit),
            peakrate: c.peakrate,
            mtu: (c.mtu != TbfConfig::new().mtu).then(|| Bytes::new(u64::from(c.mtu))),
            overhead: (c.overhead != 0).then_some(c.overhead),
            mpu: (c.mpu != 0).then_some(c.mpu),
            linklayer: match c.linklayer {
                crate::netlink::psched::LinkLayer::Ethernet => None,
                crate::netlink::psched::LinkLayer::Atm => Some("atm".into()),
                _ => Some("unaware".into()),
            },
            ..TbfRepr::default()
        }
    }
}

impl TryFrom<TbfRepr> for TbfConfig {
    type Error = String;
    fn try_from(r: TbfRepr) -> Result<Self, String> {
        let bytes = |v: Option<u32>| v.map(|v| Bytes::new(u64::from(v)));
        let mut c = TbfConfig::new();
        c.rate = either(
            r.rate,
            r.rate_bps.map(Rate::bytes_per_sec),
            "rate",
            "rate_bps",
        )?
        .ok_or("a tbf needs a `rate`")?;
        c.burst = either(r.burst, bytes(r.burst_bytes), "burst", "burst_bytes")?
            .ok_or("a tbf needs a `burst`")?;
        if let Some(limit) = either(r.limit, bytes(r.limit_bytes), "limit", "limit_bytes")? {
            c.limit = limit;
        }
        c.peakrate = either(
            r.peakrate,
            r.peakrate_bps.map(Rate::bytes_per_sec),
            "peakrate",
            "peakrate_bps",
        )?;
        if let Some(mtu) = r.mtu {
            c.mtu = mtu.as_u32_saturating();
        }
        c.overhead = r.overhead.unwrap_or(0);
        c.mpu = r.mpu.unwrap_or(0);
        c.linklayer = match r.linklayer.as_deref() {
            None | Some("ethernet") => crate::netlink::psched::LinkLayer::Ethernet,
            Some("atm" | "adsl") => crate::netlink::psched::LinkLayer::Atm,
            Some("unaware") => crate::netlink::psched::LinkLayer::Unaware,
            Some(other) => return Err(format!("tbf `linklayer` {other:?} (expected ethernet or atm)")),
        };
        Ok(c)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct SfqRepr {
    /// Whole seconds; a fraction rounds up.
    #[serde(with = "option_duration", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Option<crate::util::serde_units::HumanDuration>")
    )]
    perturb: Option<Duration>,
    /// Packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Packets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quantum: Option<Bytes>,
    /// Hash buckets, a power of two (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    divisor: Option<u32>,
    /// The most flows (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    flows: Option<u32>,
    /// The most packets a flow queues (#806).
    #[serde(skip_serializing_if = "Option::is_none")]
    depth: Option<u32>,
    /// Drop from the head of a full flow's queue (#806).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    headdrop: bool,
    #[serde(skip_serializing)]
    perturb_secs: Option<u32>,
}

impl From<&SfqConfig> for SfqRepr {
    fn from(c: &SfqConfig) -> Self {
        SfqRepr {
            perturb: (c.perturb != 0)
                .then(|| Duration::from_secs(u64::from(c.perturb.unsigned_abs()))),
            limit: nonzero(c.limit),
            quantum: (c.quantum != 0).then(|| Bytes::new(u64::from(c.quantum))),
            divisor: (c.divisor != 0).then_some(c.divisor),
            flows: (c.flows != 0).then_some(c.flows),
            depth: (c.depth != 0).then_some(c.depth),
            headdrop: c.headdrop,
            perturb_secs: None,
        }
    }
}

impl TryFrom<SfqRepr> for SfqConfig {
    type Error = String;
    fn try_from(r: SfqRepr) -> Result<Self, String> {
        let secs = |d: Duration| d.as_secs() + u64::from(d.subsec_nanos() > 0);
        let legacy = r.perturb_secs.map(|s| Duration::from_secs(u64::from(s)));
        let mut c = SfqConfig::new();
        if let Some(p) = either(r.perturb, legacy, "perturb", "perturb_secs")? {
            c.perturb = i32::try_from(secs(p))
                .map_err(|_| format!("sfq `perturb` {p:?} is past {} seconds", i32::MAX))?;
        }
        c.limit = r.limit.unwrap_or_default();
        c.quantum = r.quantum.map_or(0, Bytes::as_u32_saturating);
        c.divisor = r.divisor.unwrap_or(0);
        c.flows = r.flows.unwrap_or(0);
        c.depth = r.depth.unwrap_or(0);
        c.headdrop = r.headdrop;
        Ok(c)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct PrioRepr {
    #[serde(skip_serializing_if = "Option::is_none")]
    bands: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priomap: Option<[u8; 16]>,
}

impl From<&PrioConfig> for PrioRepr {
    fn from(c: &PrioConfig) -> Self {
        let default = PrioConfig::new();
        PrioRepr {
            bands: (c.bands != default.bands).then(|| u8::try_from(c.bands).unwrap_or(u8::MAX)),
            priomap: (c.priomap != default.priomap).then_some(c.priomap),
        }
    }
}

impl From<PrioRepr> for PrioConfig {
    fn from(r: PrioRepr) -> Self {
        let mut c = PrioConfig::new();
        if let Some(bands) = r.bands {
            c.bands = i32::from(bands);
        }
        if let Some(map) = r.priomap {
            c.priomap = map;
        }
        c
    }
}

#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub(super) struct HfscRepr {
    /// The minor of the class unclassified traffic goes to; without one,
    /// it is dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    default_class: Option<u16>,
}

impl From<&QdiscSpec> for Repr {
    fn from(s: &QdiscSpec) -> Self {
        match s {
            QdiscSpec::Netem(c) => Repr::Netem(c.into()),
            QdiscSpec::Htb(c) => Repr::Htb(c.into()),
            QdiscSpec::FqCodel(c) => Repr::FqCodel(c.into()),
            QdiscSpec::Tbf(c) => Repr::Tbf(c.into()),
            QdiscSpec::Sfq(c) => Repr::Sfq(c.into()),
            QdiscSpec::Prio(c) => Repr::Prio(c.into()),
            QdiscSpec::Hfsc(c) => Repr::Hfsc(HfscRepr {
                default_class: (c.default_class != 0).then_some(c.default_class),
            }),
            QdiscSpec::Drr(_) => Repr::Drr,
            QdiscSpec::Qfq(_) => Repr::Qfq,
            QdiscSpec::Ingress => Repr::Ingress,
            QdiscSpec::Clsact => Repr::Clsact,
            QdiscSpec::KernelDefault => Repr::KernelDefault,
        }
    }
}

impl TryFrom<Repr> for QdiscSpec {
    type Error = String;
    fn try_from(r: Repr) -> Result<Self, String> {
        Ok(match r {
            Repr::Netem(r) => QdiscSpec::Netem(r.try_into()?),
            Repr::Htb(r) => QdiscSpec::Htb(r.into()),
            Repr::FqCodel(r) => QdiscSpec::FqCodel(r.try_into()?),
            Repr::Tbf(r) => QdiscSpec::Tbf(r.try_into()?),
            Repr::Sfq(r) => QdiscSpec::Sfq(r.try_into()?),
            Repr::Prio(r) => QdiscSpec::Prio(r.into()),
            Repr::Hfsc(r) => QdiscSpec::Hfsc(HfscConfig::new().default_class(r.default_class.unwrap_or(0))),
            Repr::Drr => QdiscSpec::Drr(DrrConfig::new()),
            Repr::Qfq => QdiscSpec::Qfq(QfqConfig::new()),
            Repr::Ingress => QdiscSpec::Ingress,
            Repr::Clsact => QdiscSpec::Clsact,
            Repr::KernelDefault => QdiscSpec::KernelDefault,
        })
    }
}

impl Serialize for QdiscSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Repr::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for QdiscSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Repr::deserialize(d)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for QdiscSpec {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        Repr::schema_name()
    }
    fn schema_id() -> std::borrow::Cow<'static, str> {
        Repr::schema_id()
    }
    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Repr::json_schema(g)
    }
    fn inline_schema() -> bool {
        Repr::inline_schema()
    }
}
