//! `Display` for qdisc options, in tc(8) syntax (#515).
//!
//! Each kind prints its parameters as they follow the kind on a `tc qdisc
//! add` line — `limit 1000 delay 10ms 2ms loss 1%` — so the text is an
//! input as well as a description: given to tc(8), or split on whitespace
//! and given to the kind's `parse_params`, it installs a qdisc the kernel
//! reports exactly as this one.
//!
//! That takes some care, because the kernel does not always report what it
//! was sent. Where it quantises a value, the text holds the smallest value
//! the kernel reports the same way, which can differ from the one reported:
//! fq_codel keeps its times in 1.024 µs units, so a 20 ms target reads back
//! as 19999 µs and prints as `20ms`; a TBF bucket is kept as a transmission
//! time, and prints as the smallest size that takes as long. Percentages
//! print as the shortest decimal with the same 32-bit probability.
//!
//! A value the kind's typed config cannot set prints only when it differs
//! from the kernel's default (sfq's `depth`, `divisor`, `flows` and
//! `headdrop`, fq_codel's `drop_batch`), so the text of a qdisc the typed
//! config could have made parses back into it, and the text of one it could
//! not is refused by `parse_params` rather than half-applied.

use std::fmt::{self, Display, Formatter, Write as _};
use std::time::Duration;

use super::tc_options::{
    CakeOptions, FqCodelOptions, FqPieOptions, HtbOptions, NetemLossModel, NetemOptions,
    PrioOptions, QdiscOptions, SfqOptions, TbfOptions,
};
use crate::util::{Percent, Rate};

use crate::util::parse::format_time as time;

fn micros(us: u32) -> String {
    time(Duration::from_micros(u64::from(us)))
}

/// The µs the kernel reports for `us` sent to a time it keeps in units of
/// `1 << shift` ns: `(units << shift) / 1000`, units being
/// `(us * 1000) >> shift`.
fn reported_us(us: u32, shift: u32) -> u32 {
    let units = (u64::from(us) * 1000) >> shift;
    u32::try_from((units << shift) / 1000).unwrap_or(u32::MAX)
}

/// The smallest µs to send for a time the kernel keeps in units of
/// `1 << shift` ns that it reports as `reported` again. fq_codel's times
/// use 10 (`CODEL_SHIFT`, 1.024 µs, so the report is two short at most),
/// fq_pie's target 6 (psched ticks, finer than the µs it reports).
fn quantised_us(reported: u32, shift: u32) -> u32 {
    (reported..=reported.saturating_add(3))
        .find(|&us| reported_us(us, shift) == reported)
        .unwrap_or(reported)
}

/// The shortest decimal `x` near `value` for which `same(x)` holds, as
/// text.
fn shortest(value: f64, same: impl Fn(f64) -> bool) -> String {
    for places in 0..=12 {
        let mut text = format!("{value:.places$}");
        if text.contains('.') {
            text = text.trim_end_matches('0').trim_end_matches('.').to_string();
        }
        if text.parse::<f64>().is_ok_and(&same) {
            return text;
        }
    }
    format!("{value}")
}

/// A percentage, as the shortest decimal with the same kernel probability.
fn percent(pct: f64) -> String {
    let raw = Percent::new(pct).as_kernel_probability();
    let text = shortest(pct, |x| Percent::new(x).as_kernel_probability() == raw);
    format!("{text}%")
}

/// The percentage `x` whose complement `100 - x` is `pct` in the kernel:
/// tc's `1-h` and `1-k` for the Gilbert-Elliot model.
fn complement(pct: f64) -> String {
    let raw = Percent::new(pct).as_kernel_probability();
    let text = shortest(100.0 - pct, |x| {
        Percent::new(100.0 - x).as_kernel_probability() == raw
    });
    format!("{text}%")
}

/// Write `words` separated by single spaces.
struct Words(Vec<String>);

impl Words {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, word: impl Into<String>) {
        self.0.push(word.into());
    }

    fn pair(&mut self, key: &str, value: impl Display) {
        self.0.push(key.to_string());
        self.0.push(value.to_string());
    }
}

impl Display for Words {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(" "))
    }
}

impl Display for QdiscOptions {
    /// The parameters in tc(8) syntax; see [`NetemOptions`]'s `Display`
    /// for what the text promises. An `Unknown` kind prints nothing.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::FqCodel(o) => o.fmt(f),
            Self::Htb(o) => o.fmt(f),
            Self::Tbf(o) => o.fmt(f),
            Self::Netem(o) => o.fmt(f),
            Self::Prio(o) => o.fmt(f),
            Self::Sfq(o) => o.fmt(f),
            Self::FqPie(o) => o.fmt(f),
            Self::Cake(o) => o.fmt(f),
            Self::Unknown(_) => Ok(()),
        }
    }
}

impl Display for NetemOptions {
    /// The netem as tc(8) takes it: `limit 1000 delay 10ms 2ms loss 1%`.
    ///
    /// Given to tc, or split on whitespace and given to
    /// [`NetemConfig::parse_params`](crate::netlink::tc::NetemConfig::parse_params),
    /// the text installs a netem the kernel reports exactly as this one —
    /// with two exceptions the kernel imposes. A delay distribution table
    /// is never reported, so none is printed. And a slot drawn from a table
    /// (`slot distribution …`) prints as `slot distribution unknown …`,
    /// which `parse_params` refuses: nlink does not write those.
    ///
    /// The seed prints whenever the kernel reports one, which Linux 6.3+
    /// always does, a random one where none was set; iproute2 before 6.3
    /// does not take `seed`.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut w = Words::new();
        w.pair("limit", self.limit);
        let delay_corr = self.delay_corr > 0.0;
        if self.delay_ns > 0 || self.jitter_ns > 0 || delay_corr {
            w.pair("delay", time(Duration::from_nanos(self.delay_ns)));
            if self.jitter_ns > 0 || delay_corr {
                w.push(time(Duration::from_nanos(self.jitter_ns)));
            }
            if delay_corr {
                w.push(percent(self.delay_corr));
            }
        }
        match &self.loss_model {
            // A model replaces random loss in the kernel, which ignores the
            // random values then.
            Some(NetemLossModel::GilbertIntuitive {
                p13,
                p31,
                p32,
                p14,
                p23,
            }) => {
                w.push("loss");
                w.push("state");
                for p in [p13, p31, p32, p23, p14] {
                    w.push(percent(*p));
                }
            }
            Some(NetemLossModel::GilbertElliot { p, r, h, k1 }) => {
                w.push("loss");
                w.push("gemodel");
                w.push(percent(*p));
                w.push(percent(*r));
                w.push(complement(*h));
                w.push(percent(*k1));
            }
            None => pct_group(&mut w, "loss", self.loss_percent, self.loss_corr),
        }
        pct_group(
            &mut w,
            "duplicate",
            self.duplicate_percent,
            self.duplicate_corr,
        );
        pct_group(&mut w, "reorder", self.reorder_percent, self.reorder_corr);
        if self.gap > 0 {
            w.pair("gap", self.gap);
        }
        pct_group(&mut w, "corrupt", self.corrupt_percent, self.corrupt_corr);
        let overheads = [
            (self.packet_overhead != 0, self.packet_overhead.to_string()),
            (self.cell_size != 0, self.cell_size.to_string()),
            (self.cell_overhead != 0, self.cell_overhead.to_string()),
        ];
        if self.rate > 0 || overheads.iter().any(|(set, _)| *set) {
            w.pair("rate", Rate::bytes_per_sec(self.rate));
            // Positional: print up to the last one set.
            let last = overheads.iter().rposition(|(set, _)| *set);
            for (_, v) in overheads.iter().take(last.map_or(0, |i| i + 1)) {
                w.push(v.clone());
            }
        }
        if let Some(slot) = &self.slot {
            w.push("slot");
            if slot.dist_delay_ns != 0 || slot.dist_jitter_ns != 0 {
                w.pair("distribution", "unknown");
                w.push(time(Duration::from_nanos(slot.dist_delay_ns.max(0) as u64)));
                w.push(time(
                    Duration::from_nanos(slot.dist_jitter_ns.max(0) as u64),
                ));
            } else {
                w.push(time(Duration::from_nanos(slot.min_delay_ns.max(0) as u64)));
                w.push(time(Duration::from_nanos(slot.max_delay_ns.max(0) as u64)));
            }
            if slot.max_packets > 0 && slot.max_packets != i32::MAX {
                w.pair("packets", slot.max_packets);
            }
            if slot.max_bytes > 0 && slot.max_bytes != i32::MAX {
                w.pair("bytes", slot.max_bytes);
            }
        }
        if self.ecn {
            w.push("ecn");
        }
        if let Some(seed) = self.seed {
            w.pair("seed", seed);
        }
        w.fmt(f)
    }
}

/// `key P [C]` when either is set.
fn pct_group(w: &mut Words, key: &str, pct: f64, corr: f64) {
    if pct > 0.0 || corr > 0.0 {
        w.pair(key, percent(pct));
        if corr > 0.0 {
            w.push(percent(corr));
        }
    }
}

/// `drop_batch`'s kernel default, which `FqCodelConfig` cannot change.
const FQ_CODEL_DROP_BATCH: u32 = 64;

impl Display for FqCodelOptions {
    /// fq_codel as tc(8) takes it. Times are those that land on the
    /// kernel's 1.024 µs units: a reported target of 19999 µs prints as
    /// `20ms`. `drop_batch` prints only when it is not the default 64,
    /// which `FqCodelConfig` cannot set.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let codel = |us| micros(quantised_us(us, 10));
        let mut w = Words::new();
        w.pair("limit", self.limit);
        w.pair("flows", self.flows);
        w.pair("quantum", self.quantum);
        w.pair("target", codel(self.target_us));
        w.pair("interval", codel(self.interval_us));
        if let Some(ce) = self.ce_threshold_us {
            w.pair("ce_threshold", codel(ce));
        }
        if let Some(mem) = self.memory_limit {
            w.pair("memory_limit", mem);
        }
        w.push(if self.ecn { "ecn" } else { "noecn" });
        if let Some(batch) = self.drop_batch_size
            && batch != FQ_CODEL_DROP_BATCH
        {
            w.pair("drop_batch", batch);
        }
        w.fmt(f)
    }
}

impl Display for FqPieOptions {
    /// fq_pie as tc(8) takes it. The target lands on the kernel's 64 ns
    /// ticks; `tupdate` is kept in jiffies and reported exactly.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut w = Words::new();
        w.pair("limit", self.limit);
        w.pair("flows", self.flows);
        w.pair("target", micros(quantised_us(self.target_us, 6)));
        w.pair("tupdate", micros(self.tupdate_us));
        w.pair("alpha", self.alpha);
        w.pair("beta", self.beta);
        w.pair("quantum", self.quantum);
        w.pair("memory_limit", self.memory_limit);
        w.pair("ecn_prob", self.ecn_prob_percent);
        w.push(if self.ecn { "ecn" } else { "noecn" });
        w.push(if self.bytemode {
            "bytemode"
        } else {
            "nobytemode"
        });
        w.push(if self.dq_rate_estimator {
            "dq_rate_estimator"
        } else {
            "no_dq_rate_estimator"
        });
        w.fmt(f)
    }
}

/// The smallest bucket, in bytes, that the kernel keeps as the same
/// transmission time at `rate` as the one reported as `reported` bytes.
fn tbf_bucket(rate: u64, reported: u32) -> u32 {
    use super::psched::tbf_bucket_round_trip;
    if rate == 0 || tbf_bucket_round_trip(rate, reported) == reported {
        return reported;
    }
    // One psched tick (64 ns) is this many bytes at `rate`; the bucket
    // that reads back as `reported` is within a couple of them above it.
    let per_tick = (rate * 64).div_ceil(1_000_000_000);
    let span = u32::try_from(per_tick.saturating_mul(4).saturating_add(16)).unwrap_or(1 << 16);
    (reported..=reported.saturating_add(span.min(1 << 16)))
        .find(|&b| tbf_bucket_round_trip(rate, b) == reported)
        .unwrap_or(reported)
}

impl Display for TbfOptions {
    /// tbf as tc(8) takes it. The buckets print as the smallest size the
    /// kernel keeps as the same transmission time: it reports a bucket only
    /// as ticks, which read back a few bytes short (32768 at 10 gbit reads
    /// as 32719). `mtu` prints only with a peak rate, which it belongs to.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut w = Words::new();
        w.pair("rate", Rate::bytes_per_sec(self.rate));
        w.pair("burst", tbf_bucket(self.rate, self.burst));
        w.pair("limit", self.limit);
        if self.peakrate > 0 {
            w.pair("peakrate", Rate::bytes_per_sec(self.peakrate));
            w.pair("mtu", tbf_bucket(self.peakrate, self.mtu));
        }
        w.fmt(f)
    }
}

impl Display for HtbOptions {
    /// htb as tc(8) takes it: the default class as a hex minor, which is
    /// how tc reads `default`.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut w = Words::new();
        w.pair("default", format_args!("{:x}", self.default_class));
        w.pair("r2q", self.rate2quantum);
        if let Some(qlen) = self.direct_qlen {
            w.pair("direct_qlen", qlen);
        }
        w.fmt(f)
    }
}

impl Display for PrioOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "bands {} priomap", self.bands)?;
        for band in self.priomap {
            write!(f, " {band}")?;
        }
        Ok(())
    }
}

/// sfq's kernel defaults (`sfq_init`): a limit of `SFQ_MAX_DEPTH`
/// packets, `SFQ_DEFAULT_FLOWS` flows, `SFQ_DEFAULT_HASH_DIVISOR` buckets.
const SFQ_LIMIT: u32 = 127;
const SFQ_FLOWS: u32 = 128;
const SFQ_DIVISOR: u32 = 1024;
const SFQ_DEPTH: u32 = 127;

impl Display for SfqOptions {
    /// sfq as tc(8) takes it.
    ///
    /// A limit caps the number of flows (`sfq_change`), so the kernel's
    /// default pair — limit 127, 128 flows — prints as no limit at all, and
    /// `flows` prints only when it is not what the limit leaves. `flows`,
    /// `depth`, `divisor` and `headdrop` print only away from the kernel's
    /// defaults, which is all `SfqConfig` can install.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut w = Words::new();
        let flows_left = if (self.limit, self.flows) == (SFQ_LIMIT, SFQ_FLOWS) {
            SFQ_FLOWS
        } else {
            w.pair("limit", self.limit);
            SFQ_FLOWS.min(self.limit)
        };
        w.pair("quantum", self.quantum);
        if self.perturb_period != 0 {
            w.pair("perturb", self.perturb_period);
        }
        if let Some(depth) = self.depth
            && depth != SFQ_DEPTH
        {
            w.pair("depth", depth);
        }
        if self.divisor != SFQ_DIVISOR {
            w.pair("divisor", self.divisor);
        }
        if self.flows != flows_left {
            w.pair("flows", self.flows);
        }
        if self.headdrop == Some(true) {
            w.push("headdrop");
        }
        w.fmt(f)
    }
}

impl Display for CakeOptions {
    /// cake as tc(8) takes it. `target` prints only when it is not the
    /// twentieth of the RTT that tc's `rtt` sends with it; tc has no
    /// `target` of its own, which `CakeConfig::parse_params` does.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use super::types::tc::qdisc::cake::*;
        let mut w = Words::new();
        if self.bandwidth_bps > 0 {
            w.pair("bandwidth", Rate::bytes_per_sec(self.bandwidth_bps));
        } else {
            w.push("unlimited");
        }
        if self.autorate {
            w.push("autorate-ingress");
        }
        w.pair("rtt", micros(self.rtt_us));
        if self.target_us != (self.rtt_us / 20).max(1) {
            w.pair("target", micros(self.target_us));
        }
        w.push(match self.diffserv_mode {
            CAKE_DIFFSERV_DIFFSERV4 => "diffserv4",
            CAKE_DIFFSERV_DIFFSERV8 => "diffserv8",
            CAKE_DIFFSERV_BESTEFFORT => "besteffort",
            CAKE_DIFFSERV_PRECEDENCE => "precedence",
            _ => "diffserv3",
        });
        w.push(match self.flow_mode {
            CAKE_FLOW_NONE => "flowblind",
            CAKE_FLOW_SRC_IP => "srchost",
            CAKE_FLOW_DST_IP => "dsthost",
            CAKE_FLOW_HOSTS => "hosts",
            CAKE_FLOW_FLOWS => "flows",
            CAKE_FLOW_DUAL_SRC => "dual-srchost",
            CAKE_FLOW_DUAL_DST => "dual-dsthost",
            _ => "triple-isolate",
        });
        w.push(if self.nat { "nat" } else { "nonat" });
        w.push(if self.wash { "wash" } else { "nowash" });
        w.push(if self.ingress { "ingress" } else { "egress" });
        w.push(if self.split_gso {
            "split-gso"
        } else {
            "no-split-gso"
        });
        w.push(match self.ack_filter {
            CAKE_ACK_FILTER => "ack-filter",
            CAKE_ACK_AGGRESSIVE => "ack-filter-aggressive",
            _ => "no-ack-filter",
        });
        // `raw` before the ATM mode: tc's `raw` resets it, as its own
        // output order (`raw atm overhead 0`) has it.
        if self.raw {
            w.push("raw");
        } else {
            w.pair("overhead", self.overhead);
        }
        w.push(match self.atm_mode {
            CAKE_ATM_ATM => "atm",
            CAKE_ATM_PTM => "ptm",
            _ => "noatm",
        });
        if self.mpu != 0 {
            w.pair("mpu", self.mpu);
        }
        if self.memory_limit != 0 {
            w.pair("memlimit", self.memory_limit);
        }
        if self.fwmark != 0 {
            let mut mark = String::new();
            let _ = write!(mark, "{:#x}", self.fwmark);
            w.pair("fwmark", mark);
        }
        w.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{
        builder::MessageBuilder,
        messages::TcMessage,
        tc::{NetemConfig, NetemSlot, QdiscConfig},
    };

    /// What `write_options` puts in `TCA_OPTIONS`.
    fn written(cfg: &impl QdiscConfig) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write_options(&mut b).unwrap();
        b.as_bytes()[start..].to_vec()
    }

    fn netem_options(cfg: &NetemConfig) -> NetemOptions {
        let msg = TcMessage {
            kind: Some("netem".into()),
            options: Some(written(cfg)),
            ..TcMessage::default()
        };
        match msg.options() {
            Some(QdiscOptions::Netem(o)) => o,
            other => panic!("not netem: {other:?}"),
        }
    }

    fn full_netem() -> NetemConfig {
        let ms = Duration::from_millis;
        NetemConfig::new()
            .delay(ms(10))
            .jitter(ms(2))
            .delay_correlation(Percent::new(25.0))
            .loss(Percent::new(1.2))
            .loss_correlation(Percent::new(10.0))
            .duplicate(Percent::new(0.3))
            .corrupt(Percent::new(0.1))
            .reorder(Percent::new(5.0))
            .reorder_correlation(Percent::new(50.0))
            .gap(3)
            .rate(Rate::mbit(1))
            .rate_overhead(20, 53, 5)
            .limit(crate::util::Packets::new(500))
            .ecn(true)
            .slot(NetemSlot::new(ms(1), ms(2)).packets(crate::util::Packets::new(5)).bytes(3000))
            .seed(42)
    }

    /// A netem with every field set, and the two loss models: written,
    /// read, printed, parsed and written again, the bytes are the same.
    /// So are they through `NetemConfig::from`.
    #[test]
    fn netem_text_and_from_reinstall_the_same_netem() {
        let ge = NetemLossModel::gilbert_elliot(Percent::new(1.0))
            .r(Percent::new(30.0))
            .loss_in_bad(Percent::new(50.0))
            .loss_in_good(Percent::new(0.1));
        let gi = NetemLossModel::gilbert_intuitive(Percent::new(1.0))
            .p31(Percent::new(2.0))
            .p32(Percent::new(3.0))
            .p23(Percent::new(4.0))
            .p14(Percent::new(5.0));
        let mut no_loss = full_netem();
        no_loss.loss = Percent::ZERO;
        no_loss.loss_correlation = Percent::ZERO;
        for cfg in [
            full_netem(),
            no_loss.clone().loss_model(ge),
            no_loss.loss_model(gi),
            NetemConfig::new(),
            NetemConfig::new().delay(Duration::from_micros(1500)),
        ] {
            let opts = netem_options(&cfg);
            let text = opts.to_string();
            let tokens: Vec<&str> = text.split_whitespace().collect();
            let parsed = NetemConfig::parse_params(&tokens)
                .unwrap_or_else(|e| panic!("`{text}` does not parse: {e}"));
            assert_eq!(written(&parsed), written(&cfg), "through `{text}`");
            assert_eq!(
                written(&NetemConfig::from(&opts)),
                written(&cfg),
                "through From"
            );
        }
        assert_eq!(
            netem_options(&full_netem()).to_string(),
            "limit 500 delay 10ms 2ms 25% loss 1.2% 10% duplicate 0.3% reorder 5% 50% gap 3 \
             corrupt 0.1% rate 1mbit 20 53 5 slot 1ms 2ms packets 5 bytes 3000 ecn seed 42"
        );
    }

    #[test]
    fn times_read_back_exactly() {
        for (d, text) in [
            (Duration::from_millis(10), "10ms"),
            (Duration::from_secs(2), "2s"),
            (Duration::from_micros(1500), "1500us"),
            (Duration::from_nanos(1_499_968), "1499.968us"),
            (Duration::from_nanos(1_000_001), "1000.001us"),
            (Duration::ZERO, "0s"),
        ] {
            assert_eq!(time(d), text);
            assert_eq!(crate::util::parse::get_time(text).unwrap(), d);
        }
        // Whatever the value, the text reads back exactly.
        for ns in (0..5_000_000u64)
            .step_by(4_093)
            .chain([u64::from(u32::MAX) * 64])
        {
            let d = Duration::from_nanos(ns);
            assert_eq!(
                crate::util::parse::get_time(&time(d)).unwrap(),
                d,
                "{ns} ns"
            );
        }
    }

    /// Whatever was sent, the printed time is reported as the same value,
    /// and is no larger than what was sent.
    #[test]
    fn quantised_times_are_reported_the_same() {
        for shift in [6, 10] {
            for sent in (0..200_000u32)
                .step_by(7)
                .chain([5_000, 15_000, 20_000, 100_000])
            {
                let reported = reported_us(sent, shift);
                let printed = quantised_us(reported, shift);
                assert_eq!(
                    reported_us(printed, shift),
                    reported,
                    "shift {shift}, sent {sent}"
                );
                assert!(printed <= sent, "not the smallest: {printed} for {sent}");
            }
        }
        assert_eq!(reported_us(20_000, 10), 19_999);
        assert_eq!(quantised_us(19_999, 10), 20_000);
        assert_eq!(quantised_us(4_999, 10), 5_000);
    }

    #[test]
    fn percentages_are_short_and_exact() {
        for (pct, text) in [
            (1.0, "1%"),
            (1.2, "1.2%"),
            (0.3, "0.3%"),
            (33.333333, "33.333333%"),
        ] {
            let raw = Percent::new(pct).as_kernel_probability();
            let read = f64::from(raw) / f64::from(u32::MAX) * 100.0;
            assert_eq!(percent(read), text);
        }
        // 1-h for Gilbert-Elliot: h is 70 % delivered, so 30 % lost.
        let raw = Percent::new(70.0).as_kernel_probability();
        let h = f64::from(raw) / f64::from(u32::MAX) * 100.0;
        assert_eq!(complement(h), "30%");
    }
}
