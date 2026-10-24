//! Packet-scheduler clock (`psched`) — tick conversion for TC rate specs.
//!
//! Several TC wire fields that *look* like byte counts or microsecond
//! durations are actually **psched ticks**:
//!
//! | field | struct | kernel reads it as |
//! |---|---|---|
//! | `buffer` / `mtu` | `tc_tbf_qopt` | ticks |
//! | `buffer` / `cbuffer` | `tc_htb_opt` | ticks |
//! | `burst` | `tc_police` | ticks |
//!
//! One tick is `1 << PSCHED_SHIFT` nanoseconds (`PSCHED_SHIFT = 6`, so
//! 64 ns), giving 15.625 ticks per microsecond. Writing a raw byte count
//! or a microsecond value into any of those fields mis-programs the token
//! bucket by that factor — see the `sch_tbf.c` / `sch_htb.c` /
//! `act_police.c` conversions, all of which run the value through
//! `PSCHED_TICKS2NS()`.
//!
//! This module is the nlink equivalent of iproute2's `tc_core.c`, and
//! every TC encoder that touches a time-valued scheduler field must route
//! through it.
//!
//! # Why `/proc/net/psched` is read from library code
//!
//! The four values come from the kernel's `psched_show()` and derive from
//! the compile-time `PSCHED_SHIFT` and `HZ` — they are **global kernel
//! constants, identical in every network namespace**. Reading them through
//! the calling process's mount namespace is therefore not a
//! namespace-correctness hazard, unlike `/sys/class/net/` (per-netns device
//! state) or `/proc/sys/` (per-netns sysctls). The read happens at most once
//! per process (see [`psched`]), and falls back to [`Psched::MODERN`] — the
//! same constants — when the file is unreadable. `psched.rs` is listed in
//! `scripts/audit-sysfs-in-lib.sh`'s `ALLOWED` for exactly this reason.

use std::sync::LazyLock;

use super::types::tc::qdisc::TcRateSpec;

/// Microseconds per second — iproute2's `TIME_UNITS_PER_SEC`.
const TIME_UNITS_PER_SEC: f64 = 1_000_000.0;

/// Size of a TC rate table on the wire. The kernel's `qdisc_get_rtab()`
/// requires `nla_len(tab) == 1024` exactly (256 × `u32`).
pub const TC_RTAB_SIZE: usize = 1024;

/// Number of entries in a TC rate table.
const TC_RTAB_ENTRIES: usize = TC_RTAB_SIZE / 4;

/// Link layer a rate table is computed for.
///
/// Mirrors the kernel's `TC_LINKLAYER_*`. ATM rounds each packet up to a
/// whole number of 53-byte cells carrying 48 bytes of payload, which
/// materially changes the rate table for small packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum LinkLayer {
    /// `TC_LINKLAYER_UNAWARE` — no adjustment (kernel default).
    Unaware = 0,
    /// `TC_LINKLAYER_ETHERNET` — no size adjustment, but the kernel knows.
    #[default]
    Ethernet = 1,
    /// `TC_LINKLAYER_ATM` — round up to whole ATM cells.
    Atm = 2,
}

/// Packet-scheduler clock parameters, as published by `/proc/net/psched`.
///
/// Obtain the running kernel's values with [`psched`]. The struct is
/// `Copy` and every conversion on it is pure, so tests can construct one
/// with [`Psched::from_fields`] without touching the filesystem.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Psched {
    /// Psched ticks per microsecond. 15.625 on every kernel since 2.6.x.
    pub tick_in_usec: f64,
    /// `clock_res / 1e6` — iproute2's `clock_factor`.
    pub clock_factor: f64,
    /// iproute2's `get_hz()`. 1e9 on modern kernels.
    pub hz: u64,
}

impl Psched {
    /// The modern-kernel constants (`PSCHED_SHIFT = 6`, nanosecond clock).
    ///
    /// Used as the fallback when `/proc/net/psched` cannot be read — a
    /// hidden `/proc`, a seccomp filter, or a non-Linux test host. These
    /// are the values every kernel since 2.6 reports, so the fallback is
    /// correct rather than merely safe.
    pub const MODERN: Psched = Psched {
        tick_in_usec: 15.625,
        clock_factor: 1.0,
        hz: 1_000_000_000,
    };

    /// Derive the parameters from the four `%08x` fields the kernel's
    /// `psched_show()` prints, reproducing iproute2's `tc_core_init()`.
    pub fn from_fields(t2us: u32, us2t: u32, clock_res: u32, nsec_per_sec: u32) -> Option<Self> {
        if us2t == 0 || clock_res == 0 {
            return None;
        }

        // iproute2 tc_core_init(): a nanosecond clock reports
        // clock_res == 1e9, in which case t2us is really us2t.
        let t2us = if clock_res == 1_000_000_000 {
            us2t
        } else {
            t2us
        };

        let clock_factor = f64::from(clock_res) / TIME_UNITS_PER_SEC;
        let tick_in_usec = (f64::from(t2us) / f64::from(us2t)) * clock_factor;

        // iproute2 __get_hz(): fields 3 and 4 of /proc/net/psched.
        let hz = if clock_res == 1_000_000 {
            u64::from(nsec_per_sec)
        } else {
            Self::MODERN.hz
        };

        if !tick_in_usec.is_finite() || tick_in_usec <= 0.0 || hz == 0 {
            return None;
        }

        Some(Self {
            tick_in_usec,
            clock_factor,
            hz,
        })
    }

    /// Parse the contents of `/proc/net/psched`. `None` if malformed.
    pub fn parse(contents: &str) -> Option<Self> {
        let mut fields = contents.split_whitespace();
        let mut next = || u32::from_str_radix(fields.next()?, 16).ok();
        let (t2us, us2t, clock_res, nsec_per_sec) = (next()?, next()?, next()?, next()?);
        Self::from_fields(t2us, us2t, clock_res, nsec_per_sec)
    }

    /// Convert a duration in microseconds to psched ticks.
    pub fn time2tick(&self, time_us: f64) -> u32 {
        saturate_u32(time_us * self.tick_in_usec)
    }

    /// Convert psched ticks to a duration in microseconds.
    pub fn tick2time(&self, ticks: u32) -> f64 {
        f64::from(ticks) / self.tick_in_usec
    }

    /// Ticks taken to transmit `size_bytes` at `rate_bytes_per_sec`.
    ///
    /// iproute2's `tc_calc_xmittime()`. This is the conversion the kernel
    /// expects for `tc_tbf_qopt.buffer`, `tc_htb_opt.buffer` and
    /// `tc_police.burst`. A zero rate yields 0 rather than dividing by zero.
    pub fn calc_xmittime(&self, rate_bytes_per_sec: u64, size_bytes: u32) -> u32 {
        if rate_bytes_per_sec == 0 {
            return 0;
        }
        let secs = f64::from(size_bytes) / (rate_bytes_per_sec as f64);
        self.time2tick(TIME_UNITS_PER_SEC * secs)
    }

    /// Bytes transmitted at `rate_bytes_per_sec` in `ticks`.
    ///
    /// iproute2's `tc_calc_xmitsize()` — the inverse of [`calc_xmittime`],
    /// used to turn a tick-valued burst read back from the kernel into the
    /// byte count the user actually cares about.
    ///
    /// [`calc_xmittime`]: Self::calc_xmittime
    pub fn calc_xmitsize(&self, rate_bytes_per_sec: u64, ticks: u32) -> u32 {
        saturate_u32((rate_bytes_per_sec as f64) * self.tick2time(ticks) / TIME_UNITS_PER_SEC)
    }

    /// Build a TC rate table and stamp the matching fields into `spec`.
    ///
    /// iproute2's `tc_calc_rtable()`. Returns the 1024-byte table for
    /// `TCA_TBF_RTAB` / `TCA_HTB_RTAB` / `TCA_POLICE_RATE`, and writes
    /// `cell_log`, `linklayer` and `cell_align` back into `spec`.
    ///
    /// Taking `&mut TcRateSpec` (rather than returning the `cell_log` for
    /// the caller to apply) is deliberate: a table whose `cell_log`
    /// disagrees with its spec is silently discarded by the kernel's
    /// `qdisc_get_rtab()`, which is precisely the bug this replaces. The
    /// two cannot drift apart if they are produced together.
    pub fn calc_rtable(
        &self,
        spec: &mut TcRateSpec,
        rate_bytes_per_sec: u64,
        mtu: u32,
        linklayer: LinkLayer,
    ) -> [u8; TC_RTAB_SIZE] {
        let mtu = if mtu == 0 { 2047 } else { mtu };

        // Grow the cell size until the whole MTU is addressable by the
        // 256-entry table.
        let mut cell_log: u8 = 0;
        while (mtu >> cell_log) > (TC_RTAB_ENTRIES as u32 - 1) {
            cell_log += 1;
        }

        let mut table = [0u8; TC_RTAB_SIZE];
        for (i, entry) in table.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let size = adjust_size((i as u32 + 1) << cell_log, spec.mpu, linklayer);
            let ticks = self.calc_xmittime(rate_bytes_per_sec, size);
            *entry = ticks.to_ne_bytes();
        }

        spec.cell_log = cell_log;
        spec.cell_align = -1;
        spec.linklayer = linklayer as u8 & 0x0F;

        table
    }
}

/// Adjust a packet size for the link layer, as iproute2's `adjust_size()`.
fn adjust_size(size: u32, mpu: u16, linklayer: LinkLayer) -> u32 {
    let size = size.max(u32::from(mpu));
    match linklayer {
        LinkLayer::Atm => {
            // Round up to whole 53-byte cells carrying 48 payload bytes.
            size.div_ceil(48) * 53
        }
        LinkLayer::Ethernet | LinkLayer::Unaware => size,
    }
}

/// Clamp an `f64` into `u32`, mapping negatives and NaN to 0.
fn saturate_u32(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        0
    } else if v >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        v as u32
    }
}

static PSCHED: LazyLock<Psched> = LazyLock::new(|| {
    std::fs::read_to_string("/proc/net/psched")
        .ok()
        .and_then(|s| Psched::parse(&s))
        .unwrap_or(Psched::MODERN)
});

/// The running kernel's psched parameters, read once and cached.
///
/// Falls back to [`Psched::MODERN`] if `/proc/net/psched` is unreadable.
pub fn psched() -> Psched {
    *PSCHED
}

/// Psched ticks per microsecond on the running kernel (15.625).
pub fn tick_in_usec() -> f64 {
    psched().tick_in_usec
}

/// iproute2's `get_hz()` — 1e9 on modern kernels.
pub fn hz() -> u64 {
    psched().hz
}

/// [`Psched::calc_xmittime`] against the running kernel's clock.
pub fn tc_calc_xmittime(rate_bytes_per_sec: u64, size_bytes: u32) -> u32 {
    psched().calc_xmittime(rate_bytes_per_sec, size_bytes)
}

/// [`Psched::calc_xmitsize`] against the running kernel's clock.
pub fn tc_calc_xmitsize(rate_bytes_per_sec: u64, ticks: u32) -> u32 {
    psched().calc_xmitsize(rate_bytes_per_sec, ticks)
}

/// `PSCHED_SHIFT` (`include/net/pkt_sched.h`): one psched tick is
/// `1 << 6` ns, and `PSCHED_NS2TICKS(x)` is `x >> 6`.
pub(crate) const PSCHED_SHIFT: u32 = 6;

/// The kernel's `psched_ratecfg_precompute__()` (net/sched/sch_generic.c):
/// the multiplier and shift `psched_l2t_ns()` turns a length into
/// nanoseconds with at `rate_bytes_per_sec`.
///
/// ```c
/// u64 factor = NSEC_PER_SEC;
/// *mult = 1; *shift = 0;
/// if (rate <= 0) return;
/// for (;;) {
///         *mult = div64_u64(factor, rate);
///         if (*mult & (1U << 31) || factor & (1ULL << 63))
///                 break;
///         factor <<= 1;
///         (*shift)++;
/// }
/// ```
fn kernel_ratecfg(rate_bytes_per_sec: u64) -> (u32, u32) {
    if rate_bytes_per_sec == 0 {
        return (1, 0);
    }
    let mut factor: u64 = 1_000_000_000;
    let mut shift = 0;
    loop {
        // `*mult` is a u32; factor / rate starts below 2^32 (factor is
        // 1e9) and doubles per step, so it reaches bit 31 before it could
        // overflow.
        let mult = (factor / rate_bytes_per_sec) as u32;
        if mult & (1 << 31) != 0 || factor & (1 << 63) != 0 {
            return (mult, shift);
        }
        factor <<= 1;
        shift += 1;
    }
}

/// A rate's framing: the overhead added to each packet, the least size it
/// is charged as, and its link layer (#806).
pub(crate) type Framing = (u16, u16, LinkLayer);

/// No framing: what nlink wrote before #806.
pub(crate) const UNFRAMED: Framing = (0, 0, LinkLayer::Ethernet);

/// The kernel's `psched_l2t_ns()`: nanoseconds to send `len` bytes at
/// `rate_bytes_per_sec`, the overhead added, raised to the mpu, and for
/// ATM rounded up to whole 53-byte cells of 48 (#806).
fn kernel_l2t_ns(rate_bytes_per_sec: u64, len: u32, (overhead, mpu, linklayer): Framing) -> u64 {
    let (mult, shift) = kernel_ratecfg(rate_bytes_per_sec);
    let len = (u64::from(len) + u64::from(overhead)).max(u64::from(mpu));
    let len = if linklayer == LinkLayer::Atm { len.div_ceil(48) * 53 } else { len };
    (len * u64::from(mult)) >> shift
}

/// The byte count a TBF bucket handed to the kernel in **bytes** reads
/// back as.
///
/// `tbf_change()` turns the byte-valued `TCA_TBF_BURST` (and
/// `TCA_TBF_PBURST`) into nanoseconds with `psched_l2t_ns()` and keeps
/// only that; `tbf_dump()` echoes it as `PSCHED_NS2TICKS()` in the u32
/// `tc_tbf_qopt.buffer` / `.mtu` and never sends the byte attributes back.
/// So the bytes a dump yields are `tc_calc_xmitsize()` of that tick count
/// — exactly what `parse_tbf_options` computes — and they differ from the
/// declared bytes at most rates (32768 at 10 gbit reads back as 32719).
/// Comparing a declared bucket against the dump has to go through the
/// same round trip.
pub(crate) fn tbf_bucket_round_trip(rate_bytes_per_sec: u64, bytes: u32) -> u32 {
    tbf_bucket_round_trip_framed(rate_bytes_per_sec, bytes, UNFRAMED)
}

/// [`tbf_bucket_round_trip`] for a rate with framing, which the kernel
/// charges each packet with (#806).
pub(crate) fn tbf_bucket_round_trip_framed(rate_bytes_per_sec: u64, bytes: u32, framing: Framing) -> u32 {
    // `opt.buffer = PSCHED_NS2TICKS(q->buffer)` assigns into a __u32.
    let ticks = (kernel_l2t_ns(rate_bytes_per_sec, bytes, framing) >> PSCHED_SHIFT) as u32;
    tc_calc_xmitsize(rate_bytes_per_sec, ticks)
}

/// The bytes to send for a bucket a dump reads as `dumped`, so that it
/// reads as `dumped` again: the inverse of
/// [`tbf_bucket_round_trip_framed`] (#806). Framing makes the dumped bytes
/// the framed size, so the overhead comes off and ATM cells go back to
/// their payload; the largest such byte count is taken, near the estimate.
pub(crate) fn tbf_bucket_declared(rate_bytes_per_sec: u64, dumped: u32, framing: Framing) -> u32 {
    if framing == UNFRAMED || rate_bytes_per_sec == 0 {
        return dumped;
    }
    let (overhead, _, linklayer) = framing;
    let payload = if linklayer == LinkLayer::Atm { dumped / 53 * 48 } else { dumped };
    let estimate = payload.saturating_sub(u32::from(overhead));
    (estimate.saturating_sub(256)..=estimate.saturating_add(256))
        .rev()
        .find(|b| tbf_bucket_round_trip_framed(rate_bytes_per_sec, *b, framing) == dumped)
        .unwrap_or(estimate)
}

/// [`Psched::calc_rtable`] against the running kernel's clock.
pub fn tc_calc_rtable(
    spec: &mut TcRateSpec,
    rate_bytes_per_sec: u64,
    mtu: u32,
    linklayer: LinkLayer,
) -> [u8; TC_RTAB_SIZE] {
    psched().calc_rtable(spec, rate_bytes_per_sec, mtu, linklayer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values every modern kernel prints.
    fn modern() -> Psched {
        Psched::from_fields(1000, 64, 1_000_000, 1_000_000_000).unwrap()
    }

    #[test]
    fn from_fields_matches_the_modern_constants() {
        let p = modern();
        assert_eq!(p.tick_in_usec, 15.625);
        assert_eq!(p.clock_factor, 1.0);
        assert_eq!(p.hz, 1_000_000_000);
        assert_eq!(p, Psched::MODERN);
    }

    #[test]
    fn parse_reads_the_proc_format() {
        // Exactly what /proc/net/psched contains on a 6.x kernel.
        let p = Psched::parse("000003e8 00000040 000f4240 3b9aca00\n").unwrap();
        assert_eq!(p, Psched::MODERN);
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert!(Psched::parse("").is_none());
        assert!(Psched::parse("000003e8 00000040").is_none());
        assert!(Psched::parse("zzz 00000040 000f4240 3b9aca00").is_none());
        // us2t == 0 would divide by zero.
        assert!(Psched::parse("000003e8 00000000 000f4240 3b9aca00").is_none());
    }

    /// A nanosecond clock reports clock_res == 1e9, and iproute2 then
    /// takes t2us from us2t.
    #[test]
    fn from_fields_handles_a_nanosecond_clock() {
        let p = Psched::from_fields(1, 64, 1_000_000_000, 1_000_000_000).unwrap();
        assert_eq!(p.tick_in_usec, 1000.0);
        assert_eq!(p.hz, Psched::MODERN.hz);
    }

    /// The anchor number for the whole psched fix. 32 KiB at 1 mbit:
    ///
    ///   32768 B / 125000 B/s = 0.262144 s = 262_144 us
    ///   262_144 us * 15.625 ticks/us = 4_096_000 ticks
    ///
    /// Cross-check in the nanosecond domain: 262_144_000 ns >> 6 (one tick
    /// is 64 ns) = 4_096_000.
    #[test]
    fn calc_xmittime_tbf_anchor() {
        let p = modern();
        assert_eq!(p.calc_xmittime(125_000, 32_768), 4_096_000);
        assert_eq!(262_144_000u32 >> 6, 4_096_000);
    }

    #[test]
    fn calc_xmittime_and_xmitsize_round_trip() {
        let p = modern();
        for &(rate, size) in &[
            (125_000u64, 32_768u32),
            (12_500_000, 1_600),
            (1_250_000_000, 1_514),
            (1_250, 64),
        ] {
            let ticks = p.calc_xmittime(rate, size);
            let back = p.calc_xmitsize(rate, ticks);
            // Tick quantization costs at most one tick's worth of bytes.
            let slack = (rate as f64 / p.tick_in_usec / TIME_UNITS_PER_SEC).ceil() as u32 + 1;
            assert!(
                back.abs_diff(size) <= slack,
                "rate={rate} size={size} ticks={ticks} back={back} slack={slack}",
            );
        }
    }

    /// `psched_ratecfg_precompute__()` worked by hand for 2 gbit
    /// (250_000_000 B/s): 1e9 / 2.5e8 = 4, doubled 29 times to 2^31.
    #[test]
    fn kernel_ratecfg_matches_the_kernel_loop() {
        assert_eq!(kernel_ratecfg(250_000_000), (1 << 31, 29));
        // 10 gbit: 1e9 << 32 / 1.25e9 = 3_435_973_836 (bit 31 set).
        assert_eq!(kernel_ratecfg(1_250_000_000), (3_435_973_836, 32));
        assert_eq!(kernel_ratecfg(0), (1, 0));
        // 1514 bytes at 2 gbit: 1514 * 2^31 >> 29 = 6056 ns.
        assert_eq!(kernel_l2t_ns(250_000_000, 1514, UNFRAMED), 6056);
    }

    /// The values a live 6.12 kernel dumped for buckets nlink sent in
    /// bytes (#TBD). At 1 mbit the round trip is exact, which is why a
    /// 1 mbit-only test never saw the drift.
    #[test]
    fn tbf_bucket_round_trip_matches_the_kernel_dump() {
        for &(rate, bytes, dumped) in &[
            (125_000u64, 32_768u32, 32_768u32),
            (375_000, 32_768, 32_767),
            (375_000, 10_000, 9_999),
            (64_000, 10_000, 9_999),
            (1_250_000_000, 32_768, 32_719),
            (1_250_000_000, 10_000, 9_920),
            (250_000_000, 1_514, 1_504),
        ] {
            assert_eq!(
                tbf_bucket_round_trip(rate, bytes),
                dumped,
                "rate={rate} bytes={bytes}"
            );
        }
    }

    #[test]
    fn calc_xmittime_zero_rate_does_not_divide_by_zero() {
        assert_eq!(modern().calc_xmittime(0, 1_500), 0);
        assert_eq!(modern().calc_xmitsize(0, 1_500), 0);
    }

    /// cell_log must be large enough that the 256-entry table spans the
    /// whole MTU, and it must be stamped back into the spec — a table
    /// whose spec says cell_log == 0 is discarded by qdisc_get_rtab().
    #[test]
    fn calc_rtable_picks_cell_log_and_stamps_the_spec() {
        let p = modern();
        let mut spec = TcRateSpec::new(125_000);
        let table = p.calc_rtable(&mut spec, 125_000, 1514, LinkLayer::Ethernet);

        assert_eq!(table.len(), TC_RTAB_SIZE);
        // 1514 >> 3 == 189, which fits in 256 entries; 1514 >> 2 == 378 does not.
        assert_eq!(spec.cell_log, 3);
        assert_eq!(spec.cell_align, -1);
        assert_eq!(spec.linklayer, LinkLayer::Ethernet as u8);

        // Entry 0 covers 8 bytes: 8/125000 s = 64 us -> 64 * 15.625 = 1000 ticks.
        assert_eq!(u32::from_ne_bytes(table[0..4].try_into().unwrap()), 1_000);
        // Entry 255 covers 2048 bytes: 16_384 us -> 256_000 ticks.
        assert_eq!(
            u32::from_ne_bytes(table[1020..1024].try_into().unwrap()),
            256_000
        );
    }

    #[test]
    fn calc_rtable_cell_log_grows_with_mtu() {
        let p = modern();
        for &(mtu, expected) in &[(255u32, 0u8), (256, 1), (511, 1), (512, 2), (9000, 6)] {
            let mut spec = TcRateSpec::new(125_000);
            p.calc_rtable(&mut spec, 125_000, mtu, LinkLayer::Ethernet);
            assert_eq!(spec.cell_log, expected, "mtu={mtu}");
            assert!(
                (mtu >> spec.cell_log) <= 255,
                "mtu={mtu} does not fit 256 entries at cell_log={}",
                spec.cell_log
            );
        }
    }

    /// ATM rounds each packet up to whole 53-byte cells of 48 payload bytes,
    /// so a 1-cell packet costs 53 bytes of wire time, not 48.
    #[test]
    fn calc_rtable_atm_rounds_up_to_cells() {
        assert_eq!(adjust_size(48, 0, LinkLayer::Atm), 53);
        assert_eq!(adjust_size(49, 0, LinkLayer::Atm), 106);
        assert_eq!(adjust_size(96, 0, LinkLayer::Atm), 106);
        assert_eq!(adjust_size(96, 0, LinkLayer::Ethernet), 96);
    }

    /// mpu is a floor on the billed size — a packet smaller than the
    /// minimum policed unit still costs mpu bytes of wire time.
    #[test]
    fn adjust_size_honors_mpu() {
        assert_eq!(adjust_size(8, 64, LinkLayer::Ethernet), 64);
        assert_eq!(adjust_size(128, 64, LinkLayer::Ethernet), 128);
    }

    #[test]
    fn saturate_u32_clamps_instead_of_wrapping() {
        assert_eq!(saturate_u32(-1.0), 0);
        assert_eq!(saturate_u32(f64::NAN), 0);
        assert_eq!(saturate_u32(1e30), u32::MAX);
        assert_eq!(saturate_u32(42.9), 42);
    }
}
