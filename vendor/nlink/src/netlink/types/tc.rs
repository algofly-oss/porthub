//! Traffic control message types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::netlink::error::{Error, Result};

/// Traffic control message (struct tcmsg).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TcMsg {
    /// Address family.
    pub tcm_family: u8,
    /// Padding.
    pub tcm_pad1: u8,
    /// Padding.
    pub tcm_pad2: u16,
    /// Interface index.
    pub tcm_ifindex: i32,
    /// Qdisc handle.
    pub tcm_handle: u32,
    /// Parent qdisc.
    pub tcm_parent: u32,
    /// Info (depends on message type).
    pub tcm_info: u32,
}

/// `struct tcamsg` — the fixed header of a **standalone action**
/// message (`RTM_{NEW,DEL,GET}ACTION`).
///
/// Four bytes, not the twenty of [`TcMsg`]. The action API is the one
/// TC surface that does not use `tcmsg`, and `tc_ctl_action` parses
/// attributes from `sizeof(struct tcamsg)` onward:
///
/// ```c
/// ret = nlmsg_parse_deprecated(n, sizeof(struct tcamsg), tca, TCA_ROOT_MAX, ...);
/// if (tca[TCA_ACT_TAB] == NULL) {
///         NL_SET_ERR_MSG(extack, "Netlink action attributes missing");
///         return -EINVAL;
/// }
/// ```
///
/// Sending a 20-byte `tcmsg` meant the kernel skipped 4 and read the
/// remaining 16 as the start of the attribute chain — so it never found
/// `TCA_ACT_TAB` and refused every standalone action with exactly that
/// message. Measured on 6.12.105:
///
/// ```text
/// header=20B: errno=-22  "Netlink action attributes missing"
/// header=4B:  errno=-22  (gets past the check, fails on the payload)
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TcaMsg {
    /// Address family.
    pub tca_family: u8,
    pub tca_pad1: u8,
    pub tca_pad2: u16,
}

impl TcaMsg {
    /// Size of this structure — 4 bytes.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new standalone-action header.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
}

impl TcMsg {
    /// Size of this structure.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new TC message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn with_ifindex(mut self, ifindex: i32) -> Self {
        self.tcm_ifindex = ifindex;
        self
    }

    /// Set the handle.
    pub fn with_handle(mut self, handle: u32) -> Self {
        self.tcm_handle = handle;
        self
    }

    /// Set the parent.
    pub fn with_parent(mut self, parent: u32) -> Self {
        self.tcm_parent = parent;
        self
    }

    /// Set the raw `tcm_info` field.
    ///
    /// For filters this is a packed field — prefer
    /// [`with_filter_info`](Self::with_filter_info), which lays out the
    /// protocol and priority the way the kernel expects.
    pub fn with_info(mut self, info: u32) -> Self {
        self.tcm_info = info;
        self
    }

    /// Set `tcm_info` from a TC filter's ethernet protocol + priority.
    ///
    /// The kernel packs a filter's `tcm_info` as
    /// `TC_H_MAKE(prio << 16, protocol)` (see
    /// `include/uapi/linux/pkt_sched.h`): the **priority** occupies the upper
    /// 16 bits (the "major" half) and the **ethernet protocol** the lower 16
    /// bits (the "minor" half). The protocol additionally travels in
    /// **network byte order** — iproute2 stores `htons(ethertype)` there, and
    /// the kernel compares it against `skb->protocol` (also network byte
    /// order) when walking the per-protocol classifier dispatch.
    ///
    /// Getting the field order wrong makes the kernel reject the add with
    /// `EINVAL` (it reads the priority value as the protocol and vice versa);
    /// getting the byte order wrong registers the filter under an ethertype
    /// no packet ever carries, so it silently never matches.
    ///
    /// `protocol` and `priority` are taken in host byte order; the byte swap
    /// happens here (`u16::to_be` is a no-op on big-endian hosts).
    pub fn with_filter_info(self, protocol: u16, priority: u16) -> Self {
        self.with_info(((priority as u32) << 16) | (protocol.to_be() as u32))
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            }))
    }
}

/// Traffic control attributes (TCA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum TcaAttr {
    Unspec = 0,
    Kind = 1,
    Options = 2,
    Stats = 3,
    Xstats = 4,
    Rate = 5,
    Fcnt = 6,
    Stats2 = 7,
    Stab = 8,
    Pad = 9,
    DumpInvisible = 10,
    Chain = 11,
    HwOffload = 12,
    IngressBlock = 13,
    EgressBlock = 14,
    DumpFlags = 15,
    ExtWarnMsg = 16,
}

impl From<u16> for TcaAttr {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Unspec,
            1 => Self::Kind,
            2 => Self::Options,
            3 => Self::Stats,
            4 => Self::Xstats,
            5 => Self::Rate,
            6 => Self::Fcnt,
            7 => Self::Stats2,
            8 => Self::Stab,
            9 => Self::Pad,
            10 => Self::DumpInvisible,
            11 => Self::Chain,
            12 => Self::HwOffload,
            13 => Self::IngressBlock,
            14 => Self::EgressBlock,
            15 => Self::DumpFlags,
            16 => Self::ExtWarnMsg,
            _ => Self::Unspec,
        }
    }
}

/// Action table attribute (for RTM_*ACTION messages).
pub const TCA_ACT_TAB: u16 = 1;

/// Root action attributes (for action dump).
pub const TCA_ROOT_UNSPEC: u16 = 0;
pub const TCA_ROOT_TAB: u16 = 1;
pub const TCA_ROOT_FLAGS: u16 = 2;
pub const TCA_ROOT_COUNT: u16 = 3;
pub const TCA_ROOT_TIME_DELTA: u16 = 4;

/// Special handle values.
pub mod tc_handle {
    /// Root qdisc.
    pub const ROOT: u32 = 0xFFFFFFFF;
    /// Ingress qdisc.
    pub const INGRESS: u32 = 0xFFFFFFF1;
    /// Clsact qdisc.
    ///
    /// `pkt_sched.h` defines `TC_H_CLSACT` as a plain alias of
    /// `TC_H_INGRESS` — clsact occupies the same qdisc slot as ingress
    /// and simply exposes an egress hook as well. This was transcribed
    /// as `0xFFFFFFF2`, which is not the qdisc parent at all but
    /// `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)` — the parent a
    /// *filter* on the clsact ingress hook uses. Installing a clsact
    /// qdisc with it made the kernel answer `EOPNOTSUPP`, every time.
    pub const CLSACT: u32 = INGRESS;
    /// Minor of the clsact ingress hook (`TC_H_MIN_INGRESS`).
    pub const MIN_INGRESS: u16 = 0xFFF2;
    /// Minor of the clsact egress hook (`TC_H_MIN_EGRESS`).
    pub const MIN_EGRESS: u16 = 0xFFF3;
    /// Parent for a filter on the clsact **ingress** hook
    /// (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`).
    pub const CLSACT_INGRESS: u32 = make(0xFFFF, MIN_INGRESS);
    /// Parent for a filter on the clsact **egress** hook
    /// (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`).
    pub const CLSACT_EGRESS: u32 = make(0xFFFF, MIN_EGRESS);
    /// Unspecified.
    pub const UNSPEC: u32 = 0;

    /// Make a handle from major:minor.
    pub const fn make(major: u16, minor: u16) -> u32 {
        ((major as u32) << 16) | (minor as u32)
    }

    /// Get the major number from a handle.
    pub const fn major(handle: u32) -> u16 {
        (handle >> 16) as u16
    }

    /// Get the minor number from a handle.
    pub const fn minor(handle: u32) -> u16 {
        (handle & 0xFFFF) as u16
    }

    /// Format a handle as major:minor string.
    pub fn format(handle: u32) -> String {
        if handle == ROOT {
            "root".to_string()
        } else if handle == INGRESS {
            // == CLSACT. `tc(8)` accepts either spelling for this value;
            // "ingress" is the one it prints.
            "ingress".to_string()
        } else if handle == CLSACT_INGRESS {
            "clsact-ingress".to_string()
        } else if handle == CLSACT_EGRESS {
            "clsact-egress".to_string()
        } else if handle == UNSPEC {
            "none".to_string()
        } else {
            let maj = major(handle);
            let min = minor(handle);
            if min == 0 {
                format!("{:x}:", maj)
            } else {
                format!("{:x}:{:x}", maj, min)
            }
        }
    }

    /// Parse a handle from major:minor string.
    pub fn parse(s: &str) -> Option<u32> {
        match s {
            "root" => Some(ROOT),
            // `tc(8)` takes "ingress" and "clsact" as names for the same
            // parent; both land on TC_H_INGRESS.
            "ingress" | "clsact" => Some(INGRESS),
            "clsact-ingress" => Some(CLSACT_INGRESS),
            "clsact-egress" => Some(CLSACT_EGRESS),
            "none" => Some(UNSPEC),
            _ => {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 2 {
                    let major = u16::from_str_radix(parts[0], 16).ok()?;
                    let minor = if parts[1].is_empty() {
                        0
                    } else {
                        u16::from_str_radix(parts[1], 16).ok()?
                    };
                    Some(make(major, minor))
                } else {
                    None
                }
            }
        }
    }
}

/// TC statistics (struct tc_stats).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct TcStats {
    /// Bytes seen.
    pub bytes: u64,
    /// Packets seen.
    pub packets: u32,
    /// Packets dropped.
    pub drops: u32,
    /// Packets overlimits.
    pub overlimits: u32,
    /// Current queue length.
    pub bps: u32,
    /// Current packet rate.
    pub pps: u32,
    /// Queue length.
    pub qlen: u32,
    /// Backlog bytes.
    pub backlog: u32,
}

impl TcStats {
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}

/// TC statistics 2 (struct gnet_stats_basic).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct GnetStatsBasic {
    pub bytes: u64,
    pub packets: u32,
}

/// TC queue stats (struct gnet_stats_queue).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, Immutable, KnownLayout)]
pub struct GnetStatsQueue {
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u32,
    pub requeues: u32,
    pub overlimits: u32,
}

/// TCA_STATS2 nested attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum TcaStats {
    Unspec = 0,
    Basic = 1,
    RateEst = 2,
    Queue = 3,
    App = 4,
    RateEst64 = 5,
    Pad = 6,
    BasicHw = 7,
    Pkt64 = 8,
}

impl From<u16> for TcaStats {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::Basic,
            2 => Self::RateEst,
            3 => Self::Queue,
            4 => Self::App,
            5 => Self::RateEst64,
            6 => Self::Pad,
            7 => Self::BasicHw,
            8 => Self::Pkt64,
            _ => Self::Unspec,
        }
    }
}

/// TC rate estimator parameters.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TcEstimator {
    pub interval: i8,
    pub ewma_log: u8,
}

/// Common qdisc options.
pub mod qdisc {
    /// HTB qdisc-specific attributes.
    pub mod htb {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_HTB_UNSPEC: u16 = 0;
        pub const TCA_HTB_PARMS: u16 = 1;
        pub const TCA_HTB_INIT: u16 = 2;
        pub const TCA_HTB_CTAB: u16 = 3;
        pub const TCA_HTB_RTAB: u16 = 4;
        pub const TCA_HTB_DIRECT_QLEN: u16 = 5;
        pub const TCA_HTB_RATE64: u16 = 6;
        pub const TCA_HTB_CEIL64: u16 = 7;
        /// Unused; listed because omitting it is what put OFFLOAD at 8 (#265).
        #[allow(dead_code)]
        pub const TCA_HTB_PAD: u16 = 8;
        pub const TCA_HTB_OFFLOAD: u16 = 9;

        /// HTB global parameters (struct tc_htb_glob).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcHtbGlob {
            pub version: u32,
            pub rate2quantum: u32,
            pub defcls: u32,
            pub debug: u32,
            pub direct_pkts: u32,
        }

        impl TcHtbGlob {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self {
                    version: 3,
                    rate2quantum: 10,
                    defcls: 0,
                    debug: 0,
                    direct_pkts: 0,
                }
            }

            pub fn with_default(mut self, defcls: u32) -> Self {
                self.defcls = defcls;
                self
            }

            /// Set `rate2quantum` (tc(8) `r2q`).
            ///
            /// HTB derives each class's quantum as `rate / r2q`. Until 0.25
            /// this was hardcoded to 10 with no way to override it, so
            /// `HtbQdiscConfig::new().r2q(100)` — and the `r2q` token that
            /// `parse_params` dutifully accepted — were both silently
            /// dropped on the floor, leaving class quanta wrong for
            /// high-rate hierarchies (#213).
            pub fn with_r2q(mut self, r2q: u32) -> Self {
                self.rate2quantum = r2q;
                self
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }

            /// Parse from bytes.
            pub fn from_bytes(data: &[u8]) -> Option<&Self> {
                Self::ref_from_prefix(data).map(|(r, _)| r).ok()
            }
        }

        /// HTB class parameters (struct tc_htb_opt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcHtbOpt {
            pub rate: super::TcRateSpec,
            pub ceil: super::TcRateSpec,
            pub buffer: u32,
            pub cbuffer: u32,
            pub quantum: u32,
            pub level: u32,
            pub prio: u32,
        }

        impl TcHtbOpt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }

            /// Parse from bytes.
            pub fn from_bytes(data: &[u8]) -> Option<&Self> {
                Self::ref_from_prefix(data).map(|(r, _)| r).ok()
            }
        }
    }

    /// FQ_CODEL qdisc-specific attributes.
    pub mod fq_codel {
        pub const TCA_FQ_CODEL_UNSPEC: u16 = 0;
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

    /// ETS (Enhanced Transmission Selection) qdisc attributes
    /// (`enum` TCA_ETS_*). `QUANTA` and `PRIOMAP` are nested lists.
    pub mod ets {
        pub const TCA_ETS_UNSPEC: u16 = 0;
        /// Total number of bands (u8).
        pub const TCA_ETS_NBANDS: u16 = 1;
        /// Number of strict-priority bands (u8).
        pub const TCA_ETS_NSTRICT: u16 = 2;
        /// Nested list of per-band quanta.
        pub const TCA_ETS_QUANTA: u16 = 3;
        /// One band's DRR quantum (u32), inside the `QUANTA` nest.
        pub const TCA_ETS_QUANTA_BAND: u16 = 4;
        /// Nested priority → band map.
        pub const TCA_ETS_PRIOMAP: u16 = 5;
        /// One priority's band (u8), inside the `PRIOMAP` nest.
        pub const TCA_ETS_PRIOMAP_BAND: u16 = 6;
    }

    /// TBF qdisc-specific attributes.
    pub mod tbf {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_TBF_UNSPEC: u16 = 0;
        pub const TCA_TBF_PARMS: u16 = 1;
        pub const TCA_TBF_RTAB: u16 = 2;
        pub const TCA_TBF_PTAB: u16 = 3;
        pub const TCA_TBF_RATE64: u16 = 4;
        pub const TCA_TBF_PRATE64: u16 = 5;
        pub const TCA_TBF_BURST: u16 = 6;
        pub const TCA_TBF_PBURST: u16 = 7;

        /// TBF parameters (struct tc_tbf_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcTbfQopt {
            pub rate: super::TcRateSpec,
            pub peakrate: super::TcRateSpec,
            pub limit: u32,
            pub buffer: u32,
            pub mtu: u32,
        }

        impl TcTbfQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// PRIO qdisc-specific attributes.
    pub mod prio {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_PRIO_UNSPEC: u16 = 0;
        pub const TCA_PRIO_MQ: u16 = 1;

        /// PRIO parameters (struct tc_prio_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcPrioQopt {
            pub bands: i32,
            pub priomap: [u8; 16],
        }

        impl Default for TcPrioQopt {
            fn default() -> Self {
                Self {
                    bands: 3,
                    // Default priomap: { 1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 }
                    priomap: [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
                }
            }
        }

        impl TcPrioQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// SFQ qdisc-specific attributes.
    pub mod sfq {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// SFQ parameters (struct tc_sfq_qopt_v1).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSfqQoptV1 {
            pub v0: TcSfqQopt,
            pub depth: u32,
            pub headdrop: u32,
            pub limit: u32,
            pub qth_min: u32,
            pub qth_max: u32,
            pub wlog: u8,
            pub plog: u8,
            pub scell_log: u8,
            pub flags: u8,
            pub max_p: u32,
            /// `struct tc_sfqred_stats`. Without it the struct is short of
            /// `sizeof(tc_sfq_qopt_v1)`, and `sfq_change()` reads it as the
            /// v0 struct, ignoring depth and head drop (#806).
            pub stats: [u32; 6],
        }

        impl TcSfqQoptV1 {
            pub const SIZE: usize = std::mem::size_of::<Self>();
        }

        /// SFQ basic parameters (struct tc_sfq_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSfqQopt {
            pub quantum: u32,
            pub perturb_period: i32,
            pub limit: u32,
            pub divisor: u32,
            pub flows: u32,
        }

        impl TcSfqQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Netem qdisc-specific attributes.
    pub mod netem {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_NETEM_UNSPEC: u16 = 0;
        pub const TCA_NETEM_CORR: u16 = 1;
        pub const TCA_NETEM_DELAY_DIST: u16 = 2;
        pub const TCA_NETEM_REORDER: u16 = 3;
        pub const TCA_NETEM_CORRUPT: u16 = 4;
        pub const TCA_NETEM_LOSS: u16 = 5;
        pub const TCA_NETEM_RATE: u16 = 6;
        pub const TCA_NETEM_ECN: u16 = 7;
        pub const TCA_NETEM_RATE64: u16 = 8;
        pub const TCA_NETEM_PAD: u16 = 9;
        pub const TCA_NETEM_LATENCY64: u16 = 10;
        pub const TCA_NETEM_JITTER64: u16 = 11;
        pub const TCA_NETEM_SLOT: u16 = 12;
        pub const TCA_NETEM_SLOT_DIST: u16 = 13;
        pub const TCA_NETEM_PRNG_SEED: u16 = 14;

        /// Netem loss model types.
        pub const NETEM_LOSS_UNSPEC: u16 = 0;
        pub const NETEM_LOSS_GI: u16 = 1; // General Intuitive - 4 state model
        pub const NETEM_LOSS_GE: u16 = 2; // Gilbert Elliot model

        /// Netem basic options (struct tc_netem_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemQopt {
            /// Added delay in microseconds.
            pub latency: u32,
            /// FIFO limit (packets).
            pub limit: u32,
            /// Random packet loss (0=none, ~0=100%).
            pub loss: u32,
            /// Re-ordering gap (0 for none).
            pub gap: u32,
            /// Random packet duplication (0=none, ~0=100%).
            pub duplicate: u32,
            /// Random jitter in latency (microseconds).
            pub jitter: u32,
        }

        impl TcNetemQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self {
                    limit: 1000,
                    ..Default::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Netem correlation structure (struct tc_netem_corr).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemCorr {
            /// Delay correlation.
            pub delay_corr: u32,
            /// Packet loss correlation.
            pub loss_corr: u32,
            /// Duplicate correlation.
            pub dup_corr: u32,
        }

        impl TcNetemCorr {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Netem reorder structure (struct tc_netem_reorder).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemReorder {
            pub probability: u32,
            pub correlation: u32,
        }

        impl TcNetemReorder {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Netem corrupt structure (struct tc_netem_corrupt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemCorrupt {
            pub probability: u32,
            pub correlation: u32,
        }

        impl TcNetemCorrupt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Netem rate structure (struct tc_netem_rate).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemRate {
            /// Rate in bytes/s.
            pub rate: u32,
            /// Packet overhead.
            pub packet_overhead: i32,
            /// Cell size.
            pub cell_size: u32,
            /// Cell overhead.
            pub cell_overhead: i32,
        }

        impl TcNetemRate {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Netem slot structure (struct tc_netem_slot).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemSlot {
            /// Minimum delay in nanoseconds.
            pub min_delay: i64,
            /// Maximum delay in nanoseconds.
            pub max_delay: i64,
            /// Maximum packets per slot.
            pub max_packets: i32,
            /// Maximum bytes per slot.
            pub max_bytes: i32,
            /// Distribution delay in nanoseconds.
            pub dist_delay: i64,
            /// Distribution jitter in nanoseconds.
            pub dist_jitter: i64,
        }

        impl TcNetemSlot {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Gilbert-Intuitive loss model (4 state) (struct tc_netem_gimodel).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemGiModel {
            pub p13: u32,
            pub p31: u32,
            pub p32: u32,
            pub p14: u32,
            pub p23: u32,
        }

        impl TcNetemGiModel {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Gilbert-Elliot loss model (struct tc_netem_gemodel).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNetemGeModel {
            pub p: u32,
            pub r: u32,
            pub h: u32,
            pub k1: u32,
        }

        impl TcNetemGeModel {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Convert percentage (0.0-100.0) to netem probability (0 to u32::MAX),
        /// rounded to nearest as tc(8) does (#633).
        pub fn percent_to_prob(percent: f64) -> u32 {
            ((percent / 100.0) * (u32::MAX as f64)).round() as u32
        }

        /// Convert netem probability to percentage.
        pub fn prob_to_percent(prob: u32) -> f64 {
            (prob as f64 / u32::MAX as f64) * 100.0
        }
    }

    /// Rate specification (struct tc_ratespec).
    #[repr(C)]
    #[derive(
        Debug,
        Clone,
        Copy,
        Default,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct TcRateSpec {
        pub cell_log: u8,
        pub linklayer: u8,
        pub overhead: u16,
        pub cell_align: i16,
        pub mpu: u16,
        pub rate: u32,
    }

    impl TcRateSpec {
        pub const SIZE: usize = std::mem::size_of::<Self>();

        pub fn new(rate: u32) -> Self {
            Self {
                rate,
                ..Default::default()
            }
        }

        pub fn as_bytes(&self) -> &[u8] {
            <Self as zerocopy::IntoBytes>::as_bytes(self)
        }
    }

    /// CoDel qdisc-specific attributes.
    pub mod codel {
        pub const TCA_CODEL_UNSPEC: u16 = 0;
        pub const TCA_CODEL_TARGET: u16 = 1;
        pub const TCA_CODEL_LIMIT: u16 = 2;
        pub const TCA_CODEL_INTERVAL: u16 = 3;
        pub const TCA_CODEL_ECN: u16 = 4;
        pub const TCA_CODEL_CE_THRESHOLD: u16 = 5;
    }

    /// FQ (Fair Queue) qdisc-specific attributes.
    pub mod fq {
        pub const TCA_FQ_UNSPEC: u16 = 0;
        pub const TCA_FQ_PLIMIT: u16 = 1;
        pub const TCA_FQ_FLOW_PLIMIT: u16 = 2;
        pub const TCA_FQ_QUANTUM: u16 = 3;
        pub const TCA_FQ_INITIAL_QUANTUM: u16 = 4;
        pub const TCA_FQ_RATE_ENABLE: u16 = 5;
        pub const TCA_FQ_FLOW_DEFAULT_RATE: u16 = 6;
        pub const TCA_FQ_FLOW_MAX_RATE: u16 = 7;
        pub const TCA_FQ_BUCKETS_LOG: u16 = 8;
        pub const TCA_FQ_FLOW_REFILL_DELAY: u16 = 9;
        pub const TCA_FQ_ORPHAN_MASK: u16 = 10;
        pub const TCA_FQ_LOW_RATE_THRESHOLD: u16 = 11;
        pub const TCA_FQ_CE_THRESHOLD: u16 = 12;
        pub const TCA_FQ_TIMER_SLACK: u16 = 13;
        pub const TCA_FQ_HORIZON: u16 = 14;
        pub const TCA_FQ_HORIZON_DROP: u16 = 15;
        pub const TCA_FQ_PRIOMAP: u16 = 16;
        pub const TCA_FQ_WEIGHTS: u16 = 17;
        pub const TCA_FQ_OFFLOAD_HORIZON: u16 = 18;
    }

    /// CAKE qdisc-specific attributes.
    pub mod cake {
        pub const TCA_CAKE_UNSPEC: u16 = 0;
        pub const TCA_CAKE_PAD: u16 = 1;
        pub const TCA_CAKE_BASE_RATE64: u16 = 2;
        pub const TCA_CAKE_DIFFSERV_MODE: u16 = 3;
        pub const TCA_CAKE_ATM: u16 = 4;
        pub const TCA_CAKE_FLOW_MODE: u16 = 5;
        pub const TCA_CAKE_OVERHEAD: u16 = 6;
        pub const TCA_CAKE_RTT: u16 = 7;
        pub const TCA_CAKE_TARGET: u16 = 8;
        pub const TCA_CAKE_AUTORATE: u16 = 9;
        pub const TCA_CAKE_MEMORY: u16 = 10;
        pub const TCA_CAKE_NAT: u16 = 11;
        pub const TCA_CAKE_RAW: u16 = 12;
        pub const TCA_CAKE_WASH: u16 = 13;
        pub const TCA_CAKE_MPU: u16 = 14;
        pub const TCA_CAKE_INGRESS: u16 = 15;
        pub const TCA_CAKE_ACK_FILTER: u16 = 16;
        pub const TCA_CAKE_SPLIT_GSO: u16 = 17;
        pub const TCA_CAKE_FWMARK: u16 = 18;

        /// CAKE diffserv modes.
        pub const CAKE_DIFFSERV_DIFFSERV3: u32 = 0;
        pub const CAKE_DIFFSERV_DIFFSERV4: u32 = 1;
        pub const CAKE_DIFFSERV_DIFFSERV8: u32 = 2;
        pub const CAKE_DIFFSERV_BESTEFFORT: u32 = 3;
        pub const CAKE_DIFFSERV_PRECEDENCE: u32 = 4;

        /// CAKE flow modes.
        pub const CAKE_FLOW_NONE: u32 = 0;
        pub const CAKE_FLOW_SRC_IP: u32 = 1;
        pub const CAKE_FLOW_DST_IP: u32 = 2;
        pub const CAKE_FLOW_HOSTS: u32 = 3;
        pub const CAKE_FLOW_FLOWS: u32 = 4;
        pub const CAKE_FLOW_DUAL_SRC: u32 = 5;
        pub const CAKE_FLOW_DUAL_DST: u32 = 6;
        pub const CAKE_FLOW_TRIPLE: u32 = 7;

        /// CAKE ATM modes.
        pub const CAKE_ATM_NONE: u32 = 0;
        pub const CAKE_ATM_ATM: u32 = 1;
        pub const CAKE_ATM_PTM: u32 = 2;

        /// CAKE ACK filter modes.
        pub const CAKE_ACK_NONE: u32 = 0;
        pub const CAKE_ACK_FILTER: u32 = 1;
        pub const CAKE_ACK_AGGRESSIVE: u32 = 2;
    }

    /// RED (Random Early Detection) qdisc-specific attributes.
    pub mod red {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_RED_UNSPEC: u16 = 0;
        pub const TCA_RED_PARMS: u16 = 1;
        pub const TCA_RED_STAB: u16 = 2;
        pub const TCA_RED_MAX_P: u16 = 3;
        pub const TCA_RED_FLAGS: u16 = 4;
        pub const TCA_RED_EARLY_DROP_BLOCK: u16 = 5;
        pub const TCA_RED_MARK_BLOCK: u16 = 6;

        /// RED flags.
        pub const TC_RED_ECN: u32 = 1;
        pub const TC_RED_HARDDROP: u32 = 2;
        pub const TC_RED_ADAPTATIVE: u32 = 4;
        pub const TC_RED_NODROP: u32 = 8;

        /// RED parameters (struct tc_red_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcRedQopt {
            /// Queue limit in bytes.
            pub limit: u32,
            /// Minimum threshold.
            pub qth_min: u32,
            /// Maximum threshold.
            pub qth_max: u32,
            /// Log of weight for EWMA.
            pub wlog: u8,
            /// Log of probability.
            pub plog: u8,
            /// Log of cell size.
            pub scell_log: u8,
            /// Flags (ECN, harddrop, etc.).
            pub flags: u8,
        }

        impl TcRedQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// CHOKe qdisc-specific attributes.
    ///
    /// CHOKe is a RED variant: it shares `struct tc_red_qopt` for its
    /// parameters (re-exported from the [`red`] module) and adds the
    /// CHOKe-specific differential-dropping behaviour kernel-side. The
    /// attribute IDs differ from RED's, so they get their own module.
    pub mod choke {
        pub const TCA_CHOKE_UNSPEC: u16 = 0;
        pub const TCA_CHOKE_PARMS: u16 = 1;
        pub const TCA_CHOKE_STAB: u16 = 2;
        pub const TCA_CHOKE_MAX_P: u16 = 3;

        /// CHOKe parameters share `struct tc_red_qopt` with RED.
        pub use super::red::TcRedQopt;
    }

    /// GRED (Generic RED) qdisc-specific attributes.
    ///
    /// GRED multiplexes up to `MAX_DPS` virtual queues (drop precedences)
    /// over a single qdisc. Configuration is two-phase: the **setup**
    /// message carries `struct tc_gred_sopt` under `TCA_GRED_DPS`
    /// (queue count, default VQ, optional GRIO), and per-VQ RED
    /// parameters are sent separately under `TCA_GRED_PARMS`.
    pub mod gred {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_GRED_UNSPEC: u16 = 0;
        pub const TCA_GRED_PARMS: u16 = 1;
        pub const TCA_GRED_STAB: u16 = 2;
        pub const TCA_GRED_DPS: u16 = 3;
        pub const TCA_GRED_MAX_P: u16 = 4;
        pub const TCA_GRED_LIMIT: u16 = 5;
        pub const TCA_GRED_VQ_LIST: u16 = 6;

        /// Maximum number of virtual queues (drop precedences).
        pub const MAX_DPS: u32 = 16;

        /// GRED setup parameters (`struct tc_gred_sopt`).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcGredSopt {
            /// Number of virtual queues (drop precedences).
            pub dps: u32,
            /// Default virtual queue.
            pub def_dp: u32,
            /// GRIO (RIO-like priority dropping) enabled.
            pub grio: u8,
            /// Flags.
            pub flags: u8,
            /// Padding.
            pub pad1: u16,
        }

        impl TcGredSopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// PIE (Proportional Integral controller-Enhanced) qdisc-specific attributes.
    pub mod pie {
        pub const TCA_PIE_UNSPEC: u16 = 0;
        pub const TCA_PIE_TARGET: u16 = 1;
        pub const TCA_PIE_LIMIT: u16 = 2;
        pub const TCA_PIE_TUPDATE: u16 = 3;
        pub const TCA_PIE_ALPHA: u16 = 4;
        pub const TCA_PIE_BETA: u16 = 5;
        pub const TCA_PIE_ECN: u16 = 6;
        pub const TCA_PIE_BYTEMODE: u16 = 7;
        pub const TCA_PIE_DQ_RATE_ESTIMATOR: u16 = 8;
    }

    /// FQ-PIE (Flow Queue PIE) qdisc-specific attributes.
    ///
    /// Mainline since Linux 5.6 (Mar 2020). Combines `fq_codel`'s
    /// per-flow tracking with PIE's proportional-integral AQM.
    pub mod fq_pie {
        pub const TCA_FQ_PIE_UNSPEC: u16 = 0;
        pub const TCA_FQ_PIE_LIMIT: u16 = 1;
        pub const TCA_FQ_PIE_FLOWS: u16 = 2;
        pub const TCA_FQ_PIE_TARGET: u16 = 3;
        pub const TCA_FQ_PIE_TUPDATE: u16 = 4;
        pub const TCA_FQ_PIE_ALPHA: u16 = 5;
        pub const TCA_FQ_PIE_BETA: u16 = 6;
        pub const TCA_FQ_PIE_QUANTUM: u16 = 7;
        pub const TCA_FQ_PIE_MEMORY_LIMIT: u16 = 8;
        pub const TCA_FQ_PIE_ECN_PROB: u16 = 9;
        pub const TCA_FQ_PIE_ECN: u16 = 10;
        pub const TCA_FQ_PIE_BYTEMODE: u16 = 11;
        pub const TCA_FQ_PIE_DQ_RATE_ESTIMATOR: u16 = 12;
    }

    /// FIFO qdisc types (pfifo, bfifo).
    pub mod fifo {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// FIFO limit structure (struct tc_fifo_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcFifoQopt {
            /// Queue limit (packets for pfifo, bytes for bfifo).
            pub limit: u32,
        }

        impl TcFifoQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(limit: u32) -> Self {
                Self { limit }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// CBS (Credit-Based Shaper, IEEE 802.1Qav) qdisc attributes.
    pub mod cbs {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_CBS_UNSPEC: u16 = 0;
        pub const TCA_CBS_PARMS: u16 = 1;

        /// Credit-Based Shaper parameters (struct tc_cbs_qopt).
        ///
        /// `idleslope`/`sendslope` are in kbit/s as the kernel/tc(8)
        /// express them; `hicredit`/`locredit` are in bytes. `offload`
        /// is a boolean flag (hardware offload to the NIC's Qav
        /// shaper).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcCbsQopt {
            pub offload: u8,
            pub _pad: [u8; 3],
            pub hicredit: i32,
            pub locredit: i32,
            pub idleslope: i32,
            pub sendslope: i32,
        }

        impl TcCbsQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// SKB priority queue (skbprio) qdisc parameters.
    pub mod skbprio {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// skbprio limit structure (struct tc_skbprio_qopt). Written
        /// directly as the `TCA_OPTIONS` payload (no PARMS sub-attr).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSkbprioQopt {
            /// Queue length limit in packets.
            pub limit: u32,
        }

        impl TcSkbprioQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(limit: u32) -> Self {
                Self { limit }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// DRR (Deficit Round Robin) qdisc attributes.
    pub mod drr {
        pub const TCA_DRR_UNSPEC: u16 = 0;
        pub const TCA_DRR_QUANTUM: u16 = 1;
    }

    /// SFB (Stochastic Fair Blue) qdisc attributes.
    pub mod sfb {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_SFB_UNSPEC: u16 = 0;
        pub const TCA_SFB_PARMS: u16 = 1;

        /// SFB parameters (struct tc_sfb_qopt). `rehash_interval` and
        /// `warmup_time` are in milliseconds; `penalty_rate` is in
        /// packets/s.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSfbQopt {
            /// Delay between hash moves, in ms.
            pub rehash_interval: u32,
            /// Double-buffering warmup time, in ms (< rehash_interval).
            pub warmup_time: u32,
            /// Max length of qlen_min.
            pub max: u32,
            /// Maximum queue length per bin.
            pub bin_size: u32,
            /// Probability increment (d1 in Blue).
            pub increment: u32,
            /// Probability decrement (d2 in Blue).
            pub decrement: u32,
            /// Max SFB queue length.
            pub limit: u32,
            /// Inelastic-flow rate limit, in packets/s.
            pub penalty_rate: u32,
            /// Penalty burst.
            pub penalty_burst: u32,
        }

        impl TcSfbQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// MULTIQ (band-per-tx-queue) qdisc parameters.
    pub mod multiq {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// multiq parameters (struct tc_multiq_qopt). Written zeroed —
        /// the kernel derives `bands` from the device's tx-queue count.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcMultiqQopt {
            /// Number of bands.
            pub bands: u16,
            /// Maximum number of queues.
            pub max_bands: u16,
        }

        impl TcMultiqQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// QFQ (Quick Fair Queueing) qdisc attributes.
    pub mod qfq {
        pub const TCA_QFQ_UNSPEC: u16 = 0;
        pub const TCA_QFQ_WEIGHT: u16 = 1;
        pub const TCA_QFQ_LMAX: u16 = 2;
    }

    /// HHF (Heavy-Hitter Filter) qdisc attributes. All u32. Timeouts
    /// are microseconds (kernel calls `usecs_to_jiffies`), matching the
    /// codel time-attr convention.
    pub mod hhf {
        pub const TCA_HHF_UNSPEC: u16 = 0;
        /// Backlog limit, in packets.
        pub const TCA_HHF_BACKLOG_LIMIT: u16 = 1;
        /// Quantum, in bytes.
        pub const TCA_HHF_QUANTUM: u16 = 2;
        /// Heavy-hitter flow table size.
        pub const TCA_HHF_HH_FLOWS_LIMIT: u16 = 3;
        /// Reset timeout, in microseconds.
        pub const TCA_HHF_RESET_TIMEOUT: u16 = 4;
        /// Admit bytes, in bytes.
        pub const TCA_HHF_ADMIT_BYTES: u16 = 5;
        /// Evict timeout, in microseconds.
        pub const TCA_HHF_EVICT_TIMEOUT: u16 = 6;
        /// Weight of the non-heavy-hitter band in the WDRR scheduler.
        pub const TCA_HHF_NON_HH_WEIGHT: u16 = 7;
    }

    /// DSMARK (DiffServ marking) qdisc attributes. The qdisc carries
    /// `indices`/`default_index`/`set_tc_index`; `mask`/`value` are
    /// per-class.
    pub mod dsmark {
        pub const TCA_DSMARK_UNSPEC: u16 = 0;
        /// Number of indices (u16, power of two).
        pub const TCA_DSMARK_INDICES: u16 = 1;
        /// Default index (u16).
        pub const TCA_DSMARK_DEFAULT_INDEX: u16 = 2;
        /// Set-tc-index flag (empty attribute).
        pub const TCA_DSMARK_SET_TC_INDEX: u16 = 3;
        /// Per-class mask (u8).
        pub const TCA_DSMARK_MASK: u16 = 4;
        /// Per-class value (u8).
        pub const TCA_DSMARK_VALUE: u16 = 5;
    }

    /// MQPRIO (Multi-Queue Priority) qdisc attributes.
    pub mod mqprio {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// Maximum number of traffic classes.
        pub const TC_QOPT_MAX_QUEUE: usize = 16;

        pub const TCA_MQPRIO_UNSPEC: u16 = 0;
        pub const TCA_MQPRIO_MODE: u16 = 1;
        pub const TCA_MQPRIO_SHAPER: u16 = 2;
        pub const TCA_MQPRIO_MIN_RATE64: u16 = 3;
        pub const TCA_MQPRIO_MAX_RATE64: u16 = 4;
        pub const TCA_MQPRIO_TC_ENTRY: u16 = 5;

        /// MQPRIO modes.
        pub const TC_MQPRIO_MODE_DCB: u16 = 0;
        pub const TC_MQPRIO_MODE_CHANNEL: u16 = 1;

        /// MQPRIO shaper types.
        pub const TC_MQPRIO_SHAPER_DCB: u16 = 0;
        pub const TC_MQPRIO_SHAPER_BW_RATE: u16 = 1;

        /// MQPRIO qdisc options (struct tc_mqprio_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcMqprioQopt {
            /// Number of traffic classes.
            pub num_tc: u8,
            /// Priority to traffic class mapping.
            pub prio_tc_map: [u8; TC_QOPT_MAX_QUEUE],
            /// Enable hardware offload (0=no, 1=yes).
            pub hw: u8,
            /// Queue count for each traffic class.
            pub count: [u16; TC_QOPT_MAX_QUEUE],
            /// Queue offset for each traffic class.
            pub offset: [u16; TC_QOPT_MAX_QUEUE],
        }

        impl Default for TcMqprioQopt {
            fn default() -> Self {
                Self {
                    num_tc: 8,
                    prio_tc_map: [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 1, 1, 3, 3, 3, 3],
                    hw: 1,
                    count: [0; TC_QOPT_MAX_QUEUE],
                    offset: [0; TC_QOPT_MAX_QUEUE],
                }
            }
        }

        impl TcMqprioQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self::default()
            }

            pub fn with_num_tc(mut self, num_tc: u8) -> Self {
                self.num_tc = num_tc;
                self
            }

            pub fn with_hw(mut self, hw: bool) -> Self {
                self.hw = if hw { 1 } else { 0 };
                self
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Plug qdisc types and constants.
    pub mod plug {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        /// Plug action types.
        pub const TCQ_PLUG_BUFFER: i32 = 0;
        pub const TCQ_PLUG_RELEASE_ONE: i32 = 1;
        pub const TCQ_PLUG_RELEASE_INDEFINITE: i32 = 2;
        pub const TCQ_PLUG_LIMIT: i32 = 3;

        /// Plug qdisc options (struct tc_plug_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcPlugQopt {
            /// Action to perform.
            pub action: i32,
            /// Limit for TCQ_PLUG_LIMIT action.
            pub limit: u32,
        }

        impl TcPlugQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(action: i32, limit: u32) -> Self {
                Self { action, limit }
            }

            pub fn buffer() -> Self {
                Self::new(TCQ_PLUG_BUFFER, 0)
            }

            pub fn release_one() -> Self {
                Self::new(TCQ_PLUG_RELEASE_ONE, 0)
            }

            pub fn release_indefinite() -> Self {
                Self::new(TCQ_PLUG_RELEASE_INDEFINITE, 0)
            }

            pub fn limit(bytes: u32) -> Self {
                Self::new(TCQ_PLUG_LIMIT, bytes)
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// TAPRIO (Time Aware Priority) qdisc attributes and structures.
    pub mod taprio {
        pub const TCA_TAPRIO_ATTR_UNSPEC: u16 = 0;
        pub const TCA_TAPRIO_ATTR_PRIOMAP: u16 = 1;
        pub const TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST: u16 = 2;
        pub const TCA_TAPRIO_ATTR_SCHED_BASE_TIME: u16 = 3;
        pub const TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY: u16 = 4;
        pub const TCA_TAPRIO_ATTR_SCHED_CLOCKID: u16 = 5;
        pub const TCA_TAPRIO_PAD: u16 = 6;
        pub const TCA_TAPRIO_ATTR_ADMIN_SCHED: u16 = 7;
        pub const TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME: u16 = 8;
        pub const TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION: u16 = 9;
        pub const TCA_TAPRIO_ATTR_FLAGS: u16 = 10;
        pub const TCA_TAPRIO_ATTR_TXTIME_DELAY: u16 = 11;
        pub const TCA_TAPRIO_ATTR_TC_ENTRY: u16 = 12;

        /// The type of each entry nested in `TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST`
        /// (`TCA_TAPRIO_SCHED_ENTRY`); the kernel skips any other (#823).
        pub const TCA_TAPRIO_SCHED_ENTRY: u16 = 1;

        /// Schedule entry attributes.
        pub const TCA_TAPRIO_SCHED_ENTRY_UNSPEC: u16 = 0;
        pub const TCA_TAPRIO_SCHED_ENTRY_INDEX: u16 = 1;
        pub const TCA_TAPRIO_SCHED_ENTRY_CMD: u16 = 2;
        pub const TCA_TAPRIO_SCHED_ENTRY_GATE_MASK: u16 = 3;
        pub const TCA_TAPRIO_SCHED_ENTRY_INTERVAL: u16 = 4;

        /// Gate commands.
        pub const TC_TAPRIO_CMD_SET_GATES: u8 = 0;
        pub const TC_TAPRIO_CMD_SET_AND_HOLD: u8 = 1;
        pub const TC_TAPRIO_CMD_SET_AND_RELEASE: u8 = 2;

        /// TAPRIO flags.
        pub const TAPRIO_ATTR_FLAG_TXTIME_ASSIST: u32 = 1 << 0;
        pub const TAPRIO_ATTR_FLAG_FULL_OFFLOAD: u32 = 1 << 1;

        /// A schedule entry for TAPRIO.
        #[derive(Debug, Clone, Copy)]
        pub struct TaprioSchedEntry {
            /// Gate command (SET_GATES, SET_AND_HOLD, SET_AND_RELEASE).
            pub cmd: u8,
            /// Gate mask (bit per traffic class).
            pub gate_mask: u32,
            /// Interval in nanoseconds.
            pub interval: u32,
        }

        impl TaprioSchedEntry {
            pub fn new(cmd: u8, gate_mask: u32, interval_ns: u32) -> Self {
                Self {
                    cmd,
                    gate_mask,
                    interval: interval_ns,
                }
            }

            /// Create a SET_GATES entry.
            pub fn set_gates(gate_mask: u32, interval_ns: u32) -> Self {
                Self::new(TC_TAPRIO_CMD_SET_GATES, gate_mask, interval_ns)
            }

            /// Create a SET_AND_HOLD entry.
            pub fn set_and_hold(gate_mask: u32, interval_ns: u32) -> Self {
                Self::new(TC_TAPRIO_CMD_SET_AND_HOLD, gate_mask, interval_ns)
            }

            /// Create a SET_AND_RELEASE entry.
            pub fn set_and_release(gate_mask: u32, interval_ns: u32) -> Self {
                Self::new(TC_TAPRIO_CMD_SET_AND_RELEASE, gate_mask, interval_ns)
            }
        }
    }

    /// HFSC (Hierarchical Fair Service Curve) qdisc attributes and structures.
    pub mod hfsc {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_HFSC_UNSPEC: u16 = 0;
        pub const TCA_HFSC_RSC: u16 = 1;
        pub const TCA_HFSC_FSC: u16 = 2;
        pub const TCA_HFSC_USC: u16 = 3;

        /// HFSC qdisc options (struct tc_hfsc_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcHfscQopt {
            /// Default class ID.
            pub defcls: u16,
        }

        impl TcHfscQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(defcls: u16) -> Self {
                Self { defcls }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Service curve definition (struct tc_service_curve).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcServiceCurve {
            /// Slope of the first segment in bps.
            pub m1: u32,
            /// X-projection of the first segment in microseconds.
            pub d: u32,
            /// Slope of the second segment in bps.
            pub m2: u32,
        }

        impl TcServiceCurve {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(m1: u32, d: u32, m2: u32) -> Self {
                Self { m1, d, m2 }
            }

            /// Create a simple service curve with just a rate (m2).
            pub fn rate(rate_bps: u32) -> Self {
                Self {
                    m1: 0,
                    d: 0,
                    m2: rate_bps,
                }
            }

            /// Create a two-slope service curve.
            ///
            /// - m1: initial rate in bps
            /// - d: duration of first segment in microseconds
            /// - m2: sustained rate in bps
            pub fn two_slope(m1: u32, d_us: u32, m2: u32) -> Self {
                Self { m1, d: d_us, m2 }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// ETF (Earliest TxTime First) qdisc attributes and structures.
    pub mod etf {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_ETF_UNSPEC: u16 = 0;
        pub const TCA_ETF_PARMS: u16 = 1;

        /// ETF flags.
        pub const TC_ETF_DEADLINE_MODE_ON: i32 = 1 << 0;
        pub const TC_ETF_OFFLOAD_ON: i32 = 1 << 1;
        pub const TC_ETF_SKIP_SOCK_CHECK: i32 = 1 << 2;

        /// Clock IDs for ETF.
        pub const CLOCKID_INVALID: i32 = -1;

        /// ETF qdisc options (struct tc_etf_qopt).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcEtfQopt {
            /// Delta time in nanoseconds.
            pub delta: i32,
            /// Clock ID (e.g., CLOCK_TAI).
            pub clockid: i32,
            /// Flags (deadline_mode, offload, skip_sock_check).
            pub flags: i32,
        }

        impl Default for TcEtfQopt {
            fn default() -> Self {
                Self {
                    delta: 0,
                    clockid: CLOCKID_INVALID,
                    flags: 0,
                }
            }
        }

        impl TcEtfQopt {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new() -> Self {
                Self::default()
            }

            pub fn with_delta(mut self, delta_ns: i32) -> Self {
                self.delta = delta_ns;
                self
            }

            pub fn with_clockid(mut self, clockid: i32) -> Self {
                self.clockid = clockid;
                self
            }

            pub fn with_deadline_mode(mut self, enable: bool) -> Self {
                if enable {
                    self.flags |= TC_ETF_DEADLINE_MODE_ON;
                } else {
                    self.flags &= !TC_ETF_DEADLINE_MODE_ON;
                }
                self
            }

            pub fn with_offload(mut self, enable: bool) -> Self {
                if enable {
                    self.flags |= TC_ETF_OFFLOAD_ON;
                } else {
                    self.flags &= !TC_ETF_OFFLOAD_ON;
                }
                self
            }

            pub fn with_skip_sock_check(mut self, enable: bool) -> Self {
                if enable {
                    self.flags |= TC_ETF_SKIP_SOCK_CHECK;
                } else {
                    self.flags &= !TC_ETF_SKIP_SOCK_CHECK;
                }
                self
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }
}

/// Common filter attributes.
pub mod filter {
    /// U32 filter attributes and structures.
    pub mod u32 {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_U32_UNSPEC: u16 = 0;
        pub const TCA_U32_CLASSID: u16 = 1;
        pub const TCA_U32_HASH: u16 = 2;
        pub const TCA_U32_LINK: u16 = 3;
        pub const TCA_U32_DIVISOR: u16 = 4;
        pub const TCA_U32_SEL: u16 = 5;
        pub const TCA_U32_POLICE: u16 = 6;
        pub const TCA_U32_ACT: u16 = 7;
        pub const TCA_U32_INDEV: u16 = 8;
        pub const TCA_U32_PCNT: u16 = 9;
        pub const TCA_U32_MARK: u16 = 10;
        pub const TCA_U32_FLAGS: u16 = 11;
        pub const TCA_U32_PAD: u16 = 12;

        /// U32 selector flags.
        pub const TC_U32_TERMINAL: u8 = 1;
        pub const TC_U32_OFFSET: u8 = 2;
        pub const TC_U32_VAROFFSET: u8 = 4;
        pub const TC_U32_EAT: u8 = 8;

        /// U32 key (struct tc_u32_key).
        /// Matches a 32-bit value at a specific offset.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcU32Key {
            /// Mask to apply (big-endian).
            pub mask: u32,
            /// Value to match (big-endian).
            pub val: u32,
            /// Byte offset from header start.
            pub off: i32,
            /// Offset mask for variable offset (-1 for nexthdr+).
            pub offmask: i32,
        }

        impl TcU32Key {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            /// Create a new key with value, mask, and offset.
            pub fn new(val: u32, mask: u32, off: i32) -> Self {
                Self {
                    mask,
                    val: val & mask,
                    off,
                    offmask: 0,
                }
            }

            /// Create a key for matching at nexthdr+ offset: `val` and
            /// `mask` in host order, packed big-endian like
            /// [`pack_key32`]. The offset counts from the next header,
            /// which only a linking filter's `offset` sets
            /// (`U32Filter::offset_at`); without one it is 0, the start
            /// of the IP header.
            ///
            /// Stored `val`/`mask` in host order before 0.31 (#492), so on
            /// little-endian it compared byte-swapped.
            pub fn with_nexthdr(val: u32, mask: u32, off: i32) -> Self {
                Self {
                    mask: mask.to_be(),
                    val: (val & mask).to_be(),
                    off,
                    offmask: -1,
                }
            }
        }

        /// U32 selector header (struct tc_u32_sel without keys).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcU32SelHdr {
            /// Flags (TC_U32_TERMINAL, etc.).
            pub flags: u8,
            /// Shift for variable offset.
            pub offshift: u8,
            /// Number of keys.
            pub nkeys: u8,
            /// Padding.
            pub _pad: u8,
            /// Mask for variable offset (big-endian).
            pub offmask: u16,
            /// Fixed offset to add.
            pub off: u16,
            /// Offset to variable offset field.
            pub offoff: i16,
            /// Hash key offset.
            pub hoff: i16,
            /// Hash mask (big-endian).
            pub hmask: u32,
        }

        impl TcU32SelHdr {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// U32 selector builder - builds the full selector with keys.
        #[derive(Debug, Clone, Default)]
        pub struct TcU32Sel {
            pub hdr: TcU32SelHdr,
            pub keys: Vec<TcU32Key>,
        }

        impl TcU32Sel {
            pub fn new() -> Self {
                Self::default()
            }

            /// Add a key to the selector.
            pub fn add_key(&mut self, key: TcU32Key) {
                self.keys.push(key);
                self.hdr.nkeys = self.keys.len() as u8;
            }

            /// Set terminal flag (packet will be classified).
            pub fn set_terminal(&mut self) {
                self.hdr.flags |= TC_U32_TERMINAL;
            }

            /// Convert to bytes for netlink message.
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut buf =
                    Vec::with_capacity(TcU32SelHdr::SIZE + self.keys.len() * TcU32Key::SIZE);
                buf.extend_from_slice(self.hdr.as_bytes());
                for key in &self.keys {
                    buf.extend_from_slice(<TcU32Key as IntoBytes>::as_bytes(key));
                }
                buf
            }
        }

        /// U32 mark structure (struct tc_u32_mark).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcU32Mark {
            pub val: u32,
            pub mask: u32,
            pub success: u32,
        }

        impl TcU32Mark {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(val: u32, mask: u32) -> Self {
                Self {
                    val,
                    mask,
                    success: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Helper to pack a 32-bit key at an offset.
        pub fn pack_key32(val: u32, mask: u32, off: i32) -> TcU32Key {
            TcU32Key::new(val.to_be(), mask.to_be(), off)
        }

        /// Helper to pack a 16-bit key at an offset.
        pub fn pack_key16(val: u16, mask: u16, off: i32) -> TcU32Key {
            // 16-bit values are positioned within a 32-bit word
            let (val32, mask32) = if (off & 3) == 0 {
                // Upper 16 bits
                ((val as u32) << 16, (mask as u32) << 16)
            } else {
                // Lower 16 bits
                (val as u32, mask as u32)
            };
            TcU32Key::new(val32.to_be(), mask32.to_be(), off & !3)
        }

        /// [`pack_key16`] relative to the next header, as `tc … match
        /// tcp|udp src|dst` packs it (offmask -1).
        pub fn pack_key16_nexthdr(val: u16, mask: u16, off: i32) -> TcU32Key {
            TcU32Key {
                offmask: -1,
                ..pack_key16(val, mask, off)
            }
        }

        /// Helper to pack an 8-bit key at an offset.
        pub fn pack_key8(val: u8, mask: u8, off: i32) -> TcU32Key {
            let shift = match off & 3 {
                0 => 24,
                1 => 16,
                2 => 8,
                _ => 0,
            };
            let val32 = (val as u32) << shift;
            let mask32 = (mask as u32) << shift;
            TcU32Key::new(val32.to_be(), mask32.to_be(), off & !3)
        }
    }

    /// Flower filter attributes.
    pub mod flower {
        pub const TCA_FLOWER_UNSPEC: u16 = 0;
        pub const TCA_FLOWER_CLASSID: u16 = 1;
        pub const TCA_FLOWER_INDEV: u16 = 2;
        pub const TCA_FLOWER_ACT: u16 = 3;
        pub const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
        pub const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
        pub const TCA_FLOWER_KEY_ETH_SRC: u16 = 6;
        pub const TCA_FLOWER_KEY_ETH_SRC_MASK: u16 = 7;
        pub const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
        pub const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
        pub const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
        pub const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
        pub const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
        pub const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
        pub const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
        pub const TCA_FLOWER_KEY_IPV6_SRC_MASK: u16 = 15;
        pub const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
        pub const TCA_FLOWER_KEY_IPV6_DST_MASK: u16 = 17;
        pub const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
        pub const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
        pub const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
        pub const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
        pub const TCA_FLOWER_FLAGS: u16 = 22;
        /// How many devices offloaded the filter: a dump's, not a request's.
        pub const TCA_FLOWER_IN_HW_COUNT: u16 = 86;
        pub const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
        pub const TCA_FLOWER_KEY_VLAN_PRIO: u16 = 24;
        pub const TCA_FLOWER_KEY_VLAN_ETH_TYPE: u16 = 25;
        pub const TCA_FLOWER_KEY_ENC_KEY_ID: u16 = 26;
        pub const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
        pub const TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK: u16 = 28;
        pub const TCA_FLOWER_KEY_ENC_IPV4_DST: u16 = 29;
        pub const TCA_FLOWER_KEY_ENC_IPV4_DST_MASK: u16 = 30;
        pub const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
        pub const TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK: u16 = 32;
        pub const TCA_FLOWER_KEY_ENC_IPV6_DST: u16 = 33;
        pub const TCA_FLOWER_KEY_ENC_IPV6_DST_MASK: u16 = 34;
        pub const TCA_FLOWER_KEY_TCP_SRC_MASK: u16 = 35;
        pub const TCA_FLOWER_KEY_TCP_DST_MASK: u16 = 36;
        pub const TCA_FLOWER_KEY_UDP_SRC_MASK: u16 = 37;
        pub const TCA_FLOWER_KEY_UDP_DST_MASK: u16 = 38;
        pub const TCA_FLOWER_KEY_SCTP_SRC_MASK: u16 = 39;
        pub const TCA_FLOWER_KEY_SCTP_DST_MASK: u16 = 40;
        pub const TCA_FLOWER_KEY_SCTP_SRC: u16 = 41;
        pub const TCA_FLOWER_KEY_SCTP_DST: u16 = 42;
        pub const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT: u16 = 43;
        pub const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK: u16 = 44;
        pub const TCA_FLOWER_KEY_ENC_UDP_DST_PORT: u16 = 45;
        pub const TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK: u16 = 46;
        pub const TCA_FLOWER_KEY_FLAGS: u16 = 47;
        pub const TCA_FLOWER_KEY_FLAGS_MASK: u16 = 48;
        pub const TCA_FLOWER_KEY_ICMPV4_CODE: u16 = 49;
        pub const TCA_FLOWER_KEY_ICMPV4_CODE_MASK: u16 = 50;
        pub const TCA_FLOWER_KEY_ICMPV4_TYPE: u16 = 51;
        pub const TCA_FLOWER_KEY_ICMPV4_TYPE_MASK: u16 = 52;
        pub const TCA_FLOWER_KEY_ICMPV6_CODE: u16 = 53;
        pub const TCA_FLOWER_KEY_ICMPV6_CODE_MASK: u16 = 54;
        pub const TCA_FLOWER_KEY_ICMPV6_TYPE: u16 = 55;
        pub const TCA_FLOWER_KEY_ICMPV6_TYPE_MASK: u16 = 56;
        pub const TCA_FLOWER_KEY_ARP_SIP: u16 = 57;
        pub const TCA_FLOWER_KEY_ARP_SIP_MASK: u16 = 58;
        pub const TCA_FLOWER_KEY_ARP_TIP: u16 = 59;
        pub const TCA_FLOWER_KEY_ARP_TIP_MASK: u16 = 60;
        pub const TCA_FLOWER_KEY_ARP_OP: u16 = 61;
        pub const TCA_FLOWER_KEY_ARP_OP_MASK: u16 = 62;
        pub const TCA_FLOWER_KEY_ARP_SHA: u16 = 63;
        pub const TCA_FLOWER_KEY_ARP_SHA_MASK: u16 = 64;
        pub const TCA_FLOWER_KEY_ARP_THA: u16 = 65;
        pub const TCA_FLOWER_KEY_ARP_THA_MASK: u16 = 66;
        pub const TCA_FLOWER_KEY_MPLS_TTL: u16 = 67;
        pub const TCA_FLOWER_KEY_MPLS_BOS: u16 = 68;
        pub const TCA_FLOWER_KEY_MPLS_TC: u16 = 69;
        pub const TCA_FLOWER_KEY_MPLS_LABEL: u16 = 70;
        pub const TCA_FLOWER_KEY_TCP_FLAGS: u16 = 71;
        pub const TCA_FLOWER_KEY_TCP_FLAGS_MASK: u16 = 72;
        pub const TCA_FLOWER_KEY_IP_TOS: u16 = 73;
        pub const TCA_FLOWER_KEY_IP_TOS_MASK: u16 = 74;
        pub const TCA_FLOWER_KEY_IP_TTL: u16 = 75;
        pub const TCA_FLOWER_KEY_IP_TTL_MASK: u16 = 76;
        pub const TCA_FLOWER_KEY_CVLAN_ID: u16 = 77;
        pub const TCA_FLOWER_KEY_CVLAN_PRIO: u16 = 78;
        pub const TCA_FLOWER_KEY_CVLAN_ETH_TYPE: u16 = 79;
        pub const TCA_FLOWER_KEY_ENC_IP_TOS: u16 = 80;
        pub const TCA_FLOWER_KEY_ENC_IP_TOS_MASK: u16 = 81;
        pub const TCA_FLOWER_KEY_ENC_IP_TTL: u16 = 82;
        pub const TCA_FLOWER_KEY_ENC_IP_TTL_MASK: u16 = 83;
        /// Port ranges (kernel 5.2+), big-endian, each pair min/max.
        /// `fl_set_key_port_range` reads them only when the IP protocol
        /// is TCP, UDP or SCTP, needs both ends, and refuses `min >= max`.
        pub const TCA_FLOWER_KEY_PORT_SRC_MIN: u16 = 87;
        pub const TCA_FLOWER_KEY_PORT_SRC_MAX: u16 = 88;
        pub const TCA_FLOWER_KEY_PORT_DST_MIN: u16 = 89;
        pub const TCA_FLOWER_KEY_PORT_DST_MAX: u16 = 90;
        pub const TCA_FLOWER_KEY_CT_STATE: u16 = 91;
        pub const TCA_FLOWER_KEY_CT_STATE_MASK: u16 = 92;
        pub const TCA_FLOWER_KEY_CT_ZONE: u16 = 93;
        pub const TCA_FLOWER_KEY_CT_ZONE_MASK: u16 = 94;
        pub const TCA_FLOWER_KEY_CT_MARK: u16 = 95;
        pub const TCA_FLOWER_KEY_CT_MARK_MASK: u16 = 96;
        pub const TCA_FLOWER_KEY_CT_LABELS: u16 = 97;
        pub const TCA_FLOWER_KEY_CT_LABELS_MASK: u16 = 98;

        /// Flower filter flags.
        pub const TCA_CLS_FLAGS_SKIP_HW: u32 = 1 << 0;
        pub const TCA_CLS_FLAGS_SKIP_SW: u32 = 1 << 1;
        pub const TCA_CLS_FLAGS_IN_HW: u32 = 1 << 2;
        pub const TCA_CLS_FLAGS_NOT_IN_HW: u32 = 1 << 3;
        pub const TCA_CLS_FLAGS_VERBOSE: u32 = 1 << 4;

        /// `TCA_FLOWER_KEY_FLAGS` bits (#827).
        pub const TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT: u32 = 1 << 0;
        pub const TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST: u32 = 1 << 1;

        /// Connection tracking state flags.
        pub const TCA_FLOWER_KEY_CT_FLAGS_NEW: u16 = 1 << 0;
        pub const TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED: u16 = 1 << 1;
        pub const TCA_FLOWER_KEY_CT_FLAGS_RELATED: u16 = 1 << 2;
        pub const TCA_FLOWER_KEY_CT_FLAGS_TRACKED: u16 = 1 << 3;
        pub const TCA_FLOWER_KEY_CT_FLAGS_INVALID: u16 = 1 << 4;
        pub const TCA_FLOWER_KEY_CT_FLAGS_REPLY: u16 = 1 << 5;

        /// IP protocol constants.
        pub const IPPROTO_TCP: u8 = 6;
        pub const IPPROTO_UDP: u8 = 17;
        pub const IPPROTO_ICMP: u8 = 1;
        pub const IPPROTO_ICMPV6: u8 = 58;
        pub const IPPROTO_SCTP: u8 = 132;
        pub const IPPROTO_GRE: u8 = 47;

        /// Parse IP protocol from string.
        pub fn parse_ip_proto(s: &str) -> Option<u8> {
            match s.to_lowercase().as_str() {
                "tcp" => Some(IPPROTO_TCP),
                "udp" => Some(IPPROTO_UDP),
                "icmp" => Some(IPPROTO_ICMP),
                "icmpv6" => Some(IPPROTO_ICMPV6),
                "sctp" => Some(IPPROTO_SCTP),
                "gre" => Some(IPPROTO_GRE),
                _ => s.parse().ok(),
            }
        }
    }

    /// BPF filter attributes.
    pub mod bpf {
        pub const TCA_BPF_UNSPEC: u16 = 0;
        pub const TCA_BPF_ACT: u16 = 1;
        pub const TCA_BPF_POLICE: u16 = 2;
        pub const TCA_BPF_CLASSID: u16 = 3;
        pub const TCA_BPF_OPS_LEN: u16 = 4;
        pub const TCA_BPF_OPS: u16 = 5;
        pub const TCA_BPF_FD: u16 = 6;
        pub const TCA_BPF_NAME: u16 = 7;
        pub const TCA_BPF_FLAGS: u16 = 8;
        pub const TCA_BPF_FLAGS_GEN: u16 = 9;
        pub const TCA_BPF_TAG: u16 = 10;
        pub const TCA_BPF_ID: u16 = 11;

        /// BPF filter flags.
        pub const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1 << 0;
    }

    /// Basic/matchall filter attributes.
    pub mod basic {
        pub const TCA_BASIC_UNSPEC: u16 = 0;
        pub const TCA_BASIC_CLASSID: u16 = 1;
        pub const TCA_BASIC_EMATCHES: u16 = 2;
        pub const TCA_BASIC_ACT: u16 = 3;
        pub const TCA_BASIC_POLICE: u16 = 4;
    }

    /// Extended-match (ematch) tree types and per-kind payload structs
    /// used by the basic classifier (`cls_basic`). See kernel
    /// `include/uapi/linux/pkt_cls.h` and `net/sched/em_*.c`.
    pub mod ematch {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        // Tree-level attribute IDs nested under TCA_BASIC_EMATCHES.
        pub const TCA_EMATCH_TREE_UNSPEC: u16 = 0;
        pub const TCA_EMATCH_TREE_HDR: u16 = 1;
        pub const TCA_EMATCH_TREE_LIST: u16 = 2;

        // Tree-header `progid`. TC always uses 0.
        pub const TCF_EM_PROG_TC: u16 = 0;

        // Per-match flags in tcf_ematch_hdr.flags. The relation
        // applies to the NEXT match (or REL_END for the last one).
        pub const TCF_EM_REL_END: u16 = 0;
        pub const TCF_EM_REL_AND: u16 = 1 << 0;
        pub const TCF_EM_REL_OR: u16 = 1 << 1;
        pub const TCF_EM_INVERT: u16 = 1 << 2;
        pub const TCF_EM_SIMPLE: u16 = 1 << 3;

        // Per-match `kind` discriminant in tcf_ematch_hdr.kind.
        pub const TCF_EM_CONTAINER: u16 = 0;
        pub const TCF_EM_CMP: u16 = 1;
        pub const TCF_EM_NBYTE: u16 = 2;
        pub const TCF_EM_U32: u16 = 3;
        pub const TCF_EM_META: u16 = 4;

        // tcf_em_cmp.layer (which header offset is relative to).
        pub const TCF_LAYER_LINK: u8 = 0;
        pub const TCF_LAYER_NETWORK: u8 = 1;
        pub const TCF_LAYER_TRANSPORT: u8 = 2;

        // tcf_em_cmp.align (width of the packet field to compare).
        pub const TCF_EM_ALIGN_U8: u8 = 1;
        pub const TCF_EM_ALIGN_U16: u8 = 2;
        pub const TCF_EM_ALIGN_U32: u8 = 4;

        // tcf_em_cmp.opnd (comparison operator).
        pub const TCF_EM_OPND_EQ: u8 = 0;
        pub const TCF_EM_OPND_GT: u8 = 1;
        pub const TCF_EM_OPND_LT: u8 = 2;

        // tcf_em_cmp.flags (cmp-local; distinct from tree-level flags).
        // Setting TRANS makes the kernel ntohl() the packet bytes
        // before comparing; useful when matching fields stored in
        // network byte order against a host-order val.
        pub const TCF_EM_CMP_TRANS: u8 = 1;

        /// Tree-header struct sent under `TCA_EMATCH_TREE_HDR`.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcfEmatchTreeHdr {
            pub nmatches: u16,
            pub progid: u16,
        }

        impl TcfEmatchTreeHdr {
            pub const SIZE: usize = std::mem::size_of::<Self>();
            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Per-match header that prefixes every entry in
        /// `TCA_EMATCH_TREE_LIST`. Kind-specific data follows.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcfEmatchHdr {
            pub matchid: u16,
            pub kind: u16,
            pub flags: u16,
            pub _pad: u16,
        }

        impl TcfEmatchHdr {
            pub const SIZE: usize = std::mem::size_of::<Self>();
            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// `tcf_em_cmp` payload: 16 bytes after the per-match header
        /// (14 declared + 2 trailing alignment bytes the kernel
        /// `sizeof` rounds to).
        ///
        /// Kernel C layout uses bit fields (`align:4 / flags:4`,
        /// `layer:4 / opnd:4`); on a little-endian wire the byte at
        /// each pair is `(high << 4) | (low & 0x0F)`.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcfEmCmp {
            pub val: u32,
            pub mask: u32,
            pub off: u16,
            /// Packed: `(flags << 4) | (align & 0x0F)`.
            pub align_flags: u8,
            /// Packed: `(opnd << 4) | (layer & 0x0F)`.
            pub layer_opnd: u8,
            pub _pad: u16,
            /// Trailing alignment slot — kernel struct rounds to 16
            /// bytes via u32 alignment; we declare it explicitly so
            /// `zerocopy::IntoBytes` doesn't reject implicit padding.
            pub _pad2: u16,
        }

        impl TcfEmCmp {
            pub const SIZE: usize = std::mem::size_of::<Self>();
            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// `tcf_em_u32` payload: 12 bytes after the per-match header.
        /// Same selector primitive as `cls_u32`'s key.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcfEmU32 {
            pub mask: u32,
            pub val: u32,
            pub off: u32,
            /// The kernel's `struct tc_u32_key` ends with it; without it
            /// `tcf_em_validate` refused every u32 ematch (#828).
            pub offmask: i32,
        }

        impl TcfEmU32 {
            pub const SIZE: usize = std::mem::size_of::<Self>();
            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Matchall filter attributes.
    pub mod matchall {
        pub const TCA_MATCHALL_UNSPEC: u16 = 0;
        pub const TCA_MATCHALL_CLASSID: u16 = 1;
        pub const TCA_MATCHALL_ACT: u16 = 2;
        pub const TCA_MATCHALL_FLAGS: u16 = 3;
        pub const TCA_MATCHALL_PCNT: u16 = 4;
        pub const TCA_MATCHALL_PAD: u16 = 5;
    }

    /// Firewall mark (fw) filter attributes.
    pub mod fw {
        pub const TCA_FW_UNSPEC: u16 = 0;
        pub const TCA_FW_CLASSID: u16 = 1;
        pub const TCA_FW_POLICE: u16 = 2;
        pub const TCA_FW_INDEV: u16 = 3;
        pub const TCA_FW_ACT: u16 = 4;
        pub const TCA_FW_MASK: u16 = 5;
    }

    /// tcindex filter attributes.
    pub mod tcindex {
        pub const TCA_TCINDEX_UNSPEC: u16 = 0;
        /// Hash-table size (u32).
        pub const TCA_TCINDEX_HASH: u16 = 1;
        /// Mask applied to `tc_index` (u16).
        pub const TCA_TCINDEX_MASK: u16 = 2;
        /// Right shift applied to `tc_index` (u32).
        pub const TCA_TCINDEX_SHIFT: u16 = 3;
        /// Fall-through flag (u32): 1 = fall_through, 0 = pass_on.
        pub const TCA_TCINDEX_FALL_THROUGH: u16 = 4;
        /// Target class id (u32).
        pub const TCA_TCINDEX_CLASSID: u16 = 5;
        pub const TCA_TCINDEX_POLICE: u16 = 6;
        pub const TCA_TCINDEX_ACT: u16 = 7;
    }

    /// Cgroup filter attributes.
    pub mod cgroup {
        pub const TCA_CGROUP_UNSPEC: u16 = 0;
        pub const TCA_CGROUP_ACT: u16 = 1;
        pub const TCA_CGROUP_POLICE: u16 = 2;
        pub const TCA_CGROUP_EMATCHES: u16 = 3;
    }

    /// Route filter attributes.
    pub mod route4 {
        pub const TCA_ROUTE4_UNSPEC: u16 = 0;
        pub const TCA_ROUTE4_CLASSID: u16 = 1;
        pub const TCA_ROUTE4_TO: u16 = 2;
        pub const TCA_ROUTE4_FROM: u16 = 3;
        pub const TCA_ROUTE4_IIF: u16 = 4;
        pub const TCA_ROUTE4_POLICE: u16 = 5;
        pub const TCA_ROUTE4_ACT: u16 = 6;
    }

    /// RSVP classifier attributes (shared by `rsvp` and `rsvp6`).
    pub mod rsvp {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_RSVP_UNSPEC: u16 = 0;
        pub const TCA_RSVP_CLASSID: u16 = 1;
        pub const TCA_RSVP_DST: u16 = 2;
        pub const TCA_RSVP_SRC: u16 = 3;
        pub const TCA_RSVP_PINFO: u16 = 4;
        pub const TCA_RSVP_POLICE: u16 = 5;
        pub const TCA_RSVP_ACT: u16 = 6;

        /// General port info (`struct tc_rsvp_gpi`) — a key/mask/offset
        /// triple used for L4 port matching. Left zeroed when only
        /// address-level matching is requested.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcRsvpGpi {
            pub key: u32,
            pub mask: u32,
            pub offset: i32,
        }

        /// RSVP protocol info (`struct tc_rsvp_pinfo`).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcRsvpPinfo {
            /// Destination port info.
            pub dpi: TcRsvpGpi,
            /// Source port info.
            pub spi: TcRsvpGpi,
            /// L4 protocol number.
            pub protocol: u8,
            /// Tunnel id.
            pub tunnelid: u8,
            /// Tunnel header length.
            pub tunnelhdr: u8,
            /// Padding.
            pub pad: u8,
        }

        impl TcRsvpPinfo {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Flow filter attributes.
    pub mod flow {
        pub const TCA_FLOW_UNSPEC: u16 = 0;
        pub const TCA_FLOW_KEYS: u16 = 1;
        pub const TCA_FLOW_MODE: u16 = 2;
        pub const TCA_FLOW_BASECLASS: u16 = 3;
        pub const TCA_FLOW_RSHIFT: u16 = 4;
        pub const TCA_FLOW_ADDEND: u16 = 5;
        pub const TCA_FLOW_MASK: u16 = 6;
        pub const TCA_FLOW_XOR: u16 = 7;
        pub const TCA_FLOW_DIVISOR: u16 = 8;
        pub const TCA_FLOW_ACT: u16 = 9;
        pub const TCA_FLOW_POLICE: u16 = 10;
        pub const TCA_FLOW_EMATCHES: u16 = 11;
        pub const TCA_FLOW_PERTURB: u16 = 12;

        /// Flow modes.
        pub const FLOW_MODE_MAP: u32 = 0;
        pub const FLOW_MODE_HASH: u32 = 1;

        /// Flow keys (bit positions for key mask).
        pub const FLOW_KEY_SRC: u32 = 1 << 0;
        pub const FLOW_KEY_DST: u32 = 1 << 1;
        pub const FLOW_KEY_PROTO: u32 = 1 << 2;
        pub const FLOW_KEY_PROTO_SRC: u32 = 1 << 3;
        pub const FLOW_KEY_PROTO_DST: u32 = 1 << 4;
        pub const FLOW_KEY_IIF: u32 = 1 << 5;
        pub const FLOW_KEY_PRIORITY: u32 = 1 << 6;
        pub const FLOW_KEY_MARK: u32 = 1 << 7;
        pub const FLOW_KEY_NFCT: u32 = 1 << 8;
        pub const FLOW_KEY_NFCT_SRC: u32 = 1 << 9;
        pub const FLOW_KEY_NFCT_DST: u32 = 1 << 10;
        pub const FLOW_KEY_NFCT_PROTO_SRC: u32 = 1 << 11;
        pub const FLOW_KEY_NFCT_PROTO_DST: u32 = 1 << 12;
        pub const FLOW_KEY_RTCLASSID: u32 = 1 << 13;
        pub const FLOW_KEY_SKUID: u32 = 1 << 14;
        pub const FLOW_KEY_SKGID: u32 = 1 << 15;
        pub const FLOW_KEY_VLAN_TAG: u32 = 1 << 16;
        pub const FLOW_KEY_RXHASH: u32 = 1 << 17;
    }
}

/// Common action attributes.
pub mod action {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    /// Generic action attributes.
    pub const TCA_ACT_UNSPEC: u16 = 0;
    pub const TCA_ACT_KIND: u16 = 1;
    pub const TCA_ACT_OPTIONS: u16 = 2;
    pub const TCA_ACT_INDEX: u16 = 3;
    pub const TCA_ACT_STATS: u16 = 4;
    pub const TCA_ACT_PAD: u16 = 5;
    pub const TCA_ACT_COOKIE: u16 = 6;
    pub const TCA_ACT_FLAGS: u16 = 7;
    pub const TCA_ACT_HW_STATS: u16 = 8;
    pub const TCA_ACT_USED_HW_STATS: u16 = 9;
    pub const TCA_ACT_IN_HW_COUNT: u16 = 10;

    /// Action binding constants.
    pub const TCA_ACT_BIND: i32 = 1;
    pub const TCA_ACT_NOBIND: i32 = 0;

    /// Action results (TC_ACT_*).
    pub const TC_ACT_UNSPEC: i32 = -1;
    pub const TC_ACT_OK: i32 = 0;
    pub const TC_ACT_RECLASSIFY: i32 = 1;
    pub const TC_ACT_SHOT: i32 = 2;
    pub const TC_ACT_PIPE: i32 = 3;
    pub const TC_ACT_STOLEN: i32 = 4;
    pub const TC_ACT_QUEUED: i32 = 5;
    pub const TC_ACT_REPEAT: i32 = 6;
    pub const TC_ACT_REDIRECT: i32 = 7;
    pub const TC_ACT_TRAP: i32 = 8;
    /// Jump to chain (opcode, chain is encoded in upper bits).
    pub const TC_ACT_JUMP: i32 = 0x10000000;
    /// Goto chain (opcode, chain is encoded in upper bits).
    pub const TC_ACT_GOTO_CHAIN: i32 = 0x20000000;

    /// `TC_ACT_EXT_VAL_MASK`: the low 28 bits of an extended verdict
    /// carry its value (a goto's chain), the high four its opcode.
    pub const TC_ACT_EXT_VAL_MASK: i32 = 0x0FFF_FFFF;

    /// Encode a goto_chain action value.
    ///
    /// The chain number is encoded in the lower 28 bits
    /// (`TC_ACT_EXT_VAL_MASK`); it used to be cut to 24.
    #[inline]
    pub const fn tc_act_goto_chain(chain: u32) -> i32 {
        TC_ACT_GOTO_CHAIN | (chain as i32 & TC_ACT_EXT_VAL_MASK)
    }

    /// Decode the chain number from a goto_chain action.
    #[inline]
    pub const fn tc_act_chain(action: i32) -> u32 {
        (action & TC_ACT_EXT_VAL_MASK) as u32
    }

    /// Check if an action is a goto_chain: its opcode, the high four
    /// bits, is `TC_ACT_GOTO_CHAIN` (the kernel's `TC_ACT_EXT_CMP`). It
    /// used to test one bit, which `TC_ACT_UNSPEC` (-1, `continue`) has.
    #[inline]
    pub const fn is_goto_chain(action: i32) -> bool {
        (action & !TC_ACT_EXT_VAL_MASK) == TC_ACT_GOTO_CHAIN
    }

    /// Parse action result from string.
    pub fn parse_action_result(s: &str) -> Option<i32> {
        match s.to_lowercase().as_str() {
            "ok" | "pass" => Some(TC_ACT_OK),
            "shot" | "drop" => Some(TC_ACT_SHOT),
            "reclassify" => Some(TC_ACT_RECLASSIFY),
            "pipe" => Some(TC_ACT_PIPE),
            "stolen" => Some(TC_ACT_STOLEN),
            "queued" => Some(TC_ACT_QUEUED),
            "repeat" => Some(TC_ACT_REPEAT),
            "redirect" => Some(TC_ACT_REDIRECT),
            "trap" => Some(TC_ACT_TRAP),
            "continue" => Some(TC_ACT_PIPE), // alias
            _ => None,
        }
    }

    /// Format action result to string.
    pub fn format_action_result(action: i32) -> &'static str {
        match action {
            TC_ACT_UNSPEC => "unspec",
            TC_ACT_OK => "pass",
            TC_ACT_SHOT => "drop",
            TC_ACT_RECLASSIFY => "reclassify",
            TC_ACT_PIPE => "pipe",
            TC_ACT_STOLEN => "stolen",
            TC_ACT_QUEUED => "queued",
            TC_ACT_REPEAT => "repeat",
            TC_ACT_REDIRECT => "redirect",
            TC_ACT_TRAP => "trap",
            _ => "unknown",
        }
    }

    /// Common action header (tc_gen macro in kernel).
    /// This is the base structure for all action parameters.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct TcGen {
        pub index: u32,
        pub capab: u32,
        pub action: i32,
        pub refcnt: i32,
        pub bindcnt: i32,
    }

    impl TcGen {
        pub fn new(action: i32) -> Self {
            Self {
                index: 0,
                capab: 0,
                action,
                refcnt: 0,
                bindcnt: 0,
            }
        }

        pub fn as_bytes(&self) -> &[u8] {
            <Self as IntoBytes>::as_bytes(self)
        }
    }

    /// Mirred action attributes.
    pub mod mirred {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_MIRRED_UNSPEC: u16 = 0;
        pub const TCA_MIRRED_TM: u16 = 1;
        pub const TCA_MIRRED_PARMS: u16 = 2;
        pub const TCA_MIRRED_PAD: u16 = 3;
        pub const TCA_MIRRED_BLOCKID: u16 = 4;

        /// Mirred action types.
        pub const TCA_EGRESS_REDIR: i32 = 1;
        pub const TCA_EGRESS_MIRROR: i32 = 2;
        pub const TCA_INGRESS_REDIR: i32 = 3;
        pub const TCA_INGRESS_MIRROR: i32 = 4;

        /// Parse mirred action type from string.
        pub fn parse_mirred_action(s: &str) -> Option<i32> {
            match s.to_lowercase().as_str() {
                "egress_redir" | "redirect" => Some(TCA_EGRESS_REDIR),
                "egress_mirror" | "mirror" => Some(TCA_EGRESS_MIRROR),
                "ingress_redir" => Some(TCA_INGRESS_REDIR),
                "ingress_mirror" => Some(TCA_INGRESS_MIRROR),
                _ => None,
            }
        }

        /// Format mirred action type to string.
        pub fn format_mirred_action(eaction: i32) -> &'static str {
            match eaction {
                TCA_EGRESS_REDIR => "egress redirect",
                TCA_EGRESS_MIRROR => "egress mirror",
                TCA_INGRESS_REDIR => "ingress redirect",
                TCA_INGRESS_MIRROR => "ingress mirror",
                _ => "unknown",
            }
        }

        /// Mirred action parameters (struct tc_mirred).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcMirred {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Mirred-specific: egress/ingress mirror/redirect.
            pub eaction: i32,
            /// Target interface index.
            pub ifindex: u32,
        }

        impl TcMirred {
            pub fn new(eaction: i32, ifindex: u32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    eaction,
                    ifindex,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Gact (generic action) attributes.
    pub mod gact {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_GACT_UNSPEC: u16 = 0;
        pub const TCA_GACT_TM: u16 = 1;
        pub const TCA_GACT_PARMS: u16 = 2;
        pub const TCA_GACT_PROB: u16 = 3;
        pub const TCA_GACT_PAD: u16 = 4;

        /// Probability distribution types.
        pub const PGACT_NONE: u16 = 0;
        pub const PGACT_NETRAND: u16 = 1;
        pub const PGACT_DETERM: u16 = 2;

        /// Gact action parameters (struct tc_gact).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcGact {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcGact {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Gact probability parameters (struct tc_gact_p).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcGactP {
            pub ptype: u16,
            pub pval: u16,
            pub paction: i32,
        }

        impl TcGactP {
            pub fn new(ptype: u16, pval: u16, paction: i32) -> Self {
                Self {
                    ptype,
                    pval,
                    paction,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Police action attributes.
    pub mod police {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_POLICE_UNSPEC: u16 = 0;
        pub const TCA_POLICE_TBF: u16 = 1;
        pub const TCA_POLICE_RATE: u16 = 2;
        pub const TCA_POLICE_PEAKRATE: u16 = 3;
        pub const TCA_POLICE_AVRATE: u16 = 4;
        pub const TCA_POLICE_RESULT: u16 = 5;
        pub const TCA_POLICE_TM: u16 = 6;
        pub const TCA_POLICE_PAD: u16 = 7;
        pub const TCA_POLICE_RATE64: u16 = 8;
        pub const TCA_POLICE_PEAKRATE64: u16 = 9;
        pub const TCA_POLICE_PKTRATE64: u16 = 10;
        pub const TCA_POLICE_PKTBURST64: u16 = 11;

        use crate::netlink::types::tc::qdisc::TcRateSpec;

        /// Police action parameters (struct tc_police).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcPolice {
            pub index: u32,
            pub action: i32,
            pub limit: u32,
            pub burst: u32,
            pub mtu: u32,
            pub rate: TcRateSpec,
            pub peakrate: TcRateSpec,
            pub refcnt: i32,
            pub bindcnt: i32,
            pub capab: u32,
        }

        impl Default for TcPolice {
            fn default() -> Self {
                Self {
                    index: 0,
                    action: super::TC_ACT_OK,
                    limit: 0,
                    burst: 0,
                    mtu: 0,
                    rate: TcRateSpec::default(),
                    peakrate: TcRateSpec::default(),
                    refcnt: 0,
                    bindcnt: 0,
                    capab: 0,
                }
            }
        }

        impl TcPolice {
            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Vlan action attributes.
    pub mod vlan {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_VLAN_UNSPEC: u16 = 0;
        pub const TCA_VLAN_TM: u16 = 1;
        pub const TCA_VLAN_PARMS: u16 = 2;
        pub const TCA_VLAN_PUSH_VLAN_ID: u16 = 3;
        pub const TCA_VLAN_PUSH_VLAN_PROTOCOL: u16 = 4;
        pub const TCA_VLAN_PAD: u16 = 5;
        pub const TCA_VLAN_PUSH_VLAN_PRIORITY: u16 = 6;
        pub const TCA_VLAN_PUSH_ETH_DST: u16 = 7;
        pub const TCA_VLAN_PUSH_ETH_SRC: u16 = 8;

        /// Vlan action types.
        pub const TCA_VLAN_ACT_POP: i32 = 1;
        pub const TCA_VLAN_ACT_PUSH: i32 = 2;
        pub const TCA_VLAN_ACT_MODIFY: i32 = 3;
        pub const TCA_VLAN_ACT_POP_ETH: i32 = 4;
        pub const TCA_VLAN_ACT_PUSH_ETH: i32 = 5;

        /// Ethernet protocol for VLAN.
        pub const ETH_P_8021Q: u16 = 0x8100;
        pub const ETH_P_8021AD: u16 = 0x88A8;

        /// Format vlan action type to string.
        pub fn format_vlan_action(v_action: i32) -> &'static str {
            match v_action {
                TCA_VLAN_ACT_POP => "pop",
                TCA_VLAN_ACT_PUSH => "push",
                TCA_VLAN_ACT_MODIFY => "modify",
                TCA_VLAN_ACT_POP_ETH => "pop_eth",
                TCA_VLAN_ACT_PUSH_ETH => "push_eth",
                _ => "unknown",
            }
        }

        /// Vlan action parameters (struct tc_vlan).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcVlan {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Vlan-specific action type.
            pub v_action: i32,
        }

        impl TcVlan {
            pub fn new(v_action: i32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    v_action,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// MPLS action attributes (push/pop/modify/dec_ttl).
    pub mod mpls {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_MPLS_UNSPEC: u16 = 0;
        pub const TCA_MPLS_TM: u16 = 1;
        pub const TCA_MPLS_PARMS: u16 = 2;
        pub const TCA_MPLS_PAD: u16 = 3;
        /// Ethertype of the new MPLS header (u16, push only).
        pub const TCA_MPLS_PROTO: u16 = 4;
        /// MPLS label (u32).
        pub const TCA_MPLS_LABEL: u16 = 5;
        /// Traffic class (u8).
        pub const TCA_MPLS_TC: u16 = 6;
        /// Time to live (u8).
        pub const TCA_MPLS_TTL: u16 = 7;
        /// Bottom of stack (u8).
        pub const TCA_MPLS_BOS: u16 = 8;

        pub const TCA_MPLS_ACT_POP: i32 = 1;
        pub const TCA_MPLS_ACT_PUSH: i32 = 2;
        pub const TCA_MPLS_ACT_MODIFY: i32 = 3;
        pub const TCA_MPLS_ACT_DEC_TTL: i32 = 4;
        pub const TCA_MPLS_ACT_MAC_PUSH: i32 = 5;

        /// MPLS action parameters (struct tc_mpls).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcMpls {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// MPLS action type (`TCA_MPLS_ACT_*`).
            pub m_action: i32,
        }

        impl TcMpls {
            pub fn new(m_action: i32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    m_action,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// SKB-modify action attributes (rewrite L2 src/dst MAC + ethertype).
    pub mod skbmod {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_SKBMOD_UNSPEC: u16 = 0;
        pub const TCA_SKBMOD_TM: u16 = 1;
        pub const TCA_SKBMOD_PARMS: u16 = 2;
        /// Destination MAC (6 bytes).
        pub const TCA_SKBMOD_DMAC: u16 = 3;
        /// Source MAC (6 bytes).
        pub const TCA_SKBMOD_SMAC: u16 = 4;
        /// Ethertype (u16).
        pub const TCA_SKBMOD_ETYPE: u16 = 5;
        pub const TCA_SKBMOD_PAD: u16 = 6;

        /// Set destination MAC.
        pub const SKBMOD_F_DMAC: u64 = 0x1;
        /// Set source MAC.
        pub const SKBMOD_F_SMAC: u64 = 0x2;
        /// Set ethertype.
        pub const SKBMOD_F_ETYPE: u64 = 0x4;
        /// Swap source and destination MAC.
        pub const SKBMOD_F_SWAPMAC: u64 = 0x8;

        /// skbmod action parameters (struct tc_skbmod).
        ///
        /// The 20-byte `tc_gen` prefix leaves 4 bytes of explicit
        /// padding before the 8-byte-aligned `flags` — matching the
        /// kernel's natural layout and keeping the struct free of
        /// implicit padding (required for zerocopy `IntoBytes`).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSkbmod {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            pub _pad: u32,
            /// Modification flags (`SKBMOD_F_*`).
            pub flags: u64,
        }

        impl TcSkbmod {
            pub fn new(flags: u64, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    _pad: 0,
                    flags,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Skbedit action attributes.
    pub mod skbedit {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_SKBEDIT_UNSPEC: u16 = 0;
        pub const TCA_SKBEDIT_TM: u16 = 1;
        pub const TCA_SKBEDIT_PARMS: u16 = 2;
        pub const TCA_SKBEDIT_PRIORITY: u16 = 3;
        pub const TCA_SKBEDIT_QUEUE_MAPPING: u16 = 4;
        pub const TCA_SKBEDIT_MARK: u16 = 5;
        pub const TCA_SKBEDIT_PAD: u16 = 6;
        pub const TCA_SKBEDIT_PTYPE: u16 = 7;
        pub const TCA_SKBEDIT_MASK: u16 = 8;
        pub const TCA_SKBEDIT_FLAGS: u16 = 9;
        pub const TCA_SKBEDIT_QUEUE_MAPPING_MAX: u16 = 10;

        /// Skbedit flags.
        pub const SKBEDIT_F_PRIORITY: u64 = 0x1;
        pub const SKBEDIT_F_QUEUE_MAPPING: u64 = 0x2;
        pub const SKBEDIT_F_MARK: u64 = 0x4;
        pub const SKBEDIT_F_PTYPE: u64 = 0x8;
        pub const SKBEDIT_F_MASK: u64 = 0x10;
        pub const SKBEDIT_F_INHERITDSFIELD: u64 = 0x20;

        /// Packet types for ptype.
        pub const PACKET_HOST: u16 = 0;
        pub const PACKET_BROADCAST: u16 = 1;
        pub const PACKET_MULTICAST: u16 = 2;
        pub const PACKET_OTHERHOST: u16 = 3;
        pub const PACKET_OUTGOING: u16 = 4;
        pub const PACKET_LOOPBACK: u16 = 5;

        /// Skbedit action parameters (struct tc_skbedit).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSkbedit {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcSkbedit {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// NAT action attributes.
    pub mod nat {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_NAT_UNSPEC: u16 = 0;
        pub const TCA_NAT_PARMS: u16 = 1;
        pub const TCA_NAT_TM: u16 = 2;
        pub const TCA_NAT_PAD: u16 = 3;

        /// Flag to indicate egress NAT (source NAT), otherwise ingress (destination NAT).
        pub const TCA_NAT_FLAG_EGRESS: u32 = 1;

        /// NAT action parameters (struct tc_nat).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcNat {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Original address to match (network byte order).
            pub old_addr: u32,
            /// New address to translate to (network byte order).
            pub new_addr: u32,
            /// Network mask (network byte order).
            pub mask: u32,
            /// Flags (TCA_NAT_FLAG_EGRESS for source NAT).
            pub flags: u32,
        }

        impl TcNat {
            pub fn new(old_addr: u32, new_addr: u32, mask: u32, flags: u32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    old_addr,
                    new_addr,
                    mask,
                    flags,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Tunnel key action attributes.
    pub mod tunnel_key {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_TUNNEL_KEY_UNSPEC: u16 = 0;
        pub const TCA_TUNNEL_KEY_TM: u16 = 1;
        pub const TCA_TUNNEL_KEY_PARMS: u16 = 2;
        pub const TCA_TUNNEL_KEY_ENC_IPV4_SRC: u16 = 3;
        pub const TCA_TUNNEL_KEY_ENC_IPV4_DST: u16 = 4;
        pub const TCA_TUNNEL_KEY_ENC_IPV6_SRC: u16 = 5;
        pub const TCA_TUNNEL_KEY_ENC_IPV6_DST: u16 = 6;
        pub const TCA_TUNNEL_KEY_ENC_KEY_ID: u16 = 7;
        pub const TCA_TUNNEL_KEY_PAD: u16 = 8;
        pub const TCA_TUNNEL_KEY_ENC_DST_PORT: u16 = 9;
        pub const TCA_TUNNEL_KEY_NO_CSUM: u16 = 10;
        pub const TCA_TUNNEL_KEY_ENC_OPTS: u16 = 11;
        pub const TCA_TUNNEL_KEY_ENC_TOS: u16 = 12;
        pub const TCA_TUNNEL_KEY_ENC_TTL: u16 = 13;
        pub const TCA_TUNNEL_KEY_NO_FRAG: u16 = 14;

        /// Tunnel key action types.
        pub const TCA_TUNNEL_KEY_ACT_SET: i32 = 1;
        pub const TCA_TUNNEL_KEY_ACT_RELEASE: i32 = 2;

        /// Tunnel key action parameters (struct tc_tunnel_key).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcTunnelKey {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Tunnel key action type.
            pub t_action: i32,
        }

        impl TcTunnelKey {
            pub fn new(t_action: i32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    t_action,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Connmark action attributes and structures.
    pub mod connmark {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_CONNMARK_UNSPEC: u16 = 0;
        pub const TCA_CONNMARK_PARMS: u16 = 1;
        pub const TCA_CONNMARK_TM: u16 = 2;
        pub const TCA_CONNMARK_PAD: u16 = 3;

        /// Connmark action parameters (struct tc_connmark).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcConnmark {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Conntrack zone.
            pub zone: u16,
            /// Padding to ensure alignment for zerocopy.
            pub _pad: u16,
        }

        impl TcConnmark {
            pub fn new(zone: u16, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    zone,
                    _pad: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// ctinfo action attributes and structures.
    ///
    /// `act_ctinfo` restores a DSCP value and/or the connection mark from
    /// conntrack metadata into the packet. Its parameter struct is just
    /// the `tc_gen` header; the DSCP/cpmark masks and zone ride as
    /// separate attributes.
    pub mod ctinfo {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_CTINFO_UNSPEC: u16 = 0;
        pub const TCA_CTINFO_PAD: u16 = 1;
        pub const TCA_CTINFO_TM: u16 = 2;
        pub const TCA_CTINFO_ACT: u16 = 3;
        pub const TCA_CTINFO_ZONE: u16 = 4;
        pub const TCA_CTINFO_PARMS_DSCP_MASK: u16 = 5;
        pub const TCA_CTINFO_PARMS_DSCP_STATEMASK: u16 = 6;
        pub const TCA_CTINFO_PARMS_CPMARK_MASK: u16 = 7;

        /// ctinfo action parameters (`struct tc_ctinfo` — `tc_gen` only).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcCtinfo {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcCtinfo {
            pub fn new(action: i32) -> Self {
                Self {
                    action,
                    ..Default::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// IFE (Inter-FE) action attributes and structures.
    ///
    /// `act_ife` encodes selected skb metadata (mark / priority /
    /// tcindex) into an Ethernet header for transport between
    /// forwarding elements, and decodes it on the far side. The
    /// metadata selection rides in the nested `TCA_IFE_METALST` list.
    pub mod ife {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_IFE_UNSPEC: u16 = 0;
        pub const TCA_IFE_PARMS: u16 = 1;
        pub const TCA_IFE_TM: u16 = 2;
        pub const TCA_IFE_DMAC: u16 = 3;
        pub const TCA_IFE_SMAC: u16 = 4;
        pub const TCA_IFE_TYPE: u16 = 5;
        pub const TCA_IFE_METALST: u16 = 6;
        pub const TCA_IFE_PAD: u16 = 7;

        // Metadata identifiers (nested under TCA_IFE_METALST).
        pub const IFE_META_SKBMARK: u16 = 1;
        pub const IFE_META_HASHID: u16 = 2;
        pub const IFE_META_PRIO: u16 = 3;
        pub const IFE_META_QMAP: u16 = 4;
        pub const IFE_META_TCINDEX: u16 = 5;

        /// Encode mode (set in `tc_ife.flags`); decode is the absence
        /// of this bit.
        pub const IFE_ENCODE: u16 = 1;

        /// IFE action parameters (`struct tc_ife` — `tc_gen` + flags).
        ///
        /// The `tc_gen` prefix is 20 bytes; `flags` is a `u16` followed
        /// by 2 bytes of explicit padding so the struct has no implicit
        /// padding (required for zerocopy `IntoBytes`).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcIfe {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// `IFE_ENCODE` for encode mode, 0 for decode.
            pub flags: u16,
            /// Explicit trailing padding.
            pub _pad: u16,
        }

        impl TcIfe {
            pub fn new(flags: u16, action: i32) -> Self {
                Self {
                    action,
                    flags,
                    ..Default::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// gate (IEEE 802.1Qci PSFP) action attributes and structures.
    ///
    /// `act_gate` opens/closes a time-gated schedule, admitting packets
    /// only during open windows. The schedule is a list of entries
    /// (`TCA_GATE_ENTRY_LIST`), each nested under `TCA_GATE_ONE_ENTRY`.
    pub mod gate {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        // Top-level gate attributes.
        pub const TCA_GATE_UNSPEC: u16 = 0;
        pub const TCA_GATE_TM: u16 = 1;
        pub const TCA_GATE_PARMS: u16 = 2;
        pub const TCA_GATE_PAD: u16 = 3;
        pub const TCA_GATE_PRIORITY: u16 = 4;
        pub const TCA_GATE_ENTRY_LIST: u16 = 5;
        pub const TCA_GATE_BASE_TIME: u16 = 6;
        pub const TCA_GATE_CYCLE_TIME: u16 = 7;
        pub const TCA_GATE_CYCLE_TIME_EXT: u16 = 8;
        pub const TCA_GATE_FLAGS: u16 = 9;
        pub const TCA_GATE_CLOCKID: u16 = 10;

        // Entry-list wrapper.
        pub const TCA_GATE_ONE_ENTRY: u16 = 1;

        // Per-entry attributes (nested under TCA_GATE_ONE_ENTRY).
        pub const TCA_GATE_ENTRY_INDEX: u16 = 1;
        pub const TCA_GATE_ENTRY_GATE: u16 = 2;
        pub const TCA_GATE_ENTRY_INTERVAL: u16 = 3;
        pub const TCA_GATE_ENTRY_IPV: u16 = 4;
        pub const TCA_GATE_ENTRY_MAX_OCTETS: u16 = 5;

        /// gate action parameters (`struct tc_gate` — `tc_gen` only).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcGate {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcGate {
            pub fn new(action: i32) -> Self {
                Self {
                    action,
                    ..Default::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Csum (checksum) action attributes and structures.
    pub mod csum {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_CSUM_UNSPEC: u16 = 0;
        pub const TCA_CSUM_PARMS: u16 = 1;
        pub const TCA_CSUM_TM: u16 = 2;
        pub const TCA_CSUM_PAD: u16 = 3;

        /// Update flags for checksum recalculation.
        pub const TCA_CSUM_UPDATE_FLAG_IPV4HDR: u32 = 1;
        pub const TCA_CSUM_UPDATE_FLAG_ICMP: u32 = 2;
        pub const TCA_CSUM_UPDATE_FLAG_IGMP: u32 = 4;
        pub const TCA_CSUM_UPDATE_FLAG_TCP: u32 = 8;
        pub const TCA_CSUM_UPDATE_FLAG_UDP: u32 = 16;
        pub const TCA_CSUM_UPDATE_FLAG_UDPLITE: u32 = 32;
        pub const TCA_CSUM_UPDATE_FLAG_SCTP: u32 = 64;

        /// Csum action parameters (struct tc_csum).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcCsum {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Update flags.
            pub update_flags: u32,
        }

        impl TcCsum {
            pub fn new(update_flags: u32, action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    update_flags,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Sample action attributes and structures.
    pub mod sample {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_SAMPLE_UNSPEC: u16 = 0;
        pub const TCA_SAMPLE_TM: u16 = 1;
        pub const TCA_SAMPLE_PARMS: u16 = 2;
        pub const TCA_SAMPLE_RATE: u16 = 3;
        pub const TCA_SAMPLE_TRUNC_SIZE: u16 = 4;
        pub const TCA_SAMPLE_PSAMPLE_GROUP: u16 = 5;
        pub const TCA_SAMPLE_PAD: u16 = 6;

        /// Sample action parameters (struct tc_sample - just tc_gen).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcSample {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcSample {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// CT (Connection Tracking) action attributes and structures.
    pub mod ct {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_CT_UNSPEC: u16 = 0;
        pub const TCA_CT_PARMS: u16 = 1;
        pub const TCA_CT_TM: u16 = 2;
        pub const TCA_CT_ACTION: u16 = 3;
        pub const TCA_CT_ZONE: u16 = 4;
        pub const TCA_CT_MARK: u16 = 5;
        pub const TCA_CT_MARK_MASK: u16 = 6;
        pub const TCA_CT_LABELS: u16 = 7;
        pub const TCA_CT_LABELS_MASK: u16 = 8;
        pub const TCA_CT_NAT_IPV4_MIN: u16 = 9;
        pub const TCA_CT_NAT_IPV4_MAX: u16 = 10;
        pub const TCA_CT_NAT_IPV6_MIN: u16 = 11;
        pub const TCA_CT_NAT_IPV6_MAX: u16 = 12;
        pub const TCA_CT_NAT_PORT_MIN: u16 = 13;
        pub const TCA_CT_NAT_PORT_MAX: u16 = 14;
        pub const TCA_CT_PAD: u16 = 15;
        pub const TCA_CT_HELPER_NAME: u16 = 16;
        pub const TCA_CT_HELPER_FAMILY: u16 = 17;
        pub const TCA_CT_HELPER_PROTO: u16 = 18;

        /// CT action flags.
        pub const TCA_CT_ACT_COMMIT: u16 = 1 << 0;
        pub const TCA_CT_ACT_FORCE: u16 = 1 << 1;
        pub const TCA_CT_ACT_CLEAR: u16 = 1 << 2;
        pub const TCA_CT_ACT_NAT: u16 = 1 << 3;
        pub const TCA_CT_ACT_NAT_SRC: u16 = 1 << 4;
        pub const TCA_CT_ACT_NAT_DST: u16 = 1 << 5;

        /// CT action parameters (struct tc_ct - just tc_gen).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcCt {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcCt {
            pub fn new(action: i32) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// Pedit (packet edit) action attributes and structures.
    pub mod pedit {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
        pub const TCA_PEDIT_UNSPEC: u16 = 0;
        pub const TCA_PEDIT_TM: u16 = 1;
        pub const TCA_PEDIT_PARMS: u16 = 2;
        pub const TCA_PEDIT_PAD: u16 = 3;
        pub const TCA_PEDIT_PARMS_EX: u16 = 4;
        pub const TCA_PEDIT_KEYS_EX: u16 = 5;
        pub const TCA_PEDIT_KEY_EX: u16 = 6;

        /// Pedit key extended attributes.
        pub const TCA_PEDIT_KEY_EX_HTYPE: u16 = 1;
        pub const TCA_PEDIT_KEY_EX_CMD: u16 = 2;

        /// Pedit header types.
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK: u16 = 0;
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_ETH: u16 = 1;
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_IP4: u16 = 2;
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_IP6: u16 = 3;
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_TCP: u16 = 4;
        pub const TCA_PEDIT_KEY_EX_HDR_TYPE_UDP: u16 = 5;

        /// Pedit commands.
        pub const TCA_PEDIT_KEY_EX_CMD_SET: u16 = 0;
        pub const TCA_PEDIT_KEY_EX_CMD_ADD: u16 = 1;

        /// Pedit key (struct tc_pedit_key).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcPeditKey {
            /// Mask of bits to modify.
            pub mask: u32,
            /// Value to set.
            pub val: u32,
            /// Offset within the header.
            pub off: u32,
            /// Which header at that offset.
            pub at: u32,
            /// Offset mask.
            pub offmask: u32,
            /// Shift amount.
            pub shift: u32,
        }

        impl TcPeditKey {
            pub const SIZE: usize = std::mem::size_of::<Self>();

            pub fn new(mask: u32, val: u32, off: u32) -> Self {
                Self {
                    mask,
                    val,
                    off,
                    at: 0,
                    offmask: 0,
                    shift: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }

        /// Pedit selector header (struct tc_pedit_sel without keys array).
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcPeditSel {
            /// Common action fields (tc_gen).
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
            /// Number of keys.
            pub nkeys: u8,
            /// Flags.
            pub flags: u8,
            /// Padding to ensure alignment for zerocopy.
            pub _pad: u16,
        }

        impl TcPeditSel {
            pub fn new(action: i32, nkeys: u8) -> Self {
                Self {
                    index: 0,
                    capab: 0,
                    action,
                    refcnt: 0,
                    bindcnt: 0,
                    nkeys,
                    flags: 0,
                    _pad: 0,
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// `act_bpf` (BPF action) attributes.
    ///
    /// Companion to the `cls_bpf` filter — where the classifier matches
    /// packets, this action runs a BPF program for side effects (mark,
    /// redirect, drop). Constants follow `enum tca_act_bpf_attrs` in
    /// `include/uapi/linux/tc_act/tc_bpf.h`.
    pub mod bpf_act {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_ACT_BPF_UNSPEC: u16 = 0;
        pub const TCA_ACT_BPF_TM: u16 = 1;
        pub const TCA_ACT_BPF_PARMS: u16 = 2;
        pub const TCA_ACT_BPF_OPS_LEN: u16 = 3;
        pub const TCA_ACT_BPF_OPS: u16 = 4;
        pub const TCA_ACT_BPF_FD: u16 = 5;
        pub const TCA_ACT_BPF_NAME: u16 = 6;
        pub const TCA_ACT_BPF_PAD: u16 = 7;
        pub const TCA_ACT_BPF_TAG: u16 = 8;
        pub const TCA_ACT_BPF_ID: u16 = 9;

        /// `act_bpf` parameters (struct `tc_act_bpf`).
        ///
        /// Identical layout to [`super::TcGen`] — the BPF action carries
        /// no kind-specific parameters in the parms blob.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcActBpf {
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcActBpf {
            pub fn new(action: i32) -> Self {
                Self {
                    action,
                    ..Self::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }

    /// `act_simple` (simple debugging action) attributes.
    ///
    /// `act_simple` writes a string to the kernel log when invoked.
    /// Useful for debugging filter chains. Constants follow
    /// `enum tca_def_attrs` in `include/uapi/linux/tc_act/tc_defact.h`.
    pub mod simple_act {
        use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

        pub const TCA_DEF_UNSPEC: u16 = 0;
        pub const TCA_DEF_TM: u16 = 1;
        pub const TCA_DEF_PARMS: u16 = 2;
        pub const TCA_DEF_DATA: u16 = 3;
        pub const TCA_DEF_PAD: u16 = 4;

        /// `act_simple` parameters (struct `tc_defact`).
        ///
        /// Identical layout to [`super::TcGen`] — sdata is carried in a
        /// separate `TCA_DEF_DATA` attribute.
        #[repr(C)]
        #[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct TcDefact {
            pub index: u32,
            pub capab: u32,
            pub action: i32,
            pub refcnt: i32,
            pub bindcnt: i32,
        }

        impl TcDefact {
            pub fn new(action: i32) -> Self {
                Self {
                    action,
                    ..Self::default()
                }
            }

            pub fn as_bytes(&self) -> &[u8] {
                <Self as IntoBytes>::as_bytes(self)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirror of include/uapi/linux/pkt_sched.h.
    const TC_H_MAJ_MASK: u32 = 0xFFFF_0000;
    const TC_H_MIN_MASK: u32 = 0x0000_FFFF;

    #[test]
    fn with_filter_info_matches_iproute2_wire_format() {
        // `tc filter add ... protocol ip prio 100` builds
        // tcm_info = TC_H_MAKE(prio << 16, htons(ETH_P_IP)).
        let info = TcMsg::new().with_filter_info(0x0800, 100).tcm_info;

        // Kernel-side extraction (net/sched/cls_api.c, tc_new_tfilter):
        //   prio     = TC_H_MAJ(tcm_info)
        //   protocol = TC_H_MIN(tcm_info)   // __be16
        let kernel_prio = (info & TC_H_MAJ_MASK) >> 16;
        let kernel_proto_be = (info & TC_H_MIN_MASK) as u16;

        assert_eq!(kernel_prio, 100, "priority -> major (upper) half");
        assert_eq!(
            kernel_proto_be,
            0x0800u16.to_be(),
            "protocol -> minor (lower) half, network byte order"
        );
        assert_eq!(u16::from_be(kernel_proto_be), 0x0800, "decodes to ETH_P_IP");

        // The exact 32-bit value iproute2 emits for this filter on a
        // little-endian host: prio 0x0064 high, htons(0x0800) = 0x0008 low.
        #[cfg(target_endian = "little")]
        assert_eq!(info, 0x0064_0008);
    }

    #[test]
    fn with_filter_info_round_trips_priority_and_protocol() {
        for (proto, prio) in [(0x0800u16, 100u16), (0x86DD, 200), (0x0003, 1), (0x0806, 49)] {
            let info = TcMsg::new().with_filter_info(proto, prio).tcm_info;
            assert_eq!((info >> 16) as u16, prio, "priority {prio:#x}");
            assert_eq!(
                u16::from_be((info & 0xFFFF) as u16),
                proto,
                "protocol {proto:#x}"
            );
        }
    }

    /// Regression guard for the pre-0.18 swap bug. The old
    /// `add_filter_by_index_full` packed `(protocol << 16) | priority` with no
    /// byte swap, so the kernel read protocol and priority transposed and
    /// rejected the add with EINVAL (or registered a never-matching filter).
    #[test]
    fn pre_fix_layout_was_transposed() {
        // protocol = 0x0800 (ETH_P_IP), priority = 100.
        let buggy = (0x0800u32 << 16) | 100u32; // old packing

        // What the kernel would have parsed out of the buggy value:
        assert_eq!(
            (buggy & TC_H_MIN_MASK) as u16,
            100,
            "kernel read the priority value (100) as the protocol"
        );
        assert_eq!(
            (buggy & TC_H_MAJ_MASK) >> 16,
            0x0800,
            "kernel read the protocol value (0x0800) as the priority"
        );

        // The fix produces a different, kernel-correct value.
        let fixed = TcMsg::new().with_filter_info(0x0800, 100).tcm_info;
        assert_ne!(buggy, fixed);
    }
}
