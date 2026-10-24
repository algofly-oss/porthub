//! A dumped rule as `nft list` prints it (#708).
//!
//! The kernel keeps a rule as register-level expressions: `meta load l4proto
//! => reg 1`, `cmp eq reg 1 6`, `payload load 2b @ transport header + 2 =>
//! reg 1`, `cmp eq reg 1 22`. `nft list ruleset` prints those as `tcp dport
//! 22`. [`lift`] does what nft's `netlink_delinearize.c` does, for what nlink
//! writes and the common things nft writes:
//!
//! - it follows the registers, so a comparison knows what was loaded;
//! - it names each header field from the protocol the rule has matched so
//!   far: after `meta l4proto tcp`, transport byte 2 is `tcp dport`;
//! - it drops the protocol matches those fields imply, where nft drops them,
//!   and keeps the ones nft keeps.
//!
//! A rule it cannot read back exactly is `None`. It prints a rule as nft
//! does or not at all. Two things nft looks up on the host and this does not:
//! an interface index prints as its number (nft: `iif "lo"`), and a protocol
//! number prints from a copy of netbase's `/etc/protocols` names.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    ByteorderOp, CmpOp, CtDirection, CtKey, DynsetOp, ExthdrOp, Family, FibFlags, FibResult,
    HashKind, LimitExpr, LimitKind, LimitUnit, LogExpr, LogFlags, LogLevel, MetaKey,
    NFT_REJECT_ICMP_UNREACH, NFT_REJECT_ICMPX_PORT_UNREACH, NFT_REJECT_ICMPX_UNREACH,
    NFT_REJECT_TCP_RST, NatFlags, NatType, NumgenKind, ObjectType, ObjrefExpr, OsfTtl, PayloadBase,
    QueueExpr, QueueFlags, RangeOp, Register, RtKey, RuleExpr, SocketKey, SynproxyExpr, Verdict,
};

/// The rule body `exprs` as `nft list` prints it in a `family` table, or
/// `None` when it holds something this does not read back exactly.
pub(crate) fn lift(exprs: &[RuleExpr], family: Family) -> Option<String> {
    lift_with(exprs, family, false)
}

/// [`lift`] as `nft -s list` (`--stateless`) prints it: a counter without
/// its packets and bytes, a quota without what it has used.
pub(crate) fn lift_stateless(exprs: &[RuleExpr], family: Family) -> Option<String> {
    lift_with(exprs, family, true)
}

fn lift_with(exprs: &[RuleExpr], family: Family, stateless: bool) -> Option<String> {
    let mut lifter = Lifter::new(family);
    lifter.stateless = stateless;
    for expr in exprs {
        lifter.step(expr)?;
    }
    Some(lifter.finish())
}

/// The register file has 16 32-bit words; `NFT_REG_1` is words 0..4.
const WORDS: usize = 16;

/// nft's protocol bases, which index the dependencies.
const BASE_LL: usize = 1;
const BASE_NET: usize = 2;
const BASE_TRANSPORT: usize = 3;

/// The word a register names.
fn word(reg: Register) -> Option<usize> {
    match reg.wire() {
        n @ 1..=4 => Some((n as usize - 1) * 4),
        n @ 8..=23 => Some(n as usize - 8),
        _ => None,
    }
}

/// The protocol at the network header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Net {
    V4,
    V6,
}

/// A header nft names fields of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hdr {
    Ether,
    Ip,
    Ip6,
    Tcp,
    Udp,
    Udplite,
    Sctp,
    Dccp,
    Icmp,
    Icmp6,
}

impl Hdr {
    fn name(self) -> &'static str {
        match self {
            Self::Ether => "ether",
            Self::Ip => "ip",
            Self::Ip6 => "ip6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Udplite => "udplite",
            Self::Sctp => "sctp",
            Self::Dccp => "dccp",
            Self::Icmp => "icmp",
            Self::Icmp6 => "icmpv6",
        }
    }

    fn base(self) -> usize {
        match self {
            Self::Ether => BASE_LL,
            Self::Ip | Self::Ip6 => BASE_NET,
            _ => BASE_TRANSPORT,
        }
    }

    /// Each field: its name, its offset and length in bits, and its type.
    fn fields(self) -> &'static [(&'static str, u32, u32, Ty)] {
        match self {
            Self::Ether => &[
                ("daddr", 0, 48, Ty::Ether),
                ("saddr", 48, 48, Ty::Ether),
                ("type", 96, 16, Ty::EtherType),
            ],
            Self::Ip => &[
                ("version", 0, 4, Ty::Int),
                ("hdrlength", 4, 4, Ty::Int),
                ("dscp", 8, 6, Ty::Dscp),
                ("ecn", 14, 2, Ty::Ecn),
                ("length", 16, 16, Ty::Int),
                ("id", 32, 16, Ty::Int),
                ("frag-off", 48, 16, Ty::Int),
                ("ttl", 64, 8, Ty::Int),
                ("protocol", 72, 8, Ty::Proto),
                ("checksum", 80, 16, Ty::Int),
                ("saddr", 96, 32, Ty::Ipv4),
                ("daddr", 128, 32, Ty::Ipv4),
            ],
            Self::Ip6 => &[
                ("version", 0, 4, Ty::Int),
                ("dscp", 4, 6, Ty::Dscp),
                ("ecn", 10, 2, Ty::Ecn),
                ("flowlabel", 12, 20, Ty::Int),
                ("length", 32, 16, Ty::Int),
                ("nexthdr", 48, 8, Ty::Proto),
                ("hoplimit", 56, 8, Ty::Int),
                ("saddr", 64, 128, Ty::Ipv6),
                ("daddr", 192, 128, Ty::Ipv6),
            ],
            Self::Tcp => &[
                ("sport", 0, 16, Ty::Port),
                ("dport", 16, 16, Ty::Port),
                ("sequence", 32, 32, Ty::Int),
                ("ackseq", 64, 32, Ty::Int),
                ("doff", 96, 4, Ty::Int),
                ("reserved", 100, 4, Ty::Int),
                ("flags", 104, 8, Ty::TcpFlags),
                ("window", 112, 16, Ty::Int),
                ("checksum", 128, 16, Ty::Int),
                ("urgptr", 144, 16, Ty::Int),
            ],
            Self::Udp => &[
                ("sport", 0, 16, Ty::Port),
                ("dport", 16, 16, Ty::Port),
                ("length", 32, 16, Ty::Int),
                ("checksum", 48, 16, Ty::Int),
            ],
            Self::Udplite => &[
                ("sport", 0, 16, Ty::Port),
                ("dport", 16, 16, Ty::Port),
                ("csumcov", 32, 16, Ty::Int),
                ("checksum", 48, 16, Ty::Int),
            ],
            Self::Sctp => &[
                ("sport", 0, 16, Ty::Port),
                ("dport", 16, 16, Ty::Port),
                ("vtag", 32, 32, Ty::Int),
                ("checksum", 64, 32, Ty::Int),
            ],
            Self::Dccp => &[("sport", 0, 16, Ty::Port), ("dport", 16, 16, Ty::Port)],
            Self::Icmp => &[
                ("type", 0, 8, Ty::IcmpType),
                ("code", 8, 8, Ty::Int),
                ("checksum", 16, 16, Ty::Int),
            ],
            Self::Icmp6 => &[
                ("type", 0, 8, Ty::Icmp6Type),
                ("code", 8, 8, Ty::Int),
                ("checksum", 16, 16, Ty::Int),
            ],
        }
    }

    /// The field `[bit, bit + bits)` of this header.
    fn field(self, bit: u32, bits: u32) -> Option<(&'static str, Ty)> {
        self.fields()
            .iter()
            .find(|(_, at, len, _)| *at == bit && *len == bits)
            .map(|(name, _, _, ty)| (*name, *ty))
    }

    /// The field that starts at `bit` and is longer than `bits`: a prefix of
    /// it was loaded (nft loads one byte of an address for a /8).
    fn field_from(self, bit: u32, bits: u32) -> Option<(&'static str, u32, Ty)> {
        self.fields()
            .iter()
            .find(|(_, at, len, _)| *at == bit && *len > bits)
            .map(|(name, _, len, ty)| (*name, *len, *ty))
    }

    /// Whether a match on this field says which protocol the next header
    /// is (nft's `EXPR_F_PROTOCOL`).
    fn is_protocol(self, name: &str) -> bool {
        matches!(
            (self, name),
            (Self::Ether, "type") | (Self::Ip, "protocol") | (Self::Ip6, "nexthdr")
        )
    }
}

/// How a value prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Ipv4,
    Ipv6,
    Ether,
    Port,
    Int,
    Mark,
    Ifname,
    Str,
    Proto,
    NfProto,
    EtherType,
    PktType,
    CtState,
    CtStatus,
    CtDir,
    CtLabel,
    TcpFlags,
    IcmpType,
    Icmp6Type,
    IcmpCode,
    Icmp6Code,
    AddrType,
    Dscp,
    Ecn,
    TcHandle,
    Bool,
    Ifindex,
}

impl Ty {
    /// A bitmask: `ct state established,related` is `& 6 != 0`.
    fn is_flags(self) -> bool {
        matches!(self, Self::CtState | Self::CtStatus | Self::TcpFlags)
    }

    /// An address, matched by prefix.
    fn has_prefix(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }

    /// The flag names of each bit, lowest first.
    fn flags(self) -> &'static [(&'static str, u128)] {
        match self {
            Self::CtState => &[
                ("invalid", 1),
                ("established", 2),
                ("related", 4),
                ("new", 8),
                ("untracked", 64),
            ],
            Self::CtStatus => &[
                ("expected", 1),
                ("seen-reply", 2),
                ("assured", 4),
                ("confirmed", 8),
                ("snat", 16),
                ("dnat", 32),
                ("dying", 512),
            ],
            Self::TcpFlags => &[
                ("fin", 1),
                ("syn", 2),
                ("rst", 4),
                ("psh", 8),
                ("ack", 16),
                ("urg", 32),
                ("ecn", 64),
                ("cwr", 128),
            ],
            _ => &[],
        }
    }

    /// The names of single values, first match wins (nft's symbol tables).
    fn symbols(self) -> &'static [(&'static str, u128)] {
        match self {
            Self::NfProto => &[("ipv4", 2), ("ipv6", 10)],
            Self::EtherType => &[
                ("ip", 0x0800),
                ("arp", 0x0806),
                ("ip6", 0x86dd),
                ("8021q", 0x8100),
                ("8021ad", 0x88a8),
            ],
            Self::PktType => &[
                ("host", 0),
                ("broadcast", 1),
                ("multicast", 2),
                ("other", 3),
            ],
            Self::CtDir => &[("original", 0), ("reply", 1)],
            Self::IcmpType => &[
                ("echo-reply", 0),
                ("destination-unreachable", 3),
                ("source-quench", 4),
                ("redirect", 5),
                ("echo-request", 8),
                ("router-advertisement", 9),
                ("router-solicitation", 10),
                ("time-exceeded", 11),
                ("parameter-problem", 12),
                ("timestamp-request", 13),
                ("timestamp-reply", 14),
                ("info-request", 15),
                ("info-reply", 16),
                ("address-mask-request", 17),
                ("address-mask-reply", 18),
            ],
            Self::Icmp6Type => &[
                ("destination-unreachable", 1),
                ("packet-too-big", 2),
                ("time-exceeded", 3),
                ("parameter-problem", 4),
                ("echo-request", 128),
                ("echo-reply", 129),
                ("mld-listener-query", 130),
                ("mld-listener-report", 131),
                ("mld-listener-done", 132),
                ("nd-router-solicit", 133),
                ("nd-router-advert", 134),
                ("nd-neighbor-solicit", 135),
                ("nd-neighbor-advert", 136),
                ("nd-redirect", 137),
                ("router-renumbering", 138),
                ("ind-neighbor-solicit", 141),
                ("ind-neighbor-advert", 142),
                ("mld2-listener-report", 143),
            ],
            Self::IcmpCode => &[
                ("net-unreachable", 0),
                ("host-unreachable", 1),
                ("prot-unreachable", 2),
                ("port-unreachable", 3),
                ("net-prohibited", 9),
                ("host-prohibited", 10),
                ("admin-prohibited", 13),
                ("frag-needed", 4),
            ],
            Self::Icmp6Code => &[
                ("no-route", 0),
                ("admin-prohibited", 1),
                ("addr-unreachable", 3),
                ("port-unreachable", 4),
                ("policy-fail", 5),
                ("reject-route", 6),
            ],
            Self::AddrType => &[
                ("unspec", 0),
                ("unicast", 1),
                ("local", 2),
                ("broadcast", 3),
                ("anycast", 4),
                ("multicast", 5),
                ("blackhole", 6),
                ("unreachable", 7),
                ("prohibit", 8),
            ],
            Self::Dscp => &[
                ("cs0", 0x00),
                ("cs1", 0x08),
                ("cs2", 0x10),
                ("cs3", 0x18),
                ("cs4", 0x20),
                ("cs5", 0x28),
                ("cs6", 0x30),
                ("cs7", 0x38),
                ("lephb", 0x01),
                ("af11", 0x0a),
                ("af12", 0x0c),
                ("af13", 0x0e),
                ("af21", 0x12),
                ("af22", 0x14),
                ("af23", 0x16),
                ("af31", 0x1a),
                ("af32", 0x1c),
                ("af33", 0x1e),
                ("af41", 0x22),
                ("af42", 0x24),
                ("af43", 0x26),
                ("va", 0x2c),
                ("ef", 0x2e),
            ],
            Self::Ecn => &[("not-ect", 0), ("ect1", 1), ("ect0", 2), ("ce", 3)],
            Self::Bool => &[("missing", 0), ("exists", 1)],
            _ => &[],
        }
    }

    /// An unnamed value of a symbol type is hex where nft's table is
    /// `BASE_HEXADECIMAL`.
    fn hex_fallback(self) -> bool {
        matches!(self, Self::EtherType | Self::Dscp | Self::Ecn) || self.is_flags()
    }

    /// `value`, in the field's byte order (network order when `be`), as nft
    /// prints it; `numeric` prints symbols as numbers, as in a range.
    fn show(self, value: &[u8], be: bool, numeric: bool) -> Option<String> {
        match self {
            Self::Ipv4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?).to_string()),
            Self::Ipv6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(value).ok()?).to_string()),
            Self::Ether => {
                let octets = <[u8; 6]>::try_from(value).ok()?;
                Some(
                    octets
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                )
            }
            Self::Ifname | Self::Str => {
                let (name, wildcard) = match value.iter().position(|&b| b == 0) {
                    Some(end) => (&value[..end], false),
                    None => (value, self == Self::Ifname),
                };
                let name = std::str::from_utf8(name).ok()?;
                Some(if wildcard {
                    format!("\"{name}*\"")
                } else {
                    format!("\"{name}\"")
                })
            }
            Self::Mark => Some(format!("0x{:08x}", int(value, be)?)),
            Self::TcHandle => {
                let h = u32::try_from(int(value, be)?).ok()?;
                Some(match h {
                    0xffff_ffff => "root".into(),
                    0 => "none".into(),
                    h => format!("{:x}:{:x}", h >> 16, h & 0xffff),
                })
            }
            Self::CtLabel => {
                let bit = label_bits(value)?;
                match bit.as_slice() {
                    [one] => Some(one.to_string()),
                    _ => None,
                }
            }
            Self::Proto => {
                let v = int(value, be)?;
                match (numeric, protocol_name(v)) {
                    (false, Some(name)) => Some(name.into()),
                    _ => Some(v.to_string()),
                }
            }
            Self::Port | Self::Int | Self::Ifindex => Some(int(value, be)?.to_string()),
            _ if self.is_flags() => {
                let v = int(value, be)?;
                if numeric {
                    return Some(format!("0x{v:x}"));
                }
                let names = flag_names(self, v)?;
                Some(names.join(" | "))
            }
            _ => {
                let v = int(value, be)?;
                let name = self.symbols().iter().find(|(_, s)| *s == v);
                Some(match name {
                    Some((name, _)) if !numeric => (*name).into(),
                    _ if self.hex_fallback() => format!("0x{v:x}"),
                    _ => v.to_string(),
                })
            }
        }
    }
}

/// The names of the bits of `v`, lowest first, or `None` for a bit with no
/// name or no bits at all.
fn flag_names(ty: Ty, v: u128) -> Option<Vec<&'static str>> {
    let names: Vec<_> = ty
        .flags()
        .iter()
        .filter(|(_, bit)| v & bit != 0)
        .map(|(name, _)| *name)
        .collect();
    let covered = ty
        .flags()
        .iter()
        .filter(|(_, bit)| v & bit != 0)
        .fold(0, |a, (_, b)| a | b);
    (v != 0 && covered == v).then_some(names)
}

/// The bits set in a 128-bit ct label, kept as the kernel keeps it: an
/// array of native-endian `unsigned long`s.
fn label_bits(value: &[u8]) -> Option<Vec<u32>> {
    const WORD: usize = usize::BITS as usize / 8;
    if value.len() != 16 {
        return None;
    }
    let mut bits = Vec::new();
    for (i, chunk) in value.chunks(WORD).enumerate() {
        let w = usize::from_ne_bytes(chunk.try_into().ok()?);
        for b in 0..usize::BITS {
            if w & (1 << b) != 0 {
                bits.push(i as u32 * usize::BITS + b);
            }
        }
    }
    Some(bits)
}

/// `value` as an unsigned integer: network order when `be`, else the host's.
fn int(value: &[u8], be: bool) -> Option<u128> {
    if value.is_empty() || value.len() > 16 {
        return None;
    }
    let big = be || cfg!(target_endian = "big");
    let fold = |acc: u128, b: &u8| (acc << 8) | u128::from(*b);
    Some(if big {
        value.iter().fold(0, fold)
    } else {
        value.iter().rev().fold(0, fold)
    })
}

/// `getprotobynumber`, from netbase's `/etc/protocols`, which nft reads.
fn protocol_name(n: u128) -> Option<&'static str> {
    Some(match n {
        0 => "ip",
        1 => "icmp",
        2 => "igmp",
        3 => "ggp",
        4 => "ipencap",
        5 => "st",
        6 => "tcp",
        8 => "egp",
        9 => "igp",
        12 => "pup",
        17 => "udp",
        20 => "hmp",
        22 => "xns-idp",
        27 => "rdp",
        29 => "iso-tp4",
        33 => "dccp",
        36 => "xtp",
        37 => "ddp",
        38 => "idpr-cmtp",
        41 => "ipv6",
        43 => "ipv6-route",
        44 => "ipv6-frag",
        45 => "idrp",
        46 => "rsvp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        57 => "skip",
        58 => "ipv6-icmp",
        59 => "ipv6-nonxt",
        60 => "ipv6-opts",
        73 => "rspf",
        81 => "vmtp",
        88 => "eigrp",
        89 => "ospf",
        93 => "ax.25",
        94 => "ipip",
        97 => "etherip",
        98 => "encap",
        103 => "pim",
        108 => "ipcomp",
        112 => "vrrp",
        115 => "l2tp",
        124 => "isis",
        132 => "sctp",
        133 => "fc",
        135 => "mobility-header",
        136 => "udplite",
        137 => "mpls-in-ip",
        138 => "manet",
        139 => "hip",
        140 => "shim6",
        141 => "wesp",
        142 => "rohc",
        143 => "ethernet",
        _ => return None,
    })
}

/// What a register holds.
#[derive(Clone, Debug)]
enum Val {
    Meta(MetaKey),
    Payload {
        hdr: Hdr,
        offset: u32,
        len: u32,
    },
    Ct {
        key: CtKey,
        dir: Option<CtDirection>,
    },
    TcpOpt {
        kind: u8,
        offset: u32,
        len: u32,
    },
    Rt(RtKey),
    Fib {
        result: FibResult,
        flags: FibFlags,
    },
    Socket(SocketKey),
    Osf {
        ttl: OsfTtl,
        version: bool,
    },
    Numgen {
        kind: NumgenKind,
        modulus: u32,
        offset: u32,
    },
    Hash {
        of: Option<Box<Val>>,
        modulus: u32,
        seed: Option<u32>,
        offset: u32,
    },
    Const(Vec<u8>),
    /// `(of & mask) ^ xor`.
    Bits {
        of: Box<Val>,
        mask: Vec<u8>,
        xor: Vec<u8>,
    },
    /// `of` turned to network order.
    Hton(Box<Val>),
    /// A map's value for `key`.
    Map {
        key: Box<Val>,
        map: String,
    },
    Concat(Vec<Val>),
}

/// A selector: how nft names it, the type of its values, whether those are
/// in network order, and their length.
struct Sel {
    text: String,
    ty: Ty,
    be: bool,
    len: usize,
}

/// What nft knows about a meta key: name, type, network order, length.
fn meta_key(key: MetaKey) -> Option<(&'static str, Ty, bool, usize)> {
    use MetaKey as K;
    Some(match key {
        K::Len => ("length", Ty::Int, false, 4),
        K::Protocol => ("protocol", Ty::EtherType, true, 2),
        K::Priority => ("priority", Ty::TcHandle, false, 4),
        K::Mark => ("mark", Ty::Mark, false, 4),
        K::Iif => ("iif", Ty::Ifindex, false, 4),
        K::Oif => ("oif", Ty::Ifindex, false, 4),
        K::IifName => ("iifname", Ty::Ifname, false, 16),
        K::OifName => ("oifname", Ty::Ifname, false, 16),
        K::SkUid => ("skuid", Ty::Int, false, 4),
        K::SkGid => ("skgid", Ty::Int, false, 4),
        K::NfTrace => ("nftrace", Ty::Int, false, 1),
        K::Secmark => ("secmark", Ty::Int, false, 4),
        K::NfProto => ("nfproto", Ty::NfProto, false, 1),
        K::L4Proto => ("l4proto", Ty::Proto, false, 1),
        K::BriIifName => ("ibrname", Ty::Ifname, false, 16),
        K::BriOifName => ("obrname", Ty::Ifname, false, 16),
        K::PktType => ("pkttype", Ty::PktType, false, 1),
        K::Cpu => ("cpu", Ty::Int, false, 4),
        K::CGroup => ("cgroup", Ty::Int, false, 4),
        K::PRandom => ("random", Ty::Int, false, 4),
        K::SecPath => ("ipsec", Ty::Bool, false, 1),
        K::IifKind => ("iifkind", Ty::Ifname, false, 16),
        K::OifKind => ("oifkind", Ty::Ifname, false, 16),
        K::BriIifPvid => ("ibrpvid", Ty::Int, false, 2),
        K::Sdif => ("sdif", Ty::Ifindex, false, 4),
        K::SdifName => ("sdifname", Ty::Ifname, false, 16),
        K::BriBroute => ("broute", Ty::Int, false, 1),
        _ => return None,
    })
}

/// `meta <key>`, or the key alone where nft writes it so.
fn meta_text(key: MetaKey) -> Option<String> {
    let (name, ..) = meta_key(key)?;
    let bare = matches!(
        key,
        MetaKey::Iif | MetaKey::Oif | MetaKey::IifName | MetaKey::OifName
    );
    Some(if bare {
        name.into()
    } else {
        format!("meta {name}")
    })
}

/// What nft knows about a ct key, given the network protocol.
fn ct_key(key: CtKey, net: Option<Net>) -> Option<(String, Ty, bool, usize)> {
    use CtKey as K;
    let addr = |which: &str| -> Option<(String, Ty, bool, usize)> {
        Some(match net? {
            Net::V4 => (format!("ip {which}"), Ty::Ipv4, true, 4),
            Net::V6 => (format!("ip6 {which}"), Ty::Ipv6, true, 16),
        })
    };
    let simple = |name: &str, ty, be, len| Some((name.to_string(), ty, be, len));
    match key {
        K::State => simple("state", Ty::CtState, false, 4),
        K::Direction => simple("direction", Ty::CtDir, false, 1),
        K::Status => simple("status", Ty::CtStatus, false, 4),
        K::Mark => simple("mark", Ty::Mark, false, 4),
        K::Secmark => simple("secmark", Ty::Int, false, 4),
        K::Helper => simple("helper", Ty::Str, false, 16),
        K::L3Protocol => simple("l3proto", Ty::NfProto, false, 1),
        K::Src => addr("saddr"),
        K::Dst => addr("daddr"),
        K::Protocol => simple("protocol", Ty::Proto, false, 1),
        K::ProtoSrc => simple("proto-src", Ty::Port, true, 2),
        K::ProtoDst => simple("proto-dst", Ty::Port, true, 2),
        K::Labels => simple("label", Ty::CtLabel, false, 16),
        K::Pkts => simple("packets", Ty::Int, false, 8),
        K::Bytes => simple("bytes", Ty::Int, false, 8),
        K::AvgPkt => simple("avgpkt", Ty::Int, false, 8),
        K::Zone => simple("zone", Ty::Int, false, 2),
        K::SrcIp => simple("ip saddr", Ty::Ipv4, true, 4),
        K::DstIp => simple("ip daddr", Ty::Ipv4, true, 4),
        K::SrcIp6 => simple("ip6 saddr", Ty::Ipv6, true, 16),
        K::DstIp6 => simple("ip6 daddr", Ty::Ipv6, true, 16),
        _ => None,
    }
}

fn ct_text(name: &str, dir: Option<CtDirection>) -> String {
    match dir {
        Some(CtDirection::Original) => format!("ct original {name}"),
        Some(CtDirection::Reply) => format!("ct reply {name}"),
        None => format!("ct {name}"),
    }
}

/// `tcp option <name> <field>`: kind, field offset and length in bytes.
fn tcp_option(kind: u8, offset: u32, len: u32) -> Option<&'static str> {
    Some(match (kind, offset, len) {
        (2, 2, 2) => "maxseg size",
        (3, 2, 1) => "window count",
        (8, 2, 4) => "timestamp tsval",
        (8, 6, 4) => "timestamp tsecr",
        _ => return None,
    })
}

/// A register slot: the value and whether anything has read it yet.
#[derive(Clone, Debug)]
struct Slot {
    val: Val,
    fresh: bool,
}

/// A protocol match a later field may make redundant.
#[derive(Clone, Copy, Debug)]
struct Dep {
    /// Its statement.
    index: usize,
    /// A header field (`ip protocol tcp`), not a meta key (`meta l4proto
    /// tcp`).
    payload: bool,
    /// The header whose protocol it names.
    names: Names,
}

/// What a protocol match names.
#[derive(Clone, Copy, Debug)]
enum Names {
    /// The network protocol (`meta nfproto`, `meta protocol`, `ether
    /// type`), when it is one nlink reads.
    Network(Option<Net>),
    /// The transport protocol (`meta l4proto`, `ip protocol`).
    Transport,
}

struct Lifter {
    family: Family,
    regs: [Option<Slot>; WORDS],
    /// Each statement's text, and whether a later field implies it.
    stmts: Vec<(String, bool)>,
    /// The protocol match each base depends on (nft's `pdeps`).
    deps: [Option<Dep>; 5],
    net: Option<Net>,
    l4: Option<u8>,
    /// The last statement, when it was an ordered comparison: nft writes a
    /// range as `>= first` then `<= last`, which this turns back into one.
    bound: Option<Bound>,
    /// Leave out what the rule has counted, as `nft -s` does.
    stateless: bool,
}

/// An ordered comparison, which the next one may close into a range.
#[derive(Clone, Debug)]
struct Bound {
    index: usize,
    sel: String,
    op: CmpOp,
    value: String,
}

impl Lifter {
    fn new(family: Family) -> Self {
        let net = match family {
            Family::Ip => Some(Net::V4),
            Family::Ip6 => Some(Net::V6),
            _ => None,
        };
        Self {
            family,
            regs: Default::default(),
            stmts: Vec::new(),
            deps: [None; 5],
            net,
            l4: None,
            bound: None,
            stateless: false,
        }
    }

    fn finish(self) -> String {
        let shown: Vec<_> = self
            .stmts
            .into_iter()
            .filter(|(_, killed)| !killed)
            .map(|(text, _)| text)
            .collect();
        shown.join(" ")
    }

    /// A table that sees more than one network protocol, where nft keeps
    /// the matches that say which.
    fn multi_family(&self) -> bool {
        matches!(self.family, Family::Inet | Family::Bridge | Family::Netdev)
    }

    fn push(&mut self, text: String) -> usize {
        self.bound = None;
        self.stmts.push((text, false));
        self.stmts.len() - 1
    }

    /// `sel <= last` right after `sel >= first` is `sel first-last`, and
    /// `sel > last` after `sel < first` is `sel != first-last`, as nft's
    /// `expr_may_merge_range` has it.
    fn close_range(&mut self, sel: &Sel, op: CmpOp, data: &[u8]) -> bool {
        let Some(bound) = &self.bound else {
            return false;
        };
        let not = match (bound.op, op) {
            (CmpOp::Gte, CmpOp::Lte) => "",
            (CmpOp::Lt, CmpOp::Gt) => "!= ",
            _ => return false,
        };
        if bound.sel != sel.text || bound.index + 1 != self.stmts.len() {
            return false;
        }
        let Some(last) = sel.ty.show(data, sel.be, true) else {
            return false;
        };
        let text = format!("{} {not}{}-{last}", sel.text, bound.value);
        self.stmts[bound.index].0 = text;
        self.bound = None;
        true
    }

    /// Drop the protocol match `base` depends on.
    fn kill(&mut self, base: usize) {
        if let Some(dep) = self.deps[base].take() {
            self.stmts[dep.index].1 = true;
        }
    }

    fn load(&mut self, reg: Register, val: Val) -> Option<()> {
        let w = word(reg)?;
        self.regs[w] = Some(Slot { val, fresh: true });
        Some(())
    }

    fn take(&mut self, reg: Register) -> Option<Val> {
        let slot = self.regs[word(reg)?].as_mut()?;
        slot.fresh = false;
        Some(slot.val.clone())
    }

    /// The constant an `immediate` left in `reg`.
    fn constant(&mut self, reg: Register) -> Option<Vec<u8>> {
        match self.take(reg)? {
            Val::Const(data) => Some(data),
            _ => None,
        }
    }

    /// The key at `reg`: one value, or the fields loaded into the words after
    /// it, as a concatenation. `len` is its length in bytes where the
    /// expression says (a hash does; a lookup leaves it to the set).
    fn take_key(&mut self, reg: Register, len: Option<u32>) -> Option<Val> {
        let mut w = word(reg)?;
        let mut parts = Vec::new();
        let mut covered = 0;
        loop {
            let slot = self.regs.get_mut(w)?.as_mut()?;
            slot.fresh = false;
            let size = val_len(&slot.val).filter(|&n| n > 0)?;
            parts.push(slot.val.clone());
            covered += size.next_multiple_of(4);
            w += size.div_ceil(4);
            let more = match len {
                Some(len) => covered < len as usize,
                None => w < WORDS && self.regs[w].as_ref().is_some_and(|s| s.fresh),
            };
            if !more {
                break;
            }
        }
        Some(if parts.len() == 1 {
            parts.pop()?
        } else {
            Val::Concat(parts)
        })
    }

    /// The header a payload load at `base` reads, from what the rule has
    /// matched so far.
    fn hdr(&self, base: PayloadBase) -> Option<Hdr> {
        Some(match base {
            PayloadBase::LinkLayer => Hdr::Ether,
            PayloadBase::Network => match self.net? {
                Net::V4 => Hdr::Ip,
                Net::V6 => Hdr::Ip6,
            },
            PayloadBase::Transport => match self.l4? {
                6 => Hdr::Tcp,
                17 => Hdr::Udp,
                136 => Hdr::Udplite,
                132 => Hdr::Sctp,
                33 => Hdr::Dccp,
                1 => Hdr::Icmp,
                58 => Hdr::Icmp6,
                _ => return None,
            },
        })
    }

    /// A field of `hdr` is named: the protocol match it implies goes
    /// (nft's `payload_dependency_kill`).
    fn payload_kills(&mut self, hdr: Hdr) {
        let base = hdr.base();
        let Some(dep) = self.deps[base] else { return };
        // `ip protocol tcp` also says IPv4, which a table of several network
        // protocols needs: `tcp dport` does not make it redundant there.
        if self.multi_family() && dep.payload && base == BASE_TRANSPORT {
            return;
        }
        self.kill(base);
    }

    /// A meta or ct match at the network base that may make the match before
    /// it redundant (nft's `ct_meta_may_dependency_kill`): `meta l4proto
    /// icmp` says IPv4, `ct original ip saddr` too.
    fn net_kills(&mut self, implies: Option<Net>) {
        let Some(dep) = self.deps[BASE_NET] else {
            return;
        };
        let kill = match dep.names {
            Names::Transport => true,
            Names::Network(named) => match self.family {
                Family::Ip => named == Some(Net::V4),
                Family::Ip6 => named == Some(Net::V6),
                Family::Inet | Family::Bridge | Family::Netdev => {
                    implies.is_some() && implies == named
                }
                _ => true,
            },
        };
        if kill {
            self.kill(BASE_NET);
        }
    }

    /// A match of `left` equal to `data`: when it says which protocol comes
    /// next, note it, and keep it as what later fields depend on.
    fn protocol_match(&mut self, left: &Val, data: &[u8], index: usize) {
        let net_of = |v: Option<u128>, ethertype: bool| match (v, ethertype) {
            (Some(2), false) | (Some(0x0800), true) => Some(Net::V4),
            (Some(10), false) | (Some(0x86dd), true) => Some(Net::V6),
            _ => None,
        };
        match left {
            Val::Meta(key @ (MetaKey::NfProto | MetaKey::Protocol)) => {
                let ethertype = *key == MetaKey::Protocol;
                let net = net_of(int(data, ethertype), ethertype);
                self.net = net;
                self.deps[BASE_NET] = Some(Dep {
                    index,
                    payload: false,
                    names: Names::Network(net),
                });
            }
            Val::Meta(MetaKey::L4Proto) => {
                let proto = int(data, false);
                let implies = match proto {
                    Some(1) => Some(Net::V4),
                    Some(58) => Some(Net::V6),
                    _ => None,
                };
                self.net_kills(implies);
                self.l4 = proto.and_then(|p| u8::try_from(p).ok());
                self.deps[BASE_TRANSPORT] = Some(Dep {
                    index,
                    payload: false,
                    names: Names::Transport,
                });
            }
            Val::Ct {
                key: CtKey::SrcIp | CtKey::DstIp,
                ..
            } => self.net_kills(Some(Net::V4)),
            Val::Ct {
                key: CtKey::SrcIp6 | CtKey::DstIp6,
                ..
            } => self.net_kills(Some(Net::V6)),
            Val::Payload { hdr, offset, len } => {
                let Some((name, _)) = hdr.field(offset * 8, len * 8) else {
                    return;
                };
                if !hdr.is_protocol(name) {
                    return;
                }
                let names = if *hdr == Hdr::Ether {
                    self.net = net_of(int(data, true), true);
                    Names::Network(self.net)
                } else {
                    self.l4 = data.first().copied();
                    Names::Transport
                };
                self.deps[hdr.base() + 1] = Some(Dep {
                    index,
                    payload: true,
                    names,
                });
            }
            _ => {}
        }
    }

    /// The selector `val` names, as the left of a match or what a statement
    /// writes.
    fn sel(&mut self, val: &Val) -> Option<Sel> {
        Some(match val {
            Val::Meta(key) => {
                let (_, ty, be, len) = meta_key(*key)?;
                Sel {
                    text: meta_text(*key)?,
                    ty,
                    be,
                    len,
                }
            }
            Val::Payload { hdr, offset, len } => {
                let (name, ty) = hdr.field(offset * 8, len * 8)?;
                self.payload_kills(*hdr);
                Sel {
                    text: format!("{} {name}", hdr.name()),
                    ty,
                    be: true,
                    len: *len as usize,
                }
            }
            Val::Ct { key, dir } => {
                let (name, ty, be, len) = ct_key(*key, self.net)?;
                Sel {
                    text: ct_text(&name, *dir),
                    ty,
                    be,
                    len,
                }
            }
            Val::TcpOpt { kind, offset, len } => {
                let name = tcp_option(*kind, *offset, *len)?;
                self.kill(BASE_TRANSPORT);
                Sel {
                    text: format!("tcp option {name}"),
                    ty: Ty::Int,
                    be: true,
                    len: *len as usize,
                }
            }
            Val::Rt(key) => {
                let (text, ty, be, len) = match key {
                    RtKey::Classid => ("rt classid", Ty::Int, false, 4),
                    RtKey::Nexthop4 => ("rt ip nexthop", Ty::Ipv4, true, 4),
                    RtKey::Nexthop6 => ("rt ip6 nexthop", Ty::Ipv6, true, 16),
                    RtKey::TcpMss => ("rt mtu", Ty::Int, false, 2),
                    RtKey::Xfrm => ("rt ipsec", Ty::Bool, false, 1),
                    #[allow(unreachable_patterns)]
                    _ => return None,
                };
                Sel {
                    text: text.into(),
                    ty,
                    be,
                    len,
                }
            }
            Val::Fib { result, flags } => fib_sel(*result, *flags)?,
            Val::Socket(key) => {
                let (name, ty, len) = match key {
                    SocketKey::Transparent => ("transparent", Ty::Int, 1),
                    SocketKey::Mark => ("mark", Ty::Mark, 4),
                    SocketKey::Wildcard => ("wildcard", Ty::Int, 1),
                    _ => return None,
                };
                Sel {
                    text: format!("socket {name}"),
                    ty,
                    be: false,
                    len,
                }
            }
            Val::Osf { ttl, version } => {
                let ttl = match ttl {
                    OsfTtl::Exact => "",
                    OsfTtl::Loose => "ttl loose ",
                    OsfTtl::Skip => "ttl skip ",
                };
                let what = if *version { "version" } else { "name" };
                Sel {
                    text: format!("osf {ttl}{what}"),
                    ty: Ty::Str,
                    be: false,
                    len: 16,
                }
            }
            Val::Numgen {
                kind,
                modulus,
                offset,
            } => {
                let kind = match kind {
                    NumgenKind::Incremental => "inc",
                    NumgenKind::Random => "random",
                };
                let mut text = format!("numgen {kind} mod {modulus}");
                if *offset != 0 {
                    let _ = write!(text, " offset {offset}");
                }
                Sel {
                    text,
                    ty: Ty::Int,
                    be: false,
                    len: 4,
                }
            }
            Val::Hash {
                of,
                modulus,
                seed,
                offset,
            } => {
                let mut text = match of {
                    Some(of) => format!("jhash {}", self.sel(of)?.text),
                    None => "symhash".into(),
                };
                let _ = write!(text, " mod {modulus}");
                if let Some(seed) = seed {
                    let _ = write!(text, " seed 0x{seed:x}");
                }
                if *offset != 0 {
                    let _ = write!(text, " offset {offset}");
                }
                Sel {
                    text,
                    ty: Ty::Int,
                    be: false,
                    len: 4,
                }
            }
            Val::Hton(of) => Sel {
                be: true,
                ..self.sel(of)?
            },
            Val::Map { key, map } => Sel {
                text: format!("{} map @{map}", self.sel(key)?.text),
                ty: Ty::Int,
                be: false,
                len: 4,
            },
            Val::Concat(parts) => {
                let mut texts = Vec::new();
                for part in parts {
                    texts.push(self.sel(part)?.text);
                }
                Sel {
                    text: texts.join(" . "),
                    ty: Ty::Int,
                    be: true,
                    len: 0,
                }
            }
            Val::Const(_) | Val::Bits { .. } => return None,
        })
    }

    /// What a statement writes: a constant of type `ty`, or something read
    /// from the packet (`meta mark set ct mark`).
    fn source(&mut self, val: &Val, ty: Ty, be: bool) -> Option<String> {
        match val {
            Val::Const(data) => ty.show(data, be, false),
            Val::Bits { of, mask, xor } => {
                let sel = self.sel(of)?;
                Some(format!(
                    "{}{}",
                    sel.text,
                    bits_text(sel.ty, sel.be, mask, xor)?
                ))
            }
            other => Some(self.sel(other)?.text),
        }
    }

    fn step(&mut self, expr: &RuleExpr) -> Option<()> {
        match expr {
            RuleExpr::Meta { dreg, key } => self.load(*dreg, Val::Meta(*key)),
            RuleExpr::Payload {
                dreg,
                base,
                offset,
                len,
            } => {
                within_header(*offset, *len)?;
                let hdr = self.hdr(*base)?;
                let val = Val::Payload {
                    hdr,
                    offset: *offset,
                    len: *len,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Ct { dreg, key } => self.load(
                *dreg,
                Val::Ct {
                    key: *key,
                    dir: None,
                },
            ),
            RuleExpr::CtDirectional {
                dreg,
                key,
                direction,
            } => {
                let val = Val::Ct {
                    key: *key,
                    dir: Some(*direction),
                };
                self.load(*dreg, val)
            }
            RuleExpr::Exthdr {
                dreg,
                op: ExthdrOp::TcpOpt,
                exthdr_type,
                offset,
                len,
            } => {
                let val = Val::TcpOpt {
                    kind: *exthdr_type,
                    offset: *offset,
                    len: *len,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Rt { dreg, key } => self.load(*dreg, Val::Rt(*key)),
            RuleExpr::Fib {
                dreg,
                result,
                flags,
            } => {
                let val = Val::Fib {
                    result: *result,
                    flags: *flags,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Socket { dreg, key } => self.load(*dreg, Val::Socket(*key)),
            RuleExpr::Osf { dreg, ttl, version } => {
                let val = Val::Osf {
                    ttl: *ttl,
                    version: *version,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Numgen {
                dreg,
                kind,
                modulus,
                offset,
            } => {
                let val = Val::Numgen {
                    kind: *kind,
                    modulus: *modulus,
                    offset: *offset,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Hash {
                dreg,
                kind,
                sreg,
                len,
                modulus,
                seed,
                offset,
            } => {
                let of = match kind {
                    HashKind::Jenkins => Some(Box::new(self.take_key((*sreg)?, Some(*len))?)),
                    HashKind::Sym => None,
                };
                let val = Val::Hash {
                    of,
                    modulus: *modulus,
                    seed: *seed,
                    offset: *offset,
                };
                self.load(*dreg, val)
            }
            RuleExpr::Immediate { dreg, data } => self.load(*dreg, Val::Const(data.clone())),
            RuleExpr::Bitwise {
                sreg,
                dreg,
                mask,
                xor,
                ..
            } => {
                let of = Box::new(self.take(*sreg)?);
                let val = Val::Bits {
                    of,
                    mask: mask.clone(),
                    xor: xor.clone(),
                };
                self.load(*dreg, val)
            }
            RuleExpr::Byteorder {
                sreg,
                dreg,
                op: ByteorderOp::Hton,
                ..
            } => {
                let of = Box::new(self.take(*sreg)?);
                self.load(*dreg, Val::Hton(of))
            }
            RuleExpr::Cmp { sreg, op, data } => {
                let left = self.take(*sreg)?;
                self.compare(&left, *op, data)
            }
            RuleExpr::Range { sreg, op, from, to } => {
                let left = self.take(*sreg)?;
                let sel = self.sel(&left)?;
                let first = sel.ty.show(from, sel.be, true)?;
                let last = sel.ty.show(to, sel.be, true)?;
                let not = if *op == RangeOp::Neq { "!= " } else { "" };
                self.push(format!("{} {not}{first}-{last}", sel.text));
                Some(())
            }
            // An anonymous set's elements are not in the rule, and nft prints
            // them in its place.
            RuleExpr::Lookup { set, .. } | RuleExpr::Dynset { set, .. } if is_anonymous(set) => {
                None
            }
            RuleExpr::Lookup {
                set,
                sreg,
                dreg,
                invert,
            } => {
                let key = self.take_key(*sreg, None)?;
                match dreg {
                    None => {
                        let sel = self.sel(&key)?;
                        let not = if *invert { "!= " } else { "" };
                        self.push(format!("{} {not}@{set}", sel.text));
                        Some(())
                    }
                    Some(_) if *invert => None,
                    Some(Register::Verdict) => {
                        let sel = self.sel(&key)?;
                        self.push(format!("{} vmap @{set}", sel.text));
                        Some(())
                    }
                    Some(dreg) => {
                        let val = Val::Map {
                            key: Box::new(key),
                            map: set.clone(),
                        };
                        self.load(*dreg, val)
                    }
                }
            }
            RuleExpr::Verdict(verdict) => {
                let text = verdict_text(verdict)?;
                self.push(text);
                Some(())
            }
            RuleExpr::MetaSet { key, sreg } => {
                let val = self.take(*sreg)?;
                let (_, ty, be, _) = meta_key(*key)?;
                let value = self.source(&val, ty, be)?;
                self.push(format!("{} set {value}", meta_text(*key)?));
                Some(())
            }
            RuleExpr::CtSet { key, sreg } => {
                if !matches!(
                    key,
                    CtKey::Mark | CtKey::Zone | CtKey::Labels | CtKey::Secmark
                ) {
                    return None;
                }
                let val = self.take(*sreg)?;
                let (name, ty, be, _) = ct_key(*key, self.net)?;
                let value = self.source(&val, ty, be)?;
                self.push(format!("ct {name} set {value}"));
                Some(())
            }
            RuleExpr::PayloadSet {
                sreg,
                base,
                offset,
                len,
                ..
            } => {
                within_header(*offset, *len)?;
                let hdr = self.hdr(*base)?;
                let val = self.take(*sreg)?;
                self.payload_write(hdr, *offset, *len, &val)
            }
            RuleExpr::ExthdrSet {
                sreg,
                op: ExthdrOp::TcpOpt,
                exthdr_type,
                offset,
                len,
            } => {
                let name = tcp_option(*exthdr_type, *offset, *len)?;
                let val = self.take(*sreg)?;
                // Unlike a load, a write leaves `meta l4proto tcp` in place.
                let value = self.source(&val, Ty::Int, true)?;
                self.push(format!("tcp option {name} set {value}"));
                Some(())
            }
            RuleExpr::Counter { .. } if self.stateless => {
                self.push("counter".into());
                Some(())
            }
            RuleExpr::Counter { packets, bytes } => {
                self.push(format!("counter packets {packets} bytes {bytes}"));
                Some(())
            }
            RuleExpr::Limit(limit) => {
                let text = limit_text(limit)?;
                self.push(text);
                Some(())
            }
            RuleExpr::Log(log) => {
                self.push(log_text(log));
                Some(())
            }
            RuleExpr::Quota {
                bytes,
                consumed,
                over,
                ..
            } => {
                let used = if self.stateless { 0 } else { *consumed };
                self.push(quota_text(*bytes, *over, used));
                Some(())
            }
            RuleExpr::Connlimit { count, over } => {
                self.push(connlimit_text(*count, *over));
                Some(())
            }
            RuleExpr::Notrack => {
                self.push("notrack".into());
                Some(())
            }
            RuleExpr::FlowOffload { flowtable } => {
                self.push(format!("flow add @{flowtable}"));
                Some(())
            }
            RuleExpr::Objref(ObjrefExpr::Named { object_type, name }) => {
                let what = match object_type {
                    ObjectType::Counter => "counter name",
                    ObjectType::Quota => "quota name",
                    ObjectType::Limit => "limit name",
                    ObjectType::CtHelper => "ct helper set",
                    ObjectType::Secmark => "meta secmark set",
                    #[allow(unreachable_patterns)]
                    _ => return None,
                };
                self.push(format!("{what} \"{name}\""));
                Some(())
            }
            // A map's value prints as the map's type, which the rule does not
            // say.
            RuleExpr::Dynset {
                set,
                op,
                sreg_key,
                sreg_data: None,
                timeout,
                invert: false,
                statements,
            } => {
                let key = self.take_key(*sreg_key, None)?;
                let key = self.sel(&key)?;
                let mut text = format!("{} @{set} {{ {}", dynset_op(*op)?, key.text);
                if let Some(timeout) = timeout {
                    let ms = u64::try_from(timeout.as_millis()).ok()?;
                    let _ = write!(text, " timeout {}", time_text(ms));
                }
                for statement in statements {
                    text.push(' ');
                    text.push_str(&element_statement(statement)?);
                }
                text.push_str(" }");
                self.push(text);
                Some(())
            }
            RuleExpr::Reject {
                reject_type,
                icmp_code,
            } => {
                let text = self.reject(*reject_type, icmp_code.unwrap_or(0))?;
                self.push(text);
                Some(())
            }
            RuleExpr::Masq { proto, flags } => {
                let mut text = "masquerade".to_string();
                if let Some((lo, hi)) = proto {
                    let _ = write!(text, " to :{}", self.ports(*lo, *hi)?);
                }
                text.push_str(&nat_flags(*flags));
                self.push(text);
                Some(())
            }
            RuleExpr::Redir { proto, flags } => {
                let mut text = "redirect".to_string();
                if let Some((lo, hi)) = proto {
                    let _ = write!(text, " to :{}", self.ports(*lo, *hi)?);
                }
                text.push_str(&nat_flags(*flags));
                self.push(text);
                Some(())
            }
            RuleExpr::Nat {
                nat_type,
                family,
                addr,
                proto,
                flags,
            } => {
                let text = self.nat(*nat_type, *family, *addr, *proto, *flags)?;
                self.push(text);
                Some(())
            }
            RuleExpr::Tproxy {
                family,
                sreg_addr,
                sreg_port,
            } => {
                let text = self.tproxy(*family, *sreg_addr, *sreg_port)?;
                self.push(text);
                Some(())
            }
            RuleExpr::Queue(queue) => {
                let text = self.queue(queue)?;
                self.push(text);
                Some(())
            }
            RuleExpr::Synproxy(synproxy) => {
                self.push(synproxy_text(synproxy));
                Some(())
            }
            RuleExpr::Dup {
                sreg_addr,
                sreg_dev,
            } => {
                let mut text = "dup".to_string();
                if let Some(addr) = sreg_addr {
                    let addr = self.constant(*addr)?;
                    let _ = write!(text, " to {}", address(&addr)?);
                    if let Some(dev) = sreg_dev {
                        let dev = self.constant(*dev)?;
                        let _ = write!(text, " device {}", Ty::Ifindex.show(&dev, false, false)?);
                    }
                } else if let Some(dev) = sreg_dev {
                    let dev = self.constant(*dev)?;
                    let _ = write!(text, " to {}", Ty::Ifindex.show(&dev, false, false)?);
                }
                self.push(text);
                Some(())
            }
            RuleExpr::Fwd {
                sreg_dev,
                sreg_addr,
            } => {
                let dev = self.constant(*sreg_dev)?;
                let dev = Ty::Ifindex.show(&dev, false, false)?;
                let text = match sreg_addr {
                    Some((addr, nfproto)) => {
                        let addr = self.constant(*addr)?;
                        let family = match *nfproto {
                            2 => "ip",
                            10 => "ip6",
                            _ => return None,
                        };
                        format!("fwd {family} to {} device {dev}", address(&addr)?)
                    }
                    None => format!("fwd to {dev}"),
                };
                self.push(text);
                Some(())
            }
            _ => None,
        }
    }

    /// A `cmp` of `left` with `data`.
    fn compare(&mut self, left: &Val, op: CmpOp, data: &[u8]) -> Option<()> {
        let op_text = match op {
            CmpOp::Eq => "",
            CmpOp::Neq => "!= ",
            CmpOp::Lt => "< ",
            CmpOp::Lte => "<= ",
            CmpOp::Gt => "> ",
            CmpOp::Gte => ">= ",
        };
        let text = match left {
            Val::Bits { of, mask, xor } if xor.iter().all(|&b| b == 0) => {
                self.masked(of, mask, op, op_text, data)?
            }
            Val::Payload { hdr, offset, len } if hdr.field(offset * 8, len * 8).is_none() => {
                // An address prefix, loaded as its leading bytes.
                let (name, bits, ty) = hdr.field_from(offset * 8, len * 8)?;
                if !ty.has_prefix() || !matches!(op, CmpOp::Eq | CmpOp::Neq) {
                    return None;
                }
                self.payload_kills(*hdr);
                let mut full = data.to_vec();
                full.resize(bits as usize / 8, 0);
                let addr = ty.show(&full, true, false)?;
                format!("{} {name} {op_text}{addr}/{}", hdr.name(), len * 8)
            }
            _ => {
                let sel = self.sel(left)?;
                if self.close_range(&sel, op, data) {
                    return Some(());
                }
                let value = sel.ty.show(data, sel.be, false)?;
                // nft writes `==` before a bitmask it compares whole.
                let op_text = if op == CmpOp::Eq && sel.ty.is_flags() {
                    "== "
                } else {
                    op_text
                };
                let text = format!("{} {op_text}{value}", sel.text);
                if matches!(op, CmpOp::Lt | CmpOp::Gte) {
                    let index = self.push(text);
                    self.bound = Some(Bound {
                        index,
                        sel: sel.text,
                        op,
                        value: sel.ty.show(data, sel.be, true)?,
                    });
                    return Some(());
                }
                text
            }
        };
        let index = self.push(text);
        if op == CmpOp::Eq {
            self.protocol_match(left, data, index);
        }
        Some(())
    }

    /// `of & mask` compared with `data`: a field narrower than the bytes
    /// loaded (`ip dscp cs1`), a prefix (`ip saddr 10.0.0.0/12`), a flag test
    /// (`ct state established,related`), or a masked value (`meta mark &
    /// 0x0000ff00 == 0x00000100`).
    fn masked(
        &mut self,
        of: &Val,
        mask: &[u8],
        op: CmpOp,
        op_text: &str,
        data: &[u8],
    ) -> Option<String> {
        let eq_or_neq = matches!(op, CmpOp::Eq | CmpOp::Neq);
        if let Val::Payload { hdr, offset, len } = of {
            let loaded = len * 8;
            let span = mask_span(int(mask, true)?, loaded);
            match hdr.field(offset * 8, loaded) {
                Some((name, ty)) if ty.has_prefix() => {
                    let (first, bits) = span?;
                    if first != 0 || !eq_or_neq {
                        return None;
                    }
                    self.payload_kills(*hdr);
                    let addr = ty.show(data, true, false)?;
                    return Some(format!("{} {name} {op_text}{addr}/{bits}", hdr.name()));
                }
                Some(_) => {}
                None => {
                    let (first, bits) = span?;
                    if let Some((name, full, ty)) = hdr.field_from(offset * 8, loaded) {
                        // An address prefix loaded as part of the address.
                        if !ty.has_prefix() || first != 0 || !eq_or_neq {
                            return None;
                        }
                        self.payload_kills(*hdr);
                        let mut padded = data.to_vec();
                        padded.resize(full as usize / 8, 0);
                        let addr = ty.show(&padded, true, false)?;
                        return Some(format!("{} {name} {op_text}{addr}/{bits}", hdr.name()));
                    }
                    let (name, ty) = hdr.field(offset * 8 + first, bits)?;
                    let shift = loaded - first - bits;
                    let value = (int(data, true)? >> shift) & low_bits(bits);
                    let width = (bits as usize).div_ceil(8);
                    let bytes = value.to_be_bytes();
                    self.payload_kills(*hdr);
                    let value = ty.show(&bytes[16 - width..], true, false)?;
                    return Some(format!("{} {name} {op_text}{value}", hdr.name()));
                }
            }
        }
        let sel = self.sel(of)?;
        let zero = data.iter().all(|&b| b == 0);
        if sel.ty.is_flags() && zero && eq_or_neq {
            let names = flag_names(sel.ty, int(mask, sel.be)?)?;
            let not = if op == CmpOp::Eq { "! " } else { "" };
            return Some(format!("{} {not}{}", sel.text, names.join(",")));
        }
        if sel.ty == Ty::CtLabel && zero && op == CmpOp::Neq {
            let label = sel.ty.show(mask, sel.be, false)?;
            return Some(format!("{} {label}", sel.text));
        }
        let mask_text = mask_value(sel.ty, mask, sel.be)?;
        let value = sel.ty.show(data, sel.be, false)?;
        let op_text = if op_text.is_empty() { "== " } else { op_text };
        Some(format!("{} & {mask_text} {op_text}{value}", sel.text))
    }

    /// A header write: `ip saddr set 10.0.0.9`, or one that reads the bytes
    /// around a narrower field and keeps the rest (`ip dscp set cs1`).
    fn payload_write(&mut self, hdr: Hdr, offset: u32, len: u32, val: &Val) -> Option<()> {
        let text = match val {
            Val::Const(data) => {
                let (name, ty) = hdr.field(offset * 8, len * 8)?;
                format!("{} {name} set {}", hdr.name(), ty.show(data, true, false)?)
            }
            Val::Bits { of, mask, xor } => {
                let Val::Payload {
                    hdr: read,
                    offset: at,
                    len: bytes,
                } = of.as_ref()
                else {
                    return None;
                };
                if (*read, *at, *bytes) != (hdr, offset, len) {
                    return None;
                }
                let loaded = len * 8;
                let kept = int(mask, true)?;
                let (first, bits) = mask_span(!kept & low_bits(loaded), loaded)?;
                let (name, ty) = hdr.field(offset * 8 + first, bits)?;
                let shift = loaded - first - bits;
                let value = (int(xor, true)? >> shift) & low_bits(bits);
                let width = (bits as usize).div_ceil(8);
                let value = ty.show(&value.to_be_bytes()[16 - width..], true, false)?;
                format!("{} {name} set {value}", hdr.name())
            }
            other => {
                let (name, ty) = hdr.field(offset * 8, len * 8)?;
                let value = self.source(other, ty, true)?;
                format!("{} {name} set {value}", hdr.name())
            }
        };
        self.payload_kills(hdr);
        self.push(text);
        Some(())
    }

    /// `reject`, as nft's `stmt_reject_postprocess` and `reject_stmt_print`
    /// have it.
    fn reject(&mut self, reject_type: u32, code: u8) -> Option<String> {
        let net = match self.family {
            Family::Ip => Some(Net::V4),
            Family::Ip6 => Some(Net::V6),
            _ => self.net,
        };
        if self.multi_family() {
            if reject_type != NFT_REJECT_ICMPX_UNREACH {
                self.kill(BASE_NET);
            }
        } else if reject_type == NFT_REJECT_TCP_RST {
            self.kill(BASE_TRANSPORT);
        }
        // A table of several protocols always says which ICMP.
        let verbose = self.multi_family();
        let code_byte = [code];
        Some(match reject_type {
            NFT_REJECT_TCP_RST => "reject with tcp reset".into(),
            NFT_REJECT_ICMPX_UNREACH if code == NFT_REJECT_ICMPX_PORT_UNREACH => "reject".into(),
            NFT_REJECT_ICMPX_UNREACH => {
                let name = match code {
                    0 => "no-route".to_string(),
                    1 => "port-unreachable".into(),
                    2 => "host-unreachable".into(),
                    3 => "admin-prohibited".into(),
                    n => n.to_string(),
                };
                format!("reject with icmpx {name}")
            }
            NFT_REJECT_ICMP_UNREACH => match net {
                Some(Net::V4) if !verbose && code == 3 => "reject".into(),
                Some(Net::V4) => {
                    format!(
                        "reject with icmp {}",
                        Ty::IcmpCode.show(&code_byte, false, false)?
                    )
                }
                Some(Net::V6) if !verbose && code == 4 => "reject".into(),
                Some(Net::V6) => {
                    format!(
                        "reject with icmpv6 {}",
                        Ty::Icmp6Code.show(&code_byte, false, false)?
                    )
                }
                None => "reject".into(),
            },
            _ => return None,
        })
    }

    /// The ports a NAT range names: one, or `first-last`.
    fn ports(&mut self, lo: Register, hi: Register) -> Option<String> {
        let first = self.constant(lo)?;
        let first = Ty::Port.show(&first, true, false)?;
        if hi == lo {
            return Some(first);
        }
        let last = self.constant(hi)?;
        Some(format!("{first}-{}", Ty::Port.show(&last, true, false)?))
    }

    fn nat(
        &mut self,
        nat_type: NatType,
        family: Family,
        addr: Option<(Register, Register)>,
        proto: Option<(Register, Register)>,
        flags: NatFlags,
    ) -> Option<String> {
        let mut text = match nat_type {
            NatType::Snat => "snat".to_string(),
            NatType::Dnat => "dnat".to_string(),
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        let v6 = family == Family::Ip6;
        let addr = match addr {
            Some((lo, hi)) => Some(match self.take(lo)? {
                Val::Const(first) => {
                    let last = if hi == lo {
                        None
                    } else {
                        Some(self.constant(hi)?)
                    };
                    nat_addresses(&first, last.as_deref(), v6, proto.is_some())?
                }
                Val::Map { key, map } => format!("{} map @{map}", self.sel(&key)?.text),
                _ => return None,
            }),
            None => None,
        };
        let ports = match proto {
            Some((lo, hi)) => Some(self.ports(lo, hi)?),
            None => None,
        };
        if addr.is_some() || ports.is_some() {
            if self.family == Family::Inet {
                text.push_str(if v6 { " ip6" } else { " ip" });
            }
            if flags.contains(NatFlags::NETMAP) {
                text.push_str(" prefix");
            }
            text.push_str(" to");
        }
        if let Some(addr) = &addr {
            let _ = write!(text, " {addr}");
        }
        if let Some(ports) = ports {
            if addr.is_none() {
                text.push(' ');
            }
            let _ = write!(text, ":{ports}");
        }
        text.push_str(&nat_flags(flags));
        Some(text)
    }

    fn tproxy(
        &mut self,
        family: u8,
        sreg_addr: Option<Register>,
        sreg_port: Option<Register>,
    ) -> Option<String> {
        let mut text = "tproxy".to_string();
        if self.family == Family::Inet {
            match family {
                0 => {}
                2 => text.push_str(" ip"),
                10 => text.push_str(" ip6"),
                _ => return None,
            }
        }
        text.push_str(" to");
        let has_addr = sreg_addr.is_some();
        if let Some(reg) = sreg_addr {
            let addr = self.constant(reg)?;
            let shown = address(&addr)?;
            if addr.len() == 16 {
                let _ = write!(text, " [{shown}]");
            } else {
                let _ = write!(text, " {shown}");
            }
        }
        if let Some(reg) = sreg_port {
            let port = self.constant(reg)?;
            if !has_addr {
                text.push(' ');
            }
            let _ = write!(text, ":{}", Ty::Port.show(&port, true, false)?);
        }
        Some(text)
    }

    fn queue(&mut self, queue: &QueueExpr) -> Option<String> {
        let mut text = "queue".to_string();
        let mut delim = " flags ";
        if queue.flags.contains(QueueFlags::BYPASS) {
            let _ = write!(text, "{delim}bypass");
            delim = ",";
        }
        if queue.flags.contains(QueueFlags::FANOUT) {
            let _ = write!(text, "{delim}fanout");
        }
        match queue.sreg {
            Some(reg) => {
                let val = self.take(reg)?;
                let _ = write!(text, " to {}", self.source(&val, Ty::Int, false)?);
            }
            None if queue.total > 1 => {
                let last = u32::from(queue.num) + u32::from(queue.total) - 1;
                let _ = write!(text, " to {}-{last}", queue.num);
            }
            None => {
                let _ = write!(text, " to {}", queue.num);
            }
        }
        Some(text)
    }
}

/// A payload load no header field could be: past the headers nlink names,
/// or wider than a register. Refused before any bit arithmetic on it.
fn within_header(offset: u32, len: u32) -> Option<()> {
    (offset <= 255 && (1..=16).contains(&len)).then_some(())
}

/// A set nft made for a rule's `{ ... }`: `__set0`, `__map0`.
fn is_anonymous(set: &str) -> bool {
    set.starts_with("__")
}

/// The length in bytes of what a register holds.
fn val_len(val: &Val) -> Option<usize> {
    Some(match val {
        Val::Meta(key) => meta_key(*key)?.3,
        Val::Payload { len, .. } | Val::TcpOpt { len, .. } => *len as usize,
        Val::Ct { key, .. } => match key {
            CtKey::Src | CtKey::Dst => return None,
            key => ct_key(*key, None)?.3,
        },
        Val::Rt(RtKey::Nexthop6) => 16,
        Val::Rt(RtKey::TcpMss) => 2,
        Val::Rt(RtKey::Xfrm) => 1,
        Val::Rt(_) => 4,
        Val::Fib { result, flags } => fib_sel(*result, *flags)?.len,
        Val::Socket(SocketKey::Mark) => 4,
        Val::Socket(_) => 1,
        Val::Osf { .. } => 16,
        Val::Numgen { .. } | Val::Hash { .. } | Val::Map { .. } => 4,
        Val::Const(data) => data.len(),
        Val::Bits { mask, .. } => mask.len(),
        Val::Hton(of) => val_len(of)?,
        Val::Concat(parts) => {
            let mut total = 0;
            for part in parts {
                total += val_len(part)?.next_multiple_of(4);
            }
            total
        }
    })
}

/// `fib saddr . iif oif`: the keys it looks up by, then what it returns.
fn fib_sel(result: FibResult, flags: FibFlags) -> Option<Sel> {
    let known = FibFlags::SADDR
        | FibFlags::DADDR
        | FibFlags::MARK
        | FibFlags::IIF
        | FibFlags::OIF
        | FibFlags::PRESENT;
    if !(flags - known).is_empty() {
        return None;
    }
    let keys: Vec<_> = [
        (FibFlags::SADDR, "saddr"),
        (FibFlags::DADDR, "daddr"),
        (FibFlags::MARK, "mark"),
        (FibFlags::IIF, "iif"),
        (FibFlags::OIF, "oif"),
    ]
    .into_iter()
    .filter(|(flag, _)| flags.contains(*flag))
    .map(|(_, name)| name)
    .collect();
    let (name, ty, len) = match result {
        FibResult::Oif => ("oif", Ty::Ifindex, 4),
        FibResult::OifName => ("oifname", Ty::Ifname, 16),
        FibResult::AddrType => ("type", Ty::AddrType, 4),
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    // With `present`, the result is whether there is one.
    let (ty, len) = if flags.contains(FibFlags::PRESENT) {
        (Ty::Bool, 4)
    } else {
        (ty, len)
    };
    Some(Sel {
        text: format!("fib {} {name}", keys.join(" . ")),
        ty,
        be: false,
        len,
    })
}

/// The set bits of `mask`, a `width`-bit value: where the run starts from
/// the top, and how long it is. `None` unless they are one run.
fn mask_span(mask: u128, width: u32) -> Option<(u32, u32)> {
    if mask == 0 || width > 128 {
        return None;
    }
    let bits = mask.count_ones();
    let low = mask.trailing_zeros();
    if mask >> low != low_bits(bits) {
        return None;
    }
    let first = width.checked_sub(low + bits)?;
    Some((first, bits))
}

fn low_bits(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// `v`, `len` bytes wide, in network order when `be`, else the host's.
fn to_bytes(v: u128, len: usize, be: bool) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut out = bytes[16 - len..].to_vec();
    if !be && cfg!(target_endian = "little") {
        out.reverse();
    }
    out
}

/// A mask as nft prints it: a flag list in parentheses, else a value.
fn mask_value(ty: Ty, mask: &[u8], be: bool) -> Option<String> {
    if ty.is_flags() {
        let names = flag_names(ty, int(mask, be)?)?;
        return Some(match names.as_slice() {
            [one] => (*one).to_string(),
            several => format!("({})", several.join(" | ")),
        });
    }
    ty.show(mask, be, false)
}

/// What a `bitwise` does to a value, as nft's
/// `netlink_parse_bitwise_mask_xor` prints it: ` & mask`, ` ^ xor`, ` | or`.
fn bits_text(ty: Ty, be: bool, mask: &[u8], xor: &[u8]) -> Option<String> {
    let len = mask.len();
    let all = low_bits(u32::try_from(len * 8).ok()?);
    let (mut m, mut x) = (int(mask, be)?, int(xor, be)?);
    let mut o = 0;
    if m != all || x != 0 {
        o = (m & x) ^ x;
        x &= m;
        m |= o;
    }
    let show = |v: u128| ty.show(&to_bytes(v, len, be), be, false);
    let mut text = String::new();
    if m != all {
        let _ = write!(text, " & {}", show(m)?);
    }
    if x != 0 {
        let _ = write!(text, " ^ {}", show(x)?);
    }
    if o != 0 {
        let _ = write!(text, " | {}", show(o)?);
    }
    Some(text)
}

/// An address an `immediate` loaded.
fn address(data: &[u8]) -> Option<String> {
    match data.len() {
        4 => Ty::Ipv4.show(data, true, false),
        16 => Ty::Ipv6.show(data, true, false),
        _ => None,
    }
}

/// A NAT's addresses: one, a prefix where the range is one (nft's
/// `range_expr_to_prefix`), or `first-last`. An IPv6 address goes in
/// brackets when a port follows.
fn nat_addresses(first: &[u8], last: Option<&[u8]>, v6: bool, ports: bool) -> Option<String> {
    let wrap = |a: String| if v6 && ports { format!("[{a}]") } else { a };
    let Some(last) = last else {
        return Some(wrap(address(first)?));
    };
    if last.len() != first.len() {
        return None;
    }
    let bits = u32::try_from(first.len() * 8).ok()?;
    let (lo, hi) = (int(first, true)?, int(last, true)?);
    let host = lo ^ hi;
    if host != 0 && lo & host == 0 && host == low_bits(host.count_ones()) {
        let prefix = bits.checked_sub(host.count_ones())?;
        return Some(format!("{}/{prefix}", address(first)?));
    }
    Some(format!(
        "{}-{}",
        wrap(address(first)?),
        wrap(address(last)?)
    ))
}

fn nat_flags(flags: NatFlags) -> String {
    let mut names = Vec::new();
    if flags.contains(NatFlags::PROTO_RANDOM) {
        names.push("random");
    }
    if flags.contains(NatFlags::PROTO_RANDOM_FULLY) {
        names.push("fully-random");
    }
    if flags.contains(NatFlags::PERSISTENT) {
        names.push("persistent");
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" {}", names.join(","))
    }
}

fn verdict_text(verdict: &Verdict) -> Option<String> {
    Some(match verdict {
        Verdict::Accept => "accept".into(),
        Verdict::Drop => "drop".into(),
        Verdict::Continue => "continue".into(),
        Verdict::Return => "return".into(),
        Verdict::JumpTo(chain) => format!("jump {chain}"),
        Verdict::GotoTo(chain) => format!("goto {chain}"),
        #[allow(unreachable_patterns)]
        _ => return None,
    })
}

/// A byte count as nft prints it: in the largest unit that divides it, up to
/// mbytes.
fn data_rate(bytes: u64) -> (u64, &'static str) {
    const UNITS: [&str; 3] = ["bytes", "kbytes", "mbytes"];
    let (mut value, mut unit) = (bytes, 0);
    while value != 0 && unit + 1 < UNITS.len() && value % 1024 == 0 {
        value /= 1024;
        unit += 1;
    }
    (value, UNITS[unit])
}

fn limit_text(limit: &LimitExpr) -> Option<String> {
    let unit = match limit.unit {
        LimitUnit::Second => "second",
        LimitUnit::Minute => "minute",
        LimitUnit::Hour => "hour",
        LimitUnit::Day => "day",
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    let over = if limit.over { "over " } else { "" };
    Some(match limit.kind {
        LimitKind::Packets => format!(
            "limit rate {over}{}/{unit} burst {} packets",
            limit.rate, limit.burst
        ),
        LimitKind::Bytes => {
            let (rate, rate_unit) = data_rate(limit.rate);
            let mut text = format!("limit rate {over}{rate} {rate_unit}/{unit}");
            if limit.burst != 0 {
                let (burst, burst_unit) = data_rate(u64::from(limit.burst));
                let _ = write!(text, " burst {burst} {burst_unit}");
            }
            text
        }
        #[allow(unreachable_patterns)]
        _ => return None,
    })
}

fn log_text(log: &LogExpr) -> String {
    let mut text = "log".to_string();
    if let Some(prefix) = &log.prefix {
        let _ = write!(text, " prefix \"{prefix}\"");
    }
    if let Some(group) = log.group {
        let _ = write!(text, " group {group}");
    }
    if let Some(snaplen) = log.snaplen {
        let _ = write!(text, " snaplen {snaplen}");
    }
    if let Some(threshold) = log.queue_threshold {
        let _ = write!(text, " queue-threshold {threshold}");
    }
    if let Some(level) = log.level
        && level != LogLevel::Warning
    {
        let _ = write!(text, " level {}", level.name());
    }
    if log.flags.contains(LogFlags::ALL) {
        text.push_str(" flags all");
    } else {
        let seq = log.flags.contains(LogFlags::TCP_SEQUENCE);
        let opt = log.flags.contains(LogFlags::TCP_OPTIONS);
        if seq || opt {
            text.push_str(" flags tcp");
            if seq {
                text.push_str(" sequence");
            }
            if opt {
                text.push_str(if seq { ",options" } else { " options" });
            }
        }
        if log.flags.contains(LogFlags::IP_OPTIONS) {
            text.push_str(" flags ip options");
        }
        if log.flags.contains(LogFlags::SKUID) {
            text.push_str(" flags skuid");
        }
        if log.flags.contains(LogFlags::ETHER) {
            text.push_str(" flags ether");
        }
    }
    text
}

/// `quota`, and what it has used when that is known and not nothing.
fn quota_text(bytes: u64, over: bool, used: u64) -> String {
    let (n, unit) = data_rate(bytes);
    let over = if over { "over " } else { "" };
    let mut text = format!("quota {over}{n} {unit}");
    if used != 0 {
        let (n, unit) = data_rate(used);
        let _ = write!(text, " used {n} {unit}");
    }
    text
}

fn connlimit_text(count: u32, over: bool) -> String {
    let over = if over { "over " } else { "" };
    format!("ct count {over}{count}")
}

fn synproxy_text(synproxy: &SynproxyExpr) -> String {
    let mut text = "synproxy".to_string();
    if let Some(mss) = synproxy.mss {
        let _ = write!(text, " mss {mss}");
    }
    if let Some(wscale) = synproxy.wscale {
        let _ = write!(text, " wscale {wscale}");
    }
    if synproxy.timestamp {
        text.push_str(" timestamp");
    }
    if synproxy.sack_perm {
        text.push_str(" sack-perm");
    }
    text
}

fn dynset_op(op: DynsetOp) -> Option<&'static str> {
    Some(match op {
        DynsetOp::Add => "add",
        DynsetOp::Update => "update",
        DynsetOp::Delete => "delete",
        #[allow(unreachable_patterns)]
        _ => return None,
    })
}

/// A set element's statement, printed as nft prints it there: without its
/// state.
fn element_statement(statement: &RuleExpr) -> Option<String> {
    Some(match statement {
        RuleExpr::Counter { .. } => "counter".into(),
        RuleExpr::Limit(limit) => limit_text(limit)?,
        RuleExpr::Quota { bytes, over, .. } => quota_text(*bytes, *over, 0),
        RuleExpr::Connlimit { count, over } => connlimit_text(*count, *over),
        _ => return None,
    })
}

/// A duration as nft prints it: `1d2h3m4s5ms`, each part only when it is
/// not zero.
fn time_text(mut ms: u64) -> String {
    let mut text = String::new();
    for (unit, size) in [
        ("d", 86_400_000),
        ("h", 3_600_000),
        ("m", 60_000),
        ("s", 1000),
    ] {
        if ms >= size {
            let _ = write!(text, "{}{unit}", ms / size);
            ms %= size;
        }
    }
    if ms > 0 {
        let _ = write!(text, "{ms}ms");
    }
    if text.is_empty() {
        text.push_str("0s");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::super::{
        ChainName, CtDirection, CtKey, CtState, DynsetExpr, DynsetOp, Expr, Family, FibFlags,
        Generated, HeaderWrite, IcmpxCode, LimitUnit, LogExpr, LookupExpr, MetaKey, NatStatement,
        NumgenKind, PacketField, RawExpr, Register, Rule, RuleExpr, SocketMatch, TcpFlags,
    };
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn rule() -> Rule {
        Rule::new("t", "c")
    }

    /// Each builder's rule, printed as nft 1.1.3 lists it once installed:
    /// the integration test `nftables_lift` checks the same against the
    /// kernel and nft.
    #[test]
    fn a_rule_prints_as_nft_lists_it() {
        let inet = Family::Inet;
        let cases: Vec<(Rule, Family, &str)> = vec![
            (
                rule().match_tcp_dport(22).counter().accept(),
                inet,
                "tcp dport 22 counter packets 0 bytes 0 accept",
            ),
            (rule().match_udp_sport_not(53), inet, "udp sport != 53"),
            (
                rule().match_saddr_v4(v4("10.0.0.0"), 8).drop(),
                inet,
                "ip saddr 10.0.0.0/8 drop",
            ),
            (
                rule().match_saddr_v4(v4("10.0.0.0"), 8).drop(),
                Family::Ip,
                "ip saddr 10.0.0.0/8 drop",
            ),
            (
                rule().match_daddr_v6_not(v6("fd00::1"), 128),
                inet,
                "ip6 daddr != fd00::1",
            ),
            (
                rule().match_iif("eth0").match_oif_prefix("veth"),
                inet,
                "iifname \"eth0\" oifname \"veth*\"",
            ),
            (
                rule()
                    .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept(),
                inet,
                "ct state established,related accept",
            ),
            (
                rule().match_ct_addr(CtDirection::Original, true, IpAddr::V4(v4("1.2.3.4"))),
                inet,
                "ct original ip saddr 1.2.3.4",
            ),
            (rule().match_ct_label(3), inet, "ct label 3"),
            (
                rule().match_mark_masked(0x100, 0xff00),
                inet,
                "meta mark & 0x0000ff00 == 0x00000100",
            ),
            (
                rule().set_mark_masked(0x100, 0xff00),
                inet,
                "meta mark set meta mark & 0xffff01ff | 0x00000100",
            ),
            (
                rule().match_range(PacketField::Mark, 0x10u32, 0x20u32),
                inet,
                "meta mark 0x00000010-0x00000020",
            ),
            (
                rule().match_range_not(PacketField::TcpDport, 1000u16, 2000u16),
                inet,
                "tcp dport != 1000-2000",
            ),
            (
                rule().match_tcp_flags(
                    TcpFlags::SYN,
                    TcpFlags::SYN | TcpFlags::ACK | TcpFlags::RST | TcpFlags::FIN,
                ),
                inet,
                "tcp flags & (fin | syn | rst | ack) == syn",
            ),
            (
                rule().match_icmp_type(8).accept(),
                inet,
                "icmp type echo-request accept",
            ),
            (
                rule().match_concat_in_set(&[PacketField::Ip4Saddr, PacketField::TcpDport], "s"),
                inet,
                "ip saddr . tcp dport @s",
            ),
            (
                rule().match_in_interval_set(PacketField::Mark, "m"),
                inet,
                "meta mark @m",
            ),
            (
                rule().vmap(PacketField::TcpDport, "v"),
                inet,
                "tcp dport vmap @v",
            ),
            (
                rule().set_mark_from_map(PacketField::Ip4Saddr, "m"),
                inet,
                "meta mark set ip saddr map @m",
            ),
            (
                rule().update_in_set(PacketField::Ip4Saddr, "s", Some(Duration::from_secs(90))),
                inet,
                "update @s { ip saddr timeout 1m30s }",
            ),
            (
                rule().dynset(
                    PacketField::Ip4Saddr,
                    DynsetExpr::new(DynsetOp::Add, "s", Register::R0).counter(),
                ),
                inet,
                "add @s { ip saddr counter }",
            ),
            (
                rule().limit(10, LimitUnit::Minute),
                inet,
                "limit rate 10/minute burst 5 packets",
            ),
            (
                rule().limit_bytes(crate::Bytes::mib(1), LimitUnit::Second),
                inet,
                "limit rate 1 mbytes/second",
            ),
            (
                rule().quota_until(100 * 1024 * 1024),
                inet,
                "quota 100 mbytes",
            ),
            (
                rule().expr(LogExpr::new().prefix("p: ").group(2)),
                inet,
                "log prefix \"p: \" group 2",
            ),
            (
                rule().match_fib_missing(FibFlags::SADDR | FibFlags::IIF),
                inet,
                "fib saddr . iif oif missing",
            ),
            (
                rule().set_priority(crate::TcHandle::new(1, 0x10)),
                inet,
                "meta priority set 1:10",
            ),
            (rule().restore_mark_from_ct(), inet, "meta mark set ct mark"),
            (rule().set_ct_label(5), inet, "ct label set 5"),
            (
                rule().clamp_tcp_mss(1400),
                inet,
                "meta l4proto tcp tcp option maxseg size set 1400",
            ),
            (
                rule().clamp_tcp_mss_to_pmtu(),
                inet,
                "meta l4proto tcp tcp option maxseg size set rt mtu",
            ),
            (
                rule()
                    .generate(Generated::Jhash {
                        fields: vec![PacketField::Ip4Saddr, PacketField::TcpDport],
                        modulus: 4,
                        seed: Some(1),
                        offset: 0,
                    })
                    .set_meta_from(MetaKey::Mark),
                inet,
                "meta mark set jhash ip saddr . tcp dport mod 4 seed 0x1",
            ),
            (
                rule()
                    .generate(Generated::Numgen {
                        kind: NumgenKind::Incremental,
                        modulus: 2,
                        offset: 0,
                    })
                    .set_ct_from(CtKey::Mark),
                inet,
                "ct mark set numgen inc mod 2",
            ),
            (
                rule().match_socket(SocketMatch::Mark(7)),
                inet,
                "socket mark 0x00000007",
            ),
            (
                rule().set_header(HeaderWrite::IpDscp(8)),
                inet,
                "ip dscp set cs1",
            ),
            (
                rule().set_header(HeaderWrite::Ip6Dscp(18)),
                inet,
                "ip6 dscp set af21",
            ),
            (
                rule().set_header(HeaderWrite::Ip6Daddr(v6("2001:db8::1"))),
                inet,
                "ip6 daddr set 2001:db8::1",
            ),
            (
                rule().reject_tcp_reset(),
                inet,
                "meta l4proto tcp reject with tcp reset",
            ),
            (
                rule().reject_tcp_reset(),
                Family::Ip,
                "reject with tcp reset",
            ),
            (rule().reject(), inet, "reject"),
            (
                rule().reject_icmpx(IcmpxCode::AdminProhibited),
                inet,
                "reject with icmpx admin-prohibited",
            ),
            (
                rule().reject_icmp(3),
                inet,
                "reject with icmp port-unreachable",
            ),
            (rule().reject_icmp(3), Family::Ip, "reject"),
            (
                rule().reject_icmpv6(1),
                Family::Ip6,
                "reject with icmpv6 admin-prohibited",
            ),
            (
                rule().snat(v4("1.2.3.4"), Some(80)),
                inet,
                "snat ip to 1.2.3.4:80",
            ),
            (
                rule().snat(v4("1.2.3.4"), None),
                Family::Ip,
                "snat to 1.2.3.4",
            ),
            (
                rule().dnat_v6(v6("2001:db8::1"), Some(80)),
                inet,
                "dnat ip6 to [2001:db8::1]:80",
            ),
            (
                rule().nat(NatStatement::snat(v4("10.0.0.0")).to(v4("10.0.0.255"))),
                inet,
                "snat ip to 10.0.0.0/24",
            ),
            (
                rule().nat(
                    NatStatement::snat(v4("10.0.0.1"))
                        .to(v4("10.0.0.5"))
                        .ports(1000, 2000)
                        .random(),
                ),
                inet,
                "snat ip to 10.0.0.1-10.0.0.5:1000-2000 random",
            ),
            (
                rule().nat(NatStatement::masquerade().ports(1000, 2000).persistent()),
                inet,
                "masquerade to :1000-2000 persistent",
            ),
            (rule().redirect(Some(8080)), inet, "redirect to :8080"),
            (
                rule().tproxy(inet, Some(IpAddr::V6(v6("2001:db8::1"))), Some(53)),
                inet,
                "tproxy ip6 to [2001:db8::1]:53",
            ),
            (
                rule().match_tcp_dport(22).accept().comment("ssh"),
                inet,
                "tcp dport 22 accept comment \"ssh\"",
            ),
            (rule().comment("empty"), inet, "comment \"empty\""),
            (
                rule().match_mark(1).jump(ChainName::new("c2").unwrap()),
                inet,
                "meta mark 0x00000001 jump c2",
            ),
        ];
        let mut wrong = Vec::new();
        for (rule, family, want) in cases {
            let got = rule.family(family).nft_syntax();
            if got.as_deref() != Some(want) {
                wrong.push(format!("{family}: want {want:?}, got {got:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// nft 1.0 writes a range as two comparisons, and prints them as one.
    #[test]
    fn two_bounds_print_as_a_range() {
        let dport = || Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        };
        let cmp = |op, port: u16| Expr::Cmp {
            sreg: Register::R0,
            op,
            data: port.to_be_bytes().to_vec(),
        };
        let bounded = |first, last| {
            rule()
                .match_l4proto(6)
                .expr(dport())
                .expr(cmp(first, 1000))
                .expr(cmp(last, 2000))
                .nft_syntax()
        };
        assert_eq!(
            bounded(CmpOp::Gte, CmpOp::Lte).as_deref(),
            Some("tcp dport 1000-2000")
        );
        assert_eq!(
            bounded(CmpOp::Lt, CmpOp::Gt).as_deref(),
            Some("tcp dport != 1000-2000")
        );
        assert_eq!(
            bounded(CmpOp::Gte, CmpOp::Gt).as_deref(),
            Some("tcp dport >= 1000 tcp dport > 2000")
        );
    }

    /// `nft -s` leaves out what a counter and a quota have counted, and
    /// nothing else.
    #[test]
    fn stateless_leaves_out_what_was_counted() {
        let exprs = [
            RuleExpr::Counter {
                packets: 4,
                bytes: 240,
            },
            RuleExpr::Quota {
                bytes: 10 * 1024 * 1024,
                consumed: 2048,
                over: true,
                depleted: false,
            },
            RuleExpr::Verdict(Verdict::Accept),
        ];
        assert_eq!(
            lift(&exprs, Family::Inet).as_deref(),
            Some("counter packets 4 bytes 240 quota over 10 mbytes used 2 kbytes accept")
        );
        assert_eq!(
            lift_stateless(&exprs, Family::Inet).as_deref(),
            Some("counter quota over 10 mbytes accept")
        );
    }

    /// What nft resolves on the host prints as a number.
    #[test]
    fn an_interface_index_prints_as_its_number() {
        let r = rule()
            .expr(Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::Iif,
            })
            .expr(Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: 1u32.to_ne_bytes().to_vec(),
            });
        assert_eq!(r.nft_syntax().as_deref(), Some("iif 1"));
        assert_eq!(
            rule()
                .fwd_to(2)
                .family(Family::Netdev)
                .nft_syntax()
                .as_deref(),
            Some("fwd to 2")
        );
    }

    /// A rule this cannot print exactly is `None`, never a guess.
    #[test]
    fn what_cannot_be_read_back_is_none() {
        let cases = [
            // An expression nlink does not decode.
            rule().expr(RawExpr::new("xt", vec![])),
            // An anonymous set's elements are not in the rule.
            rule()
                .match_tcp_dport(1)
                .expr(LookupExpr::new("__set0", Register::R0)),
            // A transport field with no protocol to name it by.
            rule()
                .expr(Expr::Payload {
                    dreg: Register::R0,
                    base: PayloadBase::Transport,
                    offset: 2,
                    len: 2,
                })
                .expr(Expr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![0, 22],
                }),
            // A comparison of a register nothing loaded.
            rule().expr(Expr::Cmp {
                sreg: Register::R1,
                op: CmpOp::Eq,
                data: vec![1],
            }),
        ];
        for r in cases {
            assert_eq!(r.nft_syntax(), None, "{r:?}");
        }
        assert_eq!(
            lift(
                &[RuleExpr::Unknown {
                    name: "xt".into(),
                    data: vec![]
                }],
                Family::Inet
            ),
            None
        );
        // Bytes no kernel would dump, which must not panic.
        let wild = [
            RuleExpr::Payload {
                dreg: Register::R0,
                base: PayloadBase::Network,
                offset: u32::MAX,
                len: 4,
            },
            RuleExpr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![1; 4],
            },
        ];
        assert_eq!(lift(&wild, Family::Ip), None);
        let hash = [RuleExpr::Hash {
            dreg: Register::R0,
            kind: HashKind::Jenkins,
            sreg: Some(Register::R1),
            len: 8,
            modulus: 2,
            seed: None,
            offset: 0,
        }];
        assert_eq!(lift(&hash, Family::Ip), None);
        assert_eq!(
            nat_addresses(&[10, 0, 0, 0], Some(&[0; 16]), false, false),
            None
        );
    }

    #[test]
    fn the_helpers_print_as_nft_does() {
        assert_eq!(mask_span(0xff00_0000, 32), Some((0, 8)));
        assert_eq!(mask_span(0xfc, 8), Some((0, 6)));
        assert_eq!(mask_span(0x0fc0, 16), Some((4, 6)));
        assert_eq!(mask_span(0x17, 8), None);
        assert_eq!(data_rate(0), (0, "bytes"));
        assert_eq!(data_rate(1000), (1000, "bytes"));
        assert_eq!(data_rate(2048), (2, "kbytes"));
        assert_eq!(data_rate(5 * 1024 * 1024 * 1024), (5120, "mbytes"));
        assert_eq!(time_text(0), "0s");
        assert_eq!(time_text(90_000), "1m30s");
        assert_eq!(time_text(86_400_000 + 1), "1d1ms");
        assert_eq!(
            nat_addresses(&[10, 0, 0, 0], Some(&[10, 0, 0, 255]), false, false).as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(
            nat_addresses(&[10, 0, 0, 1], Some(&[10, 0, 0, 5]), false, false).as_deref(),
            Some("10.0.0.1-10.0.0.5")
        );
        assert_eq!(
            Ty::TcHandle
                .show(&u32::MAX.to_ne_bytes(), false, false)
                .as_deref(),
            Some("root")
        );
        assert_eq!(
            Ty::CtState
                .show(&10u32.to_ne_bytes(), false, false)
                .as_deref(),
            Some("established | new")
        );
        assert_eq!(
            Ty::Proto.show(&[58], false, false).as_deref(),
            Some("ipv6-icmp")
        );
        assert_eq!(Ty::Proto.show(&[58], false, true).as_deref(), Some("58"));
    }
}
