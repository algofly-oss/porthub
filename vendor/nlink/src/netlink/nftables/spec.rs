//! A rule body as data (#708).
//!
//! A [`RuleSpec`] is what a rule matches and does, in order, as values: a
//! [`Match`] of a [`Field`] against a [`Value`], a [`Stmt`], a [`Verdict`],
//! and for what the model does not cover, a raw [`Expr`].
//! [`RuleSpec::lower`] turns it into the expressions the kernel takes. It is
//! the only encoder: each [`Rule`](super::Rule) builder method pushes an
//! item, and a rule is lowered when it is sent.
//!
//! A spec does not know its table. `lower` takes the table's family and
//! writes the protocol guards as nft does in it: each once, without the
//! ones the family implies, and as `meta protocol` in a bridge or netdev
//! table.
//!
//! Build one from data, and fail on what does not fit, before any rule
//! exists:
//!
//! ```
//! use nlink::netlink::nftables::{Family, Field, Match, MatchOp, RuleSpec, Stmt, Value, Verdict};
//!
//! let spec = RuleSpec::new()
//!     .then(Match::new(Field::TcpDport, MatchOp::Ne, Value::range(1000u16, 2000u16)))
//!     .then(Stmt::Counter)
//!     .then(Verdict::Accept);
//! assert_eq!(
//!     spec.nft_syntax_stateless(Family::Inet).as_deref(),
//!     Some("tcp dport != 1000-2000 counter accept"),
//! );
//!
//! let too_long = RuleSpec::new().then(Match::eq(Field::Iifname, "a-name-past-fifteen"));
//! assert!(too_long.lower(Family::Inet).is_err());
//! ```

use std::fmt;
use std::net::IpAddr;

use super::expr::{
    DynsetExpr, Expr, HashKind, LimitExpr, LogExpr, LookupExpr, MasqExpr, ObjrefExpr, OsfTtl,
    QueueExpr, QuotaExpr, RedirExpr, SocketKey, SynproxyExpr,
};
use super::object::ObjectType;
use super::types::{
    ByteorderOp, CmpOp, CtDirection, CtKey, CtState, CtStatus, ExthdrOp, Family, FibFlags,
    FibResult, Generated, HeaderWrite, IcmpxCode, MetaKey, NFPROTO_IPV4, NFPROTO_IPV6, NatAddr,
    NatExpr, NatRegs, NatStatement, NatType, PacketField, PayloadBase, PayloadCsum, PktType,
    RangeOp, RangeValue, Register, RtKey, TCPOPT_MAXSEG, Verdict, ct_label_mask, prefix_to_mask,
};
use super::{
    NFT_OSF_MAXGENRELEN, NFT_REJECT_ICMP_UNREACH, NFT_REJECT_ICMPX_UNREACH, NFT_REJECT_TCP_RST,
};
use crate::netlink::error::{Error, Result};
use crate::netlink::tc_handle::TcHandle;
use crate::netlink::types::route::RouteType;

/// `meta l4proto` values.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// IFNAMSIZ, with the NUL.
const IFNAMSIZ: usize = 16;

/// A rule body: its items, in order, and its comment (#708).
///
/// See the [module documentation](self). A [`Rule`](super::Rule) is a spec
/// with a table, a chain and a family: [`Rule::from_spec`](super::Rule::from_spec)
/// makes one, and [`NftablesConfig`](super::config::NftablesConfig) takes
/// one with [`push_rule`](super::config::DeclaredTableBuilder::push_rule).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[must_use = "a spec does nothing until a rule is built from it"]
pub struct RuleSpec {
    pub(crate) items: Vec<Item>,
    pub(crate) comment: Option<String>,
}

impl RuleSpec {
    /// An empty spec: a rule that matches every packet and does nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an item: a [`Match`], a [`Stmt`], a [`Verdict`] or an
    /// [`Expr`].
    pub fn then(mut self, item: impl Into<Item>) -> Self {
        self.push(item);
        self
    }

    /// Append an item in place.
    pub fn push(&mut self, item: impl Into<Item>) {
        self.items.push(item.into());
    }

    /// Give the rule a comment, which `nft list` shows. At most 127 bytes,
    /// and less in a declarative config, whose key shares them (see
    /// [`Rule::comment`](super::Rule::comment)).
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// The comment, if any.
    pub fn comment_ref(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// The items, in order.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The expressions the rule sends in a `family` table: each item's,
    /// with the protocol guards as that family needs them.
    ///
    /// Fails on the first item the kernel could not take as meant: a value
    /// of the wrong kind for its field, an interface name past 15 bytes, a
    /// NAT range that mixes families, and the like.
    pub fn lower(&self, family: Family) -> Result<Vec<Expr>> {
        let exprs = self.lower_items().map_err(Error::invalid_message)?;
        Ok(super::expr::exprs_for_family(&exprs, family).into_owned())
    }

    /// The items' expressions, before the family's guards, or why one
    /// cannot be lowered.
    pub(crate) fn lower_items(&self) -> std::result::Result<Vec<Expr>, String> {
        let mut lowering = Lowering::default();
        for item in &self.items {
            lowering.item(item)?;
        }
        Ok(lowering.out)
    }

    /// A rule's expressions as a spec (#708): the typed inverse of
    /// [`lower`](Self::lower). Each expression becomes the item that writes
    /// it, a match or a statement with its guards and immediates, and what
    /// no item writes stays an [`Item::Expr`]. Lowering the result in the
    /// same `family` gives the rule back, as the declarative diff compares
    /// rules.
    ///
    /// [`RuleInfo::spec`](super::RuleInfo::spec) lifts a dumped rule with
    /// its comment.
    ///
    /// ```no_run
    /// # async fn run(conn: &nlink::Connection<nlink::Nftables>) -> nlink::Result<()> {
    /// use nlink::netlink::nftables::{Family, Field, Item, Match, RuleSpec, Verdict};
    ///
    /// for rule in conn.list_rules("filter", Family::Inet).await? {
    ///     let spec = RuleSpec::lift(&rule.expressions(), rule.family);
    ///     if spec.items() == [Item::from(Match::eq(Field::TcpDport, 22u16)), Verdict::Accept.into()] {
    ///         println!("handle {} accepts ssh", rule.handle);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn lift(exprs: &[super::RuleExpr], family: Family) -> Self {
        super::spec_lift::lift(exprs, None, family)
            .into_iter()
            .collect()
    }

    /// The rule as `nft list ruleset` prints it in a `family` table, or
    /// `None` where it does not lower, or holds something nlink cannot
    /// print (see [`RuleInfo::nft_syntax`](super::RuleInfo::nft_syntax)).
    pub fn nft_syntax(&self, family: Family) -> Option<String> {
        self.syntax(family, false)
    }

    /// [`nft_syntax`](Self::nft_syntax) as `nft -s list ruleset` prints it:
    /// a counter without its packets and bytes.
    pub fn nft_syntax_stateless(&self, family: Family) -> Option<String> {
        self.syntax(family, true)
    }

    fn syntax(&self, family: Family, stateless: bool) -> Option<String> {
        let exprs = self.lower(family).ok()?;
        let bytes = super::config::expression_bytes(&exprs);
        let exprs = super::expr::parse_expressions(&bytes);
        let body = if stateless {
            super::lift::lift_stateless(&exprs, family)?
        } else {
            super::lift::lift(&exprs, family)?
        };
        Some(super::expr::with_comment(body, self.comment.as_deref()))
    }
}

impl FromIterator<Item> for RuleSpec {
    fn from_iter<I: IntoIterator<Item = Item>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
            comment: None,
        }
    }
}

impl Extend<Item> for RuleSpec {
    fn extend<I: IntoIterator<Item = Item>>(&mut self, iter: I) {
        self.items.extend(iter);
    }
}

/// One thing a rule does, in its place in the rule (#708).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Item {
    /// Go on only if the packet matches.
    Match(Match),
    /// A statement: count, log, rewrite, translate, …
    Stmt(Stmt),
    /// Decide the packet's fate, or move it to another chain.
    Verdict(Verdict),
    /// An expression as it is, for what the model has no item for.
    Expr(Expr),
}

impl From<Match> for Item {
    fn from(m: Match) -> Self {
        Self::Match(m)
    }
}

impl From<Stmt> for Item {
    fn from(s: Stmt) -> Self {
        Self::Stmt(s)
    }
}

impl From<Verdict> for Item {
    fn from(v: Verdict) -> Self {
        Self::Verdict(v)
    }
}

impl From<Expr> for Item {
    fn from(e: Expr) -> Self {
        Self::Expr(e)
    }
}

/// A match: `<field> <op> <value>` (#708). `tcp dport != 1000-2000` is
/// `Match::new(Field::TcpDport, MatchOp::Ne, Value::range(1000u16, 2000u16))`.
///
/// A field nft guards, an address or a port, comes behind its guard:
/// `meta nfproto ipv4`, `meta l4proto tcp`. A packet that fails the guard
/// does not match, `!=` included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// What is compared.
    pub field: Field,
    /// How.
    pub op: MatchOp,
    /// With what.
    pub value: Value,
}

impl Match {
    /// `<field> <op> <value>`.
    pub fn new(field: impl Into<Field>, op: MatchOp, value: impl Into<Value>) -> Self {
        Self {
            field: field.into(),
            op,
            value: value.into(),
        }
    }

    /// `<field> <value>`.
    pub fn eq(field: impl Into<Field>, value: impl Into<Value>) -> Self {
        Self::new(field, MatchOp::Eq, value)
    }

    /// `<field> != <value>`.
    pub fn ne(field: impl Into<Field>, value: impl Into<Value>) -> Self {
        Self::new(field, MatchOp::Ne, value)
    }
}

/// How a [`Match`] compares. A range, a prefix, a set, an interface name
/// prefix and a flag set take only `Eq` and `Ne`; on a flag set they are
/// nft's (see [`Value::CtState`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatchOp {
    /// `==`: the field is the value, is in the range, prefix or set, or
    /// has any of the flags.
    Eq,
    /// `!=`: the field is not the value, is outside the range or prefix,
    /// is not in the set; on a flag set, is not exactly the value.
    Ne,
    /// `<`.
    Lt,
    /// `>`.
    Gt,
    /// `<=`.
    Le,
    /// `>=`.
    Ge,
}

impl MatchOp {
    fn cmp(self) -> CmpOp {
        match self {
            Self::Eq => CmpOp::Eq,
            Self::Ne => CmpOp::Neq,
            Self::Lt => CmpOp::Lt,
            Self::Gt => CmpOp::Gt,
            Self::Le => CmpOp::Lte,
            Self::Ge => CmpOp::Gte,
        }
    }

    /// `Eq` or `Ne` as whether the match is inverted; `None` for an order.
    fn inverted(self) -> Option<bool> {
        match self {
            Self::Eq => Some(false),
            Self::Ne => Some(true),
            _ => None,
        }
    }
}

impl fmt::Display for MatchOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Ge => ">=",
        })
    }
}

/// What a [`Match`] compares, with the value it takes (#708).
///
/// Integers are [`Value::Int`], checked against the field's width.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// `ip saddr`: an IPv4 [`Value::Addr`] or [`Value::Prefix`], behind
    /// `meta nfproto ipv4`.
    Ip4Saddr,
    /// `ip daddr`.
    Ip4Daddr,
    /// `ip6 saddr`, behind `meta nfproto ipv6`.
    Ip6Saddr,
    /// `ip6 daddr`.
    Ip6Daddr,
    /// `tcp sport`, behind `meta l4proto tcp`.
    TcpSport,
    /// `tcp dport`.
    TcpDport,
    /// `udp sport`, behind `meta l4proto udp`.
    UdpSport,
    /// `udp dport`.
    UdpDport,
    /// `tcp flags`: a [`Value::TcpFlags`], matched on any of them; a
    /// [`Value::Masked`], `tcp flags & (syn | ack) == syn`; or the whole
    /// byte as an `Int`, `tcp flags == syn`.
    TcpFlags,
    /// `icmp type`, behind `meta nfproto ipv4` and `meta l4proto icmp`.
    IcmpType,
    /// `icmpv6 type`, behind `meta nfproto ipv6` and `meta l4proto
    /// ipv6-icmp`.
    Icmp6Type,
    /// `meta l4proto`: an IP protocol number.
    L4Proto,
    /// `meta nfproto`: the packet's L3 protocol, `2` for IPv4, `10` for
    /// IPv6. It is the guard nft writes before an address field, and is
    /// written as one: once, not in an ip or ip6 table, where it is always
    /// true, and as `meta protocol` in a bridge or netdev table.
    NfProto,
    /// `meta protocol`: the ethertype, `0x0800` for IPv4.
    Protocol,
    /// `meta mark`.
    Mark,
    /// `meta iif`: an interface index, resolved in the rule's namespace.
    Iif,
    /// `meta oif`.
    Oif,
    /// `meta iifname`: a [`Value::Name`] of at most 15 bytes, or a
    /// [`Value::NamePrefix`] (`"eth*"`).
    Iifname,
    /// `meta oifname`.
    Oifname,
    /// `meta pkttype`: a [`Value::PktType`].
    PktType,
    /// `ct state`: a [`Value::CtState`]. See [`Value::CtState`] for what
    /// `Eq` and `Ne` mean on a set of flags.
    CtState,
    /// `ct status`: a [`Value::CtStatus`].
    CtStatus,
    /// `ct direction`: a [`Value::CtDirection`].
    CtDirection,
    /// `ct zone`.
    CtZone,
    /// `ct mark`.
    CtMark,
    /// `ct label`: the label's bit, 0..=127, as an `Int`, matched as a
    /// flag: `Eq` if the connection has it, `Ne` (nft's `!=`) if its labels
    /// are not exactly it.
    CtLabel,
    /// `ct <direction> ip saddr` or `ip6 saddr`, by the address's family.
    CtSaddr(CtDirection),
    /// `ct <direction> ip daddr` or `ip6 daddr`.
    CtDaddr(CtDirection),
    /// `ct <direction> proto-src`.
    CtSport(CtDirection),
    /// `ct <direction> proto-dst`.
    CtDport(CtDirection),
    /// `fib <flags> <result>`: for the `oif` result a
    /// [`Value::Bool`], whether a route exists (`fib saddr . iif oif
    /// missing` is `Bool(false)`), or an interface index; for `type` a
    /// [`Value::RouteType`].
    Fib {
        /// What is looked up.
        flags: FibFlags,
        /// What the lookup answers.
        result: FibResult,
    },
    /// `osf [ttl loose|skip] [version] name`: a [`Value::Name`] of at
    /// most 15 bytes.
    Osf {
        /// How the TTL compares.
        ttl: OsfTtl,
        /// With the version: `Linux:3.11`.
        version: bool,
    },
    /// `socket transparent` and `socket wildcard`, a [`Value::Bool`], or
    /// `socket mark`, an `Int`.
    Socket(SocketKey),
    /// `<field> . <field> …`: a concatenation, matched against a set of
    /// concatenated keys.
    Concat(Vec<PacketField>),
}

impl From<PacketField> for Field {
    fn from(field: PacketField) -> Self {
        match field {
            PacketField::Ip4Saddr => Self::Ip4Saddr,
            PacketField::Ip4Daddr => Self::Ip4Daddr,
            PacketField::Ip6Saddr => Self::Ip6Saddr,
            PacketField::Ip6Daddr => Self::Ip6Daddr,
            PacketField::TcpSport => Self::TcpSport,
            PacketField::TcpDport => Self::TcpDport,
            PacketField::UdpSport => Self::UdpSport,
            PacketField::UdpDport => Self::UdpDport,
            PacketField::Mark => Self::Mark,
            PacketField::Iif => Self::Iif,
            PacketField::Oif => Self::Oif,
            PacketField::L4Proto => Self::L4Proto,
        }
    }
}

impl Field {
    /// The field as a set can hold it, if one can.
    pub fn packet_field(&self) -> Option<PacketField> {
        Some(match self {
            Self::Ip4Saddr => PacketField::Ip4Saddr,
            Self::Ip4Daddr => PacketField::Ip4Daddr,
            Self::Ip6Saddr => PacketField::Ip6Saddr,
            Self::Ip6Daddr => PacketField::Ip6Daddr,
            Self::TcpSport => PacketField::TcpSport,
            Self::TcpDport => PacketField::TcpDport,
            Self::UdpSport => PacketField::UdpSport,
            Self::UdpDport => PacketField::UdpDport,
            Self::Mark => PacketField::Mark,
            Self::Iif => PacketField::Iif,
            Self::Oif => PacketField::Oif,
            Self::L4Proto => PacketField::L4Proto,
            _ => return None,
        })
    }

    /// The protocol guards nft writes in front of the field.
    fn guards(&self) -> &'static [(MetaKey, u8)] {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => &[(MetaKey::NfProto, NFPROTO_IPV4)],
            Self::Ip6Saddr | Self::Ip6Daddr => &[(MetaKey::NfProto, NFPROTO_IPV6)],
            Self::TcpSport | Self::TcpDport | Self::TcpFlags => &[(MetaKey::L4Proto, IPPROTO_TCP)],
            Self::UdpSport | Self::UdpDport => &[(MetaKey::L4Proto, IPPROTO_UDP)],
            Self::IcmpType => &[
                (MetaKey::NfProto, NFPROTO_IPV4),
                (MetaKey::L4Proto, IPPROTO_ICMP),
            ],
            Self::Icmp6Type => &[
                (MetaKey::NfProto, NFPROTO_IPV6),
                (MetaKey::L4Proto, IPPROTO_ICMPV6),
            ],
            _ => &[],
        }
    }

    /// The expression loading the field into `R0`. A conntrack address's
    /// key and a `fib`'s presence flag depend on the value.
    fn load(&self, value: &Value) -> std::result::Result<Expr, String> {
        let dreg = Register::R0;
        let payload = |offset, len| Expr::Payload {
            dreg,
            base: PayloadBase::Transport,
            offset,
            len,
        };
        let meta = |key| Expr::Meta { dreg, key };
        let ct = |key| Expr::Ct { dreg, key };
        let directional = |key, direction| Expr::CtDirectional {
            dreg,
            key,
            direction,
        };
        if let Some(field) = self.packet_field() {
            return Ok(field.load(dreg));
        }
        Ok(match self {
            Self::TcpFlags => payload(13, 1),
            Self::IcmpType | Self::Icmp6Type => payload(0, 1),
            Self::Iifname => meta(MetaKey::IifName),
            Self::Oifname => meta(MetaKey::OifName),
            Self::PktType => meta(MetaKey::PktType),
            Self::NfProto => meta(MetaKey::NfProto),
            Self::Protocol => meta(MetaKey::Protocol),
            Self::CtState => ct(CtKey::State),
            Self::CtStatus => ct(CtKey::Status),
            Self::CtDirection => ct(CtKey::Direction),
            Self::CtZone => ct(CtKey::Zone),
            Self::CtMark => ct(CtKey::Mark),
            Self::CtLabel => ct(CtKey::Labels),
            Self::CtSaddr(direction) | Self::CtDaddr(direction) => {
                let source = matches!(self, Self::CtSaddr(_));
                let key = match (value, source) {
                    (Value::Addr(IpAddr::V4(_)), true) => CtKey::SrcIp,
                    (Value::Addr(IpAddr::V4(_)), false) => CtKey::DstIp,
                    (Value::Addr(IpAddr::V6(_)), true) => CtKey::SrcIp6,
                    (Value::Addr(IpAddr::V6(_)), false) => CtKey::DstIp6,
                    _ => return Err(format!("{self}: an address, not {value:?}")),
                };
                directional(key, *direction)
            }
            Self::CtSport(direction) => directional(CtKey::ProtoSrc, *direction),
            Self::CtDport(direction) => directional(CtKey::ProtoDst, *direction),
            Self::Fib { flags, result } => Expr::Fib {
                dreg,
                result: *result,
                flags: match value {
                    Value::Bool(_) => *flags | FibFlags::PRESENT,
                    _ => *flags,
                },
            },
            Self::Osf { ttl, version } => Expr::Osf {
                dreg,
                ttl: *ttl,
                version: *version,
            },
            Self::Socket(key) => Expr::Socket { dreg, key: *key },
            Self::Concat(_) => return Err("a concatenation is matched against a set".into()),
            _ => unreachable!("a packet field"),
        })
    }

    /// An integer as the field holds it in a register, or `None` for a
    /// field that is no integer.
    fn int(&self, n: u64) -> Option<std::result::Result<Vec<u8>, String>> {
        let fits = |bits: u32| {
            if bits < 64 && n >> bits != 0 {
                Err(format!("{self}: {n} does not fit in {bits} bits"))
            } else {
                Ok(())
            }
        };
        let bytes = match self {
            Self::TcpSport
            | Self::TcpDport
            | Self::UdpSport
            | Self::UdpDport
            | Self::CtSport(_)
            | Self::CtDport(_)
            | Self::Protocol => fits(16).map(|()| (n as u16).to_be_bytes().to_vec()),
            Self::L4Proto
            | Self::NfProto
            | Self::IcmpType
            | Self::Icmp6Type
            | Self::TcpFlags
            | Self::PktType
            | Self::CtDirection => fits(8).map(|()| vec![n as u8]),
            Self::Mark
            | Self::CtMark
            | Self::Iif
            | Self::Oif
            | Self::CtState
            | Self::CtStatus
            | Self::Socket(SocketKey::Mark)
            | Self::Fib {
                result: FibResult::Oif,
                ..
            } => fits(32).map(|()| (n as u32).to_ne_bytes().to_vec()),
            Self::CtZone => fits(16).map(|()| (n as u16).to_ne_bytes().to_vec()),
            _ => return None,
        };
        Some(bytes)
    }

    /// The integer `data` is as the field holds it: what [`int`](Self::int)
    /// encodes, decoded.
    pub(crate) fn int_value(&self, data: &[u8]) -> Option<u64> {
        // Every integer field holds 0, so its encoding gives the width.
        let n = match (self.int(0)?.ok()?.len(), data.len()) {
            (1, 1) => u64::from(data[0]),
            (2, 2) => {
                let raw = [data[0], data[1]];
                match self {
                    Self::CtZone => u64::from(u16::from_ne_bytes(raw)),
                    _ => u64::from(u16::from_be_bytes(raw)),
                }
            }
            (4, 4) => u64::from(u32::from_ne_bytes([data[0], data[1], data[2], data[3]])),
            _ => return None,
        };
        (self.int(n)?.ok()?.as_slice() == data).then_some(n)
    }

    /// Whether the kernel keeps the field in host byte order, so a range
    /// compares it once it is turned to network order.
    fn is_host_order(&self) -> bool {
        match self.packet_field() {
            Some(field) => field.key_type().is_host_order(),
            None => matches!(
                self,
                Self::CtMark
                    | Self::CtZone
                    | Self::Socket(SocketKey::Mark)
                    | Self::Fib {
                        result: FibResult::Oif,
                        ..
                    }
            ),
        }
    }

    /// The bytes of a range's end, in network order, or `None` when the
    /// field cannot hold it.
    fn range_bytes(&self, value: RangeValue) -> Option<Vec<u8>> {
        if let Some(field) = self.packet_field() {
            return field.range_bytes(value);
        }
        match (self, value) {
            (Self::CtMark, RangeValue::U32(v)) => Some(v.to_be_bytes().to_vec()),
            (Self::CtSport(_) | Self::CtDport(_), RangeValue::Port(p)) => {
                Some(p.to_be_bytes().to_vec())
            }
            _ => None,
        }
    }

    /// An address field's family, as an IPv4 or IPv6 width.
    fn addr_width(&self) -> Option<u8> {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => Some(32),
            Self::Ip6Saddr | Self::Ip6Daddr => Some(128),
            _ => None,
        }
    }
}

impl fmt::Display for Field {
    /// The field as nft names it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = |d: &CtDirection| match d {
            CtDirection::Original => "original",
            CtDirection::Reply => "reply",
        };
        match self {
            Self::Ip4Saddr => f.write_str("ip saddr"),
            Self::Ip4Daddr => f.write_str("ip daddr"),
            Self::Ip6Saddr => f.write_str("ip6 saddr"),
            Self::Ip6Daddr => f.write_str("ip6 daddr"),
            Self::TcpSport => f.write_str("tcp sport"),
            Self::TcpDport => f.write_str("tcp dport"),
            Self::UdpSport => f.write_str("udp sport"),
            Self::UdpDport => f.write_str("udp dport"),
            Self::TcpFlags => f.write_str("tcp flags"),
            Self::IcmpType => f.write_str("icmp type"),
            Self::Icmp6Type => f.write_str("icmpv6 type"),
            Self::L4Proto => f.write_str("meta l4proto"),
            Self::NfProto => f.write_str("meta nfproto"),
            Self::Protocol => f.write_str("meta protocol"),
            Self::Mark => f.write_str("meta mark"),
            Self::Iif => f.write_str("meta iif"),
            Self::Oif => f.write_str("meta oif"),
            Self::Iifname => f.write_str("meta iifname"),
            Self::Oifname => f.write_str("meta oifname"),
            Self::PktType => f.write_str("meta pkttype"),
            Self::CtState => f.write_str("ct state"),
            Self::CtStatus => f.write_str("ct status"),
            Self::CtDirection => f.write_str("ct direction"),
            Self::CtZone => f.write_str("ct zone"),
            Self::CtMark => f.write_str("ct mark"),
            Self::CtLabel => f.write_str("ct label"),
            Self::CtSaddr(d) => write!(f, "ct {} saddr", dir(d)),
            Self::CtDaddr(d) => write!(f, "ct {} daddr", dir(d)),
            Self::CtSport(d) => write!(f, "ct {} proto-src", dir(d)),
            Self::CtDport(d) => write!(f, "ct {} proto-dst", dir(d)),
            Self::Fib { .. } => f.write_str("fib"),
            Self::Osf { .. } => f.write_str("osf name"),
            Self::Socket(key) => write!(f, "socket {}", format!("{key:?}").to_lowercase()),
            Self::Concat(fields) => {
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" . ")?;
                    }
                    write!(f, "{}", Field::from(*field))?;
                }
                Ok(())
            }
        }
    }
}

/// What a [`Match`] compares its field with (#708).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    /// An integer: a port, a protocol, a mark, a zone, an interface
    /// index. It must fit the field.
    Int(u64),
    /// `exists` (`true`) or `missing`, for a `fib`; `1` or `0` for a
    /// `socket transparent`.
    Bool(bool),
    /// One address.
    Addr(IpAddr),
    /// The addresses under a prefix: `10.0.0.0/8`. A prefix as long as the
    /// address is the address.
    Prefix(IpAddr, u8),
    /// `<first>-<last>`, both included.
    Range(RangeValue, RangeValue),
    /// An interface or OS name.
    Name(String),
    /// An interface name prefix: `"eth*"`.
    NamePrefix(String),
    /// A set of conntrack states, matched as nft matches flags: `Eq` is
    /// nft's `ct state established,related`, any of them; `Ne` is nft's
    /// `ct state != established`, the field is not exactly the value. For
    /// "none of them", match `Masked { value: 0, mask }`; for exactly them,
    /// an `Int`.
    CtState(CtState),
    /// Conntrack status bits, matched as [`CtState`](Self::CtState) is.
    CtStatus(CtStatus),
    /// TCP flags, matched as [`CtState`](Self::CtState) is.
    TcpFlags(super::types::TcpFlags),
    /// A conntrack direction.
    CtDirection(CtDirection),
    /// A packet type.
    PktType(PktType),
    /// An address type, for `fib ... type`.
    RouteType(RouteType),
    /// The bits under `mask`: `meta mark & 0xff00 == 0x0100` is
    /// `Masked { value: 0x100, mask: 0xff00 }`. Bits of `value` outside
    /// `mask` are ignored.
    Masked {
        /// The bits looked for.
        value: u64,
        /// Which bits are compared.
        mask: u64,
    },
    /// A named set, `@<name>`: the field is one of its elements. Its key
    /// type must be the field's.
    Set(String),
    /// A named interval set ([`Set::interval`](super::Set::interval)): a
    /// host-order field is turned to network order first, as the set keeps
    /// it.
    IntervalSet(String),
}

impl Value {
    /// `<first>-<last>`, both included.
    pub fn range(first: impl Into<RangeValue>, last: impl Into<RangeValue>) -> Self {
        Self::Range(first.into(), last.into())
    }

    /// `@<set>`.
    pub fn set(name: impl Into<String>) -> Self {
        Self::Set(name.into())
    }
}

impl From<u8> for Value {
    fn from(n: u8) -> Self {
        Self::Int(n.into())
    }
}

impl From<u16> for Value {
    fn from(n: u16) -> Self {
        Self::Int(n.into())
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Self::Int(n.into())
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<IpAddr> for Value {
    fn from(a: IpAddr) -> Self {
        Self::Addr(a)
    }
}

impl From<std::net::Ipv4Addr> for Value {
    fn from(a: std::net::Ipv4Addr) -> Self {
        Self::Addr(a.into())
    }
}

impl From<std::net::Ipv6Addr> for Value {
    fn from(a: std::net::Ipv6Addr) -> Self {
        Self::Addr(a.into())
    }
}

impl From<&str> for Value {
    /// A name.
    fn from(name: &str) -> Self {
        Self::Name(name.to_string())
    }
}

impl From<CtState> for Value {
    fn from(s: CtState) -> Self {
        Self::CtState(s)
    }
}

impl From<super::types::TcpFlags> for Value {
    fn from(f: super::types::TcpFlags) -> Self {
        Self::TcpFlags(f)
    }
}

impl From<CtStatus> for Value {
    fn from(s: CtStatus) -> Self {
        Self::CtStatus(s)
    }
}

impl From<CtDirection> for Value {
    fn from(d: CtDirection) -> Self {
        Self::CtDirection(d)
    }
}

impl From<PktType> for Value {
    fn from(t: PktType) -> Self {
        Self::PktType(t)
    }
}

impl From<RouteType> for Value {
    fn from(t: RouteType) -> Self {
        Self::RouteType(t)
    }
}

/// A statement (#708): what a rule does to a packet that has matched so
/// far, short of a verdict. Each is what the [`Rule`](super::Rule) method
/// of the same name writes; see it for the details.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stmt {
    /// `counter`.
    Counter,
    /// `limit rate …`; also a match, failed over the rate.
    Limit(LimitExpr),
    /// `quota [over|until] …`; also a match.
    Quota(QuotaExpr),
    /// `log …`.
    Log(LogExpr),
    /// `counter name "<name>"`, `quota name …`, `meta secmark set …`, `ct
    /// helper set …`: the named object of `object_type`.
    Objref {
        /// The object's type.
        object_type: ObjectType,
        /// Its name.
        name: String,
    },
    /// `counter name <field> map @<map>`: the object an object map holds
    /// for the field.
    ObjrefFromMap {
        /// The key.
        field: PacketField,
        /// The object map.
        map: String,
    },
    /// `ct count [over] <count>`; a match.
    CtCount {
        /// The connections allowed.
        count: u32,
        /// Match past `count` rather than up to it.
        over: bool,
    },
    /// `masquerade`.
    Masquerade,
    /// `snat to <addr>[:<port>]` or `dnat …`, to one address.
    NatTo {
        /// Source or destination NAT.
        nat_type: NatType,
        /// The address, of the family the statement translates.
        addr: IpAddr,
        /// The port, if any.
        port: Option<u16>,
    },
    /// A NAT statement with ranges and flags: see [`NatStatement`].
    Nat(NatStatement),
    /// `redirect [to :<port>]`.
    Redirect(Option<u16>),
    /// `tproxy [ip|ip6] to [<addr>][:<port>]`; `family` is the table's.
    Tproxy {
        /// The table's family: `Ip`, `Ip6`, or `Inet`.
        family: Family,
        /// The address, of that family.
        addr: Option<IpAddr>,
        /// The port.
        port: Option<u16>,
    },
    /// `meta mark set <mark>`.
    SetMark(u32),
    /// `meta mark set mark and ~<mask> or <value>`.
    SetMarkMasked {
        /// The bits set.
        value: u32,
        /// Which bits.
        mask: u32,
    },
    /// `meta priority set <major>:<minor>`.
    SetPriority(TcHandle),
    /// `ct mark set <mark>`.
    SetCtMark(u32),
    /// `ct mark set mark`.
    SaveMarkToCt,
    /// `meta mark set ct mark`.
    RestoreMarkFromCt,
    /// `ct zone set <zone>`.
    SetCtZone(u16),
    /// `ct label set <bit>`.
    SetCtLabel(u8),
    /// `<header field> set <value>`.
    SetHeader(HeaderWrite),
    /// `tcp option maxseg size set <mss>`.
    ClampTcpMss(u16),
    /// `tcp option maxseg size set rt mtu`.
    ClampTcpMssToPmtu,
    /// `notrack`.
    Notrack,
    /// A `numgen` or hash into the first register, for the statement after
    /// it: [`SetMetaFrom`](Self::SetMetaFrom), [`SetCtFrom`](Self::SetCtFrom).
    Generate(Generated),
    /// `meta <key> set` the first register.
    SetMetaFrom(MetaKey),
    /// `ct <key> set` the first register.
    SetCtFrom(CtKey),
    /// `meta <key> set <field> map @<map>`.
    SetMetaFromMap {
        /// What is set: `mark`, `priority`.
        key: MetaKey,
        /// The map's key.
        field: PacketField,
        /// The map.
        map: String,
    },
    /// `dup to <addr> [device <dev>]`, or `dup to <dev>` without an address.
    Dup {
        /// The gateway the copy is routed to.
        addr: Option<IpAddr>,
        /// The interface index it leaves by.
        dev: Option<u32>,
    },
    /// `fwd to <dev>`, or `fwd ip to <addr> device <dev>`.
    Fwd {
        /// The interface index.
        dev: u32,
        /// The next hop.
        addr: Option<IpAddr>,
    },
    /// `<op> @<set> { <field> … }`: the dynset's key is the field.
    Dynset {
        /// The element.
        field: PacketField,
        /// The operation, set, timeout and statements.
        dynset: DynsetExpr,
    },
    /// `<key> vmap @<map>`: the verdict the map holds for the key, a
    /// field or a [`Field::Concat`].
    Vmap {
        /// The key.
        key: Field,
        /// The verdict map.
        map: String,
    },
    /// `reject …`.
    Reject(Reject),
    /// `flow add @<flowtable>`.
    FlowOffload(String),
    /// `queue …`: hand the packet to userspace, see [`QueueExpr`].
    Queue(QueueExpr),
    /// `synproxy …`: answer a SYN with a cookie, see [`SynproxyExpr`].
    Synproxy(SynproxyExpr),
}

/// How a [`Stmt::Reject`] answers (#708).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reject {
    /// `reject with tcp reset`, behind `meta l4proto tcp` unless the rule
    /// has it.
    TcpReset,
    /// `reject with icmp <code>`, behind `meta nfproto ipv4`.
    Icmp(u8),
    /// `reject with icmpv6 <code>`, behind `meta nfproto ipv6`.
    Icmpv6(u8),
    /// `reject with icmpx <code>`; a plain `reject` is
    /// `Icmpx(IcmpxCode::PortUnreachable)`.
    Icmpx(IcmpxCode),
    /// Any reject type and code, without a guard but a TCP reset's.
    With {
        /// `NFT_REJECT_*`.
        reject_type: u32,
        /// The ICMP code.
        code: u8,
    },
}

/// The expressions a spec's items lower to, before the family's guards.
#[derive(Default)]
struct Lowering {
    out: Vec<Expr>,
}

impl Lowering {
    fn item(&mut self, item: &Item) -> std::result::Result<(), String> {
        match item {
            Item::Match(m) => self.matches(m),
            Item::Stmt(s) => self.stmt(s),
            Item::Verdict(v) => {
                self.out.push(Expr::Verdict(v.clone()));
                Ok(())
            }
            Item::Expr(e) => {
                self.out.push(e.clone());
                Ok(())
            }
        }
    }

    /// `meta <key> == <value>`: a guard's shape.
    fn meta_eq(&mut self, key: MetaKey, value: u8) {
        self.out.push(Expr::Meta {
            dreg: Register::R0,
            key,
        });
        self.out.push(Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: vec![value],
        });
    }

    fn cmp(&mut self, op: CmpOp, data: Vec<u8>) {
        self.out.push(Expr::Cmp {
            sreg: Register::R0,
            op,
            data,
        });
    }

    /// `R0 = R0 & mask`.
    fn and(&mut self, mask: Vec<u8>) {
        let len = mask.len() as u32;
        self.out.push(Expr::Bitwise {
            sreg: Register::R0,
            dreg: Register::R0,
            len,
            xor: vec![0; mask.len()],
            mask,
        });
    }

    /// `R0` turned to network order.
    fn hton(&mut self, len: u32) {
        self.out.push(Expr::Byteorder {
            sreg: Register::R0,
            dreg: Register::R0,
            op: ByteorderOp::Hton,
            len,
            size: len,
        });
    }

    fn immediate(&mut self, dreg: Register, data: Vec<u8>) {
        self.out.push(Expr::Immediate { dreg, data });
    }

    /// `field` into `R0`, behind the guard nft writes for it.
    fn field_load(&mut self, field: PacketField) {
        if let Some((key, value)) = field.guard() {
            self.meta_eq(key, value);
        }
        self.out.push(field.load(Register::R0));
    }

    /// `fields` into consecutive 32-bit words from `R0`, behind their
    /// guards: each distinct guard once, all before the first load, since a
    /// guard compares in `R0` too.
    fn concat_load(&mut self, fields: &[PacketField]) {
        let mut guarded = Vec::new();
        for field in fields {
            let guard = field.guard();
            if guard.is_some() && !guarded.contains(&guard) {
                guarded.push(guard);
                if let Some((key, value)) = guard {
                    self.meta_eq(key, value);
                }
            }
        }
        let mut word = 0;
        for field in fields {
            // Past the last word, ask for the last one: the kernel then
            // refuses the load as out of range rather than nlink building a
            // rule that matches something else.
            let dreg = Register::word(word).unwrap_or(Register::Reg32_15);
            self.out.push(field.load(dreg));
            word += field.len().div_ceil(4) as usize;
        }
    }

    /// A set's or map's key into `R0`: a field or a concatenation.
    fn key_load(&mut self, key: &Field) -> std::result::Result<(), String> {
        match key {
            Field::Concat(fields) => self.concat_load(fields),
            field => {
                let field = field
                    .packet_field()
                    .ok_or_else(|| format!("{field}: no set holds it"))?;
                self.field_load(field);
            }
        }
        Ok(())
    }

    fn matches(&mut self, m: &Match) -> std::result::Result<(), String> {
        let Match { field, op, value } = m;
        let only_eq = |what: &str| format!("{field}: {what} is matched with == or !=, not {op}");
        if let Value::Set(set) | Value::IntervalSet(set) = value {
            let invert = op.inverted().ok_or_else(|| only_eq("a set"))?;
            self.key_load(field)?;
            if let (Value::IntervalSet(_), Some(field)) = (value, field.packet_field())
                && field.key_type().is_host_order()
            {
                self.hton(field.len());
            }
            let lookup = LookupExpr::new(set, Register::R0);
            self.out
                .push(if invert { lookup.invert() } else { lookup }.into());
            return Ok(());
        }
        if let Value::Range(first, last) = value {
            let op = match op.inverted().ok_or_else(|| only_eq("a range"))? {
                false => RangeOp::Eq,
                true => RangeOp::Neq,
            };
            let (Some(from), Some(to)) = (field.range_bytes(*first), field.range_bytes(*last))
            else {
                return Err(format!("range: {field:?} cannot hold {first:?}..{last:?}"));
            };
            if from > to {
                return Err(format!(
                    "range: {field:?} {first:?}..{last:?} runs backwards"
                ));
            }
            for &(key, value) in field.guards() {
                self.meta_eq(key, value);
            }
            self.out.push(field.load(value)?);
            if field.is_host_order() {
                self.hton(from.len() as u32);
            }
            self.out.push(Expr::Range {
                sreg: Register::R0,
                op,
                from,
                to,
            });
            return Ok(());
        }
        // Checked before anything is written, as the builder did.
        let mut data = self.compared(field, *op, value)?;
        for &(key, value) in field.guards() {
            self.meta_eq(key, value);
        }
        self.out.push(field.load(value)?);
        // `cmp` compares bytes in order, so a host-order field is put in
        // network order before `<` or `>`, as nft does, and so is its value.
        if op.inverted().is_none()
            && field.is_host_order()
            && let Compared::Cmp(_, data) = &mut data
        {
            self.hton(data.len() as u32);
            *data = network_order(data);
        }
        match data {
            Compared::Cmp(op, data) => self.cmp(op, data),
            Compared::Masked { mask, op, data } => {
                self.and(mask);
                self.cmp(op, data);
            }
        }
        Ok(())
    }

    /// What `value` is compared as, after the field's load.
    fn compared(
        &self,
        field: &Field,
        op: MatchOp,
        value: &Value,
    ) -> std::result::Result<Compared, String> {
        let only_eq = |what: &str| format!("{field}: {what} is matched with == or !=, not {op}");
        // A flag set, as nft has it: `==` is its implicit match, any of
        // the bits; `!=` is its `!=`, the field is not exactly the value.
        let flags = |bits: Vec<u8>| -> std::result::Result<Compared, String> {
            match op {
                MatchOp::Eq => Ok(Compared::Masked {
                    data: vec![0; bits.len()],
                    mask: bits,
                    op: CmpOp::Neq,
                }),
                MatchOp::Ne => Ok(Compared::Cmp(CmpOp::Neq, bits)),
                _ => Err(only_eq("a flag set")),
            }
        };
        let wrong = || format!("{field}: cannot be matched against {value:?}");
        Ok(match (field, value) {
            (Field::Concat(_), _) => return Err("a concatenation is matched against a set".into()),
            (Field::Iifname | Field::Oifname, Value::Name(name) | Value::NamePrefix(name)) => {
                // IFNAMSIZ is 16 with the NUL. A longer name was cut to 15
                // bytes, which no interface has, so the rule matched nothing
                // (#484).
                if name.len() >= IFNAMSIZ {
                    return Err(format!(
                        "interface name `{name}` is longer than 15 bytes; no interface has it"
                    ));
                }
                let mut data = name.as_bytes().to_vec();
                if let Value::Name(_) = value {
                    // The whole name: NUL-terminated and padded to IFNAMSIZ.
                    data.resize(IFNAMSIZ, 0);
                } else if op.inverted().is_none() {
                    return Err(only_eq("a name prefix"));
                }
                Compared::Cmp(op.cmp(), data)
            }
            (Field::Osf { .. }, Value::Name(name)) => {
                if name.len() >= NFT_OSF_MAXGENRELEN {
                    return Err(format!(
                        "osf name `{name}` is longer than {} bytes",
                        NFT_OSF_MAXGENRELEN - 1
                    ));
                }
                let mut data = name.as_bytes().to_vec();
                data.resize(NFT_OSF_MAXGENRELEN, 0);
                Compared::Cmp(op.cmp(), data)
            }
            (Field::CtState, Value::CtState(state)) => flags(state.bits().to_ne_bytes().to_vec())?,
            (Field::CtStatus, Value::CtStatus(status)) => {
                flags(status.bits().to_ne_bytes().to_vec())?
            }
            (Field::TcpFlags, Value::TcpFlags(tcp_flags)) => flags(vec![tcp_flags.bits()])?,
            (Field::CtLabel, Value::Int(bit)) => {
                let mask = u8::try_from(*bit)
                    .ok()
                    .and_then(ct_label_mask)
                    .ok_or_else(|| format!("ct label: bit {bit} is past 127"))?;
                flags(mask)?
            }
            (Field::CtDirection, Value::CtDirection(direction)) => {
                Compared::Cmp(op.cmp(), vec![*direction as u8])
            }
            (Field::PktType, Value::PktType(pkttype)) => {
                Compared::Cmp(op.cmp(), vec![*pkttype as u8])
            }
            (
                Field::Fib {
                    result: FibResult::Oif,
                    ..
                },
                Value::Bool(exists),
            ) => {
                // The kernel stores the answer as a u32 0 or 1, and nft
                // compares all four bytes: one would read the wrong end on
                // a big-endian host.
                Compared::Cmp(op.cmp(), u32::from(*exists).to_ne_bytes().to_vec())
            }
            (
                Field::Fib {
                    result: FibResult::AddrType,
                    ..
                },
                Value::RouteType(addr_type),
            ) => Compared::Cmp(op.cmp(), (*addr_type as u32).to_ne_bytes().to_vec()),
            (Field::Socket(SocketKey::Transparent | SocketKey::Wildcard), Value::Bool(on)) => {
                Compared::Cmp(op.cmp(), vec![u8::from(*on)])
            }
            (Field::CtSaddr(_) | Field::CtDaddr(_), Value::Addr(addr)) => {
                Compared::Cmp(op.cmp(), octets(*addr))
            }
            (_, Value::Addr(addr)) => {
                let width = field.addr_width().ok_or_else(wrong)?;
                check_family(field, *addr, width)?;
                Compared::Cmp(op.cmp(), octets(*addr))
            }
            (_, Value::Prefix(addr, prefix)) => {
                let width = field.addr_width().ok_or_else(wrong)?;
                check_family(field, *addr, width)?;
                if *prefix > width {
                    return Err(format!("{field}: /{prefix} is past /{width}"));
                }
                let octets = octets(*addr);
                if *prefix == width {
                    Compared::Cmp(op.cmp(), octets)
                } else {
                    op.inverted().ok_or_else(|| only_eq("a prefix"))?;
                    let mask = prefix_to_mask(octets.len(), *prefix);
                    let data = octets.iter().zip(&mask).map(|(a, m)| a & m).collect();
                    Compared::Masked {
                        mask,
                        op: op.cmp(),
                        data,
                    }
                }
            }
            (_, Value::Masked { value, mask }) => {
                op.inverted().ok_or_else(|| only_eq("a mask"))?;
                let bytes = |n| field.int(n).ok_or_else(wrong);
                let data = bytes(value & mask)??;
                let mask = bytes(*mask)??;
                Compared::Masked {
                    mask,
                    op: op.cmp(),
                    data,
                }
            }
            (_, Value::Int(n)) => Compared::Cmp(op.cmp(), field.int(*n).ok_or_else(wrong)??),
            _ => return Err(wrong()),
        })
    }

    fn stmt(&mut self, stmt: &Stmt) -> std::result::Result<(), String> {
        match stmt {
            Stmt::Counter => self.out.push(Expr::Counter),
            Stmt::Limit(limit) => self.out.push(limit.clone().into()),
            Stmt::Quota(quota) => self.out.push(quota.clone().into()),
            Stmt::Log(log) => self.out.push(log.clone().into()),
            Stmt::Objref { object_type, name } => self.out.push(
                ObjrefExpr::Named {
                    object_type: *object_type,
                    name: name.clone(),
                }
                .into(),
            ),
            Stmt::ObjrefFromMap { field, map } => {
                self.field_load(*field);
                self.out.push(
                    ObjrefExpr::Map {
                        sreg: Register::R0,
                        map: map.clone(),
                    }
                    .into(),
                );
            }
            Stmt::CtCount { count, over } => self.out.push(Expr::Connlimit {
                count: *count,
                over: *over,
            }),
            Stmt::Masquerade => self.out.push(MasqExpr::new().into()),
            Stmt::NatTo {
                nat_type,
                addr,
                port,
            } => {
                let (family, nat_addr) = match addr {
                    IpAddr::V4(a) => (Family::Ip, NatAddr::V4(*a)),
                    IpAddr::V6(_) => (Family::Ip6, NatAddr::Reg),
                };
                self.immediate(Register::R0, octets(*addr));
                if let Some(p) = port {
                    self.immediate(Register::R1, p.to_be_bytes().to_vec());
                }
                self.out.push(Expr::Nat(NatExpr {
                    nat_type: *nat_type,
                    family,
                    addr: nat_addr,
                    port: *port,
                }));
            }
            Stmt::Nat(nat) => self.nat(nat)?,
            Stmt::Redirect(port) => {
                if let Some(p) = port {
                    self.immediate(Register::R0, p.to_be_bytes().to_vec());
                }
                self.out.push(Expr::Redirect(RedirExpr { port: *port }));
            }
            Stmt::Tproxy { family, addr, port } => self.tproxy(*family, *addr, *port)?,
            Stmt::SetMark(mark) => {
                self.immediate(Register::R0, mark.to_ne_bytes().to_vec());
                self.out.push(Expr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                });
            }
            Stmt::SetMarkMasked { value, mask } => {
                self.out.push(Expr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                });
                // (mark & !mask) ^ (value & mask): the masked bits are zero
                // after the AND, so the XOR sets them.
                self.out.push(Expr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: (!mask).to_ne_bytes().to_vec(),
                    xor: (value & mask).to_ne_bytes().to_vec(),
                });
                self.out.push(Expr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                });
            }
            Stmt::SetPriority(class) => {
                self.immediate(Register::R0, u32::from(*class).to_ne_bytes().to_vec());
                self.out.push(Expr::MetaSet {
                    key: MetaKey::Priority,
                    sreg: Register::R0,
                });
            }
            Stmt::SetCtMark(mark) => {
                self.immediate(Register::R0, mark.to_ne_bytes().to_vec());
                self.out.push(Expr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                });
            }
            Stmt::SaveMarkToCt => {
                self.out.push(Expr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                });
                self.out.push(Expr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                });
            }
            Stmt::RestoreMarkFromCt => {
                self.out.push(Expr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                });
                self.out.push(Expr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                });
            }
            Stmt::SetCtZone(zone) => {
                self.immediate(Register::R0, zone.to_ne_bytes().to_vec());
                self.out.push(Expr::CtSet {
                    key: CtKey::Zone,
                    sreg: Register::R0,
                });
            }
            Stmt::SetCtLabel(bit) => {
                let mask = ct_label_mask(*bit)
                    .ok_or_else(|| format!("ct label: bit {bit} is past 127"))?;
                self.immediate(Register::R0, mask);
                self.out.push(Expr::CtSet {
                    key: CtKey::Labels,
                    sreg: Register::R0,
                });
            }
            Stmt::SetHeader(write) => self.set_header(*write)?,
            Stmt::ClampTcpMss(mss) => {
                self.meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
                self.immediate(Register::R0, mss.to_be_bytes().to_vec());
                self.tcp_mss_write();
            }
            Stmt::ClampTcpMssToPmtu => {
                self.meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
                self.out.push(Expr::Rt {
                    dreg: Register::R0,
                    key: RtKey::TcpMss,
                });
                // `rt tcpmss` stores a host-order u16; the option wants it in
                // network order.
                self.hton(2);
                self.tcp_mss_write();
            }
            Stmt::Notrack => self.out.push(Expr::Notrack),
            Stmt::Generate(generated) => self.generate(generated),
            Stmt::SetMetaFrom(key) => self.out.push(Expr::MetaSet {
                key: *key,
                sreg: Register::R0,
            }),
            Stmt::SetCtFrom(key) => self.out.push(Expr::CtSet {
                key: *key,
                sreg: Register::R0,
            }),
            Stmt::SetMetaFromMap { key, field, map } => {
                self.field_load(*field);
                self.out
                    .push(LookupExpr::new(map, Register::R0).dreg(Register::R0).into());
                self.out.push(Expr::MetaSet {
                    key: *key,
                    sreg: Register::R0,
                });
            }
            Stmt::Dup { addr, dev } => match (addr, dev) {
                (Some(addr), dev) => {
                    self.immediate(Register::R0, octets(*addr));
                    if let Some(dev) = dev {
                        self.immediate(Register::R1, dev.to_ne_bytes().to_vec());
                    }
                    self.out.push(Expr::Dup {
                        sreg_addr: Some(Register::R0),
                        sreg_dev: dev.map(|_| Register::R1),
                    });
                }
                (None, Some(dev)) => {
                    self.immediate(Register::R0, dev.to_ne_bytes().to_vec());
                    self.out.push(Expr::Dup {
                        sreg_addr: None,
                        sreg_dev: Some(Register::R0),
                    });
                }
                (None, None) => return Err("dup: to an address, a device, or both".into()),
            },
            Stmt::Fwd { dev, addr } => {
                self.immediate(Register::R0, dev.to_ne_bytes().to_vec());
                let sreg_addr = addr.map(|addr| {
                    self.immediate(Register::R1, octets(addr));
                    let family = match addr {
                        IpAddr::V4(_) => NFPROTO_IPV4,
                        IpAddr::V6(_) => NFPROTO_IPV6,
                    };
                    (Register::R1, family)
                });
                self.out.push(Expr::Fwd {
                    sreg_dev: Register::R0,
                    sreg_addr,
                });
            }
            Stmt::Dynset { field, dynset } => {
                self.field_load(*field);
                let mut dynset = dynset.clone();
                dynset.sreg_key = Register::R0;
                self.out.push(dynset.into());
            }
            Stmt::Vmap { key, map } => {
                self.key_load(key)?;
                self.out.push(
                    LookupExpr::new(map, Register::R0)
                        .dreg(Register::Verdict)
                        .into(),
                );
            }
            Stmt::Reject(reject) => self.reject(*reject),
            Stmt::FlowOffload(flowtable) => self.out.push(Expr::FlowOffload {
                flowtable: flowtable.clone(),
            }),
            Stmt::Queue(queue) => self.out.push(Expr::Queue(queue.clone())),
            Stmt::Synproxy(synproxy) => self.out.push(Expr::Synproxy(synproxy.clone())),
        }
        Ok(())
    }

    /// The address range loaded into `R0` (and `R1`, for a range), the port
    /// range into the next registers, then the statement naming them.
    fn nat(&mut self, nat: &NatStatement) -> std::result::Result<(), String> {
        let family = nat.check()?;
        let mut free = [Register::R0, Register::R1, Register::R2, Register::R3].into_iter();
        let mut load = |out: &mut Vec<Expr>, lo: Vec<u8>, hi: Vec<u8>| {
            let first = free.next().expect("four registers hold two ranges");
            let last = if hi == lo {
                first
            } else {
                free.next().expect("four registers hold two ranges")
            };
            out.push(Expr::Immediate {
                dreg: first,
                data: lo,
            });
            if last != first {
                out.push(Expr::Immediate {
                    dreg: last,
                    data: hi,
                });
            }
            (first, last)
        };
        let addr = nat
            .addr
            .map(|(lo, hi)| load(&mut self.out, octets(lo), octets(hi)));
        let proto = nat.ports.map(|(lo, hi)| {
            load(
                &mut self.out,
                lo.to_be_bytes().to_vec(),
                hi.to_be_bytes().to_vec(),
            )
        });
        self.out.push(Expr::NatRegs(NatRegs {
            kind: nat.kind,
            family,
            addr,
            proto,
            flags: nat.flags,
        }));
        Ok(())
    }

    fn tproxy(
        &mut self,
        family: Family,
        addr: Option<IpAddr>,
        port: Option<u16>,
    ) -> std::result::Result<(), String> {
        let nfproto = match (family, addr) {
            (Family::Ip, None | Some(IpAddr::V4(_))) => NFPROTO_IPV4,
            (Family::Ip6, None | Some(IpAddr::V6(_))) => NFPROTO_IPV6,
            (Family::Inet, None) => 0,
            (Family::Inet, Some(IpAddr::V4(_))) => NFPROTO_IPV4,
            (Family::Inet, Some(IpAddr::V6(_))) => NFPROTO_IPV6,
            (family, addr) => {
                return Err(format!(
                    "tproxy: {addr:?} in a {family:?} table (an address of the table's family, \
                     in an ip, ip6 or inet table)"
                ));
            }
        };
        let mut next = [Register::R0, Register::R1].into_iter();
        let mut load = |out: &mut Vec<Expr>, data: Vec<u8>| {
            let r = next.next().expect("two at most");
            out.push(Expr::Immediate { dreg: r, data });
            r
        };
        let sreg_addr = addr.map(|a| load(&mut self.out, octets(a)));
        let sreg_port = port.map(|p| load(&mut self.out, p.to_be_bytes().to_vec()));
        self.out.push(Expr::Tproxy {
            family: nfproto,
            sreg_addr,
            sreg_port,
        });
        Ok(())
    }

    fn generate(&mut self, generated: &Generated) {
        let dreg = Register::R0;
        let expr = match generated {
            Generated::Numgen {
                kind,
                modulus,
                offset,
            } => Expr::Numgen {
                dreg,
                kind: *kind,
                modulus: *modulus,
                offset: *offset,
            },
            Generated::Jhash {
                fields,
                modulus,
                seed,
                offset,
            } => {
                // Each field in a 32-bit word of its own, from R0.
                self.concat_load(fields);
                Expr::Hash {
                    dreg,
                    kind: HashKind::Jenkins,
                    sreg: Some(Register::R0),
                    len: 4 * u32::try_from(fields.len()).unwrap_or(u32::MAX),
                    modulus: *modulus,
                    seed: *seed,
                    offset: *offset,
                }
            }
            Generated::Symhash { modulus, offset } => Expr::Hash {
                dreg,
                kind: HashKind::Sym,
                sreg: None,
                len: 0,
                modulus: *modulus,
                seed: None,
                offset: *offset,
            },
        };
        self.out.push(expr);
    }

    /// A header field written, behind the guard nft puts before it, with
    /// the checksums it is in updated. See
    /// [`Rule::set_header`](super::Rule::set_header).
    fn set_header(&mut self, write: HeaderWrite) -> std::result::Result<(), String> {
        use HeaderWrite as W;
        use PayloadBase::{Network, Transport};
        let (base, offset, len, csum, csum_offset, pseudo) = match write {
            W::IpDscp(_) => (Network, 0, 2, PayloadCsum::Inet, 10, false),
            W::IpTtl(_) => (Network, 8, 2, PayloadCsum::Inet, 10, false),
            W::IpSaddr(_) => (Network, 12, 4, PayloadCsum::Inet, 10, true),
            W::IpDaddr(_) => (Network, 16, 4, PayloadCsum::Inet, 10, true),
            W::Ip6Dscp(_) => (Network, 0, 2, PayloadCsum::None, 0, false),
            W::Ip6HopLimit(_) => (Network, 7, 1, PayloadCsum::None, 0, false),
            W::Ip6Saddr(_) => (Network, 8, 16, PayloadCsum::None, 0, true),
            W::Ip6Daddr(_) => (Network, 24, 16, PayloadCsum::None, 0, true),
            W::TcpSport(_) => (Transport, 0, 2, PayloadCsum::Inet, 16, false),
            W::TcpDport(_) => (Transport, 2, 2, PayloadCsum::Inet, 16, false),
            W::UdpSport(_) => (Transport, 0, 2, PayloadCsum::None, 0, true),
            W::UdpDport(_) => (Transport, 2, 2, PayloadCsum::None, 0, true),
        };
        if let W::IpDscp(d) | W::Ip6Dscp(d) = write
            && d > 63
        {
            return Err(format!("set_header: DSCP {d} is past 63"));
        }
        match write {
            W::IpDscp(_) | W::IpTtl(_) | W::IpSaddr(_) | W::IpDaddr(_) => {
                self.meta_eq(MetaKey::NfProto, NFPROTO_IPV4)
            }
            W::Ip6Dscp(_) | W::Ip6HopLimit(_) | W::Ip6Saddr(_) | W::Ip6Daddr(_) => {
                self.meta_eq(MetaKey::NfProto, NFPROTO_IPV6)
            }
            W::TcpSport(_) | W::TcpDport(_) => self.meta_eq(MetaKey::L4Proto, IPPROTO_TCP),
            W::UdpSport(_) | W::UdpDport(_) => self.meta_eq(MetaKey::L4Proto, IPPROTO_UDP),
        }
        // Read-modify-write: the 16 bits around the field, what keeps them
        // as `mask`, the field's new bits as `xor`.
        let masked = |out: &mut Vec<Expr>, mask: [u8; 2], xor: [u8; 2]| {
            out.push(Expr::Payload {
                dreg: Register::R0,
                base,
                offset,
                len,
            });
            out.push(Expr::Bitwise {
                sreg: Register::R0,
                dreg: Register::R0,
                len,
                mask: mask.to_vec(),
                xor: xor.to_vec(),
            });
        };
        match write {
            // DSCP is the top six bits of the TOS byte; ECN stays.
            W::IpDscp(d) => masked(&mut self.out, [0xff, 0x03], [0, d << 2]),
            W::IpTtl(t) => masked(&mut self.out, [0x00, 0xff], [t, 0]),
            // The traffic class straddles the first two bytes, after the
            // version: its DSCP is bits 4..10, its ECN 10..12.
            W::Ip6Dscp(d) => masked(&mut self.out, [0xf0, 0x3f], [d >> 2, (d & 3) << 6]),
            W::Ip6HopLimit(h) => self.immediate(Register::R0, vec![h]),
            W::IpSaddr(a) | W::IpDaddr(a) => self.immediate(Register::R0, a.octets().to_vec()),
            W::Ip6Saddr(a) | W::Ip6Daddr(a) => self.immediate(Register::R0, a.octets().to_vec()),
            W::TcpSport(p) | W::TcpDport(p) | W::UdpSport(p) | W::UdpDport(p) => {
                self.immediate(Register::R0, p.to_be_bytes().to_vec())
            }
        }
        self.out.push(Expr::PayloadSet {
            sreg: Register::R0,
            base,
            offset,
            len,
            csum,
            csum_offset,
            l4_pseudo_header: pseudo,
        });
        Ok(())
    }

    /// The `exthdr` write of the TCP MSS option from `R0`: the 2-byte value
    /// at offset 2 of the option (kind, length, value), network byte order.
    fn tcp_mss_write(&mut self) {
        self.out.push(Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        });
    }

    fn reject(&mut self, reject: Reject) {
        match reject {
            Reject::TcpReset => self.reject_with(NFT_REJECT_TCP_RST, 0),
            Reject::Icmp(code) => {
                self.meta_eq(MetaKey::NfProto, NFPROTO_IPV4);
                self.reject_with(NFT_REJECT_ICMP_UNREACH, code);
            }
            Reject::Icmpv6(code) => {
                self.meta_eq(MetaKey::NfProto, NFPROTO_IPV6);
                self.reject_with(NFT_REJECT_ICMP_UNREACH, code);
            }
            Reject::Icmpx(code) => self.reject_with(NFT_REJECT_ICMPX_UNREACH, code as u8),
            Reject::With { reject_type, code } => self.reject_with(reject_type, code),
        }
    }

    /// A TCP reset gets a `meta l4proto tcp` guard unless the rule already
    /// has one (#480).
    fn reject_with(&mut self, reject_type: u32, icmp_code: u8) {
        let tcp_guarded = self.out.windows(2).any(|w| {
            matches!(
                w,
                [
                    Expr::Meta {
                        key: MetaKey::L4Proto,
                        ..
                    },
                    Expr::Cmp {
                        op: CmpOp::Eq,
                        data,
                        ..
                    },
                ] if data.as_slice() == [IPPROTO_TCP]
            )
        });
        if reject_type == NFT_REJECT_TCP_RST && !tcp_guarded {
            self.meta_eq(MetaKey::L4Proto, IPPROTO_TCP);
        }
        self.out.push(Expr::Reject {
            reject_type,
            icmp_code,
        });
    }
}

/// What a match compares, after the field's load.
enum Compared {
    /// `cmp <op> <data>`.
    Cmp(CmpOp, Vec<u8>),
    /// `bitwise & <mask>`, then `cmp <op> <data>`.
    Masked {
        mask: Vec<u8>,
        op: CmpOp,
        data: Vec<u8>,
    },
}

/// One integer of a field's width, from host to network byte order.
fn network_order(host: &[u8]) -> Vec<u8> {
    match *host {
        [a, b] => u16::from_ne_bytes([a, b]).to_be_bytes().to_vec(),
        [a, b, c, d] => u32::from_ne_bytes([a, b, c, d]).to_be_bytes().to_vec(),
        _ => host.to_vec(),
    }
}

fn octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// An address of the field's family.
fn check_family(field: &Field, addr: IpAddr, width: u8) -> std::result::Result<(), String> {
    match (addr, width) {
        (IpAddr::V4(_), 32) | (IpAddr::V6(_), 128) => Ok(()),
        _ => Err(format!("{field}: {addr} is not an address of its family")),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn refused(item: impl Into<Item>) -> String {
        RuleSpec::new().then(item).lower_items().unwrap_err()
    }

    /// A value the field cannot hold, an operator its value does not take,
    /// a statement with nothing to act on: each says what is wrong, before
    /// anything is sent.
    #[test]
    fn what_does_not_fit_is_refused_with_why() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for (item, why) in [
            (
                Match::eq(Field::TcpDport, 70000u32).into(),
                "tcp dport: 70000 does not fit in 16 bits",
            ),
            (
                Match::eq(Field::L4Proto, 256u16).into(),
                "meta l4proto: 256 does not fit in 8 bits",
            ),
            (
                Match::eq(Field::Ip4Saddr, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)).into(),
                "ip saddr: ::1 is not an address of its family",
            ),
            (
                Match::eq(Field::Ip4Saddr, Value::Prefix(v4, 33)).into(),
                "ip saddr: /33 is past /32",
            ),
            (
                Match::new(Field::Ip4Saddr, MatchOp::Lt, Value::Prefix(v4, 8)).into(),
                "ip saddr: a prefix is matched with == or !=, not <",
            ),
            (
                Match::new(Field::TcpDport, MatchOp::Lt, Value::set("s")).into(),
                "tcp dport: a set is matched with == or !=, not <",
            ),
            (
                Match::new(Field::TcpDport, MatchOp::Ge, Value::range(1u16, 2u16)).into(),
                "tcp dport: a range is matched with == or !=, not >=",
            ),
            (
                Match::new(Field::CtState, MatchOp::Gt, CtState::NEW).into(),
                "ct state: a flag set is matched with == or !=, not >",
            ),
            (
                Match::new(Field::Iifname, MatchOp::Lt, Value::NamePrefix("e".into())).into(),
                "meta iifname: a name prefix is matched with == or !=, not <",
            ),
            (
                Match::eq(Field::Iifname, 3u32).into(),
                "meta iifname: cannot be matched against Int(3)",
            ),
            (
                Match::eq(Field::CtState, Value::set("s")).into(),
                "ct state: no set holds it",
            ),
            (
                Match::eq(Field::Concat(vec![PacketField::Mark]), 1u8).into(),
                "a concatenation is matched against a set",
            ),
            (
                Match::eq(Field::CtSaddr(CtDirection::Reply), 1u8).into(),
                "ct reply saddr: cannot be matched against Int(1)",
            ),
            (Match::eq(Field::CtLabel, 128u8).into(), "ct label: bit 128 is past 127"),
            (
                Match::new(Field::Mark, MatchOp::Gt, Value::Masked { value: 1, mask: 0xff }).into(),
                "meta mark: a mask is matched with == or !=, not >",
            ),
            (Stmt::Dup { addr: None, dev: None }.into(), "dup: to an address, a device, or both"),
            (
                Stmt::Vmap { key: Field::CtState, map: "m".into() }.into(),
                "ct state: no set holds it",
            ),
        ] {
            let item: Item = item;
            assert_eq!(refused(item.clone()), why, "{item:?}");
        }
    }

    /// The first item that does not lower is the one reported, and a spec
    /// collects from items.
    #[test]
    fn a_spec_is_its_items() {
        let spec: RuleSpec = [
            Item::from(Match::eq(Field::TcpDport, 22u16)),
            Match::eq(Field::Iifname, "a-name-past-fifteen").into(),
            Match::eq(Field::TcpDport, 70000u32).into(),
        ]
        .into_iter()
        .collect();
        assert_eq!(spec.items().len(), 3);
        assert!(
            spec.lower_items()
                .unwrap_err()
                .starts_with("interface name")
        );
        let mut spec = RuleSpec::new().comment("c");
        spec.extend([Item::Verdict(Verdict::Accept)]);
        assert_eq!(spec.comment_ref(), Some("c"));
        assert_eq!(
            spec.nft_syntax(Family::Inet).as_deref(),
            Some("accept comment \"c\"")
        );
        let err = RuleSpec::new()
            .then(Match::eq(Field::TcpDport, 70000u32))
            .lower(Family::Inet);
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("tcp dport: 70000 does not fit in 16 bits")
        );
    }

    /// An ordered compare on a host-order field compares it in network
    /// order, on any host: the load is turned, and so is the value.
    #[test]
    fn an_order_on_a_host_order_field_compares_in_network_order() {
        let lowered = |field, n: u32| {
            RuleSpec::new()
                .then(Match::new(field, MatchOp::Gt, n))
                .lower_items()
                .unwrap()
        };
        let hton = |len| Expr::Byteorder {
            sreg: Register::R0,
            dreg: Register::R0,
            op: ByteorderOp::Hton,
            len,
            size: len,
        };
        let gt = |data: &[u8]| Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Gt,
            data: data.to_vec(),
        };
        assert_eq!(
            lowered(Field::Mark, 0x10),
            [
                Expr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                },
                hton(4),
                gt(&[0, 0, 0, 0x10]),
            ]
        );
        assert_eq!(
            lowered(Field::CtZone, 0x102),
            [
                Expr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Zone,
                },
                hton(2),
                gt(&[1, 2]),
            ]
        );
        // A port is in network order already.
        assert_eq!(
            lowered(Field::TcpDport, 0x102)[2..],
            [
                Expr::Payload {
                    dreg: Register::R0,
                    base: PayloadBase::Transport,
                    offset: 2,
                    len: 2,
                },
                gt(&[1, 2]),
            ]
        );
    }

    /// Fields name themselves as nft does.
    #[test]
    fn a_field_prints_as_nft_names_it() {
        assert_eq!(Field::Ip6Daddr.to_string(), "ip6 daddr");
        assert_eq!(
            Field::CtDport(CtDirection::Original).to_string(),
            "ct original proto-dst"
        );
        assert_eq!(
            Field::Socket(SocketKey::Transparent).to_string(),
            "socket transparent"
        );
        assert_eq!(
            Field::Concat(vec![PacketField::Ip4Saddr, PacketField::TcpDport]).to_string(),
            "ip saddr . tcp dport"
        );
        assert_eq!(Field::from(PacketField::Oif), Field::Oif);
        assert_eq!(Field::Oif.packet_field(), Some(PacketField::Oif));
        assert_eq!(Field::CtZone.packet_field(), None);
    }
}
