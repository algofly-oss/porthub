//! nftables expression types and serialization.

use super::{types::*, *};
use crate::netlink::builder::MessageBuilder;

/// A single nftables expression.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expr {
    /// Load metadata into a register.
    Meta { dreg: Register, key: MetaKey },
    /// Write a register into packet metadata (`meta mark set ...`).
    MetaSet { key: MetaKey, sreg: Register },
    /// Compare register value.
    Cmp {
        sreg: Register,
        op: CmpOp,
        data: Vec<u8>,
    },
    /// Load packet payload into a register.
    Payload {
        dreg: Register,
        base: PayloadBase,
        offset: u32,
        len: u32,
    },
    /// Load immediate value into a register.
    Immediate { dreg: Register, data: Vec<u8> },
    /// Write a register into the packet (`ip dscp set`, `tcp dport set`)
    /// and update the checksums the bytes are in (#703). See
    /// [`Rule::set_header`].
    PayloadSet {
        sreg: Register,
        base: PayloadBase,
        offset: u32,
        len: u32,
        /// The checksum in the same header that the write updates.
        csum: PayloadCsum,
        /// Where that checksum is, from the start of the header.
        csum_offset: u32,
        /// The transport checksum covers the bytes through its
        /// pseudo-header (an address), so it is updated too.
        l4_pseudo_header: bool,
    },
    /// Load an extension header / option field into a register
    /// (`tcp option maxseg size`). The rule stops matching when the
    /// header or option is absent.
    Exthdr {
        dreg: Register,
        op: ExthdrOp,
        /// Extension header type, or option kind (e.g. [`TCPOPT_MAXSEG`]).
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// Overwrite an extension header / option field from a register
    /// (`tcp option maxseg size set ...`). The kernel fixes up the
    /// checksum.
    ///
    /// Only [`ExthdrOp::TcpOpt`] is writable, and `nft_exthdr_tcp_set_init`
    /// requires `offset >= 2` (the kind and length bytes are not writable)
    /// and `len` of 2 or 4 — anything else is `EOPNOTSUPP`. The register
    /// must hold the value in network byte order. The kernel never raises
    /// an MSS through this expression, and a packet without the option is
    /// left alone; a non-TCP packet ends rule evaluation.
    ExthdrSet {
        sreg: Register,
        op: ExthdrOp,
        /// Extension header type, or option kind (e.g. [`TCPOPT_MAXSEG`]).
        exthdr_type: u8,
        /// Byte offset within the option; at least 2.
        offset: u32,
        /// Number of bytes written.
        len: u32,
    },
    /// Emit a verdict.
    Verdict(Verdict),
    /// Packet counter.
    Counter,
    /// Rate limit — see [`LimitExpr`].
    Limit(LimitExpr),
    /// Masquerade (source NAT to the outgoing interface's address) — see
    /// [`MasqExpr`].
    Masquerade(MasqExpr),
    /// NAT (snat/dnat) with optional address and port.
    Nat(NatExpr),
    /// Any NAT statement at register level — snat, dnat, masquerade or
    /// redirect, with ranges and flags. [`Rule::nat`](super::types::Rule::nat)
    /// builds one after loading the values it names (#528).
    NatRegs(NatRegs),
    /// Redirect to the local machine — see [`RedirExpr`].
    Redirect(RedirExpr),
    /// Reject the packet — send an ICMP unreachable or a TCP RST, then drop.
    ///
    /// Distinct from [`Verdict::Drop`], which black-holes the packet silently
    /// and leaves the client hanging until its TCP timeout.
    ///
    /// Prefer building this through [`Rule::reject`] /
    /// [`Rule::reject_with`](super::types::Rule::reject_with), which pick a
    /// default appropriate for the chain's family.
    ///
    /// [`Rule::reject`]: super::types::Rule::reject
    Reject {
        /// `NFT_REJECT_ICMP_UNREACH` / `NFT_REJECT_TCP_RST` /
        /// `NFT_REJECT_ICMPX_UNREACH`.
        reject_type: u32,
        /// ICMP code to send. Ignored for `NFT_REJECT_TCP_RST`.
        icmp_code: u8,
    },
    /// Log the packet — see [`LogExpr`].
    Log(LogExpr),
    /// Send the packet to a userspace queue — see [`QueueExpr`] (#703).
    Queue(QueueExpr),
    /// Hand the packet to a local socket at the address and port in the
    /// registers, keeping its destination (#703). See [`Rule::tproxy`].
    Tproxy {
        /// `NFPROTO_IPV4`, `NFPROTO_IPV6`, or 0 (an inet table, either).
        family: u8,
        sreg_addr: Option<Register>,
        sreg_port: Option<Register>,
    },
    /// Load something about the packet's local socket (#703). See
    /// [`Rule::match_socket`].
    Socket {
        dreg: Register,
        key: SocketKey,
    },
    /// Answer a SYN for the server with a SYN cookie (#703) — see
    /// [`SynproxyExpr`].
    Synproxy(SynproxyExpr),
    /// The operating system a TCP SYN's fingerprint names, into `dreg`
    /// (#703) — see [`Rule::match_osf`].
    Osf {
        dreg: Register,
        ttl: OsfTtl,
        version: bool,
    },
    /// A number into `dreg`: counting up, or at random, modulo `modulus`,
    /// plus `offset` (#703). See [`Rule::generate`].
    Numgen {
        dreg: Register,
        kind: NumgenKind,
        modulus: u32,
        offset: u32,
    },
    /// A hash into `dreg`, modulo `modulus`, plus `offset` (#703): Jenkins
    /// over `len` bytes from `sreg` with `seed` (the kernel's own when
    /// `None`), or the flow's symmetric hash. See [`Rule::generate`].
    Hash {
        dreg: Register,
        kind: HashKind,
        sreg: Option<Register>,
        len: u32,
        modulus: u32,
        seed: Option<u32>,
        offset: u32,
    },
    /// Send a copy of the packet out: to the gateway in `sreg_addr`, out of
    /// the device in `sreg_dev` (#703). See [`Rule::dup_to`].
    Dup {
        sreg_addr: Option<Register>,
        sreg_dev: Option<Register>,
    },
    /// Send the packet out of the device in `sreg_dev` (netdev family), to
    /// the next hop in `sreg_addr` of family `nfproto` (#703). See
    /// [`Rule::fwd_to`].
    Fwd {
        sreg_dev: Register,
        sreg_addr: Option<(Register, u8)>,
    },
    /// Connection tracking.
    Ct { dreg: Register, key: CtKey },
    /// Write a register into the packet's conntrack entry
    /// (`ct mark set ...`). The kernel accepts `Mark`, `Secmark` and a
    /// few keys [`CtKey`] does not model (labels, zone, event mask).
    /// Needs the `nft_ct` module.
    CtSet { key: CtKey, sreg: Register },
    /// Load a conntrack key of one direction's tuple into a register
    /// (`ct original ip saddr`, `ct reply proto-dst`, …) (#528).
    CtDirectional {
        dreg: Register,
        key: CtKey,
        direction: CtDirection,
    },
    /// `ct count [over] <count>`: the connections the rule has seen
    /// (`connlimit`).
    Connlimit { count: u32, over: bool },
    /// Load routing data into a register (`rt mtu`, `rt classid`, …).
    Rt { dreg: Register, key: RtKey },
    /// Look the packet up in the routing table (`fib saddr . iif oif`),
    /// putting `result` in `dreg` (#528).
    Fib {
        dreg: Register,
        result: FibResult,
        flags: FibFlags,
    },
    /// `notrack`: leave the packet out of connection tracking.
    Notrack,
    /// Compare a register with a range of values, both ends included
    /// (`tcp dport 1000-2000`, `!= 1000-2000`). The values are in network
    /// byte order: a host-order field goes through a
    /// [`Byteorder`](Self::Byteorder) first. Built by
    /// [`Rule::match_range`](super::types::Rule::match_range) (#528).
    Range {
        sreg: Register,
        op: RangeOp,
        from: Vec<u8>,
        to: Vec<u8>,
    },
    /// Convert `len` bytes of `sreg`, in `size`-byte (2, 4 or 8) units,
    /// between host and network byte order into `dreg`.
    Byteorder {
        sreg: Register,
        dreg: Register,
        op: ByteorderOp,
        len: u32,
        size: u32,
    },
    /// Look a register up in a named set or map — see [`LookupExpr`].
    Lookup(LookupExpr),
    /// Add, refresh or delete a set element from the packet path — see
    /// [`DynsetExpr`].
    Dynset(DynsetExpr),
    /// A byte quota of the rule's own — see [`QuotaExpr`].
    Quota(QuotaExpr),
    /// Use a named stateful object — see [`ObjrefExpr`].
    Objref(ObjrefExpr),
    /// Bitwise operation.
    Bitwise {
        sreg: Register,
        dreg: Register,
        len: u32,
        mask: Vec<u8>,
        xor: Vec<u8>,
    },
    /// Add the matched flow to the named flowtable
    /// (equivalent to nft's `flow add @<ft>` rule clause). The
    /// kernel installs the flow into the named flowtable so
    /// matching follow-on packets bypass the rule traversal.
    /// See [`crate::netlink::nftables::Flowtable`].
    FlowOffload {
        /// Name of the flowtable. Must resolve to a flowtable in
        /// the same owning table as this rule.
        flowtable: String,
    },
    /// An expression nlink does not model, as raw bytes — see [`RawExpr`].
    Raw(RawExpr),
}

/// An expression nlink does not model: its `NFTA_EXPR_NAME` and the raw
/// `NFTA_EXPR_DATA` payload, written as given. The escape hatch for the
/// long tail of `nft` expressions (`fib`, `socket`, `tproxy`, `queue`, …).
///
/// The declarative diff compares a rule body byte for byte with the
/// kernel's echo of it. Where the kernel dumps an expression differently
/// from how it was sent — an attribute filled in, or one it does not echo —
/// give the dumped payload as [`echo`](Self::echo) and the diff compares
/// against that instead. An expression the kernel dumps with no data at all
/// (no `dump` callback, like `notrack`) is [`without_data`](Self::without_data):
/// an empty data nest is not the same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawExpr {
    /// Expression name (`"fib"`, `"socket"`, `"notrack"`, …).
    pub name: String,
    /// `NFTA_EXPR_DATA` payload — the expression's attributes — or `None`
    /// for an expression with no data nest at all.
    pub data: Option<Vec<u8>>,
    /// The payload the kernel dumps for it, if it differs from `data`.
    pub echo: Option<Vec<u8>>,
}

impl RawExpr {
    /// `name` with the attribute bytes `data` (an empty `data` writes an
    /// empty nest, as the kernel dumps for `masq`).
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data: Some(data),
            echo: None,
        }
    }

    /// `name` with no `NFTA_EXPR_DATA` nest, for expressions the kernel
    /// dumps without one (`notrack`).
    pub fn without_data(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: None,
            echo: None,
        }
    }

    /// What the kernel dumps for this expression, when that is not `data`.
    pub fn echo(mut self, dumped: Vec<u8>) -> Self {
        self.echo = Some(dumped);
        self
    }
}

impl From<RawExpr> for Expr {
    fn from(e: RawExpr) -> Self {
        Expr::Raw(e)
    }
}

// The expressions most likely to grow carry a `#[non_exhaustive]` payload
// struct — built with `new()` and setters, and turned into an `Expr` with
// `From`/`.into()` or pushed with `Rule::expr` — so that a field added later
// (a byte-rate limit, a log level, masquerade ports) is not a breaking
// change. The stable expressions stay plain struct variants.

/// `lookup`: look a register up in a named set (`ip saddr @s`), optionally
/// inverted (`ip saddr != @s`), or in a map, loading the mapped value into
/// [`dreg`](Self::dreg) (`Register::Verdict` for a verdict map, `vmap`).
///
/// The kernel rejects an inverted map lookup (`EINVAL`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LookupExpr {
    /// Set or map name.
    pub set: String,
    /// Register holding the key.
    pub sreg: Register,
    /// Destination register of a map lookup; `None` for a set membership
    /// test.
    pub dreg: Option<Register>,
    /// Match when the key is *not* in the set (`NFT_LOOKUP_F_INV`).
    pub invert: bool,
}

impl LookupExpr {
    /// A membership test of `sreg` in `set`.
    pub fn new(set: impl Into<String>, sreg: Register) -> Self {
        Self {
            set: set.into(),
            sreg,
            dreg: None,
            invert: false,
        }
    }

    /// Make this a map lookup, loading the value into `dreg`.
    pub fn dreg(mut self, dreg: Register) -> Self {
        self.dreg = Some(dreg);
        self
    }

    /// Match keys that are *not* in the set.
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }
}

impl From<LookupExpr> for Expr {
    fn from(e: LookupExpr) -> Self {
        Expr::Lookup(e)
    }
}

/// `quota`: a byte budget. `quota until N bytes` matches until `N` bytes
/// have passed it; with [`over`](Self::over), `quota over N bytes` matches
/// only after. As a rule expression the quota is the rule's own; as an
/// [`Object`] it is shared by name.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct QuotaExpr {
    /// The quota, in bytes.
    pub bytes: u64,
    /// Match once the quota is used up (`NFT_QUOTA_F_INV`), not until.
    pub over: bool,
}

impl QuotaExpr {
    /// `quota until <bytes> bytes`.
    pub fn new(bytes: u64) -> Self {
        Self { bytes, over: false }
    }

    /// `quota over <bytes> bytes`: match once used up.
    pub fn over(mut self) -> Self {
        self.over = true;
        self
    }
}

impl From<QuotaExpr> for Expr {
    fn from(e: QuotaExpr) -> Self {
        Expr::Quota(e)
    }
}

/// `objref`: use a named stateful object — counter, quota or limit — by name
/// (`counter name "web"`), or the one an object map picks for the key in a
/// register (`counter name ip saddr map @counters`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjrefExpr {
    /// The object `name` of type `object_type`.
    Named {
        /// Object type.
        object_type: super::object::ObjectType,
        /// Object name.
        name: String,
    },
    /// The object the object map `map` holds for the key in `sreg`.
    Map {
        /// Register holding the key.
        sreg: Register,
        /// Object map name.
        map: String,
    },
}

impl From<ObjrefExpr> for Expr {
    fn from(e: ObjrefExpr) -> Self {
        Expr::Objref(e)
    }
}

/// What a [`DynsetExpr`] does to its set: `NFT_DYNSET_OP_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum DynsetOp {
    /// `add @set { key }`: insert the key unless it is there.
    Add = 0,
    /// `update @set { key }`: insert it, or restart its timeout.
    Update = 1,
    /// `delete @set { key }`: remove it.
    Delete = 2,
}

impl DynsetOp {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Add),
            1 => Some(Self::Update),
            2 => Some(Self::Delete),
            _ => None,
        }
    }
}

/// `dynset`: add, refresh or delete a set element from the packet path —
/// `add @seen { ip saddr timeout 60s }`, ipset `SET --add-set`, and the
/// building block of "recently seen", port knocking and per-source state.
///
/// The set must be one the kernel can update from the packet path: give it
/// [`Set::dynamic`](super::types::Set::dynamic) (`NFT_SET_EVAL`, which
/// selects the resizable hash backend; interval sets cannot be updated),
/// and [`Set::timeout`](super::types::Set::timeout) or
/// [`Set::per_element_timeouts`](super::types::Set::per_element_timeouts)
/// for an element timeout. The rule continues when the update succeeds,
/// and stops when it cannot (the set is full) — or the other way round
/// with [`invert`](Self::invert).
///
/// Per-element [`statement`](Self::statement)s give each element its own
/// state: `add @seen { ip saddr counter }` counts per address, and `update
/// @flood { ip saddr limit rate over 10/second }` continues only for an
/// address over its own rate (#703). They must be stateful — counter,
/// limit, quota, connlimit — and the set dynamic. A set that declares its
/// own element statements gives them to every element instead; then give
/// the dynset none, or the same ones, which the kernel does not echo.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DynsetExpr {
    /// Set name.
    pub set: String,
    /// What to do.
    pub op: DynsetOp,
    /// Register holding the key.
    pub sreg_key: Register,
    /// Register holding the value, for a map; `None` for a set.
    pub sreg_data: Option<Register>,
    /// Timeout of the element added; `None` for the set's default.
    pub timeout: Option<std::time::Duration>,
    /// Match when the update fails rather than when it succeeds
    /// (`NFT_DYNSET_F_INV`).
    pub invert: bool,
    /// Per-element statements, each element its own (#703).
    pub statements: Vec<ElementStatement>,
}

impl DynsetExpr {
    /// `op` the key in `sreg_key` on `set`.
    pub fn new(op: DynsetOp, set: impl Into<String>, sreg_key: Register) -> Self {
        Self {
            set: set.into(),
            op,
            sreg_key,
            sreg_data: None,
            timeout: None,
            invert: false,
            statements: Vec::new(),
        }
    }

    /// Give each element its own `statement`, evaluated on every packet
    /// that adds or updates it. A limit or quota stops the rule as it would
    /// on its own.
    pub fn statement(mut self, statement: impl Into<ElementStatement>) -> Self {
        self.statements.push(statement.into());
        self
    }

    /// A per-element `counter`.
    pub fn counter(self) -> Self {
        self.statement(ElementStatement::Counter)
    }

    /// Give the element this timeout instead of the set's default. The set
    /// needs timeouts; the kernel keeps it in jiffies, so it is rounded
    /// down to one (and reads back that way).
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// For a map: the register holding the value to store with the key.
    pub fn sreg_data(mut self, sreg: Register) -> Self {
        self.sreg_data = Some(sreg);
        self
    }

    /// Match when the update fails instead.
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }
}

impl From<DynsetExpr> for Expr {
    fn from(e: DynsetExpr) -> Self {
        Expr::Dynset(e)
    }
}

/// A statement a set element carries of its own (#703), from a
/// [`DynsetExpr`] that adds it: the stateful expressions
/// `nft_set_elem_expr_alloc` accepts.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElementStatement {
    /// `counter`: the element's packets and bytes.
    Counter,
    /// `limit rate …`: the element's own rate.
    Limit(LimitExpr),
    /// `quota …`: the element's own byte budget.
    Quota(QuotaExpr),
    /// `ct count [over] N`: the element's own connection count.
    Connlimit {
        /// Connections.
        count: u32,
        /// Match over `count` instead of up to it.
        over: bool,
    },
}

impl From<LimitExpr> for ElementStatement {
    fn from(limit: LimitExpr) -> Self {
        Self::Limit(limit)
    }
}

impl From<QuotaExpr> for ElementStatement {
    fn from(quota: QuotaExpr) -> Self {
        Self::Quota(quota)
    }
}

impl ElementStatement {
    /// The statement a decoded expression is, if it is one; its live state
    /// (a counter's packets, a quota's use) is dropped.
    pub(crate) fn from_rule_expr(expr: &RuleExpr) -> Option<Self> {
        match expr {
            RuleExpr::Counter { .. } => Some(Self::Counter),
            RuleExpr::Limit(limit) => Some(Self::Limit(limit.clone())),
            RuleExpr::Quota { bytes, over, .. } => {
                let quota = QuotaExpr::new(*bytes);
                Some(Self::Quota(if *over { quota.over() } else { quota }))
            }
            RuleExpr::Connlimit { count, over } => Some(Self::Connlimit {
                count: *count,
                over: *over,
            }),
            _ => None,
        }
    }

    /// As a template the kernel dumps it: its state at zero.
    pub(crate) fn as_dumped(&self) -> RuleExpr {
        match self.kernel_form() {
            Self::Counter => RuleExpr::Counter {
                packets: 0,
                bytes: 0,
            },
            Self::Limit(limit) => RuleExpr::Limit(limit),
            Self::Quota(quota) => RuleExpr::Quota {
                bytes: quota.bytes,
                consumed: 0,
                over: quota.over,
                depleted: false,
            },
            Self::Connlimit { count, over } => RuleExpr::Connlimit { count, over },
        }
    }

    /// As the kernel keeps it: a packet limit's burst of 0 is its 5.
    pub(crate) fn kernel_form(&self) -> Self {
        match self {
            Self::Limit(limit) if limit.kind == LimitKind::Packets && limit.burst == 0 => {
                Self::Limit(limit.clone().burst(5))
            }
            other => other.clone(),
        }
    }
}

/// One statement in `nest` (an `NFTA_*_EXPR`), several in `list` (an
/// `NFTA_*_EXPRESSIONS` of `NFTA_LIST_ELEM`): how a set and a dynset carry
/// them.
pub(crate) fn write_statements(
    builder: &mut MessageBuilder,
    statements: &[ElementStatement],
    nest: u16,
    list: u16,
    form: WireForm,
) {
    match statements {
        [] => {}
        [one] => {
            let at = builder.nest_start(nest | 0x8000);
            write_expr_body(builder, &one.clone().into(), form);
            builder.nest_end(at);
        }
        several => {
            let at = builder.nest_start(list | 0x8000);
            for statement in several {
                write_expr(builder, &statement.clone().into(), form);
            }
            builder.nest_end(at);
        }
    }
}

impl From<ElementStatement> for Expr {
    fn from(statement: ElementStatement) -> Self {
        match statement {
            ElementStatement::Counter => Expr::Counter,
            ElementStatement::Limit(limit) => Expr::Limit(limit),
            ElementStatement::Quota(quota) => Expr::Quota(quota),
            ElementStatement::Connlimit { count, over } => Expr::Connlimit { count, over },
        }
    }
}

/// `limit`: a packet- or byte-rate limit, matching while under the rate
/// (or, with [`over`](Self::over), once over it).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LimitExpr {
    /// Packets, or bytes, per [`unit`](Self::unit).
    pub rate: u64,
    /// Time unit of the rate.
    pub unit: LimitUnit,
    /// Burst, in packets or bytes as the rate is. The kernel stores a
    /// packet limit's 0 as its default, 5, and nlink sends 5 for it so the
    /// declared rule matches the dump; a byte limit's 0 stays 0.
    pub burst: u32,
    /// Whether the rate counts packets or bytes (#528).
    pub kind: LimitKind,
    /// Match once the rate is exceeded (`limit rate over`,
    /// `NFT_LIMIT_F_INV`).
    pub over: bool,
}

impl LimitExpr {
    /// `limit rate <rate>/<unit>`, burst 5.
    pub fn packets(rate: u64, unit: LimitUnit) -> Self {
        Self {
            rate,
            unit,
            burst: 5,
            over: false,
            kind: LimitKind::Packets,
        }
    }

    /// `limit rate <rate> bytes/<unit>` (#528): `LimitExpr::bytes(Bytes::mib(10),
    /// LimitUnit::Second)` is nft's `limit rate 10 mbytes/second`. No burst
    /// unless [`burst`](Self::burst) gives one, in bytes.
    pub fn bytes(rate: crate::Bytes, unit: LimitUnit) -> Self {
        Self {
            rate: rate.as_u64(),
            unit,
            burst: 0,
            over: false,
            kind: LimitKind::Bytes,
        }
    }

    /// Set the burst, in packets or bytes as the rate is.
    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    /// Match packets over the rate instead of under it.
    pub fn over(mut self) -> Self {
        self.over = true;
        self
    }
}

impl From<LimitExpr> for Expr {
    fn from(e: LimitExpr) -> Self {
        Expr::Limit(e)
    }
}

/// `log`: to syslog (no group), or to an `nflog` group.
///
/// Two things every namespace user meets. To syslog, a `log` in any
/// namespace but the initial one writes **nothing** unless the host sets
/// `net.netfilter.nf_log_all_netns=1` (`nf_log_allowed()`); an `nflog`
/// group has no such limit. And the logger is the `nf_log_syslog` module:
/// where it cannot be loaded, the rule — and the whole batch with it —
/// fails with `ENOENT`.
///
/// A syslog `log` takes a [`level`](Self::level) and
/// [`flags`](Self::flags); an `nflog` [`group`](Self::group) takes a
/// [`snaplen`](Self::snaplen) and a
/// [`queue_threshold`](Self::queue_threshold). The kernel refuses a `log`
/// that mixes the two (#703).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogExpr {
    /// Prefix prepended to the log line.
    pub prefix: Option<String>,
    /// `nflog` group; `None` logs to syslog.
    pub group: Option<u16>,
    /// Syslog level; `None` is the kernel's, `warn`. A decoded `log` at
    /// `warn` reads as `None`.
    pub level: Option<LogLevel>,
    /// What a syslog `log` adds to the line.
    pub flags: LogFlags,
    /// Bytes of the packet an `nflog` group copies; `None`, all of it.
    pub snaplen: Option<u32>,
    /// Packets an `nflog` group queues before it sends them; `None` (or
    /// 0) sends each at once.
    pub queue_threshold: Option<u16>,
}

impl LogExpr {
    /// A syslog `log` with no prefix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Log to an `nflog` group instead of syslog.
    pub fn group(mut self, group: u16) -> Self {
        self.group = Some(group);
        self
    }

    /// The syslog level (`log level info`).
    pub fn level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// What a syslog `log` adds to the line (`log flags tcp sequence`).
    pub fn flags(mut self, flags: LogFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Bytes of the packet an `nflog` group copies (`log group 2 snaplen
    /// 64`).
    pub fn snaplen(mut self, bytes: u32) -> Self {
        self.snaplen = Some(bytes);
        self
    }

    /// Packets an `nflog` group queues before it sends them (`log group 2
    /// queue-threshold 10`).
    pub fn queue_threshold(mut self, packets: u16) -> Self {
        self.queue_threshold = Some(packets);
        self
    }
}

/// A syslog `log`'s level (`enum nft_log_level`). `Audit` sends the
/// packet to the audit subsystem instead of syslog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum LogLevel {
    /// `emerg`.
    Emerg = 0,
    /// `alert`.
    Alert = 1,
    /// `crit`.
    Crit = 2,
    /// `err`.
    Err = 3,
    /// `warn`, the kernel's default.
    Warning = 4,
    /// `notice`.
    Notice = 5,
    /// `info`.
    Info = 6,
    /// `debug`.
    Debug = 7,
    /// `audit`.
    Audit = 8,
}

impl LogLevel {
    fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Emerg,
            1 => Self::Alert,
            2 => Self::Crit,
            3 => Self::Err,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            7 => Self::Debug,
            8 => Self::Audit,
            _ => return None,
        })
    }

    /// nft's word for it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Emerg => "emerg",
            Self::Alert => "alert",
            Self::Crit => "crit",
            Self::Err => "err",
            Self::Warning => "warn",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Audit => "audit",
        }
    }
}

bitflags::bitflags! {
    /// What a syslog `log` adds to the line (`NF_LOG_*`,
    /// `linux/netfilter/nf_log.h`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LogFlags: u32 {
        /// `tcp sequence`.
        const TCP_SEQUENCE = super::NF_LOG_TCPSEQ;
        /// `tcp options`.
        const TCP_OPTIONS = super::NF_LOG_TCPOPT;
        /// `ip options`.
        const IP_OPTIONS = super::NF_LOG_IPOPT;
        /// `skuid`: the uid of the local socket.
        const SKUID = super::NF_LOG_UID;
        /// `ether`: the MAC header.
        const ETHER = super::NF_LOG_MACDECODE;
        /// `all`.
        const ALL = super::NF_LOG_MASK;
    }
}

impl From<LogExpr> for Expr {
    fn from(e: LogExpr) -> Self {
        Expr::Log(e)
    }
}

/// What a `socket` expression loads (`enum nft_socket_keys`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum SocketKey {
    /// `socket transparent`: the socket has `IP_TRANSPARENT` (1 byte).
    Transparent = 0,
    /// `socket mark`: the socket's mark (4 bytes).
    Mark = 1,
    /// `socket wildcard`: the socket is bound to the wildcard address
    /// (1 byte).
    Wildcard = 2,
    /// `socket cgroupv2 level N`: the socket's cgroup at a level.
    Cgroupv2 = 3,
}

/// How an `osf` compares a SYN's TTL with its fingerprint's
/// (`NF_OSF_TTL_*`, #703).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
#[non_exhaustive]
pub enum OsfTtl {
    /// Exactly — nft's default.
    #[default]
    Exact = 0,
    /// `ttl loose`: at most the fingerprint's.
    Loose = 1,
    /// `ttl skip`: not at all.
    Skip = 2,
}

/// `synproxy`: answer a SYN for a server with a SYN cookie, and open the
/// connection to it once the client's ACK proves the address (#703).
/// Allowed in `input` and `forward` filter chains; the SYN must come
/// untracked (`notrack` in a raw chain) or `ct state invalid`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SynproxyExpr {
    /// The MSS the cookie announces.
    pub mss: Option<u16>,
    /// The window scale it announces.
    pub wscale: Option<u8>,
    /// Announce timestamps.
    pub timestamp: bool,
    /// Announce selective acknowledgement.
    pub sack_perm: bool,
}

impl SynproxyExpr {
    /// `synproxy`, with nothing announced.
    pub fn new() -> Self {
        Self::default()
    }

    /// `mss <mss>`.
    pub fn mss(mut self, mss: u16) -> Self {
        self.mss = Some(mss);
        self
    }

    /// `wscale <scale>`.
    pub fn wscale(mut self, scale: u8) -> Self {
        self.wscale = Some(scale);
        self
    }

    /// `timestamp`.
    pub fn timestamp(mut self) -> Self {
        self.timestamp = true;
        self
    }

    /// `sack-perm`.
    pub fn sack_perm(mut self) -> Self {
        self.sack_perm = true;
        self
    }

    fn flags(&self) -> u32 {
        let mut f = 0;
        if self.mss.is_some() {
            f |= NF_SYNPROXY_OPT_MSS;
        }
        if self.wscale.is_some() {
            f |= NF_SYNPROXY_OPT_WSCALE;
        }
        if self.sack_perm {
            f |= NF_SYNPROXY_OPT_SACK_PERM;
        }
        if self.timestamp {
            f |= NF_SYNPROXY_OPT_TIMESTAMP;
        }
        f
    }
}

impl From<SynproxyExpr> for Expr {
    fn from(e: SynproxyExpr) -> Self {
        Expr::Synproxy(e)
    }
}

/// How a `numgen` counts (`enum nft_ng_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum NumgenKind {
    /// `inc`: 0, 1, 2, … for each packet.
    Incremental = 0,
    /// `random`.
    Random = 1,
}

/// Which hash a `hash` takes (`enum nft_hash_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum HashKind {
    /// `jhash`: Jenkins, over fields the rule loads.
    Jenkins = 0,
    /// `symhash`: the flow's hash, the same both ways.
    Sym = 1,
}

/// `queue`: hand the packet to a userspace program on an `nfqueue` (#703).
///
/// A range of queues is load-balanced by a hash of the flow, or by CPU
/// with [`QueueFlags::FANOUT`]; without a listener the packet is dropped,
/// unless [`QueueFlags::BYPASS`]. [`register`](Self::register) takes the
/// queue number from a register a `hash` or `numgen` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueExpr {
    /// The first queue.
    pub num: u16,
    /// How many queues from `num`, at least 1.
    pub total: u16,
    /// The register with the queue number, instead of `num`/`total`.
    pub sreg: Option<Register>,
    /// `bypass`, `fanout`.
    pub flags: QueueFlags,
}

impl QueueExpr {
    /// `queue num <num>`.
    pub fn num(num: u16) -> Self {
        Self {
            num,
            total: 1,
            sreg: None,
            flags: QueueFlags::empty(),
        }
    }

    /// `queue num <first>-<last>`; an inverted range is taken as given.
    pub fn range(first: u16, last: u16) -> Self {
        Self {
            num: first.min(last),
            total: first.abs_diff(last) + 1,
            ..Self::num(0)
        }
    }

    /// `queue to <register>`: the queue number from a register.
    pub fn register(sreg: Register) -> Self {
        Self {
            num: 0,
            total: 0,
            sreg: Some(sreg),
            flags: QueueFlags::empty(),
        }
    }

    /// Set the flags.
    pub fn flags(mut self, flags: QueueFlags) -> Self {
        self.flags = flags;
        self
    }
}

impl From<QueueExpr> for Expr {
    fn from(e: QueueExpr) -> Self {
        Expr::Queue(e)
    }
}

bitflags::bitflags! {
    /// A `queue`'s flags (`NFT_QUEUE_FLAG_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct QueueFlags: u16 {
        /// `bypass`: accept the packet when no program listens.
        const BYPASS = super::NFT_QUEUE_FLAG_BYPASS;
        /// `fanout`: pick the queue by CPU.
        const FANOUT = super::NFT_QUEUE_FLAG_CPU_FANOUT;
    }
}

/// `masquerade`. No options are modelled yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MasqExpr {}

impl MasqExpr {
    /// Plain `masquerade`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<MasqExpr> for Expr {
    fn from(e: MasqExpr) -> Self {
        Expr::Masquerade(e)
    }
}

/// `redirect`, optionally to a port. The port is loaded into `R0` by an
/// `Immediate` that [`Rule::redirect`](super::types::Rule::redirect) pushes
/// ahead of this expression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RedirExpr {
    /// Destination port, if any.
    pub port: Option<u16>,
}

impl RedirExpr {
    /// `redirect` to the original port.
    pub fn new() -> Self {
        Self::default()
    }

    /// Redirect to `port`.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

impl From<RedirExpr> for Expr {
    fn from(e: RedirExpr) -> Self {
        Expr::Redirect(e)
    }
}

/// Write a list of expressions into a rule's NFTA_RULE_EXPRESSIONS attribute.
pub fn write_expressions(builder: &mut MessageBuilder, exprs: &[Expr]) {
    write_expressions_as(builder, exprs, WireForm::Request);
}

/// Who the encoded expressions are for. They differ where the kernel
/// rejects in a request an attribute it then always echoes in a dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireForm {
    /// What is sent to the kernel.
    Request,
    /// What the kernel echoes back, for the declarative diff.
    Echo,
}

/// `exprs` as they must be sent in a `family` table: protocol guards as
/// the family needs them ([`guards_for_family`], #708), and rejects as it
/// takes them (#480).
pub(crate) fn exprs_for_family(exprs: &[Expr], family: Family) -> std::borrow::Cow<'_, [Expr]> {
    match guards_for_family(exprs, family) {
        std::borrow::Cow::Borrowed(exprs) => rejects_for_family(exprs, family),
        std::borrow::Cow::Owned(exprs) => {
            std::borrow::Cow::Owned(rejects_for_family(&exprs, family).into_owned())
        }
    }
}

/// The protocol guard a pair of expressions is: a `meta nfproto` or `meta
/// l4proto` load and an equality with one byte, the shape the builders
/// put in front of an address or a port.
pub(crate) fn guard_at(exprs: &[Expr], i: usize) -> Option<(Register, MetaKey, u8)> {
    match (exprs.get(i)?, exprs.get(i + 1)?) {
        (
            Expr::Meta { dreg, key: key @ (MetaKey::NfProto | MetaKey::L4Proto) },
            Expr::Cmp { sreg, op: CmpOp::Eq, data },
        ) if sreg == dreg && data.len() == 1 => Some((*dreg, *key, data[0])),
        _ => None,
    }
}

/// Whether a guard is always true in a `family` table: `meta nfproto
/// ipv4` in an ip table, `ipv6` in an ip6 one.
pub(crate) fn guard_implied(family: Family, key: MetaKey, value: u8) -> bool {
    key == MetaKey::NfProto
        && matches!((family, value), (Family::Ip, NFPROTO_IPV4) | (Family::Ip6, NFPROTO_IPV6))
}

/// `exprs` with their protocol guards as nft writes them in a `family`
/// table (#708). The builders put a guard in front of every field, in every
/// family; nft writes each once, and only where the family needs it:
///
/// - a guard already given earlier in the rule is dropped — `tcp dport 22`
///   then a `clamp mss` guarded `meta l4proto tcp` three times;
/// - `meta nfproto ipv4` is dropped in an ip table, `ipv6` in an ip6 one,
///   where it is always true (and nft 1.0.6 cannot list a hash or dynset
///   key behind it);
/// - in a bridge or netdev table `meta nfproto` is the family's own, so a
///   guard on it never matched: it is `meta protocol`, the ethertype, as
///   nft writes it.
pub(crate) fn guards_for_family(exprs: &[Expr], family: Family) -> std::borrow::Cow<'_, [Expr]> {
    let mut seen: Vec<(MetaKey, u8)> = Vec::new();
    let mut out: Option<Vec<Expr>> = None;
    let mut i = 0;
    while i < exprs.len() {
        if let Some((reg, key, value)) = guard_at(exprs, i) {
            let repeated = seen.contains(&(key, value));
            seen.push((key, value));
            let ethertype: Option<[u8; 2]> = match (family, key, value) {
                (Family::Bridge | Family::Netdev, MetaKey::NfProto, NFPROTO_IPV4) => Some([0x08, 0x00]),
                (Family::Bridge | Family::Netdev, MetaKey::NfProto, NFPROTO_IPV6) => Some([0x86, 0xdd]),
                _ => None,
            };
            if repeated || guard_implied(family, key, value) || ethertype.is_some() {
                let out = out.get_or_insert_with(|| exprs[..i].to_vec());
                if let (Some(ethertype), false) = (ethertype, repeated) {
                    out.push(Expr::Meta { dreg: reg, key: MetaKey::Protocol });
                    out.push(Expr::Cmp { sreg: reg, op: CmpOp::Eq, data: ethertype.to_vec() });
                }
                i += 2;
                continue;
            }
        }
        if let Some(out) = out.as_mut() {
            out.push(exprs[i].clone());
        }
        i += 1;
    }
    match out {
        Some(out) => std::borrow::Cow::Owned(out),
        None => std::borrow::Cow::Borrowed(exprs),
    }
}

/// `exprs` with their rejects as a `family` table takes them (#480).
///
/// `nft_reject_ipv4_eval` / `nft_reject_ipv6_eval` handle only
/// `NFT_REJECT_ICMP_UNREACH` and `NFT_REJECT_TCP_RST`; an ICMPX reject falls
/// to their `default:` and becomes a plain drop — a client waiting out its
/// timeout instead of "connection refused", the bug #205 set out to fix. In
/// `ip` and `ip6` an ICMPX reject is therefore sent as `ICMP_UNREACH` with
/// the code the kernel's own `nft_reject_icmp_code` /
/// `nft_reject_icmpv6_code` map it to, which is what the kernel echoes and
/// what `nft` writes. Every other expression, and every other family, is
/// passed through.
fn rejects_for_family(exprs: &[Expr], family: Family) -> std::borrow::Cow<'_, [Expr]> {
    // [no route, port, host, admin prohibited]
    const V4: [u8; 4] = [0, 3, 1, 13];
    const V6: [u8; 4] = [0, 4, 3, 1];
    let table = match family {
        Family::Ip => &V4,
        Family::Ip6 => &V6,
        _ => return std::borrow::Cow::Borrowed(exprs),
    };
    let icmpx = |e: &Expr| {
        matches!(e, Expr::Reject { reject_type, icmp_code }
            if *reject_type == NFT_REJECT_ICMPX_UNREACH && usize::from(*icmp_code) < table.len())
    };
    if !exprs.iter().any(icmpx) {
        return std::borrow::Cow::Borrowed(exprs);
    }
    std::borrow::Cow::Owned(
        exprs
            .iter()
            .map(|e| match e {
                Expr::Reject { icmp_code, .. } if icmpx(e) => Expr::Reject {
                    reject_type: NFT_REJECT_ICMP_UNREACH,
                    icmp_code: table[usize::from(*icmp_code)],
                },
                other => other.clone(),
            })
            .collect(),
    )
}

/// [`write_expressions`], in the given [`WireForm`].
pub(crate) fn write_expressions_as(builder: &mut MessageBuilder, exprs: &[Expr], form: WireForm) {
    let list = builder.nest_start(NFTA_RULE_EXPRESSIONS | 0x8000); // NLA_F_NESTED
    for expr in exprs {
        write_expr(builder, expr, form);
    }
    builder.nest_end(list);
}

/// Write a single expression as a nested NFTA_LIST_ELEM.
fn write_expr(builder: &mut MessageBuilder, expr: &Expr, form: WireForm) {
    let elem = builder.nest_start(NFTA_LIST_ELEM | 0x8000);
    write_expr_body(builder, expr, form);
    builder.nest_end(elem);
}

/// An expression's `NFTA_EXPR_NAME` and `NFTA_EXPR_DATA`, in the nest that
/// holds it: a list element, or a dynset's `NFTA_DYNSET_EXPR`.
fn write_expr_body(builder: &mut MessageBuilder, expr: &Expr, form: WireForm) {
    match expr {
        Expr::Meta { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_META_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::MetaSet { key, sreg } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.append_attr_u32_be(NFTA_META_SREG, sreg.wire());
            builder.nest_end(data);
        }
        Expr::Exthdr {
            dreg,
            op,
            exthdr_type,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "exthdr");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_EXTHDR_DREG, dreg.wire());
            write_exthdr_common(builder, *op, *exthdr_type, *offset, *len, true);
            builder.nest_end(data);
        }
        Expr::ExthdrSet {
            sreg,
            op,
            exthdr_type,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "exthdr");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_EXTHDR_SREG, sreg.wire());
            // The set form rejects NFTA_EXTHDR_FLAGS but dumps it (always 0).
            write_exthdr_common(
                builder,
                *op,
                *exthdr_type,
                *offset,
                *len,
                form == WireForm::Echo,
            );
            builder.nest_end(data);
        }
        Expr::Fib { dreg, result, flags } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "fib");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_FIB_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_FIB_RESULT, *result as u32);
            builder.append_attr_u32_be(NFTA_FIB_FLAGS, flags.bits());
            builder.nest_end(data);
        }
        // `nft_notrack_ops` has no `dump`, so the kernel echoes no data
        // nest: write none.
        Expr::Notrack => builder.append_attr_str(NFTA_EXPR_NAME, "notrack"),
        Expr::Range { sreg, op, from, to } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "range");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_RANGE_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_RANGE_OP, *op as u32);
            for (attr, value) in [(NFTA_RANGE_FROM_DATA, from), (NFTA_RANGE_TO_DATA, to)] {
                let nest = builder.nest_start(attr | 0x8000);
                builder.append_attr(NFTA_DATA_VALUE, value);
                builder.nest_end(nest);
            }
            builder.nest_end(expr_data);
        }
        Expr::Cmp { sreg, op, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "cmp");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CMP_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_CMP_OP, *op as u32);
            let cmp_data = builder.nest_start(NFTA_CMP_DATA | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, data);
            builder.nest_end(cmp_data);
            builder.nest_end(expr_data);
        }
        Expr::Payload {
            dreg,
            base,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "payload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_PAYLOAD_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_PAYLOAD_BASE, *base as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_OFFSET, *offset);
            builder.append_attr_u32_be(NFTA_PAYLOAD_LEN, *len);
            builder.nest_end(data);
        }
        Expr::PayloadSet {
            sreg,
            base,
            offset,
            len,
            csum,
            csum_offset,
            l4_pseudo_header,
        } => {
            // Every attribute `nft_payload_set_dump` echoes.
            builder.append_attr_str(NFTA_EXPR_NAME, "payload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_PAYLOAD_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_PAYLOAD_BASE, *base as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_OFFSET, *offset);
            builder.append_attr_u32_be(NFTA_PAYLOAD_LEN, *len);
            builder.append_attr_u32_be(NFTA_PAYLOAD_CSUM_TYPE, *csum as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_CSUM_OFFSET, *csum_offset);
            let flags = if *l4_pseudo_header {
                NFT_PAYLOAD_L4CSUM_PSEUDOHDR
            } else {
                0
            };
            builder.append_attr_u32_be(NFTA_PAYLOAD_CSUM_FLAGS, flags);
            builder.nest_end(data);
        }
        Expr::Immediate { dreg, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "immediate");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_IMMEDIATE_DREG, dreg.wire());
            let imm_data = builder.nest_start(NFTA_IMMEDIATE_DATA | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, data);
            builder.nest_end(imm_data);
            builder.nest_end(expr_data);
        }
        Expr::Verdict(verdict) => {
            write_verdict_expr(builder, verdict);
        }
        Expr::Counter => {
            builder.append_attr_str(NFTA_EXPR_NAME, "counter");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u64_be(NFTA_COUNTER_BYTES, 0);
            builder.append_attr_u64_be(NFTA_COUNTER_PACKETS, 0);
            builder.nest_end(data);
        }
        Expr::Limit(limit) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "limit");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            write_limit_attrs(builder, limit);
            builder.nest_end(data);
        }
        Expr::Quota(quota) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "quota");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            write_quota_attrs(builder, quota, form == WireForm::Echo);
            builder.nest_end(data);
        }
        Expr::Objref(objref) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "objref");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            match objref {
                ObjrefExpr::Named { object_type, name } => {
                    builder.append_attr_u32_be(NFTA_OBJREF_IMM_TYPE, *object_type as u32);
                    builder.append_attr_str(NFTA_OBJREF_IMM_NAME, name);
                }
                ObjrefExpr::Map { sreg, map } => {
                    builder.append_attr_u32_be(NFTA_OBJREF_SET_SREG, sreg.wire());
                    builder.append_attr_str(NFTA_OBJREF_SET_NAME, map);
                }
            }
            builder.nest_end(data);
        }
        Expr::Masquerade(MasqExpr {}) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "masq");
            // Basic masquerade has no attributes *inside* the data nest,
            // but the nest itself is not optional: `nft_expr_dump` opens
            // NFTA_EXPR_DATA for every expression whose ops have a
            // `dump` callback and closes it whatever the callback wrote,
            // so the kernel echoes an empty 4-byte nest here. Omitting
            // it made a declared masquerade rule render 4 bytes shorter
            // than the kernel's echo, which no amount of TLV
            // normalisation can reconcile — one side simply lacks an
            // attribute — so `NftablesDiff` reported the rule changed on
            // every diff, forever (#362).
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.nest_end(data);
        }
        Expr::NatRegs(nat) => write_nat_regs(builder, nat),
        Expr::Nat(nat) => {
            // NAT needs to load address/port into registers first via Immediate,
            // then reference those registers in the nat expression.
            // The caller should prepend Immediate expressions to load values.
            // Here we write the nat expression itself.
            builder.append_attr_str(NFTA_EXPR_NAME, "nat");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_NAT_TYPE, nat.nat_type as u32);
            debug_assert!(
                matches!(nat.family, Family::Ip | Family::Ip6),
                "NAT family must be Ip or Ip6, got {:?} (Inet is not valid for NAT expressions)",
                nat.family
            );
            builder.append_attr_u32_be(NFTA_NAT_FAMILY, nat.family as u32);
            // Emit MAX (= MIN for a single-value NAT) and the derived
            // flags explicitly: the kernel fills them in and echoes them
            // on dump, so omitting them breaks the round-trip diff.
            // nft_nat_dump skips NFTA_NAT_FLAGS when flags == 0, so we
            // mirror that to avoid a phantom diff in the no-addr-no-port
            // case (reachable via NatExpr::snat/dnat without setters).
            let mut flags = 0u32;
            if nat.addr.reg_in_use() {
                builder.append_attr_u32_be(NFTA_NAT_REG_ADDR_MIN, Register::R0 as u32);
                builder.append_attr_u32_be(NFTA_NAT_REG_ADDR_MAX, Register::R0 as u32);
                flags |= NF_NAT_RANGE_MAP_IPS;
            }
            if nat.port.is_some() {
                builder.append_attr_u32_be(NFTA_NAT_REG_PROTO_MIN, Register::R1 as u32);
                builder.append_attr_u32_be(NFTA_NAT_REG_PROTO_MAX, Register::R1 as u32);
                flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            }
            if flags != 0 {
                builder.append_attr_u32_be(NFTA_NAT_FLAGS, flags);
            }
            builder.nest_end(data);
        }
        Expr::Redirect(RedirExpr { port }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "redir");
            if port.is_some() {
                // The port value itself is loaded into R0 by an Immediate that
                // `Rule::redirect` pushes ahead of this expression — same shape
                // as the Nat arm above. All we do here is point at that
                // register.
                //
                // This used to emit NFTA_NAT_REG_PROTO_MIN (= 5), an attribute
                // from the *nat* namespace. `redir` has its own
                // (NFTA_REDIR_REG_PROTO_MIN = 1), and the kernel parses the
                // nest with maxtype = NFTA_REDIR_MAX, so 5 was above the bound
                // and silently skipped. The rule installed with no error and no
                // port rewrite: traffic was redirected to the local machine on
                // the *original* port, breaking the transparent-proxy use case
                // with no diagnostic (#206).
                let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.append_attr_u32_be(NFTA_REDIR_REG_PROTO_MIN, Register::R0 as u32);
                // MIN == MAX for a single port. The kernel echoes both on dump,
                // so omitting MAX would produce a phantom diff.
                builder.append_attr_u32_be(NFTA_REDIR_REG_PROTO_MAX, Register::R0 as u32);
                builder.append_attr_u32_be(NFTA_REDIR_FLAGS, NF_NAT_RANGE_PROTO_SPECIFIED);
                builder.nest_end(data);
            } else {
                // Portless redirect still gets the empty nest the kernel
                // echoes — same reason as the Masquerade arm above
                // (#362).
                let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.nest_end(data);
            }
        }
        Expr::Reject {
            reject_type,
            icmp_code,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "reject");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_REJECT_TYPE, *reject_type);
            // NFTA_REJECT_ICMP_CODE is a u8 on the wire. `nft_reject_init`
            // requires it for the two ICMP types and ignores it for a TCP
            // reset, and `nft_reject_dump` only emits it for the ICMP types
            // — so a TCP_RST that sent it (as this used to, on the belief
            // that the kernel wanted it) never matched its own echo, and a
            // declared `reject with tcp reset` was replaced on every apply.
            if *reject_type != NFT_REJECT_TCP_RST {
                builder.append_attr(NFTA_REJECT_ICMP_CODE, &[*icmp_code]);
            }
            builder.nest_end(data);
        }
        // What `nft_queue_dump`/`nft_queue_sreg_dump` echo: a range always
        // with its total and flags, a register with its flags.
        Expr::Queue(QueueExpr {
            num,
            total,
            sreg,
            flags,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "queue");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            match sreg {
                Some(sreg) => builder.append_attr_u32_be(NFTA_QUEUE_SREG_QNUM, sreg.wire()),
                None => {
                    builder.append_attr_u16_be(NFTA_QUEUE_NUM, *num);
                    builder.append_attr_u16_be(NFTA_QUEUE_TOTAL, (*total).max(1));
                }
            }
            builder.append_attr_u16_be(NFTA_QUEUE_FLAGS, flags.bits());
            builder.nest_end(data);
        }
        // What `nft_ng_dump` echoes: all four, always.
        Expr::Numgen {
            dreg,
            kind,
            modulus,
            offset,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "numgen");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_NG_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_NG_MODULUS, *modulus);
            builder.append_attr_u32_be(NFTA_NG_TYPE, *kind as u32);
            builder.append_attr_u32_be(NFTA_NG_OFFSET, *offset);
            builder.nest_end(data);
        }
        // What `nft_jhash_dump`/`nft_symhash_dump` echo: a seed only when
        // the request sent one (without, the kernel picks one and keeps it
        // to itself), an offset only when it is not 0.
        Expr::Hash {
            dreg,
            kind,
            sreg,
            len,
            modulus,
            seed,
            offset,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "hash");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if let Some(sreg) = sreg {
                builder.append_attr_u32_be(NFTA_HASH_SREG, sreg.wire());
            }
            builder.append_attr_u32_be(NFTA_HASH_DREG, dreg.wire());
            if *kind == HashKind::Jenkins {
                builder.append_attr_u32_be(NFTA_HASH_LEN, *len);
            }
            builder.append_attr_u32_be(NFTA_HASH_MODULUS, *modulus);
            if let Some(seed) = seed {
                builder.append_attr_u32_be(NFTA_HASH_SEED, *seed);
            }
            if *offset != 0 {
                builder.append_attr_u32_be(NFTA_HASH_OFFSET, *offset);
            }
            builder.append_attr_u32_be(NFTA_HASH_TYPE, *kind as u32);
            builder.nest_end(data);
        }
        // What `nft_tproxy_dump` echoes: the family, and each register set.
        Expr::Tproxy {
            family,
            sreg_addr,
            sreg_port,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "tproxy");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_TPROXY_FAMILY, u32::from(*family));
            if let Some(r) = sreg_addr {
                builder.append_attr_u32_be(NFTA_TPROXY_REG_ADDR, r.wire());
            }
            if let Some(r) = sreg_port {
                builder.append_attr_u32_be(NFTA_TPROXY_REG_PORT, r.wire());
            }
            builder.nest_end(data);
        }
        Expr::Socket { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "socket");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_SOCKET_KEY, *key as u32);
            builder.append_attr_u32_be(NFTA_SOCKET_DREG, dreg.wire());
            builder.nest_end(data);
        }
        // `nft_osf_dump` echoes all three; `nft_osf_init` refuses a FLAGS
        // that is not NFT_OSF_F_VERSION, 0 included.
        Expr::Osf { dreg, ttl, version } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "osf");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_OSF_DREG, dreg.wire());
            builder.append_attr(NFTA_OSF_TTL, &[*ttl as u8]);
            if *version || form == WireForm::Echo {
                let flags = if *version { NFT_OSF_F_VERSION } else { 0 };
                builder.append_attr_u32_be(NFTA_OSF_FLAGS, flags);
            }
            builder.nest_end(data);
        }
        // What `nft_synproxy_dump` echoes: all three, always.
        Expr::Synproxy(s) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "synproxy");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u16_be(NFTA_SYNPROXY_MSS, s.mss.unwrap_or(0));
            builder.append_attr(NFTA_SYNPROXY_WSCALE, &[s.wscale.unwrap_or(0)]);
            builder.append_attr_u32_be(NFTA_SYNPROXY_FLAGS, s.flags());
            builder.nest_end(data);
        }
        Expr::Dup { sreg_addr, sreg_dev } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "dup");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if let Some(r) = sreg_addr {
                builder.append_attr_u32_be(NFTA_DUP_SREG_ADDR, r.wire());
            }
            if let Some(r) = sreg_dev {
                builder.append_attr_u32_be(NFTA_DUP_SREG_DEV, r.wire());
            }
            builder.nest_end(data);
        }
        Expr::Fwd { sreg_dev, sreg_addr } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "fwd");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_FWD_SREG_DEV, sreg_dev.wire());
            if let Some((r, family)) = sreg_addr {
                builder.append_attr_u32_be(NFTA_FWD_SREG_ADDR, r.wire());
                builder.append_attr_u32_be(NFTA_FWD_NFPROTO, u32::from(*family));
            }
            builder.nest_end(data);
        }
        Expr::Log(LogExpr {
            prefix,
            group,
            level,
            flags,
            snaplen,
            queue_threshold,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "log");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if let Some(prefix) = prefix {
                builder.append_attr_str(NFTA_LOG_PREFIX, prefix);
            }
            // What the kernel takes for each kind of log, and what
            // `nft_log_dump` echoes: a group with its snaplen and threshold
            // when set; a syslog log with its level always (WARNING when the
            // request named none: send it, or the rule never matches its
            // echo) and its flags when there are any.
            match group {
                Some(group) => {
                    builder.append_attr_u16_be(NFTA_LOG_GROUP, *group);
                    if let Some(snaplen) = snaplen {
                        builder.append_attr_u32_be(NFTA_LOG_SNAPLEN, *snaplen);
                    }
                    if let Some(q) = queue_threshold.filter(|q| *q != 0) {
                        builder.append_attr_u16_be(NFTA_LOG_QTHRESHOLD, q);
                    }
                }
                None => {
                    let level = level.map_or(NFT_LOGLEVEL_WARNING, |l| l as u32);
                    builder.append_attr_u32_be(NFTA_LOG_LEVEL, level);
                    if !flags.is_empty() {
                        builder.append_attr_u32_be(NFTA_LOG_FLAGS, flags.bits());
                    }
                }
            };
            builder.nest_end(data);
        }
        Expr::Ct { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::CtDirectional { dreg, key, direction } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.append_attr(NFTA_CT_DIRECTION, &[*direction as u8]);
            builder.nest_end(data);
        }
        Expr::Connlimit { count, over } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "connlimit");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CONNLIMIT_COUNT, *count);
            // `nft_connlimit_do_dump` writes the flags only when inverted.
            if *over {
                builder.append_attr_u32_be(NFTA_CONNLIMIT_FLAGS, NFT_CONNLIMIT_F_INV);
            }
            builder.nest_end(data);
        }
        Expr::CtSet { key, sreg } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Rt { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "rt");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_RT_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_RT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Byteorder {
            sreg,
            dreg,
            op,
            len,
            size,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "byteorder");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_BYTEORDER_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_BYTEORDER_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_BYTEORDER_OP, *op as u32);
            builder.append_attr_u32_be(NFTA_BYTEORDER_LEN, *len);
            builder.append_attr_u32_be(NFTA_BYTEORDER_SIZE, *size);
            builder.nest_end(data);
        }
        Expr::Lookup(LookupExpr {
            set,
            sreg,
            dreg,
            invert,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "lookup");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_str(NFTA_LOOKUP_SET, set);
            builder.append_attr_u32_be(NFTA_LOOKUP_SREG, sreg.wire());
            if let Some(dreg) = dreg {
                builder.append_attr_u32_be(NFTA_LOOKUP_DREG, dreg.wire());
            }
            // `nft_lookup_dump` always emits FLAGS (NFT_LOOKUP_F_INV or 0).
            // Without it every declared rule matching `@set` was replaced on
            // every apply.
            let flags = if *invert { NFT_LOOKUP_F_INV } else { 0 };
            builder.append_attr_u32_be(NFTA_LOOKUP_FLAGS, flags);
            builder.nest_end(data);
        }
        Expr::Dynset(DynsetExpr {
            set,
            op,
            sreg_key,
            sreg_data,
            timeout,
            invert,
            statements,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "dynset");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_str(NFTA_DYNSET_SET_NAME, set);
            builder.append_attr_u32_be(NFTA_DYNSET_OP, *op as u32);
            builder.append_attr_u32_be(NFTA_DYNSET_SREG_KEY, sreg_key.wire());
            if let Some(sreg) = sreg_data {
                builder.append_attr_u32_be(NFTA_DYNSET_SREG_DATA, sreg.wire());
            }
            // `nft_dynset_dump` always emits TIMEOUT, 0 for none — but a
            // request carrying it is EOPNOTSUPP on a set without timeouts.
            match (timeout, form) {
                (Some(t), _) => builder.append_attr_u64_be(NFTA_DYNSET_TIMEOUT, millis(*t)),
                (None, WireForm::Echo) => builder.append_attr_u64_be(NFTA_DYNSET_TIMEOUT, 0),
                (None, WireForm::Request) => {}
            }
            let mut flags = if *invert { NFT_DYNSET_F_INV } else { 0 };
            // One statement in NFTA_DYNSET_EXPR, several in
            // NFTA_DYNSET_EXPRESSIONS, which the kernel takes only with
            // NFT_DYNSET_F_EXPR — and never dumps.
            write_statements(builder, statements, NFTA_DYNSET_EXPR, NFTA_DYNSET_EXPRESSIONS, form);
            if statements.len() > 1 && form == WireForm::Request {
                flags |= NFT_DYNSET_F_EXPR;
            }
            builder.append_attr_u32_be(NFTA_DYNSET_FLAGS, flags);
            builder.nest_end(data);
        }
        Expr::Bitwise {
            sreg,
            dreg,
            len,
            mask,
            xor,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "bitwise");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_BITWISE_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_BITWISE_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_BITWISE_LEN, *len);
            // Kernel defaults this to BOOL and echoes it on dump; emit
            // it so the round-trip diff stays byte-clean.
            builder.append_attr_u32_be(NFTA_BITWISE_OP, NFT_BITWISE_BOOL);
            let mask_nest = builder.nest_start(NFTA_BITWISE_MASK | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, mask);
            builder.nest_end(mask_nest);
            let xor_nest = builder.nest_start(NFTA_BITWISE_XOR | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, xor);
            builder.nest_end(xor_nest);
            builder.nest_end(data);
        }
        Expr::Raw(RawExpr { name, data, echo }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, name);
            let payload = match (form, echo) {
                (WireForm::Echo, Some(echo)) => Some(echo),
                _ => data.as_ref(),
            };
            if let Some(payload) = payload {
                let nest = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.append_bytes(payload);
                builder.nest_end(nest);
            }
        }
        Expr::FlowOffload { flowtable } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "flow_offload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            // The flow_offload expression carries a single string
            // attribute naming the flowtable, which the kernel resolves
            // within the rule's owning table. It is NFTA_FLOW_TABLE_NAME
            // (1), from the expression's own attribute enum. This used to
            // write NFTA_FLOWTABLE_NAME (2), the flowtable *object*'s name
            // attribute: above the expression's NFTA_FLOW_MAX, so ignored,
            // and the rule failed with EINVAL — every one of them.
            builder.append_attr_str(NFTA_FLOW_TABLE_NAME, flowtable);
            builder.nest_end(data);
        }
    }
}

/// The attributes of a packet `limit`, as an expression or a limit object.
pub(crate) fn write_limit_attrs(builder: &mut MessageBuilder, limit: &LimitExpr) {
    builder.append_attr_u64_be(NFTA_LIMIT_RATE, limit.rate);
    builder.append_attr_u64_be(NFTA_LIMIT_UNIT, limit.unit.to_u64());
    // A packet limit with burst 0 is stored (and dumped) as the
    // kernel's NFT_LIMIT_PKT_BURST_DEFAULT, 5; send what it keeps. A byte
    // limit keeps its 0.
    let burst = match limit.kind {
        LimitKind::Packets if limit.burst == 0 => 5,
        _ => limit.burst,
    };
    builder.append_attr_u32_be(NFTA_LIMIT_BURST, burst);
    builder.append_attr_u32_be(NFTA_LIMIT_TYPE, limit.kind as u32);
    // `nft_limit_dump` always emits FLAGS, 0 included. Without it a
    // declared `limit` rendered one attribute short of the echo and
    // was replaced on every apply.
    let flags = if limit.over { NFT_LIMIT_F_INV } else { 0 };
    builder.append_attr_u32_be(NFTA_LIMIT_FLAGS, flags);
}

/// A [`NatRegs`], in the order each kind's `dump` writes its attributes,
/// so the declared rule matches its echo. The kernel ORs the derived flags
/// in (an address range is `MAP_IPS`, a port range `PROTO_SPECIFIED`) and
/// dumps the result; they are sent already ORed.
fn write_nat_regs(builder: &mut MessageBuilder, nat: &NatRegs) {
    let mut flags = nat.flags;
    if nat.proto.is_some() {
        flags |= NatFlags::PROTO_SPECIFIED;
    }
    let range = |builder: &mut MessageBuilder, min, max, regs: Option<(Register, Register)>| {
        if let Some((lo, hi)) = regs {
            builder.append_attr_u32_be(min, lo.wire());
            builder.append_attr_u32_be(max, hi.wire());
        }
    };
    match nat.kind {
        NatKind::Snat | NatKind::Dnat => {
            if nat.addr.is_some() {
                flags |= NatFlags::MAP_IPS;
            }
            builder.append_attr_str(NFTA_EXPR_NAME, "nat");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            let nat_type = if nat.kind == NatKind::Snat { NatType::Snat } else { NatType::Dnat };
            builder.append_attr_u32_be(NFTA_NAT_TYPE, nat_type as u32);
            builder.append_attr_u32_be(NFTA_NAT_FAMILY, nat.family as u32);
            range(builder, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX, nat.addr);
            range(builder, NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX, nat.proto);
            if !flags.is_empty() {
                builder.append_attr_u32_be(NFTA_NAT_FLAGS, flags.bits());
            }
            builder.nest_end(data);
        }
        NatKind::Masquerade => {
            builder.append_attr_str(NFTA_EXPR_NAME, "masq");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if !flags.is_empty() {
                builder.append_attr_u32_be(NFTA_MASQ_FLAGS, flags.bits());
            }
            range(builder, NFTA_MASQ_REG_PROTO_MIN, NFTA_MASQ_REG_PROTO_MAX, nat.proto);
            builder.nest_end(data);
        }
        NatKind::Redirect => {
            builder.append_attr_str(NFTA_EXPR_NAME, "redir");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            range(builder, NFTA_REDIR_REG_PROTO_MIN, NFTA_REDIR_REG_PROTO_MAX, nat.proto);
            if !flags.is_empty() {
                builder.append_attr_u32_be(NFTA_REDIR_FLAGS, flags.bits());
            }
            builder.nest_end(data);
        }
    }
}

/// The attributes of a `quota`, as an expression or a quota object.
/// `nft_quota_do_dump` always emits CONSUMED — capped live state, which the
/// diff zeroes on both sides — so the echo form carries a zero one. A
/// request leaves it out: the kernel would start the quota there.
pub(crate) fn write_quota_attrs(builder: &mut MessageBuilder, quota: &QuotaExpr, echo: bool) {
    builder.append_attr_u64_be(NFTA_QUOTA_BYTES, quota.bytes);
    if echo {
        builder.append_attr_u64_be(NFTA_QUOTA_CONSUMED, 0);
    }
    let flags = if quota.over { NFT_QUOTA_F_INV } else { 0 };
    builder.append_attr_u32_be(NFTA_QUOTA_FLAGS, flags);
}

/// A duration in whole milliseconds, as nftables timeouts are written.
pub(crate) fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Attributes shared by the load and set forms of `exthdr`. `FLAGS` is
/// 0 (no `NFT_EXTHDR_F_PRESENT`); the kernel always dumps it, so it is
/// written whenever the kernel accepts it, to keep declared and dumped
/// bodies byte-equal.
fn write_exthdr_common(
    builder: &mut MessageBuilder,
    op: ExthdrOp,
    exthdr_type: u8,
    offset: u32,
    len: u32,
    with_flags: bool,
) {
    builder.append_attr_u8(NFTA_EXTHDR_TYPE, exthdr_type);
    builder.append_attr_u32_be(NFTA_EXTHDR_OFFSET, offset);
    builder.append_attr_u32_be(NFTA_EXTHDR_LEN, len);
    if with_flags {
        builder.append_attr_u32_be(NFTA_EXTHDR_FLAGS, 0);
    }
    builder.append_attr_u32_be(NFTA_EXTHDR_OP, op as u32);
}

fn write_verdict_expr(builder: &mut MessageBuilder, verdict: &Verdict) {
    builder.append_attr_str(NFTA_EXPR_NAME, "immediate");
    let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
    builder.append_attr_u32_be(NFTA_IMMEDIATE_DREG, Register::Verdict as u32);
    let imm_data = builder.nest_start(NFTA_IMMEDIATE_DATA | 0x8000);
    write_verdict_data(builder, verdict);
    builder.nest_end(imm_data);
    builder.nest_end(expr_data);
}

/// Write the `NFTA_DATA_VERDICT` nest of `verdict`: its code, and the chain
/// of a jump or goto. Shared by the verdict expression and verdict-map
/// elements.
pub(crate) fn write_verdict_data(builder: &mut MessageBuilder, verdict: &Verdict) {
    let verdict_nest = builder.nest_start(NFTA_DATA_VERDICT | 0x8000);

    let code = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
        Verdict::Continue => NFT_CONTINUE,
        Verdict::Return => NFT_RETURN,
        Verdict::JumpTo(_) => NFT_JUMP,
        Verdict::GotoTo(_) => NFT_GOTO,
    };
    builder.append_attr_u32_be(NFTA_VERDICT_CODE, code as u32);

    match verdict {
        Verdict::JumpTo(chain) | Verdict::GotoTo(chain) => {
            builder.append_attr_str(NFTA_VERDICT_CHAIN, chain.as_str());
        }
        _ => {}
    }

    builder.nest_end(verdict_nest);
}

// =========================================================================
// Expression decoding (#164) — read-side complement of `Expr`
// =========================================================================

use crate::netlink::attr::{AttrIter, get};

/// A rule expression decoded from a kernel dump.
///
/// The read-side complement of the write-side [`Expr`]: dumps carry
/// values the validated-input builder types can't represent (live
/// counter state, meta keys or registers outside the typed enums,
/// expression kinds nlink doesn't model). Every decoded element is
/// either a fully-typed variant or [`RuleExpr::Unknown`] with the raw
/// `NFTA_EXPR_DATA` payload preserved verbatim — nothing is dropped,
/// and partial decodes never guess.
///
/// Obtain via [`RuleInfo::expressions`]; the common per-rule counter
/// case has the [`RuleInfo::counter`] shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleExpr {
    /// `counter` — cumulative packet/byte counts as maintained by the
    /// kernel (live values in dumps, zeros right after rule creation).
    #[non_exhaustive]
    Counter {
        /// Packets matched.
        packets: u64,
        /// Bytes matched.
        bytes: u64,
    },
    /// `immediate` into the verdict register — the rule's verdict
    /// (accept / drop / continue / return / jump / goto).
    Verdict(Verdict),
    /// `meta` load into a data register.
    #[non_exhaustive]
    Meta {
        /// Destination register.
        dreg: Register,
        /// Metadata key being loaded.
        key: MetaKey,
    },
    /// `meta` set: write a register into packet metadata.
    #[non_exhaustive]
    MetaSet {
        /// Metadata key being written.
        key: MetaKey,
        /// Source register.
        sreg: Register,
    },
    /// `exthdr` load of an extension header / option field.
    #[non_exhaustive]
    Exthdr {
        /// Destination register.
        dreg: Register,
        /// Header family.
        op: ExthdrOp,
        /// Extension header type or option kind.
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// `exthdr` set: overwrite an extension header / option field.
    #[non_exhaustive]
    ExthdrSet {
        /// Source register.
        sreg: Register,
        /// Header family.
        op: ExthdrOp,
        /// Extension header type or option kind.
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes written.
        len: u32,
    },
    /// `cmp` of a register against a value.
    #[non_exhaustive]
    Cmp {
        /// Source register.
        sreg: Register,
        /// Comparison operator.
        op: CmpOp,
        /// Comparison operand (network byte order, as on the wire).
        data: Vec<u8>,
    },
    /// `immediate` value load into a data register.
    #[non_exhaustive]
    Immediate {
        /// Destination register.
        dreg: Register,
        /// Loaded value (as on the wire).
        data: Vec<u8>,
    },
    /// `payload` load into a data register.
    #[non_exhaustive]
    Payload {
        /// Destination register.
        dreg: Register,
        /// Which packet header the offset is relative to.
        base: PayloadBase,
        /// Byte offset within the base header.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// `payload` write from a register, with the checksums it updates
    /// (#703).
    #[non_exhaustive]
    PayloadSet {
        /// Source register.
        sreg: Register,
        /// Which packet header the offset is relative to.
        base: PayloadBase,
        /// Byte offset within the base header.
        offset: u32,
        /// Number of bytes written.
        len: u32,
        /// The checksum in the same header that is updated.
        csum: PayloadCsum,
        /// Where that checksum is, from the start of the header.
        csum_offset: u32,
        /// Whether the transport checksum's pseudo-header changes too.
        l4_pseudo_header: bool,
    },
    /// `ct` load into a data register (no direction).
    #[non_exhaustive]
    Ct {
        /// Destination register.
        dreg: Register,
        /// Conntrack key being loaded.
        key: CtKey,
    },
    /// `ct` set: write a register into the conntrack entry.
    #[non_exhaustive]
    CtSet {
        /// Conntrack key being written.
        key: CtKey,
        /// Source register.
        sreg: Register,
    },
    /// `rt` load of routing data.
    #[non_exhaustive]
    Rt {
        /// Destination register.
        dreg: Register,
        /// Routing key being loaded.
        key: RtKey,
    },
    /// `byteorder` conversion.
    #[non_exhaustive]
    Byteorder {
        /// Source register.
        sreg: Register,
        /// Destination register.
        dreg: Register,
        /// Conversion direction.
        op: ByteorderOp,
        /// Bytes converted.
        len: u32,
        /// Unit size in bytes (2, 4 or 8).
        size: u32,
    },
    /// `bitwise` mask-and-xor (`(reg & mask) ^ xor`). The shift and
    /// register-operand forms decode as [`Unknown`](Self::Unknown).
    #[non_exhaustive]
    Bitwise {
        /// Source register.
        sreg: Register,
        /// Destination register.
        dreg: Register,
        /// Bytes operated on.
        len: u32,
        /// AND mask (as on the wire).
        mask: Vec<u8>,
        /// XOR value (as on the wire).
        xor: Vec<u8>,
    },
    /// `lookup` of a register in a named set or map (`@set`,
    /// `!= @set`, `map @m`, `vmap @m`). Lookups with flags other than
    /// `NFT_LOOKUP_F_INV` decode as [`Unknown`](Self::Unknown).
    #[non_exhaustive]
    Lookup {
        /// Set name.
        set: String,
        /// Source register.
        sreg: Register,
        /// Destination register of a map lookup (`Register::Verdict` for a
        /// verdict map); `None` for a membership test.
        dreg: Option<Register>,
        /// `!= @set` (`NFT_LOOKUP_F_INV`).
        invert: bool,
    },
    /// `quota` — a rule's own byte quota, with its live consumption.
    #[non_exhaustive]
    Quota {
        /// The quota, in bytes.
        bytes: u64,
        /// Bytes used, capped at the quota.
        consumed: u64,
        /// `quota over`.
        over: bool,
        /// Used up (`NFT_QUOTA_F_DEPLETED`).
        depleted: bool,
    },
    /// `objref` — a named object, or an object map's pick. One naming an
    /// object type nlink does not model decodes as [`Unknown`](Self::Unknown).
    Objref(ObjrefExpr),
    /// `dynset` — `add|update|delete @set { <key> [timeout T]
    /// [statements] }`. A dynset with unknown flags, or a statement that
    /// does not decode, decodes as [`Unknown`](Self::Unknown).
    #[non_exhaustive]
    Dynset {
        /// Set name.
        set: String,
        /// Add, update or delete.
        op: DynsetOp,
        /// Register holding the key.
        sreg_key: Register,
        /// Register holding the value, for a map.
        sreg_data: Option<Register>,
        /// The element timeout; `None` for the set's default (dumped as 0).
        timeout: Option<std::time::Duration>,
        /// `NFT_DYNSET_F_INV`.
        invert: bool,
        /// Per-element statements (#703). Dumped only when the set
        /// declares none of its own.
        statements: Vec<RuleExpr>,
    },
    /// `ct` load of one direction's tuple.
    #[non_exhaustive]
    CtDirectional {
        /// Destination register.
        dreg: Register,
        /// The key.
        key: CtKey,
        /// Original or reply.
        direction: CtDirection,
    },
    /// `ct count [over] <count>`.
    #[non_exhaustive]
    Connlimit {
        /// The connection count.
        count: u32,
        /// `over`: match above it rather than up to it.
        over: bool,
    },
    /// `fib` — a routing lookup.
    #[non_exhaustive]
    Fib {
        /// Register the result goes to.
        dreg: Register,
        /// What it returns.
        result: FibResult,
        /// What it keys on.
        flags: FibFlags,
    },
    /// `notrack`.
    Notrack,
    /// `range` — a register within (or, `Neq`, outside) `from..=to`, both
    /// in network byte order.
    #[non_exhaustive]
    Range {
        /// Register compared.
        sreg: Register,
        /// In or out of the range.
        op: RangeOp,
        /// The first value.
        from: Vec<u8>,
        /// The last value.
        to: Vec<u8>,
    },
    /// `limit` — a packet- or byte-rate limit.
    Limit(LimitExpr),
    /// `log` — to syslog or to an `nflog` group, with its options.
    Log(LogExpr),
    /// `queue`.
    Queue(QueueExpr),
    /// `tproxy`.
    #[non_exhaustive]
    Tproxy {
        /// `NFPROTO_IPV4`, `NFPROTO_IPV6`, or 0.
        family: u8,
        /// The register with the address, if any.
        sreg_addr: Option<Register>,
        /// The register with the port, if any.
        sreg_port: Option<Register>,
    },
    /// `socket <key>` load.
    #[non_exhaustive]
    Socket {
        /// Destination register.
        dreg: Register,
        /// What is loaded.
        key: SocketKey,
    },
    /// `synproxy`.
    Synproxy(SynproxyExpr),
    /// `osf`.
    #[non_exhaustive]
    Osf {
        /// Destination register.
        dreg: Register,
        /// How the TTL is compared.
        ttl: OsfTtl,
        /// The name carries the version: `genre:version`.
        version: bool,
    },
    /// `numgen`.
    #[non_exhaustive]
    Numgen {
        /// Destination register.
        dreg: Register,
        /// Counting up, or at random.
        kind: NumgenKind,
        /// Modulo this.
        modulus: u32,
        /// Plus this.
        offset: u32,
    },
    /// `jhash` or `symhash`.
    #[non_exhaustive]
    Hash {
        /// Destination register.
        dreg: Register,
        /// Jenkins or symmetric.
        kind: HashKind,
        /// Jenkins: the register the hashed bytes start at.
        sreg: Option<Register>,
        /// Jenkins: how many bytes.
        len: u32,
        /// Modulo this.
        modulus: u32,
        /// Jenkins: the seed, when one was given.
        seed: Option<u32>,
        /// Plus this.
        offset: u32,
    },
    /// `dup`: the registers with its gateway and its output device.
    #[non_exhaustive]
    Dup {
        /// The register with the gateway address.
        sreg_addr: Option<Register>,
        /// The register with the output ifindex.
        sreg_dev: Option<Register>,
    },
    /// `fwd`: the register with the output device, and the one with the
    /// next hop and its family.
    #[non_exhaustive]
    Fwd {
        /// The register with the output ifindex.
        sreg_dev: Register,
        /// The register with the next hop, and its `NFPROTO_*` family.
        sreg_addr: Option<(Register, u8)>,
    },
    /// `reject`.
    #[non_exhaustive]
    Reject {
        /// [`NFT_REJECT_ICMP_UNREACH`], [`NFT_REJECT_TCP_RST`] or
        /// [`NFT_REJECT_ICMPX_UNREACH`].
        reject_type: u32,
        /// The ICMP code; `None` for a TCP reset.
        icmp_code: Option<u8>,
    },
    /// `masquerade`, to the port range in `proto`'s registers if any.
    #[non_exhaustive]
    Masq {
        /// The registers holding the first and last port.
        proto: Option<(Register, Register)>,
        /// `random`, `fully-random`, `persistent`, ….
        flags: NatFlags,
    },
    /// `snat`/`dnat`. The address and port values are in the
    /// [`Immediate`](Self::Immediate) loads ahead of it; this says which
    /// registers hold them.
    #[non_exhaustive]
    Nat {
        /// Source or destination NAT.
        nat_type: NatType,
        /// The address family it rewrites: `ip` or `ip6`.
        family: Family,
        /// The registers holding the first and last address.
        addr: Option<(Register, Register)>,
        /// The registers holding the first and last port.
        proto: Option<(Register, Register)>,
        /// The range flags.
        flags: NatFlags,
    },
    /// `redirect`, to the port range in `proto`'s registers if any.
    #[non_exhaustive]
    Redir {
        /// The registers holding the first and last port.
        proto: Option<(Register, Register)>,
        /// The range flags.
        flags: NatFlags,
    },
    /// `flow add @<flowtable>`.
    #[non_exhaustive]
    FlowOffload {
        /// The flowtable's name, in the rule's table.
        flowtable: String,
    },
    /// Expression not (or not fully) decodable: kind name plus the raw
    /// `NFTA_EXPR_DATA` payload, preserved verbatim.
    #[non_exhaustive]
    Unknown {
        /// `NFTA_EXPR_NAME` (e.g. `"quota"`, `"limit"`, `"nat"`).
        name: String,
        /// Raw `NFTA_EXPR_DATA` payload.
        data: Vec<u8>,
    },
}

impl RuleExpr {
    /// The expression as nlink would send it again (#708): the typed lift's
    /// fallback for what it has no item for. Live state is dropped (a
    /// counter's packets, a quota's consumption), as the diff's canonical
    /// form drops it; an expression nlink does not decode goes back as the
    /// raw attributes it came as.
    pub(crate) fn to_expr(&self) -> Expr {
        let nat = |kind, family, addr, proto, flags| {
            Expr::NatRegs(NatRegs {
                kind,
                family,
                addr,
                proto,
                flags,
            })
        };
        match self.clone() {
            Self::Counter { .. } => Expr::Counter,
            Self::Verdict(v) => Expr::Verdict(v),
            Self::Meta { dreg, key } => Expr::Meta { dreg, key },
            Self::MetaSet { key, sreg } => Expr::MetaSet { key, sreg },
            Self::Exthdr {
                dreg,
                op,
                exthdr_type,
                offset,
                len,
            } => Expr::Exthdr {
                dreg,
                op,
                exthdr_type,
                offset,
                len,
            },
            Self::ExthdrSet {
                sreg,
                op,
                exthdr_type,
                offset,
                len,
            } => Expr::ExthdrSet {
                sreg,
                op,
                exthdr_type,
                offset,
                len,
            },
            Self::Cmp { sreg, op, data } => Expr::Cmp { sreg, op, data },
            Self::Immediate { dreg, data } => Expr::Immediate { dreg, data },
            Self::Payload {
                dreg,
                base,
                offset,
                len,
            } => Expr::Payload {
                dreg,
                base,
                offset,
                len,
            },
            Self::PayloadSet {
                sreg,
                base,
                offset,
                len,
                csum,
                csum_offset,
                l4_pseudo_header,
            } => Expr::PayloadSet {
                sreg,
                base,
                offset,
                len,
                csum,
                csum_offset,
                l4_pseudo_header,
            },
            Self::Ct { dreg, key } => Expr::Ct { dreg, key },
            Self::CtSet { key, sreg } => Expr::CtSet { key, sreg },
            Self::Rt { dreg, key } => Expr::Rt { dreg, key },
            Self::Byteorder {
                sreg,
                dreg,
                op,
                len,
                size,
            } => Expr::Byteorder {
                sreg,
                dreg,
                op,
                len,
                size,
            },
            Self::Bitwise {
                sreg,
                dreg,
                len,
                mask,
                xor,
            } => Expr::Bitwise {
                sreg,
                dreg,
                len,
                mask,
                xor,
            },
            Self::Lookup {
                set,
                sreg,
                dreg,
                invert,
            } => Expr::Lookup(LookupExpr {
                set,
                sreg,
                dreg,
                invert,
            }),
            Self::Quota { bytes, over, .. } => Expr::Quota(QuotaExpr { bytes, over }),
            Self::Objref(o) => Expr::Objref(o),
            Self::Dynset {
                set,
                op,
                sreg_key,
                sreg_data,
                timeout,
                invert,
                statements,
            } => {
                let decoded: Option<Vec<ElementStatement>> = statements
                    .iter()
                    .map(ElementStatement::from_rule_expr)
                    .collect();
                // `parse_dynset` keeps a dynset whose statements do not all
                // decode as `Unknown`, so this is always `Some`.
                match decoded {
                    Some(statements) => Expr::Dynset(DynsetExpr {
                        set,
                        op,
                        sreg_key,
                        sreg_data,
                        timeout,
                        invert,
                        statements,
                    }),
                    None => Expr::Raw(RawExpr::without_data("dynset")),
                }
            }
            Self::CtDirectional {
                dreg,
                key,
                direction,
            } => Expr::CtDirectional {
                dreg,
                key,
                direction,
            },
            Self::Connlimit { count, over } => Expr::Connlimit { count, over },
            Self::Fib {
                dreg,
                result,
                flags,
            } => Expr::Fib {
                dreg,
                result,
                flags,
            },
            Self::Notrack => Expr::Notrack,
            Self::Range { sreg, op, from, to } => Expr::Range { sreg, op, from, to },
            Self::Limit(l) => Expr::Limit(l),
            Self::Log(l) => Expr::Log(l),
            Self::Queue(q) => Expr::Queue(q),
            Self::Tproxy {
                family,
                sreg_addr,
                sreg_port,
            } => Expr::Tproxy {
                family,
                sreg_addr,
                sreg_port,
            },
            Self::Socket { dreg, key } => Expr::Socket { dreg, key },
            Self::Synproxy(s) => Expr::Synproxy(s),
            Self::Osf { dreg, ttl, version } => Expr::Osf { dreg, ttl, version },
            Self::Numgen {
                dreg,
                kind,
                modulus,
                offset,
            } => Expr::Numgen {
                dreg,
                kind,
                modulus,
                offset,
            },
            Self::Hash {
                dreg,
                kind,
                sreg,
                len,
                modulus,
                seed,
                offset,
            } => Expr::Hash {
                dreg,
                kind,
                sreg,
                len,
                modulus,
                seed,
                offset,
            },
            Self::Dup {
                sreg_addr,
                sreg_dev,
            } => Expr::Dup {
                sreg_addr,
                sreg_dev,
            },
            Self::Fwd {
                sreg_dev,
                sreg_addr,
            } => Expr::Fwd {
                sreg_dev,
                sreg_addr,
            },
            Self::Reject {
                reject_type,
                icmp_code,
            } => Expr::Reject {
                reject_type,
                icmp_code: icmp_code.unwrap_or(0),
            },
            // The family is a snat's or a dnat's; a masquerade and a
            // redirect take the table's.
            Self::Masq { proto, flags } => {
                nat(NatKind::Masquerade, Family::Inet, None, proto, flags)
            }
            Self::Nat {
                nat_type,
                family,
                addr,
                proto,
                flags,
            } => {
                let kind = match nat_type {
                    NatType::Snat => NatKind::Snat,
                    NatType::Dnat => NatKind::Dnat,
                };
                nat(kind, family, addr, proto, flags)
            }
            Self::Redir { proto, flags } => {
                nat(NatKind::Redirect, Family::Inet, None, proto, flags)
            }
            Self::FlowOffload { flowtable } => Expr::FlowOffload { flowtable },
            Self::Unknown { name, data } if data.is_empty() => {
                Expr::Raw(RawExpr::without_data(name))
            }
            Self::Unknown { name, data } => Expr::Raw(RawExpr::new(name, data)),
        }
    }
}

/// Decode the inner payload of `NFTA_RULE_EXPRESSIONS` (a list of
/// `NFTA_LIST_ELEM`) into typed expressions.
///
/// Infallible by design: elements whose kind or contents exceed the
/// typed variants come back as [`RuleExpr::Unknown`]; structurally
/// malformed elements (no `NFTA_EXPR_NAME`) are skipped. One odd
/// expression from a future kernel must not fail a rule dump.
pub fn parse_expressions(bytes: &[u8]) -> Vec<RuleExpr> {
    AttrIter::new(bytes)
        .filter(|(kind, _)| *kind == NFTA_LIST_ELEM)
        .filter_map(|(_, elem)| parse_elem(elem))
        .collect()
}

/// One expression from its `NFTA_EXPR_NAME` and `NFTA_EXPR_DATA`; `None`
/// for a nameless one, which the kernel never emits.
pub(crate) fn parse_elem(elem: &[u8]) -> Option<RuleExpr> {
    let mut name: Option<&str> = None;
    let mut data: &[u8] = &[];
    for (attr, payload) in AttrIter::new(elem) {
        match attr {
            NFTA_EXPR_NAME => name = get::string(payload).ok(),
            NFTA_EXPR_DATA => data = payload,
            _ => {}
        }
    }
    Some(parse_expr(name?, data))
}

/// Decode one expression; anything undecodable demotes to `Unknown`.
fn parse_expr(name: &str, data: &[u8]) -> RuleExpr {
    let decoded = match name {
        "counter" => parse_counter(data),
        "immediate" => parse_immediate(data),
        "meta" => parse_meta(data),
        "cmp" => parse_cmp(data),
        "payload" => parse_payload(data),
        "exthdr" => parse_exthdr(data),
        "ct" => parse_ct(data),
        "rt" => parse_rt(data),
        "byteorder" => parse_byteorder(data),
        "bitwise" => parse_bitwise(data),
        "lookup" => parse_lookup(data),
        "dynset" => parse_dynset(data),
        "quota" => parse_quota(data),
        "objref" => parse_objref(data),
        "limit" => parse_limit_attrs(data).map(RuleExpr::Limit),
        "range" => parse_range(data),
        "fib" => parse_fib(data),
        "connlimit" => u32_attr(data, NFTA_CONNLIMIT_COUNT).map(|count| RuleExpr::Connlimit {
            count,
            over: u32_attr(data, NFTA_CONNLIMIT_FLAGS).unwrap_or(0) & NFT_CONNLIMIT_F_INV != 0,
        }),
        "notrack" if data.is_empty() => Some(RuleExpr::Notrack),
        "log" => parse_log(data),
        "queue" => parse_queue(data),
        "tproxy" => u32_attr(data, NFTA_TPROXY_FAMILY)
            .and_then(|f| u8::try_from(f).ok())
            .map(|family| RuleExpr::Tproxy {
                family,
                sreg_addr: reg_attr(data, NFTA_TPROXY_REG_ADDR),
                sreg_port: reg_attr(data, NFTA_TPROXY_REG_PORT),
            }),
        "socket" => parse_socket(data),
        "synproxy" => parse_synproxy(data),
        "osf" => parse_osf(data),
        "numgen" => parse_numgen(data),
        "hash" => parse_hash(data),
        "dup" => Some(RuleExpr::Dup {
            sreg_addr: reg_attr(data, NFTA_DUP_SREG_ADDR),
            sreg_dev: reg_attr(data, NFTA_DUP_SREG_DEV),
        }),
        "fwd" => parse_fwd(data),
        "reject" => parse_reject(data),
        "masq" => parse_masq(data),
        "nat" => parse_nat(data),
        "redir" => parse_redir(data),
        "flow_offload" => parse_flow_offload(data),
        _ => None,
    };
    decoded.unwrap_or_else(|| RuleExpr::Unknown {
        name: name.to_string(),
        data: data.to_vec(),
    })
}

bitflags::bitflags! {
    /// The `NF_NAT_RANGE_*` flags of a `snat`, `dnat`, `masquerade` or
    /// `redirect` (`linux/netfilter/nf_nat.h`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct NatFlags: u32 {
        /// The address is rewritten.
        const MAP_IPS = 1 << 0;
        /// The port is rewritten.
        const PROTO_SPECIFIED = 1 << 1;
        /// `random`: the port is picked at random.
        const PROTO_RANDOM = 1 << 2;
        /// `persistent`: a client keeps its address.
        const PERSISTENT = 1 << 3;
        /// `fully-random`: the port is picked fully at random.
        const PROTO_RANDOM_FULLY = 1 << 4;
        /// The port range is an offset.
        const PROTO_OFFSET = 1 << 5;
        /// `netmap`: the address is mapped prefix to prefix.
        const NETMAP = 1 << 6;
        // A newer kernel's flags read back as they are.
        const _ = !0;
    }
}

/// The value of attribute `id` among `data`'s, as a big-endian u32.
/// A register attribute.
fn reg_attr(data: &[u8], id: u16) -> Option<Register> {
    Register::from_u32(u32_attr(data, id)?)
}

/// A `socket` load; a `cgroupv2` one stays Unknown (its level and the
/// cgroup id it compares are not modelled).
fn parse_socket(data: &[u8]) -> Option<RuleExpr> {
    let key = match u32_attr(data, NFTA_SOCKET_KEY)? {
        0 => SocketKey::Transparent,
        1 => SocketKey::Mark,
        2 => SocketKey::Wildcard,
        _ => return None,
    };
    Some(RuleExpr::Socket {
        dreg: reg_attr(data, NFTA_SOCKET_DREG)?,
        key,
    })
}

/// An `osf`.
fn parse_osf(data: &[u8]) -> Option<RuleExpr> {
    let attr = |id| AttrIter::new(data).find(|(t, _)| t & 0x7FFF == id).map(|(_, p)| p);
    let ttl = match attr(NFTA_OSF_TTL).map_or(Some(0), |p| p.first().copied())? {
        0 => OsfTtl::Exact,
        1 => OsfTtl::Loose,
        2 => OsfTtl::Skip,
        _ => return None,
    };
    let version = match u32_attr(data, NFTA_OSF_FLAGS).unwrap_or(0) {
        0 => false,
        NFT_OSF_F_VERSION => true,
        _ => return None,
    };
    Some(RuleExpr::Osf {
        dreg: reg_attr(data, NFTA_OSF_DREG)?,
        ttl,
        version,
    })
}

/// A `synproxy`: its announced options, by its flags.
fn parse_synproxy(data: &[u8]) -> Option<RuleExpr> {
    let flags = u32_attr(data, NFTA_SYNPROXY_FLAGS).unwrap_or(0);
    let known = NF_SYNPROXY_OPT_MSS
        | NF_SYNPROXY_OPT_WSCALE
        | NF_SYNPROXY_OPT_SACK_PERM
        | NF_SYNPROXY_OPT_TIMESTAMP;
    if flags & !known != 0 {
        return None;
    }
    let attr = |id| AttrIter::new(data).find(|(t, _)| t & 0x7FFF == id).map(|(_, p)| p);
    let mss = attr(NFTA_SYNPROXY_MSS).and_then(|p| get::u16_be(p).ok());
    let wscale = attr(NFTA_SYNPROXY_WSCALE).and_then(|p| p.first().copied());
    Some(RuleExpr::Synproxy(SynproxyExpr {
        mss: (flags & NF_SYNPROXY_OPT_MSS != 0).then_some(mss?),
        wscale: (flags & NF_SYNPROXY_OPT_WSCALE != 0).then_some(wscale?),
        timestamp: flags & NF_SYNPROXY_OPT_TIMESTAMP != 0,
        sack_perm: flags & NF_SYNPROXY_OPT_SACK_PERM != 0,
    }))
}

/// A `numgen`.
fn parse_numgen(data: &[u8]) -> Option<RuleExpr> {
    Some(RuleExpr::Numgen {
        dreg: reg_attr(data, NFTA_NG_DREG)?,
        kind: match u32_attr(data, NFTA_NG_TYPE)? {
            0 => NumgenKind::Incremental,
            1 => NumgenKind::Random,
            _ => return None,
        },
        modulus: u32_attr(data, NFTA_NG_MODULUS)?,
        offset: u32_attr(data, NFTA_NG_OFFSET).unwrap_or(0),
    })
}

/// A `hash`.
fn parse_hash(data: &[u8]) -> Option<RuleExpr> {
    let kind = match u32_attr(data, NFTA_HASH_TYPE).unwrap_or(0) {
        0 => HashKind::Jenkins,
        1 => HashKind::Sym,
        _ => return None,
    };
    Some(RuleExpr::Hash {
        dreg: reg_attr(data, NFTA_HASH_DREG)?,
        kind,
        sreg: reg_attr(data, NFTA_HASH_SREG),
        len: u32_attr(data, NFTA_HASH_LEN).unwrap_or(0),
        modulus: u32_attr(data, NFTA_HASH_MODULUS)?,
        seed: u32_attr(data, NFTA_HASH_SEED),
        offset: u32_attr(data, NFTA_HASH_OFFSET).unwrap_or(0),
    })
}

/// A `fwd`: its device register, and its next hop's with the family.
fn parse_fwd(data: &[u8]) -> Option<RuleExpr> {
    let sreg_addr = match (reg_attr(data, NFTA_FWD_SREG_ADDR), u32_attr(data, NFTA_FWD_NFPROTO)) {
        (Some(r), Some(p)) => Some((r, u8::try_from(p).ok()?)),
        (None, None) => None,
        _ => return None,
    };
    Some(RuleExpr::Fwd {
        sreg_dev: reg_attr(data, NFTA_FWD_SREG_DEV)?,
        sreg_addr,
    })
}

/// A `queue`: its range, or its register; its flags.
fn parse_queue(data: &[u8]) -> Option<RuleExpr> {
    let u16_attr = |id| {
        AttrIter::new(data)
            .find(|(attr, _)| attr & 0x7FFF == id)
            .and_then(|(_, p)| get::u16_be(p).ok())
    };
    let flags = QueueFlags::from_bits(u16_attr(NFTA_QUEUE_FLAGS).unwrap_or(0))?;
    let mut q = match reg_attr(data, NFTA_QUEUE_SREG_QNUM) {
        Some(sreg) => QueueExpr::register(sreg),
        None => QueueExpr {
            num: u16_attr(NFTA_QUEUE_NUM)?,
            total: u16_attr(NFTA_QUEUE_TOTAL).unwrap_or(1),
            ..QueueExpr::num(0)
        },
    };
    q.flags = flags;
    Some(RuleExpr::Queue(q))
}

fn u32_attr(data: &[u8], id: u16) -> Option<u32> {
    AttrIter::new(data)
        .find(|(attr, _)| attr & 0x7FFF == id)
        .and_then(|(_, payload)| get::u32_be(payload).ok())
}

/// A register pair: the attributes `min` and `max` among `data`'s. Just
/// `min` is a range of one value.
fn register_range(data: &[u8], min: u16, max: u16) -> Option<Option<(Register, Register)>> {
    let Some(lo) = u32_attr(data, min) else {
        return Some(None);
    };
    let lo = Register::from_u32(lo)?;
    let hi = match u32_attr(data, max) {
        Some(hi) => Register::from_u32(hi)?,
        None => lo,
    };
    Some(Some((lo, hi)))
}

/// A `limit`'s attributes — an expression's or a limit object's. `None`
/// for a type or a unit nlink has no name for.
pub(crate) fn parse_limit_attrs(data: &[u8]) -> Option<LimitExpr> {
    let u64_of = |id| {
        AttrIter::new(data)
            .find(|(attr, _)| attr & 0x7FFF == id)
            .and_then(|(_, payload)| get::u64_be(payload).ok())
    };
    let unit = match u64_of(NFTA_LIMIT_UNIT)? {
        1 => LimitUnit::Second,
        60 => LimitUnit::Minute,
        3600 => LimitUnit::Hour,
        86400 => LimitUnit::Day,
        _ => return None,
    };
    let rate = u64_of(NFTA_LIMIT_RATE)?;
    let limit = match LimitKind::from_u32(u32_attr(data, NFTA_LIMIT_TYPE).unwrap_or(0))? {
        LimitKind::Packets => LimitExpr::packets(rate, unit),
        LimitKind::Bytes => LimitExpr::bytes(crate::Bytes::new(rate), unit),
    };
    let mut limit = limit.burst(u32_attr(data, NFTA_LIMIT_BURST).unwrap_or(0));
    if u32_attr(data, NFTA_LIMIT_FLAGS).unwrap_or(0) & NFT_LIMIT_F_INV != 0 {
        limit = limit.over();
    }
    Some(limit)
}

fn parse_fib(data: &[u8]) -> Option<RuleExpr> {
    Some(RuleExpr::Fib {
        dreg: Register::from_u32(u32_attr(data, NFTA_FIB_DREG)?)?,
        result: FibResult::from_u32(u32_attr(data, NFTA_FIB_RESULT)?)?,
        flags: FibFlags::from_bits_retain(u32_attr(data, NFTA_FIB_FLAGS)?),
    })
}

fn parse_range(data: &[u8]) -> Option<RuleExpr> {
    let value = |nest: &[u8]| {
        AttrIter::new(nest)
            .find(|(attr, _)| attr & 0x7FFF == NFTA_DATA_VALUE)
            .map(|(_, v)| v.to_vec())
    };
    let mut from = None;
    let mut to = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr & 0x7FFF {
            NFTA_RANGE_FROM_DATA => from = value(payload),
            NFTA_RANGE_TO_DATA => to = value(payload),
            _ => {}
        }
    }
    Some(RuleExpr::Range {
        sreg: Register::from_u32(u32_attr(data, NFTA_RANGE_SREG)?)?,
        op: RangeOp::from_u32(u32_attr(data, NFTA_RANGE_OP)?)?,
        from: from?,
        to: to?,
    })
}

fn parse_log(data: &[u8]) -> Option<RuleExpr> {
    let mut log = LogExpr::new();
    for (attr, payload) in AttrIter::new(data) {
        match attr & 0x7FFF {
            NFTA_LOG_PREFIX => log.prefix = Some(get::string(payload).ok()?.to_string()),
            NFTA_LOG_GROUP => log.group = Some(get::u16_be(payload).ok()?),
            // The kernel's default, which every syslog log echoes.
            NFTA_LOG_LEVEL if get::u32_be(payload).ok()? == NFT_LOGLEVEL_WARNING => {}
            NFTA_LOG_LEVEL => log.level = Some(LogLevel::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_LOG_FLAGS => log.flags = LogFlags::from_bits(get::u32_be(payload).ok()?)?,
            NFTA_LOG_SNAPLEN => log.snaplen = Some(get::u32_be(payload).ok()?),
            NFTA_LOG_QTHRESHOLD => log.queue_threshold = Some(get::u16_be(payload).ok()?),
            // An attribute LogExpr cannot carry.
            _ => return None,
        }
    }
    Some(RuleExpr::Log(log))
}

fn parse_reject(data: &[u8]) -> Option<RuleExpr> {
    let mut reject_type = None;
    let mut icmp_code = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr & 0x7FFF {
            NFTA_REJECT_TYPE => reject_type = Some(get::u32_be(payload).ok()?),
            NFTA_REJECT_ICMP_CODE => icmp_code = Some(*payload.first()?),
            _ => {}
        }
    }
    Some(RuleExpr::Reject {
        reject_type: reject_type?,
        icmp_code,
    })
}

fn parse_masq(data: &[u8]) -> Option<RuleExpr> {
    Some(RuleExpr::Masq {
        proto: register_range(data, NFTA_MASQ_REG_PROTO_MIN, NFTA_MASQ_REG_PROTO_MAX)?,
        flags: NatFlags::from_bits_retain(u32_attr(data, NFTA_MASQ_FLAGS).unwrap_or(0)),
    })
}

fn parse_nat(data: &[u8]) -> Option<RuleExpr> {
    let nat_type = match u32_attr(data, NFTA_NAT_TYPE)? {
        0 => NatType::Snat,
        1 => NatType::Dnat,
        _ => return None,
    };
    let family = Family::from_u8(u8::try_from(u32_attr(data, NFTA_NAT_FAMILY)?).ok()?)?;
    Some(RuleExpr::Nat {
        nat_type,
        family,
        addr: register_range(data, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX)?,
        proto: register_range(data, NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX)?,
        flags: NatFlags::from_bits_retain(u32_attr(data, NFTA_NAT_FLAGS).unwrap_or(0)),
    })
}

fn parse_redir(data: &[u8]) -> Option<RuleExpr> {
    Some(RuleExpr::Redir {
        proto: register_range(data, NFTA_REDIR_REG_PROTO_MIN, NFTA_REDIR_REG_PROTO_MAX)?,
        flags: NatFlags::from_bits_retain(u32_attr(data, NFTA_REDIR_FLAGS).unwrap_or(0)),
    })
}

fn parse_flow_offload(data: &[u8]) -> Option<RuleExpr> {
    let (_, name) = AttrIter::new(data).find(|(attr, _)| attr & 0x7FFF == NFTA_FLOW_TABLE_NAME)?;
    Some(RuleExpr::FlowOffload {
        flowtable: get::string(name).ok()?.to_string(),
    })
}

fn parse_counter(data: &[u8]) -> Option<RuleExpr> {
    let mut packets = None;
    let mut bytes = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_COUNTER_PACKETS => packets = Some(get::u64_be(payload).ok()?),
            NFTA_COUNTER_BYTES => bytes = Some(get::u64_be(payload).ok()?),
            _ => {}
        }
    }
    // The kernel always emits both; default missing ones to 0 rather
    // than rejecting (accept-larger/lenient read policy).
    if packets.is_none() && bytes.is_none() {
        return None;
    }
    Some(RuleExpr::Counter {
        packets: packets.unwrap_or(0),
        bytes: bytes.unwrap_or(0),
    })
}

fn parse_immediate(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut imm_nest: &[u8] = &[];
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_IMMEDIATE_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_IMMEDIATE_DATA => imm_nest = payload,
            _ => {}
        }
    }
    let dreg = dreg?;
    for (attr, payload) in AttrIter::new(imm_nest) {
        match attr {
            NFTA_DATA_VALUE if dreg != Register::Verdict => {
                return Some(RuleExpr::Immediate {
                    dreg,
                    data: payload.to_vec(),
                });
            }
            NFTA_DATA_VERDICT if dreg == Register::Verdict => {
                return parse_verdict(payload).map(RuleExpr::Verdict);
            }
            _ => {}
        }
    }
    None
}

/// Decode an `NFTA_DATA_VERDICT` nest. `None` for codes outside the
/// typed [`Verdict`] (`NFT_BREAK`, queue verdicts) or a jump/goto
/// whose chain name fails validation.
pub(crate) fn parse_verdict(nest: &[u8]) -> Option<Verdict> {
    let mut code = None;
    let mut chain = None;
    for (attr, payload) in AttrIter::new(nest) {
        match attr {
            NFTA_VERDICT_CODE => code = Some(get::u32_be(payload).ok()? as i32),
            NFTA_VERDICT_CHAIN => chain = get::string(payload).ok().map(str::to_string),
            _ => {}
        }
    }
    match code? {
        NF_ACCEPT => Some(Verdict::Accept),
        NF_DROP => Some(Verdict::Drop),
        NFT_CONTINUE => Some(Verdict::Continue),
        NFT_RETURN => Some(Verdict::Return),
        NFT_JUMP => Some(Verdict::JumpTo(ChainName::new(chain?).ok()?)),
        NFT_GOTO => Some(Verdict::GotoTo(ChainName::new(chain?).ok()?)),
        _ => None,
    }
}

fn parse_meta(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_META_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_META_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_META_KEY => key = MetaKey::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    let key = key?;
    match (dreg, sreg) {
        (Some(dreg), None) => Some(RuleExpr::Meta { dreg, key }),
        (None, Some(sreg)) => Some(RuleExpr::MetaSet { key, sreg }),
        _ => None,
    }
}

fn parse_exthdr(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut exthdr_type = None;
    let mut offset = None;
    let mut len = None;
    let mut flags = 0;
    let mut op = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_EXTHDR_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_EXTHDR_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_EXTHDR_TYPE => exthdr_type = Some(get::u8(payload).ok()?),
            NFTA_EXTHDR_OFFSET => offset = Some(get::u32_be(payload).ok()?),
            NFTA_EXTHDR_LEN => len = Some(get::u32_be(payload).ok()?),
            NFTA_EXTHDR_FLAGS => flags = get::u32_be(payload).ok()?,
            NFTA_EXTHDR_OP => op = ExthdrOp::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    // Flags (`NFT_EXTHDR_F_PRESENT`) are not modelled: never guess.
    if flags != 0 {
        return None;
    }
    let (op, exthdr_type, offset, len) = (op?, exthdr_type?, offset?, len?);
    match (dreg, sreg) {
        (Some(dreg), None) => Some(RuleExpr::Exthdr {
            dreg,
            op,
            exthdr_type,
            offset,
            len,
        }),
        (None, Some(sreg)) => Some(RuleExpr::ExthdrSet {
            sreg,
            op,
            exthdr_type,
            offset,
            len,
        }),
        _ => None,
    }
}

fn parse_ct(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut key = None;
    let mut direction = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_CT_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_CT_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_CT_KEY => key = CtKey::from_u32(get::u32_be(payload).ok()?),
            NFTA_CT_DIRECTION => direction = Some(CtDirection::from_u8(*payload.first()?)?),
            _ => {}
        }
    }
    let key = key?;
    match (dreg, sreg, direction) {
        (Some(dreg), None, None) => Some(RuleExpr::Ct { dreg, key }),
        (Some(dreg), None, Some(direction)) => Some(RuleExpr::CtDirectional { dreg, key, direction }),
        (None, Some(sreg), None) => Some(RuleExpr::CtSet { key, sreg }),
        // A `ct set` with a direction (a zone's) is not modelled.
        _ => None,
    }
}

fn parse_rt(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_RT_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_RT_KEY => key = RtKey::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    Some(RuleExpr::Rt {
        dreg: dreg?,
        key: key?,
    })
}

fn parse_byteorder(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut dreg = None;
    let mut op = None;
    let mut len = None;
    let mut size = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_BYTEORDER_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_OP => op = ByteorderOp::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_LEN => len = Some(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_SIZE => size = Some(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    Some(RuleExpr::Byteorder {
        sreg: sreg?,
        dreg: dreg?,
        op: op?,
        len: len?,
        size: size?,
    })
}

/// The `NFTA_DATA_VALUE` inside an `NFTA_DATA_*` nest.
fn data_value(nest: &[u8]) -> Option<Vec<u8>> {
    AttrIter::new(nest)
        .find(|(attr, _)| *attr == NFTA_DATA_VALUE)
        .map(|(_, value)| value.to_vec())
}

fn parse_bitwise(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut dreg = None;
    let mut len = None;
    let mut mask = None;
    let mut xor = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_BITWISE_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BITWISE_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BITWISE_LEN => len = Some(get::u32_be(payload).ok()?),
            // Only the mask/xor boolean form is modelled; shifts and the
            // register-operand ops carry other attributes.
            NFTA_BITWISE_OP if get::u32_be(payload).ok()? != NFT_BITWISE_BOOL => return None,
            NFTA_BITWISE_MASK => mask = data_value(payload),
            NFTA_BITWISE_XOR => xor = data_value(payload),
            NFTA_BITWISE_OP => {}
            _ => return None,
        }
    }
    Some(RuleExpr::Bitwise {
        sreg: sreg?,
        dreg: dreg?,
        len: len?,
        mask: mask?,
        xor: xor?,
    })
}

fn parse_lookup(data: &[u8]) -> Option<RuleExpr> {
    let mut set = None;
    let mut sreg = None;
    let mut dreg = None;
    let mut invert = false;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_LOOKUP_SET => set = get::string(payload).ok().map(str::to_string),
            NFTA_LOOKUP_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_LOOKUP_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_LOOKUP_FLAGS => match get::u32_be(payload).ok()? {
                0 => {}
                NFT_LOOKUP_F_INV => invert = true,
                // A flag this decoder does not know: never guess.
                _ => return None,
            },
            _ => {}
        }
    }
    Some(RuleExpr::Lookup {
        set: set?,
        sreg: sreg?,
        dreg,
        invert,
    })
}

fn parse_quota(data: &[u8]) -> Option<RuleExpr> {
    let mut bytes = None;
    let mut consumed = 0;
    let mut flags = 0;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_QUOTA_BYTES => bytes = Some(get::u64_be(payload).ok()?),
            NFTA_QUOTA_CONSUMED => consumed = get::u64_be(payload).ok()?,
            NFTA_QUOTA_FLAGS => flags = get::u32_be(payload).ok()?,
            _ => {}
        }
    }
    Some(RuleExpr::Quota {
        bytes: bytes?,
        consumed,
        over: flags & NFT_QUOTA_F_INV != 0,
        depleted: flags & NFT_QUOTA_F_DEPLETED != 0,
    })
}

fn parse_objref(data: &[u8]) -> Option<RuleExpr> {
    let mut object_type = None;
    let mut name = None;
    let mut sreg = None;
    let mut map = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_OBJREF_IMM_TYPE => {
                object_type = super::object::ObjectType::from_u32(get::u32_be(payload).ok()?);
            }
            NFTA_OBJREF_IMM_NAME => name = get::string(payload).ok().map(str::to_string),
            NFTA_OBJREF_SET_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_OBJREF_SET_NAME => map = get::string(payload).ok().map(str::to_string),
            _ => {}
        }
    }
    let objref = match (name, map) {
        (Some(name), None) => ObjrefExpr::Named {
            object_type: object_type?,
            name,
        },
        (None, Some(map)) => ObjrefExpr::Map { sreg: sreg?, map },
        _ => return None,
    };
    Some(RuleExpr::Objref(objref))
}

fn parse_dynset(data: &[u8]) -> Option<RuleExpr> {
    let mut set = None;
    let mut op = None;
    let mut sreg_key = None;
    let mut sreg_data = None;
    let mut timeout = None;
    let mut invert = false;
    let mut statements = Vec::new();
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_DYNSET_SET_NAME => set = get::string(payload).ok().map(str::to_string),
            NFTA_DYNSET_OP => op = DynsetOp::from_u32(get::u32_be(payload).ok()?),
            NFTA_DYNSET_SREG_KEY => sreg_key = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_DYNSET_SREG_DATA => {
                sreg_data = Some(Register::from_u32(get::u32_be(payload).ok()?)?);
            }
            NFTA_DYNSET_TIMEOUT => {
                let ms = get::u64_be(payload).ok()?;
                timeout = (ms != 0).then(|| std::time::Duration::from_millis(ms));
            }
            NFTA_DYNSET_FLAGS => {
                let flags = get::u32_be(payload).ok()?;
                if flags & !(NFT_DYNSET_F_INV | NFT_DYNSET_F_EXPR) != 0 {
                    return None;
                }
                invert = flags & NFT_DYNSET_F_INV != 0;
            }
            NFTA_DYNSET_EXPR => statements.push(parse_elem(payload)?),
            NFTA_DYNSET_EXPRESSIONS => statements.extend(parse_expressions(payload)),
            _ => {}
        }
    }
    // Never half-decode: a statement nlink cannot read, or one no set
    // element carries, keeps the whole dynset raw.
    if statements
        .iter()
        .any(|s| ElementStatement::from_rule_expr(s).is_none())
    {
        return None;
    }
    Some(RuleExpr::Dynset {
        set: set?,
        op: op?,
        sreg_key: sreg_key?,
        sreg_data,
        timeout,
        invert,
        statements,
    })
}

fn parse_cmp(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut op = None;
    let mut value = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_CMP_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_CMP_OP => op = CmpOp::from_u32(get::u32_be(payload).ok()?),
            NFTA_CMP_DATA => {
                for (inner, inner_payload) in AttrIter::new(payload) {
                    if inner == NFTA_DATA_VALUE {
                        value = Some(inner_payload.to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    Some(RuleExpr::Cmp {
        sreg: sreg?,
        op: op?,
        data: value?,
    })
}

fn parse_payload(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut base = None;
    let mut offset = None;
    let mut len = None;
    let mut csum = PayloadCsum::None;
    let mut csum_offset = 0;
    let mut csum_flags = 0;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_PAYLOAD_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_BASE => base = PayloadBase::from_u32(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_OFFSET => offset = Some(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_LEN => len = Some(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_CSUM_TYPE => csum = PayloadCsum::from_u32(get::u32_be(payload).ok()?)?,
            NFTA_PAYLOAD_CSUM_OFFSET => csum_offset = get::u32_be(payload).ok()?,
            NFTA_PAYLOAD_CSUM_FLAGS => csum_flags = get::u32_be(payload).ok()?,
            _ => {}
        }
    }
    // A write (#703); a flag nlink does not know stays Unknown.
    if let Some(sreg) = sreg {
        if csum_flags & !NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
            return None;
        }
        return Some(RuleExpr::PayloadSet {
            sreg,
            base: base?,
            offset: offset?,
            len: len?,
            csum,
            csum_offset,
            l4_pseudo_header: csum_flags & NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0,
        });
    }
    Some(RuleExpr::Payload {
        dreg: dreg?,
        base: base?,
        offset: offset?,
        len: len?,
    })
}

/// A rule body and its comment, as nft prints the two.
pub(crate) fn with_comment(body: String, comment: Option<&str>) -> String {
    match comment {
        Some(comment) if body.is_empty() => format!("comment \"{comment}\""),
        Some(comment) => format!("{body} comment \"{comment}\""),
        None => body,
    }
}

impl super::types::RuleInfo {
    /// Decode this rule's [`expression_bytes`](Self::expression_bytes)
    /// into typed expressions.
    ///
    /// Infallible: undecodable elements come back as
    /// [`RuleExpr::Unknown`] with their raw payload preserved. The raw
    /// `expression_bytes` field stays untouched as the round-trip
    /// source of truth (the declarative diff compares bodies
    /// byte-wise, not through this decoder).
    pub fn expressions(&self) -> Vec<RuleExpr> {
        parse_expressions(&self.expression_bytes)
    }

    /// The rule as a [`RuleSpec`] (#708): its expressions
    /// lifted to the matches, statements and verdict that write them, and
    /// its comment, without nlink's key. What nlink has no item for stays a
    /// raw [`Expr`]. Lowering the spec in the rule's family gives this rule's
    /// expressions back, as the declarative diff compares them.
    pub fn spec(&self) -> super::RuleSpec {
        let items = super::spec_lift::lift(
            &self.expressions(),
            Some(&self.expression_bytes),
            self.family,
        );
        let mut spec: super::RuleSpec = items.into_iter().collect();
        spec.comment = self
            .userdata_raw
            .as_deref()
            .and_then(super::userdata::human_comment_of);
        spec
    }

    /// The rule as `nft list ruleset` prints it: `tcp dport 22 counter
    /// packets 4 bytes 240 accept comment "ssh"` (#708).
    ///
    /// `None` when the rule holds something nlink does not read back
    /// exactly as nft prints it: an expression it does not decode, a field
    /// of a header it does not name, an anonymous set (the rule names it,
    /// its elements are elsewhere), an object map (whose type the rule does
    /// not say). Two things nft looks up on the host print as numbers
    /// instead: an interface index (`iif 1`, where nft prints `iif "lo"`),
    /// and the device of a `dup` or `fwd`.
    pub fn nft_syntax(&self) -> Option<String> {
        let body = super::lift::lift(&self.expressions(), self.family)?;
        Some(with_comment(body, self.comment_text.as_deref()))
    }

    /// [`nft_syntax`](Self::nft_syntax) as `nft -s list ruleset`
    /// (`--stateless`) prints it: `tcp dport 22 counter accept`, a counter
    /// without its packets and bytes and a quota without what it has used.
    /// The same rule prints the same way however much traffic it has seen,
    /// which is why [`NftablesDiff`] shows rules this way.
    ///
    /// [`NftablesDiff`]: super::config::NftablesDiff
    pub fn nft_syntax_stateless(&self) -> Option<String> {
        let body = super::lift::lift_stateless(&self.expressions(), self.family)?;
        Some(with_comment(body, self.comment_text.as_deref()))
    }

    /// Cumulative `(packets, bytes)` from the first `counter`
    /// expression in this rule, if any.
    ///
    /// The common "per-rule hit counters" shortcut: dump rules, join
    /// on [`key`](Self::key)/handle, read `counter()`. Rules
    /// can legally carry several counter expressions; this returns the
    /// first (position order = evaluation order).
    pub fn counter(&self) -> Option<(u64, u64)> {
        self.expressions().into_iter().find_map(|e| match e {
            RuleExpr::Counter { packets, bytes } => Some((packets, bytes)),
            _ => None,
        })
    }
}

#[cfg(test)]
mod verdict_tests {
    //! Verdict wire-format coverage. The 0.20.1 deprecated
    //! `Verdict::Jump(String)` / `Verdict::Goto(String)` variants
    //! were removed in 0.21; the typed `JumpTo(ChainName)` /
    //! `GotoTo(ChainName)` are the only forms now.

    use super::*;

    fn encode_verdict(verdict: &Verdict) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        write_verdict_expr(&mut b, verdict);
        b.as_bytes().to_vec()
    }

    #[test]
    fn jumpto_emits_nft_jump_code_with_chain_name() {
        let typed = Verdict::JumpTo(ChainName::new("input_filter").unwrap());
        let bytes = encode_verdict(&typed);
        // Sanity that the encoder produced *something* — the byte-shape
        // is exercised more thoroughly in cycle_0_19_backfill.rs.
        assert!(!bytes.is_empty());
    }

    #[test]
    fn goto_to_emits_nft_goto_code_with_chain_name() {
        let typed = Verdict::GotoTo(ChainName::new("output_chain").unwrap());
        let bytes = encode_verdict(&typed);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn different_chain_names_produce_different_bytes() {
        let a = Verdict::JumpTo(ChainName::new("a").unwrap());
        let b = Verdict::JumpTo(ChainName::new("b").unwrap());
        assert_ne!(encode_verdict(&a), encode_verdict(&b));
    }
}

#[cfg(test)]
mod decode_tests {
    //! #164 — expression-decoder coverage. Fixtures come from the
    //! write path (`write_expressions`) so encode/decode stay in
    //! lockstep, plus hand-built elements for read-only shapes the
    //! writer can't produce (live counter values, unknown kinds,
    //! pathological lengths).

    use super::*;

    /// Encode `exprs` and return exactly what `parse_rule` stores in
    /// `expression_bytes`: the inner payload of the outer
    /// `NFTA_RULE_EXPRESSIONS` attribute (16-byte nlmsghdr + 4-byte
    /// attr header peeled — same trick as
    /// `config::diff::lower_to_expression_bytes`).
    fn encode(exprs: &[Expr]) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        write_expressions(&mut b, exprs);
        b.as_bytes()[20..].to_vec()
    }

    /// Hand-build one `NFTA_LIST_ELEM` with the given name and
    /// pre-encoded `NFTA_EXPR_DATA` payload.
    fn build_elem(name: &str, data_payload: &[u8]) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let elem = b.nest_start(NFTA_LIST_ELEM | 0x8000);
        b.append_attr_str(NFTA_EXPR_NAME, name);
        if !data_payload.is_empty() {
            b.append_attr(NFTA_EXPR_DATA | 0x8000, data_payload);
        }
        b.nest_end(elem);
        b.as_bytes()[16..].to_vec()
    }

    /// Encode a bare attribute stream (no nlmsghdr), for building
    /// inner NFTA_EXPR_DATA payloads by hand.
    fn build_attrs(f: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        f(&mut b);
        b.as_bytes()[16..].to_vec()
    }

    /// Split a bare attribute stream into `type -> payload`, with the
    /// nested/byteorder flag bits masked off. Lets a test pin exactly which
    /// attribute *numbers* an expression emits — which is the whole bug in
    /// #206 (an attribute from the wrong namespace, silently skipped by the
    /// kernel because it was above the nest's maxtype).
    fn attrs_of(mut input: &[u8]) -> std::collections::BTreeMap<u16, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        while input.len() >= 4 {
            let len = u16::from_ne_bytes(input[0..2].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
            assert!((4..=input.len()).contains(&len), "bogus nla_len {len}");
            out.insert(ty, input[4..len].to_vec());
            input = &input[len.next_multiple_of(4).min(input.len())..];
        }
        out
    }

    /// The `NFTA_EXPR_DATA` payload of the expression named `name`, as
    /// encoded: the raw attributes, whatever the decoder makes of them.
    fn expr_data(exprs: &[Expr], name: &str) -> Vec<u8> {
        let bytes = encode(exprs);
        for (_, elem) in AttrIter::new(&bytes) {
            let attrs: Vec<_> = AttrIter::new(elem).collect();
            let named = attrs
                .iter()
                .any(|(a, v)| *a == NFTA_EXPR_NAME && get::string(v).ok() == Some(name));
            if named {
                return attrs
                    .iter()
                    .find(|(a, _)| a & 0x7FFF == NFTA_EXPR_DATA)
                    .map(|(_, v)| v.to_vec())
                    .unwrap_or_default();
            }
        }
        panic!("no `{name}` expression emitted");
    }

    /// `redir` has its own attribute namespace (`NFTA_REDIR_*`). nlink emitted
    /// `NFTA_NAT_REG_PROTO_MIN` (= 5) into it, which is above the nest's
    /// `NFTA_REDIR_MAX`, so the kernel **silently skipped** it: the rule
    /// installed with no error and no port rewrite, and traffic was redirected
    /// to the local machine on the *original* port. Transparent proxying broke
    /// with no diagnostic (#206).
    #[test]
    fn redirect_uses_the_redir_attribute_namespace() {
        let exprs = vec![
            // Rule::redirect pushes this Immediate ahead of the Redirect.
            Expr::Immediate {
                dreg: Register::R0,
                data: 3128u16.to_be_bytes().to_vec(),
            },
            RedirExpr::new().port(3128).into(),
        ];

        let attrs = attrs_of(&expr_data(&exprs, "redir"));

        assert_eq!(
            attrs.get(&NFTA_REDIR_REG_PROTO_MIN).map(|v| v.as_slice()),
            Some((Register::R0 as u32).to_be_bytes().as_slice()),
            "the port register must be referenced through NFTA_REDIR_REG_PROTO_MIN (1)",
        );
        assert!(
            attrs.contains_key(&NFTA_REDIR_REG_PROTO_MAX),
            "MAX must equal MIN for a single port, or the kernel's dump won't round-trip",
        );
        assert_eq!(
            attrs.get(&NFTA_REDIR_FLAGS).map(|v| v.as_slice()),
            Some(NF_NAT_RANGE_PROTO_SPECIFIED.to_be_bytes().as_slice()),
        );
        assert!(
            !attrs.contains_key(&NFTA_NAT_REG_PROTO_MIN) || NFTA_NAT_REG_PROTO_MIN == NFTA_REDIR_REG_PROTO_MIN,
            "regression: emitting a nat-namespace attribute (5) inside a redir nest — \
             the kernel skips it silently",
        );
    }

    /// A redirect with no port rewrites nothing and needs no data nest.
    #[test]
    fn redirect_without_a_port_emits_no_data() {
        let data = expr_data(&[Expr::Redirect(RedirExpr::new())], "redir");
        assert!(data.is_empty());
    }

    /// `Rule::reject()` used to push a bare NF_DROP verdict, so the packet was
    /// black-holed with no ICMP and no RST and the client hung until its TCP
    /// timeout — the opposite of the fast "connection refused" the doc-comment
    /// promised (#205).
    #[test]
    fn reject_emits_a_real_reject_expression() {
        let exprs = vec![Expr::Reject {
            reject_type: NFT_REJECT_ICMPX_UNREACH,
            icmp_code: 1,
        }];

        let attrs = attrs_of(&expr_data(&exprs, "reject"));

        assert_eq!(
            attrs.get(&NFTA_REJECT_TYPE).map(|v| v.as_slice()),
            Some(NFT_REJECT_ICMPX_UNREACH.to_be_bytes().as_slice()),
        );
        assert_eq!(
            attrs.get(&NFTA_REJECT_ICMP_CODE).map(|v| v.as_slice()),
            Some([1u8].as_slice()),
            "NFTA_REJECT_ICMP_CODE is a single byte",
        );
    }

    /// The builder must reach the reject expression, not a drop verdict.
    #[test]
    fn rule_reject_is_not_a_drop() {
        use super::super::types::Rule;

        let rule = Rule::new("t", "c").reject();
        assert!(
            matches!(rule.exprs().as_slice(), [Expr::Reject { .. }]),
            "Rule::reject() pushed {:?}, not a Reject expression",
            rule.exprs(),
        );

        // And drop() still black-holes, which is a legitimate thing to want.
        let rule = Rule::new("t", "c").drop();
        assert!(matches!(
            rule.exprs().as_slice(),
            [Expr::Verdict(Verdict::Drop)]
        ));
    }

    #[test]
    fn roundtrip_meta_payload_cmp_immediate() {
        let bytes = encode(&[
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::L4Proto,
            },
            Expr::Payload {
                dreg: Register::R1,
                base: PayloadBase::Transport,
                offset: 2,
                len: 2,
            },
            Expr::Cmp {
                sreg: Register::R1,
                op: CmpOp::Eq,
                data: 443u16.to_be_bytes().to_vec(),
            },
            Expr::Immediate {
                dreg: Register::R2,
                data: vec![1, 2, 3, 4],
            },
        ]);
        let decoded = parse_expressions(&bytes);
        assert_eq!(
            decoded,
            vec![
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::L4Proto,
                },
                RuleExpr::Payload {
                    dreg: Register::R1,
                    base: PayloadBase::Transport,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::Cmp {
                    sreg: Register::R1,
                    op: CmpOp::Eq,
                    data: 443u16.to_be_bytes().to_vec(),
                },
                RuleExpr::Immediate {
                    dreg: Register::R2,
                    data: vec![1, 2, 3, 4],
                },
            ]
        );
    }

    #[test]
    fn roundtrip_verdict_all_variants() {
        let verdicts = [
            Verdict::Accept,
            Verdict::Drop,
            Verdict::Continue,
            Verdict::Return,
            Verdict::JumpTo(ChainName::new("subchain").unwrap()),
            Verdict::GotoTo(ChainName::new("tailchain").unwrap()),
        ];
        for v in verdicts {
            let bytes = encode(&[Expr::Verdict(v.clone())]);
            let decoded = parse_expressions(&bytes);
            assert_eq!(decoded, vec![RuleExpr::Verdict(v)], "verdict round-trip");
        }
    }

    #[test]
    fn roundtrip_counter_write_side_zeroes() {
        let bytes = encode(&[Expr::Counter]);
        assert_eq!(
            parse_expressions(&bytes),
            vec![RuleExpr::Counter {
                packets: 0,
                bytes: 0,
            }]
        );
    }

    #[test]
    fn counter_with_live_values_decodes_in_any_attr_order() {
        for swapped in [false, true] {
            let data = build_attrs(|b| {
                if swapped {
                    b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 7);
                    b.append_attr_u64_be(NFTA_COUNTER_BYTES, 4242);
                } else {
                    b.append_attr_u64_be(NFTA_COUNTER_BYTES, 4242);
                    b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 7);
                }
            });
            let elem = build_elem("counter", &data);
            assert_eq!(
                parse_expressions(&elem),
                vec![RuleExpr::Counter {
                    packets: 7,
                    bytes: 4242,
                }]
            );
        }
    }

    #[test]
    fn counter_short_payload_falls_back_to_unknown() {
        // 4-byte NFTA_COUNTER_PACKETS — not a valid u64.
        let data = build_attrs(|b| b.append_attr(NFTA_COUNTER_PACKETS, &[0, 0, 0, 7]));
        let elem = build_elem("counter", &data);
        match &parse_expressions(&elem)[..] {
            [RuleExpr::Unknown { name, data: raw }] => {
                assert_eq!(name, "counter");
                assert!(!raw.is_empty(), "raw payload preserved");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn unknown_expr_name_preserves_payload() {
        let data = build_attrs(|b| b.append_attr(1, &[9, 9, 9, 9]));
        let elem = build_elem("quota", &data);
        assert_eq!(
            parse_expressions(&elem),
            vec![RuleExpr::Unknown {
                name: "quota".to_string(),
                data: data.clone(),
            }]
        );
    }

    #[test]
    fn a_dataless_masq_decodes_as_a_plain_masquerade() {
        // `masq` writes an NFTA_EXPR_DATA nest with nothing in it.
        let bytes = encode(&[Expr::Masquerade(MasqExpr::new())]);
        assert_eq!(
            parse_expressions(&bytes),
            vec![RuleExpr::Masq {
                proto: None,
                flags: NatFlags::empty(),
            }]
        );
    }

    /// #528: what nlink writes for each statement decodes as its typed
    /// variant, not `Unknown`.
    #[test]
    fn statements_decode_typed() {
        use std::net::Ipv4Addr;

        let rule = super::super::types::Rule::new("t", "c")
            .limit(10, LimitUnit::Minute)
            .log(Some("dropped: "))
            .expr(LogExpr::new().group(3))
            .reject_with(NFT_REJECT_ICMPX_UNREACH, NFT_REJECT_ICMPX_PORT_UNREACH)
            .dnat(Ipv4Addr::new(10, 0, 0, 1), Some(8080))
            .redirect(Some(3128))
            .masquerade()
            .flow_offload("ft");
        let decoded: Vec<_> = parse_expressions(&encode(&rule.exprs()))
            .into_iter()
            .filter(|e| !matches!(e, RuleExpr::Immediate { .. }))
            .collect();
        let both = Some((Register::R0, Register::R0));
        assert_eq!(
            decoded,
            vec![
                RuleExpr::Limit(LimitExpr::packets(10, LimitUnit::Minute)),
                RuleExpr::Log(LogExpr::new().prefix("dropped: ")),
                RuleExpr::Log(LogExpr::new().group(3)),
                RuleExpr::Reject {
                    reject_type: NFT_REJECT_ICMPX_UNREACH,
                    icmp_code: Some(NFT_REJECT_ICMPX_PORT_UNREACH),
                },
                RuleExpr::Nat {
                    nat_type: NatType::Dnat,
                    family: Family::Ip,
                    addr: both,
                    proto: Some((Register::R1, Register::R1)),
                    flags: NatFlags::MAP_IPS | NatFlags::PROTO_SPECIFIED,
                },
                RuleExpr::Redir {
                    proto: both,
                    flags: NatFlags::PROTO_SPECIFIED,
                },
                RuleExpr::Masq {
                    proto: None,
                    flags: NatFlags::empty(),
                },
                RuleExpr::FlowOffload {
                    flowtable: "ft".into(),
                },
            ]
        );
    }

    /// #528: `Rule::nat` loads each range into the next registers, and the
    /// statement decodes back to them with the flags the ranges imply.
    #[test]
    fn nat_statements_load_their_ranges_and_decode() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use super::super::types::{NatStatement, Rule};
        let decode = |rule: Rule| {
            rule.check().unwrap();
            parse_expressions(&encode(&rule.exprs()))
        };
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 9));
        let exprs = decode(Rule::new("t", "c").nat(NatStatement::snat(a).to(b).ports(40000, 40010).fully_random()));
        assert_eq!(
            exprs,
            vec![
                RuleExpr::Immediate { dreg: Register::R0, data: a.octets().to_vec() },
                RuleExpr::Immediate { dreg: Register::R1, data: b.octets().to_vec() },
                RuleExpr::Immediate { dreg: Register::R2, data: 40000u16.to_be_bytes().to_vec() },
                RuleExpr::Immediate { dreg: Register::R3, data: 40010u16.to_be_bytes().to_vec() },
                RuleExpr::Nat {
                    nat_type: NatType::Snat,
                    family: Family::Ip,
                    addr: Some((Register::R0, Register::R1)),
                    proto: Some((Register::R2, Register::R3)),
                    flags: NatFlags::MAP_IPS | NatFlags::PROTO_SPECIFIED | NatFlags::PROTO_RANDOM_FULLY,
                },
            ]
        );
        let exprs = decode(Rule::new("t", "c").nat(NatStatement::dnat_to_port(Family::Ip6, 8080)));
        assert!(matches!(
            exprs.last(),
            Some(RuleExpr::Nat { nat_type: NatType::Dnat, family: Family::Ip6, addr: None, proto: Some((Register::R0, Register::R0)), flags })
                if *flags == NatFlags::PROTO_SPECIFIED
        ), "{exprs:?}");
        let exprs = decode(Rule::new("t", "c").nat(NatStatement::masquerade().ports(1024, 2048).random()));
        assert_eq!(
            exprs.last(),
            Some(&RuleExpr::Masq {
                proto: Some((Register::R0, Register::R1)),
                flags: NatFlags::PROTO_SPECIFIED | NatFlags::PROTO_RANDOM,
            })
        );
        let exprs = decode(Rule::new("t", "c").nat(NatStatement::snat(Ipv6Addr::LOCALHOST)));
        assert!(matches!(exprs.last(), Some(RuleExpr::Nat { family: Family::Ip6, .. })), "{exprs:?}");
    }

    /// The single-value forms are the bytes the older builders write, so a
    /// rule moved to `nat()` is not replaced by the declarative diff.
    #[test]
    fn nat_single_values_encode_as_the_older_builders() {
        use std::net::Ipv4Addr;

        use super::super::types::{NatStatement, Rule};
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let same = |new: Rule, old: Rule| assert_eq!(encode(&new.exprs()), encode(&old.exprs()));
        same(Rule::new("t", "c").nat(NatStatement::snat(a).port(4000)), Rule::new("t", "c").snat(a, Some(4000)));
        same(Rule::new("t", "c").nat(NatStatement::dnat(a)), Rule::new("t", "c").dnat(a, None));
        same(Rule::new("t", "c").nat(NatStatement::redirect().port(3128)), Rule::new("t", "c").redirect(Some(3128)));
        same(Rule::new("t", "c").nat(NatStatement::redirect()), Rule::new("t", "c").redirect(None));
        same(Rule::new("t", "c").nat(NatStatement::masquerade()), Rule::new("t", "c").masquerade());
    }

    /// What the kernel would refuse fails the rule, naming the statement.
    #[test]
    fn nat_statements_the_kernel_refuses_fail_the_rule() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use super::super::types::{NatStatement, Rule};
        let v4 = Ipv4Addr::new(10, 0, 0, 1);
        for (nat, want) in [
            (NatStatement::masquerade().to(v4), "masquerade has no address"),
            (NatStatement::snat(v4).to(Ipv6Addr::LOCALHOST), "mixes IPv4 and IPv6"),
            (NatStatement::snat(Ipv4Addr::new(10, 0, 0, 9)).to(v4), "runs backwards"),
            (NatStatement::dnat(v4).ports(9, 1), "port range 9-1 runs backwards"),
            (NatStatement::dnat_to_port(Family::Inet, 80), "must be ip or ip6"),
            (NatStatement::redirect().netmap(), "cannot netmap"),
            (NatStatement::snat_to_port(Family::Ip, 1).netmap(), "netmap needs an address range"),
        ] {
            let rule = Rule::new("t", "c").nat(nat);
            let error = rule.spec().lower_items().err().unwrap_or_default();
            assert!(error.starts_with("nat: ") && error.contains(want), "{error:?} lacks {want:?}");
        }
    }

    /// #528: a byte-rate limit and a named ICMPX code encode and decode.
    #[test]
    fn byte_limits_and_icmpx_codes_round_trip() {
        use super::super::types::{IcmpxCode, Rule};
        let rule = Rule::new("t", "c")
            .expr(LimitExpr::bytes(crate::Bytes::kib(10), LimitUnit::Second).burst(2048).over())
            .limit_bytes(crate::Bytes::new(500), LimitUnit::Minute)
            .reject_icmpx(IcmpxCode::HostUnreachable);
        assert_eq!(
            parse_expressions(&encode(&rule.exprs())),
            vec![
                RuleExpr::Limit(LimitExpr::bytes(crate::Bytes::kib(10), LimitUnit::Second).burst(2048).over()),
                RuleExpr::Limit(LimitExpr::bytes(crate::Bytes::new(500), LimitUnit::Minute)),
                RuleExpr::Reject {
                    reject_type: NFT_REJECT_ICMPX_UNREACH,
                    icmp_code: Some(IcmpxCode::HostUnreachable as u8),
                },
            ]
        );
        assert_eq!(IcmpxCode::from_u8(3), Some(IcmpxCode::AdminProhibited));
        assert_eq!(IcmpxCode::from_u8(4), None);
    }

    /// #528: a range is behind its field's guard, compares network-order
    /// bytes, and turns a host-order field around first.
    #[test]
    fn ranges_encode_as_nft_does() {
        use super::super::types::{PacketField, RangeOp, Rule};
        let rule = Rule::new("t", "c").match_range(PacketField::TcpDport, 1000u16, 2000u16);
        rule.check().unwrap();
        let exprs = parse_expressions(&encode(&rule.exprs()));
        assert!(matches!(&exprs[..2], [RuleExpr::Meta { key: MetaKey::L4Proto, .. }, RuleExpr::Cmp { .. }]), "{exprs:?}");
        assert_eq!(
            exprs.last(),
            Some(&RuleExpr::Range { sreg: Register::R0, op: RangeOp::Eq, from: vec![0x03, 0xe8], to: vec![0x07, 0xd0] })
        );

        let rule = Rule::new("t", "c").match_range_not(PacketField::Mark, 0x10u32, 0x20u32);
        let exprs = parse_expressions(&encode(&rule.exprs()));
        assert!(matches!(exprs[1], RuleExpr::Byteorder { op: ByteorderOp::Hton, len: 4, size: 4, .. }), "{exprs:?}");
        assert_eq!(
            exprs[2],
            RuleExpr::Range { sreg: Register::R0, op: RangeOp::Neq, from: vec![0, 0, 0, 0x10], to: vec![0, 0, 0, 0x20] }
        );

        for (rule, want) in [
            (Rule::new("t", "c").match_range(PacketField::TcpDport, 2000u16, 1000u16), "runs backwards"),
            (Rule::new("t", "c").match_range(PacketField::Ip4Saddr, 1u16, 2u16), "cannot hold"),
            (
                Rule::new("t", "c").match_range(
                    PacketField::Ip4Saddr,
                    std::net::Ipv6Addr::LOCALHOST,
                    std::net::Ipv6Addr::LOCALHOST,
                ),
                "cannot hold",
            ),
        ] {
            let error = rule.spec().lower_items().err().unwrap_or_default();
            assert!(error.starts_with("range: ") && error.contains(want), "{error:?}");
        }
    }

    /// What these decoders cannot carry demotes to `Unknown`, never to a
    /// guess: a limit type nlink does not know, a log level past `audit`,
    /// a reject with no type.
    #[test]
    fn statements_beyond_the_types_stay_unknown() {
        let mut limit = MessageBuilder::new(0, 0);
        limit.append_attr_u64_be(NFTA_LIMIT_RATE, 1000);
        limit.append_attr_u64_be(NFTA_LIMIT_UNIT, 1);
        limit.append_attr_u32_be(NFTA_LIMIT_TYPE, 7); // a type nlink does not know
        let mut log = MessageBuilder::new(0, 0);
        log.append_attr_u32_be(NFTA_LOG_LEVEL, 9);
        let reject = MessageBuilder::new(0, 0);
        for (name, b) in [("limit", limit), ("log", log), ("reject", reject)] {
            let data = b.finish()[16..].to_vec();
            assert!(
                matches!(&parse_expressions(&build_elem(name, &data))[..], [RuleExpr::Unknown { name: n, .. }] if n == name),
                "{name}"
            );
        }
    }

    /// The empty nest is not cosmetic. `nft_expr_dump` opens
    /// NFTA_EXPR_DATA for every expression with a `dump` callback and
    /// closes it whatever the callback wrote, so the kernel echoes one
    /// even for an expression with no attributes. Rendering the
    /// expression without it makes the declared bytes 4 shorter than
    /// the kernel's, which `NftablesDiff` reads as "changed" on every
    /// diff, for the life of the rule (#362).
    ///
    /// Asserted on the wire bytes rather than through
    /// `parse_expressions`, which cannot tell an absent nest from an
    /// empty one — that is exactly why the omission went unnoticed.
    #[test]
    fn dataless_exprs_still_emit_the_empty_data_nest() {
        // The trailing attribute of the elem: len 4, type
        // NFTA_EXPR_DATA (2), no payload. The nested flag is a parser
        // hint the diff strips, so only len and type matter here.
        let empty_nest = {
            let mut v = 4u16.to_ne_bytes().to_vec();
            v.extend_from_slice(&(NFTA_EXPR_DATA | 0x8000).to_ne_bytes());
            v
        };
        for expr in [Expr::Masquerade(MasqExpr::new()), Expr::Redirect(RedirExpr::new())] {
            let bytes = encode(std::slice::from_ref(&expr));
            assert!(
                bytes.ends_with(&empty_nest),
                "{expr:?} must end with an empty NFTA_EXPR_DATA nest; got {bytes:02x?}"
            );
        }
        // A redirect *with* a port carries real attributes, so the nest
        // is non-empty and this must not match.
        let with_port = encode(&[Expr::Redirect(RedirExpr::new().port(8080))]);
        assert!(!with_port.ends_with(&empty_nest), "{with_port:02x?}");
    }

    #[test]
    fn verdict_break_code_falls_back_to_unknown() {
        // NFT_BREAK (-2) is not representable in the typed Verdict.
        let verdict_nest = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_VERDICT_CODE, NFT_BREAK as u32);
        });
        let imm_nest = build_attrs(|b| b.append_attr(NFTA_DATA_VERDICT | 0x8000, &verdict_nest));
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_IMMEDIATE_DREG, Register::Verdict as u32);
            b.append_attr(NFTA_IMMEDIATE_DATA | 0x8000, &imm_nest);
        });
        let elem = build_elem("immediate", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "immediate"
        ));
    }

    #[test]
    fn meta_without_dreg_falls_back_to_unknown() {
        // SREG-form meta (meta-set) carries no NFTA_META_DREG.
        let data = build_attrs(|b| b.append_attr_u32_be(NFTA_META_KEY, MetaKey::Mark as u32));
        let elem = build_elem("meta", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "meta"
        ));
    }

    #[test]
    fn meta_unmodelled_key_falls_back_to_unknown() {
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_META_DREG, Register::R0 as u32);
            b.append_attr_u32_be(NFTA_META_KEY, 9999);
        });
        let elem = build_elem("meta", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "meta"
        ));
    }

    #[test]
    fn nameless_elem_is_skipped_and_empty_input_is_empty() {
        assert!(parse_expressions(&[]).is_empty());

        // Element with data but no NFTA_EXPR_NAME.
        let data = build_attrs(|b| b.append_attr(NFTA_COUNTER_BYTES, &42u64.to_be_bytes()));
        let elem = {
            let mut b = MessageBuilder::new(0, 0);
            let e = b.nest_start(NFTA_LIST_ELEM | 0x8000);
            b.append_attr(NFTA_EXPR_DATA | 0x8000, &data);
            b.nest_end(e);
            b.as_bytes()[16..].to_vec()
        };
        assert!(parse_expressions(&elem).is_empty());
    }

    #[test]
    fn pathological_lengths_terminate_without_panic() {
        // Truncated mid-attribute: claim 64 bytes, provide 8.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&64u16.to_ne_bytes());
        truncated.extend_from_slice(&(NFTA_LIST_ELEM | 0x8000).to_ne_bytes());
        truncated.extend_from_slice(&[0u8; 4]);
        assert!(parse_expressions(&truncated).is_empty());

        // Zero-length attribute header: must terminate, not spin.
        let zero_len = [0u8, 0, 1, 0, 0, 0, 0, 0];
        assert!(parse_expressions(&zero_len).is_empty());

        // nla_len below the 4-byte header minimum.
        let mut short = Vec::new();
        short.extend_from_slice(&2u16.to_ne_bytes());
        short.extend_from_slice(&NFTA_LIST_ELEM.to_ne_bytes());
        assert!(parse_expressions(&short).is_empty());
    }

    #[test]
    fn ruleinfo_expressions_and_counter_shortcut() {
        let live_counter = {
            let data = build_attrs(|b| {
                b.append_attr_u64_be(NFTA_COUNTER_BYTES, 1_000_000);
                b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 1_000);
            });
            build_elem("counter", &data)
        };
        let mut expression_bytes = encode(&[
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::NfProto,
            },
            Expr::Verdict(Verdict::Accept),
        ]);
        // Splice the live counter between the encoded exprs.
        expression_bytes.extend_from_slice(&live_counter);

        let rule = RuleInfo {
            table: "t".into(),
            chain: "c".into(),
            family: Family::Inet,
            handle: 1,
            position: None,
            key: None,
            comment_text: None,
            userdata_raw: None,
            expression_bytes,
        };
        let exprs = rule.expressions();
        assert_eq!(exprs.len(), 3);
        assert_eq!(rule.counter(), Some((1_000, 1_000_000)));

        let no_counter = RuleInfo {
            expression_bytes: encode(&[Expr::Verdict(Verdict::Drop)]),
            ..rule
        };
        assert_eq!(no_counter.counter(), None);
    }

    /// The `NFTA_EXPR_DATA` attributes of the single expression in `exprs`,
    /// keyed by attribute number.
    fn data_attrs(exprs: &[Expr]) -> std::collections::BTreeMap<u16, Vec<u8>> {
        let bytes = encode(exprs);
        let (_, elem) = AttrIter::new(&bytes).next().expect("one LIST_ELEM");
        let (_, data) = AttrIter::new(elem)
            .find(|(attr, _)| *attr == NFTA_EXPR_DATA)
            .expect("NFTA_EXPR_DATA");
        attrs_of(data)
    }

    #[test]
    fn meta_set_emits_key_and_sreg_but_no_dreg() {
        let attrs = data_attrs(&[Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        }]);
        assert_eq!(
            attrs.keys().copied().collect::<Vec<_>>(),
            [NFTA_META_KEY, NFTA_META_SREG]
        );
        assert_eq!(attrs[&NFTA_META_KEY], 3u32.to_be_bytes());
        assert_eq!(attrs[&NFTA_META_SREG], 1u32.to_be_bytes());
    }

    #[test]
    fn exthdr_set_emits_kernel_attribute_layout() {
        let attrs = data_attrs(&[Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        }]);
        // No FLAGS: nft_exthdr_tcp_set_init() rejects it with EINVAL.
        assert_eq!(
            attrs.keys().copied().collect::<Vec<_>>(),
            [
                NFTA_EXTHDR_TYPE,
                NFTA_EXTHDR_OFFSET,
                NFTA_EXTHDR_LEN,
                NFTA_EXTHDR_OP,
                NFTA_EXTHDR_SREG,
            ]
        );
        // NLA_U8 in the kernel policy.
        assert_eq!(attrs[&NFTA_EXTHDR_TYPE], [TCPOPT_MAXSEG]);
        assert_eq!(attrs[&NFTA_EXTHDR_OP], 1u32.to_be_bytes());
    }

    #[test]
    fn exthdr_set_echo_form_carries_the_flags_the_kernel_dumps() {
        let mut b = MessageBuilder::new(0, 0);
        let set = Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        write_expressions_as(&mut b, &[set], WireForm::Echo);
        let bytes = b.as_bytes()[20..].to_vec();
        let (_, elem) = AttrIter::new(&bytes).next().expect("one LIST_ELEM");
        let (_, data) = AttrIter::new(elem)
            .find(|(attr, _)| *attr == NFTA_EXPR_DATA)
            .expect("NFTA_EXPR_DATA");
        assert_eq!(attrs_of(data)[&NFTA_EXTHDR_FLAGS], 0u32.to_be_bytes());
    }

    /// [`data_attrs`], in `form`.
    fn data_attrs_as(exprs: &[Expr], form: WireForm) -> std::collections::BTreeMap<u16, Vec<u8>> {
        let mut b = MessageBuilder::new(0, 0);
        write_expressions_as(&mut b, exprs, form);
        let bytes = b.as_bytes()[20..].to_vec();
        let (_, elem) = AttrIter::new(&bytes).next().expect("one LIST_ELEM");
        let (_, data) = AttrIter::new(elem)
            .find(|(attr, _)| *attr == NFTA_EXPR_DATA)
            .expect("NFTA_EXPR_DATA");
        attrs_of(data)
    }

    /// `nft_dynset_dump` always emits TIMEOUT (0 for none) and FLAGS, but a
    /// request with a TIMEOUT is EOPNOTSUPP for a set without timeouts.
    #[test]
    fn dynset_sends_a_timeout_only_when_it_has_one_and_echoes_zero() {
        let plain = [DynsetExpr::new(DynsetOp::Update, "seen", Register::R0).into()];
        let request = data_attrs_as(&plain, WireForm::Request);
        assert!(!request.contains_key(&NFTA_DYNSET_TIMEOUT));
        assert_eq!(request[&NFTA_DYNSET_FLAGS], 0u32.to_be_bytes());
        assert_eq!(request[&NFTA_DYNSET_OP], 1u32.to_be_bytes());
        let echo = data_attrs_as(&plain, WireForm::Echo);
        assert_eq!(echo[&NFTA_DYNSET_TIMEOUT], 0u64.to_be_bytes());

        let timed = [DynsetExpr::new(DynsetOp::Add, "seen", Register::R0)
            .timeout(std::time::Duration::from_secs(60))
            .invert()
            .into()];
        for form in [WireForm::Request, WireForm::Echo] {
            let attrs = data_attrs_as(&timed, form);
            assert_eq!(attrs[&NFTA_DYNSET_TIMEOUT], 60_000u64.to_be_bytes());
            assert_eq!(attrs[&NFTA_DYNSET_FLAGS], NFT_DYNSET_F_INV.to_be_bytes());
        }
    }

    /// `nft_quota_do_dump` always emits CONSUMED; a request must not (the
    /// quota would start there).
    #[test]
    fn quota_echoes_a_zero_consumption_and_objrefs_round_trip() {
        let quota = [QuotaExpr::new(500).over().into()];
        assert!(!data_attrs_as(&quota, WireForm::Request).contains_key(&NFTA_QUOTA_CONSUMED));
        let echo = data_attrs_as(&quota, WireForm::Echo);
        assert_eq!(echo[&NFTA_QUOTA_CONSUMED], 0u64.to_be_bytes());
        assert_eq!(echo[&NFTA_QUOTA_FLAGS], NFT_QUOTA_F_INV.to_be_bytes());

        let exprs: Vec<Expr> = vec![
            ObjrefExpr::Named {
                object_type: super::super::object::ObjectType::Counter,
                name: "web".into(),
            }
            .into(),
            ObjrefExpr::Map {
                sreg: Register::R0,
                map: "counters".into(),
            }
            .into(),
            QuotaExpr::new(500).into(),
        ];
        let decoded = parse_expressions(&encode(&exprs));
        let want: Vec<RuleExpr> = vec![
            RuleExpr::Objref(ObjrefExpr::Named {
                object_type: super::super::object::ObjectType::Counter,
                name: "web".into(),
            }),
            RuleExpr::Objref(ObjrefExpr::Map {
                sreg: Register::R0,
                map: "counters".into(),
            }),
        ];
        assert_eq!(decoded[..2], want[..]);
        assert!(matches!(
            decoded[2],
            RuleExpr::Quota { bytes: 500, over: false, depleted: false, .. }
        ));
    }

    #[test]
    fn dynset_decodes_typed_and_a_zero_timeout_is_none() {
        let exprs = [
            DynsetExpr::new(DynsetOp::Delete, "s", Register::R0).into(),
            DynsetExpr::new(DynsetOp::Update, "s", Register::R0)
                .timeout(std::time::Duration::from_millis(1500))
                .into(),
        ];
        let mut b = MessageBuilder::new(0, 0);
        write_expressions_as(&mut b, &exprs, WireForm::Echo);
        let decoded = parse_expressions(&b.as_bytes()[20..]);
        assert!(matches!(
            &decoded[0],
            RuleExpr::Dynset { op: DynsetOp::Delete, timeout: None, invert: false, .. }
        ));
        assert!(matches!(
            &decoded[1],
            RuleExpr::Dynset { op: DynsetOp::Update, timeout: Some(t), .. }
                if *t == std::time::Duration::from_millis(1500)
        ));
    }

    /// One per-element statement goes in NFTA_DYNSET_EXPR, several in
    /// NFTA_DYNSET_EXPRESSIONS with NFT_DYNSET_F_EXPR, a flag the kernel
    /// requires and never dumps (#703). Both decode typed; a statement that
    /// does not keeps the whole dynset raw.
    #[test]
    fn dynset_statements_go_as_the_kernel_takes_them_and_decode() {
        let one = DynsetExpr::new(DynsetOp::Add, "seen", Register::R0).counter();
        let limit = LimitExpr::packets(10, LimitUnit::Second).over();
        let several = DynsetExpr::new(DynsetOp::Update, "flood", Register::R0)
            .counter()
            .statement(limit.clone());

        let attrs = data_attrs_as(&[one.clone().into()], WireForm::Request);
        assert!(attrs.contains_key(&NFTA_DYNSET_EXPR));
        assert!(!attrs.contains_key(&NFTA_DYNSET_EXPRESSIONS));
        assert_eq!(attrs[&NFTA_DYNSET_FLAGS], 0u32.to_be_bytes());
        let request = data_attrs_as(&[several.clone().into()], WireForm::Request);
        assert!(request.contains_key(&NFTA_DYNSET_EXPRESSIONS));
        assert_eq!(request[&NFTA_DYNSET_FLAGS], NFT_DYNSET_F_EXPR.to_be_bytes());
        let echo = data_attrs_as(&[several.clone().into()], WireForm::Echo);
        assert_eq!(echo[&NFTA_DYNSET_FLAGS], 0u32.to_be_bytes());

        let statements = |e: &RuleExpr| match e {
            RuleExpr::Dynset { statements, .. } => statements.clone(),
            other => panic!("not a dynset: {other:?}"),
        };
        let counter = RuleExpr::Counter { packets: 0, bytes: 0 };
        let decoded = parse_expressions(&encode(&[one.into(), several.into()]));
        assert_eq!(statements(&decoded[0]), std::slice::from_ref(&counter));
        assert_eq!(statements(&decoded[1]), [counter, RuleExpr::Limit(limit)]);

        let mut b = MessageBuilder::new(0, 0);
        b.append_attr_str(NFTA_DYNSET_SET_NAME, "seen");
        b.append_attr_u32_be(NFTA_DYNSET_OP, 0);
        b.append_attr_u32_be(NFTA_DYNSET_SREG_KEY, 1);
        let odd = b.nest_start(NFTA_DYNSET_EXPR | 0x8000);
        b.append_attr_str(NFTA_EXPR_NAME, "future");
        b.nest_end(odd);
        let decoded = parse_expressions(&build_elem("dynset", &b.as_bytes()[16..]));
        assert!(matches!(&decoded[0], RuleExpr::Unknown { name, .. } if name == "dynset"));
    }

    /// `nft_osf_init` refuses a FLAGS that is not NFT_OSF_F_VERSION, 0
    /// included, and `nft_osf_dump` always writes it (#703).
    #[test]
    fn osf_sends_flags_only_for_a_version_and_echoes_them_always() {
        let plain = [Expr::Osf { dreg: Register::R0, ttl: OsfTtl::Skip, version: false }];
        assert!(!data_attrs_as(&plain, WireForm::Request).contains_key(&NFTA_OSF_FLAGS));
        let echo = data_attrs_as(&plain, WireForm::Echo);
        assert_eq!(echo[&NFTA_OSF_FLAGS], 0u32.to_be_bytes());
        assert_eq!(echo[&NFTA_OSF_TTL], [2]);
        let versioned = [Expr::Osf { dreg: Register::R0, ttl: OsfTtl::Loose, version: true }];
        let request = data_attrs_as(&versioned, WireForm::Request);
        assert_eq!(request[&NFTA_OSF_FLAGS], NFT_OSF_F_VERSION.to_be_bytes());

        let decoded = parse_expressions(&encode(&[plain[0].clone(), versioned[0].clone()]));
        assert_eq!(
            decoded,
            [
                RuleExpr::Osf { dreg: Register::R0, ttl: OsfTtl::Skip, version: false },
                RuleExpr::Osf { dreg: Register::R0, ttl: OsfTtl::Loose, version: true },
            ]
        );
    }

    #[test]
    fn roundtrip_meta_set_and_exthdr() {
        let load = Expr::Exthdr {
            dreg: Register::R1,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        let set = Expr::ExthdrSet {
            sreg: Register::R1,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        let meta_set = Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R2,
        };
        assert_eq!(
            parse_expressions(&encode(&[load, set, meta_set])),
            vec![
                RuleExpr::Exthdr {
                    dreg: Register::R1,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R1,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R2,
                },
            ]
        );
    }

    #[test]
    fn exthdr_with_present_flag_decodes_as_unknown() {
        // `tcp option maxseg exists`: NFT_EXTHDR_F_PRESENT is not modelled.
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_EXTHDR_DREG, 1);
            b.append_attr_u8(NFTA_EXTHDR_TYPE, TCPOPT_MAXSEG);
            b.append_attr_u32_be(NFTA_EXTHDR_OFFSET, 0);
            b.append_attr_u32_be(NFTA_EXTHDR_LEN, 1);
            b.append_attr_u32_be(NFTA_EXTHDR_FLAGS, 1);
            b.append_attr_u32_be(NFTA_EXTHDR_OP, 1);
        });
        let decoded = parse_expressions(&build_elem("exthdr", &data));
        assert!(
            matches!(decoded.as_slice(), [RuleExpr::Unknown { name, .. }] if name == "exthdr"),
            "got {decoded:?}"
        );
    }

    #[test]
    fn rule_set_mark_loads_then_sets() {
        let rule = Rule::new("t", "c").set_mark(0x10);
        assert_eq!(
            parse_expressions(&encode(&rule.exprs())),
            vec![
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 0x10u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn rule_clamp_tcp_mss_is_the_nft_statement() {
        let rule = Rule::new("t", "c").clamp_tcp_mss(1360);
        let decoded = parse_expressions(&encode(&rule.exprs()));
        // `nft add rule ... tcp option maxseg size set 1360` (nftables
        // tests/py/any/tcpopt.t.payload): an immediate and the exthdr
        // write, nothing else — behind nlink's `meta l4proto tcp` guard.
        // No load-and-compare first: the kernel already refuses to raise
        // an MSS, and a load would end rule evaluation for SYNs without the
        // option, skipping whatever follows the clamp in the rule.
        assert_eq!(
            decoded,
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::L4Proto,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![6],
                },
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: vec![0x05, 0x50],
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R0,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
            ]
        );
    }

    #[test]
    fn rule_match_tcp_flags_masks_the_flags_byte() {
        let rule =
            Rule::new("t", "c").match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST);
        let decoded = parse_expressions(&encode(&rule.exprs()));
        assert_eq!(
            decoded[2],
            RuleExpr::Payload {
                dreg: Register::R0,
                base: PayloadBase::Transport,
                offset: 13,
                len: 1,
            }
        );
        assert_eq!(
            decoded[4],
            RuleExpr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![TcpFlags::SYN.bits()],
            }
        );
    }

    // ---- Writers must send what the kernel echoes, and nothing it drops.
    // Each of these sat behind a green suite because no `is_empty()` diff
    // assertion ever declared the shape; `nftables_echo.rs` now does, and
    // these pin the bytes.

    #[test]
    fn lookup_sends_the_flags_the_kernel_always_dumps() {
        let attrs = data_attrs(&[LookupExpr::new("s", Register::R0).into()]);
        assert_eq!(attrs[&NFTA_LOOKUP_FLAGS], 0u32.to_be_bytes());
    }

    #[test]
    fn limit_sends_flags_and_the_burst_the_kernel_stores() {
        let attrs = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).burst(0).into()]);
        assert_eq!(attrs[&NFTA_LIMIT_FLAGS], 0u32.to_be_bytes());
        // A packet limit's burst 0 becomes NFT_LIMIT_PKT_BURST_DEFAULT.
        assert_eq!(attrs[&NFTA_LIMIT_BURST], 5u32.to_be_bytes());
        let explicit = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).burst(20).into()]);
        assert_eq!(explicit[&NFTA_LIMIT_BURST], 20u32.to_be_bytes());
    }

    #[test]
    fn syslog_log_sends_the_default_level_and_group_log_does_not() {
        let syslog = data_attrs(&[LogExpr::new().prefix("p").into()]);
        assert_eq!(syslog[&NFTA_LOG_LEVEL], NFT_LOGLEVEL_WARNING.to_be_bytes());
        assert!(!syslog.contains_key(&NFTA_LOG_GROUP));

        // A group makes it NF_LOG_TYPE_ULOG, whose dump has no level.
        let group = data_attrs(&[LogExpr::new().group(5).into()]);
        assert!(!group.contains_key(&NFTA_LOG_LEVEL));
        assert_eq!(group[&NFTA_LOG_GROUP], 5u16.to_be_bytes());
    }

    /// #703: a log's level and flags (syslog) and its snaplen and queue
    /// threshold (nflog) are written as the kernel echoes them and read
    /// back; the default level reads as none.
    #[test]
    fn log_options_round_trip() {
        let syslog = LogExpr::new()
            .prefix("p")
            .level(LogLevel::Info)
            .flags(LogFlags::TCP_SEQUENCE | LogFlags::SKUID);
        let attrs = data_attrs(&[syslog.clone().into()]);
        assert_eq!(attrs[&NFTA_LOG_LEVEL], 6u32.to_be_bytes());
        assert_eq!(attrs[&NFTA_LOG_FLAGS], 0x09u32.to_be_bytes());
        let nflog = LogExpr::new().group(2).snaplen(64).queue_threshold(10);
        let attrs = data_attrs(&[nflog.clone().into()]);
        assert_eq!(attrs[&NFTA_LOG_SNAPLEN], 64u32.to_be_bytes());
        assert_eq!(attrs[&NFTA_LOG_QTHRESHOLD], 10u16.to_be_bytes());
        assert!(!attrs.contains_key(&NFTA_LOG_LEVEL));

        let audit = LogExpr::new().level(LogLevel::Audit).flags(LogFlags::ALL);
        let warn = LogExpr::new().level(LogLevel::Warning);
        assert_eq!(
            parse_expressions(&encode(&[
                syslog.clone().into(),
                nflog.clone().into(),
                audit.clone().into(),
                warn.into(),
            ])),
            [
                RuleExpr::Log(syslog),
                RuleExpr::Log(nflog),
                RuleExpr::Log(audit),
                // The kernel's default level is no level.
                RuleExpr::Log(LogExpr::new()),
            ]
        );
        // A level the kernel does not have, or a flag it would refuse,
        // reads as unknown rather than as something else.
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        b.append_attr_u32_be(NFTA_LOG_LEVEL, 9);
        assert!(parse_log(&b.as_bytes()[start..]).is_none());
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        b.append_attr_u32_be(NFTA_LOG_FLAGS, 0x10);
        assert!(parse_log(&b.as_bytes()[start..]).is_none());
    }

    /// #703: `tproxy`, `socket` and `synproxy` as the kernel echoes them,
    /// and read back.
    #[test]
    fn tproxy_socket_and_synproxy_round_trip() {
        let full = SynproxyExpr::new().mss(1460).wscale(7).timestamp().sack_perm();
        let attrs = data_attrs(&[full.clone().into()]);
        assert_eq!(attrs[&NFTA_SYNPROXY_FLAGS], 0x0fu32.to_be_bytes());
        let mss_only = SynproxyExpr::new().mss(1400);
        let exprs = [
            Expr::Tproxy {
                family: 2,
                sreg_addr: Some(Register::R0),
                sreg_port: Some(Register::R1),
            },
            Expr::Tproxy {
                family: 0,
                sreg_addr: None,
                sreg_port: Some(Register::R0),
            },
            Expr::Socket {
                dreg: Register::R0,
                key: SocketKey::Mark,
            },
            full.clone().into(),
            mss_only.clone().into(),
        ];
        assert_eq!(
            parse_expressions(&encode(&exprs)),
            [
                RuleExpr::Tproxy {
                    family: 2,
                    sreg_addr: Some(Register::R0),
                    sreg_port: Some(Register::R1),
                },
                RuleExpr::Tproxy {
                    family: 0,
                    sreg_addr: None,
                    sreg_port: Some(Register::R0),
                },
                RuleExpr::Socket {
                    dreg: Register::R0,
                    key: SocketKey::Mark,
                },
                RuleExpr::Synproxy(full),
                RuleExpr::Synproxy(mss_only),
            ]
        );
    }

    /// #703: `numgen` and `hash` as the kernel echoes them — a jhash's seed
    /// only when given, an offset only when not 0 — and read back.
    #[test]
    fn numgen_and_hash_round_trip() {
        let numgen = Expr::Numgen {
            dreg: Register::R0,
            kind: NumgenKind::Random,
            modulus: 10,
            offset: 5,
        };
        let jhash = |seed, offset| Expr::Hash {
            dreg: Register::R0,
            kind: HashKind::Jenkins,
            sreg: Some(Register::R1),
            len: 8,
            modulus: 4,
            seed,
            offset,
        };
        let sym = Expr::Hash {
            dreg: Register::R0,
            kind: HashKind::Sym,
            sreg: None,
            len: 0,
            modulus: 2,
            seed: None,
            offset: 0,
        };
        let attrs = data_attrs(&[jhash(None, 0)]);
        assert!(!attrs.contains_key(&NFTA_HASH_SEED) && !attrs.contains_key(&NFTA_HASH_OFFSET));
        let attrs = data_attrs(std::slice::from_ref(&sym));
        assert!(!attrs.contains_key(&NFTA_HASH_LEN) && !attrs.contains_key(&NFTA_HASH_SREG));
        let back = parse_expressions(&encode(&[numgen, jhash(Some(0xdead), 2), sym]));
        assert_eq!(
            back,
            [
                RuleExpr::Numgen {
                    dreg: Register::R0,
                    kind: NumgenKind::Random,
                    modulus: 10,
                    offset: 5,
                },
                RuleExpr::Hash {
                    dreg: Register::R0,
                    kind: HashKind::Jenkins,
                    sreg: Some(Register::R1),
                    len: 8,
                    modulus: 4,
                    seed: Some(0xdead),
                    offset: 2,
                },
                RuleExpr::Hash {
                    dreg: Register::R0,
                    kind: HashKind::Sym,
                    sreg: None,
                    len: 0,
                    modulus: 2,
                    seed: None,
                    offset: 0,
                },
            ]
        );
    }

    /// #703: `queue`, `dup` and `fwd` as the kernel echoes them, and read
    /// back.
    #[test]
    fn queue_dup_and_fwd_round_trip() {
        let single = QueueExpr::num(3).flags(QueueFlags::BYPASS);
        let attrs = data_attrs(&[single.clone().into()]);
        assert_eq!(attrs[&NFTA_QUEUE_TOTAL], 1u16.to_be_bytes(), "a total is always echoed");
        let range = QueueExpr::range(1, 4).flags(QueueFlags::BYPASS | QueueFlags::FANOUT);
        assert_eq!((range.num, range.total), (1, 4));
        let by_reg = QueueExpr::register(Register::R1);
        let dup = Expr::Dup {
            sreg_addr: Some(Register::R0),
            sreg_dev: Some(Register::R1),
        };
        let fwd = Expr::Fwd {
            sreg_dev: Register::R0,
            sreg_addr: Some((Register::R1, 2)),
        };
        assert_eq!(
            parse_expressions(&encode(&[
                single.clone().into(),
                range.clone().into(),
                by_reg.clone().into(),
                dup,
                fwd,
            ])),
            [
                RuleExpr::Queue(single),
                RuleExpr::Queue(range),
                RuleExpr::Queue(by_reg),
                RuleExpr::Dup {
                    sreg_addr: Some(Register::R0),
                    sreg_dev: Some(Register::R1),
                },
                RuleExpr::Fwd {
                    sreg_dev: Register::R0,
                    sreg_addr: Some((Register::R1, 2)),
                },
            ]
        );
    }

    #[test]
    fn tcp_reset_reject_omits_the_icmp_code() {
        let rst = data_attrs(&[Expr::Reject {
            reject_type: NFT_REJECT_TCP_RST,
            icmp_code: 0,
        }]);
        assert_eq!(rst.keys().copied().collect::<Vec<_>>(), [NFTA_REJECT_TYPE]);

        // The ICMP types require it.
        for reject_type in [NFT_REJECT_ICMP_UNREACH, NFT_REJECT_ICMPX_UNREACH] {
            let icmp = data_attrs(&[Expr::Reject {
                reject_type,
                icmp_code: 1,
            }]);
            assert_eq!(icmp[&NFTA_REJECT_ICMP_CODE], [1]);
        }
    }

    #[test]
    fn flow_offload_names_the_flowtable_with_the_expression_attribute() {
        let attrs = data_attrs(&[Expr::FlowOffload { flowtable: "ft".into() }]);
        // NFTA_FLOW_TABLE_NAME (1), not NFTA_FLOWTABLE_NAME (2) — the
        // latter is above the expression's NFTA_FLOW_MAX.
        assert_eq!(attrs.keys().copied().collect::<Vec<_>>(), [NFTA_FLOW_TABLE_NAME]);
        assert_eq!(attrs[&NFTA_FLOW_TABLE_NAME], b"ft\0");
    }

    #[test]
    fn set_matchers_carry_the_nfproto_guard() {
        for rule in [
            Rule::new("t", "c").match_saddr_in_set("s"),
            Rule::new("t", "c").match_daddr_in_set("s"),
        ] {
            let decoded = parse_expressions(&encode(&rule.exprs()));
            assert_eq!(
                decoded[..2],
                [
                    RuleExpr::Meta {
                        dreg: Register::R0,
                        key: MetaKey::NfProto,
                    },
                    RuleExpr::Cmp {
                        sreg: Register::R0,
                        op: CmpOp::Eq,
                        data: vec![NFPROTO_IPV4],
                    },
                ],
                "an IPv4 set match in an inet chain needs `meta nfproto ipv4`"
            );
        }
    }

    // ---- ct / rt / byteorder / bitwise / lookup decode, and the mark,
    // priority, connmark and path-MTU helpers built from them.

    #[test]
    fn roundtrip_ct_rt_byteorder_bitwise_lookup() {
        let exprs = [
            Expr::Ct {
                dreg: Register::R0,
                key: CtKey::Mark,
            },
            Expr::CtSet {
                key: CtKey::Mark,
                sreg: Register::R1,
            },
            Expr::Rt {
                dreg: Register::R2,
                key: RtKey::TcpMss,
            },
            Expr::Byteorder {
                sreg: Register::R2,
                dreg: Register::R3,
                op: ByteorderOp::Hton,
                len: 2,
                size: 2,
            },
            Expr::Bitwise {
                sreg: Register::R0,
                dreg: Register::R0,
                len: 4,
                mask: vec![0xff, 0, 0, 0],
                xor: vec![1, 0, 0, 0],
            },
            LookupExpr::new("s", Register::R0).into(),
            LookupExpr::new("s", Register::R1).invert().into(),
            LookupExpr::new("m", Register::R2).dreg(Register::Verdict).into(),
        ];
        assert_eq!(
            parse_expressions(&encode(&exprs)),
            [
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R1,
                },
                RuleExpr::Rt {
                    dreg: Register::R2,
                    key: RtKey::TcpMss,
                },
                RuleExpr::Byteorder {
                    sreg: Register::R2,
                    dreg: Register::R3,
                    op: ByteorderOp::Hton,
                    len: 2,
                    size: 2,
                },
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: vec![0xff, 0, 0, 0],
                    xor: vec![1, 0, 0, 0],
                },
                RuleExpr::Lookup {
                    set: "s".into(),
                    sreg: Register::R0,
                    dreg: None,
                    invert: false,
                },
                RuleExpr::Lookup {
                    set: "s".into(),
                    sreg: Register::R1,
                    dreg: None,
                    invert: true,
                },
                RuleExpr::Lookup {
                    set: "m".into(),
                    sreg: Register::R2,
                    dreg: Some(Register::Verdict),
                    invert: false,
                },
            ]
        );
    }

    #[test]
    fn shapes_the_typed_variants_do_not_describe_stay_unknown() {
        // `ct original zone set`: a direction `RuleExpr::CtSet` cannot
        // carry. (A directional load is `CtDirectional`.)
        let directional = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_CT_SREG, 1);
            b.append_attr_u32_be(NFTA_CT_KEY, 17);
            b.append_attr_u8(NFTA_CT_DIRECTION, 0);
        });
        // A lookup flag this decoder does not know.
        let unknown_flag = build_attrs(|b| {
            b.append_attr_str(NFTA_LOOKUP_SET, "s");
            b.append_attr_u32_be(NFTA_LOOKUP_SREG, 1);
            b.append_attr_u32_be(NFTA_LOOKUP_FLAGS, 2);
        });
        // `meta mark >> 8`: NFT_BITWISE_RSHIFT (2) with a data operand.
        let shift = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_BITWISE_SREG, 1);
            b.append_attr_u32_be(NFTA_BITWISE_DREG, 1);
            b.append_attr_u32_be(NFTA_BITWISE_LEN, 4);
            b.append_attr_u32_be(NFTA_BITWISE_OP, 2);
        });
        for (name, data) in [("ct", directional), ("lookup", unknown_flag), ("bitwise", shift)] {
            let decoded = parse_expressions(&build_elem(name, &data));
            assert!(
                matches!(decoded.as_slice(), [RuleExpr::Unknown { name: n, .. }] if n == name),
                "{name}: got {decoded:?}"
            );
        }
    }

    #[test]
    fn set_mark_masked_keeps_the_bits_outside_the_mask() {
        let rule = Rule::new("t", "c").set_mark_masked(0x1234, 0xff);
        assert_eq!(
            parse_expressions(&encode(&rule.exprs())),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                },
                // (mark & !0xff) ^ (0x1234 & 0xff), host order like the mark.
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: (!0xffu32).to_ne_bytes().to_vec(),
                    xor: 0x34u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn match_mark_masked_compares_only_the_masked_bits() {
        let rule = Rule::new("t", "c").match_mark_masked(0x1234, 0xff);
        let decoded = parse_expressions(&encode(&rule.exprs()));
        assert_eq!(
            decoded[1..],
            [
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: 0xffu32.to_ne_bytes().to_vec(),
                    xor: vec![0; 4],
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: 0x34u32.to_ne_bytes().to_vec(),
                },
            ]
        );
    }

    #[test]
    fn set_priority_writes_the_classid() {
        let rule = Rule::new("t", "c").set_priority(crate::TcHandle::new(1, 0x10));
        assert_eq!(
            parse_expressions(&encode(&rule.exprs())),
            [
                // `meta priority set 1:10` is `immediate reg 1 0x00010010`.
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 0x0001_0010u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Priority,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn connmark_helpers_are_the_iptables_translations() {
        // CONNMARK --save-mark: `ct mark set mark`.
        let save = Rule::new("t", "c").save_mark_to_ct();
        assert_eq!(
            parse_expressions(&encode(&save.exprs())),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
        // CONNMARK --restore-mark: `meta mark set ct mark`.
        let restore = Rule::new("t", "c").restore_mark_from_ct();
        assert_eq!(
            parse_expressions(&encode(&restore.exprs())),
            [
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
        let set = Rule::new("t", "c").set_ct_mark(7).match_ct_mark(7);
        assert_eq!(
            parse_expressions(&encode(&set.exprs())),
            [
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 7u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                },
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: 7u32.to_ne_bytes().to_vec(),
                },
            ]
        );
    }

    #[test]
    fn clamp_tcp_mss_to_pmtu_is_the_nft_statement() {
        // `tcp option maxseg size set rt mtu` (nftables
        // tests/py/inet/rt.t.payload): rt load tcpmss, byteorder
        // hton(reg, 2, 2), exthdr write — behind the l4proto guard.
        let rule = Rule::new("t", "c").clamp_tcp_mss_to_pmtu();
        let decoded = parse_expressions(&encode(&rule.exprs()));
        assert_eq!(
            decoded[2..],
            [
                RuleExpr::Rt {
                    dreg: Register::R0,
                    key: RtKey::TcpMss,
                },
                RuleExpr::Byteorder {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    op: ByteorderOp::Hton,
                    len: 2,
                    size: 2,
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R0,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
            ]
        );
    }

    // ---- 0.30 payload structs: what each setter puts on the wire.

    #[test]
    fn lookup_invert_and_map_write_their_attributes() {
        let inverted = data_attrs(&[LookupExpr::new("s", Register::R0).invert().into()]);
        assert_eq!(inverted[&NFTA_LOOKUP_FLAGS], NFT_LOOKUP_F_INV.to_be_bytes());
        assert!(!inverted.contains_key(&NFTA_LOOKUP_DREG));

        let map = data_attrs(&[LookupExpr::new("m", Register::R0)
            .dreg(Register::Verdict)
            .into()]);
        assert_eq!(map[&NFTA_LOOKUP_DREG], 0u32.to_be_bytes());
        assert_eq!(map[&NFTA_LOOKUP_FLAGS], 0u32.to_be_bytes());
    }

    #[test]
    fn limit_over_sends_the_inverse_flag() {
        let over = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).over().into()]);
        assert_eq!(over[&NFTA_LIMIT_FLAGS], NFT_LIMIT_F_INV.to_be_bytes());
    }

    #[test]
    fn rule_expr_pushes_payload_structs() {
        let rule = Rule::new("t", "c")
            .expr(LogExpr::new().group(3))
            .expr(MasqExpr::new());
        assert!(matches!(
            rule.exprs().as_slice(),
            [Expr::Log(LogExpr { group: Some(3), .. }), Expr::Masquerade(_)]
        ));
    }

    // ---- set lookups by packet field, and the raw escape hatch.

    #[test]
    fn match_in_set_loads_the_field_behind_its_guard() {
        let rule = Rule::new("t", "c").match_in_set(PacketField::Ip6Daddr, "s6");
        assert_eq!(
            parse_expressions(&encode(&rule.exprs())),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::NfProto,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![10],
                },
                RuleExpr::Payload {
                    dreg: Register::R0,
                    base: PayloadBase::Network,
                    offset: 24,
                    len: 16,
                },
                RuleExpr::Lookup {
                    set: "s6".into(),
                    sreg: Register::R0,
                    dreg: None,
                    invert: false,
                },
            ]
        );
        let ports = Rule::new("t", "c").match_not_in_set(PacketField::UdpDport, "p");
        let decoded = parse_expressions(&encode(&ports.exprs()));
        assert_eq!(
            decoded[2],
            RuleExpr::Payload {
                dreg: Register::R0,
                base: PayloadBase::Transport,
                offset: 2,
                len: 2,
            }
        );
        assert!(matches!(&decoded[3], RuleExpr::Lookup { invert: true, .. }));
        assert_eq!(PacketField::UdpDport.key_type(), SetKeyType::InetService);
    }

    #[test]
    fn raw_expressions_write_their_payload_or_no_nest() {
        let bytes = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_META_DREG, 1);
            b.append_attr_u32_be(NFTA_META_KEY, MetaKey::Mark as u32);
        });
        // A raw `meta` written from bytes decodes like the typed one.
        assert_eq!(
            parse_expressions(&encode(&[RawExpr::new("meta", bytes).into()])),
            [RuleExpr::Meta {
                dreg: Register::R0,
                key: MetaKey::Mark,
            }]
        );
        // `without_data` writes the name and nothing else.
        let notrack = encode(&[RawExpr::without_data("notrack").into()]);
        let (_, elem) = AttrIter::new(&notrack).next().unwrap();
        let attrs: Vec<u16> = AttrIter::new(elem).map(|(t, _)| t).collect();
        assert_eq!(attrs, [NFTA_EXPR_NAME]);
    }

    /// #480: the `ip`/`ip6` reject expressions do not handle ICMPX, so a
    /// `reject()` there is sent as the family's port unreachable — the
    /// code the kernel's own icmpx mapping gives.
    #[test]
    fn an_icmpx_reject_is_sent_as_the_familys_icmp() {
        let reject = |t, c| Expr::Reject {
            reject_type: t,
            icmp_code: c,
        };
        let sent = |exprs: &[Expr], family| match exprs_for_family(exprs, family).as_ref() {
            [
                Expr::Reject {
                    reject_type,
                    icmp_code,
                },
            ] => (*reject_type, *icmp_code),
            other => panic!("{other:?}"),
        };
        let port = [reject(
            NFT_REJECT_ICMPX_UNREACH,
            NFT_REJECT_ICMPX_PORT_UNREACH,
        )];
        assert_eq!(sent(&port, Family::Ip), (NFT_REJECT_ICMP_UNREACH, 3));
        assert_eq!(sent(&port, Family::Ip6), (NFT_REJECT_ICMP_UNREACH, 4));
        for family in [Family::Inet, Family::Bridge, Family::Netdev] {
            assert_eq!(sent(&port, family), (NFT_REJECT_ICMPX_UNREACH, 1));
        }
        let admin = [reject(
            NFT_REJECT_ICMPX_UNREACH,
            NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
        )];
        assert_eq!(sent(&admin, Family::Ip), (NFT_REJECT_ICMP_UNREACH, 13));
        assert_eq!(sent(&admin, Family::Ip6), (NFT_REJECT_ICMP_UNREACH, 1));
        // Not an ICMPX reject: untouched.
        let rst = [reject(NFT_REJECT_TCP_RST, 0)];
        assert_eq!(sent(&rst, Family::Ip), (NFT_REJECT_TCP_RST, 0));
    }

    /// A TCP reset gets one `meta l4proto tcp` guard — not a second one
    /// behind a port match that already carries it.
    #[test]
    fn a_tcp_reset_is_guarded_once() {
        let l4 = |r: &Rule| {
            r.exprs()
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        Expr::Meta {
                            key: MetaKey::L4Proto,
                            ..
                        }
                    )
                })
                .count()
        };
        let bare = Rule::new("t", "c").reject_tcp_reset();
        assert_eq!(l4(&bare), 1);
        assert!(
            matches!(bare.exprs().last(), Some(Expr::Reject { reject_type, .. }) if *reject_type == NFT_REJECT_TCP_RST)
        );
        let after_port = Rule::new("t", "c").match_tcp_dport(22).reject_tcp_reset();
        assert_eq!(l4(&after_port), 1);
        let icmp = Rule::new("t", "c").reject_icmp(3);
        assert!(matches!(
            icmp.exprs().as_slice(),
            [
                Expr::Meta {
                    key: MetaKey::NfProto,
                    ..
                },
                Expr::Cmp { .. },
                Expr::Reject { .. }
            ]
        ));
    }
}
