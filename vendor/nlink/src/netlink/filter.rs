//! TC filter builders and configuration.
//!
//! This module provides strongly-typed configuration for TC filters including
//! u32, flower, matchall, and bpf filters.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::filter::{U32Filter, FlowerFilter, MatchallFilter};
//! use nlink::TcHandle;
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a u32 filter to match destination port 80
//! let filter = U32Filter::new()
//!     .classid(TcHandle::new(1, 0x10))
//!     .match_dst_port(80)
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//!
//! // Add a flower filter to match TCP traffic to 10.0.0.0/8
//! let filter = FlowerFilter::new()
//!     .classid(TcHandle::new(1, 0x20))
//!     .ip_proto_tcp()
//!     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//!
//! // Add a matchall filter with an action
//! let filter = MatchallFilter::new()
//!     .classid(TcHandle::new(1, 0x30))
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use super::{
    Connection,
    action::{ActionList, Estimator},
    builder::MessageBuilder,
    connection::{ack_request, create_request, replace_request},
    error::{Error, Result},
    eth_proto::EthProto,
    interface_ref::InterfaceRef,
    message::NlMsgType,
    protocol::Route,
    tc_handle::{FilterPriority, TcHandle},
    types::tc::{
        TcMsg, TcaAttr,
        filter::{basic, bpf, ematch, flower, fw, matchall, tcindex, u32 as u32_mod},
    },
};

/// Ethernet protocol: all protocols.
const ETH_P_ALL: u16 = EthProto::ALL.as_u16();

// ============================================================================
// FilterConfig trait
// ============================================================================

/// Trait for filter configurations that can be applied.
pub trait FilterConfig: Send + Sync {
    /// Get the filter kind (e.g., "u32", "flower", "matchall").
    fn kind(&self) -> &'static str;

    /// Write the filter options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Get the classid if set.
    fn classid(&self) -> Option<u32>;

    /// Get the chain index if set.
    fn chain(&self) -> Option<u32> {
        None
    }

    /// Set the chain index (tc(8) `chain N`).
    ///
    /// Default no-op so external `FilterConfig` impls stay
    /// source-compatible; every config nlink ships overrides this to
    /// store the value, so generic callers (e.g. the `tc` binary's
    /// `--chain` flag) can set the chain without naming the concrete
    /// type.
    fn set_chain(&mut self, chain: u32) {
        let _ = chain;
    }

    /// The ethertype this filter matches (tc(8) `protocol ip|ipv6|all|…`).
    ///
    /// `None` means "unset" and `add_filter` falls back to
    /// [`DEFAULT_FILTER_PROTOCOL`].
    ///
    /// Every filter config nlink ships has a public `.protocol()` **setter**,
    /// and until 0.25 nothing ever read the value back: `add_filter`
    /// hardcoded `ETH_P_IP`. On a clsact/ingress hook that meant IPv6, ARP
    /// and VLAN traffic never reached the filter at all, with no error (#201).
    /// This accessor is what closes that gap.
    ///
    /// Defaulted so external impls stay source-compatible, same as
    /// [`set_chain`](Self::set_chain).
    fn protocol(&self) -> Option<EthProto> {
        None
    }

    /// Set the ethertype the filter is installed under (tc(8) `protocol`).
    ///
    /// The `*_full` entry points take the protocol as an argument and call
    /// this with it before writing the options, so a config that derives
    /// something from its protocol sees the one it is installed under:
    /// flower takes its TCA_FLOWER_KEY_ETH_TYPE from it, as tc(8) does
    /// (#433). Every config nlink ships that carries a protocol stores it.
    ///
    /// Default no-op so external `FilterConfig` impls stay source-compatible,
    /// same as [`set_chain`](Self::set_chain).
    fn set_protocol(&mut self, protocol: EthProto) {
        let _ = protocol;
    }

    /// The filter priority, a.k.a. `pref` (tc(8) `prio N`).
    ///
    /// `None` means "unset", and the kernel auto-assigns. As with
    /// [`protocol`](Self::protocol), every shipped config had a setter whose
    /// value `add_filter` silently discarded — so explicit priority ordering
    /// was ignored and filters landed in an unintended evaluation order
    /// relative to operator-installed rules (#201).
    fn priority(&self) -> Option<FilterPriority> {
        None
    }

    /// The handle to install the filter under when the caller gives none:
    /// one the kind derives from what it matches, as tc(8) does. A route
    /// filter's is its key, and the kernel refuses it without one (#825).
    ///
    /// Called after [`resolve_devices`](Self::resolve_devices). `None`
    /// leaves the kernel to choose. Defaulted so external impls stay
    /// source-compatible.
    fn default_handle(&self) -> Option<TcHandle> {
        None
    }

    /// The devices the filter names rather than indexes — a
    /// [`MirredAction::to_dev`](super::action::MirredAction::to_dev)
    /// target, a [`RouteFilter::from_if`] — which the connection that
    /// installs it resolves in its own namespace (#645). None by default.
    fn device_names(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Take the ifindex of each name [`device_names`](Self::device_names)
    /// gave from `ifindexes`; an error for one it does not have.
    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        let _ = ifindexes;
        Ok(())
    }

    /// The rate estimator for the filter's actions, sent as `TCA_RATE`
    /// (#792): its [`ActionList::with_estimator`]. None by default.
    fn estimator(&self) -> Option<Estimator> {
        None
    }
}

/// [`FilterConfig::device_names`], [`FilterConfig::resolve_devices`] and
/// [`FilterConfig::estimator`] for a filter that names devices only in its
/// `actions`.
macro_rules! from_actions {
    () => {
        fn estimator(&self) -> Option<Estimator> {
            self.actions.as_ref().and_then(ActionList::estimator)
        }

        fn device_names(&self) -> Vec<&str> {
            self.actions
                .as_ref()
                .map(ActionList::device_names)
                .unwrap_or_default()
        }

        fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
            match &mut self.actions {
                Some(actions) => actions.resolve_devices(ifindexes),
                None => Ok(()),
            }
        }
    };
}

/// The filter's [`FilterConfig::estimator`] as `TCA_RATE`, which the kernel
/// hands to every action the filter creates (#792).
fn write_estimator(builder: &mut MessageBuilder, config: &impl FilterConfig) {
    use zerocopy::IntoBytes;
    if let Some(estimator) = config.estimator() {
        builder.append_attr(TcaAttr::Rate as u16, estimator.parms().as_bytes());
    }
}

/// The ethertype `add_filter` falls back to when a [`FilterConfig`] leaves
/// [`protocol`](FilterConfig::protocol) unset.
///
/// `ETH_P_IP` (0x0800), which is what `add_filter` used to hardcode
/// unconditionally. Every filter config nlink ships overrides `protocol()`
/// with its own field, so in practice this only applies to external impls
/// written against the pre-0.25 trait.
///
/// **The observable change in 0.25** is not this constant — it is that the
/// shipped configs' own defaults now reach the wire. `MatchallFilter` and
/// `FlowerFilter` default to `ETH_P_ALL` (0x0003), so a filter that used to
/// be silently installed as IPv4-only now matches all traffic, as its builder
/// always claimed.
pub const DEFAULT_FILTER_PROTOCOL: EthProto = EthProto::IP;

// ============================================================================
// U32Filter
// ============================================================================

/// U32 filter configuration.
///
/// The u32 filter is a versatile classifier that matches packets based on
/// arbitrary fields in the packet header using a set of keys (value/mask pairs).
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::U32Filter;
///
/// // Match destination port 80 (HTTP)
/// let filter = U32Filter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .match_dst_port(80)
///     .build();
///
/// // Match source IP 192.168.1.0/24
/// let filter = U32Filter::new()
///     .classid(nlink::TcHandle::new(1, 0x20))
///     .match_src_ipv4("192.168.1.0".parse().unwrap(), 24)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct U32Filter {
    /// Target class ID.
    classid: Option<u32>,
    /// Selector keys.
    keys: Vec<u32_mod::TcU32Key>,
    /// Hash table this filter belongs to (`TCA_U32_HASH`).
    ht: Option<u32>,
    /// Hash table link to chase on match (`TCA_U32_LINK`).
    link: Option<u32>,
    /// Hash divisor (for creating hash tables).
    divisor: Option<u32>,
    /// Hash key — (mask, offset) pair packed into `sel.hmask`/`hoff`.
    hashkey: Option<(u32, i16)>,
    /// Match mark value/mask.
    mark: Option<(u32, u32)>,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_IP).
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Filter flags (`TCA_CLS_FLAGS_SKIP_HW`/`SKIP_SW`).
    flags: u32,
    /// `offset …`: where the next header starts, for the keys of the
    /// table this filter links to (#492).
    offset: U32Offset,
}

/// The selector's `offset` fields (`tc … u32 offset [plus N] [at N]
/// [mask N] [shift N] [eat]`).
#[derive(Debug, Clone, Copy, Default)]
struct U32Offset {
    /// `TC_U32_OFFSET` / `TC_U32_VAROFFSET` / `TC_U32_EAT`.
    flags: u8,
    plus: u16,
    at: i16,
    mask: u16,
    shift: u8,
}

impl U32Filter {
    /// A u32 handle: hash table `htid`, bucket and node, which `tc(8)`
    /// writes `htid:bucket:node` in hex — `htid << 20 | bucket << 12 |
    /// node`. `U32Filter::handle(2, 0, 0)` is `2:`, the form [`ht`],
    /// [`link`] and a table-creating filter's handle take.
    ///
    /// Not a qdisc handle: `2:` is `0x00200000` here and `0x00020000` as
    /// a [`TcHandle`] (#492).
    ///
    /// [`ht`]: Self::ht
    /// [`link`]: Self::link
    pub const fn handle(htid: u16, bucket: u8, node: u16) -> u32 {
        ((htid as u32 & 0xFFF) << 20) | ((bucket as u32) << 12) | (node as u32 & 0xFFF)
    }

    /// Create a new u32 filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0800, // ETH_P_IP
            priority: 0,
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority (lower = higher priority).
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol (default: ETH_P_IP = 0x0800).
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Add a raw 32-bit key.
    pub fn add_key(mut self, val: u32, mask: u32, off: i32) -> Self {
        self.keys.push(u32_mod::pack_key32(val, mask, off));
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn match_src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        // A /0 is mask 0, as tc makes it (#831): `1 << 32` overflowed.
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0);
        let val = u32::from_be_bytes(addr.octets());
        // IP source address is at offset 12 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 12));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn match_dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0);
        let val = u32::from_be_bytes(addr.octets());
        // IP destination address is at offset 16 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 16));
        self
    }

    /// Match IP protocol (e.g., 6 for TCP, 17 for UDP).
    pub fn match_ip_proto(mut self, proto: u8) -> Self {
        // IP protocol is at offset 9, single byte
        self.keys.push(u32_mod::pack_key8(proto, 0xFF, 9));
        self
    }

    /// Match the L4 source port of an IPv4 packet with no IP options:
    /// bytes 20–21, as `tc … u32 match ip sport` does.
    ///
    /// It used to be a next-header-relative key with its value and mask
    /// in host order. On little-endian that compared the wrong bytes, and
    /// with no linking `offset` "next header" is the IP header itself, so
    /// it never matched a port (#492). For IP options, see
    /// [`match_nexthdr_src_port`](Self::match_nexthdr_src_port).
    pub fn match_src_port(mut self, port: u16) -> Self {
        self.keys.push(u32_mod::pack_key16(port, 0xFFFF, 20));
        self
    }

    /// Match the L4 destination port of an IPv4 packet with no IP
    /// options: bytes 22–23, as `tc … u32 match ip dport` does. See
    /// [`match_src_port`](Self::match_src_port).
    pub fn match_dst_port(mut self, port: u16) -> Self {
        self.keys.push(u32_mod::pack_key16(port, 0xFFFF, 22));
        self
    }

    /// Match the TCP/UDP source port at the start of the next header, as
    /// `tc … u32 match tcp src` does.
    ///
    /// "Next header" is wherever the filter that linked to this one's
    /// table put it, with [`offset_at`](Self::offset_at). Without that,
    /// it is the start of the IP header. The usual pair:
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// # async fn example() -> nlink::Result<()> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::{TcHandle, netlink::filter::U32Filter};
    ///
    /// let table = U32Filter::handle(2, 0, 0);
    /// // Table 2:, one bucket.
    /// conn.add_filter_full("eth0", TcHandle::major_only(1), Some(TcHandle::from_raw(table)),
    ///     EthProto::IP, FilterPriority::new(1), U32Filter::new().divisor(1)).await?;
    /// // In the root table: UDP goes on to 2:, with the next header IHL*4 bytes in.
    /// conn.add_filter_full("eth0", TcHandle::major_only(1), None, EthProto::IP, FilterPriority::new(1),
    ///     U32Filter::new().match_ip_proto(17).offset_at(0, 0x0f00, 6).link(table)).await?;
    /// // In 2: — the port, wherever the IP header ends.
    /// conn.add_filter_full("eth0", TcHandle::major_only(1), None, EthProto::IP, FilterPriority::new(1),
    ///     U32Filter::new().ht(table).match_nexthdr_dst_port(53)
    ///         .classid(TcHandle::new(1, 0x10))).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn match_nexthdr_src_port(mut self, port: u16) -> Self {
        self.keys.push(u32_mod::pack_key16_nexthdr(port, 0xFFFF, 0));
        self
    }

    /// Match the TCP/UDP destination port two bytes into the next header,
    /// as `tc … u32 match tcp dst` does. See
    /// [`match_nexthdr_src_port`](Self::match_nexthdr_src_port).
    pub fn match_nexthdr_dst_port(mut self, port: u16) -> Self {
        self.keys.push(u32_mod::pack_key16_nexthdr(port, 0xFFFF, 2));
        self
    }

    /// `offset at AT mask MASK shift SHIFT`: where the next header starts,
    /// for the keys of the table this filter [`link`](Self::link)s to —
    /// `(be16 at AT & MASK) >> SHIFT` bytes in. For IPv4,
    /// `offset_at(0, 0x0f00, 6)` is the header length (IHL × 4).
    pub fn offset_at(mut self, at: i16, mask: u16, shift: u8) -> Self {
        self.offset.flags |= u32_mod::TC_U32_VAROFFSET;
        self.offset.at = at;
        self.offset.mask = mask;
        self.offset.shift = shift;
        self
    }

    /// `offset plus N`: a fixed next-header offset, added to any
    /// [`offset_at`](Self::offset_at).
    pub fn offset_plus(mut self, plus: u16) -> Self {
        self.offset.flags |= u32_mod::TC_U32_OFFSET;
        self.offset.plus = plus;
        self
    }

    /// `offset … eat`: move the base past the next-header offset, so the
    /// linked table's plain (not next-header) keys count from there.
    pub fn eat(mut self) -> Self {
        self.offset.flags |= u32_mod::TC_U32_EAT;
        self
    }

    /// Match IP TOS/DSCP field.
    pub fn match_tos(mut self, tos: u8, mask: u8) -> Self {
        // TOS is at offset 1
        self.keys.push(u32_mod::pack_key8(tos, mask, 1));
        self
    }

    /// Set hash table divisor (for creating a hash table).
    pub fn divisor(mut self, div: u32) -> Self {
        self.divisor = Some(div);
        self
    }

    /// Link to a hash table: a u32 handle, from [`U32Filter::handle`].
    pub fn link(mut self, link: u32) -> Self {
        self.link = Some(link);
        self
    }

    /// Set the hash table this filter belongs to (`TCA_U32_HASH`): a
    /// u32 handle, from [`U32Filter::handle`] — `U32Filter::handle(0x100,
    /// 0, 0)` for `100:`. Not a [`TcHandle`]'s raw form, which puts the
    /// table id 4 bits too low (#492).
    pub fn ht(mut self, handle: u32) -> Self {
        self.ht = Some(handle);
        self
    }

    /// Set the hash key — the bytes of the packet header used to
    /// compute the bucket index when this filter is part of a hash
    /// table. `mask` and `offset` are packed into `sel.hmask` and
    /// `sel.hoff` of the u32 selector header. `mask` is in
    /// host-byte-order; the encoder converts to big-endian on the
    /// wire.
    pub fn hashkey(mut self, mask: u32, offset: i16) -> Self {
        self.hashkey = Some((mask, offset));
        self
    }

    /// Match firewall mark.
    pub fn match_mark(mut self, val: u32, mask: u32) -> Self {
        self.mark = Some((val, mask));
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Set the `TCA_CLS_FLAGS_SKIP_HW` flag — instruct the kernel
    /// to skip hardware offload for this filter.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Set the `TCA_CLS_FLAGS_SKIP_SW` flag — instruct the kernel
    /// to skip software fallback for this filter (hardware-only).
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Parse a `tc(8)`-style `u32` token slice into a typed filter.
    ///
    /// # Phase 1 surface (raw matches + structural tokens)
    ///
    /// - `match u32 <hex-value> <hex-mask> at <offset>` — append a
    ///   32-bit-wide selector key. `value` and `mask` accept
    ///   `0x`-prefixed hex (or bare hex digits); `offset` accepts
    ///   decimal or hex.
    /// - `match u16 <hex-value> <hex-mask> at <offset>` — narrower
    ///   width, packed into the right half of a 32-bit-sized key
    ///   based on the offset's alignment (offset & 3).
    /// - `match u8 <hex-value> <hex-mask> at <offset>` — same idea,
    ///   one of four byte slots in the 32-bit key.
    /// - `classid <handle>` / `flowid <handle>` — target class
    ///   (e.g. `1:10`).
    /// - `chain <n>` — TC chain index (Linux 4.1+).
    /// - `skip_hw` / `skip_sw` — flag tokens setting
    ///   `TCA_CLS_FLAGS_SKIP_HW` / `SKIP_SW`.
    ///
    /// # Phase 2 surface (named-match shortcuts, IPv4 only)
    ///
    /// Sugar over the typed setters (`match_src_ipv4` /
    /// `match_dst_ipv4` / `match_ip_proto` / `match_src_port` /
    /// `match_dst_port` / `match_nexthdr_src_port` /
    /// `match_nexthdr_dst_port`), with tc(8)'s wire encoding.
    ///
    /// - `match ip src <addr>[/<prefix>]` — IPv4 source address.
    ///   Bare address defaults to `/32`.
    /// - `match ip dst <addr>[/<prefix>]` — IPv4 destination address.
    /// - `match ip protocol <name|number>` — IP protocol.
    ///   Names: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `ah`, `esp`,
    ///   `gre`. Numeric: 0–255.
    /// - `match ip sport|dport <port> [<hex-mask>]` — L4 port at bytes
    ///   20/22, past an option-less IPv4 header, as tc(8) has it.
    ///   `match tcp|udp sport|dport` are nlink's aliases.
    /// - `match tcp|udp src|dst <port> [<hex-mask>]` — L4 port relative
    ///   to the next header, which only a linking filter's `offset`
    ///   sets (tc(8)'s meaning; #492).
    /// - `offset [plus <n>] [at <n>] [mask <hex>] [shift <n>] [eat]` —
    ///   where the next header starts, for the table this filter
    ///   `link`s to: `offset at 0 mask 0f00 shift 6` is the IPv4 header
    ///   length.
    ///
    /// Stricter than the legacy `add_u32_options` parser (which
    /// silently dropped unknown tokens via a default `_ => i += 1`
    /// arm): unknown tokens, missing values, and unparseable hex
    /// return `Error::invalid_message("u32: ...")`.
    ///
    /// # Phase 3 surface (hash-table grammar)
    ///
    /// - `divisor <n>` — divisor for the bucket count when this
    ///   filter creates a hash table. Combine with no keys for the
    ///   table-create case.
    /// - `ht <handle>` — hash table this filter belongs to,
    ///   encoded as `TCA_U32_HASH`. A u32 handle, `htid[:bucket[:node]]`
    ///   in hex: `100:` is `0x10000000` (see [`U32Filter::handle`]). It
    ///   was parsed as a qdisc handle, `0x01000000` (#492).
    /// - `link <handle>` — next-hop hash table to chase on match; a u32
    ///   handle, as for `ht`.
    /// - `hashkey mask <hex> at <offset>` — bytes of the packet
    ///   used to compute the hash bucket index. `mask` is hex,
    ///   `offset` is decimal or hex (i16 range).
    ///
    /// # Not yet typed-modelled
    ///
    /// - `order <n>` — modifies the filter's own handle (not
    ///   parse_params territory). Returns a clear error pointing
    ///   at the future bin-side support.
    /// - `match icmp type|code` and IPv6 named-matches need new
    ///   setters; defer until requested.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "match" => {
                    let width = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "u32: `match` requires `WIDTH ...` (missing WIDTH)".to_string(),
                        )
                    })?;
                    match width {
                        "u32" | "u16" | "u8" => {
                            let triple = parse_u32_raw_match(params, i, width)?;
                            f.keys.push(triple.key);
                            i = triple.consumed;
                        }
                        // `match mark VAL MASK`, as tc(8) writes it.
                        "mark" => {
                            let val = need_value(params, i + 1, "u32", "match mark")?;
                            let mask = need_value(params, i + 2, "u32", "match mark VAL")?;
                            // Both in any base, as tc reads them (#831).
                            let (val, mask) = (
                                parse_u32_any("u32", "mark", val)?,
                                parse_u32_any("u32", "mark mask", mask)?,
                            );
                            if val & mask != val {
                                return Err(Error::invalid_message(format!(
                                    "u32: mark {val:#x} has bits outside its mask {mask:#x}"
                                )));
                            }
                            f = f.match_mark(val, mask);
                            i += 4;
                        }
                        "ip" | "tcp" | "udp" | "ip6" | "ether" | "icmp" => {
                            let consumed;
                            (f, consumed) = apply_named_match(f, params, i, width)?;
                            i += consumed;
                        }
                        other => {
                            return Err(Error::invalid_message(format!(
                                "u32: unknown match width `{other}` \
                                 (expected u32, u16, u8, mark, ip, ip6, tcp, udp, icmp or ether)"
                            )));
                        }
                    }
                }
                "classid" | "flowid" => {
                    let s = need_value(params, i, "u32", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("u32: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.chain(parse_u32_int("u32", "chain", s)?);
                    i += 2;
                }
                "skip_hw" => {
                    f = f.skip_hw();
                    i += 1;
                }
                "skip_sw" => {
                    f = f.skip_sw();
                    i += 1;
                }
                "divisor" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.divisor(parse_u32_int("u32", "divisor", s)?);
                    i += 2;
                }
                "ht" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.ht(parse_u32_handle("ht", s)?);
                    i += 2;
                }
                "link" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.link(parse_u32_handle("link", s)?);
                    i += 2;
                }
                "offset" => {
                    // offset [plus N] [at N] [mask HEX] [shift N] [eat]
                    let mut j = i + 1;
                    let (mut at, mut mask, mut shift, mut var) = (0i16, 0u16, 0u8, false);
                    while let Some(&sub) = params.get(j) {
                        match sub {
                            "plus" => {
                                let s = need_value(params, j, "u32", "offset plus")?;
                                let plus = parse_offset("u32", s)?;
                                let plus = u16::try_from(plus).map_err(|_| {
                                    Error::invalid_message(format!(
                                        "u32: offset plus `{s}` out of range (0–65535)"
                                    ))
                                })?;
                                f = f.offset_plus(plus);
                                j += 2;
                            }
                            "at" => {
                                let s = need_value(params, j, "u32", "offset at")?;
                                at = i16::try_from(parse_offset("u32", s)?).map_err(|_| {
                                    Error::invalid_message(format!(
                                        "u32: offset at `{s}` out of range for i16"
                                    ))
                                })?;
                                (var, j) = (true, j + 2);
                            }
                            "mask" => {
                                let s = need_value(params, j, "u32", "offset mask")?;
                                mask = u16::try_from(parse_hex_u32("u32", "offset mask", s)?)
                                    .map_err(|_| {
                                        Error::invalid_message(format!(
                                            "u32: offset mask `{s}` is wider than 16 bits"
                                        ))
                                    })?;
                                (var, j) = (true, j + 2);
                            }
                            "shift" => {
                                let s = need_value(params, j, "u32", "offset shift")?;
                                shift = s.parse().map_err(|_| {
                                    Error::invalid_message(format!(
                                        "u32: invalid offset shift `{s}` (expected 0–255)"
                                    ))
                                })?;
                                (var, j) = (true, j + 2);
                            }
                            "eat" => {
                                f = f.eat();
                                j += 1;
                            }
                            _ => break,
                        }
                    }
                    if j == i + 1 {
                        return Err(Error::invalid_message(
                            "u32: `offset` requires `plus`, `at`, `mask`, `shift` or `eat`"
                                .to_string(),
                        ));
                    }
                    if var {
                        f = f.offset_at(at, mask, shift);
                    }
                    i = j;
                }
                "hashkey" => {
                    // Form: hashkey mask <hex> at <offset> → 5 tokens total.
                    let mask_kw = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "u32: `hashkey` requires `mask <hex> at <offset>`".to_string(),
                        )
                    })?;
                    if mask_kw != "mask" {
                        return Err(Error::invalid_message(format!(
                            "u32: expected `mask` after `hashkey`, got `{mask_kw}`"
                        )));
                    }
                    let mask_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "u32: `hashkey mask` requires a hex value".to_string(),
                        )
                    })?;
                    let at_kw = params.get(i + 3).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "u32: `hashkey mask <hex>` requires `at <offset>`".to_string(),
                        )
                    })?;
                    if at_kw != "at" {
                        return Err(Error::invalid_message(format!(
                            "u32: expected `at` between hashkey mask and offset, got `{at_kw}`"
                        )));
                    }
                    let off_s = params.get(i + 4).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "u32: `hashkey mask <hex> at` requires an offset".to_string(),
                        )
                    })?;
                    let mask = parse_hex_u32("u32", "hashkey mask", mask_s)?;
                    let offset = parse_offset("u32", off_s)?;
                    if !(i16::MIN as i32..=i16::MAX as i32).contains(&offset) {
                        return Err(Error::invalid_message(format!(
                            "u32: hashkey offset `{off_s}` out of range for i16"
                        )));
                    }
                    f = f.hashkey(mask, offset as i16);
                    i += 5;
                }
                "order" => {
                    return Err(Error::invalid_message(
                        "u32: `order` is not yet typed-modelled — modifying the filter's own \
                         handle requires bin-side support that isn't wired through \
                         parse_params; ship `order` support separately when needed"
                            .to_string(),
                    ));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "u32: unknown token `{other}` (supports: match u32|u16|u8 VAL MASK at OFFSET, match mark VAL MASK, match ip|tcp|udp ..., classid/flowid, chain, divisor, ht, link, offset, hashkey, skip_hw, skip_sw)"
                    )));
                }
            }
        }
        // Keys at the same offset are one key, as tc's pack_key() makes them.
        f.keys = merge_u32_keys(std::mem::take(&mut f.keys))?;
        Ok(f)
    }

    /// The filter as the tokens [`parse_params`](Self::parse_params) reads,
    /// its inverse (#645): each key as a raw `match u32`, which is what a
    /// named match (`match ip src …`) packs into.
    pub fn to_params(&self) -> Result<Vec<String>> {
        let unsigned = |what: &str, v: i32| {
            u32::try_from(v).map_err(|_| {
                Error::not_supported(format!("u32: a negative {what} ({v}) has no token"))
            })
        };
        let mut out: Vec<String> = Vec::new();
        for k in &self.keys {
            let at = match k.offmask {
                0 => unsigned("offset", k.off)?.to_string(),
                -1 => format!("nexthdr+{}", unsigned("offset", k.off)?),
                m => {
                    return Err(Error::not_supported(format!(
                        "u32: a key's offset mask {m:#x} has no token"
                    )));
                }
            };
            out.extend([
                "match".to_string(),
                "u32".to_string(),
                format!("0x{:08x}", u32::from_be(k.val)),
                format!("0x{:08x}", u32::from_be(k.mask)),
                "at".to_string(),
                at,
            ]);
        }
        if let Some((val, mask)) = self.mark {
            out.extend([
                "match".to_string(),
                "mark".to_string(),
                format!("0x{val:x}"),
                format!("0x{mask:x}"),
            ]);
        }
        if let Some(c) = self.classid {
            out.extend(["classid".to_string(), classid_param(c)]);
        }
        if let Some(c) = self.chain {
            out.extend(["chain".to_string(), c.to_string()]);
        }
        if let Some(d) = self.divisor {
            out.extend(["divisor".to_string(), d.to_string()]);
        }
        if let Some(h) = self.ht {
            out.extend(["ht".to_string(), format!("0x{h:08x}")]);
        }
        if let Some(h) = self.link {
            out.extend(["link".to_string(), format!("0x{h:08x}")]);
        }
        let o = self.offset;
        let known = u32_mod::TC_U32_OFFSET | u32_mod::TC_U32_VAROFFSET | u32_mod::TC_U32_EAT;
        if o.flags & !known != 0 {
            return Err(Error::not_supported(format!(
                "u32: offset flags {:#x} have no token",
                o.flags
            )));
        }
        if o.flags != 0 {
            out.push("offset".to_string());
            if o.flags & u32_mod::TC_U32_OFFSET != 0 {
                out.extend(["plus".to_string(), o.plus.to_string()]);
            }
            if o.flags & u32_mod::TC_U32_VAROFFSET != 0 {
                out.extend([
                    "at".to_string(),
                    unsigned("offset at", i32::from(o.at))?.to_string(),
                    "mask".to_string(),
                    format!("0x{:x}", o.mask),
                    "shift".to_string(),
                    o.shift.to_string(),
                ]);
            }
            if o.flags & u32_mod::TC_U32_EAT != 0 {
                out.push("eat".to_string());
            }
        }
        if let Some((mask, at)) = self.hashkey {
            out.extend([
                "hashkey".to_string(),
                "mask".to_string(),
                format!("0x{mask:08x}"),
                "at".to_string(),
                unsigned("hashkey offset", i32::from(at))?.to_string(),
            ]);
        }
        out.extend(skip_flags_params("u32", self.flags)?);
        Ok(out)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for U32Filter {
    fn kind(&self) -> &'static str {
        "u32"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add classid if set
        if let Some(classid) = self.classid {
            builder.append_attr_u32(u32_mod::TCA_U32_CLASSID, classid);
        }

        // Add divisor if creating hash table
        if let Some(div) = self.divisor {
            builder.append_attr_u32(u32_mod::TCA_U32_DIVISOR, div);
        }

        // Add hash table reference (which bucket this filter belongs to)
        if let Some(ht) = self.ht {
            builder.append_attr_u32(u32_mod::TCA_U32_HASH, ht);
        }

        // Add link if set
        if let Some(link) = self.link {
            builder.append_attr_u32(u32_mod::TCA_U32_LINK, link);
        }

        // Add mark if set
        if let Some((val, mask)) = self.mark {
            let mark = u32_mod::TcU32Mark::new(val, mask);
            builder.append_attr(u32_mod::TCA_U32_MARK, mark.as_bytes());
        }

        // Build and add selector if we have keys, a hashkey or a mark
        // configured: tc sends one for every `match`, and the kernel
        // refuses a mark-only filter without it (#825). Divisor-only
        // filters (which create the hash table itself) emit just
        // TCA_U32_DIVISOR — no selector.
        if !self.keys.is_empty() || self.hashkey.is_some() || self.offset.flags != 0 || self.mark.is_some() {
            let mut sel = u32_mod::TcU32Sel::new();
            sel.set_terminal();
            for key in &self.keys {
                sel.add_key(*key);
            }
            if let Some((mask, offset)) = self.hashkey {
                // hmask is big-endian on the wire; offset is host-order i16.
                sel.hdr.hmask = mask.to_be();
                sel.hdr.hoff = offset;
            }
            // offmask is big-endian; off and offoff are host order.
            sel.hdr.flags |= self.offset.flags;
            sel.hdr.off = self.offset.plus;
            sel.hdr.offoff = self.offset.at;
            sel.hdr.offmask = self.offset.mask.to_be();
            sel.hdr.offshift = self.offset.shift;
            builder.append_attr(u32_mod::TCA_U32_SEL, &sel.to_bytes());
        }

        // Add classifier flags (skip_hw / skip_sw) if any are set.
        if self.flags != 0 {
            builder.append_attr_u32(u32_mod::TCA_U32_FLAGS, self.flags);
        }

        Ok(())
    }
}

/// Borrow `params[i + 1]`, returning a kind-prefixed
/// `InvalidMessage` if the value slot is missing.
/// A filter's classid as its token.
fn classid_param(classid: u32) -> String {
    TcHandle::from_raw(classid).to_string()
}

/// The `skip_hw`/`skip_sw` tokens of a filter's `TCA_CLS_FLAGS_*`, or an
/// error for another flag.
fn skip_flags_params(kind: &str, flags: u32) -> Result<Vec<String>> {
    use super::types::tc::filter::flower::{TCA_CLS_FLAGS_SKIP_HW, TCA_CLS_FLAGS_SKIP_SW};
    if flags & !(TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW) != 0 {
        return Err(Error::not_supported(format!("{kind}: flags {flags:#x} have no token")));
    }
    let mut out = Vec::new();
    if flags & TCA_CLS_FLAGS_SKIP_HW != 0 {
        out.push("skip_hw".to_string());
    }
    if flags & TCA_CLS_FLAGS_SKIP_SW != 0 {
        out.push("skip_sw".to_string());
    }
    Ok(out)
}

fn need_value<'a>(params: &[&'a str], i: usize, kind: &str, key: &str) -> Result<&'a str> {
    params
        .get(i + 1)
        .copied()
        .ok_or_else(|| Error::invalid_message(format!("{kind}: `{key}` requires a value")))
}

/// Parse a decimal `u32` with kind-prefixed error context.
fn parse_u32_int(kind: &str, key: &str, s: &str) -> Result<u32> {
    s.parse::<u32>().map_err(|_| {
        Error::invalid_message(format!(
            "{kind}: invalid {key} `{s}` (expected unsigned integer)"
        ))
    })
}

/// Parse a hex value (with or without `0x` prefix) into `u32`.
fn parse_hex_u32(kind: &str, key: &str, s: &str) -> Result<u32> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(body, 16).map_err(|_| {
        Error::invalid_message(format!("{kind}: invalid {key} `{s}` (expected hex value)"))
    })
}

/// Parse an offset as tc(8)'s `get_integer(.., 0)` does: a sign, then
/// decimal, `0x` hex or `0` octal. The kernel's offsets are signed: a
/// negative one reaches back before the network header (#835).
fn parse_offset(kind: &str, s: &str) -> Result<i32> {
    let invalid = || Error::invalid_message(format!("{kind}: invalid offset `{s}`"));
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.starts_with(['+', '-']) {
        return Err(invalid());
    }
    let magnitude = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<i64>()
    }
    .map_err(|_| invalid())?;
    i32::try_from(if negative { -magnitude } else { magnitude }).map_err(|_| invalid())
}

/// Result of parsing one `match WIDTH VAL MASK at OFFSET` triple.
struct U32MatchTriple {
    key: u32_mod::TcU32Key,
    /// Index of the next unconsumed token (i.e. `i + 6` on success).
    consumed: usize,
}

/// Parse `match WIDTH VAL MASK at OFFSET` starting at `params[i]`,
/// where `WIDTH` is one of `u32`/`u16`/`u8` (validated by the caller).
fn parse_u32_raw_match(params: &[&str], i: usize, width: &str) -> Result<U32MatchTriple> {
    // Need: match WIDTH VAL MASK at OFFSET → 6 tokens total.
    let need = |k: usize, name: &str| -> Result<&str> {
        params.get(i + k).copied().ok_or_else(|| {
            Error::invalid_message(format!(
                "u32: `match` requires `WIDTH VAL MASK at OFFSET` (missing {name})"
            ))
        })
    };
    let val_s = need(2, "VAL")?;
    let mask_s = need(3, "MASK")?;
    let at_kw = need(4, "`at`")?;
    let off_s = need(5, "OFFSET")?;

    if at_kw != "at" {
        return Err(Error::invalid_message(format!(
            "u32: expected `at` between MASK and OFFSET, got `{at_kw}`"
        )));
    }
    // `at nexthdr+N`: relative to the next header, as tc(8) writes it.
    let (off_s, nexthdr) = match off_s.strip_prefix("nexthdr+") {
        Some(rest) => (rest, true),
        None => (off_s, false),
    };
    let offset = parse_offset("u32", off_s)?;
    let mut key = match width {
        "u32" => {
            let val = parse_u32_any("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            u32_mod::pack_key32(val, mask, offset)
        }
        "u16" => {
            let val = parse_u32_any("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            if val > 0xFFFF || mask > 0xFFFF {
                return Err(Error::invalid_message(format!(
                    "u32: u16 match VAL/MASK must fit in 16 bits (got val={val_s}, mask={mask_s})"
                )));
            }
            u32_mod::pack_key16(val as u16, mask as u16, offset)
        }
        "u8" => {
            let val = parse_u32_any("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            if val > 0xFF || mask > 0xFF {
                return Err(Error::invalid_message(format!(
                    "u32: u8 match VAL/MASK must fit in 8 bits (got val={val_s}, mask={mask_s})"
                )));
            }
            u32_mod::pack_key8(val as u8, mask as u8, offset)
        }
        other => {
            // Caller pre-validated; unreachable in practice.
            return Err(Error::invalid_message(format!(
                "u32: unknown match width `{other}`"
            )));
        }
    };
    if nexthdr {
        key.offmask = -1;
    }
    Ok(U32MatchTriple {
        key,
        consumed: i + 6,
    })
}

/// Apply `match ip|ip6|tcp|udp|icmp|ether FIELD VALUE [MASK]`, as tc(8)'s
/// `parse_ip`, `parse_ip6`, `parse_icmp` and `parse_ether` do; returns the
/// filter and the number of tokens consumed. Values read in any base and
/// masks in hex, as tc reads them; a mask tc requires is optional here and
/// defaults to all of the field.
fn apply_named_match(
    filter: U32Filter,
    params: &[&str],
    i: usize,
    layer: &str,
) -> Result<(U32Filter, usize)> {
    let field = params
        .get(i + 2)
        .copied()
        .ok_or_else(|| Error::invalid_message(format!("u32: `match {layer}` requires FIELD")))?;
    let mut filter = filter;

    // The IPv4 fragment fields take no value.
    let frag = match (layer, field) {
        ("ip", "nofrag") => Some((0, 0x3FFF)),
        ("ip", "firstfrag") => Some((0x2000, 0x3FFF)),
        ("ip", "df") => Some((0x4000, 0x4000)),
        ("ip", "mf") => Some((0x2000, 0x2000)),
        _ => None,
    };
    if let Some((val, mask)) = frag {
        filter.keys.push(u32_mod::pack_key16(val, mask, 6));
        return Ok((filter, 3));
    }

    let value = params.get(i + 3).copied().ok_or_else(|| {
        Error::invalid_message(format!("u32: `match {layer} {field}` requires VALUE"))
    })?;
    // `VALUE [MASK]`: the mask is taken when the next token is hex.
    let masked = |width: u32| -> Result<(u32, u32, usize)> {
        let full = if width == 32 { u32::MAX } else { (1u32 << width) - 1 };
        let val = parse_u32_any("u32", &format!("{layer} {field}"), value)?;
        let (mask, consumed) = match params.get(i + 4).and_then(|s| parse_hex_u32("u32", "mask", s).ok()) {
            Some(mask) => (mask, 5),
            None => (full, 4),
        };
        if val > full || mask > full {
            return Err(Error::invalid_message(format!(
                "u32: `match {layer} {field}` value or mask is wider than {width} bits"
            )));
        }
        Ok((val, mask, consumed))
    };
    let u8_at = |mut filter: U32Filter, off: i32, offmask: i32| -> Result<(U32Filter, usize)> {
        let (val, mask, consumed) = masked(8)?;
        let mut key = u32_mod::pack_key8((val & mask) as u8, mask as u8, off);
        key.offmask = offmask;
        filter.keys.push(key);
        Ok((filter, consumed))
    };
    let u16_at = |mut filter: U32Filter, off: i32, offmask: i32| -> Result<(U32Filter, usize)> {
        let (val, mask, consumed) = masked(16)?;
        let mut key = u32_mod::pack_key16((val & mask) as u16, mask as u16, off);
        key.offmask = offmask;
        filter.keys.push(key);
        Ok((filter, consumed))
    };

    match (layer, field) {
        ("ip", "src") => {
            let (addr, prefix) = parse_u32_ipv4_with_prefix(value)?;
            Ok((filter.match_src_ipv4(addr, prefix), 4))
        }
        ("ip", "dst") => {
            let (addr, prefix) = parse_u32_ipv4_with_prefix(value)?;
            Ok((filter.match_dst_ipv4(addr, prefix), 4))
        }
        ("ip", "protocol") => {
            // tc(8) writes it with a mask too: `match ip protocol 6 0xff`;
            // nlink also takes a protocol name.
            let proto = parse_ip_proto_name_or_num(value)?;
            match params
                .get(i + 4)
                .and_then(|s| parse_hex_u32("u32", "protocol mask", s).ok())
            {
                Some(mask) => {
                    let mask = u8::try_from(mask).map_err(|_| {
                        Error::invalid_message(format!(
                            "u32: `match ip protocol` mask `{}` is wider than 8 bits",
                            params[i + 4]
                        ))
                    })?;
                    filter.keys.push(u32_mod::pack_key8(proto & mask, mask, 9));
                    Ok((filter, 5))
                }
                None => Ok((filter.match_ip_proto(proto), 4)),
            }
        }
        ("ip", "tos" | "dsfield" | "precedence") => u8_at(filter, 1, 0),
        ("ip", "ihl") => u8_at(filter, 0, 0),
        ("ip", "icmp_type") => u8_at(filter, 20, 0),
        ("ip", "icmp_code") => u8_at(filter, 21, 0),
        // Fixed offsets past a 20-byte IPv4 header, as tc's `ip sport|dport`.
        // `tcp|udp sport|dport` are nlink's aliases for them.
        ("ip" | "tcp" | "udp", "sport") => u16_at(filter, 20, 0),
        ("ip" | "tcp" | "udp", "dport") => u16_at(filter, 22, 0),
        // tc's `tcp|udp src|dst` and `icmp type|code`: relative to the next
        // header, which a linking filter's `offset` sets.
        ("tcp" | "udp", "src") => u16_at(filter, 0, -1),
        ("tcp" | "udp", "dst") => u16_at(filter, 2, -1),
        ("icmp", "type") => u8_at(filter, 0, -1),
        ("icmp", "code") => u8_at(filter, 1, -1),
        ("ip6", "src" | "dst") => {
            let (addr, plen) = match value.split_once('/') {
                Some((a, p)) => (a, p.parse::<u32>().ok().filter(|p| *p <= 128)),
                None => (value, Some(128)),
            };
            let (addr, plen) = addr.parse::<std::net::Ipv6Addr>().ok().zip(plen).ok_or_else(|| {
                Error::invalid_message(format!("u32: invalid IPv6 prefix `{value}`"))
            })?;
            let base = if field == "src" { 8 } else { 24 };
            let octets = addr.octets();
            for word in 0..4u32 {
                let bits = plen.saturating_sub(word * 32).min(32);
                if bits == 0 {
                    break;
                }
                let n = word as usize * 4;
                let val = u32::from_be_bytes([octets[n], octets[n + 1], octets[n + 2], octets[n + 3]]);
                let mask = u32::MAX << (32 - bits);
                filter.keys.push(u32_mod::pack_key32(val, mask, base + 4 * word as i32));
            }
            Ok((filter, 4))
        }
        // The traffic class: eight bits, 20 bits into the first word.
        ("ip6", "priority") => {
            let (val, mask, consumed) = masked(8)?;
            filter.keys.push(u32_mod::pack_key32(val << 20, mask << 20, 0));
            Ok((filter, consumed))
        }
        ("ip6", "protocol") => u8_at(filter, 6, 0),
        ("ip6", "flowlabel") => {
            let (val, mask, consumed) = masked(32)?;
            filter.keys.push(u32_mod::pack_key32(val, mask, 0));
            Ok((filter, consumed))
        }
        ("ip6", "sport") => u16_at(filter, 40, 0),
        ("ip6", "dport") => u16_at(filter, 42, 0),
        ("ip6", "icmp_type") => u8_at(filter, 40, 0),
        // tc gives this one an offmask of 1; kept, so a line means here
        // what it means there.
        ("ip6", "icmp_code") => u8_at(filter, 41, 1),
        // Before the network header: the destination at -14, the source
        // at -8.
        ("ether", "src" | "dst") => {
            let mac = parse_mac(value)
                .map_err(|_| Error::invalid_message(format!("u32: invalid MAC `{value}`")))?;
            let base = if field == "src" { -8 } else { -14 };
            for (n, byte) in mac.iter().enumerate() {
                filter.keys.push(u32_mod::pack_key8(*byte, 0xFF, base + n as i32));
            }
            Ok((filter, 4))
        }
        _ => Err(Error::invalid_message(format!(
            "u32: unsupported `match {layer} {field}` (supported: ip src/dst/protocol/tos/dsfield/\
             precedence/ihl/nofrag/firstfrag/df/mf/sport/dport/icmp_type/icmp_code, ip6 src/dst/\
             priority/protocol/flowlabel/sport/dport/icmp_type/icmp_code, tcp/udp src/dst/sport/\
             dport, icmp type/code, ether src/dst)"
        ))),
    }
}

/// Merge keys at the same offset into one, as tc's `pack_key()` does: a
/// value both name the same bits of must agree (#831).
fn merge_u32_keys(keys: Vec<u32_mod::TcU32Key>) -> Result<Vec<u32_mod::TcU32Key>> {
    let mut out: Vec<u32_mod::TcU32Key> = Vec::with_capacity(keys.len());
    for key in keys {
        match out.iter_mut().find(|k| k.off == key.off && k.offmask == key.offmask) {
            Some(k) => {
                if (k.val ^ key.val) & k.mask & key.mask != 0 {
                    return Err(Error::invalid_message(format!(
                        "u32: two matches disagree at offset {}",
                        key.off
                    )));
                }
                k.val |= key.val;
                k.mask |= key.mask;
            }
            None => out.push(key),
        }
    }
    Ok(out)
}

/// A value as tc(8)'s `get_u32(.., 0)` reads it: decimal, `0x` hex or `0`
/// octal (#831).
fn parse_u32_any(kind: &str, key: &str, s: &str) -> Result<u32> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8)
    } else {
        s.parse::<u32>()
    };
    parsed.map_err(|_| Error::invalid_message(format!("{kind}: invalid {key} `{s}` (expected unsigned integer)")))
}

/// Parse a u32 handle in tc(8) notation — `htid[:[bucket[:node]]]`, hex,
/// or a `0x` raw value — as iproute2's `get_u32_handle` does (#492). Not a
/// qdisc handle: `2:` is `0x00200000`.
fn parse_u32_handle(key: &str, s: &str) -> Result<u32> {
    let bad = || Error::invalid_message(format!("u32: invalid {key} handle `{s}`"));
    let Some((htid, rest)) = s.split_once(':') else {
        return s
            .strip_prefix("0x")
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .ok_or_else(bad);
    };
    let hex = |part: &str, max: u32| -> Result<u32> {
        if part.is_empty() {
            return Ok(0);
        }
        let v = u32::from_str_radix(part, 16).map_err(|_| bad())?;
        if v > max { Err(bad()) } else { Ok(v) }
    };
    let (bucket, node) = rest.split_once(':').unwrap_or((rest, ""));
    Ok((hex(htid, 0xFFF)? << 20) | (hex(bucket, 0xFF)? << 12) | hex(node, 0xFFF)?)
}

/// Parse `ADDR[/PREFIX]` into (Ipv4Addr, u8) with `u32:` error
/// prefix. Bare addresses get /32. The flower filter has its own
/// equivalent (`parse_ipv4_with_prefix`) with a `flower:` prefix.
fn parse_u32_ipv4_with_prefix(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr_s, prefix) = match s.split_once('/') {
        Some((a, p)) => {
            let pl: u8 = p.parse().map_err(|_| {
                Error::invalid_message(format!(
                    "u32: invalid IPv4 prefix length `{p}` (expected 0–32)"
                ))
            })?;
            if pl > 32 {
                return Err(Error::invalid_message(format!(
                    "u32: IPv4 prefix length `{pl}` out of range (expected 0–32)"
                )));
            }
            (a, pl)
        }
        None => (s, 32),
    };
    let addr: Ipv4Addr = addr_s
        .parse()
        .map_err(|_| Error::invalid_message(format!("u32: invalid IPv4 address `{addr_s}`")))?;
    Ok((addr, prefix))
}

/// Parse an IP protocol name or numeric value into a u8.
fn parse_ip_proto_name_or_num(s: &str) -> Result<u8> {
    // Try numeric first; common case is `match ip protocol 6`.
    if let Ok(n) = s.parse::<u8>() {
        return Ok(n);
    }
    // Fall back to the small set of named protocols `tc(8)` accepts.
    Ok(match s {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        "sctp" => 132,
        "ah" => 51,
        "esp" => 50,
        "gre" => 47,
        other => {
            return Err(Error::invalid_message(format!(
                "u32: unknown IP protocol `{other}` \
                 (expected name [tcp/udp/icmp/icmpv6/sctp/ah/esp/gre] or number 0–255)"
            )));
        }
    })
}


// ============================================================================
// FlowerFilter
// ============================================================================

/// Flower filter configuration.
///
/// The flower filter provides a more user-friendly way to match packets
/// based on various header fields including L2/L3/L4 headers.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::FlowerFilter;
/// use std::net::Ipv4Addr;
///
/// // Match TCP traffic to 10.0.0.0/8 on port 80
/// let filter = FlowerFilter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .ip_proto_tcp()
///     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .dst_port(80)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct FlowerFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Ethernet type (e.g., 0x0800 for IPv4).
    eth_type: Option<u16>,
    /// IP protocol.
    ip_proto: Option<u8>,
    /// Source IPv4 address and prefix length.
    src_ipv4: Option<(Ipv4Addr, u8)>,
    /// Destination IPv4 address and prefix length.
    dst_ipv4: Option<(Ipv4Addr, u8)>,
    /// Source IPv6 address and prefix length.
    src_ipv6: Option<(Ipv6Addr, u8)>,
    /// Destination IPv6 address and prefix length.
    dst_ipv6: Option<(Ipv6Addr, u8)>,
    /// Source port.
    src_port: Option<u16>,
    /// Destination port.
    dst_port: Option<u16>,
    /// Source port range, inclusive (min, max).
    src_port_range: Option<(u16, u16)>,
    /// Destination port range, inclusive (min, max).
    dst_port_range: Option<(u16, u16)>,
    /// Source MAC address.
    src_mac: Option<[u8; 6]>,
    /// Destination MAC address.
    dst_mac: Option<[u8; 6]>,
    /// VLAN ID.
    vlan_id: Option<u16>,
    /// VLAN priority.
    vlan_prio: Option<u8>,
    /// IP TOS.
    ip_tos: Option<(u8, u8)>,
    /// IP TTL.
    ip_ttl: Option<(u8, u8)>,
    /// TCP flags.
    tcp_flags: Option<(u16, u16)>,
    /// ICMP type and code, each with its mask: ICMPv4 or ICMPv6 by the
    /// network ethertype and `ip_proto` (#827).
    icmp_type: Option<(u8, u8)>,
    icmp_code: Option<(u8, u8)>,
    /// `TCA_FLOWER_KEY_FLAGS`: the fragment flags and their mask (#827).
    ip_flags: Option<(u32, u32)>,
    /// Conntrack state, zone, mark and labels, each with its mask (#827).
    ct_state: Option<(u16, u16)>,
    ct_zone: Option<(u16, u16)>,
    ct_mark: Option<(u32, u32)>,
    ct_labels: Option<([u8; 16], [u8; 16])>,
    /// The device packets arrived on (#827).
    indev: Option<String>,
    /// The ethertype inside the VLAN tag, the inner tag's id and priority,
    /// and the ethertype inside that (#827).
    vlan_ethtype: Option<u16>,
    cvlan_id: Option<u16>,
    cvlan_prio: Option<u8>,
    cvlan_ethtype: Option<u16>,
    /// The top MPLS label stack entry (#827).
    mpls_label: Option<u32>,
    mpls_tc: Option<u8>,
    mpls_bos: Option<u8>,
    mpls_ttl: Option<u8>,
    /// MAC masks; all ones when not given (#827).
    src_mac_mask: Option<[u8; 6]>,
    dst_mac_mask: Option<[u8; 6]>,
    /// ARP opcode, addresses and hardware addresses, with masks (#827).
    arp_op: Option<(u8, u8)>,
    arp_sip: Option<(Ipv4Addr, u8)>,
    arp_tip: Option<(Ipv4Addr, u8)>,
    arp_sha: Option<([u8; 6], [u8; 6])>,
    arp_tha: Option<([u8; 6], [u8; 6])>,
    /// Tunnel metadata: key id, outer addresses, UDP port, TOS and TTL
    /// (#827).
    enc_key_id: Option<u32>,
    enc_src_ip: Option<(IpAddr, u8)>,
    enc_dst_ip: Option<(IpAddr, u8)>,
    enc_dst_port: Option<u16>,
    enc_tos: Option<(u8, u8)>,
    enc_ttl: Option<(u8, u8)>,
    /// Filter flags (skip_hw, skip_sw, etc.).
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_ALL).
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Goto chain action (jump to another chain on match).
    goto_chain: Option<u32>,
    /// Actions run on a match (#450).
    actions: Option<ActionList>,
}

impl FlowerFilter {
    /// Create a new flower filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Match IPv4 packets.
    pub fn ipv4(mut self) -> Self {
        self.eth_type = Some(0x0800);
        self
    }

    /// Match IPv6 packets.
    pub fn ipv6(mut self) -> Self {
        self.eth_type = Some(0x86DD);
        self
    }

    /// Match ARP packets.
    pub fn arp(mut self) -> Self {
        self.eth_type = Some(0x0806);
        self
    }

    /// Match 802.1Q-tagged frames — the ethertype [`vlan_id`](Self::vlan_id)
    /// and [`vlan_prio`](Self::vlan_prio) are read under.
    pub fn vlan(mut self) -> Self {
        self.eth_type = Some(0x8100);
        self
    }

    /// Match 802.1AD (QinQ) outer-tagged frames.
    pub fn qinq(mut self) -> Self {
        self.eth_type = Some(0x88A8);
        self
    }

    /// Set IP protocol.
    pub fn ip_proto(mut self, proto: u8) -> Self {
        self.ip_proto = Some(proto);
        self
    }

    /// Match TCP packets.
    pub fn ip_proto_tcp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_TCP);
        self
    }

    /// Match UDP packets.
    pub fn ip_proto_udp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_UDP);
        self
    }

    /// Match ICMP packets.
    pub fn ip_proto_icmp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMP);
        self
    }

    /// Match ICMPv6 packets.
    pub fn ip_proto_icmpv6(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMPV6);
        self
    }

    /// Match SCTP packets. Its ports are matched like TCP's and UDP's
    /// ([`dst_port`](Self::dst_port), [`dst_port_range`](Self::dst_port_range)).
    pub fn ip_proto_sctp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_SCTP);
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.src_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.dst_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match source IPv6 address with prefix length.
    pub fn src_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.src_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv6 address with prefix length.
    pub fn dst_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.dst_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match source port. Replaces a [`src_port_range`](Self::src_port_range).
    ///
    /// cls_flower reads a port only for TCP, UDP or SCTP, so the filter
    /// must also set [`ip_proto_tcp`](Self::ip_proto_tcp) /
    /// [`ip_proto_udp`](Self::ip_proto_udp) /
    /// [`ip_proto_sctp`](Self::ip_proto_sctp) and an ethertype. Installing
    /// one that does not is an error rather than the match-all the kernel
    /// would make of it.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self.src_port_range = None;
        self
    }

    /// Match destination port. Replaces a
    /// [`dst_port_range`](Self::dst_port_range). The same rules as
    /// [`src_port`](Self::src_port) apply.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self.dst_port_range = None;
        self
    }

    /// Match a source port in `min..=max` (`TCA_FLOWER_KEY_PORT_SRC_MIN`
    /// / `_MAX`, kernel 5.2+; tc(8) `src_port min-max`). Replaces a
    /// [`src_port`](Self::src_port).
    ///
    /// The kernel needs `min < max` — a single port is
    /// [`src_port`](Self::src_port) — and reads a range only for TCP, UDP
    /// or SCTP, so the filter must also set
    /// [`ip_proto_tcp`](Self::ip_proto_tcp) / [`ip_proto_udp`](Self::ip_proto_udp)
    /// / [`ip_proto_sctp`](Self::ip_proto_sctp) and an ethertype. Installing
    /// one that does not is an error rather than the match-all the kernel
    /// would make of it.
    pub fn src_port_range(mut self, min: u16, max: u16) -> Self {
        self.src_port_range = Some((min, max));
        self.src_port = None;
        self
    }

    /// Match a destination port in `min..=max`
    /// (`TCA_FLOWER_KEY_PORT_DST_MIN` / `_MAX`, kernel 5.2+; tc(8)
    /// `dst_port min-max`). Replaces a [`dst_port`](Self::dst_port). The
    /// same rules as [`src_port_range`](Self::src_port_range) apply.
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::filter::FlowerFilter;
    /// use nlink::TcHandle;
    ///
    /// // UDP to ports 8000-8100 into class 1:2.
    /// let filter = FlowerFilter::new()
    ///     .classid(TcHandle::new(1, 2))
    ///     .ipv4()
    ///     .ip_proto_udp()
    ///     .dst_port_range(8000, 8100)
    ///     .build();
    /// conn.add_filter_full("eth0", TcHandle::major_only(1), None, EthProto::IP, FilterPriority::new(1), filter)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dst_port_range(mut self, min: u16, max: u16) -> Self {
        self.dst_port_range = Some((min, max));
        self.dst_port = None;
        self
    }

    /// Match source MAC address.
    pub fn src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = Some(mac);
        self
    }

    /// Match destination MAC address.
    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    /// Match VLAN ID. `cls_flower` reads it only under a VLAN ethertype, so
    /// this implies [`vlan`](Self::vlan) (802.1Q) unless one is set —
    /// [`qinq`](Self::qinq), or a filter protocol of 802.1AD, for an 802.1AD
    /// tag. Under any other ethertype the filter is refused (#431).
    pub fn vlan_id(mut self, id: u16) -> Self {
        self.vlan_id = Some(id);
        self
    }

    /// Match VLAN priority; like [`vlan_id`](Self::vlan_id), implies 802.1Q
    /// unless an ethertype is set.
    pub fn vlan_prio(mut self, prio: u8) -> Self {
        self.vlan_prio = Some(prio);
        self
    }

    /// Match IP TOS with mask.
    pub fn ip_tos(mut self, tos: u8, mask: u8) -> Self {
        self.ip_tos = Some((tos, mask));
        self
    }

    /// Match IP TTL with mask.
    pub fn ip_ttl(mut self, ttl: u8, mask: u8) -> Self {
        self.ip_ttl = Some((ttl, mask));
        self
    }

    /// Match TCP flags with mask. Needs `ip_proto tcp`: `cls_flower` reads
    /// the flags only there, so anything else is refused (#431).
    pub fn tcp_flags(mut self, flags: u16, mask: u16) -> Self {
        self.tcp_flags = Some((flags, mask));
        self
    }

    /// Match the ICMP (or ICMPv6) type under a mask. Needs `ip_proto` icmp
    /// on IPv4 or icmpv6 on IPv6.
    pub fn icmp_type(mut self, icmp_type: u8, mask: u8) -> Self {
        self.icmp_type = Some((icmp_type, mask));
        self
    }

    /// Match the ICMP (or ICMPv6) code under a mask.
    pub fn icmp_code(mut self, code: u8, mask: u8) -> Self {
        self.icmp_code = Some((code, mask));
        self
    }

    /// Match `TCA_FLOWER_KEY_FLAGS` under a mask: the fragment bits,
    /// `TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT` and `…_FRAG_IS_FIRST`.
    pub fn ip_flags(mut self, flags: u32, mask: u32) -> Self {
        self.ip_flags = Some((flags, mask));
        self
    }

    /// Match the conntrack state (`TCA_FLOWER_KEY_CT_FLAGS_*`) under a mask.
    pub fn ct_state(mut self, state: u16, mask: u16) -> Self {
        self.ct_state = Some((state, mask));
        self
    }

    /// Match the conntrack zone under a mask.
    pub fn ct_zone(mut self, zone: u16, mask: u16) -> Self {
        self.ct_zone = Some((zone, mask));
        self
    }

    /// Match the conntrack mark under a mask.
    pub fn ct_mark(mut self, mark: u32, mask: u32) -> Self {
        self.ct_mark = Some((mark, mask));
        self
    }

    /// Match the 128-bit conntrack labels under a mask.
    pub fn ct_labels(mut self, labels: [u8; 16], mask: [u8; 16]) -> Self {
        self.ct_labels = Some((labels, mask));
        self
    }

    /// Match only packets that arrived on `dev`; the kernel resolves the
    /// name in the filter's namespace.
    pub fn indev(mut self, dev: impl Into<String>) -> Self {
        self.indev = Some(dev.into());
        self
    }

    /// The ethertype inside the VLAN tag: the protocol the L3 keys match
    /// under a VLAN, or a second tag's for QinQ.
    pub fn vlan_ethtype(mut self, ethertype: EthProto) -> Self {
        self.vlan_ethtype = Some(ethertype.as_u16());
        self
    }

    /// Match the inner (customer) VLAN id. Needs `vlan_ethtype` a VLAN tag.
    pub fn cvlan_id(mut self, id: u16) -> Self {
        self.cvlan_id = Some(id);
        self
    }

    /// Match the inner VLAN priority.
    pub fn cvlan_prio(mut self, prio: u8) -> Self {
        self.cvlan_prio = Some(prio);
        self
    }

    /// The ethertype inside the inner VLAN tag.
    pub fn cvlan_ethtype(mut self, ethertype: EthProto) -> Self {
        self.cvlan_ethtype = Some(ethertype.as_u16());
        self
    }

    /// Match the top MPLS label. Needs the MPLS ethertype.
    pub fn mpls_label(mut self, label: u32) -> Self {
        self.mpls_label = Some(label);
        self
    }

    /// Match the top MPLS entry's traffic class.
    pub fn mpls_tc(mut self, tc: u8) -> Self {
        self.mpls_tc = Some(tc);
        self
    }

    /// Match the top MPLS entry's bottom-of-stack bit.
    pub fn mpls_bos(mut self, bos: u8) -> Self {
        self.mpls_bos = Some(bos);
        self
    }

    /// Match the top MPLS entry's TTL.
    pub fn mpls_ttl(mut self, ttl: u8) -> Self {
        self.mpls_ttl = Some(ttl);
        self
    }

    /// Match the source MAC under a mask.
    pub fn src_mac_masked(mut self, mac: [u8; 6], mask: [u8; 6]) -> Self {
        self.src_mac = Some(mac);
        self.src_mac_mask = Some(mask);
        self
    }

    /// Match the destination MAC under a mask.
    pub fn dst_mac_masked(mut self, mac: [u8; 6], mask: [u8; 6]) -> Self {
        self.dst_mac = Some(mac);
        self.dst_mac_mask = Some(mask);
        self
    }

    /// Match the ARP opcode under a mask. Needs the ARP or RARP ethertype.
    pub fn arp_op(mut self, op: u8, mask: u8) -> Self {
        self.arp_op = Some((op, mask));
        self
    }

    /// Match the ARP sender address under a prefix.
    pub fn arp_sip(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.arp_sip = Some((addr, prefix_len));
        self
    }

    /// Match the ARP target address under a prefix.
    pub fn arp_tip(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.arp_tip = Some((addr, prefix_len));
        self
    }

    /// Match the ARP sender hardware address under a mask.
    pub fn arp_sha(mut self, mac: [u8; 6], mask: [u8; 6]) -> Self {
        self.arp_sha = Some((mac, mask));
        self
    }

    /// Match the ARP target hardware address under a mask.
    pub fn arp_tha(mut self, mac: [u8; 6], mask: [u8; 6]) -> Self {
        self.arp_tha = Some((mac, mask));
        self
    }

    /// Match a tunnel's key id (a VNI, a GRE key).
    pub fn enc_key_id(mut self, id: u32) -> Self {
        self.enc_key_id = Some(id);
        self
    }

    /// Match a tunnel's outer source address under a prefix.
    pub fn enc_src_ip(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.enc_src_ip = Some((addr, prefix_len));
        self
    }

    /// Match a tunnel's outer destination address under a prefix.
    pub fn enc_dst_ip(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.enc_dst_ip = Some((addr, prefix_len));
        self
    }

    /// Match a tunnel's outer UDP destination port.
    pub fn enc_dst_port(mut self, port: u16) -> Self {
        self.enc_dst_port = Some(port);
        self
    }

    /// Match a tunnel's outer TOS under a mask.
    pub fn enc_tos(mut self, tos: u8, mask: u8) -> Self {
        self.enc_tos = Some((tos, mask));
        self
    }

    /// Match a tunnel's outer TTL under a mask.
    pub fn enc_ttl(mut self, ttl: u8, mask: u8) -> Self {
        self.enc_ttl = Some((ttl, mask));
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Jump to another chain on match.
    ///
    /// This adds a goto_chain action that transfers packet processing
    /// to the specified chain when this filter matches. With
    /// [`actions`](Self::actions) it runs after them.
    pub fn goto_chain(mut self, chain: u32) -> Self {
        self.goto_chain = Some(chain);
        self
    }

    /// Run actions on a match: tc(8)'s `flower … action …`.
    ///
    /// They share `TCA_FLOWER_ACT` with [`goto_chain`](Self::goto_chain),
    /// which, when set, runs after them. Until 0.30 the builder could only
    /// jump chains, so a flower filter on an ingress or clsact hook, where a
    /// classid means nothing, could not act at all (#450).
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::TcHandle;
    /// use nlink::netlink::action::{ActionList, GactAction};
    /// use nlink::netlink::filter::FlowerFilter;
    ///
    /// // tc filter add dev eth0 ingress protocol ip flower ip_proto tcp dst_port 23 action drop
    /// let telnet = FlowerFilter::new()
    ///     .ipv4()
    ///     .ip_proto_tcp()
    ///     .dst_port(23)
    ///     .actions(ActionList::new().with(GactAction::drop()))
    ///     .build();
    /// conn.add_filter_full("eth0", TcHandle::INGRESS, None, EthProto::IP, FilterPriority::new(10), telnet)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn actions(mut self, actions: ActionList) -> Self {
        self.actions = Some(actions);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// The TCA_FLOWER_KEY_ETH_TYPE this filter writes, resolved the way
    /// tc(8) resolves it: an ethertype set on the filter (`.ipv4()`,
    /// `.qinq()`, an address setter, `eth_type`), else the filter's protocol
    /// unless that is `all` (#433), else 802.1Q when a VLAN key needs a tag.
    ///
    /// The VLAN default is resolved here and not in the setter so that
    /// `protocol 802.1ad flower vlan_id 20` matches an 802.1AD tag. When the
    /// setter wrote 0x8100, a filter that the protocol had already
    /// restricted to 0x88a8 frames asked for a 0x8100 TPID and matched
    /// nothing.
    fn effective_eth_type(&self) -> Option<u16> {
        let protocol = (!matches!(self.protocol, 0 | ETH_P_ALL)).then_some(self.protocol);
        // Under a VLAN tag, an address's implied ethertype is the inner
        // protocol's, which `vlan_ethtype` carries: the outer one stays the
        // tag the filter is installed under (#827).
        if self.vlan_ethtype.is_some()
            && let Some(tag) = protocol.filter(|p| matches!(p, 0x8100 | 0x88A8))
        {
            return Some(tag);
        }
        self.eth_type
            .or(protocol)
            .or((self.vlan_id.is_some() || self.vlan_prio.is_some()).then_some(0x8100))
    }

    /// Parse a tc-style flower params slice into a typed `FlowerFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id (`1:10`)
    /// - `ip_proto <name|num>` — `tcp` / `udp` / `sctp` / `icmp` /
    ///   `icmpv6`, or a protocol number in hex as tc(8) reads it (`2f` or
    ///   `0x2f` is GRE; `47` is 0x47)
    /// - `src_ip <addr[/prefix]>` / `dst_ip <addr[/prefix]>` — IPv4 or
    ///   IPv6 (auto-detected via `:` presence). Bare address means
    ///   `/32` (v4) or `/128` (v6). Sets `eth_type` if not already set.
    /// - `src_port <port|min-max>` / `dst_port <port|min-max>` — a range
    ///   (`8000-8100`, inclusive, `min` below `max`) is a port-range key,
    ///   as in tc(8). Either needs `ip_proto` `tcp`, `udp` or `sctp`, in any
    ///   order; installing one without is an error
    /// - `src_mac <mac>` / `dst_mac <mac>` — `xx:xx:xx:xx:xx:xx`
    /// - `eth_type <name|hex>` — `ip` / `ipv4` / `ipv6` / `arp` / `vlan`
    ///   / `802.1q` / `802.1ad`, or hex (`0x800`). nlink's own token: tc(8)
    ///   takes the ethertype from the filter's `protocol`, and so does nlink
    ///   when this is absent (#433)
    /// - `vlan_id <1-4094>` / `vlan_prio <0-7>`
    /// - `ip_tos <val[/mask]>` / `ip_ttl <val[/mask]>` — the value in
    ///   decimal (hex if it is not decimal: `1a`, `0x10`), the mask in hex,
    ///   as tc(8) reads them; a bare value implies `/ff`
    /// - `tcp_flags <flags[/mask]>` — hex u16
    /// - `skip_hw` / `skip_sw` — flag tokens (no value)
    ///
    /// **Not yet typed-modelled** (returns `Error::invalid_message`):
    /// `ct_state`, `ct_zone`, `ct_mark`, `enc_key_id`,
    /// `enc_dst_ip`, `enc_src_ip`, `enc_dst_port`, `indev`. File
    /// an issue if you need any of these.
    ///
    /// Stricter than the legacy `add_flower_options`: unknown tokens,
    /// missing values, and unparseable addresses / ports / MACs all
    /// return `Error::invalid_message` rather than silently being
    /// skipped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::filter::FlowerFilter;
    /// let f = FlowerFilter::parse_params(&[
    ///     "classid", "1:10",
    ///     "ip_proto", "tcp",
    ///     "dst_port", "80",
    /// ])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("flower: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("flower: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "ip_proto" => {
                    let s = need_value()?;
                    let proto = parse_flower_ip_proto(s)?;
                    f = f.ip_proto(proto);
                    i += 2;
                }
                "src_port" => {
                    f = match parse_flower_port(key, need_value()?)? {
                        FlowerPort::One(port) => f.src_port(port),
                        FlowerPort::Range(min, max) => f.src_port_range(min, max),
                    };
                    i += 2;
                }
                "dst_port" => {
                    f = match parse_flower_port(key, need_value()?)? {
                        FlowerPort::One(port) => f.dst_port(port),
                        FlowerPort::Range(min, max) => f.dst_port_range(min, max),
                    };
                    i += 2;
                }
                "src_ip" => {
                    let s = need_value()?;
                    if s.contains(':') {
                        let (addr, plen) = parse_ipv6_with_prefix(s)?;
                        f = f.src_ipv6(addr, plen);
                    } else {
                        let (addr, plen) = parse_ipv4_with_prefix(s)?;
                        f = f.src_ipv4(addr, plen);
                    }
                    i += 2;
                }
                "dst_ip" => {
                    let s = need_value()?;
                    if s.contains(':') {
                        let (addr, plen) = parse_ipv6_with_prefix(s)?;
                        f = f.dst_ipv6(addr, plen);
                    } else {
                        let (addr, plen) = parse_ipv4_with_prefix(s)?;
                        f = f.dst_ipv4(addr, plen);
                    }
                    i += 2;
                }
                // A MAC with an optional `/MASK`, a MAC or a bit count (#827).
                "src_mac" => {
                    let (mac, mask) = parse_flower_mac(need_value()?, key)?;
                    f = f.src_mac_masked(mac, mask);
                    i += 2;
                }
                "dst_mac" => {
                    let (mac, mask) = parse_flower_mac(need_value()?, key)?;
                    f = f.dst_mac_masked(mac, mask);
                    i += 2;
                }
                "eth_type" => {
                    let s = need_value()?;
                    f.eth_type = Some(parse_flower_eth_type(s)?);
                    i += 2;
                }
                "vlan_id" => {
                    let s = need_value()?;
                    let id: u16 = s.parse().map_err(|_| {
                        Error::invalid_message(format!("flower: invalid vlan_id `{s}`"))
                    })?;
                    if !(1..=4094).contains(&id) {
                        return Err(Error::invalid_message(format!(
                            "flower: vlan_id `{id}` out of range (must be 1-4094)"
                        )));
                    }
                    f = f.vlan_id(id);
                    i += 2;
                }
                "vlan_prio" => {
                    let s = need_value()?;
                    let prio: u8 = s.parse().map_err(|_| {
                        Error::invalid_message(format!("flower: invalid vlan_prio `{s}`"))
                    })?;
                    if prio > 7 {
                        return Err(Error::invalid_message(format!(
                            "flower: vlan_prio `{prio}` out of range (must be 0-7)"
                        )));
                    }
                    f = f.vlan_prio(prio);
                    i += 2;
                }
                "ip_tos" => {
                    let (v, m) = parse_value_mask_u8(need_value()?, "ip_tos")?;
                    f = f.ip_tos(v, m);
                    i += 2;
                }
                "ip_ttl" => {
                    let (v, m) = parse_value_mask_u8(need_value()?, "ip_ttl")?;
                    f = f.ip_ttl(v, m);
                    i += 2;
                }
                "tcp_flags" => {
                    let (v, m) = parse_value_mask_u16_hex(need_value()?, "tcp_flags")?;
                    f = f.tcp_flags(v, m);
                    i += 2;
                }
                "skip_hw" => {
                    f.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
                    i += 1;
                }
                "skip_sw" => {
                    f.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
                    i += 1;
                }
                "chain" | "goto_chain" => {
                    let s = need_value()?;
                    let n: u32 = s.parse().map_err(|_| {
                        Error::invalid_message(format!("flower: invalid {key} `{s}`"))
                    })?;
                    f = if key == "chain" { f.chain(n) } else { f.goto_chain(n) };
                    i += 2;
                }
                // tc-flower(8)'s other keys (#827), read as f_flower.c reads
                // them.
                "type" | "code" => {
                    let (v, m) = parse_flower_u8_dec(need_value()?, key, None)?;
                    f = if key == "type" { f.icmp_type(v, m) } else { f.icmp_code(v, m) };
                    i += 2;
                }
                "ip_flags" => {
                    let (v, m) = parse_flower_ip_flags(need_value()?)?;
                    f = f.ip_flags(v, m);
                    i += 2;
                }
                "ct_state" => {
                    let (v, m) = parse_flower_ct_state(need_value()?)?;
                    f = f.ct_state(v, m);
                    i += 2;
                }
                "ct_zone" => {
                    let (v, m) = parse_flower_masked_any(need_value()?, key, u16::MAX.into())?;
                    f = f.ct_zone(v as u16, m as u16);
                    i += 2;
                }
                "ct_mark" => {
                    let (v, m) = parse_flower_masked_any(need_value()?, key, u32::MAX)?;
                    f = f.ct_mark(v, m);
                    i += 2;
                }
                "ct_label" => {
                    let (v, m) = parse_flower_ct_label(need_value()?)?;
                    f = f.ct_labels(v, m);
                    i += 2;
                }
                "indev" => {
                    f = f.indev(need_value()?);
                    i += 2;
                }
                "vlan_ethtype" | "cvlan_ethtype" => {
                    let t = EthProto::new(parse_flower_eth_type(need_value()?)?);
                    f = if key == "vlan_ethtype" { f.vlan_ethtype(t) } else { f.cvlan_ethtype(t) };
                    i += 2;
                }
                "cvlan_id" => {
                    let s = need_value()?;
                    let id = s.parse::<u16>().ok().filter(|id| *id < 4096).ok_or_else(|| {
                        Error::invalid_message(format!("flower: invalid cvlan_id `{s}` (expected 0-4095)"))
                    })?;
                    f = f.cvlan_id(id);
                    i += 2;
                }
                "cvlan_prio" | "mpls_tc" | "mpls_bos" | "mpls_ttl" => {
                    let s = need_value()?;
                    let max = match key {
                        "mpls_bos" => 1,
                        "mpls_ttl" => 255,
                        _ => 7,
                    };
                    let v = s.parse::<u8>().ok().filter(|v| *v <= max).ok_or_else(|| {
                        Error::invalid_message(format!("flower: invalid {key} `{s}` (expected 0-{max})"))
                    })?;
                    f = match key {
                        "cvlan_prio" => f.cvlan_prio(v),
                        "mpls_tc" => f.mpls_tc(v),
                        "mpls_bos" => f.mpls_bos(v),
                        _ => f.mpls_ttl(v),
                    };
                    i += 2;
                }
                "mpls_label" => {
                    let s = need_value()?;
                    let label = s.parse::<u32>().ok().filter(|l| *l <= 0xF_FFFF).ok_or_else(|| {
                        Error::invalid_message(format!("flower: invalid mpls_label `{s}` (expected 0-1048575)"))
                    })?;
                    f = f.mpls_label(label);
                    i += 2;
                }
                "arp_op" => {
                    let names = |s: &str| match s {
                        "request" => Some(1),
                        "reply" => Some(2),
                        _ => None,
                    };
                    let (v, m) = parse_flower_u8_dec(need_value()?, key, Some(&names))?;
                    if v > 2 {
                        return Err(Error::invalid_message(format!(
                            "flower: invalid arp_op `{v}` (expected request, reply, 1 or 2)"
                        )));
                    }
                    f = f.arp_op(v, m);
                    i += 2;
                }
                "arp_sip" | "arp_tip" => {
                    let (addr, plen) = parse_ipv4_with_prefix(need_value()?)?;
                    f = if key == "arp_sip" { f.arp_sip(addr, plen) } else { f.arp_tip(addr, plen) };
                    i += 2;
                }
                "arp_sha" | "arp_tha" => {
                    let (mac, mask) = parse_flower_mac(need_value()?, key)?;
                    f = if key == "arp_sha" { f.arp_sha(mac, mask) } else { f.arp_tha(mac, mask) };
                    i += 2;
                }
                "enc_key_id" => {
                    let s = need_value()?;
                    let id = s.parse::<u32>().map_err(|_| {
                        Error::invalid_message(format!("flower: invalid enc_key_id `{s}`"))
                    })?;
                    f = f.enc_key_id(id);
                    i += 2;
                }
                "enc_src_ip" | "enc_dst_ip" => {
                    let s = need_value()?;
                    let (addr, plen) = if s.contains(':') {
                        let (a, p) = parse_ipv6_with_prefix(s)?;
                        (IpAddr::V6(a), p)
                    } else {
                        let (a, p) = parse_ipv4_with_prefix(s)?;
                        (IpAddr::V4(a), p)
                    };
                    f = if key == "enc_src_ip" { f.enc_src_ip(addr, plen) } else { f.enc_dst_ip(addr, plen) };
                    i += 2;
                }
                "enc_dst_port" => {
                    let s = need_value()?;
                    let port = s.parse::<u16>().map_err(|_| {
                        Error::invalid_message(format!("flower: invalid enc_dst_port `{s}`"))
                    })?;
                    f = f.enc_dst_port(port);
                    i += 2;
                }
                "enc_tos" | "enc_ttl" => {
                    let (v, m) = parse_value_mask_u8(need_value()?, key)?;
                    f = if key == "enc_tos" { f.enc_tos(v, m) } else { f.enc_ttl(v, m) };
                    i += 2;
                }
                "action" | "actions" => {
                    return Err(Error::invalid_message(format!(
                        "flower: `{key}` is not modelled by FlowerFilter::parse_params — build the \
                         filter and attach them with FlowerFilter::actions(ActionList)"
                    )));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "flower: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// The filter as the tokens [`parse_params`](Self::parse_params) reads,
    /// its inverse (#645). Its actions are not in that grammar and are not
    /// written; its protocol and priority go beside the tokens.
    pub fn to_params(&self) -> crate::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut put = |k: &str, v: String| {
            out.push(k.to_string());
            out.push(v);
        };
        if let Some(c) = self.classid {
            put("classid", classid_param(c));
        }
        if let Some(t) = self.eth_type {
            put("eth_type", EthProto::from(t).to_string());
        }
        if let Some(p) = self.ip_proto {
            let name = match p {
                flower::IPPROTO_TCP => "tcp".to_string(),
                flower::IPPROTO_UDP => "udp".to_string(),
                flower::IPPROTO_SCTP => "sctp".to_string(),
                flower::IPPROTO_ICMP => "icmp".to_string(),
                flower::IPPROTO_ICMPV6 => "icmpv6".to_string(),
                other => format!("0x{other:x}"),
            };
            put("ip_proto", name);
        }
        for (key, v4, v6) in [
            ("src_ip", self.src_ipv4, self.src_ipv6),
            ("dst_ip", self.dst_ipv4, self.dst_ipv6),
        ] {
            if let Some((a, l)) = v4 {
                put(key, format!("{a}/{l}"));
            }
            if let Some((a, l)) = v6 {
                put(key, format!("{a}/{l}"));
            }
        }
        for (key, one, range) in [
            ("src_port", self.src_port, self.src_port_range),
            ("dst_port", self.dst_port, self.dst_port_range),
        ] {
            if let Some(p) = one {
                put(key, p.to_string());
            }
            if let Some((lo, hi)) = range {
                put(key, format!("{lo}-{hi}"));
            }
        }
        let mac = |m: [u8; 6]| {
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        let masked_mac = |m: [u8; 6], mask: Option<[u8; 6]>| match mask {
            Some(k) if k != [0xFF; 6] => format!("{}/{}", mac(m), mac(k)),
            _ => mac(m),
        };
        if let Some(m) = self.src_mac {
            put("src_mac", masked_mac(m, self.src_mac_mask));
        }
        if let Some(m) = self.dst_mac {
            put("dst_mac", masked_mac(m, self.dst_mac_mask));
        }
        if let Some(v) = self.vlan_id {
            put("vlan_id", v.to_string());
        }
        if let Some(p) = self.vlan_prio {
            put("vlan_prio", p.to_string());
        }
        if let Some((v, m)) = self.ip_tos {
            put("ip_tos", format!("{v}/0x{m:x}"));
        }
        if let Some((v, m)) = self.ip_ttl {
            put("ip_ttl", format!("{v}/0x{m:x}"));
        }
        if let Some((v, m)) = self.tcp_flags {
            put("tcp_flags", format!("0x{v:x}/0x{m:x}"));
        }
        // The keys #827 added, in tc-flower(8)'s words.
        if let Some((v, m)) = self.icmp_type {
            put("type", format!("{v}/{m}"));
        }
        if let Some((v, m)) = self.icmp_code {
            put("code", format!("{v}/{m}"));
        }
        if let Some((v, m)) = self.ip_flags {
            let mut words = Vec::new();
            for (flag, name) in [
                (flower::TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT, "frag"),
                (flower::TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST, "firstfrag"),
            ] {
                if m & flag != 0 {
                    words.push(if v & flag != 0 { name.to_string() } else { format!("no{name}") });
                }
            }
            if m & !(flower::TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT | flower::TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST) != 0 {
                return Err(Error::not_supported(format!("flower: ip_flags mask {m:#x} has no token")));
            }
            put("ip_flags", words.join("/"));
        }
        if let Some((v, m)) = self.ct_state {
            const STATES: [(&str, u16); 6] = [
                ("trk", flower::TCA_FLOWER_KEY_CT_FLAGS_TRACKED),
                ("new", flower::TCA_FLOWER_KEY_CT_FLAGS_NEW),
                ("est", flower::TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED),
                ("rel", flower::TCA_FLOWER_KEY_CT_FLAGS_RELATED),
                ("inv", flower::TCA_FLOWER_KEY_CT_FLAGS_INVALID),
                ("rpl", flower::TCA_FLOWER_KEY_CT_FLAGS_REPLY),
            ];
            let words: String = STATES
                .iter()
                .filter(|(_, f)| m & f != 0)
                .map(|(n, f)| format!("{}{n}", if v & f != 0 { '+' } else { '-' }))
                .collect();
            put("ct_state", words);
        }
        if let Some((v, m)) = self.ct_zone {
            put("ct_zone", format!("{v}/0x{m:x}"));
        }
        if let Some((v, m)) = self.ct_mark {
            put("ct_mark", format!("{v}/0x{m:x}"));
        }
        if let Some((v, m)) = self.ct_labels {
            let hex = |b: [u8; 16]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            put("ct_label", format!("{}/{}", hex(v), hex(m)));
        }
        if let Some(dev) = &self.indev {
            put("indev", dev.clone());
        }
        if let Some(t) = self.vlan_ethtype {
            put("vlan_ethtype", EthProto::from(t).to_string());
        }
        if let Some(v) = self.cvlan_id {
            put("cvlan_id", v.to_string());
        }
        if let Some(p) = self.cvlan_prio {
            put("cvlan_prio", p.to_string());
        }
        if let Some(t) = self.cvlan_ethtype {
            put("cvlan_ethtype", EthProto::from(t).to_string());
        }
        for (key, v) in [
            ("mpls_label", self.mpls_label),
            ("mpls_tc", self.mpls_tc.map(u32::from)),
            ("mpls_bos", self.mpls_bos.map(u32::from)),
            ("mpls_ttl", self.mpls_ttl.map(u32::from)),
        ] {
            if let Some(v) = v {
                put(key, v.to_string());
            }
        }
        if let Some((v, m)) = self.arp_op {
            put("arp_op", format!("{v}/{m}"));
        }
        if let Some((a, l)) = self.arp_sip {
            put("arp_sip", format!("{a}/{l}"));
        }
        if let Some((a, l)) = self.arp_tip {
            put("arp_tip", format!("{a}/{l}"));
        }
        if let Some((m, k)) = self.arp_sha {
            put("arp_sha", masked_mac(m, Some(k)));
        }
        if let Some((m, k)) = self.arp_tha {
            put("arp_tha", masked_mac(m, Some(k)));
        }
        if let Some(id) = self.enc_key_id {
            put("enc_key_id", id.to_string());
        }
        if let Some((a, l)) = self.enc_src_ip {
            put("enc_src_ip", format!("{a}/{l}"));
        }
        if let Some((a, l)) = self.enc_dst_ip {
            put("enc_dst_ip", format!("{a}/{l}"));
        }
        if let Some(p) = self.enc_dst_port {
            put("enc_dst_port", p.to_string());
        }
        if let Some((v, m)) = self.enc_tos {
            put("enc_tos", format!("{v}/0x{m:x}"));
        }
        if let Some((v, m)) = self.enc_ttl {
            put("enc_ttl", format!("{v}/0x{m:x}"));
        }
        if let Some(c) = self.chain {
            put("chain", c.to_string());
        }
        if let Some(c) = self.goto_chain {
            put("goto_chain", c.to_string());
        }
        out.extend(skip_flags_params("flower", self.flags)?);
        Ok(out)
    }

    /// Its actions, if any.
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    pub(crate) fn action_list(&self) -> Option<&ActionList> {
        self.actions.as_ref()
    }
}

/// A flower `src_port` / `dst_port` value: a port, or tc(8)'s `min-max`.
enum FlowerPort {
    One(u16),
    Range(u16, u16),
}

fn parse_flower_port(key: &str, s: &str) -> crate::Result<FlowerPort> {
    use crate::Error;
    let port = |p: &str| {
        p.parse::<u16>().map_err(|_| {
            Error::invalid_message(format!(
                "flower: invalid {key} `{s}` (expected 0-65535 or min-max)"
            ))
        })
    };
    let Some((min, max)) = s.split_once('-') else {
        return Ok(FlowerPort::One(port(s)?));
    };
    let (min, max) = (port(min)?, port(max)?);
    // `fl_set_key_port_range` refuses `max <= min`; so does tc(8).
    if min >= max {
        return Err(Error::invalid_message(format!(
            "flower: invalid {key} range `{s}` (min must be below max; a single port is \
             `{key} {min}`)"
        )));
    }
    Ok(FlowerPort::Range(min, max))
}

/// A flower `ip_proto`: a name, or a number read as hex the way tc(8) reads
/// it (`flower_parse_ip_proto` → `get_u8(.., 16)`), so `2f` and `0x2f` are
/// GRE and `47` is 0x47. nlink read the number as decimal, and the same
/// command installed a different filter from tc(8)'s (#432).
fn parse_flower_ip_proto(s: &str) -> crate::Result<u8> {
    use crate::Error;
    Ok(match s {
        "tcp" => flower::IPPROTO_TCP,
        "udp" => flower::IPPROTO_UDP,
        "sctp" => flower::IPPROTO_SCTP,
        "icmp" => flower::IPPROTO_ICMP,
        "icmpv6" => flower::IPPROTO_ICMPV6,
        other => u8::from_str_radix(other.strip_prefix("0x").unwrap_or(other), 16).map_err(|_| {
            Error::invalid_message(format!(
                "flower: invalid ip_proto `{other}` (expected tcp/udp/sctp/icmp/icmpv6 or a \
                 protocol number in hex, as tc(8) reads it: 2f or 0x2f for GRE)"
            ))
        })?,
    })
}

/// An `eth_type` value, read as tc(8) reads a protocol (`ll_proto_a2n`):
/// a name, or a number in any base `strtoul` takes. A bare number was read
/// as hex before 0.32, so `2048` meant 0x2048 rather than IPv4 (#515).
fn parse_flower_eth_type(s: &str) -> crate::Result<u16> {
    s.parse::<EthProto>().map(EthProto::as_u16).map_err(|_| {
        crate::Error::invalid_message(format!(
            "flower: invalid eth_type `{s}` (expected a protocol name or a number)"
        ))
    })
}

fn parse_ipv4_with_prefix(s: &str) -> crate::Result<(Ipv4Addr, u8)> {
    use crate::Error;
    if let Some((addr_s, plen_s)) = s.split_once('/') {
        let addr: Ipv4Addr = addr_s.parse().map_err(|_| {
            Error::invalid_message(format!("flower: invalid IPv4 address `{addr_s}`"))
        })?;
        let plen: u8 = plen_s.parse().map_err(|_| {
            Error::invalid_message(format!("flower: invalid IPv4 prefix `{plen_s}`"))
        })?;
        if plen > 32 {
            return Err(Error::invalid_message(format!(
                "flower: IPv4 prefix `{plen}` out of range (max 32)"
            )));
        }
        Ok((addr, plen))
    } else {
        let addr: Ipv4Addr = s
            .parse()
            .map_err(|_| Error::invalid_message(format!("flower: invalid IPv4 address `{s}`")))?;
        Ok((addr, 32))
    }
}

fn parse_ipv6_with_prefix(s: &str) -> crate::Result<(Ipv6Addr, u8)> {
    use crate::Error;
    if let Some((addr_s, plen_s)) = s.rsplit_once('/')
        && let Ok(addr) = addr_s.parse::<Ipv6Addr>()
    {
        let plen: u8 = plen_s.parse().map_err(|_| {
            Error::invalid_message(format!("flower: invalid IPv6 prefix `{plen_s}`"))
        })?;
        if plen > 128 {
            return Err(Error::invalid_message(format!(
                "flower: IPv6 prefix `{plen}` out of range (max 128)"
            )));
        }
        return Ok((addr, plen));
    }
    let addr: Ipv6Addr = s
        .parse()
        .map_err(|_| Error::invalid_message(format!("flower: invalid IPv6 address `{s}`")))?;
    Ok((addr, 128))
}

fn parse_mac(s: &str) -> crate::Result<[u8; 6]> {
    use crate::Error;
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::invalid_message(format!(
            "flower: invalid MAC `{s}` (expected xx:xx:xx:xx:xx:xx)"
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| Error::invalid_message(format!("flower: invalid MAC `{s}`")))?;
    }
    Ok(mac)
}

/// An `ip_tos` / `ip_ttl` `value[/mask]`, read as tc(8)'s
/// `flower_parse_ip_tos_ttl` reads it: the value as decimal, falling back to
/// hex, and the mask as hex. nlink tried hex first. Every all-digit value
/// is valid hex, so `ip_ttl 64` came out as TTL 100 (#447).
fn parse_value_mask_u8(s: &str, label: &str) -> crate::Result<(u8, u8)> {
    use crate::Error;
    let invalid = |t: &str| Error::invalid_message(format!("flower: invalid {label} `{t}`"));
    let hex = |t: &str| u8::from_str_radix(t.strip_prefix("0x").unwrap_or(t), 16);
    let (v, m) = s.split_once('/').map_or((s, None), |(v, m)| (v, Some(m)));
    let value = v.parse::<u8>().or_else(|_| hex(v)).map_err(|_| invalid(v))?;
    let mask = m.map_or(Ok(0xff), |m| hex(m).map_err(|_| invalid(m)))?;
    Ok((value, mask))
}

/// The `TCA_FLOWER_KEY_ETH_TYPE` a dump reports for a flower that wrote a
/// `TCA_FLOWER_KEY_VLAN_ETH_TYPE`, from the attributes it wrote (`get`):
/// the kernel keeps the innermost protocol in `n_proto` and dumps that, so
/// a tag written outermost reads back as `vlan_ethtype`, or under two tags
/// as `cvlan_ethtype`, absent when none was given (#827). `None` when the
/// filter wrote no `vlan_ethtype`: the dump is what was written.
pub(crate) fn flower_dumped_eth_type(get: impl Fn(u16) -> Option<[u8; 2]>) -> Option<Option<[u8; 2]>> {
    let inner = get(flower::TCA_FLOWER_KEY_VLAN_ETH_TYPE)?;
    Some(match u16::from_be_bytes(inner) {
        0x8100 | 0x88A8 => get(flower::TCA_FLOWER_KEY_CVLAN_ETH_TYPE),
        _ => Some(inner),
    })
}

/// Maps a word, such as an ARP opcode's name, to its value.
type ValueNames<'a> = &'a dyn Fn(&str) -> Option<u8>;

/// A `u8` with an optional `/MASK`, both decimal, as tc-flower's
/// `flower_parse_u8()` reads them; `names` maps words such as `request`.
fn parse_flower_u8_dec(s: &str, label: &str, names: Option<ValueNames<'_>>) -> crate::Result<(u8, u8)> {
    use crate::Error;
    let invalid = |t: &str| Error::invalid_message(format!("flower: invalid {label} `{t}`"));
    let (v, m) = s.split_once('/').map_or((s, None), |(v, m)| (v, Some(m)));
    let value = match names.and_then(|n| n(v)) {
        Some(v) => v,
        None => v.parse::<u8>().map_err(|_| invalid(v))?,
    };
    let mask = m.map_or(Ok(u8::MAX), |m| m.parse::<u8>().map_err(|_| invalid(m)))?;
    Ok((value, mask))
}

/// A value with an optional `/MASK`, both in any base, as tc-flower's
/// `flower_parse_u16()`/`flower_parse_u32()` read them; `max` is the
/// field's all-ones.
fn parse_flower_masked_any(s: &str, label: &str, max: u32) -> crate::Result<(u32, u32)> {
    use crate::Error;
    let one = |t: &str| {
        parse_u32_any("flower", label, t).ok().filter(|v| *v <= max).ok_or_else(|| {
            Error::invalid_message(format!("flower: invalid {label} `{t}` (expected up to {max:#x})"))
        })
    };
    match s.split_once('/') {
        Some((v, m)) => Ok((one(v)?, one(m)?)),
        None => Ok((one(s)?, max)),
    }
}

/// `frag`, `firstfrag` and their `no` forms, joined by `/`, as tc-flower's
/// `ip_flags`: the flags, and the mask of those named.
fn parse_flower_ip_flags(s: &str) -> crate::Result<(u32, u32)> {
    use crate::Error;
    let (mut flags, mut mask) = (0u32, 0u32);
    for token in s.split('/') {
        let (no, name) = match token.strip_prefix("no") {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        let flag = match name {
            "frag" => flower::TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT,
            "firstfrag" => flower::TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST,
            _ => {
                return Err(Error::invalid_message(format!(
                    "flower: invalid ip_flags `{s}` (expected frag, firstfrag or their no forms, joined by /)"
                )));
            }
        };
        if no {
            flags &= !flag;
        } else {
            flags |= flag;
        }
        mask |= flag;
    }
    Ok((flags, mask))
}

/// `+trk+est-new`: the conntrack states set and the mask of those named.
fn parse_flower_ct_state(s: &str) -> crate::Result<(u16, u16)> {
    use crate::Error;
    const STATES: [(&str, u16); 6] = [
        ("trk", flower::TCA_FLOWER_KEY_CT_FLAGS_TRACKED),
        ("new", flower::TCA_FLOWER_KEY_CT_FLAGS_NEW),
        ("est", flower::TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED),
        ("rel", flower::TCA_FLOWER_KEY_CT_FLAGS_RELATED),
        ("inv", flower::TCA_FLOWER_KEY_CT_FLAGS_INVALID),
        ("rpl", flower::TCA_FLOWER_KEY_CT_FLAGS_REPLY),
    ];
    let invalid = || {
        Error::invalid_message(format!(
            "flower: invalid ct_state `{s}` (expected +/- before each of trk, new, est, rel, inv, rpl)"
        ))
    };
    let (mut flags, mut mask) = (0u16, 0u16);
    let mut rest = s;
    while !rest.is_empty() {
        let on = match rest.as_bytes()[0] {
            b'+' => true,
            b'-' => false,
            _ => return Err(invalid()),
        };
        let (name, flag) = STATES.iter().find(|(n, _)| rest[1..].starts_with(n)).ok_or_else(invalid)?;
        if on {
            flags |= flag;
        }
        mask |= flag;
        rest = &rest[1 + name.len()..];
    }
    Ok((flags, mask))
}

/// A conntrack label, up to 32 hex digits, with an optional `/MASK`. Sent
/// as all 16 bytes, padded with zeros, which the kernel reads in full.
fn parse_flower_ct_label(s: &str) -> crate::Result<([u8; 16], [u8; 16])> {
    use crate::Error;
    let bytes = |t: &str| -> Option<[u8; 16]> {
        if t.len() > 32 || !t.len().is_multiple_of(2) {
            return None;
        }
        let mut out = [0u8; 16];
        for (n, pair) in t.as_bytes().chunks(2).enumerate() {
            out[n] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(out)
    };
    let invalid = || Error::invalid_message(format!("flower: invalid ct_label `{s}` (expected up to 32 hex digits)"));
    match s.split_once('/') {
        Some((v, m)) => Ok((bytes(v).ok_or_else(invalid)?, bytes(m).ok_or_else(invalid)?)),
        None => Ok((bytes(s).ok_or_else(invalid)?, [0xFF; 16])),
    }
}

/// A MAC with an optional `/MASK`: a MAC, or a count of leading one bits.
fn parse_flower_mac(s: &str, label: &str) -> crate::Result<([u8; 6], [u8; 6])> {
    use crate::Error;
    let (mac, mask) = s.split_once('/').map_or((s, None), |(m, k)| (m, Some(k)));
    let mac = parse_mac(mac)?;
    let mask = match mask {
        None => [0xFF; 6],
        Some(k) => match k.parse::<u32>() {
            Ok(bits) if bits <= 48 => {
                let m = u64::MAX.checked_shl(64 - bits).unwrap_or(0) >> 16;
                let b = m.to_be_bytes();
                [b[2], b[3], b[4], b[5], b[6], b[7]]
            }
            Ok(_) => return Err(Error::invalid_message(format!("flower: invalid {label} mask `{k}`"))),
            Err(_) => parse_mac(k)?,
        },
    };
    Ok((mac, mask))
}

fn parse_value_mask_u16_hex(s: &str, label: &str) -> crate::Result<(u16, u16)> {
    use crate::Error;
    let parse_one = |t: &str| -> crate::Result<u16> {
        let trimmed = t.strip_prefix("0x").unwrap_or(t);
        u16::from_str_radix(trimmed, 16)
            .or_else(|_| t.parse::<u16>())
            .map_err(|_| Error::invalid_message(format!("flower: invalid {label} `{t}`")))
    };
    if let Some((v, m)) = s.split_once('/') {
        Ok((parse_one(v)?, parse_one(m)?))
    } else {
        Ok((parse_one(s)?, 0xffff))
    }
}

/// Map a tc-style flow key name to the typed `FlowKey` enum.
fn parse_flow_key(s: &str) -> crate::Result<FlowKey> {
    use crate::Error;
    Ok(match s {
        "src" => FlowKey::Src,
        "dst" => FlowKey::Dst,
        "proto" => FlowKey::Proto,
        "proto-src" => FlowKey::ProtoSrc,
        "proto-dst" => FlowKey::ProtoDst,
        "iif" => FlowKey::Iif,
        "priority" => FlowKey::Priority,
        "mark" => FlowKey::Mark,
        "nfct" => FlowKey::Nfct,
        "nfct-src" => FlowKey::NfctSrc,
        "nfct-dst" => FlowKey::NfctDst,
        "nfct-proto-src" => FlowKey::NfctProtoSrc,
        "nfct-proto-dst" => FlowKey::NfctProtoDst,
        "rt-classid" => FlowKey::RtClassid,
        "sk-uid" => FlowKey::SkUid,
        "sk-gid" => FlowKey::SkGid,
        "vlan-tag" => FlowKey::VlanTag,
        "rxhash" => FlowKey::RxHash,
        other => {
            return Err(Error::invalid_message(format!(
                "flow: unknown key `{other}` (see FlowKey enum docs for the list)"
            )));
        }
    })
}

/// Parse a u32 in 0x-prefix-means-hex / otherwise-decimal form,
/// matching the tc(8) `parse_hex_or_dec` semantics.
fn parse_flow_u32_hex_or_dec(s: &str, label: &str) -> crate::Result<u32> {
    use crate::Error;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
    .map_err(|_| Error::invalid_message(format!("flow: invalid {label} `{s}`")))
}

/// Helper to create an IPv4 mask from prefix length.
fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else if prefix_len == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        Ipv4Addr::from(mask.to_be_bytes())
    }
}

/// Helper to create an IPv6 mask from prefix length.
fn ipv6_mask(prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        Ipv6Addr::from([0xFFu8; 16])
    } else if prefix_len == 0 {
        Ipv6Addr::from([0u8; 16])
    } else {
        let mut bytes = [0u8; 16];
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        for byte in bytes.iter_mut().take(full_bytes) {
            *byte = 0xFF;
        }
        if full_bytes < 16 && remaining_bits > 0 {
            bytes[full_bytes] = !((1u8 << (8 - remaining_bits)) - 1);
        }
        Ipv6Addr::from(bytes)
    }
}

impl FilterConfig for FlowerFilter {
    from_actions!();

    fn kind(&self) -> &'static str {
        "flower"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // `fl_set_key` reads every L3/L4 key only inside
        //
        //   if (key->basic.n_proto == htons(ETH_P_IP) ||
        //       key->basic.n_proto == htons(ETH_P_IPV6))
        //
        // and `n_proto` comes from TCA_FLOWER_KEY_ETH_TYPE — never from
        // the filter's `tcm_info` protocol. Emitting an ip_proto or a
        // port without it makes the kernel ACK the request and install
        // a classifier that matches *everything*, which is worse than
        // any error: a rule meant for one port silently claims the
        // whole interface. Refuse instead (#288) — and the same for any
        // other ethertype, which drops them just as silently (ARP, or a
        // VLAN tag: nlink writes no TCA_FLOWER_KEY_VLAN_ETH_TYPE, so
        // `n_proto` is never set to the inner protocol) (#424).
        let eth_type = self.effective_eth_type();
        // Under a VLAN tag the kernel takes the network protocol from
        // TCA_FLOWER_KEY_VLAN_ETH_TYPE, and under a second tag from
        // TCA_FLOWER_KEY_CVLAN_ETH_TYPE (`fl_set_key`, #827).
        let is_vlan = |t: Option<u16>| matches!(t, Some(0x8100 | 0x88A8));
        let l3_type = if !is_vlan(eth_type) {
            eth_type
        } else if is_vlan(self.vlan_ethtype) {
            self.cvlan_ethtype
        } else {
            self.vlan_ethtype
        };
        if self.vlan_ethtype.is_some() && !is_vlan(eth_type) {
            return Err(Error::invalid_message(
                "flower: vlan_ethtype needs an 802.1Q or 802.1AD ethertype — cls_flower reads it only under a VLAN tag".to_string(),
            ));
        }
        if (self.cvlan_id.is_some() || self.cvlan_prio.is_some() || self.cvlan_ethtype.is_some())
            && !(is_vlan(eth_type) && is_vlan(self.vlan_ethtype))
        {
            return Err(Error::invalid_message(
                "flower: cvlan_id, cvlan_prio and cvlan_ethtype need a VLAN ethertype and a VLAN vlan_ethtype \
                 (QinQ) — cls_flower reads them only under two tags"
                    .to_string(),
            ));
        }
        // ARP and MPLS keys are read only under their own ethertypes, and
        // the ICMP keys only under IPv4 with ip_proto icmp or IPv6 with
        // icmpv6: anywhere else the kernel drops them into a match-all.
        let arp = [self.arp_op.is_some(), self.arp_sip.is_some(), self.arp_tip.is_some(), self.arp_sha.is_some(), self.arp_tha.is_some()];
        if arp.contains(&true) && !matches!(l3_type, Some(0x0806 | 0x8035)) {
            return Err(Error::invalid_message(
                "flower: arp_op, arp_sip, arp_tip, arp_sha and arp_tha need the ARP or RARP ethertype".to_string(),
            ));
        }
        let mpls = [self.mpls_label.is_some(), self.mpls_tc.is_some(), self.mpls_bos.is_some(), self.mpls_ttl.is_some()];
        if mpls.contains(&true) && !matches!(l3_type, Some(0x8847 | 0x8848)) {
            return Err(Error::invalid_message(
                "flower: mpls_label, mpls_tc, mpls_bos and mpls_ttl need an MPLS ethertype (mpls_uc or mpls_mc)".to_string(),
            ));
        }
        let icmp_keys = match (l3_type, self.ip_proto) {
            (Some(0x0800), Some(flower::IPPROTO_ICMP)) => Some((
                flower::TCA_FLOWER_KEY_ICMPV4_TYPE,
                flower::TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
                flower::TCA_FLOWER_KEY_ICMPV4_CODE,
                flower::TCA_FLOWER_KEY_ICMPV4_CODE_MASK,
            )),
            (Some(0x86DD), Some(flower::IPPROTO_ICMPV6)) => Some((
                flower::TCA_FLOWER_KEY_ICMPV6_TYPE,
                flower::TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,
                flower::TCA_FLOWER_KEY_ICMPV6_CODE,
                flower::TCA_FLOWER_KEY_ICMPV6_CODE_MASK,
            )),
            _ => None,
        };
        if (self.icmp_type.is_some() || self.icmp_code.is_some()) && icmp_keys.is_none() {
            return Err(Error::invalid_message(
                "flower: an ICMP type or code needs ip_proto icmp under IPv4, or icmpv6 under IPv6".to_string(),
            ));
        }
        if !matches!(l3_type, Some(0x0800 | 0x86DD)) {
            let unusable = [
                self.ip_proto.map(|_| "ip_proto"),
                self.src_port.map(|_| "src_port"),
                self.dst_port.map(|_| "dst_port"),
                self.src_port_range.map(|_| "src_port range"),
                self.dst_port_range.map(|_| "dst_port range"),
                self.ip_tos.map(|_| "ip_tos"),
                self.ip_ttl.map(|_| "ip_ttl"),
                self.tcp_flags.map(|_| "tcp_flags"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            if !unusable.is_empty() {
                let other = match l3_type {
                    Some(t) if Some(t) != eth_type => format!(" (the one inside the VLAN tag is {t:#06x})"),
                    Some(t) => format!(" (this one is {t:#06x})"),
                    None => String::new(),
                };
                return Err(Error::invalid_message(format!(
                    "flower: {} needs an ethertype of IPv4 or IPv6{other} — cls_flower \
                     discards L3/L4 keys unless TCA_FLOWER_KEY_ETH_TYPE says IPv4 or \
                     IPv6, and would install this as a match-all filter. Call .ipv4() \
                     or .ipv6() (an address setter such as .dst_ipv4() implies one), or \
                     install it under protocol ip or ipv6",
                    unusable.join(", ")
                )));
            }
        }

        // TCP flags are read only under `ip_proto tcp`, and the VLAN keys only
        // when TCA_FLOWER_KEY_ETH_TYPE is a VLAN tag (`is_vlan_key` →
        // `eth_type_vlan`; nlink does not model TCA_FLOWER_KEY_NUM_OF_VLANS,
        // the other way in). Anywhere else the kernel ACKs and drops them,
        // leaving a match-all (#431).
        if self.tcp_flags.is_some() && self.ip_proto != Some(flower::IPPROTO_TCP) {
            let proto = match self.ip_proto {
                Some(p) => format!("ip_proto {p}"),
                None => "no ip_proto".to_string(),
            };
            return Err(Error::invalid_message(format!(
                "flower: tcp_flags needs ip_proto tcp, not {proto} — cls_flower reads TCP \
                 flags only for TCP, and would install this as a match-all"
            )));
        }
        if (self.vlan_id.is_some() || self.vlan_prio.is_some())
            && !matches!(eth_type, Some(0x8100 | 0x88A8))
        {
            let what = match (self.vlan_id, self.vlan_prio) {
                (Some(_), Some(_)) => "vlan_id and vlan_prio",
                (Some(_), None) => "vlan_id",
                _ => "vlan_prio",
            };
            let ethertype = match eth_type {
                Some(t) => format!("ethertype {t:#06x}"),
                None => "no ethertype".to_string(),
            };
            return Err(Error::invalid_message(format!(
                "flower: {what} needs an 802.1Q or 802.1AD ethertype, not {ethertype} — \
                 cls_flower reads VLAN keys only under a VLAN tag, and would install this \
                 as a match-all. Match an IP header inside a VLAN with vlan_ethtype"
            )));
        }

        // Ports, checked the way `fl_set_key` reads them. An exact port is
        // read from the key of the filter's own protocol —
        // TCA_FLOWER_KEY_{TCP,UDP,SCTP}_{SRC,DST}, each only under its
        // `ip_proto` — and a range by `fl_set_key_port_range`, which is
        // only reached for those three as well. For any other protocol, or
        // none, the kernel ACKs and drops the port, which leaves a
        // match-all (#416, #424).
        let has_ports = matches!(
            self.ip_proto,
            Some(flower::IPPROTO_TCP | flower::IPPROTO_UDP | flower::IPPROTO_SCTP)
        );
        let proto = match self.ip_proto {
            Some(p) => format!("ip_proto {p}"),
            None => "no ip_proto".to_string(),
        };
        for (what, exact, range) in [
            ("src_port", self.src_port, self.src_port_range),
            ("dst_port", self.dst_port, self.dst_port_range),
        ] {
            if let Some((min, max)) = range {
                if min >= max {
                    return Err(Error::invalid_message(format!(
                        "flower: {what} range {min}-{max} is invalid: the kernel needs min \
                         below max (a single port is .{what}({min}))"
                    )));
                }
                if !has_ports {
                    return Err(Error::invalid_message(format!(
                        "flower: a {what} range needs ip_proto tcp, udp or sctp, not {proto} — \
                         cls_flower reads port ranges for those only, and would install this \
                         as a match-all"
                    )));
                }
            }
            if let Some(port) = exact
                && !has_ports
            {
                return Err(Error::invalid_message(format!(
                    "flower: {what} {port} needs ip_proto tcp, udp or sctp, not {proto} — \
                     cls_flower reads ports for those only, and would install this as a \
                     match-all"
                )));
            }
        }

        // Add classid
        if let Some(classid) = self.classid {
            builder.append_attr_u32(flower::TCA_FLOWER_CLASSID, classid);
        }

        // Add flags
        if self.flags != 0 {
            builder.append_attr_u32(flower::TCA_FLOWER_FLAGS, self.flags);
        }

        // Add ethernet type
        if let Some(eth_type) = eth_type {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_TYPE, &eth_type.to_be_bytes());
        }

        // Add IP protocol
        if let Some(proto) = self.ip_proto {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_PROTO, &[proto]);
        }

        // Add source IPv4
        if let Some((addr, prefix_len)) = self.src_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC_MASK, &mask.octets());
        }

        // Add destination IPv4
        if let Some((addr, prefix_len)) = self.dst_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST_MASK, &mask.octets());
        }

        // Add source IPv6
        if let Some((addr, prefix_len)) = self.src_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC_MASK, &mask.octets());
        }

        // Add destination IPv6
        if let Some((addr, prefix_len)) = self.dst_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST_MASK, &mask.octets());
        }

        // Exact ports: the protocol's own keys, network order. No mask —
        // `fl_set_key_val` fills an absent one with all-ones. The checks
        // above leave no port on any other protocol.
        let port_keys = match self.ip_proto {
            Some(flower::IPPROTO_TCP) => Some((
                flower::TCA_FLOWER_KEY_TCP_SRC,
                flower::TCA_FLOWER_KEY_TCP_DST,
            )),
            Some(flower::IPPROTO_UDP) => Some((
                flower::TCA_FLOWER_KEY_UDP_SRC,
                flower::TCA_FLOWER_KEY_UDP_DST,
            )),
            Some(flower::IPPROTO_SCTP) => Some((
                flower::TCA_FLOWER_KEY_SCTP_SRC,
                flower::TCA_FLOWER_KEY_SCTP_DST,
            )),
            _ => None,
        };
        if let Some((src_key, dst_key)) = port_keys {
            if let Some(port) = self.src_port {
                builder.append_attr(src_key, &port.to_be_bytes());
            }
            if let Some(port) = self.dst_port {
                builder.append_attr(dst_key, &port.to_be_bytes());
            }
        }

        // Port ranges: protocol-independent attributes, network order.
        if let Some((min, max)) = self.src_port_range {
            builder.append_attr(flower::TCA_FLOWER_KEY_PORT_SRC_MIN, &min.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_PORT_SRC_MAX, &max.to_be_bytes());
        }
        if let Some((min, max)) = self.dst_port_range {
            builder.append_attr(flower::TCA_FLOWER_KEY_PORT_DST_MIN, &min.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_PORT_DST_MAX, &max.to_be_bytes());
        }

        // Add MAC addresses
        if let Some(mac) = self.src_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC_MASK, &self.src_mac_mask.unwrap_or([0xFF; 6]));
        }

        if let Some(mac) = self.dst_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST_MASK, &self.dst_mac_mask.unwrap_or([0xFF; 6]));
        }

        // Add VLAN
        if let Some(id) = self.vlan_id {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_ID, &id.to_ne_bytes());
        }

        if let Some(prio) = self.vlan_prio {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_PRIO, &[prio]);
        }

        // Add IP TOS
        if let Some((tos, mask)) = self.ip_tos {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS, &[tos]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS_MASK, &[mask]);
        }

        // Add IP TTL
        if let Some((ttl, mask)) = self.ip_ttl {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL, &[ttl]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL_MASK, &[mask]);
        }

        // Add TCP flags
        if let Some((flags, mask)) = self.tcp_flags {
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS, &flags.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS_MASK, &mask.to_be_bytes());
        }

        // The keys #827 added, as tc-flower writes them.
        if let Some((t_key, t_mask, c_key, c_mask)) = icmp_keys {
            if let Some((v, m)) = self.icmp_type {
                builder.append_attr(t_key, &[v]);
                builder.append_attr(t_mask, &[m]);
            }
            if let Some((v, m)) = self.icmp_code {
                builder.append_attr(c_key, &[v]);
                builder.append_attr(c_mask, &[m]);
            }
        }
        if let Some((v, m)) = self.ip_flags {
            builder.append_attr(flower::TCA_FLOWER_KEY_FLAGS, &v.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_FLAGS_MASK, &m.to_be_bytes());
        }
        if let Some((v, m)) = self.ct_state {
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_STATE, &v.to_ne_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_STATE_MASK, &m.to_ne_bytes());
        }
        if let Some((v, m)) = self.ct_zone {
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_ZONE, &v.to_ne_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_ZONE_MASK, &m.to_ne_bytes());
        }
        if let Some((v, m)) = self.ct_mark {
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_MARK, &v.to_ne_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_MARK_MASK, &m.to_ne_bytes());
        }
        if let Some((v, m)) = self.ct_labels {
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_LABELS, &v);
            builder.append_attr(flower::TCA_FLOWER_KEY_CT_LABELS_MASK, &m);
        }
        if let Some(dev) = &self.indev {
            builder.append_attr_str(flower::TCA_FLOWER_INDEV, dev);
        }
        if let Some(t) = self.vlan_ethtype {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_ETH_TYPE, &t.to_be_bytes());
        }
        if let Some(id) = self.cvlan_id {
            builder.append_attr(flower::TCA_FLOWER_KEY_CVLAN_ID, &id.to_ne_bytes());
        }
        if let Some(prio) = self.cvlan_prio {
            builder.append_attr(flower::TCA_FLOWER_KEY_CVLAN_PRIO, &[prio]);
        }
        if let Some(t) = self.cvlan_ethtype {
            builder.append_attr(flower::TCA_FLOWER_KEY_CVLAN_ETH_TYPE, &t.to_be_bytes());
        }
        if let Some(label) = self.mpls_label {
            builder.append_attr(flower::TCA_FLOWER_KEY_MPLS_LABEL, &label.to_ne_bytes());
        }
        if let Some(tc) = self.mpls_tc {
            builder.append_attr(flower::TCA_FLOWER_KEY_MPLS_TC, &[tc]);
        }
        if let Some(bos) = self.mpls_bos {
            builder.append_attr(flower::TCA_FLOWER_KEY_MPLS_BOS, &[bos]);
        }
        if let Some(ttl) = self.mpls_ttl {
            builder.append_attr(flower::TCA_FLOWER_KEY_MPLS_TTL, &[ttl]);
        }
        if let Some((op, mask)) = self.arp_op {
            builder.append_attr(flower::TCA_FLOWER_KEY_ARP_OP, &[op]);
            builder.append_attr(flower::TCA_FLOWER_KEY_ARP_OP_MASK, &[mask]);
        }
        for (addr, key, mask_key) in [
            (self.arp_sip, flower::TCA_FLOWER_KEY_ARP_SIP, flower::TCA_FLOWER_KEY_ARP_SIP_MASK),
            (self.arp_tip, flower::TCA_FLOWER_KEY_ARP_TIP, flower::TCA_FLOWER_KEY_ARP_TIP_MASK),
        ] {
            if let Some((addr, plen)) = addr {
                builder.append_attr(key, &addr.octets());
                builder.append_attr(mask_key, &ipv4_mask(plen).octets());
            }
        }
        for (mac, key, mask_key) in [
            (self.arp_sha, flower::TCA_FLOWER_KEY_ARP_SHA, flower::TCA_FLOWER_KEY_ARP_SHA_MASK),
            (self.arp_tha, flower::TCA_FLOWER_KEY_ARP_THA, flower::TCA_FLOWER_KEY_ARP_THA_MASK),
        ] {
            if let Some((mac, mask)) = mac {
                builder.append_attr(key, &mac);
                builder.append_attr(mask_key, &mask);
            }
        }
        if let Some(id) = self.enc_key_id {
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_KEY_ID, &id.to_be_bytes());
        }
        for (addr, v4, v4_mask, v6, v6_mask) in [
            (
                self.enc_src_ip,
                flower::TCA_FLOWER_KEY_ENC_IPV4_SRC,
                flower::TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
                flower::TCA_FLOWER_KEY_ENC_IPV6_SRC,
                flower::TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
            ),
            (
                self.enc_dst_ip,
                flower::TCA_FLOWER_KEY_ENC_IPV4_DST,
                flower::TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
                flower::TCA_FLOWER_KEY_ENC_IPV6_DST,
                flower::TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
            ),
        ] {
            match addr {
                Some((IpAddr::V4(a), plen)) => {
                    builder.append_attr(v4, &a.octets());
                    builder.append_attr(v4_mask, &ipv4_mask(plen).octets());
                }
                Some((IpAddr::V6(a), plen)) => {
                    builder.append_attr(v6, &a.octets());
                    builder.append_attr(v6_mask, &ipv6_mask(plen).octets());
                }
                None => {}
            }
        }
        if let Some(port) = self.enc_dst_port {
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_UDP_DST_PORT, &port.to_be_bytes());
        }
        if let Some((v, m)) = self.enc_tos {
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_IP_TOS, &[v]);
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_IP_TOS_MASK, &[m]);
        }
        if let Some((v, m)) = self.enc_ttl {
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_IP_TTL, &[v]);
            builder.append_attr(flower::TCA_FLOWER_KEY_ENC_IP_TTL_MASK, &[m]);
        }

        // Actions and goto_chain share `TCA_FLOWER_ACT`, so they share one
        // nest, as matchall's do: writing the attribute twice would leave
        // the kernel to keep one and silently drop the other.
        if self.actions.is_some() || self.goto_chain.is_some() {
            use super::{
                action::{ActionConfig, GactAction},
                types::tc::{action, filter::flower::TCA_FLOWER_ACT},
            };

            let act_token = builder.nest_start(TCA_FLOWER_ACT);

            // `write_to` numbers its entries from 1; the goto continues that
            // numbering rather than colliding with the first action.
            let mut next_index = 1u16;
            if let Some(actions) = &self.actions {
                actions.write_to(builder)?;
                next_index += actions.len() as u16;
            }

            if let Some(chain) = self.goto_chain {
                let goto = GactAction::goto_chain(chain);
                let goto_token = builder.nest_start(next_index);
                builder.append_attr_str(action::TCA_ACT_KIND, goto.kind());
                let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
                goto.write_options(builder)?;
                builder.nest_end(opt_token);
                builder.nest_end(goto_token);
            }

            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// MatchallFilter
// ============================================================================

/// Matchall filter configuration.
///
/// The matchall filter matches all packets and is typically used with actions.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::MatchallFilter;
///
/// let filter = MatchallFilter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct MatchallFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Filter flags.
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Goto chain action (jump to another chain on match).
    goto_chain: Option<u32>,
    /// Actions to run on every packet.
    actions: Option<ActionList>,
}

impl MatchallFilter {
    /// Create a new matchall filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Attach actions to run on every packet.
    ///
    /// This is what `cls_matchall` is normally installed for: it carries no
    /// keys, so the action list is the point. Composes with
    /// [`Self::goto_chain`] — both live in `TCA_MATCHALL_ACT`, and the goto
    /// is emitted last, which is the order `tc(8)` uses and the order the
    /// kernel runs them in.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::TcHandle;
    /// use nlink::netlink::action::{ActionList, MirredAction};
    /// use nlink::netlink::filter::MatchallFilter;
    ///
    /// let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let mirror_to = conn
    ///     .get_link_by_name("eth1")
    ///     .await?
    ///     .expect("eth1 exists")
    ///     .ifindex();
    ///
    /// // Mirror every ingress packet to eth1.
    /// let filter = MatchallFilter::new()
    ///     .actions(ActionList::new().with(MirredAction::mirror_to_egress(mirror_to)));
    /// conn.add_filter("eth0", TcHandle::CLSACT_INGRESS, filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn actions(mut self, actions: ActionList) -> Self {
        self.actions = Some(actions);
        self
    }

    /// Jump to another chain on match.
    ///
    /// This adds a goto_chain action that transfers packet processing
    /// to the specified chain when this filter matches.
    pub fn goto_chain(mut self, chain: u32) -> Self {
        self.goto_chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style matchall params slice into a typed
    /// `MatchallFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `chain <n>` — chain index.
    /// - `goto_chain <n>` — jump-on-match action.
    /// - `skip_hw` / `skip_sw` — flag tokens.
    ///
    /// Stricter than the legacy parser (which only recognised
    /// `classid` / `flowid` and silently dropped everything else):
    /// unknown tokens, missing values, and unparseable handles
    /// return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("matchall: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("matchall: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("matchall: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                "goto_chain" => {
                    let s = need_value()?;
                    f = f.goto_chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("matchall: invalid goto_chain `{s}`"))
                    })?);
                    i += 2;
                }
                "skip_hw" => {
                    f = f.skip_hw();
                    i += 1;
                }
                "skip_sw" => {
                    f = f.skip_sw();
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "matchall: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// The filter as the tokens [`parse_params`](Self::parse_params) reads,
    /// its inverse (#645). Its actions are not in that grammar and are not
    /// written.
    pub fn to_params(&self) -> crate::Result<Vec<String>> {
        let mut out = Vec::new();
        if let Some(c) = self.classid {
            out.extend(["classid".to_string(), classid_param(c)]);
        }
        if let Some(c) = self.chain {
            out.extend(["chain".to_string(), c.to_string()]);
        }
        if let Some(c) = self.goto_chain {
            out.extend(["goto_chain".to_string(), c.to_string()]);
        }
        out.extend(skip_flags_params("matchall", self.flags)?);
        Ok(out)
    }

    /// Its actions, if any.
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    pub(crate) fn action_list(&self) -> Option<&ActionList> {
        self.actions.as_ref()
    }
}

impl FilterConfig for MatchallFilter {
    from_actions!();

    fn kind(&self) -> &'static str {
        "matchall"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(matchall::TCA_MATCHALL_CLASSID, classid);
        }

        if self.flags != 0 {
            builder.append_attr_u32(matchall::TCA_MATCHALL_FLAGS, self.flags);
        }

        // Actions and goto_chain share `TCA_MATCHALL_ACT`, so they share one
        // nest: writing the attribute twice would leave the kernel to pick
        // one and silently drop the other.
        if self.actions.is_some() || self.goto_chain.is_some() {
            use super::{
                action::{ActionConfig, GactAction},
                types::tc::action,
            };

            let act_token = builder.nest_start(matchall::TCA_MATCHALL_ACT);

            // `write_to` numbers its entries from 1; the goto continues that
            // numbering rather than colliding with the first action.
            let mut next_index = 1u16;
            if let Some(actions) = &self.actions {
                actions.write_to(builder)?;
                next_index += actions.len() as u16;
            }

            if let Some(chain) = self.goto_chain {
                let goto = GactAction::goto_chain(chain);
                let goto_token = builder.nest_start(next_index);
                builder.append_attr_str(action::TCA_ACT_KIND, goto.kind());
                let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
                goto.write_options(builder)?;
                builder.nest_end(opt_token);
                builder.nest_end(goto_token);
            }

            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// FwFilter
// ============================================================================

/// Firewall mark (fw) filter configuration.
///
/// The fw filter matches packets based on the firewall mark (fwmark) set by iptables.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::FwFilter;
///
/// // Match on the firewall mark. The mark itself is the filter *handle*,
/// // passed to `add_filter_full`; the builder carries the mask.
/// let filter = FwFilter::new()
///     .mask(0xFF)
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .build();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct FwFilter {
    /// Mask for the mark.
    mask: u32,
    /// Target class ID.
    classid: Option<u32>,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Match only packets that arrived on this device (tc(8)'s `indev`,
    /// #829); the kernel resolves the name in the filter's namespace.
    indev: Option<String>,
}

impl FwFilter {
    /// Create a new fw filter builder.
    ///
    /// Note: The firewall mark is specified as the filter handle when calling
    /// `add_filter_full()`. Use handle format like "10" for fwmark 10.
    pub fn new() -> Self {
        Self {
            mask: 0xFFFFFFFF,
            classid: None,
            chain: None,
            indev: None,
        }
    }

    /// Set the mask for the mark.
    pub fn mask(mut self, mask: u32) -> Self {
        self.mask = mask;
        self
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Match only packets that arrived on `dev`.
    pub fn indev(mut self, dev: impl Into<String>) -> Self {
        self.indev = Some(dev.into());
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fw params slice into a typed `FwFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `mask <hex|dec>` — mask for the firewall mark.
    /// - `indev <dev>` — the device packets arrived on (#829).
    /// - `chain <n>` — chain index.
    ///
    /// Stricter than the legacy parser: unknown tokens, missing
    /// values, and unparseable values return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("fw: `{key}` requires a value")))
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("fw: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "mask" => {
                    let s = need_value()?;
                    // Match the legacy semantics: "0x"-prefix is hex,
                    // everything else is decimal. Hex-first guessing
                    // would silently flip "255" to 0x255 = 597.
                    let m =
                        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                            u32::from_str_radix(hex, 16)
                        } else {
                            s.parse::<u32>()
                        }
                        .map_err(|_| {
                            Error::invalid_message(format!(
                                "fw: invalid mask `{s}` (expected hex `0xNN` or decimal u32)"
                            ))
                        })?;
                    f = f.mask(m);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f =
                        f.chain(s.parse().map_err(|_| {
                            Error::invalid_message(format!("fw: invalid chain `{s}`"))
                        })?);
                    i += 2;
                }
                "indev" => {
                    f = f.indev(need_value()?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "fw: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// The filter as the tokens [`parse_params`](Self::parse_params) reads,
    /// its inverse (#645).
    pub fn to_params(&self) -> crate::Result<Vec<String>> {
        let mut out = Vec::new();
        if let Some(c) = self.classid {
            out.extend(["classid".to_string(), classid_param(c)]);
        }
        if self.mask != 0xFFFF_FFFF {
            out.extend(["mask".to_string(), format!("0x{:x}", self.mask)]);
        }
        if let Some(dev) = &self.indev {
            out.extend(["indev".to_string(), dev.clone()]);
        }
        if let Some(c) = self.chain {
            out.extend(["chain".to_string(), c.to_string()]);
        }
        Ok(out)
    }
}

impl Default for FwFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterConfig for FwFilter {
    fn kind(&self) -> &'static str {
        "fw"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(fw::TCA_FW_CLASSID, classid);
        }

        if self.mask != 0xFFFFFFFF {
            builder.append_attr_u32(fw::TCA_FW_MASK, self.mask);
        }

        if let Some(dev) = &self.indev {
            builder.append_attr_str(fw::TCA_FW_INDEV, dev);
        }

        Ok(())
    }
}

// ============================================================================
// TcindexFilter
// ============================================================================

/// tcindex filter configuration.
///
/// The tcindex classifier maps `skb->tc_index` (set upstream by dsmark
/// or an `skbedit`/`flow` action) through a hash table to a class id.
/// It was the canonical companion to the `dsmark` qdisc for DiffServ;
/// note that the kernel retired `cls_tcindex` in Linux 6.3 and
/// `sch_dsmark` in 6.8, so on current kernels neither can be installed.
///
/// ```no_run
/// use nlink::netlink::filter::TcindexFilter;
/// use nlink::TcHandle;
///
/// let f = TcindexFilter::new()
///     .mask(0xff)
///     .shift(0)
///     .classid(TcHandle::new(1, 0x10))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct TcindexFilter {
    /// Hash-table size.
    hash: Option<u32>,
    /// Mask applied to `tc_index`.
    mask: Option<u16>,
    /// Right shift applied to `tc_index`.
    shift: Option<u32>,
    /// `Some(true)` = fall_through, `Some(false)` = pass_on.
    fall_through: Option<bool>,
    /// Target class id.
    classid: Option<u32>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl TcindexFilter {
    /// Create a new tcindex filter builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hash-table size.
    pub fn hash(mut self, hash: u32) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Set the mask applied to `tc_index`.
    pub fn mask(mut self, mask: u16) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Set the right shift applied to `tc_index`.
    pub fn shift(mut self, shift: u32) -> Self {
        self.shift = Some(shift);
        self
    }

    /// Fall through to the next filter on a miss (vs. `pass_on`).
    pub fn fall_through(mut self, fall_through: bool) -> Self {
        self.fall_through = Some(fall_through);
        self
    }

    /// Set the target class id.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the chain index for this filter.
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style tcindex params slice into a typed
    /// `TcindexFilter`.
    ///
    /// Recognised tokens: `hash <n>`, `mask <hex|dec>`, `shift <n>`,
    /// `fall_through`, `pass_on`, `classid <handle>` (alias `flowid`),
    /// `chain <n>`. Strict: unknown tokens, missing values, and
    /// unparseable values all error.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("tcindex: `{key}` requires a value"))
                })
            };
            match key {
                "hash" => {
                    let s = need_value()?;
                    f.hash = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("tcindex: invalid hash `{s}`"))
                    })?);
                    i += 2;
                }
                "mask" => {
                    let s = need_value()?;
                    let m = if let Some(hex) =
                        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
                    {
                        u16::from_str_radix(hex, 16)
                    } else {
                        s.parse::<u16>()
                    }
                    .map_err(|_| {
                        Error::invalid_message(format!(
                            "tcindex: invalid mask `{s}` (expected hex `0xNN` or decimal u16)"
                        ))
                    })?;
                    f.mask = Some(m);
                    i += 2;
                }
                "shift" => {
                    let s = need_value()?;
                    f.shift = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("tcindex: invalid shift `{s}`"))
                    })?);
                    i += 2;
                }
                "fall_through" => {
                    f.fall_through = Some(true);
                    i += 1;
                }
                "pass_on" => {
                    f.fall_through = Some(false);
                    i += 1;
                }
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("tcindex: invalid {key} `{s}`: {e}"))
                    })?;
                    f.classid = Some(h.as_raw());
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f.chain = Some(s.parse().map_err(|_| {
                        Error::invalid_message(format!("tcindex: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "tcindex: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for TcindexFilter {
    fn kind(&self) -> &'static str {
        "tcindex"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(hash) = self.hash {
            builder.append_attr_u32(tcindex::TCA_TCINDEX_HASH, hash);
        }
        if let Some(mask) = self.mask {
            builder.append_attr_u16(tcindex::TCA_TCINDEX_MASK, mask);
        }
        if let Some(shift) = self.shift {
            builder.append_attr_u32(tcindex::TCA_TCINDEX_SHIFT, shift);
        }
        if let Some(fall_through) = self.fall_through {
            builder.append_attr_u32(tcindex::TCA_TCINDEX_FALL_THROUGH, u32::from(fall_through));
        }
        if let Some(classid) = self.classid {
            builder.append_attr_u32(tcindex::TCA_TCINDEX_CLASSID, classid);
        }
        Ok(())
    }
}

// ============================================================================
// BpfFilter
// ============================================================================

/// BPF filter configuration.
///
/// The BPF filter allows using eBPF programs for packet classification.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::BpfFilter;
///
/// // Attach a BPF program by file descriptor. Loading it is the caller's
/// // job — `aya` or `libbpf-rs` hand back the fd.
/// # let bpf_fd = std::fs::File::open("/dev/null").unwrap();
/// let filter = BpfFilter::new(&bpf_fd)
///     .name("my_classifier")
///     .direct_action()
///     .build();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BpfFilter {
    /// BPF program file descriptor.
    fd: super::bpf_fd::ProgFd,
    /// Program name.
    name: Option<String>,
    /// Use direct action mode.
    direct_action: bool,
    /// Target class ID (for non-direct-action mode).
    classid: Option<u32>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl BpfFilter {
    /// Create a new BPF filter with the given program file descriptor.
    ///
    /// The fd is duplicated, so the caller's can be closed; the duplicate
    /// is closed with the last clone of the filter (#532).
    pub fn new(fd: impl std::os::fd::AsFd) -> Self {
        Self::with_fd(super::bpf_fd::ProgFd::dup(fd))
    }

    #[cfg(test)]
    fn with_raw_fd(fd: i32) -> Self {
        Self::with_fd(super::bpf_fd::ProgFd::Raw(fd))
    }

    fn with_fd(fd: super::bpf_fd::ProgFd) -> Self {
        Self {
            fd,
            name: None,
            direct_action: false,
            classid: None,
            priority: 0,
            protocol: 0x0003, // ETH_P_ALL
            chain: None,
        }
    }

    /// Create a BPF filter from a pinned program path.
    ///
    /// Opens the pinned BPF program at the given path and uses the
    /// resulting file descriptor. The program must be pinned via
    /// `bpf_obj_pin()` or `bpftool prog pin`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::filter::BpfFilter;
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.add_filter("eth0", TcHandle::INGRESS, filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pinned(path: impl AsRef<std::path::Path>) -> crate::netlink::Result<Self> {
        Ok(Self::with_fd(super::bpf_fd::ProgFd::open_pinned(path.as_ref())?))
    }

    /// Set the program name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Enable direct action mode.
    ///
    /// In direct action mode, the BPF program returns the action directly
    /// (TC_ACT_OK, TC_ACT_SHOT, etc.) instead of a classid.
    pub fn direct_action(mut self) -> Self {
        self.direct_action = true;
        self
    }

    /// Set the target class ID (for non-direct-action mode).
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Parse a tc-style bpf params slice into a typed `BpfFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `fd <n>` — raw BPF program file descriptor.
    /// - `pinned <path>` (alias `object-pinned`) — open the pinned
    ///   program at `path` and use its fd. Mutually exclusive with
    ///   `fd`.
    /// - `name <s>` (alias `section`) — program name (informational).
    /// - `direct-action` (alias `da`) — flag, no value. In direct-
    ///   action mode the BPF program returns the action directly
    ///   (TC_ACT_OK / TC_ACT_SHOT / etc.) instead of a classid.
    /// - `classid <handle>` (alias `flowid`) — target class id (for
    ///   non-direct-action mode).
    /// - `chain <n>` — chain index.
    ///
    /// **Required**: either `fd <n>` or `pinned <path>` must be
    /// supplied; the kernel won't accept a BPF filter without a
    /// program reference. The parser returns
    /// `Error::invalid_message` if neither is present.
    ///
    /// **Not yet typed-modelled** (returns `Error::invalid_message`):
    /// `skip_hw` / `skip_sw` — `BpfFilter` doesn't expose a flags
    /// field. File an issue if you need hardware-offload control
    /// on a BPF filter.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use super::bpf_fd::ProgFd;
        use crate::Error;

        let mut fd: Option<ProgFd> = None;
        let mut name: Option<String> = None;
        let mut classid: Option<TcHandle> = None;
        let mut chain: Option<u32> = None;
        let mut direct_action = false;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = |k: &str, idx: usize| {
                params
                    .get(idx + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("bpf: `{k}` requires a value")))
            };
            match key {
                "fd" => {
                    let s = need_value(key, i)?;
                    if fd.is_some() {
                        return Err(Error::invalid_message(
                            "bpf: `fd` and `pinned` are mutually exclusive",
                        ));
                    }
                    fd = Some(ProgFd::Raw(s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "bpf: invalid fd `{s}` (expected signed integer)"
                        ))
                    })?));
                    i += 2;
                }
                "pinned" | "object-pinned" => {
                    let path = need_value(key, i)?;
                    if fd.is_some() {
                        return Err(Error::invalid_message(
                            "bpf: `fd` and `pinned` are mutually exclusive",
                        ));
                    }
                    // `BPF_OBJ_GET`: bpffs refuses `open(2)` on a pin (#710).
                    // The errno survives: ENOENT is not found, EPERM denied (#718).
                    fd = Some(ProgFd::open_pinned(std::path::Path::new(path)).map_err(|e| {
                        Error::from(e).with_context(format!("bpf: open pinned program `{path}`"))
                    })?);
                    i += 2;
                }
                "name" | "section" => {
                    name = Some(need_value(key, i)?.to_string());
                    i += 2;
                }
                "classid" | "flowid" => {
                    let s = need_value(key, i)?;
                    classid = Some(s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("bpf: invalid {key} `{s}`: {e}"))
                    })?);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(key, i)?;
                    chain =
                        Some(s.parse().map_err(|_| {
                            Error::invalid_message(format!("bpf: invalid chain `{s}`"))
                        })?);
                    i += 2;
                }
                "da" | "direct-action" => {
                    direct_action = true;
                    i += 1;
                }
                "skip_hw" | "skip_sw" => {
                    return Err(Error::invalid_message(format!(
                        "bpf: `{key}` is not modelled by BpfFilter — file an issue if you need hardware-offload control"
                    )));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "bpf: unknown token `{other}`"
                    )));
                }
            }
        }

        let Some(fd) = fd else {
            return Err(Error::invalid_message(
                "bpf: program reference required — supply `fd <n>` or `pinned <path>`",
            ));
        };

        let mut f = Self::with_fd(fd);
        if let Some(n) = name {
            f = f.name(n);
        }
        if let Some(c) = classid {
            f = f.classid(c);
        }
        if let Some(ch) = chain {
            f = f.chain(ch);
        }
        if direct_action {
            f = f.direct_action();
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BpfFilter {
    fn kind(&self) -> &'static str {
        "bpf"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add file descriptor
        builder.append_attr_u32(bpf::TCA_BPF_FD, self.fd.raw()? as u32);

        // Add name if set
        if let Some(ref name) = self.name {
            builder.append_attr_str(bpf::TCA_BPF_NAME, name);
        }

        // Add flags
        let mut flags = 0u32;
        if self.direct_action {
            flags |= bpf::TCA_BPF_FLAG_ACT_DIRECT;
        }
        if flags != 0 {
            builder.append_attr_u32(bpf::TCA_BPF_FLAGS, flags);
        }

        // Add classid if not using direct action
        if let Some(classid) = self.classid {
            builder.append_attr_u32(bpf::TCA_BPF_CLASSID, classid);
        }

        Ok(())
    }
}

// ============================================================================
// BasicFilter — ematch tree (Plan 133 PR C, Plan 142 Phase 1)
// ============================================================================

/// Comparison operator for an [`EmatchCmp`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpOp {
    Eq,
    Gt,
    Lt,
}

/// Layer the offset in [`EmatchCmp::offset`] is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpLayer {
    Link,
    Network,
    Transport,
}

/// Width of the packet field an [`EmatchCmp`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpAlign {
    U8,
    U16,
    U32,
}

/// Relation joining one [`Ematch`] with the next in the tree.
/// `Or` short-circuits on a match; `And` requires both. The last
/// match in the tree is encoded with `TCF_EM_REL_END` regardless
/// of the value carried here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmatchOp {
    And,
    Or,
}

/// `cmp` ematch — compare a packet field against a constant.
///
/// `value` and `mask` are stored host-byte-order; set `trans = true`
/// for the kernel to `ntohl()` the packet bytes before comparison
/// (use this when matching network-byte-order fields with an
/// host-byte-order `value`).
#[derive(Debug, Clone)]
pub struct EmatchCmp {
    pub layer: CmpLayer,
    pub align: CmpAlign,
    pub offset: u16,
    pub mask: u32,
    pub value: u32,
    pub op: CmpOp,
    pub trans: bool,
}

/// `u32` ematch — same selector primitive as `cls_u32`'s key, but
/// embedded in a `cls_basic` ematch tree: the 32-bit word at `offset` (a
/// multiple of four, from the network header) under `mask` equals
/// `value`. `mask` and `value` are that word in host order; the writer
/// sends it big-endian, as the packet holds it (#828).
#[derive(Debug, Clone)]
pub struct EmatchU32 {
    pub mask: u32,
    pub value: u32,
    pub offset: u32,
}

/// Ematch payload kinds. `Meta` is intentionally absent until a
/// downstream user asks for it (the wire format is more complex
/// and benefits from golden-hex captures).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EmatchKind {
    Cmp(EmatchCmp),
    U32(EmatchU32),
}

/// One entry in a `cls_basic` ematch tree.
#[derive(Debug, Clone)]
pub struct Ematch {
    pub kind: EmatchKind,
    /// Relation to the next match. Ignored for the last match in
    /// the tree (encoded as `TCF_EM_REL_END`).
    pub op: EmatchOp,
    /// Set `TCF_EM_INVERT` on this match (negate the result).
    pub negate: bool,
}

impl Ematch {
    /// Build an `Ematch` wrapping a [`EmatchCmp`] with default
    /// relation (AND) and no negation.
    pub fn cmp(cmp: EmatchCmp) -> Self {
        Self {
            kind: EmatchKind::Cmp(cmp),
            op: EmatchOp::And,
            negate: false,
        }
    }

    /// Build an `Ematch` wrapping a [`EmatchU32`] with default
    /// relation (AND) and no negation.
    pub fn u32(u: EmatchU32) -> Self {
        Self {
            kind: EmatchKind::U32(u),
            op: EmatchOp::And,
            negate: false,
        }
    }

    /// Set the relation-to-next-match to OR.
    pub fn or(mut self) -> Self {
        self.op = EmatchOp::Or;
        self
    }

    /// Set the negate flag (`TCF_EM_INVERT`).
    pub fn negate(mut self) -> Self {
        self.negate = true;
        self
    }
}

/// Basic filter configuration with optional ematch tree support.
///
/// `cls_basic` is the kernel's "compose primitive matches via
/// boolean operators" classifier. Use it when `flower` and `u32`
/// are too specialized.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::BasicFilter;
/// use nlink::TcHandle;
///
/// // Match TCP traffic to class 1:10.
/// let filter = BasicFilter::new()
///     .classid(TcHandle::new(1, 0x10))
///     .ip_proto_eq(6)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BasicFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Ematch tree (zero or more matches AND/OR'd together).
    matches: Vec<Ematch>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl BasicFilter {
    /// Create a new basic filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better
    /// performance and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Append an ematch to the tree. Multiple calls accumulate;
    /// the relation between adjacent matches is taken from each
    /// match's [`Ematch::op`]. The last match's `op` is ignored
    /// (encoded as `TCF_EM_REL_END`).
    pub fn ematch(mut self, m: Ematch) -> Self {
        self.matches.push(m);
        self
    }

    /// Convenience: append a `cmp` match for the IP protocol byte
    /// at offset 9 of the network header.
    ///
    /// Equivalent to:
    /// ```no_run
    /// # use nlink::netlink::filter::{BasicFilter, CmpAlign, CmpLayer, CmpOp, Ematch, EmatchCmp};
    /// # fn example(f: BasicFilter, proto: u8) -> BasicFilter {
    /// f.ematch(Ematch::cmp(EmatchCmp {
    ///     layer: CmpLayer::Network,
    ///     align: CmpAlign::U8,
    ///     offset: 9,
    ///     mask: 0xff,
    ///     value: proto as u32,
    ///     op: CmpOp::Eq,
    ///     trans: false,
    /// }))
    /// # }
    /// ```
    pub fn ip_proto_eq(self, proto: u8) -> Self {
        self.ematch(Ematch::cmp(EmatchCmp {
            layer: CmpLayer::Network,
            align: CmpAlign::U8,
            offset: 9,
            mask: 0xff,
            value: proto as u32,
            op: CmpOp::Eq,
            trans: false,
        }))
    }

    /// Parse a `tc(8)`-style `basic` token slice into a typed
    /// filter.
    ///
    /// # Recognised tokens
    ///
    /// - `classid <handle>` / `flowid <handle>` — target class.
    /// - `chain <n>` — TC chain index.
    /// - `ip_proto_eq <name|number>` — convenience for a single
    ///   `cmp` match on the IP protocol byte. Names accepted:
    ///   `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `ah`, `esp`,
    ///   `gre`. Numeric: 0–255.
    ///
    /// - `match EXPR` — a tc-ematch(8) expression (#828): `cmp(...)` and
    ///   `u32(...)` matches, each optionally `not`, joined by `and` or
    ///   `or`, read as tc reads them. A match may be one argument
    ///   (`'cmp(u8 at 9 layer network eq 6)'`, as the shell passes a
    ///   quoted one) or several. Parenthesised groups, `meta(...)` and
    ///   the other modules are not modelled; build those with
    ///   [`BasicFilter::ematch`].
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "classid" | "flowid" => {
                    let s = need_value(params, i, "basic", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("basic: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(params, i, "basic", key)?;
                    f = f.chain(parse_u32_int("basic", "chain", s)?);
                    i += 2;
                }
                "match" => {
                    let (matches, used) = parse_ematch_expr("basic", &params[i + 1..])?;
                    for m in matches {
                        f = f.ematch(m);
                    }
                    i += 1 + used;
                }
                "ip_proto_eq" => {
                    let s = need_value(params, i, "basic", key)?;
                    let proto = parse_ip_proto_name_or_num(s).map_err(|e| {
                        // Re-prefix from `u32:` to `basic:`.
                        let msg = e.to_string().replace("u32:", "basic:");
                        Error::invalid_message(msg)
                    })?;
                    f = f.ip_proto_eq(proto);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "basic: unknown token `{other}` (recognised: classid/flowid, chain, match, ip_proto_eq)"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BasicFilter {
    fn kind(&self) -> &'static str {
        "basic"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(basic::TCA_BASIC_CLASSID, classid);
        }
        if !self.matches.is_empty() {
            write_ematch_tree(builder, &self.matches);
        }
        Ok(())
    }
}

/// One lexeme of a tc-ematch(8) expression, and the argument it came from.
#[derive(Debug, Clone, Copy, PartialEq)]
enum EmLex<'a> {
    Open,
    Close,
    And,
    Or,
    Not,
    Word(&'a str),
}

/// Split the arguments after `match` into lexemes, as tc's lexer does:
/// `(` and `)` stand alone wherever they are, words split on spaces.
fn ematch_lex<'a>(params: &[&'a str]) -> Vec<(EmLex<'a>, usize)> {
    let mut out = Vec::new();
    for (n, p) in params.iter().enumerate() {
        let mut word_start = None;
        let flush = |out: &mut Vec<(EmLex<'a>, usize)>, start: Option<usize>, end: usize| {
            if let Some(start) = start {
                let w = &p[start..end];
                let lex = match w {
                    "and" | "AND" | "&&" => EmLex::And,
                    "or" | "OR" | "||" => EmLex::Or,
                    "not" | "NOT" | "!" => EmLex::Not,
                    _ => EmLex::Word(w),
                };
                out.push((lex, n));
            }
        };
        for (at, c) in p.char_indices() {
            match c {
                '(' | ')' => {
                    flush(&mut out, word_start.take(), at);
                    out.push((if c == '(' { EmLex::Open } else { EmLex::Close }, n));
                }
                c if c.is_whitespace() => flush(&mut out, word_start.take(), at),
                _ => {
                    word_start.get_or_insert(at);
                }
            }
        }
        flush(&mut out, word_start, p.len());
    }
    out
}

/// Parse a tc-ematch(8) expression from the arguments after `match`, as
/// tc's grammar reads it: matches, each optionally `not`, joined by `and`
/// or `or`, ending at the first argument that does not continue it.
/// Returns the matches and how many arguments they took (#828).
fn parse_ematch_expr(kind: &str, params: &[&str]) -> Result<(Vec<Ematch>, usize)> {
    let err = |msg: String| Error::invalid_message(format!("{kind}: match: {msg}"));
    let lex = ematch_lex(params);
    let mut at = 0;
    let mut matches = Vec::new();
    loop {
        let negate = matches!(lex.get(at), Some((EmLex::Not, _)));
        if negate {
            at += 1;
        }
        let (module, args_from) = match (lex.get(at), lex.get(at + 1)) {
            (Some((EmLex::Word(m), _)), Some((EmLex::Open, _))) => (*m, at + 2),
            (Some((EmLex::Open, _)), _) => {
                return Err(err("parenthesised groups are not modelled; build them with BasicFilter::ematch".into()));
            }
            _ => return Err(err("expected `module(args)`, such as `cmp(u8 at 9 layer network eq 6)`".into())),
        };
        let close = lex[args_from..]
            .iter()
            .position(|(l, _)| *l == EmLex::Close)
            .map(|n| args_from + n)
            .ok_or_else(|| err(format!("`{module}(` has no `)`")))?;
        let args: Vec<&str> = lex[args_from..close]
            .iter()
            .map(|(l, _)| match l {
                EmLex::Word(w) => Ok(*w),
                _ => Err(err(format!("unexpected token in `{module}(...)`"))),
            })
            .collect::<Result<_>>()?;
        let mut m = match module {
            "cmp" => Ematch::cmp(parse_em_cmp(&err, &args)?),
            "u32" => Ematch::u32(parse_em_u32(&err, &args)?),
            other => {
                return Err(err(format!(
                    "the `{other}` ematch is not modelled (cmp and u32 are); build it with BasicFilter::ematch"
                )));
            }
        };
        if negate {
            m = m.negate();
        }
        at = close + 1;
        match lex.get(at) {
            Some((EmLex::And, _)) => {
                matches.push(m);
                at += 1;
            }
            Some((EmLex::Or, _)) => {
                matches.push(m.or());
                at += 1;
            }
            _ => {
                matches.push(m);
                break;
            }
        }
    }
    // The expression ends with the argument its last `)` is in, which
    // must end there.
    let (_, last) = lex[at - 1];
    if lex.get(at).is_some_and(|(_, n)| *n == last) {
        return Err(err(format!("unexpected `{}` after the expression", params[last])));
    }
    Ok((matches, last + 1))
}

/// A number as tc's ematch modules read one: `strtoul(.., 0)`.
fn em_number(err: &dyn Fn(String) -> Error, what: &str, s: &str) -> Result<u32> {
    parse_u32_any("ematch", what, s).map_err(|_| err(format!("invalid {what} `{s}`")))
}

/// `cmp(ALIGN at OFFSET [layer LAYER] [mask MASK] [trans] eq|gt|lt VALUE)`,
/// as tc's `em_cmp.c` reads it. An offset and a value are required.
fn parse_em_cmp(err: &dyn Fn(String) -> Error, args: &[&str]) -> Result<EmatchCmp> {
    let align = match args.first() {
        Some(&"u8") => CmpAlign::U8,
        Some(&"u16") => CmpAlign::U16,
        Some(&"u32") => CmpAlign::U32,
        _ => return Err(err("cmp: expected an alignment, u8, u16 or u32, first".into())),
    };
    let (mut offset, mut value, mut layer, mut mask, mut trans, mut op) = (None, None, CmpLayer::Network, 0, false, CmpOp::Eq);
    let mut i = 1;
    while i < args.len() {
        let next = || args.get(i + 1).copied().ok_or_else(|| err(format!("cmp: `{}` requires a value", args[i])));
        match args[i] {
            "at" => {
                let off = em_number(err, "cmp offset", next()?)?;
                offset = Some(u16::try_from(off).map_err(|_| err(format!("cmp: offset {off} is past 65535")))?);
                i += 2;
            }
            "layer" => {
                layer = match next()? {
                    "link" | "0" => CmpLayer::Link,
                    "network" | "1" => CmpLayer::Network,
                    "transport" | "2" => CmpLayer::Transport,
                    other => return Err(err(format!("cmp: invalid layer `{other}` (expected link, network or transport)"))),
                };
                i += 2;
            }
            "mask" => {
                mask = em_number(err, "cmp mask", next()?)?;
                i += 2;
            }
            "trans" => {
                trans = true;
                i += 1;
            }
            w @ ("eq" | "gt" | "lt") => {
                op = match w {
                    "eq" => CmpOp::Eq,
                    "gt" => CmpOp::Gt,
                    _ => CmpOp::Lt,
                };
                value = Some(em_number(err, "cmp value", next()?)?);
                i += 2;
            }
            other => return Err(err(format!("cmp: unknown parameter `{other}`"))),
        }
    }
    let (Some(offset), Some(value)) = (offset, value) else {
        return Err(err("cmp: an offset (`at`) and a value (`eq`, `gt` or `lt`) are required".into()));
    };
    Ok(EmatchCmp { layer, align, offset, mask, value, op, trans })
}

/// `u32(ALIGN KEY MASK at OFFSET)`, packed into the 32-bit word at the
/// offset rounded down to four, as tc's `em_u32.c` packs it. An offset
/// from the next header (`nexthdr+`) is not modelled.
fn parse_em_u32(err: &dyn Fn(String) -> Error, args: &[&str]) -> Result<EmatchU32> {
    let [align, key, mask, at, off] = args else {
        return Err(err("u32: expected `u32(ALIGN KEY MASK at OFFSET)`".into()));
    };
    if *at != "at" {
        return Err(err(format!("u32: expected `at`, not `{at}`")));
    }
    if off.starts_with("nexthdr+") {
        return Err(err("u32: an offset from the next header is not modelled".into()));
    }
    let (key, mask, off) = (em_number(err, "u32 key", key)?, em_number(err, "u32 mask", mask)?, em_number(err, "u32 offset", off)?);
    let (key, mask, off) = match *align {
        "u8" if key <= 0xFF && mask <= 0xFF => {
            let shift = 24 - (off & 3) * 8;
            (key << shift, mask << shift, off & !3)
        }
        "u16" if key <= 0xFFFF && mask <= 0xFFFF => {
            let shift = if off & 3 == 0 { 16 } else { 0 };
            (key << shift, mask << shift, off & !3)
        }
        "u32" => (key, mask, off),
        "u8" | "u16" => return Err(err(format!("u32: key or mask is wider than {align}"))),
        other => return Err(err(format!("u32: invalid alignment `{other}` (expected u8, u16 or u32)"))),
    };
    if off % 4 != 0 {
        return Err(err(format!("u32: offset {off} is not a multiple of 4")));
    }
    Ok(EmatchU32 { mask, value: key & mask, offset: off })
}

/// Encode an ematch tree under `TCA_BASIC_EMATCHES`.
fn write_ematch_tree(builder: &mut MessageBuilder, matches: &[Ematch]) {
    let outer = builder.nest_start(basic::TCA_BASIC_EMATCHES);

    let tree_hdr = ematch::TcfEmatchTreeHdr {
        nmatches: matches.len() as u16,
        progid: ematch::TCF_EM_PROG_TC,
    };
    builder.append_attr(ematch::TCA_EMATCH_TREE_HDR, tree_hdr.as_bytes());

    let list = builder.nest_start(ematch::TCA_EMATCH_TREE_LIST);
    let last = matches.len().saturating_sub(1);
    for (i, m) in matches.iter().enumerate() {
        // 1-based attribute type per kernel convention.
        let attr_type = (i + 1) as u16;

        let mut flags = if m.negate { ematch::TCF_EM_INVERT } else { 0 };
        if i < last {
            flags |= match m.op {
                EmatchOp::And => ematch::TCF_EM_REL_AND,
                EmatchOp::Or => ematch::TCF_EM_REL_OR,
            };
        }
        // Last match: REL_END (0) — leave unmasked.

        let kind_id = match &m.kind {
            EmatchKind::Cmp(_) => ematch::TCF_EM_CMP,
            EmatchKind::U32(_) => ematch::TCF_EM_U32,
        };

        let hdr = ematch::TcfEmatchHdr {
            matchid: 0,
            kind: kind_id,
            flags,
            _pad: 0,
        };

        let mut payload = Vec::with_capacity(ematch::TcfEmatchHdr::SIZE + 16);
        payload.extend_from_slice(hdr.as_bytes());

        match &m.kind {
            EmatchKind::Cmp(c) => payload.extend_from_slice(encode_cmp(c).as_bytes()),
            // The kernel's `struct tc_u32_key`, all 16 bytes, its word
            // big-endian as the packet holds it; nlink sent 12 bytes,
            // which `tcf_em_validate` refuses (#828).
            EmatchKind::U32(u) => {
                let body = ematch::TcfEmU32 {
                    mask: u.mask.to_be(),
                    val: (u.value & u.mask).to_be(),
                    off: u.offset,
                    offmask: 0,
                };
                payload.extend_from_slice(body.as_bytes());
            }
        }

        builder.append_attr(attr_type, &payload);
    }
    builder.nest_end(list);
    builder.nest_end(outer);
}

/// Pack an [`EmatchCmp`] into the kernel `tcf_em_cmp` byte layout.
fn encode_cmp(c: &EmatchCmp) -> ematch::TcfEmCmp {
    let align = match c.align {
        CmpAlign::U8 => ematch::TCF_EM_ALIGN_U8,
        CmpAlign::U16 => ematch::TCF_EM_ALIGN_U16,
        CmpAlign::U32 => ematch::TCF_EM_ALIGN_U32,
    };
    let layer = match c.layer {
        CmpLayer::Link => ematch::TCF_LAYER_LINK,
        CmpLayer::Network => ematch::TCF_LAYER_NETWORK,
        CmpLayer::Transport => ematch::TCF_LAYER_TRANSPORT,
    };
    let opnd = match c.op {
        CmpOp::Eq => ematch::TCF_EM_OPND_EQ,
        CmpOp::Gt => ematch::TCF_EM_OPND_GT,
        CmpOp::Lt => ematch::TCF_EM_OPND_LT,
    };
    let cmp_flags = if c.trans { ematch::TCF_EM_CMP_TRANS } else { 0 };

    ematch::TcfEmCmp {
        val: c.value,
        mask: c.mask,
        off: c.offset,
        align_flags: (cmp_flags << 4) | (align & 0x0F),
        layer_opnd: (opnd << 4) | (layer & 0x0F),
        _pad: 0,
        _pad2: 0,
    }
}

// ============================================================================
// CgroupFilter
// ============================================================================

/// Cgroup filter configuration.
///
/// The cgroup filter classifies packets based on their originating control group.
/// This filter is typically used with the net_cls cgroup controller, which assigns
/// a classid to all packets originating from processes in that cgroup.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::CgroupFilter;
/// use nlink::netlink::action::GactAction;
///
/// // Simple cgroup filter (classifies based on net_cls cgroup)
/// let filter = CgroupFilter::new();
///
/// // With an action attached
/// let filter = CgroupFilter::new()
///     .with_action(GactAction::drop());
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct CgroupFilter {
    /// Actions to attach.
    actions: Option<super::action::ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl CgroupFilter {
    /// Create a new cgroup filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action to the filter.
    pub fn with_action<A: super::action::ActionConfig + Clone + std::fmt::Debug + 'static>(
        mut self,
        action: A,
    ) -> Self {
        let actions = self.actions.take().unwrap_or_default().with(action);
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cgroup params slice into a typed
    /// `CgroupFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `chain <n>` — chain index.
    ///
    /// **Note**: a bare `cgroup` filter without ematch matches every
    /// packet that belongs to any cgroup, which is rarely useful.
    /// The interesting matches (`cgroup CGRP_ID`) need ematch (Plan
    /// 133 PR C). Action attachment isn't parsed here; build the
    /// filter typed and use `with_action` if you need that.
    ///
    /// **Net new CLI capability**: the legacy filter dispatcher's
    /// `_ => i += 1` arm silently swallowed `cgroup`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "chain" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::invalid_message("cgroup: `chain` requires a value")
                    })?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("cgroup: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "cgroup: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for CgroupFilter {
    from_actions!();

    fn kind(&self) -> &'static str {
        "cgroup"
    }

    fn classid(&self) -> Option<u32> {
        None // Cgroup filter doesn't have a classid in the traditional sense
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::cgroup;

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(cgroup::TCA_CGROUP_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }
        Ok(())
    }
}

// ============================================================================
// RouteFilter
// ============================================================================

/// Route filter configuration.
///
/// The route filter classifies packets based on routing table metadata (realms).
/// Realms are assigned to routes and can be used to classify traffic based on
/// its destination or source routing properties.
///
/// # Example
///
/// ```no_run
/// # let eth1_ifindex: u32 = 3;
/// use nlink::netlink::filter::RouteFilter;
///
/// // Match traffic to realm 10
/// let filter = RouteFilter::new()
///     .to_realm(10)
///     .classid(nlink::TcHandle::new(1, 0x10));
///
/// // Match traffic from realm 5 arriving on eth1 (by index for namespace safety)
/// let filter = RouteFilter::new()
///     .from_realm(5)
///     .from_if_index(eth1_ifindex)
///     .classid(nlink::TcHandle::new(1, 0x20));
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct RouteFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Destination realm.
    to_realm: Option<u32>,
    /// Source realm.
    from_realm: Option<u32>,
    /// Input interface reference.
    from_if: Option<InterfaceRef>,
    /// Actions to attach.
    actions: Option<super::action::ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// The filter's order among route filters, bits 8–14 of its handle
    /// (tc(8)'s `order`, #829).
    order: Option<u32>,
}

impl RouteFilter {
    /// Create a new route filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Match traffic destined for a specific realm.
    pub fn to_realm(mut self, realm: u32) -> Self {
        self.to_realm = Some(realm);
        self
    }

    /// Match traffic originating from a specific realm.
    pub fn from_realm(mut self, realm: u32) -> Self {
        self.from_realm = Some(realm);
        self
    }

    /// Match traffic arriving from a specific interface by name.
    ///
    /// The connection that installs the filter resolves the name, in its
    /// own namespace (#645). Until 0.32 nothing did, and a filter with a
    /// name here could not be installed at all.
    pub fn from_if(mut self, dev: impl Into<String>) -> Self {
        self.from_if = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the filter's order among route filters (tc(8)'s `order`), which
    /// goes in its handle.
    pub fn order(mut self, order: u32) -> Self {
        self.order = Some(order);
        self
    }

    /// Match traffic arriving from a specific interface by index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn from_if_index(mut self, ifindex: u32) -> Self {
        self.from_if = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the interface reference for the input interface filter.
    pub fn from_if_ref(&self) -> Option<&InterfaceRef> {
        self.from_if.as_ref()
    }

    /// Add an action to the filter.
    pub fn with_action<A: super::action::ActionConfig + Clone + std::fmt::Debug + 'static>(
        mut self,
        action: A,
    ) -> Self {
        let actions = self.actions.take().unwrap_or_default().with(action);
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style route params slice into a typed `RouteFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `to <realm>` — match destination routing realm.
    /// - `from <realm>` — match source routing realm.
    /// - `fromif <dev>` (or `iif`) — match input interface by name.
    ///   Resolved at filter-add time; for namespace operations prefer
    ///   setting `from_if_index()` on the typed builder directly.
    /// - `order <n>` — the filter's order, which goes in its handle.
    /// - `chain <n>` — chain index.
    ///
    /// Action attachment is not parsed here; build the filter typed
    /// and use `with_action` if you need to attach actions.
    ///
    /// **Net new CLI capability**: the legacy filter parser doesn't
    /// recognise `route` at all (silently swallowed in the
    /// `_ => i += 1` arm). Prior to this method the CLI couldn't
    /// configure route filters.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("route: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("route: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "to" => {
                    let s = need_value()?;
                    f = f.to_realm(s.parse().map_err(|_| {
                        Error::invalid_message(format!("route: invalid to realm `{s}`"))
                    })?);
                    i += 2;
                }
                "from" => {
                    let s = need_value()?;
                    f = f.from_realm(s.parse().map_err(|_| {
                        Error::invalid_message(format!("route: invalid from realm `{s}`"))
                    })?);
                    i += 2;
                }
                // tc(8) says `fromif`; `iif` is nlink's (#829).
                "fromif" | "iif" => {
                    let s = need_value()?;
                    f = f.from_if(s);
                    i += 2;
                }
                "order" => {
                    let s = need_value()?;
                    f = f.order(s.parse().map_err(|_| {
                        Error::invalid_message(format!("route: invalid order `{s}`"))
                    })?);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("route: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "route: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for RouteFilter {
    fn estimator(&self) -> Option<Estimator> {
        self.actions.as_ref().and_then(ActionList::estimator)
    }

    fn device_names(&self) -> Vec<&str> {
        let mut names = match &self.from_if {
            Some(InterfaceRef::Name(name)) => vec![name.as_str()],
            _ => Vec::new(),
        };
        names.extend(self.actions.as_ref().map(ActionList::device_names).unwrap_or_default());
        names
    }

    /// tc(8)'s: `to`'s realm in the low byte, `from`'s realm or
    /// `0x8000 | ifindex` for an input interface in the upper half, `order`
    /// in bits 8–14, from `0xFFFF8000` (#825).
    fn default_handle(&self) -> Option<TcHandle> {
        let mut fh: u32 = 0xFFFF_8000;
        if let Some(to) = self.to_realm {
            fh &= !0x80FF;
            fh |= to & 0xFF;
        }
        if let Some(from) = self.from_realm {
            fh &= 0xFFFF;
            fh |= from << 16;
        }
        if let Some(InterfaceRef::Index(ifindex)) = self.from_if {
            fh &= 0xFFFF;
            fh |= (0x8000 | ifindex) << 16;
        }
        if let Some(order) = self.order.filter(|o| *o != 0) {
            fh &= !0x7F00;
            fh |= (order << 8) & 0x7F00;
        }
        Some(TcHandle::from_raw(fh))
    }

    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        if let Some(InterfaceRef::Name(name)) = &self.from_if {
            let ifindex = *ifindexes
                .get(name)
                .ok_or_else(|| Error::interface_not_found(name).with_context("route filter"))?;
            self.from_if = Some(InterfaceRef::Index(ifindex));
        }
        match &mut self.actions {
            Some(actions) => actions.resolve_devices(ifindexes),
            None => Ok(()),
        }
    }

    fn kind(&self) -> &'static str {
        "route"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::route4;

        if let Some(classid) = self.classid {
            builder.append_attr_u32(route4::TCA_ROUTE4_CLASSID, classid);
        }

        if let Some(realm) = self.to_realm {
            builder.append_attr_u32(route4::TCA_ROUTE4_TO, realm);
        }

        if let Some(realm) = self.from_realm {
            builder.append_attr_u32(route4::TCA_ROUTE4_FROM, realm);
        }

        if let Some(ref iface) = self.from_if {
            let ifindex = match iface {
                InterfaceRef::Index(idx) => *idx,
                InterfaceRef::Name(name) => {
                    return Err(Error::invalid_message(format!(
                        "RouteFilter from_if interface '{}' is resolved by the connection that \
                         installs the filter; install it through one, or use from_if_index()",
                        name
                    )));
                }
            };
            builder.append_attr_u32(route4::TCA_ROUTE4_IIF, ifindex);
        }

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(route4::TCA_ROUTE4_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// RsvpFilter
// ============================================================================

/// RSVP classifier configuration (`rsvp` / `rsvp6`).
///
/// The RSVP classifier matches flows by session (destination) and sender
/// (source) address, optionally narrowed by L4 protocol and tunnel id.
/// The address family is inferred from the addresses you set: an IPv6
/// session/sender selects the `rsvp6` kernel classifier, IPv4 selects
/// `rsvp`.
///
/// ```no_run
/// use nlink::netlink::filter::RsvpFilter;
/// use nlink::TcHandle;
///
/// let f = RsvpFilter::new()
///     .ipproto(6) // TCP
///     .session("10.0.0.1".parse().unwrap())
///     .sender("10.0.0.2".parse().unwrap())
///     .classid(TcHandle::new(1, 0x10))
///     .build();
/// ```
///
/// # Port matching is not modelled
///
/// `tc`'s `session <addr>/<port>` and `sender <addr>/<port>` forms match
/// on an L4 port via a general-port-info (GPI) key/mask/offset triple
/// whose offset is protocol-specific. `RsvpFilter` matches at the address
/// level only and rejects an embedded `/<port>` with a clear not-modelled
/// error (the `tc_rsvp_pinfo` port fields are left zeroed). Use a
/// hand-rolled `MessageBuilder` if you need port-level RSVP matching.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct RsvpFilter {
    classid: Option<u32>,
    /// Session (destination) address.
    dst: Option<IpAddr>,
    /// Sender (source) address.
    src: Option<IpAddr>,
    /// L4 protocol number.
    ipproto: Option<u8>,
    /// Tunnel id.
    tunnelid: Option<u8>,
    actions: Option<super::action::ActionList>,
    chain: Option<u32>,
}

impl RsvpFilter {
    /// Create a new RSVP filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target class id.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Match the session (destination) address.
    pub fn session(mut self, addr: IpAddr) -> Self {
        self.dst = Some(addr);
        self
    }

    /// Match the sender (source) address.
    pub fn sender(mut self, addr: IpAddr) -> Self {
        self.src = Some(addr);
        self
    }

    /// Match a specific L4 protocol number (e.g. 6 = TCP, 17 = UDP).
    pub fn ipproto(mut self, proto: u8) -> Self {
        self.ipproto = Some(proto);
        self
    }

    /// Match a specific tunnel id.
    pub fn tunnelid(mut self, id: u8) -> Self {
        self.tunnelid = Some(id);
        self
    }

    /// Add an action to the filter.
    pub fn with_action<A: super::action::ActionConfig + Clone + std::fmt::Debug + 'static>(
        mut self,
        action: A,
    ) -> Self {
        let actions = self.actions.take().unwrap_or_default().with(action);
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Whether this filter targets the IPv6 (`rsvp6`) classifier — true
    /// if any configured address is IPv6.
    fn is_v6(&self) -> bool {
        matches!(self.dst, Some(IpAddr::V6(_))) || matches!(self.src, Some(IpAddr::V6(_)))
    }

    /// Parse a tc-style rsvp params slice into a typed `RsvpFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `ipproto <proto>` — `tcp`, `udp`, or a numeric protocol.
    /// - `session <addr>` — match destination address. An embedded
    ///   `/<port>` is rejected (port GPI matching is not modelled).
    /// - `sender <addr>` — match source address (same port caveat).
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `tunnelid <id>` — match tunnel id.
    /// - `chain <n>` — chain index.
    ///
    /// Strict: unknown tokens, missing values, unparseable values, and
    /// not-modelled port forms all return `Error::invalid_message`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;

        let parse_addr = |key: &str, s: &str| -> crate::Result<IpAddr> {
            if s.contains('/') {
                return Err(Error::invalid_message(format!(
                    "rsvp: `{key} {s}` port matching is not modelled by RsvpFilter — \
                     use an address without `/<port>`, or a hand-rolled MessageBuilder"
                )));
            }
            s.parse::<IpAddr>().map_err(|_| {
                Error::invalid_message(format!("rsvp: invalid {key} address `{s}`"))
            })
        };

        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::invalid_message(format!("rsvp: `{key}` requires a value"))
                })
            };
            match key {
                "ipproto" => {
                    let s = need_value()?;
                    let proto = match s {
                        "tcp" => 6,
                        "udp" => 17,
                        other => other.parse::<u8>().map_err(|_| {
                            Error::invalid_message(format!(
                                "rsvp: invalid ipproto `{other}` (expected tcp, udp, or a number)"
                            ))
                        })?,
                    };
                    f = f.ipproto(proto);
                    i += 2;
                }
                "session" => {
                    let s = need_value()?;
                    f = f.session(parse_addr("session", s)?);
                    i += 2;
                }
                "sender" => {
                    let s = need_value()?;
                    f = f.sender(parse_addr("sender", s)?);
                    i += 2;
                }
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("rsvp: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "tunnelid" => {
                    let s = need_value()?;
                    f = f.tunnelid(s.parse::<u8>().map_err(|_| {
                        Error::invalid_message(format!("rsvp: invalid tunnelid `{s}`"))
                    })?);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("rsvp: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                "tunnel" => {
                    return Err(Error::invalid_message(
                        "rsvp: `tunnel <id> skip <n>` tunnel-creation form is not modelled by \
                         RsvpFilter — use a hand-rolled MessageBuilder"
                            .to_string(),
                    ));
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "rsvp: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for RsvpFilter {
    from_actions!();

    fn kind(&self) -> &'static str {
        if self.is_v6() { "rsvp6" } else { "rsvp" }
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::rsvp;

        if let Some(classid) = self.classid {
            builder.append_attr_u32(rsvp::TCA_RSVP_CLASSID, classid);
        }

        // Address attributes carry the raw 4- or 16-byte address.
        let mut append_addr = |attr: u16, addr: &IpAddr| match addr {
            IpAddr::V4(v4) => builder.append_attr(attr, &v4.octets()),
            IpAddr::V6(v6) => builder.append_attr(attr, &v6.octets()),
        };
        if let Some(dst) = self.dst {
            append_addr(rsvp::TCA_RSVP_DST, &dst);
        }
        if let Some(src) = self.src {
            append_addr(rsvp::TCA_RSVP_SRC, &src);
        }

        // Only emit pinfo when protocol or tunnel narrowing is requested;
        // the port GPI fields stay zeroed (port matching not modelled).
        if self.ipproto.is_some() || self.tunnelid.is_some() {
            let pinfo = rsvp::TcRsvpPinfo {
                protocol: self.ipproto.unwrap_or(0),
                tunnelid: self.tunnelid.unwrap_or(0),
                ..Default::default()
            };
            builder.append_attr(rsvp::TCA_RSVP_PINFO, pinfo.as_bytes());
        }

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(rsvp::TCA_RSVP_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// FlowFilter
// ============================================================================

/// Flow filter configuration.
///
/// The flow filter classifies packets based on various fields and uses
/// hashing to distribute traffic across classes.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::filter::{FlowFilter, FlowKey};
///
/// // Hash based on source and destination addresses
/// let filter = FlowFilter::new()
///     .keys(&[FlowKey::Src, FlowKey::Dst])
///     .mode_hash()
///     .divisor(256)
///     .baseclass(nlink::TcHandle::new(1, 0x10))
///     .build();
///
/// conn.add_filter("eth0", nlink::TcHandle::major_only(1), filter).await?;
///
/// // Map mode: direct mapping without hashing
/// let filter = FlowFilter::new()
///     .key(FlowKey::Mark)
///     .mode_map()
///     .baseclass(nlink::TcHandle::major_only(1))
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct FlowFilter {
    /// Key mask (which fields to use).
    keys: u32,
    /// Flow mode (map or hash).
    mode: u32,
    /// Base class ID.
    baseclass: Option<u32>,
    /// Right shift amount.
    rshift: Option<u32>,
    /// Additive constant.
    addend: Option<u32>,
    /// Bitwise AND mask.
    mask: Option<u32>,
    /// Bitwise XOR value.
    xor: Option<u32>,
    /// Hash table divisor.
    divisor: Option<u32>,
    /// Hash perturbation interval in seconds.
    perturb: Option<u32>,
    /// Filter priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Actions to perform.
    actions: Option<ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

/// Flow filter keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowKey {
    /// Source address.
    Src,
    /// Destination address.
    Dst,
    /// IP protocol.
    Proto,
    /// Source port.
    ProtoSrc,
    /// Destination port.
    ProtoDst,
    /// Input interface.
    Iif,
    /// Packet priority.
    Priority,
    /// Packet mark.
    Mark,
    /// Conntrack state.
    Nfct,
    /// Conntrack source.
    NfctSrc,
    /// Conntrack destination.
    NfctDst,
    /// Conntrack source port.
    NfctProtoSrc,
    /// Conntrack destination port.
    NfctProtoDst,
    /// Routing realm.
    RtClassid,
    /// Socket UID.
    SkUid,
    /// Socket GID.
    SkGid,
    /// VLAN tag.
    VlanTag,
    /// Receive hash.
    RxHash,
}

impl FlowKey {
    fn to_bit(self) -> u32 {
        use super::types::tc::filter::flow;
        match self {
            FlowKey::Src => flow::FLOW_KEY_SRC,
            FlowKey::Dst => flow::FLOW_KEY_DST,
            FlowKey::Proto => flow::FLOW_KEY_PROTO,
            FlowKey::ProtoSrc => flow::FLOW_KEY_PROTO_SRC,
            FlowKey::ProtoDst => flow::FLOW_KEY_PROTO_DST,
            FlowKey::Iif => flow::FLOW_KEY_IIF,
            FlowKey::Priority => flow::FLOW_KEY_PRIORITY,
            FlowKey::Mark => flow::FLOW_KEY_MARK,
            FlowKey::Nfct => flow::FLOW_KEY_NFCT,
            FlowKey::NfctSrc => flow::FLOW_KEY_NFCT_SRC,
            FlowKey::NfctDst => flow::FLOW_KEY_NFCT_DST,
            FlowKey::NfctProtoSrc => flow::FLOW_KEY_NFCT_PROTO_SRC,
            FlowKey::NfctProtoDst => flow::FLOW_KEY_NFCT_PROTO_DST,
            FlowKey::RtClassid => flow::FLOW_KEY_RTCLASSID,
            FlowKey::SkUid => flow::FLOW_KEY_SKUID,
            FlowKey::SkGid => flow::FLOW_KEY_SKGID,
            FlowKey::VlanTag => flow::FLOW_KEY_VLAN_TAG,
            FlowKey::RxHash => flow::FLOW_KEY_RXHASH,
        }
    }
}

impl Default for FlowFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowFilter {
    /// Create a new flow filter builder.
    pub fn new() -> Self {
        use super::types::tc::filter::flow;
        Self {
            keys: 0,
            mode: flow::FLOW_MODE_MAP,
            baseclass: None,
            rshift: None,
            addend: None,
            mask: None,
            xor: None,
            divisor: None,
            perturb: None,
            priority: 0,
            protocol: ETH_P_ALL,
            actions: None,
            chain: None,
        }
    }

    /// Add a single key.
    pub fn key(mut self, key: FlowKey) -> Self {
        self.keys |= key.to_bit();
        self
    }

    /// Add multiple keys.
    pub fn keys(mut self, keys: &[FlowKey]) -> Self {
        for key in keys {
            self.keys |= key.to_bit();
        }
        self
    }

    /// Set mode to map (direct mapping).
    pub fn mode_map(mut self) -> Self {
        use super::types::tc::filter::flow;
        self.mode = flow::FLOW_MODE_MAP;
        self
    }

    /// Set mode to hash (multi-key hashing).
    pub fn mode_hash(mut self) -> Self {
        use super::types::tc::filter::flow;
        self.mode = flow::FLOW_MODE_HASH;
        self
    }

    /// Set the base class ID.
    pub fn baseclass(mut self, classid: TcHandle) -> Self {
        self.baseclass = Some(classid.as_raw());
        self
    }

    /// Set the right shift amount.
    pub fn rshift(mut self, shift: u32) -> Self {
        self.rshift = Some(shift);
        self
    }

    /// Set the additive constant.
    pub fn addend(mut self, addend: u32) -> Self {
        self.addend = Some(addend);
        self
    }

    /// Set the bitwise AND mask.
    pub fn mask(mut self, mask: u32) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Set the bitwise XOR value.
    pub fn xor(mut self, xor: u32) -> Self {
        self.xor = Some(xor);
        self
    }

    /// Set the hash table divisor.
    pub fn divisor(mut self, divisor: u32) -> Self {
        self.divisor = Some(divisor);
        self
    }

    /// Set the hash perturbation interval in seconds.
    pub fn perturb(mut self, seconds: u32) -> Self {
        self.perturb = Some(seconds);
        self
    }

    /// Set filter priority.
    pub fn priority(mut self, priority: FilterPriority) -> Self {
        self.priority = priority.as_u16();
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: EthProto) -> Self {
        self.protocol = protocol.as_u16();
        self
    }

    /// Add actions to perform on matching packets.
    pub fn actions(mut self, actions: ActionList) -> Self {
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Parse a tc-style flow params slice into a typed `FlowFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `keys <key1>,<key2>,...` (or `key`) — comma-separated list of flow
    ///   keys (e.g. `src,dst,proto`, `nfct-src,nfct-dst`). Each key
    ///   is the lowercase tc-style name; supported names: `src`,
    ///   `dst`, `proto`, `proto-src`, `proto-dst`, `iif`, `priority`,
    ///   `mark`, `nfct`, `nfct-src`, `nfct-dst`, `nfct-proto-src`,
    ///   `nfct-proto-dst`, `rt-classid`, `sk-uid`, `sk-gid`,
    ///   `vlan-tag`, `rxhash`.
    /// - `hash` / `map` — flow mode (multi-key hashing vs direct map).
    /// - `baseclass <handle>` — base class id.
    /// - `divisor <n>` — hash table divisor.
    /// - `perturb <seconds>` — hash perturbation interval.
    /// - `rshift <n>` — right-shift amount.
    /// - `addend <n>` — additive constant.
    /// - `and <n>` (or `mask`), `or <n>`, `xor <n>` — bit operations,
    ///   folded into one mask and xor in order, as tc(8) folds them (#829).
    /// - `chain <n>` — chain index.
    ///
    /// **Net new CLI capability**: the legacy filter dispatcher's
    /// `_ => i += 1` arm silently swallowed `flow`.
    ///
    /// Action attachment isn't parsed here; build the filter typed
    /// and use `actions()` if you need that.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut bitop = (u32::MAX, 0u32);
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::invalid_message(format!("flow: `{key}` requires a value")))
            };
            match key {
                // tc(8) matches a prefix: `key` is `keys` (#829).
                "keys" | "key" => {
                    let s = need_value()?;
                    for k in s.split(',') {
                        f = f.key(parse_flow_key(k.trim())?);
                    }
                    i += 2;
                }
                "hash" => {
                    f = f.mode_hash();
                    i += 1;
                }
                "map" => {
                    f = f.mode_map();
                    i += 1;
                }
                "baseclass" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::invalid_message(format!("flow: invalid baseclass `{s}`: {e}"))
                    })?;
                    f = f.baseclass(h);
                    i += 2;
                }
                "divisor" => {
                    let s = need_value()?;
                    f = f.divisor(s.parse().map_err(|_| {
                        Error::invalid_message(format!("flow: invalid divisor `{s}`"))
                    })?);
                    i += 2;
                }
                "perturb" => {
                    let s = need_value()?;
                    f = f.perturb(s.parse().map_err(|_| {
                        Error::invalid_message(format!("flow: invalid perturb `{s}`"))
                    })?);
                    i += 2;
                }
                "rshift" => {
                    let s = need_value()?;
                    f = f.rshift(s.parse().map_err(|_| {
                        Error::invalid_message(format!("flow: invalid rshift `{s}`"))
                    })?);
                    i += 2;
                }
                "addend" => {
                    let s = need_value()?;
                    f = f.addend(s.parse().map_err(|_| {
                        Error::invalid_message(format!("flow: invalid addend `{s}`"))
                    })?);
                    i += 2;
                }
                // tc(8)'s `and`, `or` and `xor`, folded into one mask and
                // xor as its transfer_bitop() folds them (#829). `mask` is
                // nlink's word for `and`.
                "and" | "mask" | "or" | "xor" => {
                    let v = parse_flow_u32_hex_or_dec(need_value()?, key)?;
                    let (m, x) = match key {
                        "or" => (!v, v),
                        "xor" => (u32::MAX, v),
                        _ => (v, 0),
                    };
                    bitop = (bitop.0 & m, x ^ (bitop.1 & m));
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::invalid_message(format!("flow: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "flow: unknown token `{other}`"
                    )));
                }
            }
        }
        if bitop != (u32::MAX, 0) {
            f = f.mask(bitop.0).xor(bitop.1);
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for FlowFilter {
    from_actions!();

    fn kind(&self) -> &'static str {
        "flow"
    }

    fn classid(&self) -> Option<u32> {
        self.baseclass
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn set_chain(&mut self, chain: u32) {
        self.chain = Some(chain);
    }

    fn protocol(&self) -> Option<EthProto> {
        Some(EthProto::new(self.protocol))
    }

    fn set_protocol(&mut self, protocol: EthProto) {
        self.protocol = protocol.as_u16();
    }

    fn priority(&self) -> Option<FilterPriority> {
        Some(FilterPriority::new(self.priority))
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::flow;

        if self.keys != 0 {
            builder.append_attr_u32(flow::TCA_FLOW_KEYS, self.keys);
        }

        builder.append_attr_u32(flow::TCA_FLOW_MODE, self.mode);

        if let Some(baseclass) = self.baseclass {
            builder.append_attr_u32(flow::TCA_FLOW_BASECLASS, baseclass);
        }

        if let Some(rshift) = self.rshift {
            builder.append_attr_u32(flow::TCA_FLOW_RSHIFT, rshift);
        }

        if let Some(addend) = self.addend {
            builder.append_attr_u32(flow::TCA_FLOW_ADDEND, addend);
        }

        if let Some(mask) = self.mask {
            builder.append_attr_u32(flow::TCA_FLOW_MASK, mask);
        }

        if let Some(xor) = self.xor {
            builder.append_attr_u32(flow::TCA_FLOW_XOR, xor);
        }

        if let Some(divisor) = self.divisor {
            builder.append_attr_u32(flow::TCA_FLOW_DIVISOR, divisor);
        }

        if let Some(perturb) = self.perturb {
            builder.append_attr_u32(flow::TCA_FLOW_PERTURB, perturb);
        }

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(flow::TCA_FLOW_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// Connection extension methods for filters
// ============================================================================

/// The `(protocol, priority)` pair to stamp into `tcm_info` for a config.
///
/// `priority == 0` tells the kernel to auto-assign, which is what the
/// convenience `add_filter` / `replace_filter` entry points used to do
/// unconditionally — along with hardcoding `ETH_P_IP` (#201).
fn filter_info(config: &impl FilterConfig) -> (EthProto, FilterPriority) {
    (
        config.protocol().unwrap_or(DEFAULT_FILTER_PROTOCOL),
        config.priority().unwrap_or(FilterPriority::new(0)),
    )
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Add a filter to an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::filter::FlowerFilter;
    ///
    /// let filter = FlowerFilter::new()
    ///     .classid(TcHandle::new(1, 0x10))
    ///     .ipv4()
    ///     .ip_proto_tcp()
    ///     .dst_port(80)
    ///     .build();
    ///
    /// conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The config's own `protocol` and `priority` are honored. Until 0.25
    /// they were silently discarded and every filter went on as
    /// `protocol ip, prio auto` (#201).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter"))]
    pub async fn add_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        let (protocol, priority) = filter_info(&config);
        self.add_filter_full(dev, parent, None, protocol, priority, config)
            .await
    }

    /// Add a filter with explicit parameters.
    ///
    /// # Arguments
    /// * `dev` - Interface name
    /// * `parent` - Parent qdisc handle (e.g., "1:")
    /// * `handle` - Filter handle (optional)
    /// * `protocol` - Ethernet protocol (e.g., 0x0800 for IPv4)
    /// * `priority` - Filter priority (lower = higher priority)
    /// * `config` - Filter configuration
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_full"))]
    pub async fn add_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Add a filter by interface index.
    ///
    /// The config's own `protocol` and `priority` are honored (#201).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_by_index"))]
    pub async fn add_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        let (protocol, priority) = filter_info(&config);
        self.add_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Add a filter by interface index with explicit parameters.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_by_index_full"))]
    pub async fn add_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        mut config: impl FilterConfig,
    ) -> Result<()> {
        config.set_protocol(protocol);
        let names = self.ifindexes_of(&config.device_names()).await?;
        config.resolve_devices(&names)?;
        let parent_handle = parent.as_raw();
        let filter_handle = handle.or_else(|| config.default_handle()).map_or(0, |h| h.as_raw());

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_filter_info(protocol.as_u16(), priority.as_u16());

        let mut builder = create_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }
        write_estimator(&mut builder, &config);

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_filter"))
    }

    /// Replace a filter on an interface (create if not exists).
    ///
    /// This uses NLM_F_CREATE | NLM_F_REPLACE flags to atomically replace
    /// an existing filter or create a new one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// use nlink::{TcHandle, netlink::filter::FlowerFilter};
    /// # async fn f(conn: &nlink::Connection<nlink::Route>) -> nlink::Result<()> {
    /// let filter = FlowerFilter::new()
    ///     .classid(TcHandle::new(1, 0x10))
    ///     .ipv4()
    ///     .ip_proto_tcp()
    ///     .dst_port(80)
    ///     .priority(FilterPriority::new(200)) // pin it — see below
    ///     .build();
    /// conn.replace_filter("eth0", TcHandle::major_only(1), filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Two things that make a replace a replace
    ///
    /// **Pin the priority.** The target is identified by
    /// `(parent, protocol, priority, handle)`. Leave the priority unset
    /// and the kernel auto-assigns a fresh one, so you get a *second*
    /// filter rather than a replacement — `tc(8)` does the same:
    ///
    /// ```text
    /// # tc filter add     dev d0 parent 1: protocol all matchall classid 1:10
    /// filter protocol all pref 49152 matchall ... flowid 1:10
    /// # tc filter replace dev d0 parent 1: protocol all matchall classid 1:20
    /// filter protocol all pref 49151 matchall ... flowid 1:20
    /// filter protocol all pref 49152 matchall ...      <- the original
    /// ```
    ///
    /// **Not every classifier supports it.** `cls_matchall` holds
    /// exactly one filter per `tcf_proto`, and `mall_change` answers
    /// `EEXIST` when one is already there — there is no replace path.
    /// Delete and re-add instead. `flower` and `u32` replace normally.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter"))]
    pub async fn replace_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        let (protocol, priority) = filter_info(&config);
        self.replace_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Replace a filter with explicit parameters.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter_full"))]
    pub async fn replace_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Replace a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter_by_index"))]
    pub async fn replace_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        let (protocol, priority) = filter_info(&config);
        self.replace_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Replace a filter by interface index with explicit parameters.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_filter_by_index_full")
    )]
    pub async fn replace_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        mut config: impl FilterConfig,
    ) -> Result<()> {
        config.set_protocol(protocol);
        let names = self.ifindexes_of(&config.device_names()).await?;
        config.resolve_devices(&names)?;
        let parent_handle = parent.as_raw();
        let filter_handle = handle.or_else(|| config.default_handle()).map_or(0, |h| h.as_raw());

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_filter_info(protocol.as_u16(), priority.as_u16());

        let mut builder = replace_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }
        write_estimator(&mut builder, &config);

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_filter"))
    }

    /// Change an existing filter's parameters.
    ///
    /// Unlike `replace_filter`, this fails if the filter doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # use nlink::netlink::filter::U32Filter;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let filter = U32Filter::new()
    ///     .classid(TcHandle::new(1, 0x20))  // Change to different class
    ///     .match_dst_port(80)
    ///     .build();
    /// conn.change_filter("eth0", TcHandle::major_only(1), EthProto::IP, FilterPriority::new(100), filter)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter"))]
    pub async fn change_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Change a filter with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter_full"))]
    pub async fn change_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Change a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter_by_index"))]
    pub async fn change_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.change_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Change a filter by interface index with explicit handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "change_filter_by_index_full")
    )]
    pub async fn change_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: EthProto,
        priority: FilterPriority,
        mut config: impl FilterConfig,
    ) -> Result<()> {
        config.set_protocol(protocol);
        let names = self.ifindexes_of(&config.device_names()).await?;
        config.resolve_devices(&names)?;
        let parent_handle = parent.as_raw();
        let filter_handle = handle.or_else(|| config.default_handle()).map_or(0, |h| h.as_raw());

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_filter_info(protocol.as_u16(), priority.as_u16());

        let mut builder = ack_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }
        write_estimator(&mut builder, &config);

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("change_filter"))
    }

    /// Delete a filter from an interface.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::{EthProto, FilterPriority};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::TcHandle;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_filter("eth0", TcHandle::major_only(1), EthProto::IP, FilterPriority::new(100))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter"))]
    pub async fn del_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_filter_by_index(ifindex, parent, protocol, priority)
            .await
    }

    /// Delete a filter if it exists. Returns `Ok(true)` if the
    /// filter was deleted, `Ok(false)` if there was none. Unlike
    /// [`Self::del_filter`], does NOT error on `ENOENT` (#169;
    /// mirrors the nftables `del_*_if_exists` family).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter_if_exists"))]
    pub async fn del_filter_if_exists(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> Result<bool> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        // "If it exists" has to cover the parent too. With no qdisc at
        // `parent` there is nowhere for a filter to live, and the kernel
        // says so with EINVAL ("Parent Qdisc doesn't exists") rather
        // than ENOENT — so the plain not-found arm let the error
        // through and the whole point of the `_if_exists` variant was
        // lost on any interface with no qdisc installed.
        if !self.qdisc_exists_at(ifindex, parent).await? {
            return Ok(false);
        }
        match self.del_filter_by_index(ifindex, parent, protocol, priority).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Is there a qdisc that could hold filters at `parent`?
    async fn qdisc_exists_at(&self, ifindex: u32, parent: TcHandle) -> Result<bool> {
        let qdiscs = self.get_qdiscs_by_index(ifindex).await?;
        Ok(qdiscs.iter().any(|q| {
            if parent.is_root() {
                // A kernel-implicit root qdisc (handle 0) holds no
                // filters; `qdisc_lookup` cannot find it either.
                q.parent().is_root() && q.handle_raw() != 0
            } else {
                q.handle().major() == parent.major()
            }
        }))
    }

    /// Delete a filter in a chain by interface index (tc(8)
    /// `chain N`, #793). [`del_filter_by_index`](Self::del_filter_by_index)
    /// deletes in chain 0, and a filter in another chain at the same
    /// priority and protocol is a different filter.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter_in_chain_by_index"))]
    pub async fn del_filter_in_chain_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        chain: u32,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> Result<()> {
        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent.as_raw())
            .with_filter_info(protocol.as_u16(), priority.as_u16());

        let mut builder = create_request(NlMsgType::RTM_DELTFILTER);
        builder.append(&tcmsg);
        builder.append_attr_u32(TcaAttr::Chain as u16, chain);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_filter"))
    }

    /// Delete a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter_by_index"))]
    pub async fn del_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_filter_info(protocol.as_u16(), priority.as_u16());

        let mut builder = create_request(NlMsgType::RTM_DELTFILTER);
        builder.append(&tcmsg);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_filter"))
    }

    /// Delete all filters from a parent qdisc.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_filters"))]
    pub async fn flush_filters(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// Delete all filters from a parent qdisc by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_filters_by_index"))]
    pub async fn flush_filters_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<()> {
        // Get all filters
        let filters = self.get_filters().await?;

        // Delete each filter that matches the parent and interface
        for filter in filters {
            if filter.ifindex() == ifindex && filter.parent() == parent {
                let protocol = filter.protocol();
                let priority = filter.priority();
                if let Err(e) = self
                    .del_filter_by_index(ifindex, parent, protocol, priority)
                    .await
                {
                    // Ignore not found errors
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Attach a BPF program to ingress or egress using clsact.
    ///
    /// Creates the clsact qdisc if it doesn't exist, then attaches the
    /// BPF filter. This is the standard pattern for BPF TC programs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::filter::{BpfFilter, BpfDirection};
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.attach_bpf("eth0", BpfDirection::Ingress, filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "attach_bpf"))]
    pub async fn attach_bpf(
        &self,
        dev: impl Into<InterfaceRef>,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.attach_bpf_by_index(ifindex, direction, filter).await
    }

    /// Attach a BPF program by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "attach_bpf_by_index"))]
    pub async fn attach_bpf_by_index(
        &self,
        ifindex: u32,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        // Add clsact qdisc (ignore EEXIST)
        match self
            .add_qdisc_by_index(ifindex, crate::netlink::tc::ClsactConfig::new())
            .await
        {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e),
        }

        // The *filter* parent is the hook, not the qdisc: TcHandle::CLSACT
        // is TC_H_INGRESS (where the qdisc lives), so naming it here
        // worked only while CLSACT was mis-transcribed as 0xFFFFFFF2.
        let parent = match direction {
            BpfDirection::Ingress => TcHandle::CLSACT_INGRESS,
            BpfDirection::Egress => TcHandle::CLSACT_EGRESS,
        };

        self.add_filter_by_index(ifindex, parent, filter).await
    }

    /// Detach all BPF filters from an interface direction.
    ///
    /// Flushes all filters attached to the ingress or egress hook of
    /// the clsact qdisc.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::filter::BpfDirection;
    ///
    /// conn.detach_bpf("eth0", BpfDirection::Ingress).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "detach_bpf"))]
    pub async fn detach_bpf(
        &self,
        dev: impl Into<InterfaceRef>,
        direction: BpfDirection,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.detach_bpf_by_index(ifindex, direction).await
    }

    /// Detach all BPF filters from an interface direction by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "detach_bpf_by_index"))]
    pub async fn detach_bpf_by_index(&self, ifindex: u32, direction: BpfDirection) -> Result<()> {
        // The *filter* parent is the hook, not the qdisc: TcHandle::CLSACT
        // is TC_H_INGRESS (where the qdisc lives), so naming it here
        // worked only while CLSACT was mis-transcribed as 0xFFFFFFF2.
        let parent = match direction {
            BpfDirection::Ingress => TcHandle::CLSACT_INGRESS,
            BpfDirection::Egress => TcHandle::CLSACT_EGRESS,
        };
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// List attached BPF programs on an interface (both directions).
    ///
    /// Returns BPF program info for each BPF filter found on the interface's
    /// clsact qdisc. Returns an empty vec if no clsact qdisc exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let programs = conn.list_bpf_programs("eth0").await?;
    /// for prog in &programs {
    ///     println!("BPF: id={:?} name={:?} da={}", prog.id, prog.name, prog.direct_action);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_bpf_programs"))]
    pub async fn list_bpf_programs(
        &self,
        dev: impl Into<InterfaceRef>,
    ) -> Result<Vec<crate::netlink::messages::BpfInfo>> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.list_bpf_programs_by_index(ifindex).await
    }

    /// List attached BPF programs by interface index.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "list_bpf_programs_by_index")
    )]
    pub async fn list_bpf_programs_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<crate::netlink::messages::BpfInfo>> {
        let mut programs = Vec::new();

        let all_filters = match self.get_filters_by_index(ifindex).await {
            Ok(f) => f,
            Err(e) if e.is_not_found() || e.is_invalid_argument() => {
                return Ok(programs);
            }
            Err(e) => return Err(e),
        };

        for filter in &all_filters {
            if let Some(info) = filter.bpf_info() {
                programs.push(info);
            }
        }

        Ok(programs)
    }
}

/// Direction for BPF program attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BpfDirection {
    /// Ingress (clsact ingress hook).
    Ingress,
    /// Egress (clsact egress hook).
    Egress,
}

/// `add_filter` must honor the config's protocol and priority (#201).
///
/// Every shipped filter has public `.protocol()` / `.priority()` setters whose
/// values `add_filter` used to throw away, hardcoding `ETH_P_IP` and
/// auto-priority. The fields *were* assigned, so the compiler could not warn.
/// These pin the accessor path that `add_filter`/`replace_filter` now read.
#[cfg(test)]
mod filter_info_tests {
    use super::*;

    /// The headline failure: a matchall on clsact asking for ETH_P_ALL was
    /// installed as `protocol ip`, so IPv6, ARP and VLAN traffic never hit the
    /// filter at all — with no error returned.
    #[test]
    fn explicit_protocol_and_priority_reach_the_wire() {
        use crate::{EthProto, FilterPriority};

        let f = MatchallFilter::new()
            .protocol(EthProto::ALL)
            .priority(FilterPriority::new(1));
        assert_eq!(filter_info(&f), (EthProto::ALL, FilterPriority::new(1)));

        let f = FlowerFilter::new()
            .protocol(EthProto::IPV6)
            .priority(FilterPriority::new(7));
        assert_eq!(filter_info(&f), (EthProto::IPV6, FilterPriority::new(7)));
    }

    /// Matchall and flower default to ETH_P_ALL. That default is the whole
    /// point of them, and it used to be overridden with ETH_P_IP on the way
    /// out.
    #[test]
    fn shipped_defaults_reach_the_wire() {
        assert_eq!(filter_info(&MatchallFilter::new()).0, 0x0003);
        assert_eq!(filter_info(&FlowerFilter::new()).0, 0x0003);
        // u32 is genuinely an IPv4 classifier by default.
        assert_eq!(filter_info(&U32Filter::new()).0, 0x0800);
    }

    /// A config that carries no ethertype of its own (fw, cgroup, tcindex,
    /// route, rsvp) leaves the trait default, and `add_filter` falls back.
    /// Priority 0 means "kernel, you pick".
    #[test]
    fn configs_without_their_own_ethertype_fall_back() {
        assert_eq!(FwFilter::new().protocol(), None);
        assert_eq!(FwFilter::new().priority(), None);
        assert_eq!(
            filter_info(&FwFilter::new()),
            (DEFAULT_FILTER_PROTOCOL, crate::FilterPriority::new(0)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcindex_parse_and_write() {
        let f = TcindexFilter::parse_params(&[
            "hash", "256", "mask", "0xff", "shift", "0", "fall_through", "classid", "1:10",
        ])
        .unwrap();
        assert_eq!(f.hash, Some(256));
        assert_eq!(f.mask, Some(0xff));
        assert_eq!(f.shift, Some(0));
        assert_eq!(f.fall_through, Some(true));
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));

        // pass_on flips fall_through; set_chain via trait works.
        let mut f = TcindexFilter::parse_params(&["pass_on"]).unwrap();
        assert_eq!(f.fall_through, Some(false));
        FilterConfig::set_chain(&mut f, 4);
        assert_eq!(FilterConfig::chain(&f), Some(4));

        let mut b = MessageBuilder::new(NlMsgType::RTM_NEWTFILTER, 0);
        f.write_options(&mut b).unwrap();

        // strict: missing value, bad mask, unknown token.
        assert!(TcindexFilter::parse_params(&["hash"]).is_err());
        assert!(TcindexFilter::parse_params(&["mask", "zz"]).is_err());
        assert!(TcindexFilter::parse_params(&["unknown"]).is_err());
    }

    #[test]
    fn set_chain_through_trait_object() {
        // The `tc --chain` flag drives every filter kind generically
        // through `FilterConfig::set_chain`; verify the value lands in
        // the concrete config's `chain()` getter for a representative
        // sample of kinds.
        let mut u32f = U32Filter::new().build();
        assert_eq!(FilterConfig::chain(&u32f), None);
        FilterConfig::set_chain(&mut u32f, 7);
        assert_eq!(FilterConfig::chain(&u32f), Some(7));

        let mut flower = FlowerFilter::new().build();
        FilterConfig::set_chain(&mut flower, 3);
        assert_eq!(FilterConfig::chain(&flower), Some(3));

        let mut matchall = MatchallFilter::new().build();
        FilterConfig::set_chain(&mut matchall, 0);
        assert_eq!(FilterConfig::chain(&matchall), Some(0));
    }

    #[test]
    fn test_u32_filter_builder() {
        let filter = U32Filter::new()
            .classid(TcHandle::new(1, 0x10))
            .match_dst_ipv4(Ipv4Addr::new(192, 168, 1, 0), 24)
            .priority(crate::FilterPriority::new(100))
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.keys.len(), 1);
    }

    #[test]
    fn test_flower_filter_builder() {
        let filter = FlowerFilter::new()
            .classid(TcHandle::new(1, 0x20))
            .ip_proto_tcp()
            .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dst_port(80)
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x20).as_raw()));
        assert_eq!(filter.ip_proto, Some(flower::IPPROTO_TCP));
        assert_eq!(filter.dst_ipv4, Some((Ipv4Addr::new(10, 0, 0, 0), 8)));
        assert_eq!(filter.dst_port, Some(80));
        assert_eq!(filter.eth_type, Some(0x0800));
    }

    /// #313 — `cls_matchall` carries no keys, so the action list is the
    /// only thing it is normally installed for, and `MatchallFilter` had
    /// no way to set one. Two doc examples showed the `.actions()` call
    /// that did not exist; both were ```ignore, so nothing compiled them.
    ///
    /// Asserted at the byte level because `goto_chain` shares
    /// `TCA_MATCHALL_ACT` with the action list: emitting the attribute
    /// twice would leave the kernel to keep one nest and drop the other,
    /// and no return value would say so.
    #[test]
    fn matchall_actions_and_goto_chain_share_one_act_nest() {
        use crate::netlink::{
            action::{ActionList, GactAction},
            test_support::parse_attrs,
        };

        let encode = |f: &MatchallFilter| {
            let mut b = MessageBuilder::new(NlMsgType::RTM_NEWTFILTER, 0);
            f.write_options(&mut b).unwrap();
            crate::netlink::test_support::builder_attrs(&b)
        };

        // Actions alone: one nest, one action at index 1.
        let attrs = encode(&MatchallFilter::new().actions(
            ActionList::new().with(GactAction::drop()),
        ));
        let act = attrs
            .get(&matchall::TCA_MATCHALL_ACT)
            .expect("TCA_MATCHALL_ACT missing: the action list was dropped");
        let inner = parse_attrs(act);
        assert_eq!(inner.len(), 1, "expected one action, got {inner:?}");
        assert!(inner.contains_key(&1), "actions are numbered from 1");

        // goto_chain alone keeps working, still at index 1.
        let attrs = encode(&MatchallFilter::new().goto_chain(3));
        let inner = parse_attrs(attrs.get(&matchall::TCA_MATCHALL_ACT).unwrap());
        assert_eq!(inner.len(), 1);
        assert!(inner.contains_key(&1));

        // Both: one nest, two entries, the goto after the action — the
        // order tc(8) emits and the kernel runs.
        let attrs = encode(
            &MatchallFilter::new()
                .actions(ActionList::new().with(GactAction::drop()))
                .goto_chain(3),
        );
        let inner = parse_attrs(attrs.get(&matchall::TCA_MATCHALL_ACT).unwrap());
        assert_eq!(
            inner.len(),
            2,
            "the goto must extend the action list, not collide with it: {inner:?}"
        );
        assert!(inner.contains_key(&1) && inner.contains_key(&2));
    }

    #[test]
    fn test_matchall_filter_builder() {
        let filter = MatchallFilter::new()
            .classid(TcHandle::new(1, 0x30))
            .skip_hw()
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x30).as_raw()));
        assert!(filter.flags & flower::TCA_CLS_FLAGS_SKIP_HW != 0);
    }

    #[test]
    fn test_fw_filter_builder() {
        let filter = FwFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .mask(0xFF)
            .build();

        assert_eq!(filter.mask, 0xFF);
        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn test_ipv4_mask() {
        assert_eq!(ipv4_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(ipv4_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(ipv4_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_ipv6_mask() {
        let full = ipv6_mask(128);
        assert_eq!(full.octets(), [0xFF; 16]);

        let zero = ipv6_mask(0);
        assert_eq!(zero.octets(), [0; 16]);

        let half = ipv6_mask(64);
        assert_eq!(
            half.octets(),
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_cgroup_filter_builder() {
        let filter = CgroupFilter::new().build();

        assert_eq!(FilterConfig::kind(&filter), "cgroup");
        assert_eq!(filter.classid(), None);
    }

    #[test]
    fn test_route_filter_builder() {
        let filter = RouteFilter::new()
            .to_realm(10)
            .from_realm(5)
            .classid(TcHandle::new(1, 0x10))
            .build();

        assert_eq!(FilterConfig::kind(&filter), "route");
        assert_eq!(filter.to_realm, Some(10));
        assert_eq!(filter.from_realm, Some(5));
        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn test_flow_filter_builder() {
        use crate::netlink::types::tc::filter::flow;

        let filter = FlowFilter::new()
            .keys(&[FlowKey::Src, FlowKey::Dst])
            .mode_hash()
            .divisor(256)
            .baseclass(TcHandle::new(1, 0x10))
            .build();

        assert_eq!(FilterConfig::kind(&filter), "flow");
        assert_eq!(filter.keys, flow::FLOW_KEY_SRC | flow::FLOW_KEY_DST);
        assert_eq!(filter.mode, flow::FLOW_MODE_HASH);
        assert_eq!(filter.divisor, Some(256));
        assert_eq!(filter.baseclass, Some(TcHandle::new(1, 0x10).as_raw()));

        // Test single key
        let filter = FlowFilter::new()
            .key(FlowKey::Mark)
            .mode_map()
            .mask(0xff)
            .rshift(8)
            .build();

        assert_eq!(filter.keys, flow::FLOW_KEY_MARK);
        assert_eq!(filter.mode, flow::FLOW_MODE_MAP);
        assert_eq!(filter.mask, Some(0xff));
        assert_eq!(filter.rshift, Some(8));
    }

    #[test]
    fn test_bpf_filter_builder() {
        let filter = BpfFilter::with_raw_fd(42)
            .name("my_prog")
            .direct_action()
            .priority(crate::FilterPriority::new(100))
            .chain(5);

        assert_eq!(filter.fd.raw().unwrap(), 42);
        assert_eq!(filter.name.as_deref(), Some("my_prog"));
        assert!(filter.direct_action);
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.chain, Some(5));
    }

    #[test]
    fn test_bpf_filter_defaults() {
        let filter = BpfFilter::with_raw_fd(7);

        assert_eq!(filter.fd.raw().unwrap(), 7);
        assert!(filter.name.is_none());
        assert!(!filter.direct_action);
        assert_eq!(filter.priority, 0);
        assert_eq!(filter.protocol, 3); // ETH_P_ALL in host byte order
        assert!(filter.chain.is_none());
        assert!(filter.classid.is_none());
    }

    #[test]
    fn test_bpf_from_pinned_invalid_path() {
        let result = BpfFilter::from_pinned("/nonexistent/path/to/bpf");
        assert!(result.is_err());
    }

    #[test]
    fn flower_parse_params_empty_yields_default() {
        let f = FlowerFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.eth_type.is_none());
        assert!(f.ip_proto.is_none());
        assert_eq!(f.flags, 0);
    }

    #[test]
    fn flower_parse_params_classid_and_proto() {
        let f = FlowerFilter::parse_params(&["classid", "1:10", "ip_proto", "tcp"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.ip_proto, Some(flower::IPPROTO_TCP));
    }

    #[test]
    fn flower_parse_params_flowid_alias() {
        let f = FlowerFilter::parse_params(&["flowid", "1:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
    }

    #[test]
    fn flower_parse_params_ip_proto_numeric() {
        // Hex, as tc(8) reads it (#432).
        let f = FlowerFilter::parse_params(&["ip_proto", "2f"]).unwrap();
        assert_eq!(f.ip_proto, Some(47)); // GRE
    }

    #[test]
    fn flower_parse_params_dst_port() {
        let f = FlowerFilter::parse_params(&["dst_port", "443"]).unwrap();
        assert_eq!(f.dst_port, Some(443));
    }

    /// tc(8)'s `min-max` is a port range (#416).
    #[test]
    fn flower_parse_params_port_ranges() {
        let f = FlowerFilter::parse_params(&["dst_port", "8000-8100"]).unwrap();
        assert_eq!(f.dst_port_range, Some((8000, 8100)));
        assert_eq!(f.dst_port, None);
        let f = FlowerFilter::parse_params(&["src_port", "1-2"]).unwrap();
        assert_eq!(f.src_port_range, Some((1, 2)));

        for bad in ["8100-8000", "8000-8000", "8000-", "-8000", "8000-x", "1-70000"] {
            let crate::ErrorDetail::InvalidMessage(err) = FlowerFilter::parse_params(&["dst_port", bad]).expect_err(bad).into_detail() else {
                panic!("{bad}: not an InvalidMessage");
            };
            assert!(err.starts_with("flower: "), "{bad}: {err}");
            assert!(err.contains(bad), "{bad}: the error must quote the value: {err}");
        }
    }

    #[test]
    fn flower_parse_params_src_ip_v4_with_prefix() {
        let f = FlowerFilter::parse_params(&["src_ip", "10.0.0.0/8"]).unwrap();
        assert_eq!(f.src_ipv4, Some(("10.0.0.0".parse().unwrap(), 8)));
        // sets eth_type implicitly
        assert_eq!(f.eth_type, Some(0x0800));
    }

    #[test]
    fn flower_parse_params_src_ip_v4_bare() {
        let f = FlowerFilter::parse_params(&["dst_ip", "192.168.1.1"]).unwrap();
        assert_eq!(f.dst_ipv4, Some(("192.168.1.1".parse().unwrap(), 32)));
    }

    #[test]
    fn flower_parse_params_dst_ip_v6_with_prefix() {
        let f = FlowerFilter::parse_params(&["dst_ip", "fe80::1/64"]).unwrap();
        assert_eq!(f.dst_ipv6, Some(("fe80::1".parse().unwrap(), 64)));
        assert_eq!(f.eth_type, Some(0x86dd));
    }

    #[test]
    fn flower_parse_params_dst_ip_v6_bare() {
        let f = FlowerFilter::parse_params(&["src_ip", "::1"]).unwrap();
        assert_eq!(f.src_ipv6, Some(("::1".parse().unwrap(), 128)));
    }

    #[test]
    fn flower_parse_params_dst_mac() {
        let f = FlowerFilter::parse_params(&["dst_mac", "aa:bb:cc:dd:ee:ff"]).unwrap();
        assert_eq!(f.dst_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn flower_parse_params_eth_type_names() {
        for (name, expected) in [
            ("ip", 0x0800u16),
            ("ipv4", 0x0800),
            ("ipv6", 0x86dd),
            ("arp", 0x0806),
            ("802.1q", 0x8100),
            ("802.1ad", 0x88a8),
        ] {
            let f = FlowerFilter::parse_params(&["eth_type", name]).unwrap();
            assert_eq!(f.eth_type, Some(expected), "eth_type {name}");
        }
    }

    #[test]
    fn flower_parse_params_eth_type_hex() {
        let f = FlowerFilter::parse_params(&["eth_type", "0x806"]).unwrap();
        assert_eq!(f.eth_type, Some(0x0806));
    }

    /// #515: a bare number is decimal, as tc(8) reads a protocol
    /// (`ll_proto_a2n`, base 0); it was read as hex, so 2048 meant 0x2048.
    #[test]
    fn flower_parse_params_eth_type_numbers_as_tc_reads_them() {
        for (text, want) in [("2048", 0x0800), ("34525", 0x86DD), ("04000", 0x0800)] {
            let f = FlowerFilter::parse_params(&["eth_type", text]).unwrap();
            assert_eq!(f.eth_type, Some(want), "{text}");
        }
        assert!(FlowerFilter::parse_params(&["eth_type", "0x10000"]).is_err());
    }

    #[test]
    fn flower_parse_params_vlan_id_and_prio() {
        let f = FlowerFilter::parse_params(&["vlan_id", "100", "vlan_prio", "5"]).unwrap();
        assert_eq!(f.vlan_id, Some(100));
        assert_eq!(f.vlan_prio, Some(5));
    }

    #[test]
    fn flower_parse_params_vlan_id_out_of_range_errors() {
        let err = FlowerFilter::parse_params(&["vlan_id", "0"]).unwrap_err();
        assert!(err.to_string().contains("vlan_id"));
        let err = FlowerFilter::parse_params(&["vlan_id", "5000"]).unwrap_err();
        assert!(err.to_string().contains("vlan_id"));
    }

    #[test]
    fn flower_parse_params_ip_tos_with_mask() {
        let f = FlowerFilter::parse_params(&["ip_tos", "0x10/0x3f"]).unwrap();
        assert_eq!(f.ip_tos, Some((0x10, 0x3f)));
    }

    #[test]
    fn flower_parse_params_ip_tos_bare_implies_mask_ff() {
        let f = FlowerFilter::parse_params(&["ip_tos", "0x10"]).unwrap();
        assert_eq!(f.ip_tos, Some((0x10, 0xff)));
    }

    #[test]
    fn flower_parse_params_skip_hw_sw_flags() {
        let f = FlowerFilter::parse_params(&["skip_hw", "skip_sw"]).unwrap();
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn flower_parse_params_unknown_token_errors() {
        let err = FlowerFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    /// The options a flower writes, by attribute type.
    fn flower_attrs(f: &FlowerFilter) -> std::collections::HashMap<u16, Vec<u8>> {
        let mut b = MessageBuilder::new(0, 0);
        f.write_options(&mut b).unwrap();
        let bytes = b.finish()[16..].to_vec();
        crate::netlink::attr::AttrIter::new(&bytes).map(|(ty, p)| (ty & 0x3fff, p.to_vec())).collect()
    }

    /// tc-ematch(8) expressions after `match`, as tc reads them (#828).
    #[test]
    fn basic_reads_tcs_ematch_expressions() {
        // One argument per match, as the shell passes a quoted one, or
        // split across several; the expression ends where it stops.
        let quoted = BasicFilter::parse_params(&["match", "cmp(u8 at 9 layer network eq 6)", "classid", "1:10"]).unwrap();
        let split = BasicFilter::parse_params(&["match", "cmp(", "u8", "at", "9", "layer", "network", "eq", "6", ")", "classid", "1:10"]).unwrap();
        assert_eq!(format!("{:?}", quoted.matches), format!("{:?}", split.matches));
        assert_eq!(quoted.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        let f = BasicFilter::parse_params(&["match", "not", "cmp(u8 at 9 layer network eq 17)", "or", "u32(u8 0x06 0xff at 9)"]).unwrap();
        assert_eq!(f.matches.len(), 2);
        assert!(f.matches[0].negate && f.matches[0].op == EmatchOp::Or);
        let EmatchKind::U32(u) = &f.matches[1].kind else { panic!() };
        // The protocol byte, the second of the word at 8.
        assert_eq!((u.mask, u.value, u.offset), (0x00ff_0000, 0x0006_0000, 8));
        let f = BasicFilter::parse_params(&["match", "cmp(u32 at 12 mask 0xffffff00 trans gt 167772160)"]).unwrap();
        let EmatchKind::Cmp(c) = &f.matches[0].kind else { panic!() };
        assert_eq!((c.offset, c.mask, c.value, c.op, c.trans), (12, 0xffff_ff00, 167_772_160, CmpOp::Gt, true));

        for (bad, says) in [
            (&["match", "(cmp(u8 at 9 eq 6))"][..], "groups"),
            (&["match", "meta(priority eq 5)"], "not modelled"),
            (&["match", "cmp(u8 at 9 eq 6"], "no `)`"),
            (&["match", "cmp(u8 eq 6)"], "required"),
            (&["match", "u32(u8 0x106 0xff at 9)"], "wider"),
            (&["match", "u32(u8 1 0xff at nexthdr+0)"], "next header"),
            (&["match", "cmp(u8 at 9 eq 6) classid"], "unexpected"),
        ] {
            let err = BasicFilter::parse_params(bad).unwrap_err().to_string();
            assert!(err.contains(says), "{bad:?}: {err}");
        }
    }

    /// A u32 ematch's key is the kernel's whole `struct tc_u32_key`, its
    /// word big-endian (#828).
    #[test]
    fn a_u32_ematchs_key_is_tcs() {
        let f = BasicFilter::new().ematch(Ematch::u32(EmatchU32 { mask: 0x00ff_0000, value: 0x0006_0000, offset: 8 }));
        let mut b = MessageBuilder::new(0, 0);
        f.write_options(&mut b).unwrap();
        let bytes = b.finish();
        let needle = [0x00, 0xff, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 8, 0, 0, 0, 0, 0, 0, 0];
        assert!(bytes.windows(16).any(|w| w == needle), "{bytes:02x?}");
        assert_eq!(ematch::TcfEmU32::SIZE, 16);
    }

    /// tc-flower(8)'s other keys, written as f_flower.c writes them (#827).
    #[test]
    fn flower_reads_and_writes_tcs_other_keys() {
        let parse = |w: &[&str], proto: u16| {
            let mut f = FlowerFilter::parse_params(w).unwrap();
            f.set_protocol(EthProto::new(proto));
            flower_attrs(&f)
        };
        let a = parse(&["ip_proto", "icmp", "type", "8", "code", "0/255"], 0x0800);
        assert_eq!((&a[&flower::TCA_FLOWER_KEY_ICMPV4_TYPE], &a[&flower::TCA_FLOWER_KEY_ICMPV4_CODE_MASK]), (&vec![8], &vec![255]));
        let a = parse(&["ip_proto", "icmpv6", "type", "128"], 0x86DD);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ICMPV6_TYPE], [128]);
        let a = parse(&["ip_flags", "frag/nofirstfrag"], 0x0800);
        assert_eq!((&a[&flower::TCA_FLOWER_KEY_FLAGS], &a[&flower::TCA_FLOWER_KEY_FLAGS_MASK]), (&1u32.to_be_bytes().to_vec(), &3u32.to_be_bytes().to_vec()));
        let a = parse(&["ct_state", "+trk+est-new", "ct_zone", "3", "ct_mark", "5/0xff"], 0x0800);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_CT_STATE], 0b1010u16.to_ne_bytes());
        assert_eq!(a[&flower::TCA_FLOWER_KEY_CT_STATE_MASK], 0b1011u16.to_ne_bytes());
        assert_eq!(a[&flower::TCA_FLOWER_KEY_CT_ZONE_MASK], u16::MAX.to_ne_bytes());
        assert_eq!(a[&flower::TCA_FLOWER_KEY_CT_MARK_MASK], 0xffu32.to_ne_bytes());
        let a = parse(&["enc_key_id", "100", "enc_dst_ip", "10.0.0.0/24", "enc_dst_port", "4789"], 0x0800);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ENC_KEY_ID], 100u32.to_be_bytes());
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ENC_IPV4_DST_MASK], [255, 255, 255, 0]);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ENC_UDP_DST_PORT], 4789u16.to_be_bytes());
        let a = parse(&["src_mac", "02:00:00:00:00:00/24"], 0x0800);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ETH_SRC_MASK], [0xff, 0xff, 0xff, 0, 0, 0]);
        let a = parse(&["vlan_id", "10", "vlan_ethtype", "ip", "src_ip", "10.0.0.1"], 0x8100);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_ETH_TYPE], 0x8100u16.to_be_bytes());
        assert_eq!(a[&flower::TCA_FLOWER_KEY_VLAN_ETH_TYPE], 0x0800u16.to_be_bytes());
        let a = parse(&["arp_op", "request", "arp_tip", "10.0.0.0/8"], 0x0806);
        assert_eq!((&a[&flower::TCA_FLOWER_KEY_ARP_OP], &a[&flower::TCA_FLOWER_KEY_ARP_TIP_MASK]), (&vec![1], &vec![255, 0, 0, 0]));
        let a = parse(&["mpls_label", "100", "mpls_bos", "1"], 0x8847);
        assert_eq!(a[&flower::TCA_FLOWER_KEY_MPLS_LABEL], 100u32.to_ne_bytes());

        // The text round trips.
        for words in [
            &["ip_proto", "icmp", "type", "8/255", "ct_state", "+trk-est", "ct_label", "01/ff"][..],
            &["arp_op", "reply", "arp_sha", "02:00:00:00:00:01/ff:ff:ff:00:00:00", "indev", "lo"],
            &["enc_src_ip", "fd00::/64", "enc_tos", "16/0xfc", "ip_flags", "nofrag"],
        ] {
            let f = FlowerFilter::parse_params(words).unwrap();
            let back = f.to_params().unwrap();
            let refs: Vec<&str> = back.iter().map(String::as_str).collect();
            assert_eq!(FlowerFilter::parse_params(&refs).unwrap().to_params().unwrap(), back, "{words:?}");
        }
        assert!(FlowerFilter::parse_params(&["ct_state", "+bogus"]).is_err());
        assert!(FlowerFilter::parse_params(&["ip_flags", "csum"]).is_err());
        assert!(FlowerFilter::parse_params(&["mpls_tc", "8"]).is_err());
    }

    /// The kernel reads ARP, MPLS and ICMP keys only under their own
    /// ethertypes, and the inner VLAN keys only under two tags: anywhere
    /// else it drops them and installs a match-all, so they are refused.
    #[test]
    fn flower_refuses_keys_the_kernel_would_drop() {
        let refused = |w: &[&str], proto: u16| {
            let mut f = FlowerFilter::parse_params(w).unwrap();
            f.set_protocol(EthProto::new(proto));
            let mut b = MessageBuilder::new(0, 0);
            f.write_options(&mut b).unwrap_err().to_string()
        };
        assert!(refused(&["arp_op", "request"], 0x0800).contains("ARP"));
        assert!(refused(&["mpls_label", "5"], 0x0800).contains("MPLS"));
        assert!(refused(&["ip_proto", "tcp", "type", "8"], 0x0800).contains("ICMP"));
        assert!(refused(&["ip_proto", "icmp", "type", "8"], 0x86DD).contains("ICMP"));
        assert!(refused(&["vlan_ethtype", "ip"], 0x0800).contains("vlan_ethtype"));
        assert!(refused(&["vlan_id", "1", "vlan_ethtype", "ip", "cvlan_id", "2"], 0x8100).contains("cvlan"));
        // Under a VLAN, the L3 keys follow vlan_ethtype.
        assert!(refused(&["vlan_id", "1", "vlan_ethtype", "arp", "ip_proto", "tcp"], 0x8100).contains("inside the VLAN"));
    }

    #[test]
    fn flower_parse_params_missing_value_errors() {
        let err = FlowerFilter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn flower_parse_params_invalid_mac_errors() {
        let err = FlowerFilter::parse_params(&["dst_mac", "not-a-mac"]).unwrap_err();
        assert!(err.to_string().contains("invalid MAC"));
    }

    #[test]
    fn flower_parse_params_invalid_ipv4_prefix_errors() {
        let err = FlowerFilter::parse_params(&["src_ip", "10.0.0.0/40"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn matchall_parse_params_empty_yields_default() {
        let f = MatchallFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.chain.is_none());
        assert!(f.goto_chain.is_none());
        assert_eq!(f.flags, 0);
    }

    #[test]
    fn matchall_parse_params_classid() {
        let f = MatchallFilter::parse_params(&["classid", "1:10"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn matchall_parse_params_flowid_alias() {
        let f = MatchallFilter::parse_params(&["flowid", "1:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
    }

    #[test]
    fn matchall_parse_params_chain_and_goto_chain() {
        let f = MatchallFilter::parse_params(&["chain", "5", "goto_chain", "100"]).unwrap();
        assert_eq!(f.chain, Some(5));
        assert_eq!(f.goto_chain, Some(100));
    }

    #[test]
    fn matchall_parse_params_skip_flags() {
        let f = MatchallFilter::parse_params(&["skip_hw", "skip_sw"]).unwrap();
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn matchall_parse_params_unknown_token_errors() {
        let err = MatchallFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn matchall_parse_params_missing_value_errors() {
        let err = MatchallFilter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn fw_parse_params_empty_yields_default() {
        let f = FwFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert_eq!(f.mask, 0xFFFFFFFF);
        assert!(f.chain.is_none());
    }

    #[test]
    fn fw_parse_params_classid_and_mask() {
        let f = FwFilter::parse_params(&["classid", "1:10", "mask", "0xff"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.mask, 0xff);
    }

    #[test]
    fn fw_parse_params_mask_decimal() {
        let f = FwFilter::parse_params(&["mask", "255"]).unwrap();
        assert_eq!(f.mask, 255);
    }

    #[test]
    fn fw_parse_params_chain() {
        let f = FwFilter::parse_params(&["chain", "3"]).unwrap();
        assert_eq!(f.chain, Some(3));
    }

    #[test]
    fn fw_parse_params_unknown_token_errors() {
        let err = FwFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fw_parse_params_invalid_mask_errors() {
        let err = FwFilter::parse_params(&["mask", "zzzz"]).unwrap_err();
        assert!(err.to_string().contains("invalid mask"));
    }

    #[test]
    fn route_parse_params_empty_yields_default() {
        let f = RouteFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.to_realm.is_none());
        assert!(f.from_realm.is_none());
        assert!(f.from_if.is_none());
        assert!(f.chain.is_none());
    }

    #[test]
    fn route_parse_params_typical() {
        let f =
            RouteFilter::parse_params(&["classid", "1:10", "to", "10", "from", "5", "iif", "eth1"])
                .unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.to_realm, Some(10));
        assert_eq!(f.from_realm, Some(5));
        assert_eq!(f.chain, None);
    }

    #[test]
    fn route_parse_params_chain_and_flowid_alias() {
        let f = RouteFilter::parse_params(&["flowid", "1:20", "chain", "3"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
        assert_eq!(f.chain, Some(3));
    }

    #[test]
    fn route_parse_params_unknown_token_errors() {
        let err = RouteFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn route_parse_params_missing_value_errors() {
        let err = RouteFilter::parse_params(&["to"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn route_parse_params_invalid_realm_errors() {
        let err = RouteFilter::parse_params(&["to", "not-a-number"]).unwrap_err();
        assert!(err.to_string().contains("invalid to realm"));
    }

    #[test]
    fn rsvp_parse_params_v4_session_sender_proto() {
        let f = RsvpFilter::parse_params(&[
            "ipproto", "tcp", "session", "10.0.0.1", "sender", "10.0.0.2", "classid", "1:10",
        ])
        .unwrap();
        assert_eq!(f.kind(), "rsvp");
        assert_eq!(f.ipproto, Some(6));
        assert_eq!(f.dst, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(f.src, Some("10.0.0.2".parse().unwrap()));
        assert!(f.classid.is_some());
    }

    #[test]
    fn rsvp_parse_params_v6_selects_rsvp6_kind() {
        let f = RsvpFilter::parse_params(&["session", "2001:db8::1"]).unwrap();
        assert_eq!(f.kind(), "rsvp6");
    }

    #[test]
    fn rsvp_parse_params_port_form_not_modelled() {
        let err = RsvpFilter::parse_params(&["session", "10.0.0.1/22"]).unwrap_err();
        assert!(
            err.to_string().contains("not modelled"),
            "expected not-modelled for port form, got: {err}"
        );
    }

    #[test]
    fn rsvp_parse_params_ipproto_numeric_and_udp() {
        assert_eq!(
            RsvpFilter::parse_params(&["ipproto", "udp"]).unwrap().ipproto,
            Some(17)
        );
        assert_eq!(
            RsvpFilter::parse_params(&["ipproto", "47"]).unwrap().ipproto,
            Some(47)
        );
        let err = RsvpFilter::parse_params(&["ipproto", "bogus"]).unwrap_err();
        assert!(err.to_string().contains("invalid ipproto"));
    }

    #[test]
    fn rsvp_parse_params_strict_errors() {
        assert!(
            RsvpFilter::parse_params(&["nonsense"])
                .unwrap_err()
                .to_string()
                .contains("unknown token")
        );
        assert!(
            RsvpFilter::parse_params(&["session"])
                .unwrap_err()
                .to_string()
                .contains("requires a value")
        );
        assert!(
            RsvpFilter::parse_params(&["session", "not-an-ip"])
                .unwrap_err()
                .to_string()
                .contains("invalid session address")
        );
    }

    #[test]
    fn bpf_parse_params_requires_program_ref() {
        let err = BpfFilter::parse_params(&[]).unwrap_err();
        assert!(
            err.to_string().contains("program reference required"),
            "got: {err}"
        );
        let err = BpfFilter::parse_params(&["da"]).unwrap_err();
        assert!(err.to_string().contains("program reference required"));
    }

    #[test]
    fn bpf_parse_params_fd() {
        let f = BpfFilter::parse_params(&["fd", "42"]).unwrap();
        assert_eq!(f.fd.raw().unwrap(), 42);
        assert!(!f.direct_action);
    }

    #[test]
    fn bpf_parse_params_full_set() {
        let f = BpfFilter::parse_params(&[
            "fd", "10", "name", "my_prog", "classid", "1:5", "chain", "2", "da",
        ])
        .unwrap();
        assert_eq!(f.fd.raw().unwrap(), 10);
        assert_eq!(f.name.as_deref(), Some("my_prog"));
        assert_eq!(f.classid, Some(TcHandle::new(1, 5).as_raw()));
        assert_eq!(f.chain, Some(2));
        assert!(f.direct_action);
    }

    #[test]
    fn bpf_parse_params_aliases() {
        let f = BpfFilter::parse_params(&[
            "fd",
            "1",
            "section",
            "my_section",
            "flowid",
            "1:7",
            "direct-action",
        ])
        .unwrap();
        assert_eq!(f.name.as_deref(), Some("my_section"));
        assert_eq!(f.classid, Some(TcHandle::new(1, 7).as_raw()));
        assert!(f.direct_action);
    }

    #[test]
    fn bpf_parse_params_pinned_and_fd_mutually_exclusive() {
        // Use a path that doesn't exist so File::open fails — but the
        // mutex check happens before that lookup.
        let err = BpfFilter::parse_params(&["fd", "1", "pinned", "/nonexistent"]).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn bpf_parse_params_pinned_open_failure_surfaces_err() {
        let err = BpfFilter::parse_params(&["pinned", "/nonexistent/path/to/bpf"]).unwrap_err();
        assert!(err.to_string().contains("open pinned program"), "got: {err}");
        // The kernel's errno survives, not a message (#718).
        assert!(err.errno().is_some(), "got: {err:?}");
    }

    #[test]
    fn bpf_parse_params_skip_flags_rejected() {
        let err = BpfFilter::parse_params(&["fd", "1", "skip_hw"]).unwrap_err();
        assert!(err.to_string().contains("not modelled"), "got: {err}");
    }

    #[test]
    fn bpf_parse_params_unknown_token_errors() {
        let err = BpfFilter::parse_params(&["fd", "1", "nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn cgroup_parse_params_empty_yields_default() {
        let f = CgroupFilter::parse_params(&[]).unwrap();
        assert!(f.chain.is_none());
    }

    #[test]
    fn cgroup_parse_params_chain() {
        let f = CgroupFilter::parse_params(&["chain", "5"]).unwrap();
        assert_eq!(f.chain, Some(5));
    }

    #[test]
    fn cgroup_parse_params_unknown_token_errors() {
        let err = CgroupFilter::parse_params(&["classid", "1:10"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn flow_parse_params_keys_csv() {
        let f = FlowFilter::parse_params(&["keys", "src,dst,proto"]).unwrap();
        assert!(f.keys != 0);
        // Three keys should each be set.
        assert_eq!(
            f.keys,
            FlowKey::Src.to_bit() | FlowKey::Dst.to_bit() | FlowKey::Proto.to_bit()
        );
    }

    #[test]
    fn flow_parse_params_keys_with_dashes() {
        let f = FlowFilter::parse_params(&["keys", "nfct-src,nfct-dst,proto-src"]).unwrap();
        assert_eq!(
            f.keys,
            FlowKey::NfctSrc.to_bit() | FlowKey::NfctDst.to_bit() | FlowKey::ProtoSrc.to_bit()
        );
    }

    #[test]
    fn flow_parse_params_mode_hash_and_baseclass() {
        let f = FlowFilter::parse_params(&["hash", "baseclass", "1:10"]).unwrap();
        assert_eq!(f.baseclass, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn flow_parse_params_mask_xor_hex_and_dec() {
        let f = FlowFilter::parse_params(&["mask", "0xff", "xor", "16", "divisor", "256"]).unwrap();
        assert_eq!(f.mask, Some(0xff));
        assert_eq!(f.xor, Some(16));
        assert_eq!(f.divisor, Some(256));
    }

    #[test]
    fn flow_parse_params_unknown_key_errors() {
        let err = FlowFilter::parse_params(&["keys", "src,nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown key"));
    }

    #[test]
    fn flow_parse_params_unknown_token_errors() {
        let err = FlowFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    // ==========================================================
    // U32Filter::parse_params — Plan 138 PR A (raw match triples
    // + structural tokens). Phase 2 (named-match shortcuts) and
    // Phase 3 (hash-table grammar) land in subsequent PRs.
    // ==========================================================

    #[test]
    fn u32_parse_params_empty_yields_default() {
        let f = U32Filter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.keys.is_empty());
        assert_eq!(f.flags, 0);
        assert!(f.chain.is_none());
    }

    #[test]
    fn u32_parse_params_match_u32_triple() {
        let f = U32Filter::parse_params(&["match", "u32", "0xCAFEBABE", "0xFFFFFFFF", "at", "0"])
            .unwrap();
        assert_eq!(f.keys.len(), 1);
        let k = f.keys[0];
        // The kernel stores val/mask big-endian; pack_key32 applies to_be().
        assert_eq!(u32::from_be(k.val), 0xCAFEBABE);
        assert_eq!(u32::from_be(k.mask), 0xFFFFFFFF);
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u32_decimal_offset() {
        let f = U32Filter::parse_params(&["match", "u32", "0x01020304", "0xFFFFFFFF", "at", "16"])
            .unwrap();
        assert_eq!(f.keys[0].off, 16);
    }

    #[test]
    fn u32_parse_params_match_u16_upper_half() {
        // offset=0 → upper 16 bits of the 32-bit slot.
        let f = U32Filter::parse_params(&["match", "u16", "0x1234", "0xFFFF", "at", "0"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x1234_0000);
        assert_eq!(u32::from_be(k.mask), 0xFFFF_0000);
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u16_lower_half() {
        // offset=2 → lower 16 bits of the 32-bit slot at offset 0.
        let f = U32Filter::parse_params(&["match", "u16", "0x5678", "0xFFFF", "at", "2"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x0000_5678);
        assert_eq!(u32::from_be(k.mask), 0x0000_FFFF);
        // pack_key16 normalises offset to the 32-bit-aligned base.
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u8_byte_quadrant() {
        // offset=9 → bits 16..23 of the 32-bit slot at offset 8.
        let f = U32Filter::parse_params(&["match", "u8", "0x06", "0xFF", "at", "9"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x0006_0000);
        assert_eq!(u32::from_be(k.mask), 0x00FF_0000);
        assert_eq!(k.off, 8);
    }

    #[test]
    fn u32_parse_params_multiple_matches_append_in_order() {
        let f = U32Filter::parse_params(&[
            "match", "u32", "0xAA", "0xFF", "at", "0", "match", "u32", "0xBB", "0xFF", "at", "4",
        ])
        .unwrap();
        assert_eq!(f.keys.len(), 2);
        assert_eq!(u32::from_be(f.keys[0].val), 0xAA);
        assert_eq!(u32::from_be(f.keys[1].val), 0xBB);
        assert_eq!(f.keys[1].off, 4);
    }

    #[test]
    fn u32_parse_params_classid_and_flowid_alias() {
        let by_classid = U32Filter::parse_params(&["classid", "1:10"]).unwrap();
        let by_flowid = U32Filter::parse_params(&["flowid", "1:10"]).unwrap();
        let want = TcHandle::new(1, 0x10).as_raw();
        assert_eq!(by_classid.classid, Some(want));
        assert_eq!(by_flowid.classid, Some(want));
    }

    #[test]
    fn u32_parse_params_chain_and_skip_flags() {
        let f = U32Filter::parse_params(&["chain", "5", "skip_hw", "skip_sw"]).unwrap();
        assert_eq!(f.chain, Some(5));
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn u32_parse_params_unknown_token_errors() {
        let err = U32Filter::parse_params(&["nonsense"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("u32: unknown token `nonsense`"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_invalid_hex_errors() {
        let err =
            U32Filter::parse_params(&["match", "u32", "notahex", "0xFF", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("expected unsigned integer"), "{err}");
        let err = U32Filter::parse_params(&["match", "u32", "1", "notahex", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("expected hex value"), "{err}");
    }

    /// An offset with a sign, in any base, as tc's `get_integer(.., 0)`
    /// reads it (#835): before the network header for a negative one.
    #[test]
    fn u32_offsets_take_a_sign() {
        let f = U32Filter::parse_params(&["match", "u16", "0x0800", "0xffff", "at", "-2"]).unwrap();
        assert_eq!((f.keys[0].off, f.keys[0].mask), (-4, 0xffffu32.to_be()));
        let f = U32Filter::parse_params(&["match", "u8", "2", "0xff", "at", "-0xe"]).unwrap();
        assert_eq!(f.keys[0].off, -16);
        for (s, want) in [("010", 8), ("+4", 4), ("-0", 0)] {
            assert_eq!(parse_offset("u32", s).unwrap(), want, "{s}");
        }
        for bad in ["--2", "-+2", "x", "-"] {
            assert!(parse_offset("u32", bad).is_err(), "{bad}");
        }
    }

    /// A value in any base and a mask in hex, as tc's `get_u32(.., 0)` and
    /// `get_u32(.., 16)` read them (#831): `80` is port 80, not 0x80.
    #[test]
    fn u32_values_read_as_tc_reads_them() {
        let f = U32Filter::parse_params(&["match", "u16", "80", "ffff", "at", "22"]).unwrap();
        assert_eq!(f.keys[0].val, 80u32.to_be());
        let f = U32Filter::parse_params(&["match", "mark", "16", "255"]).unwrap();
        assert_eq!(f.mark, Some((16, 255)));
        assert!(U32Filter::parse_params(&["match", "mark", "0x100", "0xff"]).is_err());
        // A /0 is mask 0.
        let f = U32Filter::parse_params(&["match", "ip", "dst", "0.0.0.0/0"]).unwrap();
        assert_eq!((f.keys[0].val, f.keys[0].mask), (0, 0));
        // Keys at one offset merge, as tc's pack_key() merges them.
        let f = U32Filter::parse_params(&["match", "ip", "sport", "80", "0xffff", "match", "ip", "dport", "443", "0xffff"]).unwrap();
        assert_eq!(f.keys.len(), 1);
        assert_eq!((f.keys[0].val, f.keys[0].mask), (((80u32 << 16) | 443).to_be(), u32::MAX));
        assert!(U32Filter::parse_params(&["match", "ip", "dport", "80", "match", "ip", "dport", "81"]).is_err());
        // ether dst spans -14..-9: two keys after merging.
        let f = U32Filter::parse_params(&["match", "ether", "dst", "02:00:00:00:00:01"]).unwrap();
        let offs: Vec<i32> = f.keys.iter().map(|k| k.off).collect();
        assert_eq!(offs, [-16, -12]);
        // ip6 src /40: a whole word and eight bits of the next.
        let f = U32Filter::parse_params(&["match", "ip6", "src", "fd00:1::/40"]).unwrap();
        assert_eq!((f.keys.len(), f.keys[1].off, f.keys[1].mask), (2, 12, 0xFF00_0000u32.to_be()));
        let f = U32Filter::parse_params(&["match", "ip", "nofrag"]).unwrap();
        assert_eq!((f.keys[0].off, f.keys[0].mask), (4, 0x3FFFu32.to_be()));
    }

    #[test]
    fn u32_parse_params_match_unknown_width_errors() {
        let err = U32Filter::parse_params(&["match", "u64", "0x1", "0x1", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("unknown match width"));
    }

    #[test]
    fn u32_parse_params_match_short_errors() {
        // Missing `at OFFSET`.
        let err = U32Filter::parse_params(&["match", "u32", "0xAA", "0xFF"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("requires") && msg.contains("at"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_missing_at_keyword_errors() {
        let err =
            U32Filter::parse_params(&["match", "u32", "0xAA", "0xFF", "INSTEAD", "0"]).unwrap_err();
        assert!(err.to_string().contains("expected `at`"));
    }

    #[test]
    fn u32_parse_params_match_u8_value_too_large_errors() {
        let err =
            U32Filter::parse_params(&["match", "u8", "0xDEAD", "0xFF", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("must fit in 8 bits"));
    }

    #[test]
    fn u32_parse_params_classid_missing_value_errors() {
        let err = U32Filter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    // ==========================================================
    // Phase 2 — named-match shortcuts (Plan 138 PR B). Each
    // shortcut routes through the existing typed setter; the
    // tests verify wire equivalence by comparing parser output to
    // the direct-setter output rather than hard-coding offsets.
    // Golden-hex fixtures captured from `tc(8)` are deferred until
    // the privileged GHA runner ships (Plan 142 Phase 0 GHA file
    // is no-op until then). Until then, setter equivalence is
    // the strongest check we have.
    // ==========================================================

    #[test]
    fn u32_parse_params_match_ip_src_with_prefix() {
        let parsed = U32Filter::parse_params(&["match", "ip", "src", "10.0.0.0/24"]).unwrap();
        let direct = U32Filter::new().match_src_ipv4("10.0.0.0".parse().unwrap(), 24);
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        assert_eq!(parsed.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_src_no_prefix_defaults_to_32() {
        let parsed = U32Filter::parse_params(&["match", "ip", "src", "10.1.2.3"]).unwrap();
        let direct = U32Filter::new().match_src_ipv4("10.1.2.3".parse().unwrap(), 32);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        // /32 → mask is 0xFFFF_FFFF (host order before to_be).
        assert_eq!(u32::from_be(parsed.keys[0].mask), 0xFFFF_FFFF);
    }

    #[test]
    fn u32_parse_params_match_ip_dst_with_prefix() {
        let parsed = U32Filter::parse_params(&["match", "ip", "dst", "192.168.0.0/16"]).unwrap();
        let direct = U32Filter::new().match_dst_ipv4("192.168.0.0".parse().unwrap(), 16);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        assert_eq!(parsed.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_named() {
        let by_name = U32Filter::parse_params(&["match", "ip", "protocol", "tcp"]).unwrap();
        let direct = U32Filter::new().match_ip_proto(6);
        assert_eq!(by_name.keys[0].val, direct.keys[0].val);
        assert_eq!(by_name.keys[0].mask, direct.keys[0].mask);
        assert_eq!(by_name.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_numeric() {
        let parsed = U32Filter::parse_params(&["match", "ip", "protocol", "6"]).unwrap();
        let direct = U32Filter::new().match_ip_proto(6);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_named_set() {
        // Spot-check each named protocol resolves to the kernel value.
        let cases = [
            ("tcp", 6),
            ("udp", 17),
            ("icmp", 1),
            ("icmpv6", 58),
            ("sctp", 132),
            ("ah", 51),
            ("esp", 50),
            ("gre", 47),
        ];
        for (name, num) in cases {
            let parsed = U32Filter::parse_params(&["match", "ip", "protocol", name]).unwrap();
            let direct = U32Filter::new().match_ip_proto(num);
            assert_eq!(
                parsed.keys[0].val, direct.keys[0].val,
                "{name} should map to proto {num}"
            );
        }
    }

    #[test]
    fn u32_parse_params_match_ip_dport_and_sport() {
        let dport = U32Filter::parse_params(&["match", "ip", "dport", "443"]).unwrap();
        let sport = U32Filter::parse_params(&["match", "ip", "sport", "12345"]).unwrap();
        let dport_direct = U32Filter::new().match_dst_port(443);
        let sport_direct = U32Filter::new().match_src_port(12345);
        assert_eq!(dport.keys[0].val, dport_direct.keys[0].val);
        assert_eq!(dport.keys[0].mask, dport_direct.keys[0].mask);
        assert_eq!(dport.keys[0].offmask, dport_direct.keys[0].offmask); // 0: fixed offset
        assert_eq!(sport.keys[0].val, sport_direct.keys[0].val);
        assert_eq!(sport.keys[0].mask, sport_direct.keys[0].mask);
    }

    /// #492: the keys' bytes, as iproute2 packs them (`pack_key16`:
    /// `htonl` of the value and mask, the half chosen by `off & 3`).
    /// Port matches were next-header keys in host order: on little-endian
    /// `match_dst_port(443)` compared the first 16 bits of the IP header
    /// with 0xBB01. The old test compared the parser with the setter,
    /// which were wrong the same way.
    #[test]
    fn u32_port_keys_have_tcs_wire_bytes() {
        use zerocopy::IntoBytes;
        /// tokens, off, offmask, mask bytes, value bytes
        type Case<'a> = (&'a [&'a str], i32, i32, [u8; 4], [u8; 4]);
        let cases: [Case; 5] = [
            (
                &["match", "ip", "dport", "443", "0xffff"],
                20,
                0,
                [0, 0, 0xff, 0xff],
                [0, 0, 0x01, 0xbb],
            ),
            (
                &["match", "ip", "sport", "12345"],
                20,
                0,
                [0xff, 0xff, 0, 0],
                [0x30, 0x39, 0, 0],
            ),
            (
                &["match", "udp", "dst", "53", "ffff"],
                0,
                -1,
                [0, 0, 0xff, 0xff],
                [0, 0, 0, 53],
            ),
            (
                &["match", "tcp", "src", "80", "0xff00"],
                0,
                -1,
                [0xff, 0, 0, 0],
                [0, 0, 0, 0],
            ),
            (
                &["match", "tcp", "dport", "8080"],
                20,
                0,
                [0, 0, 0xff, 0xff],
                [0, 0, 0x1f, 0x90],
            ),
        ];
        for (tokens, off, offmask, mask, val) in cases {
            let f = U32Filter::parse_params(tokens).unwrap();
            let key = f.keys[0];
            assert_eq!((key.off, key.offmask), (off, offmask), "{tokens:?}");
            assert_eq!(key.mask.as_bytes(), mask, "{tokens:?} mask");
            assert_eq!(key.val.as_bytes(), val, "{tokens:?} value");
        }
        let direct = U32Filter::new()
            .match_dst_port(443)
            .match_nexthdr_dst_port(443);
        assert_eq!(direct.keys[0].val.as_bytes(), [0, 0, 0x01, 0xbb]);
        assert_eq!((direct.keys[1].off, direct.keys[1].offmask), (0, -1));
        assert_eq!(direct.keys[1].val.as_bytes(), [0, 0, 0x01, 0xbb]);
    }

    /// `offset at 0 mask 0f00 shift 6` lands in the selector header:
    /// `TC_U32_VAROFFSET`, `offoff` 0, `offmask` big-endian, `offshift` 6.
    #[test]
    fn u32_offset_lands_in_the_selector() {
        let f = U32Filter::parse_params(&[
            "match", "ip", "protocol", "17", "offset", "at", "0", "mask", "0f00", "shift", "6",
            "link", "2:",
        ])
        .unwrap();
        let mut b = MessageBuilder::new(0, 0);
        f.write_options(&mut b).unwrap();
        let bytes = b.as_bytes()[16..].to_vec();
        let sel = crate::netlink::attr::AttrIter::new(&bytes)
            .find(|(ty, _)| *ty == u32_mod::TCA_U32_SEL)
            .map(|(_, p)| p.to_vec())
            .expect("a selector");
        // flags, offshift, nkeys, pad, offmask (be16), off, offoff
        assert_eq!(sel[0], u32_mod::TC_U32_TERMINAL | u32_mod::TC_U32_VAROFFSET);
        assert_eq!(sel[1], 6);
        assert_eq!(&sel[4..6], &[0x0f, 0x00]);
        assert_eq!(&sel[8..10], &0i16.to_ne_bytes());
        assert_eq!(f.link, Some(0x0020_0000));
        assert!(U32Filter::parse_params(&["offset"]).is_err());
    }

    #[test]
    fn u32_parse_params_match_tcp_udp_port_aliases() {
        let by_ip = U32Filter::parse_params(&["match", "ip", "dport", "80"]).unwrap();
        let by_tcp = U32Filter::parse_params(&["match", "tcp", "dport", "80"]).unwrap();
        let by_udp = U32Filter::parse_params(&["match", "udp", "dport", "80"]).unwrap();
        // The tcp/udp prefix is sugar; the wire is identical.
        assert_eq!(by_ip.keys[0].val, by_tcp.keys[0].val);
        assert_eq!(by_ip.keys[0].val, by_udp.keys[0].val);
        assert_eq!(by_ip.keys[0].mask, by_tcp.keys[0].mask);
    }

    #[test]
    fn u32_parse_params_named_match_combines_with_classid() {
        let f = U32Filter::parse_params(&[
            "match",
            "ip",
            "src",
            "10.0.0.0/24",
            "match",
            "tcp",
            "dport",
            "80",
            "classid",
            "1:10",
        ])
        .unwrap();
        assert_eq!(f.keys.len(), 2);
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn u32_parse_params_match_ip_invalid_prefix_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "src", "10.0.0.0/40"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("u32:") && msg.contains("prefix"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_ip_invalid_addr_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "src", "999.999.999.999"]).unwrap_err();
        assert!(err.to_string().contains("invalid IPv4 address"));
    }

    #[test]
    fn u32_parse_params_match_ip_unknown_field_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "fragment", "yes"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported `match ip fragment`"),
            "got: {msg}"
        );
    }

    #[test]
    fn u32_parse_params_match_ip_unknown_proto_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "protocol", "wat"]).unwrap_err();
        assert!(err.to_string().contains("unknown IP protocol"));
    }

    #[test]
    fn u32_parse_params_match_ip_dport_invalid_port_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "dport", "70000"]).unwrap_err();
        assert!(err.to_string().contains("wider than 16 bits"), "{err}");
    }

    #[test]
    fn u32_parse_params_match_ip_missing_value_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "src"]).unwrap_err();
        assert!(err.to_string().contains("requires VALUE"));
    }

    // ==========================================================
    // Phase 3 — hash-table grammar (Plan 138 PR C). Tokens:
    //   divisor <n>, ht <handle>, link <handle>,
    //   hashkey mask <hex> at <offset>.
    // `order <n>` is explicitly rejected as not yet typed-modelled
    // because it modifies the filter's own handle, which lives
    // outside parse_params.
    // ==========================================================

    #[test]
    fn u32_parse_params_divisor_only() {
        let f = U32Filter::parse_params(&["divisor", "256"]).unwrap();
        assert_eq!(f.divisor, Some(256));
        assert!(f.keys.is_empty(), "divisor-only filter has no keys");
        assert!(f.link.is_none());
        assert!(f.ht.is_none());
        assert!(f.hashkey.is_none());
    }

    /// A u32 handle is `htid << 20 | bucket << 12 | node` (iproute2's
    /// `get_u32_handle`), not a qdisc handle: `100:` is 0x10000000. It was
    /// parsed as a `TcHandle`, 0x01000000 (#492).
    #[test]
    fn u32_parse_params_ht_handle_is_a_u32_handle() {
        let f = U32Filter::parse_params(&["ht", "100:"]).unwrap();
        assert_eq!(f.ht, Some(0x1000_0000));
        assert_eq!(U32Filter::handle(0x100, 0, 0), 0x1000_0000);
        let f = U32Filter::parse_params(&["ht", "2:3:4"]).unwrap();
        assert_eq!(f.ht, Some(0x0020_3004));
        assert!(
            U32Filter::parse_params(&["ht", "1000:"]).is_err(),
            "htid is 12 bits"
        );
        let f = U32Filter::parse_params(&["link", "0x00200000"]).unwrap();
        assert_eq!(f.link, Some(0x0020_0000));
    }

    #[test]
    fn u32_parse_params_ht_link_combo() {
        // Typical "hashed chain" usage: filter belongs to ht 100:,
        // matches a key, links to ht 200: on match.
        let f = U32Filter::parse_params(&[
            "ht", "100:", "match", "ip", "dst", "10.0.0.1", "link", "200:", "classid", "1:1",
        ])
        .unwrap();
        assert_eq!(f.ht, Some(U32Filter::handle(0x100, 0, 0)));
        assert_eq!(f.link, Some(U32Filter::handle(0x200, 0, 0)));
        assert_eq!(f.classid, Some(TcHandle::new(1, 1).as_raw()));
        assert_eq!(f.keys.len(), 1, "the dst match should append a key");
    }

    #[test]
    fn u32_parse_params_link_via_handle_notation() {
        let f = U32Filter::parse_params(&["link", "1:a"]).unwrap();
        assert_eq!(f.link, Some(U32Filter::handle(1, 0xa, 0)));
    }

    #[test]
    fn u32_parse_params_hashkey_packs_into_sel() {
        let f = U32Filter::parse_params(&[
            "hashkey",
            "mask",
            "0xff000000",
            "at",
            "12",
            "match",
            "u32",
            "0x0a000001",
            "0xffffffff",
            "at",
            "12",
        ])
        .unwrap();
        assert_eq!(f.hashkey, Some((0xff000000, 12)));
        assert_eq!(f.keys.len(), 1);
    }

    #[test]
    fn u32_parse_params_hashkey_negative_offset_errors() {
        // i16 max is 32767. 100000 is out of range.
        let err =
            U32Filter::parse_params(&["hashkey", "mask", "0xff", "at", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range for i16"));
    }

    #[test]
    fn u32_parse_params_hashkey_missing_mask_keyword_errors() {
        let err = U32Filter::parse_params(&["hashkey", "0xff", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("expected `mask` after `hashkey`"));
    }

    #[test]
    fn u32_parse_params_order_rejected_with_clear_message() {
        let err = U32Filter::parse_params(&["order", "5"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("`order` is not yet typed-modelled"),
            "got: {msg}"
        );
    }

    #[test]
    fn u32_parse_params_divisor_invalid_int_errors() {
        let err = U32Filter::parse_params(&["divisor", "wat"]).unwrap_err();
        assert!(err.to_string().contains("expected unsigned integer"));
    }

    #[test]
    fn u32_parse_params_ht_invalid_handle_errors() {
        let err = U32Filter::parse_params(&["ht", "not-a-handle"]).unwrap_err();
        assert!(err.to_string().contains("invalid ht handle"));
    }

    // ==========================================================
    // BasicFilter — Plan 133 PR C (cls_basic ematch tree).
    // Tests: wire format spot-checks (one-match cmp + two-match
    // cmp/u32 combo), ip_proto_eq builder/parser equivalence,
    // parse_params token shapes + strict errors.
    // ==========================================================

    use crate::netlink::builder::MessageBuilder;
    use crate::netlink::types::tc::filter::ematch as ematch_consts;

    /// Build a `BasicFilter` and run write_options into a fresh
    /// MessageBuilder; returns the produced bytes for inspection.
    fn basic_to_bytes(f: &BasicFilter) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        f.write_options(&mut b).expect("write_options");
        b.as_bytes().to_vec()
    }

    #[test]
    fn basic_ip_proto_eq_emits_single_cmp_match() {
        let f = BasicFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .ip_proto_eq(6); // TCP

        // Wire output should contain a TCA_BASIC_EMATCHES nest with
        // one tcf_em_cmp (16 bytes) for the proto check at offset 9.
        assert_eq!(f.matches.len(), 1, "one match accumulated");
        match &f.matches[0].kind {
            EmatchKind::Cmp(c) => {
                assert_eq!(c.layer, CmpLayer::Network);
                assert_eq!(c.align, CmpAlign::U8);
                assert_eq!(c.offset, 9);
                assert_eq!(c.value, 6);
                assert_eq!(c.mask, 0xff);
                assert_eq!(c.op, CmpOp::Eq);
                assert!(!c.trans);
            }
            _ => panic!("expected Cmp"),
        }
    }

    #[test]
    fn basic_two_match_tree_encodes_relations() {
        let f = BasicFilter::new()
            .ip_proto_eq(6) // first match
            .ematch(Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Transport,
                align: CmpAlign::U16,
                offset: 2,
                mask: 0xffff,
                value: 80,
                op: CmpOp::Eq,
                trans: false,
            }));

        assert_eq!(f.matches.len(), 2);

        let bytes = basic_to_bytes(&f);
        // The encoder must emit non-empty output that contains the
        // tree-header attribute (TCA_EMATCH_TREE_HDR = 1) followed by
        // a TCA_EMATCH_TREE_LIST (= 2) carrying both matches.
        assert!(!bytes.is_empty(), "write_options produced no bytes");
        // The 2-match tree header should be present somewhere in the
        // payload as the bytes [02, 00] (nmatches=2, le).
        let has_nmatches_2 = bytes.windows(4).any(|w| w == [0x02, 0x00, 0x00, 0x00]);
        assert!(has_nmatches_2, "tree header should advertise nmatches=2");
    }

    #[test]
    fn basic_negate_sets_invert_flag() {
        let f = BasicFilter::new().ematch(
            Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Network,
                align: CmpAlign::U8,
                offset: 9,
                mask: 0xff,
                value: 6,
                op: CmpOp::Eq,
                trans: false,
            })
            .negate(),
        );
        assert!(f.matches[0].negate);
        // Spot-check that TCF_EM_INVERT is the documented bit.
        assert_eq!(ematch_consts::TCF_EM_INVERT, 1 << 2);
    }

    #[test]
    fn basic_or_sets_relation() {
        let f = BasicFilter::new()
            .ematch(
                Ematch::cmp(EmatchCmp {
                    layer: CmpLayer::Network,
                    align: CmpAlign::U8,
                    offset: 9,
                    mask: 0xff,
                    value: 6,
                    op: CmpOp::Eq,
                    trans: false,
                })
                .or(),
            )
            .ematch(Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Network,
                align: CmpAlign::U8,
                offset: 9,
                mask: 0xff,
                value: 17,
                op: CmpOp::Eq,
                trans: false,
            }));
        assert_eq!(f.matches[0].op, EmatchOp::Or);
        // Last match's op is encoded as REL_END regardless.
        assert_eq!(f.matches[1].op, EmatchOp::And);
    }

    #[test]
    fn basic_cmp_byte_layout_matches_kernel_struct() {
        // Hand-pack the tcf_em_cmp the kernel expects for
        // `match u8 6 0xff at 9 layer ip eq`, then compare.
        let want = ematch_consts::TcfEmCmp {
            val: 6,
            mask: 0xff,
            off: 9,
            // align=U8 (1) low nibble, flags=0 high nibble → 0x01
            align_flags: ematch_consts::TCF_EM_ALIGN_U8 & 0x0F,
            // layer=Network (1) low nibble, opnd=Eq (0) high nibble → 0x01
            layer_opnd: ematch_consts::TCF_LAYER_NETWORK & 0x0F,
            _pad: 0,
            _pad2: 0,
        };
        let got = encode_cmp(&EmatchCmp {
            layer: CmpLayer::Network,
            align: CmpAlign::U8,
            offset: 9,
            mask: 0xff,
            value: 6,
            op: CmpOp::Eq,
            trans: false,
        });
        assert_eq!(got.as_bytes(), want.as_bytes());
    }

    #[test]
    fn basic_parse_params_empty_yields_default() {
        let f = BasicFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.matches.is_empty());
        assert!(f.chain.is_none());
    }

    #[test]
    fn basic_parse_params_classid_and_chain() {
        let f = BasicFilter::parse_params(&["classid", "1:10", "chain", "5"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.chain, Some(5));
    }

    #[test]
    fn basic_parse_params_flowid_alias() {
        let f = BasicFilter::parse_params(&["flowid", "2:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(2, 0x20).as_raw()));
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_named_matches_builder() {
        let parsed = BasicFilter::parse_params(&["ip_proto_eq", "tcp"]).unwrap();
        let direct = BasicFilter::new().ip_proto_eq(6);
        assert_eq!(parsed.matches.len(), 1);
        match (&parsed.matches[0].kind, &direct.matches[0].kind) {
            (EmatchKind::Cmp(p), EmatchKind::Cmp(d)) => {
                assert_eq!(p.value, d.value);
                assert_eq!(p.mask, d.mask);
                assert_eq!(p.offset, d.offset);
                assert_eq!(p.align, d.align);
                assert_eq!(p.layer, d.layer);
            }
            _ => panic!("expected Cmp on both"),
        }
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_numeric() {
        let f = BasicFilter::parse_params(&["ip_proto_eq", "6"]).unwrap();
        match &f.matches[0].kind {
            EmatchKind::Cmp(c) => assert_eq!(c.value, 6),
            _ => panic!("expected Cmp"),
        }
    }

    #[test]
    fn basic_parse_params_unknown_token_errors() {
        let err = BasicFilter::parse_params(&["nonsense"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("basic: unknown token `nonsense`"),
            "got: {msg}"
        );
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_unknown_proto_rebrands_error_prefix() {
        let err = BasicFilter::parse_params(&["ip_proto_eq", "wat"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("basic:"),
            "error must rebrand u32→basic: {msg}"
        );
        assert!(!msg.contains("u32:"), "error must NOT mention u32: {msg}");
        assert!(msg.contains("unknown IP protocol"), "got: {msg}");
    }

// ========================================================================
// #288 — an L4 flower key without an ethertype is a match-all
// ========================================================================

fn flower_option_ids(f: &FlowerFilter) -> crate::Result<Vec<u16>> {
    let mut builder = MessageBuilder::new(0, 0);
    let start = builder.len();
    f.write_options(&mut builder)?;
    let blob = builder.as_bytes()[start..builder.len()].to_vec();
    let mut ids = Vec::new();
    let mut input = &blob[..];
    while input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
        assert!(len >= 4 && input.len() >= len);
        ids.push(ty);
        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }
    Ok(ids)
}

#[test]
fn flower_l4_keys_without_an_ethertype_are_refused() {
    // cls_flower reads ip_proto and the port keys only when
    // TCA_FLOWER_KEY_ETH_TYPE names IPv4 or IPv6. Emitting them alone
    // gets a clean ACK and a filter that matches every packet — so the
    // writer refuses rather than shipping a match-all.
    for f in [
        FlowerFilter::new().ip_proto_tcp().dst_port(443).build(),
        FlowerFilter::new().ip_proto_udp().src_port(53).build(),
        FlowerFilter::new().ip_proto(6).build(),
    ] {
        let err = flower_option_ids(&f).expect_err("must not silently install match-all");
        let msg = err.to_string();
        assert!(msg.contains("needs an ethertype"), "unexpected error: {msg}");
    }
}

#[test]
fn flower_l4_keys_with_an_ethertype_are_emitted() {
    let ids = flower_option_ids(&FlowerFilter::new().ipv4().ip_proto_tcp().dst_port(443).build())
        .expect("accepted");
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_ETH_TYPE));
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_IP_PROTO));
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_TCP_DST));
}

#[test]
fn flower_address_setters_still_imply_the_ethertype() {
    // The address setters carry their own ethertype, so an address rule
    // combined with a port stays valid without an explicit `.ipv4()`.
    let ids = flower_option_ids(
        &FlowerFilter::new()
            .dst_ipv4("10.0.0.1".parse().unwrap(), 32)
            .ip_proto_tcp()
            .dst_port(443)
            .build(),
    )
    .expect("accepted");
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_ETH_TYPE));
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_TCP_DST));

    // A pure address rule needs no L4 gate at all.
    assert!(
        flower_option_ids(
            &FlowerFilter::new()
                .dst_ipv6("fd00::1".parse().unwrap(), 128)
                .build()
        )
        .is_ok()
    );
}

#[test]
fn flower_with_no_l4_keys_needs_no_ethertype() {
    // A classid-only flower filter is a legitimate match-all; the guard
    // must not turn that into an error.
    assert!(flower_option_ids(&FlowerFilter::new().classid(TcHandle::new(1, 2)).build()).is_ok());
}

/// A port range is written as the protocol-independent MIN/MAX keys,
/// in network order, and replaces an exact port (#416).
#[test]
fn flower_port_ranges_are_written_as_min_max_keys() {
    let f = FlowerFilter::new()
        .ipv4()
        .ip_proto_udp()
        .dst_port(53)
        .dst_port_range(8000, 8100)
        .build();
    let mut builder = MessageBuilder::new(0, 0);
    let start = builder.len();
    f.write_options(&mut builder).expect("accepted");
    let blob = builder.as_bytes()[start..].to_vec();
    let attrs: Vec<(u16, Vec<u8>)> = crate::netlink::attr::AttrIter::new(&blob)
        .map(|(t, p)| (t, p.to_vec()))
        .collect();
    assert!(attrs.contains(&(flower::TCA_FLOWER_KEY_PORT_DST_MIN, 8000u16.to_be_bytes().to_vec())));
    assert!(attrs.contains(&(flower::TCA_FLOWER_KEY_PORT_DST_MAX, 8100u16.to_be_bytes().to_vec())));
    assert!(
        !attrs.iter().any(|(t, _)| *t == flower::TCA_FLOWER_KEY_UDP_DST),
        "the range replaced the exact port"
    );

    let ids = flower_option_ids(&FlowerFilter::new().ipv4().ip_proto_tcp().src_port_range(1, 2))
        .expect("accepted");
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_PORT_SRC_MIN));
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_PORT_SRC_MAX));
}

/// What `fl_set_key_port_range` would refuse, and what it would silently
/// turn into a match-all, is refused here.
#[test]
fn flower_unusable_port_ranges_are_refused() {
    let cases = [
        (FlowerFilter::new().ipv4().ip_proto_udp().dst_port_range(80, 80), "min below max"),
        (FlowerFilter::new().ipv4().ip_proto_udp().dst_port_range(90, 80), "min below max"),
        (FlowerFilter::new().ipv4().dst_port_range(80, 90), "needs ip_proto"),
        (FlowerFilter::new().ipv4().ip_proto_icmp().src_port_range(80, 90), "needs ip_proto"),
        (FlowerFilter::new().ip_proto_udp().dst_port_range(80, 90), "needs an ethertype"),
    ];
    for (f, why) in cases {
        let crate::ErrorDetail::InvalidMessage(err) = flower_option_ids(&f).expect_err(why).into_detail() else {
            panic!("{why}: not an InvalidMessage");
        };
        assert!(err.starts_with("flower: ") && err.contains(why), "{why}: {err}");
    }
    assert!(
        flower_option_ids(&FlowerFilter::new().ipv6().ip_proto(132).dst_port_range(80, 90)).is_ok(),
        "SCTP takes a range"
    );
}

// ========================================================================
// #424 — an exact port cls_flower does not read is a match-all
// ========================================================================

/// The `(type, payload)` pairs `write_options` emits.
fn flower_option_attrs(f: &FlowerFilter) -> crate::Result<Vec<(u16, Vec<u8>)>> {
    let mut builder = MessageBuilder::new(0, 0);
    let start = builder.len();
    f.write_options(&mut builder)?;
    let blob = builder.as_bytes()[start..].to_vec();
    Ok(crate::netlink::attr::AttrIter::new(&blob)
        .map(|(t, p)| (t, p.to_vec()))
        .collect())
}

/// `fl_set_key` reads an exact port from the key of the filter's own
/// `ip_proto`: `TCA_FLOWER_KEY_SCTP_{SRC,DST}` for SCTP. A TCP or UDP key
/// would be ignored there, and so would no key at all.
#[test]
fn flower_sctp_ports_are_written_as_sctp_keys() {
    let port_keys = [
        flower::TCA_FLOWER_KEY_TCP_SRC,
        flower::TCA_FLOWER_KEY_TCP_DST,
        flower::TCA_FLOWER_KEY_UDP_SRC,
        flower::TCA_FLOWER_KEY_UDP_DST,
        flower::TCA_FLOWER_KEY_SCTP_SRC,
        flower::TCA_FLOWER_KEY_SCTP_DST,
    ];
    for f in [
        FlowerFilter::new().ipv4().ip_proto(flower::IPPROTO_SCTP).src_port(5000).dst_port(80),
        FlowerFilter::new().ipv6().ip_proto_sctp().src_port(5000).dst_port(80),
    ] {
        let attrs = flower_option_attrs(&f).expect("accepted");
        let ports: Vec<_> = attrs.iter().filter(|(t, _)| port_keys.contains(t)).collect();
        assert_eq!(
            ports,
            [
                &(flower::TCA_FLOWER_KEY_SCTP_SRC, 5000u16.to_be_bytes().to_vec()),
                &(flower::TCA_FLOWER_KEY_SCTP_DST, 80u16.to_be_bytes().to_vec()),
            ],
            "{attrs:?}"
        );
    }

    // TCP and UDP keep their own keys.
    let udp = flower_option_attrs(&FlowerFilter::new().ipv4().ip_proto_udp().src_port(53))
        .expect("accepted");
    assert!(udp.contains(&(flower::TCA_FLOWER_KEY_UDP_SRC, 53u16.to_be_bytes().to_vec())));
}

/// A port `fl_set_key` would not read — on a protocol without ports, on no
/// `ip_proto` at all, or under an ethertype that is not IP — is refused,
/// not shipped as the match-all the kernel would make of it.
#[test]
fn flower_exact_ports_cls_flower_would_drop_are_refused() {
    let cases = [
        (FlowerFilter::new().ipv4().ip_proto_icmp().dst_port(80), "dst_port 80"),
        (FlowerFilter::new().ipv6().ip_proto(47).src_port(80), "src_port 80"),
        (FlowerFilter::new().ipv4().dst_port(80), "dst_port 80"),
        (
            FlowerFilter::new()
                .dst_ipv6("fd00::1".parse().unwrap(), 128)
                .src_port(80),
            "src_port 80",
        ),
    ];
    for (f, what) in cases {
        let crate::ErrorDetail::InvalidMessage(err) = flower_option_ids(&f).expect_err(what).into_detail() else {
            panic!("{what}: not an InvalidMessage");
        };
        assert!(
            err.starts_with("flower: ")
                && err.contains(what)
                && err.contains("needs ip_proto tcp, udp or sctp"),
            "{what}: {err}"
        );
    }

    // `fl_set_key` reads `ip_proto` only under an IPv4 or IPv6 ethertype;
    // under ARP it is dropped, and the port with it.
    let f = FlowerFilter::parse_params(&["eth_type", "arp", "ip_proto", "tcp", "dst_port", "80"])
        .expect("parses");
    let crate::ErrorDetail::InvalidMessage(err) = flower_option_ids(&f).expect_err("ARP").into_detail() else {
        panic!("ARP: not an InvalidMessage");
    };
    assert!(
        err.starts_with("flower: ") && err.contains("needs an ethertype"),
        "{err}"
    );
}

/// tc(8)'s `ip_proto sctp dst_port 80` parses, in any order, and installs
/// the SCTP key.
#[test]
fn flower_parse_params_sctp_ports() {
    for params in [
        &["eth_type", "ipv4", "ip_proto", "sctp", "dst_port", "80"][..],
        &["dst_port", "80", "ip_proto", "sctp", "eth_type", "ipv6"][..],
        &["eth_type", "ipv4", "ip_proto", "84", "dst_port", "80"][..],
    ] {
        let f = FlowerFilter::parse_params(params).expect("tc(8) takes this");
        assert_eq!(f.ip_proto, Some(flower::IPPROTO_SCTP), "{params:?}");
        let attrs = flower_option_attrs(&f).expect("accepted");
        assert!(
            attrs.contains(&(flower::TCA_FLOWER_KEY_SCTP_DST, 80u16.to_be_bytes().to_vec())),
            "{params:?}: {attrs:?}"
        );
    }
}

// ========================================================================
// #431 — tcp_flags and VLAN keys cls_flower does not read are a match-all
// ========================================================================

/// `fl_set_key` reads TCP flags only under `ip_proto tcp`, and the VLAN keys
/// only under an 802.1Q/802.1AD ethertype. Anywhere else they were written,
/// ACKed and ignored.
#[test]
fn flower_tcp_flags_and_vlan_keys_cls_flower_would_drop_are_refused() {
    let cases = [
        (FlowerFilter::new().ipv4().ip_proto_udp().tcp_flags(0x02, 0x02), "tcp_flags needs ip_proto tcp"),
        (FlowerFilter::new().ipv4().tcp_flags(0x02, 0x12), "tcp_flags needs ip_proto tcp"),
        (FlowerFilter::new().ipv4().vlan_id(10), "vlan_id needs an 802.1Q or 802.1AD ethertype"),
        (FlowerFilter::new().vlan_prio(3).arp(), "vlan_prio needs an 802.1Q"),
        (
            FlowerFilter::new().vlan_id(10).vlan_prio(3).ipv6(),
            "vlan_id and vlan_prio needs",
        ),
    ];
    for (f, why) in cases {
        let crate::ErrorDetail::InvalidMessage(err) = flower_option_ids(&f).expect_err(why).into_detail() else {
            panic!("{why}: not an InvalidMessage");
        };
        assert!(err.starts_with("flower: ") && err.contains(why), "{why}: {err}");
    }
    let ids = flower_option_ids(&FlowerFilter::new().ipv4().ip_proto_tcp().tcp_flags(0x02, 0x12))
        .expect("TCP takes flags");
    assert!(ids.contains(&flower::TCA_FLOWER_KEY_TCP_FLAGS));
}

/// The typed builder had no way to set a VLAN ethertype, so `.vlan_id(10)`
/// could only ever install a match-all. It now implies 802.1Q, and
/// `.qinq()` picks 802.1AD.
#[test]
fn flower_vlan_keys_imply_a_vlan_ethertype() {
    let ethertype = |f: FlowerFilter| {
        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        f.write_options(&mut builder).expect("accepted");
        let blob = builder.as_bytes()[start..].to_vec();
        crate::netlink::attr::AttrIter::new(&blob)
            .find(|(t, _)| *t == flower::TCA_FLOWER_KEY_ETH_TYPE)
            .map(|(_, p)| u16::from_be_bytes(p.try_into().unwrap()))
    };
    assert_eq!(ethertype(FlowerFilter::new().vlan_id(10)), Some(0x8100));
    assert_eq!(ethertype(FlowerFilter::new().vlan_prio(5)), Some(0x8100));
    assert_eq!(ethertype(FlowerFilter::new().qinq().vlan_id(10)), Some(0x88A8));
    assert_eq!(ethertype(FlowerFilter::new().vlan().vlan_id(10)), Some(0x8100));
    // tc(8)'s spelling still works.
    let parsed = FlowerFilter::parse_params(&["vlan_id", "10"]).unwrap();
    assert_eq!(ethertype(parsed), Some(0x8100));
}

// ========================================================================
// #432, #447 — numbers read the way tc(8) reads them
// ========================================================================

/// tc(8) reads a numeric `ip_proto` as hex (`flower_parse_ip_proto` calls
/// `get_u8(.., 16)`), so `ip_proto 47` is protocol 0x47 there, not GRE. nlink
/// read it as decimal, and the same command installed a different filter
/// (#432).
#[test]
fn flower_parse_params_reads_a_numeric_ip_proto_as_hex_like_tc() {
    // What tc 6.15 installs for each spelling.
    for (arg, want) in [("2f", 0x2f), ("0x2f", 0x2f), ("47", 0x47), ("010", 0x10), ("84", 132), ("ff", 0xff)] {
        let f = FlowerFilter::parse_params(&["ip_proto", arg]).unwrap();
        assert_eq!(f.ip_proto, Some(want), "ip_proto {arg}");
    }
    // …and what it refuses: 132 is 0x132, out of range.
    for arg in ["132", "100", "0x", "zz", "-1"] {
        let err = FlowerFilter::parse_params(&["ip_proto", arg]).unwrap_err().to_string();
        assert!(err.contains("flower: invalid ip_proto"), "ip_proto {arg}: {err}");
    }
}

/// tc(8) reads an `ip_tos` / `ip_ttl` value as decimal and falls back to hex;
/// it reads the mask as hex (`flower_parse_ip_tos_ttl`). nlink tried hex
/// first. Every all-digit value is valid hex, so `ip_ttl 64` installed TTL
/// 100 (#447).
#[test]
fn flower_parse_params_reads_ip_tos_and_ttl_like_tc() {
    // What tc 6.15 installs for each spelling (`tc -j filter show`).
    for (arg, want) in [
        ("64", (64, 0xff)),
        ("1a", (26, 0xff)),
        ("16/10", (16, 0x10)),
        ("0x10/0xfc", (16, 0xfc)),
        ("010", (10, 0xff)),
        ("255/ff", (255, 0xff)),
    ] {
        let f = FlowerFilter::parse_params(&["ip_ttl", arg]).unwrap();
        assert_eq!(f.ip_ttl, Some(want), "ip_ttl {arg}");
        let f = FlowerFilter::parse_params(&["ip_tos", arg]).unwrap();
        assert_eq!(f.ip_tos, Some(want), "ip_tos {arg}");
    }
    for arg in ["256", "1/100", "zz", "1/"] {
        let err = FlowerFilter::parse_params(&["ip_ttl", arg]).unwrap_err().to_string();
        assert!(err.contains("flower: invalid ip_ttl"), "ip_ttl {arg}: {err}");
    }
}

// ========================================================================
// #433 — the flower ethertype comes from the filter's protocol
// ========================================================================

/// The TCA_FLOWER_KEY_ETH_TYPE a filter writes, or the error that refuses it.
fn flower_eth_type_key(f: &FlowerFilter) -> crate::Result<Option<u16>> {
    Ok(flower_option_attrs(f)?
        .into_iter()
        .find(|(t, _)| *t == flower::TCA_FLOWER_KEY_ETH_TYPE)
        .map(|(_, p)| u16::from_be_bytes(p.try_into().unwrap())))
}

/// tc(8) writes TCA_FLOWER_KEY_ETH_TYPE from the filter's `protocol` unless
/// that is `all`, so `protocol ip flower ip_proto tcp dst_port 80` installs.
/// nlink took the ethertype from the flower keys alone and refused that
/// filter for want of one (#433).
#[test]
fn flower_takes_its_ethertype_from_the_filter_protocol() {
    let f = FlowerFilter::new()
        .protocol(crate::EthProto::IP)
        .ip_proto_tcp()
        .dst_port(80);
    assert_eq!(flower_eth_type_key(&f).expect("tc(8) takes this"), Some(0x0800));
    let f = FlowerFilter::new().protocol(crate::EthProto::IPV6).ip_proto(0x3a);
    assert_eq!(flower_eth_type_key(&f).expect("tc(8) takes this"), Some(0x86DD));
    // A filter with no keys carries it too, as tc(8)'s does.
    let f = FlowerFilter::new().protocol(crate::EthProto::ARP);
    assert_eq!(flower_eth_type_key(&f).unwrap(), Some(0x0806));

    // `all` names no ethertype, so L3/L4 keys still need one; tc(8) refuses
    // `protocol all flower ip_proto tcp` too. So does a zero protocol, which
    // is what `FlowerFilter::default()` carries.
    for f in [FlowerFilter::new(), FlowerFilter::default()] {
        let err = flower_eth_type_key(&f.ip_proto_tcp()).unwrap_err().to_string();
        assert!(err.contains("needs an ethertype"), "{err}");
    }
    assert_eq!(flower_eth_type_key(&FlowerFilter::new()).unwrap(), None);
}

/// The `*_full` entry points take the protocol as an argument and hand it to
/// the config through `set_protocol` before writing the options, so a filter
/// parsed from tc(8) arguments takes its ethertype from the protocol it is
/// installed under. That covers 802.1AD as well: `.vlan_id()` used to write
/// 802.1Q there and match nothing (#433).
#[test]
fn flower_set_protocol_supplies_the_ethertype() {
    let mut f = FlowerFilter::parse_params(&["ip_proto", "tcp", "dst_port", "80"]).unwrap();
    f.set_protocol(crate::EthProto::IPV6);
    assert_eq!(FilterConfig::protocol(&f), Some(crate::EthProto::IPV6));
    assert_eq!(flower_eth_type_key(&f).expect("tc(8) takes this"), Some(0x86DD));

    let mut f = FlowerFilter::parse_params(&["vlan_id", "20"]).unwrap();
    f.set_protocol(crate::EthProto::VLAN_8021AD);
    assert_eq!(flower_eth_type_key(&f).expect("tc(8) takes this"), Some(0x88A8));
    // Under `all` a VLAN key still implies 802.1Q…
    f.set_protocol(crate::EthProto::ALL);
    assert_eq!(flower_eth_type_key(&f).unwrap(), Some(0x8100));
    // …and an ethertype set on the filter wins over the protocol.
    let mut f = FlowerFilter::new().qinq().vlan_id(20);
    f.set_protocol(crate::EthProto::VLAN_8021Q);
    assert_eq!(flower_eth_type_key(&f).unwrap(), Some(0x88A8));

    // Every shipped config that carries a protocol stores it.
    let mut configs: Vec<Box<dyn FilterConfig>> = vec![
        Box::new(U32Filter::new()),
        Box::new(FlowerFilter::new()),
        Box::new(MatchallFilter::new()),
        Box::new(BpfFilter::with_raw_fd(0)),
        Box::new(BasicFilter::new()),
        Box::new(FlowFilter::new()),
    ];
    for c in &mut configs {
        c.set_protocol(crate::EthProto::IPV6);
        assert_eq!(c.protocol(), Some(crate::EthProto::IPV6), "{}", c.kind());
    }
}

// ========================================================================
// #450 — flower carries actions
// ========================================================================

/// `FlowerFilter` had no way to attach actions: it wrote `TCA_FLOWER_ACT`
/// only for `goto_chain`, so tc(8)'s `flower … action drop` had no
/// equivalent, and on an ingress or clsact hook a flower filter could only
/// jump chains (#450). Asserted at the byte level for the same reason as
/// matchall's: the action list and `goto_chain` share one nest, and writing
/// it twice would leave the kernel to keep one and drop the other.
#[test]
fn flower_actions_and_goto_chain_share_one_act_nest() {
    use crate::netlink::{
        action::{ActionList, GactAction},
        test_support::{builder_attrs, parse_attrs},
    };

    let encode = |f: &FlowerFilter| {
        let mut b = MessageBuilder::new(NlMsgType::RTM_NEWTFILTER, 0);
        f.write_options(&mut b).unwrap();
        builder_attrs(&b)
    };
    let udp53 = || FlowerFilter::new().ipv4().ip_proto_udp().dst_port(53);

    // Actions alone: one nest, one action at index 1, beside the keys.
    let attrs = encode(&udp53().actions(ActionList::new().with(GactAction::drop())));
    assert!(attrs.contains_key(&flower::TCA_FLOWER_KEY_UDP_DST));
    let act = attrs
        .get(&flower::TCA_FLOWER_ACT)
        .expect("TCA_FLOWER_ACT missing: the action list was dropped");
    let inner = parse_attrs(act);
    assert_eq!(inner.len(), 1, "expected one action, got {inner:?}");
    assert!(inner.contains_key(&1), "actions are numbered from 1");

    // goto_chain alone keeps working, still at index 1.
    let attrs = encode(&udp53().goto_chain(3));
    let inner = parse_attrs(attrs.get(&flower::TCA_FLOWER_ACT).unwrap());
    assert_eq!(inner.len(), 1);
    assert!(inner.contains_key(&1));

    // Both: one nest; the goto follows the list, the order tc(8) emits and
    // the kernel runs.
    let attrs = encode(
        &udp53()
            .actions(ActionList::new().with(GactAction::pass()).with(GactAction::drop()))
            .goto_chain(3),
    );
    let inner = parse_attrs(attrs.get(&flower::TCA_FLOWER_ACT).unwrap());
    assert_eq!(
        inner.len(),
        3,
        "the goto must extend the action list, not collide with it: {inner:?}"
    );
    assert!((1..=3).all(|i| inner.contains_key(&i)));
}

/// tc(8) spells actions after the keys (`flower dst_port 80 action drop`).
/// `parse_params` does not model them; it says so and names the builder
/// method instead of calling `action` an unknown token.
#[test]
fn flower_parse_params_points_action_at_the_builder() {
    let err = FlowerFilter::parse_params(&["ip_proto", "tcp", "action", "drop"])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("flower: `action` is not modelled") && err.contains("FlowerFilter::actions"),
        "{err}"
    );
}
}

/// `to_params` is `parse_params`' inverse for the filters a declared tree
/// holds (#645): the tokens parse back to a filter that writes the same
/// request, and the same tokens.
#[cfg(test)]
mod params_tests {
    use super::*;

    /// What `f` writes installed under `protocol`, as the tree installs
    /// it (flower takes its ethertype from the protocol).
    fn bytes(f: &(impl FilterConfig + Clone), protocol: EthProto) -> Vec<u8> {
        let mut f = f.clone();
        f.set_protocol(protocol);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        f.write_options(&mut b).unwrap();
        b.as_bytes()[start..].to_vec()
    }

    macro_rules! round_trips {
        ($ty:ident, $f:expr) => {
            round_trips!($ty, $f, EthProto::IP)
        };
        ($ty:ident, $f:expr, $proto:expr) => {{
            let f: $ty = $f;
            let tokens = f.to_params().unwrap_or_else(|e| panic!("{e}"));
            let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let back = $ty::parse_params(&refs).unwrap_or_else(|e| panic!("{tokens:?}: {e}"));
            assert_eq!(back.to_params().unwrap(), tokens);
            assert_eq!(bytes(&back, $proto), bytes(&f, $proto), "{tokens:?}");
            tokens
        }};
    }

    #[test]
    fn flower_round_trips() {
        let h = |m, n| TcHandle::new(m, n);
        assert_eq!(
            round_trips!(FlowerFilter, FlowerFilter::new().ip_proto_tcp().dst_port(22).classid(h(1, 0x10))),
            ["classid", "1:10", "ip_proto", "tcp", "dst_port", "22"]
        );
        round_trips!(
            FlowerFilter,
            FlowerFilter::new()
                .ip_proto(47)
                .src_ipv6("2001:db8:1::".parse().unwrap(), 48)
                .dst_ipv6("2001:db8::".parse().unwrap(), 32),
            EthProto::IPV6
        );
        round_trips!(
            FlowerFilter,
            FlowerFilter::new()
                .ip_proto_tcp()
                .src_ipv4("10.0.0.0".parse().unwrap(), 8)
                .src_port_range(1000, 2000)
                .src_mac([0xaa, 0xbb, 0xcc, 0, 1, 2])
                .dst_mac([2, 0, 0, 0, 0, 1])
                .ip_tos(0x10, 0xfc)
                .ip_ttl(64, 0xff)
                .tcp_flags(0x12, 0x3f)
                .chain(2)
                .goto_chain(5)
                .skip_hw()
        );
        round_trips!(
            FlowerFilter,
            FlowerFilter::new().vlan_id(42).vlan_prio(3),
            EthProto::VLAN_8021Q
        );
        let mut eth = FlowerFilter::new();
        eth.eth_type = Some(0x88cc);
        round_trips!(FlowerFilter, eth, EthProto::ALL);
    }

    #[test]
    fn matchall_fw_and_u32_round_trip() {
        let h = |m, n| TcHandle::new(m, n);
        assert_eq!(
            round_trips!(MatchallFilter, MatchallFilter::new().classid(h(1, 0x20)).skip_sw()),
            ["classid", "1:20", "skip_sw"]
        );
        round_trips!(MatchallFilter, MatchallFilter::new().chain(1).goto_chain(3));
        assert_eq!(
            round_trips!(FwFilter, FwFilter::new().classid(h(1, 5)).mask(0xff00)),
            ["classid", "1:5", "mask", "0xff00"]
        );
        round_trips!(FwFilter, FwFilter::new().chain(4));

        // Named matches pack into raw keys; nexthdr+ offsets included.
        let named = U32Filter::parse_params(&[
            "match", "ip", "src", "10.1.0.0/16", "match", "ip", "protocol", "6", "0xff", "match",
            "tcp", "dport", "22", "0xffff", "match", "u16", "0x0016", "0xffff", "at",
            "nexthdr+2", "classid", "1:10",
        ])
        .unwrap();
        let tokens = round_trips!(U32Filter, named);
        assert!(tokens.iter().any(|t| t.starts_with("nexthdr+")), "{tokens:?}");
        round_trips!(
            U32Filter,
            U32Filter::new()
                .match_mark(0x10, 0xff)
                .divisor(256)
                .ht(U32Filter::handle(2, 0, 0))
                .link(U32Filter::handle(3, 0, 0))
                .hashkey(0x0000_00ff, 16)
                .offset_plus(4)
                .offset_at(0, 0x0f00, 6)
                .eat()
                .chain(9)
                .skip_hw()
        );
    }
}
