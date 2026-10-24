//! Strongly-typed traffic control messages.

use winnow::{prelude::*, token::take};

use crate::netlink::{
    message::NlMsgType,
    parse::{FromNetlink, PResult, parse_string_from_bytes},
    types::tc::TcMsg,
};

/// Attribute IDs for TCA_* constants.
mod attr_ids {
    pub const TCA_KIND: u16 = 1;
    pub const TCA_OPTIONS: u16 = 2;
    pub const TCA_STATS: u16 = 3;
    pub const TCA_XSTATS: u16 = 4;
    pub const TCA_STATS2: u16 = 7;
    pub const TCA_CHAIN: u16 = 11;
    pub const TCA_HW_OFFLOAD: u16 = 12;
    pub const TCA_INGRESS_BLOCK: u16 = 13;
    pub const TCA_EGRESS_BLOCK: u16 = 14;
}

/// Nested TCA_STATS2 attribute IDs.
mod stats2_ids {
    pub const TCA_STATS_BASIC: u16 = 1;
    pub const TCA_STATS_RATE_EST: u16 = 2;
    pub const TCA_STATS_QUEUE: u16 = 3;
    pub const TCA_STATS_APP: u16 = 4;
    pub const TCA_STATS_RATE_EST64: u16 = 5;
    pub const TCA_STATS_BASIC_HW: u16 = 7;
    pub const TCA_STATS_PKT64: u16 = 8;
}

/// Strongly-typed traffic control message.
///
/// This struct represents a qdisc, class, or filter message from the kernel.
/// The specific type is determined by the netlink message type (RTM_NEWQDISC,
/// RTM_NEWTCLASS, RTM_NEWTFILTER).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TcMessage {
    /// Fixed-size header (struct tcmsg).
    pub(crate) header: TcMsg,
    /// Qdisc/class/filter type (e.g., "htb", "fq_codel", "u32").
    pub(crate) kind: Option<String>,
    /// Raw options data (type-specific, nested attributes).
    pub(crate) options: Option<Vec<u8>>,
    /// Chain index for filters.
    pub(crate) chain: Option<u32>,
    /// Hardware offload flag.
    pub(crate) hw_offload: Option<u8>,
    /// Ingress block index.
    pub(crate) ingress_block: Option<u32>,
    /// Egress block index.
    pub(crate) egress_block: Option<u32>,
    /// Basic statistics — the **software** total (`TCA_STATS_BASIC`).
    pub(crate) stats_basic: Option<TcStatsBasic>,
    /// The hardware-offloaded **subset** of [`Self::stats_basic`]
    /// (`TCA_STATS_BASIC_HW`), dumped alongside it for offloaded
    /// qdiscs/filters. `None` on a device with no tc offload.
    pub(crate) stats_basic_hw: Option<TcStatsBasic>,
    /// Queue statistics.
    pub(crate) stats_queue: Option<TcStatsQueue>,
    /// Rate estimator.
    pub(crate) stats_rate_est: Option<TcStatsRateEst>,
    /// Extended statistics (type-specific).
    pub(crate) xstats: Option<Vec<u8>>,
    /// Interface name (not from netlink, populated separately for convenience).
    ///
    /// This field is not populated by netlink parsing since TC messages only
    /// contain interface indices. Use [`TcMessage::with_name`] or
    /// [`TcMessage::resolve_name`] to populate it.
    pub(crate) name: Option<String>,
    /// The `nlmsg_type` this message arrived with (`RTM_NEWQDISC`,
    /// `RTM_NEWTCLASS`, `RTM_NEWTFILTER`, …).
    ///
    /// The `tcmsg` payload is byte-identical for qdiscs, classes and filters —
    /// only the message type distinguishes them, and it lives in the netlink
    /// header rather than the payload. Populated by the dump and event paths
    /// via `FromNetlink::set_msg_type`; `None` for a message parsed straight
    /// from a payload with no header in hand (#214).
    pub(crate) msg_type: Option<u16>,
}

/// Basic traffic control statistics (from TCA_STATS2/TCA_STATS_BASIC).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsBasic {
    /// Bytes transmitted.
    pub bytes: u64,
    /// Packets transmitted.
    pub packets: u64,
}

impl TcStatsBasic {
    /// Calculate the delta (difference) from a previous sample.
    ///
    /// Uses saturating subtraction to handle counter wraps gracefully.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// let prev = qdisc.stats_basic().unwrap().clone();
    /// // ... wait some time ...
    /// let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// let curr = qdisc.stats_basic().unwrap();
    /// let delta = curr.delta(&prev);
    /// println!("Transferred {} bytes, {} packets", delta.bytes, delta.packets);
    /// # Ok(())
    /// # }
    /// ```
    pub fn delta(&self, previous: &Self) -> TcStatsBasic {
        TcStatsBasic {
            bytes: self.bytes.saturating_sub(previous.bytes),
            packets: self.packets.saturating_sub(previous.packets),
        }
    }
}

/// Queue statistics (from TCA_STATS2/TCA_STATS_QUEUE).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsQueue {
    /// Current queue length in packets.
    pub qlen: u32,
    /// Backlog in bytes.
    pub backlog: u32,
    /// Total drops.
    pub drops: u32,
    /// Requeue count.
    pub requeues: u32,
    /// Overlimit count.
    pub overlimits: u32,
}

impl TcStatsQueue {
    /// Calculate the delta (difference) from a previous sample.
    ///
    /// Note: `qlen` and `backlog` are instantaneous values, not counters,
    /// so they are taken from the current sample directly.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// let prev = qdisc.stats_queue().unwrap().clone();
    /// // ... wait some time ...
    /// let qdisc = conn.get_root_qdisc_by_name("eth0").await?.unwrap();
    /// let curr = qdisc.stats_queue().unwrap();
    /// let delta = curr.delta(&prev);
    /// println!("New drops: {}, new overlimits: {}", delta.drops, delta.overlimits);
    /// # Ok(())
    /// # }
    /// ```
    pub fn delta(&self, previous: &Self) -> TcStatsQueue {
        TcStatsQueue {
            qlen: self.qlen,       // Instantaneous, not a counter
            backlog: self.backlog, // Instantaneous, not a counter
            drops: self.drops.saturating_sub(previous.drops),
            requeues: self.requeues.saturating_sub(previous.requeues),
            overlimits: self.overlimits.saturating_sub(previous.overlimits),
        }
    }
}

/// Rate estimator statistics (from TCA_STATS2/TCA_STATS_RATE_EST, or
/// `TCA_STATS_RATE_EST64` when the rate does not fit 32 bits).
///
/// 64-bit since 0.31.0 (#489): `TCA_STATS_RATE_EST` caps the byte rate at
/// `u32::MAX` (about 34 Gbit/s), and the kernel sends the real value in
/// `TCA_STATS_RATE_EST64` only then.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcStatsRateEst {
    /// Bytes per second.
    pub bps: u64,
    /// Packets per second.
    pub pps: u64,
}

impl TcMessage {
    /// Create a new empty TC message.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Accessor methods
    // =========================================================================

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.header.tcm_ifindex as u32
    }

    /// Get the handle (qdisc/class ID) as a typed [`TcHandle`](crate::TcHandle).
    ///
    /// For the raw `u32` (e.g. for use as a `HashMap` key), call
    /// [`handle_raw`](Self::handle_raw).
    pub fn handle(&self) -> crate::TcHandle {
        crate::TcHandle::from_raw(self.header.tcm_handle)
    }

    /// Get the raw `u32` handle the kernel returned, without wrapping it in
    /// a [`TcHandle`](crate::TcHandle). Prefer [`handle`](Self::handle) unless you need the
    /// raw integer (e.g. as a `HashMap` key).
    pub fn handle_raw(&self) -> u32 {
        self.header.tcm_handle
    }

    /// Get the parent handle as a typed [`TcHandle`](crate::TcHandle).
    ///
    /// For the raw `u32`, call [`parent_raw`](Self::parent_raw).
    pub fn parent(&self) -> crate::TcHandle {
        crate::TcHandle::from_raw(self.header.tcm_parent)
    }

    /// Get the raw `u32` parent the kernel returned, without wrapping it in
    /// a [`TcHandle`](crate::TcHandle). Prefer [`parent`](Self::parent) unless you need the
    /// raw integer.
    pub fn parent_raw(&self) -> u32 {
        self.header.tcm_parent
    }

    /// Get the raw `tcm_info` field.
    ///
    /// For filters this packs the priority (upper 16 bits) and the ethernet
    /// protocol (lower 16 bits, network byte order); see
    /// [`protocol`](Self::protocol) / [`priority`](Self::priority) to unpack,
    /// and `TcMsg::with_filter_info` for the packing side.
    pub fn info(&self) -> u32 {
        self.header.tcm_info
    }

    /// For filters: the ethernet protocol (e.g. `0x0800` for IPv4), in host
    /// byte order.
    ///
    /// The protocol lives in the lower 16 bits of `tcm_info` in network byte
    /// order (the kernel compares it against `skb->protocol`), so this
    /// converts back from big-endian.
    pub fn protocol(&self) -> crate::netlink::eth_proto::EthProto {
        crate::netlink::eth_proto::EthProto::new(u16::from_be(
            (self.header.tcm_info & 0xFFFF) as u16,
        ))
    }

    /// For filters: the priority, held in the upper 16 bits of `tcm_info`.
    pub fn priority(&self) -> crate::netlink::tc_handle::FilterPriority {
        crate::netlink::tc_handle::FilterPriority::new((self.header.tcm_info >> 16) as u16)
    }

    /// Get the kind (type name) if present.
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Get the raw options data.
    pub fn raw_options(&self) -> Option<&[u8]> {
        self.options.as_deref()
    }

    /// Get the chain index.
    pub fn chain(&self) -> Option<u32> {
        self.chain
    }

    /// Get the hardware offload flag.
    pub fn hw_offload(&self) -> Option<u8> {
        self.hw_offload
    }

    /// Get the ingress block index.
    pub fn ingress_block(&self) -> Option<u32> {
        self.ingress_block
    }

    /// Get the egress block index.
    pub fn egress_block(&self) -> Option<u32> {
        self.egress_block
    }

    /// Get the basic statistics — the **software** total.
    pub fn stats_basic(&self) -> Option<&TcStatsBasic> {
        self.stats_basic.as_ref()
    }

    /// Get the hardware-offloaded **subset** of the basic statistics
    /// (`TCA_STATS_BASIC_HW`).
    ///
    /// This is not a separate counter to add to [`stats_basic`](Self::stats_basic)
    /// — it is the portion of that same total which the NIC counted in
    /// hardware. `None` on a device without tc offload.
    ///
    /// Until 0.25 the HW value silently overwrote the software one (they shared
    /// a match arm, and 7 > 1 so it arrived last), which made
    /// [`bytes`](Self::bytes) and [`packets`](Self::packets) report only the
    /// offloaded portion on an offloading NIC — often zero (#215).
    pub fn stats_basic_hw(&self) -> Option<&TcStatsBasic> {
        self.stats_basic_hw.as_ref()
    }

    /// Get the queue statistics.
    pub fn stats_queue(&self) -> Option<&TcStatsQueue> {
        self.stats_queue.as_ref()
    }

    /// Get the rate estimator statistics.
    pub fn stats_rate_est(&self) -> Option<&TcStatsRateEst> {
        self.stats_rate_est.as_ref()
    }

    /// Get the extended statistics.
    pub fn xstats(&self) -> Option<&[u8]> {
        self.xstats.as_deref()
    }

    /// Get the interface name if set.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the interface name or a fallback value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     println!("{}: {}", qdisc.name_or("?"), qdisc.kind().unwrap_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn name_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(fallback)
    }

    // =========================================================================
    // Convenience statistics accessors
    // =========================================================================

    /// Get total bytes from basic stats.
    pub fn bytes(&self) -> u64 {
        self.stats_basic.map(|s| s.bytes).unwrap_or(0)
    }

    /// Get total packets from basic stats.
    pub fn packets(&self) -> u64 {
        self.stats_basic.map(|s| s.packets).unwrap_or(0)
    }

    /// Get drops from queue stats.
    pub fn drops(&self) -> u32 {
        self.stats_queue.map(|s| s.drops).unwrap_or(0)
    }

    /// Get overlimits from queue stats.
    pub fn overlimits(&self) -> u32 {
        self.stats_queue.map(|s| s.overlimits).unwrap_or(0)
    }

    /// Get requeues from queue stats.
    pub fn requeues(&self) -> u32 {
        self.stats_queue.map(|s| s.requeues).unwrap_or(0)
    }

    /// Get queue length from queue stats.
    pub fn qlen(&self) -> u32 {
        self.stats_queue.map(|s| s.qlen).unwrap_or(0)
    }

    /// Get backlog from queue stats.
    pub fn backlog(&self) -> u32 {
        self.stats_queue.map(|s| s.backlog).unwrap_or(0)
    }

    /// Get bytes per second from rate estimator.
    ///
    /// Returns 0 if rate estimator statistics are not available.
    pub fn bps(&self) -> u64 {
        self.stats_rate_est.map(|s| s.bps).unwrap_or(0)
    }

    /// Get packets per second from rate estimator.
    ///
    /// Returns 0 if rate estimator statistics are not available.
    pub fn pps(&self) -> u64 {
        self.stats_rate_est.map(|s| s.pps).unwrap_or(0)
    }

    // =========================================================================
    // Name resolution
    // =========================================================================

    /// Set the interface name.
    ///
    /// Returns self for method chaining.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Resolve and set the interface name from the ifindex.
    ///
    /// This performs a syscall to look up the interface name.
    /// Returns self for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// if let Some(qdisc) = conn.get_root_qdisc_by_name("eth0").await? {
    ///     let qdisc = qdisc.resolve_name();
    ///     println!("Interface: {}", qdisc.name_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **Host only.** The name comes from `/sys/class/net` in the calling
    /// process's mount namespace, so for a message from another network
    /// namespace it is that of whatever has the same ifindex on the host, or
    /// nothing (#497). There, ask the message's own connection:
    /// `conn.get_link_by_index(msg.ifindex())`.
    pub fn resolve_name(mut self) -> Self {
        if let Ok(name) = crate::util::ifname::index_to_name(self.ifindex()) {
            self.name = Some(name);
        }
        self
    }

    /// Resolve and set the interface name, mutating in place. Host only,
    /// as [`resolve_name`](Self::resolve_name).
    pub fn resolve_name_mut(&mut self) {
        if let Ok(name) = crate::util::ifname::index_to_name(self.ifindex()) {
            self.name = Some(name);
        }
    }

    // =========================================================================
    // Options parsing
    // =========================================================================

    /// Get parsed qdisc options if available.
    ///
    /// This parses the raw options data into a strongly-typed enum
    /// based on the qdisc kind. Use pattern matching to extract
    /// type-specific options.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::tc_options::QdiscOptions;
    ///
    /// let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     match qdisc.options() {
    ///         Some(QdiscOptions::Netem(netem)) => {
    ///             println!("delay={:?}, loss={:?}", netem.delay(), netem.loss());
    ///         }
    ///         Some(QdiscOptions::FqCodel(fq)) => {
    ///             println!("target={}us", fq.target_us);
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn options(&self) -> Option<crate::netlink::tc_options::QdiscOptions> {
        crate::netlink::tc_options::parse_qdisc_options(self)
    }

    /// Check if this is a netem qdisc.
    #[inline]
    pub fn is_netem(&self) -> bool {
        self.kind() == Some("netem")
    }

    /// Check if this qdisc is attached to the root.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.header.tcm_parent == crate::netlink::types::tc::tc_handle::ROOT
    }

    /// Check if this is an ingress qdisc.
    ///
    /// Decided by kind (#493). An `ingress` and a `clsact` qdisc both sit
    /// at parent `TC_H_INGRESS` (`TcHandle::INGRESS == TcHandle::CLSACT`),
    /// so comparing the parent made a clsact read as ingress and an ingress
    /// as clsact. For "anything at the ingress hook", ask
    /// `msg.parent().is_ingress()`.
    #[inline]
    pub fn is_ingress(&self) -> bool {
        self.kind() == Some("ingress")
    }

    /// Check if this is a clsact qdisc. Decided by kind; see
    /// [`is_ingress`](Self::is_ingress).
    #[inline]
    pub fn is_clsact(&self) -> bool {
        self.kind() == Some("clsact")
    }

    /// The `nlmsg_type` this message arrived with, if known.
    ///
    /// `None` when the message was parsed from a bare payload with no netlink
    /// header available. See [`is_qdisc`](Self::is_qdisc) for why this matters.
    #[inline]
    pub fn msg_type(&self) -> Option<u16> {
        self.msg_type
    }

    /// Check if this is a qdisc.
    ///
    /// # Why this reads the message type and not the header
    ///
    /// `struct tcmsg` is byte-identical for qdiscs, classes and filters. The
    /// only reliable discriminator is the `nlmsg_type`
    /// (`RTM_NEWQDISC` / `RTM_NEWTCLASS` / `RTM_NEWTFILTER`), which lives in
    /// the netlink header.
    ///
    /// Until 0.25 these predicates guessed from header fields, and got it
    /// wrong (#214): `is_filter()` tested `tcm_info != 0`, but `tc_fill_qdisc()`
    /// sets `tcm_info` to the qdisc **refcount** — always ≥ 1 — so **every
    /// qdisc reported `is_filter() == true`**, and `filter_protocol()` handed
    /// back refcount bits reinterpreted as an ethertype.
    ///
    /// Returns `false` (not `true`) when the message type is unknown, so a
    /// caller can never be told something is a qdisc on a guess.
    #[inline]
    pub fn is_qdisc(&self) -> bool {
        self.is_msg_type(&[
            NlMsgType::RTM_NEWQDISC,
            NlMsgType::RTM_DELQDISC,
            NlMsgType::RTM_GETQDISC,
        ])
    }

    /// Check if this is a TC class.
    ///
    /// Classified on the `nlmsg_type` — see [`is_qdisc`](Self::is_qdisc).
    #[inline]
    pub fn is_class(&self) -> bool {
        self.is_msg_type(&[
            NlMsgType::RTM_NEWTCLASS,
            NlMsgType::RTM_DELTCLASS,
            NlMsgType::RTM_GETTCLASS,
        ])
    }

    /// Check if this is a TC filter.
    ///
    /// Classified on the `nlmsg_type` — see [`is_qdisc`](Self::is_qdisc).
    #[inline]
    pub fn is_filter(&self) -> bool {
        self.is_msg_type(&[
            NlMsgType::RTM_NEWTFILTER,
            NlMsgType::RTM_DELTFILTER,
            NlMsgType::RTM_GETTFILTER,
        ])
    }

    #[inline]
    fn is_msg_type(&self, types: &[u16]) -> bool {
        self.msg_type.is_some_and(|t| types.contains(&t))
    }

    /// Get the filter protocol (`ETH_P_*` value), in host byte order, if this
    /// is a filter. `Option` wrapper over [`protocol`](Self::protocol).
    ///
    /// Returns `None` for a qdisc or class, whose `tcm_info` carries something
    /// else entirely (the refcount, for a qdisc).
    #[inline]
    pub fn filter_protocol(&self) -> Option<crate::netlink::eth_proto::EthProto> {
        self.is_filter().then(|| self.protocol())
    }

    /// Get the filter priority, if this is a filter. `Option` wrapper over
    /// [`priority`](Self::priority).
    #[inline]
    pub fn filter_priority(&self) -> Option<crate::netlink::tc_handle::FilterPriority> {
        self.is_filter().then(|| self.priority())
    }

    /// Get the handle as a human-readable string (e.g., "1:0", "ffff:").
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     println!("handle: {}", qdisc.handle_str());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn handle_str(&self) -> String {
        crate::netlink::types::tc::tc_handle::format(self.header.tcm_handle)
    }

    /// Get the parent as a human-readable string (e.g., "root", "1:0").
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let qdiscs = conn.get_qdiscs().await?;
    /// for qdisc in &qdiscs {
    ///     println!("parent: {}", qdisc.parent_str());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn parent_str(&self) -> String {
        crate::netlink::types::tc::tc_handle::format(self.header.tcm_parent)
    }

    /// Get BPF program info if this is a BPF filter.
    ///
    /// Returns `None` if the filter kind is not "bpf" or if no options are present.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let filters = conn.get_filters_by_name("eth0").await?;
    /// for filter in &filters {
    ///     if let Some(bpf) = filter.bpf_info() {
    ///         println!("BPF: id={:?} name={:?} tag={:?} da={}",
    ///             bpf.id, bpf.name, bpf.tag_hex(), bpf.direct_action);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn bpf_info(&self) -> Option<BpfInfo> {
        if self.kind() != Some("bpf") {
            return None;
        }

        let options = self.options.as_deref()?;

        use crate::netlink::types::tc::filter::bpf;

        let mut info = BpfInfo {
            id: None,
            name: None,
            tag: None,
            direct_action: false,
            classid: None,
        };

        // Parse nested attributes from options data
        let mut pos = 0;
        while pos + 4 <= options.len() {
            let len = u16::from_ne_bytes([options[pos], options[pos + 1]]) as usize;
            let attr_type = u16::from_ne_bytes([options[pos + 2], options[pos + 3]]) & 0x3FFF;

            if len < 4 || pos + len > options.len() {
                break;
            }

            let payload = &options[pos + 4..pos + len];

            match attr_type {
                bpf::TCA_BPF_ID if payload.len() >= 4 => {
                    info.id = Some(u32::from_ne_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
                bpf::TCA_BPF_NAME => {
                    let name = std::str::from_utf8(payload)
                        .ok()
                        .map(|s| s.trim_end_matches('\0').to_string());
                    info.name = name;
                }
                bpf::TCA_BPF_TAG if payload.len() >= 8 => {
                    let mut tag = [0u8; 8];
                    tag.copy_from_slice(&payload[..8]);
                    info.tag = Some(tag);
                }
                bpf::TCA_BPF_FLAGS if payload.len() >= 4 => {
                    let flags =
                        u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    info.direct_action = (flags & bpf::TCA_BPF_FLAG_ACT_DIRECT) != 0;
                }
                bpf::TCA_BPF_CLASSID if payload.len() >= 4 => {
                    info.classid = Some(u32::from_ne_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
                _ => {}
            }

            // Align to 4 bytes
            pos += (len + 3) & !3;
        }

        Some(info)
    }
}

/// Information about an attached BPF program.
///
/// Parsed from `TCA_BPF_*` attributes in TC filter dump responses.
#[derive(Debug, Clone)]
pub struct BpfInfo {
    /// BPF program ID (stable kernel identifier).
    pub id: Option<u32>,
    /// BPF program name (set by the loader).
    pub name: Option<String>,
    /// BPF program tag (8-byte SHA-1 truncation of instructions).
    pub tag: Option<[u8; 8]>,
    /// Whether direct action mode is enabled.
    pub direct_action: bool,
    /// TC classid (for non-DA mode).
    pub classid: Option<u32>,
}

impl BpfInfo {
    /// Format the tag as a hex string (e.g., "a1b2c3d4e5f6a7b8").
    pub fn tag_hex(&self) -> Option<String> {
        self.tag
            .map(|t| t.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl FromNetlink for TcMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // TC dump requests require a TcMsg header
        let header = TcMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    /// `tcmsg` is byte-identical for qdiscs, classes and filters — only the
    /// message type tells them apart, and it lives in the header rather than
    /// the payload `parse()` sees. See [`TcMessage::is_qdisc`] (#214).
    fn set_msg_type(&mut self, msg_type: u16) {
        self.msg_type = Some(msg_type);
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (20 bytes)
        if input.len() < TcMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(TcMsg::SIZE).parse_next(input)?;
        let header = *TcMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = TcMessage {
            header,
            ..Default::default()
        };

        let mut saw_stats2 = false;
        let mut legacy_stats = None;

        // Parse attributes
        while !input.is_empty() && input.len() >= 4 {
            // 0.19 N9 — nla_len/nla_type are host-order, not LE.
            let len_bytes: &[u8] = take(2usize).parse_next(input)?;
            let type_bytes: &[u8] = take(2usize).parse_next(input)?;
            let len = u16::from_ne_bytes(len_bytes.try_into().unwrap()) as usize;
            let attr_type = u16::from_ne_bytes(type_bytes.try_into().unwrap());

            if len < 4 {
                break;
            }

            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len {
                break;
            }

            let attr_data: &[u8] = take(payload_len).parse_next(input)?;

            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }

            // Match attribute type (mask out NLA_F_NESTED and other flags)
            match attr_type & 0x3FFF {
                attr_ids::TCA_KIND => {
                    msg.kind = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::TCA_OPTIONS => {
                    msg.options = Some(attr_data.to_vec());
                }
                attr_ids::TCA_XSTATS => {
                    msg.xstats = Some(attr_data.to_vec());
                }
                attr_ids::TCA_CHAIN if attr_data.len() >= 4 => {
                    msg.chain = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::TCA_HW_OFFLOAD if !attr_data.is_empty() => {
                    msg.hw_offload = Some(attr_data[0]);
                }
                attr_ids::TCA_INGRESS_BLOCK if attr_data.len() >= 4 => {
                    msg.ingress_block =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::TCA_EGRESS_BLOCK if attr_data.len() >= 4 => {
                    msg.egress_block = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::TCA_STATS2 => {
                    saw_stats2 = true;
                    parse_stats2(&mut msg, attr_data);
                }
                attr_ids::TCA_STATS => {
                    // Legacy stats format (struct tc_stats)
                    legacy_stats = Some(attr_data);
                }
                _ => {} // Ignore unknown attributes
            }
        }

        // The kernel appends the legacy `tc_stats` after TCA_STATS2 as a
        // compat copy (`gnet_stats_finish_copy`): 32-bit packets, no
        // requeues. Parsed unconditionally, it overwrote the real counters,
        // so `requeues()` read 0 and packets wrapped at 2^32 (#489). It is
        // the answer only from a kernel that sends nothing else.
        if !saw_stats2 && let Some(data) = legacy_stats {
            parse_legacy_stats(&mut msg, data);
        }

        Ok(msg)
    }
}

/// Parse TCA_STATS2 nested attributes.
fn parse_stats2(msg: &mut TcMessage, data: &[u8]) {
    let mut input = data;

    while !input.is_empty() && input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().unwrap());

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            // TCA_STATS_BASIC (1) is the software total. TCA_STATS_BASIC_HW (7)
            // is the *hardware-offloaded subset* of it, and an offloaded
            // qdisc/filter dumps BOTH. They used to share this arm, so the HW
            // value — arriving later, since 7 > 1 — clobbered the total, and
            // bytes()/packets() reported only the offloaded portion (often 0,
            // when nothing had been offloaded yet). Keep them apart (#215).
            stats2_ids::TCA_STATS_BASIC
                // struct gnet_stats_basic: u64 bytes, u32 packets (+ padding)
                if payload.len() >= 12 => {
                    let bytes = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    let packets = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    msg.stats_basic = Some(TcStatsBasic {
                        bytes,
                        packets: packets as u64,
                    });
                }
            stats2_ids::TCA_STATS_BASIC_HW
                if payload.len() >= 12 => {
                    let bytes = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    let packets = u32::from_ne_bytes(payload[8..12].try_into().unwrap());
                    msg.stats_basic_hw = Some(TcStatsBasic {
                        bytes,
                        packets: packets as u64,
                    });
                }
            stats2_ids::TCA_STATS_PKT64
                // 64-bit packet count
                if payload.len() >= 8 => {
                    let packets = u64::from_ne_bytes(payload[..8].try_into().unwrap());
                    if let Some(ref mut stats) = msg.stats_basic {
                        stats.packets = packets;
                    } else {
                        msg.stats_basic = Some(TcStatsBasic { bytes: 0, packets });
                    }
                }
            stats2_ids::TCA_STATS_QUEUE
                // struct gnet_stats_queue: u32 qlen, backlog, drops, requeues, overlimits
                if payload.len() >= 20 => {
                    msg.stats_queue = Some(TcStatsQueue {
                        qlen: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                        backlog: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
                        drops: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
                        requeues: u32::from_ne_bytes(payload[12..16].try_into().unwrap()),
                        overlimits: u32::from_ne_bytes(payload[16..20].try_into().unwrap()),
                    });
                }
            stats2_ids::TCA_STATS_RATE_EST
                // struct gnet_stats_rate_est: u32 bps, pps
                if payload.len() >= 8 => {
                    msg.stats_rate_est = Some(TcStatsRateEst {
                        bps: u32::from_ne_bytes(payload[0..4].try_into().unwrap()).into(),
                        pps: u32::from_ne_bytes(payload[4..8].try_into().unwrap()).into(),
                    });
                }
            stats2_ids::TCA_STATS_RATE_EST64
                // struct gnet_stats_rate_est64: u64 bps, pps. Sent after
                // RATE_EST, and only when its u32 byte rate was capped.
                if payload.len() >= 16 => {
                    msg.stats_rate_est = Some(TcStatsRateEst {
                        bps: u64::from_ne_bytes(payload[0..8].try_into().unwrap()),
                        pps: u64::from_ne_bytes(payload[8..16].try_into().unwrap()),
                    });
                }
            stats2_ids::TCA_STATS_APP
                // Application-specific stats, store in xstats if not already set
                if msg.xstats.is_none() => {
                    msg.xstats = Some(payload.to_vec());
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

/// Parse legacy TCA_STATS (struct tc_stats).
fn parse_legacy_stats(msg: &mut TcMessage, data: &[u8]) {
    // struct tc_stats {
    //     __u64 bytes;
    //     __u32 packets;
    //     __u32 drops;
    //     __u32 overlimits;
    //     __u32 bps;
    //     __u32 pps;
    //     __u32 qlen;
    //     __u32 backlog;
    // }
    if data.len() >= 36 {
        let bytes = u64::from_ne_bytes(data[0..8].try_into().unwrap());
        let packets = u32::from_ne_bytes(data[8..12].try_into().unwrap());
        let drops = u32::from_ne_bytes(data[12..16].try_into().unwrap());
        let overlimits = u32::from_ne_bytes(data[16..20].try_into().unwrap());
        let bps = u32::from_ne_bytes(data[20..24].try_into().unwrap());
        let pps = u32::from_ne_bytes(data[24..28].try_into().unwrap());
        let qlen = u32::from_ne_bytes(data[28..32].try_into().unwrap());
        let backlog = u32::from_ne_bytes(data[32..36].try_into().unwrap());

        msg.stats_basic = Some(TcStatsBasic {
            bytes,
            packets: packets as u64,
        });
        msg.stats_queue = Some(TcStatsQueue {
            qlen,
            backlog,
            drops,
            requeues: 0,
            overlimits,
        });
        msg.stats_rate_est = Some(TcStatsRateEst {
            bps: bps.into(),
            pps: pps.into(),
        });
    }
}

// ============================================================================
// Type Aliases for Discoverability
// ============================================================================

/// Type alias for [`TcMessage`] when working with qdiscs.
///
/// This is the same type as `TcMessage` but provides better discoverability
/// when working specifically with qdisc operations.
pub type QdiscMessage = TcMessage;

/// Type alias for [`TcMessage`] when working with TC classes.
///
/// This is the same type as `TcMessage` but provides better discoverability
/// when working specifically with class operations (HTB, HFSC, etc.).
pub type ClassMessage = TcMessage;

/// Type alias for [`TcMessage`] when working with TC filters.
///
/// This is the same type as `TcMessage` but provides better discoverability
/// when working specifically with filter operations (u32, flower, etc.).
pub type FilterMessage = TcMessage;

/// Message classification and the software/hardware stats split
/// (#214, #215).
#[cfg(test)]
mod classification_tests {
    use super::*;

    fn msg(msg_type: u16, tcm_info: u32) -> TcMessage {
        let mut m = TcMessage::new();
        m.header.tcm_info = tcm_info;
        m.set_msg_type(msg_type);
        m
    }

    /// The bug: `is_filter()` tested `tcm_info != 0`, but `tc_fill_qdisc()`
    /// sets `tcm_info` to the qdisc **refcount** — always >= 1. So every qdisc
    /// reported `is_filter() == true`, and `filter_protocol()` handed back
    /// refcount bits reinterpreted as an ethertype.
    #[test]
    fn a_qdisc_with_a_refcount_is_not_a_filter() {
        // A perfectly ordinary qdisc: refcount 1 in tcm_info.
        let q = msg(NlMsgType::RTM_NEWQDISC, 1);

        assert!(q.is_qdisc());
        assert!(!q.is_filter(), "tcm_info is the refcount, not filter info");
        assert!(!q.is_class());

        // And so the filter accessors must not hand back refcount bits.
        assert_eq!(q.filter_protocol(), None);
        assert_eq!(q.filter_priority(), None);
    }

    #[test]
    fn a_filter_is_a_filter() {
        // tcm_info for a filter is (priority << 16) | protocol.
        let f = msg(NlMsgType::RTM_NEWTFILTER, (1u32 << 16) | 0x0008);

        assert!(f.is_filter());
        assert!(!f.is_qdisc());
        assert!(!f.is_class());
        assert_eq!(f.filter_priority(), Some(crate::FilterPriority::new(1)));
    }

    /// A filter attached to a root qdisc has tcm_parent = 1:0 and a handle
    /// with a non-zero minor (800::800), which satisfied every clause of the
    /// old is_class() heuristic.
    #[test]
    fn a_filter_is_not_a_class() {
        let mut f = msg(NlMsgType::RTM_NEWTFILTER, 1);
        f.header.tcm_parent = 0x0001_0000; // 1:0
        f.header.tcm_handle = 0x0800_0800; // 800::800

        assert!(!f.is_class(), "the old heuristic said class here");
        assert!(f.is_filter());
    }

    /// #493: an ingress and a clsact qdisc both sit at parent `TC_H_INGRESS`,
    /// so comparing the parent made each read as the other.
    #[test]
    fn ingress_and_clsact_are_told_apart_by_kind() {
        let at_ingress = |kind: &str| {
            let mut m = msg(NlMsgType::RTM_NEWQDISC, 1);
            m.header.tcm_parent = crate::netlink::types::tc::tc_handle::INGRESS;
            m.kind = Some(kind.to_string());
            m
        };
        let clsact = at_ingress("clsact");
        assert!(clsact.is_clsact());
        assert!(!clsact.is_ingress(), "a clsact read as ingress");
        let ingress = at_ingress("ingress");
        assert!(ingress.is_ingress());
        assert!(!ingress.is_clsact(), "an ingress read as clsact");
        assert!(clsact.parent().is_ingress() && ingress.parent().is_ingress());
    }

    #[test]
    fn a_class_is_a_class() {
        let c = msg(NlMsgType::RTM_NEWTCLASS, 0);
        assert!(c.is_class());
        assert!(!c.is_qdisc());
        assert!(!c.is_filter());
    }

    /// With no header in hand nothing can be classified — and the predicates
    /// must say "no" rather than guess.
    #[test]
    fn an_unknown_message_type_classifies_as_nothing() {
        let mut m = TcMessage::new();
        m.header.tcm_info = 1;

        assert_eq!(m.msg_type(), None);
        assert!(!m.is_qdisc());
        assert!(!m.is_class());
        assert!(!m.is_filter());
    }

    /// TCA_STATS_BASIC (1) is the software total; TCA_STATS_BASIC_HW (7) is
    /// the offloaded subset of it. They shared a match arm, so the HW value —
    /// arriving last, since 7 > 1 — clobbered the total. On an offloading NIC
    /// `bytes()` then reported only the offloaded portion, often 0 (#215).
    #[test]
    fn hardware_stats_do_not_clobber_the_software_total() {
        fn stats_attr(ty: u16, bytes: u64, packets: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&16u16.to_ne_bytes()); // nla_len: 4 + 12
            v.extend_from_slice(&ty.to_ne_bytes());
            v.extend_from_slice(&bytes.to_ne_bytes());
            v.extend_from_slice(&packets.to_ne_bytes());
            v
        }

        // What an offloaded qdisc dumps: the full total, then the hw subset.
        let mut data = stats_attr(stats2_ids::TCA_STATS_BASIC, 10_000, 100);
        data.extend(stats_attr(stats2_ids::TCA_STATS_BASIC_HW, 400, 4));

        let mut msg = TcMessage::new();
        parse_stats2(&mut msg, &data);

        assert_eq!(msg.bytes(), 10_000, "bytes() must be the software total");
        assert_eq!(msg.packets(), 100);
        assert_eq!(msg.stats_basic_hw().unwrap().bytes, 400);
        assert_eq!(msg.stats_basic_hw().unwrap().packets, 4);
    }

    /// One netlink attribute, padded.
    fn nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(4 + payload.len() as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        v.resize(v.len().next_multiple_of(4), 0);
        v
    }

    /// A qdisc dump as the kernel builds it: `TCA_STATS2`, then the legacy
    /// `TCA_STATS` compat copy (`gnet_stats_finish_copy`), which has 32-bit
    /// packets and no requeues. The copy overwrote the real counters, so
    /// `requeues()` was 0 and packets wrapped at 2^32 (#489).
    #[test]
    fn the_legacy_stats_copy_does_not_overwrite_stats2() {
        let packets: u64 = 5_000_000_000;
        let mut basic = 123_456_789_000u64.to_ne_bytes().to_vec();
        basic.extend_from_slice(&(packets as u32).to_ne_bytes());
        basic.extend_from_slice(&[0; 4]);
        let mut queue = Vec::new();
        for v in [3u32, 4500, 11, 7, 13] {
            queue.extend_from_slice(&v.to_ne_bytes()); // qlen backlog drops requeues overlimits
        }
        let mut rate = 5_000_000_000u64.to_ne_bytes().to_vec(); // past u32
        rate.extend_from_slice(&400_000u64.to_ne_bytes());
        let mut rate32 = u32::MAX.to_ne_bytes().to_vec();
        rate32.extend_from_slice(&400_000u32.to_ne_bytes());
        let stats2 = [
            nla(stats2_ids::TCA_STATS_BASIC, &basic),
            nla(stats2_ids::TCA_STATS_RATE_EST, &rate32),
            nla(stats2_ids::TCA_STATS_RATE_EST64, &rate),
            nla(stats2_ids::TCA_STATS_QUEUE, &queue),
            nla(stats2_ids::TCA_STATS_PKT64, &packets.to_ne_bytes()),
        ]
        .concat();
        // struct tc_stats: bytes, packets, drops, overlimits, bps, pps, qlen, backlog.
        let mut legacy = 123_456_789_000u64.to_ne_bytes().to_vec();
        for v in [packets as u32, 11, 13, u32::MAX, 400_000, 3, 4500] {
            legacy.extend_from_slice(&v.to_ne_bytes());
        }
        let mut wire = vec![0u8; std::mem::size_of::<TcMsg>()];
        wire.extend(nla(attr_ids::TCA_KIND, b"fq_codel\0"));
        wire.extend(nla(attr_ids::TCA_STATS2 | 0x8000, &stats2));
        wire.extend(nla(attr_ids::TCA_STATS, &legacy));

        let msg = TcMessage::from_bytes(&wire).expect("parses");
        assert_eq!(msg.requeues(), 7, "requeues come from TCA_STATS_QUEUE");
        assert_eq!(msg.packets(), packets, "packets come from TCA_STATS_PKT64");
        assert_eq!(msg.bytes(), 123_456_789_000);
        assert_eq!(msg.bps(), 5_000_000_000, "RATE_EST64 past the u32 cap");
        assert_eq!(msg.drops(), 11);

        // A kernel that sends only the legacy block is still read.
        let mut old = vec![0u8; std::mem::size_of::<TcMsg>()];
        old.extend(nla(attr_ids::TCA_STATS, &legacy));
        let msg = TcMessage::from_bytes(&old).expect("parses");
        assert_eq!(msg.packets(), u64::from(packets as u32));
        assert_eq!(msg.drops(), 11);
        assert_eq!(
            msg.bps(),
            u64::from(u32::MAX),
            "the legacy block caps the rate"
        );
    }

    /// The nastiest shape: nothing has been offloaded yet, so the hw counter
    /// is zero. It used to zero out the real total.
    #[test]
    fn an_empty_hardware_counter_does_not_zero_the_total() {
        fn stats_attr(ty: u16, bytes: u64, packets: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&16u16.to_ne_bytes());
            v.extend_from_slice(&ty.to_ne_bytes());
            v.extend_from_slice(&bytes.to_ne_bytes());
            v.extend_from_slice(&packets.to_ne_bytes());
            v
        }

        let mut data = stats_attr(stats2_ids::TCA_STATS_BASIC, 10_000, 100);
        data.extend(stats_attr(stats2_ids::TCA_STATS_BASIC_HW, 0, 0));

        let mut msg = TcMessage::new();
        parse_stats2(&mut msg, &data);

        assert_eq!(msg.bytes(), 10_000, "regression: hw zero clobbered the total");
        assert_eq!(msg.stats_basic_hw().unwrap().bytes, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc_message_default() {
        let msg = TcMessage::new();
        assert_eq!(msg.ifindex(), 0);
        assert_eq!(msg.handle(), crate::TcHandle::UNSPEC);
        assert_eq!(msg.parent(), crate::TcHandle::UNSPEC);
        assert!(msg.kind().is_none());
    }

    #[test]
    fn test_filter_protocol_priority() {
        // Pack tcm_info the way the kernel expects (priority in the upper 16
        // bits, ethernet protocol in the lower 16 bits, network byte order),
        // then confirm the getters unpack it back to host-order values.
        let mut msg = TcMessage::new();
        msg.header = TcMsg::new().with_filter_info(0x0800, 100);
        // filter_protocol()/filter_priority() are gated on this actually being
        // a filter, which only the message type can say (#214) — tcm_info
        // means something different for a qdisc (the refcount).
        msg.set_msg_type(NlMsgType::RTM_NEWTFILTER);

        assert_eq!(msg.protocol(), 0x0800, "ETH_P_IP, host byte order");
        assert_eq!(msg.priority(), 100);
        assert_eq!(msg.filter_protocol(), Some(crate::EthProto::IP));
        assert_eq!(msg.filter_priority(), Some(crate::FilterPriority::new(100)));

        // Layout check: priority is the major half, protocol the minor half.
        let info = msg.info();
        assert_eq!(info >> 16, 100, "priority occupies the upper 16 bits");
        assert_eq!(
            u16::from_be((info & 0xFFFF) as u16),
            0x0800,
            "protocol occupies the lower 16 bits in network byte order"
        );
    }
}
