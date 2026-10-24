//! MPLS routes and encapsulation.
//!
//! This module provides support for MPLS (Multi-Protocol Label Switching) routes,
//! including label operations (push, pop, swap) and MPLS encapsulation for IP routes.
//!
//! # Prerequisites
//!
//! MPLS support requires the following kernel modules and sysctl settings:
//!
//! ```bash
//! # Load MPLS modules
//! sudo modprobe mpls_router
//! sudo modprobe mpls_iptunnel
//!
//! # Enable MPLS platform labels
//! sudo sysctl -w net.mpls.platform_labels=1048575
//!
//! # Enable MPLS input on interfaces
//! sudo sysctl -w net.mpls.conf.eth0.input=1
//! ```
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::net::Ipv4Addr;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::mpls::{MplsEncap, MplsLabel, MplsRouteBuilder};
//! use nlink::netlink::route::Ipv4Route;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // IP route with MPLS encapsulation (push labels)
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
//!         .gateway("192.168.1.1".parse()?)
//!         .dev("eth0")
//!         .mpls_encap(MplsEncap::new().label(100))
//! ).await?;
//!
//! // MPLS pop route (decapsulate at egress PE)
//! conn.add_mpls_route(
//!     MplsRouteBuilder::pop(100)
//!         .dev("eth0")
//! ).await?;
//!
//! // MPLS swap route (transit LSR)
//! conn.add_mpls_route(
//!     MplsRouteBuilder::swap(100, 200)
//!         .via("192.168.2.1".parse()?)
//!         .dev("eth1")
//! ).await?;
//!
//! // Query MPLS routes
//! let routes = conn.get_mpls_routes().await?;
//! for route in &routes {
//!     println!("Label {}: {:?}", route.label().0, route.action());
//! }
//!
//! // Cleanup
//! conn.del_mpls_route(100).await?;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use super::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgType},
    protocol::Route,
    types::{
        mpls::{MplsLabelEntry, lwtunnel_encap, mpls_label, mpls_tunnel},
        route::{RtMsg, RtaAttr},
    },
};

/// AF_MPLS address family.
const AF_MPLS: u8 = 28;

/// NLM_F_REPLACE flag.
const NLM_F_REPLACE: u16 = 0x100;

// ============================================================================
// MplsLabel
// ============================================================================

/// An MPLS label (20-bit value, 0-1048575).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MplsLabel(pub u32);

impl MplsLabel {
    /// Create a new MPLS label.
    ///
    /// Returns `None` if the label is out of range (> 1048575).
    pub fn new(label: u32) -> Option<Self> {
        if label <= mpls_label::MAX {
            Some(Self(label))
        } else {
            None
        }
    }

    /// Create a new MPLS label, clamping to valid range.
    pub fn new_clamped(label: u32) -> Self {
        Self(label.min(mpls_label::MAX))
    }

    /// IPv4 Explicit NULL label (0).
    ///
    /// Used to explicitly signal the end of the label stack for IPv4.
    pub const EXPLICIT_NULL_V4: Self = Self(mpls_label::IPV4_EXPLICIT_NULL);

    /// Router Alert label (1).
    ///
    /// Signals that the packet should be examined by the router.
    pub const ROUTER_ALERT: Self = Self(mpls_label::ROUTER_ALERT);

    /// IPv6 Explicit NULL label (2).
    ///
    /// Used to explicitly signal the end of the label stack for IPv6.
    pub const EXPLICIT_NULL_V6: Self = Self(mpls_label::IPV6_EXPLICIT_NULL);

    /// Implicit NULL label (3).
    ///
    /// Used for penultimate hop popping (PHP). The penultimate router
    /// pops the label and forwards the packet as native IP.
    pub const IMPLICIT_NULL: Self = Self(mpls_label::IMPLICIT_NULL);

    /// Entropy Label Indicator (7).
    pub const ENTROPY_INDICATOR: Self = Self(mpls_label::ENTROPY_INDICATOR);

    /// Generic Associated Channel label (13).
    pub const GAL: Self = Self(mpls_label::GAL);

    /// OAM Alert label (14).
    pub const OAM_ALERT: Self = Self(mpls_label::OAM_ALERT);

    /// Extension label (15).
    pub const EXTENSION: Self = Self(mpls_label::EXTENSION);

    /// Check if this is a reserved label (0-15).
    pub fn is_reserved(&self) -> bool {
        self.0 <= 15
    }

    /// Get the raw label value.
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for MplsLabel {
    fn from(val: u32) -> Self {
        Self::new_clamped(val)
    }
}

impl From<MplsLabel> for u32 {
    fn from(val: MplsLabel) -> Self {
        val.0
    }
}

// ============================================================================
// MplsEncap
// ============================================================================

/// MPLS encapsulation for IP routes.
///
/// Used to push MPLS labels onto IP packets when forwarding.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::mpls::MplsEncap;
///
/// // Single label
/// let encap = MplsEncap::new().label(100);
///
/// // Label stack (outer to inner)
/// let encap = MplsEncap::new().labels(&[100, 200, 300]);
///
/// // With TTL
/// let encap = MplsEncap::new().label(100).ttl(64);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MplsEncap {
    /// Label stack (outer to inner).
    labels: Vec<MplsLabel>,
    /// TTL for the bottom label.
    ttl: Option<u8>,
}

impl MplsEncap {
    /// Create a new empty MPLS encapsulation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a label to the stack.
    ///
    /// Labels are added in order from outer to inner.
    pub fn label(mut self, label: u32) -> Self {
        self.labels.push(MplsLabel::new_clamped(label));
        self
    }

    /// Add multiple labels to the stack.
    ///
    /// Labels are added in order from outer to inner.
    pub fn labels(mut self, labels: &[u32]) -> Self {
        for &label in labels {
            self.labels.push(MplsLabel::new_clamped(label));
        }
        self
    }

    /// Set the TTL the encapsulation gives the packet
    /// (`MPLS_IPTUNNEL_TTL`). Unset, the kernel's: copied from the IP
    /// header, or `net.mpls.default_ttl`.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Check if the encapsulation has any labels.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Get the label stack.
    pub fn get_labels(&self) -> &[MplsLabel] {
        &self.labels
    }

    /// Get the TTL.
    pub fn get_ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// Encode the label stack for netlink: the bottom of stack marked, and
    /// no TTL in any entry — the kernel refuses one ("TTL in label must be
    /// 0"); the TTL is `MPLS_IPTUNNEL_TTL`'s (#678).
    pub(crate) fn encode_labels(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.labels.len() * 4);

        for (i, label) in self.labels.iter().enumerate() {
            let is_bottom = i == self.labels.len() - 1;
            let entry = if is_bottom {
                MplsLabelEntry::bottom(label.0, 0)
            } else {
                MplsLabelEntry::new(label.0)
            };
            data.extend_from_slice(entry.as_bytes());
        }

        data
    }

    /// Write the encapsulation to a message builder.
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder) {
        if self.labels.is_empty() {
            return;
        }

        // RTA_ENCAP_TYPE
        builder.append_attr_u16(RtaAttr::EncapType as u16, lwtunnel_encap::MPLS);

        // RTA_ENCAP (nested)
        let encap_nest = builder.nest_start(RtaAttr::Encap as u16);

        // MPLS_IPTUNNEL_DST
        let label_data = self.encode_labels();
        builder.append_attr(mpls_tunnel::DST, &label_data);

        // MPLS_IPTUNNEL_TTL (optional)
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(mpls_tunnel::TTL, ttl);
        }

        builder.nest_end(encap_nest);
    }
}

// ============================================================================
// MplsAction
// ============================================================================

/// MPLS forwarding action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MplsAction {
    /// Pop the label and forward as IP.
    Pop,
    /// Swap with new label(s).
    Swap(Vec<MplsLabel>),
}

impl MplsAction {
    /// Check if this is a pop action.
    pub fn is_pop(&self) -> bool {
        matches!(self, Self::Pop)
    }

    /// Check if this is a swap action.
    pub fn is_swap(&self) -> bool {
        matches!(self, Self::Swap(_))
    }
}

// ============================================================================
// MplsRoute
// ============================================================================

/// A parsed MPLS route.
///
/// Fields are `pub(crate)`; consumers read via the per-field
/// accessor methods. The struct is `#[non_exhaustive]` so the
/// kernel can grow new MPLS attribute fields without it being a
/// breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MplsRoute {
    /// Incoming label.
    pub(crate) label: MplsLabel,
    /// Forwarding action.
    pub(crate) action: MplsAction,
    /// Output interface index.
    pub(crate) oif: Option<u32>,
    /// Next hop address.
    pub(crate) via: Option<IpAddr>,
    /// Route protocol.
    pub(crate) protocol: u8,
}

impl MplsRoute {
    /// Incoming MPLS label.
    pub fn label(&self) -> MplsLabel {
        self.label
    }

    /// Forwarding action (pop / swap / …).
    pub fn action(&self) -> &MplsAction {
        &self.action
    }

    /// Output interface index, if reported.
    pub fn oif(&self) -> Option<u32> {
        self.oif
    }

    /// Next-hop address, if reported.
    pub fn via(&self) -> Option<IpAddr> {
        self.via
    }

    /// Route protocol byte (`RTPROT_*` from `linux/rtnetlink.h`).
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Parse an MPLS route from netlink message payload.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < RtMsg::SIZE {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: RtMsg::SIZE,
                actual: data.len(),
            }));
        }

        let rtmsg = RtMsg::from_bytes(data)?;
        let attrs_data = &data[RtMsg::SIZE..];

        let mut label = MplsLabel(0);
        let mut action = MplsAction::Pop;
        let mut oif = None;
        let mut via = None;

        for (attr_type, payload) in AttrIter::new(attrs_data) {
            match RtaAttr::from(attr_type) {
                RtaAttr::Dst => {
                    if let Some(entry) = MplsLabelEntry::from_bytes(payload) {
                        label = MplsLabel(entry.label());
                    }
                }
                RtaAttr::Newdst => {
                    // Parse outgoing label stack
                    let mut out_labels = Vec::new();
                    let mut offset = 0;
                    while offset + 4 <= payload.len() {
                        if let Some(entry) = MplsLabelEntry::from_bytes(&payload[offset..]) {
                            out_labels.push(MplsLabel(entry.label()));
                            if entry.is_bos() {
                                break;
                            }
                        }
                        offset += 4;
                    }
                    if !out_labels.is_empty() {
                        action = MplsAction::Swap(out_labels);
                    }
                }
                RtaAttr::Oif
                    if payload.len() >= 4 => {
                        oif = Some(u32::from_ne_bytes(
                            payload[..4].try_into().unwrap_or([0; 4]),
                        ));
                    }
                RtaAttr::Via
                    // RTA_VIA: { family(2), addr(4 or 16) }
                    if payload.len() >= 6 => {
                        let family = u16::from_ne_bytes(payload[..2].try_into().unwrap_or([0; 2]));
                        match family as i32 {
                            libc::AF_INET if payload.len() >= 6 => {
                                let addr_bytes: [u8; 4] =
                                    payload[2..6].try_into().unwrap_or([0; 4]);
                                via = Some(IpAddr::from(addr_bytes));
                            }
                            libc::AF_INET6 if payload.len() >= 18 => {
                                let addr_bytes: [u8; 16] =
                                    payload[2..18].try_into().unwrap_or([0; 16]);
                                via = Some(IpAddr::from(addr_bytes));
                            }
                            _ => {}
                        }
                    }
                _ => {}
            }
        }

        Ok(Self {
            label,
            action,
            oif,
            via,
            protocol: rtmsg.rtm_protocol,
        })
    }
}

// ============================================================================
// MplsRouteBuilder
// ============================================================================

/// Builder for MPLS routes.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::mpls::MplsRouteBuilder;
///
/// // Pop route (label -> IP)
/// let route = MplsRouteBuilder::pop(100)
///     .dev("eth0");
///
/// // Swap route (label -> label)
/// let route = MplsRouteBuilder::swap(100, 200)
///     .via("192.168.1.1".parse()?)
///     .dev("eth0");
///
/// // Swap with label stack
/// let route = MplsRouteBuilder::swap_stack(100, &[200, 300])
///     .via("192.168.1.1".parse()?)
///     .dev("eth0");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct MplsRouteBuilder {
    /// Incoming label.
    label: u32,
    /// Outgoing labels (empty for pop).
    out_labels: Vec<u32>,
    /// Output interface.
    dev: Option<InterfaceRef>,
    /// Next hop address.
    via: Option<IpAddr>,
}

impl MplsRouteBuilder {
    /// Create a pop route.
    ///
    /// Pops the label and forwards the packet as native IP.
    pub fn pop(label: u32) -> Self {
        Self {
            label,
            out_labels: Vec::new(),
            dev: None,
            via: None,
        }
    }

    /// Create a swap route with a single label.
    pub fn swap(in_label: u32, out_label: u32) -> Self {
        Self {
            label: in_label,
            out_labels: vec![out_label],
            dev: None,
            via: None,
        }
    }

    /// Create a swap route with a label stack.
    ///
    /// The labels are specified from outer to inner.
    pub fn swap_stack(in_label: u32, out_labels: &[u32]) -> Self {
        Self {
            label: in_label,
            out_labels: out_labels.to_vec(),
            dev: None,
            via: None,
        }
    }

    /// Set the output interface by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the output interface by index.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Set the next hop address.
    pub fn via(mut self, via: IpAddr) -> Self {
        self.via = Some(via);
        self
    }

    /// Write the netlink message with resolved interface index.
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder, ifindex: Option<u32>) {
        // MPLS routes use dst_len = 20 (label bit width), and the kernel
        // takes only the main table and unicast (`rtm_to_route_config`,
        // #678).
        let rtmsg = RtMsg::new()
            .with_family(AF_MPLS)
            .with_dst_len(20)
            .with_table(254)
            .with_type(1); // RTN_UNICAST

        builder.append(&rtmsg);

        // RTA_DST - incoming label
        let label_entry = MplsLabelEntry::bottom(self.label, 0);
        builder.append_attr(RtaAttr::Dst as u16, label_entry.as_bytes());

        // RTA_NEWDST - outgoing labels (for swap)
        if !self.out_labels.is_empty() {
            let mut label_data = Vec::with_capacity(self.out_labels.len() * 4);
            for (i, &label) in self.out_labels.iter().enumerate() {
                let is_bottom = i == self.out_labels.len() - 1;
                // No TTL in the entry: the kernel refuses one (#678).
                let entry = if is_bottom {
                    MplsLabelEntry::bottom(label, 0)
                } else {
                    MplsLabelEntry::new(label)
                };
                label_data.extend_from_slice(entry.as_bytes());
            }
            builder.append_attr(RtaAttr::Newdst as u16, &label_data);
        }

        // RTA_OIF - output interface
        if let Some(idx) = ifindex {
            builder.append_attr_u32(RtaAttr::Oif as u16, idx);
        }

        // RTA_VIA - next hop
        if let Some(via) = self.via {
            let mut via_data = Vec::new();
            match via {
                IpAddr::V4(addr) => {
                    via_data.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                    via_data.extend_from_slice(&addr.octets());
                }
                IpAddr::V6(addr) => {
                    via_data.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
                    via_data.extend_from_slice(&addr.octets());
                }
            }
            builder.append_attr(RtaAttr::Via as u16, &via_data);
        }
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Resolve MplsRouteBuilder interface reference.
    async fn resolve_mpls_interface(&self, builder: &MplsRouteBuilder) -> Result<Option<u32>> {
        match builder.device_ref() {
            Some(iface) => Ok(Some(self.resolve_interface(iface).await?)),
            None => Ok(None),
        }
    }

    /// Get all MPLS routes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let routes = conn.get_mpls_routes().await?;
    /// for route in &routes {
    ///     println!("Label {}: {:?}", route.label().0, route.action());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_mpls_routes"))]
    pub async fn get_mpls_routes(&self) -> Result<Vec<MplsRoute>> {
        let rtmsg = RtMsg::new().with_family(AF_MPLS);

        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&rtmsg);

        let responses = self.send_dump(builder).await?;

        let mut routes = Vec::new();
        for data in responses {
            if data.len() > NLMSG_HDRLEN
                && let Ok(route) = MplsRoute::parse(&data[NLMSG_HDRLEN..])
            {
                routes.push(route);
            }
        }

        Ok(routes)
    }

    /// Add an MPLS route.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::mpls::MplsRouteBuilder;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // Pop route
    /// conn.add_mpls_route(
    ///     MplsRouteBuilder::pop(100)
    ///         .dev("eth0")
    /// ).await?;
    ///
    /// // Swap route
    /// conn.add_mpls_route(
    ///     MplsRouteBuilder::swap(100, 200)
    ///         .via("192.168.1.1".parse()?)
    ///         .dev("eth0")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_mpls_route"))]
    pub async fn add_mpls_route(&self, route_builder: MplsRouteBuilder) -> Result<()> {
        let ifindex = self.resolve_mpls_interface(&route_builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        route_builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("add_mpls_route"))
    }

    /// Replace an MPLS route (add or update).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_mpls_route"))]
    pub async fn replace_mpls_route(&self, route_builder: MplsRouteBuilder) -> Result<()> {
        let ifindex = self.resolve_mpls_interface(&route_builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        route_builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("replace_mpls_route"))
    }

    /// Delete an MPLS route by label.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_mpls_route(100).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_mpls_route"))]
    pub async fn del_mpls_route(&self, label: u32) -> Result<()> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);

        // The main table and unicast, as the add sends them (#678).
        let rtmsg = RtMsg::new()
            .with_family(AF_MPLS)
            .with_dst_len(20)
            .with_table(254)
            .with_type(1);
        builder.append(&rtmsg);

        // RTA_DST with label
        let label_entry = MplsLabelEntry::bottom(label, 0);
        builder.append_attr(RtaAttr::Dst as u16, label_entry.as_bytes());

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_mpls_route"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_label_new() {
        assert!(MplsLabel::new(100).is_some());
        assert!(MplsLabel::new(mpls_label::MAX).is_some());
        assert!(MplsLabel::new(mpls_label::MAX + 1).is_none());
    }

    #[test]
    fn test_mpls_label_clamped() {
        assert_eq!(MplsLabel::new_clamped(100).0, 100);
        assert_eq!(MplsLabel::new_clamped(2_000_000).0, mpls_label::MAX);
    }

    #[test]
    fn test_mpls_label_reserved() {
        assert!(MplsLabel::IMPLICIT_NULL.is_reserved());
        assert!(MplsLabel::EXPLICIT_NULL_V4.is_reserved());
        assert!(!MplsLabel::new_clamped(100).is_reserved());
    }

    #[test]
    fn test_mpls_encap_single() {
        let encap = MplsEncap::new().label(100);
        assert_eq!(encap.get_labels().len(), 1);
        assert_eq!(encap.get_labels()[0].0, 100);
    }

    #[test]
    fn test_mpls_encap_stack() {
        let encap = MplsEncap::new().labels(&[100, 200, 300]);
        assert_eq!(encap.get_labels().len(), 3);
        assert_eq!(encap.get_labels()[0].0, 100);
        assert_eq!(encap.get_labels()[1].0, 200);
        assert_eq!(encap.get_labels()[2].0, 300);
    }

    /// The TTL goes in `MPLS_IPTUNNEL_TTL`, not in the label entry, which
    /// the kernel refuses with one (#678).
    #[test]
    fn test_mpls_encap_encode() {
        let encap = MplsEncap::new().label(100).ttl(64);
        let data = encap.encode_labels();
        assert_eq!(data.len(), 4);

        // Parse it back
        let entry = MplsLabelEntry::from_bytes(&data).unwrap();
        assert_eq!(entry.label(), 100);
        assert!(entry.is_bos());
        assert_eq!(entry.ttl(), 0);
        assert_eq!(encap.get_ttl(), Some(64));
    }

    #[test]
    fn test_mpls_encap_stack_encode() {
        let encap = MplsEncap::new().labels(&[100, 200]);
        let data = encap.encode_labels();
        assert_eq!(data.len(), 8);

        // First label
        let entry1 = MplsLabelEntry::from_bytes(&data[..4]).unwrap();
        assert_eq!(entry1.label(), 100);
        assert!(!entry1.is_bos());

        // Second label (bottom)
        let entry2 = MplsLabelEntry::from_bytes(&data[4..]).unwrap();
        assert_eq!(entry2.label(), 200);
        assert!(entry2.is_bos());
    }

    #[test]
    fn test_mpls_route_builder_pop() {
        let builder = MplsRouteBuilder::pop(100);
        assert_eq!(builder.label, 100);
        assert!(builder.out_labels.is_empty());
    }

    #[test]
    fn test_mpls_route_builder_swap() {
        let builder = MplsRouteBuilder::swap(100, 200);
        assert_eq!(builder.label, 100);
        assert_eq!(builder.out_labels, vec![200]);
    }

    #[test]
    fn test_mpls_route_builder_swap_stack() {
        let builder = MplsRouteBuilder::swap_stack(100, &[200, 300]);
        assert_eq!(builder.label, 100);
        assert_eq!(builder.out_labels, vec![200, 300]);
    }

    #[test]
    fn test_mpls_action() {
        assert!(MplsAction::Pop.is_pop());
        assert!(!MplsAction::Pop.is_swap());
        assert!(MplsAction::Swap(vec![MplsLabel(100)]).is_swap());
    }
}
