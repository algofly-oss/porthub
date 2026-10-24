//! SRv6 (Segment Routing over IPv6) routes and encapsulation.
//!
//! This module provides support for SRv6 (Segment Routing over IPv6), enabling
//! source-routed paths using IPv6 addresses as segment identifiers.
//!
//! # Prerequisites
//!
//! SRv6 support requires the following sysctl settings:
//!
//! ```bash
//! # Enable SRv6 globally
//! sudo sysctl -w net.ipv6.conf.all.seg6_enabled=1
//!
//! # Enable SRv6 on specific interfaces
//! sudo sysctl -w net.ipv6.conf.eth0.seg6_enabled=1
//! ```
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::net::Ipv4Addr;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::srv6::{Srv6Encap, Srv6LocalBuilder, Srv6Mode};
//! use nlink::netlink::route::Ipv4Route;
//! use std::net::Ipv6Addr;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // IPv4 route with SRv6 encapsulation (IPv4oIPv6)
//! conn.add_route(
//!     Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
//!         .dev("eth0")
//!         .srv6_encap(
//!             Srv6Encap::encap()
//!                 .segment("fc00:1::1".parse()?)
//!         )
//! ).await?;
//!
//! // SRv6 End.DT4 local SID (decap to VRF)
//! conn.add_srv6_local(
//!     Srv6LocalBuilder::end_dt4("fc00:1::100".parse()?, 100)
//!         .dev("eth0")
//! ).await?;
//!
//! // SRv6 End.X local SID (pop and forward)
//! conn.add_srv6_local(
//!     Srv6LocalBuilder::end_x("fc00:1::1".parse()?, "fe80::1".parse()?)
//!         .dev("eth0")
//! ).await?;
//!
//! // Query SRv6 local routes
//! let routes = conn.get_srv6_local_routes().await?;
//! for route in &routes {
//!     println!("SID {:?}: {:?}", route.sid, route.action);
//! }
//!
//! // Cleanup
//! conn.del_srv6_local("fc00:1::100".parse()?).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgType},
    protocol::Route,
    types::{
        mpls::lwtunnel_encap,
        route::{RtMsg, RtaAttr},
        srv6::{Ipv6SrHdr, seg6_iptunnel, seg6_local, seg6_local_action, seg6_mode},
    },
};

/// NLM_F_REPLACE flag.
const NLM_F_REPLACE: u16 = 0x100;

/// AF_INET6 address family.
const AF_INET6: u8 = 10;

// ============================================================================
// Srv6Mode
// ============================================================================

/// SRv6 encapsulation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Srv6Mode {
    /// Inline mode: insert SRH into existing IPv6 packet.
    Inline,
    /// Encap mode: encapsulate in new IPv6 header with SRH.
    #[default]
    Encap,
    /// L2 encap: encapsulate L2 frame.
    L2Encap,
    /// Encap with reduced SRH (first segment is destination).
    EncapRed,
    /// L2 encap with reduced SRH.
    L2EncapRed,
}

impl Srv6Mode {
    /// Convert to kernel value.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Inline => seg6_mode::INLINE,
            Self::Encap => seg6_mode::ENCAP,
            Self::L2Encap => seg6_mode::L2ENCAP,
            Self::EncapRed => seg6_mode::ENCAP_RED,
            Self::L2EncapRed => seg6_mode::L2ENCAP_RED,
        }
    }

    /// Parse from kernel value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            seg6_mode::INLINE => Some(Self::Inline),
            seg6_mode::ENCAP => Some(Self::Encap),
            seg6_mode::L2ENCAP => Some(Self::L2Encap),
            seg6_mode::ENCAP_RED => Some(Self::EncapRed),
            seg6_mode::L2ENCAP_RED => Some(Self::L2EncapRed),
            _ => None,
        }
    }
}

// ============================================================================
// Srv6Action
// ============================================================================

/// SRv6 local action types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Srv6Action {
    /// End: regular SID, pop and continue.
    End,
    /// End.X: pop and forward to specific IPv6 nexthop.
    EndX { nexthop: Ipv6Addr },
    /// End.T: pop and lookup in specific table.
    EndT { table: u32 },
    /// End.DX2: decap and forward L2 frame.
    EndDX2,
    /// End.DX4: decap and forward IPv4 packet.
    EndDX4 { nexthop: Option<Ipv4Addr> },
    /// End.DX6: decap and forward IPv6 packet.
    EndDX6 { nexthop: Option<Ipv6Addr> },
    /// End.DT4: decap and lookup IPv4 in table.
    EndDT4 { table: u32 },
    /// End.DT6: decap and lookup IPv6 in table.
    EndDT6 { table: u32 },
    /// End.DT46: decap and lookup IPv4 or IPv6 in table.
    EndDT46 { table: u32 },
    /// End.B6: insert SRH and forward.
    EndB6 { segments: Vec<Ipv6Addr> },
    /// End.B6.Encaps: encap with new header and SRH.
    EndB6Encaps { segments: Vec<Ipv6Addr> },
    /// End.BPF: BPF program.
    EndBPF,
    /// Unknown action.
    Unknown { action_type: u32 },
}

impl Srv6Action {
    /// Get the kernel action type value.
    pub fn action_type(&self) -> u32 {
        match self {
            Self::End => seg6_local_action::END,
            Self::EndX { .. } => seg6_local_action::END_X,
            Self::EndT { .. } => seg6_local_action::END_T,
            Self::EndDX2 => seg6_local_action::END_DX2,
            Self::EndDX4 { .. } => seg6_local_action::END_DX4,
            Self::EndDX6 { .. } => seg6_local_action::END_DX6,
            Self::EndDT4 { .. } => seg6_local_action::END_DT4,
            Self::EndDT6 { .. } => seg6_local_action::END_DT6,
            Self::EndDT46 { .. } => seg6_local_action::END_DT46,
            Self::EndB6 { .. } => seg6_local_action::END_B6,
            Self::EndB6Encaps { .. } => seg6_local_action::END_B6_ENCAP,
            Self::EndBPF => seg6_local_action::END_BPF,
            Self::Unknown { action_type } => *action_type,
        }
    }

    /// Get a human-readable name for the action.
    pub fn name(&self) -> &'static str {
        match self {
            Self::End => "End",
            Self::EndX { .. } => "End.X",
            Self::EndT { .. } => "End.T",
            Self::EndDX2 => "End.DX2",
            Self::EndDX4 { .. } => "End.DX4",
            Self::EndDX6 { .. } => "End.DX6",
            Self::EndDT4 { .. } => "End.DT4",
            Self::EndDT6 { .. } => "End.DT6",
            Self::EndDT46 { .. } => "End.DT46",
            Self::EndB6 { .. } => "End.B6",
            Self::EndB6Encaps { .. } => "End.B6.Encaps",
            Self::EndBPF => "End.BPF",
            Self::Unknown { .. } => "Unknown",
        }
    }
}

// ============================================================================
// Srv6Encap
// ============================================================================

/// SRv6 encapsulation for routes.
///
/// Used to encapsulate packets with an SRv6 header when forwarding.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::srv6::{Srv6Encap, Srv6Mode};
///
/// // Encap mode with single segment
/// let encap = Srv6Encap::encap()
///     .segment("fc00:1::1".parse()?);
///
/// // Inline mode with multiple segments
/// let encap = Srv6Encap::inline()
///     .segments(&[
///         "fc00:1::1".parse()?,
///         "fc00:2::1".parse()?,
///     ]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Srv6Encap {
    /// Encapsulation mode.
    mode: Srv6Mode,
    /// Segment list (first segment = final destination).
    segments: Vec<Ipv6Addr>,
}

impl Srv6Encap {
    /// Create a new SRv6 encapsulation with default (Encap) mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an encap mode encapsulation.
    ///
    /// Encap mode encapsulates the original packet in a new IPv6 header
    /// with an SRH extension header.
    pub fn encap() -> Self {
        Self {
            mode: Srv6Mode::Encap,
            segments: Vec::new(),
        }
    }

    /// Create an inline mode encapsulation.
    ///
    /// Inline mode inserts the SRH directly into an existing IPv6 packet.
    /// Only valid when the original packet is IPv6.
    pub fn inline() -> Self {
        Self {
            mode: Srv6Mode::Inline,
            segments: Vec::new(),
        }
    }

    /// Create an L2 encap mode encapsulation.
    ///
    /// L2 encap mode encapsulates L2 frames in an IPv6 header with SRH.
    pub fn l2_encap() -> Self {
        Self {
            mode: Srv6Mode::L2Encap,
            segments: Vec::new(),
        }
    }

    /// Set the encapsulation mode.
    pub fn mode(mut self, mode: Srv6Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Add a segment to the list.
    ///
    /// Segments are added in order from first to last. The first segment
    /// is the final destination.
    pub fn segment(mut self, seg: Ipv6Addr) -> Self {
        self.segments.push(seg);
        self
    }

    /// Add multiple segments to the list.
    pub fn segments(mut self, segs: &[Ipv6Addr]) -> Self {
        self.segments.extend_from_slice(segs);
        self
    }

    /// Check if the encapsulation has any segments.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Get the segment list.
    pub fn get_segments(&self) -> &[Ipv6Addr] {
        &self.segments
    }

    /// Get the encapsulation mode.
    pub fn get_mode(&self) -> Srv6Mode {
        self.mode
    }

    /// Build the SRH (Segment Routing Header) for netlink.
    ///
    /// The SRH format is:
    /// - Ipv6SrHdr (8 bytes)
    /// - Segments in reverse order (each 16 bytes)
    fn build_srh(&self) -> Vec<u8> {
        if self.segments.is_empty() {
            return Vec::new();
        }

        let num_segments = self.segments.len() as u8;
        let hdr = Ipv6SrHdr::new(num_segments);

        let mut data = Vec::with_capacity(Ipv6SrHdr::SIZE + self.segments.len() * 16);
        data.extend_from_slice(hdr.as_bytes());

        // Segments are stored in reverse order (last segment first in memory)
        for seg in self.segments.iter().rev() {
            data.extend_from_slice(&seg.octets());
        }

        data
    }

    /// Write the encapsulation to a message builder.
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder) {
        if self.segments.is_empty() {
            return;
        }

        // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6
        builder.append_attr_u16(RtaAttr::EncapType as u16, lwtunnel_encap::SEG6);

        // RTA_ENCAP (nested)
        let encap_nest = builder.nest_start(RtaAttr::Encap as u16);

        // SEG6_IPTUNNEL_SRH - contains mode (4 bytes) + SRH
        let mut srh_data = Vec::new();
        srh_data.extend_from_slice(&self.mode.to_u32().to_ne_bytes());
        srh_data.extend_from_slice(&self.build_srh());
        builder.append_attr(seg6_iptunnel::SRH, &srh_data);

        builder.nest_end(encap_nest);
    }
}

// ============================================================================
// Srv6LocalRoute
// ============================================================================

/// A parsed SRv6 local route (segment endpoint behavior).
#[derive(Debug, Clone)]
pub struct Srv6LocalRoute {
    /// Local SID (segment identifier).
    pub sid: Ipv6Addr,
    /// Prefix length (usually 128 for exact SID).
    pub prefix_len: u8,
    /// Action to perform.
    pub action: Srv6Action,
    /// Output interface index.
    pub oif: Option<u32>,
    /// Input interface index.
    pub iif: Option<u32>,
    /// Route protocol.
    pub protocol: u8,
}

impl Srv6LocalRoute {
    /// The routing table this SID directs traffic into, if the
    /// action carries one.
    ///
    /// SRv6 endpoint actions split into two groups:
    ///
    /// - Variants that look traffic up in a specific table:
    ///   `EndT`, `EndDT4`, `EndDT6`, `EndDT46`. Returns
    ///   `Some(table_id)`.
    /// - Variants that don't (deliver direct, push, decap to
    ///   default table, etc.): `End`, `EndX`, `EndDX2`,
    ///   `EndDX4`, `EndDX6`, `B6`, `B6Encaps`, …. Returns
    ///   `None`.
    ///
    /// This getter encapsulates the per-variant match so
    /// callers asking "what table is this SID in?" don't need
    /// to enumerate the action enum themselves.
    pub fn table(&self) -> Option<u32> {
        match &self.action {
            Srv6Action::EndT { table }
            | Srv6Action::EndDT4 { table }
            | Srv6Action::EndDT6 { table }
            | Srv6Action::EndDT46 { table } => Some(*table),
            _ => None,
        }
    }

    /// Parse an SRv6 local route from netlink message payload.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < RtMsg::SIZE {
            return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: RtMsg::SIZE,
                actual: data.len(),
            }));
        }

        let rtmsg = RtMsg::from_bytes(data)?;
        let attrs_data = &data[RtMsg::SIZE..];

        let mut sid = Ipv6Addr::UNSPECIFIED;
        let mut action_type = 0u32;
        let mut table = None;
        let mut nh4 = None;
        let mut nh6 = None;
        let mut oif = None;
        let mut iif = None;
        let mut srh_segments = Vec::new();

        // First pass: get encap attributes
        for (attr_type, payload) in AttrIter::new(attrs_data) {
            match RtaAttr::from(attr_type) {
                RtaAttr::Dst if payload.len() >= 16 => {
                    let bytes: [u8; 16] = payload[..16].try_into().unwrap_or([0; 16]);
                    sid = Ipv6Addr::from(bytes);
                }
                RtaAttr::Oif if payload.len() >= 4 => {
                    oif = Some(u32::from_ne_bytes(
                        payload[..4].try_into().unwrap_or([0; 4]),
                    ));
                }
                RtaAttr::Iif if payload.len() >= 4 => {
                    iif = Some(u32::from_ne_bytes(
                        payload[..4].try_into().unwrap_or([0; 4]),
                    ));
                }
                RtaAttr::Encap => {
                    // Parse nested seg6_local attributes
                    for (local_attr, local_payload) in AttrIter::new(payload) {
                        match local_attr {
                            x if x == seg6_local::ACTION && local_payload.len() >= 4 => {
                                action_type = u32::from_ne_bytes(
                                    local_payload[..4].try_into().unwrap_or([0; 4]),
                                );
                            }
                            x if x == seg6_local::TABLE && local_payload.len() >= 4 => {
                                table = Some(u32::from_ne_bytes(
                                    local_payload[..4].try_into().unwrap_or([0; 4]),
                                ));
                            }
                            x if x == seg6_local::NH4 && local_payload.len() >= 4 => {
                                let bytes: [u8; 4] =
                                    local_payload[..4].try_into().unwrap_or([0; 4]);
                                nh4 = Some(Ipv4Addr::from(bytes));
                            }
                            x if x == seg6_local::NH6 && local_payload.len() >= 16 => {
                                let bytes: [u8; 16] =
                                    local_payload[..16].try_into().unwrap_or([0; 16]);
                                nh6 = Some(Ipv6Addr::from(bytes));
                            }
                            x if x == seg6_local::SRH
                                // Parse SRH: skip mode (4 bytes) + header (8 bytes)
                                && local_payload.len() >= 12 =>
                            {
                                let srh_data = &local_payload[4..];
                                if let Some(hdr) = Ipv6SrHdr::from_bytes(srh_data) {
                                    let seg_data = &srh_data[Ipv6SrHdr::SIZE..];
                                    let num_segs = (hdr.first_segment as usize) + 1;
                                    for i in 0..num_segs {
                                        let offset = i * 16;
                                        if offset + 16 <= seg_data.len() {
                                            let bytes: [u8; 16] = seg_data[offset..offset + 16]
                                                .try_into()
                                                .unwrap_or([0; 16]);
                                            srh_segments.push(Ipv6Addr::from(bytes));
                                        }
                                    }
                                    // Reverse to get original order
                                    srh_segments.reverse();
                                }
                            }
                            x if x == seg6_local::OIF && local_payload.len() >= 4 => {
                                oif = Some(u32::from_ne_bytes(
                                    local_payload[..4].try_into().unwrap_or([0; 4]),
                                ));
                            }
                            x if x == seg6_local::IIF && local_payload.len() >= 4 => {
                                iif = Some(u32::from_ne_bytes(
                                    local_payload[..4].try_into().unwrap_or([0; 4]),
                                ));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        // Build the action from parsed attributes
        let action = match action_type {
            seg6_local_action::END => Srv6Action::End,
            seg6_local_action::END_X => Srv6Action::EndX {
                nexthop: nh6.unwrap_or(Ipv6Addr::UNSPECIFIED),
            },
            seg6_local_action::END_T => Srv6Action::EndT {
                table: table.unwrap_or(0),
            },
            seg6_local_action::END_DX2 => Srv6Action::EndDX2,
            seg6_local_action::END_DX4 => Srv6Action::EndDX4 { nexthop: nh4 },
            seg6_local_action::END_DX6 => Srv6Action::EndDX6 { nexthop: nh6 },
            seg6_local_action::END_DT4 => Srv6Action::EndDT4 {
                table: table.unwrap_or(0),
            },
            seg6_local_action::END_DT6 => Srv6Action::EndDT6 {
                table: table.unwrap_or(0),
            },
            seg6_local_action::END_DT46 => Srv6Action::EndDT46 {
                table: table.unwrap_or(0),
            },
            seg6_local_action::END_B6 => Srv6Action::EndB6 {
                segments: srh_segments.clone(),
            },
            seg6_local_action::END_B6_ENCAP => Srv6Action::EndB6Encaps {
                segments: srh_segments,
            },
            seg6_local_action::END_BPF => Srv6Action::EndBPF,
            _ => Srv6Action::Unknown { action_type },
        };

        Ok(Self {
            sid,
            prefix_len: rtmsg.rtm_dst_len,
            action,
            oif,
            iif,
            protocol: rtmsg.rtm_protocol,
        })
    }
}

// ============================================================================
// Srv6LocalBuilder
// ============================================================================

/// Builder for SRv6 local routes.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::srv6::Srv6LocalBuilder;
///
/// // End action (simple transit)
/// let route = Srv6LocalBuilder::end("fc00:1::1".parse()?)
///     .dev("eth0");
///
/// // End.X action (pop and forward)
/// let route = Srv6LocalBuilder::end_x(
///     "fc00:1::1".parse()?,
///     "fe80::1".parse()?,
/// ).dev("eth0");
///
/// // End.DT4 action (decap and lookup IPv4)
/// let route = Srv6LocalBuilder::end_dt4("fc00:1::100".parse()?, 100)
///     .dev("eth0");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Srv6LocalBuilder {
    /// Local SID.
    sid: Ipv6Addr,
    /// Action type.
    action: Srv6Action,
    /// Output interface (by name or index).
    dev: Option<InterfaceRef>,
}

impl Srv6LocalBuilder {
    /// Create an End action route.
    ///
    /// End action: pop the SRH segment and continue routing based on
    /// the next segment or the IPv6 destination.
    pub fn end(sid: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::End,
            dev: None,
        }
    }

    /// Create an End.X action route.
    ///
    /// End.X action: pop the SRH segment and forward to the specified
    /// IPv6 next hop via the specified interface.
    pub fn end_x(sid: Ipv6Addr, nexthop: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndX { nexthop },
            dev: None,
        }
    }

    /// Create an End.T action route.
    ///
    /// End.T action: pop the SRH segment and lookup the next segment
    /// in the specified routing table.
    pub fn end_t(sid: Ipv6Addr, table: u32) -> Self {
        Self {
            sid,
            action: Srv6Action::EndT { table },
            dev: None,
        }
    }

    /// Create an End.DX2 action route.
    ///
    /// End.DX2 action: decapsulate and forward as L2 frame.
    pub fn end_dx2(sid: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDX2,
            dev: None,
        }
    }

    /// Create an End.DX4 action route.
    ///
    /// End.DX4 action: decapsulate and forward the IPv4 packet.
    /// Optionally specify a next hop.
    pub fn end_dx4(sid: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDX4 { nexthop: None },
            dev: None,
        }
    }

    /// Create an End.DX4 action route with nexthop.
    pub fn end_dx4_via(sid: Ipv6Addr, nexthop: Ipv4Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDX4 {
                nexthop: Some(nexthop),
            },
            dev: None,
        }
    }

    /// Create an End.DX6 action route.
    ///
    /// End.DX6 action: decapsulate and forward the IPv6 packet.
    /// Optionally specify a next hop.
    pub fn end_dx6(sid: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDX6 { nexthop: None },
            dev: None,
        }
    }

    /// Create an End.DX6 action route with nexthop.
    pub fn end_dx6_via(sid: Ipv6Addr, nexthop: Ipv6Addr) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDX6 {
                nexthop: Some(nexthop),
            },
            dev: None,
        }
    }

    /// Create an End.DT4 action route.
    ///
    /// End.DT4 action: decapsulate and lookup the IPv4 packet in
    /// the specified routing table.
    pub fn end_dt4(sid: Ipv6Addr, table: u32) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDT4 { table },
            dev: None,
        }
    }

    /// Create an End.DT6 action route.
    ///
    /// End.DT6 action: decapsulate and lookup the IPv6 packet in
    /// the specified routing table.
    pub fn end_dt6(sid: Ipv6Addr, table: u32) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDT6 { table },
            dev: None,
        }
    }

    /// Create an End.DT46 action route.
    ///
    /// End.DT46 action: decapsulate and lookup either IPv4 or IPv6
    /// in the specified routing table.
    pub fn end_dt46(sid: Ipv6Addr, table: u32) -> Self {
        Self {
            sid,
            action: Srv6Action::EndDT46 { table },
            dev: None,
        }
    }

    /// Create an End.B6 action route.
    ///
    /// End.B6 action: insert SRH and forward to binding SID.
    pub fn end_b6(sid: Ipv6Addr, segments: &[Ipv6Addr]) -> Self {
        Self {
            sid,
            action: Srv6Action::EndB6 {
                segments: segments.to_vec(),
            },
            dev: None,
        }
    }

    /// Create an End.B6.Encaps action route.
    ///
    /// End.B6.Encaps action: encapsulate with new IPv6 header and SRH.
    pub fn end_b6_encaps(sid: Ipv6Addr, segments: &[Ipv6Addr]) -> Self {
        Self {
            sid,
            action: Srv6Action::EndB6Encaps {
                segments: segments.to_vec(),
            },
            dev: None,
        }
    }

    /// Set the output interface by name.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the output interface by index.
    pub fn oif(mut self, oif: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(oif));
        self
    }

    /// Get a reference to the interface reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Build an SRH for B6 actions.
    fn build_srh(segments: &[Ipv6Addr]) -> Vec<u8> {
        if segments.is_empty() {
            return Vec::new();
        }

        let num_segments = segments.len() as u8;
        let hdr = Ipv6SrHdr::new(num_segments);

        let mut data = Vec::with_capacity(Ipv6SrHdr::SIZE + segments.len() * 16);
        data.extend_from_slice(hdr.as_bytes());

        // Segments in reverse order
        for seg in segments.iter().rev() {
            data.extend_from_slice(&seg.octets());
        }

        data
    }

    /// Write the SRv6 local route to a message builder.
    ///
    /// The `ifindex` parameter should be the resolved interface index
    /// (if any interface was specified).
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder, ifindex: Option<u32>) {
        // SRv6 local routes are IPv6 routes with encap type SEG6_LOCAL
        let rtmsg = RtMsg::new()
            .with_family(AF_INET6)
            .with_dst_len(128) // Full SID
            .with_type(1); // RTN_UNICAST

        builder.append(&rtmsg);

        // RTA_DST - the SID
        builder.append_attr(RtaAttr::Dst as u16, &self.sid.octets());

        // RTA_OIF - output interface
        if let Some(idx) = ifindex {
            builder.append_attr_u32(RtaAttr::Oif as u16, idx);
        }

        // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL
        builder.append_attr_u16(RtaAttr::EncapType as u16, lwtunnel_encap::SEG6_LOCAL);

        // RTA_ENCAP (nested seg6_local attributes)
        let encap_nest = builder.nest_start(RtaAttr::Encap as u16);

        // SEG6_LOCAL_ACTION
        builder.append_attr_u32(seg6_local::ACTION, self.action.action_type());

        // Action-specific attributes
        match &self.action {
            Srv6Action::EndX { nexthop } => {
                builder.append_attr(seg6_local::NH6, &nexthop.octets());
            }
            Srv6Action::EndT { table } => {
                builder.append_attr_u32(seg6_local::TABLE, *table);
            }
            Srv6Action::EndDX4 { nexthop } => {
                if let Some(nh) = nexthop {
                    builder.append_attr(seg6_local::NH4, &nh.octets());
                }
            }
            Srv6Action::EndDX6 { nexthop } => {
                if let Some(nh) = nexthop {
                    builder.append_attr(seg6_local::NH6, &nh.octets());
                }
            }
            Srv6Action::EndDT4 { table }
            | Srv6Action::EndDT6 { table }
            | Srv6Action::EndDT46 { table } => {
                builder.append_attr_u32(seg6_local::TABLE, *table);
            }
            Srv6Action::EndB6 { segments } | Srv6Action::EndB6Encaps { segments } => {
                if !segments.is_empty() {
                    // SEG6_LOCAL_SRH: mode (4 bytes) + SRH
                    let mut srh_data = Vec::new();
                    srh_data.extend_from_slice(&seg6_mode::ENCAP.to_ne_bytes());
                    srh_data.extend_from_slice(&Self::build_srh(segments));
                    builder.append_attr(seg6_local::SRH, &srh_data);
                }
            }
            Srv6Action::End
            | Srv6Action::EndDX2
            | Srv6Action::EndBPF
            | Srv6Action::Unknown { .. } => {}
        }

        builder.nest_end(encap_nest);
    }
}

// ============================================================================
// Connection Methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Resolve interface for SRv6 local builder.
    async fn resolve_srv6_interface(&self, builder: &Srv6LocalBuilder) -> Result<Option<u32>> {
        match builder.device_ref() {
            Some(iface_ref) => Ok(Some(self.resolve_interface(iface_ref).await?)),
            None => Ok(None),
        }
    }

    /// Get all SRv6 local routes.
    ///
    /// Returns routes that use LWTUNNEL_ENCAP_SEG6_LOCAL encapsulation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let routes = conn.get_srv6_local_routes().await?;
    /// for route in &routes {
    ///     println!("SID {:?}: {:?}", route.sid, route.action);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_srv6_local_routes"))]
    pub async fn get_srv6_local_routes(&self) -> Result<Vec<Srv6LocalRoute>> {
        let rtmsg = RtMsg::new().with_family(AF_INET6);

        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&rtmsg);

        let responses = self.send_dump(builder).await?;

        let mut routes = Vec::new();
        for data in responses {
            if data.len() <= NLMSG_HDRLEN {
                continue;
            }

            let payload = &data[NLMSG_HDRLEN..];

            // Check if this is an SRv6 local route
            let mut is_srv6_local = false;
            if payload.len() >= RtMsg::SIZE {
                for (attr_type, attr_payload) in AttrIter::new(&payload[RtMsg::SIZE..]) {
                    if RtaAttr::from(attr_type) == RtaAttr::EncapType && attr_payload.len() >= 2 {
                        let encap_type =
                            u16::from_ne_bytes(attr_payload[..2].try_into().unwrap_or([0; 2]));
                        if encap_type == lwtunnel_encap::SEG6_LOCAL {
                            is_srv6_local = true;
                            break;
                        }
                    }
                }
            }

            if is_srv6_local && let Ok(route) = Srv6LocalRoute::parse(payload) {
                routes.push(route);
            }
        }

        Ok(routes)
    }

    /// Add an SRv6 local route.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::srv6::Srv6LocalBuilder;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// // End.DT4 SID
    /// conn.add_srv6_local(
    ///     Srv6LocalBuilder::end_dt4("fc00:1::100".parse()?, 100)
    ///         .dev("eth0")
    /// ).await?;
    ///
    /// // End.X SID
    /// conn.add_srv6_local(
    ///     Srv6LocalBuilder::end_x("fc00:1::1".parse()?, "fe80::1".parse()?)
    ///         .dev("eth0")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_srv6_local"))]
    pub async fn add_srv6_local(&self, builder: Srv6LocalBuilder) -> Result<()> {
        let ifindex = self.resolve_srv6_interface(&builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("add_srv6_local"))
    }

    /// Replace an SRv6 local route (add or update).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_srv6_local"))]
    pub async fn replace_srv6_local(&self, builder: Srv6LocalBuilder) -> Result<()> {
        let ifindex = self.resolve_srv6_interface(&builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("replace_srv6_local"))
    }

    /// Delete an SRv6 local route by SID.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// conn.del_srv6_local("fc00:1::100".parse()?).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_srv6_local"))]
    pub async fn del_srv6_local(&self, sid: Ipv6Addr) -> Result<()> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);

        let rtmsg = RtMsg::new().with_family(AF_INET6).with_dst_len(128);
        builder.append(&rtmsg);

        // RTA_DST with SID
        builder.append_attr(RtaAttr::Dst as u16, &sid.octets());

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_srv6_local"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_mode() {
        assert_eq!(Srv6Mode::Encap.to_u32(), seg6_mode::ENCAP);
        assert_eq!(Srv6Mode::Inline.to_u32(), seg6_mode::INLINE);
        assert_eq!(Srv6Mode::from_u32(seg6_mode::ENCAP), Some(Srv6Mode::Encap));
    }

    #[test]
    fn test_srv6_encap_empty() {
        let encap = Srv6Encap::encap();
        assert!(encap.is_empty());
    }

    #[test]
    fn test_srv6_encap_single_segment() {
        let seg: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let encap = Srv6Encap::encap().segment(seg);
        assert!(!encap.is_empty());
        assert_eq!(encap.get_segments().len(), 1);
        assert_eq!(encap.get_segments()[0], seg);
    }

    #[test]
    fn test_srv6_encap_multiple_segments() {
        let seg1: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let seg2: Ipv6Addr = "fc00:2::1".parse().unwrap();
        let encap = Srv6Encap::encap().segments(&[seg1, seg2]);
        assert_eq!(encap.get_segments().len(), 2);
    }

    #[test]
    fn test_srv6_encap_build_srh() {
        let seg: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let encap = Srv6Encap::encap().segment(seg);
        let srh = encap.build_srh();
        // Header (8) + 1 segment (16) = 24 bytes
        assert_eq!(srh.len(), 24);
    }

    #[test]
    fn srv6_local_route_table_getter() {
        let sid: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let mk = |action| Srv6LocalRoute {
            sid,
            prefix_len: 128,
            action,
            oif: None,
            iif: None,
            protocol: 3,
        };

        // Variants WITH table → Some.
        assert_eq!(mk(Srv6Action::EndT { table: 100 }).table(), Some(100));
        assert_eq!(
            mk(Srv6Action::EndDT4 { table: 200 }).table(),
            Some(200),
        );
        assert_eq!(
            mk(Srv6Action::EndDT6 { table: 300 }).table(),
            Some(300),
        );
        assert_eq!(
            mk(Srv6Action::EndDT46 { table: 400 }).table(),
            Some(400),
        );

        // Variants WITHOUT table → None.
        assert_eq!(mk(Srv6Action::End).table(), None);
        assert_eq!(
            mk(Srv6Action::EndX {
                nexthop: Ipv6Addr::UNSPECIFIED,
            })
            .table(),
            None,
        );
    }

    #[test]
    fn test_srv6_action_names() {
        assert_eq!(Srv6Action::End.name(), "End");
        assert_eq!(
            Srv6Action::EndX {
                nexthop: Ipv6Addr::UNSPECIFIED
            }
            .name(),
            "End.X"
        );
        assert_eq!(Srv6Action::EndDT4 { table: 100 }.name(), "End.DT4");
    }

    #[test]
    fn test_srv6_local_builder_end() {
        let sid: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let builder = Srv6LocalBuilder::end(sid);
        assert_eq!(builder.sid, sid);
        assert!(matches!(builder.action, Srv6Action::End));
    }

    #[test]
    fn test_srv6_local_builder_end_dt4() {
        let sid: Ipv6Addr = "fc00:1::100".parse().unwrap();
        let builder = Srv6LocalBuilder::end_dt4(sid, 100);
        assert!(matches!(builder.action, Srv6Action::EndDT4 { table: 100 }));
    }

    #[test]
    fn test_srv6_local_builder_end_x() {
        let sid: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let nh: Ipv6Addr = "fe80::1".parse().unwrap();
        let builder = Srv6LocalBuilder::end_x(sid, nh);
        assert!(matches!(builder.action, Srv6Action::EndX { nexthop } if nexthop == nh));
    }

    #[test]
    fn test_srv6_local_builder_with_dev() {
        let sid: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let builder = Srv6LocalBuilder::end(sid).dev("eth0");
        assert_eq!(builder.dev, Some(InterfaceRef::Name("eth0".to_string())));
    }

    #[test]
    fn test_srv6_local_builder_with_oif() {
        let sid: Ipv6Addr = "fc00:1::1".parse().unwrap();
        let builder = Srv6LocalBuilder::end(sid).oif(5);
        assert_eq!(builder.dev, Some(InterfaceRef::Index(5)));
    }
}
