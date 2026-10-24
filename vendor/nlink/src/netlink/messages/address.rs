//! Strongly-typed address message.

use std::net::IpAddr;

use winnow::{prelude::*, token::take};

use crate::netlink::{
    error::Result,
    parse::{FromNetlink, PResult, ToNetlink, parse_ip_addr, parse_string_from_bytes},
    types::addr::{IfAddrMsg, IfaCacheinfo, Scope},
};

/// Attribute IDs for IFA_* constants.
mod attr_ids {
    pub const IFA_ADDRESS: u16 = 1;
    pub const IFA_LOCAL: u16 = 2;
    pub const IFA_LABEL: u16 = 3;
    pub const IFA_BROADCAST: u16 = 4;
    pub const IFA_ANYCAST: u16 = 5;
    pub const IFA_CACHEINFO: u16 = 6;
    pub const IFA_FLAGS: u16 = 8;
    pub const IFA_RT_PRIORITY: u16 = 9;
}

/// Strongly-typed address message with all attributes parsed.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AddressMessage {
    /// Fixed-size header.
    pub(crate) header: IfAddrMsg,
    /// Address (IFA_ADDRESS).
    pub(crate) address: Option<IpAddr>,
    /// Local address (IFA_LOCAL).
    pub(crate) local: Option<IpAddr>,
    /// Interface label (IFA_LABEL).
    pub(crate) label: Option<String>,
    /// Broadcast address (IFA_BROADCAST).
    pub(crate) broadcast: Option<IpAddr>,
    /// Anycast address (IFA_ANYCAST).
    pub(crate) anycast: Option<IpAddr>,
    /// Extended flags (IFA_FLAGS).
    pub(crate) flags: Option<u32>,
    /// Cache info (IFA_CACHEINFO) - preferred/valid lifetimes.
    pub(crate) cache_info: Option<AddressCacheInfo>,
    /// The metric of the prefix route (IFA_RT_PRIORITY).
    pub(crate) rt_priority: Option<u32>,
}

/// Address cache information.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddressCacheInfo {
    /// Preferred lifetime in seconds.
    pub preferred: u32,
    /// Valid lifetime in seconds.
    pub valid: u32,
    /// Creation timestamp.
    pub created: u32,
    /// Last update timestamp.
    pub updated: u32,
}

impl AddressMessage {
    /// Create a new empty address message.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Accessor methods
    // =========================================================================

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.ifa_family
    }

    /// Get the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.header.ifa_prefixlen
    }

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.header.ifa_index
    }

    /// Get the scope.
    pub fn scope(&self) -> Scope {
        Scope::from(self.header.ifa_scope)
    }

    /// Get the address.
    pub fn address(&self) -> Option<&IpAddr> {
        self.address.as_ref()
    }

    /// Get the local address.
    pub fn local(&self) -> Option<&IpAddr> {
        self.local.as_ref()
    }

    /// Get the interface label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Get the broadcast address.
    pub fn broadcast(&self) -> Option<&IpAddr> {
        self.broadcast.as_ref()
    }

    /// Get the anycast address.
    pub fn anycast(&self) -> Option<&IpAddr> {
        self.anycast.as_ref()
    }

    /// Get the extended flags.
    pub fn flags(&self) -> u32 {
        self.flags.unwrap_or(self.header.ifa_flags as u32)
    }

    /// Get the cache info.
    pub fn cache_info(&self) -> Option<&AddressCacheInfo> {
        self.cache_info.as_ref()
    }

    /// The metric of the prefix route the address installs
    /// (`IFA_RT_PRIORITY`, `ip addr … metric N`); `None` when it was added
    /// without one.
    pub fn metric(&self) -> Option<u32> {
        self.rt_priority
    }

    /// The peer of a point-to-point address (`ip addr add A peer P`): the
    /// kernel then reports the local address as `IFA_LOCAL` and the peer
    /// as `IFA_ADDRESS`. `None` for an ordinary address.
    pub fn peer(&self) -> Option<&IpAddr> {
        match (&self.local, &self.address) {
            (Some(local), Some(address)) if local != address => Some(address),
            _ => None,
        }
    }

    /// Get the primary address (local or address).
    ///
    /// For point-to-point links, `local` is the local address and `address` is
    /// the peer address. For other links, they are typically the same.
    pub fn primary_address(&self) -> Option<&IpAddr> {
        self.local.as_ref().or(self.address.as_ref())
    }

    // =========================================================================
    // Boolean checks
    // =========================================================================

    /// Check if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        self.header.ifa_family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        self.header.ifa_family == libc::AF_INET6 as u8
    }

    /// Check if this is a secondary/temporary address.
    pub fn is_secondary(&self) -> bool {
        self.flags() & 0x01 != 0 // IFA_F_SECONDARY
    }

    /// Check if this is a permanent address.
    pub fn is_permanent(&self) -> bool {
        self.flags() & 0x80 != 0 // IFA_F_PERMANENT
    }

    /// Check if this address is deprecated.
    pub fn is_deprecated(&self) -> bool {
        self.flags() & 0x20 != 0 // IFA_F_DEPRECATED
    }

    /// Check if this address is tentative: IPv6 duplicate address
    /// detection has not finished, and the address cannot be used yet.
    pub fn is_tentative(&self) -> bool {
        self.flags() & 0x40 != 0 // IFA_F_TENTATIVE
    }

    /// Check if duplicate address detection found this address in use
    /// elsewhere on the link (`IFA_F_DADFAILED`). It stays tentative, and
    /// never becomes usable (#524).
    pub fn is_dad_failed(&self) -> bool {
        self.flags() & 0x08 != 0 // IFA_F_DADFAILED
    }

    /// Check if this is an optimistic address (`IFA_F_OPTIMISTIC`, RFC
    /// 4429): usable while duplicate address detection is still running
    /// (#524).
    pub fn is_optimistic(&self) -> bool {
        self.flags() & 0x04 != 0 // IFA_F_OPTIMISTIC
    }
}

impl FromNetlink for AddressMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETADDR requires an IfAddrMsg header
        let header = IfAddrMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (8 bytes)
        if input.len() < IfAddrMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(IfAddrMsg::SIZE).parse_next(input)?;
        let header = *IfAddrMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = AddressMessage {
            header,
            ..Default::default()
        };

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

            // Match attribute type (mask out flags)
            match attr_type & 0x3FFF {
                attr_ids::IFA_ADDRESS => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.ifa_family) {
                        msg.address = Some(addr);
                    }
                }
                attr_ids::IFA_LOCAL => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.ifa_family) {
                        msg.local = Some(addr);
                    }
                }
                attr_ids::IFA_LABEL => {
                    msg.label = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::IFA_BROADCAST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.ifa_family) {
                        msg.broadcast = Some(addr);
                    }
                }
                attr_ids::IFA_ANYCAST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, header.ifa_family) {
                        msg.anycast = Some(addr);
                    }
                }
                attr_ids::IFA_FLAGS if attr_data.len() >= 4 => {
                    let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                    msg.flags = Some(u32::from_ne_bytes(bytes));
                }
                attr_ids::IFA_RT_PRIORITY if attr_data.len() >= 4 => {
                    let bytes: [u8; 4] = attr_data[..4].try_into().unwrap();
                    msg.rt_priority = Some(u32::from_ne_bytes(bytes));
                }
                attr_ids::IFA_CACHEINFO => {
                    if let Some(info) = IfaCacheinfo::from_bytes(attr_data) {
                        msg.cache_info = Some(AddressCacheInfo {
                            preferred: info.ifa_prefered,
                            valid: info.ifa_valid,
                            created: info.cstamp,
                            updated: info.tstamp,
                        });
                    }
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

impl ToNetlink for AddressMessage {
    fn netlink_len(&self) -> usize {
        let mut len = IfAddrMsg::SIZE;

        if self.address.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if self.local.is_some() {
            len += nla_size(if self.is_ipv4() { 4 } else { 16 });
        }
        if let Some(ref label) = self.label {
            len += nla_size(label.len() + 1);
        }
        if self.broadcast.is_some() {
            len += nla_size(4); // Only IPv4
        }
        if self.flags.is_some() {
            len += nla_size(4);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref addr) = self.address {
            write_attr(buf, attr_ids::IFA_ADDRESS, addr)?;
        }
        if let Some(ref addr) = self.local {
            write_attr(buf, attr_ids::IFA_LOCAL, addr)?;
        }
        if let Some(ref label) = self.label {
            write_attr_str(buf, attr_ids::IFA_LABEL, label);
        }
        if let Some(ref addr) = self.broadcast {
            write_attr(buf, attr_ids::IFA_BROADCAST, addr)?;
        }
        if let Some(flags) = self.flags {
            write_attr(buf, attr_ids::IFA_FLAGS, &flags)?;
        }

        Ok(buf.len() - start)
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

/// Write a string attribute to a buffer.
fn write_attr_str(buf: &mut Vec<u8>, attr_type: u16, value: &str) {
    let payload_len = value.len() + 1; // Include null terminator
    let len = 4 + payload_len;

    // Write header
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());

    // Write payload
    buf.extend_from_slice(value.as_bytes());
    buf.push(0); // Null terminator

    // Add padding
    let aligned = (len + 3) & !3;
    let padding = aligned - len;
    for _ in 0..padding {
        buf.push(0);
    }
}

/// Write a netlink attribute to a buffer.
fn write_attr<T: ToNetlink>(buf: &mut Vec<u8>, attr_type: u16, value: &T) -> Result<()> {
    let payload_len = value.netlink_len();
    let len = 4 + payload_len;

    // Write header
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());

    // Write payload
    value.write_to(buf)?;

    // Add padding
    let aligned = (len + 3) & !3;
    let padding = aligned - len;
    for _ in 0..padding {
        buf.push(0);
    }

    Ok(())
}

/// Builder for constructing AddressMessage.
#[derive(Debug, Clone, Default)]
pub struct AddressMessageBuilder {
    msg: AddressMessage,
}

impl AddressMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family to IPv4.
    pub fn ipv4(mut self) -> Self {
        self.msg.header.ifa_family = libc::AF_INET as u8;
        self
    }

    /// Set the address family to IPv6.
    pub fn ipv6(mut self) -> Self {
        self.msg.header.ifa_family = libc::AF_INET6 as u8;
        self
    }

    /// Set the interface index.
    pub fn ifindex(mut self, index: u32) -> Self {
        self.msg.header.ifa_index = index;
        self
    }

    /// Set the prefix length.
    pub fn prefix_len(mut self, len: u8) -> Self {
        self.msg.header.ifa_prefixlen = len;
        self
    }

    /// Set the scope.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.msg.header.ifa_scope = scope as u8;
        self
    }

    /// Set the address.
    pub fn address(mut self, addr: IpAddr) -> Self {
        // Auto-detect family
        match addr {
            IpAddr::V4(_) => self.msg.header.ifa_family = libc::AF_INET as u8,
            IpAddr::V6(_) => self.msg.header.ifa_family = libc::AF_INET6 as u8,
        }
        self.msg.address = Some(addr);
        self
    }

    /// Set the local address.
    pub fn local(mut self, addr: IpAddr) -> Self {
        self.msg.local = Some(addr);
        self
    }

    /// Set the label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.msg.label = Some(label.into());
        self
    }

    /// Set the broadcast address.
    pub fn broadcast(mut self, addr: IpAddr) -> Self {
        self.msg.broadcast = Some(addr);
        self
    }

    /// Set flags.
    pub fn flags(mut self, flags: u32) -> Self {
        self.msg.flags = Some(flags);
        self
    }

    /// Build the message.
    pub fn build(self) -> AddressMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    /// `IFA_F_DADFAILED` and `IFA_F_OPTIMISTIC` are read from the flags
    /// (#524).
    #[test]
    fn dad_failed_and_optimistic_flags() {
        let with = |flags| AddressMessageBuilder::new().flags(flags).build();
        assert!(with(0x08 | 0x40).is_dad_failed());
        assert!(with(0x08 | 0x40).is_tentative());
        assert!(with(0x04).is_optimistic());
        assert!(!with(0x80).is_dad_failed() && !with(0x80).is_optimistic());
    }

    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_builder() {
        let msg = AddressMessageBuilder::new()
            .ifindex(2)
            .prefix_len(24)
            .scope(Scope::Universe)
            .address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .local(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .label("eth0")
            .build();

        assert_eq!(msg.ifindex(), 2);
        assert_eq!(msg.prefix_len(), 24);
        assert!(msg.is_ipv4());
        assert_eq!(msg.label, Some("eth0".to_string()));
    }

    #[test]
    fn test_roundtrip() {
        let original = AddressMessageBuilder::new()
            .ifindex(5)
            .prefix_len(24)
            .address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .build();

        let bytes = original.to_bytes().unwrap();
        let parsed = AddressMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.ifindex(), original.ifindex());
        assert_eq!(parsed.prefix_len(), original.prefix_len());
        assert_eq!(parsed.address, original.address);
    }
}
