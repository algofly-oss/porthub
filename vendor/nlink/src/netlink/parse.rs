//! Parser combinators and traits for strongly-typed netlink message parsing.
//!
//! This module provides:
//! - `FromNetlink` trait for parsing netlink messages
//! - `ToNetlink` trait for serializing netlink messages
//! - Core parser combinators using winnow
//!
//! # Example
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use nlink::AddressMessage;
//! use nlink::netlink::parse::{FromNetlink, parse_nlmsghdr};
//!
//! // `data` is one message as handed out by `MessageIter`.
//! # let data: Vec<u8> = Vec::new();
//! // Parse a complete netlink message
//! let msg = AddressMessage::from_bytes(&data)?;
//!
//! // Or use low-level combinators
//! let header = parse_nlmsghdr(&mut data.as_ref())
//!     .map_err(|e| format!("bad header: {e}"))?;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use winnow::{
    binary::{le_u8, le_u16, le_u32},
    error::ContextError,
    prelude::*,
    token::take,
};

use super::{
    error::{Error, Result},
    message::NlMsgHdr,
};

/// Result type for winnow parsers.
pub type PResult<T> = core::result::Result<T, winnow::error::ErrMode<ContextError>>;

// Re-export winnow for use in derive macros
pub use winnow;

/// Trait for types that can be parsed from netlink wire format.
pub trait FromNetlink: Sized {
    /// Parse from a mutable byte slice reference.
    /// The slice is advanced past the consumed bytes.
    fn parse(input: &mut &[u8]) -> PResult<Self>;

    /// Parse from a complete byte slice.
    fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::parse
            .parse(data)
            .map_err(|e| Error::invalid_message(format!("parse error: {}", e)))
    }

    /// Write the header required for dump requests.
    /// This is appended to the netlink message after the nlmsghdr.
    /// Default implementation writes nothing (for messages that don't need a header).
    fn write_dump_header(_buf: &mut Vec<u8>) {}

    /// Record the `nlmsg_type` this message arrived with.
    ///
    /// [`parse`](Self::parse) only sees the payload, but a few message types
    /// cannot classify themselves without the header — `tcmsg` is the same
    /// struct for qdiscs, classes and filters, and its `tcm_info` field means
    /// something different for each (for a qdisc it is the *refcount*, which
    /// is why guessing from it never worked; see #214). The dump and event
    /// paths call this after parsing, since they have the header in hand.
    ///
    /// Default no-op: only [`TcMessage`](crate::netlink::messages::TcMessage)
    /// needs it today.
    fn set_msg_type(&mut self, _msg_type: u16) {}
}

/// Trait for types that can be serialized to netlink wire format.
pub trait ToNetlink {
    /// Calculate the serialized size in bytes.
    fn netlink_len(&self) -> usize;

    /// Write to a byte buffer.
    /// Returns the number of bytes written.
    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize>;

    /// Serialize to a new byte vector.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.netlink_len());
        self.write_to(&mut buf)?;
        Ok(buf)
    }
}

// ============================================================================
// Core Parser Combinators
// ============================================================================

/// Parse a netlink message header.
pub fn parse_nlmsghdr(input: &mut &[u8]) -> PResult<NlMsgHdr> {
    let len = le_u32.parse_next(input)?;
    let msg_type = le_u16.parse_next(input)?;
    let flags = le_u16.parse_next(input)?;
    let seq = le_u32.parse_next(input)?;
    let pid = le_u32.parse_next(input)?;

    Ok(NlMsgHdr {
        nlmsg_len: len,
        nlmsg_type: msg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    })
}

/// Parse a netlink attribute header and return (type, payload).
pub fn parse_attr<'a>(input: &mut &'a [u8]) -> PResult<(u16, &'a [u8])> {
    let len = le_u16.parse_next(input)? as usize;
    let attr_type = le_u16.parse_next(input)?;

    if len < 4 {
        return Err(winnow::error::ErrMode::Cut(ContextError::new()));
    }

    let payload_len = len.saturating_sub(4);
    let payload: &[u8] = take(payload_len).parse_next(input)?;

    // Align to 4 bytes
    let aligned = (len + 3) & !3;
    let padding = aligned.saturating_sub(len);
    if input.len() >= padding {
        let _: &[u8] = take(padding).parse_next(input)?;
    }

    Ok((attr_type, payload))
}

/// Parse all attributes from remaining input.
pub fn parse_attrs<'a>(input: &mut &'a [u8]) -> PResult<Vec<(u16, &'a [u8])>> {
    let mut attrs = Vec::new();
    while !input.is_empty() && input.len() >= 4 {
        match parse_attr(input) {
            Ok(attr) => attrs.push(attr),
            Err(_) => break,
        }
    }
    Ok(attrs)
}

// ============================================================================
// Primitive Parsers
// ============================================================================

/// Parse a u8.
pub fn parse_u8(input: &mut &[u8]) -> PResult<u8> {
    le_u8.parse_next(input)
}

/// Parse a u16 in native endian.
pub fn parse_u16_ne(input: &mut &[u8]) -> PResult<u16> {
    let bytes: &[u8] = take(2usize).parse_next(input)?;
    Ok(u16::from_ne_bytes(bytes.try_into().unwrap()))
}

/// Parse a u32 in native endian.
pub fn parse_u32_ne(input: &mut &[u8]) -> PResult<u32> {
    let bytes: &[u8] = take(4usize).parse_next(input)?;
    Ok(u32::from_ne_bytes(bytes.try_into().unwrap()))
}

/// Parse a u64 in native endian.
pub fn parse_u64_ne(input: &mut &[u8]) -> PResult<u64> {
    let bytes: &[u8] = take(8usize).parse_next(input)?;
    Ok(u64::from_ne_bytes(bytes.try_into().unwrap()))
}

/// Parse an i32 in native endian.
pub fn parse_i32_ne(input: &mut &[u8]) -> PResult<i32> {
    let bytes: &[u8] = take(4usize).parse_next(input)?;
    Ok(i32::from_ne_bytes(bytes.try_into().unwrap()))
}

/// Parse a null-terminated C string.
pub fn parse_cstring(input: &mut &[u8]) -> PResult<String> {
    // Find null terminator or use entire input
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let s = std::str::from_utf8(&input[..end])
        .map_err(|_| winnow::error::ErrMode::Cut(ContextError::new()))?
        .to_string();

    // Consume the string including null terminator if present
    let consume = if end < input.len() { end + 1 } else { end };
    let _: &[u8] = take(consume).parse_next(input)?;

    Ok(s)
}

/// Parse a string from a fixed-size buffer (null-terminated).
///
/// Plan 232 B10 — pre-fix used `from_utf8(...).unwrap_or("")` which
/// silently truncated to the empty string on any invalid UTF-8.
/// Consumers couldn't distinguish "kernel emitted empty name" from
/// "kernel emitted bytes nlink couldn't decode". The kernel allows
/// arbitrary bytes in IFLA_IFNAME (up to IFNAMSIZ); lossy decoding
/// preserves every observable byte using U+FFFD for invalid
/// sequences — strictly more information.
pub fn parse_string_from_bytes(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Parse an IPv4 address (4 bytes).
pub fn parse_ipv4(input: &mut &[u8]) -> PResult<Ipv4Addr> {
    let bytes: &[u8] = take(4usize).parse_next(input)?;
    Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Parse an IPv6 address (16 bytes).
pub fn parse_ipv6(input: &mut &[u8]) -> PResult<Ipv6Addr> {
    let bytes: &[u8] = take(16usize).parse_next(input)?;
    let arr: [u8; 16] = bytes.try_into().unwrap();
    Ok(Ipv6Addr::from(arr))
}

/// Parse an IP address based on address family.
pub fn parse_ip_addr(data: &[u8], family: u8) -> Result<IpAddr> {
    match family {
        2 => {
            // AF_INET
            if data.len() < 4 {
                return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                    expected: 4,
                    actual: data.len(),
                }));
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            )))
        }
        10 => {
            // AF_INET6
            if data.len() < 16 {
                return Err(Error::from(crate::netlink::ErrorDetail::Truncated {
                    expected: 16,
                    actual: data.len(),
                }));
            }
            let arr: [u8; 16] = data[..16].try_into().unwrap();
            Ok(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => Err(Error::invalid_message(format!(
            "unknown address family: {}",
            family
        ))),
    }
}

/// Parse a MAC address (6 bytes).
pub fn parse_mac_addr(input: &mut &[u8]) -> PResult<[u8; 6]> {
    let bytes: &[u8] = take(6usize).parse_next(input)?;
    Ok(bytes.try_into().unwrap())
}

/// Format a MAC address as a string.
pub fn format_mac_addr(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// ============================================================================
// FromNetlink implementations for primitive types
// ============================================================================

impl FromNetlink for u8 {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_u8(input)
    }
}

impl FromNetlink for u16 {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_u16_ne(input)
    }
}

impl FromNetlink for u32 {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_u32_ne(input)
    }
}

impl FromNetlink for u64 {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_u64_ne(input)
    }
}

impl FromNetlink for i32 {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_i32_ne(input)
    }
}

impl FromNetlink for String {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_cstring(input)
    }
}

impl FromNetlink for Ipv4Addr {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_ipv4(input)
    }
}

impl FromNetlink for Ipv6Addr {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        parse_ipv6(input)
    }
}

impl FromNetlink for Vec<u8> {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let data = input.to_vec();
        *input = &[];
        Ok(data)
    }
}

impl<const N: usize> FromNetlink for [u8; N] {
    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let bytes: &[u8] = take(N).parse_next(input)?;
        Ok(bytes.try_into().unwrap())
    }
}

// ============================================================================
// ToNetlink implementations for primitive types
// ============================================================================

impl ToNetlink for u8 {
    fn netlink_len(&self) -> usize {
        1
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.push(*self);
        Ok(1)
    }
}

impl ToNetlink for u16 {
    fn netlink_len(&self) -> usize {
        2
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(2)
    }
}

impl ToNetlink for u32 {
    fn netlink_len(&self) -> usize {
        4
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(4)
    }
}

impl ToNetlink for u64 {
    fn netlink_len(&self) -> usize {
        8
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(8)
    }
}

impl ToNetlink for i32 {
    fn netlink_len(&self) -> usize {
        4
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.to_ne_bytes());
        Ok(4)
    }
}

impl ToNetlink for String {
    fn netlink_len(&self) -> usize {
        self.len() + 1 // Include null terminator
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(self.as_bytes());
        buf.push(0);
        Ok(self.len() + 1)
    }
}

impl ToNetlink for &str {
    fn netlink_len(&self) -> usize {
        self.len() + 1
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(self.as_bytes());
        buf.push(0);
        Ok(self.len() + 1)
    }
}

impl ToNetlink for Ipv4Addr {
    fn netlink_len(&self) -> usize {
        4
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.octets());
        Ok(4)
    }
}

impl ToNetlink for Ipv6Addr {
    fn netlink_len(&self) -> usize {
        16
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(&self.octets());
        Ok(16)
    }
}

impl ToNetlink for IpAddr {
    fn netlink_len(&self) -> usize {
        match self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        match self {
            IpAddr::V4(addr) => addr.write_to(buf),
            IpAddr::V6(addr) => addr.write_to(buf),
        }
    }
}

impl ToNetlink for Vec<u8> {
    fn netlink_len(&self) -> usize {
        self.len()
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(self);
        Ok(self.len())
    }
}

impl<const N: usize> ToNetlink for [u8; N] {
    fn netlink_len(&self) -> usize {
        N
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        buf.extend_from_slice(self);
        Ok(N)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate the aligned size for a netlink attribute.
pub fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Calculate the total size of a netlink attribute including header and padding.
pub fn nla_size(payload_len: usize) -> usize {
    nla_align(4 + payload_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_u32_ne() {
        let data = 0x12345678u32.to_ne_bytes();
        let result = u32::from_bytes(&data).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_parse_cstring() {
        let data = b"hello\0world";
        let mut input = data.as_ref();
        let result = parse_cstring(&mut input).unwrap();
        assert_eq!(result, "hello");
        assert_eq!(input, b"world");
    }

    #[test]
    fn test_parse_ipv4() {
        let data = [192, 168, 1, 1];
        let result = Ipv4Addr::from_bytes(&data).unwrap();
        assert_eq!(result, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_nla_align() {
        assert_eq!(nla_align(1), 4);
        assert_eq!(nla_align(4), 4);
        assert_eq!(nla_align(5), 8);
        assert_eq!(nla_align(8), 8);
    }

    #[test]
    fn test_roundtrip_u32() {
        let value = 0xDEADBEEFu32;
        let bytes = value.to_bytes().unwrap();
        let parsed = u32::from_bytes(&bytes).unwrap();
        assert_eq!(value, parsed);
    }

    #[test]
    fn test_roundtrip_string() {
        let value = "test string".to_string();
        let bytes = value.to_bytes().unwrap();
        let parsed = String::from_bytes(&bytes).unwrap();
        assert_eq!(value, parsed);
    }

    /// Plan 232 B10 — invalid UTF-8 bytes now surface as U+FFFD
    /// instead of truncating the whole string to "".
    #[test]
    fn b10_parse_string_from_bytes_uses_lossy_decoding() {
        // `\xff\xfe` is invalid UTF-8 — should produce U+FFFD
        // chars, sandwiched between valid prefix/suffix.
        let parsed = parse_string_from_bytes(b"foo\xff\xfebar\0extra");
        assert!(parsed.starts_with("foo"));
        assert!(parsed.ends_with("bar"));
        assert!(
            parsed.contains(char::REPLACEMENT_CHARACTER),
            "expected U+FFFD in lossy decode: {parsed:?}"
        );
    }

    #[test]
    fn b10_parse_string_from_bytes_handles_no_invalid_utf8() {
        let parsed = parse_string_from_bytes(b"eth0\0extra");
        assert_eq!(parsed, "eth0");
    }
}
