//! Address parsing and formatting utilities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Error type for address parsing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AddrError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),

    #[error("invalid MAC address: {0}")]
    InvalidMac(String),
}

pub type Result<T> = std::result::Result<T, AddrError>;

/// Parse an IP address from string.
pub fn parse_addr(s: &str) -> Result<IpAddr> {
    s.parse()
        .map_err(|_| AddrError::InvalidAddress(s.to_string()))
}

/// Parse an IP address with prefix length (CIDR notation).
/// Returns (address, prefix_length).
pub fn parse_prefix(s: &str) -> Result<(IpAddr, u8)> {
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr = parse_addr(addr_str)?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| AddrError::InvalidPrefix(prefix_str.to_string()))?;

        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(AddrError::InvalidPrefix(format!(
                "{} exceeds maximum {} for address family",
                prefix, max_prefix
            )));
        }

        Ok((addr, prefix))
    } else {
        // No prefix specified, use default
        let addr = parse_addr(s)?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, prefix))
    }
}

/// Format an IP address.
pub fn format_addr(addr: &IpAddr) -> String {
    addr.to_string()
}

/// Format an IP address with prefix.
pub fn format_prefix(addr: &IpAddr, prefix: u8) -> String {
    format!("{}/{}", addr, prefix)
}

/// Format an IPv4 address from bytes.
pub fn format_ipv4(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
    } else {
        None
    }
}

/// Format an IPv6 address from bytes.
pub fn format_ipv6(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 16 {
        let octets: [u8; 16] = bytes[..16].try_into().ok()?;
        Some(Ipv6Addr::from(octets).to_string())
    } else {
        None
    }
}

/// Format an IP address from bytes, given the address family.
pub fn format_addr_bytes(bytes: &[u8], family: u8) -> Option<String> {
    match family {
        2 => format_ipv4(bytes),  // AF_INET
        10 => format_ipv6(bytes), // AF_INET6
        _ => None,
    }
}

/// Parse a MAC address from string.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(AddrError::InvalidMac(s.to_string()));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| AddrError::InvalidMac(s.to_string()))?;
    }

    Ok(mac)
}

/// Format a MAC address.
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Check if an IPv4 address is in a given prefix.
pub fn ipv4_in_prefix(addr: Ipv4Addr, prefix_addr: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }

    let mask = !0u32 << (32 - prefix_len);
    let addr_bits = u32::from(addr);
    let prefix_bits = u32::from(prefix_addr);

    (addr_bits & mask) == (prefix_bits & mask)
}

/// Check if an IPv6 address is in a given prefix.
pub fn ipv6_in_prefix(addr: Ipv6Addr, prefix_addr: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }

    let addr_bits = u128::from(addr);
    let prefix_bits = u128::from(prefix_addr);
    let mask = !0u128 << (128 - prefix_len);

    (addr_bits & mask) == (prefix_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_addr() {
        assert_eq!(
            parse_addr("192.168.1.1").unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(parse_addr("::1").unwrap(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_prefix() {
        let (addr, prefix) = parse_prefix("192.168.1.0/24").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
    }
}
