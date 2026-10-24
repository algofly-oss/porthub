//! Device lookup helpers with netlink-compatible error handling.
//!
//! This module provides convenience functions for device name/index
//! conversion that return errors compatible with rip-netlink's Error type.

use super::ifname;

/// Get interface index from name with a formatted error message.
///
/// Returns the interface index as u32.
///
/// # Example
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ifindex = nlink::util::get_ifindex("eth0")?;
/// # Ok(())
/// # }
/// ```
pub fn get_ifindex(name: &str) -> Result<u32, String> {
    ifname::name_to_index(name).map_err(|e| format!("interface not found: {}", e))
}

/// Get optional interface index from optional name.
///
/// Useful for filtering operations where the device is optional.
///
/// # Example
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ifindex = nlink::util::get_ifindex_opt(Some("eth0"))?;
/// # Ok(())
/// # }
/// ```
pub fn get_ifindex_opt(name: Option<&str>) -> Result<Option<u32>, String> {
    match name {
        Some(n) => Ok(Some(get_ifindex(n)?)),
        None => Ok(None),
    }
}

/// Get interface name from index.
///
/// # Example
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let name = nlink::util::get_ifname(1)?;
/// # Ok(())
/// # }
/// ```
pub fn get_ifname(index: u32) -> Result<String, String> {
    ifname::index_to_name(index).map_err(|e| format!("interface not found: {}", e))
}

/// Get interface name from index, or return a fallback string.
///
/// Useful for display purposes where you want to show something
/// even if the interface lookup fails.
///
/// # Example
/// ```no_run
/// let name = nlink::util::get_ifname_or_index(1);
/// // Returns "eth0" if found, or "if1" if not
/// ```
pub fn get_ifname_or_index(index: u32) -> String {
    if index == 0 {
        return format!("if{}", index);
    }
    ifname::index_to_name(index).unwrap_or_else(|_| format!("if{}", index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ifindex_lo() {
        // "lo" should always exist
        let result = get_ifindex("lo");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // lo is typically index 1
    }

    #[test]
    fn test_get_ifindex_not_found() {
        let result = get_ifindex("nonexistent_interface_xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("interface not found"));
    }

    #[test]
    fn test_get_ifindex_opt_some() {
        let result = get_ifindex_opt(Some("lo"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_get_ifindex_opt_none() {
        let result = get_ifindex_opt(None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_ifname_or_index() {
        // lo is index 1
        assert_eq!(get_ifname_or_index(1), "lo");
        // Very high index probably doesn't exist
        let result = get_ifname_or_index(99999);
        assert!(result.starts_with("if"));
    }
}
