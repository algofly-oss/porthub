//! Sysctl management via `/proc/sys/`.
//!
//! This module provides functions for reading and writing kernel parameters
//! (sysctls) through the `/proc/sys/` filesystem. For namespace-aware
//! operations, use the wrappers in [`super::namespace`].
//!
//! # Example
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::sysctl;
//!
//! // Read a sysctl value
//! let val = sysctl::get("net.ipv4.ip_forward")?;
//! println!("ip_forward = {}", val);
//!
//! // Set a sysctl value (requires root)
//! sysctl::set("net.ipv4.ip_forward", "1")?;
//!
//! // Set multiple values at once
//! sysctl::set_many(&[
//!     ("net.ipv4.ip_forward", "1"),
//!     ("net.ipv6.conf.all.forwarding", "1"),
//! ])?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use super::error::{Error, Result};

/// Convert a sysctl key to a `/proc/sys/` path.
///
/// Two forms, as `sysctl(8)` takes them:
/// - dotted, `net.ipv4.ip_forward`: every `.` is a path separator;
/// - slashed, `net/ipv4/conf/eth0.100/rp_filter`: taken verbatim, so a
///   segment can contain dots — an interface named `eth0.100` can only be
///   addressed this way (#477). [`ipv4_conf_key`] and [`ipv6_conf_key`]
///   build it.
///
/// ```text
/// sysctl_path("net.ipv4.ip_forward")
///     == PathBuf::from("/proc/sys/net/ipv4/ip_forward")
/// sysctl_path("net/ipv4/conf/eth0.100/rp_filter")
///     == PathBuf::from("/proc/sys/net/ipv4/conf/eth0.100/rp_filter")
/// ```
///
/// Shown rather than run: this function is private, and a doctest compiles
/// as a separate crate.
fn sysctl_path(key: &str) -> Result<PathBuf> {
    validate_key(key)?;
    let relative = if key.contains('/') {
        key.to_string()
    } else {
        key.replace('.', "/")
    };
    Ok(PathBuf::from("/proc/sys").join(relative))
}

/// Validate a sysctl key to prevent path traversal.
fn validate_key(key: &str) -> Result<()> {
    let invalid = || Error::invalid_message(format!("invalid sysctl key: {key}"));
    if key.is_empty() {
        return Err(Error::invalid_message("sysctl key cannot be empty"));
    }
    if key.starts_with('/') || key.contains('\0') {
        return Err(invalid());
    }
    if key.contains('/') {
        // Slashed: every segment is a name, never `.`/`..` or empty.
        if key
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        {
            return Err(invalid());
        }
    } else if key.contains("..") {
        return Err(invalid());
    }
    Ok(())
}

/// The key of a per-interface IPv4 setting, `net/ipv4/conf/<dev>/<setting>`,
/// in the slashed form that addresses a device whose name has dots in it.
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::sysctl;
///
/// sysctl::set(&sysctl::ipv4_conf_key("eth0.100", "rp_filter"), "2")?;
/// # Ok(())
/// # }
/// ```
pub fn ipv4_conf_key(dev: &str, setting: &str) -> String {
    format!("net/ipv4/conf/{dev}/{setting}")
}

/// The key of a per-interface IPv6 setting, `net/ipv6/conf/<dev>/<setting>`;
/// see [`ipv4_conf_key`].
pub fn ipv6_conf_key(dev: &str, setting: &str) -> String {
    format!("net/ipv6/conf/{dev}/{setting}")
}

/// Read a sysctl value.
///
/// Reads from `/proc/sys/` in the current namespace. For namespace-aware
/// operations, use [`super::namespace::get_sysctl`].
///
/// A missing key is an [`ErrorDetail::Sysctl`](crate::ErrorDetail::Sysctl) for which `is_not_found()` holds;
/// every error names the key.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::sysctl;
///
/// let val = sysctl::get("net.ipv4.ip_forward")?;
/// assert!(val == "0" || val == "1");
/// # Ok(())
/// # }
/// ```
pub fn get(key: &str) -> Result<String> {
    let path = sysctl_path(key)?;
    let contents = std::fs::read_to_string(&path).map_err(|source| Error::from(crate::netlink::ErrorDetail::Sysctl {
        key: key.to_string(),
        source,
    }))?;
    Ok(contents.trim_end().to_string())
}

/// Set a sysctl value.
///
/// Writes to `/proc/sys/` in the current namespace. Requires root or
/// `CAP_SYS_ADMIN`. For namespace-aware operations, use
/// [`super::namespace::set_sysctl`]. Errors as for [`get`].
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::sysctl;
///
/// sysctl::set("net.ipv4.ip_forward", "1")?;
/// # Ok(())
/// # }
/// ```
pub fn set(key: &str, value: &str) -> Result<()> {
    let path = sysctl_path(key)?;
    std::fs::write(&path, value).map_err(|source| Error::from(crate::netlink::ErrorDetail::Sysctl {
        key: key.to_string(),
        source,
    }))?;
    Ok(())
}

/// Set multiple sysctl values.
///
/// Applies all entries in order. If any entry fails, returns the error
/// immediately without applying remaining entries.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::sysctl;
///
/// sysctl::set_many(&[
///     ("net.ipv4.ip_forward", "1"),
///     ("net.ipv6.conf.all.forwarding", "1"),
/// ])?;
/// # Ok(())
/// # }
/// ```
pub fn set_many(entries: &[(&str, &str)]) -> Result<()> {
    for &(key, value) in entries {
        set(key, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_path_conversion() {
        assert_eq!(
            sysctl_path("net.ipv4.ip_forward").unwrap(),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
        assert_eq!(
            sysctl_path("net.ipv6.conf.all.forwarding").unwrap(),
            PathBuf::from("/proc/sys/net/ipv6/conf/all/forwarding")
        );
    }

    #[test]
    fn test_validate_key_rejects_traversal() {
        assert!(validate_key("net..ipv4").is_err());
        assert!(validate_key("/etc/passwd").is_err());
        assert!(validate_key("").is_err());
        assert!(validate_key("net.ipv4\0.ip_forward").is_err());
    }

    /// A slashed key is taken verbatim, so a device name with a dot in it
    /// can be addressed (#477).
    #[test]
    fn a_slashed_key_keeps_the_dots_in_its_segments() {
        assert_eq!(
            sysctl_path(&ipv4_conf_key("eth0.100", "rp_filter")).unwrap(),
            PathBuf::from("/proc/sys/net/ipv4/conf/eth0.100/rp_filter")
        );
        assert_eq!(
            sysctl_path("net/ipv6/conf/v.1/forwarding").unwrap(),
            PathBuf::from("/proc/sys/net/ipv6/conf/v.1/forwarding")
        );
        assert!(validate_key("net/ipv4/../../etc").is_err());
        assert!(validate_key("net//ipv4").is_err());
        assert!(validate_key("net/./ipv4").is_err());
    }

    /// A missing key is not-found and names itself (#477).
    #[test]
    fn a_missing_key_is_not_found_and_named() {
        let err = get("net.ipv4.nlink_no_such_key").unwrap_err();
        assert!(err.is_not_found(), "{err:?}");
        assert!(
            err.to_string().contains("net.ipv4.nlink_no_such_key"),
            "{err}"
        );
    }

    #[test]
    fn test_validate_key_accepts_valid() {
        assert!(validate_key("net.ipv4.ip_forward").is_ok());
        assert!(validate_key("net.ipv6.conf.all.forwarding").is_ok());
        assert!(validate_key("kernel.hostname").is_ok());
    }
}
