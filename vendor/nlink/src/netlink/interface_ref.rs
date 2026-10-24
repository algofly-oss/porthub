//! Interface reference type for namespace-safe operations.
//!
//! This module provides [`InterfaceRef`], which can hold either an interface name
//! or an interface index. This enables namespace-safe operations by allowing
//! callers to either:
//!
//! 1. Use interface names (convenient, resolved via netlink at operation time)
//! 2. Use interface indices (pre-resolved, for explicit namespace control)
//!
//! # Why This Exists
//!
//! When working with network namespaces via [`Connection::new_in()`],
//! interface name resolution must happen through netlink (not sysfs) to query
//! the correct namespace. By deferring name resolution to the Connection methods,
//! the library can resolve names in the namespace context of the connection.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::netlink::{Connection, Route, InterfaceRef};
//! use nlink::netlink::addr::Ipv4Address;
//!
//! // Using interface name (convenient for simple cases)
//! let addr = Ipv4Address::new("eth0", "192.168.1.100".parse()?, 24);
//!
//! // Using interface index (namespace-safe, when you've already resolved the index)
//! let link = conn.get_link_by_name("eth0").await?.unwrap();
//! let addr = Ipv4Address::with_index(link.ifindex(), "192.168.1.100".parse()?, 24);
//! # Ok(())
//! # }
//! ```

use std::fmt;

/// A reference to a network interface, either by name or by index.
///
/// This type is used throughout the nlink API to allow flexible interface
/// specification. When an `InterfaceRef::Name` is used, the connection will
/// resolve it to an index via netlink before performing the operation,
/// ensuring correct namespace handling.
///
/// # Creating an InterfaceRef
///
/// ```no_run
/// use nlink::netlink::InterfaceRef;
///
/// // From a name (most common)
/// let by_name = InterfaceRef::name("eth0");
///
/// // From an index (when you've already resolved it)
/// let by_index = InterfaceRef::index(2);
///
/// // Using Into<InterfaceRef> implementations
/// let from_str: InterfaceRef = "eth0".into();
/// let from_string: InterfaceRef = String::from("eth0").into();
/// let from_u32: InterfaceRef = 2u32.into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InterfaceRef {
    /// Interface specified by name (will be resolved via netlink).
    Name(String),
    /// Interface specified by index (already resolved).
    Index(u32),
}

impl InterfaceRef {
    /// Create an interface reference from a name.
    ///
    /// The name will be resolved to an index via netlink when the operation
    /// is performed, ensuring correct namespace handling.
    #[inline]
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    /// Create an interface reference from an index.
    ///
    /// Use this when you've already resolved the interface index, for example
    /// via `conn.get_link_by_name()` in a namespace context.
    #[inline]
    pub fn index(index: u32) -> Self {
        Self::Index(index)
    }

    /// Returns `true` if this is a name reference that needs resolution.
    #[inline]
    pub fn is_name(&self) -> bool {
        matches!(self, Self::Name(_))
    }

    /// Returns `true` if this is an already-resolved index.
    #[inline]
    pub fn is_index(&self) -> bool {
        matches!(self, Self::Index(_))
    }

    /// Get the name if this is a name reference.
    #[inline]
    pub fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::Index(_) => None,
        }
    }

    /// Get the index if this is an index reference.
    #[inline]
    pub fn as_index(&self) -> Option<u32> {
        match self {
            Self::Name(_) => None,
            Self::Index(idx) => Some(*idx),
        }
    }
}

impl fmt::Display for InterfaceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "{}", name),
            Self::Index(idx) => write!(f, "ifindex:{}", idx),
        }
    }
}

// Convenient From implementations

impl From<&str> for InterfaceRef {
    #[inline]
    fn from(name: &str) -> Self {
        Self::Name(name.to_string())
    }
}

impl From<String> for InterfaceRef {
    #[inline]
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl From<&String> for InterfaceRef {
    #[inline]
    fn from(name: &String) -> Self {
        Self::Name(name.clone())
    }
}

impl From<u32> for InterfaceRef {
    #[inline]
    fn from(index: u32) -> Self {
        Self::Index(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_ref_name() {
        let iface = InterfaceRef::name("eth0");
        assert!(iface.is_name());
        assert!(!iface.is_index());
        assert_eq!(iface.as_name(), Some("eth0"));
        assert_eq!(iface.as_index(), None);
        assert_eq!(iface.to_string(), "eth0");
    }

    #[test]
    fn test_interface_ref_index() {
        let iface = InterfaceRef::index(42);
        assert!(!iface.is_name());
        assert!(iface.is_index());
        assert_eq!(iface.as_name(), None);
        assert_eq!(iface.as_index(), Some(42));
        assert_eq!(iface.to_string(), "ifindex:42");
    }

    #[test]
    fn test_from_str() {
        let iface: InterfaceRef = "eth0".into();
        assert_eq!(iface, InterfaceRef::Name("eth0".to_string()));
    }

    #[test]
    fn test_from_string() {
        let iface: InterfaceRef = String::from("eth0").into();
        assert_eq!(iface, InterfaceRef::Name("eth0".to_string()));
    }

    #[test]
    fn test_from_u32() {
        let iface: InterfaceRef = 42u32.into();
        assert_eq!(iface, InterfaceRef::Index(42));
    }

    #[test]
    fn test_equality() {
        assert_eq!(InterfaceRef::name("eth0"), InterfaceRef::name("eth0"));
        assert_eq!(InterfaceRef::index(1), InterfaceRef::index(1));
        assert_ne!(InterfaceRef::name("eth0"), InterfaceRef::index(1));
    }
}
