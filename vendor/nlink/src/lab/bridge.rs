//! [`LabBridge`] — thin builder for creating + populating a bridge
//! inside a [`LabNamespace`].

use crate::{
    Result,
    netlink::{Connection, Route, link::BridgeLink},
};

use super::LabNamespace;

/// A bridge builder scoped to a lab namespace.
///
/// Creates a bridge via rtnetlink, enslaves ports to it, and brings it
/// up — the three steps you'd normally sequence yourself in test code.
///
/// This is a tiny convenience wrapper over
/// [`BridgeLink`] +
/// `Connection::enslave` + `Connection::set_link_up`. Each chained
/// method runs a single rtnetlink op.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::lab::{LabBridge, LabNamespace, LabVeth};
///
/// let ns = LabNamespace::new("bridged")?;
///
/// // Create two dummy-style ports (a veth pair with both ends local).
/// LabVeth::new("p1", "p1-peer").create_in(&ns).await?;
/// LabVeth::new("p2", "p2-peer").create_in(&ns).await?;
///
/// // Build br0 and enslave the two ports + bring it up.
/// let br = LabBridge::new(&ns, "br0")
///     .create().await?
///     .add_port("p1").await?
///     .add_port("p2").await?
///     .up().await?;
///
/// assert_eq!(br.name(), "br0");
/// # Ok(())
/// # }
/// ```
pub struct LabBridge<'a> {
    ns: &'a LabNamespace,
    name: String,
}

#[nlink_macros::send_futures]
impl<'a> LabBridge<'a> {
    /// Start a new bridge builder for `name` inside `ns`.
    pub fn new(ns: &'a LabNamespace, name: impl Into<String>) -> Self {
        Self {
            ns,
            name: name.into(),
        }
    }

    /// Get the bridge name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create the bridge via rtnetlink inside the scoped namespace.
    pub async fn create(self) -> Result<Self> {
        let conn: Connection<Route> = self.ns.connection()?;
        conn.add_link(BridgeLink::new(&self.name)).await?;
        Ok(self)
    }

    /// Enslave `port` (an existing interface in the same namespace)
    /// to this bridge.
    pub async fn add_port(self, port: &str) -> Result<Self> {
        let conn: Connection<Route> = self.ns.connection()?;
        conn.enslave(port, self.name.as_str()).await?;
        Ok(self)
    }

    /// Bring the bridge up.
    pub async fn up(self) -> Result<Self> {
        let conn: Connection<Route> = self.ns.connection()?;
        conn.set_link_up(self.name.as_str()).await?;
        Ok(self)
    }
}
