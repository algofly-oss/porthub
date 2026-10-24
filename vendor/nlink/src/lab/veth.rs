//! [`LabVeth`] — thin builder for a veth pair whose two ends live in
//! (optionally different) [`LabNamespace`]s.

use crate::{
    Result,
    netlink::{Connection, Route, link::VethLink},
};

use super::LabNamespace;

/// A veth pair builder scoped to one or two lab namespaces.
///
/// The "local" end is created in the primary namespace (see
/// [`LabVeth::create_in`]). The "peer" end is placed in the namespace
/// configured via [`LabVeth::peer_in`] (default: same namespace as
/// local).
///
/// This is a tiny convenience wrapper around
/// [`VethLink`]: it chains the
/// rtnetlink create call with peer-namespace placement and returns a
/// handle carrying both interface names.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::lab::{LabNamespace, LabVeth};
///
/// let hq    = LabNamespace::new("hq")?;
/// let alpha = LabNamespace::new("alpha")?;
///
/// let link = LabVeth::new("veth_hq", "veth_alpha")
///     .peer_in(&alpha)
///     .create_in(&hq)
///     .await?;
///
/// assert_eq!(link.local_name(), "veth_hq");
/// assert_eq!(link.peer_name(), "veth_alpha");
/// # Ok(())
/// # }
/// ```
pub struct LabVeth<'a> {
    local_name: String,
    peer_name: String,
    peer_ns: Option<&'a LabNamespace>,
}

#[nlink_macros::send_futures]
impl<'a> LabVeth<'a> {
    /// Start a new veth pair builder.
    pub fn new(local_name: impl Into<String>, peer_name: impl Into<String>) -> Self {
        Self {
            local_name: local_name.into(),
            peer_name: peer_name.into(),
            peer_ns: None,
        }
    }

    /// Place the peer end in `peer_ns` when the pair is created.
    pub fn peer_in(mut self, peer_ns: &'a LabNamespace) -> Self {
        self.peer_ns = Some(peer_ns);
        self
    }

    /// Get the local interface name.
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Get the peer interface name.
    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    /// Create the veth pair inside `ns`. The local end stays in `ns`;
    /// the peer goes to the namespace set via
    /// [`Self::peer_in`], if any.
    pub async fn create_in(self, ns: &LabNamespace) -> Result<Self> {
        let conn: Connection<Route> = ns.connection()?;
        let mut link = VethLink::new(&self.local_name, &self.peer_name);
        if let Some(peer_ns) = self.peer_ns {
            link = link.peer_netns(peer_ns.name())?;
        }
        conn.add_link(link).await?;
        Ok(self)
    }
}
