//! A configured native TUN/DNS listener cannot acquire a new local address merely
//! by replacing an ACL snapshot. End the private worker and let its existing
//! supervisor cleanly recreate those resources; public forwarding is independent.
use anyhow::{ensure, Result};
use std::net::Ipv4Addr;
#[derive(Default)]
pub(crate) struct Binding(Option<Ipv4Addr>);
impl Binding {
    pub(crate) fn check(&self, next: Ipv4Addr) -> Result<()> {
        ensure!(next.is_private(), "invalid private local address");
        ensure!(self.0.is_none_or(|old|old==next),"private address changed; rebuild the private tunnel before accepting the new authority");
        Ok(())
    }
    pub(crate) fn configured(&mut self, address: Ipv4Addr) -> Result<()> {
        self.check(address)?;
        self.0 = Some(address);
        Ok(())
    }
}
