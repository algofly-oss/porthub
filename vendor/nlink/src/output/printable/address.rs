//! Printable implementation for AddressMessage.

use std::io::Write;

use crate::{
    netlink::messages::AddressMessage,
    output::{OutputOptions, Printable},
};

impl Printable for AddressMessage {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        let family = crate::util::names::family_name(self.family());

        // Get the primary address to display
        let display_addr = self
            .primary_address()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        write!(w, "    {} {}/{}", family, display_addr, self.prefix_len())?;

        // Show peer if different from local
        if let (Some(local), Some(address)) = (&self.local, &self.address)
            && local != address
        {
            write!(w, " peer {}", address)?;
        }

        // Show broadcast for IPv4
        if let Some(ref brd) = self.broadcast {
            write!(w, " brd {}", brd)?;
        }

        write!(w, " scope {}", self.scope().name())?;

        // Show flags
        if self.is_secondary() {
            write!(w, " secondary")?;
        }
        if self.is_deprecated() {
            write!(w, " deprecated")?;
        }
        if self.is_tentative() {
            write!(w, " tentative")?;
        }

        if let Some(ref label) = self.label {
            write!(w, " {}", label)?;
        }

        writeln!(w)?;

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let ifname = crate::util::get_ifname_or_index(self.ifindex());

        let mut obj = serde_json::json!({
            "ifindex": self.ifindex(),
            "ifname": ifname,
            "family": crate::util::names::family_name(self.family()),
            "prefixlen": self.prefix_len(),
            "scope": self.scope().name(),
        });

        if let Some(ref address) = self.address {
            obj["address"] = serde_json::json!(address.to_string());
        }
        if let Some(ref local) = self.local {
            obj["local"] = serde_json::json!(local.to_string());
        }
        if let Some(ref label) = self.label {
            obj["label"] = serde_json::json!(label);
        }
        if let Some(ref broadcast) = self.broadcast {
            obj["broadcast"] = serde_json::json!(broadcast.to_string());
        }

        // Add flags
        let mut flags = Vec::new();
        if self.is_secondary() {
            flags.push("secondary");
        }
        if self.is_permanent() {
            flags.push("permanent");
        }
        if self.is_deprecated() {
            flags.push("deprecated");
        }
        if self.is_tentative() {
            flags.push("tentative");
        }
        if !flags.is_empty() {
            obj["flags"] = serde_json::json!(flags);
        }

        obj
    }
}
