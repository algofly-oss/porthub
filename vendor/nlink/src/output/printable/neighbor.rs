//! Printable implementation for NeighborMessage.

use std::io::Write;

use crate::{
    netlink::{messages::NeighborMessage, types::neigh::nud_state_name},
    output::{OutputOptions, Printable},
};

impl Printable for NeighborMessage {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        // Destination
        if let Some(ref dst) = self.destination {
            write!(w, "{}", dst)?;
        } else {
            write!(w, "?")?;
        }

        // Device
        let dev = crate::util::ifname::index_to_name(self.ifindex())
            .unwrap_or_else(|_| format!("if{}", self.ifindex()));
        write!(w, " dev {}", dev)?;

        // Link-layer address
        if let Some(ref lladdr) = self.mac_address() {
            write!(w, " lladdr {}", lladdr)?;
        }

        // Router flag for IPv6
        if self.is_router() {
            write!(w, " router")?;
        }

        // State
        write!(w, " {}", nud_state_name(self.header.ndm_state))?;

        writeln!(w)?;

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let dev = crate::util::ifname::index_to_name(self.ifindex())
            .unwrap_or_else(|_| format!("if{}", self.ifindex()));

        let mut obj = serde_json::json!({
            "ifindex": self.ifindex(),
            "dev": dev,
            "state": nud_state_name(self.header.ndm_state),
        });

        if let Some(ref dst) = self.destination {
            obj["dst"] = serde_json::json!(dst.to_string());
        }

        if let Some(ref mac) = self.mac_address() {
            obj["lladdr"] = serde_json::json!(mac);
        }

        if self.is_router() {
            obj["router"] = serde_json::json!(true);
        }

        if self.is_proxy() {
            obj["proxy"] = serde_json::json!(true);
        }

        obj
    }
}
