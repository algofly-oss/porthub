//! Printable implementation for LinkMessage.

use std::io::Write;

use crate::{
    netlink::messages::LinkMessage,
    output::{OutputOptions, Printable},
};

impl Printable for LinkMessage {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        let name = self.name.as_deref().unwrap_or("?");

        // Build flags string, adding NO-CARRIER if carrier is false
        let mut flags = crate::util::names::format_link_flags(self.flags());
        if let Some(false) = self.carrier
            && !self.is_loopback()
        {
            flags = format!("NO-CARRIER,{}", flags);
        }

        let mtu = self.mtu.unwrap_or(0);
        let qdisc = self.qdisc.as_deref().unwrap_or("noqueue");
        let operstate = self.operstate.map(|s| s.name()).unwrap_or("UNKNOWN");

        // Line 1: index, name, flags, mtu, qdisc, state, group, qlen
        write!(
            w,
            "{}: {}: <{}> mtu {} qdisc {} state {}",
            self.ifindex(),
            name,
            flags,
            mtu,
            qdisc,
            operstate
        )?;

        if let Some(group) = self.group {
            write!(w, " group {}", group_name(group))?;
        }

        if let Some(qlen) = self.txqlen {
            write!(w, " qlen {}", qlen)?;
        }

        if let Some(master) = self.master
            && let Ok(master_name) = crate::util::ifname::index_to_name(master)
        {
            write!(w, " master {}", master_name)?;
        }

        writeln!(w)?;

        // Line 2: link type, address
        write!(w, "    link/{}", link_type_name(self.header.ifi_type))?;
        if let Some(ref addr) = self.mac_address() {
            write!(w, " {}", addr)?;
        }
        if let Some(ref brd) = self.broadcast
            && brd.len() == 6
        {
            write!(
                w,
                " brd {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                brd[0], brd[1], brd[2], brd[3], brd[4], brd[5]
            )?;
        }
        // Show permanent address if different from current
        if let Some(ref perm) = self.perm_address {
            let perm_mac = if perm.len() == 6 {
                Some(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    perm[0], perm[1], perm[2], perm[3], perm[4], perm[5]
                ))
            } else {
                None
            };
            if perm_mac.as_ref() != self.mac_address().as_ref()
                && let Some(ref perm_str) = perm_mac
            {
                write!(w, " permaddr {}", perm_str)?;
            }
        }
        writeln!(w)?;

        // Line 3 (optional): bond info
        if let Some(bond) = self.bond_info() {
            let mode_name = bond
                .bond_mode()
                .map(|m| format!("{:?}", m))
                .unwrap_or_else(|| format!("mode {}", bond.mode));
            write!(w, "    bond mode {} miimon {}ms", mode_name, bond.miimon)?;
            if bond.min_links > 0 {
                write!(w, " min_links {}", bond.min_links)?;
            }
            if let Some(policy) = bond.hash_policy() {
                write!(w, " xmit_hash {:?}", policy)?;
            }
            if let Some(rate) = bond.lacp_rate {
                write!(w, " lacp_rate {}", if rate == 0 { "slow" } else { "fast" })?;
            }
            if let Some(ref ad) = bond.ad_info {
                write!(
                    w,
                    " ad_aggregator {} ad_ports {}",
                    ad.aggregator_id, ad.num_ports
                )?;
            }
            writeln!(w)?;
        }

        // Line 3/4 (optional): bond slave info
        if let Some(slave) = self.bond_slave_info() {
            write!(w, "    bond_slave state {:?}", slave.state)?;
            write!(w, " mii {:?}", slave.mii_status)?;
            if slave.link_failure_count > 0 {
                write!(w, " failures {}", slave.link_failure_count)?;
            }
            writeln!(w)?;
        }

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "ifindex": self.ifindex(),
            "ifname": self.name.as_deref().unwrap_or(""),
            "flags": crate::util::names::format_link_flags(self.flags()),
            "mtu": self.mtu.unwrap_or(0),
            "qdisc": self.qdisc.as_deref().unwrap_or(""),
            "operstate": self.operstate.map(|s| s.name()).unwrap_or("UNKNOWN"),
            "link_type": link_type_name(self.header.ifi_type),
        });

        if let Some(ref addr) = self.mac_address() {
            obj["address"] = serde_json::json!(addr);
        }
        if let Some(master) = self.master {
            obj["master"] = serde_json::json!(master);
        }
        if let Some(ref info) = self.link_info
            && let Some(ref kind) = info.kind
        {
            obj["link_kind"] = serde_json::json!(kind);
        }
        if let Some(txqlen) = self.txqlen {
            obj["txqlen"] = serde_json::json!(txqlen);
        }
        if let Some(group) = self.group {
            obj["group"] = serde_json::json!(group_name(group));
        }

        if let Some(bond) = self.bond_info() {
            let mut bond_obj = serde_json::Map::new();
            bond_obj.insert(
                "mode".into(),
                serde_json::json!(
                    bond.bond_mode()
                        .map(|m| format!("{:?}", m))
                        .unwrap_or_else(|| bond.mode.to_string())
                ),
            );
            bond_obj.insert("miimon".into(), serde_json::json!(bond.miimon));
            bond_obj.insert("min_links".into(), serde_json::json!(bond.min_links));
            if let Some(policy) = bond.hash_policy() {
                bond_obj.insert(
                    "xmit_hash_policy".into(),
                    serde_json::json!(format!("{:?}", policy)),
                );
            }
            if let Some(ref ad) = bond.ad_info {
                bond_obj.insert(
                    "ad_aggregator_id".into(),
                    serde_json::json!(ad.aggregator_id),
                );
                bond_obj.insert("ad_num_ports".into(), serde_json::json!(ad.num_ports));
            }
            obj["bond"] = serde_json::Value::Object(bond_obj);
        }

        if let Some(slave) = self.bond_slave_info() {
            let mut slave_obj = serde_json::Map::new();
            slave_obj.insert(
                "state".into(),
                serde_json::json!(format!("{:?}", slave.state)),
            );
            slave_obj.insert(
                "mii_status".into(),
                serde_json::json!(format!("{:?}", slave.mii_status)),
            );
            slave_obj.insert(
                "link_failure_count".into(),
                serde_json::json!(slave.link_failure_count),
            );
            obj["bond_slave"] = serde_json::Value::Object(slave_obj);
        }

        obj
    }
}

fn group_name(group: u32) -> String {
    if group == 0 {
        "default".to_string()
    } else {
        format!("{}", group)
    }
}

fn link_type_name(ifi_type: u16) -> &'static str {
    match ifi_type {
        1 => "ether",      // ARPHRD_ETHER
        772 => "loopback", // ARPHRD_LOOPBACK
        776 => "sit",      // ARPHRD_SIT
        778 => "gre",      // ARPHRD_IPGRE
        823 => "ip6gre",   // ARPHRD_IP6GRE
        65534 => "none",   // ARPHRD_NONE
        _ => "unknown",
    }
}
