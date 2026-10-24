//! A stable, serializable projection of every event (#523; feature
//! `serde`).
//!
//! [`NetworkEvent`] and [`NftablesEvent`] carry the kernel's messages,
//! which are not a format: they grow with every kernel, and much of what
//! they hold is wire detail. An [`EventView`] is what a log line, an
//! NDJSON stream or a UI wants instead — the object, whether it came or
//! went, and the fields that identify and describe it — in one shape for
//! both families, with names that do not change when the messages do.
//!
//! [`ResyncedEvent`](crate::netlink::resync::ResyncedEvent),
//! [`ResyncMarker`](crate::netlink::resync::ResyncMarker) and
//! [`EventMeta`](crate::netlink::EventMeta) serialize too, so a resync
//! stream maps straight to JSON:
//!
//! ```no_run
//! # async fn example(conn: nlink::Connection<nlink::Route>,
//! #     factory: nlink::netlink::resync::ConnectionFactory<nlink::Route>) -> nlink::Result<()> {
//! use nlink::netlink::events::view::EventView;
//! use nlink::netlink::resync_ext::ResyncStreamExt;
//! use tokio_stream::StreamExt;
//!
//! let mut events = conn
//!     .into_events_with_resync(factory)
//!     .await?
//!     .map_event(|e| EventView::from(&e));
//! while let Some(item) = events.next().await {
//!     println!("{}", serde_json::to_string(&item?).unwrap());
//!     // {"Event":{"object":"link","action":"new","ifindex":7,"name":"d0",…}}
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};

use crate::netlink::events::NetworkEvent;
use crate::netlink::nftables::NftablesEvent;

/// Whether an object came (or changed) or went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Added or changed: a `New*` message.
    New,
    /// Removed: a `Del*` message.
    Del,
}

/// One event, as the object it is about (`"object"`), whether it came or
/// went (`"action"`), and the fields that identify and describe it.
/// Optional fields are left out when absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "object", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventView {
    /// A network interface.
    Link {
        /// New or deleted.
        action: Action,
        /// Its index.
        ifindex: u32,
        /// Its name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Its kind: `veth`, `bridge`, `vxlan`, ….
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link_kind: Option<String>,
        /// Its MTU.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtu: Option<u32>,
        /// Its operational state: `up`, `down`, `lowerlayerdown`, ….
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operstate: Option<String>,
        /// Whether it is administratively up.
        up: bool,
        /// The index of its master: a bridge, a bond, a VRF.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        master: Option<u32>,
        /// Its MAC address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    /// An IP address on an interface.
    Address {
        /// New or deleted.
        action: Action,
        /// The interface's index.
        ifindex: u32,
        /// The address and prefix length, `10.0.0.1/24`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cidr: Option<String>,
        /// Its scope: `global`, `link`, `host`, ….
        scope: String,
        /// Its label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// A route.
    Route {
        /// New or deleted.
        action: Action,
        /// `inet`, `inet6`, `mpls`, ….
        family: String,
        /// Its table.
        table: u32,
        /// Its destination, `10.0.0.0/24`, or `default`.
        dst: String,
        /// Its gateway.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<String>,
        /// The output interface's index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oif: Option<u32>,
        /// Its metric.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metric: Option<u32>,
        /// Who installed it: `kernel`, `boot`, `static`, ….
        protocol: String,
        /// `unicast`, `local`, `blackhole`, ….
        route_type: String,
        /// Its nexthop object.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nhid: Option<u32>,
    },
    /// A neighbour (ARP/NDP) entry, or a proxy entry.
    Neighbour {
        /// New or deleted.
        action: Action,
        /// The interface's index.
        ifindex: u32,
        /// The IP address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        /// The link-layer address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lladdr: Option<String>,
        /// `reachable`, `stale`, `permanent`, ….
        state: String,
        /// Whether it is a proxy entry.
        proxy: bool,
    },
    /// A bridge or VXLAN forwarding-database entry.
    Fdb {
        /// New or deleted.
        action: Action,
        /// The port's index.
        ifindex: u32,
        /// The MAC address.
        mac: String,
        /// Its VLAN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vlan: Option<u16>,
        /// A VXLAN remote.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dst: Option<String>,
        /// The bridge's index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        master: Option<u32>,
    },
    /// A queueing discipline.
    Qdisc {
        /// New or deleted.
        action: Action,
        /// The interface's index.
        ifindex: u32,
        /// Its handle, `1:`.
        handle: String,
        /// Its parent: `root`, `ingress`, `1:10`.
        parent: String,
        /// Its kind: `htb`, `netem`, ….
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tc_kind: Option<String>,
    },
    /// A traffic-control class.
    Class {
        /// New or deleted.
        action: Action,
        /// The interface's index.
        ifindex: u32,
        /// Its handle, `1:10`.
        handle: String,
        /// Its parent.
        parent: String,
        /// Its kind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tc_kind: Option<String>,
    },
    /// A traffic-control filter.
    Filter {
        /// New or deleted.
        action: Action,
        /// The interface's index.
        ifindex: u32,
        /// Its handle.
        handle: String,
        /// The qdisc or class it is attached to.
        parent: String,
        /// Its priority.
        priority: u16,
        /// Its kind: `flower`, `u32`, `matchall`, ….
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tc_kind: Option<String>,
    },
    /// A shared traffic-control action.
    TcAction {
        /// New or deleted.
        action: Action,
    },
    /// A policy-routing rule.
    Rule {
        /// New or deleted.
        action: Action,
        /// `inet` or `inet6`.
        family: String,
        /// Its priority.
        priority: u32,
        /// The table it looks up.
        table: u32,
        /// `lookup`, `blackhole`, `goto`, ….
        rule_action: String,
        /// Its source prefix.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        src: Option<String>,
        /// Its destination prefix.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dst: Option<String>,
        /// Its input interface.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        iif: Option<String>,
        /// Its output interface.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oif: Option<String>,
        /// Its firewall mark.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fwmark: Option<u32>,
    },
    /// A nexthop object.
    Nexthop {
        /// New or deleted.
        action: Action,
        /// Its id.
        id: u32,
        /// Its gateway.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<String>,
        /// Its interface's index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oif: Option<u32>,
        /// A group's members, by id.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        group: Vec<u32>,
        /// Whether it drops what it is given.
        blackhole: bool,
    },
    /// A peer namespace's id.
    NsId {
        /// Assigned or released.
        action: Action,
        /// The id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nsid: Option<u32>,
    },
    /// A bridge multicast-database entry.
    Mdb {
        /// New or deleted.
        action: Action,
        /// The bridge's index.
        bridge: u32,
        /// The port's index.
        port: u32,
        /// The group.
        group: String,
        /// Its VLAN; 0 for none.
        vid: u16,
    },
    /// An interface's IP configuration: forwarding, rp_filter, ….
    Netconf {
        /// Changed or gone.
        action: Action,
        /// `inet` or `inet6`.
        family: String,
        /// The interface's index; absent for `all` and `default`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ifindex: Option<u32>,
        /// Whether it forwards.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        forwarding: Option<i32>,
        /// Its reverse-path filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rp_filter: Option<i32>,
    },
    /// An nftables table.
    NftTable {
        /// New or deleted.
        action: Action,
        /// `inet`, `ip`, `ip6`, ….
        family: String,
        /// Its name.
        table: String,
    },
    /// An nftables chain.
    NftChain {
        /// New or deleted.
        action: Action,
        /// Its family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        chain: String,
        /// A base chain's priority.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        priority: Option<i32>,
    },
    /// An nftables rule.
    NftRule {
        /// New or deleted.
        action: Action,
        /// Its family.
        family: String,
        /// Its table.
        table: String,
        /// Its chain.
        chain: String,
        /// Its handle.
        handle: u64,
        /// Its counter's packets and bytes, if it has one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        counter: Option<(u64, u64)>,
    },
    /// An nftables set or map.
    NftSet {
        /// New or deleted.
        action: Action,
        /// Its family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        set: String,
    },
    /// Elements added to or removed from a set.
    NftSetElements {
        /// Added or removed.
        action: Action,
        /// The set's family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        set: String,
        /// How many elements.
        elements: usize,
    },
    /// An nftables flowtable.
    NftFlowtable {
        /// New or deleted.
        action: Action,
        /// Its family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        flowtable: String,
    },
    /// A named nftables object: a counter, quota or limit.
    NftObject {
        /// New or deleted.
        action: Action,
        /// Its family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        name: String,
        /// `counter`, `quota`, `limit`; absent for one nlink does not
        /// model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        object_type: Option<String>,
    },
    /// A committed nftables transaction: the ruleset's new generation.
    NftGen {
        /// The generation id.
        id: u32,
        /// The committing process's pid.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// Its name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proc_name: Option<String>,
    },
}

/// `inet`, `inet6` and the rest, as `ip` and `nft` name them.
fn af_name(family: u8) -> String {
    match family as i32 {
        libc::AF_INET => "inet".into(),
        libc::AF_INET6 => "inet6".into(),
        libc::AF_BRIDGE => "bridge".into(),
        libc::AF_MPLS => "mpls".into(),
        libc::AF_UNSPEC => "unspec".into(),
        other => other.to_string(),
    }
}

fn ip(a: Option<&std::net::IpAddr>) -> Option<String> {
    a.map(ToString::to_string)
}

fn prefix(a: Option<std::net::IpAddr>, len: u8) -> Option<String> {
    a.map(|a| format!("{a}/{len}"))
}

fn action(new: bool) -> Action {
    if new { Action::New } else { Action::Del }
}

impl From<&NetworkEvent> for EventView {
    fn from(event: &NetworkEvent) -> Self {
        let action = action(event.is_new());
        match event {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Self::Link {
                action,
                ifindex: m.ifindex(),
                name: m.name().map(str::to_string),
                link_kind: m.kind().map(str::to_string),
                mtu: m.mtu(),
                operstate: m.operstate().map(|s| s.name().to_string()),
                up: m.is_up(),
                master: m.master(),
                mac: m.mac_address(),
            },
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Self::Address {
                action,
                ifindex: m.ifindex(),
                cidr: prefix(m.local().or(m.address()).copied(), m.prefix_len()),
                scope: m.scope().name().to_string(),
                label: m.label().map(str::to_string),
            },
            NetworkEvent::NewRoute(m) | NetworkEvent::DelRoute(m) => Self::Route {
                action,
                family: af_name(m.family()),
                table: m.table_id(),
                dst: prefix(m.destination().copied(), m.dst_len())
                    .unwrap_or_else(|| "default".into()),
                gateway: ip(m.gateway().or(m.via())),
                oif: m.oif(),
                metric: m.priority(),
                protocol: m.protocol().name().to_string(),
                route_type: m.route_type().name().to_string(),
                nhid: m.nh_id(),
            },
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Self::Neighbour {
                action,
                ifindex: m.ifindex(),
                address: ip(m.destination()),
                lladdr: m.mac_address(),
                state: m.state().name().to_string(),
                proxy: m.is_proxy(),
            },
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Self::Fdb {
                action,
                ifindex: m.ifindex(),
                mac: m.mac_str(),
                vlan: m.vlan(),
                dst: m.dst().map(|d| d.to_string()),
                master: m.master(),
            },
            NetworkEvent::NewQdisc(m) | NetworkEvent::DelQdisc(m) => Self::Qdisc {
                action,
                ifindex: m.ifindex(),
                handle: m.handle_str(),
                parent: m.parent_str(),
                tc_kind: m.kind().map(str::to_string),
            },
            NetworkEvent::NewClass(m) | NetworkEvent::DelClass(m) => Self::Class {
                action,
                ifindex: m.ifindex(),
                handle: m.handle_str(),
                parent: m.parent_str(),
                tc_kind: m.kind().map(str::to_string),
            },
            NetworkEvent::NewFilter(m) | NetworkEvent::DelFilter(m) => Self::Filter {
                action,
                ifindex: m.ifindex(),
                handle: format!("{:#x}", m.handle_raw()),
                parent: m.parent_str(),
                priority: m.priority().as_u16(),
                tc_kind: m.kind().map(str::to_string),
            },
            NetworkEvent::NewAction(_) | NetworkEvent::DelAction(_) => Self::TcAction { action },
            NetworkEvent::NewRule(m) | NetworkEvent::DelRule(m) => Self::Rule {
                action,
                family: af_name(m.family()),
                priority: m.priority(),
                table: m.table(),
                rule_action: m.action().name().to_string(),
                src: prefix(m.source(), m.src_len()),
                dst: prefix(m.destination(), m.dst_len()),
                iif: m.iifname().map(str::to_string),
                oif: m.oifname().map(str::to_string),
                fwmark: m.fwmark(),
            },
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => Self::Nexthop {
                action,
                id: m.id(),
                gateway: m.gateway().map(|g| g.to_string()),
                oif: m.ifindex(),
                group: m
                    .group()
                    .map(|g| g.iter().map(|member| member.id()).collect())
                    .unwrap_or_default(),
                blackhole: m.is_blackhole(),
            },
            NetworkEvent::NewNsId(m) | NetworkEvent::DelNsId(m) => Self::NsId {
                action,
                nsid: m.nsid(),
            },
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Self::Mdb {
                action,
                bridge: m.bridge_ifindex,
                port: m.port_ifindex,
                group: m.group.to_string(),
                vid: m.vid,
            },
            NetworkEvent::NewNetconf(m) | NetworkEvent::DelNetconf(m) => Self::Netconf {
                action,
                family: af_name(m.family()),
                ifindex: m.ifindex(),
                forwarding: m.forwarding(),
                rp_filter: m.rp_filter(),
            },
        }
    }
}

impl From<&NftablesEvent> for EventView {
    fn from(event: &NftablesEvent) -> Self {
        use crate::netlink::resync_ext::GapDelta;
        let action = action(!event.is_removal());
        match event {
            NftablesEvent::NewTable(t) | NftablesEvent::DelTable(t) => Self::NftTable {
                action,
                family: t.family.to_string(),
                table: t.name.clone(),
            },
            NftablesEvent::NewChain(c) | NftablesEvent::DelChain(c) => Self::NftChain {
                action,
                family: c.family.to_string(),
                table: c.table.clone(),
                chain: c.name.clone(),
                priority: c.priority,
            },
            NftablesEvent::NewRule(r) | NftablesEvent::DelRule(r) => Self::NftRule {
                action,
                family: r.family.to_string(),
                table: r.table.clone(),
                chain: r.chain.clone(),
                handle: r.handle,
                counter: r.counter(),
            },
            NftablesEvent::NewSet(s) | NftablesEvent::DelSet(s) => Self::NftSet {
                action,
                family: s.family.to_string(),
                table: s.table.clone(),
                set: s.name.clone(),
            },
            NftablesEvent::NewSetElements(e) | NftablesEvent::DelSetElements(e) => {
                Self::NftSetElements {
                    action,
                    family: e.family.to_string(),
                    table: e.table.clone(),
                    set: e.set.clone(),
                    elements: e.elements.len(),
                }
            }
            NftablesEvent::NewFlowtable(f) | NftablesEvent::DelFlowtable(f) => Self::NftFlowtable {
                action,
                family: f.family.to_string(),
                table: f.table.clone(),
                flowtable: f.name.clone(),
            },
            NftablesEvent::NewObject(o) | NftablesEvent::DelObject(o) => Self::NftObject {
                action,
                family: o.family.to_string(),
                table: o.table.clone(),
                name: o.name.clone(),
                object_type: o.object_type().map(|t| format!("{t:?}").to_lowercase()),
            },
            NftablesEvent::NewGen(g) => Self::NftGen {
                id: g.id,
                pid: g.pid,
                proc_name: g.proc_name.clone(),
            },
        }
    }
}

impl From<NetworkEvent> for EventView {
    fn from(event: NetworkEvent) -> Self {
        Self::from(&event)
    }
}

impl From<NftablesEvent> for EventView {
    fn from(event: NftablesEvent) -> Self {
        Self::from(&event)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::netlink::Route;
    use crate::netlink::resync::{ResyncMarker, ResyncedEvent};
    use crate::netlink::stream::EventSource;

    fn frame(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(16 + payload.len() as u32).to_ne_bytes());
        frame.extend_from_slice(&kind.to_ne_bytes());
        frame.extend_from_slice(&[0; 10]);
        frame.extend_from_slice(payload);
        frame
    }

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&(4 + data.len() as u16).to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(data);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn view_of(kind: u16, payload: &[u8]) -> EventView {
        let events = Route::parse_events(&frame(kind, payload));
        assert_eq!(events.len(), 1, "{events:?}");
        EventView::from(&events[0])
    }

    /// The JSON is the contract: a stable shape, every field named.
    fn assert_json(view: &EventView, want: serde_json::Value) {
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json, want);
        let back: EventView = serde_json::from_value(json).unwrap();
        assert_eq!(&back, view, "round trip");
    }

    #[test]
    fn a_link_event_views_as_a_link() {
        // ifinfomsg: AF_UNSPEC, type, index 7, IFF_UP.
        let mut p = vec![0u8; 16];
        p[4..8].copy_from_slice(&7i32.to_ne_bytes());
        p[8..12].copy_from_slice(&1u32.to_ne_bytes());
        p.extend(attr(3, b"d0\0")); // IFLA_IFNAME
        p.extend(attr(4, &1500u32.to_ne_bytes())); // IFLA_MTU
        assert_json(
            &view_of(16, &p), // RTM_NEWLINK
            json!({"object": "link", "action": "new", "ifindex": 7, "name": "d0", "mtu": 1500, "up": true}),
        );
    }

    #[test]
    fn a_route_event_views_as_a_route() {
        // rtmsg: AF_INET, /24, table main, static, universe, unicast.
        let p0 = [libc::AF_INET as u8, 24, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0];
        let mut p = p0.to_vec();
        p.extend(attr(1, &[10, 1, 0, 0])); // RTA_DST
        p.extend(attr(5, &[10, 0, 0, 1])); // RTA_GATEWAY
        p.extend(attr(4, &3u32.to_ne_bytes())); // RTA_OIF
        p.extend(attr(6, &100u32.to_ne_bytes())); // RTA_PRIORITY
        assert_json(
            &view_of(25, &p), // RTM_DELROUTE
            json!({
                "object": "route", "action": "del", "family": "inet", "table": 254,
                "dst": "10.1.0.0/24", "gateway": "10.0.0.1", "oif": 3, "metric": 100,
                "protocol": "static", "route_type": "unicast",
            }),
        );
        // No destination: the default route.
        let mut p = p0.to_vec();
        p[1] = 0;
        let EventView::Route { dst, .. } = view_of(24, &p) else { panic!() };
        assert_eq!(dst, "default");
    }

    #[test]
    fn an_nftables_event_views_with_its_family_name() {
        let table = crate::netlink::nftables::types::Table {
            name: "filter".into(),
            family: crate::netlink::nftables::Family::Inet,
            flags: 0,
            use_count: 0,
            handle: 3,
            comment: None,
        };
        assert_json(
            &EventView::from(NftablesEvent::DelTable(table)),
            json!({"object": "nft_table", "action": "del", "family": "inet", "table": "filter"}),
        );
    }

    /// A resync stream's items and their metadata serialize as they are.
    #[test]
    fn resync_items_and_meta_serialize() {
        let marker: ResyncedEvent<EventView> = ResyncedEvent::Marker(ResyncMarker::ResyncStart);
        assert_eq!(serde_json::to_value(&marker).unwrap(), json!({"Marker": "ResyncStart"}));
        let item = ResyncedEvent::Resynced(EventView::NsId {
            action: Action::New,
            nsid: Some(4),
        });
        assert_eq!(
            serde_json::to_value(&item).unwrap(),
            json!({"Resynced": {"object": "ns_id", "action": "new", "nsid": 4}})
        );
        let meta = crate::netlink::EventMeta {
            portid: 0,
            seq: 0,
            kind: 16,
            group: Some(1),
            nsid: None,
        };
        assert_eq!(
            serde_json::to_value(meta).unwrap(),
            json!({"portid": 0, "seq": 0, "kind": 16, "group": 1, "nsid": null})
        );
    }
}
