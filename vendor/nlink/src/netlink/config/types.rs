//! Core types for declarative network configuration.

use std::net::IpAddr;
use std::time::Duration;

pub use crate::netlink::link::{
    AdSelect as BondAdSelect, LacpRate as BondLacpRate, NetkitMode, NetkitPolicy, NetkitScrub,
    VlanProtocol, XmitHashPolicy as BondXmitHashPolicy,
};
pub use crate::netlink::tc_spec::QdiscSpec;

/// Declarative network configuration.
///
/// Represents the desired state of network resources. Use the builder methods
/// to add links, addresses, routes, and qdiscs, then call [`diff()`](NetworkConfig::diff)
/// or [`apply()`](NetworkConfig::apply) to reconcile with the current state.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", default))]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetworkConfig {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) links: Vec<DeclaredLink>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) addresses: Vec<DeclaredAddress>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) routes: Vec<DeclaredRoute>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) qdiscs: Vec<DeclaredQdisc>,
    /// Permanent and proxy neighbours (#516).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) neighbours: Vec<DeclaredNeighbour>,
    /// Bridge FDB entries and VXLAN remotes (#516).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) fdb: Vec<DeclaredFdb>,
    /// Policy routing rules (#516).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) rules: Vec<DeclaredRule>,
    /// Nexthop objects and groups (#516).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) nexthops: Vec<DeclaredNexthop>,
    /// The TC trees declared with [`tc`](Self::tc): in JSON and YAML, each
    /// class, filter and action as its kind and tc(8)'s words (#645).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub(crate) tc: Vec<super::tc_tree::DeclaredTc>,
    /// The `rtm_protocol` declared routes are installed with, and the one
    /// the diff treats as the config's own; `None` is `boot` (#512). See
    /// [`route_protocol`](Self::route_protocol).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) route_protocol: Option<u8>,
    /// The tag written as the alias of every link the apply creates, and
    /// the one a purge removes undeclared links by (#512). See
    /// [`owner`](Self::owner).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) owner: Option<String>,
    /// The namespace's `net.vrf.strict_mode` (#680): `None` leaves it as it
    /// is. See [`vrf_strict_mode`](Self::vrf_strict_mode).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) vrf_strict_mode: Option<bool>,
    /// Mistakes a builder made that it could not return, reported by
    /// [`validate`](Self::validate) — which `diff` and `apply` run — rather
    /// than turned into a silently different config (#476).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) invalid: Vec<crate::netlink::error::ValidationErrorInfo>,
}

/// The draft-7 JSON Schema of `T`, the dialect nlink's schemas promise
/// (see [`NetworkConfig::json_schema_value`]).
#[cfg(feature = "schemars")]
pub(crate) fn draft07_schema<T: schemars::JsonSchema>() -> schemars::Schema {
    schemars::generate::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<T>()
}

/// The draft-7 JSON Schema of the JSON `T` serializes to, for a type that is
/// only ever written: the diffs. [`draft07_schema`] describes what
/// deserializes, where a field with no default is required, so a list a
/// diff leaves out when it is empty was required by its schema and missing
/// from its JSON (#876).
#[cfg(feature = "schemars")]
pub(crate) fn draft07_output_schema<T: schemars::JsonSchema>() -> schemars::Schema {
    schemars::generate::SchemaSettings::draft07()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<T>()
}

/// [`draft07_output_schema`], pretty-printed.
#[cfg(feature = "schemars")]
pub(crate) fn draft07_output_schema_text<T: schemars::JsonSchema>() -> String {
    // Library-generated: no user data, no serializer that can fail.
    serde_json::to_string_pretty(&draft07_output_schema::<T>())
        .expect("schema serialization is infallible")
}

impl NetworkConfig {
    /// Create an empty network configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a [`NetworkConfig`] from a JSON document.
    ///
    /// Resource fields are validated as they parse — addresses and
    /// routes from their CIDR strings (prefix bounds checked), MACs
    /// from `aa:bb:cc:dd:ee:ff` — so a malformed document is a parse
    /// error rather than a silently-wrong config. Requires the
    /// `serde` feature.
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::config::NetworkConfig;
    /// let cfg = NetworkConfig::from_json_str(r#"{
    ///     "addresses": [{ "dev": "eth0", "address": "10.0.0.1/24" }]
    /// }"#)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "serde")]
    pub fn from_json_str(s: &str) -> crate::netlink::Result<Self> {
        let cfg: Self = serde_json::from_str(s)
            .map_err(|e| crate::netlink::Error::from(e).with_context("config JSON parse"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Refuse declarations that contradict each other (#462): a link, a
    /// route (same destination, table and metric) or a qdisc (same device
    /// and parent) declared twice.
    ///
    /// The builder cannot produce a duplicate link — [`link`](Self::link)
    /// updates an earlier declaration of the name — but a JSON document can,
    /// and two declarations of one link used to be diffed separately, each
    /// undoing the other. [`diff`](Self::diff) and
    /// [`from_json_str`](Self::from_json_str) run this first.
    pub fn validate(&self) -> crate::netlink::Result<()> {
        use crate::netlink::error::ValidationErrorInfo;
        use std::collections::HashSet;

        let mut errors = self.invalid.clone();
        for r in &self.routes {
            let at = || format!("routes.{}/{}", r.destination, r.prefix_len);
            if let Some(why) = r.gateway_family_mismatch() {
                errors.push(ValidationErrorInfo::new(at(), why));
            }
            // `rtnh_hops` is a u8, the weight less one (#783).
            if let Some(h) = r.attrs.multipath.iter().find(|h| h.weight > 256) {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    format!("a next hop's weight is 1 to 256, not {}", h.weight),
                ));
            }
            // IPv6 masks host bits away; IPv4 refuses them (EINVAL,
            // "Invalid prefix for given prefix length") (#518).
            if let IpAddr::V4(v4) = r.destination {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(r.prefix_len.min(32)))
                    .unwrap_or(0);
                if u32::from(v4) & !mask != 0 {
                    let net = std::net::Ipv4Addr::from(u32::from(v4) & mask);
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        format!(
                            "host bits are set; the kernel refuses that for IPv4 — declare {net}/{}",
                            r.prefix_len
                        ),
                    ));
                }
            }
            // `fib_check_nh` refuses it: "Nexthop device required for
            // onlink" (#516).
            if r.attrs.onlink && r.dev.is_none() {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    "onlink needs a device: declare the route's dev",
                ));
            }
            // Table 0 is RT_TABLE_UNSPEC: the kernel puts the route in main
            // (254), and a diff comparing 0 with 254 re-added it forever.
            if r.table == Some(0) {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    "table 0 is unspecified, which the kernel reads as main (254); \
                     declare 254 or leave the table out",
                ));
            }
        }
        for (i, n) in self.neighbours.iter().enumerate() {
            let at = || format!("neighbours.{}/{}", n.dev, n.destination);
            if n.destination.is_unspecified() || n.destination.is_multicast() {
                errors.push(ValidationErrorInfo::new(at(), "a neighbour's address is a unicast address"));
            }
            match (n.proxy, n.lladdr) {
                (true, Some(_)) => {
                    errors.push(ValidationErrorInfo::new(at(), "a proxy entry has no link-layer address"))
                }
                (false, None) => {
                    errors.push(ValidationErrorInfo::new(at(), "a neighbour needs its link-layer address"))
                }
                _ => {}
            }
            if self.neighbours[..i].iter().any(|o| o.same_entry(n)) {
                errors.push(ValidationErrorInfo::new(at(), "declared twice"));
            }
        }
        for (i, n) in self.nexthops.iter().enumerate() {
            let at = || format!("nexthops.{}", n.id);
            let mut bad = |why: String| errors.push(ValidationErrorInfo::new(at(), why));
            if n.id == 0 {
                bad("a nexthop's id is not 0".into());
            }
            if self.nexthops[..i].iter().any(|o| o.id == n.id) {
                bad(format!("nexthop {} is declared twice", n.id));
            }
            let via = n.gateway.is_some() || n.dev.is_some();
            match (via, n.blackhole, n.is_group()) {
                (true, false, false) | (false, true, false) | (false, false, true) => {}
                (false, false, false) => bad("a nexthop needs a gateway or device, a blackhole, or a group".into()),
                _ => bad("a nexthop is one of: a gateway and device, a blackhole, a group".into()),
            }
            // `rtm_to_nh_config`: "Device attribute required for
            // non-blackhole and non-fdb nexthops".
            if n.gateway.is_some() && n.dev.is_none() {
                bad("a nexthop with a gateway needs its device".into());
            }
            if n.onlink && (n.gateway.is_none() || n.dev.is_none()) {
                bad("onlink needs a gateway and a device".into());
            }
            if n.ipv6 && n.gateway.is_some_and(|g| g.is_ipv4()) {
                bad("ipv6() with an IPv4 gateway".into());
            }
            for (member, weight) in &n.group {
                if *weight == 0 {
                    bad(format!("member {member}: a weight is 1 or more"));
                }
                match self.nexthops.iter().find(|o| o.id == *member) {
                    None => bad(format!("member {member} is not a declared nexthop")),
                    Some(m) if m.is_group() => bad(format!("member {member} is a group; groups do not nest")),
                    Some(_) => {}
                }
            }
            if n.group.iter().enumerate().any(|(j, (m, _))| n.group[..j].iter().any(|(o, _)| o == m)) {
                bad("a member is listed twice".into());
            }
        }
        for r in self.routes.iter().filter(|r| !r.attrs.mpls_encap.is_empty()) {
            let at = || format!("routes.{}/{}", r.destination, r.prefix_len);
            if let Some(l) = r.attrs.mpls_encap.iter().find(|l| **l > 0xF_FFFF) {
                errors.push(ValidationErrorInfo::new(at(), format!("MPLS label {l} is past 1048575")));
            }
            if r.gateway.is_none() && r.dev.is_none() {
                errors.push(ValidationErrorInfo::new(at(), "an MPLS encapsulation needs a gateway or device"));
            }
        }
        for r in self.routes.iter().filter(|r| !r.attrs.multipath.is_empty()) {
            let at = || format!("routes.{}/{}", r.destination, r.prefix_len);
            let mut bad = |why: String| errors.push(ValidationErrorInfo::new(at(), why));
            if r.gateway.is_some() || r.dev.is_some() || r.attrs.nhid.is_some() {
                bad("a multipath route has no gateway, device or nexthop object of its own".into());
            }
            // The kernel dumps a one-hop route as a plain one, and the diff
            // would never match it.
            if r.attrs.multipath.len() < 2 {
                bad("a multipath route has two next hops or more; one is .via() and .dev()".into());
            }
            if r.route_type != DeclaredRouteType::Unicast {
                bad("a multipath route is a unicast one".into());
            }
            for hop in &r.attrs.multipath {
                if hop.gateway.is_none() && hop.dev.is_none() {
                    bad(format!("{hop}: a next hop needs a gateway or device"));
                }
                if hop.gateway.is_some_and(|g| g.is_ipv4() != r.destination.is_ipv4()) {
                    bad(format!("{hop}: the gateway is not of the destination's family"));
                }
                if hop.onlink && (hop.gateway.is_none() || hop.dev.is_none()) {
                    bad(format!("{hop}: onlink needs a gateway and a device"));
                }
            }
        }
        for r in &self.routes {
            let Some(id) = r.attrs.nhid else { continue };
            let at = || format!("routes.{}/{}", r.destination, r.prefix_len);
            if r.gateway.is_some() || r.dev.is_some() {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    "a route through a nexthop object has no gateway or device of its own",
                ));
            }
            // The kernel takes the type from the object.
            if r.route_type != DeclaredRouteType::Unicast {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    "a route through a nexthop object takes its type from it; declare a blackhole nexthop",
                ));
            }
            if let Some(nh) = self.nexthops.iter().find(|n| n.id == id)
                && !nh.is_group()
                && !nh.blackhole
                && nh.is_ipv6() != r.destination.is_ipv6()
            {
                errors.push(ValidationErrorInfo::new(at(), format!("nexthop {id} is of the other family")));
            }
        }
        for (i, r) in self.rules.iter().enumerate() {
            let at = || format!("rules.{}", r.priority);
            let mut bad = |why: String| errors.push(ValidationErrorInfo::new(at(), why));
            for (what, cidr) in [("from", r.from), ("to", r.to)] {
                let Some((addr, len)) = cidr else { continue };
                let max = if addr.is_ipv6() { 128 } else { 32 };
                if len > max {
                    bad(format!("{what} {addr}/{len}: the prefix is at most {max} bits"));
                }
                if addr.is_ipv6() != r.is_ipv6() {
                    bad(format!("{what} {addr} is not in the rule's family"));
                }
            }
            if r.action == RuleAction::Table(0) {
                bad("table 0 is unspecified; declare 254 for main".into());
            }
            if r.fwmask.is_some() && r.fwmark.is_none() {
                bad("a mark mask without a mark".into());
            }
            for (what, range) in [("sport", r.sport), ("dport", r.dport)] {
                if let Some((a, b)) = range
                    && a > b
                {
                    bad(format!("{what} {a}-{b} runs backwards"));
                }
            }
            if self.rules[..i].contains(r) {
                bad("declared twice".into());
            }
        }
        for (i, e) in self.fdb.iter().enumerate() {
            let at = || format!("fdb.{e}");
            let mut bad = |why: &str| errors.push(ValidationErrorInfo::new(at(), why.to_string()));
            if let Some(vlan) = e.vlan
                && !(1..=4094).contains(&vlan)
            {
                bad("a VLAN id is 1 to 4094");
            }
            match e.dst {
                Some(_) if e.vlan.is_some() => bad("a VXLAN remote has no bridge VLAN"),
                Some(_) if e.local => bad("a VXLAN remote is not a local entry"),
                Some(dst) if dst.is_unspecified() => bad("a VXLAN remote's address is not unspecified"),
                // `fdb_add_entry` refuses any other (EINVAL).
                None if e.floods() => bad("a bridge entry's MAC is a unicast one"),
                _ => {}
            }
            let earlier = &self.fdb[..i];
            if earlier.iter().any(|o| o.same_entry(e)) {
                bad("declared twice");
            } else if e.dst.is_some()
                && !e.floods()
                && earlier.iter().any(|o| o.dev == e.dev && o.mac == e.mac && o.dst.is_some())
            {
                bad("a unicast MAC has one remote; only an all-zeros or multicast one floods to several");
            }
            // A bridge has one entry per MAC and VLAN, whichever port.
            let master = |dev: &str| {
                self.links
                    .iter()
                    .find(|l| l.name == dev)
                    .and_then(|l| l.master.name().map(str::to_string))
            };
            if e.dst.is_none()
                && let Some(br) = master(&e.dev)
                && let Some(o) = earlier.iter().find(|o| {
                    o.dst.is_none() && o.mac == e.mac && o.vlan == e.vlan && o.dev != e.dev
                        && master(&o.dev).as_deref() == Some(br.as_str())
                })
            {
                bad(&format!("{br} has one entry per MAC and VLAN, and {} declares it too", o.dev));
            }
        }
        let mut links = HashSet::new();
        for l in &self.links {
            if !links.insert(l.name.as_str()) {
                errors.push(ValidationErrorInfo::new(
                    format!("links.{}", l.name),
                    "declared more than once",
                ));
            }
            // What the kernel refuses mid-apply, after earlier links were
            // created, is refused here (#598).
            if let Err(e) = crate::util::ifname::validate(&l.name) {
                errors.push(ValidationErrorInfo::new(
                    format!("links.{}", l.name),
                    e.to_string(),
                ));
            }
            if let Some(why) = l.unaddressable_mac() {
                errors.push(ValidationErrorInfo::new(format!("links.{}", l.name), why));
            }
            // What `do_setlink` and `rtnl_linkprop` refuse (#516).
            let at = || format!("links.{}", l.name);
            if let Some(alias) = &l.attrs.alias {
                if alias.len() > 255 {
                    errors.push(ValidationErrorInfo::new(at(), "an alias is at most 255 bytes"));
                }
                if self.owner.is_some() {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        "an alias and an owner tag: the owner tag is written as the alias",
                    ));
                }
            }
            // `macsec_validate_attr` refuses an SCI left out of frames without
            // end-station or SCB mode, which are not modelled (#516).
            if let DeclaredLinkType::Macsec { include_sci: Some(false), .. } = &l.link_type {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    "macsec_include_sci(false) needs end-station or SCB mode, which a \
                     declaration does not carry; the kernel refuses it",
                ));
            }
            // Port options need a bridge master (#516).
            if l.port.is_some() {
                let master = l.master.name();
                let master_kind = master.and_then(|m| self.links.iter().find(|x| x.name == m));
                match (master, master_kind) {
                    (None, _) => errors.push(ValidationErrorInfo::new(
                        at(),
                        "port options without a master: a port is a bridge's",
                    )),
                    (Some(m), Some(x)) if !matches!(x.link_type, DeclaredLinkType::Bridge) => {
                        errors.push(ValidationErrorInfo::new(
                            at(),
                            format!("port options, but its master {m} is not a bridge"),
                        ))
                    }
                    _ => {}
                }
            }
            if let Some(vlans) = l.port.as_ref().and_then(|p| p.vlans.as_ref()) {
                let mut seen = std::collections::HashSet::new();
                for v in vlans {
                    if !(1..=4094).contains(&v.vid) || !seen.insert(v.vid) {
                        errors.push(ValidationErrorInfo::new(
                            at(),
                            format!("port vlan {}: 1 to 4094, once each", v.vid),
                        ));
                    }
                }
                if vlans.iter().filter(|v| v.pvid).count() > 1 {
                    errors.push(ValidationErrorInfo::new(at(), "a port has one PVID"));
                }
            }
            // The kernel gives every namespace a fallback device per tunnel
            // module, which nothing can configure (`ip_tunnel_changelink`
            // refuses it, EINVAL).
            const FALLBACK: [(&str, &str); 9] = [
                ("gre0", "gre"),
                ("gretap0", "gretap"),
                ("erspan0", "erspan"),
                ("tunl0", "ipip"),
                ("sit0", "sit"),
                ("ip_vti0", "vti"),
                ("ip6tnl0", "ip6tnl"),
                ("ip6gre0", "ip6gre"),
                ("ip6_vti0", "vti6"),
            ];
            if let Some((_, kind)) = FALLBACK
                .iter()
                .find(|(name, kind)| *name == l.name && l.link_type.kind() == Some(*kind))
            {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    format!(
                        "{} is the kernel's fallback {kind} device, in every namespace, and \
                         cannot be configured; name the tunnel otherwise",
                        l.name
                    ),
                ));
            }
            match &l.link_type {
                // `ip6_tnl_locate` finds a tunnel by its ends and underlay,
                // so one with none is the fallback's (EEXIST).
                DeclaredLinkType::Ip6tnl(p)
                    if p.local.is_none() && p.remote.is_none() && p.underlay_dev.is_none() =>
                {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        "an ip6tnl tunnel with no local end, remote end or underlay device is the \
                         fallback ip6tnl0's, and the kernel refuses it",
                    ));
                }
                // `ip6gre_tunnel_find`: the ends, the underlay and the key.
                DeclaredLinkType::Ip6gre(p)
                    if p.local.is_none() && p.remote.is_none() && p.underlay_dev.is_none() && p.key.is_none() =>
                {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        "an ip6gre tunnel with no end, underlay device or key is the fallback ip6gre0's, \
                         and the kernel refuses it",
                    ));
                }
                DeclaredLinkType::Ip6tnl(p) if p.key.is_some() => {
                    errors.push(ValidationErrorInfo::new(at(), "an ip6tnl tunnel has no key; ip6gre has"));
                }
                DeclaredLinkType::Ip6gre(p) | DeclaredLinkType::Ip6gretap(p)
                    if p.mode != crate::netlink::link::Ip6tnlMode::default() =>
                {
                    errors.push(ValidationErrorInfo::new(at(), "a GRE tunnel has no mode; ip6tnl has"));
                }
                // `vti6_locate`: the ends, the underlay and the key (#680).
                DeclaredLinkType::Vti6(p)
                    if p.local.is_none() && p.remote.is_none() && p.underlay_dev.is_none() && p.key.is_none() =>
                {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        "a vti6 tunnel with no end, underlay device or key is the fallback ip6_vti0's, \
                         and the kernel refuses it",
                    ));
                }
                DeclaredLinkType::Vti6(p)
                    if p.mode != crate::netlink::link::Ip6tnlMode::default()
                        || p.hoplimit.is_some()
                        || p.encap_limit.is_some() =>
                {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        "a vti6 tunnel has no mode, hop limit or encapsulation limit; ip6tnl has",
                    ));
                }
                DeclaredLinkType::Erspan(p) | DeclaredLinkType::Ip6erspan(p) => {
                    let v6 = matches!(l.link_type, DeclaredLinkType::Ip6erspan(_));
                    let kind = if v6 { "ip6erspan" } else { "erspan" };
                    if [p.local, p.remote].into_iter().flatten().any(|a| a.is_ipv6() != v6) {
                        let family = if v6 { "IPv6" } else { "IPv4" };
                        errors.push(ValidationErrorInfo::new(at(), format!("an {kind} tunnel's ends are {family}")));
                    }
                    // `erspan_validate`: the session id is 10 bits; the
                    // index 20, the hardware id 6 (`ipgre_netlink_parms`).
                    if p.session > 0x3ff {
                        errors.push(ValidationErrorInfo::new(
                            at(),
                            format!("an ERSPAN session id is 10 bits, up to 1023, not {}", p.session),
                        ));
                    }
                    match p.version {
                        crate::netlink::link::ErspanVersion::V1 { index } if index > 0xf_ffff => {
                            errors.push(ValidationErrorInfo::new(
                                at(),
                                format!("an ERSPAN type II index is 20 bits, up to 1048575, not {index}"),
                            ));
                        }
                        crate::netlink::link::ErspanVersion::V2 { hwid, .. } if hwid > 0x3f => {
                            errors.push(ValidationErrorInfo::new(
                                at(),
                                format!("an ERSPAN type III hardware id is 6 bits, up to 63, not {hwid}"),
                            ));
                        }
                        _ => {}
                    }
                }
                DeclaredLinkType::Xfrm { if_id: 0, .. } => {
                    errors.push(ValidationErrorInfo::new(at(), "an xfrm interface's if_id is not 0"));
                }
                // `xfrmi_locate` finds an interface by its if_id alone.
                DeclaredLinkType::Xfrm { if_id, .. } => {
                    if let Some(other) = self.links.iter().find(|o| {
                        o.name != l.name
                            && matches!(o.link_type, DeclaredLinkType::Xfrm { if_id: id, .. } if id == *if_id)
                    }) {
                        errors.push(ValidationErrorInfo::new(
                            at(),
                            format!("xfrm if_id {if_id} is also {}'s; a namespace has one interface per if_id", other.name),
                        ));
                    }
                }
                _ => {}
            }
            if l.bridge.is_some() && !matches!(l.link_type, DeclaredLinkType::Bridge) {
                errors.push(ValidationErrorInfo::new(at(), "bridge options on a link that is not a bridge"));
            }
            for name in l.attrs.ipv4_conf.keys() {
                if crate::netlink::devconf::Ipv4Devconf::from_name(name).is_none() {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        format!("ipv4-conf: no IPv4 device setting is called {name:?}"),
                    ));
                }
            }
            for name in l.attrs.ipv6_conf.keys() {
                if crate::netlink::devconf::Ipv6Devconf::from_name(name).is_none() {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        format!("ipv6-conf: no IPv6 device setting nlink manages is called {name:?}"),
                    ));
                }
            }
            if let Some(token) = l.attrs.ipv6_token
                && token.octets()[..8] != [0; 8]
            {
                errors.push(ValidationErrorInfo::new(
                    at(),
                    format!("ipv6-token {token}: an interface identifier has its upper 64 bits zero"),
                ));
            }
            for altname in l.attrs.altnames.iter().flatten() {
                let bad = altname.is_empty()
                    || altname.len() > 127
                    || altname == "."
                    || altname == ".."
                    || altname.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace());
                if bad || *altname == l.name {
                    errors.push(ValidationErrorInfo::new(
                        at(),
                        format!("altname {altname:?}: 1 to 127 bytes, no '/', ':' or space, not the name"),
                    ));
                }
            }
            match &l.link_type {
                DeclaredLinkType::Vxlan { vni, .. } if *vni >= 1 << 24 => {
                    errors.push(ValidationErrorInfo::new(
                        format!("links.{}", l.name),
                        format!("VNI {vni} does not fit the 24 bits a VXLAN header has"),
                    ));
                }
                // The kernel refuses to open a VLAN whose lower device is down
                // (ENETDOWN), and closes it when that goes down.
                DeclaredLinkType::Vlan { parent, .. }
                    if l.state == LinkState::Up
                        && self
                            .links
                            .iter()
                            .any(|p| p.name == *parent && p.state == LinkState::Down) =>
                {
                    errors.push(ValidationErrorInfo::new(
                        format!("links.{}", l.name),
                        format!(
                            "a VLAN declared up on {parent}, which is declared down, cannot be \
                             up (ENETDOWN); declare one of them differently"
                        ),
                    ));
                }
                _ => {}
            }
            match &l.link_type {
                DeclaredLinkType::Veth { peer, .. } | DeclaredLinkType::Netkit { peer, .. } => {
                    if let Err(e) = crate::util::ifname::validate(peer) {
                        errors.push(ValidationErrorInfo::new(
                            format!("links.{}", l.name),
                            format!("peer: {e}"),
                        ));
                    }
                    if let DeclaredLinkType::Veth {
                        peer_netns,
                        peer_address,
                        peer_mtu,
                        peer_state,
                        ..
                    } = &l.link_type
                        && (peer_address.is_some() || peer_mtu.is_some() || !peer_state.is_unchanged())
                        && peer_netns.as_ref().is_none_or(|n| n.is_default())
                    {
                        errors.push(ValidationErrorInfo::new(
                            format!("links.{}", l.name),
                            format!(
                                "the peer's MAC, MTU and state are set in the peer's namespace \
                                 (veth_peer_netns); a peer here is a link of its own: declare \
                                 {peer} and set it there"
                            ),
                        ));
                    }
                }
                DeclaredLinkType::Vlan { vlan_id, .. } if *vlan_id > 4094 => {
                    errors.push(ValidationErrorInfo::new(
                        format!("links.{}", l.name),
                        format!("VLAN id {vlan_id} is past 4094; the kernel refuses it (ERANGE)"),
                    ));
                }
                _ => {}
            }
        }
        for cycle in self.master_cycles() {
            errors.push(ValidationErrorInfo::new(
                format!("links.{}", cycle[0]),
                format!("masters form a cycle: {}", cycle.join(" → ")),
            ));
        }
        let mut routes = HashSet::new();
        for r in &self.routes {
            let key = (
                super::diff::kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
                super::diff::kernel_metric(r),
            );
            if !routes.insert(key) {
                errors.push(ValidationErrorInfo::new(
                    format!("routes.{}/{}", r.destination, r.prefix_len),
                    "declared more than once with the same table and metric",
                ));
            }
        }
        let mut qdiscs = HashSet::new();
        for q in &self.qdiscs {
            if !qdiscs.insert((q.dev.as_str(), q.effective_parent())) {
                errors.push(ValidationErrorInfo::new(
                    format!("qdiscs.{}", q.dev),
                    format!("declared more than once at {:?}", q.effective_parent()),
                ));
            }
            // What installing the qdisc would refuse before sending anything
            // (#515): percentages and sfq's perturb are checked as a document
            // is read, the rest here.
            if let Err(e) = q.qdisc_type.validate() {
                errors.push(ValidationErrorInfo::new(
                    format!("qdiscs.{}", q.dev),
                    e.to_string(),
                ));
            }
        }
        for t in &self.tc {
            for problem in t.problems() {
                errors.push(ValidationErrorInfo::new(format!("tc.{}", t.dev), problem));
            }
            // A class is of its qdisc's kind (#645).
            for c in t.classes() {
                let qdisc = self.qdiscs.iter().find(|q| {
                    q.dev == t.dev && q.effective_handle().map(|h| h.major()) == Some(c.id.major())
                });
                if let Some(q) = qdisc
                    && q.qdisc_type.kind() != c.spec.kind()
                {
                    errors.push(ValidationErrorInfo::new(
                        format!("tc.{}", t.dev),
                        format!(
                            "class {} is {}, but its qdisc {} is {}",
                            c.id,
                            c.spec.kind(),
                            crate::TcHandle::major_only(c.id.major()),
                            q.qdisc_type.kind()
                        ),
                    ));
                }
            }
        }
        // With strict mode on, a table is one VRF's (#680).
        if self.vrf_strict_mode == Some(true) {
            let mut by_table: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
            for l in &self.links {
                if let DeclaredLinkType::Vrf { table } = l.link_type
                    && let Some(other) = by_table.insert(table, &l.name)
                {
                    errors.push(ValidationErrorInfo::new(
                        format!("links.{}", l.name),
                        format!(
                            "table {table} is also VRF {other}'s; with vrf_strict_mode on, a \
                             table belongs to one VRF"
                        ),
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::netlink::Error::validation(errors))
        }
    }

    /// Each cycle of declared masters (`a` enslaved to `b`, `b` to `a`),
    /// once, as the names around it, starting and ending at its first.
    fn master_cycles(&self) -> Vec<Vec<String>> {
        use std::collections::HashSet;
        let master_of = |name: &str| {
            self.links
                .iter()
                .find(|l| l.name == name)
                .and_then(|l| match &l.master {
                    MasterSpec::Name(m) => Some(m.as_str()),
                    _ => None,
                })
        };
        let mut seen: HashSet<&str> = HashSet::new();
        let mut cycles = Vec::new();
        for l in &self.links {
            let mut path: Vec<&str> = vec![l.name.as_str()];
            let mut at = l.name.as_str();
            while let Some(m) = master_of(at) {
                if let Some(i) = path.iter().position(|p| *p == m) {
                    let cycle = &path[i..];
                    if cycle.iter().all(|n| seen.insert(n)) {
                        let mut names: Vec<String> = cycle.iter().map(|s| s.to_string()).collect();
                        names.push(m.to_string());
                        cycles.push(names);
                    }
                    break;
                }
                path.push(m);
                at = m;
            }
        }
        cycles
    }

    /// Serialize this configuration to a compact JSON string.
    /// Requires the `serde` feature.
    #[cfg(feature = "serde")]
    pub fn to_json_string(&self) -> crate::netlink::Result<String> {
        serde_json::to_string(self)
            .map_err(|e| crate::netlink::Error::from(e).with_context("config JSON serialize"))
    }

    /// Serialize this configuration to a pretty-printed JSON string.
    /// Requires the `serde` feature.
    #[cfg(feature = "serde")]
    pub fn to_json_string_pretty(&self) -> crate::netlink::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::netlink::Error::from(e).with_context("config JSON serialize"))
    }

    /// Generate a [JSON Schema](https://json-schema.org) (draft 7)
    /// describing the JSON accepted by [`from_json_str`](Self::from_json_str),
    /// as a pretty-printed string. Requires the `schemars` feature.
    ///
    /// Wire this into editor tooling (VS Code's `json.schemas`,
    /// `yaml.schemas`) for autocomplete + inline validation of
    /// `NetworkConfig` files, or check it into a repo for CI
    /// validation. The schema reflects the human-facing JSON shape —
    /// addresses/routes as CIDR strings, MACs as `aa:bb:..` strings,
    /// the `default` route keyword — not the in-memory representation.
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// std::fs::write("network-config.schema.json",
    ///     nlink::netlink::config::NetworkConfig::json_schema())?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "schemars")]
    pub fn json_schema() -> String {
        let schema = Self::json_schema_value();
        // The schema is library-generated — no user data, no custom
        // serializers that can fail — so the unwrap is infallible.
        serde_json::to_string_pretty(&schema).expect("schema serialization is infallible")
    }

    /// The JSON Schema as a [`schemars::Schema`], for callers that
    /// want to inspect or merge it rather than emit text. Requires
    /// the `schemars` feature.
    ///
    /// Draft 7 is pinned explicitly rather than taken from the
    /// library's default, which is not stable across schemars major
    /// versions — 0.8 defaulted to draft 7, 1.0 defaults to 2020-12.
    /// The dialect is part of what this method promises (editors and
    /// CI validators are configured against it), so it is chosen here
    /// rather than inherited.
    #[cfg(feature = "schemars")]
    pub fn json_schema_value() -> schemars::Schema {
        draft07_schema::<NetworkConfig>()
    }

    /// `true` when the config declares nothing: no links, addresses,
    /// routes, qdiscs, TC trees, neighbours, FDB entries, rules or
    /// nexthops, and no builder mistake waiting for
    /// [`validate`](Self::validate) (#531).
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
            && self.addresses.is_empty()
            && self.routes.is_empty()
            && self.qdiscs.is_empty()
            && self.tc.is_empty()
            && self.neighbours.is_empty()
            && self.fdb.is_empty()
            && self.rules.is_empty()
            && self.nexthops.is_empty()
            && self.invalid.is_empty()
    }

    /// Install the declared routes with routing protocol `protocol`
    /// (`rtm_protocol`, what `ip route` shows as `proto`), and treat the
    /// routes with it as the config's own (#512).
    ///
    /// The default, `boot`, is what `ip route add` uses, so the diff takes
    /// any `boot` or `static` route as one it may replace or purge — another
    /// tool's included. With a number of its own (`RouteProtocol::Other`,
    /// for instance 250, an unused `RTPROT_*`), the config owns exactly its
    /// routes: a purge removes only those, and a declared route never
    /// replaces a route with another protocol in its place, which the diff
    /// refuses (`routes_refused`) instead. A route identical to the
    /// declared one, whoever added it, already carries it.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::netlink::types::route::RouteProtocol;
    ///
    /// let cfg = NetworkConfig::new().route_protocol(RouteProtocol::Other(250));
    /// assert_eq!(cfg.routes_protocol(), RouteProtocol::Other(250));
    /// ```
    pub fn route_protocol(mut self, protocol: crate::netlink::types::route::RouteProtocol) -> Self {
        self.route_protocol = Some(protocol.number());
        self
    }

    /// Tag the links this config creates as `owner`'s: the apply writes
    /// `owner` as each one's alias (`IFLA_IFALIAS`, what `ip link` shows as
    /// `alias`), and a purge then also removes a link that carries the tag
    /// and that the config no longer declares (#512).
    ///
    /// It is how a caller finds its own links again with no record of
    /// what it applied before: after a crash, say, where
    /// [`PlanOptions::previous`](super::PlanOptions::previous) needs the
    /// previous config. Everything on a tagged link (addresses, routes,
    /// qdiscs) goes with it; what the kernel would destroy with it that
    /// cannot be declared (FDB entries, neighbours, an untagged link
    /// stacked on it) refuses the removal, as for a recreate. The alias is
    /// the tag's alone: a config with an owner should not set aliases of
    /// its own.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Set the namespace's VRF strict mode (#680): `net.vrf.strict_mode`,
    /// with which a routing table belongs to one VRF at most, and a VRF
    /// cannot be created on a table another one has.
    ///
    /// It is a sysctl of the namespace, not of a link, so a config sets it
    /// for the namespace it is applied to. The apply turns it off before it
    /// creates links, and on after, and the kernel refuses to turn it on
    /// while two VRFs share a table: validation refuses a config that
    /// turns it on and declares two that do.
    pub fn vrf_strict_mode(mut self, on: bool) -> Self {
        self.vrf_strict_mode = Some(on);
        self
    }

    /// The protocol declared routes are installed with: `boot` unless
    /// [`route_protocol`](Self::route_protocol) says otherwise.
    pub fn routes_protocol(&self) -> crate::netlink::types::route::RouteProtocol {
        self.route_protocol.map_or(
            crate::netlink::types::route::RouteProtocol::Boot,
            crate::netlink::types::route::RouteProtocol::from,
        )
    }

    /// Whether a route with protocol `protocol` is the config's own: its
    /// [`routes_protocol`](Self::routes_protocol), and with the default
    /// `boot`, `static` as well.
    pub(crate) fn owns_route_protocol(
        &self,
        protocol: crate::netlink::types::route::RouteProtocol,
    ) -> bool {
        use crate::netlink::types::route::RouteProtocol;
        match self.route_protocol {
            None => matches!(protocol, RouteProtocol::Static | RouteProtocol::Boot),
            Some(own) => protocol.number() == own,
        }
    }

    /// Add a link (interface) configuration.
    ///
    /// **Ordering note (Plan 186 §3c)**: declared order of
    /// `.link()` calls is preserved at the surface, but the
    /// internal apply step topologically sorts parent → child
    /// (e.g., a `vlan` whose parent is also being created in
    /// this apply). You can declare the VLAN before its parent
    /// dummy and the apply still works:
    ///
    /// ```no_run
    /// # use nlink::netlink::config::NetworkConfig;
    /// // Either order works — the apply sorts before sending.
    /// let cfg = NetworkConfig::new()
    ///     .link("eth0.42", |l| l.vlan("eth0", 42))
    ///     .link("eth0",    |l| l.dummy());
    /// ```
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::netlink::config::NetworkConfig;
    /// let config = NetworkConfig::new()
    ///     .link("br0", |l| l.bridge().up())
    ///     .link("dummy0", |l| l.dummy())
    ///     .link("veth0", |l| l.veth("veth1").master("br0"));
    /// ```
    ///
    /// Declaring a name twice **updates** the first declaration: `f` gets
    /// a builder holding what is already declared, so
    /// `.link("v10", |l| l.vlan("eth0", 10)).link("v10", |l| l.master("red"))`
    /// is one VLAN in `red`. Two declarations used to be diffed
    /// separately, and the one without a master released the link from
    /// the master the other named — on every other apply (#462).
    pub fn link(mut self, name: &str, f: impl FnOnce(LinkBuilder) -> LinkBuilder) -> Self {
        let at = self.links.iter().position(|l| l.name == name);
        let builder = match at {
            Some(i) => f(LinkBuilder::from_declared(self.links.remove(i))),
            None => f(LinkBuilder::new(name)),
        };
        for e in &builder.errors {
            self.invalid
                .push(crate::netlink::error::ValidationErrorInfo::new(
                    format!("links.{name}"),
                    e.clone(),
                ));
        }
        let link = builder.build();
        match at {
            Some(i) => self.links.insert(i, link),
            None => self.links.push(link),
        }
        self
    }

    /// Add an IP address to an interface.
    ///
    /// The address should be in CIDR notation (e.g., "192.168.1.1/24").
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::config::NetworkConfig;
    /// let config = NetworkConfig::new()
    ///     .address("eth0", "192.168.1.1/24")?
    ///     .address("eth0", "2001:db8::1/64")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn address(mut self, dev: &str, addr: &str) -> Result<Self, AddressParseError> {
        let declared = DeclaredAddress::parse(dev, addr)?;
        self.addresses.push(declared);
        Ok(self)
    }

    /// Add an address with more than its prefix (#516): a peer, a label,
    /// a metric, flags, lifetimes. A setter the address's family has no
    /// use for is a validation error.
    ///
    /// ```
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::time::Duration;
    /// use nlink::netlink::config::NetworkConfig;
    ///
    /// let config = NetworkConfig::new()
    ///     .address_with("eth0", "fd00::1/64", |a| a.nodad().noprefixroute().metric(100))?
    ///     .address_with("eth0", "10.0.0.1/24", |a| a.label("eth0:mgmt"))?
    ///     .address_with("eth0", "10.0.1.1/24", |a| {
    ///         a.lifetime(Duration::from_secs(3600), Duration::from_secs(1800))
    ///     })?;
    /// config.validate()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn address_with(
        mut self,
        dev: &str,
        addr: &str,
        f: impl FnOnce(AddressBuilder) -> AddressBuilder,
    ) -> Result<Self, AddressParseError> {
        let built = f(AddressBuilder::new(DeclaredAddress::parse(dev, addr)?));
        let at = format!("addresses.{dev}/{addr}");
        self.invalid.extend(
            built
                .errors
                .into_iter()
                .map(|e| crate::netlink::error::ValidationErrorInfo::new(at.clone(), e)),
        );
        self.addresses.push(built.address);
        Ok(self)
    }

    /// Declare a permanent neighbour on `dev` (#516), as
    /// `ip neigh replace <destination> lladdr <lladdr> dev <dev> nud permanent`
    /// does: an ARP entry for an IPv4 address, an ND entry for an IPv6 one.
    ///
    /// The kernel flushes a device's neighbours when it goes down, moves to
    /// or from an L3 master, changes its MAC or is recreated; the apply
    /// that does any of those puts the declared ones back. A recreate does
    /// not count them among what it destroys. Neighbours are removed only
    /// through [`PlanOptions::previous`](super::PlanOptions::previous), not
    /// by a purge.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use std::net::Ipv4Addr;
    ///
    /// let config = NetworkConfig::new()
    ///     .neighbour("eth0", Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0x02])
    ///     .proxy_neighbour("eth0", Ipv4Addr::new(10, 0, 0, 9));
    /// config.validate().unwrap();
    /// ```
    pub fn neighbour(mut self, dev: &str, destination: impl Into<IpAddr>, lladdr: [u8; 6]) -> Self {
        self.neighbours.push(DeclaredNeighbour {
            dev: dev.to_string(),
            destination: destination.into(),
            lladdr: Some(lladdr),
            proxy: false,
        });
        self
    }

    /// Declare a proxy entry on `dev` (#516), as `ip neigh add proxy
    /// <destination> dev <dev>` does: the device answers ARP or neighbour
    /// solicitations for the address (with `proxy_arp` or `proxy_ndp` on).
    pub fn proxy_neighbour(mut self, dev: &str, destination: impl Into<IpAddr>) -> Self {
        self.neighbours.push(DeclaredNeighbour {
            dev: dev.to_string(),
            destination: destination.into(),
            lladdr: None,
            proxy: true,
        });
        self
    }

    /// Declare nexthop object `id` (#516), as `ip nexthop replace id <id> …`
    /// does: a gateway and device, a blackhole, or a group of other
    /// nexthops. A route uses one with [`RouteBuilder::nhid`].
    ///
    /// It carries the config's [`route_protocol`](Self::route_protocol), and
    /// a live nexthop with the id and another protocol is another tool's:
    /// the apply refuses to replace it. A nexthop on a device that goes
    /// down or is recreated is deleted by the kernel, with every route
    /// through it; the apply that does it puts the declared ones back. A
    /// nexthop goes when it leaves the config, through
    /// [`PlanOptions::previous`](super::PlanOptions::previous).
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    ///
    /// let config = NetworkConfig::new()
    ///     .nexthop(1, |n| n.via("10.0.0.2".parse().unwrap()).dev("eth0"))
    ///     .nexthop(2, |n| n.via("10.0.0.3".parse().unwrap()).dev("eth0"))
    ///     .nexthop(10, |n| n.group(&[(1, 1), (2, 3)]))
    ///     .route("10.1.0.0/16", |r| r.nhid(10))
    ///     .unwrap();
    /// config.validate().unwrap();
    /// ```
    pub fn nexthop(mut self, id: u32, f: impl FnOnce(NexthopSpecBuilder) -> NexthopSpecBuilder) -> Self {
        let built = f(NexthopSpecBuilder {
            nexthop: DeclaredNexthop {
                id,
                gateway: None,
                dev: None,
                onlink: false,
                blackhole: false,
                ipv6: false,
                group: Vec::new(),
            },
        });
        self.nexthops.push(built.nexthop);
        self
    }

    /// Declare a policy routing rule at `priority` (#516), as `ip rule add
    /// pref <priority> …` does. Without an action it looks the main table
    /// up.
    ///
    /// The rule carries the config's
    /// [`route_protocol`](Self::route_protocol) (`boot` by default) and
    /// only a rule with it is the config's: the kernel keeps an identical
    /// rule another tool added — `ip rule add` leaves the protocol
    /// `unspec` — as a rule of its own, and a delete that names the
    /// protocol removes only this one. A rule goes when it leaves the
    /// config, through [`PlanOptions::previous`](super::PlanOptions::previous);
    /// a purge leaves rules alone. Rules name devices, so a recreated link
    /// keeps its rules.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use std::net::Ipv4Addr;
    ///
    /// let config = NetworkConfig::new()
    ///     .rule(100, |r| r.from(Ipv4Addr::new(10, 0, 0, 0), 8).table(100))
    ///     .rule(110, |r| r.invert().fwmark(0xca6c).table(51820))
    ///     .rule(120, |r| r.table(254).suppress_prefixlen(0));
    /// config.validate().unwrap();
    /// ```
    pub fn rule(mut self, priority: u32, f: impl FnOnce(PolicyRuleBuilder) -> PolicyRuleBuilder) -> Self {
        let built = f(PolicyRuleBuilder {
            rule: DeclaredRule {
                priority,
                ipv6: false,
                from: None,
                to: None,
                iif: None,
                oif: None,
                fwmark: None,
                fwmask: None,
                ipproto: None,
                sport: None,
                dport: None,
                invert: false,
                suppress_prefixlen: None,
                action: RuleAction::Table(254),
            },
        });
        self.rules.push(built.rule);
        self
    }

    /// Declare an FDB entry for `mac` on `dev` (#516).
    ///
    /// By default it is a static entry in the bridge `dev` is a port of,
    /// as `bridge fdb replace <mac> dev <dev> master static` makes: frames
    /// for the MAC leave through `dev`, and the entry never ages. With
    /// [`FdbBuilder::local`] it is the bridge's own MAC instead
    /// (`permanent`). With [`FdbBuilder::dst`] it is a VXLAN remote, in
    /// the device's own table (`bridge fdb append <mac> dev <dev> dst
    /// <ip>`); an all-zeros or multicast MAC takes any number of remotes.
    ///
    /// A bridge port leaving its bridge loses its entries, and a recreated
    /// device all of them; the apply that does either puts the declared
    /// ones back, and a recreate does not count them among what it
    /// destroys. Entries are removed only through
    /// [`PlanOptions::previous`](super::PlanOptions::previous), not by a
    /// purge.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    ///
    /// let config = NetworkConfig::new()
    ///     .fdb("veth0", [0x02, 0, 0, 0, 0, 0x01], |e| e.vlan(10))
    ///     .fdb("vxlan0", [0; 6], |e| e.dst("192.0.2.1".parse().unwrap()))
    ///     .fdb("vxlan0", [0; 6], |e| e.dst("192.0.2.2".parse().unwrap()));
    /// config.validate().unwrap();
    /// ```
    pub fn fdb(mut self, dev: &str, mac: [u8; 6], f: impl FnOnce(FdbBuilder) -> FdbBuilder) -> Self {
        let built = f(FdbBuilder {
            entry: DeclaredFdb {
                dev: dev.to_string(),
                mac,
                vlan: None,
                dst: None,
                local: false,
            },
        });
        self.fdb.push(built.entry);
        self
    }

    /// Add a route.
    ///
    /// The destination should be in CIDR notation (e.g., "10.0.0.0/8" or "0.0.0.0/0").
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::config::NetworkConfig;
    /// let config = NetworkConfig::new()
    ///     .route("10.0.0.0/8", |r| r.via("192.168.1.1"))?
    ///     .route("0.0.0.0/0", |r| r.via("192.168.1.254").dev("eth0"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn route(
        mut self,
        dst: &str,
        f: impl FnOnce(RouteBuilder) -> RouteBuilder,
    ) -> Result<Self, RouteParseError> {
        let builder = f(RouteBuilder::new(dst)?);
        if let Some(error) = builder.error {
            return Err(error);
        }
        let route = builder.build();
        if let Some(why) = route.gateway_family_mismatch() {
            return Err(RouteParseError::InvalidGateway(why));
        }
        self.routes.push(route);
        Ok(self)
    }

    /// Add a qdisc configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::netlink::config::NetworkConfig;
    /// use nlink::util::Percent;
    /// let config = NetworkConfig::new()
    ///     .qdisc("eth0", |q| q.netem().delay_ms(100).loss_pct(Percent::new(1.0)))
    ///     .qdisc("eth1", |q| q.htb().default_class(0x30));
    /// ```
    ///
    /// A builder with no kind (`.netem()`, `.htb(..)`, …), or a setter for
    /// another kind, is reported by [`validate`](Self::validate). With no
    /// kind it used to become an fq_codel — which replaced whatever root
    /// qdisc was there — and a setter called before its kind did nothing
    /// (#476).
    pub fn qdisc(mut self, dev: &str, f: impl FnOnce(QdiscBuilder) -> QdiscBuilder) -> Self {
        match f(QdiscBuilder::new(dev)).build() {
            Ok(qdisc) => self.qdiscs.push(qdisc),
            Err(errors) => self.invalid.extend(errors.into_iter().map(|e| {
                crate::netlink::error::ValidationErrorInfo::new(format!("qdiscs.{dev}"), e)
            })),
        }
        self
    }

    /// Whether it declares an ingress or clsact qdisc on `dev`, the hook a
    /// tree's redirect hangs off.
    pub(crate) fn declares_ingress_hook(&self, dev: &str) -> bool {
        self.qdiscs
            .iter()
            .any(|q| q.dev == dev && q.effective_parent() == QdiscParent::Ingress)
    }

    /// Declare `dev`'s TC tree (#514): HTB, HFSC, DRR or QFQ classes, the
    /// leaf qdisc in a class, and filters with their actions. See
    /// [`TcBuilder`](super::TcBuilder) for what it declares; the device's
    /// root and ingress/clsact qdiscs are declared with
    /// [`qdisc`](Self::qdisc), before this when the tree uses a hook.
    pub fn tc(
        mut self,
        dev: &str,
        f: impl FnOnce(super::tc_tree::TcBuilder) -> super::tc_tree::TcBuilder,
    ) -> Self {
        let hook = self
            .qdiscs
            .iter()
            .find(|q| q.dev == dev && q.effective_parent() == QdiscParent::Ingress)
            .map(|q| match q.qdisc_type {
                QdiscSpec::Clsact => crate::TcHandle::CLSACT_INGRESS,
                _ => crate::TcHandle::INGRESS,
            });
        match f(super::tc_tree::TcBuilder::new(dev, hook)).build() {
            Ok(tree) => match self.tc.iter_mut().find(|t| t.dev == dev) {
                Some(t) => {
                    t.classes.extend(tree.classes);
                    t.leaves.extend(tree.leaves);
                    t.filters.extend(tree.filters);
                }
                None => self.tc.push(tree),
            },
            Err(errors) => self.invalid.extend(errors.into_iter().map(|e| {
                crate::netlink::error::ValidationErrorInfo::new(format!("tc.{dev}"), e)
            })),
        }
        self
    }

    /// The declared TC trees, one per device.
    pub fn tc_trees(&self) -> &[super::tc_tree::DeclaredTc] {
        &self.tc
    }

    /// Get the configured links.
    pub fn links(&self) -> &[DeclaredLink] {
        &self.links
    }

    /// Get the configured addresses.
    pub fn addresses(&self) -> &[DeclaredAddress] {
        &self.addresses
    }

    /// Get the configured routes.
    pub fn routes(&self) -> &[DeclaredRoute] {
        &self.routes
    }

    /// Get the configured qdiscs.
    pub fn qdiscs(&self) -> &[DeclaredQdisc] {
        &self.qdiscs
    }

    /// Get the configured neighbours.
    pub fn neighbours(&self) -> &[DeclaredNeighbour] {
        &self.neighbours
    }

    /// Get the configured FDB entries.
    pub fn fdb_entries(&self) -> &[DeclaredFdb] {
        &self.fdb
    }

    /// Get the configured policy routing rules.
    pub fn rules(&self) -> &[DeclaredRule] {
        &self.rules
    }

    /// Get the configured nexthop objects.
    pub fn nexthops(&self) -> &[DeclaredNexthop] {
        &self.nexthops
    }
}

// ============================================================================
// Link Types
// ============================================================================

/// Declared link configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredLink {
    pub(crate) name: String,
    pub(crate) link_type: DeclaredLinkType,
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) state: LinkState,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) mtu: Option<u32>,
    /// Absent: [`MasterSpec::Unmanaged`]; `null`: [`MasterSpec::None`];
    /// a name: [`MasterSpec::Name`].
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            with = "master_serde",
            skip_serializing_if = "MasterSpec::is_unmanaged"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) master: MasterSpec,
    /// Hardware address, round-tripped as the canonical
    /// `aa:bb:cc:dd:ee:ff` string rather than a raw byte array.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "mac_serde", skip_serializing_if = "Option::is_none")
    )]
    // `mac_serde` renders this as the `aa:bb:..` string, so the
    // schema must say "optional string", not "array of 6 integers".
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) address: Option<[u8; 6]>,
    /// The queue length, alias, group, GSO/GRO limits, promiscuous mode,
    /// protodown and alternative names (#516). Unset ones are left alone.
    #[cfg_attr(feature = "serde", serde(flatten, default))]
    pub(crate) attrs: LinkAttrs,
    /// A bridge's own options (#516): VLAN filtering, STP, timers.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) bridge: Option<BridgeOptions>,
    /// A bridge port's options (#516): learning, flooding, isolation, …
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) port: Option<PortOptions>,
}

/// A bridge's options: a link's `bridge` section (#516). Each one unset is
/// the kernel's and not compared. Build with [`LinkBuilder::bridge_options`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeOptions {
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) vlan_filtering: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) vlan_default_pvid: Option<u16>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) stp: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) priority: Option<u16>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::serde_units::option_duration")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) ageing_time: Option<std::time::Duration>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::serde_units::option_duration")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) forward_delay: Option<std::time::Duration>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::serde_units::option_duration")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) hello_time: Option<std::time::Duration>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", with = "crate::util::serde_units::option_duration")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) max_age: Option<std::time::Duration>,
}

impl BridgeOptions {
    /// VLAN filtering on or off.
    pub fn vlan_filtering(mut self, on: bool) -> Self {
        self.vlan_filtering = Some(on);
        self
    }
    /// The PVID a port joining gets (`vlan_default_pvid`; 0 for none).
    pub fn vlan_default_pvid(mut self, vid: u16) -> Self {
        self.vlan_default_pvid = Some(vid);
        self
    }
    /// The spanning tree on or off.
    pub fn stp(mut self, on: bool) -> Self {
        self.stp = Some(on);
        self
    }
    /// The bridge's STP priority.
    pub fn priority(mut self, priority: u16) -> Self {
        self.priority = Some(priority);
        self
    }
    /// How long an FDB entry lives unrefreshed. The kernel keeps 1/100 s.
    pub fn ageing_time(mut self, t: std::time::Duration) -> Self {
        self.ageing_time = Some(t);
        self
    }
    /// The STP forward delay.
    pub fn forward_delay(mut self, t: std::time::Duration) -> Self {
        self.forward_delay = Some(t);
        self
    }
    /// The STP hello time.
    pub fn hello_time(mut self, t: std::time::Duration) -> Self {
        self.hello_time = Some(t);
        self
    }
    /// The STP max age.
    pub fn max_age(mut self, t: std::time::Duration) -> Self {
        self.max_age = Some(t);
        self
    }
}

/// A bridge port's options: a link's `port` section (#516), for a link
/// whose master is a bridge. Each one unset is the kernel's and not
/// compared. Build with [`LinkBuilder::port_options`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PortOptions {
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) learning: Option<bool>,
    /// Unknown-unicast flooding (`flood`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) flood: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) mcast_flood: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) bcast_flood: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) isolated: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) neigh_suppress: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) hairpin: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) proxy_arp: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) bpdu_guard: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) root_block: Option<bool>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) cost: Option<u32>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) priority: Option<u16>,
    /// The port's VLANs: exactly these, when declared (#516). One the port
    /// has and this does not name is removed, the default PVID a port gets
    /// when it joins a VLAN-filtering bridge included.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) vlans: Option<Vec<PortVlan>>,
}

/// One VLAN of a bridge port (#516): `bridge vlan add vid V [pvid]
/// [untagged]`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PortVlan {
    /// The VLAN id, 1 to 4094.
    pub vid: u16,
    /// Untagged traffic arriving on the port belongs to it.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub pvid: bool,
    /// It leaves the port untagged.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub untagged: bool,
}

impl PortVlan {
    /// VLAN `vid`, with these flags.
    pub fn new(vid: u16, pvid: bool, untagged: bool) -> Self {
        Self { vid, pvid, untagged }
    }
}

impl std::fmt::Display for PortVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vlan {}", self.vid)?;
        if self.pvid {
            f.write_str(" pvid")?;
        }
        if self.untagged {
            f.write_str(" untagged")?;
        }
        Ok(())
    }
}

macro_rules! port_bool {
    ($($(#[$m:meta])* $name:ident),*) => {$(
        $(#[$m])*
        pub fn $name(mut self, on: bool) -> Self {
            self.$name = Some(on);
            self
        }
    )*};
}

impl PortOptions {
    port_bool!(
        /// MAC learning.
        learning,
        /// Unknown-unicast flooding.
        flood,
        /// Multicast flooding.
        mcast_flood,
        /// Broadcast flooding.
        bcast_flood,
        /// Isolated: talks only to non-isolated ports.
        isolated,
        /// ARP/ND suppression.
        neigh_suppress,
        /// Hairpin: frames may leave the port they came in.
        hairpin,
        /// Proxy ARP.
        proxy_arp,
        /// BPDU guard.
        bpdu_guard,
        /// Root block.
        root_block
    );

    /// The STP path cost.
    pub fn cost(mut self, cost: u32) -> Self {
        self.cost = Some(cost);
        self
    }

    /// The STP port priority.
    pub fn priority(mut self, priority: u16) -> Self {
        self.priority = Some(priority);
        self
    }

    /// A tagged VLAN on the port (a trunk member).
    pub fn vlan(self, vid: u16) -> Self {
        self.vlan_with(PortVlan::new(vid, false, false))
    }

    /// A VLAN that leaves the port untagged.
    pub fn untagged(self, vid: u16) -> Self {
        self.vlan_with(PortVlan::new(vid, false, true))
    }

    /// The port's access VLAN: its PVID, leaving untagged.
    pub fn pvid(self, vid: u16) -> Self {
        self.vlan_with(PortVlan::new(vid, true, true))
    }

    /// A VLAN with the flags given.
    pub fn vlan_with(mut self, vlan: PortVlan) -> Self {
        self.vlans.get_or_insert_with(Vec::new).push(vlan);
        self
    }

    /// The imperative config that sets these.
    pub(crate) fn to_config(&self) -> crate::netlink::link::BridgePortConfig {
        crate::netlink::link::BridgePortConfig {
            learning: self.learning,
            unicast_flood: self.flood,
            mcast_flood: self.mcast_flood,
            bcast_flood: self.bcast_flood,
            isolated: self.isolated,
            neigh_suppress: self.neigh_suppress,
            hairpin: self.hairpin,
            proxy_arp: self.proxy_arp,
            bpdu_guard: self.bpdu_guard,
            root_block: self.root_block,
            cost: self.cost,
            priority: self.priority,
            ..Default::default()
        }
    }
}

/// What a link carries besides kind, state, MTU, master and MAC (#516).
/// Each is changed in place; one left unset is not compared.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LinkAttrs {
    /// The transmit queue length (`txqlen`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) txqlen: Option<u32>,
    /// The alias (`IFLA_IFALIAS`, `ip link set … alias`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) alias: Option<String>,
    /// The group (`IFLA_GROUP`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) group: Option<u32>,
    /// The largest GSO packet, in bytes.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) gso_max_size: Option<u32>,
    /// The most segments of a GSO packet.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) gso_max_segs: Option<u32>,
    /// The largest GRO packet, in bytes.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) gro_max_size: Option<u32>,
    /// Promiscuous mode.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) promisc: Option<bool>,
    /// Held down for a control plane (only devices that implement it).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) protodown: Option<bool>,
    /// The alternative names: exactly these, when declared.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) altnames: Option<Vec<String>>,
    /// IPv4 per-device settings by sysctl name (`rp_filter`, `forwarding`,
    /// …), set over netlink before the link comes up.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")
    )]
    pub(crate) ipv4_conf: std::collections::BTreeMap<String, u32>,
    /// IPv6 per-device settings by sysctl name (`accept_dad`,
    /// `disable_ipv6`, …), written to `/proc/sys` in the link's namespace
    /// before it comes up.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")
    )]
    pub(crate) ipv6_conf: std::collections::BTreeMap<String, i32>,
    /// How the kernel makes the IPv6 link-local address.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) addr_gen_mode: Option<crate::netlink::devconf::AddrGenMode>,
    /// The IPv6 interface identifier token (`ip token`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) ipv6_token: Option<std::net::Ipv6Addr>,
}

impl LinkAttrs {
    /// Whether any is declared.
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl DeclaredLink {
    /// Why the declared MAC address cannot go on this kind of link: an
    /// ovpn link, or a netkit link in L3 mode, has no hardware address.
    pub(crate) fn unaddressable_mac(&self) -> Option<&'static str> {
        self.address?;
        match &self.link_type {
            DeclaredLinkType::Ovpn => Some(
                "a MAC address is declared, but an ovpn link is an L3 device with no hardware address",
            ),
            DeclaredLinkType::Ipvlan { .. } => Some(
                "a MAC address is declared, but an ipvlan link shares its parent's and cannot have its own",
            ),
            DeclaredLinkType::Gre(_)
            | DeclaredLinkType::Ipip(_)
            | DeclaredLinkType::Sit(_)
            | DeclaredLinkType::Vti(_)
            | DeclaredLinkType::Ip6tnl(_)
            | DeclaredLinkType::Ip6gre(_)
            | DeclaredLinkType::Vti6(_)
            | DeclaredLinkType::Xfrm { .. }
            | DeclaredLinkType::Bareudp { .. } => Some(
                "a MAC address is declared, but an L3 tunnel has no hardware address (gretap has one)",
            ),
            DeclaredLinkType::Netkit { mode, .. }
                if *mode != Some(crate::netlink::link::NetkitMode::L2) =>
            {
                Some(
                    "a MAC address is declared, but a netkit link in L3 mode (the default) has no \
                     hardware address; declare .netkit_mode(NetkitMode::L2) to give it one",
                )
            }
            _ => None,
        }
    }

    /// The namespace a veth's peer is declared in (#516).
    /// Whether it is a veth whose peer's MAC, MTU or state is declared
    /// (#680).
    pub(crate) fn sets_veth_peer(&self) -> bool {
        matches!(
            &self.link_type,
            DeclaredLinkType::Veth { peer_address, peer_mtu, peer_state, .. }
                if peer_address.is_some() || peer_mtu.is_some() || !peer_state.is_unchanged()
        )
    }

    pub(crate) fn peer_netns(&self) -> Option<&crate::netlink::namespace::NetnsRef> {
        match &self.link_type {
            DeclaredLinkType::Veth { peer_netns, .. } => peer_netns.as_ref(),
            _ => None,
        }
    }

    /// Get the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the link type.
    pub fn link_type(&self) -> &DeclaredLinkType {
        &self.link_type
    }

    /// Get the desired state.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Get the desired MTU.
    pub fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    /// Get the master interface name, when one is declared.
    pub fn master(&self) -> Option<&str> {
        self.master.name()
    }

    /// What this declaration says about the link's master: nothing, "none",
    /// or a name.
    pub fn master_spec(&self) -> &MasterSpec {
        &self.master
    }
}

/// What a link declaration says about its master (#462).
///
/// MTU and MAC are `Option`s that mean "don't care" when unset, and the
/// master was an `Option` that meant "no master": a declaration that did
/// not mention one released the link from whatever enslaved it — a bridge
/// someone else manages, or the VRF a second declaration of the same link
/// named, which then flipped on every apply.
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MasterSpec {
    /// Leave the master as it is. The default.
    #[default]
    Unmanaged,
    /// No master: release the link from one it has
    /// ([`LinkBuilder::nomaster`]).
    None,
    /// Enslave the link to this master ([`LinkBuilder::master`]).
    Name(String),
}

impl MasterSpec {
    /// The master's name, for [`MasterSpec::Name`].
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            _ => None,
        }
    }

    /// `true` for [`MasterSpec::Unmanaged`].
    pub fn is_unmanaged(&self) -> bool {
        matches!(self, Self::Unmanaged)
    }
}

/// `master` as JSON: absent is unmanaged (via `#[serde(default)]`), `null`
/// is "no master", a string is the master's name.
#[cfg(feature = "serde")]
mod master_serde {
    use super::MasterSpec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(spec: &MasterSpec, s: S) -> Result<S::Ok, S::Error> {
        match spec {
            MasterSpec::Name(name) => s.serialize_str(name),
            _ => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MasterSpec, D::Error> {
        Ok(match Option::<String>::deserialize(d)? {
            Some(name) => MasterSpec::Name(name),
            None => MasterSpec::None,
        })
    }
}

/// Link type for declared configuration.
///
/// # Changing a live link's kind or parameters
///
/// The diff compares the kind and every parameter here that the kernel
/// reports back in the link dump. What a live link can take is changed in
/// place: a VXLAN's remote, local address and underlay, a bond's
/// `miimon`, delays, `xmit_hash_policy`, `min_links` and `resend_igmp`, a
/// macvlan's mode (except into or out of passthru), netkit policies. The
/// rest — the kind itself, a VLAN's id, protocol or parent, a VXLAN's VNI
/// or port, a bond's mode, `lacp_rate` or `ad_select`, a macvlan's parent,
/// a VRF's table — the kernel cannot change on a live link, so the apply
/// deletes the link and creates it again, putting back what the config
/// declares on it (see [`ConfigDiff::links_to_recreate`]). It refuses
/// instead if the link carries something the config does not declare —
/// including what a config cannot declare: FDB entries someone added,
/// permanent and proxy neighbours, nexthop objects, multipath routes and
/// routes through a nexthop object, on the link or on the ports a deleted
/// bond or VRF flushes as it releases them.
/// A netkit pair's mode and scrubbing are never changed: recreating the
/// pair would delete a peer that usually lives in another namespace.
///
/// An optional parameter left out is compared against the kernel's
/// default where the kernel fixes one (a VLAN is 802.1Q; a VXLAN has no
/// remote, local address or underlay; netkit is L3 and forwards), and not
/// compared where the default is a module parameter (the VXLAN port, every
/// bond option).
///
/// [`ConfigDiff::links_to_recreate`]: super::ConfigDiff::links_to_recreate
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclaredLinkType {
    /// Dummy interface.
    Dummy,
    /// Veth pair with peer name.
    Veth {
        peer: String,
        /// The namespace the peer lives in (#516). Unset, the apply creates
        /// the peer here and leaves it wherever it is moved — a CNI moving
        /// it into a container is not undone. Set, the peer is kept there:
        /// one elsewhere, here included, is recreated in it.
        /// [`NetnsRef::Default`](crate::netlink::namespace::NetnsRef::Default)
        /// is this namespace.
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
        peer_netns: Option<crate::netlink::namespace::NetnsRef>,
        /// The peer's MAC, in its namespace (#680). A peer in this
        /// namespace is declared as a link of its own instead.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none", with = "mac_serde")
        )]
        #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
        peer_address: Option<[u8; 6]>,
        /// The peer's MTU, in its namespace (#680).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
        peer_mtu: Option<u32>,
        /// The peer's state, in its namespace (#680).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "LinkState::is_unchanged"))]
        peer_state: LinkState,
    },
    /// Bridge interface.
    Bridge,
    /// VLAN interface. Plan 190 §2.2 added `protocol`.
    Vlan {
        parent: String,
        vlan_id: u16,
        /// VLAN tagging protocol; `None` == kernel default
        /// (802.1Q). Use [`VlanProtocol::Dot1ad`] for Q-in-Q.
        protocol: Option<VlanProtocol>,
    },
    /// VXLAN interface. Plan 190 §2.1 added `local`/`port`/`underlay_dev`.
    Vxlan {
        vni: u32,
        remote: Option<IpAddr>,
        /// Tunnel source IP (`IFLA_VXLAN_LOCAL` /
        /// `IFLA_VXLAN_LOCAL6`), either family — but the same family as
        /// `remote`; the kernel refuses a VXLAN that mixes them.
        local: Option<IpAddr>,
        /// UDP destination port (`IFLA_VXLAN_PORT`). Left out, the
        /// kernel uses the `vxlan` module's `udp_port` parameter — 8472
        /// unless set, not the IANA 4789.
        port: Option<u16>,
        /// Underlay parent device by name
        /// (`IFLA_VXLAN_LINK`).
        underlay_dev: Option<String>,
    },
    /// Macvlan interface.
    Macvlan { parent: String, mode: MacvlanMode },
    /// Ipvlan interface (#516): it shares its parent's MAC.
    Ipvlan {
        parent: String,
        mode: IpvlanMode,
        isolation: IpvlanIsolation,
    },
    /// Macvtap interface (#516): a macvlan with a tap queue.
    Macvtap { parent: String, mode: MacvlanMode },
    /// GRE tunnel (#516).
    Gre(TunnelParams),
    /// GRE tunnel carrying Ethernet (#516).
    Gretap(TunnelParams),
    /// IPv4-in-IPv4 tunnel (#516).
    Ipip(TunnelParams),
    /// IPv6-in-IPv4 tunnel (#516).
    Sit(TunnelParams),
    /// IPsec virtual tunnel interface (#516).
    Vti(TunnelParams),
    /// IPv6 tunnel, IPv6 or IPv4 over IPv6 (#516).
    Ip6tnl(Ip6tnlParams),
    /// GRE over IPv6 (#516); its `mode` is unused.
    Ip6gre(Ip6tnlParams),
    /// GRE over IPv6 carrying Ethernet (#516); its `mode` is unused.
    Ip6gretap(Ip6tnlParams),
    /// IPsec virtual tunnel interface over IPv6 (#680); its `mode`, hop
    /// limit and encapsulation limit are unused.
    Vti6(Ip6tnlParams),
    /// ERSPAN tunnel over IPv4 (#680): a gretap that wraps what it mirrors
    /// in an ERSPAN header.
    Erspan(ErspanParams),
    /// ERSPAN tunnel over IPv6 (#680).
    Ip6erspan(ErspanParams),
    /// XFRM (IPsec) interface (#516): routed traffic meets the IPsec
    /// policies with its `if_id`. The if_id changes in place; a new
    /// underlay, which `xfrmi_changelink` refuses, recreates it.
    Xfrm {
        /// The policies' interface id; not 0.
        if_id: u32,
        /// The device its packets leave through.
        underlay_dev: Option<String>,
    },
    /// Geneve tunnel (#516). The VNI, port and the remote's family are
    /// fixed at create; the remote, TTL and TOS change in place.
    Geneve {
        vni: u32,
        remote: Option<IpAddr>,
        ttl: Option<u8>,
        tos: Option<u8>,
        /// The UDP port; the kernel's 6081 when unset.
        port: Option<u16>,
    },
    /// MACsec (IEEE 802.1AE) link on `parent` (#516). The SCI and port are
    /// fixed at create; encryption, protection, SCI inclusion and the
    /// replay window change in place. Its keys and SAs are the MACsec
    /// Generic Netlink API's, not a declaration's.
    Macsec {
        parent: String,
        /// The Secure Channel Identifier, MAC then port as `ip macsec`
        /// shows it; the kernel derives one from the parent's MAC and
        /// [`port`](Self::Macsec::port) when unset.
        sci: Option<u64>,
        port: Option<u16>,
        encrypt: Option<bool>,
        protect: Option<bool>,
        include_sci: Option<bool>,
        /// Replay protection with this window; unset leaves it alone.
        replay_window: Option<u32>,
    },
    /// Bare UDP tunnel (#516): an L3 tunnel of `ethertype` over UDP `port`.
    /// It has no changelink, so any change is a recreate. Unverified on a
    /// live kernel: the one these were written on does not build it.
    Bareudp {
        port: u16,
        ethertype: u16,
        srcport_min: Option<u16>,
        multiproto: bool,
    },
    /// Bond interface. Plan 190 §8 added 5 new option knobs.
    Bond {
        mode: BondMode,
        miimon: Option<u32>,
        /// Typed since 0.31: as a raw `u8`, the create path dropped an
        /// invalid value and the in-place update sent it, so every apply
        /// after the first failed with `EINVAL` (#476).
        xmit_hash_policy: Option<BondXmitHashPolicy>,
        min_links: Option<u32>,
        /// 802.3ad aggregator selection logic. Plan 190 §8.
        ad_select: Option<BondAdSelect>,
        /// LACPDU transmit rate. Plan 190 §8.
        lacp_rate: Option<BondLacpRate>,
        /// Time (ms) to wait before disabling a slave on
        /// link-down. Plan 190 §8.
        downdelay: Option<u32>,
        /// Time (ms) to wait before enabling a slave on
        /// link-up. Plan 190 §8.
        updelay: Option<u32>,
        /// Number of IGMP membership reports to resend on
        /// failover. Plan 190 §8.
        resend_igmp: Option<u32>,
    },
    /// IFB (Intermediate Functional Block).
    Ifb,
    /// VRF (Virtual Routing & Forwarding) — table-scoped
    /// forwarding domain. Members enslave via
    /// [`LinkBuilder::master`]. Plan 190 §2.3.
    Vrf { table: u32 },
    /// OpenVPN data-channel-offload link (kernel 6.16+).
    /// Link-half only — peer / cipher config goes through
    /// the GENL `ovpn` family (Plan 197 / 0.20). Plan 190 §2.3b.
    Ovpn,
    /// Netkit BPF-programmable veth pair (kernel 6.7+).
    /// Plan 190 §2.3a.
    Netkit {
        /// Name of the peer interface.
        peer: String,
        /// L2 vs L3 operating mode.
        mode: Option<NetkitMode>,
        /// Default policy on the primary peer.
        primary_policy: Option<NetkitPolicy>,
        /// Default policy on the peer interface.
        peer_policy: Option<NetkitPolicy>,
        /// Scrub mode on the primary peer (kernel 6.10+).
        scrub: Option<NetkitScrub>,
        /// Scrub mode on the peer interface (kernel 6.10+).
        peer_scrub: Option<NetkitScrub>,
    },
    /// Existing physical interface (not created, only configured).
    Physical,
}

impl DeclaredLinkType {
    /// Get the kind string for this link type.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Self::Dummy => Some("dummy"),
            Self::Veth { .. } => Some("veth"),
            Self::Bridge => Some("bridge"),
            Self::Vlan { .. } => Some("vlan"),
            Self::Vxlan { .. } => Some("vxlan"),
            Self::Macvlan { .. } => Some("macvlan"),
            Self::Ipvlan { .. } => Some("ipvlan"),
            Self::Macvtap { .. } => Some("macvtap"),
            Self::Gre(_) => Some("gre"),
            Self::Gretap(_) => Some("gretap"),
            Self::Ipip(_) => Some("ipip"),
            Self::Sit(_) => Some("sit"),
            Self::Vti(_) => Some("vti"),
            Self::Ip6tnl(_) => Some("ip6tnl"),
            Self::Ip6gre(_) => Some("ip6gre"),
            Self::Ip6gretap(_) => Some("ip6gretap"),
            Self::Vti6(_) => Some("vti6"),
            Self::Erspan(_) => Some("erspan"),
            Self::Ip6erspan(_) => Some("ip6erspan"),
            Self::Xfrm { .. } => Some("xfrm"),
            Self::Geneve { .. } => Some("geneve"),
            Self::Bareudp { .. } => Some("bareudp"),
            Self::Macsec { .. } => Some("macsec"),
            Self::Bond { .. } => Some("bond"),
            Self::Ifb => Some("ifb"),
            Self::Vrf { .. } => Some("vrf"),
            Self::Netkit { .. } => Some("netkit"),
            Self::Ovpn => Some("ovpn"),
            Self::Physical => None,
        }
    }
}

/// Link state (up or down).
///
/// The default is [`Unchanged`](Self::Unchanged), as for a link declared
/// through [`LinkBuilder`] without `.up()` or `.down()`. It used to be
/// `Down`, which is what serde filled in for a JSON/YAML link that omits
/// `state` — so declaring only a NIC's MTU in a document took the NIC
/// down.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LinkState {
    /// Interface should be up.
    Up,
    /// Interface should be down.
    Down,
    /// Don't change the state.
    #[default]
    Unchanged,
}

impl LinkState {
    /// `Unchanged`: nothing declared.
    pub fn is_unchanged(&self) -> bool {
        *self == Self::Unchanged
    }
}

/// Macvlan mode.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MacvlanMode {
    /// Private mode (no communication between macvlans).
    Private,
    /// VEPA mode (Virtual Ethernet Port Aggregator).
    Vepa,
    /// Bridge mode (macvlans can communicate).
    #[default]
    Bridge,
    /// Passthru mode (single macvlan, exclusive access).
    Passthru,
    /// Source mode (filter by source MAC).
    Source,
}

/// An IPv4 tunnel's parameters (#516): a gre, gretap, ipip, sit or vti
/// link. Each one unset is the kernel's default (no address, TTL inherited,
/// no key, no underlay device), and a change sends them all: a tunnel's
/// `changelink` takes its whole configuration from the request.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunnelParams {
    /// The local end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub local: Option<std::net::Ipv4Addr>,
    /// The remote end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub remote: Option<std::net::Ipv4Addr>,
    /// The outer TTL (not for vti). Unset is the kernel's — inherit for
    /// gre and ipip, 64 for sit — and not compared.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u8>,
    /// The key, both ways (gre, gretap and vti only).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub key: Option<u32>,
    /// The device the tunnel's packets leave through.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub underlay_dev: Option<String>,
}

/// An ip6tnl tunnel's parameters (#516). Each one unset is the kernel's
/// default (no address, hop limit inherited, an encapsulation limit of 0,
/// no underlay device) and is not compared; a change sends them all, since
/// `ip6_tnl_changelink` takes the whole configuration from the request.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ip6tnlParams {
    /// The local end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub local: Option<std::net::Ipv6Addr>,
    /// The remote end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub remote: Option<std::net::Ipv6Addr>,
    /// The outer hop limit.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub hoplimit: Option<u8>,
    /// The tunnel encapsulation limit (RFC 2473).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub encap_limit: Option<u8>,
    /// What it carries; either by default. An ip6tnl's only.
    #[cfg_attr(feature = "serde", serde(default))]
    pub mode: crate::netlink::link::Ip6tnlMode,
    /// The GRE key, both ways: an ip6gre's or ip6gretap's only.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub key: Option<u32>,
    /// The device the tunnel's packets leave through.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub underlay_dev: Option<String>,
}

/// An ERSPAN tunnel's parameters (#680): an `erspan`'s ends are IPv4, an
/// `ip6erspan`'s IPv6. Each one unset is the kernel's default and is not
/// compared; a change sends them all, since `erspan_changelink` rebuilds
/// the configuration from the request.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErspanParams {
    /// The session id, the GRE key both ways: 10 bits, up to 1023.
    pub session: u16,
    /// The ERSPAN header: type II with its index, or type III with its
    /// direction and hardware id.
    #[cfg_attr(feature = "serde", serde(default))]
    pub version: crate::netlink::link::ErspanVersion,
    /// The local end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub local: Option<IpAddr>,
    /// The remote end.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub remote: Option<IpAddr>,
    /// The outer TTL, or hop limit.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub ttl: Option<u8>,
    /// The device the tunnel's packets leave through.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub underlay_dev: Option<String>,
}

/// Ipvlan mode (#516).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IpvlanMode {
    /// L2: the slaves see the parent's broadcasts.
    #[default]
    L2,
    /// L3: routed, no broadcast or multicast.
    L3,
    /// L3 with netfilter on the slave (`l3s`).
    L3s,
}

/// Ipvlan isolation between slaves (#516).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IpvlanIsolation {
    /// Slaves talk to each other.
    #[default]
    Bridge,
    /// They do not.
    Private,
    /// Their traffic goes out through the parent.
    Vepa,
}

/// Bond mode.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BondMode {
    /// Round-robin (balance-rr).
    #[default]
    BalanceRr,
    /// Active-backup.
    ActiveBackup,
    /// XOR (balance-xor).
    BalanceXor,
    /// Broadcast.
    Broadcast,
    /// 802.3ad (LACP).
    Ieee802_3ad,
    /// Transmit load balancing.
    BalanceTlb,
    /// Adaptive load balancing.
    BalanceAlb,
}

/// Builder for link configuration.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct LinkBuilder {
    name: String,
    link_type: DeclaredLinkType,
    state: LinkState,
    mtu: Option<u32>,
    master: MasterSpec,
    address: Option<[u8; 6]>,
    attrs: LinkAttrs,
    bridge: Option<BridgeOptions>,
    port: Option<PortOptions>,
    /// Setters called for another kind, which did nothing. `link` moves
    /// them into the config, where `validate()` reports them (#518).
    errors: Vec<String>,
}

impl LinkBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            link_type: DeclaredLinkType::Physical,
            state: LinkState::Unchanged,
            mtu: None,
            master: MasterSpec::Unmanaged,
            address: None,
            attrs: LinkAttrs::default(),
            bridge: None,
            port: None,
            errors: Vec::new(),
        }
    }

    /// A builder holding what `link` already declares, for
    /// [`NetworkConfig::link`]'s upsert.
    fn from_declared(link: DeclaredLink) -> Self {
        Self {
            name: link.name,
            link_type: link.link_type,
            state: link.state,
            mtu: link.mtu,
            master: link.master,
            address: link.address,
            attrs: link.attrs,
            bridge: link.bridge,
            port: link.port,
            errors: Vec::new(),
        }
    }

    /// Record a setter called for the wrong kind: it did nothing, which
    /// [`NetworkConfig::validate`] reports, as `QdiscBuilder` does (#476,
    /// #518).
    fn wrong_kind(&mut self, setter: &str, kind: &str) {
        let is = match self.link_type.kind() {
            Some(k) => format!("is a {k}"),
            None => "has no kind (choose the kind first)".to_string(),
        };
        self.errors.push(format!(
            "`.{setter}()` sets a {kind} parameter, but link {} {is}",
            self.name
        ));
    }

    /// Create a dummy interface.
    pub fn dummy(mut self) -> Self {
        self.link_type = DeclaredLinkType::Dummy;
        self
    }

    /// Create a veth pair with the given peer name.
    pub fn veth(mut self, peer: &str) -> Self {
        self.link_type = DeclaredLinkType::Veth {
            peer: peer.to_string(),
            peer_netns: None,
            peer_address: None,
            peer_mtu: None,
            peer_state: LinkState::Unchanged,
        };
        self
    }

    /// The namespace a veth's peer lives in (#516): created there, and
    /// kept there. Without it the peer is created here and left wherever
    /// it is moved.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::netlink::namespace::NetnsRef;
    ///
    /// let config = NetworkConfig::new().link("veth0", |l| {
    ///     l.veth("eth0").veth_peer_netns(NetnsRef::Named("tenant-a".into()))
    /// });
    /// config.validate().unwrap();
    /// ```
    pub fn veth_peer_netns(mut self, netns: crate::netlink::namespace::NetnsRef) -> Self {
        if let DeclaredLinkType::Veth { peer_netns, .. } = &mut self.link_type {
            *peer_netns = Some(netns);
        } else {
            self.wrong_kind("veth_peer_netns", "veth");
        }
        self
    }

    /// The MAC of a veth's peer in [`veth_peer_netns`](Self::veth_peer_netns)
    /// (#680): set at create, and changed in place there.
    ///
    /// A peer in this namespace is a link of its own: declare it with
    /// [`NetworkConfig::link`] and set it there.
    pub fn veth_peer_address(mut self, mac: [u8; 6]) -> Self {
        if let DeclaredLinkType::Veth { peer_address, .. } = &mut self.link_type {
            *peer_address = Some(mac);
        } else {
            self.wrong_kind("veth_peer_address", "veth");
        }
        self
    }

    /// The MTU of a veth's peer in [`veth_peer_netns`](Self::veth_peer_netns)
    /// (#680).
    pub fn veth_peer_mtu(mut self, mtu: u32) -> Self {
        if let DeclaredLinkType::Veth { peer_mtu, .. } = &mut self.link_type {
            *peer_mtu = Some(mtu);
        } else {
            self.wrong_kind("veth_peer_mtu", "veth");
        }
        self
    }

    /// Bring a veth's peer in [`veth_peer_netns`](Self::veth_peer_netns) up
    /// (#680).
    pub fn veth_peer_up(self) -> Self {
        self.veth_peer_state("veth_peer_up", LinkState::Up)
    }

    /// Keep a veth's peer in [`veth_peer_netns`](Self::veth_peer_netns)
    /// down (#680).
    pub fn veth_peer_down(self) -> Self {
        self.veth_peer_state("veth_peer_down", LinkState::Down)
    }

    fn veth_peer_state(mut self, setter: &str, state: LinkState) -> Self {
        if let DeclaredLinkType::Veth { peer_state, .. } = &mut self.link_type {
            *peer_state = state;
        } else {
            self.wrong_kind(setter, "veth");
        }
        self
    }

    /// Create a bridge interface.
    pub fn bridge(mut self) -> Self {
        self.link_type = DeclaredLinkType::Bridge;
        self
    }

    /// Create a VLAN interface on the given parent with the specified VLAN ID.
    pub fn vlan(mut self, parent: &str, vlan_id: u16) -> Self {
        self.link_type = DeclaredLinkType::Vlan {
            parent: parent.to_string(),
            vlan_id,
            protocol: None,
        };
        self
    }

    /// Set the VLAN tagging protocol. Defaults to 802.1Q
    /// (kernel default) when unset. Use
    /// [`VlanProtocol::Dot1ad`] for Q-in-Q stacked VLAN
    /// encap. Plan 190 §2.2. No-op if the link isn't a VLAN.
    pub fn vlan_protocol(mut self, p: VlanProtocol) -> Self {
        if let DeclaredLinkType::Vlan { protocol, .. } = &mut self.link_type {
            *protocol = Some(p);
        } else {
            self.wrong_kind("vlan_protocol", "vlan");
        }
        self
    }

    /// Create a VXLAN interface with the given VNI.
    pub fn vxlan(mut self, vni: u32) -> Self {
        self.link_type = DeclaredLinkType::Vxlan {
            vni,
            remote: None,
            local: None,
            port: None,
            underlay_dev: None,
        };
        self
    }

    /// Set the VXLAN remote endpoint (`IFLA_VXLAN_GROUP` /
    /// `IFLA_VXLAN_GROUP6`), IPv4 or IPv6. No-op if the builder isn't a
    /// VXLAN.
    pub fn vxlan_remote(mut self, remote_addr: IpAddr) -> Self {
        if let DeclaredLinkType::Vxlan { remote, .. } = &mut self.link_type {
            *remote = Some(remote_addr);
        } else {
            self.wrong_kind("vxlan_remote", "vxlan");
        }
        self
    }

    /// Set the VXLAN tunnel source IP (`IFLA_VXLAN_LOCAL` /
    /// `IFLA_VXLAN_LOCAL6`), IPv4 or IPv6 — the same family as the
    /// remote, or the kernel refuses the link ("Local and remote address
    /// must be from the same family"). An IPv6 one used to be dropped
    /// (#418). Plan 190 §2.1.
    pub fn vxlan_local(mut self, local_addr: IpAddr) -> Self {
        if let DeclaredLinkType::Vxlan { local, .. } = &mut self.link_type {
            *local = Some(local_addr);
        } else {
            self.wrong_kind("vxlan_local", "vxlan");
        }
        self
    }

    /// Set the VXLAN UDP destination port (`IFLA_VXLAN_PORT`). Left
    /// unset, the kernel uses the `vxlan` module's `udp_port` parameter,
    /// which is 8472 unless set — declare 4789 for the IANA port.
    /// Plan 190 §2.1.
    pub fn vxlan_port(mut self, udp_port: u16) -> Self {
        if let DeclaredLinkType::Vxlan { port, .. } = &mut self.link_type {
            *port = Some(udp_port);
        } else {
            self.wrong_kind("vxlan_port", "vxlan");
        }
        self
    }

    /// Set the VXLAN underlay parent device name
    /// (`IFLA_VXLAN_LINK`). Plan 190 §2.1.
    pub fn vxlan_underlay_dev(mut self, dev: impl Into<String>) -> Self {
        if let DeclaredLinkType::Vxlan {
            underlay_dev, ..
        } = &mut self.link_type
        {
            *underlay_dev = Some(dev.into());
        } else {
            self.wrong_kind("vxlan_underlay_dev", "vxlan");
        }
        self
    }

    /// Create a macvlan interface on the given parent.
    pub fn macvlan(mut self, parent: &str) -> Self {
        self.link_type = DeclaredLinkType::Macvlan {
            parent: parent.to_string(),
            mode: MacvlanMode::default(),
        };
        self
    }

    /// Set the macvlan mode.
    pub fn macvlan_mode(mut self, mode: MacvlanMode) -> Self {
        if let DeclaredLinkType::Macvlan { parent, .. } = &self.link_type {
            self.link_type = DeclaredLinkType::Macvlan {
                parent: parent.clone(),
                mode,
            };
        } else {
            self.wrong_kind("macvlan_mode", "macvlan");
        }
        self
    }

    /// Create a GRE tunnel (#516); set its ends with the `tunnel_*` setters.
    pub fn gre(mut self) -> Self {
        self.link_type = DeclaredLinkType::Gre(TunnelParams::default());
        self
    }

    /// Create a GRE tunnel carrying Ethernet (#516).
    pub fn gretap(mut self) -> Self {
        self.link_type = DeclaredLinkType::Gretap(TunnelParams::default());
        self
    }

    /// Create an IPv4-in-IPv4 tunnel (#516).
    pub fn ipip(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ipip(TunnelParams::default());
        self
    }

    /// Create an IPv6-in-IPv4 (sit) tunnel (#516).
    pub fn sit(mut self) -> Self {
        self.link_type = DeclaredLinkType::Sit(TunnelParams::default());
        self
    }

    /// Create an IPsec virtual tunnel interface (#516).
    pub fn vti(mut self) -> Self {
        self.link_type = DeclaredLinkType::Vti(TunnelParams::default());
        self
    }

    fn tunnel_params(&mut self, setter: &str) -> Option<&mut TunnelParams> {
        let is_tunnel = matches!(
            self.link_type,
            DeclaredLinkType::Gre(_)
                | DeclaredLinkType::Gretap(_)
                | DeclaredLinkType::Ipip(_)
                | DeclaredLinkType::Sit(_)
                | DeclaredLinkType::Vti(_)
        );
        if !is_tunnel {
            self.wrong_kind(setter, "gre, gretap, ipip, sit or vti");
            return None;
        }
        match &mut self.link_type {
            DeclaredLinkType::Gre(p)
            | DeclaredLinkType::Gretap(p)
            | DeclaredLinkType::Ipip(p)
            | DeclaredLinkType::Sit(p)
            | DeclaredLinkType::Vti(p) => Some(p),
            _ => None,
        }
    }

    /// A tunnel's local end.
    pub fn tunnel_local(mut self, local: std::net::Ipv4Addr) -> Self {
        if let Some(p) = self.tunnel_params("tunnel_local") {
            p.local = Some(local);
        }
        self
    }

    /// A tunnel's remote end.
    pub fn tunnel_remote(mut self, remote: std::net::Ipv4Addr) -> Self {
        if let Some(p) = self.tunnel_params("tunnel_remote") {
            p.remote = Some(remote);
        }
        self
    }

    /// A tunnel's outer TTL (not vti).
    pub fn tunnel_ttl(mut self, ttl: u8) -> Self {
        if matches!(self.link_type, DeclaredLinkType::Vti(_)) {
            self.wrong_kind("tunnel_ttl", "gre, gretap, ipip or sit");
        } else if let Some(p) = self.tunnel_params("tunnel_ttl") {
            p.ttl = Some(ttl);
        }
        self
    }

    /// A tunnel's key, both ways (gre, gretap, vti, ip6gre, ip6gretap,
    /// vti6). An ERSPAN tunnel's key is its session id.
    pub fn tunnel_key(mut self, key: u32) -> Self {
        if let DeclaredLinkType::Ip6gre(p) | DeclaredLinkType::Ip6gretap(p) | DeclaredLinkType::Vti6(p) =
            &mut self.link_type
        {
            p.key = Some(key);
        } else if matches!(
            self.link_type,
            DeclaredLinkType::Ipip(_) | DeclaredLinkType::Sit(_) | DeclaredLinkType::Ip6tnl(_)
        ) {
            self.wrong_kind("tunnel_key", "gre, gretap, vti, ip6gre, ip6gretap or vti6");
        } else if let Some(p) = self.tunnel_params("tunnel_key") {
            p.key = Some(key);
        }
        self
    }

    /// The device a tunnel's packets leave through: a gre, gretap, ipip,
    /// sit, vti, ip6tnl, ip6gre, ip6gretap, vti6, erspan, ip6erspan or xfrm
    /// link's.
    pub fn tunnel_underlay_dev(mut self, dev: &str) -> Self {
        match &mut self.link_type {
            DeclaredLinkType::Ip6tnl(p)
            | DeclaredLinkType::Ip6gre(p)
            | DeclaredLinkType::Ip6gretap(p)
            | DeclaredLinkType::Vti6(p) => p.underlay_dev = Some(dev.to_string()),
            DeclaredLinkType::Erspan(p) | DeclaredLinkType::Ip6erspan(p) => {
                p.underlay_dev = Some(dev.to_string())
            }
            DeclaredLinkType::Xfrm { underlay_dev, .. } => *underlay_dev = Some(dev.to_string()),
            _ => {
                if let Some(p) = self.tunnel_params("tunnel_underlay_dev") {
                    p.underlay_dev = Some(dev.to_string());
                }
            }
        }
        self
    }

    /// Create an IPv6 tunnel (#516); set it with the `ip6tnl_*` setters.
    pub fn ip6tnl(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ip6tnl(Ip6tnlParams::default());
        self
    }

    fn ip6tnl_params(mut self, setter: &str, set: impl FnOnce(&mut Ip6tnlParams)) -> Self {
        match &mut self.link_type {
            DeclaredLinkType::Ip6tnl(p)
            | DeclaredLinkType::Ip6gre(p)
            | DeclaredLinkType::Ip6gretap(p)
            | DeclaredLinkType::Vti6(p) => set(p),
            _ => self.wrong_kind(setter, "ip6tnl, ip6gre, ip6gretap or vti6"),
        }
        self
    }

    /// Create a GRE tunnel over IPv6 (#516); set it with the `ip6tnl_*`
    /// setters and [`tunnel_key`](Self::tunnel_key).
    pub fn ip6gre(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ip6gre(Ip6tnlParams::default());
        self
    }

    /// Create a GRE tunnel over IPv6 carrying Ethernet (#516).
    pub fn ip6gretap(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ip6gretap(Ip6tnlParams::default());
        self
    }

    /// Create an IPsec virtual tunnel interface over IPv6 (#680); set its
    /// ends with [`ip6tnl_local`](Self::ip6tnl_local) and
    /// [`ip6tnl_remote`](Self::ip6tnl_remote), its key with
    /// [`tunnel_key`](Self::tunnel_key).
    pub fn vti6(mut self) -> Self {
        self.link_type = DeclaredLinkType::Vti6(Ip6tnlParams::default());
        self
    }

    /// Create an ERSPAN tunnel over IPv4 with this session id (#680); set
    /// it with the `erspan_*` setters.
    pub fn erspan(mut self, session: u16) -> Self {
        self.link_type = DeclaredLinkType::Erspan(ErspanParams {
            session,
            ..ErspanParams::default()
        });
        self
    }

    /// Create an ERSPAN tunnel over IPv6 with this session id (#680).
    pub fn ip6erspan(mut self, session: u16) -> Self {
        self.link_type = DeclaredLinkType::Ip6erspan(ErspanParams {
            session,
            ..ErspanParams::default()
        });
        self
    }

    fn erspan_params(mut self, setter: &str, set: impl FnOnce(&mut ErspanParams)) -> Self {
        match &mut self.link_type {
            DeclaredLinkType::Erspan(p) | DeclaredLinkType::Ip6erspan(p) => set(p),
            _ => self.wrong_kind(setter, "erspan or ip6erspan"),
        }
        self
    }

    /// An ERSPAN tunnel's local end: IPv4 for erspan, IPv6 for ip6erspan.
    pub fn erspan_local(self, local: impl Into<IpAddr>) -> Self {
        let local = local.into();
        self.erspan_params("erspan_local", |p| p.local = Some(local))
    }

    /// An ERSPAN tunnel's remote end.
    pub fn erspan_remote(self, remote: impl Into<IpAddr>) -> Self {
        let remote = remote.into();
        self.erspan_params("erspan_remote", |p| p.remote = Some(remote))
    }

    /// An ERSPAN tunnel's outer TTL, or hop limit.
    pub fn erspan_ttl(self, ttl: u8) -> Self {
        self.erspan_params("erspan_ttl", |p| p.ttl = Some(ttl))
    }

    /// An ERSPAN tunnel's header version: type II and an index, or type
    /// III and a direction and hardware id.
    pub fn erspan_version(self, version: crate::netlink::link::ErspanVersion) -> Self {
        self.erspan_params("erspan_version", |p| p.version = version)
    }

    /// An ip6tnl tunnel's local end.
    pub fn ip6tnl_local(self, addr: std::net::Ipv6Addr) -> Self {
        self.ip6tnl_params("ip6tnl_local", |p| p.local = Some(addr))
    }

    /// An ip6tnl tunnel's remote end.
    pub fn ip6tnl_remote(self, addr: std::net::Ipv6Addr) -> Self {
        self.ip6tnl_params("ip6tnl_remote", |p| p.remote = Some(addr))
    }

    /// An ip6tnl tunnel's outer hop limit.
    pub fn ip6tnl_hoplimit(self, hoplimit: u8) -> Self {
        self.ip6tnl_params("ip6tnl_hoplimit", |p| p.hoplimit = Some(hoplimit))
    }

    /// An ip6tnl tunnel's encapsulation limit.
    pub fn ip6tnl_encap_limit(self, limit: u8) -> Self {
        self.ip6tnl_params("ip6tnl_encap_limit", |p| p.encap_limit = Some(limit))
    }

    /// What an ip6tnl tunnel carries.
    pub fn ip6tnl_mode(self, mode: crate::netlink::link::Ip6tnlMode) -> Self {
        self.ip6tnl_params("ip6tnl_mode", |p| p.mode = mode)
    }

    /// Create an XFRM interface with `if_id` (#516).
    pub fn xfrm(mut self, if_id: u32) -> Self {
        self.link_type = DeclaredLinkType::Xfrm {
            if_id,
            underlay_dev: None,
        };
        self
    }

    /// Create a Geneve tunnel with `vni` (#516).
    pub fn geneve(mut self, vni: u32) -> Self {
        self.link_type = DeclaredLinkType::Geneve {
            vni,
            remote: None,
            ttl: None,
            tos: None,
            port: None,
        };
        self
    }

    /// A Geneve tunnel's remote end (IPv4 or IPv6).
    pub fn geneve_remote(mut self, addr: IpAddr) -> Self {
        if let DeclaredLinkType::Geneve { remote, .. } = &mut self.link_type {
            *remote = Some(addr);
        } else {
            self.wrong_kind("geneve_remote", "geneve");
        }
        self
    }

    /// A Geneve tunnel's outer TTL.
    pub fn geneve_ttl(mut self, want: u8) -> Self {
        if let DeclaredLinkType::Geneve { ttl, .. } = &mut self.link_type {
            *ttl = Some(want);
        } else {
            self.wrong_kind("geneve_ttl", "geneve");
        }
        self
    }

    /// A Geneve tunnel's outer TOS.
    pub fn geneve_tos(mut self, want: u8) -> Self {
        if let DeclaredLinkType::Geneve { tos, .. } = &mut self.link_type {
            *tos = Some(want);
        } else {
            self.wrong_kind("geneve_tos", "geneve");
        }
        self
    }

    /// A Geneve tunnel's UDP port.
    pub fn geneve_port(mut self, want: u16) -> Self {
        if let DeclaredLinkType::Geneve { port, .. } = &mut self.link_type {
            *port = Some(want);
        } else {
            self.wrong_kind("geneve_port", "geneve");
        }
        self
    }

    /// Create a MACsec link on `parent` (#516).
    pub fn macsec(mut self, parent: &str) -> Self {
        self.link_type = DeclaredLinkType::Macsec {
            parent: parent.to_string(),
            sci: None,
            port: None,
            encrypt: None,
            protect: None,
            include_sci: None,
            replay_window: None,
        };
        self
    }

    fn macsec_field<T>(
        mut self,
        setter: &str,
        set: impl FnOnce(&mut Option<u64>, &mut Option<u16>, &mut Option<bool>, &mut Option<bool>, &mut Option<bool>, &mut Option<u32>) -> T,
    ) -> Self {
        if let DeclaredLinkType::Macsec {
            sci,
            port,
            encrypt,
            protect,
            include_sci,
            replay_window,
            ..
        } = &mut self.link_type
        {
            set(sci, port, encrypt, protect, include_sci, replay_window);
        } else {
            self.wrong_kind(setter, "macsec");
        }
        self
    }

    /// A MACsec link's SCI (fixed at create).
    pub fn macsec_sci(self, v: u64) -> Self {
        self.macsec_field("macsec_sci", |sci, _, _, _, _, _| *sci = Some(v))
    }

    /// The port the kernel derives a MACsec SCI with (fixed at create).
    pub fn macsec_port(self, v: u16) -> Self {
        self.macsec_field("macsec_port", |_, port, _, _, _, _| *port = Some(v))
    }

    /// Encrypt, or only authenticate.
    pub fn macsec_encrypt(self, on: bool) -> Self {
        self.macsec_field("macsec_encrypt", |_, _, e, _, _, _| *e = Some(on))
    }

    /// Protect frames at all.
    pub fn macsec_protect(self, on: bool) -> Self {
        self.macsec_field("macsec_protect", |_, _, _, p, _, _| *p = Some(on))
    }

    /// Put the SCI in every frame. Leaving it out needs end-station or
    /// SCB mode, which a declaration does not model: `false` is refused.
    pub fn macsec_include_sci(self, on: bool) -> Self {
        self.macsec_field("macsec_include_sci", |_, _, _, _, i, _| *i = Some(on))
    }

    /// Replay protection with `window`.
    pub fn macsec_replay_window(self, window: u32) -> Self {
        self.macsec_field("macsec_replay_window", |_, _, _, _, _, w| *w = Some(window))
    }

    /// Create a bare UDP tunnel of `ethertype` (0x8847 MPLS, 0x0800 IPv4,
    /// …) over UDP `port` (#516). Unverified on a live kernel.
    pub fn bareudp(mut self, port: u16, ethertype: u16) -> Self {
        self.link_type = DeclaredLinkType::Bareudp {
            port,
            ethertype,
            srcport_min: None,
            multiproto: false,
        };
        self
    }

    /// A bare UDP tunnel's lowest source port.
    pub fn bareudp_srcport_min(mut self, want: u16) -> Self {
        if let DeclaredLinkType::Bareudp { srcport_min, .. } = &mut self.link_type {
            *srcport_min = Some(want);
        } else {
            self.wrong_kind("bareudp_srcport_min", "bareudp");
        }
        self
    }

    /// A bare UDP tunnel's multiprotocol mode (MPLS unicast and multicast,
    /// or IPv4 and IPv6).
    pub fn bareudp_multiproto(mut self, on: bool) -> Self {
        if let DeclaredLinkType::Bareudp { multiproto, .. } = &mut self.link_type {
            *multiproto = on;
        } else {
            self.wrong_kind("bareudp_multiproto", "bareudp");
        }
        self
    }

    /// Create an ipvlan interface on `parent` (#516). It shares the
    /// parent's MAC, so it takes no [`address`](Self::address).
    pub fn ipvlan(mut self, parent: &str) -> Self {
        self.link_type = DeclaredLinkType::Ipvlan {
            parent: parent.to_string(),
            mode: IpvlanMode::default(),
            isolation: IpvlanIsolation::default(),
        };
        self
    }

    /// Set the ipvlan mode.
    pub fn ipvlan_mode(mut self, want: IpvlanMode) -> Self {
        if let DeclaredLinkType::Ipvlan { mode, .. } = &mut self.link_type {
            *mode = want;
        } else {
            self.wrong_kind("ipvlan_mode", "ipvlan");
        }
        self
    }

    /// Set the ipvlan isolation.
    pub fn ipvlan_isolation(mut self, want: IpvlanIsolation) -> Self {
        if let DeclaredLinkType::Ipvlan { isolation, .. } = &mut self.link_type {
            *isolation = want;
        } else {
            self.wrong_kind("ipvlan_isolation", "ipvlan");
        }
        self
    }

    /// Create a macvtap interface on `parent` (#516). A device hosts
    /// macvlan/macvtap links or ipvlan links, not both.
    pub fn macvtap(mut self, parent: &str) -> Self {
        self.link_type = DeclaredLinkType::Macvtap {
            parent: parent.to_string(),
            mode: MacvlanMode::default(),
        };
        self
    }

    /// Set the macvtap mode.
    pub fn macvtap_mode(mut self, want: MacvlanMode) -> Self {
        if let DeclaredLinkType::Macvtap { mode, .. } = &mut self.link_type {
            *mode = want;
        } else {
            self.wrong_kind("macvtap_mode", "macvtap");
        }
        self
    }

    /// Create a bond interface.
    pub fn bond(mut self) -> Self {
        self.link_type = DeclaredLinkType::Bond {
            mode: BondMode::default(),
            miimon: None,
            xmit_hash_policy: None,
            min_links: None,
            ad_select: None,
            lacp_rate: None,
            downdelay: None,
            updelay: None,
            resend_igmp: None,
        };
        self
    }

    /// Set the bond mode.
    pub fn bond_mode(mut self, mode: BondMode) -> Self {
        if let DeclaredLinkType::Bond {
            mode: ref mut m, ..
        } = self.link_type
        {
            *m = mode;
        } else {
            self.wrong_kind("bond_mode", "bond");
        }
        self
    }

    /// Set the MII monitoring interval in milliseconds.
    pub fn miimon(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { miimon, .. } = &mut self.link_type {
            *miimon = Some(ms);
        } else {
            self.wrong_kind("miimon", "bond");
        }
        self
    }

    /// Set the transmit hash policy.
    pub fn xmit_hash_policy(mut self, policy: BondXmitHashPolicy) -> Self {
        if let DeclaredLinkType::Bond {
            xmit_hash_policy, ..
        } = &mut self.link_type
        {
            *xmit_hash_policy = Some(policy);
        } else {
            self.wrong_kind("xmit_hash_policy", "bond");
        }
        self
    }

    /// Set the minimum number of active links.
    pub fn min_links(mut self, count: u32) -> Self {
        if let DeclaredLinkType::Bond { min_links, .. } = &mut self.link_type {
            *min_links = Some(count);
        } else {
            self.wrong_kind("min_links", "bond");
        }
        self
    }

    /// Set the 802.3ad aggregator selection logic.
    /// No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_ad_select(mut self, sel: BondAdSelect) -> Self {
        if let DeclaredLinkType::Bond { ad_select, .. } = &mut self.link_type {
            *ad_select = Some(sel);
        } else {
            self.wrong_kind("bond_ad_select", "bond");
        }
        self
    }

    /// Set the LACPDU transmit rate (Slow=30s, Fast=1s).
    /// No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_lacp_rate(mut self, rate: BondLacpRate) -> Self {
        if let DeclaredLinkType::Bond { lacp_rate, .. } = &mut self.link_type {
            *lacp_rate = Some(rate);
        } else {
            self.wrong_kind("bond_lacp_rate", "bond");
        }
        self
    }

    /// Set the time (ms) to wait before disabling a slave on
    /// link-down. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_downdelay(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { downdelay, .. } = &mut self.link_type {
            *downdelay = Some(ms);
        } else {
            self.wrong_kind("bond_downdelay", "bond");
        }
        self
    }

    /// Set the time (ms) to wait before enabling a slave on
    /// link-up. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_updelay(mut self, ms: u32) -> Self {
        if let DeclaredLinkType::Bond { updelay, .. } = &mut self.link_type {
            *updelay = Some(ms);
        } else {
            self.wrong_kind("bond_updelay", "bond");
        }
        self
    }

    /// Set the number of IGMP membership reports to resend
    /// on failover. No-op on non-Bond builders. Plan 190 §8.
    pub fn bond_resend_igmp(mut self, count: u32) -> Self {
        if let DeclaredLinkType::Bond { resend_igmp, .. } = &mut self.link_type {
            *resend_igmp = Some(count);
        } else {
            self.wrong_kind("bond_resend_igmp", "bond");
        }
        self
    }

    /// Create an IFB interface.
    pub fn ifb(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ifb;
        self
    }

    /// Build an OpenVPN data-channel-offload link (kernel
    /// 6.16+). Link half only — peer / cipher config goes
    /// through the GENL `ovpn` family (deferred to Plan
    /// 197). Plan 190 §2.3b.
    pub fn ovpn(mut self) -> Self {
        self.link_type = DeclaredLinkType::Ovpn;
        self
    }

    /// Build a netkit BPF-programmable veth pair (kernel
    /// 6.7+). The `peer` argument names the peer interface;
    /// both ends are created atomically. Use
    /// [`LinkBuilder::netkit_mode`] / `netkit_primary_policy` /
    /// `netkit_peer_policy` / `netkit_scrub` /
    /// `netkit_peer_scrub` to refine. Plan 190 §2.3a.
    pub fn netkit(mut self, peer: impl Into<String>) -> Self {
        self.link_type = DeclaredLinkType::Netkit {
            peer: peer.into(),
            mode: None,
            primary_policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
        };
        self
    }

    /// Set netkit L2 vs L3 mode. No-op on non-netkit builders.
    pub fn netkit_mode(mut self, m: NetkitMode) -> Self {
        if let DeclaredLinkType::Netkit { mode, .. } = &mut self.link_type {
            *mode = Some(m);
        } else {
            self.wrong_kind("netkit_mode", "netkit");
        }
        self
    }

    /// Set the netkit primary-peer default policy. No-op on
    /// non-netkit builders.
    pub fn netkit_primary_policy(mut self, p: NetkitPolicy) -> Self {
        if let DeclaredLinkType::Netkit { primary_policy, .. } = &mut self.link_type {
            *primary_policy = Some(p);
        } else {
            self.wrong_kind("netkit_primary_policy", "netkit");
        }
        self
    }

    /// Set the netkit peer default policy. No-op on
    /// non-netkit builders.
    pub fn netkit_peer_policy(mut self, p: NetkitPolicy) -> Self {
        if let DeclaredLinkType::Netkit { peer_policy, .. } = &mut self.link_type {
            *peer_policy = Some(p);
        } else {
            self.wrong_kind("netkit_peer_policy", "netkit");
        }
        self
    }

    /// Set the netkit primary-peer scrub mode (kernel 6.10+).
    /// No-op on non-netkit builders.
    pub fn netkit_scrub(mut self, s: NetkitScrub) -> Self {
        if let DeclaredLinkType::Netkit { scrub, .. } = &mut self.link_type {
            *scrub = Some(s);
        } else {
            self.wrong_kind("netkit_scrub", "netkit");
        }
        self
    }

    /// Set the netkit peer scrub mode (kernel 6.10+). No-op
    /// on non-netkit builders.
    pub fn netkit_peer_scrub(mut self, s: NetkitScrub) -> Self {
        if let DeclaredLinkType::Netkit { peer_scrub, .. } = &mut self.link_type {
            *peer_scrub = Some(s);
        } else {
            self.wrong_kind("netkit_peer_scrub", "netkit");
        }
        self
    }

    /// Build a VRF link bound to routing-table `table`.
    ///
    /// VRF (Virtual Routing & Forwarding) groups interfaces
    /// under a per-table forwarding domain; common in
    /// multi-tenant networks. Members enslave via
    /// [`LinkBuilder::master`].
    ///
    /// Requires the kernel `vrf` module. Plan 190 §2.3.
    pub fn vrf(mut self, table: u32) -> Self {
        self.link_type = DeclaredLinkType::Vrf { table };
        self
    }

    /// Set the interface state to up.
    pub fn up(mut self) -> Self {
        self.state = LinkState::Up;
        self
    }

    /// Set the interface state to down.
    pub fn down(mut self) -> Self {
        self.state = LinkState::Down;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the master interface (for bridging/bonding).
    pub fn master(mut self, master: &str) -> Self {
        self.master = MasterSpec::Name(master.to_string());
        self
    }

    /// Declare that the link has no master: release it from one it has.
    ///
    /// Without this, or [`master`](Self::master), the declaration leaves
    /// the master alone (#462).
    pub fn nomaster(mut self) -> Self {
        self.master = MasterSpec::None;
        self
    }

    /// Set the MAC address.
    pub fn address(mut self, addr: [u8; 6]) -> Self {
        self.address = Some(addr);
        self
    }

    /// The transmit queue length (`ip link set … txqlen`).
    pub fn txqlen(mut self, txqlen: u32) -> Self {
        self.attrs.txqlen = Some(txqlen);
        self
    }

    /// The alias (`ip link set … alias`), at most 255 bytes. A config with
    /// an [`owner`](NetworkConfig::owner) tag writes that as the alias of
    /// the links it creates, so the two do not mix.
    pub fn alias(mut self, alias: &str) -> Self {
        self.attrs.alias = Some(alias.to_string());
        self
    }

    /// The group (`ip link set … group N`).
    pub fn group(mut self, group: u32) -> Self {
        self.attrs.group = Some(group);
        self
    }

    /// The largest GSO packet the link builds, in bytes.
    pub fn gso_max_size(mut self, bytes: u32) -> Self {
        self.attrs.gso_max_size = Some(bytes);
        self
    }

    /// The most segments a GSO packet has.
    pub fn gso_max_segs(mut self, segs: u32) -> Self {
        self.attrs.gso_max_segs = Some(segs);
        self
    }

    /// The largest packet GRO builds, in bytes.
    pub fn gro_max_size(mut self, bytes: u32) -> Self {
        self.attrs.gro_max_size = Some(bytes);
        self
    }

    /// Promiscuous mode on or off.
    pub fn promisc(mut self, on: bool) -> Self {
        self.attrs.promisc = Some(on);
        self
    }

    /// Hold the link down for a control plane, or not (`protodown`). Only
    /// devices that implement it take it (vxlan, macvlan, …): on a dummy
    /// or veth the apply fails with `EOPNOTSUPP`.
    pub fn protodown(mut self, on: bool) -> Self {
        self.attrs.protodown = Some(on);
        self
    }

    /// An alternative name (`ip link property add … altname`), up to 127
    /// bytes. Declared ones are the link's alternative names: one it has
    /// and no declaration names is taken off.
    pub fn altname(mut self, altname: &str) -> Self {
        self.attrs
            .altnames
            .get_or_insert_with(Vec::new)
            .push(altname.to_string());
        self
    }

    /// An IPv4 per-device setting (`/proc/sys/net/ipv4/conf/<dev>/<name>`),
    /// set over netlink before the link comes up (#516).
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::netlink::devconf::Ipv4Devconf;
    /// let cfg = NetworkConfig::new()
    ///     .link("v0", |l| l.ipv4_conf(Ipv4Devconf::RpFilter, 2).ipv4_conf(Ipv4Devconf::Forwarding, 1));
    /// cfg.validate().unwrap();
    /// ```
    pub fn ipv4_conf(mut self, setting: crate::netlink::devconf::Ipv4Devconf, value: u32) -> Self {
        self.attrs.ipv4_conf.insert(setting.name().to_string(), value);
        self
    }

    /// An IPv6 per-device setting (`/proc/sys/net/ipv6/conf/<dev>/<name>`)
    /// (#516). The kernel takes these only through `/proc/sys`: the apply
    /// writes them from a thread in the link's namespace, before the link
    /// comes up, which is when `accept_dad` and `disable_ipv6` matter.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::netlink::devconf::Ipv6Devconf;
    /// let cfg = NetworkConfig::new()
    ///     .link("v0", |l| l.ipv6_conf(Ipv6Devconf::AcceptDad, 0).ipv6_conf(Ipv6Devconf::AcceptRa, 2));
    /// cfg.validate().unwrap();
    /// ```
    pub fn ipv6_conf(mut self, setting: crate::netlink::devconf::Ipv6Devconf, value: i32) -> Self {
        self.attrs.ipv6_conf.insert(setting.name().to_string(), value);
        self
    }

    /// How the kernel makes the link's IPv6 link-local address
    /// (`addrgenmode`). Set before the link comes up, when it applies.
    pub fn addr_gen_mode(mut self, mode: crate::netlink::devconf::AddrGenMode) -> Self {
        self.attrs.addr_gen_mode = Some(mode);
        self
    }

    /// The IPv6 interface identifier SLAAC uses in place of the
    /// MAC-derived one (`ip token set ::1:2/64`): its upper 64 bits zero.
    /// The kernel takes it only on a device that does neighbour discovery
    /// and accepts router advertisements: not a dummy (`NOARP`).
    pub fn ipv6_token(mut self, token: std::net::Ipv6Addr) -> Self {
        self.attrs.ipv6_token = Some(token);
        self
    }

    fn build(self) -> DeclaredLink {
        DeclaredLink {
            name: self.name,
            link_type: self.link_type,
            state: self.state,
            mtu: self.mtu,
            master: self.master,
            address: self.address,
            attrs: self.attrs,
            bridge: self.bridge,
            port: self.port,
        }
    }

    /// A bridge's options (#516). Only for [`bridge`](Self::bridge) links.
    ///
    /// ```
    /// use std::time::Duration;
    /// use nlink::netlink::config::NetworkConfig;
    /// let cfg = NetworkConfig::new()
    ///     .link("br0", |l| l.bridge().bridge_options(|b| b.vlan_filtering(true).stp(true)))
    ///     .link("swp1", |l| l.master("br0").port_options(|p| p.learning(false).isolated(true)));
    /// cfg.validate().unwrap();
    /// ```
    pub fn bridge_options(mut self, f: impl FnOnce(BridgeOptions) -> BridgeOptions) -> Self {
        if !matches!(self.link_type, DeclaredLinkType::Bridge) {
            self.errors
                .push("bridge_options set on a link that is not a bridge".into());
        }
        self.bridge = Some(f(self.bridge.take().unwrap_or_default()));
        self
    }

    /// A bridge port's options (#516), for a link whose master is a bridge.
    pub fn port_options(mut self, f: impl FnOnce(PortOptions) -> PortOptions) -> Self {
        self.port = Some(f(self.port.take().unwrap_or_default()));
        self
    }
}

// ============================================================================
// Address Types
// ============================================================================

/// Declared address configuration.
///
/// Round-trips through serde as `{ dev, address }` where `address`
/// is CIDR notation (`10.0.0.1/24`). Deserialization goes through
/// [`DeclaredAddress::parse`], so prefix-length bounds are validated
/// rather than bypassed — an out-of-range prefix is a deserialize
/// error, not a silently-accepted struct.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "AddressRepr", try_from = "AddressRepr"))]
// JsonSchema is NOT derived here. The JSON shape goes through
// `AddressRepr` (a CIDR string), so a *derived* schema would wrongly
// expose the parsed `address`/`prefix_len` fields. schemars'
// `with` is field-level only, so a container override is a no-op —
// the manual impl below delegates to `AddressRepr` instead, keeping
// the schema faithful to the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredAddress {
    pub(crate) dev: String,
    pub(crate) address: IpAddr,
    pub(crate) prefix_len: u8,
    /// Everything else an address can carry (#516): the peer, label,
    /// metric, flags and lifetimes. All unset by default.
    pub(crate) attrs: AddressAttrs,
}

/// A declared neighbour (#516): a permanent ARP or ND entry with its
/// link-layer address, or a proxy entry. See
/// [`NetworkConfig::neighbour`] and [`NetworkConfig::proxy_neighbour`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredNeighbour {
    /// The device.
    pub dev: String,
    /// The neighbour's address.
    pub destination: IpAddr,
    /// Its link-layer address, as `aa:bb:cc:dd:ee:ff`; none for a proxy
    /// entry.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "mac_serde", skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub lladdr: Option<[u8; 6]>,
    /// A proxy entry: the device answers for the address.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub proxy: bool,
}

impl DeclaredNeighbour {
    /// Whether `other` is the same entry: the same device, address and
    /// proxy-ness. The kernel keeps one of each.
    pub(crate) fn same_entry(&self, other: &DeclaredNeighbour) -> bool {
        self.dev == other.dev && self.destination == other.destination && self.proxy == other.proxy
    }
}

impl std::fmt::Display for DeclaredNeighbour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.proxy {
            return write!(f, "proxy neighbour {} dev {}", self.destination, self.dev);
        }
        write!(f, "neighbour {}", self.destination)?;
        if let Some(m) = self.lladdr {
            write!(
                f,
                " lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )?;
        }
        write!(f, " dev {}", self.dev)
    }
}

/// A declared nexthop object (#516). See [`NetworkConfig::nexthop`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredNexthop {
    /// The id routes name it by; not 0.
    pub id: u32,
    /// The gateway.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub gateway: Option<IpAddr>,
    /// The device.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub dev: Option<String>,
    /// The gateway is on the link whatever the subnets say.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub onlink: bool,
    /// Drop what is routed to it.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub blackhole: bool,
    /// An IPv6 nexthop with no gateway (a blackhole, or a device alone).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub ipv6: bool,
    /// The members of a group, `[id, weight]`, weight 1 and up.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub group: Vec<(u32, u16)>,
}

impl DeclaredNexthop {
    /// Whether it is a group.
    pub fn is_group(&self) -> bool {
        !self.group.is_empty()
    }

    /// Whether it is an IPv6 nexthop.
    pub fn is_ipv6(&self) -> bool {
        self.ipv6 || self.gateway.is_some_and(|g| g.is_ipv6())
    }
}

impl std::fmt::Display for DeclaredNexthop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nexthop {}", self.id)?;
        if self.is_group() {
            let members: Vec<String> = self
                .group
                .iter()
                .map(|(id, w)| if *w == 1 { id.to_string() } else { format!("{id},{w}") })
                .collect();
            return write!(f, " group {}", members.join("/"));
        }
        if self.blackhole {
            return f.write_str(" blackhole");
        }
        if let Some(g) = self.gateway {
            write!(f, " via {g}")?;
        }
        if let Some(d) = &self.dev {
            write!(f, " dev {d}")?;
        }
        if self.onlink {
            f.write_str(" onlink")?;
        }
        Ok(())
    }
}

/// Builds a declared nexthop object; see [`NetworkConfig::nexthop`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct NexthopSpecBuilder {
    nexthop: DeclaredNexthop,
}

impl NexthopSpecBuilder {
    /// The gateway.
    pub fn via(mut self, gateway: IpAddr) -> Self {
        self.nexthop.gateway = Some(gateway);
        self
    }

    /// The device.
    pub fn dev(mut self, dev: &str) -> Self {
        self.nexthop.dev = Some(dev.to_string());
        self
    }

    /// The gateway is on the link whatever the subnets say.
    pub fn onlink(mut self) -> Self {
        self.nexthop.onlink = true;
        self
    }

    /// Drop what is routed to it.
    pub fn blackhole(mut self) -> Self {
        self.nexthop.blackhole = true;
        self
    }

    /// An IPv6 nexthop, for one with no gateway to say so.
    pub fn ipv6(mut self) -> Self {
        self.nexthop.ipv6 = true;
        self
    }

    /// A group of the nexthops `members` names, `(id, weight)`, as `ip
    /// nexthop … group` takes them: weight 1 and up.
    pub fn group(mut self, members: &[(u32, u16)]) -> Self {
        self.nexthop.group = members.to_vec();
        self
    }
}

/// A declared policy routing rule (#516). See [`NetworkConfig::rule`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredRule {
    /// Its place in the rule list (`pref`). Required: the kernel would
    /// pick one, and a rule is known by it.
    pub priority: u32,
    /// An IPv6 rule; implied by an IPv6 `from` or `to`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub ipv6: bool,
    /// The source prefix, as `10.0.0.0/8`.
    #[cfg_attr(feature = "serde", serde(default, with = "cidr_serde", skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub from: Option<(IpAddr, u8)>,
    /// The destination prefix.
    #[cfg_attr(feature = "serde", serde(default, with = "cidr_serde", skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub to: Option<(IpAddr, u8)>,
    /// The input device.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub iif: Option<String>,
    /// The output device.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub oif: Option<String>,
    /// The firewall mark.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub fwmark: Option<u32>,
    /// The mask the mark is compared under; the kernel's is all ones.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub fwmask: Option<u32>,
    /// The IP protocol.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub ipproto: Option<u8>,
    /// The source port range, `[first, last]`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub sport: Option<(u16, u16)>,
    /// The destination port range.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub dport: Option<(u16, u16)>,
    /// Match what the selectors do not (`not`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub invert: bool,
    /// Ignore a lookup whose route's prefix is this long or shorter
    /// (`suppress_prefixlength`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub suppress_prefixlen: Option<u32>,
    /// What it does.
    pub action: RuleAction,
}

/// What a declared rule does (#516).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleAction {
    /// Look this table up.
    Table(u32),
    /// Drop silently.
    Blackhole,
    /// Drop with ICMP unreachable.
    Unreachable,
    /// Drop with ICMP prohibited.
    Prohibit,
}

impl DeclaredRule {
    /// Whether it is an IPv6 rule: declared one, or by an address.
    pub fn is_ipv6(&self) -> bool {
        self.ipv6 || [self.from, self.to].iter().flatten().any(|(a, _)| a.is_ipv6())
    }
}

impl std::fmt::Display for DeclaredRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rule {}", self.priority)?;
        if self.is_ipv6() && self.from.is_none() && self.to.is_none() {
            f.write_str(" (ipv6)")?;
        }
        if self.invert {
            f.write_str(" not")?;
        }
        if let Some((a, l)) = self.from {
            write!(f, " from {a}/{l}")?;
        }
        if let Some((a, l)) = self.to {
            write!(f, " to {a}/{l}")?;
        }
        if let Some(m) = self.fwmark {
            write!(f, " fwmark {m:#x}")?;
            if let Some(mask) = self.fwmask {
                write!(f, "/{mask:#x}")?;
            }
        }
        if let Some(iif) = &self.iif {
            write!(f, " iif {iif}")?;
        }
        if let Some(oif) = &self.oif {
            write!(f, " oif {oif}")?;
        }
        if let Some(p) = self.ipproto {
            write!(f, " ipproto {p}")?;
        }
        for (what, range) in [("sport", self.sport), ("dport", self.dport)] {
            match range {
                Some((a, b)) if a == b => write!(f, " {what} {a}")?,
                Some((a, b)) => write!(f, " {what} {a}-{b}")?,
                None => {}
            }
        }
        match self.action {
            RuleAction::Table(t) => write!(f, " lookup {t}")?,
            RuleAction::Blackhole => f.write_str(" blackhole")?,
            RuleAction::Unreachable => f.write_str(" unreachable")?,
            RuleAction::Prohibit => f.write_str(" prohibit")?,
        }
        if let Some(len) = self.suppress_prefixlen {
            write!(f, " suppress_prefixlength {len}")?;
        }
        Ok(())
    }
}

/// Builds a declared policy routing rule; see [`NetworkConfig::rule`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct PolicyRuleBuilder {
    rule: DeclaredRule,
}

impl PolicyRuleBuilder {
    /// An IPv6 rule; implied by an IPv6 address.
    pub fn ipv6(mut self) -> Self {
        self.rule.ipv6 = true;
        self
    }

    /// Match the source prefix.
    pub fn from(mut self, addr: impl Into<IpAddr>, prefix_len: u8) -> Self {
        self.rule.from = Some((addr.into(), prefix_len));
        self
    }

    /// Match the destination prefix.
    pub fn to(mut self, addr: impl Into<IpAddr>, prefix_len: u8) -> Self {
        self.rule.to = Some((addr.into(), prefix_len));
        self
    }

    /// Match the input device.
    pub fn iif(mut self, dev: &str) -> Self {
        self.rule.iif = Some(dev.to_string());
        self
    }

    /// Match the output device.
    pub fn oif(mut self, dev: &str) -> Self {
        self.rule.oif = Some(dev.to_string());
        self
    }

    /// Match the firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.rule.fwmark = Some(mark);
        self
    }

    /// Match the firewall mark under `mask`.
    pub fn fwmark_masked(mut self, mark: u32, mask: u32) -> Self {
        self.rule.fwmark = Some(mark);
        self.rule.fwmask = Some(mask);
        self
    }

    /// Match the IP protocol.
    pub fn ipproto(mut self, proto: u8) -> Self {
        self.rule.ipproto = Some(proto);
        self
    }

    /// Match a source port range.
    pub fn sport(mut self, first: u16, last: u16) -> Self {
        self.rule.sport = Some((first, last));
        self
    }

    /// Match a destination port range.
    pub fn dport(mut self, first: u16, last: u16) -> Self {
        self.rule.dport = Some((first, last));
        self
    }

    /// Match what the selectors do not.
    pub fn invert(mut self) -> Self {
        self.rule.invert = true;
        self
    }

    /// Ignore a lookup whose route's prefix is `len` long or shorter.
    pub fn suppress_prefixlen(mut self, len: u32) -> Self {
        self.rule.suppress_prefixlen = Some(len);
        self
    }

    /// Look `table` up.
    pub fn table(mut self, table: u32) -> Self {
        self.rule.action = RuleAction::Table(table);
        self
    }

    /// Drop silently.
    pub fn blackhole(mut self) -> Self {
        self.rule.action = RuleAction::Blackhole;
        self
    }

    /// Drop with ICMP unreachable.
    pub fn unreachable(mut self) -> Self {
        self.rule.action = RuleAction::Unreachable;
        self
    }

    /// Drop with ICMP prohibited.
    pub fn prohibit(mut self) -> Self {
        self.rule.action = RuleAction::Prohibit;
        self
    }
}

/// A declared FDB entry (#516): a static or local entry in a bridge, or a
/// VXLAN remote. See [`NetworkConfig::fdb`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredFdb {
    /// The bridge port, or the VXLAN device.
    pub dev: String,
    /// The MAC, as `aa:bb:cc:dd:ee:ff`.
    #[cfg_attr(feature = "serde", serde(with = "mac_str_serde"))]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub mac: [u8; 6],
    /// The bridge VLAN; none is the untagged entry, and on a VLAN-filtering
    /// bridge one per VLAN of the port as well.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub vlan: Option<u16>,
    /// A VXLAN remote: the entry goes in the device's own table.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub dst: Option<IpAddr>,
    /// The bridge's own MAC (`permanent`), rather than one forwarded to the
    /// port (`static`).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub local: bool,
}

impl DeclaredFdb {
    /// Whether `other` is the same entry: the same device, MAC, VLAN and
    /// remote.
    pub(crate) fn same_entry(&self, other: &DeclaredFdb) -> bool {
        self.dev == other.dev && self.mac == other.mac && self.vlan == other.vlan && self.dst == other.dst
    }

    /// An all-zeros or multicast MAC, which a VXLAN device floods to every
    /// remote it lists.
    pub(crate) fn floods(&self) -> bool {
        self.mac == [0; 6] || self.mac[0] & 1 != 0
    }
}

impl std::fmt::Display for DeclaredFdb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.mac;
        write!(
            f,
            "fdb {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} dev {}",
            m[0], m[1], m[2], m[3], m[4], m[5], self.dev
        )?;
        if let Some(vlan) = self.vlan {
            write!(f, " vlan {vlan}")?;
        }
        match self.dst {
            Some(dst) => write!(f, " dst {dst}"),
            None if self.local => f.write_str(" local"),
            None => f.write_str(" static"),
        }
    }
}

/// Builds a declared FDB entry; see [`NetworkConfig::fdb`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct FdbBuilder {
    entry: DeclaredFdb,
}

impl FdbBuilder {
    /// The bridge VLAN.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.entry.vlan = Some(vlan);
        self
    }

    /// A VXLAN remote: the entry goes in the device's own table.
    pub fn dst(mut self, dst: IpAddr) -> Self {
        self.entry.dst = Some(dst);
        self
    }

    /// The bridge's own MAC (`permanent`), delivered up the bridge's stack
    /// rather than forwarded to the port.
    pub fn local(mut self) -> Self {
        self.entry.local = true;
        self
    }
}

/// What an address carries besides its address and prefix (#516). Set
/// with [`AddressBuilder`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AddressAttrs {
    /// The other end of a point-to-point address.
    pub(crate) peer: Option<IpAddr>,
    /// The IPv4 label (`eth0:1`); the kernel's default is the device name.
    pub(crate) label: Option<String>,
    /// The IPv4 broadcast address (`IFA_BROADCAST`, `ip addr add … brd`);
    /// none unless declared (#783).
    pub(crate) broadcast: Option<std::net::Ipv4Addr>,
    /// The metric of the prefix route (`IFA_RT_PRIORITY`).
    pub(crate) metric: Option<u32>,
    /// `IFA_F_NODAD`: skip duplicate address detection (IPv6).
    pub(crate) nodad: bool,
    /// `IFA_F_OPTIMISTIC`: usable during DAD (IPv6, RFC 4429).
    pub(crate) optimistic: bool,
    /// `IFA_F_NOPREFIXROUTE`: no prefix route for it.
    pub(crate) noprefixroute: bool,
    /// `IFA_F_HOMEADDRESS`: a Mobile IPv6 home address.
    pub(crate) home: bool,
    /// `IFA_F_MANAGETEMPADDR`: make privacy addresses from it (IPv6).
    pub(crate) mngtmpaddr: bool,
    /// The valid and preferred lifetimes; `None` is forever.
    pub(crate) lifetimes: Option<(std::time::Duration, std::time::Duration)>,
}

impl AddressAttrs {
    /// The `IFA_F_*` bits a declaration sets.
    pub(crate) fn flag_bits(&self) -> u32 {
        use crate::netlink::types::addr::ifa_flags as f;
        let mut bits = 0;
        for (on, bit) in [
            (self.nodad, f::NODAD),
            (self.optimistic, f::OPTIMISTIC),
            (self.noprefixroute, f::NOPREFIXROUTE),
            (self.home, f::HOMEADDRESS),
            (self.mngtmpaddr, f::MANAGETEMPADDR),
        ] {
            if on {
                bits |= bit;
            }
        }
        bits
    }
}

/// The attributes of an address beyond `address/prefix`, for
/// [`NetworkConfig::address_with`] (#516). A setter for the other family
/// (a label on IPv6, `nodad` on IPv4) is a validation error.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct AddressBuilder {
    address: DeclaredAddress,
    errors: Vec<String>,
}

impl AddressBuilder {
    fn new(address: DeclaredAddress) -> Self {
        Self {
            address,
            errors: Vec::new(),
        }
    }

    fn ipv6_only(&mut self, what: &str) {
        if self.address.address.is_ipv4() {
            self.errors.push(format!("{what} is an IPv6 address flag"));
        }
    }

    /// The other end of a point-to-point address (`ip addr add A peer P`).
    /// The declared prefix is the peer's.
    pub fn peer(mut self, peer: &str) -> Self {
        match peer.parse::<IpAddr>() {
            Ok(p) if p.is_ipv4() == self.address.address.is_ipv4() => {
                self.address.attrs.peer = Some(p)
            }
            Ok(p) => self.errors.push(format!("peer {p} is another address family")),
            Err(_) => self.errors.push(format!("peer {peer:?} is not an IP address")),
        }
        self
    }

    /// The IPv4 label (`ip addr add … label eth0:1`). The kernel wants it
    /// to start with the device name, and at most 15 bytes.
    pub fn label(mut self, label: &str) -> Self {
        if self.address.address.is_ipv6() {
            self.errors.push("a label is IPv4 only".into());
        } else if !label.starts_with(self.address.dev.as_str()) || label.len() > 15 {
            self.errors.push(format!(
                "label {label:?} must start with the device name {:?} and be at most 15 bytes",
                self.address.dev
            ));
        }
        self.address.attrs.label = Some(label.to_string());
        self
    }

    /// The IPv4 broadcast address (`ip addr add … brd 10.0.0.255`), which
    /// the kernel also routes as broadcast in the local table (#783). Left
    /// undeclared, an address's broadcast is not compared, since the tools
    /// that add addresses set one (`brd +`, DHCP clients).
    pub fn broadcast(mut self, broadcast: &str) -> Self {
        match broadcast.parse::<std::net::Ipv4Addr>() {
            Ok(b) if self.address.address.is_ipv4() => self.address.attrs.broadcast = Some(b),
            Ok(_) => self.errors.push("a broadcast address is IPv4 only".into()),
            Err(_) => self
                .errors
                .push(format!("broadcast {broadcast:?} is not an IPv4 address")),
        }
        self
    }

    /// The metric of the prefix route the address installs.
    pub fn metric(mut self, metric: u32) -> Self {
        self.address.attrs.metric = Some(metric);
        self
    }

    /// Skip duplicate address detection (IPv6).
    pub fn nodad(mut self) -> Self {
        self.ipv6_only("nodad");
        self.address.attrs.nodad = true;
        self
    }

    /// Usable while duplicate address detection runs (IPv6, RFC 4429;
    /// the device needs `optimistic_dad`). Set at creation only: the
    /// kernel clears the flag when DAD ends, so it is not compared.
    pub fn optimistic(mut self) -> Self {
        self.ipv6_only("optimistic");
        self.address.attrs.optimistic = true;
        self
    }

    /// Install no prefix route for it.
    pub fn noprefixroute(mut self) -> Self {
        self.address.attrs.noprefixroute = true;
        self
    }

    /// A Mobile IPv6 home address.
    pub fn home(mut self) -> Self {
        self.address.attrs.home = true;
        self
    }

    /// Make privacy (temporary) addresses from this one (IPv6).
    pub fn mngtmpaddr(mut self) -> Self {
        self.ipv6_only("mngtmpaddr");
        self.address.attrs.mngtmpaddr = true;
        self
    }

    /// Expire the address: `valid` after the apply it is removed,
    /// `preferred` after it is deprecated. Whole seconds, at most
    /// `u32::MAX - 1`; `preferred` no longer than `valid`. Each apply
    /// that changes the address sets them afresh; an apply that finds it
    /// in place does not refresh them.
    pub fn lifetime(mut self, valid: std::time::Duration, preferred: std::time::Duration) -> Self {
        if preferred > valid {
            self.errors
                .push("the preferred lifetime is longer than the valid one".into());
        }
        if valid.as_secs() >= u64::from(u32::MAX) {
            self.errors
                .push("a lifetime is at most u32::MAX - 1 seconds; leave it out for forever".into());
        }
        self.address.attrs.lifetimes = Some((valid, preferred));
        self
    }
}

/// Serde shadow for [`DeclaredAddress`] — the human-facing
/// `{ dev, address: "<cidr>" }` form. Also the schema source for
/// [`DeclaredAddress`] (see its manual `JsonSchema` impl).
#[cfg(feature = "serde")]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AddressRepr {
    /// `dev` the address is attached to.
    dev: String,
    /// CIDR-notation address, e.g. `"10.0.0.1/24"` or `"fd00::1/64"`.
    address: String,
    /// The other end of a point-to-point address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    /// The IPv4 label (`eth0:1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// The IPv4 broadcast address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broadcast: Option<String>,
    /// The metric of the prefix route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    /// Address flags: `nodad`, `optimistic`, `noprefixroute`, `home`,
    /// `mngtmpaddr`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
    /// The valid lifetime (`"3600s"`, in tc(8)'s time units); forever when
    /// absent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::util::serde_units::option_duration"
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    valid_lft: Option<std::time::Duration>,
    /// The preferred lifetime; the valid one when absent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::util::serde_units::option_duration"
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    preferred_lft: Option<std::time::Duration>,
}

// Delegate `DeclaredAddress`'s schema to `AddressRepr` so it
// describes the actual `{ dev, address: "<cidr>" }` JSON.
#[cfg(feature = "schemars")]
impl schemars::JsonSchema for DeclaredAddress {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        AddressRepr::schema_name()
    }
    fn schema_id() -> std::borrow::Cow<'static, str> {
        AddressRepr::schema_id()
    }
    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        AddressRepr::json_schema(g)
    }
    // schemars 1.0 replaced `is_referenceable` with its inverse. Keep
    // delegating rather than hardcoding: whether the shadow is
    // inlined or `$ref`-ed is the shadow's business, and this type
    // must produce the identical schema either way.
    fn inline_schema() -> bool {
        AddressRepr::inline_schema()
    }
}

#[cfg(feature = "serde")]
impl From<DeclaredAddress> for AddressRepr {
    fn from(a: DeclaredAddress) -> Self {
        let t = &a.attrs;
        let flags = [
            (t.nodad, "nodad"),
            (t.optimistic, "optimistic"),
            (t.noprefixroute, "noprefixroute"),
            (t.home, "home"),
            (t.mngtmpaddr, "mngtmpaddr"),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| name.to_string())
        .collect();
        AddressRepr {
            address: format!("{}/{}", a.address, a.prefix_len),
            peer: t.peer.map(|p| p.to_string()),
            label: t.label.clone(),
            broadcast: t.broadcast.map(|b| b.to_string()),
            metric: t.metric,
            flags,
            valid_lft: t.lifetimes.map(|(v, _)| v),
            preferred_lft: t.lifetimes.map(|(_, p)| p),
            dev: a.dev,
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<AddressRepr> for DeclaredAddress {
    type Error = AddressParseError;

    fn try_from(r: AddressRepr) -> Result<Self, Self::Error> {
        let mut b = AddressBuilder::new(DeclaredAddress::parse(&r.dev, &r.address)?);
        if let Some(peer) = &r.peer {
            b = b.peer(peer);
        }
        if let Some(label) = &r.label {
            b = b.label(label);
        }
        if let Some(broadcast) = &r.broadcast {
            b = b.broadcast(broadcast);
        }
        if let Some(metric) = r.metric {
            b = b.metric(metric);
        }
        for flag in &r.flags {
            b = match flag.as_str() {
                "nodad" => b.nodad(),
                "optimistic" => b.optimistic(),
                "noprefixroute" => b.noprefixroute(),
                "home" => b.home(),
                "mngtmpaddr" => b.mngtmpaddr(),
                other => {
                    return Err(AddressParseError::Invalid(format!(
                        "unknown address flag {other:?} (nodad, optimistic, noprefixroute, \
                         home, mngtmpaddr)"
                    )));
                }
            };
        }
        match (r.valid_lft, r.preferred_lft) {
            (Some(valid), preferred) => b = b.lifetime(valid, preferred.unwrap_or(valid)),
            (None, Some(_)) => {
                return Err(AddressParseError::Invalid(
                    "a preferred lifetime needs a valid one".into(),
                ));
            }
            (None, None) => {}
        }
        if let Some(e) = b.errors.first() {
            return Err(AddressParseError::Invalid(e.clone()));
        }
        Ok(b.address)
    }
}

impl DeclaredAddress {
    /// Parse an address from CIDR notation.
    pub fn parse(dev: &str, addr: &str) -> Result<Self, AddressParseError> {
        let (ip_str, prefix_str) = addr
            .split_once('/')
            .ok_or_else(|| AddressParseError::MissingPrefix(addr.to_string()))?;

        let address: IpAddr = ip_str
            .parse()
            .map_err(|_| AddressParseError::InvalidAddress(ip_str.to_string()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| AddressParseError::InvalidPrefix(prefix_str.to_string()))?;

        // Validate prefix length
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(AddressParseError::PrefixTooLarge {
                prefix: prefix_len,
                max: max_prefix,
            });
        }

        Ok(Self {
            dev: dev.to_string(),
            address,
            prefix_len,
            attrs: AddressAttrs::default(),
        })
    }

    /// The address at `prefix_len` on `dev`, with nothing else declared.
    pub(crate) fn plain(dev: &str, address: IpAddr, prefix_len: u8) -> Self {
        Self {
            dev: dev.to_string(),
            address,
            prefix_len,
            attrs: AddressAttrs::default(),
        }
    }

    /// The peer of a point-to-point address.
    pub fn peer(&self) -> Option<IpAddr> {
        self.attrs.peer
    }

    /// The declared IPv4 label.
    pub fn label(&self) -> Option<&str> {
        self.attrs.label.as_deref()
    }

    /// The declared metric of its prefix route.
    pub fn metric(&self) -> Option<u32> {
        self.attrs.metric
    }

    /// The declared IPv4 broadcast address (#783).
    pub fn broadcast(&self) -> Option<std::net::Ipv4Addr> {
        self.attrs.broadcast
    }

    /// The `IFA_F_*` flags declared (`nodad`, `optimistic`,
    /// `noprefixroute`, `home`, `mngtmpaddr`).
    pub fn flags(&self) -> u32 {
        self.attrs.flag_bits()
    }

    /// The declared valid and preferred lifetimes; `None` is forever.
    pub fn lifetimes(&self) -> Option<(std::time::Duration, std::time::Duration)> {
        self.attrs.lifetimes
    }

    /// Get the device name.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// Get the IP address.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Get the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Check if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// Check if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }
}

/// Error parsing an address.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AddressParseError {
    /// Address is missing prefix (no "/").
    #[error("address missing prefix: {0} (expected format: 192.168.1.1/24)")]
    MissingPrefix(String),
    /// Invalid IP address.
    #[error("invalid IP address: {0}")]
    InvalidAddress(String),
    /// Invalid prefix length.
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),
    /// Prefix length too large.
    #[error("prefix length {prefix} exceeds maximum {max}")]
    PrefixTooLarge { prefix: u8, max: u8 },
    /// An attribute beyond the address that cannot be (#516).
    #[error("{0}")]
    Invalid(String),
}

// ============================================================================
// Route Types
// ============================================================================

/// Declared route configuration.
///
/// Round-trips through serde with `destination` (and `gateway`) as
/// strings: a CIDR like `10.0.0.0/8`, or the bare keyword `default`
/// for `0.0.0.0/0` / `::/0` (family inferred from the gateway, IPv4
/// when there is none). Deserialization validates the prefix length
/// and the gateway address, so malformed input is a deserialize error.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "RouteRepr", try_from = "RouteRepr"))]
// JsonSchema delegated to `RouteRepr` via the manual impl below (the
// JSON shape is string destination/gateway, not the parsed fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRoute {
    pub(crate) destination: IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) dev: Option<String>,
    pub(crate) metric: Option<u32>,
    pub(crate) table: Option<u32>,
    pub(crate) route_type: DeclaredRouteType,
    /// The source, scope, on-link flag and metrics (#516). All unset by
    /// default: none of them is sent.
    pub(crate) attrs: RouteAttrs,
}

/// What a route carries besides where it goes and how (#516). A replace
/// drops what it is not sent, so an attribute left out is one the route
/// does not have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouteAttrs {
    /// `src`: the source address for traffic it carries (`RTA_PREFSRC`).
    pub(crate) prefsrc: Option<IpAddr>,
    /// The scope; the kernel's (link for a route with no gateway, global
    /// otherwise) when unset, and then not compared.
    pub(crate) scope: Option<crate::netlink::types::route::RouteScope>,
    /// `onlink`: the gateway is on the link whatever the subnets say.
    pub(crate) onlink: bool,
    /// The metrics `ip route` sets: `mtu`, `advmss`, `window`,
    /// `initcwnd`, `initrwnd`, `hoplimit`.
    pub(crate) mtu: Option<u32>,
    pub(crate) advmss: Option<u32>,
    pub(crate) window: Option<u32>,
    pub(crate) initcwnd: Option<u32>,
    pub(crate) initrwnd: Option<u32>,
    pub(crate) hoplimit: Option<u32>,
    /// The nexthop object the route goes through (`nhid`, `RTA_NH_ID`),
    /// in place of a gateway and device.
    pub(crate) nhid: Option<u32>,
    /// The next hops of a multipath route (`RTA_MULTIPATH`), in place of a
    /// gateway and device; in the kernel's order, which is the declared.
    pub(crate) multipath: Vec<RouteNexthop>,
    /// The labels an MPLS encapsulation pushes (`encap mpls`), outermost
    /// first; none for no encapsulation.
    pub(crate) mpls_encap: Vec<u32>,
}

/// One next hop of a multipath route (#516); see [`RouteBuilder::nexthop`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RouteNexthop {
    /// The gateway.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub gateway: Option<IpAddr>,
    /// The device; the kernel's, from the gateway, when unset.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub dev: Option<String>,
    /// Its share of the flows, 1 to 256 (a `u16` since 0.32, #783).
    #[cfg_attr(feature = "serde", serde(default = "one", skip_serializing_if = "is_one"))]
    pub weight: u16,
    /// The gateway is on the link whatever the subnets say.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "std::ops::Not::not"))]
    pub onlink: bool,
}

#[cfg(feature = "serde")]
fn one() -> u16 {
    1
}

#[cfg(feature = "serde")]
fn is_one(w: &u16) -> bool {
    *w == 1
}

impl std::fmt::Display for RouteNexthop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("nexthop")?;
        if let Some(g) = self.gateway {
            write!(f, " via {g}")?;
        }
        if let Some(d) = &self.dev {
            write!(f, " dev {d}")?;
        }
        if self.weight != 1 {
            write!(f, " weight {}", self.weight)?;
        }
        if self.onlink {
            f.write_str(" onlink")?;
        }
        Ok(())
    }
}

/// Builds one next hop of a multipath route; see [`RouteBuilder::nexthop`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct RouteNexthopBuilder {
    hop: RouteNexthop,
    error: Option<RouteParseError>,
}

impl RouteNexthopBuilder {
    /// The gateway; one that does not parse is an error from
    /// [`NetworkConfig::route`].
    pub fn via(mut self, gateway: &str) -> Self {
        match gateway.parse() {
            Ok(addr) => self.hop.gateway = Some(addr),
            Err(_) => {
                self.error.get_or_insert(RouteParseError::InvalidGateway(gateway.to_string()));
            }
        }
        self
    }

    /// The device.
    pub fn dev(mut self, dev: &str) -> Self {
        self.hop.dev = Some(dev.to_string());
        self
    }

    /// Its share of the flows, 1 and up (0 is 1).
    pub fn weight(mut self, weight: u16) -> Self {
        self.hop.weight = weight.max(1);
        self
    }

    /// The gateway is on the link whatever the subnets say.
    pub fn onlink(mut self) -> Self {
        self.hop.onlink = true;
        self
    }
}

impl RouteAttrs {
    /// The metrics, as the imperative API takes them; `None` for none.
    pub(crate) fn metrics(&self) -> Option<crate::netlink::route::RouteMetrics> {
        let m = crate::netlink::route::RouteMetrics {
            mtu: self.mtu,
            advmss: self.advmss,
            window: self.window,
            initcwnd: self.initcwnd,
            initrwnd: self.initrwnd,
            hoplimit: self.hoplimit,
            ..Default::default()
        };
        (m != crate::netlink::route::RouteMetrics::default()).then_some(m)
    }

    /// The six metrics a declaration has, from a route's metrics.
    pub(crate) fn with_metrics(mut self, m: Option<&crate::netlink::route::RouteMetrics>) -> Self {
        if let Some(m) = m {
            (self.mtu, self.advmss, self.window) = (m.mtu, m.advmss, m.window);
            (self.initcwnd, self.initrwnd, self.hoplimit) = (m.initcwnd, m.initrwnd, m.hoplimit);
        }
        self
    }
}

/// Serde shadow for [`DeclaredRoute`] — string `destination`/`gateway`
/// plus the optional knobs, with `type` omitted when it is the
/// default `unicast`.
#[cfg(feature = "serde")]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RouteRepr {
    /// CIDR-notation destination, or the bare keyword `"default"`.
    destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    table: Option<u32>,
    #[serde(
        rename = "type",
        default,
        skip_serializing_if = "DeclaredRouteType::is_unicast"
    )]
    route_type: DeclaredRouteType,
    /// The source address for traffic the route carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    /// `global`, `site`, `link` or `host`; the kernel's when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    /// The gateway is on the link whatever the subnets say.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    onlink: bool,
    /// Path MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
    /// Advertised MSS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    advmss: Option<u32>,
    /// TCP window clamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window: Option<u32>,
    /// Initial congestion window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initcwnd: Option<u32>,
    /// Initial receive window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initrwnd: Option<u32>,
    /// Hop limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hoplimit: Option<u32>,
    /// The nexthop object it goes through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nhid: Option<u32>,
    /// The next hops of a multipath route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nexthops: Vec<RouteNexthop>,
    /// The labels an MPLS encapsulation pushes, outermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    encap_mpls: Vec<u32>,
}

// Delegate `DeclaredRoute`'s schema to `RouteRepr` so it describes
// the actual string-destination/gateway JSON, not the parsed fields.
#[cfg(feature = "schemars")]
impl schemars::JsonSchema for DeclaredRoute {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        RouteRepr::schema_name()
    }
    fn schema_id() -> std::borrow::Cow<'static, str> {
        RouteRepr::schema_id()
    }
    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RouteRepr::json_schema(g)
    }
    // schemars 1.0 replaced `is_referenceable` with its inverse. Keep
    // delegating rather than hardcoding: whether the shadow is
    // inlined or `$ref`-ed is the shadow's business, and this type
    // must produce the identical schema either way.
    fn inline_schema() -> bool {
        RouteRepr::inline_schema()
    }
}

#[cfg(feature = "serde")]
impl From<DeclaredRoute> for RouteRepr {
    fn from(r: DeclaredRoute) -> Self {
        // A `0.0.0.0/0` or `::/0` destination renders as the iproute2
        // `default` keyword for readability.
        let destination = if r.prefix_len == 0 && r.destination.is_unspecified() {
            "default".to_string()
        } else {
            format!("{}/{}", r.destination, r.prefix_len)
        };
        let a = r.attrs;
        RouteRepr {
            destination,
            gateway: r.gateway.map(|g| g.to_string()),
            dev: r.dev,
            metric: r.metric,
            table: r.table,
            route_type: r.route_type,
            src: a.prefsrc.map(|s| s.to_string()),
            scope: a.scope.map(|s| s.name().to_string()),
            onlink: a.onlink,
            mtu: a.mtu,
            advmss: a.advmss,
            window: a.window,
            initcwnd: a.initcwnd,
            initrwnd: a.initrwnd,
            hoplimit: a.hoplimit,
            nhid: a.nhid,
            nexthops: a.multipath,
            encap_mpls: a.mpls_encap,
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<RouteRepr> for DeclaredRoute {
    type Error = RouteParseError;

    fn try_from(r: RouteRepr) -> Result<Self, Self::Error> {
        // Parse the gateway first; its family disambiguates a bare
        // `default` destination.
        let gateway = match r.gateway.as_deref() {
            Some(g) => Some(
                g.parse::<IpAddr>()
                    .map_err(|_| RouteParseError::InvalidGateway(g.to_string()))?,
            ),
            None => None,
        };

        let (destination, prefix_len) = if r.destination == "default" {
            if matches!(gateway, Some(IpAddr::V6(_))) {
                (IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            } else {
                (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
        } else {
            let (ip_str, prefix_str) = r
                .destination
                .split_once('/')
                .ok_or_else(|| RouteParseError::MissingPrefix(r.destination.clone()))?;
            let dst: IpAddr = ip_str
                .parse()
                .map_err(|_| RouteParseError::InvalidDestination(ip_str.to_string()))?;
            let plen: u8 = prefix_str
                .parse()
                .map_err(|_| RouteParseError::InvalidPrefix(prefix_str.to_string()))?;
            let max = if dst.is_ipv4() { 32 } else { 128 };
            if plen > max {
                return Err(RouteParseError::PrefixTooLarge { prefix: plen, max });
            }
            (dst, plen)
        };

        let prefsrc = match r.src.as_deref() {
            Some(s) => match s.parse::<IpAddr>() {
                Ok(ip) if ip.is_ipv4() == destination.is_ipv4() => Some(ip),
                _ => return Err(RouteParseError::InvalidAttribute(format!("src {s:?}"))),
            },
            None => None,
        };
        let scope = match r.scope.as_deref() {
            Some(name) => Some(
                route_scope(name)
                    .ok_or_else(|| RouteParseError::InvalidAttribute(format!("scope {name:?}")))?,
            ),
            None => None,
        };
        Ok(DeclaredRoute {
            destination,
            prefix_len,
            gateway,
            dev: r.dev,
            metric: r.metric,
            table: r.table,
            route_type: r.route_type,
            attrs: RouteAttrs {
                prefsrc,
                scope,
                onlink: r.onlink,
                mtu: r.mtu,
                advmss: r.advmss,
                window: r.window,
                initcwnd: r.initcwnd,
                initrwnd: r.initrwnd,
                hoplimit: r.hoplimit,
                nhid: r.nhid,
                multipath: r.nexthops,
                mpls_encap: r.encap_mpls,
            },
        })
    }
}

impl DeclaredRoute {
    /// Why the gateway cannot be used, if its family is not the
    /// destination's (#476). The apply dropped such a gateway and the diff
    /// still compared it, so the route was installed without one and
    /// replaced on every apply. An IPv4 route via an IPv6 gateway is
    /// RFC 5549's, sent as `RTA_VIA` since 0.32 (#516); the other way round
    /// the kernel has no use for.
    pub(crate) fn gateway_family_mismatch(&self) -> Option<String> {
        let gateway = self.gateway?;
        (gateway.is_ipv4() && self.destination.is_ipv6()).then(|| {
            format!("gateway {gateway} is IPv4, and an IPv6 route takes an IPv6 gateway")
        })
    }

    /// Get the destination address.
    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Get the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Get the gateway address.
    pub fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }

    /// Get the output device.
    pub fn dev(&self) -> Option<&str> {
        self.dev.as_deref()
    }

    /// Get the route metric.
    pub fn metric(&self) -> Option<u32> {
        self.metric
    }

    /// The declared source address (`src`).
    pub fn src(&self) -> Option<IpAddr> {
        self.attrs.prefsrc
    }

    /// The declared scope; `None` leaves it to the kernel.
    pub fn scope(&self) -> Option<crate::netlink::types::route::RouteScope> {
        self.attrs.scope
    }

    /// Whether the gateway is declared on-link.
    pub fn is_onlink(&self) -> bool {
        self.attrs.onlink
    }

    /// The declared metrics (`mtu`, `advmss`, …); `None` for none.
    pub fn metrics(&self) -> Option<crate::netlink::route::RouteMetrics> {
        self.attrs.metrics()
    }

    /// Get the routing table.
    pub fn table(&self) -> Option<u32> {
        self.table
    }

    /// Get the route type.
    pub fn route_type(&self) -> DeclaredRouteType {
        self.route_type
    }

    /// Check if this is an IPv4 route.
    pub fn is_ipv4(&self) -> bool {
        self.destination.is_ipv4()
    }

    /// Check if this is an IPv6 route.
    pub fn is_ipv6(&self) -> bool {
        self.destination.is_ipv6()
    }
}

/// Route type for declared configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DeclaredRouteType {
    /// Normal unicast route.
    #[default]
    Unicast,
    /// Blackhole (silently drop).
    Blackhole,
    /// Unreachable (ICMP unreachable).
    Unreachable,
    /// Prohibit (ICMP prohibited).
    Prohibit,
}

impl DeclaredRouteType {
    /// True for the default `unicast` type — lets serde omit the
    /// redundant `type: unicast` field from serialized routes.
    #[cfg(feature = "serde")]
    fn is_unicast(&self) -> bool {
        matches!(self, Self::Unicast)
    }

    /// The `rtm_type` this declares — what `apply` sends and the diff
    /// compares the dump against.
    pub(crate) fn kernel_type(self) -> crate::netlink::types::route::RouteType {
        use crate::netlink::types::route::RouteType;
        match self {
            Self::Unicast => RouteType::Unicast,
            Self::Blackhole => RouteType::Blackhole,
            Self::Unreachable => RouteType::Unreachable,
            Self::Prohibit => RouteType::Prohibit,
        }
    }
}

/// Error parsing a route.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RouteParseError {
    /// Destination is missing prefix.
    #[error("destination missing prefix: {0} (expected format: 10.0.0.0/8)")]
    MissingPrefix(String),
    /// Invalid destination address.
    #[error("invalid destination address: {0}")]
    InvalidDestination(String),
    /// Invalid prefix length.
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),
    /// Prefix length too large.
    #[error("prefix length {prefix} exceeds maximum {max}")]
    PrefixTooLarge { prefix: u8, max: u8 },
    /// Invalid gateway address.
    #[error("invalid gateway address: {0}")]
    InvalidGateway(String),
    /// An attribute beyond the destination and gateway that cannot be
    /// (#516): a `src` of the other family, an unknown scope.
    #[error("invalid route attribute: {0}")]
    InvalidAttribute(String),
}

/// Builder for route configuration.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct RouteBuilder {
    destination: IpAddr,
    prefix_len: u8,
    gateway: Option<IpAddr>,
    /// A setter's input that did not parse; `NetworkConfig::route`
    /// returns it.
    error: Option<RouteParseError>,
    dev: Option<String>,
    metric: Option<u32>,
    table: Option<u32>,
    route_type: DeclaredRouteType,
    attrs: RouteAttrs,
}

impl RouteBuilder {
    /// `RouteBuilder` whose destination is `0.0.0.0/0` — the
    /// IPv4 default route. Mirrors [`crate::Ipv4Route::default_route`]
    /// (Plan 184) on the declarative side. Pairs with `.via()` to
    /// set the gateway:
    ///
    /// ```no_run
    /// use nlink::netlink::config::RouteBuilder;
    /// let r = RouteBuilder::default_v4().via("192.0.2.1");
    /// ```
    ///
    /// Plan 188 §2.3.
    pub fn default_v4() -> Self {
        // 0.0.0.0/0 is always a valid IPv4 CIDR; expect is safe.
        Self::new("0.0.0.0/0").expect("0.0.0.0/0 is a valid IPv4 CIDR")
    }

    /// `RouteBuilder` whose destination is `::/0` — the IPv6
    /// default route. Mirrors [`crate::Ipv6Route::default_route`].
    ///
    /// Plan 188 §2.3.
    pub fn default_v6() -> Self {
        Self::new("::/0").expect("::/0 is a valid IPv6 CIDR")
    }

    fn new(dst: &str) -> Result<Self, RouteParseError> {
        let (ip_str, prefix_str) = dst
            .split_once('/')
            .ok_or_else(|| RouteParseError::MissingPrefix(dst.to_string()))?;

        let destination: IpAddr = ip_str
            .parse()
            .map_err(|_| RouteParseError::InvalidDestination(ip_str.to_string()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| RouteParseError::InvalidPrefix(prefix_str.to_string()))?;

        let max_prefix = if destination.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(RouteParseError::PrefixTooLarge {
                prefix: prefix_len,
                max: max_prefix,
            });
        }

        Ok(Self {
            destination,
            prefix_len,
            gateway: None,
            error: None,
            dev: None,
            metric: None,
            table: None,
            route_type: DeclaredRouteType::default(),
            attrs: RouteAttrs::default(),
        })
    }

    /// The source address for traffic the route carries (`ip route …
    /// src`, `RTA_PREFSRC`). It must be an address of the route's family.
    pub fn src(mut self, src: &str) -> Self {
        match src.parse::<IpAddr>() {
            Ok(ip) if ip.is_ipv4() == self.destination.is_ipv4() => self.attrs.prefsrc = Some(ip),
            _ => {
                self.error
                    .get_or_insert(RouteParseError::InvalidAttribute(format!("src {src:?}")));
            }
        }
        self
    }

    /// The route's scope (`global`, `site`, `link`, `host`). Unset, the
    /// kernel's: link for a route with no gateway, global otherwise.
    pub fn scope(mut self, scope: crate::netlink::types::route::RouteScope) -> Self {
        self.attrs.scope = Some(scope);
        self
    }

    /// The gateway is on the link whatever the subnets say (`onlink`).
    /// Needs a device.
    pub fn onlink(mut self) -> Self {
        self.attrs.onlink = true;
        self
    }

    /// Route through nexthop object `id` (`nhid`, #516), declared with
    /// [`NetworkConfig::nexthop`]: in place of a gateway and device.
    pub fn nhid(mut self, id: u32) -> Self {
        self.attrs.nhid = Some(id);
        self
    }

    /// Push these MPLS labels on what the route carries, outermost first
    /// (`ip route … encap mpls 100/200`, #516). Needs the `mpls_iptunnel`
    /// module, and a gateway or device.
    pub fn encap_mpls(mut self, labels: &[u32]) -> Self {
        self.attrs.mpls_encap = labels.to_vec();
        self
    }

    /// Add a next hop of a multipath route (#516), as `ip route … nexthop
    /// via <gw> dev <dev> weight <w>` does: two or more, in place of a
    /// gateway and device, kept in the order declared.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    ///
    /// let config = NetworkConfig::new()
    ///     .route("10.1.0.0/16", |r| {
    ///         r.nexthop(|h| h.via("10.0.0.2").dev("eth0"))
    ///             .nexthop(|h| h.via("10.0.1.2").dev("eth1").weight(3))
    ///     })
    ///     .unwrap();
    /// config.validate().unwrap();
    /// ```
    pub fn nexthop(mut self, f: impl FnOnce(RouteNexthopBuilder) -> RouteNexthopBuilder) -> Self {
        let built = f(RouteNexthopBuilder {
            hop: RouteNexthop {
                gateway: None,
                dev: None,
                weight: 1,
                onlink: false,
            },
            error: None,
        });
        if let Some(e) = built.error {
            self.error.get_or_insert(e);
        }
        self.attrs.multipath.push(built.hop);
        self
    }

    /// The path MTU (`ip route … mtu`).
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.attrs.mtu = Some(mtu);
        self
    }

    /// The advertised MSS (`advmss`).
    pub fn advmss(mut self, advmss: u32) -> Self {
        self.attrs.advmss = Some(advmss);
        self
    }

    /// The TCP window clamp (`window`).
    pub fn window(mut self, window: u32) -> Self {
        self.attrs.window = Some(window);
        self
    }

    /// The initial congestion window (`initcwnd`).
    pub fn initcwnd(mut self, initcwnd: u32) -> Self {
        self.attrs.initcwnd = Some(initcwnd);
        self
    }

    /// The initial receive window (`initrwnd`).
    pub fn initrwnd(mut self, initrwnd: u32) -> Self {
        self.attrs.initrwnd = Some(initrwnd);
        self
    }

    /// The hop limit (`hoplimit`).
    pub fn hoplimit(mut self, hoplimit: u32) -> Self {
        self.attrs.hoplimit = Some(hoplimit);
        self
    }

    /// Set the gateway address.
    ///
    /// A gateway that does not parse is an error from
    /// [`NetworkConfig::route`]. It was dropped, and `.via("10.0.0.1x")
    /// .dev("eth0")` became an on-link route (#476).
    pub fn via(mut self, gateway: &str) -> Self {
        match gateway.parse() {
            Ok(addr) => self.gateway = Some(addr),
            Err(_) => {
                self.error
                    .get_or_insert(RouteParseError::InvalidGateway(gateway.to_string()));
            }
        }
        self
    }

    /// Set the output device.
    pub fn dev(mut self, dev: &str) -> Self {
        self.dev = Some(dev.to_string());
        self
    }

    /// Set the route metric (priority).
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Set the routing table.
    pub fn table(mut self, table: u32) -> Self {
        self.table = Some(table);
        self
    }

    /// Make this a blackhole route.
    pub fn blackhole(mut self) -> Self {
        self.route_type = DeclaredRouteType::Blackhole;
        self
    }

    /// Make this an unreachable route.
    pub fn unreachable(mut self) -> Self {
        self.route_type = DeclaredRouteType::Unreachable;
        self
    }

    /// Make this a prohibit route.
    pub fn prohibit(mut self) -> Self {
        self.route_type = DeclaredRouteType::Prohibit;
        self
    }

    fn build(self) -> DeclaredRoute {
        DeclaredRoute {
            destination: self.destination,
            prefix_len: self.prefix_len,
            gateway: self.gateway,
            dev: self.dev,
            metric: self.metric,
            table: self.table,
            route_type: self.route_type,
            attrs: self.attrs,
        }
    }
}

/// A scope by the name `ip route` gives it.
#[cfg(feature = "serde")]
fn route_scope(name: &str) -> Option<crate::netlink::types::route::RouteScope> {
    use crate::netlink::types::route::RouteScope;
    Some(match name {
        "global" | "universe" => RouteScope::Universe,
        "site" => RouteScope::Site,
        "link" => RouteScope::Link,
        "host" => RouteScope::Host,
        _ => return None,
    })
}

// ============================================================================
// Qdisc Types
// ============================================================================

/// Declared qdisc configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredQdisc {
    pub(crate) dev: String,
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) parent: QdiscParent,
    pub(crate) qdisc_type: QdiscSpec,
    /// The qdisc's handle, in tc(8) notation in JSON (`"1:"`). `None`: `1:`
    /// for a classful kind, so its classes and filters can name it, and
    /// the kernel's choice for the others (#514).
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "handle_serde"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<String>"))]
    pub(crate) handle: Option<crate::TcHandle>,
}

/// A qdisc handle as tc(8) writes it, `"1:"`, in JSON.
#[cfg(feature = "serde")]
mod handle_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        h: &Option<crate::TcHandle>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match h {
            Some(h) => s.serialize_str(&h.to_string()),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Option<crate::TcHandle>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

impl DeclaredQdisc {
    /// Get the device name.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// The handle it is installed with: the declared one, `1:` for a
    /// classful kind (HTB, prio), and `None`, the kernel's choice, for the
    /// others (#514).
    pub fn effective_handle(&self) -> Option<crate::TcHandle> {
        self.handle.or_else(|| {
            self.qdisc_type
                .is_classful()
                .then(|| crate::TcHandle::major_only(1))
        })
    }

    /// Get the parent as declared.
    ///
    /// For `ingress`/`clsact` this can disagree with reality; see
    /// [`effective_parent`](Self::effective_parent).
    pub fn parent(&self) -> QdiscParent {
        self.parent
    }

    /// The parent slot this qdisc will actually occupy.
    ///
    /// Equal to [`parent`](Self::parent) except for the hook kinds
    /// (`ingress`, `clsact`), which the kernel only accepts at
    /// `TC_H_INGRESS` whatever the declaration says.
    pub fn effective_parent(&self) -> QdiscParent {
        self.qdisc_type.required_parent().unwrap_or(self.parent)
    }

    /// Get the qdisc type.
    pub fn qdisc_type(&self) -> &QdiscSpec {
        &self.qdisc_type
    }
}

/// Qdisc parent location.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum QdiscParent {
    /// Root qdisc.
    #[default]
    Root,
    /// Ingress qdisc.
    Ingress,
}

impl QdiscSpec {
    /// The parent slot this kind must occupy, overriding whatever the
    /// declaration says.
    ///
    /// `ingress` and `clsact` are hooks, not schedulers: the kernel
    /// only accepts them at `TC_H_INGRESS`. A declaration that pairs
    /// either with `parent: root` is not a request to put them
    /// somewhere else — there is nowhere else — so `apply` and `diff`
    /// both resolve the slot from the kind rather than trusting the
    /// field, which a deserialized document can set freely.
    pub(crate) fn required_parent(&self) -> Option<QdiscParent> {
        match self {
            QdiscSpec::Ingress | QdiscSpec::Clsact => Some(QdiscParent::Ingress),
            QdiscSpec::KernelDefault => Some(QdiscParent::Root),
            _ => None,
        }
    }
}

/// The declarative qdisc type: [`QdiscSpec`], which the imperative path
/// takes too, since 0.32 (#515).
#[deprecated(
    since = "0.32.0",
    note = "renamed `QdiscSpec`, which holds the imperative configs (#515)"
)]
pub type DeclaredQdiscType = QdiscSpec;

/// Builder for qdisc configuration.
///
/// Its setters write into the [`QdiscSpec`] the qdisc is declared as —
/// the imperative config itself since 0.32 (#515) — and [`spec`](Self::spec)
/// takes a whole one, for what has no setter here (netem's slot, seed and
/// rate overheads, a TBF's peak rate, …).
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct QdiscBuilder {
    dev: String,
    parent: QdiscParent,
    qdisc_type: Option<QdiscSpec>,
    handle: Option<crate::TcHandle>,
    /// Setters called for a kind the qdisc is not (#476).
    errors: Vec<String>,
}

/// The config of `$variant` in `$self.qdisc_type`, or a wrong-kind error
/// for `$setter` naming `$kinds`.
macro_rules! with_kind {
    ($self:ident, $setter:literal, $kinds:literal, $($variant:ident)|+, |$c:ident| $body:expr) => {{
        match &mut $self.qdisc_type {
            $(Some(QdiscSpec::$variant($c)) => {
                $body;
            })+
            _ => $self.wrong_kind($setter, $kinds),
        }
        $self
    }};
}

impl QdiscBuilder {
    fn new(dev: &str) -> Self {
        Self {
            dev: dev.to_string(),
            parent: QdiscParent::Root,
            qdisc_type: None,
            handle: None,
            errors: Vec::new(),
        }
    }

    /// Install the qdisc with handle `handle` (`1:` is
    /// `TcHandle::major_only(1)`), which its classes and filters name. A
    /// classful kind defaults to `1:`; the others get the kernel's choice
    /// (#514). A handle with a minor is an error.
    pub fn handle(mut self, handle: crate::TcHandle) -> Self {
        if handle.minor() != 0 {
            self.errors.push(format!(
                "`.handle({handle})`: a qdisc handle has no minor (`1:`, not `1:1`)"
            ));
        } else {
            self.handle = Some(handle);
        }
        self
    }

    /// Declare the qdisc as `spec`, whole: any config a `Connection`
    /// installs (#515). The hook kinds take their slot.
    ///
    /// ```
    /// use std::time::Duration;
    /// use nlink::netlink::{config::NetworkConfig, tc::{NetemConfig, NetemSlot}};
    ///
    /// let netem = NetemConfig::new()
    ///     .delay(Duration::from_millis(10))
    ///     .slot(NetemSlot::new(Duration::from_millis(1), Duration::from_millis(2)))
    ///     .seed(7);
    /// let cfg = NetworkConfig::new().qdisc("eth0", |q| q.spec(netem));
    /// # let _ = cfg;
    /// ```
    pub fn spec(mut self, spec: impl Into<QdiscSpec>) -> Self {
        let spec = spec.into();
        if let Some(parent) = spec.required_parent() {
            self.parent = parent;
        }
        self.qdisc_type = Some(spec);
        self
    }

    /// Declare the kernel's own root qdisc: whatever root is installed is
    /// deleted, and the kernel puts its default back (#514).
    pub fn kernel_default(mut self) -> Self {
        self.parent = QdiscParent::Root;
        self.qdisc_type = Some(QdiscSpec::KernelDefault);
        self
    }

    /// Record a setter called for the wrong kind: it did nothing, so
    /// `q.delay_ms(10).netem()` lost its delay and `q.htb().delay_ms(10)`
    /// was ignored (#476).
    fn wrong_kind(&mut self, setter: &str, kinds: &str) {
        let is = match &self.qdisc_type {
            Some(kind) => format!("is {}", kind.kind()),
            None => "has no kind yet — choose the kind first".to_string(),
        };
        self.errors.push(format!(
            "`.{setter}()` sets a {kinds} parameter, but this qdisc {is}"
        ));
    }

    /// Configure as netem qdisc.
    pub fn netem(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Netem(crate::netlink::tc::NetemConfig::new()));
        self
    }

    /// Set netem delay in milliseconds.
    pub fn delay_ms(mut self, ms: u32) -> Self {
        let d = Duration::from_millis(u64::from(ms));
        with_kind!(self, "delay_ms", "netem", Netem, |c| c.delay = Some(d))
    }

    /// Set netem delay in microseconds.
    pub fn delay_us(mut self, us: u32) -> Self {
        let d = Duration::from_micros(u64::from(us));
        with_kind!(self, "delay_us", "netem", Netem, |c| c.delay = Some(d))
    }

    /// Set netem delay as a [`Duration`] — the same type
    /// `NetemConfig::delay` takes (#332).
    pub fn delay(mut self, delay: Duration) -> Self {
        with_kind!(self, "delay", "netem", Netem, |c| c.delay = Some(delay))
    }

    /// Set netem jitter in milliseconds.
    pub fn jitter_ms(mut self, ms: u32) -> Self {
        let d = Duration::from_millis(u64::from(ms));
        with_kind!(self, "jitter_ms", "netem", Netem, |c| c.jitter = Some(d))
    }

    /// Set netem jitter in microseconds (#332).
    pub fn jitter_us(mut self, us: u32) -> Self {
        let d = Duration::from_micros(u64::from(us));
        with_kind!(self, "jitter_us", "netem", Netem, |c| c.jitter = Some(d))
    }

    /// Set netem jitter as a [`Duration`] (#332).
    pub fn jitter(mut self, jitter: Duration) -> Self {
        with_kind!(self, "jitter", "netem", Netem, |c| c.jitter = Some(jitter))
    }

    /// Set the netem rate limit (netem `rate`), typed (#332).
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        with_kind!(self, "rate", "netem", Netem, |c| c.rate = Some(rate))
    }

    /// Set the netem reorder gap in packets (netem `gap`). Only
    /// meaningful with [`Self::reorder_pct`]; `NetemConfig` forces a
    /// gap of 1 when reorder is set and no gap is given.
    pub fn gap(mut self, packets: u32) -> Self {
        with_kind!(self, "gap", "netem", Netem, |c| c.gap = packets)
    }

    /// Set netem packet loss.
    pub fn loss_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "loss_pct", "netem", Netem, |c| c.loss = percent)
    }

    /// Set netem packet-duplication probability
    /// (`NetemConfig::duplicate`).
    pub fn duplicate_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "duplicate_pct", "netem", Netem, |c| c.duplicate =
            percent)
    }

    /// Set netem packet-corruption probability (`NetemConfig::corrupt`).
    pub fn corrupt_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "corrupt_pct", "netem", Netem, |c| c.corrupt = percent)
    }

    /// Set netem packet-reorder probability (`NetemConfig::reorder`); its
    /// correlation is [`reorder_correlation_pct`](Self::reorder_correlation_pct).
    pub fn reorder_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "reorder_pct", "netem", Netem, |c| c.reorder = percent)
    }

    /// Set netem loss correlation (`loss <p>% <corr>%`).
    ///
    /// **It lowers the loss rate, it does not make loss bursty**: netem
    /// averages each random draw with the previous one, so a small loss
    /// probability almost never triggers (`loss 0.5% 25%` drops ~0 %; #369,
    /// table on [`NetemConfig::loss_correlation`](crate::netlink::tc::NetemConfig::loss_correlation)).
    /// For loss in bursts use [`loss_model`](Self::loss_model).
    pub fn loss_correlation_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "loss_correlation_pct", "netem", Netem, |c| c
            .loss_correlation =
            percent)
    }

    /// Set a netem Markov loss model — Gilbert-Elliot (`loss gemodel …`)
    /// or the 4-state Gilbert-Intuitive model (`loss state …`), netem's
    /// generators for **bursty** loss.
    ///
    /// Exclusive with [`loss_pct`](Self::loss_pct) and
    /// [`loss_correlation_pct`](Self::loss_correlation_pct): a declaration
    /// that sets both fails validation (#368).
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::Percent;
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::netlink::tc::NetemLossModel;
    ///
    /// let model = NetemLossModel::gilbert_elliot(Percent::new(1.0))
    ///     .r(Percent::new(30.0))
    ///     .loss_in_bad(Percent::new(50.0));
    /// let config = NetworkConfig::new().qdisc("eth0", |q| q.netem().loss_model(model));
    /// # let _ = config;
    /// # Ok(())
    /// # }
    /// ```
    pub fn loss_model(mut self, model: crate::netlink::tc_options::NetemLossModel) -> Self {
        with_kind!(self, "loss_model", "netem", Netem, |c| c.loss_model =
            Some(model))
    }

    /// Set netem delay correlation (`NetemConfig::delay_correlation`).
    pub fn delay_correlation_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "delay_correlation_pct", "netem", Netem, |c| c
            .delay_correlation =
            percent)
    }

    /// Set netem reorder correlation, the second argument of
    /// `NetemConfig::reorder` (#332).
    pub fn reorder_correlation_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "reorder_correlation_pct", "netem", Netem, |c| c
            .reorder_correlation =
            percent)
    }

    /// Set netem duplicate correlation (`NetemConfig::duplicate_correlation`).
    pub fn duplicate_correlation_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "duplicate_correlation_pct", "netem", Netem, |c| c
            .duplicate_correlation =
            percent)
    }

    /// Set netem corrupt correlation (`NetemConfig::corrupt_correlation`).
    pub fn corrupt_correlation_pct(mut self, percent: crate::util::Percent) -> Self {
        with_kind!(self, "corrupt_correlation_pct", "netem", Netem, |c| c
            .corrupt_correlation =
            percent)
    }

    /// Set the queue limit in **packets**: netem's, fq_codel's and sfq's.
    /// TBF's limit is a byte count, [`limit_bytes`](Self::limit_bytes).
    ///
    /// sfq caps its limit at 127 × 128 = 16256 packets (`sfq_change()`,
    /// default depth times default flows); the diff compares against the
    /// capped value, so declaring more installs 16256.
    pub fn limit(mut self, packets: crate::util::Packets) -> Self {
        match &mut self.qdisc_type {
            Some(QdiscSpec::Netem(c)) => c.limit = packets,
            Some(QdiscSpec::FqCodel(c)) => c.limit = Some(packets),
            Some(QdiscSpec::Sfq(c)) => c.limit = packets,
            _ => self.wrong_kind("limit", "fq_codel or netem or sfq"),
        }
        self
    }

    /// Set the fq_codel target delay (`FqCodelConfig::target`). The kernel
    /// keeps CoDel times in 1.024 µs units; the diff compares in them.
    pub fn target(mut self, target: Duration) -> Self {
        with_kind!(self, "target", "fq_codel", FqCodel, |c| c.target =
            Some(target))
    }

    /// Set the fq_codel interval (`FqCodelConfig::interval`).
    pub fn interval(mut self, interval: Duration) -> Self {
        with_kind!(self, "interval", "fq_codel", FqCodel, |c| c.interval =
            Some(interval))
    }

    /// Set the number of fq_codel flow buckets (`FqCodelConfig::flows`).
    ///
    /// The kernel sizes the flow table in `fq_codel_init` and will not
    /// resize it, so a different one replaces the qdisc, which drops its
    /// queue and resets its statistics (#361, #596).
    ///
    /// On sfq, the most flows (`SfqConfig::flows`, #806).
    pub fn flows(mut self, flows: u32) -> Self {
        match &mut self.qdisc_type {
            Some(QdiscSpec::FqCodel(c)) => c.flows = Some(flows),
            Some(QdiscSpec::Sfq(c)) => c.flows = flows,
            _ => self.wrong_kind("flows", "fq_codel or sfq"),
        }
        self
    }

    /// Set sfq's hash buckets (`SfqConfig::divisor`, #806).
    pub fn divisor(mut self, buckets: u32) -> Self {
        with_kind!(self, "divisor", "sfq", Sfq, |c| c.divisor = buckets)
    }

    /// Set the most packets an sfq flow queues (`SfqConfig::depth`, #806).
    pub fn depth(mut self, packets: u32) -> Self {
        with_kind!(self, "depth", "sfq", Sfq, |c| c.depth = packets)
    }

    /// Drop from the head of a full sfq flow's queue
    /// (`SfqConfig::headdrop`, #806).
    pub fn headdrop(mut self, on: bool) -> Self {
        with_kind!(self, "headdrop", "sfq", Sfq, |c| c.headdrop = on)
    }

    /// Set the bytes dequeued per round — fq_codel's and sfq's
    /// `quantum`. fq_codel raises anything below 256 to 256, and the diff
    /// compares against that (#361).
    pub fn quantum(mut self, bytes: u32) -> Self {
        match &mut self.qdisc_type {
            Some(QdiscSpec::FqCodel(c)) => c.quantum = Some(bytes),
            Some(QdiscSpec::Sfq(c)) => c.quantum = bytes,
            _ => self.wrong_kind("quantum", "fq_codel or sfq"),
        }
        self
    }

    /// Enable fq_codel ECN marking instead of dropping, where the flow
    /// negotiated it (`FqCodelConfig::ecn`) (#361).
    pub fn ecn(mut self, enabled: bool) -> Self {
        with_kind!(self, "ecn", "fq_codel", FqCodel, |c| c.ecn = Some(enabled))
    }

    /// Set the most packets fq_codel drops at once when full
    /// (`FqCodelConfig::drop_batch`, #806).
    pub fn drop_batch(mut self, packets: u32) -> Self {
        with_kind!(self, "drop_batch", "fq_codel", FqCodel, |c| c.drop_batch = Some(packets))
    }

    /// Apply fq_codel's CE threshold to the packets whose DS field, masked
    /// with `mask`, equals `value` (`FqCodelConfig::ce_threshold_selector`,
    /// #806).
    pub fn ce_threshold_selector(mut self, value: u8, mask: u8) -> Self {
        with_kind!(self, "ce_threshold_selector", "fq_codel", FqCodel, |c| c.ce_threshold_selector =
            Some((value, mask)))
    }

    /// Set the sfq hash-perturbation period (`SfqConfig::perturb`).
    ///
    /// The kernel's field is whole seconds, and 0 turns perturbation off,
    /// so a fraction rounds up: 500 ms installs 1 s. A period past
    /// `i32::MAX` seconds is a validation error (#597).
    pub fn perturb(mut self, period: Duration) -> Self {
        let secs = period.as_secs() + u64::from(period.subsec_nanos() > 0);
        match (&mut self.qdisc_type, i32::try_from(secs)) {
            (Some(QdiscSpec::Sfq(c)), Ok(secs)) => c.perturb = secs,
            (Some(QdiscSpec::Sfq(_)), Err(_)) => self.errors.push(format!(
                "`.perturb({period:?})` is past the kernel's limit of {} seconds",
                i32::MAX
            )),
            _ => self.wrong_kind("perturb", "sfq"),
        }
        self
    }

    /// Set the number of prio bands (`PrioConfig::bands`) (#361).
    pub fn bands(mut self, bands: u8) -> Self {
        with_kind!(self, "bands", "prio", Prio, |c| c.bands = i32::from(bands))
    }

    /// Set the prio priomap: the band each of the 16 priorities goes to
    /// (`PrioConfig::priomap`). Without one, the default map is used,
    /// fitted to [`bands`](Self::bands) below three (#487).
    pub fn priomap(mut self, map: [u8; 16]) -> Self {
        with_kind!(self, "priomap", "prio", Prio, |c| c.priomap = map)
    }

    /// Set the TBF peak rate (`TbfConfig::peakrate`): the ceiling a burst
    /// may drain at. The kernel sizes the peak bucket from the
    /// [`mtu`](Self::mtu), so set it too (#361).
    pub fn peakrate(mut self, rate: crate::util::Rate) -> Self {
        with_kind!(self, "peakrate", "tbf", Tbf, |c| c.peakrate = Some(rate))
    }

    /// Set the TBF peak-burst / maximum packet size in bytes
    /// (`TbfConfig::mtu`), 1514 unless set (#361).
    pub fn mtu(mut self, bytes: u32) -> Self {
        with_kind!(self, "mtu", "tbf", Tbf, |c| c.mtu = bytes)
    }

    /// Configure as HTB qdisc.
    pub fn htb(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Htb(crate::netlink::tc::HtbQdiscConfig::new()));
        self
    }

    /// Set the default class of an HTB or HFSC qdisc: the minor
    /// unclassified traffic goes to.
    ///
    /// HTB's is fixed for the qdisc's lifetime: the kernel's htb has no
    /// change operation, so `apply` refuses to edit it on a live HTB root
    /// (`Error::NotSupported`) rather than delete the root and every class
    /// and filter under it. Delete the qdisc yourself to change it. HFSC's
    /// changes in place.
    pub fn default_class(mut self, class: u32) -> Self {
        match (&mut self.qdisc_type, u16::try_from(class)) {
            (Some(QdiscSpec::Htb(c)), _) => c.default_class = class,
            (Some(QdiscSpec::Hfsc(c)), Ok(class)) => c.default_class = class,
            (Some(QdiscSpec::Hfsc(_)), Err(_)) => self.errors.push(format!(
                "`.default_class({class:#x})`: a class minor is 16 bits"
            )),
            _ => self.wrong_kind("default_class", "htb, hfsc"),
        }
        self
    }

    /// Configure as HFSC qdisc; its classes are declared with
    /// [`NetworkConfig::tc`].
    pub fn hfsc(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Hfsc(crate::netlink::tc::HfscConfig::new()));
        self
    }

    /// Configure as DRR qdisc; its classes are declared with
    /// [`NetworkConfig::tc`].
    pub fn drr(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Drr(crate::netlink::tc::DrrConfig::new()));
        self
    }

    /// Configure as QFQ qdisc; its classes are declared with
    /// [`NetworkConfig::tc`].
    pub fn qfq(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Qfq(crate::netlink::tc::QfqConfig::new()));
        self
    }

    /// Configure as fq_codel qdisc.
    pub fn fq_codel(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::FqCodel(crate::netlink::tc::FqCodelConfig::new()));
        self
    }

    /// Configure as TBF qdisc with a typed rate and bucket size (#349).
    /// Follow it with [`limit_bytes`](Self::limit_bytes): a TBF needs a
    /// queue limit, and one without fails validation.
    ///
    /// ```
    /// use nlink::netlink::config::NetworkConfig;
    /// use nlink::{Bytes, Rate};
    ///
    /// let cfg = NetworkConfig::new().qdisc("eth0", |q| {
    ///     q.tbf(Rate::mbit(100), Bytes::kib(32)).limit_bytes(Bytes::kib(64))
    /// });
    /// # let _ = cfg;
    /// ```
    pub fn tbf(mut self, rate: crate::util::Rate, burst: crate::util::Bytes) -> Self {
        let tbf = crate::netlink::tc::TbfConfig::new().rate(rate).burst(burst);
        self.qdisc_type = Some(QdiscSpec::Tbf(tbf));
        self
    }

    /// Set the TBF queue limit (`TbfConfig::limit`). Required for a TBF:
    /// the kernel gives one without a limit no queue, so it drops every
    /// packet. netem's packet limit is [`limit`](Self::limit).
    pub fn limit_bytes(mut self, limit: crate::util::Bytes) -> Self {
        with_kind!(self, "limit_bytes", "tbf", Tbf, |c| c.limit = limit)
    }

    /// Set the bytes a TBF adds to each packet's size when it charges its
    /// rates (`TbfConfig::overhead`, #806).
    pub fn overhead(mut self, bytes: u16) -> Self {
        with_kind!(self, "overhead", "tbf", Tbf, |c| c.overhead = bytes)
    }

    /// Set the least size a TBF charges a packet as (`TbfConfig::mpu`,
    /// #806).
    pub fn mpu(mut self, bytes: u16) -> Self {
        with_kind!(self, "mpu", "tbf", Tbf, |c| c.mpu = bytes)
    }

    /// Set the link layer a TBF's rate tables are for
    /// (`TbfConfig::linklayer`, #806).
    pub fn linklayer(mut self, linklayer: crate::netlink::psched::LinkLayer) -> Self {
        with_kind!(self, "linklayer", "tbf", Tbf, |c| c.linklayer = linklayer)
    }

    /// Configure as SFQ qdisc.
    pub fn sfq(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Sfq(crate::netlink::tc::SfqConfig::new()));
        self
    }

    /// Configure as prio qdisc.
    pub fn prio(mut self) -> Self {
        self.qdisc_type = Some(QdiscSpec::Prio(crate::netlink::tc::PrioConfig::new()));
        self
    }

    /// Configure as ingress qdisc.
    pub fn ingress(mut self) -> Self {
        self.parent = QdiscParent::Ingress;
        self.qdisc_type = Some(QdiscSpec::Ingress);
        self
    }

    /// Configure as clsact qdisc. Sets the parent to
    /// [`QdiscParent::Ingress`]: clsact shares the ingress slot.
    pub fn clsact(mut self) -> Self {
        self.parent = QdiscParent::Ingress;
        self.qdisc_type = Some(QdiscSpec::Clsact);
        self
    }

    /// The declared qdisc, or what was wrong with the builder: no kind —
    /// it used to become an fq_codel that replaced the root qdisc (#476) —
    /// or setters for another kind.
    fn build(mut self) -> Result<DeclaredQdisc, Vec<String>> {
        let Some(qdisc_type) = self.qdisc_type.take() else {
            self.errors.push(
                "no qdisc kind: choose one (`.netem()`, `.htb(..)`, `.fq_codel()`, …)".to_string(),
            );
            return Err(self.errors);
        };
        if !self.errors.is_empty() {
            return Err(self.errors);
        }
        Ok(DeclaredQdisc {
            dev: self.dev,
            parent: self.parent,
            qdisc_type,
            handle: self.handle,
        })
    }
}

#[cfg(test)]
mod plan_190_tests {
    //! Plan 190 — LinkBuilder gaps.
    //! Unit-level coverage for new DeclaredLinkType variants
    //! + LinkBuilder setters.

    use super::*;

    #[test]
    fn vrf_builder_sets_table() {
        let link = LinkBuilder::new("vrf-red").vrf(100).build();
        match link.link_type {
            DeclaredLinkType::Vrf { table } => assert_eq!(table, 100),
            other => panic!("expected DeclaredLinkType::Vrf, got {other:?}"),
        }
    }

    #[test]
    fn vrf_kind_string_is_vrf() {
        let lt = DeclaredLinkType::Vrf { table: 7 };
        assert_eq!(lt.kind(), Some("vrf"));
    }

    // -------- Plan 190 §2.3b — ovpn link half --------

    #[test]
    fn ovpn_builder_creates_ovpn_variant() {
        let link = LinkBuilder::new("ovpn0").ovpn().build();
        assert!(matches!(link.link_type, DeclaredLinkType::Ovpn));
    }

    #[test]
    fn ovpn_kind_string_is_ovpn() {
        assert_eq!(DeclaredLinkType::Ovpn.kind(), Some("ovpn"));
    }

    // -------- end Plan 190 §2.3b --------

    // -------- Plan 190 §2.3a — netkit --------

    #[test]
    fn netkit_builder_peer_carried_others_default_none() {
        let link = LinkBuilder::new("nk0").netkit("nk1").build();
        match link.link_type {
            DeclaredLinkType::Netkit {
                peer,
                mode,
                primary_policy,
                peer_policy,
                scrub,
                peer_scrub,
            } => {
                assert_eq!(peer, "nk1");
                assert!(mode.is_none());
                assert!(primary_policy.is_none());
                assert!(peer_policy.is_none());
                assert!(scrub.is_none());
                assert!(peer_scrub.is_none());
            }
            other => panic!("expected Netkit, got {other:?}"),
        }
    }

    #[test]
    fn netkit_builder_full_setter_chain() {
        let link = LinkBuilder::new("nk0")
            .netkit("nk1")
            .netkit_mode(NetkitMode::L2)
            .netkit_primary_policy(NetkitPolicy::Forward)
            .netkit_peer_policy(NetkitPolicy::Blackhole)
            .netkit_scrub(NetkitScrub::Default)
            .netkit_peer_scrub(NetkitScrub::None)
            .build();
        match link.link_type {
            DeclaredLinkType::Netkit {
                peer,
                mode,
                primary_policy,
                peer_policy,
                scrub,
                peer_scrub,
            } => {
                assert_eq!(peer, "nk1");
                assert_eq!(mode, Some(NetkitMode::L2));
                assert_eq!(primary_policy, Some(NetkitPolicy::Forward));
                assert_eq!(peer_policy, Some(NetkitPolicy::Blackhole));
                assert_eq!(scrub, Some(NetkitScrub::Default));
                assert_eq!(peer_scrub, Some(NetkitScrub::None));
            }
            other => panic!("expected Netkit, got {other:?}"),
        }
    }

    #[test]
    fn netkit_kind_string_is_netkit() {
        let lt = DeclaredLinkType::Netkit {
            peer: "x".into(),
            mode: None,
            primary_policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
        };
        assert_eq!(lt.kind(), Some("netkit"));
    }

    // -------- end Plan 190 §2.3a --------

    // -------- Plan 190 §8 — Bond options gap-fill --------

    #[test]
    fn bond_builder_defaults_all_new_knobs_to_none() {
        let link = LinkBuilder::new("bond0").bond().build();
        match link.link_type {
            DeclaredLinkType::Bond {
                ad_select,
                lacp_rate,
                downdelay,
                updelay,
                resend_igmp,
                ..
            } => {
                assert!(ad_select.is_none());
                assert!(lacp_rate.is_none());
                assert!(downdelay.is_none());
                assert!(updelay.is_none());
                assert!(resend_igmp.is_none());
            }
            other => panic!("expected Bond, got {other:?}"),
        }
    }

    #[test]
    fn bond_builder_all_5_setters_round_trip() {
        let link = LinkBuilder::new("bond0")
            .bond()
            .bond_ad_select(BondAdSelect::Bandwidth)
            .bond_lacp_rate(BondLacpRate::Fast)
            .bond_downdelay(200)
            .bond_updelay(500)
            .bond_resend_igmp(3)
            .build();
        match link.link_type {
            DeclaredLinkType::Bond {
                ad_select,
                lacp_rate,
                downdelay,
                updelay,
                resend_igmp,
                ..
            } => {
                assert_eq!(ad_select, Some(BondAdSelect::Bandwidth));
                assert_eq!(lacp_rate, Some(BondLacpRate::Fast));
                assert_eq!(downdelay, Some(200));
                assert_eq!(updelay, Some(500));
                assert_eq!(resend_igmp, Some(3));
            }
            other => panic!("expected Bond, got {other:?}"),
        }
    }

    #[test]
    fn bond_setters_no_op_on_non_bond() {
        let link = LinkBuilder::new("eth0")
            .dummy()
            .bond_ad_select(BondAdSelect::Stable)
            .bond_lacp_rate(BondLacpRate::Slow)
            .bond_downdelay(100)
            .bond_updelay(100)
            .bond_resend_igmp(1);
        assert_eq!(link.errors.len(), 5, "each setter is recorded (#518)");
        assert!(matches!(link.build().link_type, DeclaredLinkType::Dummy));
    }

    // -------- end Plan 190 §8 --------

    // -------- Plan 190 §2.1 — VXLAN extras --------

    #[test]
    fn vxlan_builder_defaults_to_none_for_new_knobs() {
        let link = LinkBuilder::new("vx0").vxlan(42).build();
        match link.link_type {
            DeclaredLinkType::Vxlan {
                vni,
                remote,
                local,
                port,
                underlay_dev,
            } => {
                assert_eq!(vni, 42);
                assert!(remote.is_none());
                assert!(local.is_none());
                assert!(port.is_none());
                assert!(underlay_dev.is_none());
            }
            other => panic!("expected Vxlan, got {other:?}"),
        }
    }

    #[test]
    fn vxlan_builder_local_port_underlay_round_trip() {
        use std::net::Ipv4Addr;
        let link = LinkBuilder::new("vx0")
            .vxlan(100)
            .vxlan_remote(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .vxlan_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .vxlan_port(4790)
            .vxlan_underlay_dev("eth0")
            .build();
        match link.link_type {
            DeclaredLinkType::Vxlan {
                vni,
                remote,
                local,
                port,
                underlay_dev,
            } => {
                assert_eq!(vni, 100);
                assert_eq!(remote, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
                assert_eq!(local, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
                assert_eq!(port, Some(4790));
                assert_eq!(underlay_dev.as_deref(), Some("eth0"));
            }
            other => panic!("expected Vxlan, got {other:?}"),
        }
    }

    #[test]
    fn vxlan_setters_no_op_on_non_vxlan() {
        // Each new setter must early-return if the builder
        // isn't a VXLAN — same shape as vlan_protocol.
        use std::net::Ipv4Addr;
        let link = LinkBuilder::new("eth0")
            .dummy()
            .vxlan_local(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .vxlan_port(4790)
            .vxlan_underlay_dev("ignored");
        assert_eq!(link.errors.len(), 3, "each setter is recorded (#518)");
        assert!(matches!(link.build().link_type, DeclaredLinkType::Dummy));
    }

    // -------- end Plan 190 §2.1 --------

    // -------- Plan 190 §2.2 — VLAN protocol --------

    #[test]
    fn vlan_builder_protocol_defaults_to_none() {
        let link = LinkBuilder::new("eth0.100").vlan("eth0", 100).build();
        match link.link_type {
            DeclaredLinkType::Vlan { protocol, .. } => assert!(protocol.is_none()),
            other => panic!("expected Vlan, got {other:?}"),
        }
    }

    #[test]
    fn vlan_builder_protocol_setter_records_dot1ad() {
        let link = LinkBuilder::new("eth0.100")
            .vlan("eth0", 100)
            .vlan_protocol(VlanProtocol::Dot1ad)
            .build();
        match link.link_type {
            DeclaredLinkType::Vlan { protocol, .. } => {
                assert_eq!(protocol, Some(VlanProtocol::Dot1ad));
            }
            other => panic!("expected Vlan, got {other:?}"),
        }
    }

    #[test]
    fn vlan_protocol_setter_no_op_on_non_vlan() {
        // Calling vlan_protocol() on a builder that isn't a
        // VLAN should leave the link_type unchanged.
        let link = LinkBuilder::new("eth0")
            .dummy()
            .vlan_protocol(VlanProtocol::Dot1ad);
        assert_eq!(link.errors.len(), 1, "the setter is recorded (#518)");
        assert!(matches!(link.build().link_type, DeclaredLinkType::Dummy));
    }

    #[test]
    fn vlan_protocol_wire_values() {
        // 802.1Q == 0x8100, 802.1ad == 0x88a8. Pins the wire
        // contract for IFLA_VLAN_PROTOCOL emission.
        assert_eq!(VlanProtocol::Dot1q.as_u16(), 0x8100);
        assert_eq!(VlanProtocol::Dot1ad.as_u16(), 0x88a8);
    }

    // -------- end Plan 190 §2.2 --------

    #[test]
    fn vrf_in_network_config_carries_master_chain() {
        // The master() chain works alongside vrf(); confirms
        // recipes that enslave a dummy into a VRF via the
        // declarative path compose correctly.
        let cfg = NetworkConfig::new()
            .link("vrf-red", |b| b.vrf(100))
            .link("eth0", |b| b.dummy().master("vrf-red"));
        assert_eq!(cfg.links.len(), 2);
        assert!(matches!(
            cfg.links[0].link_type,
            DeclaredLinkType::Vrf { table: 100 }
        ));
        assert_eq!(cfg.links[1].master.name(), Some("vrf-red"));
    }
}

#[cfg(test)]
mod plan_228_tests {
    //! Plan 228 — typed Percent on declarative QdiscBuilder.
    //!
    //! Adversarial coverage that the new `loss_pct(Percent)` and the
    //! deprecated `loss(f64)` produce identical stored state for sane
    //! inputs, and that the typed sibling clamps adversarial floats
    //! while the raw f64 path lets them through.

    use super::*;
    use crate::util::Percent;

    /// The netem config a declaration holds.
    fn netem_of(q: &DeclaredQdisc) -> &crate::netlink::tc::NetemConfig {
        match &q.qdisc_type {
            QdiscSpec::Netem(c) => c,
            other => panic!("expected netem, got {other:?}"),
        }
    }

    fn netem_loss(q: &DeclaredQdisc) -> f64 {
        netem_of(q).loss.as_percent()
    }

    #[test]
    fn loss_pct_lands_in_the_netem_config() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::new(1.5));
        assert_eq!(netem_loss(&q.build().unwrap()), 1.5);
        // `Percent` clamps at the setter: 150 is 100, -1.5 is 0, NaN is 0
        // (#598), infinity is 100.
        for (input, stored) in [
            (150.0, 100.0),
            (-1.5, 0.0),
            (f64::NAN, 0.0),
            (f64::INFINITY, 100.0),
        ] {
            let q = QdiscBuilder::new("eth0")
                .netem()
                .loss_pct(Percent::new(input))
                .build()
                .unwrap();
            assert_eq!(netem_loss(&q), stored, "{input}");
        }
        // The headline footgun the typed boundary kills: fraction vs percent.
        let q = QdiscBuilder::new("eth0")
            .netem()
            .loss_pct(Percent::from_fraction(0.015))
            .build()
            .unwrap();
        assert_eq!(netem_loss(&q), 1.5);
    }

    #[test]
    fn the_netem_percent_setters_land_in_their_fields() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .duplicate_pct(Percent::new(2.5))
            .corrupt_pct(Percent::new(0.75))
            .reorder_pct(Percent::new(5.0))
            .loss_correlation_pct(Percent::new(25.0))
            .delay_correlation_pct(Percent::new(50.0))
            .build()
            .unwrap();
        let c = netem_of(&q);
        assert_eq!(c.duplicate, Percent::new(2.5));
        assert_eq!(c.corrupt, Percent::new(0.75));
        assert_eq!(c.reorder, Percent::new(5.0));
        assert_eq!(c.loss_correlation, Percent::new(25.0));
        assert_eq!(c.delay_correlation, Percent::new(50.0));
    }

    #[test]
    fn rate_is_the_netem_configs_rate() {
        use crate::util::Rate;
        let q = QdiscBuilder::new("eth0")
            .netem()
            .rate(Rate::mbit(100))
            .build()
            .unwrap();
        assert_eq!(netem_of(&q).rate, Some(Rate::mbit(100)));
    }

    // ---- #349 / #361 / #515 — every kind's knobs land in its config ----

    #[test]
    fn tbf_takes_typed_units_into_its_config() {
        use crate::netlink::tc::TbfConfig;
        use crate::util::{Bytes, Rate};
        let q = QdiscBuilder::new("eth0")
            .tbf(Rate::mbit(100), Bytes::kib(32))
            .limit_bytes(Bytes::kib(64))
            .peakrate(Rate::mbit(200))
            .mtu(1600)
            .build()
            .unwrap();
        let by_hand = TbfConfig::new()
            .rate(Rate::mbit(100))
            .burst(Bytes::kib(32))
            .limit(Bytes::kib(64))
            .peakrate(Rate::mbit(200))
            .mtu(1600);
        assert_eq!(q.qdisc_type, QdiscSpec::Tbf(by_hand));
        // No limit declared: TbfConfig's zero, which validation refuses.
        let q = NetworkConfig::new().qdisc("eth0", |q| q.tbf(Rate::kbit(512), Bytes::kb(10)));
        assert!(q.validate().unwrap_err().to_string().contains("limit"));
        // limit_bytes on a non-tbf kind is an error, like every setter
        // for another kind (#476).
        let errors = QdiscBuilder::new("eth0")
            .htb()
            .limit_bytes(Bytes::kib(1))
            .build()
            .unwrap_err();
        assert!(errors[0].contains("tbf"), "{errors:?}");
    }

    #[test]
    fn fq_codel_sfq_and_prio_knobs_land_in_their_configs() {
        use crate::netlink::tc::{FqCodelConfig, PrioConfig, SfqConfig};
        let q = QdiscBuilder::new("eth0")
            .fq_codel()
            .limit(crate::util::Packets::new(1200))
            .target(Duration::from_millis(5))
            .interval(Duration::from_millis(100))
            .flows(1024)
            .quantum(300)
            .ecn(true)
            .build()
            .unwrap();
        let by_hand = FqCodelConfig::new()
            .limit(crate::util::Packets::new(1200))
            .target(Duration::from_millis(5))
            .interval(Duration::from_millis(100))
            .flows(1024)
            .quantum(300)
            .ecn(true);
        assert_eq!(q.qdisc_type, QdiscSpec::FqCodel(by_hand));

        let q = QdiscBuilder::new("eth0")
            .sfq()
            .perturb(Duration::from_secs(10))
            .limit(crate::util::Packets::new(200))
            .quantum(1514)
            .build()
            .unwrap();
        let by_hand = SfqConfig::new().perturb(10).limit(crate::util::Packets::new(200)).quantum(1514);
        assert_eq!(q.qdisc_type, QdiscSpec::Sfq(by_hand));

        let q = QdiscBuilder::new("eth0").prio().bands(4).build().unwrap();
        assert_eq!(q.qdisc_type, QdiscSpec::Prio(PrioConfig::new().bands(4)));
        let bare = QdiscBuilder::new("eth0").prio().build().unwrap();
        assert_eq!(
            bare.qdisc_type,
            QdiscSpec::Prio(PrioConfig::new()),
            "the kernel's 3 bands"
        );
    }

    /// `perturb` takes a `Duration`, but the kernel field is whole
    /// seconds, and 0 turns perturbation off. A fraction rounds up, so a
    /// sub-second period is never silently "off" (#597).
    #[test]
    fn sfq_perturb_rounds_up_to_whole_seconds() {
        let secs = |d| {
            let q = QdiscBuilder::new("eth0").sfq().perturb(d).build().unwrap();
            let QdiscSpec::Sfq(c) = q.qdisc_type else {
                panic!("sfq");
            };
            c.perturb
        };
        assert_eq!(secs(Duration::from_millis(1_500)), 2);
        assert_eq!(secs(Duration::from_millis(500)), 1);
        assert_eq!(secs(Duration::from_secs(1)), 1);
        assert_eq!(secs(Duration::ZERO), 0, "zero is still off");

        // The kernel field is an int: past it is a builder error, not a
        // silent saturation.
        let err = QdiscBuilder::new("eth0")
            .sfq()
            .perturb(Duration::from_secs(u64::from(i32::MAX.unsigned_abs()) + 1))
            .build()
            .unwrap_err();
        assert!(err.iter().any(|e| e.contains("perturb")), "{err:?}");
    }

    /// The whole of any config, through `spec`: what has no setter here.
    #[test]
    fn spec_takes_a_whole_config() {
        use crate::netlink::tc::{NetemConfig, NetemSlot};
        let netem = NetemConfig::new()
            .delay(Duration::from_millis(10))
            .slot(NetemSlot::new(
                Duration::from_millis(1),
                Duration::from_millis(2),
            ))
            .seed(7);
        let q = QdiscBuilder::new("eth0")
            .spec(netem.clone())
            .build()
            .unwrap();
        assert_eq!(q.qdisc_type, QdiscSpec::Netem(netem));
        let q = QdiscBuilder::new("eth0")
            .spec(QdiscSpec::Clsact)
            .build()
            .unwrap();
        assert_eq!(q.effective_parent(), QdiscParent::Ingress);
    }

    /// #476: a gateway that does not parse was dropped, so
    /// `.via("10.0.0.1x").dev("eth0")` became an on-link route; and one of
    /// the other family was dropped at apply while the diff compared it.
    #[test]
    fn a_bad_or_foreign_gateway_is_an_error() {
        let typo = NetworkConfig::new().route("10.0.0.0/8", |r| r.via("10.0.0.1x").dev("eth0"));
        assert!(
            matches!(typo, Err(RouteParseError::InvalidGateway(ref g)) if g == "10.0.0.1x"),
            "{typo:?}"
        );
        // An IPv4 route via an IPv6 gateway is RFC 5549's, sent as RTA_VIA
        // since 0.32 (#516); the other way round is refused.
        assert!(NetworkConfig::new().route("10.0.0.0/8", |r| r.via("fd00::1").dev("eth0")).is_ok());
        let v4_for_v6 = NetworkConfig::new().route("fd00:1::/64", |r| r.via("10.0.0.1"));
        assert!(
            matches!(v4_for_v6, Err(RouteParseError::InvalidGateway(_))),
            "{v4_for_v6:?}"
        );
        assert!(
            NetworkConfig::new()
                .route("10.0.0.0/8", |r| r.via("10.0.0.1"))
                .is_ok()
        );
    }

    /// #476: a qdisc with no kind became an fq_codel, which replaced the
    /// root qdisc; a setter before its kind was lost. Both now fail
    /// `validate()`, which `diff` and `apply` run.
    #[test]
    fn a_kindless_or_misordered_qdisc_fails_validation() {
        let kindless = NetworkConfig::new().qdisc("eth0", |q| q);
        let err = kindless.validate().expect_err("no kind");
        assert!(err.to_string().contains("no qdisc kind"), "{err}");
        assert!(
            kindless.qdiscs().is_empty(),
            "nothing is declared in its place"
        );

        let misordered = NetworkConfig::new().qdisc("eth0", |q| q.delay_ms(10).netem());
        let err = misordered.validate().expect_err("delay before netem");
        assert!(err.to_string().contains("`.delay_ms()`"), "{err}");

        let fine = NetworkConfig::new().qdisc("eth0", |q| q.netem().delay_ms(10));
        assert!(fine.validate().is_ok());
    }

    /// A setter for another kind does not rewrite the qdisc — and is no
    /// longer silently dropped either: each is an error the config's
    /// `validate()` reports (#476).
    #[test]
    fn setters_for_another_kind_are_errors() {
        use crate::util::{Bytes, Rate};
        let errors = QdiscBuilder::new("eth0")
            .htb()
            .flows(8)
            .ecn(true)
            .bands(4)
            .peakrate(Rate::mbit(1))
            .mtu(9000)
            .target(Duration::from_millis(5))
            .perturb(Duration::from_secs(1))
            .build()
            .unwrap_err();
        assert_eq!(errors.len(), 7, "{errors:?}");
        assert!(
            errors.iter().all(|e| e.ends_with("this qdisc is htb")),
            "{errors:?}"
        );

        // `limit` and `quantum` are shared across kinds by design; each
        // must land on the kind in hand and nowhere else.
        let netem = QdiscBuilder::new("eth0").netem().limit(crate::util::Packets::new(50)).build().unwrap();
        assert_eq!(netem_of(&netem).limit, crate::util::Packets::new(50));
        // tbf's limit is a byte count with its own setter; the packet
        // `limit` must not land on it — and is an error rather than lost.
        let errors = QdiscBuilder::new("eth0")
            .tbf(Rate::mbit(1), Bytes::kib(4))
            .limit(crate::util::Packets::new(50))
            .build()
            .unwrap_err();
        assert!(errors[0].starts_with("`.limit()`"), "{errors:?}");
    }

    #[test]
    fn duration_setters_keep_their_precision() {
        let q = QdiscBuilder::new("eth0")
            .netem()
            .delay(Duration::from_micros(1_500))
            .jitter_us(250)
            .build()
            .unwrap();
        assert_eq!(netem_of(&q).delay, Some(Duration::from_micros(1_500)));
        assert_eq!(netem_of(&q).jitter, Some(Duration::from_micros(250)));
        // The millisecond setters do not wrap: 4_294_968 ms × 1000 wrapped
        // to 1000 µs once.
        let q = QdiscBuilder::new("eth0")
            .netem()
            .delay_ms(u32::MAX)
            .jitter_ms(u32::MAX)
            .build()
            .unwrap();
        let max = Duration::from_millis(u64::from(u32::MAX));
        assert_eq!(
            (netem_of(&q).delay, netem_of(&q).jitter),
            (Some(max), Some(max))
        );
    }

    #[test]
    fn every_netem_setter_lands_in_the_netem_config() {
        use crate::netlink::tc::NetemConfig;
        use crate::util::Rate;
        let q = QdiscBuilder::new("eth0")
            .netem()
            .delay(Duration::from_millis(20))
            .jitter(Duration::from_micros(250))
            .delay_correlation_pct(Percent::new(25.0))
            .loss_pct(Percent::new(1.0))
            .loss_correlation_pct(Percent::new(10.0))
            .duplicate_pct(Percent::new(0.5))
            .duplicate_correlation_pct(Percent::new(5.0))
            .corrupt_pct(Percent::new(0.1))
            .corrupt_correlation_pct(Percent::new(2.0))
            .reorder_pct(Percent::new(3.0))
            .reorder_correlation_pct(Percent::new(50.0))
            .gap(5)
            .rate(Rate::mbit(100))
            .limit(crate::util::Packets::new(2000))
            .build()
            .unwrap();
        let by_hand = NetemConfig::new()
            .delay(Duration::from_millis(20))
            .jitter(Duration::from_micros(250))
            .delay_correlation(Percent::new(25.0))
            .loss(Percent::new(1.0))
            .loss_correlation(Percent::new(10.0))
            .duplicate(Percent::new(0.5))
            .duplicate_correlation(Percent::new(5.0))
            .corrupt(Percent::new(0.1))
            .corrupt_correlation(Percent::new(2.0))
            .reorder(Percent::new(3.0))
            .reorder_correlation(Percent::new(50.0))
            .gap(5)
            .rate(Rate::mbit(100))
            .limit(crate::util::Packets::new(2000));
        assert_eq!(q.qdisc_type, QdiscSpec::Netem(by_hand));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_roundtrip_tests {
    use super::*;
    use crate::netlink::link::VlanProtocol;

    /// A config that round-trips must serialize, deserialize, and
    /// re-serialize to a byte-identical document. (The `Declared*`
    /// types don't all implement `PartialEq` — `DeclaredQdiscType`
    /// carries `f64` — so re-serialization equality is the round-trip
    /// oracle.)
    fn assert_roundtrips(cfg: &NetworkConfig) {
        let json = cfg.to_json_string().expect("serialize");
        let back = NetworkConfig::from_json_str(&json).expect("deserialize");
        let json2 = back.to_json_string().expect("re-serialize");
        assert_eq!(json, json2, "round-trip changed the document:\n{json}\n{json2}");
    }

    #[test]
    fn full_config_roundtrips() {
        let cfg = NetworkConfig::new()
            .link("br0", |l| l.bridge().up().mtu(1500))
            .link("eth0.42", |l| {
                l.vlan("eth0", 42).vlan_protocol(VlanProtocol::Dot1ad)
            })
            .link("bond0", |l| l.bond().bond_mode(BondMode::Ieee802_3ad))
            .link("dummy0", |l| l.dummy().address([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]))
            .address("br0", "10.0.0.1/24")
            .expect("addr")
            .address("br0", "2001:db8::1/64")
            .expect("addr6")
            .route("0.0.0.0/0", |r| r.via("10.0.0.254"))
            .expect("route")
            .route("10.10.0.0/16", |r| r.blackhole().metric(100))
            .expect("blackhole")
            .qdisc("eth0", |q| q.netem().delay_ms(100));
        assert_roundtrips(&cfg);
    }

    /// #515 — a qdisc is written in the units tc(8) writes, and reads
    /// back as the same spec.
    #[test]
    fn netem_is_written_in_human_units_and_reads_back() {
        use crate::util::{Percent, Rate};
        let cfg = NetworkConfig::new().qdisc("eth0", |q| {
            q.netem()
                .delay(Duration::from_micros(1_500))
                .jitter(Duration::from_micros(250))
                .rate(Rate::mbit(100))
                .reorder_pct(Percent::new(3.0))
                .reorder_correlation_pct(Percent::new(50.0))
                .gap(5)
        });
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        assert!(
            json.contains(
                r#""netem":{"delay":"1500us","jitter":"250us","reorder":"3%","reorder_correlation":"50%","gap":5,"rate":"100mbit"}"#
            ),
            "{json}"
        );
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.qdiscs()[0].qdisc_type, cfg.qdiscs()[0].qdisc_type);
    }

    /// #645 — HFSC's default class, and the roots with no parameters of
    /// their own, are written and read back.
    #[test]
    fn hfsc_drr_and_qfq_roots_read_back() {
        let cfg = NetworkConfig::new()
            .qdisc("eth0", |q| q.hfsc().default_class(0x20))
            .qdisc("eth1", |q| q.drr())
            .qdisc("eth2", |q| q.qfq());
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""hfsc":{"default_class":32}"#,
            r#""qdisc-type":"drr""#,
            r#""qdisc-type":"qfq""#,
        ] {
            assert!(json.contains(want), "{want} missing from {json}");
        }
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.qdiscs()[0].qdisc_type, cfg.qdiscs()[0].qdisc_type);
    }

    /// A document written by 0.31 or before still reads: its raw-unit
    /// fields are taken beside the new ones, in their old units.
    #[test]
    fn a_0_31_qdisc_document_still_reads() {
        use crate::netlink::tc::{NetemConfig, TbfConfig};
        use crate::util::{Bytes, Percent, Rate};
        let old = r#"{"qdiscs":[{"dev":"eth0","qdisc-type":{"netem":{
            "delay_us":100000,"jitter_us":null,"loss_percent":1.5,"rate_bps":12500000,
            "loss_correlation":null,"gap":null,"limit":500}}}]}"#;
        let back = NetworkConfig::from_json_str(old).unwrap();
        let want = NetemConfig::new()
            .delay(Duration::from_millis(100))
            .loss(Percent::new(1.5))
            .rate(Rate::mbit(100))
            .limit(crate::util::Packets::new(500));
        assert_eq!(back.qdiscs()[0].qdisc_type, QdiscSpec::Netem(want));

        let pre_0_28 = r#"{"qdiscs":[{"dev":"eth0","qdisc-type":{"tbf":
            {"rate_bps":1,"burst_bytes":2,"limit_bytes":3}}}]}"#;
        let back = NetworkConfig::from_json_str(pre_0_28).unwrap();
        let want = TbfConfig::new()
            .rate(Rate::bytes_per_sec(1))
            .burst(Bytes::new(2))
            .limit(Bytes::new(3));
        assert_eq!(back.qdiscs()[0].qdisc_type, QdiscSpec::Tbf(want));

        let tbf = NetworkConfig::new().qdisc("eth0", |q| {
            q.tbf(Rate::mbit(100), Bytes::kib(32))
                .limit_bytes(Bytes::kib(64))
        });
        let json = tbf.to_json_string().unwrap();
        assert!(
            json.contains(r#""tbf":{"rate":"100mbit","burst":"32kib","limit":"64kib"}"#),
            "{json}"
        );
    }

    /// What a document cannot mean is refused as it is read: a value set
    /// both ways, a percentage outside 0..=100, an sfq period past the
    /// kernel's int, a misspelt field, a rate without its unit.
    #[test]
    fn a_qdisc_document_that_cannot_mean_anything_is_refused() {
        for (doc, says) in [
            (r#"{"netem":{"delay":"10ms","delay_us":10000}}"#, "twice"),
            (r#"{"netem":{"loss":"150%"}}"#, "0 to 100"),
            (r#"{"netem":{"loss_percent":1e9}}"#, "0 to 100"),
            (r#"{"netem":{"deley":"10ms"}}"#, "unknown field"),
            (r#"{"netem":{"rate":1000}}"#, "rate"),
            (r#"{"sfq":{"perturb_secs":4294967295}}"#, "perturb"),
            (r#"{"tbf":{"burst":"32kib"}}"#, "rate"),
        ] {
            let full = format!(r#"{{"qdiscs":[{{"dev":"eth0","qdisc-type":{doc}}}]}}"#);
            let err = NetworkConfig::from_json_str(&full)
                .expect_err(doc)
                .to_string();
            assert!(err.contains(says), "{doc}: {err}");
        }
    }

    /// #718: a JSON error keeps serde_json's error as its detail, where its
    /// line and column are, under a context.
    #[test]
    fn a_json_error_keeps_its_source() {
        let err = NetworkConfig::from_json_str("{\"links\": [}").unwrap_err();
        let crate::netlink::ErrorDetail::Json(json) = err.detail() else {
            panic!("expected ErrorDetail::Json, got {err:?}");
        };
        assert_eq!(json.line(), 1, "{err}");
        assert_eq!(err.context(), ["config JSON parse"], "{err:?}");
    }

    #[test]
    fn address_roundtrips_as_cidr_string() {
        let cfg = NetworkConfig::new()
            .address("eth0", "192.168.1.5/24")
            .unwrap();
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""address":"192.168.1.5/24""#), "{json}");
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.addresses()[0].address().to_string(), "192.168.1.5");
        assert_eq!(back.addresses()[0].prefix_len(), 24);
    }

    #[test]
    fn address_attributes_roundtrip_and_validate() {
        use std::time::Duration;
        let cfg = NetworkConfig::new()
            .address_with("eth0", "fd00::1/64", |a| a.nodad().noprefixroute().metric(100))
            .unwrap()
            .address_with("eth0", "10.0.0.1/32", |a| a.peer("10.0.0.2").label("eth0:p"))
            .unwrap()
            .address_with("eth0", "10.0.1.1/24", |a| {
                a.lifetime(Duration::from_secs(3600), Duration::from_secs(1800))
            })
            .unwrap();
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""flags":["nodad","noprefixroute"]"#,
            r#""metric":100"#,
            r#""peer":"10.0.0.2""#,
            r#""label":"eth0:p""#,
            r#""valid-lft":"3600s""#,
            r#""preferred-lft":"1800s""#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }

        // The other family's setters, a label without the device name, a
        // preferred lifetime past the valid one: refused, builder and
        // document alike.
        for (cfg, says) in [
            (
                NetworkConfig::new().address_with("eth0", "10.0.0.1/24", |a| a.nodad()).unwrap(),
                "nodad is an IPv6 address flag",
            ),
            (
                NetworkConfig::new().address_with("eth0", "fd00::1/64", |a| a.label("eth0:x")).unwrap(),
                "a label is IPv4 only",
            ),
            (
                NetworkConfig::new().address_with("eth0", "10.0.0.1/24", |a| a.label("lan")).unwrap(),
                "must start with the device name",
            ),
            (
                NetworkConfig::new()
                    .address_with("eth0", "10.0.0.1/24", |a| {
                        a.lifetime(Duration::from_secs(10), Duration::from_secs(20))
                    })
                    .unwrap(),
                "preferred lifetime is longer",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        for (doc, says) in [
            (
                r#"{"addresses":[{"dev":"eth0","address":"10.0.0.1/24","flags":["fast"]}]}"#,
                "unknown address flag",
            ),
            (
                r#"{"addresses":[{"dev":"eth0","address":"fd00::1/64","label":"eth0:x"}]}"#,
                "IPv4 only",
            ),
            (
                r#"{"addresses":[{"dev":"eth0","address":"10.0.0.1/24","preferred-lft":"3600s"}]}"#,
                "needs a valid one",
            ),
        ] {
            let err = NetworkConfig::from_json_str(doc).unwrap_err().to_string();
            assert!(err.contains(says), "{doc}: {err}");
        }
    }

    #[test]
    fn link_attributes_roundtrip_and_validate() {
        let cfg = NetworkConfig::new().link("d0", |l| {
            l.dummy()
                .txqlen(500)
                .alias("lab")
                .group(7)
                .gso_max_size(32000)
                .gso_max_segs(50)
                .gro_max_size(32000)
                .promisc(true)
                .protodown(false)
                .altname("d0-a")
                .altname("d0-b")
        });
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""txqlen":500"#,
            r#""alias":"lab""#,
            r#""group":7"#,
            r#""gso-max-size":32000"#,
            r#""promisc":true"#,
            r#""protodown":false"#,
            r#""altnames":["d0-a","d0-b"]"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (
                NetworkConfig::new()
                    .owner("lab")
                    .link("d0", |l| l.dummy().alias("mine")),
                "the owner tag is written as the alias",
            ),
            (
                NetworkConfig::new().link("d0", |l| l.dummy().alias(&"x".repeat(256))),
                "at most 255 bytes",
            ),
            (
                NetworkConfig::new().link("d0", |l| l.dummy().altname("a/b")),
                "altname \"a/b\"",
            ),
            (
                NetworkConfig::new().link("d0", |l| l.dummy().altname("d0")),
                "not the name",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    /// Geneve and bareudp (#516). Bareudp is unverified on a live kernel
    /// (the one this was written on does not build it): the offline
    /// prediction, which encodes a declaration as the apply sends it and
    /// reads it back as a dump, pins what a change does.
    #[test]
    fn geneve_and_bareudp_roundtrip_and_predict() {
        let geneve = |vni, last| {
            NetworkConfig::new().link("gn1", move |l| {
                l.geneve(vni).geneve_remote(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last)))
            })
        };
        assert_roundtrips(&geneve(5, 2));
        let json = geneve(5, 2).to_json_string().unwrap();
        assert!(json.contains(r#""geneve":{"vni":5,"remote":"10.0.0.2""#), "{json}");
        // A new remote changes in place; a new VNI recreates.
        assert!(geneve(5, 3).diff_against(&geneve(5, 2)).recreates.is_empty());
        let r = geneve(6, 2).diff_against(&geneve(5, 2)).recreates;
        assert!(r.iter().any(|r| r.reason.contains("geneve vni 5 -> 6")), "{r:?}");

        let bareudp = |port, multi| {
            NetworkConfig::new().link("bu1", move |l| l.bareudp(port, 0x8847).bareudp_multiproto(multi))
        };
        assert_roundtrips(&bareudp(6635, false));
        assert!(bareudp(6635, true).diff_against(&bareudp(6635, true)).recreates.is_empty());
        for (b, says) in [
            (bareudp(6636, false), "bareudp port 6635 -> 6636"),
            (bareudp(6635, true), "bareudp multiproto -> true"),
        ] {
            let r = b.diff_against(&bareudp(6635, false)).recreates;
            assert!(r.iter().any(|r| r.reason.contains(says)), "{says}: {r:?}");
        }
        let err = NetworkConfig::new()
            .link("bu1", |l| l.bareudp(6635, 0x8847).address([2, 0, 0, 0, 0, 1]))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("an L3 tunnel has no hardware address"), "{err}");
    }

    #[test]
    fn macsec_roundtrips_predicts_and_validates() {
        let ms = |sci: u64, encrypt: bool| {
            NetworkConfig::new().link("ms1", move |l| {
                l.macsec("d0").macsec_sci(sci).macsec_encrypt(encrypt).macsec_replay_window(32)
            })
        };
        assert_roundtrips(&ms(0x0200_0000_0001_0001, true));
        let json = ms(0x0200_0000_0001_0001, true).to_json_string().unwrap();
        assert!(json.contains(r#""macsec":{"parent":"d0","sci":144115188075921409"#), "{json}");
        // Encryption changes in place; a new SCI recreates.
        assert!(ms(1, false).diff_against(&ms(1, true)).recreates.is_empty());
        let r = ms(2, true).diff_against(&ms(1, true)).recreates;
        assert!(r.iter().any(|r| r.reason.contains("macsec sci")), "{r:?}");
        let err = NetworkConfig::new()
            .link("ms1", |l| l.macsec("d0").macsec_include_sci(false))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("end-station or SCB"), "{err}");
    }

    #[test]
    fn a_veth_peer_namespace_roundtrips() {
        use crate::netlink::namespace::NetnsRef;
        let cfg = NetworkConfig::new()
            .link("v0", |l| l.veth("p0").veth_peer_netns(NetnsRef::Named("blue".into())))
            .link("v1", |l| l.veth("p1"));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#"{"veth":{"peer":"p0","peer_netns":{"named":"blue"}}}"#), "{json}");
        assert!(json.contains(r#"{"veth":{"peer":"p1"}}"#), "{json}");
        let err = NetworkConfig::new()
            .link("d0", |l| l.dummy().veth_peer_netns(NetnsRef::Default))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("veth_peer_netns"), "{err}");
    }

    /// #680: a veth peer's MAC, MTU and state, set in its namespace,
    /// round-trip; set for a peer here they are refused, since that peer is
    /// a link of its own.
    #[test]
    fn a_veth_peers_settings_roundtrip_and_need_its_namespace() {
        use crate::netlink::namespace::NetnsRef;
        let cfg = NetworkConfig::new().link("v0", |l| {
            l.veth("p0")
                .veth_peer_netns(NetnsRef::Named("blue".into()))
                .veth_peer_address([2, 0, 0, 0, 0, 1])
                .veth_peer_mtu(1400)
                .veth_peer_up()
        });
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        assert!(
            json.contains(
                r#""peer_netns":{"named":"blue"},"peer_address":"02:00:00:00:00:01","peer_mtu":1400,"peer_state":"up""#
            ),
            "{json}"
        );
        for cfg in [
            NetworkConfig::new().link("v0", |l| l.veth("p0").veth_peer_mtu(1400)),
            NetworkConfig::new()
                .link("v0", |l| l.veth("p0").veth_peer_netns(NetnsRef::Default).veth_peer_up()),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("a peer here is a link of its own: declare p0"), "{err}");
        }
        let err = NetworkConfig::new()
            .link("d0", |l| l.dummy().veth_peer_mtu(1400))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("veth_peer_mtu"), "{err}");
    }

    /// #680: VRF strict mode round-trips, and with it on two VRFs on one
    /// table are refused, as the kernel would.
    #[test]
    fn vrf_strict_mode_roundtrips_and_keeps_a_table_to_one_vrf() {
        let cfg = NetworkConfig::new()
            .vrf_strict_mode(true)
            .link("red", |l| l.vrf(10))
            .link("blue", |l| l.vrf(20));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        assert!(cfg.to_json_string().unwrap().contains(r#""vrf-strict-mode":true"#));
        let shared = |strict: bool| {
            NetworkConfig::new()
                .vrf_strict_mode(strict)
                .link("red", |l| l.vrf(10))
                .link("green", |l| l.vrf(10))
        };
        shared(false).validate().unwrap();
        let err = shared(true).validate().unwrap_err().to_string();
        assert!(err.contains("table 10 is also VRF red's"), "{err}");
    }

    #[test]
    fn mpls_encap_and_via_routes_roundtrip_and_validate() {
        let cfg = NetworkConfig::new()
            .route("10.1.0.0/16", |r| r.via("10.0.0.2").dev("eth0").encap_mpls(&[100, 200]))
            .unwrap()
            .route("10.2.0.0/16", |r| r.via("fd00::2").dev("eth0"))
            .unwrap();
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""encap-mpls":[100,200]"#), "{json}");
        assert!(json.contains(r#""gateway":"fd00::2""#), "{json}");
        for (cfg, says) in [
            (
                NetworkConfig::new()
                    .route("10.1.0.0/16", |r| r.via("10.0.0.2").encap_mpls(&[1 << 20]))
                    .unwrap(),
                "past 1048575",
            ),
            (
                NetworkConfig::new()
                    .route("10.1.0.0/16", |r| r.encap_mpls(&[100]))
                    .unwrap(),
                "needs a gateway or device",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn multipath_routes_roundtrip_and_validate() {
        let cfg = NetworkConfig::new()
            .route("10.1.0.0/16", |r| {
                r.nexthop(|h| h.via("10.0.0.2").dev("eth0"))
                    .nexthop(|h| h.via("10.0.1.2").weight(3).onlink().dev("eth1"))
            })
            .unwrap();
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        let want = r#""nexthops":[{"gateway":"10.0.0.2","dev":"eth0"},{"gateway":"10.0.1.2","dev":"eth1","weight":3,"onlink":true}]"#;
        assert!(json.contains(want), "{json}");
        let route = |f: fn(RouteBuilder) -> RouteBuilder| NetworkConfig::new().route("10.1.0.0/16", f).unwrap();
        for (cfg, says) in [
            (route(|r| r.nexthop(|h| h.via("10.0.0.2"))), "two next hops or more"),
            (
                route(|r| r.via("10.0.0.9").nexthop(|h| h.via("10.0.0.2")).nexthop(|h| h.via("10.0.0.3"))),
                "no gateway, device or nexthop object of its own",
            ),
            (route(|r| r.nexthop(|h| h).nexthop(|h| h.via("10.0.0.3"))), "needs a gateway or device"),
            (
                route(|r| r.nexthop(|h| h.via("fd00::2")).nexthop(|h| h.via("10.0.0.3"))),
                "not of the destination's family",
            ),
            (
                route(|r| r.nexthop(|h| h.via("10.0.0.2").onlink()).nexthop(|h| h.via("10.0.0.3"))),
                "onlink needs a gateway and a device",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        assert!(NetworkConfig::new().route("10.1.0.0/16", |r| r.nexthop(|h| h.via("x"))).is_err());
    }

    #[test]
    fn nexthops_roundtrip_display_and_validate() {
        let gw = |h: u8| IpAddr::from([10, 0, 0, h]);
        let cfg = NetworkConfig::new()
            .nexthop(1, |n| n.via(gw(2)).dev("eth0"))
            .nexthop(2, |n| n.via(gw(3)).dev("eth0").onlink())
            .nexthop(3, |n| n.blackhole().ipv6())
            .nexthop(10, |n| n.group(&[(1, 1), (2, 300)]))
            .route("10.1.0.0/16", |r| r.nhid(10))
            .unwrap();
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#"{"id":1,"gateway":"10.0.0.2","dev":"eth0"}"#,
            r#"{"id":10,"group":[[1,1],[2,300]]}"#,
            r#""nhid":10"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        let shown: Vec<String> = cfg.nexthops().iter().map(|n| n.to_string()).collect();
        assert_eq!(
            shown,
            [
                "nexthop 1 via 10.0.0.2 dev eth0",
                "nexthop 2 via 10.0.0.3 dev eth0 onlink",
                "nexthop 3 blackhole",
                "nexthop 10 group 1/2,300",
            ]
        );
        let one = |f: fn(NexthopSpecBuilder) -> NexthopSpecBuilder| NetworkConfig::new().nexthop(1, f);
        for (cfg, says) in [
            (NetworkConfig::new().nexthop(0, |n| n.blackhole()), "id is not 0"),
            (one(|n| n), "needs a gateway or device"),
            (one(|n| n.blackhole().dev("eth0")), "is one of"),
            (one(|n| n.via("10.0.0.2".parse().unwrap())), "needs its device"),
            (one(|n| n.dev("eth0").onlink()), "onlink needs a gateway"),
            (one(|n| n.group(&[(5, 1)])), "member 5 is not a declared nexthop"),
            (
                one(|n| n.blackhole()).nexthop(2, |n| n.group(&[(1, 0)])),
                "a weight is 1 or more",
            ),
            (
                one(|n| n.blackhole()).nexthop(2, |n| n.group(&[(1, 1)])).nexthop(3, |n| n.group(&[(2, 1)])),
                "groups do not nest",
            ),
            (one(|n| n.blackhole()).nexthop(1, |n| n.blackhole()), "declared twice"),
            (
                NetworkConfig::new().route("10.1.0.0/16", |r| r.nhid(1).dev("eth0")).unwrap(),
                "no gateway or device of its own",
            ),
            (
                one(|n| n.via("fd00::2".parse().unwrap()).dev("eth0"))
                    .route("10.1.0.0/16", |r| r.nhid(1))
                    .unwrap(),
                "of the other family",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn rules_roundtrip_display_and_validate() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let cfg = NetworkConfig::new()
            .rule(100, |r| r.from(Ipv4Addr::new(10, 0, 0, 0), 8).table(100))
            .rule(110, |r| r.invert().fwmark_masked(0x10, 0xff).iif("eth0").table(200))
            .rule(120, |r| r.table(254).suppress_prefixlen(0))
            .rule(130, |r| r.ipproto(6).dport(80, 89).sport(1024, 1024).prohibit())
            .rule(140, |r| r.ipv6().blackhole())
            .rule(100, |r| r.to("fd00::".parse::<Ipv6Addr>().unwrap(), 64).table(100));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#"{"priority":100,"from":"10.0.0.0/8","action":{"table":100}}"#,
            r#"{"priority":140,"ipv6":true,"action":"blackhole"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        let shown: Vec<String> = cfg.rules().iter().map(|r| r.to_string()).collect();
        assert_eq!(
            shown,
            [
                "rule 100 from 10.0.0.0/8 lookup 100",
                "rule 110 not fwmark 0x10/0xff iif eth0 lookup 200",
                "rule 120 lookup 254 suppress_prefixlength 0",
                "rule 130 ipproto 6 sport 1024 dport 80-89 prohibit",
                "rule 140 (ipv6) blackhole",
                "rule 100 to fd00::/64 lookup 100",
            ]
        );
        assert!(cfg.rules()[5].is_ipv6() && !cfg.rules()[0].is_ipv6());
        for (cfg, says) in [
            (NetworkConfig::new().rule(1, |r| r.from(Ipv4Addr::LOCALHOST, 33)), "at most 32 bits"),
            (
                NetworkConfig::new().rule(1, |r| r.from(Ipv4Addr::LOCALHOST, 8).to(Ipv6Addr::LOCALHOST, 8)),
                "not in the rule's family",
            ),
            (NetworkConfig::new().rule(1, |r| r.table(0)), "table 0 is unspecified"),
            (NetworkConfig::new().rule(1, |r| r.dport(90, 80)), "runs backwards"),
            (NetworkConfig::new().rule(1, |r| r).rule(1, |r| r), "declared twice"),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        // Two rules at one priority are fine: the kernel keeps both.
        NetworkConfig::new()
            .rule(1, |r| r.fwmark(1).table(100))
            .rule(1, |r| r.fwmark(2).table(101))
            .validate()
            .unwrap();
    }

    #[test]
    fn fdb_roundtrips_and_validates() {
        use std::net::Ipv4Addr;
        let ip = |h: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, h));
        let cfg = NetworkConfig::new()
            .link("br0", |l| l.bridge())
            .link("p0", |l| l.dummy().master("br0"))
            .link("p1", |l| l.dummy().master("br0"))
            .fdb("p0", [2, 0, 0, 0, 0, 1], |e| e.vlan(10))
            .fdb("p0", [2, 0, 0, 0, 0, 2], |e| e.local())
            .fdb("vx0", [0; 6], |e| e.dst(ip(2)))
            .fdb("vx0", [0; 6], |e| e.dst(ip(3)));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#"{"dev":"p0","mac":"02:00:00:00:00:01","vlan":10}"#,
            r#"{"dev":"p0","mac":"02:00:00:00:00:02","local":true}"#,
            r#"{"dev":"vx0","mac":"00:00:00:00:00:00","dst":"10.0.0.2"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        assert_eq!(cfg.fdb_entries()[0].to_string(), "fdb 02:00:00:00:00:01 dev p0 vlan 10 static");
        let one = |f: fn(FdbBuilder) -> FdbBuilder| NetworkConfig::new().fdb("p0", [2, 0, 0, 0, 0, 1], f);
        let ports = || {
            NetworkConfig::new()
                .link("br0", |l| l.bridge())
                .link("p0", |l| l.dummy().master("br0"))
                .link("p1", |l| l.dummy().master("br0"))
        };
        for (cfg, says) in [
            (one(|e| e.vlan(4095)), "a VLAN id is 1 to 4094"),
            (one(|e| e.dst("10.0.0.2".parse().unwrap()).vlan(10)), "a VXLAN remote has no bridge VLAN"),
            (one(|e| e.dst("10.0.0.2".parse().unwrap()).local()), "a VXLAN remote is not a local entry"),
            (NetworkConfig::new().fdb("p0", [0; 6], |e| e), "a bridge entry's MAC is a unicast one"),
            (one(|e| e).fdb("p0", [2, 0, 0, 0, 0, 1], |e| e), "declared twice"),
            (
                NetworkConfig::new()
                    .fdb("vx0", [2, 0, 0, 0, 0, 1], move |e| e.dst(ip(2)))
                    .fdb("vx0", [2, 0, 0, 0, 0, 1], move |e| e.dst(ip(3))),
                "a unicast MAC has one remote",
            ),
            (
                ports().fdb("p0", [2, 0, 0, 0, 0, 1], |e| e).fdb("p1", [2, 0, 0, 0, 0, 1], |e| e),
                "br0 has one entry per MAC and VLAN",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        // The same MAC in two VLANs, or on ports of two bridges, is two entries.
        ports()
            .fdb("p0", [2, 0, 0, 0, 0, 1], |e| e.vlan(10))
            .fdb("p1", [2, 0, 0, 0, 0, 1], |e| e.vlan(20))
            .validate()
            .unwrap();
    }

    #[test]
    fn neighbours_roundtrip_and_validate() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let cfg = NetworkConfig::new()
            .neighbour("d0", Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 0xa])
            .neighbour("d0", "fd00::2".parse::<Ipv6Addr>().unwrap(), [2, 0, 0, 0, 0, 0xb])
            .proxy_neighbour("d0", Ipv4Addr::new(10, 0, 0, 9));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#"{"dev":"d0","destination":"10.0.0.2","lladdr":"02:00:00:00:00:0a"}"#,
            r#"{"dev":"d0","destination":"10.0.0.9","proxy":true}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        assert_eq!(
            cfg.neighbours()[0].to_string(),
            "neighbour 10.0.0.2 lladdr 02:00:00:00:00:0a dev d0"
        );
        let mut proxy_with_mac = NetworkConfig::new().proxy_neighbour("d0", Ipv4Addr::new(10, 0, 0, 9));
        proxy_with_mac.neighbours[0].lladdr = Some([2, 0, 0, 0, 0, 1]);
        let mut no_mac = NetworkConfig::new().neighbour("d0", Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 1]);
        no_mac.neighbours[0].lladdr = None;
        for (cfg, says) in [
            (proxy_with_mac, "a proxy entry has no link-layer address"),
            (no_mac, "a neighbour needs its link-layer address"),
            (
                NetworkConfig::new().neighbour("d0", Ipv4Addr::UNSPECIFIED, [2, 0, 0, 0, 0, 1]),
                "a unicast address",
            ),
            (
                NetworkConfig::new()
                    .neighbour("d0", Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 1])
                    .neighbour("d0", Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 2]),
                "declared twice",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        // The same address as a neighbour and a proxy entry is two entries.
        NetworkConfig::new()
            .neighbour("d0", Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 1])
            .proxy_neighbour("d0", Ipv4Addr::new(10, 0, 0, 2))
            .validate()
            .unwrap();
    }

    #[test]
    fn ip6gre_roundtrips_and_validates() {
        use std::net::Ipv6Addr;
        let cfg = NetworkConfig::new()
            .link("g61", |l| l.ip6gre().ip6tnl_remote(Ipv6Addr::LOCALHOST).tunnel_key(7))
            .link("g62", |l| l.ip6gretap().ip6tnl_local(Ipv6Addr::LOCALHOST));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""ip6gre":{"remote":"::1","mode":"any","key":7}"#), "{json}");
        for (cfg, says) in [
            (NetworkConfig::new().link("g61", |l| l.ip6gre()), "fallback ip6gre0's"),
            (
                NetworkConfig::new().link("ip6gre0", |l| l.ip6gre().tunnel_key(1)),
                "the kernel's fallback ip6gre device",
            ),
            (
                NetworkConfig::new().link("t61", |l| {
                    l.ip6tnl().ip6tnl_remote(Ipv6Addr::LOCALHOST).tunnel_key(1)
                }),
                "`.tunnel_key()` sets a gre, gretap, vti, ip6gre, ip6gretap or vti6 parameter",
            ),
            (
                NetworkConfig::new().link("g61", |l| {
                    l.ip6gre().tunnel_key(1).ip6tnl_mode(crate::netlink::link::Ip6tnlMode::Ipip6)
                }),
                "a GRE tunnel has no mode",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    /// #680: vti6, erspan and ip6erspan declare, round-trip and validate.
    #[test]
    fn vti6_and_erspan_roundtrip_and_validate() {
        use crate::netlink::link::{ErspanDirection, ErspanVersion};
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v2 = ErspanVersion::V2 {
            direction: ErspanDirection::Egress,
            hwid: 7,
        };
        let cfg = NetworkConfig::new()
            .link("v61", |l| l.vti6().ip6tnl_remote(Ipv6Addr::LOCALHOST).tunnel_key(5))
            .link("es1", |l| {
                l.erspan(100)
                    .erspan_local(Ipv4Addr::new(10, 0, 0, 1))
                    .erspan_version(ErspanVersion::V1 { index: 123 })
            })
            .link("es6", |l| l.ip6erspan(9).erspan_remote(Ipv6Addr::LOCALHOST).erspan_version(v2));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""vti6":{"remote":"::1","mode":"any","key":5}"#,
            r#""erspan":{"session":100,"version":{"v1":{"index":123}},"local":"10.0.0.1"}"#,
            r#""ip6erspan":{"session":9,"version":{"v2":{"direction":"egress","hwid":7}},"remote":"::1"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (NetworkConfig::new().link("v61", |l| l.vti6()), "fallback ip6_vti0's"),
            (
                NetworkConfig::new().link("ip6_vti0", |l| l.vti6().tunnel_key(1)),
                "the kernel's fallback vti6 device",
            ),
            (
                NetworkConfig::new().link("v61", |l| l.vti6().tunnel_key(1).ip6tnl_hoplimit(3)),
                "a vti6 tunnel has no mode, hop limit or encapsulation limit",
            ),
            (
                NetworkConfig::new().link("es1", |l| l.erspan(1).erspan_remote(Ipv6Addr::LOCALHOST)),
                "an erspan tunnel's ends are IPv4",
            ),
            (
                NetworkConfig::new().link("es6", |l| l.ip6erspan(1).erspan_local(Ipv4Addr::LOCALHOST)),
                "an ip6erspan tunnel's ends are IPv6",
            ),
            (NetworkConfig::new().link("es1", |l| l.erspan(1024)), "10 bits, up to 1023"),
            (
                NetworkConfig::new()
                    .link("es1", |l| l.erspan(1).erspan_version(ErspanVersion::V1 { index: 1 << 20 })),
                "20 bits",
            ),
            (
                NetworkConfig::new().link("es1", |l| {
                    l.erspan(1).erspan_version(ErspanVersion::V2 {
                        direction: ErspanDirection::Ingress,
                        hwid: 64,
                    })
                }),
                "6 bits, up to 63",
            ),
            (NetworkConfig::new().link("d0", |l| l.dummy().erspan_ttl(3)), "erspan or ip6erspan"),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn ip6tnl_and_xfrm_roundtrip_and_validate() {
        use crate::netlink::link::Ip6tnlMode;
        use std::net::Ipv6Addr;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link("t61", |l| {
                l.ip6tnl()
                    .ip6tnl_local(Ipv6Addr::LOCALHOST)
                    .ip6tnl_remote("fd00::2".parse().unwrap())
                    .ip6tnl_hoplimit(64)
                    .ip6tnl_encap_limit(4)
                    .ip6tnl_mode(Ip6tnlMode::Ipip6)
                    .tunnel_underlay_dev("d0")
            })
            .link("xf1", |l| l.xfrm(7).tunnel_underlay_dev("d0"));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""ip6tnl":{"local":"::1","remote":"fd00::2","hoplimit":64,"encap-limit":4,"mode":"ipip6","underlay-dev":"d0"}"#,
            r#""xfrm":{"if_id":7,"underlay_dev":"d0"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (NetworkConfig::new().link("t61", |l| l.ip6tnl()), "fallback ip6tnl0's"),
            (
                NetworkConfig::new().link("ip6tnl0", |l| l.ip6tnl().ip6tnl_remote(Ipv6Addr::LOCALHOST)),
                "the kernel's fallback ip6tnl device",
            ),
            (NetworkConfig::new().link("d0", |l| l.dummy().ip6tnl_hoplimit(1)), "ip6tnl_hoplimit"),
            (NetworkConfig::new().link("xf1", |l| l.xfrm(0)), "if_id is not 0"),
            (
                NetworkConfig::new().link("xf1", |l| l.xfrm(3)).link("xf2", |l| l.xfrm(3)),
                "xfrm if_id 3 is also xf2's",
            ),
            (
                NetworkConfig::new().link("xf1", |l| l.xfrm(3).address([2, 0, 0, 0, 0, 1])),
                "an L3 tunnel has no hardware address",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn tunnels_roundtrip_and_validate() {
        use std::net::Ipv4Addr;
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link("gr1", |l| {
                l.gre()
                    .tunnel_local(Ipv4Addr::new(10, 0, 0, 1))
                    .tunnel_remote(Ipv4Addr::new(10, 0, 0, 2))
                    .tunnel_ttl(64)
                    .tunnel_key(7)
                    .tunnel_underlay_dev("d0")
            })
            .link("st1", |l| l.sit().tunnel_remote(Ipv4Addr::new(10, 0, 1, 2)));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""gre":{"local":"10.0.0.1","remote":"10.0.0.2","ttl":64,"key":7,"underlay-dev":"d0"}"#,
            r#""sit":{"remote":"10.0.1.2"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (NetworkConfig::new().link("ip1", |l| l.ipip().tunnel_key(1)), "tunnel_key"),
            (NetworkConfig::new().link("vt1", |l| l.vti().tunnel_ttl(1)), "tunnel_ttl"),
            (NetworkConfig::new().link("d0", |l| l.dummy().tunnel_remote(Ipv4Addr::LOCALHOST)), "tunnel_remote"),
            (
                NetworkConfig::new().link("gr1", |l| l.gre().address([2, 0, 0, 0, 0, 1])),
                "an L3 tunnel has no hardware address",
            ),
            (NetworkConfig::new().link("gre0", |l| l.gre()), "the kernel's fallback gre device"),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn ipvlan_and_macvtap_roundtrip_and_validate() {
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link("iv0", |l| {
                l.ipvlan("d0")
                    .ipvlan_mode(IpvlanMode::L3s)
                    .ipvlan_isolation(IpvlanIsolation::Private)
            })
            .link("mt0", |l| l.macvtap("d0").macvtap_mode(MacvlanMode::Vepa));
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""ipvlan":{"parent":"d0","mode":"l3s","isolation":"private"}"#,
            r#""macvtap":{"parent":"d0","mode":"vepa"}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (
                NetworkConfig::new().link("iv0", |l| l.ipvlan("d0").address([2, 0, 0, 0, 0, 1])),
                "an ipvlan link shares its parent's",
            ),
            (
                NetworkConfig::new().link("m0", |l| l.macvlan("d0").ipvlan_mode(IpvlanMode::L3)),
                "ipvlan_mode",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
    }

    #[test]
    fn bridge_and_port_options_roundtrip_and_validate() {
        use std::time::Duration;
        let cfg = NetworkConfig::new()
            .link("br0", |l| {
                l.bridge().bridge_options(|b| {
                    b.vlan_filtering(true)
                        .vlan_default_pvid(10)
                        .stp(true)
                        .ageing_time(Duration::from_secs(100))
                })
            })
            .link("d0", |l| {
                l.dummy()
                    .master("br0")
                    .port_options(|p| p.learning(false).isolated(true).cost(50).pvid(10).vlan(20))
            });
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""link-type":"bridge""#,
            r#""bridge":{"vlan-filtering":true,"vlan-default-pvid":10,"stp":true,"ageing-time":"100s"}"#,
            r#""port":{"learning":false,"isolated":true,"cost":50,"vlans":[{"vid":10,"pvid":true,"untagged":true},{"vid":20}]}"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        for (cfg, says) in [
            (
                NetworkConfig::new().link("d0", |l| l.dummy().bridge_options(|b| b.stp(true))),
                "not a bridge",
            ),
            (
                NetworkConfig::new().link("d0", |l| l.dummy().port_options(|p| p.learning(false))),
                "port options without a master",
            ),
            (
                NetworkConfig::new()
                    .link("bond0", |l| l.bond())
                    .link("d0", |l| l.dummy().master("bond0").port_options(|p| p.learning(false))),
                "its master bond0 is not a bridge",
            ),
            (
                NetworkConfig::new()
                    .link("br0", |l| l.bridge())
                    .link("d0", |l| l.dummy().master("br0").port_options(|p| p.vlan(4095))),
                "port vlan 4095",
            ),
            (
                NetworkConfig::new()
                    .link("br0", |l| l.bridge())
                    .link("d0", |l| l.dummy().master("br0").port_options(|p| p.pvid(10).pvid(20))),
                "a port has one PVID",
            ),
        ] {
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(says), "{says}: {err}");
        }
        let doc = r#"{"links":[{"name":"br0","link-type":"bridge","bridge":{"stp-on":true}}]}"#;
        let err = NetworkConfig::from_json_str(doc).unwrap_err().to_string();
        assert!(err.contains("stp-on"), "{err}");
    }

    #[test]
    fn devconf_roundtrips_and_validates() {
        use crate::netlink::devconf::{AddrGenMode, Ipv4Devconf};
        let cfg = NetworkConfig::new().link("v0", |l| {
            l.veth("v1")
                .ipv4_conf(Ipv4Devconf::RpFilter, 2)
                .ipv4_conf(Ipv4Devconf::NoPolicy, 1)
                .ipv6_conf(crate::netlink::devconf::Ipv6Devconf::AcceptDad, 0)
                .ipv6_conf(crate::netlink::devconf::Ipv6Devconf::KeepAddrOnDown, -1)
                .addr_gen_mode(AddrGenMode::StablePrivacy)
                .ipv6_token("::1:2".parse().unwrap())
        });
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""ipv4-conf":{"disable_policy":1,"rp_filter":2}"#,
            r#""ipv6-conf":{"accept_dad":0,"keep_addr_on_down":-1}"#,
            r#""addr-gen-mode":"stable_secret""#,
            r#""ipv6-token":"::1:2""#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        let err = NetworkConfig::new()
            .link("v0", |l| l.ipv6_token("2001:db8::1".parse().unwrap()))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("upper 64 bits zero"), "{err}");
        for (doc, says) in [
            (
                r#"{"links":[{"name":"v0","link-type":"physical","ipv4-conf":{"rp_filtre":1}}]}"#,
                "no IPv4 device setting is called \"rp_filtre\"",
            ),
            (
                r#"{"links":[{"name":"v0","link-type":"physical","addr-gen-mode":"eui48"}]}"#,
                "unknown addrgenmode",
            ),
            (
                r#"{"links":[{"name":"v0","link-type":"physical","ipv6-conf":{"stable_secret":1}}]}"#,
                "no IPv6 device setting nlink manages",
            ),
        ] {
            let err = NetworkConfig::from_json_str(doc).unwrap_err().to_string();
            assert!(err.contains(says), "{doc}: {err}");
        }
    }

    #[test]
    fn route_attributes_roundtrip_and_validate() {
        use crate::netlink::types::route::RouteScope;
        let cfg = NetworkConfig::new()
            .route("10.81.0.0/16", |r| {
                r.via("10.80.0.2")
                    .dev("d0")
                    .src("10.80.0.1")
                    .onlink()
                    .scope(RouteScope::Universe)
                    .mtu(1400)
                    .advmss(1300)
            })
            .unwrap()
            .route("fd81::/64", |r| r.via("fd80::2").hoplimit(10).initrwnd(20))
            .unwrap();
        cfg.validate().unwrap();
        assert_roundtrips(&cfg);
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""src":"10.80.0.1""#,
            r#""scope":"global""#,
            r#""onlink":true"#,
            r#""mtu":1400"#,
            r#""hoplimit":10"#,
        ] {
            assert!(json.contains(want), "{want} missing: {json}");
        }
        assert_eq!(cfg.routes()[0].metrics().and_then(|m| m.advmss), Some(1300));

        // A source of the other family, at the builder and in a document.
        assert!(NetworkConfig::new().route("10.0.0.0/8", |r| r.src("fd00::1")).is_err());
        let err = NetworkConfig::new()
            .route("10.0.0.0/8", |r| r.via("10.1.0.1").onlink())
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("onlink needs a device"), "{err}");
        for (doc, says) in [
            (r#"{"routes":[{"destination":"10.0.0.0/8","src":"fd00::1"}]}"#, "src"),
            (r#"{"routes":[{"destination":"10.0.0.0/8","scope":"galaxy"}]}"#, "scope"),
        ] {
            let err = NetworkConfig::from_json_str(doc).unwrap_err().to_string();
            assert!(err.contains(says), "{doc}: {err}");
        }
    }

    #[test]
    fn address_rejects_out_of_range_prefix() {
        // /99 is invalid for IPv4 — the try_from must surface it as a
        // deserialize error rather than silently accepting it.
        let err = NetworkConfig::from_json_str(
            r#"{"addresses":[{"dev":"eth0","address":"10.0.0.1/99"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
    }

    #[test]
    fn route_default_keyword_roundtrips() {
        let cfg = NetworkConfig::new()
            .route("0.0.0.0/0", |r| r.via("192.0.2.1"))
            .unwrap();
        let json = cfg.to_json_string().unwrap();
        // A 0.0.0.0/0 destination renders as the `default` keyword.
        assert!(json.contains(r#""destination":"default""#), "{json}");
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert!(back.routes()[0].destination().is_unspecified());
        assert_eq!(back.routes()[0].prefix_len(), 0);
    }

    #[test]
    fn route_default_infers_v6_from_gateway() {
        let back = NetworkConfig::from_json_str(
            r#"{"routes":[{"destination":"default","gateway":"2001:db8::1"}]}"#,
        )
        .unwrap();
        assert!(back.routes()[0].destination().is_ipv6());
    }

    #[test]
    fn route_rejects_bad_gateway() {
        let err = NetworkConfig::from_json_str(
            r#"{"routes":[{"destination":"10.0.0.0/8","gateway":"not-an-ip"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("gateway"), "{err}");
    }

    #[test]
    fn mac_roundtrips_as_colon_string() {
        let cfg = NetworkConfig::new()
            .link("dummy0", |l| l.dummy().address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""address":"aa:bb:cc:dd:ee:ff""#), "{json}");
        assert_roundtrips(&cfg);
    }

    #[test]
    fn mac_rejects_malformed_string() {
        let err = NetworkConfig::from_json_str(
            r#"{"links":[{"name":"d0","link-type":"dummy","address":"aa:bb:cc"}]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("MAC"), "{err}");
    }

    #[test]
    fn empty_config_omits_empty_sections() {
        let json = NetworkConfig::new().to_json_string().unwrap();
        assert_eq!(json, "{}");
        // And an empty document deserializes back to an empty config.
        let back = NetworkConfig::from_json_str("{}").unwrap();
        assert!(back.links().is_empty() && back.addresses().is_empty());
    }

    #[test]
    fn documented_json_example_parses() {
        // Pins the exact JSON shown in docs/library.md "Declarative
        // Network Configuration" so the docs can't drift from the
        // Deserialize impl (veth is externally-tagged, address/route
        // are CIDR strings, the bridge is a bare-string unit variant).
        let cfg = NetworkConfig::from_json_str(
            r#"{
                "links": [
                    { "name": "br0", "link-type": "bridge", "state": "up" },
                    { "name": "veth0", "link-type": { "veth": { "peer": "veth1" } } }
                ],
                "addresses": [ { "dev": "br0", "address": "10.0.0.1/24" } ],
                "routes":    [ { "destination": "10.1.0.0/16", "gateway": "10.0.0.254", "dev": "br0" } ]
            }"#,
        )
        .expect("documented JSON must parse");
        assert_eq!(cfg.links().len(), 2);
        assert_eq!(cfg.addresses().len(), 1);
        assert_eq!(cfg.routes().len(), 1);
        assert_eq!(cfg.links()[1].name(), "veth0");
    }

    /// #476: a JSON route whose gateway is of the other family is a
    /// validation error, as from the builder; and a bond's hash policy is
    /// typed, named in JSON.
    #[test]
    fn json_gateways_and_hash_policies_are_checked() {
        // `from_json_str` validates, so it is refused at parse time.
        let err = NetworkConfig::from_json_str(
            r#"{ "routes": [ { "destination": "fd00:1::/64", "gateway": "10.0.0.1" } ] }"#,
        )
        .expect_err("v4 gateway for a v6 route");
        assert!(
            err.to_string().contains("an IPv6 route takes an IPv6 gateway"),
            "{err}"
        );
        // RFC 5549: an IPv4 route via an IPv6 gateway (#516).
        NetworkConfig::from_json_str(
            r#"{ "routes": [ { "destination": "10.1.0.0/16", "gateway": "fd00::1", "dev": "eth0" } ] }"#,
        )
        .expect("v6 gateway for a v4 route");

        let bond = NetworkConfig::new().link("bond0", |l| {
            l.bond().xmit_hash_policy(BondXmitHashPolicy::Layer34)
        });
        let json = bond.to_json_string().unwrap();
        assert!(json.contains(r#""xmit_hash_policy":"layer34""#), "{json}");
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.to_json_string().unwrap(), json);
        assert!(
            NetworkConfig::from_json_str(&json.replace("layer34", "layer99")).is_err(),
            "an unknown policy does not parse"
        );
    }

    /// A link that does not mention `state` is left as it is — what the
    /// builder does — not taken down. Declaring a physical NIC's MTU in
    /// JSON used to take the NIC down.
    #[test]
    fn a_link_without_a_state_is_left_alone() {
        let cfg = NetworkConfig::from_json_str(
            r#"{"links":[{"name":"eth0","link-type":"physical","mtu":9000}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.links()[0].state(), LinkState::Unchanged);
        let built = NetworkConfig::new().link("eth0", |l| l.mtu(9000));
        assert_eq!(built.links()[0].state(), cfg.links()[0].state());
    }

    #[test]
    fn unit_link_type_keeps_bare_string_shape() {
        // Plan 189 shape: a unit link-type serializes as the bare
        // string "dummy", not {"dummy": null}.
        let cfg = NetworkConfig::new().link("d0", |l| l.dummy());
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""link-type":"dummy""#), "{json}");
    }
}

/// Serde adapter for an optional prefix — `10.0.0.0/8` — as
/// [`DeclaredRule::from`] has one.
#[cfg(feature = "serde")]
mod cidr_serde {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &Option<(IpAddr, u8)>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some((addr, len)) => s.serialize_some(&format!("{addr}/{len}")),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<(IpAddr, u8)>, D::Error> {
        let Some(text) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let (addr, len) = text
            .split_once('/')
            .ok_or_else(|| serde::de::Error::custom(format!("`{text}` is not a prefix: no `/len`")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("`{addr}` is not an address")))?;
        let len: u8 = len
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("`{len}` is not a prefix length")))?;
        let max = if addr.is_ipv6() { 128 } else { 32 };
        if len > max {
            return Err(serde::de::Error::custom(format!("{text}: the prefix is at most {max} bits")));
        }
        Ok(Some((addr, len)))
    }
}

/// Serde adapter for a required MAC — `aa:bb:cc:dd:ee:ff` — as
/// [`DeclaredFdb::mac`] has one.
#[cfg(feature = "serde")]
mod mac_str_serde {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(mac: &[u8; 6], s: S) -> Result<S::Ok, S::Error> {
        super::mac_serde::serialize(&Some(*mac), s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 6], D::Error> {
        super::mac_serde::deserialize(d)?
            .ok_or_else(|| serde::de::Error::custom("a MAC is required"))
    }
}

/// Serde adapter for [`DeclaredLink::address`] — represents the
/// `Option<[u8; 6]>` hardware address as a canonical
/// `aa:bb:cc:dd:ee:ff` string (or absent) rather than a raw byte
/// array, and validates the string form on the way back in.
#[cfg(feature = "serde")]
mod mac_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(mac: &Option<[u8; 6]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match mac {
            Some(m) => s.serialize_some(&format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(d: D) -> Result<Option<[u8; 6]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => parse_mac(&s).map(Some).map_err(serde::de::Error::custom),
        }
    }

    fn parse_mac(s: &str) -> Result<[u8; 6], String> {
        let mut out = [0u8; 6];
        let mut n = 0;
        for (i, part) in s.split(':').enumerate() {
            if i >= 6 {
                return Err(format!(
                    "invalid MAC `{s}`: expected 6 colon-separated octets"
                ));
            }
            out[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("invalid MAC `{s}`: octet `{part}` is not hex"))?;
            n = i + 1;
        }
        if n != 6 {
            return Err(format!(
                "invalid MAC `{s}`: expected 6 colon-separated octets, got {n}"
            ));
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "schemars"))]
pub(super) mod schemars_tests {
    use super::*;

    fn schema_value() -> serde_json::Value {
        serde_json::from_str(&NetworkConfig::json_schema()).expect("schema is valid JSON")
    }

    /// Draft-07 puts subschemas under `definitions`; 2020-12 uses
    /// `$defs`. `json_schema_value` pins draft-07, but accept either
    /// so these tests assert about content rather than dialect.
    fn defs(schema: &serde_json::Value) -> &serde_json::Map<String, serde_json::Value> {
        schema
            .get("definitions")
            .or_else(|| schema.get("$defs"))
            .and_then(|d| d.as_object())
            .expect("schema exposes a definitions/$defs map")
    }

    /// The dialect is part of the promise: editors (`json.schemas`,
    /// `yaml.schemas`) and CI validators are configured against a
    /// specific draft, and a silent switch invalidates them.
    ///
    /// It is also not something the library holds still — schemars
    /// 0.8 defaulted to draft 7 and 1.0 to 2020-12, so `json_schema`
    /// pins it rather than inheriting it. Nothing asserted this
    /// before, which is exactly how the default could have moved
    /// under the crate during a dependency bump without a test going
    /// red.
    #[test]
    fn schema_declares_draft_07() {
        let s = schema_value();
        assert_eq!(
            s.get("$schema").and_then(|v| v.as_str()),
            Some("http://json-schema.org/draft-07/schema#"),
            "json_schema must emit draft-07, as its docs and CLAUDE.md state"
        );
        // Draft-07 spells the subschema map `definitions`; 2020-12
        // uses `$defs`. Pinned together so the pair cannot drift.
        assert!(
            s.get("definitions").is_some(),
            "draft-07 output should carry `definitions`"
        );
    }

    #[test]
    fn schema_generates_and_titles_the_config_root() {
        let s = schema_value();
        assert_eq!(
            s.get("title").and_then(|t| t.as_str()),
            Some("NetworkConfig"),
            "root schema title should be the type name"
        );
        let d = defs(&s);
        for t in ["DeclaredLink", "DeclaredLinkType", "QdiscSpec"] {
            assert!(
                d.contains_key(t),
                "schema missing definition for {t}; has {:?}",
                d.keys().collect::<Vec<_>>()
            );
        }
        // The Repr shadow types must appear — proof the manual
        // `JsonSchema` delegation to `*Repr` took effect (addresses /
        // routes describe the string wire shape, not parsed fields).
        assert!(d.contains_key("AddressRepr"), "schema must route addresses through AddressRepr");
        assert!(d.contains_key("RouteRepr"), "schema must route routes through RouteRepr");
        // And the parsed structs must NOT leak into the schema.
        assert!(!d.contains_key("DeclaredAddress"), "DeclaredAddress parsed fields must not appear");
        assert!(!d.contains_key("DeclaredRoute"), "DeclaredRoute parsed fields must not appear");
    }

    #[test]
    fn address_and_route_describe_cidr_strings_not_parsed_fields() {
        // The correctness guard: DeclaredAddress / DeclaredRoute
        // serialize THROUGH their `*Repr` (a CIDR string), so the
        // schema must say "string", not expose the in-memory
        // `{ address: <ip>, prefix_len: <u8> }` fields. A schema that
        // didn't match the real JSON would be worse than none.
        let s = schema_value();
        let d = defs(&s);
        assert_eq!(
            d["AddressRepr"].pointer("/properties/address/type").and_then(|v| v.as_str()),
            Some("string"),
            "AddressRepr.address must be a (CIDR) string"
        );
        assert_eq!(
            d["RouteRepr"].pointer("/properties/destination/type").and_then(|v| v.as_str()),
            Some("string"),
            "RouteRepr.destination must be a (CIDR/default) string"
        );
    }

    #[test]
    fn mac_field_is_a_string_not_a_byte_array() {
        // DeclaredLink.address is Option<[u8; 6]> but `mac_serde`
        // renders it as the `aa:bb:..` string. The schema must agree.
        let s = schema_value();
        let d = defs(&s);
        let mac = d["DeclaredLink"]
            .pointer("/properties/address")
            .expect("DeclaredLink.address present in schema");
        let rendered = serde_json::to_string(mac).unwrap();
        assert!(rendered.contains("string"), "MAC must be string-typed: {rendered}");
        assert!(
            !rendered.contains("integer") && !rendered.contains("\"array\""),
            "MAC must NOT be modelled as a byte array: {rendered}"
        );
    }

    /// A config that declares something in every section, with the kinds
    /// whose JSON a custom serializer writes: MACs, CIDRs, durations, rates,
    /// handles and route protocols.
    pub(crate) fn every_section() -> NetworkConfig {
        use crate::netlink::filter::FlowerFilter;
        use crate::netlink::link::VlanProtocol;
        use crate::netlink::tc::{FqCodelConfig, HtbClassConfig};
        use crate::netlink::types::route::RouteProtocol;
        use crate::util::{Percent, Rate};
        use crate::{EthProto, FilterPriority, TcHandle};

        NetworkConfig::new()
            .owner("schema-test")
            .vrf_strict_mode(true)
            .route_protocol(RouteProtocol::Static)
            .link("br0", |l| {
                l.bridge()
                    .bridge_options(|b| b.vlan_filtering(true).hello_time(Duration::from_secs(2)))
                    .up()
                    .mtu(1500)
            })
            .link("d0", |l| {
                l.dummy()
                    .address([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33])
                    .master("br0")
                    .port_options(|p| p.vlan(10).pvid(20).untagged(30))
            })
            .link("d0.42", |l| {
                l.vlan("d0", 42).vlan_protocol(VlanProtocol::Dot1ad)
            })
            .link("ve0", |l| {
                l.veth("ve1")
                    .veth_peer_netns(crate::netlink::namespace::NetnsRef::Named("peer".into()))
                    .veth_peer_mtu(1400)
            })
            .link("vx0", |l| {
                l.vxlan(100)
                    .vxlan_remote("10.0.0.2".parse().unwrap())
                    .vxlan_port(4789)
            })
            .address("br0", "10.0.0.1/24")
            .unwrap()
            .address("br0", "2001:db8::1/64")
            .unwrap()
            .route("0.0.0.0/0", |r| r.via("10.0.0.254"))
            .unwrap()
            .route("10.10.0.0/16", |r| r.blackhole().metric(100))
            .unwrap()
            .neighbour(
                "br0",
                "10.0.0.9".parse::<IpAddr>().unwrap(),
                [0x02, 0, 0, 0, 0, 9],
            )
            .proxy_neighbour("br0", "10.0.0.10".parse::<IpAddr>().unwrap())
            .fdb("d0", [0x02, 0, 0, 0, 0, 1], |e| e.vlan(10))
            .fdb("vx0", [0; 6], |e| e.dst("192.0.2.1".parse().unwrap()))
            .nexthop(1, |n| n.via("10.0.0.2".parse().unwrap()).dev("br0"))
            .nexthop(2, |n| n.via("10.0.0.3".parse().unwrap()).dev("br0"))
            .nexthop(10, |n| n.group(&[(1, 1), (2, 3)]))
            .rule(100, |r| {
                r.from("10.0.0.0".parse::<IpAddr>().unwrap(), 8).table(100)
            })
            .qdisc("ve0", |q| {
                q.netem()
                    .delay(Duration::from_micros(1_500))
                    .rate(Rate::mbit(100))
                    .loss_pct(Percent::new(1.0))
            })
            .qdisc("d0", |q| q.htb().default_class(0x20))
            .tc("d0", |t| {
                t.class(
                    TcHandle::major_only(1),
                    TcHandle::new(1, 1),
                    HtbClassConfig::new(Rate::mbit(100)),
                )
                .class(
                    TcHandle::new(1, 1),
                    TcHandle::new(1, 0x20),
                    HtbClassConfig::new(Rate::mbit(40)),
                )
                .leaf(
                    TcHandle::new(1, 0x20),
                    TcHandle::major_only(0x20),
                    FqCodelConfig::new(),
                )
                .filter(
                    TcHandle::major_only(1),
                    FilterPriority::new(1),
                    EthProto::IP,
                    FlowerFilter::new()
                        .ip_proto_tcp()
                        .dst_port(22)
                        .classid(TcHandle::new(1, 0x20)),
                )
            })
    }

    /// #876 — a config's JSON validates against the schema it publishes,
    /// with every section in it. The schema was only ever checked by
    /// reading pieces of it.
    #[test]
    fn config_json_matches_its_schema() {
        use crate::netlink::config::schema_check;
        let cfg = every_section();
        cfg.validate().expect("the test config is valid");
        schema_check::assert_every_root_property_populated(
            &cfg,
            NetworkConfig::json_schema_value(),
        );
        schema_check::assert_matches_schema(&cfg, NetworkConfig::json_schema_value());
    }

    #[test]
    fn schema_value_helper_matches_string_helper() {
        let from_value = serde_json::to_value(NetworkConfig::json_schema_value()).unwrap();
        let from_string = schema_value();
        assert_eq!(from_value, from_string, "the two json_schema accessors must agree");
    }
}

#[cfg(test)]
mod master_and_validate_tests {
    //! #462 — `MasterSpec`, the `link` upsert and `validate`.
    use super::*;

    /// Declaring a link twice updates the first declaration; a link that
    /// never mentions a master leaves it unmanaged.
    #[test]
    fn link_is_an_upsert_and_master_defaults_to_unmanaged() {
        let cfg = NetworkConfig::new()
            .link("v10", |l| l.vlan("eth0", 10))
            .link("eth0", |l| l.mtu(9000))
            .link("v10", |l| l.master("red"));
        assert_eq!(cfg.links.len(), 2);
        assert!(matches!(
            cfg.links[0].link_type,
            DeclaredLinkType::Vlan { .. }
        ));
        assert_eq!(cfg.links[0].master, MasterSpec::Name("red".into()));
        assert_eq!(cfg.links[1].master, MasterSpec::Unmanaged);
        let released = NetworkConfig::new().link("eth0", |l| l.nomaster());
        assert_eq!(released.links[0].master, MasterSpec::None);
    }

    /// Duplicate routes and qdiscs are refused; the builder cannot
    /// produce a duplicate link, JSON can.
    #[test]
    fn validate_refuses_duplicates() {
        let cfg = NetworkConfig::new()
            .route("10.0.0.0/8", |r| r.dev("eth0"))
            .unwrap()
            .route("10.0.0.0/8", |r| r.dev("eth1"))
            .unwrap()
            .qdisc("eth0", |q| q.fq_codel())
            .qdisc("eth0", |q| q.sfq());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("routes.10.0.0.0/8"), "{err}");
        assert!(err.contains("qdiscs.eth0"), "{err}");
        let distinct = NetworkConfig::new()
            .route("10.0.0.0/8", |r| r.dev("eth0").metric(100))
            .unwrap()
            .route("10.0.0.0/8", |r| r.dev("eth1").metric(200))
            .unwrap();
        distinct.validate().unwrap();
    }

    /// What the kernel refuses late is refused by `validate()` first:
    /// interface names `dev_valid_name` rejects (link and peer), VLAN ids
    /// past 4094, and netem percentages that are not a number in 0..=100,
    /// which a JSON or YAML document can carry (#598).
    #[test]
    fn validate_refuses_what_the_kernel_would() {
        for name in ["", ".", "..", "a/b", "a b", "a:b", "à0", "sixteen-bytes-xx"] {
            let err = NetworkConfig::new()
                .link(name, |l| l.dummy())
                .validate()
                .expect_err(name)
                .to_string();
            assert!(err.contains("links."), "{name:?}: {err}");
        }
        let err = NetworkConfig::new()
            .link("v0", |l| l.veth("a:b"))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("peer"), "{err}");

        NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link("v4094", |l| l.vlan("d0", 4094))
            .validate()
            .unwrap();
        let err = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link("v4095", |l| l.vlan("d0", 4095))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("4095"), "{err}");

        // A netem percentage is a `Percent`, clamped where it is set and
        // refused outside 0..=100 where a document is read (#515), so no
        // declared qdisc carries one out of range any more.
    }

    /// What the apply would fail on, or never converge on, is refused by
    /// `validate()` before anything changes (#518).
    #[test]
    fn validate_catches_what_the_apply_would_fail_on() {
        let refused = |cfg: NetworkConfig, what: &str| {
            let err = cfg.validate().expect_err(what).to_string();
            assert!(err.contains(what), "{what}: {err}");
        };
        refused(
            NetworkConfig::new().link("d0", |l| l.dummy().miimon(100)),
            "bond parameter",
        );
        refused(
            NetworkConfig::new().link("vx0", |l| l.vxlan(1 << 24)),
            "24 bits",
        );
        refused(
            NetworkConfig::new()
                .route("10.0.0.1/24", |r| r.dev("d0"))
                .unwrap(),
            "host bits",
        );
        refused(
            NetworkConfig::new()
                .route("10.0.0.0/24", |r| r.dev("d0").table(0))
                .unwrap(),
            "table 0",
        );
        refused(
            NetworkConfig::new()
                .link("a", |l| l.bridge().master("b"))
                .link("b", |l| l.bridge().master("a")),
            "cycle",
        );
        refused(
            NetworkConfig::new().link("o0", |l| l.ovpn().address([2, 0, 0, 0, 0, 1])),
            "hardware address",
        );
        refused(
            NetworkConfig::new()
                .link("d0", |l| l.dummy().down())
                .link("d0.10", |l| l.vlan("d0", 10).up()),
            "declared down",
        );

        // IPv6 masks host bits itself, and a VNI just under 2^24 fits.
        NetworkConfig::new()
            .route("2001:db8::1/64", |r| r.dev("d0"))
            .unwrap()
            .link("vx0", |l| l.vxlan((1 << 24) - 1))
            .validate()
            .unwrap();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_master_absent_null_and_named() {
        let cfg = NetworkConfig::from_json_str(
            r#"{"links": [
                {"name": "a", "link-type": "physical"},
                {"name": "b", "link-type": "physical", "master": null},
                {"name": "c", "link-type": "physical", "master": "br0"}
            ]}"#,
        )
        .unwrap();
        let specs: Vec<MasterSpec> = cfg.links.iter().map(|l| l.master.clone()).collect();
        assert_eq!(
            specs,
            [
                MasterSpec::Unmanaged,
                MasterSpec::None,
                MasterSpec::Name("br0".into())
            ]
        );
        let back = NetworkConfig::from_json_str(&cfg.to_json_string().unwrap()).unwrap();
        let again: Vec<MasterSpec> = back.links.iter().map(|l| l.master.clone()).collect();
        assert_eq!(again, specs);
        let dup = NetworkConfig::from_json_str(
            r#"{"links": [{"name": "a", "link-type": "physical"},
                          {"name": "a", "link-type": "physical"}]}"#,
        );
        assert!(dup.unwrap_err().to_string().contains("links.a"));
    }
}
