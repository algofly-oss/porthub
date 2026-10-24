//! Name resolution utilities for protocols, scopes, tables, etc.

/// Get the name of a routing protocol.
pub fn protocol_name(id: u8) -> &'static str {
    match id {
        0 => "unspec",
        1 => "redirect",
        2 => "kernel",
        3 => "boot",
        4 => "static",
        8 => "gated",
        9 => "ra",
        10 => "mrt",
        11 => "zebra",
        12 => "bird",
        13 => "dnrouted",
        14 => "xorp",
        15 => "ntk",
        16 => "dhcp",
        17 => "mrouted",
        18 => "keepalived",
        42 => "babel",
        186 => "bgp",
        187 => "isis",
        188 => "ospf",
        189 => "rip",
        192 => "eigrp",
        _ => "unknown",
    }
}

/// Get protocol ID from name.
pub fn protocol_id(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "unspec" => Some(0),
        "redirect" => Some(1),
        "kernel" => Some(2),
        "boot" => Some(3),
        "static" => Some(4),
        "gated" => Some(8),
        "ra" => Some(9),
        "mrt" => Some(10),
        "zebra" => Some(11),
        "bird" => Some(12),
        "dnrouted" => Some(13),
        "xorp" => Some(14),
        "ntk" => Some(15),
        "dhcp" => Some(16),
        "mrouted" => Some(17),
        "keepalived" => Some(18),
        "babel" => Some(42),
        "bgp" => Some(186),
        "isis" => Some(187),
        "ospf" => Some(188),
        "rip" => Some(189),
        "eigrp" => Some(192),
        _ => name.parse().ok(),
    }
}

/// Get the name of a route scope.
pub fn scope_name(id: u8) -> &'static str {
    match id {
        0 => "global",
        200 => "site",
        253 => "link",
        254 => "host",
        255 => "nowhere",
        _ => "unknown",
    }
}

/// Get scope ID from name.
pub fn scope_id(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "global" | "universe" => Some(0),
        "site" => Some(200),
        "link" => Some(253),
        "host" => Some(254),
        "nowhere" => Some(255),
        _ => name.parse().ok(),
    }
}

/// Get the name of a routing table.
pub fn table_name(id: u32) -> String {
    match id {
        0 => "unspec".to_string(),
        252 => "compat".to_string(),
        253 => "default".to_string(),
        254 => "main".to_string(),
        255 => "local".to_string(),
        _ => id.to_string(),
    }
}

/// Get table ID from name.
pub fn table_id(name: &str) -> Option<u32> {
    match name.to_lowercase().as_str() {
        "unspec" => Some(0),
        "compat" => Some(252),
        "default" => Some(253),
        "main" => Some(254),
        "local" => Some(255),
        _ => name.parse().ok(),
    }
}

/// Get the name of a route type.
pub fn route_type_name(id: u8) -> &'static str {
    match id {
        0 => "unspec",
        1 => "unicast",
        2 => "local",
        3 => "broadcast",
        4 => "anycast",
        5 => "multicast",
        6 => "blackhole",
        7 => "unreachable",
        8 => "prohibit",
        9 => "throw",
        10 => "nat",
        11 => "xresolve",
        _ => "unknown",
    }
}

/// Get route type ID from name.
pub fn route_type_id(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "unspec" => Some(0),
        "unicast" => Some(1),
        "local" => Some(2),
        "broadcast" => Some(3),
        "anycast" => Some(4),
        "multicast" => Some(5),
        "blackhole" => Some(6),
        "unreachable" => Some(7),
        "prohibit" => Some(8),
        "throw" => Some(9),
        "nat" => Some(10),
        "xresolve" => Some(11),
        _ => name.parse().ok(),
    }
}

/// Get the name of an address family.
pub fn family_name(id: u8) -> &'static str {
    match id {
        0 => "unspec",
        1 => "unix",
        2 => "inet",
        10 => "inet6",
        16 => "netlink",
        17 => "packet",
        28 => "mpls",
        7 => "bridge",
        _ => "unknown",
    }
}

/// Get address family ID from name.
pub fn family_id(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "unspec" => Some(0),
        "unix" => Some(1),
        "inet" | "ipv4" | "4" => Some(2),
        "inet6" | "ipv6" | "6" => Some(10),
        "netlink" => Some(16),
        "packet" => Some(17),
        "mpls" => Some(28),
        "bridge" => Some(7),
        _ => None,
    }
}

/// Get the name of an interface operational state.
pub fn operstate_name(id: u8) -> &'static str {
    match id {
        0 => "UNKNOWN",
        1 => "NOTPRESENT",
        2 => "DOWN",
        3 => "LOWERLAYERDOWN",
        4 => "TESTING",
        5 => "DORMANT",
        6 => "UP",
        _ => "UNKNOWN",
    }
}

/// Format interface flags as a string.
pub fn format_link_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    if flags & 0x1 != 0 {
        parts.push("UP");
    }
    if flags & 0x2 != 0 {
        parts.push("BROADCAST");
    }
    if flags & 0x8 != 0 {
        parts.push("LOOPBACK");
    }
    if flags & 0x10 != 0 {
        parts.push("POINTOPOINT");
    }
    if flags & 0x40 != 0 {
        parts.push("RUNNING");
    }
    if flags & 0x80 != 0 {
        parts.push("NOARP");
    }
    if flags & 0x100 != 0 {
        parts.push("PROMISC");
    }
    if flags & 0x200 != 0 {
        parts.push("ALLMULTI");
    }
    if flags & 0x400 != 0 {
        parts.push("MASTER");
    }
    if flags & 0x800 != 0 {
        parts.push("SLAVE");
    }
    if flags & 0x1000 != 0 {
        parts.push("MULTICAST");
    }
    if flags & 0x10000 != 0 {
        parts.push("LOWER_UP");
    }
    if flags & 0x20000 != 0 {
        parts.push("DORMANT");
    }

    if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join(",")
    }
}
