# nlink Examples

This directory contains examples demonstrating the nlink library's capabilities for Linux network configuration via netlink.

## Directory Structure

```
examples/
├── README.md
├── route/              # Route protocol (RTNetlink) examples
│   ├── addresses.rs
│   ├── error_handling.rs
│   ├── link_create.rs
│   ├── list_interfaces.rs
│   ├── mpls.rs           # MPLS routes and encapsulation
│   ├── namespaces.rs
│   ├── neighbors.rs
│   ├── nexthop.rs        # Nexthop objects and groups
│   ├── routes.rs
│   ├── srv6.rs           # SRv6 segment routing
│   ├── stats.rs
│   └── tc/               # Traffic control examples
│       ├── actions.rs    # TC actions (drop, mirror, police, etc.)
│       ├── chains.rs     # TC filter chains
│       ├── classes.rs    # TC class management (HTB)
│       ├── filters.rs    # TC filters (u32, flower, matchall)
│       ├── htb.rs
│       ├── netem.rs
│       └── stats.rs
├── bridge/             # Bridge management examples
│   ├── fdb.rs            # FDB (forwarding database) management
│   └── vlan.rs           # VLAN filtering
├── config/             # Declarative configuration examples
│   ├── declarative.rs    # Define desired state, compute diff, apply
│   └── round_trip.rs     # Validating JSON round-trip (serde feature)
├── diagnostics/        # Network diagnostics examples
│   ├── bottleneck.rs     # Find network bottlenecks
│   ├── connectivity.rs   # Check connectivity to destination
│   └── scan.rs           # Full diagnostic scan
├── ratelimit/          # Rate limiting examples
│   └── simple.rs         # High-level rate limiting API
├── events/             # Event monitoring examples
│   ├── ip_monitor.rs
│   ├── monitor.rs
│   ├── monitor_namespace.rs
│   ├── multi_source.rs
│   └── tc_monitor.rs
├── namespace/          # Namespace management examples
│   ├── events.rs
│   └── watch.rs
├── genl/               # Generic Netlink examples
│   ├── macsec.rs         # MACsec (IEEE 802.1AE) configuration
│   ├── mptcp.rs          # MPTCP endpoint configuration
│   └── wireguard.rs      # WireGuard configuration
├── sockdiag/           # Socket diagnostics examples
│   ├── list_sockets.rs
│   ├── tcp_connections.rs
│   └── unix_sockets.rs
├── uevent/             # Kernel uevent examples
│   ├── device_monitor.rs
│   └── device_monitor_stream.rs
├── connector/          # Kernel connector examples
│   ├── process_monitor.rs
│   └── process_monitor_stream.rs
├── netfilter/          # Netfilter examples
│   └── conntrack.rs
├── xfrm/               # XFRM (IPsec) examples
│   └── ipsec_monitor.rs
├── fib_lookup/         # FIB lookup examples
│   └── route_lookup.rs
├── audit/              # Linux Audit examples
│   └── audit_status.rs
└── selinux/            # SELinux examples
    ├── selinux_monitor.rs
    └── selinux_monitor_stream.rs
```

## Running Examples

Examples can be run with:

```bash
cargo run -p nlink --example <example_name>
```

Some examples require specific features or root privileges. See the individual example descriptions below.

## Route Protocol Examples

### Basic Network Information

| Example | Description | Command |
|---------|-------------|---------|
| `route_list_interfaces` | List all network interfaces with state, MAC, and MTU | `cargo run -p nlink --example route_list_interfaces` |
| `route_addresses` | List, add, or delete IP addresses | `cargo run -p nlink --example route_addresses` |
| `route_routes` | List routes (optionally filter by IPv4/IPv6) | `cargo run -p nlink --example route_routes` |
| `route_neighbors` | List ARP/NDP neighbor entries | `cargo run -p nlink --example route_neighbors` |
| `route_stats` | Monitor interface statistics in real-time | `cargo run -p nlink --example route_stats` |

### Link Management

| Example | Description | Command |
|---------|-------------|---------|
| `route_link_create` | Create virtual interfaces (dummy, veth, bridge) | `sudo cargo run -p nlink --example route_link_create` |

### Advanced Routing

| Example | Description | Command |
|---------|-------------|---------|
| `route_nexthop` | Nexthop objects and ECMP groups (Linux 5.3+) | `cargo run -p nlink --example route_nexthop` |
| `route_mpls` | MPLS routes and encapsulation | `cargo run -p nlink --example route_mpls` |
| `route_srv6` | SRv6 segment routing and local SIDs | `cargo run -p nlink --example route_srv6` |

### Traffic Control (TC)

| Example | Description | Command |
|---------|-------------|---------|
| `route_tc_netem` | Network emulation (delay, loss, corruption) | `cargo run -p nlink --example route_tc_netem` |
| `route_tc_htb` | HTB qdisc and class inspection | `cargo run -p nlink --example route_tc_htb` |
| `route_tc_stats` | Real-time TC qdisc statistics monitoring | `cargo run -p nlink --example route_tc_stats` |
| `route_tc_classes` | TC class management with typed builders | `cargo run -p nlink --example route_tc_classes` |
| `route_tc_filters` | TC filters (u32, flower, matchall, etc.) | `cargo run -p nlink --example route_tc_filters` |
| `route_tc_chains` | TC filter chains for complex classification | `cargo run -p nlink --example route_tc_chains` |
| `route_tc_actions` | TC actions (drop, mirror, police, NAT, etc.) | `cargo run -p nlink --example route_tc_actions` |

### Namespaces

| Example | Description | Command |
|---------|-------------|---------|
| `route_namespaces` | List namespaces and query interfaces in each | `cargo run -p nlink --example route_namespaces` |

### Error Handling

| Example | Description | Command |
|---------|-------------|---------|
| `route_error_handling` | Demonstrate error handling patterns | `cargo run -p nlink --example route_error_handling` |

## Bridge Examples

| Example | Description | Command |
|---------|-------------|---------|
| `bridge_fdb` | Bridge FDB (forwarding database) management | `cargo run -p nlink --example bridge_fdb` |
| `bridge_vlan` | Bridge VLAN filtering configuration | `cargo run -p nlink --example bridge_vlan` |

## Declarative Configuration Examples

| Example | Description | Command |
|---------|-------------|---------|
| `config_declarative` | Define network state, compute diff, apply changes | `cargo run -p nlink --example config_declarative` |
| `config_round_trip` | Validating `NetworkConfig` JSON round-trip (serde) | `cargo run -p nlink --features serde --example config_round_trip` |

## Rate Limiting Examples

| Example | Description | Command |
|---------|-------------|---------|
| `ratelimit_simple` | High-level rate limiting API (RateLimiter, PerHostLimiter) | `cargo run -p nlink --example ratelimit_simple` |

## Network Diagnostics Examples

| Example | Description | Command |
|---------|-------------|---------|
| `diagnostics_scan` | Full diagnostic scan of all interfaces | `cargo run -p nlink --example diagnostics_scan` |
| `diagnostics_connectivity` | Check connectivity to a destination | `cargo run -p nlink --example diagnostics_connectivity` |
| `diagnostics_bottleneck` | Find network bottlenecks | `cargo run -p nlink --example diagnostics_bottleneck` |

## Event Monitoring Examples

| Example | Description | Command |
|---------|-------------|---------|
| `events_monitor` | Monitor network events (link, address, route changes) | `cargo run -p nlink --example events_monitor` |
| `events_monitor_namespace` | Monitor events in a specific namespace | `cargo run -p nlink --example events_monitor_namespace -- <ns_name>` |
| `events_ip_monitor` | Monitor events like `ip monitor` (links, addresses, routes, neighbors) | `cargo run -p nlink --example events_ip_monitor` |
| `events_tc_monitor` | Monitor TC events like `tc monitor` (qdiscs, classes, filters) | `cargo run -p nlink --example events_tc_monitor` |
| `events_multi_source` | Combine multiple event sources with `tokio::select!` | `sudo cargo run -p nlink --example events_multi_source` |

## Namespace Examples

| Example | Description | Command |
|---------|-------------|---------|
| `namespace_events` | Monitor NSID netlink events | `cargo run -p nlink --example namespace_events` |
| `namespace_watch` | Watch namespace creation/deletion (inotify) | `cargo run -p nlink --features namespace_watcher --example namespace_watch` |

## Generic Netlink Examples

| Example | Description | Command |
|---------|-------------|---------|
| `genl_wireguard` | Query WireGuard device configuration | `cargo run -p nlink --example genl_wireguard` |
| `genl_macsec` | MACsec (IEEE 802.1AE) device configuration | `cargo run -p nlink --example genl_macsec` |
| `genl_mptcp` | MPTCP (Multipath TCP) endpoint configuration | `cargo run -p nlink --example genl_mptcp` |

## Socket Diagnostics Examples

| Example | Description | Command |
|---------|-------------|---------|
| `sockdiag_list_sockets` | List all sockets (TCP, UDP, Unix) | `cargo run -p nlink --features sockdiag --example sockdiag_list_sockets` |
| `sockdiag_tcp_connections` | List TCP connections with state | `cargo run -p nlink --features sockdiag --example sockdiag_tcp_connections` |
| `sockdiag_unix_sockets` | List Unix domain sockets | `cargo run -p nlink --features sockdiag --example sockdiag_unix_sockets` |

## Uevent Examples (Device Hotplug)

| Example | Description | Command |
|---------|-------------|---------|
| `uevent_device_monitor` | Monitor device hotplug events (like udev) | `cargo run -p nlink --example uevent_device_monitor` |
| `uevent_device_monitor_stream` | Same using Stream API with `conn.events()` | `cargo run -p nlink --example uevent_device_monitor_stream` |

## Connector Examples (Process Events)

| Example | Description | Command |
|---------|-------------|---------|
| `connector_process_monitor` | Monitor process fork/exec/exit events | `sudo cargo run -p nlink --example connector_process_monitor` |
| `connector_process_monitor_stream` | Same using Stream API with `conn.events()` | `sudo cargo run -p nlink --example connector_process_monitor_stream` |

## Netfilter Examples (Connection Tracking)

| Example | Description | Command |
|---------|-------------|---------|
| `netfilter_conntrack` | List connection tracking entries | `cargo run -p nlink --example netfilter_conntrack` |

## XFRM Examples (IPsec)

| Example | Description | Command |
|---------|-------------|---------|
| `xfrm_ipsec_monitor` | List IPsec Security Associations and Policies | `cargo run -p nlink --example xfrm_ipsec_monitor` |

## FIB Lookup Examples

| Example | Description | Command |
|---------|-------------|---------|
| `fib_lookup_route_lookup` | Perform FIB route lookups for IP addresses | `cargo run -p nlink --example fib_lookup_route_lookup` |

## Audit Examples (Linux Audit Subsystem)

| Example | Description | Command |
|---------|-------------|---------|
| `audit_status` | Display audit daemon status, TTY auditing, and features | `cargo run -p nlink --example audit_status` |

## SELinux Examples

| Example | Description | Command |
|---------|-------------|---------|
| `selinux_monitor` | Monitor SELinux enforcement mode changes and policy loads | `cargo run -p nlink --example selinux_monitor` |
| `selinux_monitor_stream` | Same using Stream API with `conn.events()` | `cargo run -p nlink --example selinux_monitor_stream` |

## Example Usage Patterns

### Using `get_interface_names()` helper

Build an ifindex-to-name map efficiently:

```rust
let conn = Connection::<Route>::new()?;
let names = conn.get_interface_names().await?;

// Now use names.get(&ifindex) to resolve interface names
let routes = conn.get_routes().await?;
for route in routes {
    let dev = route.oif
        .and_then(|idx| names.get(&idx))
        .map(|s| s.as_str())
        .unwrap_or("-");
    println!("Route via {}", dev);
}
```

### Using `LinkMessage::name_or()` helper

Get interface name with a default value:

```rust
let links = conn.get_links().await?;
for link in links {
    println!("Interface: {}", link.name_or("?"));
}
```

### Using the Stream API with `conn.events()`

Protocols implementing `EventSource` can use the unified Stream API:

```rust
use nlink::netlink::{Connection, KobjectUevent, Connector, SELinux};
use tokio_stream::StreamExt;

// Device hotplug events
let conn = Connection::<KobjectUevent>::new()?;
let mut events = conn.events();  // Borrows connection
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}

// Process events (requires root)
let conn = Connection::<Connector>::new().await?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}

// SELinux events
let conn = Connection::<SELinux>::new()?;
let mut events = conn.events();
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}
```

### Combining multiple event sources

```rust
use nlink::netlink::{Connection, KobjectUevent, Connector};
use std::pin::pin;
use tokio_stream::StreamExt;

let uevent_conn = Connection::<KobjectUevent>::new()?;
let proc_conn = Connection::<Connector>::new().await?;

let mut uevent_events = pin!(uevent_conn.events());
let mut proc_events = pin!(proc_conn.events());

loop {
    tokio::select! {
        Some(result) = uevent_events.next() => {
            println!("[device] {:?}", result?);
        }
        Some(result) = proc_events.next() => {
            println!("[proc] {:?}", result?);
        }
    }
}
```

### Error handling with semantic checks

```rust
use nlink::{ErrorObject, TcHandle};

// Helper methods for common error checks
match conn.del_qdisc("eth0", TcHandle::ROOT).await {
    Ok(()) => println!("Deleted"),
    Err(e) if e.is_not_found() => println!("Nothing to delete"),
    Err(e) if e.is_permission_denied() => println!("Need root"),
    Err(e) => return Err(e),
}

// What was not found, from `Error::object()` (promoted from kernel ENOENT)
match conn.change_qdisc("eth0", TcHandle::ROOT, netem.clone()).await {
    Ok(()) => {}
    Err(e) if matches!(e.object(), Some(ErrorObject::Link { .. })) => eprintln!("Interface gone"),
    Err(e) if e.is_not_found() => conn.add_qdisc("eth0", netem).await?,
    Err(e) => return Err(e),
}

// Errors include operation context automatically
// "add_link(veth0, kind=veth): File exists (errno 17)"
```

### Declarative configuration

```rust
use nlink::netlink::config::{NetworkConfig, LinkConfig, LinkType, AddressConfig};

let config = NetworkConfig::new()
    .link(LinkConfig::new("dummy0").link_type(LinkType::Dummy).up())
    .address(AddressConfig::new("dummy0", "10.0.0.1/24"));

// Compute diff and apply
let diff = config.diff(&conn).await?;
if !diff.is_empty() {
    config.apply(&conn).await?;
}
```

### Rate limiting

```rust
use nlink::Rate;
use nlink::netlink::ratelimit::RateLimiter;

let limiter = RateLimiter::new("eth0")
    .egress(Rate::mbit(100))
    .ingress(Rate::mbit(50));
limiter.apply(&conn).await?;
```

### Network diagnostics

```rust
use nlink::netlink::diagnostics::Diagnostics;

let diag = Diagnostics::new(conn);
let report = diag.scan().await?;
for issue in &report.issues {
    println!("[{:?}] {}", issue.severity, issue.message);
}
```

## Root Privileges

Some operations require root privileges:
- Creating/deleting interfaces (`route_link_create`)
- Adding/deleting addresses (`route_addresses -- add/del`)
- Modifying TC configuration
- Accessing other network namespaces
- Applying rate limits
- Adding MPLS/SRv6 routes

Run with `sudo` when needed:

```bash
sudo cargo run -p nlink --example route_link_create
```

## Features

Some examples require specific features:

| Feature | Examples |
|---------|----------|
| `namespace_watcher` | `namespace_watch` |
| `sockdiag` | `sockdiag_*` examples |

Enable features with `--features`:

```bash
cargo run -p nlink --features namespace_watcher --example namespace_watch
cargo run -p nlink --features sockdiag --example sockdiag_list_sockets
```
