//! Monitor helper utilities for event-based output.
//!
//! This module provides output formatting helpers for monitoring netlink events
//! in both text and JSON formats.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use nlink::output::OutputFormat;
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup};
//! use nlink::output::{MonitorConfig, print_event};
//! use tokio_stream::StreamExt;
//!
//! let config = MonitorConfig::new()
//!     .with_timestamp(true)
//!     .with_format(OutputFormat::Text);
//!
//! let conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link])?;
//! let mut events = conn.events().await;
//!
//! while let Some(result) = events.next().await {
//!     let event = result?;
//!     // Convert and print event...
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    io::{self, Write},
    time::SystemTime,
};

use super::{OutputFormat, OutputOptions};

/// Configuration for monitor output.
#[derive(Debug, Clone, Default)]
pub struct MonitorConfig {
    /// Whether to prefix output with timestamps.
    pub timestamp: bool,
    /// Output format (text or JSON).
    pub format: OutputFormat,
    /// Output options.
    pub opts: OutputOptions,
}

impl MonitorConfig {
    /// Create a new monitor config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable timestamp prefixes.
    pub fn with_timestamp(mut self, enabled: bool) -> Self {
        self.timestamp = enabled;
        self
    }

    /// Set the output format.
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the output options.
    pub fn with_opts(mut self, opts: OutputOptions) -> Self {
        self.opts = opts;
        self
    }
}

/// Write a timestamp prefix to the output if enabled.
///
/// Format: `[seconds.milliseconds] `
pub fn write_timestamp<W: Write>(w: &mut W, config: &MonitorConfig) -> io::Result<()> {
    if config.timestamp {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        write!(w, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
    }
    Ok(())
}

/// Helper trait for event types that can be printed in monitor mode.
pub trait MonitorEvent {
    /// Print the event in text format.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> io::Result<()>;

    /// Convert the event to a JSON value.
    fn to_json(&self) -> serde_json::Value;
}

/// Print a monitor event using the configured format.
pub fn print_event<W, E>(w: &mut W, event: &E, config: &MonitorConfig) -> io::Result<()>
where
    W: Write,
    E: MonitorEvent,
{
    write_timestamp(w, config)?;

    match config.format {
        OutputFormat::Text => {
            event.print_text(w, &config.opts)?;
        }
        OutputFormat::Json => {
            let json = event.to_json();
            writeln!(w, "{}", serde_json::to_string(&json).unwrap_or_default())?;
        }
    }

    w.flush()?;
    Ok(())
}

/// Print a startup message for monitor mode (text format only).
pub fn print_monitor_start<W: Write>(
    w: &mut W,
    config: &MonitorConfig,
    message: &str,
) -> io::Result<()> {
    if config.format == OutputFormat::Text {
        writeln!(w, "{}", message)?;
    }
    Ok(())
}

// ============================================================================
// IP Monitor Events
// ============================================================================

/// Link event for monitoring.
pub struct LinkEvent {
    pub action: &'static str,
    pub ifindex: u32,
    pub name: String,
    pub flags: u32,
    pub up: bool,
    pub mtu: Option<u32>,
    pub operstate: Option<&'static str>,
}

impl MonitorEvent for LinkEvent {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        let state = if self.up { "UP" } else { "DOWN" };
        writeln!(
            w,
            "LINK{}: {} index {} state {}",
            if self.action == "del" { " DEL" } else { "" },
            self.name,
            self.ifindex,
            state
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": "link",
            "action": self.action,
            "ifname": self.name,
            "ifindex": self.ifindex,
            "flags": self.flags,
            "up": self.up,
            "mtu": self.mtu,
            "operstate": self.operstate,
        })
    }
}

/// Address event for monitoring.
pub struct AddressEvent {
    pub action: &'static str,
    pub address: String,
    pub prefix_len: u8,
    pub ifindex: u32,
    pub family: u8,
    pub scope: &'static str,
    pub label: Option<String>,
}

impl MonitorEvent for AddressEvent {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        let ifname = crate::util::get_ifname_or_index(self.ifindex);
        writeln!(
            w,
            "ADDR{}: {}/{} dev {}",
            if self.action == "del" { " DEL" } else { "" },
            self.address,
            self.prefix_len,
            ifname
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": "address",
            "action": self.action,
            "address": self.address,
            "prefixlen": self.prefix_len,
            "ifindex": self.ifindex,
            "family": self.family,
            "scope": self.scope,
            "label": self.label,
        })
    }
}

/// Route event for monitoring.
pub struct RouteEvent {
    pub action: &'static str,
    pub destination: Option<String>,
    pub dst_len: u8,
    pub gateway: Option<String>,
    pub oif: Option<u32>,
    pub table: u32,
    pub protocol: &'static str,
    pub scope: &'static str,
    pub route_type: &'static str,
}

impl MonitorEvent for RouteEvent {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        let dst_str = self
            .destination
            .as_ref()
            .map(|d| format!("{}/{}", d, self.dst_len))
            .unwrap_or_else(|| "default".to_string());

        write!(
            w,
            "ROUTE{}: {}",
            if self.action == "del" { " DEL" } else { "" },
            dst_str
        )?;

        if let Some(ref gw) = self.gateway {
            write!(w, " via {}", gw)?;
        }

        if let Some(oif) = self.oif {
            let name = crate::util::get_ifname_or_index(oif);
            write!(w, " dev {}", name)?;
        }

        writeln!(w)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": "route",
            "action": self.action,
            "dst": self.destination,
            "dst_len": self.dst_len,
            "gateway": self.gateway,
            "oif": self.oif,
            "table": self.table,
            "protocol": self.protocol,
            "scope": self.scope,
            "type": self.route_type,
        })
    }
}

/// Neighbor event for monitoring.
pub struct NeighborEvent {
    pub action: &'static str,
    pub destination: String,
    pub lladdr: Option<String>,
    pub ifindex: u32,
    pub state: &'static str,
    pub router: bool,
}

impl MonitorEvent for NeighborEvent {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        let ifname = crate::util::get_ifname_or_index(self.ifindex);

        write!(
            w,
            "NEIGH{}: {} dev {}",
            if self.action == "del" { " DEL" } else { "" },
            self.destination,
            ifname
        )?;

        if let Some(ref mac) = self.lladdr {
            write!(w, " lladdr {}", mac)?;
        }

        writeln!(w, " {}", self.state)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": "neigh",
            "action": self.action,
            "dst": self.destination,
            "lladdr": self.lladdr,
            "ifindex": self.ifindex,
            "state": self.state,
            "router": self.router,
        })
    }
}

// ============================================================================
// TC Monitor Events
// ============================================================================

/// TC event for monitoring (qdisc, class, filter).
pub struct TcEvent {
    pub object: &'static str,
    pub action: &'static str,
    pub kind: String,
    pub handle: String,
    pub parent: String,
    pub dev: String,
    pub ifindex: u32,
}

impl MonitorEvent for TcEvent {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        write!(w, "{} {} ", self.action, self.object)?;

        if !self.kind.is_empty() {
            write!(w, "{} ", self.kind)?;
        }

        write!(w, "{} dev {} ", self.handle, self.dev)?;

        if self.parent == "root" || self.parent == "ingress" {
            write!(w, "{}", self.parent)?;
        } else if !self.parent.is_empty() && self.parent != "0:" {
            write!(w, "parent {}", self.parent)?;
        }

        writeln!(w)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": self.object,
            "action": self.action,
            "kind": self.kind,
            "handle": self.handle,
            "dev": self.dev,
            "parent": self.parent,
            "ifindex": self.ifindex,
        })
    }
}

/// Enum for any IP-related monitor event.
pub enum IpEvent {
    Link(LinkEvent),
    Address(AddressEvent),
    Route(RouteEvent),
    Neighbor(NeighborEvent),
}

impl MonitorEvent for IpEvent {
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> io::Result<()> {
        match self {
            IpEvent::Link(e) => e.print_text(w, opts),
            IpEvent::Address(e) => e.print_text(w, opts),
            IpEvent::Route(e) => e.print_text(w, opts),
            IpEvent::Neighbor(e) => e.print_text(w, opts),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            IpEvent::Link(e) => e.to_json(),
            IpEvent::Address(e) => e.to_json(),
            IpEvent::Route(e) => e.to_json(),
            IpEvent::Neighbor(e) => e.to_json(),
        }
    }
}
