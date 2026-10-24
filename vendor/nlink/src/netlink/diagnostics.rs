//! Network diagnostics module.
//!
//! Provides a unified diagnostic API that combines data from multiple sources
//! (links, TC, routes, addresses) to provide actionable insights about network issues.
//!
//! # Quick Start
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::diagnostics::Diagnostics;
//!
//! let conn = Connection::<Route>::new()?;
//! let diag = Diagnostics::new(conn);
//!
//! // Full scan
//! let report = diag.scan().await?;
//! for issue in &report.issues {
//!     println!("[{:?}] {}: {}", issue.severity, issue.category, issue.message);
//! }
//!
//! // Interface diagnostics
//! let eth0 = diag.scan_interface("eth0").await?;
//! println!("eth0: {} bit/s, {} drops", eth0.rates.tx_bps(), eth0.stats.tx_dropped());
//!
//! // Connectivity check
//! let report = diag.check_connectivity("8.8.8.8".parse()?).await?;
//! if !report.issues.is_empty() {
//!     for issue in &report.issues {
//!         println!("  - {}", issue.message);
//!     }
//! }
//!
//! // Find bottleneck
//! if let Some(bottleneck) = diag.find_bottleneck().await? {
//!     println!("Bottleneck: {}", bottleneck.location);
//!     println!("  Drop rate: {:.2}%", bottleneck.drop_rate * 100.0);
//!     println!("  Recommendation: {}", bottleneck.recommendation);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Real-time Monitoring
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::diagnostics::Diagnostics;
//! use tokio_stream::StreamExt;
//!
//! let conn = nlink::Connection::<nlink::Route>::new()?;
//! let diag = Diagnostics::new(conn);
//! let mut issues = diag.watch().await?;
//! while let Some(issue) = issues.next().await {
//!     let issue = issue?;
//!     println!("[{:?}] {}", issue.severity, issue.message);
//! }
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use tokio::sync::Mutex;
use tokio_stream::Stream;

/// The rates in [`InterfaceDiag::rates`]: the crate's one `LinkRates`,
/// from [`stats`](crate::netlink::stats), since 0.32 (#525). This module had
/// its own, in whole units with `rx_pps`/`tx_pps`.
pub use crate::netlink::stats::LinkRates;
use crate::netlink::{
    connection::Connection,
    error::Result,
    events::NetworkEvent,
    messages::{AddressMessage, LinkMessage, LinkStats, RouteMessage, TcMessage},
    protocol::Route,
    stream::OwnedEventStream,
    types::{link::OperState, neigh::NeighborState},
};

// ============================================================================
// Core Types
// ============================================================================

/// Network diagnostic report containing all collected information.
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    /// When the link counters were read: the end of the link dump. A
    /// [`Diagnostics::scan_since`] given this report takes its rates over
    /// the time since.
    pub timestamp: Instant,
    /// Interface diagnostics.
    pub interfaces: Vec<InterfaceDiag>,
    /// Route diagnostics.
    pub routes: RouteDiag,
    /// All detected issues across the system.
    pub issues: Vec<Issue>,
}

/// Diagnostics for a single network interface.
#[derive(Debug, Clone)]
pub struct InterfaceDiag {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub ifindex: u32,
    /// Operational state.
    pub state: OperState,
    /// Interface flags (IFF_UP, IFF_RUNNING, etc.).
    pub flags: u32,
    /// MTU.
    pub mtu: Option<u32>,
    /// Link statistics.
    pub stats: LinkStats,
    /// The rates since the previous sample of this link — the runner's
    /// last scan, or the report given to [`Diagnostics::scan_since`] — and
    /// zero without one. Since 0.32 this is the crate's one `LinkRates`,
    /// in bytes and packets per second as `f64` (#525).
    pub rates: LinkRates,
    /// Traffic control diagnostics.
    pub tc: Option<TcDiag>,
    /// Issues detected for this interface.
    pub issues: Vec<Issue>,
}

impl InterfaceDiag {
    /// True if the interface is administratively up (`IFF_UP`
    /// set in `flags`). Mirrors `LinkMessage::is_up()`.
    pub fn is_up(&self) -> bool {
        // IFF_UP = 0x1 — see <net/if.h>.
        self.flags & 0x1 != 0
    }

    /// True if the link layer detected carrier (`IFF_RUNNING`
    /// set in `flags`). Mirrors `LinkMessage::has_carrier()`.
    pub fn has_carrier(&self) -> bool {
        // IFF_RUNNING = 0x40 — see <net/if.h>.
        self.flags & 0x40 != 0
    }

    /// True if the interface is administratively up AND its
    /// operstate is `OperState::Up`. Convenience predicate
    /// answering "is this interface ready to carry traffic
    /// right now?"
    pub fn is_operational(&self) -> bool {
        self.is_up() && matches!(self.state, OperState::Up)
    }
}

/// Traffic control diagnostics for an interface.
#[derive(Debug, Clone)]
pub struct TcDiag {
    /// Qdisc type (e.g., "fq_codel", "htb", "netem").
    pub qdisc: String,
    /// Qdisc handle as string (e.g., "1:0").
    pub handle: String,
    /// Total drops from this qdisc.
    pub drops: u64,
    /// Overlimit count.
    pub overlimits: u64,
    /// Current backlog in bytes.
    pub backlog: u32,
    /// Current queue length in packets.
    pub qlen: u32,
    /// Current rate in bytes per second (from rate estimator).
    pub rate_bps: u64,
    /// Current packet rate (from rate estimator).
    pub rate_pps: u64,
    /// Total bytes processed.
    pub bytes: u64,
    /// Total packets processed.
    pub packets: u64,
}

impl TcDiag {
    /// Create TC diagnostics from a TcMessage.
    pub fn from_tc_message(tc: &TcMessage) -> Self {
        Self {
            qdisc: tc.kind().unwrap_or("unknown").to_string(),
            handle: tc.handle_str(),
            drops: tc.drops() as u64,
            overlimits: tc.overlimits() as u64,
            backlog: tc.backlog(),
            qlen: tc.qlen(),
            rate_bps: tc.bps(),
            rate_pps: tc.pps(),
            bytes: tc.bytes(),
            packets: tc.packets(),
        }
    }
}

/// Route diagnostics summary.
#[derive(Debug, Clone, Default)]
pub struct RouteDiag {
    /// Total number of IPv4 routes.
    pub ipv4_route_count: usize,
    /// Total number of IPv6 routes.
    pub ipv6_route_count: usize,
    /// Whether a default IPv4 route exists.
    pub has_default_ipv4: bool,
    /// Whether a default IPv6 route exists.
    pub has_default_ipv6: bool,
    /// Default gateway for IPv4 (if any).
    pub default_gateway_v4: Option<IpAddr>,
    /// Default gateway for IPv6 (if any).
    pub default_gateway_v6: Option<IpAddr>,
}

/// A detected issue.
#[derive(Debug, Clone)]
pub struct Issue {
    /// Severity level.
    pub severity: Severity,
    /// Category of the issue.
    pub category: IssueCategory,
    /// Human-readable message.
    pub message: String,
    /// Additional details or recommendations.
    pub details: Option<String>,
    /// Interface name if issue is interface-specific.
    pub interface: Option<String>,
    /// When the issue was detected.
    pub timestamp: Instant,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref iface) = self.interface {
            write!(f, "[{}] ", iface)?;
        }
        write!(f, "{}", self.message)?;
        if let Some(ref details) = self.details {
            write!(f, " ({})", details)?;
        }
        Ok(())
    }
}

/// Issue severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Informational message.
    Info,
    /// Warning that may indicate a problem.
    Warning,
    /// Error that affects functionality.
    Error,
    /// Critical issue requiring immediate attention.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of detected issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IssueCategory {
    /// Interface is down.
    LinkDown,
    /// No carrier detected.
    NoCarrier,
    /// High packet loss rate.
    HighPacketLoss,
    /// RX/TX errors detected.
    LinkErrors,
    /// Qdisc dropping packets.
    QdiscDrops,
    /// Buffer overflow / backlog.
    BufferOverflow,
    /// No route to destination.
    NoRoute,
    /// Destination unreachable.
    Unreachable,
    /// High latency detected.
    HighLatency,
    /// Interface has no addresses.
    NoAddress,
    /// No default route configured.
    NoDefaultRoute,
    /// MTU mismatch or issue.
    MtuIssue,
    /// Duplex/speed mismatch.
    DuplexMismatch,
}

impl fmt::Display for IssueCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueCategory::LinkDown => write!(f, "LinkDown"),
            IssueCategory::NoCarrier => write!(f, "NoCarrier"),
            IssueCategory::HighPacketLoss => write!(f, "HighPacketLoss"),
            IssueCategory::LinkErrors => write!(f, "LinkErrors"),
            IssueCategory::QdiscDrops => write!(f, "QdiscDrops"),
            IssueCategory::BufferOverflow => write!(f, "BufferOverflow"),
            IssueCategory::NoRoute => write!(f, "NoRoute"),
            IssueCategory::Unreachable => write!(f, "Unreachable"),
            IssueCategory::HighLatency => write!(f, "HighLatency"),
            IssueCategory::NoAddress => write!(f, "NoAddress"),
            IssueCategory::NoDefaultRoute => write!(f, "NoDefaultRoute"),
            IssueCategory::MtuIssue => write!(f, "MtuIssue"),
            IssueCategory::DuplexMismatch => write!(f, "DuplexMismatch"),
        }
    }
}

/// Connectivity check result.
#[derive(Debug, Clone)]
pub struct ConnectivityReport {
    /// Destination that was checked.
    pub destination: IpAddr,
    /// Route information if found.
    pub route: Option<RouteInfo>,
    /// Output interface for the route.
    pub output_interface: Option<String>,
    /// Gateway address if any.
    pub gateway: Option<IpAddr>,
    /// Whether the gateway is reachable (based on neighbor state).
    pub gateway_reachable: bool,
    /// Issues detected during connectivity check.
    pub issues: Vec<Issue>,
}

/// Basic route information.
///
/// `#[non_exhaustive]` so future kernel attributes can be added
/// without an SHV bump. Construct via the diagnostics layer
/// (`Diagnostics::scan` / `Diagnostics::check_connectivity`);
/// the struct is not a builder input.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouteInfo {
    /// Destination prefix.
    pub destination: String,
    /// Prefix length.
    pub prefix_len: u8,
    /// Gateway address.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub oif: Option<u32>,
    /// Resolved output-interface name (filled in by the scan
    /// pass via `Connection::get_link_by_index(oif)`).
    /// `None` when `oif` is unset or the lookup failed; for
    /// most kernel-installed routes a value is populated.
    pub dev_name: Option<String>,
    /// Preferred source address (RTA_PREFSRC). The address the
    /// kernel binds when this host originates a connection
    /// matching this route. Empty for routes with no prefsrc
    /// hint (most kernel-default routes).
    pub source: Option<IpAddr>,
    /// Route metric.
    pub metric: Option<u32>,
}

/// Bottleneck analysis result.
#[derive(Debug, Clone)]
pub struct Bottleneck {
    /// Location description (e.g., "eth0 egress qdisc").
    pub location: String,
    /// Type of bottleneck.
    pub bottleneck_type: BottleneckType,
    /// Current rate in bytes per second.
    pub current_rate: u64,
    /// Drop rate as fraction (0.0 to 1.0).
    pub drop_rate: f64,
    /// Total drops observed.
    pub total_drops: u64,
    /// Recommendation for fixing the bottleneck.
    pub recommendation: String,
}

impl Bottleneck {
    /// Normalized severity score in 0.0..=1.0. Higher = worse.
    ///
    /// Combines three signals with documented weights:
    /// - `drop_rate` (weight **0.6**) — the most direct measure
    ///   of "packets are being lost."
    /// - Backlog pressure (weight **0.3**) — `min(current_rate
    ///   / 1 MB, 1.0)` for `BottleneckType::{QdiscDrops,
    ///   BufferFull}` (where `current_rate` doubles as the
    ///   backlog proxy in the existing field set); 0 for
    ///   other variants.
    /// - Error rate (weight **0.1**) — `min(total_drops /
    ///   current_rate, 1.0)` for `BottleneckType::{HardwareErrors,
    ///   InterfaceDrops}`; 0 for other variants. Falls back to
    ///   0 when `current_rate` is 0 (would divide by zero).
    ///
    /// Saturates at 1.0 in extreme cases.
    ///
    /// **The weights are documented rather than configurable**
    /// (Plan 169 Phase 3 decision). For use cases that need
    /// different weighting — e.g., a latency-sensitive RT
    /// workload that treats any drop as critical — compute
    /// the score yourself from the underlying fields. The lib
    /// commits to this formula across 0.17.x; revision possible
    /// in 0.18 if real-world signal indicates a better
    /// combination.
    pub fn score(&self) -> f64 {
        let drop_component = self.drop_rate * 0.6;

        let backlog_pressure = match self.bottleneck_type {
            BottleneckType::QdiscDrops | BottleneckType::BufferFull => {
                (self.current_rate as f64 / 1_048_576.0).min(1.0)
            }
            _ => 0.0,
        };
        let backlog_component = backlog_pressure * 0.3;

        let error_component = match self.bottleneck_type {
            BottleneckType::HardwareErrors | BottleneckType::InterfaceDrops
                if self.current_rate > 0 =>
            {
                (self.total_drops as f64 / self.current_rate as f64).min(1.0) * 0.1
            }
            _ => 0.0,
        };

        (drop_component + backlog_component + error_component).min(1.0)
    }
}

/// Type of bottleneck detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BottleneckType {
    /// Qdisc is dropping packets.
    QdiscDrops,
    /// Interface is dropping packets.
    InterfaceDrops,
    /// Buffer overflow.
    BufferFull,
    /// Rate limiting in effect.
    RateLimited,
    /// Hardware errors.
    HardwareErrors,
}

impl fmt::Display for BottleneckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BottleneckType::QdiscDrops => write!(f, "Qdisc Drops"),
            BottleneckType::InterfaceDrops => write!(f, "Interface Drops"),
            BottleneckType::BufferFull => write!(f, "Buffer Full"),
            BottleneckType::RateLimited => write!(f, "Rate Limited"),
            BottleneckType::HardwareErrors => write!(f, "Hardware Errors"),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for issue detection thresholds.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct DiagnosticsConfig {
    /// Packet loss threshold as fraction (default: 0.01 = 1%).
    pub packet_loss_threshold: f64,
    /// Error rate threshold as fraction (default: 0.001 = 0.1%).
    pub error_rate_threshold: f64,
    /// Qdisc drop threshold as fraction of packets (default: 0.01 = 1%).
    pub qdisc_drop_threshold: f64,
    /// Backlog threshold in bytes (default: 100KB).
    pub backlog_threshold: u32,
    /// Queue length threshold in packets (default: 1000).
    pub qlen_threshold: u32,
    /// Whether to skip loopback interfaces.
    pub skip_loopback: bool,
    /// Whether to skip down interfaces.
    pub skip_down: bool,
    /// Minimum bytes transferred before calculating loss or error
    /// rates.
    ///
    /// Compared against `rx_bytes + tx_bytes`. It used to be compared
    /// against a *packet* count, so `1_000_000` — meaning "1 MB" —
    /// actually waited for a million packets, roughly 1.5 GB at MTU:
    /// loss detection stayed silent about 1500× longer than asked
    /// (#274).
    pub min_bytes_for_rate: u64,
    /// Whether a scan warns that there is no default route. On by default;
    /// a lab namespace often has none on purpose (#509).
    pub warn_no_default_route: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            packet_loss_threshold: 0.01,
            error_rate_threshold: 0.001,
            qdisc_drop_threshold: 0.01,
            backlog_threshold: 100_000,
            qlen_threshold: 1000,
            skip_loopback: true,
            skip_down: false,
            min_bytes_for_rate: 1000,
            warn_no_default_route: true,
        }
    }
}

// ============================================================================
// Diagnostics Runner
// ============================================================================

/// Network diagnostics runner.
///
/// Provides methods to scan and analyze network configuration.
pub struct Diagnostics {
    conn: Connection<Route>,
    config: DiagnosticsConfig,
    /// Previous statistics for rate calculation.
    prev_stats: Arc<Mutex<HashMap<u32, LinkSample>>>,
    /// Previous TC stats for rate calculation (reserved for future use).
    #[allow(dead_code, clippy::type_complexity)]
    prev_tc_stats: Arc<Mutex<HashMap<(u32, u32), (Instant, u64, u64)>>>,
}

/// A link's counters as sampled: when, under what name, and the counters.
type LinkSample = (Instant, String, LinkStats);

/// The rates since `prev`, and its counters, when it is a sample of the
/// same link — the same name — and none went backwards; zero rates (and
/// still the counters, for the same link) otherwise.
fn rates_since(
    prev: Option<&LinkSample>,
    name: &str,
    stats: &LinkStats,
    now: Instant,
) -> (LinkRates, Option<LinkStats>) {
    match prev {
        Some((at, prev_name, prev)) if prev_name == name => {
            let elapsed = now.saturating_duration_since(*at);
            let rates = LinkRates::between(prev, stats, elapsed).unwrap_or_default();
            (rates, Some(*prev))
        }
        _ => (LinkRates::default(), None),
    }
}

#[nlink_macros::send_futures]
impl Diagnostics {
    /// Create a new diagnostics runner with default configuration.
    pub fn new(conn: Connection<Route>) -> Self {
        Self {
            conn,
            config: DiagnosticsConfig::default(),
            prev_stats: Arc::new(Mutex::new(HashMap::new())),
            prev_tc_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new diagnostics runner with custom configuration.
    pub fn with_config(conn: Connection<Route>, config: DiagnosticsConfig) -> Self {
        Self {
            conn,
            config,
            prev_stats: Arc::new(Mutex::new(HashMap::new())),
            prev_tc_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &DiagnosticsConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut DiagnosticsConfig {
        &mut self.config
    }

    /// Run a full diagnostic scan of all interfaces and routes.
    ///
    /// Rates are since this runner's previous scan; a fresh runner has
    /// none, and reports zero. [`scan_since`](Self::scan_since) takes the
    /// previous sample from the caller instead.
    pub async fn scan(&self) -> Result<DiagnosticReport> {
        let prev = self.prev_stats.lock().await.clone();
        let (report, samples) = self.scan_with(&prev).await?;
        *self.prev_stats.lock().await = samples;
        Ok(report)
    }

    /// A full scan whose rates are since `previous`, a report the caller
    /// kept (#525): a collector that builds a runner per tick, or scans
    /// many namespaces with one, gets rates from its first scan. This
    /// runner's own previous sample is neither used nor updated.
    pub async fn scan_since(&self, previous: &DiagnosticReport) -> Result<DiagnosticReport> {
        let prev = previous
            .interfaces
            .iter()
            .map(|i| (i.ifindex, (previous.timestamp, i.name.clone(), i.stats)))
            .collect();
        Ok(self.scan_with(&prev).await?.0)
    }

    /// The scan, with the previous samples to take rates against; returns
    /// the report and this scan's samples.
    async fn scan_with(
        &self,
        prev_stats: &HashMap<u32, LinkSample>,
    ) -> Result<(DiagnosticReport, HashMap<u32, LinkSample>)> {
        let mut all_issues = Vec::new();

        // Get all links. Their counters' time is the end of this dump.
        let links = self.conn.get_links().await?;
        let timestamp = Instant::now();

        // Get all addresses for checking
        let addresses = self.conn.get_addresses().await?;
        let addr_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for addr in addresses {
                map.entry(addr.ifindex()).or_default().push(addr);
            }
            map
        };

        // Get all qdiscs
        let qdiscs = self.conn.get_qdiscs().await?;
        let qdiscs_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for qdisc in qdiscs {
                map.entry(qdisc.ifindex()).or_default().push(qdisc);
            }
            map
        };

        // Get routes and split by family. A failed dump is an error: it was
        // swallowed into an empty list, which then raised a spurious "no
        // default route" (#509).
        let all_routes = self.conn.get_routes().await?;
        let ipv4_routes: Vec<_> = all_routes.iter().filter(|r| r.is_ipv4()).collect();
        let ipv6_routes: Vec<_> = all_routes.iter().filter(|r| r.is_ipv6()).collect();

        // Build route diagnostics
        let routes = self.build_route_diag(&ipv4_routes, &ipv6_routes);

        // Check for missing default route
        if self.config.warn_no_default_route && !routes.has_default_ipv4 && !routes.has_default_ipv6
        {
            all_issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::NoDefaultRoute,
                message: "No default route configured".to_string(),
                details: Some("System may not have internet connectivity".to_string()),
                interface: None,
                timestamp,
            });
        }

        // Scan each interface. A sample is only compared with one of the
        // same name: a reused ifindex is another link (#274).
        let mut interfaces = Vec::new();
        let mut samples = HashMap::new();

        for link in links {
            // Skip loopback if configured
            if self.config.skip_loopback && link.is_loopback() {
                continue;
            }

            // Skip down interfaces if configured
            if self.config.skip_down && !link.is_up() {
                continue;
            }

            let ifindex = link.ifindex();
            let name = link.name().unwrap_or("?").to_string();
            let state = link.operstate().unwrap_or(OperState::Unknown);
            let stats = link.stats().cloned().unwrap_or_default();

            let (rates, prev) = rates_since(prev_stats.get(&ifindex), &name, &stats, timestamp);
            samples.insert(ifindex, (timestamp, name.clone(), stats));

            // Detect issues for this interface
            let mut issues =
                self.detect_link_issues(&link, &stats, prev.as_ref(), &addr_by_ifindex, timestamp);

            // Get TC diagnostics
            let tc = qdiscs_by_ifindex.get(&ifindex).and_then(|qs| {
                // Find the root qdisc
                qs.iter()
                    .find(|q| q.is_root())
                    .or_else(|| qs.first())
                    .map(|q| {
                        let tc_diag = TcDiag::from_tc_message(q);
                        // Check for TC issues
                        issues.extend(self.detect_tc_issues(q, &name, timestamp));
                        tc_diag
                    })
            });

            // Add interface issues to global list
            all_issues.extend(issues.iter().cloned());

            interfaces.push(InterfaceDiag {
                name,
                ifindex,
                state,
                flags: link.flags(),
                mtu: link.mtu(),
                stats,
                rates,
                tc,
                issues,
            });
        }

        let report = DiagnosticReport {
            timestamp,
            interfaces,
            routes,
            issues: all_issues,
        };
        Ok((report, samples))
    }

    /// Diagnose a specific interface.
    pub async fn scan_interface(&self, dev: &str) -> Result<InterfaceDiag> {
        let timestamp = Instant::now();

        // Get the link
        let link = self.conn.get_link_by_name(dev).await?;
        let link = link.ok_or_else(|| self.conn.interface_not_found(dev))?;

        let ifindex = link.ifindex();
        let name = dev.to_string();
        let state = link.operstate().unwrap_or(OperState::Unknown);
        let stats = link.stats().cloned().unwrap_or_default();

        // Get addresses
        let addresses = self.conn.get_addresses_by_name(dev).await?;
        let addr_by_ifindex: HashMap<u32, Vec<_>> = {
            let mut map: HashMap<u32, Vec<_>> = HashMap::new();
            for addr in addresses {
                map.entry(addr.ifindex()).or_default().push(addr);
            }
            map
        };

        // Calculate rates
        let read_at = Instant::now();
        let mut prev_stats = self.prev_stats.lock().await;
        let (rates, prev) = rates_since(prev_stats.get(&ifindex), &name, &stats, read_at);
        prev_stats.insert(ifindex, (read_at, name.clone(), stats));
        drop(prev_stats);

        // Detect issues
        let mut issues =
            self.detect_link_issues(&link, &stats, prev.as_ref(), &addr_by_ifindex, timestamp);

        // Get TC diagnostics
        let qdiscs = self.conn.get_qdiscs_by_name(dev).await?;
        let tc = qdiscs
            .iter()
            .find(|q| q.is_root())
            .or(qdiscs.first())
            .map(|q| {
                let tc_diag = TcDiag::from_tc_message(q);
                issues.extend(self.detect_tc_issues(q, &name, timestamp));
                tc_diag
            });

        Ok(InterfaceDiag {
            name,
            ifindex,
            state,
            flags: link.flags(),
            mtu: link.mtu(),
            stats,
            rates,
            tc,
            issues,
        })
    }

    /// Check connectivity to a destination IP address.
    pub async fn check_connectivity(&self, dest: IpAddr) -> Result<ConnectivityReport> {
        let timestamp = Instant::now();
        let mut issues = Vec::new();

        // What the kernel would do with a packet to `dest`: a FIB lookup,
        // as `ip route get` does. This was a `find` over a dump of every
        // table, called "longest prefix match": the first route that
        // contained `dest` won — usually the default route — whatever the
        // policy rules said, and a blackhole counted as a route (#509).
        let lookup = match self.conn.lookup_route(dest).await {
            Ok(route) => Ok(route),
            Err(e) => {
                let why = match e.errno() {
                    Some(libc::ENETUNREACH) => "no route matches it",
                    Some(libc::EHOSTUNREACH) => "an unreachable route matches it",
                    Some(libc::EACCES) => "a prohibit route matches it",
                    Some(libc::EINVAL) => "a blackhole route matches it",
                    _ => return Err(e),
                };
                Err(why)
            }
        };

        let (route, gateway, output_interface, oif) = match lookup {
            Ok(r) => {
                let gateway = r.gateway;
                let oif = r.oif;
                let output_interface = if let Some(idx) = oif {
                    self.conn
                        .get_link_by_index(idx)
                        .await?
                        .and_then(|l| l.name().map(|s| s.to_string()))
                } else {
                    None
                };

                let route_info = RouteInfo {
                    destination: r
                        .destination
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "default".to_string()),
                    prefix_len: r.dst_len(),
                    gateway,
                    oif,
                    dev_name: output_interface.clone(),
                    source: r.prefsrc().copied(),
                    metric: r.priority(),
                };

                (Some(route_info), gateway, output_interface, oif)
            }
            Err(why) => {
                issues.push(Issue {
                    severity: Severity::Error,
                    category: IssueCategory::NoRoute,
                    message: format!("No route to {}", dest),
                    details: Some(why.to_string()),
                    interface: None,
                    timestamp,
                });
                (None, None, None, None)
            }
        };

        // Check if gateway is reachable via neighbor cache
        let gateway_reachable = if let Some(gw) = gateway {
            // Check neighbor cache
            let neighbors = self.conn.get_neighbors().await.unwrap_or_default();
            neighbors.iter().any(|n| {
                n.destination == Some(gw)
                    && n.state() != NeighborState::Incomplete
                    && n.state() != NeighborState::Failed
            })
        } else {
            true // No gateway means direct route
        };

        if gateway.is_some() && !gateway_reachable {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::Unreachable,
                message: format!("Gateway {:?} may be unreachable", gateway),
                details: Some("Not found in neighbor cache or in failed state".to_string()),
                interface: output_interface.clone(),
                timestamp,
            });
        }

        // Check if output interface is up
        if let Some(idx) = oif
            && let Some(link) = self.conn.get_link_by_index(idx).await?
            && !link.is_up()
        {
            issues.push(Issue {
                severity: Severity::Error,
                category: IssueCategory::LinkDown,
                message: format!("Output interface {} is down", link.name().unwrap_or("?")),
                details: None,
                interface: link.name().map(|s| s.to_string()),
                timestamp,
            });
        }

        Ok(ConnectivityReport {
            destination: dest,
            route,
            output_interface,
            gateway,
            gateway_reachable,
            issues,
        })
    }

    /// Find the most significant bottleneck in the system.
    pub async fn find_bottleneck(&self) -> Result<Option<Bottleneck>> {
        let mut bottlenecks = Vec::new();

        // Check all interfaces
        let links = self.conn.get_links().await?;

        for link in &links {
            // Same filters as `scan()`. These were hardcoded — loopback
            // always skipped, `skip_down` never consulted — so a caller
            // who set `skip_loopback = false` to include `lo` got it
            // from one entry point and not the other (#274).
            if self.config.skip_loopback && link.is_loopback() {
                continue;
            }
            if self.config.skip_down && !link.is_up() {
                continue;
            }

            let name = link.name().unwrap_or("?");

            if let Some(stats) = link.stats() {
                let total_packets = stats.total_packets();
                let total_bytes = stats.total_bytes();
                let total_dropped = stats.total_dropped();
                let total_errors = stats.total_errors();

                // …and the same sampling gate, rather than a bare
                // `total_packets > 0`, so the two agree on when there is
                // enough traffic to divide by.
                if total_bytes > self.config.min_bytes_for_rate && total_packets > 0 {
                    let drop_rate = total_dropped as f64 / total_packets as f64;

                    if drop_rate > self.config.packet_loss_threshold {
                        bottlenecks.push(Bottleneck {
                            location: format!("{} interface", name),
                            bottleneck_type: BottleneckType::InterfaceDrops,
                            current_rate: 0,
                            drop_rate,
                            total_drops: total_dropped,
                            recommendation: format!(
                                "Check {} for hardware issues or increase buffer sizes",
                                name
                            ),
                        });
                    }

                    if total_errors > 0 {
                        let error_rate = total_errors as f64 / total_packets as f64;
                        if error_rate > self.config.error_rate_threshold {
                            bottlenecks.push(Bottleneck {
                                location: format!("{} interface", name),
                                bottleneck_type: BottleneckType::HardwareErrors,
                                current_rate: 0,
                                drop_rate: error_rate,
                                total_drops: total_errors,
                                recommendation: format!(
                                    "Check cable, PHY settings, or NIC on {}",
                                    name
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Check all qdiscs
        let qdiscs = self.conn.get_qdiscs().await?;
        let names = self.conn.get_interface_names().await?;

        for qdisc in &qdiscs {
            if !qdisc.is_root() {
                continue;
            }

            let name = names
                .get(&qdisc.ifindex())
                .map(|s| s.as_str())
                .unwrap_or("?");

            let drops = qdisc.drops() as u64;
            // Dropped packets are not among the sent ones (#509); and
            // netem's drops are its configured loss, not a bottleneck.
            let offered = qdisc.packets() + drops;

            if offered > 0 && qdisc.kind() != Some("netem") {
                let drop_rate = drops as f64 / offered as f64;

                if drop_rate > self.config.qdisc_drop_threshold {
                    bottlenecks.push(Bottleneck {
                        location: format!(
                            "{} egress qdisc ({})",
                            name,
                            qdisc.kind().unwrap_or("?")
                        ),
                        bottleneck_type: BottleneckType::QdiscDrops,
                        current_rate: qdisc.bps(),
                        drop_rate,
                        total_drops: drops,
                        recommendation: format!(
                            "Increase qdisc limit or rate on {}, or switch to a different qdisc",
                            name
                        ),
                    });
                }
            }

            // Check for buffer issues
            let backlog = qdisc.backlog();
            let qlen = qdisc.qlen();

            if backlog > self.config.backlog_threshold || qlen > self.config.qlen_threshold {
                bottlenecks.push(Bottleneck {
                    location: format!("{} egress qdisc ({})", name, qdisc.kind().unwrap_or("?")),
                    bottleneck_type: BottleneckType::BufferFull,
                    current_rate: qdisc.bps(),
                    drop_rate: 0.0,
                    total_drops: drops,
                    recommendation: format!(
                        "High queue depth on {} - consider reducing buffering or increasing rate",
                        name
                    ),
                });
            }
        }

        // Return the worst bottleneck (highest drop rate)
        bottlenecks.sort_by(|a, b| {
            b.drop_rate
                .partial_cmp(&a.drop_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(bottlenecks.into_iter().next())
    }

    /// Watch for issues in real-time.
    ///
    /// Returns a stream of issues detected from network events.
    ///
    /// The events come from the namespace this `Diagnostics`' connection is
    /// in. It used to subscribe on a new connection in the process's
    /// namespace, so a `Diagnostics::new(lab_conn)` watched the host (#497).
    pub async fn watch(&self) -> Result<IssueStream> {
        let conn = self.conn.route_sibling()?;
        conn.subscribe_all()?;
        Ok(IssueStream {
            events: conn.into_events().await,
            config: self.config.clone(),
            names: HashMap::new(),
        })
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    fn build_route_diag(
        &self,
        ipv4_routes: &[&RouteMessage],
        ipv6_routes: &[&RouteMessage],
    ) -> RouteDiag {
        let mut diag = RouteDiag {
            ipv4_route_count: ipv4_routes.len(),
            ipv6_route_count: ipv6_routes.len(),
            ..Default::default()
        };

        // Find default IPv4 route
        for route in ipv4_routes {
            if route.dst_len() == 0 {
                diag.has_default_ipv4 = true;
                diag.default_gateway_v4 = route.gateway;
                break;
            }
        }

        // Find default IPv6 route
        for route in ipv6_routes {
            if route.dst_len() == 0 {
                diag.has_default_ipv6 = true;
                diag.default_gateway_v6 = route.gateway;
                break;
            }
        }

        diag
    }

    fn detect_link_issues(
        &self,
        link: &LinkMessage,
        stats: &LinkStats,
        prev: Option<&LinkStats>,
        addr_by_ifindex: &HashMap<u32, Vec<AddressMessage>>,
        timestamp: Instant,
    ) -> Vec<Issue> {
        let mut issues = Vec::new();
        let name = link.name().unwrap_or("?").to_string();
        let ifindex = link.ifindex();

        // Check if interface is down
        if !link.is_up() {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::LinkDown,
                message: format!("Interface {} is down", name),
                details: None,
                interface: Some(name.clone()),
                timestamp,
            });
        }

        // Check carrier
        if link.is_up() && !link.has_carrier() {
            issues.push(Issue {
                severity: Severity::Error,
                category: IssueCategory::NoCarrier,
                message: format!("No carrier on {}", name),
                details: Some("Check cable connection".to_string()),
                interface: Some(name.clone()),
                timestamp,
            });
        }

        // Check for packet loss. The *rate* is a fraction of packets;
        // the *gate* is a byte count, as its name says (#274).
        //
        // Since the previous sample when there is one: on lifetime counters
        // one old burst flagged the interface for as long as it existed
        // (#509). A counter that went backwards — a recreated link — means
        // the lifetime figures are the interval's.
        let current = (
            stats.total_packets(),
            stats.total_bytes(),
            stats.total_dropped(),
            stats.total_errors(),
        );
        let (total_packets, total_bytes, total_dropped, total_errors) = match prev {
            Some(p)
                if current.0 >= p.total_packets()
                    && current.1 >= p.total_bytes()
                    && current.2 >= p.total_dropped()
                    && current.3 >= p.total_errors() =>
            {
                (
                    current.0 - p.total_packets(),
                    current.1 - p.total_bytes(),
                    current.2 - p.total_dropped(),
                    current.3 - p.total_errors(),
                )
            }
            _ => current,
        };

        if total_bytes > self.config.min_bytes_for_rate && total_packets > 0 && total_dropped > 0 {
            let drop_rate = total_dropped as f64 / total_packets as f64;
            if drop_rate > self.config.packet_loss_threshold {
                issues.push(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::HighPacketLoss,
                    message: format!("{:.2}% packet loss on {}", drop_rate * 100.0, name),
                    details: Some(format!(
                        "{} dropped out of {} packets",
                        total_dropped, total_packets
                    )),
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        // Check for errors
        if total_bytes > self.config.min_bytes_for_rate && total_packets > 0 && total_errors > 0 {
            let error_rate = total_errors as f64 / total_packets as f64;
            if error_rate > self.config.error_rate_threshold {
                issues.push(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::LinkErrors,
                    message: format!(
                        "{} errors on {} ({:.3}%)",
                        total_errors,
                        name,
                        error_rate * 100.0
                    ),
                    details: Some(format!(
                        "RX errors: {}, TX errors: {}",
                        stats.rx_errors(),
                        stats.tx_errors()
                    )),
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        // Check for missing addresses (skip loopback)
        if link.is_up() && !link.is_loopback() {
            let has_addrs = addr_by_ifindex
                .get(&ifindex)
                .map(|addrs| !addrs.is_empty())
                .unwrap_or(false);
            if !has_addrs {
                issues.push(Issue {
                    severity: Severity::Info,
                    category: IssueCategory::NoAddress,
                    message: format!("No IP addresses configured on {}", name),
                    details: None,
                    interface: Some(name.clone()),
                    timestamp,
                });
            }
        }

        issues
    }

    fn detect_tc_issues(&self, tc: &TcMessage, iface: &str, timestamp: Instant) -> Vec<Issue> {
        let mut issues = Vec::new();

        let drops = tc.drops() as u64;
        // A dropped packet is not among the ones sent, so the share of
        // packets dropped is out of both (#509).
        let offered = tc.packets() + drops;

        if offered > 0 && drops > 0 {
            let drop_rate = drops as f64 / offered as f64;
            // netem drops what its configured loss tells it to, and the
            // kernel counts those as drops: that is the impairment working,
            // not a fault (#509).
            let netem = tc.kind() == Some("netem");
            if drop_rate > self.config.qdisc_drop_threshold {
                issues.push(Issue {
                    severity: if netem {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                    category: IssueCategory::QdiscDrops,
                    message: if netem {
                        format!(
                            "netem on {} dropped {:.2}% of packets (emulated loss counts as drops)",
                            iface,
                            drop_rate * 100.0
                        )
                    } else {
                        format!(
                            "Qdisc {} dropping {:.2}% of packets on {}",
                            tc.kind().unwrap_or("?"),
                            drop_rate * 100.0,
                            iface
                        )
                    },
                    details: Some(format!("{drops} dropped out of {offered} packets")),
                    interface: Some(iface.to_string()),
                    timestamp,
                });
            }
        }

        // Check backlog
        if tc.backlog() > self.config.backlog_threshold {
            issues.push(Issue {
                severity: Severity::Warning,
                category: IssueCategory::BufferOverflow,
                message: format!("High backlog ({} bytes) on {} qdisc", tc.backlog(), iface),
                details: Some(format!("Queue length: {} packets", tc.qlen())),
                interface: Some(iface.to_string()),
                timestamp,
            });
        }

        issues
    }
}

// ============================================================================
// Issue Stream
// ============================================================================

/// Stream of issues from real-time monitoring.
pub struct IssueStream {
    events: OwnedEventStream<Route>,
    /// Interface names by ifindex, from the stream's own link events: the
    /// host's `/sys/class/net` is the wrong namespace to ask (#497).
    names: HashMap<u32, String>,
    /// Configuration for issue thresholds (reserved for future filtering).
    #[allow(dead_code)]
    config: DiagnosticsConfig,
}

impl Stream for IssueStream {
    type Item = Result<Issue>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let events = Pin::new(&mut self.events);

            match events.poll_next(cx) {
                Poll::Ready(Some(Ok(event))) => {
                    match &event {
                        NetworkEvent::NewLink(link) => {
                            if let Some(name) = link.name() {
                                self.names.insert(link.ifindex(), name.to_string());
                            }
                        }
                        NetworkEvent::DelLink(link) => {
                            self.names.remove(&link.ifindex());
                        }
                        _ => {}
                    }
                    if let Some(issue) = self.event_to_issue(&event) {
                        return Poll::Ready(Some(Ok(issue)));
                    }
                    // Continue polling for next event
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl IssueStream {
    fn event_to_issue(&self, event: &NetworkEvent) -> Option<Issue> {
        let timestamp = Instant::now();

        match event {
            NetworkEvent::DelLink(link) => {
                let name = link.name().unwrap_or("?").to_string();
                Some(Issue {
                    severity: Severity::Warning,
                    category: IssueCategory::LinkDown,
                    message: format!("Interface {} removed", name),
                    details: None,
                    interface: Some(name),
                    timestamp,
                })
            }
            NetworkEvent::NewLink(link) => {
                let name = link.name().unwrap_or("?").to_string();

                // Check for carrier issues on new/changed links
                if link.is_up() && !link.has_carrier() {
                    return Some(Issue {
                        severity: Severity::Error,
                        category: IssueCategory::NoCarrier,
                        message: format!("No carrier on {}", name),
                        details: Some("Check cable connection".to_string()),
                        interface: Some(name),
                        timestamp,
                    });
                }

                // Check for operstate changes
                if let Some(state) = link.operstate()
                    && (state == OperState::Down || state == OperState::LowerLayerDown)
                {
                    return Some(Issue {
                        severity: Severity::Warning,
                        category: IssueCategory::LinkDown,
                        message: format!("Interface {} is {:?}", name, state),
                        details: None,
                        interface: Some(name),
                        timestamp,
                    });
                }

                None
            }
            NetworkEvent::DelAddress(addr) => {
                let name = self
                    .names
                    .get(&addr.ifindex())
                    .cloned()
                    .unwrap_or_else(|| format!("if{}", addr.ifindex()));
                Some(Issue {
                    severity: Severity::Info,
                    category: IssueCategory::NoAddress,
                    message: format!("Address {:?} removed from {}", addr.address(), name),
                    details: None,
                    interface: Some(name),
                    timestamp,
                })
            }
            NetworkEvent::DelRoute(route) => {
                // Check if it's the default route
                if route.dst_len() == 0 {
                    return Some(Issue {
                        severity: Severity::Warning,
                        category: IssueCategory::NoDefaultRoute,
                        message: "Default route removed".to_string(),
                        details: None,
                        interface: None,
                        timestamp,
                    });
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_iface_diag(flags: u32, state: OperState) -> InterfaceDiag {
        InterfaceDiag {
            name: "test0".into(),
            ifindex: 1,
            state,
            flags,
            mtu: None,
            stats: LinkStats::default(),
            rates: LinkRates::default(),
            tc: None,
            issues: Vec::new(),
        }
    }

    #[test]
    fn interface_diag_is_up_reads_iff_up_bit() {
        assert!(!empty_iface_diag(0, OperState::Down).is_up());
        assert!(empty_iface_diag(0x1, OperState::Down).is_up());
        // IFF_RUNNING (0x40) without IFF_UP is not "up".
        assert!(!empty_iface_diag(0x40, OperState::Down).is_up());
    }

    #[test]
    fn interface_diag_has_carrier_reads_iff_running_bit() {
        assert!(!empty_iface_diag(0, OperState::Down).has_carrier());
        assert!(empty_iface_diag(0x40, OperState::Down).has_carrier());
        // IFF_UP alone doesn't imply carrier.
        assert!(!empty_iface_diag(0x1, OperState::Down).has_carrier());
    }

    #[test]
    fn interface_diag_is_operational_requires_iff_up_plus_operstate_up() {
        assert!(!empty_iface_diag(0, OperState::Up).is_operational());
        assert!(!empty_iface_diag(0x1, OperState::Down).is_operational());
        assert!(empty_iface_diag(0x1, OperState::Up).is_operational());
    }

    fn bottleneck_with(
        bottleneck_type: BottleneckType,
        drop_rate: f64,
        current_rate: u64,
        total_drops: u64,
    ) -> Bottleneck {
        Bottleneck {
            location: "test".into(),
            bottleneck_type,
            current_rate,
            drop_rate,
            total_drops,
            recommendation: String::new(),
        }
    }

    #[test]
    fn bottleneck_score_zero_for_empty() {
        let b = bottleneck_with(BottleneckType::QdiscDrops, 0.0, 0, 0);
        assert_eq!(b.score(), 0.0);
    }

    #[test]
    fn bottleneck_score_pure_drop_rate() {
        // drop_rate=1.0, no backlog, no errors → 0.6 (just the
        // drop_rate weight).
        let b = bottleneck_with(BottleneckType::QdiscDrops, 1.0, 0, 0);
        assert!((b.score() - 0.6).abs() < 1e-9, "got {}", b.score());
    }

    #[test]
    fn bottleneck_score_pure_backlog_on_buffer_full() {
        // 1 MB current_rate, no drops, BufferFull → 0.3
        // (just the backlog weight).
        let b = bottleneck_with(BottleneckType::BufferFull, 0.0, 1_048_576, 0);
        assert!((b.score() - 0.3).abs() < 1e-9, "got {}", b.score());
    }

    #[test]
    fn bottleneck_score_composite_qdisc_drops() {
        // drop_rate=0.5 → 0.30, current_rate=512 KB → backlog
        // pressure=0.5 → 0.15. Total: 0.45.
        let b = bottleneck_with(BottleneckType::QdiscDrops, 0.5, 524_288, 0);
        assert!((b.score() - 0.45).abs() < 1e-9, "got {}", b.score());
    }

    #[test]
    fn bottleneck_score_saturates_at_one() {
        // Pathological: huge drop_rate (above 1.0 — defensive
        // input) and huge backlog. min(...).min(1.0) saturates.
        let b = bottleneck_with(BottleneckType::QdiscDrops, 2.0, 100_000_000, 0);
        assert!(b.score() <= 1.0, "got {}", b.score());
        assert!(b.score() >= 0.9, "should be near saturation: {}", b.score());
    }

    #[test]
    fn bottleneck_score_no_backlog_component_for_unrelated_type() {
        // RateLimited shouldn't reach into backlog or error
        // components — only the drop_rate contributes.
        let b = bottleneck_with(BottleneckType::RateLimited, 0.5, 1_048_576, 1000);
        assert!((b.score() - 0.3).abs() < 1e-9, "got {}", b.score());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn test_issue_display() {
        let issue = Issue {
            severity: Severity::Warning,
            category: IssueCategory::HighPacketLoss,
            message: "5% packet loss".to_string(),
            details: Some("Check cable".to_string()),
            interface: Some("eth0".to_string()),
            timestamp: Instant::now(),
        };

        let s = format!("{}", issue);
        assert!(s.contains("eth0"));
        assert!(s.contains("5% packet loss"));
        assert!(s.contains("Check cable"));
    }

    /// The rates come from the one `LinkRates` (#525), in bytes per
    /// second with bits eight times that (#274), and only against a sample
    /// of the same link: another name at the ifindex is another link.
    #[test]
    fn rates_are_since_a_sample_of_the_same_link() {
        let t0 = Instant::now();
        let at = |bytes: u64, packets: u64| LinkStats {
            rx_bytes: bytes,
            rx_packets: packets,
            ..Default::default()
        };
        let prev: LinkSample = (t0, "eth0".into(), at(1000, 10));
        let now = t0 + std::time::Duration::from_secs(2);
        let (rates, back) = rates_since(Some(&prev), "eth0", &at(3_501_000, 30), now);
        assert_eq!(rates.rx_bytes_per_sec, 1_750_000.0);
        assert_eq!(rates.rx_bps(), 14_000_000.0);
        assert_eq!(rates.rx_packets_per_sec, 10.0);
        assert!(back.is_some());

        let (rates, back) = rates_since(Some(&prev), "eth1", &at(3_501_000, 30), now);
        assert_eq!(rates, LinkRates::default());
        assert!(
            back.is_none(),
            "another link's counters are not a previous sample"
        );
        // A counter that went backwards is a reset: no rate.
        let (rates, _) = rates_since(Some(&prev), "eth0", &at(10, 1), now);
        assert_eq!(rates, LinkRates::default());
    }

    #[test]
    fn test_config_defaults() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.packet_loss_threshold, 0.01);
        assert!(config.skip_loopback);
    }

    fn qdisc(kind: &str, packets: u64, drops: u32) -> TcMessage {
        use crate::netlink::messages::{TcStatsBasic, TcStatsQueue};
        let mut q = TcMessage::new();
        q.kind = Some(kind.to_string());
        q.stats_basic = Some(TcStatsBasic {
            bytes: packets * 1000,
            packets,
        });
        q.stats_queue = Some(TcStatsQueue {
            drops,
            ..Default::default()
        });
        q
    }

    /// #509: a qdisc's drop rate is out of the packets it was offered,
    /// sent and dropped, not of the sent alone; and netem's drops are its
    /// configured loss, reported as such rather than as a fault.
    #[tokio::test]
    async fn qdisc_drops_are_a_share_of_what_was_offered_and_netem_is_info() {
        let diag = Diagnostics::new(Connection::<Route>::new().expect("socket"));
        let issues = diag.detect_tc_issues(&qdisc("fq_codel", 50, 50), "eth0", Instant::now());
        let issue = issues
            .iter()
            .find(|i| i.category == IssueCategory::QdiscDrops)
            .unwrap();
        assert!(issue.message.contains("50.00%"), "{}", issue.message);
        assert_eq!(issue.severity, Severity::Warning);

        let issues = diag.detect_tc_issues(&qdisc("netem", 90, 10), "eth0", Instant::now());
        let issue = issues
            .iter()
            .find(|i| i.category == IssueCategory::QdiscDrops)
            .unwrap();
        assert_eq!(issue.severity, Severity::Info, "{}", issue.message);
        assert!(issue.message.contains("emulated loss"), "{}", issue.message);
    }

    /// #509: loss and error rates came from lifetime counters, so one old
    /// burst flagged an interface for as long as it existed. With a previous
    /// sample they are the interval's.
    #[tokio::test]
    async fn loss_is_measured_since_the_previous_sample() {
        let diag = Diagnostics::new(Connection::<Route>::new().expect("socket"));
        let link = crate::netlink::messages::LinkMessageBuilder::new()
            .ifindex(7)
            .name("eth7")
            .build();
        let stats = |packets: u64, dropped: u64| LinkStats {
            rx_packets: packets,
            rx_bytes: packets * 1000,
            rx_dropped: dropped,
            ..Default::default()
        };
        let lossy = |issues: &[Issue]| {
            issues
                .iter()
                .any(|i| i.category == IssueCategory::HighPacketLoss)
        };
        let none = HashMap::new();
        // A burst long ago: 5,000 drops in the first 10,000 packets.
        let then = stats(10_000, 5_000);
        // Since then: 100,000 clean packets.
        let now = stats(110_000, 5_000);
        assert!(lossy(&diag.detect_link_issues(
            &link,
            &now,
            None,
            &none,
            Instant::now()
        )));
        assert!(!lossy(&diag.detect_link_issues(
            &link,
            &now,
            Some(&then),
            &none,
            Instant::now()
        )));
        // Counters went backwards (the link was recreated): lifetime again.
        let fresh = stats(1_000, 500);
        assert!(lossy(&diag.detect_link_issues(
            &link,
            &fresh,
            Some(&now),
            &none,
            Instant::now()
        )));
    }
}
