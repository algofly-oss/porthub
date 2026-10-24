//! Ethtool response types.
//!
//! This module contains strongly-typed structures for ethtool query responses.

use std::collections::HashMap;

use super::EthtoolBitset;

// =============================================================================
// Common Types
// =============================================================================

/// Duplex mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Duplex {
    /// Half duplex.
    Half,
    /// Full duplex.
    Full,
    /// Unknown duplex.
    #[default]
    Unknown,
}

impl Duplex {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Duplex::Half,
            0x01 => Duplex::Full,
            _ => Duplex::Unknown,
        }
    }

    /// Convert to kernel value.
    pub fn to_u8(self) -> u8 {
        match self {
            Duplex::Half => 0x00,
            Duplex::Full => 0x01,
            Duplex::Unknown => 0xff,
        }
    }
}

/// Port type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Port {
    /// Twisted pair (RJ45).
    Tp,
    /// Attachment Unit Interface.
    Aui,
    /// Media Independent Interface.
    Mii,
    /// Fiber optic.
    Fibre,
    /// BNC connector.
    Bnc,
    /// Direct attach (copper SFP+).
    Da,
    /// No port.
    None,
    /// Other port type.
    #[default]
    Other,
}

impl Port {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Port::Tp,
            0x01 => Port::Aui,
            0x02 => Port::Mii,
            0x03 => Port::Fibre,
            0x04 => Port::Bnc,
            0x05 => Port::Da,
            0xef => Port::None,
            _ => Port::Other,
        }
    }
}

/// Transceiver type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Transceiver {
    /// Internal transceiver.
    Internal,
    /// External transceiver.
    External,
    /// Unknown transceiver.
    #[default]
    Unknown,
}

impl Transceiver {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Transceiver::Internal,
            0x01 => Transceiver::External,
            _ => Transceiver::Unknown,
        }
    }
}

/// MDI-X status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MdiX {
    /// MDI (straight-through).
    Mdi,
    /// MDI-X (crossover).
    MdiX,
    /// Auto MDI-X.
    Auto,
    /// Unknown.
    #[default]
    Unknown,
}

impl MdiX {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => MdiX::Mdi,
            0x01 => MdiX::MdiX,
            0x02 => MdiX::Auto,
            _ => MdiX::Unknown,
        }
    }
}

/// Extended link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LinkExtState {
    /// Link is up.
    #[default]
    Ok,
    /// Autonegotiation in progress.
    Autoneg,
    /// Link training failure.
    LinkTrainingFailure,
    /// Link logical mismatch.
    LinkLogicalMismatch,
    /// Bad signal integrity.
    BadSignalIntegrity,
    /// No cable.
    NoCable,
    /// Cable issue.
    CableIssue,
    /// EEPROM issue.
    EepromIssue,
    /// Calibration failure.
    CalibrationFailure,
    /// Power budget exceeded.
    PowerBudgetExceeded,
    /// Overheat.
    Overheat,
    /// Module not present.
    ModuleNotPresent,
}

impl LinkExtState {
    /// Parse from kernel value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => LinkExtState::Autoneg,
            2 => LinkExtState::LinkTrainingFailure,
            3 => LinkExtState::LinkLogicalMismatch,
            4 => LinkExtState::BadSignalIntegrity,
            5 => LinkExtState::NoCable,
            6 => LinkExtState::CableIssue,
            7 => LinkExtState::EepromIssue,
            8 => LinkExtState::CalibrationFailure,
            9 => LinkExtState::PowerBudgetExceeded,
            10 => LinkExtState::Overheat,
            11 => LinkExtState::ModuleNotPresent,
            _ => LinkExtState::Ok,
        }
    }
}

// =============================================================================
// Link State
// =============================================================================

/// Link state information.
///
/// Contains the current link status including carrier detection,
/// signal quality, and extended state information.
#[derive(Debug, Clone, Default)]
pub struct LinkState {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Link is detected (carrier present), or `None` when the driver
    /// cannot tell: one without `ethtool_ops::get_link`, such as a dummy,
    /// gets no `ETHTOOL_A_LINKSTATE_LINK`, and ethtool prints no "Link
    /// detected" (#839).
    pub link: Option<bool>,
    /// Signal Quality Index (0-100, if supported).
    pub sqi: Option<u32>,
    /// Maximum SQI value supported by the device.
    pub sqi_max: Option<u32>,
    /// Extended link state (reason for link down).
    pub ext_state: Option<LinkExtState>,
    /// Extended link substate (additional detail).
    pub ext_substate: Option<u8>,
}

// =============================================================================
// Link Info
// =============================================================================

/// Link information.
///
/// Contains physical layer information about the link.
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Physical port type.
    pub port: Option<Port>,
    /// PHY address.
    pub phyaddr: Option<u8>,
    /// MDI-X control setting.
    pub tp_mdix_ctrl: Option<MdiX>,
    /// Current MDI-X status.
    pub tp_mdix: Option<MdiX>,
    /// Transceiver type.
    pub transceiver: Option<Transceiver>,
}

// =============================================================================
// Link Modes
// =============================================================================

/// Link modes configuration.
///
/// Contains speed, duplex, and autonegotiation settings.
#[derive(Debug, Clone, Default)]
pub struct LinkModes {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Autonegotiation enabled.
    pub autoneg: bool,
    /// Current speed in Mb/s.
    pub speed: Option<u32>,
    /// Current duplex mode.
    pub duplex: Option<Duplex>,
    /// Number of lanes (for multi-lane links).
    pub lanes: Option<u32>,
    /// Master/slave configuration.
    pub master_slave_cfg: Option<u8>,
    /// Master/slave state.
    pub master_slave_state: Option<u8>,
    /// Supported link modes.
    pub supported: EthtoolBitset,
    /// Advertised link modes.
    pub advertised: EthtoolBitset,
    /// Peer's advertised link modes.
    pub peer: EthtoolBitset,
}

impl LinkModes {
    /// Check if a specific mode is supported.
    pub fn supports(&self, mode: &str) -> bool {
        self.supported.is_set(mode)
    }

    /// Check if a specific mode is advertised.
    pub fn advertises(&self, mode: &str) -> bool {
        self.advertised.is_set(mode)
    }

    /// Get list of supported mode names.
    pub fn supported_modes(&self) -> Vec<&str> {
        self.supported.active_names()
    }

    /// Get list of advertised mode names.
    pub fn advertised_modes(&self) -> Vec<&str> {
        self.advertised.active_names()
    }
}

/// Builder for setting link modes.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct LinkModesBuilder {
    pub(crate) autoneg: Option<bool>,
    pub(crate) speed: Option<u32>,
    pub(crate) duplex: Option<Duplex>,
    pub(crate) lanes: Option<u32>,
    pub(crate) advertised: Vec<String>,
}

impl LinkModesBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set autonegotiation on or off.
    pub fn autoneg(mut self, enabled: bool) -> Self {
        self.autoneg = Some(enabled);
        self
    }

    /// Set speed in Mb/s.
    pub fn speed(mut self, speed: u32) -> Self {
        self.speed = Some(speed);
        self
    }

    /// Set duplex mode.
    pub fn duplex(mut self, duplex: Duplex) -> Self {
        self.duplex = Some(duplex);
        self
    }

    /// Set number of lanes.
    pub fn lanes(mut self, lanes: u32) -> Self {
        self.lanes = Some(lanes);
        self
    }

    /// Advertise a specific link mode.
    pub fn advertise(mut self, mode: &str) -> Self {
        self.advertised.push(mode.to_string());
        self
    }

    /// Advertise multiple link modes.
    pub fn advertise_modes(mut self, modes: &[&str]) -> Self {
        for mode in modes {
            self.advertised.push((*mode).to_string());
        }
        self
    }
}

// =============================================================================
// Features
// =============================================================================

/// Device features (offloads).
///
/// Contains information about hardware and software features.
#[derive(Debug, Clone, Default)]
pub struct Features {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Hardware-supported features.
    pub hw: EthtoolBitset,
    /// Requested features.
    pub wanted: EthtoolBitset,
    /// Currently active features.
    pub active: EthtoolBitset,
    /// Features that cannot be changed.
    pub nochange: EthtoolBitset,
}

impl Features {
    /// Check if a feature is currently active.
    pub fn is_active(&self, feature: &str) -> bool {
        self.active.is_set(feature)
    }

    /// Check if a feature is supported by hardware.
    pub fn is_hw_supported(&self, feature: &str) -> bool {
        self.hw.is_set(feature)
    }

    /// Check if a feature can be changed: the device lists it in `hw`
    /// (its `hw_features`) and the kernel does not hold it fixed. ethtool
    /// marks the rest `[fixed]`; until #839 only the second half was
    /// checked.
    pub fn is_changeable(&self, feature: &str) -> bool {
        self.hw.is_set(feature) && !self.nochange.is_set(feature)
    }

    /// Get all active feature names.
    pub fn active_features(&self) -> Vec<&str> {
        self.active.active_names()
    }

    /// Iterate over all features with their status.
    pub fn iter(&self) -> impl Iterator<Item = (&str, bool)> {
        self.active.iter()
    }
}

/// Builder for setting features.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct FeaturesBuilder {
    pub(crate) enable: Vec<String>,
    pub(crate) disable: Vec<String>,
}

impl FeaturesBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a feature.
    pub fn enable(mut self, feature: &str) -> Self {
        self.enable.push(feature.to_string());
        self
    }

    /// Disable a feature.
    pub fn disable(mut self, feature: &str) -> Self {
        self.disable.push(feature.to_string());
        self
    }
}

// =============================================================================
// Rings
// =============================================================================

/// Ring buffer sizes.
///
/// Contains current and maximum ring buffer sizes for RX and TX.
#[derive(Debug, Clone, Default)]
pub struct Rings {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Maximum RX ring size.
    pub rx_max: Option<u32>,
    /// Maximum RX mini ring size.
    pub rx_mini_max: Option<u32>,
    /// Maximum RX jumbo ring size.
    pub rx_jumbo_max: Option<u32>,
    /// Maximum TX ring size.
    pub tx_max: Option<u32>,
    /// Current RX ring size.
    pub rx: Option<u32>,
    /// Current RX mini ring size.
    pub rx_mini: Option<u32>,
    /// Current RX jumbo ring size.
    pub rx_jumbo: Option<u32>,
    /// Current TX ring size.
    pub tx: Option<u32>,
    /// RX buffer length.
    pub rx_buf_len: Option<u32>,
    /// CQE size.
    pub cqe_size: Option<u32>,
    /// TX push enabled.
    pub tx_push: Option<bool>,
    /// RX push enabled.
    pub rx_push: Option<bool>,
}

/// Builder for setting ring sizes.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct RingsBuilder {
    pub(crate) rx: Option<u32>,
    pub(crate) rx_mini: Option<u32>,
    pub(crate) rx_jumbo: Option<u32>,
    pub(crate) tx: Option<u32>,
}

impl RingsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX ring size.
    pub fn rx(mut self, size: u32) -> Self {
        self.rx = Some(size);
        self
    }

    /// Set RX mini ring size.
    pub fn rx_mini(mut self, size: u32) -> Self {
        self.rx_mini = Some(size);
        self
    }

    /// Set RX jumbo ring size.
    pub fn rx_jumbo(mut self, size: u32) -> Self {
        self.rx_jumbo = Some(size);
        self
    }

    /// Set TX ring size.
    pub fn tx(mut self, size: u32) -> Self {
        self.tx = Some(size);
        self
    }
}

// =============================================================================
// Timestamping
// =============================================================================

/// What timestamping a device can do (`ethtool -T`, #166): which
/// `SO_TIMESTAMPING` flags a socket can ask of it, its hardware transmit
/// modes and receive filters, and its PTP clock.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Tsinfo {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// The `SOF_TIMESTAMPING_*` capabilities, by the kernel's names:
    /// `software-transmit`, `hardware-receive`, `software-system-clock`, ….
    pub timestamping: EthtoolBitset,
    /// The `HWTSTAMP_TX_*` modes: `off`, `on`, `onestep-sync`, ….
    pub tx_types: EthtoolBitset,
    /// The `HWTSTAMP_FILTER_*` receive filters: `none`, `all`,
    /// `ptpv2-event`, ….
    pub rx_filters: EthtoolBitset,
    /// The index of its PTP hardware clock (`/dev/ptp<n>`), if it has one.
    pub phc_index: Option<u32>,
}

// =============================================================================
// PHYs
// =============================================================================

/// One PHY on a link (`ethtool --show-phys`, kernel 6.12, #166). A link
/// can have several: a media converter in front of the PHY on the board,
/// a PHY on an SFP module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PhyInfo {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Its index on the link, which PHY-specific requests name it by.
    pub index: u32,
    /// Its driver's name.
    pub driver: Option<String>,
    /// Its device name.
    pub name: Option<String>,
    /// What it is attached to.
    pub upstream: Option<PhyUpstream>,
    /// The SFP bus it sits behind, when it is on an SFP module.
    pub upstream_sfp: Option<String>,
    /// The SFP cage it drives, if any.
    pub downstream_sfp: Option<String>,
}

/// What a PHY is attached to (`enum phy_upstream`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PhyUpstream {
    /// The MAC: a switch port or an Ethernet controller.
    Mac,
    /// Another PHY, by its index on the link: a media converter's.
    Phy {
        /// The upstream PHY's index.
        index: u32,
    },
    /// A kind of upstream newer than nlink, by the kernel's number.
    Other(u32),
}

// =============================================================================
// Channels
// =============================================================================

/// Channel counts.
///
/// Contains current and maximum channel (queue) counts.
#[derive(Debug, Clone, Default)]
pub struct Channels {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Maximum RX channels.
    pub rx_max: Option<u32>,
    /// Maximum TX channels.
    pub tx_max: Option<u32>,
    /// Maximum other channels.
    pub other_max: Option<u32>,
    /// Maximum combined channels.
    pub combined_max: Option<u32>,
    /// Current RX channels.
    pub rx_count: Option<u32>,
    /// Current TX channels.
    pub tx_count: Option<u32>,
    /// Current other channels.
    pub other_count: Option<u32>,
    /// Current combined channels.
    pub combined_count: Option<u32>,
}

/// Builder for setting channel counts.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct ChannelsBuilder {
    pub(crate) rx: Option<u32>,
    pub(crate) tx: Option<u32>,
    pub(crate) other: Option<u32>,
    pub(crate) combined: Option<u32>,
}

impl ChannelsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX channel count.
    pub fn rx(mut self, count: u32) -> Self {
        self.rx = Some(count);
        self
    }

    /// Set TX channel count.
    pub fn tx(mut self, count: u32) -> Self {
        self.tx = Some(count);
        self
    }

    /// Set other channel count.
    pub fn other(mut self, count: u32) -> Self {
        self.other = Some(count);
        self
    }

    /// Set combined channel count.
    pub fn combined(mut self, count: u32) -> Self {
        self.combined = Some(count);
        self
    }
}

// =============================================================================
// Coalesce
// =============================================================================

/// Interrupt coalescing parameters.
#[derive(Debug, Clone, Default)]
pub struct Coalesce {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// RX coalesce microseconds.
    pub rx_usecs: Option<u32>,
    /// RX max frames before interrupt.
    pub rx_max_frames: Option<u32>,
    /// RX coalesce microseconds (irq context).
    pub rx_usecs_irq: Option<u32>,
    /// RX max frames (irq context).
    pub rx_max_frames_irq: Option<u32>,
    /// TX coalesce microseconds.
    pub tx_usecs: Option<u32>,
    /// TX max frames before interrupt.
    pub tx_max_frames: Option<u32>,
    /// TX coalesce microseconds (irq context).
    pub tx_usecs_irq: Option<u32>,
    /// TX max frames (irq context).
    pub tx_max_frames_irq: Option<u32>,
    /// Stats block update microseconds.
    pub stats_block_usecs: Option<u32>,
    /// Use adaptive RX coalescing.
    pub use_adaptive_rx: Option<bool>,
    /// Use adaptive TX coalescing.
    pub use_adaptive_tx: Option<bool>,
    /// Packet rate low threshold.
    pub pkt_rate_low: Option<u32>,
    /// Packet rate high threshold.
    pub pkt_rate_high: Option<u32>,
    /// Rate sample interval.
    pub rate_sample_interval: Option<u32>,
}

/// Builder for setting coalescing parameters.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct CoalesceBuilder {
    pub(crate) rx_usecs: Option<u32>,
    pub(crate) rx_max_frames: Option<u32>,
    pub(crate) tx_usecs: Option<u32>,
    pub(crate) tx_max_frames: Option<u32>,
    pub(crate) use_adaptive_rx: Option<bool>,
    pub(crate) use_adaptive_tx: Option<bool>,
}

impl CoalesceBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set RX coalesce microseconds.
    pub fn rx_usecs(mut self, usecs: u32) -> Self {
        self.rx_usecs = Some(usecs);
        self
    }

    /// Set RX max frames before interrupt.
    pub fn rx_max_frames(mut self, frames: u32) -> Self {
        self.rx_max_frames = Some(frames);
        self
    }

    /// Set TX coalesce microseconds.
    pub fn tx_usecs(mut self, usecs: u32) -> Self {
        self.tx_usecs = Some(usecs);
        self
    }

    /// Set TX max frames before interrupt.
    pub fn tx_max_frames(mut self, frames: u32) -> Self {
        self.tx_max_frames = Some(frames);
        self
    }

    /// Enable or disable adaptive RX coalescing.
    pub fn use_adaptive_rx(mut self, enabled: bool) -> Self {
        self.use_adaptive_rx = Some(enabled);
        self
    }

    /// Enable or disable adaptive TX coalescing.
    pub fn use_adaptive_tx(mut self, enabled: bool) -> Self {
        self.use_adaptive_tx = Some(enabled);
        self
    }
}

// =============================================================================
// Pause
// =============================================================================

/// Pause/flow control settings.
#[derive(Debug, Clone, Default)]
pub struct Pause {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Autonegotiation of pause enabled.
    pub autoneg: Option<bool>,
    /// RX pause enabled.
    pub rx: Option<bool>,
    /// TX pause enabled.
    pub tx: Option<bool>,
    /// Pause statistics.
    pub stats: Option<PauseStats>,
}

/// Pause statistics.
#[derive(Debug, Clone, Default)]
pub struct PauseStats {
    /// TX pause frames sent.
    pub tx_frames: Option<u64>,
    /// RX pause frames received.
    pub rx_frames: Option<u64>,
}

/// Builder for setting pause parameters.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct PauseBuilder {
    pub(crate) autoneg: Option<bool>,
    pub(crate) rx: Option<bool>,
    pub(crate) tx: Option<bool>,
}

impl PauseBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set autonegotiation of pause.
    pub fn autoneg(mut self, enabled: bool) -> Self {
        self.autoneg = Some(enabled);
        self
    }

    /// Set RX pause.
    pub fn rx(mut self, enabled: bool) -> Self {
        self.rx = Some(enabled);
        self
    }

    /// Set TX pause.
    pub fn tx(mut self, enabled: bool) -> Self {
        self.tx = Some(enabled);
        self
    }
}

// =============================================================================
// Wake-on-LAN
// =============================================================================

/// Wake-on-LAN settings (`ethtool -w`/`-W`).
#[derive(Debug, Clone, Default)]
pub struct Wol {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// WoL modes the device supports (e.g. `magic`, `phy`).
    pub supported: Vec<String>,
    /// WoL modes currently active.
    pub active: Vec<String>,
    /// SecureOn password (`magicsecure`), if set.
    pub sopass: Option<[u8; 6]>,
}

/// Builder for setting Wake-on-LAN parameters.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct WolBuilder {
    /// Modes to enable (kernel `wol_mode_names`, e.g. `magic`, `phy`).
    pub(crate) modes: Vec<String>,
    /// Optional SecureOn password (6 bytes).
    pub(crate) sopass: Option<[u8; 6]>,
}

impl WolBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a WoL mode by name (one of the kernel `wol_mode_names`:
    /// `phy`, `ucast`, `mcast`, `bcast`, `arp`, `magic`,
    /// `magicsecure`, `filter`).
    pub fn mode(mut self, name: impl Into<String>) -> Self {
        self.modes.push(name.into());
        self
    }

    /// Set the modes from a slice, replacing any already added.
    pub fn modes<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.modes = names.into_iter().map(Into::into).collect();
        self
    }

    /// Set the SecureOn password (for `magicsecure`).
    pub fn sopass(mut self, sopass: [u8; 6]) -> Self {
        self.sopass = Some(sopass);
        self
    }
}

// =============================================================================
// Energy-Efficient Ethernet
// =============================================================================

/// Energy-Efficient Ethernet settings (`ethtool --show-eee`/`--set-eee`).
#[derive(Debug, Clone, Default)]
pub struct Eee {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Whether EEE is currently active on the link.
    pub active: Option<bool>,
    /// Whether EEE is administratively enabled.
    pub enabled: Option<bool>,
    /// Whether TX low-power idle is enabled.
    pub tx_lpi_enabled: Option<bool>,
    /// TX low-power-idle timer, in microseconds.
    pub tx_lpi_timer: Option<u32>,
    /// Link modes we advertise EEE on.
    pub advertised: Vec<String>,
    /// Link modes the peer advertises EEE on.
    pub peer: Vec<String>,
}

/// Builder for setting Energy-Efficient Ethernet parameters.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct EeeBuilder {
    pub(crate) enabled: Option<bool>,
    pub(crate) tx_lpi_enabled: Option<bool>,
    pub(crate) tx_lpi_timer: Option<u32>,
}

impl EeeBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Administratively enable or disable EEE.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// Enable or disable TX low-power idle.
    pub fn tx_lpi_enabled(mut self, enabled: bool) -> Self {
        self.tx_lpi_enabled = Some(enabled);
        self
    }

    /// Set the TX low-power-idle timer (microseconds).
    pub fn tx_lpi_timer(mut self, usecs: u32) -> Self {
        self.tx_lpi_timer = Some(usecs);
        self
    }
}

// =============================================================================
// Forward Error Correction
// =============================================================================

/// Forward Error Correction settings (`ethtool --show-fec`).
#[derive(Debug, Clone, Default)]
pub struct Fec {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Configured FEC modes (kernel-labelled names, e.g. `None`, `RS`,
    /// `BASER`, `LLRS`).
    pub modes: Vec<String>,
    /// Whether the FEC mode is auto-negotiated.
    pub auto: Option<bool>,
    /// Active FEC mode as the raw `ETHTOOL_LINK_MODE_FEC_*` bit (0 if
    /// none/unreported). Exposed raw to avoid mismodelling the kernel's
    /// link-mode numbering.
    pub active: Option<u32>,
}

/// Builder for setting Forward Error Correction parameters
/// (`ethtool --set-fec`).
///
/// FEC mode names are the kernel-labelled bitset names — the same
/// strings [`Fec::modes`] reports for the device (e.g. `None`, `RS`,
/// `BASER`, `LLRS`, `Off`). Passing the names `get_fec` returns is
/// correct by construction; common lowercase spellings (`off`, `none`,
/// `rs`, `baser`, `llrs`) are normalised to the canonical forms.
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct FecBuilder {
    pub(crate) modes: Vec<String>,
    pub(crate) auto: Option<bool>,
}

impl FecBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a FEC mode by name. May be called multiple times to
    /// enable several encodings; names are normalised
    /// (`off`→`Off`, `rs`→`RS`, `baser`→`BASER`, `llrs`→`LLRS`,
    /// `none`→`None`) and otherwise passed through verbatim so device
    /// reported names always work.
    pub fn mode(mut self, name: &str) -> Self {
        self.modes.push(Self::normalise_mode(name));
        self
    }

    /// Enable or disable FEC auto-negotiation.
    pub fn auto(mut self, on: bool) -> Self {
        self.auto = Some(on);
        self
    }

    fn normalise_mode(name: &str) -> String {
        match name.to_ascii_lowercase().as_str() {
            "off" => "Off".to_string(),
            "none" => "None".to_string(),
            "rs" => "RS".to_string(),
            "baser" => "BASER".to_string(),
            "llrs" => "LLRS".to_string(),
            _ => name.to_string(),
        }
    }
}

// =============================================================================
// Module EEPROM
// =============================================================================

/// A request to read bytes from an SFP/QSFP module's EEPROM.
///
/// A single read is bounded to one 128-byte page at one I2C address.
/// Use [`ModuleEepromRequest::new`] then the setters for non-default
/// page/bank/address (e.g. page 1 at I2C `0x51` for diagnostics).
#[derive(Debug, Clone)]
#[must_use = "build a request then pass it to get_module_eeprom"]
pub struct ModuleEepromRequest {
    /// Byte offset within the page (0..=255).
    pub offset: u32,
    /// Number of bytes to read (1..=128).
    pub length: u32,
    /// Page number.
    pub page: u8,
    /// Bank number.
    pub bank: u8,
    /// I2C address (`0x50` lower / `0x51` upper).
    pub i2c_address: u8,
}

impl ModuleEepromRequest {
    /// A read of `length` bytes from `offset` on page 0, bank 0, at the
    /// standard lower I2C address `0x50`.
    pub fn new(offset: u32, length: u32) -> Self {
        Self {
            offset,
            length,
            page: 0,
            bank: 0,
            i2c_address: 0x50,
        }
    }

    /// Set the page number.
    pub fn page(mut self, page: u8) -> Self {
        self.page = page;
        self
    }

    /// Set the bank number.
    pub fn bank(mut self, bank: u8) -> Self {
        self.bank = bank;
        self
    }

    /// Set the I2C address (`0x50` / `0x51`).
    pub fn i2c_address(mut self, addr: u8) -> Self {
        self.i2c_address = addr;
        self
    }
}

/// Raw bytes read from a module EEPROM (`ethtool -m`).
#[derive(Debug, Clone, Default)]
pub struct ModuleEeprom {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// The EEPROM bytes returned by the device.
    pub data: Vec<u8>,
}

// =============================================================================
// Receive Side Scaling (RSS)
// =============================================================================

/// Receive Side Scaling configuration (`ethtool -x`).
#[derive(Debug, Clone, Default)]
pub struct Rss {
    /// Interface name.
    pub ifname: Option<String>,
    /// Interface index.
    pub ifindex: Option<u32>,
    /// RSS context id (`None` for the default context).
    pub context: Option<u32>,
    /// Hash-function bitmask, raw (`ETHTOOL_A_RSS_HFUNC`). Exposed raw —
    /// the bit-to-name mapping lives in the device's
    /// `ETH_SS_RSS_HASH_FUNCS` string set.
    pub hfunc: Option<u32>,
    /// The RSS indirection table: each entry is a receive-queue index.
    pub indirection_table: Vec<u32>,
    /// The RSS hash key bytes.
    pub hash_key: Vec<u8>,
}

// =============================================================================
// String Sets
// =============================================================================

/// A string set from the device.
#[derive(Debug, Clone, Default)]
pub struct StringSet {
    /// String set ID.
    pub id: u32,
    /// Strings in the set, indexed by position.
    pub strings: HashMap<u32, String>,
}

impl StringSet {
    /// Get a string by index.
    pub fn get(&self, index: u32) -> Option<&str> {
        self.strings.get(&index).map(|s| s.as_str())
    }

    /// Get all strings as a vector.
    pub fn to_vec(&self) -> Vec<&str> {
        let mut result: Vec<_> = self.strings.iter().collect();
        result.sort_by_key(|(idx, _)| *idx);
        result.into_iter().map(|(_, s)| s.as_str()).collect()
    }
}

// =============================================================================
// Events
// =============================================================================

/// Ethtool event received from the monitor multicast group.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EthtoolEvent {
    /// Link info changed.
    LinkInfoChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link info.
        info: LinkInfo,
    },
    /// Link modes changed.
    LinkModesChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link modes.
        modes: LinkModes,
    },
    /// Link state changed.
    LinkStateChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New link state.
        state: LinkState,
    },
    /// Features changed.
    FeaturesChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New features.
        features: Features,
    },
    /// Ring sizes changed.
    RingsChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New ring sizes.
        rings: Rings,
    },
    /// Channel counts changed.
    ChannelsChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New channel counts.
        channels: Channels,
    },
    /// Coalesce parameters changed.
    CoalesceChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New coalesce parameters.
        coalesce: Coalesce,
    },
    /// Pause settings changed.
    PauseChanged {
        /// Interface name.
        ifname: Option<String>,
        /// New pause settings.
        pause: Pause,
    },
    /// Unknown or unhandled event.
    Unknown {
        /// Command that generated this event.
        cmd: u8,
    },
}

/// One standardized statistics group's values, keyed by the kernel's
/// per-group stat index. Use [`StatGroup::get`] with the index
/// constants in [`super::stats_index`], or iterate `values`
/// directly.
#[derive(Debug, Clone, Default)]
pub struct StatGroup {
    /// Stat index → counter value. Indices are the kernel's
    /// per-group `ETHTOOL_A_STATS_<GROUP>_*` enum positions.
    pub values: std::collections::BTreeMap<u32, u64>,
}

impl StatGroup {
    /// Look up a stat by its per-group index.
    pub fn get(&self, index: u32) -> Option<u64> {
        self.values.get(&index).copied()
    }

    /// `true` if the group carried no stats.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Standardized device statistics (`ethtool -S --groups …`), returned
/// by [`Connection::get_eth_stats`](crate::netlink::Connection::get_eth_stats).
///
/// Only the IEEE-802.3 / RMON standardized groups are exposed —
/// these are the stable, driver-independent counters available over
/// the ethtool netlink API. A group is `None` if the device didn't
/// report it.
#[derive(Debug, Clone, Default)]
pub struct EthtoolStats {
    /// Interface name, if echoed back in the reply header.
    pub ifname: Option<String>,
    /// Interface index, if echoed back in the reply header.
    pub ifindex: Option<u32>,
    /// IEEE 802.3 PHY stats.
    pub eth_phy: Option<StatGroup>,
    /// IEEE 802.3 MAC stats.
    pub eth_mac: Option<StatGroup>,
    /// IEEE 802.3 MAC-control stats.
    pub eth_ctrl: Option<StatGroup>,
    /// RMON (RFC 2819) stats.
    pub rmon: Option<StatGroup>,
}

/// Per-group stat index constants for the well-known standardized
/// counters (`ETHTOOL_A_STATS_<GROUP>_*` positions). Pass these to
/// [`StatGroup::get`]. Drivers may report additional indices not
/// named here; those are preserved in [`StatGroup::values`].
pub mod stats_index {
    /// eth-mac: frames transmitted OK.
    pub const ETH_MAC_TX_PKT: u32 = 0;
    /// eth-mac: frames received OK.
    pub const ETH_MAC_RX_PKT: u32 = 3;
    /// eth-mac: frame-check-sequence errors.
    pub const ETH_MAC_FCS_ERR: u32 = 4;
    /// eth-mac: octets transmitted OK.
    pub const ETH_MAC_TX_BYTES: u32 = 6;
    /// eth-mac: octets received OK.
    pub const ETH_MAC_RX_BYTES: u32 = 12;
    /// eth-mac: multicast frames transmitted OK.
    pub const ETH_MAC_TX_MCAST: u32 = 14;
    /// eth-mac: broadcast frames transmitted OK.
    pub const ETH_MAC_TX_BCAST: u32 = 15;
    /// eth-mac: multicast frames received OK.
    pub const ETH_MAC_RX_MCAST: u32 = 17;
    /// eth-mac: broadcast frames received OK.
    pub const ETH_MAC_RX_BCAST: u32 = 18;

    /// eth-ctrl: MAC-control frames transmitted.
    pub const ETH_CTRL_TX: u32 = 0;
    /// eth-ctrl: MAC-control frames received.
    pub const ETH_CTRL_RX: u32 = 1;
    /// eth-ctrl: unsupported MAC-control frames received.
    pub const ETH_CTRL_RX_UNSUP: u32 = 2;

    /// rmon: undersized packets.
    pub const RMON_UNDERSIZE: u32 = 0;
    /// rmon: oversized packets.
    pub const RMON_OVERSIZE: u32 = 1;
    /// rmon: fragments.
    pub const RMON_FRAG: u32 = 2;
    /// rmon: jabbers.
    pub const RMON_JABBER: u32 = 3;
}

/// Human-readable name for a `(group_id, stat_index)` pair, for the
/// well-known standardized counters. Returns `None` for indices not
/// named in [`stats_index`] (callers can fall back to the numeric
/// index).
pub fn standard_stat_name(group_id: u32, index: u32) -> Option<&'static str> {
    use super::stats_group::*;
    use stats_index::*;
    Some(match (group_id, index) {
        (ETH_MAC, ETH_MAC_TX_PKT) => "tx-packets",
        (ETH_MAC, ETH_MAC_RX_PKT) => "rx-packets",
        (ETH_MAC, ETH_MAC_FCS_ERR) => "fcs-errors",
        (ETH_MAC, ETH_MAC_TX_BYTES) => "tx-bytes",
        (ETH_MAC, ETH_MAC_RX_BYTES) => "rx-bytes",
        (ETH_MAC, ETH_MAC_TX_MCAST) => "tx-multicast",
        (ETH_MAC, ETH_MAC_TX_BCAST) => "tx-broadcast",
        (ETH_MAC, ETH_MAC_RX_MCAST) => "rx-multicast",
        (ETH_MAC, ETH_MAC_RX_BCAST) => "rx-broadcast",
        (ETH_CTRL, ETH_CTRL_TX) => "tx-control",
        (ETH_CTRL, ETH_CTRL_RX) => "rx-control",
        (ETH_CTRL, ETH_CTRL_RX_UNSUP) => "rx-control-unsupported",
        (RMON, RMON_UNDERSIZE) => "undersize",
        (RMON, RMON_OVERSIZE) => "oversize",
        (RMON, RMON_FRAG) => "fragments",
        (RMON, RMON_JABBER) => "jabbers",
        _ => return None,
    })
}
