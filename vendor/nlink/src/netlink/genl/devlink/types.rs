//! Devlink data types.

use crate::netlink::error::{Error, Result};

/// Devlink port type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum PortType {
    NotSet = 0,
    Auto = 1,
    Eth = 2,
    Ib = 3,
}

impl TryFrom<u16> for PortType {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::NotSet),
            1 => Ok(Self::Auto),
            2 => Ok(Self::Eth),
            3 => Ok(Self::Ib),
            _ => Err(Error::invalid_attribute(format!(
                "unknown devlink port type: {value}"
            ))),
        }
    }
}

/// Devlink port flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum PortFlavour {
    Physical = 0,
    Cpu = 1,
    Dsa = 2,
    PciPf = 3,
    PciVf = 4,
    Virtual = 5,
    /// A port that exists in the switch but is not used.
    ///
    /// nlink omitted this, so `PciSf` claimed 6 — the kernel's `UNUSED` — and
    /// an unused port decoded as a PCI subfunction (#231).
    Unused = 6,
    /// PCI subfunction.
    PciSf = 7,
}

impl TryFrom<u16> for PortFlavour {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Physical),
            1 => Ok(Self::Cpu),
            2 => Ok(Self::Dsa),
            3 => Ok(Self::PciPf),
            4 => Ok(Self::PciVf),
            5 => Ok(Self::Virtual),
            6 => Ok(Self::Unused),
            7 => Ok(Self::PciSf),
            _ => Err(Error::invalid_attribute(format!(
                "unknown devlink port flavour: {value}"
            ))),
        }
    }
}

/// Health reporter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum HealthState {
    Healthy = 0,
    Error = 1,
}

impl TryFrom<u8> for HealthState {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Healthy),
            1 => Ok(Self::Error),
            _ => Err(Error::invalid_attribute(format!(
                "unknown health state: {value}"
            ))),
        }
    }
}

/// Configuration mode for device parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ConfigMode {
    Runtime = 0,
    Driverinit = 1,
    Permanent = 2,
}

impl TryFrom<u8> for ConfigMode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Runtime),
            1 => Ok(Self::Driverinit),
            2 => Ok(Self::Permanent),
            _ => Err(Error::invalid_attribute(format!(
                "unknown config mode: {value}"
            ))),
        }
    }
}

/// A devlink device (typically a NIC or switch ASIC).
#[derive(Debug, Clone)]
pub struct DevlinkDevice {
    /// Bus name (e.g., "pci", "auxiliary").
    pub bus: String,
    /// Device name (e.g., "0000:03:00.0").
    pub device: String,
}

impl DevlinkDevice {
    /// Format as "bus/device" (e.g., "pci/0000:03:00.0").
    pub fn path(&self) -> String {
        format!("{}/{}", self.bus, self.device)
    }
}

/// Device information including driver and firmware versions.
#[derive(Debug, Clone)]
pub struct DevlinkInfo {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Driver name (e.g., "mlx5_core", "ice").
    pub driver: String,
    /// Device serial number.
    pub serial: Option<String>,
    /// Board serial number.
    pub board_serial: Option<String>,
    /// Fixed (hardware) version information.
    pub versions_fixed: Vec<VersionInfo>,
    /// Running (loaded) firmware versions.
    pub versions_running: Vec<VersionInfo>,
    /// Stored (on-flash) firmware versions.
    pub versions_stored: Vec<VersionInfo>,
}

impl DevlinkInfo {
    /// Get a specific running firmware version by name.
    pub fn running_version(&self, name: &str) -> Option<&str> {
        self.versions_running
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }

    /// Get a specific fixed (hardware) version by name.
    pub fn fixed_version(&self, name: &str) -> Option<&str> {
        self.versions_fixed
            .iter()
            .find(|v| v.name == name)
            .map(|v| v.value.as_str())
    }

    /// Check if there's a pending firmware update (stored != running).
    pub fn has_pending_update(&self) -> bool {
        for stored in &self.versions_stored {
            if let Some(running) = self.running_version(&stored.name)
                && running != stored.value
            {
                return true;
            }
        }
        false
    }
}

/// Firmware or hardware version information.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Version component name (e.g., "fw.mgmt", "fw.undi", "board.id").
    pub name: String,
    /// Version value (e.g., "22.31.1014", "1.2881.0").
    pub value: String,
}

/// A devlink port representing a physical or virtual port.
#[derive(Debug, Clone)]
pub struct DevlinkPort {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Port index (unique per device).
    pub index: u32,
    /// Port type.
    pub port_type: PortType,
    /// Network device interface index (if mapped).
    pub netdev_ifindex: Option<u32>,
    /// Network device name (if mapped).
    pub netdev_name: Option<String>,
    /// InfiniBand device name (if IB port).
    pub ibdev_name: Option<String>,
    /// Port flavour.
    pub flavour: Option<PortFlavour>,
    /// Physical port number.
    pub number: Option<u32>,
    /// Split sub-port number.
    pub split_subport: Option<u32>,
    /// Split group.
    pub split_group: Option<u32>,
    /// PCI PF number (for PF/VF/SF flavours).
    pub pci_pf: Option<u16>,
    /// PCI VF number (for VF flavour).
    pub pci_vf: Option<u16>,
    /// PCI SF number (for SF flavour).
    pub pci_sf: Option<u32>,
    /// Controller number (for multi-host).
    pub controller: Option<u32>,
}

impl DevlinkPort {
    /// Format the port path as "bus/device/port_index".
    pub fn path(&self) -> String {
        format!("{}/{}/{}", self.bus, self.device, self.index)
    }

    /// Whether this port is mapped to a netdev.
    pub fn has_netdev(&self) -> bool {
        self.netdev_ifindex.is_some()
    }

    /// Whether this is a physical port.
    pub fn is_physical(&self) -> bool {
        self.flavour == Some(PortFlavour::Physical)
    }

    /// Whether this is a PCI VF representor.
    pub fn is_vf_representor(&self) -> bool {
        self.flavour == Some(PortFlavour::PciVf)
    }

    /// Whether this is a PCI SF representor.
    pub fn is_sf_representor(&self) -> bool {
        self.flavour == Some(PortFlavour::PciSf)
    }
}

/// Health reporter status.
#[derive(Debug, Clone)]
pub struct HealthReporter {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Reporter name (e.g., "fw", "fw_fatal", "tx").
    pub name: String,
    /// Current state.
    pub state: HealthState,
    /// Total number of errors detected.
    pub error_count: u64,
    /// Total number of recovery attempts.
    pub recover_count: u64,
    /// Whether automatic recovery is enabled.
    pub auto_recover: bool,
    /// Whether automatic dump on error is enabled.
    pub auto_dump: bool,
    /// Graceful period between recoveries in milliseconds.
    pub graceful_period_ms: Option<u64>,
    /// Timestamp of last dump (jiffies).
    pub dump_ts_jiffies: Option<u64>,
    /// The port whose reporter it is (`DEVLINK_ATTR_PORT_INDEX`); `None`
    /// for the device's own (#777).
    pub port: Option<u32>,
}

impl HealthReporter {
    /// Whether this reporter is in error state.
    pub fn is_error(&self) -> bool {
        self.state == HealthState::Error
    }

    /// Whether this reporter has had any errors.
    pub fn has_errors(&self) -> bool {
        self.error_count > 0
    }
}

/// Device parameter with its current values across configuration modes.
#[derive(Debug, Clone)]
pub struct DevlinkParam {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Parameter name (e.g., "enable_sriov", "fw_load_policy").
    pub name: String,
    /// Whether this is a generic (driver-independent) parameter.
    pub generic: bool,
    /// Current values for each configuration mode.
    pub values: Vec<ParamValue>,
}

/// A parameter value in a specific configuration mode.
#[derive(Debug, Clone)]
pub struct ParamValue {
    /// Configuration mode (runtime, driverinit, permanent).
    pub cmode: ConfigMode,
    /// The value (type depends on param_type).
    pub data: ParamData,
}

/// Parameter data variants.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ParamData {
    U8(u8),
    U16(u16),
    U32(u32),
    String(String),
    Bool(bool),
}

impl std::fmt::Display for ParamData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamData::U8(v) => write!(f, "{v}"),
            ParamData::U16(v) => write!(f, "{v}"),
            ParamData::U32(v) => write!(f, "{v}"),
            ParamData::String(v) => write!(f, "{v}"),
            ParamData::Bool(v) => write!(f, "{v}"),
        }
    }
}

impl ParamData {
    /// Get the devlink param type ID.
    pub(crate) fn type_id(&self) -> u8 {
        match self {
            ParamData::U8(_) => 1,
            ParamData::U16(_) => 2,
            ParamData::U32(_) => 3,
            ParamData::String(_) => 5,
            ParamData::Bool(_) => 6,
        }
    }

    /// Serialize the value to bytes.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            ParamData::U8(v) => vec![*v],
            ParamData::U16(v) => v.to_ne_bytes().to_vec(),
            ParamData::U32(v) => v.to_ne_bytes().to_vec(),
            ParamData::String(v) => {
                let mut bytes = v.as_bytes().to_vec();
                bytes.push(0);
                bytes
            }
            ParamData::Bool(v) => vec![u8::from(*v)],
        }
    }
}

/// Devlink event received from the multicast group.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DevlinkEvent {
    /// New devlink device appeared.
    NewDevice {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
    },
    /// Devlink device removed.
    DelDevice {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
    },
    /// New devlink port appeared.
    NewPort {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Port index.
        port_index: u32,
        /// Network device name (if mapped).
        netdev_name: Option<String>,
    },
    /// Devlink port removed.
    DelPort {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Port index.
        port_index: u32,
    },
    /// Health reporter state changed.
    HealthEvent {
        /// Bus name.
        bus: String,
        /// Device name.
        device: String,
        /// Reporter name.
        reporter: Option<String>,
    },
    /// Flash update progress notification.
    FlashUpdate(FlashProgress),
}

/// Flash update progress notification.
///
/// Received via devlink multicast events during a firmware flash operation.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::genl::devlink::FlashProgress;
///
/// let progress = FlashProgress {
///     message: Some("Flashing firmware".into()),
///     component: Some("fw.mgmt".into()),
///     done: 50,
///     total: 100,
/// };
/// assert_eq!(progress.percent(), 50.0);
/// assert!(!progress.is_complete());
/// ```
#[derive(Debug, Clone)]
pub struct FlashProgress {
    /// Status message from the driver.
    pub message: Option<String>,
    /// Component being flashed.
    pub component: Option<String>,
    /// Bytes/units completed.
    pub done: u64,
    /// Total bytes/units.
    pub total: u64,
}

impl FlashProgress {
    /// Progress as a percentage (0.0 to 100.0).
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.done as f64 / self.total as f64) * 100.0
        }
    }

    /// Whether the flash operation is complete.
    pub fn is_complete(&self) -> bool {
        self.total > 0 && self.done >= self.total
    }
}

/// Reload action for `reload()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ReloadAction {
    /// Reload the driver.
    DriverReinit = 1,
    /// Activate stored firmware.
    FwActivate = 2,
}

/// Flash update request builder.
#[derive(Debug, Clone)]
pub struct FlashRequest {
    /// Path to firmware file.
    pub file_name: String,
    /// Optional component to flash (e.g., "fw.mgmt").
    pub component: Option<String>,
}

impl FlashRequest {
    /// Create a new flash request for the given firmware file.
    pub fn new(file_name: impl Into<String>) -> Self {
        Self {
            file_name: file_name.into(),
            component: None,
        }
    }

    /// Flash only a specific component.
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }
}

// =============================================================================
// Devlink rate (Plan 153.2) — SR-IOV VF + node rate-limiting via devlink-rate
// =============================================================================

/// Devlink rate-object type — leaf (terminal, applies to a VF or
/// PF) or node (internal scheduler node grouping leaves).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevlinkRateType {
    /// Terminal rate object — applies to a specific port-function
    /// (typically an SR-IOV VF or PF).
    Leaf,
    /// Internal scheduler node — groups leaves into a rate
    /// hierarchy. Useful for shared-link-aggregation rate
    /// management.
    Node,
}

impl DevlinkRateType {
    /// Kernel wire value (`DEVLINK_RATE_TYPE_*`).
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Leaf => super::DEVLINK_RATE_TYPE_LEAF,
            Self::Node => super::DEVLINK_RATE_TYPE_NODE,
        }
    }
}

/// Port-function state — controls whether the function's
/// underlying resource (typically an SR-IOV VF) is active. Sent
/// via `Connection::<Devlink>::set_port_function_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevlinkPortFunctionState {
    /// Function is allocated but the underlying VF is not
    /// presented to the kernel — useful for stopping traffic on
    /// a VF without tearing it down.
    Inactive,
    /// Function is presented and operational.
    Active,
}

impl DevlinkPortFunctionState {
    /// Kernel wire value (`DEVLINK_PORT_FN_STATE_*`).
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Inactive => super::DEVLINK_PORT_FN_STATE_INACTIVE,
            Self::Active => super::DEVLINK_PORT_FN_STATE_ACTIVE,
        }
    }
}

/// A devlink rate object — terminal-leaf or scheduler-node.
///
/// Cloud + SmartNIC users use these to rate-limit SR-IOV VFs at
/// the kernel/firmware boundary (vs in the guest's TC stack).
///
/// Construct via [`Self::new`] + fluent setters; install via
/// [`super::super::super::Connection::<Devlink>::add_rate`]
/// (`Connection<Devlink>::add_rate(&rate)`).
#[derive(Debug, Clone)]
pub struct DevlinkRate {
    /// Bus identifier (e.g., `"pci"`).
    pub bus_name: String,
    /// Device identifier (e.g., `"0000:01:00.0"`).
    pub device_name: String,
    /// Rate-object node name (caller-chosen).
    pub node_name: String,
    /// Parent scheduler node, if this rate is grouped under one.
    pub parent_node: Option<String>,
    /// Guaranteed bandwidth share in **bytes/second** (kernel
    /// units — pair with [`crate::Rate`]'s `bytes_per_sec()`).
    pub tx_share: Option<u64>,
    /// Maximum bandwidth cap in bytes/second.
    pub tx_max: Option<u64>,
    /// Rate-object type (leaf vs node).
    pub rate_type: DevlinkRateType,
}

impl DevlinkRate {
    /// New rate-object builder. Defaults to `Leaf` type; call
    /// `.rate_type(DevlinkRateType::Node)` to build a scheduler
    /// node instead.
    pub fn new(
        bus_name: impl Into<String>,
        device_name: impl Into<String>,
        node_name: impl Into<String>,
    ) -> Self {
        Self {
            bus_name: bus_name.into(),
            device_name: device_name.into(),
            node_name: node_name.into(),
            parent_node: None,
            tx_share: None,
            tx_max: None,
            rate_type: DevlinkRateType::Leaf,
        }
    }

    /// Set the rate-object type. Default is `Leaf`.
    pub fn rate_type(mut self, t: DevlinkRateType) -> Self {
        self.rate_type = t;
        self
    }

    /// Guaranteed-share rate in bytes/sec. Accepts an
    /// [`crate::Rate`] to keep the unit story straight.
    pub fn tx_share(mut self, rate: crate::Rate) -> Self {
        self.tx_share = Some(rate.as_bytes_per_sec());
        self
    }

    /// Maximum-cap rate in bytes/sec.
    pub fn tx_max(mut self, rate: crate::Rate) -> Self {
        self.tx_max = Some(rate.as_bytes_per_sec());
        self
    }

    /// Group this rate object under a parent scheduler node.
    pub fn parent_node(mut self, name: impl Into<String>) -> Self {
        self.parent_node = Some(name.into());
        self
    }
}

/// A devlink shared-buffer instance (`devlink sb show`).
#[derive(Debug, Clone)]
pub struct SharedBuffer {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Shared-buffer index.
    pub index: u32,
    /// Total buffer size in bytes.
    pub size: u32,
    /// Number of ingress pools.
    pub ingress_pools: u32,
    /// Number of egress pools.
    pub egress_pools: u32,
    /// Number of ingress traffic classes.
    pub ingress_tcs: u32,
    /// Number of egress traffic classes.
    pub egress_tcs: u32,
}

/// Action a packet trap takes when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrapAction {
    /// Silently drop.
    Drop,
    /// Trap to the CPU.
    Trap,
    /// Mirror to the CPU while forwarding.
    Mirror,
    /// Unknown action value (forward-compat).
    Unknown(u8),
}

impl TrapAction {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            TrapAction::Drop => "drop",
            TrapAction::Trap => "trap",
            TrapAction::Mirror => "mirror",
            TrapAction::Unknown(_) => "unknown",
        }
    }
}

/// Classification of a packet trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrapType {
    /// Drop trap.
    Drop,
    /// Exception trap.
    Exception,
    /// Control trap.
    Control,
    /// Unknown type value (forward-compat).
    Unknown(u8),
}

impl TrapType {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            TrapType::Drop => "drop",
            TrapType::Exception => "exception",
            TrapType::Control => "control",
            TrapType::Unknown(_) => "unknown",
        }
    }
}

/// A devlink packet trap (`devlink trap show`).
#[derive(Debug, Clone)]
pub struct DevlinkTrap {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Trap name.
    pub name: String,
    /// Action taken when the trap fires.
    pub action: TrapAction,
    /// Trap classification.
    pub trap_type: TrapType,
    /// `true` for a kernel-generic trap.
    pub generic: bool,
    /// Owning trap group, if reported.
    pub group: Option<String>,
}

/// A devlink hardware resource (`devlink resource show`).
///
/// Resources form a tree; [`name`](Self::name) is the full
/// slash-joined path from the root (e.g. `"kvd/linear"`).
#[derive(Debug, Clone)]
pub struct DevlinkResource {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Slash-joined resource path.
    pub name: String,
    /// Resource ID.
    pub id: u64,
    /// Configured size.
    pub size: u64,
    /// Current occupancy, if the driver reports it.
    pub occ: Option<u64>,
    /// `true` if `size` reflects a valid (driver-acked) value.
    pub size_valid: bool,
}

/// A devlink address region (`devlink region show`).
#[derive(Debug, Clone)]
pub struct DevlinkRegion {
    /// Bus name.
    pub bus: String,
    /// Device name.
    pub device: String,
    /// Region name.
    pub name: String,
    /// Region size in bytes, if reported.
    pub size: Option<u64>,
    /// Number of snapshots currently held.
    pub snapshot_count: usize,
}

#[cfg(test)]
mod rate_tests {
    use super::*;

    #[test]
    fn devlink_rate_type_wire_values() {
        assert_eq!(DevlinkRateType::Leaf.as_u16(), 0);
        assert_eq!(DevlinkRateType::Node.as_u16(), 1);
    }

    #[test]
    fn devlink_port_function_state_wire_values() {
        assert_eq!(DevlinkPortFunctionState::Inactive.as_u8(), 0);
        assert_eq!(DevlinkPortFunctionState::Active.as_u8(), 1);
    }

    #[test]
    fn devlink_rate_builder_composition() {
        use crate::Rate;
        let r = DevlinkRate::new("pci", "0000:01:00.0", "vf0_rate")
            .rate_type(DevlinkRateType::Leaf)
            .tx_share(Rate::mbit(100))
            .tx_max(Rate::gbit(1))
            .parent_node("group_a");
        assert_eq!(r.bus_name, "pci");
        assert_eq!(r.device_name, "0000:01:00.0");
        assert_eq!(r.node_name, "vf0_rate");
        assert_eq!(r.rate_type, DevlinkRateType::Leaf);
        // Rate::mbit(100) = 100 Mbit/s = 12_500_000 bytes/s.
        assert_eq!(r.tx_share, Some(12_500_000));
        // Rate::gbit(1) = 1 Gbit/s = 125_000_000 bytes/s.
        assert_eq!(r.tx_max, Some(125_000_000));
        assert_eq!(r.parent_node.as_deref(), Some("group_a"));
    }
}
