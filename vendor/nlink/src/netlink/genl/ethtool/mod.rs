//! Ethtool configuration via Generic Netlink.
//!
//! This module provides an API for querying and configuring network device
//! settings using the kernel's ethtool netlink interface (available since
//! Linux 5.6).
//!
//! # Overview
//!
//! Ethtool provides access to:
//! - Link state (up/down, speed, duplex)
//! - Link modes (autonegotiation, advertised speeds)
//! - Device features (offloads, checksumming)
//! - Ring buffer sizes
//! - Channel counts (RX/TX queues)
//! - Interrupt coalescing
//! - Pause/flow control
//! - Statistics
//! - SFP/QSFP module information
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Ethtool};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Ethtool>::new_async().await?;
//!
//! // Query link state
//! let state = conn.get_link_state("eth0").await?;
//! println!("Link: {:?}", state.link);
//!
//! // Query link modes
//! let modes = conn.get_link_modes("eth0").await?;
//! println!("Speed: {:?} Mb/s", modes.speed);
//! println!("Duplex: {:?}", modes.duplex);
//! # Ok(())
//! # }
//! ```
//!
//! # Setting Configuration
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Ethtool};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Ethtool>::new_async().await?;
//!
//! // Set link modes
//! conn.set_link_modes("eth0", |m| {
//!     m.autoneg(true)
//!      .speed(1000)
//!      .duplex(nlink::netlink::genl::ethtool::Duplex::Full)
//! }).await?;
//!
//! // Query and modify features
//! let features = conn.get_features("eth0").await?;
//! println!("TSO: {}", features.is_active("tx-tcp-segmentation"));
//! # Ok(())
//! # }
//! ```

mod bitset;
mod connection;
mod types;

pub use bitset::EthtoolBitset;
pub use types::*;

/// Ethtool Generic Netlink family name.
pub const ETHTOOL_GENL_NAME: &str = "ethtool";

/// Ethtool Generic Netlink version.
pub const ETHTOOL_GENL_VERSION: u8 = 1;

/// Ethtool multicast group for monitoring.
pub const ETHTOOL_MCGRP_MONITOR: &str = "monitor";

// =============================================================================
// Commands
// =============================================================================

/// Ethtool netlink commands.
///
/// Commands ending in `Get` retrieve information, `Set` modify parameters,
/// and `Act` perform actions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolCmd {
    /// Get string set (enumerate available options).
    StrsetGet = 1,
    /// Get link info (port type, MDI-X, transceiver).
    LinkinfoGet = 2,
    /// Set link info.
    LinkinfoSet = 3,
    /// Get link modes (speed, duplex, autoneg).
    LinkmodesGet = 4,
    /// Set link modes.
    LinkmodesSet = 5,
    /// Get link state (carrier, SQI).
    LinkstateGet = 6,
    /// Get debug settings.
    DebugGet = 7,
    /// Set debug settings.
    DebugSet = 8,
    /// Get Wake-on-LAN settings.
    WolGet = 9,
    /// Set Wake-on-LAN settings.
    WolSet = 10,
    /// Get device features (offloads).
    FeaturesGet = 11,
    /// Set device features.
    FeaturesSet = 12,
    /// Get private flags.
    PrivflagsGet = 13,
    /// Set private flags.
    PrivflagsSet = 14,
    /// Get ring buffer sizes.
    RingsGet = 15,
    /// Set ring buffer sizes.
    RingsSet = 16,
    /// Get channel counts.
    ChannelsGet = 17,
    /// Set channel counts.
    ChannelsSet = 18,
    /// Get interrupt coalescing parameters.
    CoalesceGet = 19,
    /// Set interrupt coalescing parameters.
    CoalesceSet = 20,
    /// Get pause/flow control settings.
    PauseGet = 21,
    /// Set pause/flow control settings.
    PauseSet = 22,
    /// Get Energy Efficient Ethernet settings.
    EeeGet = 23,
    /// Set Energy Efficient Ethernet settings.
    EeeSet = 24,
    /// Get timestamping info.
    TsinfoGet = 25,
    /// Start cable test.
    CableTestAct = 26,
    /// Start TDR cable test.
    CableTestTdrAct = 27,
    /// Get tunnel offload info.
    TunnelInfoGet = 28,
    /// Get Forward Error Correction settings.
    FecGet = 29,
    /// Set Forward Error Correction settings.
    FecSet = 30,
    /// Get SFP module EEPROM.
    ModuleEepromGet = 31,
    /// Get standard statistics.
    StatsGet = 32,
    /// Get PHC virtual clocks.
    PhcVclocksGet = 33,
    /// Get transceiver module parameters.
    ModuleGet = 34,
    /// Set transceiver module parameters.
    ModuleSet = 35,
    /// Get Power Sourcing Equipment status.
    PseGet = 36,
    /// Set Power Sourcing Equipment parameters.
    PseSet = 37,
    /// Get Receive Side Scaling settings.
    RssGet = 38,
    /// Get PLCA RS configuration.
    PlcaGetCfg = 39,
    /// Set PLCA RS configuration.
    PlcaSetCfg = 40,
    /// Get PLCA RS status.
    PlcaGetStatus = 41,
    /// Get MAC Merge layer state.
    MmGet = 42,
    /// Set MAC Merge layer configuration.
    MmSet = 43,
    /// Activate a flashed module firmware image.
    ///
    /// The kernel inserted this at 44, which pushed `PHY_GET` to 45. nlink
    /// still had `PhyGet = 44` — so wiring up a PHY query would have sent the
    /// NIC a **module firmware-flash activate** (#229).
    ModuleFwFlashAct = 44,
    /// Get PHY information.
    PhyGet = 45,
}

// =============================================================================
// Header Attributes
// =============================================================================

/// `ETHTOOL_FLAG_OMIT_REPLY`: a set or act request does not answer with
/// its optional reply message.
pub const ETHTOOL_FLAG_OMIT_REPLY: u32 = 1 << 1;

/// Attributes for the request header (nested under ETHTOOL_A_HEADER).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolHeaderAttr {
    Unspec = 0,
    /// Device interface index (u32).
    DevIndex = 1,
    /// Device name (string).
    DevName = 2,
    /// Request flags (u32).
    Flags = 3,
    /// PHY device index (u32, optional).
    PhyIndex = 4,
}

/// Request flags for ethtool commands.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolFlag {
    /// Use compact bitset format in reply.
    CompactBitsets = 1 << 0,
    /// Don't send reply for SET commands.
    OmitReply = 1 << 1,
    /// Include statistics in reply.
    Stats = 1 << 2,
}

// =============================================================================
// Bitset Attributes
// =============================================================================

/// Attributes for bitset encoding.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolBitsetAttr {
    Unspec = 0,
    /// Bitset is a list of bit names (flag).
    Nomask = 1,
    /// Number of significant bits (u32).
    Size = 2,
    /// Nested list of bits.
    Bits = 3,
    /// Compact bitmap of values.
    Value = 4,
    /// Compact bitmap of mask.
    Mask = 5,
}

/// Attributes for individual bits in a bitset.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolBitsetBitAttr {
    Unspec = 0,
    /// Bit index (u32).
    Index = 1,
    /// Bit name (string).
    Name = 2,
    /// Bit is set (flag).
    Value = 3,
}

// =============================================================================
// String Set Attributes
// =============================================================================

/// Attributes for string set queries.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStrsetAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Nested list of string sets.
    Stringsets = 2,
    /// Include counts only (flag).
    CountsOnly = 3,
}

/// Attributes for individual string sets.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStringsetAttr {
    Unspec = 0,
    /// String set ID (u32).
    Id = 1,
    /// Number of strings (u32).
    Count = 2,
    /// Nested list of strings.
    Strings = 3,
}

/// Attributes for individual strings.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStringAttr {
    Unspec = 0,
    /// String index (u32).
    Index = 1,
    /// String value.
    Value = 2,
}

/// String set IDs — `enum ethtool_stringset`.
///
/// nlink used to omit `ETH_SS_FEATURES` (kernel id **4**), so every id from 4
/// up was one too low and a query for one string set returned a different one:
/// asking for `LinkModes` (nlink 8) actually requested `PHY_TUNABLES` (kernel
/// 8). It also invented `RssContexts` and `StatsEth`, which are not kernel
/// string sets at all (#227).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStringSet {
    /// Test strings.
    Test = 0,
    /// Statistic names.
    Stats = 1,
    /// Private flags.
    PrivFlags = 2,
    /// N-tuple filter strings.
    NtupleFltrs = 3,
    /// Device feature names.
    Features = 4,
    /// RSS hash function names.
    RssHashFuncs = 5,
    /// Tunables.
    Tunables = 6,
    /// PHY statistics.
    PhyStats = 7,
    /// PHY tunables.
    PhyTunables = 8,
    /// Link modes (speeds).
    LinkModes = 9,
    /// Message levels.
    MsgClasses = 10,
    /// WoL modes.
    WolModes = 11,
    /// SOF timestamping.
    SofTimestamping = 12,
    /// TX timestamping types.
    TsTxTypes = 13,
    /// RX filters.
    TsRxFilters = 14,
    /// UDP tunnel types.
    UdpTunnelTypes = 15,
    /// Standardized stats.
    StatsStd = 16,
    /// IEEE 802.3 PHY statistics.
    StatsEthPhy = 17,
    /// IEEE 802.3 MAC statistics.
    StatsEthMac = 18,
    /// IEEE 802.3 MAC Control statistics.
    StatsEthCtrl = 19,
    /// RMON statistics.
    StatsRmon = 20,
    /// PHY(dev) statistics.
    StatsPhy = 21,
    /// Hardware timestamping flags.
    TsFlags = 22,
}

// =============================================================================
// Link Info Attributes
// =============================================================================

/// Attributes for link info.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolLinkinfoAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Physical port type (u8).
    Port = 2,
    /// PHY address (u8).
    Phyaddr = 3,
    /// MDI-X status (u8).
    TpMdix = 4,
    /// MDI-X control setting (u8).
    TpMdiCtrl = 5,
    /// Transceiver type (u8).
    Transceiver = 6,
}

// =============================================================================
// Link Modes Attributes
// =============================================================================

/// Attributes for link modes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolLinkmodesAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Autonegotiation enabled (u8).
    Autoneg = 2,
    /// **Our** link modes (bitset) — the supported/advertised modes of this
    /// end, in one attribute.
    ///
    /// nlink used to split this into `Supported = 3` + `Advertised = 4`. The
    /// kernel has a single `ETHTOOL_A_LINKMODES_OURS = 3`, so the invented
    /// second variant shifted **every** later id up by one and silently
    /// corrupted the whole struct: `Speed` read `DUPLEX` (a 1-byte attribute,
    /// so the `len >= 4` guard never matched and **speed was always `None`**),
    /// `Duplex` read `MASTER_SLAVE_CFG`, `Peer` read `SPEED`. On the write path
    /// a speed `u32` landed in the id the kernel's policy declares `NLA_U8`, so
    /// setting speed/duplex could only ever `EINVAL` (#196).
    Ours = 3,
    /// Peer advertised link modes (bitset).
    Peer = 4,
    /// Current speed in Mb/s (u32).
    Speed = 5,
    /// Current duplex (u8).
    Duplex = 6,
    /// Master/slave configuration (u8).
    MasterSlaveCfg = 7,
    /// Master/slave state (u8).
    MasterSlaveState = 8,
    /// Number of lanes (u32).
    Lanes = 9,
    /// Rate matching (u8).
    RateMatching = 10,
}

// =============================================================================
// Link State Attributes
// =============================================================================

/// Attributes for link state.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolLinkstateAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Link detected (u8, boolean).
    Link = 2,
    /// Signal Quality Index (u32).
    Sqi = 3,
    /// Maximum SQI value (u32).
    SqiMax = 4,
    /// Extended link state (u8).
    ExtState = 5,
    /// Extended link substate (u8).
    ExtSubstate = 6,
    /// Extended link down reason (u32).
    ExtDownCnt = 7,
}

// =============================================================================
// Features Attributes
// =============================================================================

/// Attributes for device features.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolFeaturesAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Hardware features (bitset).
    Hw = 2,
    /// Features that can be changed (bitset).
    Wanted = 3,
    /// Currently active features (bitset).
    Active = 4,
    /// Features that cannot be changed (bitset).
    NoChange = 5,
}

// =============================================================================
// Rings Attributes
// =============================================================================

/// Attributes for ring buffer sizes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolRingsAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Maximum RX ring size (u32).
    RxMax = 2,
    /// Maximum RX mini ring size (u32).
    RxMiniMax = 3,
    /// Maximum RX jumbo ring size (u32).
    RxJumboMax = 4,
    /// Maximum TX ring size (u32).
    TxMax = 5,
    /// Current RX ring size (u32).
    Rx = 6,
    /// Current RX mini ring size (u32).
    RxMini = 7,
    /// Current RX jumbo ring size (u32).
    RxJumbo = 8,
    /// Current TX ring size (u32).
    Tx = 9,
    /// RX buffer length (u32).
    RxBufLen = 10,
    /// TCP data split (u8).
    TcpDataSplit = 11,
    /// CQE size (u32).
    CqeSize = 12,
    /// TX push enabled (u8).
    TxPush = 13,
    /// RX push enabled (u8).
    RxPush = 14,
    /// TX push buffer length (u32).
    TxPushBufLen = 15,
    /// Maximum TX push buffer length (u32).
    TxPushBufLenMax = 16,
}

// =============================================================================
// Channels Attributes
// =============================================================================

/// Attributes of a device's timestamping capabilities
/// (`ETHTOOL_MSG_TSINFO_GET`, #166).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolTsinfoAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// `SOF_TIMESTAMPING_*` supported (bitset).
    Timestamping = 2,
    /// `HWTSTAMP_TX_*` modes (bitset).
    TxTypes = 3,
    /// `HWTSTAMP_FILTER_*` receive filters (bitset).
    RxFilters = 4,
    /// The PTP hardware clock's index (u32), when there is one.
    PhcIndex = 5,
    /// Hardware timestamping statistics (nested).
    Stats = 6,
}

/// Attributes of one PHY on a link (`ETHTOOL_MSG_PHY_GET`, kernel 6.12,
/// #166).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolPhyAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// The PHY's index on its link (u32), which PHY-specific requests name
    /// it by.
    Index = 2,
    /// Its driver's name (string).
    Drvname = 3,
    /// Its device name (string).
    Name = 4,
    /// What it is attached to (u32, `enum phy_upstream`): the MAC (0) or
    /// another PHY (1).
    UpstreamType = 5,
    /// The index of the PHY it is attached to, when that is a PHY (u32).
    UpstreamIndex = 6,
    /// The SFP bus it sits behind, on an SFP module (string).
    UpstreamSfpName = 7,
    /// The SFP cage it drives (string).
    DownstreamSfpName = 8,
}

/// Attributes for channel counts.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolChannelsAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Maximum RX channels (u32).
    RxMax = 2,
    /// Maximum TX channels (u32).
    TxMax = 3,
    /// Maximum other channels (u32).
    OtherMax = 4,
    /// Maximum combined channels (u32).
    CombinedMax = 5,
    /// Current RX channels (u32).
    RxCount = 6,
    /// Current TX channels (u32).
    TxCount = 7,
    /// Current other channels (u32).
    OtherCount = 8,
    /// Current combined channels (u32).
    CombinedCount = 9,
}

// =============================================================================
// Coalesce Attributes
// =============================================================================

/// Attributes for interrupt coalescing.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolCoalesceAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// RX coalesce usecs (u32).
    RxUsecs = 2,
    /// RX max frames (u32).
    RxMaxFrames = 3,
    /// RX coalesce usecs irq (u32).
    RxUsecsIrq = 4,
    /// RX max frames irq (u32).
    RxMaxFramesIrq = 5,
    /// TX coalesce usecs (u32).
    TxUsecs = 6,
    /// TX max frames (u32).
    TxMaxFrames = 7,
    /// TX coalesce usecs irq (u32).
    TxUsecsIrq = 8,
    /// TX max frames irq (u32).
    TxMaxFramesIrq = 9,
    /// Stats block usecs (u32).
    StatsBlockUsecs = 10,
    /// Use adaptive RX coalescing (u8).
    UseAdaptiveRx = 11,
    /// Use adaptive TX coalescing (u8).
    UseAdaptiveTx = 12,
    /// Packet rate low (u32).
    PktRateLow = 13,
    /// RX usecs low (u32).
    RxUsecsLow = 14,
    /// RX max frames low (u32).
    RxMaxFramesLow = 15,
    /// TX usecs low (u32).
    TxUsecsLow = 16,
    /// TX max frames low (u32).
    TxMaxFramesLow = 17,
    /// Packet rate high (u32).
    PktRateHigh = 18,
    /// RX usecs high (u32).
    RxUsecsHigh = 19,
    /// RX max frames high (u32).
    RxMaxFramesHigh = 20,
    /// TX usecs high (u32).
    TxUsecsHigh = 21,
    /// TX max frames high (u32).
    TxMaxFramesHigh = 22,
    /// Sample interval (u32).
    RateSampleInterval = 23,
    /// Use CQE mode TX (u8).
    ///
    /// The kernel lists **TX before RX** here, unlike every other RX/TX pair in
    /// this enum. nlink had them the natural way round and therefore backwards
    /// — found by `scripts/audit-uapi-constants.sh` on its first run.
    UseCqeTx = 24,
    /// Use CQE mode RX (u8).
    UseCqeRx = 25,
    /// TX aggregate max bytes (u32).
    TxAggrMaxBytes = 26,
    /// TX aggregate max frames (u32).
    TxAggrMaxFrames = 27,
    /// TX aggregate time usecs (u32).
    TxAggrTimeUsecs = 28,
}

// =============================================================================
// Pause Attributes
// =============================================================================

/// Attributes for pause/flow control.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolPauseAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Autonegotiation enabled (u8).
    Autoneg = 2,
    /// RX pause enabled (u8).
    Rx = 3,
    /// TX pause enabled (u8).
    Tx = 4,
    /// Pause statistics (nested).
    Stats = 5,
    /// RX source select (u32).
    StatsRxSrc = 6,
}

// =============================================================================
// Wake-on-LAN Attributes
// =============================================================================

/// Attributes for Wake-on-LAN (`ETHTOOL_MSG_WOL_{GET,SET}`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolWolAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// WoL modes (bitset — supported via mask, active via value).
    Modes = 2,
    /// SecureOn password (6 bytes, for `magicsecure`).
    Sopass = 3,
}

/// Wake-on-LAN mode bit names, indexed by `ilog2(WAKE_*)`, matching
/// the kernel's `wol_mode_names`. Used to build the outgoing modes
/// bitset by name.
pub const WOL_MODE_NAMES: [&str; 8] = [
    "phy",
    "ucast",
    "mcast",
    "bcast",
    "arp",
    "magic",
    "magicsecure",
    "filter",
];

// =============================================================================
// Energy-Efficient Ethernet Attributes
// =============================================================================

/// Attributes for Energy-Efficient Ethernet (`ETHTOOL_MSG_EEE_{GET,SET}`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolEeeAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Modes we advertise (link-mode bitset).
    ModesOurs = 2,
    /// Modes the link partner advertises (link-mode bitset).
    ModesPeer = 3,
    /// EEE currently active (u8).
    Active = 4,
    /// EEE administratively enabled (u8).
    Enabled = 5,
    /// TX LPI enabled (u8).
    TxLpiEnabled = 6,
    /// TX LPI timer, microseconds (u32).
    TxLpiTimer = 7,
}

// =============================================================================
// Forward Error Correction Attributes
// =============================================================================

/// Attributes for Forward Error Correction (`ETHTOOL_MSG_FEC_{GET,SET}`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolFecAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Configured FEC modes (bitset).
    Modes = 2,
    /// FEC mode auto-negotiated (u8).
    Auto = 3,
    /// Active FEC mode (u32 — an `ETHTOOL_LINK_MODE_FEC_*` bit, or 0).
    Active = 4,
    /// FEC statistics (nested).
    Stats = 5,
}

/// Attributes for SFP/QSFP module EEPROM reads
/// (`ETHTOOL_MSG_MODULE_EEPROM_GET`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolModuleEepromAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// Byte offset within the page (u32).
    Offset = 2,
    /// Number of bytes to read (u32, 1..=128).
    Length = 3,
    /// Page number (u8).
    Page = 4,
    /// Bank number (u8).
    Bank = 5,
    /// I2C address (u8 — 0x50 lower / 0x51 upper).
    I2cAddress = 6,
    /// Raw EEPROM bytes (binary).
    Data = 7,
}

/// Attributes for Receive Side Scaling (`ETHTOOL_MSG_RSS_GET`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolRssAttr {
    Unspec = 0,
    /// Request header (nested).
    Header = 1,
    /// RSS context id (u32).
    Context = 2,
    /// Hash function bitmask (u32).
    Hfunc = 3,
    /// Indirection table (binary — array of u32).
    Indir = 4,
    /// Hash key (binary).
    Hkey = 5,
    /// Input transform (u32).
    InputXfrm = 6,
}

// =============================================================================
// Statistics Attributes
// =============================================================================

/// Attributes for statistics.
///
/// # Warning — discriminants are off by one (kept for ABI stability)
///
/// These values are **wrong** versus the kernel: the real
/// `ETHTOOL_A_STATS_*` enum has `PAD` at index 1, so the header is 2,
/// groups 3, grp 4, src 5. Correcting these discriminants on a
/// `#[repr(u16)]` enum is a breaking change, so the fix is deferred to
/// the next major bump. Internal STATS_GET code uses the correct
/// private `stats_attr` constants in the ethtool connection module
/// instead; prefer those if you build raw STATS requests yourself.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStatsAttr {
    Unspec = 0,
    /// Padding (`ETHTOOL_A_STATS_PAD`).
    ///
    /// The kernel has a `PAD` at index 1, which nlink's enum omitted — so every
    /// id was one too low. The values used to ship with doc-comments saying so
    /// (`**Wrong**: kernel value is 2`) and the connection module carried
    /// private shadow constants to work around its own public enum. A public
    /// enum with knowingly-wrong values is a bug, not documentation (#230).
    Pad = 1,
    /// Request header (nested).
    Header = 2,
    /// Stat groups to query (bitset).
    Groups = 3,
    /// GRP nested stats.
    Grp = 4,
    /// Source for stats (u32).
    Src = 5,
}

/// Attributes nested under `ETHTOOL_A_STATS_GRP` (`ETHTOOL_A_STATS_GRP_*`).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EthtoolStatsGrpAttr {
    Unspec = 0,
    /// Padding (index 1).
    Pad = 1,
    /// Group id (u32) — one of [`stats_group`].
    Id = 2,
    /// String-set id (u32).
    SsId = 3,
    /// One stat: a nested attr whose type is the stat index and
    /// whose payload is a `u64` value.
    Stat = 4,
}

/// Standardized stat-group ids (`enum stats_group` in
/// `ethtool_netlink.h`), used as `ETHTOOL_A_STATS_GRP_ID` values and
/// as bit positions in the request `Groups` bitset.
pub mod stats_group {
    /// IEEE 802.3 PHY stats.
    pub const ETH_PHY: u32 = 0;
    /// IEEE 802.3 MAC stats.
    pub const ETH_MAC: u32 = 1;
    /// IEEE 802.3 MAC-control stats.
    pub const ETH_CTRL: u32 = 2;
    /// RMON (RFC 2819) stats.
    pub const RMON: u32 = 3;
}

#[cfg(test)]
mod uapi_conformance_tests {
    //! The values here are transcribed from the kernel headers, and there was
    //! **no test in this module at all** — which is how six of the eight
    //! constant drifts the 0.25.0 cycle fixed managed to ship.
    //!
    //! `scripts/audit-uapi-constants.sh` is the real gate (it diffs every
    //! `#[repr(uN)]` enum in the crate against `/usr/include/linux` on every
    //! push, so it catches drift in enums nobody thought to test). These pin the
    //! specific values that were wrong, so the regression is named in the test
    //! output and not just in a script's diff.

    use super::*;

    /// #196 — the kernel has ONE `ETHTOOL_A_LINKMODES_OURS = 3`.
    ///
    /// nlink split it into `Supported = 3` + `Advertised = 4`, which shifted
    /// every later id up by one. `Speed` then read `DUPLEX` — a 1-byte
    /// attribute, so the `len >= 4` guard never matched and **speed was always
    /// `None`** — while `Duplex` read `MASTER_SLAVE_CFG`.
    #[test]
    fn linkmodes_attrs_match_the_kernel() {
        assert_eq!(EthtoolLinkmodesAttr::Header as u16, 1);
        assert_eq!(EthtoolLinkmodesAttr::Autoneg as u16, 2);
        assert_eq!(EthtoolLinkmodesAttr::Ours as u16, 3);
        assert_eq!(EthtoolLinkmodesAttr::Peer as u16, 4);
        assert_eq!(EthtoolLinkmodesAttr::Speed as u16, 5);
        assert_eq!(EthtoolLinkmodesAttr::Duplex as u16, 6);
        assert_eq!(EthtoolLinkmodesAttr::MasterSlaveCfg as u16, 7);
        assert_eq!(EthtoolLinkmodesAttr::MasterSlaveState as u16, 8);
        assert_eq!(EthtoolLinkmodesAttr::Lanes as u16, 9);
        assert_eq!(EthtoolLinkmodesAttr::RateMatching as u16, 10);
    }

    /// #228 — TP_MDIX is 4 and TP_MDIX_CTRL is 5; nlink had them transposed, so
    /// the reported MDI-X status and its control setting were swapped.
    #[test]
    fn linkinfo_mdix_attrs_are_not_transposed() {
        assert_eq!(EthtoolLinkinfoAttr::TpMdix as u16, 4);
        assert_eq!(EthtoolLinkinfoAttr::TpMdiCtrl as u16, 5);
    }

    /// #227 — `ETH_SS_FEATURES` is 4. Omitting it made every set id from 4 up
    /// one too low, so a query for one string set returned a different one.
    #[test]
    fn string_set_ids_match_the_kernel() {
        assert_eq!(EthtoolStringSet::NtupleFltrs as u32, 3);
        assert_eq!(EthtoolStringSet::Features as u32, 4);
        assert_eq!(EthtoolStringSet::RssHashFuncs as u32, 5);
        assert_eq!(EthtoolStringSet::LinkModes as u32, 9);
        assert_eq!(EthtoolStringSet::StatsStd as u32, 16);
    }

    /// #229 — the kernel inserted `MODULE_FW_FLASH_ACT` at 44, pushing `PHY_GET`
    /// to 45. A PHY query wired to 44 would send the NIC a **firmware-flash
    /// activate**.
    #[test]
    fn phy_get_is_not_the_firmware_flash_command() {
        assert_eq!(EthtoolCmd::MmSet as u8, 43);
        assert_eq!(EthtoolCmd::ModuleFwFlashAct as u8, 44);
        assert_eq!(EthtoolCmd::PhyGet as u8, 45);
    }

    /// #230 — the kernel's STATS enum has a `PAD` at index 1. nlink's public
    /// enum omitted it and shipped values its own doc-comments called wrong,
    /// while the connection module quietly used private shadow constants.
    #[test]
    fn stats_attrs_account_for_the_pad() {
        assert_eq!(EthtoolStatsAttr::Pad as u16, 1);
        assert_eq!(EthtoolStatsAttr::Header as u16, 2);
        assert_eq!(EthtoolStatsAttr::Groups as u16, 3);
        assert_eq!(EthtoolStatsAttr::Grp as u16, 4);
        assert_eq!(EthtoolStatsAttr::Src as u16, 5);
    }

    /// Found by the audit script on its first run: the kernel lists **TX before
    /// RX** for the CQE-mode pair, unlike every other RX/TX pair in the enum.
    /// nlink had them the natural way round, and therefore backwards.
    #[test]
    fn coalesce_cqe_mode_puts_tx_before_rx() {
        assert_eq!(EthtoolCoalesceAttr::UseCqeTx as u16, 24);
        assert_eq!(EthtoolCoalesceAttr::UseCqeRx as u16, 25);
    }
}
