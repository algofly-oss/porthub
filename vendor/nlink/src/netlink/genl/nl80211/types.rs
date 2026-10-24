//! nl80211 data types.

use crate::netlink::error::{Error, Result};

/// Wireless interface operating mode.
///
/// Maps to `NL80211_IFTYPE_*` kernel constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum InterfaceType {
    /// Not specified.
    Unspecified = 0,
    /// Independent BSS (ad-hoc) member.
    Adhoc = 1,
    /// Managed BSS (station) member.
    Station = 2,
    /// Access point.
    Ap = 3,
    /// VLAN interface for access point.
    ApVlan = 4,
    /// Monitor interface (raw 802.11 frames).
    Monitor = 6,
    /// Mesh point (802.11s).
    MeshPoint = 7,
    /// P2P client.
    P2pClient = 8,
    /// P2P group owner.
    P2pGo = 9,
    /// P2P device (not a netdev).
    P2pDevice = 10,
    /// Outside Context of BSS.
    Ocb = 11,
    /// Neighbor Awareness Networking.
    Nan = 12,
}

impl TryFrom<u32> for InterfaceType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::Adhoc),
            2 => Ok(Self::Station),
            3 => Ok(Self::Ap),
            4 => Ok(Self::ApVlan),
            6 => Ok(Self::Monitor),
            7 => Ok(Self::MeshPoint),
            8 => Ok(Self::P2pClient),
            9 => Ok(Self::P2pGo),
            10 => Ok(Self::P2pDevice),
            11 => Ok(Self::Ocb),
            12 => Ok(Self::Nan),
            _ => Err(Error::invalid_attribute(format!(
                "unknown nl80211 interface type: {value}"
            ))),
        }
    }
}

/// BSS connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum BssStatus {
    /// Authenticated with this BSS.
    Authenticated = 0,
    /// Associated to this BSS.
    Associated = 1,
    /// Joined IBSS (ad-hoc).
    IbssJoined = 2,
}

impl TryFrom<u32> for BssStatus {
    type Error = Error;

    /// `enum nl80211_bss_status` starts at **0**.
    ///
    /// nlink used to prepend an invented `NotAuthenticated = 0`, shifting every
    /// real status up by one — so an *associated* BSS decoded as `IbssJoined`
    /// and an authenticated one as `Associated` (#231). There is no
    /// "not authenticated" status on the wire: the kernel simply omits
    /// `NL80211_BSS_STATUS` for a BSS the station has no relationship with,
    /// which the parser already models as `status: None`.
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Authenticated),
            1 => Ok(Self::Associated),
            2 => Ok(Self::IbssJoined),
            _ => Err(Error::invalid_attribute(format!(
                "unknown BSS status: {value}"
            ))),
        }
    }
}

/// Power save state for a wireless interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum PowerSaveState {
    Disabled = 0,
    Enabled = 1,
}

impl TryFrom<u32> for PowerSaveState {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Enabled),
            _ => Err(Error::invalid_attribute(format!(
                "unknown power save state: {value}"
            ))),
        }
    }
}

/// Authentication type for connect/associate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum AuthType {
    OpenSystem = 0,
    SharedKey = 1,
    Ft = 2,
    NetworkEap = 3,
    Sae = 4,
    FilsSk = 5,
    FilsSkPfs = 6,
    FilsPk = 7,
}

/// Channel width — `enum nl80211_chan_width`.
///
/// nlink used to stop at `Width320 = 8`. The kernel had since inserted the five
/// S1G narrow widths (1/2/4/8/16 MHz) at 8..=12, which pushed 320 MHz out to
/// **13** — so a Wi-Fi 7 320 MHz channel decoded as "unknown channel width" and
/// an S1G 1 MHz channel decoded as **320 MHz**, the widest possible answer to
/// the narrowest possible channel. Found by
/// `scripts/audit-uapi-constants.sh` (#232).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum ChannelWidth {
    Width20NoHt = 0,
    Width20 = 1,
    Width40 = 2,
    Width80 = 3,
    Width80P80 = 4,
    Width160 = 5,
    Width5 = 6,
    Width10 = 7,
    /// 1 MHz (802.11ah S1G).
    Width1 = 8,
    /// 2 MHz (802.11ah S1G).
    Width2 = 9,
    /// 4 MHz (802.11ah S1G).
    Width4 = 10,
    /// 8 MHz (802.11ah S1G).
    Width8 = 11,
    /// 16 MHz (802.11ah S1G).
    Width16 = 12,
    /// 320 MHz (802.11be / Wi-Fi 7).
    Width320 = 13,
}

impl TryFrom<u32> for ChannelWidth {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Width20NoHt),
            1 => Ok(Self::Width20),
            2 => Ok(Self::Width40),
            3 => Ok(Self::Width80),
            4 => Ok(Self::Width80P80),
            5 => Ok(Self::Width160),
            6 => Ok(Self::Width5),
            7 => Ok(Self::Width10),
            8 => Ok(Self::Width1),
            9 => Ok(Self::Width2),
            10 => Ok(Self::Width4),
            11 => Ok(Self::Width8),
            12 => Ok(Self::Width16),
            13 => Ok(Self::Width320),
            _ => Err(Error::invalid_attribute(format!(
                "unknown channel width: {value}"
            ))),
        }
    }
}

/// Information about a wireless interface.
#[derive(Debug, Clone)]
pub struct WirelessInterface {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Interface name.
    pub name: Option<String>,
    /// Operating mode.
    pub iftype: InterfaceType,
    /// Physical device index.
    pub wiphy: u32,
    /// MAC address.
    pub mac: Option<[u8; 6]>,
    /// Current frequency in MHz.
    pub frequency: Option<u32>,
    /// Current SSID (if connected).
    pub ssid: Option<String>,
    /// Signal strength in dBm (from station info).
    pub signal_dbm: Option<i32>,
    /// TX bitrate in 100kbps units.
    pub tx_bitrate: Option<u32>,
    /// Generation counter (for cache invalidation).
    pub generation: Option<u32>,
}

impl WirelessInterface {
    /// Format MAC address as colon-separated hex.
    pub fn mac_str(&self) -> Option<String> {
        self.mac.map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
    }

    /// The channel number of the interface's frequency
    /// ([`freq_to_channel`]); `None` with no frequency, or one in no band.
    pub fn channel(&self) -> Option<u32> {
        self.frequency.and_then(freq_to_channel)
    }
}

/// Per-channel survey information (`NL80211_CMD_GET_SURVEY`).
///
/// One entry per surveyed frequency. The `time_*_ms` counters are
/// monotonic channel-occupation times the kernel reports; subtract two
/// samples to derive utilisation. `#[non_exhaustive]` — the kernel
/// grows `NL80211_SURVEY_INFO_*` attributes over time.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SurveyInfo {
    /// Channel frequency in MHz.
    pub frequency_mhz: u32,
    /// Frequency offset in kHz (S1G / fine-grained channels).
    pub frequency_offset_khz: Option<u32>,
    /// Channel noise floor in dBm.
    pub noise_dbm: Option<i8>,
    /// Whether this is the channel the interface is currently on.
    pub in_use: bool,
    /// Total channel active time (ms).
    pub time_ms: Option<u64>,
    /// Time the channel was busy (ms).
    pub time_busy_ms: Option<u64>,
    /// Time the channel was busy due to extension-channel CCA (ms).
    pub time_ext_busy_ms: Option<u64>,
    /// Time spent receiving (ms).
    pub time_rx_ms: Option<u64>,
    /// Time spent transmitting (ms).
    pub time_tx_ms: Option<u64>,
    /// Time spent scanning (ms).
    pub time_scan_ms: Option<u64>,
    /// Time spent receiving from the associated BSS only (ms).
    pub time_bss_rx_ms: Option<u64>,
}

/// BSS (Basic Service Set) from scan results.
///
/// `#[non_exhaustive]` — the kernel grows `NL80211_BSS_*` attributes
/// over time; new fields are added without breaking downstream readers.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ScanResult {
    /// BSSID (AP MAC address).
    pub bssid: [u8; 6],
    /// Frequency in MHz.
    pub frequency: u32,
    /// Network name. `None` for hidden networks.
    pub ssid: Option<String>,
    /// Signal strength in mBm (millidecibel-milliwatts).
    /// Divide by 100 for dBm.
    pub signal_mbm: i32,
    /// BSS capability field (IEEE 802.11).
    pub capability: u16,
    /// Beacon interval in TU (1024 us).
    pub beacon_interval: u16,
    /// Milliseconds since this BSS was last seen.
    pub seen_ms_ago: u32,
    /// TSF (Timing Synchronization Function) timestamp.
    pub tsf: Option<u64>,
    /// Connection status (if this is the associated BSS).
    pub status: Option<BssStatus>,
    /// Raw information elements (vendor-specific, WPA, RSN, etc.) from
    /// the probe response (or beacon if no probe response was seen).
    pub information_elements: Vec<u8>,
    /// Information elements from the beacon, when they differ from
    /// [`information_elements`](Self::information_elements) (probe
    /// response). Empty if the kernel didn't report a separate set.
    pub beacon_ies: Vec<u8>,
    /// Unspecified-units signal quality (0–100), reported by drivers
    /// that don't provide an absolute mBm value.
    pub signal_unspec: Option<u8>,
    /// `CLOCK_BOOTTIME` (nanoseconds) when this BSS was last seen.
    pub last_seen_boottime_ns: Option<u64>,
    /// Frequency offset from [`frequency`](Self::frequency), in kHz
    /// (S1G / fine-grained channels).
    pub frequency_offset_khz: Option<u32>,
}

impl ScanResult {
    /// Signal strength in dBm (rounded from mBm).
    pub fn signal_dbm(&self) -> i32 {
        self.signal_mbm / 100
    }

    /// Format BSSID as colon-separated hex.
    pub fn bssid_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bssid[0],
            self.bssid[1],
            self.bssid[2],
            self.bssid[3],
            self.bssid[4],
            self.bssid[5]
        )
    }

    /// Whether this BSS advertises privacy (WEP/WPA).
    pub fn is_privacy(&self) -> bool {
        self.capability & 0x0010 != 0
    }

    /// Whether this BSS is an ESS (infrastructure mode).
    pub fn is_ess(&self) -> bool {
        self.capability & 0x0001 != 0
    }
}

/// Station (connected peer) information.
///
/// `#[non_exhaustive]` — the kernel grows `NL80211_STA_INFO_*`
/// attributes over time; new fields are added without breaking
/// downstream readers.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct StationInfo {
    /// Station MAC address.
    pub mac: [u8; 6],
    /// Interface index.
    pub ifindex: u32,
    /// Time since last activity in milliseconds.
    pub inactive_time_ms: Option<u32>,
    /// Total bytes received from this station.
    pub rx_bytes: Option<u64>,
    /// Total bytes transmitted to this station.
    pub tx_bytes: Option<u64>,
    /// Total packets received from this station.
    pub rx_packets: Option<u32>,
    /// Total packets transmitted to this station.
    pub tx_packets: Option<u32>,
    /// Total TX retries to this station.
    pub tx_retries: Option<u32>,
    /// Total failed TX packets to this station.
    pub tx_failed: Option<u32>,
    /// Signal strength in dBm.
    pub signal_dbm: Option<i8>,
    /// Average signal strength in dBm.
    pub signal_avg_dbm: Option<i8>,
    /// Average beacon signal strength in dBm.
    pub beacon_signal_avg_dbm: Option<i8>,
    /// Signal strength of the last ACK frame, in dBm.
    pub ack_signal_dbm: Option<i8>,
    /// TX bitrate info.
    pub tx_bitrate: Option<BitrateInfo>,
    /// RX bitrate info.
    pub rx_bitrate: Option<BitrateInfo>,
    /// Count of times beacon loss was detected.
    pub beacon_loss: Option<u32>,
    /// RX packets dropped for unspecified reasons.
    pub rx_drop_misc: Option<u64>,
    /// Expected throughput in kbit/s (considers rate + probabilities).
    pub expected_throughput_kbps: Option<u32>,
    /// Time connected in seconds.
    pub connected_time_secs: Option<u32>,
}

/// Bitrate information (from NL80211_RATE_INFO_*).
#[derive(Debug, Clone)]
pub struct BitrateInfo {
    /// Bitrate in 100 kbps units.
    pub bitrate_100kbps: Option<u32>,
    /// MCS index (for HT/VHT).
    pub mcs: Option<u8>,
    /// Channel width.
    pub width: Option<ChannelWidth>,
    /// Short guard interval.
    pub short_gi: bool,
}

impl BitrateInfo {
    /// Bitrate in Mbps.
    pub fn mbps(&self) -> Option<f64> {
        self.bitrate_100kbps.map(|r| r as f64 / 10.0)
    }
}

/// Physical wireless device capabilities.
///
/// `#[non_exhaustive]` — the kernel grows `NL80211_ATTR_*` wiphy
/// attributes over time; new fields are added without breaking
/// downstream readers.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PhyInfo {
    /// Physical device index.
    pub index: u32,
    /// Physical device name.
    pub name: String,
    /// Supported frequency bands.
    pub bands: Vec<Band>,
    /// Supported interface types.
    pub supported_iftypes: Vec<InterfaceType>,
    /// Maximum number of SSIDs in a scan request.
    pub max_scan_ssids: Option<u8>,
    /// Supported cipher suites (`NL80211_ATTR_CIPHER_SUITES`), each a
    /// 32-bit suite selector (`OUI << 8 | type`).
    pub cipher_suites: Vec<u32>,
}

/// Frequency band (2.4 GHz, 5 GHz, 6 GHz).
///
/// `#[non_exhaustive]` — the kernel grows `NL80211_BAND_ATTR_*`
/// attributes over time (S1G, EDMG, …); new fields are additive.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Band {
    /// Available frequencies.
    pub frequencies: Vec<Frequency>,
    /// Supported bitrates in 100kbps units.
    pub rates: Vec<u32>,
    /// HT (802.11n) capabilities.
    pub ht_capa: Option<u16>,
    /// VHT (802.11ac) capabilities.
    pub vht_capa: Option<u32>,
    /// HT MCS set (16 bytes) from `NL80211_BAND_ATTR_HT_MCS_SET`.
    pub ht_mcs_set: Option<Vec<u8>>,
    /// VHT MCS set (8 bytes) from `NL80211_BAND_ATTR_VHT_MCS_SET`.
    pub vht_mcs_set: Option<Vec<u8>>,
    /// Per-interface-type HE (802.11ax) / EHT (802.11be) capabilities
    /// (`NL80211_BAND_ATTR_IFTYPE_DATA`). Empty on pre-HE hardware.
    pub iftype_capa: Vec<BandIftypeCapa>,
}

impl Band {
    /// Whether any interface type on this band advertises HE (802.11ax).
    pub fn he_supported(&self) -> bool {
        self.iftype_capa.iter().any(|c| c.he_cap_phy.is_some())
    }

    /// Whether any interface type on this band advertises EHT (802.11be).
    pub fn eht_supported(&self) -> bool {
        self.iftype_capa.iter().any(|c| c.eht_cap_phy.is_some())
    }
}

/// HE/EHT capabilities for a set of interface types on a band
/// (`NL80211_BAND_ATTR_IFTYPE_DATA` element). Capability fields hold
/// the raw kernel bytes (their bit layouts are defined by 802.11ax/be).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BandIftypeCapa {
    /// Interface types these capabilities apply to.
    pub iftypes: Vec<InterfaceType>,
    /// HE MAC capability info (`HE_CAP_MAC`).
    pub he_cap_mac: Option<Vec<u8>>,
    /// HE PHY capability info (`HE_CAP_PHY`).
    pub he_cap_phy: Option<Vec<u8>>,
    /// HE supported MCS/NSS set (`HE_CAP_MCS_SET`).
    pub he_cap_mcs_set: Option<Vec<u8>>,
    /// EHT MAC capability info (`EHT_CAP_MAC`).
    pub eht_cap_mac: Option<Vec<u8>>,
    /// EHT PHY capability info (`EHT_CAP_PHY`).
    pub eht_cap_phy: Option<Vec<u8>>,
}

/// DFS (radar) state of a channel, from `NL80211_FREQUENCY_ATTR_DFS_STATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DfsState {
    /// Channel is usable but a CAC (channel availability check) must
    /// run before use.
    Usable,
    /// A radar pattern was detected; the channel is unavailable.
    Unavailable,
    /// CAC completed; the channel is available for use.
    Available,
}

impl TryFrom<u32> for DfsState {
    type Error = ();

    fn try_from(v: u32) -> core::result::Result<Self, ()> {
        match v {
            0 => Ok(DfsState::Usable),
            1 => Ok(DfsState::Unavailable),
            2 => Ok(DfsState::Available),
            _ => Err(()),
        }
    }
}

/// Individual frequency/channel info.
///
/// `#[non_exhaustive]` — the kernel grows `NL80211_FREQUENCY_ATTR_*`
/// attributes over time; new fields are additive.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Frequency {
    /// Frequency in MHz.
    pub freq: u32,
    /// Maximum TX power in mBm.
    pub max_power_mbm: u32,
    /// Whether this frequency is disabled by regulation.
    pub disabled: bool,
    /// Whether radar detection is required (DFS).
    pub radar: bool,
    /// Whether initiating radiation is not allowed (NO-IR).
    pub no_ir: bool,
    /// DFS state, when this is a radar/DFS channel.
    pub dfs_state: Option<DfsState>,
    /// HT40- is not allowed on this channel.
    pub no_ht40_minus: bool,
    /// HT40+ is not allowed on this channel.
    pub no_ht40_plus: bool,
    /// 80 MHz operation is not allowed on this channel.
    pub no_80mhz: bool,
    /// 160 MHz operation is not allowed on this channel.
    pub no_160mhz: bool,
    /// Frequency offset from `freq`, in kHz (S1G / fine-grained).
    pub offset_khz: u32,
}

impl Frequency {
    /// Maximum TX power in dBm.
    pub fn max_power_dbm(&self) -> f32 {
        self.max_power_mbm as f32 / 100.0
    }

    /// The channel number ([`freq_to_channel`]), or 0 for a frequency in
    /// no band.
    pub fn channel(&self) -> u32 {
        freq_to_channel(self.freq).unwrap_or(0)
    }
}

/// A frequency band (`enum nl80211_band`).
///
/// Channel numbers repeat across bands — channel 1 is 2412 MHz, 5005 MHz
/// and 5955 MHz — so turning one back into a frequency needs the band
/// ([`channel_to_freq`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum WifiBand {
    /// 2.4 GHz ISM band.
    Band2Ghz = 0,
    /// Around 5 GHz (4.9–5.9 GHz).
    Band5Ghz = 1,
    /// Around 60 GHz (58.32–69.12 GHz).
    Band60Ghz = 2,
    /// Around 6 GHz (5.9–7.2 GHz).
    Band6Ghz = 3,
    /// Around 900 MHz, for S1G PHYs. Its channels are 500 kHz apart; see
    /// [`channel_to_freq_khz`].
    S1Ghz = 4,
    /// Light communication (a placeholder in the kernel).
    Lc = 5,
}

/// The channel number of a frequency in MHz, as the kernel's
/// `ieee80211_freq_khz_to_channel` computes it — 2484 MHz is channel 14,
/// which the old `(f - 2407) / 5` made 15 (#508). `None` for a frequency
/// in no band.
pub fn freq_to_channel(freq_mhz: u32) -> Option<u32> {
    match freq_mhz {
        2484 => Some(14),
        2412..=2472 => Some((freq_mhz - 2407) / 5),
        4910..=4980 => Some((freq_mhz - 4000) / 5),
        5005..=5920 => Some((freq_mhz - 5000) / 5),
        5935 => Some(2),
        5955..=7115 => Some((freq_mhz - 5950) / 5),
        58320..=70200 => Some((freq_mhz - 56160) / 2160),
        _ => None,
    }
}

/// The centre frequency in MHz of `channel` in `band`, as the kernel's
/// `ieee80211_channel_to_freq_khz` computes it. `None` for a channel the
/// band does not have, and for S1G, whose channels fall on 500 kHz steps
/// ([`channel_to_freq_khz`]).
pub fn channel_to_freq(channel: u32, band: WifiBand) -> Option<u32> {
    match band {
        WifiBand::S1Ghz => None,
        _ => channel_to_freq_khz(channel, band).map(|khz| khz / 1000),
    }
}

/// [`channel_to_freq`] in kHz, which S1G needs.
pub fn channel_to_freq_khz(channel: u32, band: WifiBand) -> Option<u32> {
    let mhz = match (band, channel) {
        (_, 0) => return None,
        (WifiBand::Band2Ghz | WifiBand::Lc, 14) => 2484,
        (WifiBand::Band2Ghz | WifiBand::Lc, 1..=13) => 2407 + channel * 5,
        (WifiBand::Band5Ghz, 182..=196) => 4000 + channel * 5,
        (WifiBand::Band5Ghz, 1..=184) => 5000 + channel * 5,
        (WifiBand::Band6Ghz, 2) => 5935,
        (WifiBand::Band6Ghz, 1..=233) => 5950 + channel * 5,
        (WifiBand::Band60Ghz, 1..=6) => 56160 + channel * 2160,
        (WifiBand::S1Ghz, _) => return channel.checked_mul(500)?.checked_add(902_000),
        _ => return None,
    };
    Some(mhz * 1000)
}

/// Regulatory domain information.
#[derive(Debug, Clone)]
pub struct RegulatoryDomain {
    /// Two-letter country code (e.g., "US", "DE").
    pub country: String,
    /// Regulatory rules.
    pub rules: Vec<RegulatoryRule>,
}

/// Single regulatory rule defining allowed frequency range and power.
#[derive(Debug, Clone)]
pub struct RegulatoryRule {
    /// Start frequency in kHz.
    pub start_freq_khz: u32,
    /// End frequency in kHz.
    pub end_freq_khz: u32,
    /// Maximum bandwidth in kHz.
    pub max_bandwidth_khz: u32,
    /// Maximum antenna gain in mBi (milli-dBi).
    pub max_antenna_gain_mbi: u32,
    /// Maximum EIRP in mBm.
    pub max_eirp_mbm: u32,
    /// Regulatory flags (DFS, NO-IR, etc.).
    pub flags: u32,
}

/// Scan request configuration.
#[derive(Debug, Clone, Default)]
pub struct ScanRequest {
    /// Specific frequencies to scan (empty = all).
    pub frequencies: Vec<u32>,
    /// Specific SSIDs to probe for (empty = broadcast probe).
    pub ssids: Vec<Vec<u8>>,
}

impl ScanRequest {
    /// Scan a specific frequency.
    pub fn frequency(mut self, freq: u32) -> Self {
        self.frequencies.push(freq);
        self
    }

    /// Probe for a specific SSID.
    pub fn ssid(mut self, ssid: impl Into<Vec<u8>>) -> Self {
        self.ssids.push(ssid.into());
        self
    }
}

/// nl80211 multicast events.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Nl80211Event {
    /// Scan completed successfully on an interface.
    ScanComplete {
        /// Interface index.
        ifindex: u32,
    },
    /// Scan was aborted.
    ScanAborted {
        /// Interface index.
        ifindex: u32,
    },
    /// Connected to a BSS.
    Connect {
        /// Interface index.
        ifindex: u32,
        /// AP BSSID.
        bssid: [u8; 6],
        /// IEEE 802.11 status code.
        status_code: u16,
    },
    /// Disconnected from BSS.
    Disconnect {
        /// Interface index.
        ifindex: u32,
        /// AP BSSID (if available).
        bssid: Option<[u8; 6]>,
        /// IEEE 802.11 reason code.
        reason_code: u16,
    },
    /// New wireless interface appeared.
    NewInterface {
        /// Interface index.
        ifindex: u32,
        /// Interface name.
        name: Option<String>,
        /// Interface type.
        iftype: InterfaceType,
    },
    /// Wireless interface removed.
    DelInterface {
        /// Interface index.
        ifindex: u32,
    },
    /// Regulatory domain changed.
    RegChange {
        /// Country code (if available).
        country: Option<String>,
    },
}

/// Connect request builder.
pub struct ConnectRequest {
    /// SSID to connect to.
    pub(crate) ssid: Vec<u8>,
    /// Target BSSID (optional).
    pub(crate) bssid: Option<[u8; 6]>,
    /// Target frequency (optional).
    pub(crate) frequency: Option<u32>,
    /// Authentication type.
    pub(crate) auth_type: AuthType,
}

impl ConnectRequest {
    /// Connect to a network by SSID.
    pub fn new(ssid: impl Into<Vec<u8>>) -> Self {
        Self {
            ssid: ssid.into(),
            bssid: None,
            frequency: None,
            auth_type: AuthType::OpenSystem,
        }
    }

    /// Target a specific BSSID (AP).
    pub fn bssid(mut self, bssid: [u8; 6]) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Restrict to a specific frequency.
    pub fn frequency(mut self, freq: u32) -> Self {
        self.frequency = Some(freq);
        self
    }

    /// Set authentication type.
    pub fn auth_type(mut self, auth: AuthType) -> Self {
        self.auth_type = auth;
        self
    }
}

#[cfg(test)]
mod channel_tests {
    use super::*;

    /// #508: 2484 MHz is channel 14 (Japan); `(f - 2407) / 5` made it 15.
    #[test]
    fn channel_14_is_2484_mhz() {
        assert_eq!(freq_to_channel(2484), Some(14));
        let f = Frequency {
            freq: 2484,
            ..Default::default()
        };
        assert_eq!(f.channel(), 14);
        assert_eq!(channel_to_freq(14, WifiBand::Band2Ghz), Some(2484));
    }

    /// Spot values from the kernel's `ieee80211_channel_to_freq_khz`, and a
    /// round trip over every channel of every band with integral MHz.
    #[test]
    fn conversions_follow_the_kernel() {
        for (freq, ch) in [
            (2412, 1),
            (2472, 13),
            (4920, 184),
            (5180, 36),
            (5825, 165),
            (5935, 2),
            (5955, 1),
            (7115, 233),
            (58320, 1),
            (69120, 6),
        ] {
            assert_eq!(freq_to_channel(freq), Some(ch), "{freq} MHz");
        }
        for freq in [0, 2400, 2477, 5925, 45000] {
            assert_eq!(freq_to_channel(freq), None, "{freq} MHz is in no band");
        }
        let bands = [
            (WifiBand::Band2Ghz, 1..=14),
            (WifiBand::Band5Ghz, 1..=196),
            (WifiBand::Band6Ghz, 1..=233),
            (WifiBand::Band60Ghz, 1..=6),
        ];
        for (band, channels) in bands {
            for ch in channels {
                let freq = channel_to_freq(ch, band).unwrap_or_else(|| panic!("{band:?} {ch}"));
                assert_eq!(
                    freq_to_channel(freq),
                    Some(ch),
                    "{band:?} channel {ch} = {freq} MHz"
                );
            }
        }
        assert_eq!(channel_to_freq(197, WifiBand::Band5Ghz), None);
        assert_eq!(channel_to_freq(0, WifiBand::Band2Ghz), None);
        assert_eq!(channel_to_freq(15, WifiBand::Band2Ghz), None);
        assert_eq!(channel_to_freq_khz(1, WifiBand::S1Ghz), Some(902_500));
        assert_eq!(
            channel_to_freq(1, WifiBand::S1Ghz),
            None,
            "S1G is in 500 kHz steps"
        );
    }
}
