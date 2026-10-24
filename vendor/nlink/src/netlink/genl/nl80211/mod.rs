//! nl80211 Generic Netlink support for WiFi configuration.
//!
//! This module provides a typed API for querying wireless interfaces,
//! scan results, station info, physical device capabilities, and
//! regulatory domains via the nl80211 Generic Netlink family.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Nl80211};
//!
//! let conn = Connection::<Nl80211>::new_async().await?;
//!
//! // List wireless interfaces
//! let ifaces = conn.get_interfaces().await?;
//! for iface in &ifaces {
//!     println!("{}: {:?} freq={:?}",
//!         iface.name.as_deref().unwrap_or("?"),
//!         iface.iftype,
//!         iface.frequency);
//! }
//!
//! // Get scan results
//! let results = conn.get_scan_results("wlan0").await?;
//! for bss in &results {
//!     println!("{} {} {}dBm",
//!         bss.bssid_str(),
//!         bss.ssid.as_deref().unwrap_or("<hidden>"),
//!         bss.signal_dbm());
//! }
//! # Ok(())
//! # }
//! ```

pub mod connection;
pub mod types;

pub use types::*;

/// nl80211 GENL family name.
pub const NL80211_GENL_NAME: &str = "nl80211";

/// nl80211 GENL version.
pub const NL80211_GENL_VERSION: u8 = 1;

// =============================================================================
// Commands
// =============================================================================

pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_SET_WIPHY: u8 = 2;
/// Move a wiphy to another network namespace (`iw phy <phy> set netns`).
pub const NL80211_CMD_SET_WIPHY_NETNS: u8 = 49;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_GET_KEY: u8 = 9;
pub const NL80211_CMD_GET_STATION: u8 = 17;
pub const NL80211_CMD_DEL_STATION: u8 = 20;
pub const NL80211_CMD_SET_REG: u8 = 26;
/// User-space country hint (`iw reg set`). Unlike `SET_REG` (the
/// CRDA full-regdom path), this only carries an alpha2 and lets the
/// kernel's regulatory core apply the matching domain.
pub const NL80211_CMD_REQ_SET_REG: u8 = 27;
pub const NL80211_CMD_GET_REG: u8 = 31;
pub const NL80211_CMD_GET_SCAN: u8 = 32;
pub const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
pub const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
pub const NL80211_CMD_SCAN_ABORTED: u8 = 35;
pub const NL80211_CMD_GET_SURVEY: u8 = 50;
pub const NL80211_CMD_CONNECT: u8 = 46;
pub const NL80211_CMD_DISCONNECT: u8 = 48;
pub const NL80211_CMD_SET_POWER_SAVE: u8 = 61;
pub const NL80211_CMD_GET_POWER_SAVE: u8 = 62;

// Notification commands (received via multicast)
pub const NL80211_CMD_NEW_WIPHY: u8 = 3;
pub const NL80211_CMD_DEL_WIPHY: u8 = 4;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
/// Change an interface's type (#530).
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
/// Join a mesh (#530).
pub const NL80211_CMD_JOIN_MESH: u8 = 68;
/// Leave a mesh (#530).
pub const NL80211_CMD_LEAVE_MESH: u8 = 69;
/// A mesh id, up to 32 bytes.
pub const NL80211_ATTR_MESH_ID: u16 = 24;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_NEW_STATION: u8 = 19;
pub const NL80211_CMD_REG_CHANGE: u8 = 36;
pub const NL80211_CMD_REG_BEACON_HINT: u8 = 42;

// =============================================================================
// Multicast Group Names
// =============================================================================

pub const NL80211_MCGRP_SCAN: &str = "scan";
pub const NL80211_MCGRP_MLME: &str = "mlme";
pub const NL80211_MCGRP_REGULATORY: &str = "regulatory";
pub const NL80211_MCGRP_CONFIG: &str = "config";

// =============================================================================
// Top-level Attributes
// =============================================================================

pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_WIPHY_NAME: u16 = 2;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY: u16 = 80;
pub const NL80211_ATTR_MAX_NUM_SCAN_SSIDS: u16 = 43;
pub const NL80211_ATTR_REG_ALPHA2: u16 = 33;
pub const NL80211_ATTR_REG_RULES: u16 = 34;
pub const NL80211_ATTR_SCAN_FREQUENCIES: u16 = 44;
pub const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
pub const NL80211_ATTR_STA_INFO: u16 = 21;
pub const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
pub const NL80211_ATTR_SURVEY_INFO: u16 = 84;
pub const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
pub const NL80211_ATTR_GENERATION: u16 = 46;
pub const NL80211_ATTR_BSS: u16 = 47;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_REASON_CODE: u16 = 54;
pub const NL80211_ATTR_NETNS_FD: u16 = 219;
pub const NL80211_ATTR_STATUS_CODE: u16 = 72;
pub const NL80211_ATTR_PID: u16 = 82;
pub const NL80211_ATTR_PS_STATE: u16 = 93;
/// Supported cipher suites — a flat array of `u32` suite selectors.
pub const NL80211_ATTR_CIPHER_SUITES: u16 = 57;
/// Flag attribute requesting a split `GET_WIPHY` dump: the kernel
/// emits a wiphy's attributes across multiple messages (sharing the
/// same `NL80211_ATTR_WIPHY` index) rather than truncating them to a
/// single skb. `iw` always sets it; without it, rich PHYs lose
/// bands/channels/HE caps. Reassembled by wiphy index in `get_phys`.
pub const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;

// =============================================================================
// Survey Info Nested Attributes (NL80211_SURVEY_INFO_*)
// =============================================================================
// Values are positions in `enum nl80211_survey_info`; pinned by a test.
pub const NL80211_SURVEY_INFO_FREQUENCY: u16 = 1;
pub const NL80211_SURVEY_INFO_NOISE: u16 = 2;
pub const NL80211_SURVEY_INFO_IN_USE: u16 = 3;
pub const NL80211_SURVEY_INFO_TIME: u16 = 4;
pub const NL80211_SURVEY_INFO_TIME_BUSY: u16 = 5;
pub const NL80211_SURVEY_INFO_TIME_EXT_BUSY: u16 = 6;
pub const NL80211_SURVEY_INFO_TIME_RX: u16 = 7;
pub const NL80211_SURVEY_INFO_TIME_TX: u16 = 8;
pub const NL80211_SURVEY_INFO_TIME_SCAN: u16 = 9;
pub const NL80211_SURVEY_INFO_TIME_BSS_RX: u16 = 11;
pub const NL80211_SURVEY_INFO_FREQUENCY_OFFSET: u16 = 12;

// =============================================================================
// BSS Nested Attributes
// =============================================================================

// Values are the positions in `enum nl80211_bss` (linux/nl80211.h);
// pinned by a test in connection.rs.
pub const NL80211_BSS_BSSID: u16 = 1;
pub const NL80211_BSS_FREQUENCY: u16 = 2;
pub const NL80211_BSS_TSF: u16 = 3;
pub const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
pub const NL80211_BSS_CAPABILITY: u16 = 5;
pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
pub const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
pub const NL80211_BSS_STATUS: u16 = 9;
pub const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
pub const NL80211_BSS_BEACON_IES: u16 = 11;
pub const NL80211_BSS_LAST_SEEN_BOOTTIME: u16 = 15;
pub const NL80211_BSS_FREQUENCY_OFFSET: u16 = 20;

// =============================================================================
// Station Info Nested Attributes
// =============================================================================

// Values are the positions in `enum nl80211_sta_info`
// (linux/nl80211.h); pinned by a test in connection.rs.
pub const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
pub const NL80211_STA_INFO_RX_BYTES: u16 = 2;
pub const NL80211_STA_INFO_TX_BYTES: u16 = 3;
pub const NL80211_STA_INFO_SIGNAL: u16 = 7;
pub const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
pub const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
pub const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
pub const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
pub const NL80211_STA_INFO_TX_FAILED: u16 = 12;
pub const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
// NB: RX_BITRATE is 14, not 12 — 12 is TX_FAILED. Pre-0.23 nlink had
// this as 12, so rx_bitrate was parsed off the wrong attribute.
pub const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
pub const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
pub const NL80211_STA_INFO_STA_FLAGS: u16 = 17;
pub const NL80211_STA_INFO_BEACON_LOSS: u16 = 18;
pub const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
pub const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
pub const NL80211_STA_INFO_EXPECTED_THROUGHPUT: u16 = 27;
pub const NL80211_STA_INFO_RX_DROP_MISC: u16 = 28;
pub const NL80211_STA_INFO_BEACON_RX: u16 = 29;
pub const NL80211_STA_INFO_BEACON_SIGNAL_AVG: u16 = 30;
pub const NL80211_STA_INFO_ACK_SIGNAL: u16 = 34;

// =============================================================================
// Bitrate Info Nested Attributes
// =============================================================================

pub const NL80211_RATE_INFO_BITRATE: u16 = 1;
pub const NL80211_RATE_INFO_MCS: u16 = 2;
pub const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
pub const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
pub const NL80211_RATE_INFO_BITRATE32: u16 = 5;
pub const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
pub const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
pub const NL80211_RATE_INFO_80_MHZ_WIDTH: u16 = 8;
pub const NL80211_RATE_INFO_80P80_MHZ_WIDTH: u16 = 9;
pub const NL80211_RATE_INFO_160_MHZ_WIDTH: u16 = 10;

// =============================================================================
// Band Nested Attributes
// =============================================================================

// Values are positions in `enum nl80211_band_attr` (linux/nl80211.h);
// pinned by a test in connection.rs.
pub const NL80211_BAND_ATTR_FREQS: u16 = 1;
pub const NL80211_BAND_ATTR_RATES: u16 = 2;
pub const NL80211_BAND_ATTR_HT_MCS_SET: u16 = 3;
pub const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
pub const NL80211_BAND_ATTR_VHT_MCS_SET: u16 = 7;
// NB: VHT_CAPA is 8, not 9 — 9 is IFTYPE_DATA. Pre-0.23 nlink had
// this as 9, so vht_capa was parsed off the wrong attribute (the
// per-iftype HE/EHT nest).
pub const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;
pub const NL80211_BAND_ATTR_IFTYPE_DATA: u16 = 9;

// =============================================================================
// Band Iftype-Data Nested Attributes (NL80211_BAND_IFTYPE_ATTR_*)
// =============================================================================
// HE (802.11ax) / EHT (802.11be) per-interface-type capabilities,
// nested under each NL80211_BAND_ATTR_IFTYPE_DATA element.

pub const NL80211_BAND_IFTYPE_ATTR_IFTYPES: u16 = 1;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC: u16 = 2;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET: u16 = 4;
pub const NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA: u16 = 6;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC: u16 = 8;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET: u16 = 10;

// =============================================================================
// Frequency Nested Attributes
// =============================================================================

// Values are positions in `enum nl80211_frequency_attr`
// (linux/nl80211.h); pinned by a test in connection.rs.
pub const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
pub const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
pub const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
pub const NL80211_FREQUENCY_ATTR_RADAR: u16 = 5;
pub const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;
pub const NL80211_FREQUENCY_ATTR_DFS_STATE: u16 = 7;
pub const NL80211_FREQUENCY_ATTR_NO_HT40_MINUS: u16 = 9;
pub const NL80211_FREQUENCY_ATTR_NO_HT40_PLUS: u16 = 10;
pub const NL80211_FREQUENCY_ATTR_NO_80MHZ: u16 = 11;
pub const NL80211_FREQUENCY_ATTR_NO_160MHZ: u16 = 12;
pub const NL80211_FREQUENCY_ATTR_OFFSET: u16 = 20;

// =============================================================================
// Bitrate Nested Attributes (within Band)
// =============================================================================

pub const NL80211_BITRATE_ATTR_RATE: u16 = 1;

// =============================================================================
// Regulatory Rule Attributes
// =============================================================================

pub const NL80211_ATTR_REG_RULE_FLAGS: u16 = 1;
pub const NL80211_ATTR_FREQ_RANGE_START: u16 = 2;
pub const NL80211_ATTR_FREQ_RANGE_END: u16 = 3;
pub const NL80211_ATTR_FREQ_RANGE_MAX_BW: u16 = 4;
pub const NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN: u16 = 5;
pub const NL80211_ATTR_POWER_RULE_MAX_EIRP: u16 = 6;
