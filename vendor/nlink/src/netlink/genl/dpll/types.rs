//! DPLL command + attribute + value enums.
//!
//! Direct translation of the kernel UAPI in
//! `include/uapi/linux/dpll.h` (kernel 6.7+), expressed via the
//! `nlink-macros` typed-codec derives. Every kind, attribute,
//! and value lookup that used to require a hand-written
//! `From<u8>` / `TryFrom<u32>` pair is now one annotation away.
//!
//! Constants stay verbatim from the kernel UAPI — discriminants
//! are 1-based throughout except for [`DpllFeatureState`] (the
//! single 0-based enum in the family; the discriminants are
//! preserved as-is).

use crate::macros::{GenlAttribute, GenlCommand, GenlEnum};

// ============================================================
// Commands (DPLL_CMD_*)
// ============================================================

/// DPLL command codes. Sent in the GENL header's `cmd` byte;
/// also appears as the message type on notifications.
///
/// Wire: `u8` per the kernel UAPI.
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
#[non_exhaustive]
pub enum DpllCmd {
    /// `DPLL_CMD_DEVICE_ID_GET` — resolve device by metadata
    /// (module-name + clock-id + type) to a numeric ID.
    DeviceIdGet = 1,
    /// `DPLL_CMD_DEVICE_GET` — read a device's full state.
    DeviceGet = 2,
    /// `DPLL_CMD_DEVICE_SET` — mutate device state (mode,
    /// phase-offset monitor, frequency monitor).
    DeviceSet = 3,
    /// `DPLL_CMD_DEVICE_CREATE_NTF` — device-create notification
    /// (multicast group `monitor`).
    DeviceCreateNtf = 4,
    /// `DPLL_CMD_DEVICE_DELETE_NTF` — device-delete notification.
    DeviceDeleteNtf = 5,
    /// `DPLL_CMD_DEVICE_CHANGE_NTF` — device-state-change
    /// notification.
    DeviceChangeNtf = 6,
    /// `DPLL_CMD_PIN_ID_GET` — resolve pin by metadata.
    PinIdGet = 7,
    /// `DPLL_CMD_PIN_GET` — read a pin's full state.
    PinGet = 8,
    /// `DPLL_CMD_PIN_SET` — mutate pin state (priority,
    /// frequency, direction, phase-adjust, …).
    PinSet = 9,
    /// `DPLL_CMD_PIN_CREATE_NTF`.
    PinCreateNtf = 10,
    /// `DPLL_CMD_PIN_DELETE_NTF`.
    PinDeleteNtf = 11,
    /// `DPLL_CMD_PIN_CHANGE_NTF`.
    PinChangeNtf = 12,
}

// ============================================================
// Device-side attributes (DPLL_A_*)
// ============================================================

/// DPLL device-message attribute kinds.
///
/// Wire: `u16` per the kernel UAPI (`enum dpll_a`).
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum DpllAttr {
    /// `DPLL_A_ID` — numeric device ID.
    Id = 1,
    /// `DPLL_A_MODULE_NAME` — driver module name (e.g. "ice").
    ModuleName = 2,
    /// `DPLL_A_PAD`.
    Pad = 3,
    /// `DPLL_A_CLOCK_ID` — hardware clock identifier (u64).
    ClockId = 4,
    /// `DPLL_A_MODE` — current mode ([`DpllMode`]).
    Mode = 5,
    /// `DPLL_A_MODE_SUPPORTED` — list of supported modes
    /// (repeated attr).
    ModeSupported = 6,
    /// `DPLL_A_LOCK_STATUS` — current lock state
    /// ([`DpllLockStatus`]).
    LockStatus = 7,
    /// `DPLL_A_TEMP` — device temperature in milli-degrees
    /// Celsius (signed). Divide by 1000 for °C.
    Temp = 8,
    /// `DPLL_A_TYPE` — DPLL kind ([`DpllType`]).
    Type = 9,
    /// `DPLL_A_LOCK_STATUS_ERROR` — reason for lock failure
    /// ([`DpllLockStatusError`]), kernel 6.10+.
    LockStatusError = 10,
    /// `DPLL_A_CLOCK_QUALITY_LEVEL` — ITU-T G.8264 quality
    /// level (repeated attr, [`DpllClockQualityLevel`]).
    ClockQualityLevel = 11,
    /// `DPLL_A_PHASE_OFFSET_MONITOR` — boolean: phase-offset
    /// monitoring on/off ([`DpllFeatureState`], kernel 6.12+).
    PhaseOffsetMonitor = 12,
    /// `DPLL_A_PHASE_OFFSET_AVG_FACTOR` — moving-average factor
    /// for phase-offset reporting (u32, kernel 6.12+).
    PhaseOffsetAvgFactor = 13,
    /// `DPLL_A_FREQUENCY_MONITOR` — boolean: frequency monitor
    /// on/off ([`DpllFeatureState`], kernel 6.12+).
    FrequencyMonitor = 14,
}

// ============================================================
// Pin-side attributes (DPLL_A_PIN_*)
// ============================================================

/// DPLL pin-message attribute kinds.
///
/// Wire: `u16` per the kernel UAPI (`enum dpll_a_pin`). Lots of
/// surface — DPLL pins carry direction, frequency, priority,
/// phase-adjust, capability flags, ESYNC params, and 6.11+
/// additions for measured-frequency / reference-sync.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum DpllPinAttr {
    /// `DPLL_A_PIN_ID`.
    Id = 1,
    /// `DPLL_A_PIN_PARENT_ID`.
    ParentId = 2,
    /// `DPLL_A_PIN_MODULE_NAME`.
    ModuleName = 3,
    /// `DPLL_A_PIN_PAD`.
    Pad = 4,
    /// `DPLL_A_PIN_CLOCK_ID`.
    ClockId = 5,
    /// `DPLL_A_PIN_BOARD_LABEL`.
    BoardLabel = 6,
    /// `DPLL_A_PIN_PANEL_LABEL`.
    PanelLabel = 7,
    /// `DPLL_A_PIN_PACKAGE_LABEL`.
    PackageLabel = 8,
    /// `DPLL_A_PIN_TYPE` — [`DpllPinType`].
    Type = 9,
    /// `DPLL_A_PIN_DIRECTION` — [`DpllPinDirection`].
    Direction = 10,
    /// `DPLL_A_PIN_FREQUENCY` — current frequency in Hz (u64).
    Frequency = 11,
    /// `DPLL_A_PIN_FREQUENCY_SUPPORTED` — repeated; supported
    /// frequency ranges (u64 each).
    FrequencySupported = 12,
    /// `DPLL_A_PIN_FREQUENCY_MIN`.
    FrequencyMin = 13,
    /// `DPLL_A_PIN_FREQUENCY_MAX`.
    FrequencyMax = 14,
    /// `DPLL_A_PIN_PRIO` — selection priority (u32, lower wins).
    Prio = 15,
    /// `DPLL_A_PIN_STATE` — current state ([`DpllPinState`]).
    State = 16,
    /// `DPLL_A_PIN_CAPABILITIES` — bitmask
    /// ([`DpllPinCapabilities`]).
    Capabilities = 17,
    /// `DPLL_A_PIN_PARENT_DEVICE` — nested attr group with the
    /// parent device's ID + connection state.
    ParentDevice = 18,
    /// `DPLL_A_PIN_PARENT_PIN` — nested attr group for
    /// pin-to-pin parenting (mux pins).
    ParentPin = 19,
    /// `DPLL_A_PIN_PHASE_ADJUST_MIN`.
    PhaseAdjustMin = 20,
    /// `DPLL_A_PIN_PHASE_ADJUST_MAX`.
    PhaseAdjustMax = 21,
    /// `DPLL_A_PIN_PHASE_ADJUST` — current phase adjust in
    /// picoseconds (s32).
    PhaseAdjust = 22,
    /// `DPLL_A_PIN_PHASE_OFFSET` — measured phase offset in
    /// attoseconds × 1000 (s64; divide by
    /// `DPLL_PHASE_OFFSET_DIVIDER` for ns).
    PhaseOffset = 23,
    /// `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET`.
    FractionalFrequencyOffset = 24,
    /// `DPLL_A_PIN_ESYNC_FREQUENCY` (kernel 6.10+).
    EsyncFrequency = 25,
    /// `DPLL_A_PIN_ESYNC_FREQUENCY_SUPPORTED`.
    EsyncFrequencySupported = 26,
    /// `DPLL_A_PIN_ESYNC_PULSE` — ESYNC pulse-width
    /// configuration (u32).
    EsyncPulse = 27,
    /// `DPLL_A_PIN_REFERENCE_SYNC` (kernel 6.11+).
    ReferenceSync = 28,
    /// `DPLL_A_PIN_PHASE_ADJUST_GRAN` — phase-adjust granularity
    /// in picoseconds (kernel 6.11+).
    PhaseAdjustGran = 29,
    /// `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT` — FFO in
    /// parts-per-trillion (kernel 6.11+).
    FractionalFrequencyOffsetPpt = 30,
    /// `DPLL_A_PIN_MEASURED_FREQUENCY` — measured frequency in
    /// mHz × 1000 (divide by `DPLL_PIN_MEASURED_FREQUENCY_DIVIDER`
    /// for Hz; kernel 6.11+).
    MeasuredFrequency = 31,
}

// ============================================================
// Value enums (encoded inside attribute payloads)
// ============================================================

/// DPLL mode — how the device selects its reference clock.
///
/// Wire: `u32` per `DPLL_MODE_*` in `linux/dpll.h`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllMode {
    /// `DPLL_MODE_MANUAL` — operator picks the active reference.
    Manual = 1,
    /// `DPLL_MODE_AUTOMATIC` — device auto-selects by pin
    /// priority + lock health.
    Automatic = 2,
}

/// DPLL lock state.
///
/// Wire: `u32` per `DPLL_LOCK_STATUS_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllLockStatus {
    /// `DPLL_LOCK_STATUS_UNLOCKED` — searching for a reference.
    Unlocked = 1,
    /// `DPLL_LOCK_STATUS_LOCKED` — locked to a reference,
    /// holdover not yet acquired.
    Locked = 2,
    /// `DPLL_LOCK_STATUS_LOCKED_HO_ACQ` — locked AND holdover
    /// is acquired (can survive reference loss without
    /// frequency drift beyond holdover spec).
    LockedHoAcq = 3,
    /// `DPLL_LOCK_STATUS_HOLDOVER` — reference lost; running in
    /// holdover mode.
    Holdover = 4,
}

/// DPLL kind / class of device.
///
/// Wire: `u32` per `DPLL_TYPE_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllType {
    /// `DPLL_TYPE_PPS` — generic pulse-per-second clock.
    Pps = 1,
    /// `DPLL_TYPE_EEC` — Ethernet Equipment Clock (SyncE
    /// recovery clock).
    Eec = 2,
}

/// Pin kind — what the pin represents physically.
///
/// Wire: `u32` per `DPLL_PIN_TYPE_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllPinType {
    /// `DPLL_PIN_TYPE_MUX` — multiplexer (selects between other
    /// pins).
    Mux = 1,
    /// `DPLL_PIN_TYPE_EXT` — external reference (e.g., SMA
    /// connector).
    Ext = 2,
    /// `DPLL_PIN_TYPE_SYNCE_ETH_PORT` — SyncE-capable Ethernet
    /// port.
    SynceEthPort = 3,
    /// `DPLL_PIN_TYPE_INT_OSCILLATOR` — on-board oscillator.
    IntOscillator = 4,
    /// `DPLL_PIN_TYPE_GNSS` — GNSS-disciplined oscillator.
    Gnss = 5,
}

/// Pin direction — input (reference) vs output (clock output).
///
/// Wire: `u32` per `DPLL_PIN_DIRECTION_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllPinDirection {
    /// `DPLL_PIN_DIRECTION_INPUT`.
    Input = 1,
    /// `DPLL_PIN_DIRECTION_OUTPUT`.
    Output = 2,
}

/// Pin connection state.
///
/// Wire: `u32` per `DPLL_PIN_STATE_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllPinState {
    /// `DPLL_PIN_STATE_CONNECTED` — pin is selected as the
    /// active reference.
    Connected = 1,
    /// `DPLL_PIN_STATE_DISCONNECTED` — pin is forced
    /// disconnected (operator policy).
    Disconnected = 2,
    /// `DPLL_PIN_STATE_SELECTABLE` — pin is eligible for
    /// automatic selection.
    Selectable = 3,
}

/// Reason a DPLL lost lock.
///
/// Wire: `u32` per `DPLL_LOCK_STATUS_ERROR_*` (kernel 6.10+).
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllLockStatusError {
    /// `DPLL_LOCK_STATUS_ERROR_NONE`.
    None = 1,
    /// `DPLL_LOCK_STATUS_ERROR_UNDEFINED`.
    Undefined = 2,
    /// `DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN` — physical layer
    /// down on the source link.
    MediaDown = 3,
    /// `DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH`.
    FractionalFrequencyOffsetTooHigh = 4,
}

/// ITU-T G.8264 clock quality level (SyncE SSM-style indication).
///
/// Wire: `u32` per `DPLL_CLOCK_QUALITY_LEVEL_*` (kernel 6.10+).
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllClockQualityLevel {
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_PRC` — primary
    /// reference clock.
    ItuOpt1Prc = 1,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_SSU_A`.
    ItuOpt1SsuA = 2,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_SSU_B`.
    ItuOpt1SsuB = 3,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_EEC1`.
    ItuOpt1Eec1 = 4,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_PRTC` — primary
    /// reference time clock.
    ItuOpt1Prtc = 5,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_EPRTC` — enhanced
    /// primary reference time clock.
    ItuOpt1Eprtc = 6,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_EEEC`.
    ItuOpt1Eeec = 7,
    /// `DPLL_CLOCK_QUALITY_LEVEL_ITU_OPT_1_EPRC` — enhanced
    /// primary reference clock.
    ItuOpt1Eprc = 8,
}

/// On/off toggle for the kernel 6.12+ phase-offset and
/// frequency monitoring features. The one 0-based DPLL enum —
/// `DPLL_FEATURE_STATE_DISABLE = 0`, `_ENABLE = 1`.
///
/// Wire: `u32` per `DPLL_FEATURE_STATE_*`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum DpllFeatureState {
    /// `DPLL_FEATURE_STATE_DISABLE`.
    Disable = 0,
    /// `DPLL_FEATURE_STATE_ENABLE`.
    Enable = 1,
}

// ============================================================
// Pin capability bitmask
// ============================================================

bitflags::bitflags! {
    /// Per-pin capability bitmask reported by
    /// `DPLL_A_PIN_CAPABILITIES`. Decides which `pin_set`
    /// operations the kernel will accept on the pin —
    /// `DIRECTION_CAN_CHANGE` for example means
    /// `Connection::set_pin_state(Output)` is allowed.
    ///
    /// Wire: `u32` per `DPLL_PIN_CAPABILITIES_*`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct DpllPinCapabilities: u32 {
        /// `DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE`.
        const DIRECTION_CAN_CHANGE = 1;
        /// `DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE`.
        const PRIORITY_CAN_CHANGE = 2;
        /// `DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE`.
        const STATE_CAN_CHANGE = 4;
    }
}

// ============================================================
// Tests — round-trips through every typed-codec derive
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codec_round_trips_every_variant() {
        for (variant, expected) in [
            (DpllCmd::DeviceIdGet, 1u8),
            (DpllCmd::DeviceGet, 2),
            (DpllCmd::DeviceSet, 3),
            (DpllCmd::DeviceCreateNtf, 4),
            (DpllCmd::DeviceDeleteNtf, 5),
            (DpllCmd::DeviceChangeNtf, 6),
            (DpllCmd::PinIdGet, 7),
            (DpllCmd::PinGet, 8),
            (DpllCmd::PinSet, 9),
            (DpllCmd::PinCreateNtf, 10),
            (DpllCmd::PinDeleteNtf, 11),
            (DpllCmd::PinChangeNtf, 12),
        ] {
            let raw: u8 = variant.into();
            assert_eq!(raw, expected, "From<DpllCmd> for u8 mismatch");
            let back: DpllCmd = DpllCmd::try_from(raw).expect("TryFrom roundtrip");
            assert_eq!(back, variant, "TryFrom<u8> for DpllCmd mismatch");
        }
    }

    #[test]
    fn command_codec_rejects_unknown_value() {
        let err = DpllCmd::try_from(99u8).unwrap_err();
        assert!(format!("{err}").contains("99"));
    }

    #[test]
    fn device_attribute_codec_round_trips() {
        let pairs = [
            (DpllAttr::Id, 1u16),
            (DpllAttr::Mode, 5),
            (DpllAttr::LockStatus, 7),
            (DpllAttr::FrequencyMonitor, 14),
        ];
        for (variant, expected) in pairs {
            let raw: u16 = variant.into();
            assert_eq!(raw, expected);
            assert_eq!(DpllAttr::try_from(raw).unwrap(), variant);
        }
    }

    #[test]
    fn pin_attribute_codec_round_trips_low_and_high_ids() {
        // Cover the 1, mid, and 31 variants — the high-numbered
        // attrs are the 6.11+ additions; ensures we didn't
        // misnumber them.
        for (v, expected) in [
            (DpllPinAttr::Id, 1u16),
            (DpllPinAttr::Capabilities, 17),
            (DpllPinAttr::PhaseAdjustGran, 29),
            (DpllPinAttr::MeasuredFrequency, 31),
        ] {
            assert_eq!(u16::from(v), expected);
            assert_eq!(DpllPinAttr::try_from(expected).unwrap(), v);
        }
    }

    #[test]
    fn value_enums_round_trip_via_u32() {
        // Sample one variant from every value enum — exhaustive
        // listing would be repetitive without adding coverage.
        macro_rules! check {
            ($enum:ty, $variant:expr, $expected:expr) => {{
                let v: $enum = $variant;
                let raw: u32 = v.into();
                assert_eq!(raw, $expected);
                assert_eq!(<$enum>::try_from(raw).unwrap(), v);
            }};
        }
        check!(DpllMode, DpllMode::Automatic, 2);
        check!(DpllLockStatus, DpllLockStatus::LockedHoAcq, 3);
        check!(DpllType, DpllType::Eec, 2);
        check!(DpllPinType, DpllPinType::SynceEthPort, 3);
        check!(DpllPinDirection, DpllPinDirection::Output, 2);
        check!(DpllPinState, DpllPinState::Selectable, 3);
        check!(DpllLockStatusError, DpllLockStatusError::MediaDown, 3);
        check!(DpllClockQualityLevel, DpllClockQualityLevel::ItuOpt1Prtc, 5);
    }

    #[test]
    fn feature_state_handles_zero_discriminant() {
        // The one 0-based enum. Verifies the GenlEnum derive
        // doesn't assume 1-based discriminants.
        let raw: u32 = DpllFeatureState::Disable.into();
        assert_eq!(raw, 0);
        assert_eq!(
            DpllFeatureState::try_from(0u32).unwrap(),
            DpllFeatureState::Disable
        );
        assert_eq!(
            DpllFeatureState::try_from(1u32).unwrap(),
            DpllFeatureState::Enable
        );
    }

    #[test]
    fn pin_capabilities_combine_via_bitor() {
        let combined =
            DpllPinCapabilities::DIRECTION_CAN_CHANGE | DpllPinCapabilities::STATE_CAN_CHANGE;
        assert_eq!(combined.bits(), 0b101);
        assert!(combined.contains(DpllPinCapabilities::DIRECTION_CAN_CHANGE));
        assert!(!combined.contains(DpllPinCapabilities::PRIORITY_CAN_CHANGE));
        // from_bits_retain preserves unknown bits — the contract
        // the GenlMessage bitflags-field codec relies on.
        let with_unknown = DpllPinCapabilities::from_bits_retain(0xFF);
        assert_eq!(with_unknown.bits(), 0xFF);
    }
}
