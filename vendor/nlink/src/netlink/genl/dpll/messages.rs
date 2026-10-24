//! Typed request + reply structs for the DPLL family.
//!
//! Every struct in this file is declared via
//! `#[derive(GenlMessage)]` from `nlink-macros` — the wire-format
//! plumbing (`to_bytes` / `from_bytes`) is generated, leaving the
//! Rust-side declaration to read like a schema document.
//!
//! Compare with the hand-written GENL families
//! (`crates/nlink/src/netlink/genl/wireguard/`, `macsec/`, etc.)
//! where the equivalent code spans 200+ lines of manual
//! `MessageBuilder` + `AttrIter` walks.

use crate::macros::{GenlMessage, NetlinkAttrs};

use super::types::{
    DpllAttr, DpllClockQualityLevel, DpllCmd, DpllFeatureState, DpllLockStatus,
    DpllLockStatusError, DpllMode, DpllPinAttr, DpllPinCapabilities, DpllPinDirection,
    DpllPinState, DpllPinType, DpllType,
};

// ============================================================
// Device-side messages
// ============================================================

/// `DPLL_CMD_DEVICE_GET` request — single-device get or dump.
///
/// Set `id` to `Some(id)` for a single-device query (sent with
/// `NLM_F_REQUEST | NLM_F_ACK` via `Connection::send_typed`).
/// Set `id` to `None` for a full dump via
/// `Connection::dump_typed_stream` — the dump emits no
/// `DPLL_A_ID` attribute (matches the kernel's "no filter ⇒ list
/// every device" shape).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceGet)]
pub struct DpllDeviceGetRequest {
    /// Device ID to query. `None` = "no filter; dump all".
    #[genl_attr(DpllAttr::Id)]
    pub id: Option<u32>,
}

impl DpllDeviceGetRequest {
    /// Construct a single-device get request by ID.
    pub fn by_id(id: u32) -> Self {
        Self { id: Some(id) }
    }

    /// Construct a dump request (no ID filter).
    pub fn dump() -> Self {
        Self { id: None }
    }
}

/// `DPLL_CMD_DEVICE_GET` / `_CHANGE_NTF` reply — a device's
/// complete state.
///
/// Every field reflects an attribute the kernel may emit:
/// values present in every reply are non-`Option`; values added
/// in later kernel versions or only emitted in some configurations
/// are `Option<T>`. The macro derive defaults missing fields to
/// their type-defaults, so consumers can match on `None` to detect
/// "the kernel didn't ship this attribute" without surfacing a
/// parse error.
///
/// **Scaling fields:**
/// - `temp_mdeg` is milli-degrees Celsius. Divide by
///   [`super::DPLL_TEMP_DIVIDER`] (= 1000) for °C.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceGet)]
#[non_exhaustive]
pub struct DpllDeviceReply {
    /// Numeric device ID (stable across the kernel's lifetime).
    #[genl_attr(DpllAttr::Id)]
    pub id: u32,
    /// Driver module name (e.g., `"ice"`, `"mlx5"`).
    #[genl_attr(DpllAttr::ModuleName)]
    pub module_name: String,
    /// Hardware clock identifier (PCIe BDF-derived per UAPI).
    #[genl_attr(DpllAttr::ClockId)]
    pub clock_id: u64,
    /// Current mode. `None` if the kernel didn't ship the
    /// attribute (shouldn't happen on a normal `DEVICE_GET` —
    /// would indicate a kernel/binary mismatch).
    #[genl_attr(DpllAttr::Mode, repr = "u32")]
    pub mode: Option<DpllMode>,
    /// Modes the device supports. Each `DPLL_A_MODE_SUPPORTED`
    /// attr in the response is one element.
    #[genl_attr(DpllAttr::ModeSupported, repr = "u32")]
    pub mode_supported: Vec<DpllMode>,
    /// Current lock state. `None` if absent — see `mode` note.
    #[genl_attr(DpllAttr::LockStatus, repr = "u32")]
    pub lock_status: Option<DpllLockStatus>,
    /// Device temperature, milli-degrees Celsius. `None` if the
    /// driver doesn't expose temperature.
    #[genl_attr(DpllAttr::Temp)]
    pub temp_mdeg: Option<i32>,
    /// DPLL kind (PPS / EEC). `None` if absent.
    #[genl_attr(DpllAttr::Type, repr = "u32")]
    pub kind: Option<DpllType>,
    /// Reason for lock failure (kernel 6.10+). `None` on older
    /// kernels or when no error is active.
    #[genl_attr(DpllAttr::LockStatusError, repr = "u32")]
    pub lock_status_error: Option<DpllLockStatusError>,
    /// Currently-asserted ITU-T G.8264 quality levels (kernel
    /// 6.10+; may be multiple, hence Vec).
    #[genl_attr(DpllAttr::ClockQualityLevel, repr = "u32")]
    pub clock_quality_level: Vec<DpllClockQualityLevel>,
    /// Phase-offset monitor on/off (kernel 6.12+). `None` on
    /// older kernels.
    #[genl_attr(DpllAttr::PhaseOffsetMonitor, repr = "u32")]
    pub phase_offset_monitor: Option<DpllFeatureState>,
    /// Moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[genl_attr(DpllAttr::PhaseOffsetAvgFactor)]
    pub phase_offset_avg_factor: Option<u32>,
    /// Frequency monitor on/off (kernel 6.12+).
    #[genl_attr(DpllAttr::FrequencyMonitor, repr = "u32")]
    pub frequency_monitor: Option<DpllFeatureState>,
}

/// `DPLL_CMD_DEVICE_SET` request — mutate a device's state.
///
/// Construct with [`Self::new`] then chain setter methods for
/// the fields you want to change. Unset fields stay `None` and
/// are omitted from the wire request (`Option`-typed attrs).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::DeviceSet)]
pub struct DpllDeviceSetRequest {
    /// Target device ID. Always present.
    #[genl_attr(DpllAttr::Id)]
    pub id: u32,
    /// New mode, if changing.
    #[genl_attr(DpllAttr::Mode, repr = "u32")]
    pub mode: Option<DpllMode>,
    /// Toggle the kernel 6.12+ phase-offset monitor.
    #[genl_attr(DpllAttr::PhaseOffsetMonitor, repr = "u32")]
    pub phase_offset_monitor: Option<DpllFeatureState>,
    /// Set the moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[genl_attr(DpllAttr::PhaseOffsetAvgFactor)]
    pub phase_offset_avg_factor: Option<u32>,
    /// Toggle the kernel 6.12+ frequency monitor.
    #[genl_attr(DpllAttr::FrequencyMonitor, repr = "u32")]
    pub frequency_monitor: Option<DpllFeatureState>,
}

impl DpllDeviceSetRequest {
    /// Start a set request targeting `id`. Chain `mode(...)`,
    /// `phase_offset_monitor(...)`, etc. before sending.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }

    /// Switch the device into the given mode.
    #[must_use]
    pub fn mode(mut self, mode: DpllMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Enable or disable the kernel 6.12+ phase-offset monitor.
    #[must_use]
    pub fn phase_offset_monitor(mut self, state: DpllFeatureState) -> Self {
        self.phase_offset_monitor = Some(state);
        self
    }

    /// Set the moving-average factor for phase-offset reporting
    /// (kernel 6.12+).
    #[must_use]
    pub fn phase_offset_avg_factor(mut self, factor: u32) -> Self {
        self.phase_offset_avg_factor = Some(factor);
        self
    }

    /// Enable or disable the kernel 6.12+ frequency monitor.
    #[must_use]
    pub fn frequency_monitor(mut self, state: DpllFeatureState) -> Self {
        self.frequency_monitor = Some(state);
        self
    }
}

impl DpllDeviceReply {
    /// Device temperature in degrees Celsius, if reported.
    /// Convenience wrapper around the raw `temp_mdeg` field.
    pub fn temp_celsius(&self) -> Option<f32> {
        self.temp_mdeg.map(|m| m as f32 / super::DPLL_TEMP_DIVIDER as f32)
    }
}

// ============================================================
// Pin-side nested attribute groups
// ============================================================

/// Inner block of `DPLL_A_PIN_PARENT_DEVICE` — links a pin to
/// its parent device with a per-link connection state.
///
/// Wire shape: nested attribute group inside the pin reply.
#[derive(NetlinkAttrs, Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DpllPinParentDevice {
    /// Parent device's numeric ID.
    #[genl_attr(DpllPinAttr::ParentId)]
    pub parent_id: u32,
    /// Connection state from this pin to the parent device.
    /// `Option<>` because the kernel may report a parenting link
    /// without an active state (e.g., disabled parent).
    #[genl_attr(DpllPinAttr::State, repr = "u32")]
    pub state: Option<DpllPinState>,
}

/// Inner block of `DPLL_A_PIN_PARENT_PIN` — chains a pin to
/// another pin (mux selection).
///
/// Wire shape: nested attribute group inside the pin reply.
#[derive(NetlinkAttrs, Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DpllPinParentPin {
    /// Parent pin's numeric ID.
    #[genl_attr(DpllPinAttr::ParentId)]
    pub parent_id: u32,
    /// Connection state from this pin to the parent pin.
    #[genl_attr(DpllPinAttr::State, repr = "u32")]
    pub state: Option<DpllPinState>,
}

// ============================================================
// Pin-side messages
// ============================================================

/// `DPLL_CMD_PIN_GET` request — single-pin get or full dump.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::PinGet)]
pub struct DpllPinGetRequest {
    /// Pin ID to query. `None` = "no filter; dump all".
    #[genl_attr(DpllPinAttr::Id)]
    pub id: Option<u32>,
}

impl DpllPinGetRequest {
    /// Construct a single-pin get request by ID.
    pub fn by_id(id: u32) -> Self {
        Self { id: Some(id) }
    }

    /// Construct a dump request (no ID filter).
    pub fn dump() -> Self {
        Self { id: None }
    }
}

/// `DPLL_CMD_PIN_GET` / `_CHANGE_NTF` reply — a pin's complete
/// state. Every supported attribute is represented; version-gated
/// fields are `Option<T>`. Repeated attributes (frequency
/// supported ranges, ESYNC supported frequencies) are `Vec<u64>`.
///
/// **Scaling fields:**
/// - `phase_offset` is attoseconds × 1000. Divide by
///   [`super::DPLL_PHASE_OFFSET_DIVIDER`] (= 1000) for ns —
///   [`Self::phase_offset_ns`] does this.
/// - `measured_frequency` is mHz × 1000. Divide by
///   [`super::DPLL_PIN_MEASURED_FREQUENCY_DIVIDER`] (= 1000) for
///   Hz — [`Self::measured_frequency_hz`] does this.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::PinGet)]
#[non_exhaustive]
pub struct DpllPinReply {
    /// Pin ID.
    #[genl_attr(DpllPinAttr::Id)]
    pub id: u32,
    /// Driver module name.
    #[genl_attr(DpllPinAttr::ModuleName)]
    pub module_name: String,
    /// Hardware clock ID this pin belongs to.
    #[genl_attr(DpllPinAttr::ClockId)]
    pub clock_id: u64,
    /// Vendor-supplied board label (silkscreen).
    #[genl_attr(DpllPinAttr::BoardLabel)]
    pub board_label: Option<String>,
    /// Front-panel label.
    #[genl_attr(DpllPinAttr::PanelLabel)]
    pub panel_label: Option<String>,
    /// Package-level label.
    #[genl_attr(DpllPinAttr::PackageLabel)]
    pub package_label: Option<String>,
    /// Pin kind (mux, ext, SyncE eth port, …).
    #[genl_attr(DpllPinAttr::Type, repr = "u32")]
    pub kind: Option<DpllPinType>,
    /// Direction (input / output).
    #[genl_attr(DpllPinAttr::Direction, repr = "u32")]
    pub direction: Option<DpllPinDirection>,
    /// Current frequency in Hz.
    #[genl_attr(DpllPinAttr::Frequency)]
    pub frequency: Option<u64>,
    /// Supported frequencies (repeated `DPLL_A_PIN_FREQUENCY_SUPPORTED`).
    #[genl_attr(DpllPinAttr::FrequencyMin)]
    pub frequency_min: Option<u64>,
    /// Maximum supported frequency.
    #[genl_attr(DpllPinAttr::FrequencyMax)]
    pub frequency_max: Option<u64>,
    /// Selection priority (lower wins).
    #[genl_attr(DpllPinAttr::Prio)]
    pub prio: Option<u32>,
    /// Current state.
    #[genl_attr(DpllPinAttr::State, repr = "u32")]
    pub state: Option<DpllPinState>,
    /// Capability bitmask — decides which `set_pin_*` ops the
    /// kernel will accept.
    #[genl_attr(DpllPinAttr::Capabilities, bitflags = "u32")]
    pub capabilities: DpllPinCapabilities,
    /// Nested: parent-device link block.
    #[genl_attr(DpllPinAttr::ParentDevice, nested)]
    pub parent_device: Option<DpllPinParentDevice>,
    /// Nested: parent-pin link block (only set on mux pins).
    #[genl_attr(DpllPinAttr::ParentPin, nested)]
    pub parent_pin: Option<DpllPinParentPin>,
    /// Phase-adjust minimum (picoseconds).
    #[genl_attr(DpllPinAttr::PhaseAdjustMin)]
    pub phase_adjust_min: Option<i32>,
    /// Phase-adjust maximum.
    #[genl_attr(DpllPinAttr::PhaseAdjustMax)]
    pub phase_adjust_max: Option<i32>,
    /// Current phase adjustment.
    #[genl_attr(DpllPinAttr::PhaseAdjust)]
    pub phase_adjust: Option<i32>,
    /// Measured phase offset (attoseconds × 1000 — use
    /// [`Self::phase_offset_ns`] for nanoseconds).
    ///
    /// Wire type: kernel `s64` per
    /// `Documentation/netlink/specs/dpll.yaml`. Plan 206 (0.19)
    /// corrected this from `Option<i32>` to `Option<i64>` — the
    /// pre-0.19 type silently truncated the high 4 bytes on LE
    /// platforms, producing nonsense readings for any offset
    /// above ~2.147 seconds in attoseconds × 1000 units
    /// (essentially always; a 1 ns offset is 1e9 in those units,
    /// well past `i32::MAX`).
    #[genl_attr(DpllPinAttr::PhaseOffset)]
    pub phase_offset: Option<i64>,
    /// ESYNC carrier frequency (kernel 6.10+).
    #[genl_attr(DpllPinAttr::EsyncFrequency)]
    pub esync_frequency: Option<u64>,
    /// ESYNC pulse-width configuration (kernel 6.10+).
    #[genl_attr(DpllPinAttr::EsyncPulse)]
    pub esync_pulse: Option<u32>,
    /// Phase-adjust granularity (picoseconds, kernel 6.11+).
    #[genl_attr(DpllPinAttr::PhaseAdjustGran)]
    pub phase_adjust_gran: Option<u32>,
    /// Fractional frequency offset in parts-per-trillion
    /// (kernel 6.11+).
    ///
    /// The kernel emits this field as `sint` (variable-length signed
    /// integer per `nla_put_sint`) — 4 bytes if the value fits in
    /// `s32`, 8 bytes otherwise. The macro routes through
    /// `parse_sint_attr_as_i64`, so both widths parse correctly.
    ///
    /// **0.21 widening (BREAKING)**: type widened from `Option<i32>`
    /// to `Option<i64>`. Pre-0.21 the field silently failed the whole
    /// `DpllPinReply::from_bytes` parse when the kernel emitted an
    /// 8-byte sint that overflowed `i32`; SyncE bring-up typically
    /// emits such values. The widening removes that failure mode.
    /// Callers using `as i32` casts or `i32` arithmetic on the field
    /// must widen to `i64`.
    #[genl_attr(DpllPinAttr::FractionalFrequencyOffsetPpt, sint)]
    pub fractional_frequency_offset_ppt: Option<i64>,
    /// Measured frequency in mHz × 1000 (kernel 6.11+) — use
    /// [`Self::measured_frequency_hz`] for Hz.
    #[genl_attr(DpllPinAttr::MeasuredFrequency)]
    pub measured_frequency: Option<u64>,
}

impl DpllPinReply {
    /// Pin phase offset in nanoseconds, if reported.
    /// Applies the kernel's `DPLL_PHASE_OFFSET_DIVIDER = 1000`.
    pub fn phase_offset_ns(&self) -> Option<i64> {
        // Plan 206: phase_offset is now already i64; no truncation
        // cast needed.
        self.phase_offset.map(|p| p / super::DPLL_PHASE_OFFSET_DIVIDER)
    }

    /// Measured pin frequency in Hz, if reported (kernel 6.11+).
    /// Applies the kernel's
    /// `DPLL_PIN_MEASURED_FREQUENCY_DIVIDER = 1000`.
    pub fn measured_frequency_hz(&self) -> Option<u64> {
        self.measured_frequency
            .map(|m| m / super::DPLL_PIN_MEASURED_FREQUENCY_DIVIDER)
    }

    /// Fractional frequency offset as `i64`, parsed from a raw
    /// payload byte slice without going through
    /// [`Self::from_bytes`].
    ///
    /// As of 0.21 the struct field
    /// [`Self::fractional_frequency_offset_ppt`] is already `i64`,
    /// so this helper is informational — call it when you have the
    /// raw attribute bytes but not a parsed `DpllPinReply` (e.g.
    /// when extracting a single attribute from a dump frame).
    ///
    /// Returns:
    /// - `Some(value)` when the payload contains a 4- or 8-byte
    ///   `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT` attribute.
    /// - `None` when the attribute is absent.
    pub fn ffo_ppt_i64_from_payload(payload: &[u8]) -> Option<i64> {
        for (attr_type, attr_payload)
            in crate::macros::__rt::attr_iter(payload)
        {
            if attr_type as u32
                == super::types::DpllPinAttr::FractionalFrequencyOffsetPpt as u32
            {
                return crate::macros::__rt::parse_sint_attr_as_i64(attr_payload).ok();
            }
        }
        None
    }
}

/// `DPLL_CMD_PIN_SET` request — mutate a pin's state.
///
/// Construct with [`Self::new`] then chain setter methods.
/// Unset fields stay `None` and are omitted from the wire request.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = DpllCmd::PinSet)]
pub struct DpllPinSetRequest {
    /// Target pin ID. Always present.
    #[genl_attr(DpllPinAttr::Id)]
    pub id: u32,
    /// New selection priority.
    #[genl_attr(DpllPinAttr::Prio)]
    pub prio: Option<u32>,
    /// New state (Connected / Disconnected / Selectable).
    #[genl_attr(DpllPinAttr::State, repr = "u32")]
    pub state: Option<DpllPinState>,
    /// New frequency in Hz.
    #[genl_attr(DpllPinAttr::Frequency)]
    pub frequency: Option<u64>,
    /// New direction (if the pin's capabilities allow changing).
    #[genl_attr(DpllPinAttr::Direction, repr = "u32")]
    pub direction: Option<DpllPinDirection>,
    /// New phase adjustment in picoseconds.
    #[genl_attr(DpllPinAttr::PhaseAdjust)]
    pub phase_adjust: Option<i32>,
}

impl DpllPinSetRequest {
    /// Start a set request targeting `id`.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }

    /// Set the pin's selection priority (lower = higher priority).
    #[must_use]
    pub fn prio(mut self, prio: u32) -> Self {
        self.prio = Some(prio);
        self
    }

    /// Set the pin's connection state.
    #[must_use]
    pub fn state(mut self, state: DpllPinState) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the pin's frequency in Hz.
    #[must_use]
    pub fn frequency(mut self, hz: u64) -> Self {
        self.frequency = Some(hz);
        self
    }

    /// Set the pin's direction (input ↔ output) — only legal if
    /// the pin's `DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE` bit
    /// is set in its capabilities; the kernel rejects otherwise.
    #[must_use]
    pub fn direction(mut self, direction: DpllPinDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Set the pin's phase adjustment in picoseconds.
    #[must_use]
    pub fn phase_adjust(mut self, ps: i32) -> Self {
        self.phase_adjust = Some(ps);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::__rt;
    use crate::netlink::MessageBuilder;

    #[test]
    fn device_get_request_with_id_emits_one_attr() {
        let req = DpllDeviceGetRequest::by_id(7);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        assert_eq!(attrs, vec![DpllAttr::Id as u16]);
    }

    #[test]
    fn device_get_dump_emits_no_attrs() {
        let req = DpllDeviceGetRequest::dump();
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let count = __rt::attr_iter(bytes).count();
        assert_eq!(count, 0, "dump request should emit zero attrs");
    }

    #[test]
    fn device_reply_round_trips_a_full_attr_set() {
        let original = DpllDeviceReply {
            id: 42,
            module_name: "ice".to_string(),
            clock_id: 0x0011_2233_4455_6677,
            mode: Some(DpllMode::Automatic),
            mode_supported: vec![DpllMode::Manual, DpllMode::Automatic],
            lock_status: Some(DpllLockStatus::LockedHoAcq),
            temp_mdeg: Some(47_500),
            kind: Some(DpllType::Eec),
            lock_status_error: None,
            clock_quality_level: vec![DpllClockQualityLevel::ItuOpt1Prc],
            phase_offset_monitor: Some(DpllFeatureState::Enable),
            phase_offset_avg_factor: Some(8),
            frequency_monitor: Some(DpllFeatureState::Disable),
        };

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        original.to_bytes(&mut b).expect("emit");
        let parsed = DpllDeviceReply::from_bytes(&b.as_bytes()[start..]).expect("parse");
        // Vec fields preserve order; everything else compares directly.
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.module_name, original.module_name);
        assert_eq!(parsed.clock_id, original.clock_id);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.mode_supported, original.mode_supported);
        assert_eq!(parsed.lock_status, original.lock_status);
        assert_eq!(parsed.temp_mdeg, original.temp_mdeg);
        assert_eq!(parsed.kind, original.kind);
        assert_eq!(parsed.lock_status_error, original.lock_status_error);
        assert_eq!(parsed.clock_quality_level, original.clock_quality_level);
        assert_eq!(parsed.phase_offset_monitor, original.phase_offset_monitor);
        assert_eq!(parsed.phase_offset_avg_factor, original.phase_offset_avg_factor);
        assert_eq!(parsed.frequency_monitor, original.frequency_monitor);
    }

    /// v7.x added `DPLL_TYPE_GENERIC` (3), which `DpllType` doesn't
    /// have yet. A device of that type reads with `kind: None`; before
    /// #727 its whole reply failed to parse, and so did the dump.
    #[test]
    fn a_device_of_a_newer_type_still_parses() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        __rt::emit_u32_attr(&mut b, DpllAttr::Id as u16, 5);
        __rt::emit_str_attr(&mut b, DpllAttr::ModuleName as u16, "zl3073x");
        __rt::emit_u32_attr(&mut b, DpllAttr::Type as u16, 3);
        __rt::emit_u32_attr(&mut b, DpllAttr::Mode as u16, DpllMode::Automatic as u32);
        __rt::emit_u32_attr(&mut b, DpllAttr::ModeSupported as u16, DpllMode::Manual as u32);
        __rt::emit_u32_attr(&mut b, DpllAttr::ModeSupported as u16, 99);
        let parsed = DpllDeviceReply::from_bytes(&b.as_bytes()[start..])
            .expect("a newer enum value must not fail the reply");
        assert_eq!(parsed.id, 5);
        assert_eq!(parsed.module_name, "zl3073x");
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.mode, Some(DpllMode::Automatic));
        assert_eq!(parsed.mode_supported, vec![DpllMode::Manual]);
    }

    #[test]
    fn device_reply_missing_attrs_yield_defaults_and_nones() {
        let parsed = DpllDeviceReply::from_bytes(&[]).expect("parse");
        assert_eq!(parsed.id, 0);
        assert_eq!(parsed.module_name, "");
        assert_eq!(parsed.clock_id, 0);
        assert_eq!(parsed.mode, None);
        assert!(parsed.mode_supported.is_empty());
        assert_eq!(parsed.lock_status, None);
        assert_eq!(parsed.temp_mdeg, None);
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.lock_status_error, None);
        assert!(parsed.clock_quality_level.is_empty());
        assert_eq!(parsed.phase_offset_monitor, None);
        assert_eq!(parsed.frequency_monitor, None);
    }

    #[test]
    fn device_set_builder_emits_only_set_fields() {
        let req = DpllDeviceSetRequest::new(7)
            .mode(DpllMode::Manual)
            .frequency_monitor(DpllFeatureState::Enable);

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        // id is always emitted; mode + frequency_monitor were set;
        // phase_offset_monitor + phase_offset_avg_factor were left None.
        assert_eq!(
            attrs,
            vec![
                DpllAttr::Id as u16,
                DpllAttr::Mode as u16,
                DpllAttr::FrequencyMonitor as u16,
            ]
        );
    }

    // ---- Pin-side tests --------------------------------------

    #[test]
    fn pin_get_request_with_id_emits_one_attr() {
        let req = DpllPinGetRequest::by_id(12);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        assert_eq!(attrs, vec![DpllPinAttr::Id as u16]);
    }

    #[test]
    fn pin_reply_round_trips_with_nested_parent_device() {
        let original = DpllPinReply {
            id: 5,
            module_name: "ice".to_string(),
            clock_id: 0xC1F0_D000,
            board_label: Some("REF0".to_string()),
            kind: Some(DpllPinType::SynceEthPort),
            direction: Some(DpllPinDirection::Input),
            frequency: Some(10_000_000),
            prio: Some(1),
            state: Some(DpllPinState::Connected),
            capabilities: DpllPinCapabilities::PRIORITY_CAN_CHANGE
                | DpllPinCapabilities::STATE_CAN_CHANGE,
            parent_device: Some(DpllPinParentDevice {
                parent_id: 42,
                state: Some(DpllPinState::Connected),
            }),
            phase_offset: Some(123_000),
            measured_frequency: Some(10_000_000_000),
            ..DpllPinReply::default()
        };

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        original.to_bytes(&mut b).expect("emit");
        let parsed = DpllPinReply::from_bytes(&b.as_bytes()[start..]).expect("parse");

        assert_eq!(parsed.id, 5);
        assert_eq!(parsed.module_name, "ice");
        assert_eq!(parsed.clock_id, 0xC1F0_D000);
        assert_eq!(parsed.board_label.as_deref(), Some("REF0"));
        assert_eq!(parsed.kind, Some(DpllPinType::SynceEthPort));
        assert_eq!(parsed.direction, Some(DpllPinDirection::Input));
        assert_eq!(parsed.frequency, Some(10_000_000));
        assert_eq!(parsed.prio, Some(1));
        assert_eq!(parsed.state, Some(DpllPinState::Connected));
        assert_eq!(
            parsed.capabilities,
            DpllPinCapabilities::PRIORITY_CAN_CHANGE | DpllPinCapabilities::STATE_CAN_CHANGE
        );
        let parent = parsed.parent_device.expect("parent_device present");
        assert_eq!(parent.parent_id, 42);
        assert_eq!(parent.state, Some(DpllPinState::Connected));
        assert_eq!(parsed.phase_offset, Some(123_000));
        assert_eq!(parsed.measured_frequency, Some(10_000_000_000));
    }

    #[test]
    fn pin_reply_helpers_apply_dividers() {
        let reply = DpllPinReply {
            phase_offset: Some(123_456_000),
            measured_frequency: Some(10_000_000_000),
            ..DpllPinReply::default()
        };
        assert_eq!(reply.phase_offset_ns(), Some(123_456));
        assert_eq!(reply.measured_frequency_hz(), Some(10_000_000));
        assert_eq!(DpllPinReply::default().phase_offset_ns(), None);
        assert_eq!(DpllPinReply::default().measured_frequency_hz(), None);
    }

    /// Plan 206 regression — phase_offset is now `Option<i64>` so
    /// kernel values exceeding `i32::MAX` round-trip correctly.
    /// Pre-fix the value was silently truncated to the low 4 bytes
    /// on parse (`5_000_000_000` as `i32` → `705_032_704`),
    /// producing nonsense readings. A 5ns offset
    /// (5_000_000_000_000 attoseconds × 1000) is a realistic
    /// telco/PTP/SyncE value.
    #[test]
    fn pin_phase_offset_round_trips_value_above_i32_max() {
        let big_offset: i64 = 5_000_000_000_000; // 5 ns × DIVIDER
        assert!(
            big_offset > i32::MAX as i64,
            "test value must exceed i32::MAX to expose pre-fix truncation"
        );
        let original = DpllPinReply {
            id: 7,
            phase_offset: Some(big_offset),
            ..DpllPinReply::default()
        };
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        original.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let parsed = DpllPinReply::from_bytes(bytes).expect("parse");
        assert_eq!(
            parsed.phase_offset,
            Some(big_offset),
            "Plan 206 — i64 round-trip must preserve high bits"
        );
        // phase_offset_ns divides by 1000.
        assert_eq!(parsed.phase_offset_ns(), Some(5_000_000_000));
    }

    #[test]
    fn pin_set_builder_chains_priority_and_state() {
        let req = DpllPinSetRequest::new(7)
            .prio(2)
            .state(DpllPinState::Selectable);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        req.to_bytes(&mut b).expect("emit");
        let bytes = &b.as_bytes()[start..];

        let mut attrs: Vec<u16> = Vec::new();
        for (ty, _) in __rt::attr_iter(bytes) {
            attrs.push(ty);
        }
        assert_eq!(
            attrs,
            vec![
                DpllPinAttr::Id as u16,
                DpllPinAttr::Prio as u16,
                DpllPinAttr::State as u16,
            ]
        );
    }

    #[test]
    fn temp_celsius_helper_applies_divider() {
        let reply = DpllDeviceReply {
            temp_mdeg: Some(47_500),
            ..DpllDeviceReply::default()
        };
        let c = reply.temp_celsius().expect("temp present");
        assert!((c - 47.5).abs() < f32::EPSILON, "expected 47.5°C, got {c}");
        assert_eq!(
            DpllDeviceReply::default().temp_celsius(),
            None,
            "missing temp_mdeg → None"
        );
    }

    // -- Plan 226 DPLL FFO sint coverage ----------------------------

    /// Plan 226 (0.20.1) — small FFO values (in i32 range) still
    /// parse correctly through the new sint path.
    #[test]
    fn plan_226_ffo_ppt_small_value_round_trips_via_sint() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        // Emit as 4-byte sint (mimics what the kernel does for
        // values that fit in s32).
        __rt::emit_sint_attr(
            &mut b,
            DpllPinAttr::FractionalFrequencyOffsetPpt as u16,
            -42_i64,
        );
        let bytes = &b.as_bytes()[start..];

        // The macro-derived parse arm uses parse_sint_attr_as_i32;
        // a 4-byte payload becomes Some(-42).
        let parsed = DpllPinReply::from_bytes(bytes).expect("parse");
        assert_eq!(parsed.fractional_frequency_offset_ppt, Some(-42));
    }

    /// Plan 226 (0.20.1) — 8-byte FFO that fits in i32 parses cleanly
    /// (pre-Plan-226 would have silently truncated to the low 32 bits).
    #[test]
    fn plan_226_ffo_ppt_8_byte_in_range_parses_correctly() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        // Force 8-byte emit by routing through the u64-attr path
        // (mimics a kernel that ships a small value via the wider
        // sint width — e.g. a future kernel taking the always-8-byte
        // path for sint emission).
        b.append_attr_u64(
            DpllPinAttr::FractionalFrequencyOffsetPpt as u16,
            1_000_000_i64 as u64,
        );
        let bytes = &b.as_bytes()[start..];

        let parsed = DpllPinReply::from_bytes(bytes).expect("parse");
        assert_eq!(
            parsed.fractional_frequency_offset_ppt,
            Some(1_000_000),
            "8-byte sint payload that fits in i32 must parse exactly \
             (Plan 226 fix; pre-fix this would silently truncate)"
        );
    }

    /// 0.21 widening — 8-byte FFO that overflows `i32` now parses
    /// cleanly into the widened `i64` field. Pre-0.21 this would have
    /// failed the entire `from_bytes` call and forced callers through
    /// `ffo_ppt_i64_from_payload`; post-0.21 the struct field holds
    /// the full-width value directly.
    #[test]
    fn ffo_ppt_8_byte_overflow_parses_into_i64_field() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        let overflow = i32::MAX as i64 + 1_000_000;
        b.append_attr_u64(
            DpllPinAttr::FractionalFrequencyOffsetPpt as u16,
            overflow as u64,
        );
        let bytes = &b.as_bytes()[start..];

        // 0.21: parse succeeds, field holds the full-width value.
        let parsed = DpllPinReply::from_bytes(bytes).expect("parse");
        assert_eq!(
            parsed.fractional_frequency_offset_ppt,
            Some(overflow),
            "0.21 widening: i32-overflowing FFO now parses cleanly into i64 field"
        );

        // The raw-payload helper still returns the same value (kept for
        // callers that have the bytes but not a parsed struct).
        let recovered = DpllPinReply::ffo_ppt_i64_from_payload(bytes);
        assert_eq!(recovered, Some(overflow));
    }

    /// Plan 226 (0.20.1) — the helper returns None when the FFO
    /// attribute is absent (rather than spuriously synthesizing a
    /// value).
    #[test]
    fn plan_226_ffo_helper_returns_none_when_attribute_absent() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        b.append_attr_u32(DpllPinAttr::Id as u16, 7);
        let bytes = &b.as_bytes()[start..];

        assert_eq!(
            DpllPinReply::ffo_ppt_i64_from_payload(bytes),
            None,
            "absent FFO attr → None"
        );
    }
}
