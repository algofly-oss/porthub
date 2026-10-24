//! `Connection<Dpll>` helper methods.
//!
//! Thin wrappers over the generic
//! [`Connection::send_typed`][crate::netlink::Connection::send_typed]
//! / [`dump_typed_stream`][crate::netlink::Connection::dump_typed_stream]
//! dispatch that the `#[derive(GenlMessage)]` + `#[genl_family]`
//! machinery (Plan 154) provides. The helpers exist so downstream
//! code can write `conn.get_device(id).await?` instead of
//! `conn.send_typed(DpllDeviceGetRequest::by_id(id)).await?` —
//! same semantics, more discoverable.

use crate::macros::GenlTypedDumpStream;
use crate::netlink::{
    connection::Connection,
    error::Result,
    genl::dpll::messages::{
        DpllDeviceGetRequest, DpllDeviceReply, DpllDeviceSetRequest, DpllPinGetRequest,
        DpllPinReply, DpllPinSetRequest,
    },
    genl::dpll::types::{DpllFeatureState, DpllMode, DpllPinDirection, DpllPinState},
};

use super::Dpll;

#[nlink_macros::send_futures]
impl Connection<Dpll> {
    /// Query a single device by ID.
    ///
    /// Returns the kernel's [`DpllDeviceReply`] — every attribute
    /// the device exposes, with version-gated fields surfacing as
    /// `None` on kernels that don't ship them.
    ///
    /// `Error::is_not_found()` if the kernel doesn't have a
    /// device with `id`.
    pub async fn get_device(&self, id: u32) -> Result<DpllDeviceReply> {
        self.send_typed(DpllDeviceGetRequest::by_id(id)).await
    }

    /// Stream every DPLL device the kernel reports.
    ///
    /// Returns a [`GenlTypedDumpStream`] that yields one
    /// [`DpllDeviceReply`] per kernel frame. On hosts without
    /// DPLL hardware the stream completes immediately with zero
    /// elements; no per-element error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::Dpll;
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<Dpll>::new_async().await?;
    /// let mut stream = conn.dump_devices().await?;
    /// while let Some(dev) = stream.next().await {
    ///     let dev = dev?;
    ///     println!("{}: {:?}", dev.id, dev.lock_status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_devices(
        &self,
    ) -> Result<GenlTypedDumpStream<'_, Dpll, DpllDeviceReply>> {
        self.dump_typed_stream(DpllDeviceGetRequest::dump()).await
    }

    /// Switch a device into the given mode (Manual ↔ Automatic).
    ///
    /// Most drivers reject `Manual` while in lock state
    /// `Unlocked` — surfaces as
    /// `Error::is_invalid_argument()`.
    pub async fn set_device_mode(&self, id: u32, mode: DpllMode) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).mode(mode))
            .await?;
        Ok(())
    }

    /// Enable or disable the device's phase-offset monitor
    /// (kernel 6.12+). Returns
    /// `Error::is_invalid_argument()` on older kernels (kernel
    /// refuses the unknown attribute under
    /// `enable_strict_checking`).
    pub async fn set_device_phase_offset_monitor(
        &self,
        id: u32,
        state: DpllFeatureState,
    ) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).phase_offset_monitor(state))
            .await?;
        Ok(())
    }

    /// Enable or disable the device's frequency monitor (kernel
    /// 6.12+).
    pub async fn set_device_frequency_monitor(
        &self,
        id: u32,
        state: DpllFeatureState,
    ) -> Result<()> {
        let _: DpllDeviceReply = self
            .send_typed(DpllDeviceSetRequest::new(id).frequency_monitor(state))
            .await?;
        Ok(())
    }

    // ---- Pin-side helpers ----------------------------------------

    /// Query a single pin by ID. Returns
    /// `Error::is_not_found()` if no pin with `id` exists.
    pub async fn get_pin(&self, id: u32) -> Result<DpllPinReply> {
        self.send_typed(DpllPinGetRequest::by_id(id)).await
    }

    /// Stream every DPLL pin the kernel reports — every device's
    /// pins are flattened into a single stream (use
    /// `pin.parent_device.parent_id` to group by device).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::Dpll;
    /// use tokio_stream::StreamExt;
    /// let conn = Connection::<Dpll>::new_async().await?;
    /// let mut stream = conn.dump_pins().await?;
    /// while let Some(pin) = stream.next().await {
    ///     let pin = pin?;
    ///     println!(
    ///         "pin {} ({:?}): {:?}",
    ///         pin.id,
    ///         pin.board_label.as_deref().unwrap_or("?"),
    ///         pin.state,
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_pins(
        &self,
    ) -> Result<GenlTypedDumpStream<'_, Dpll, DpllPinReply>> {
        self.dump_typed_stream(DpllPinGetRequest::dump()).await
    }

    /// Set a pin's selection priority. Lower priority wins
    /// during automatic-mode selection. Requires the pin's
    /// `DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE` capability.
    pub async fn set_pin_priority(&self, id: u32, priority: u32) -> Result<()> {
        let _: DpllPinReply = self
            .send_typed(DpllPinSetRequest::new(id).prio(priority))
            .await?;
        Ok(())
    }

    /// Set a pin's connection state. Requires
    /// `DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE`.
    pub async fn set_pin_state(&self, id: u32, state: DpllPinState) -> Result<()> {
        let _: DpllPinReply = self
            .send_typed(DpllPinSetRequest::new(id).state(state))
            .await?;
        Ok(())
    }

    /// Set a pin's frequency in Hz. The kernel rejects values
    /// outside the pin's `[frequency_min, frequency_max]` range
    /// or not in its `frequency_supported` list (driver-specific).
    pub async fn set_pin_frequency(&self, id: u32, hz: u64) -> Result<()> {
        let _: DpllPinReply = self
            .send_typed(DpllPinSetRequest::new(id).frequency(hz))
            .await?;
        Ok(())
    }

    /// Set a pin's direction (input ↔ output). Requires
    /// `DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE`.
    pub async fn set_pin_direction(
        &self,
        id: u32,
        direction: DpllPinDirection,
    ) -> Result<()> {
        let _: DpllPinReply = self
            .send_typed(DpllPinSetRequest::new(id).direction(direction))
            .await?;
        Ok(())
    }
}

