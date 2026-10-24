//! Devlink connection implementation for `Connection<Devlink>`.

use super::{types::*, *};
use crate::macros::{GenlFamily, __rt::resolve_genl_family_with_groups};
use crate::netlink::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    dump_frame::{Classification, classify},
    error::{Error, Result},
    genl::{GENL_HDRLEN, GenlMsgHdr},
    message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError},
    protocol::{AsyncProtocolInit, Devlink},
    socket::NetlinkSocket,
};

impl AsyncProtocolInit for Devlink {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        let (family_id, mcast_groups) =
            resolve_genl_family_with_groups(socket, DEVLINK_GENL_NAME).await?;
        Ok(Self {
            family_id,
            mcast_groups,
        })
    }
}

impl GenlFamily for Devlink {
    const VERSION: u8 = DEVLINK_GENL_VERSION;
    const NAME: &'static str = DEVLINK_GENL_NAME;

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn mcast_group(&self, name: &str) -> Option<u32> {
        self.mcast_groups.get(name).copied()
    }
}

#[nlink_macros::send_futures]
impl Connection<Devlink> {
    /// Get the devlink family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Subscribe to devlink multicast events.
    ///
    /// Convenience wrapper around
    /// [`subscribe_group`](Connection::subscribe_group) for the
    /// `"config"` group (the only one devlink ships in-tree).
    /// After subscribing, use `events()` or `into_events()` to
    /// receive events.
    pub fn subscribe(&self) -> Result<()> {
        self.subscribe_group(DEVLINK_MCGRP_NAME)
    }

    // =========================================================================
    // Device Queries
    // =========================================================================

    /// List all devlink devices.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Devlink;
    /// # let conn = nlink::Connection::<nlink::netlink::Devlink>::new_async().await?;
    /// let devices = conn.get_devices().await?;
    /// for dev in &devices {
    ///     println!("{}", dev.path());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_devices"))]
    pub async fn get_devices(&self) -> Result<Vec<DevlinkDevice>> {
        let responses = self.devlink_dump(DEVLINK_CMD_GET).await?;
        let mut devices = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(dev) = parse_device(&payload[GENL_HDRLEN..]) {
                devices.push(dev);
            }
        }

        Ok(devices)
    }

    /// Get information for a specific device (driver, firmware versions).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Devlink;
    /// # let conn = nlink::Connection::<nlink::netlink::Devlink>::new_async().await?;
    /// let info = conn.get_device_info("pci", "0000:03:00.0").await?;
    /// println!("Driver: {}", info.driver);
    /// for v in &info.versions_running {
    ///     println!("  {}: {}", v.name, v.value);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device_info"))]
    pub async fn get_device_info(&self, bus: &str, device: &str) -> Result<DevlinkInfo> {
        let response = self.devlink_get(DEVLINK_CMD_INFO_GET, bus, device).await?;

        if response.len() < GENL_HDRLEN {
            return Err(Error::invalid_message("empty info response"));
        }

        parse_info(&response[GENL_HDRLEN..])
    }

    // =========================================================================
    // Port Queries
    // =========================================================================

    /// List all ports across all devices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_ports"))]
    pub async fn get_ports(&self) -> Result<Vec<DevlinkPort>> {
        let responses = self.devlink_dump(DEVLINK_CMD_PORT_GET).await?;
        let mut ports = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(port) = parse_port(&payload[GENL_HDRLEN..]) {
                ports.push(port);
            }
        }

        Ok(ports)
    }

    /// List ports for a specific device.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device_ports"))]
    pub async fn get_device_ports(&self, bus: &str, device: &str) -> Result<Vec<DevlinkPort>> {
        let ports = self.get_ports().await?;
        Ok(ports
            .into_iter()
            .filter(|p| p.bus == bus && p.device == device)
            .collect())
    }

    /// Get a specific port by device and index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_port"))]
    pub async fn get_port(
        &self,
        bus: &str,
        device: &str,
        index: u32,
    ) -> Result<Option<DevlinkPort>> {
        let ports = self.get_device_ports(bus, device).await?;
        Ok(ports.into_iter().find(|p| p.index == index))
    }

    /// Find the port associated with a network interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_port_by_netdev"))]
    pub async fn get_port_by_netdev(&self, netdev: &str) -> Result<Option<DevlinkPort>> {
        let ports = self.get_ports().await?;
        Ok(ports
            .into_iter()
            .find(|p| p.netdev_name.as_deref() == Some(netdev)))
    }

    // =========================================================================
    // Health Reporters
    // =========================================================================

    /// List all health reporters for a device: its own, and its ports'
    /// ([`HealthReporter::port`]). Only the device's: a kernel before
    /// per-instance dump filtering answers for every device (#777).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_health_reporters"))]
    pub async fn get_health_reporters(
        &self,
        bus: &str,
        device: &str,
    ) -> Result<Vec<HealthReporter>> {
        let responses = self
            .devlink_dump_with_device(DEVLINK_CMD_HEALTH_REPORTER_GET, bus, device)
            .await?;
        let mut reporters = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(reporter) = parse_health_response(bus, device, &payload[GENL_HDRLEN..]) {
                reporters.push(reporter);
            }
        }

        Ok(reporters)
    }

    /// Get a device's own health reporter by name; a port's of the same
    /// name is in [`get_health_reporters`](Self::get_health_reporters),
    /// with its [`port`](HealthReporter::port) (#777).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_health_reporter"))]
    pub async fn get_health_reporter(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<HealthReporter>> {
        let reporters = self.get_health_reporters(bus, device).await?;
        Ok(reporters.into_iter().find(|r| r.name == name && r.port.is_none()))
    }

    /// List health reporters that are in error state.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_health_errors"))]
    pub async fn get_health_errors(&self, bus: &str, device: &str) -> Result<Vec<HealthReporter>> {
        let reporters = self.get_health_reporters(bus, device).await?;
        Ok(reporters.into_iter().filter(|r| r.is_error()).collect())
    }

    // =========================================================================
    // Parameters
    // =========================================================================

    /// List all parameters for a device: only its own, where a kernel
    /// before per-instance dump filtering answers for every device (#777).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_params"))]
    pub async fn get_params(&self, bus: &str, device: &str) -> Result<Vec<DevlinkParam>> {
        let responses = self
            .devlink_dump_with_device(DEVLINK_CMD_PARAM_GET, bus, device)
            .await?;
        let mut params = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(param) = parse_param_response(bus, device, &payload[GENL_HDRLEN..]) {
                params.push(param);
            }
        }

        Ok(params)
    }

    /// Get a specific parameter by name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_param"))]
    pub async fn get_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
    ) -> Result<Option<DevlinkParam>> {
        let params = self.get_params(bus, device).await?;
        Ok(params.into_iter().find(|p| p.name == name))
    }

    // =========================================================================
    // Health Reporter Management
    // =========================================================================

    /// Trigger recovery on a health reporter.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "health_reporter_recover"))]
    pub async fn health_reporter_recover(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
    ) -> Result<()> {
        let mut builder =
            self.devlink_cmd_builder(DEVLINK_CMD_HEALTH_REPORTER_RECOVER, bus, device);
        let nested = builder.nest_start(DEVLINK_ATTR_HEALTH_REPORTER | 0x8000);
        builder.append_attr_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, reporter);
        builder.nest_end(nested);
        self.devlink_send_ack(builder).await
    }

    /// Configure a health reporter's settings.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_health_reporter"))]
    pub async fn set_health_reporter(
        &self,
        bus: &str,
        device: &str,
        reporter: &str,
        auto_recover: Option<bool>,
        auto_dump: Option<bool>,
        graceful_period_ms: Option<u64>,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_HEALTH_REPORTER_SET, bus, device);
        let nested = builder.nest_start(DEVLINK_ATTR_HEALTH_REPORTER | 0x8000);
        builder.append_attr_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, reporter);
        if let Some(v) = auto_recover {
            builder.append_attr(DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, &[u8::from(v)]);
        }
        if let Some(v) = auto_dump {
            builder.append_attr(DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, &[u8::from(v)]);
        }
        if let Some(ms) = graceful_period_ms {
            builder.append_attr(
                DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD,
                &ms.to_ne_bytes(),
            );
        }
        builder.nest_end(nested);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Flash Update
    // =========================================================================

    /// Flash firmware to a device.
    ///
    /// This is a long-running operation. The kernel will send progress
    /// notifications asynchronously.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flash_update"))]
    pub async fn flash_update(&self, bus: &str, device: &str, request: FlashRequest) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_FLASH_UPDATE, bus, device);
        builder.append_attr_str(DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME, &request.file_name);
        if let Some(component) = &request.component {
            builder.append_attr_str(DEVLINK_ATTR_FLASH_UPDATE_COMPONENT, component);
        }
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Reload
    // =========================================================================

    /// Reload the device with the specified action.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "reload"))]
    pub async fn reload(&self, bus: &str, device: &str, action: ReloadAction) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_RELOAD, bus, device);
        builder.append_attr(DEVLINK_ATTR_RELOAD_ACTION, &[action as u8]);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Rate-object CRUD (Plan 153.2) — SR-IOV VF / scheduler-node
    // rate-limiting via devlink-rate. Reuses the existing
    // devlink_cmd_builder helper for the bus/device prefix.
    // =========================================================================

    /// Create a new devlink rate object. Sets `rate_type`,
    /// `node_name`, and any of `tx_share` / `tx_max` /
    /// `parent_node` that the builder populated.
    ///
    /// On NICs without rate support (most non-SmartNIC hardware),
    /// the kernel returns `EOPNOTSUPP` — callers dispatch via
    /// `Error::is_not_supported()`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rate"))]
    pub async fn add_rate(&self, rate: &super::types::DevlinkRate) -> Result<()> {
        self.send_rate(DEVLINK_CMD_RATE_NEW, rate).await
    }

    /// Update an existing devlink rate object's fields.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_rate"))]
    pub async fn set_rate(&self, rate: &super::types::DevlinkRate) -> Result<()> {
        self.send_rate(DEVLINK_CMD_RATE_SET, rate).await
    }

    /// Delete a devlink rate object (`Leaf` or `Node`) by
    /// (bus, device, node_name).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rate"))]
    pub async fn del_rate(
        &self,
        bus: &str,
        device: &str,
        node_name: &str,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_RATE_DEL, bus, device);
        builder.append_attr_str(DEVLINK_ATTR_RATE_NODE_NAME, node_name);
        self.devlink_send_ack(builder).await
    }

    /// Set port-function state. Used to activate/deactivate the
    /// SR-IOV VF underlying a devlink port without tearing it
    /// down — see [`super::types::DevlinkPortFunctionState`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_port_function_state"))]
    pub async fn set_port_function_state(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
        state: super::types::DevlinkPortFunctionState,
    ) -> Result<()> {
        // Port-function config goes through DEVLINK_CMD_PORT_SET carrying a
        // DEVLINK_ATTR_PORT_FUNCTION nest. There is no
        // DEVLINK_CMD_PORT_FUNCTION_SET — nlink invented one at 68, which is
        // the kernel's DEVLINK_CMD_TRAP_GROUP_DEL (#264).
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PORT_SET, bus, device);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_INDEX, port_index);
        // DEVLINK_ATTR_PORT_FUNCTION is a NESTED attribute. The
        // inner attributes live in a SEPARATE namespace defined by
        // `enum devlink_port_function_attr`:
        // `DEVLINK_PORT_FN_ATTR_STATE = 2` (u8). Earlier versions
        // wrongly used 174 (an outer-namespace constant from a
        // different enum), which the kernel rejected with EINVAL.
        let nested = builder.nest_start(DEVLINK_ATTR_PORT_FUNCTION | 0x8000);
        builder.append_attr(DEVLINK_PORT_FN_ATTR_STATE, &[state.as_u8()]);
        builder.nest_end(nested);
        self.devlink_send_ack(builder).await
    }

    /// Shared implementation for `add_rate` / `set_rate` — the
    /// only difference is the command byte (NEW vs SET).
    async fn send_rate(
        &self,
        cmd: u8,
        rate: &super::types::DevlinkRate,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(cmd, &rate.bus_name, &rate.device_name);
        builder.append_attr_str(DEVLINK_ATTR_RATE_NODE_NAME, &rate.node_name);
        builder.append_attr_u16(DEVLINK_ATTR_RATE_TYPE, rate.rate_type.as_u16());
        if let Some(share) = rate.tx_share {
            builder.append_attr_u64(DEVLINK_ATTR_RATE_TX_SHARE, share);
        }
        if let Some(max) = rate.tx_max {
            builder.append_attr_u64(DEVLINK_ATTR_RATE_TX_MAX, max);
        }
        if let Some(parent) = &rate.parent_node {
            builder.append_attr_str(DEVLINK_ATTR_RATE_PARENT_NODE_NAME, parent);
        }
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Port Split/Unsplit
    // =========================================================================

    /// Split a port into sub-ports.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "port_split"))]
    pub async fn port_split(
        &self,
        bus: &str,
        device: &str,
        port_index: u32,
        count: u32,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PORT_SPLIT, bus, device);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_INDEX, port_index);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_SPLIT_COUNT, count);
        self.devlink_send_ack(builder).await
    }

    /// Unsplit a previously split port.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "port_unsplit"))]
    pub async fn port_unsplit(&self, bus: &str, device: &str, port_index: u32) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PORT_UNSPLIT, bus, device);
        builder.append_attr_u32(DEVLINK_ATTR_PORT_INDEX, port_index);
        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Parameter Configuration
    // =========================================================================

    /// Set a device parameter.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_param"))]
    pub async fn set_param(
        &self,
        bus: &str,
        device: &str,
        name: &str,
        cmode: ConfigMode,
        data: ParamData,
    ) -> Result<()> {
        let mut builder = self.devlink_cmd_builder(DEVLINK_CMD_PARAM_SET, bus, device);
        builder.append_attr_str(DEVLINK_ATTR_PARAM_NAME, name);
        builder.append_attr(DEVLINK_ATTR_PARAM_TYPE, &[data.type_id()]);

        // Nested: PARAM_VALUE_CMODE + PARAM_VALUE_DATA
        let value_list = builder.nest_start(DEVLINK_ATTR_PARAM_VALUES_LIST | 0x8000);
        let value_entry = builder.nest_start(DEVLINK_ATTR_PARAM_VALUE | 0x8000);
        builder.append_attr(DEVLINK_ATTR_PARAM_VALUE_CMODE, &[cmode as u8]);
        builder.append_attr(DEVLINK_ATTR_PARAM_VALUE_DATA, &data.to_bytes());
        builder.nest_end(value_entry);
        builder.nest_end(value_list);

        self.devlink_send_ack(builder).await
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a GENL dump request (no device filter).
    async fn devlink_dump(&self, cmd: u8) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(&mut session, seq).await
    }

    /// Send a GENL dump request with device filter.
    async fn devlink_dump_with_device(
        &self,
        cmd: u8,
        bus: &str,
        device: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(&mut session, seq).await
    }

    /// Send a GENL GET request for a specific device.
    async fn devlink_get(&self, cmd: u8, bus: &str, device: &str) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s).
        self.with_timeout(async {
            // Collect response
            let mut result_payload: Option<Vec<u8>> = None;

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                let mut done = false;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    match classify(header, payload, seq) {
                        Classification::SkipSeq => continue,
                        // This loop alone treats an ACK as the end of
                        // the response, because the command it serves
                        // is sent with NLM_F_ACK and answers with a
                        // single message followed by one. Preserved
                        // deliberately: normalising it to "keep reading"
                        // would hang here until the 30s timeout.
                        Classification::Ack => {
                            done = true;
                            continue;
                        }
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            done = true;
                            break;
                        }
                        Classification::Data { payload } => {
                            if result_payload.is_none() {
                                result_payload = Some(payload.to_vec());
                            }
                        }
                    }
                }

                if done {
                    break;
                }
            }

            result_payload.ok_or_else(|| Error::invalid_message("no response received"))
        })
        .await
    }

    /// Build a GENL command message for a device.
    fn devlink_cmd_builder(&self, cmd: u8, bus: &str, device: &str) -> MessageBuilder {
        let family_id = self.state().family_id;
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(cmd, DEVLINK_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_str(DEVLINK_ATTR_BUS_NAME, bus);
        builder.append_attr_str(DEVLINK_ATTR_DEV_NAME, device);
        builder
    }

    /// Send a command and wait for ACK.
    async fn devlink_send_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s).
        self.with_timeout(async {
            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    if header.nlmsg_seq != seq {
                        continue;
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        err.warn_if_ack_warns(header.nlmsg_flags, payload);
                        if err.is_ack() {
                            return Ok(());
                        }
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }

                    if header.is_done() {
                        return Ok(());
                    }
                }
            }
        })
        .await
    }

    /// Collect all responses from a dump request.
    async fn collect_dump_responses(
        &self,
        session: &mut crate::netlink::connection::RecvSession,
        seq: u32,
    ) -> Result<Vec<Vec<u8>>> {
        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s).
        self.with_timeout(async {
            let mut results = Vec::new();

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                let mut done = false;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    match classify(header, payload, seq) {
                        Classification::SkipSeq | Classification::Ack => continue,
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            done = true;
                            break;
                        }
                        Classification::Data { payload } => results.push(payload.to_vec()),
                    }
                }

                if done {
                    break;
                }
            }

            Ok(results)
        })
        .await
    }

    // =========================================================================
    // Shared buffers / traps / resources / regions (read-only)
    // =========================================================================

    /// List shared-buffer instances across all devlink devices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_shared_buffers"))]
    pub async fn get_shared_buffers(&self) -> Result<Vec<SharedBuffer>> {
        let responses = self.devlink_dump(DEVLINK_CMD_SB_GET).await?;
        Ok(responses
            .iter()
            .filter(|p| p.len() >= GENL_HDRLEN)
            .filter_map(|p| parse_shared_buffer(&p[GENL_HDRLEN..]))
            .collect())
    }

    /// List packet traps across all devlink devices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_traps"))]
    pub async fn get_traps(&self) -> Result<Vec<DevlinkTrap>> {
        let responses = self.devlink_dump(DEVLINK_CMD_TRAP_GET).await?;
        Ok(responses
            .iter()
            .filter(|p| p.len() >= GENL_HDRLEN)
            .filter_map(|p| parse_trap(&p[GENL_HDRLEN..]))
            .collect())
    }

    /// List address regions across all devlink devices.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_regions"))]
    pub async fn get_regions(&self) -> Result<Vec<DevlinkRegion>> {
        let responses = self.devlink_dump(DEVLINK_CMD_REGION_GET).await?;
        Ok(responses
            .iter()
            .filter(|p| p.len() >= GENL_HDRLEN)
            .filter_map(|p| parse_region(&p[GENL_HDRLEN..]))
            .collect())
    }

    /// Get the hardware-resource tree for a specific device.
    ///
    /// Unlike sb/trap/region, `RESOURCE_DUMP` is a per-device `doit`
    /// (not a netlink dump), so it takes `bus`/`device` and returns
    /// the whole tree in one message, flattened here into a list with
    /// slash-joined [`DevlinkResource::name`] paths.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_resources"))]
    pub async fn get_resources(&self, bus: &str, device: &str) -> Result<Vec<DevlinkResource>> {
        let response = self
            .devlink_get(DEVLINK_CMD_RESOURCE_DUMP, bus, device)
            .await?;
        if response.len() < GENL_HDRLEN {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (attr_type, payload) in AttrIter::new(&response[GENL_HDRLEN..]) {
            if attr_type == DEVLINK_ATTR_RESOURCE_LIST {
                parse_resource_list(bus, device, "", payload, &mut out);
            }
        }
        Ok(out)
    }
}

// =============================================================================
// Attribute Parsing
// =============================================================================

/// Read a `u16` attribute payload (native endian), ignoring trailing
/// bytes the kernel may have grown the attribute by.
fn attr_u16(payload: &[u8]) -> Option<u16> {
    payload.get(0..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
}

/// Read a `u32` attribute payload (native endian).
fn attr_u32(payload: &[u8]) -> Option<u32> {
    payload
        .get(0..4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a `u64` attribute payload (native endian).
fn attr_u64(payload: &[u8]) -> Option<u64> {
    payload.get(0..8).map(|b| {
        u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

fn parse_shared_buffer(data: &[u8]) -> Option<SharedBuffer> {
    let mut bus = None;
    let mut device = None;
    let mut index = None;
    let mut size = 0;
    let (mut ing_pools, mut egr_pools, mut ing_tcs, mut egr_tcs) = (0, 0, 0, 0);

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => bus = attr_str(payload),
            DEVLINK_ATTR_DEV_NAME => device = attr_str(payload),
            DEVLINK_ATTR_SB_INDEX => index = attr_u32(payload),
            DEVLINK_ATTR_SB_SIZE => size = attr_u32(payload).unwrap_or(0),
            DEVLINK_ATTR_SB_INGRESS_POOL_COUNT => {
                ing_pools = u32::from(attr_u16(payload).unwrap_or(0))
            }
            DEVLINK_ATTR_SB_EGRESS_POOL_COUNT => {
                egr_pools = u32::from(attr_u16(payload).unwrap_or(0))
            }
            DEVLINK_ATTR_SB_INGRESS_TC_COUNT => {
                ing_tcs = u32::from(attr_u16(payload).unwrap_or(0))
            }
            DEVLINK_ATTR_SB_EGRESS_TC_COUNT => {
                egr_tcs = u32::from(attr_u16(payload).unwrap_or(0))
            }
            _ => {}
        }
    }

    Some(SharedBuffer {
        bus: bus?,
        device: device?,
        index: index?,
        size,
        ingress_pools: ing_pools,
        egress_pools: egr_pools,
        ingress_tcs: ing_tcs,
        egress_tcs: egr_tcs,
    })
}

fn parse_trap(data: &[u8]) -> Option<DevlinkTrap> {
    let mut bus = None;
    let mut device = None;
    let mut name = None;
    let mut action = TrapAction::Unknown(u8::MAX);
    let mut trap_type = TrapType::Unknown(u8::MAX);
    let mut generic = false;
    let mut group = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => bus = attr_str(payload),
            DEVLINK_ATTR_DEV_NAME => device = attr_str(payload),
            DEVLINK_ATTR_TRAP_NAME => name = attr_str(payload),
            DEVLINK_ATTR_TRAP_ACTION => {
                action = match payload.first().copied() {
                    Some(DEVLINK_TRAP_ACTION_DROP) => TrapAction::Drop,
                    Some(DEVLINK_TRAP_ACTION_TRAP) => TrapAction::Trap,
                    Some(DEVLINK_TRAP_ACTION_MIRROR) => TrapAction::Mirror,
                    Some(v) => TrapAction::Unknown(v),
                    None => action,
                };
            }
            DEVLINK_ATTR_TRAP_TYPE => {
                trap_type = match payload.first().copied() {
                    Some(DEVLINK_TRAP_TYPE_DROP) => TrapType::Drop,
                    Some(DEVLINK_TRAP_TYPE_EXCEPTION) => TrapType::Exception,
                    Some(DEVLINK_TRAP_TYPE_CONTROL) => TrapType::Control,
                    Some(v) => TrapType::Unknown(v),
                    None => trap_type,
                };
            }
            DEVLINK_ATTR_TRAP_GENERIC => generic = true,
            DEVLINK_ATTR_TRAP_GROUP_NAME => group = attr_str(payload),
            _ => {}
        }
    }

    Some(DevlinkTrap {
        bus: bus?,
        device: device?,
        name: name?,
        action,
        trap_type,
        generic,
        group,
    })
}

fn parse_region(data: &[u8]) -> Option<DevlinkRegion> {
    let mut bus = None;
    let mut device = None;
    let mut name = None;
    let mut size = None;
    let mut snapshot_count = 0;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => bus = attr_str(payload),
            DEVLINK_ATTR_DEV_NAME => device = attr_str(payload),
            DEVLINK_ATTR_REGION_NAME => name = attr_str(payload),
            DEVLINK_ATTR_REGION_SIZE => size = attr_u64(payload),
            DEVLINK_ATTR_REGION_SNAPSHOTS => {
                snapshot_count = AttrIter::new(payload).count();
            }
            _ => {}
        }
    }

    Some(DevlinkRegion {
        bus: bus?,
        device: device?,
        name: name?,
        size,
        snapshot_count,
    })
}

/// Recursively flatten a `DEVLINK_ATTR_RESOURCE_LIST` nest into `out`,
/// joining nested resource names under `prefix` with `/`.
fn parse_resource_list(
    bus: &str,
    device: &str,
    prefix: &str,
    data: &[u8],
    out: &mut Vec<DevlinkResource>,
) {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == DEVLINK_ATTR_RESOURCE {
            parse_resource(bus, device, prefix, payload, out);
        }
    }
}

fn parse_resource(
    bus: &str,
    device: &str,
    prefix: &str,
    data: &[u8],
    out: &mut Vec<DevlinkResource>,
) {
    let mut name = String::new();
    let mut id = 0u64;
    let mut size = 0u64;
    let mut occ = None;
    let mut size_valid = false;
    let mut children: Option<&[u8]> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_RESOURCE_NAME => name = attr_str(payload).unwrap_or_default(),
            DEVLINK_ATTR_RESOURCE_ID => id = attr_u64(payload).unwrap_or(0),
            DEVLINK_ATTR_RESOURCE_SIZE => size = attr_u64(payload).unwrap_or(0),
            DEVLINK_ATTR_RESOURCE_OCC => occ = attr_u64(payload),
            DEVLINK_ATTR_RESOURCE_SIZE_VALID => {
                size_valid = payload.first().copied().unwrap_or(0) != 0;
            }
            DEVLINK_ATTR_RESOURCE_LIST => children = Some(payload),
            _ => {}
        }
    }

    let full = if prefix.is_empty() {
        name.clone()
    } else {
        format!("{prefix}/{name}")
    };

    out.push(DevlinkResource {
        bus: bus.to_string(),
        device: device.to_string(),
        name: full.clone(),
        id,
        size,
        occ,
        size_valid,
    });

    if let Some(child_data) = children {
        parse_resource_list(bus, device, &full, child_data, out);
    }
}

fn parse_device(data: &[u8]) -> Option<DevlinkDevice> {
    let mut bus = None;
    let mut device = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                bus = attr_str(payload);
            }
            DEVLINK_ATTR_DEV_NAME => {
                device = attr_str(payload);
            }
            _ => {}
        }
    }

    Some(DevlinkDevice {
        bus: bus?,
        device: device?,
    })
}

fn parse_info(data: &[u8]) -> Result<DevlinkInfo> {
    let mut info = DevlinkInfo {
        bus: String::new(),
        device: String::new(),
        driver: String::new(),
        serial: None,
        board_serial: None,
        versions_fixed: Vec::new(),
        versions_running: Vec::new(),
        versions_stored: Vec::new(),
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                info.bus = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_DEV_NAME => {
                info.device = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_INFO_DRIVER_NAME => {
                info.driver = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => {
                info.serial = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER => {
                info.board_serial = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_VERSION_FIXED => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_fixed.push(v);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_RUNNING => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_running.push(v);
                }
            }
            DEVLINK_ATTR_INFO_VERSION_STORED => {
                if let Some(v) = parse_version_nested(payload) {
                    info.versions_stored.push(v);
                }
            }
            _ => {}
        }
    }

    Ok(info)
}

fn parse_version_nested(data: &[u8]) -> Option<VersionInfo> {
    let mut name = None;
    let mut value = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_INFO_VERSION_NAME => {
                name = attr_str(payload);
            }
            DEVLINK_ATTR_INFO_VERSION_VALUE => {
                value = attr_str(payload);
            }
            _ => {}
        }
    }

    Some(VersionInfo {
        name: name?,
        value: value?,
    })
}

fn parse_port(data: &[u8]) -> Option<DevlinkPort> {
    let mut port = DevlinkPort {
        bus: String::new(),
        device: String::new(),
        index: 0,
        port_type: PortType::NotSet,
        netdev_ifindex: None,
        netdev_name: None,
        ibdev_name: None,
        flavour: None,
        number: None,
        split_subport: None,
        split_group: None,
        pci_pf: None,
        pci_vf: None,
        pci_sf: None,
        controller: None,
    };

    let mut has_index = false;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_BUS_NAME => {
                port.bus = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_DEV_NAME => {
                port.device = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_PORT_INDEX if payload.len() >= 4 => {
                port.index = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                has_index = true;
            }
            DEVLINK_ATTR_PORT_TYPE if payload.len() >= 2 => {
                let v = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                port.port_type = PortType::try_from(v).unwrap_or(PortType::NotSet);
            }
            DEVLINK_ATTR_PORT_NETDEV_IFINDEX if payload.len() >= 4 => {
                port.netdev_ifindex = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_NETDEV_NAME => {
                port.netdev_name = attr_str(payload);
            }
            DEVLINK_ATTR_PORT_IBDEV_NAME => {
                port.ibdev_name = attr_str(payload);
            }
            DEVLINK_ATTR_PORT_FLAVOUR if payload.len() >= 2 => {
                let v = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                port.flavour = PortFlavour::try_from(v).ok();
            }
            DEVLINK_ATTR_PORT_NUMBER if payload.len() >= 4 => {
                port.number = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER if payload.len() >= 4 => {
                port.split_subport = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_SPLIT_GROUP if payload.len() >= 4 => {
                port.split_group = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_PCI_PF_NUMBER if payload.len() >= 2 => {
                port.pci_pf = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_PCI_VF_NUMBER if payload.len() >= 2 => {
                port.pci_vf = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_PCI_SF_NUMBER if payload.len() >= 4 => {
                port.pci_sf = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            DEVLINK_ATTR_PORT_CONTROLLER_NUMBER if payload.len() >= 4 => {
                port.controller = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }

    if has_index { Some(port) } else { None }
}

/// The device and port a reply names (#777).
struct ReplyHandle {
    bus: Option<String>,
    device: Option<String>,
    port: Option<u32>,
}

impl ReplyHandle {
    fn of(data: &[u8]) -> Self {
        let mut h = Self { bus: None, device: None, port: None };
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                DEVLINK_ATTR_BUS_NAME => h.bus = attr_str(payload),
                DEVLINK_ATTR_DEV_NAME => h.device = attr_str(payload),
                DEVLINK_ATTR_PORT_INDEX if payload.len() >= 4 => {
                    h.port = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        h
    }

    /// Whether it is `bus`/`device`'s. A dump that names a device answers
    /// for every device on a kernel before per-instance filtering, and the
    /// requested names used to be stamped on each reply.
    fn is(&self, bus: &str, device: &str) -> bool {
        self.bus.as_deref().is_none_or(|b| b == bus) && self.device.as_deref().is_none_or(|d| d == device)
    }
}

fn parse_health_response(bus: &str, device: &str, data: &[u8]) -> Option<HealthReporter> {
    let handle = ReplyHandle::of(data);
    if !handle.is(bus, device) {
        return None;
    }
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == DEVLINK_ATTR_HEALTH_REPORTER {
            let mut reporter = parse_health_reporter(bus, device, payload)?;
            reporter.port = handle.port;
            return Some(reporter);
        }
    }
    None
}

fn parse_health_reporter(bus: &str, device: &str, data: &[u8]) -> Option<HealthReporter> {
    let mut reporter = HealthReporter {
        bus: bus.to_string(),
        device: device.to_string(),
        name: String::new(),
        state: HealthState::Healthy,
        error_count: 0,
        recover_count: 0,
        auto_recover: false,
        auto_dump: false,
        graceful_period_ms: None,
        dump_ts_jiffies: None,
        port: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_HEALTH_REPORTER_NAME => {
                reporter.name = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_HEALTH_REPORTER_STATE if !payload.is_empty() => {
                reporter.state = HealthState::try_from(payload[0]).unwrap_or(HealthState::Healthy);
            }
            DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT if payload.len() >= 8 => {
                reporter.error_count = u64::from_ne_bytes(payload[..8].try_into().unwrap());
            }
            DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT if payload.len() >= 8 => {
                reporter.recover_count = u64::from_ne_bytes(payload[..8].try_into().unwrap());
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER if !payload.is_empty() => {
                reporter.auto_recover = payload[0] != 0;
            }
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP if !payload.is_empty() => {
                reporter.auto_dump = payload[0] != 0;
            }
            DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD if payload.len() >= 8 => {
                reporter.graceful_period_ms =
                    Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS if payload.len() >= 8 => {
                reporter.dump_ts_jiffies =
                    Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            _ => {}
        }
    }

    if reporter.name.is_empty() {
        None
    } else {
        Some(reporter)
    }
}

fn parse_param_response(bus: &str, device: &str, data: &[u8]) -> Option<DevlinkParam> {
    if !ReplyHandle::of(data).is(bus, device) {
        return None;
    }
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == DEVLINK_ATTR_PARAM {
            return parse_param(bus, device, payload);
        }
    }
    None
}

fn parse_param(bus: &str, device: &str, data: &[u8]) -> Option<DevlinkParam> {
    let mut param = DevlinkParam {
        bus: bus.to_string(),
        device: device.to_string(),
        name: String::new(),
        generic: false,
        values: Vec::new(),
    };

    let mut param_type: Option<u8> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_PARAM_NAME => {
                param.name = attr_str(payload).unwrap_or_default();
            }
            DEVLINK_ATTR_PARAM_GENERIC => {
                param.generic = true; // Flag attribute — presence means true
            }
            DEVLINK_ATTR_PARAM_TYPE if !payload.is_empty() => {
                param_type = Some(payload[0]);
            }
            DEVLINK_ATTR_PARAM_VALUES_LIST => {
                // Parse nested value entries
                for (_idx, value_data) in AttrIter::new(payload) {
                    if let Some(pv) = parse_param_value(value_data, param_type) {
                        param.values.push(pv);
                    }
                }
            }
            _ => {}
        }
    }

    if param.name.is_empty() {
        None
    } else {
        Some(param)
    }
}

fn parse_param_value(data: &[u8], param_type: Option<u8>) -> Option<ParamValue> {
    let mut cmode = None;
    let mut value_data: Option<&[u8]> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            DEVLINK_ATTR_PARAM_VALUE_CMODE if !payload.is_empty() => {
                cmode = ConfigMode::try_from(payload[0]).ok();
            }
            DEVLINK_ATTR_PARAM_VALUE_DATA => {
                value_data = Some(payload);
            }
            _ => {}
        }
    }

    let cmode = cmode?;
    let raw = value_data?;

    let data = match param_type {
        Some(1) if !raw.is_empty() => ParamData::U8(raw[0]),
        Some(2) if raw.len() >= 2 => {
            ParamData::U16(u16::from_ne_bytes(raw[..2].try_into().unwrap()))
        }
        Some(3) if raw.len() >= 4 => {
            ParamData::U32(u32::from_ne_bytes(raw[..4].try_into().unwrap()))
        }
        Some(5) => ParamData::String(attr_str(raw).unwrap_or_default()),
        Some(6) if !raw.is_empty() => ParamData::Bool(raw[0] != 0),
        _ => ParamData::U32(if raw.len() >= 4 {
            u32::from_ne_bytes(raw[..4].try_into().unwrap())
        } else {
            0
        }),
    };

    Some(ParamValue { cmode, data })
}

/// Extract a null-terminated string from attribute payload.
fn attr_str(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(payload)
        .unwrap_or("")
        .trim_end_matches('\0');
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}


#[cfg(test)]
mod read_parse_tests {
    use super::*;
    use crate::netlink::builder::MessageBuilder;

    /// Build a bare attribute region (no headers) for feeding to the
    /// free parse functions, which expect the post-GENL_HDRLEN slice.
    fn attrs(build: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        build(&mut b);
        // Strip the 16-byte nlmsghdr the builder prepends.
        b.as_bytes()[16..].to_vec()
    }

    /// #777: a reply for another device is not this one's, whatever the
    /// request named, and a port's reporter says which port.
    #[test]
    fn replies_are_the_requested_devices_and_reporters_know_their_port() {
        let reply = |dev: &str, port: Option<u32>, name: &str| {
            attrs(|b| {
                b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "netdevsim");
                b.append_attr_str(DEVLINK_ATTR_DEV_NAME, dev);
                if let Some(p) = port {
                    b.append_attr(DEVLINK_ATTR_PORT_INDEX, &p.to_ne_bytes());
                }
                let nest = b.nest_start(DEVLINK_ATTR_HEALTH_REPORTER);
                b.append_attr_str(DEVLINK_ATTR_HEALTH_REPORTER_NAME, name);
                b.nest_end(nest);
            })
        };
        let mine = parse_health_response("netdevsim", "netdevsim1", &reply("netdevsim1", None, "fw")).unwrap();
        assert_eq!((mine.name.as_str(), mine.port), ("fw", None));
        let port = parse_health_response("netdevsim", "netdevsim1", &reply("netdevsim1", Some(3), "tx")).unwrap();
        assert_eq!((port.name.as_str(), port.port), ("tx", Some(3)));
        assert!(parse_health_response("netdevsim", "netdevsim1", &reply("netdevsim2", None, "fw")).is_none());

        let param = |dev: &str| {
            attrs(|b| {
                b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "netdevsim");
                b.append_attr_str(DEVLINK_ATTR_DEV_NAME, dev);
                let nest = b.nest_start(DEVLINK_ATTR_PARAM);
                b.append_attr_str(DEVLINK_ATTR_PARAM_NAME, "max_macs");
                b.nest_end(nest);
            })
        };
        assert!(parse_param_response("netdevsim", "netdevsim1", &param("netdevsim1")).is_some());
        assert!(parse_param_response("netdevsim", "netdevsim1", &param("netdevsim2")).is_none());
    }

    #[test]
    fn parse_shared_buffer_basic() {
        let data = attrs(|b| {
            b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "pci");
            b.append_attr_str(DEVLINK_ATTR_DEV_NAME, "0000:03:00.0");
            b.append_attr(DEVLINK_ATTR_SB_INDEX, &0u32.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_SB_SIZE, &16_000_000u32.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_SB_INGRESS_POOL_COUNT, &4u16.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_SB_EGRESS_POOL_COUNT, &4u16.to_ne_bytes());
        });
        let sb = parse_shared_buffer(&data).expect("parse");
        assert_eq!(sb.bus, "pci");
        assert_eq!(sb.device, "0000:03:00.0");
        assert_eq!(sb.index, 0);
        assert_eq!(sb.size, 16_000_000);
        assert_eq!(sb.ingress_pools, 4);
        assert_eq!(sb.egress_pools, 4);
    }

    #[test]
    fn parse_trap_basic() {
        let data = attrs(|b| {
            b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "pci");
            b.append_attr_str(DEVLINK_ATTR_DEV_NAME, "0000:03:00.0");
            b.append_attr_str(DEVLINK_ATTR_TRAP_NAME, "source_mac_is_multicast");
            b.append_attr(DEVLINK_ATTR_TRAP_ACTION, &[DEVLINK_TRAP_ACTION_DROP]);
            b.append_attr(DEVLINK_ATTR_TRAP_TYPE, &[DEVLINK_TRAP_TYPE_DROP]);
            b.append_attr(DEVLINK_ATTR_TRAP_GENERIC, &[]);
            b.append_attr_str(DEVLINK_ATTR_TRAP_GROUP_NAME, "l2_drops");
        });
        let t = parse_trap(&data).expect("parse");
        assert_eq!(t.name, "source_mac_is_multicast");
        assert_eq!(t.action, TrapAction::Drop);
        assert_eq!(t.trap_type, TrapType::Drop);
        assert!(t.generic);
        assert_eq!(t.group.as_deref(), Some("l2_drops"));
    }

    #[test]
    fn parse_trap_unknown_action_is_forward_compat() {
        let data = attrs(|b| {
            b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "pci");
            b.append_attr_str(DEVLINK_ATTR_DEV_NAME, "d");
            b.append_attr_str(DEVLINK_ATTR_TRAP_NAME, "future");
            b.append_attr(DEVLINK_ATTR_TRAP_ACTION, &[99]);
        });
        let t = parse_trap(&data).expect("parse");
        assert_eq!(t.action, TrapAction::Unknown(99));
    }

    #[test]
    fn parse_region_counts_snapshots() {
        let data = attrs(|b| {
            b.append_attr_str(DEVLINK_ATTR_BUS_NAME, "pci");
            b.append_attr_str(DEVLINK_ATTR_DEV_NAME, "d");
            b.append_attr_str(DEVLINK_ATTR_REGION_NAME, "cr-space");
            b.append_attr(DEVLINK_ATTR_REGION_SIZE, &1024u64.to_ne_bytes());
            // Two snapshot sub-attrs nested under SNAPSHOTS.
            let tok = b.nest_start(DEVLINK_ATTR_REGION_SNAPSHOTS);
            b.append_attr(1, &0u32.to_ne_bytes());
            b.append_attr(1, &1u32.to_ne_bytes());
            b.nest_end(tok);
        });
        let r = parse_region(&data).expect("parse");
        assert_eq!(r.name, "cr-space");
        assert_eq!(r.size, Some(1024));
        assert_eq!(r.snapshot_count, 2);
    }

    #[test]
    fn parse_resource_tree_flattens_with_paths() {
        // Build RESOURCE_LIST { RESOURCE(kvd) { RESOURCE_LIST {
        //   RESOURCE(linear) } } }.
        let data = attrs(|b| {
            let list = b.nest_start(DEVLINK_ATTR_RESOURCE_LIST);
            let parent = b.nest_start(DEVLINK_ATTR_RESOURCE);
            b.append_attr_str(DEVLINK_ATTR_RESOURCE_NAME, "kvd");
            b.append_attr(DEVLINK_ATTR_RESOURCE_ID, &1u64.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_RESOURCE_SIZE, &1000u64.to_ne_bytes());
            let child_list = b.nest_start(DEVLINK_ATTR_RESOURCE_LIST);
            let child = b.nest_start(DEVLINK_ATTR_RESOURCE);
            b.append_attr_str(DEVLINK_ATTR_RESOURCE_NAME, "linear");
            b.append_attr(DEVLINK_ATTR_RESOURCE_ID, &2u64.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_RESOURCE_SIZE, &500u64.to_ne_bytes());
            b.append_attr(DEVLINK_ATTR_RESOURCE_OCC, &123u64.to_ne_bytes());
            b.nest_end(child);
            b.nest_end(child_list);
            b.nest_end(parent);
            b.nest_end(list);
        });

        let mut out = Vec::new();
        for (attr_type, payload) in AttrIter::new(&data) {
            if attr_type == DEVLINK_ATTR_RESOURCE_LIST {
                parse_resource_list("pci", "d", "", payload, &mut out);
            }
        }
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "kvd");
        assert_eq!(out[0].size, 1000);
        assert_eq!(out[1].name, "kvd/linear");
        assert_eq!(out[1].size, 500);
        assert_eq!(out[1].occ, Some(123));
    }
}
