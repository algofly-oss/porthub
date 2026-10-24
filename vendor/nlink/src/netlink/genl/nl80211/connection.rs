//! nl80211 connection implementation for `Connection<Nl80211>`.

use std::collections::BTreeMap;

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
    protocol::{AsyncProtocolInit, Nl80211},
    socket::NetlinkSocket,
};

impl AsyncProtocolInit for Nl80211 {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        let (family_id, mcast_groups) =
            resolve_genl_family_with_groups(socket, NL80211_GENL_NAME).await?;
        Ok(Self {
            family_id,
            mcast_groups,
        })
    }
}

impl GenlFamily for Nl80211 {
    const VERSION: u8 = NL80211_GENL_VERSION;
    const NAME: &'static str = NL80211_GENL_NAME;

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn mcast_group(&self, name: &str) -> Option<u32> {
        self.mcast_groups.get(name).copied()
    }
}

#[nlink_macros::send_futures]
impl Connection<Nl80211> {
    /// Get the nl80211 family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Subscribe to all nl80211 multicast event groups exposed by
    /// the kernel — typically `scan`, `mlme`, `regulatory`, and
    /// `config`. For fine-grained subscription, use the generic
    /// [`subscribe_group`](Connection::subscribe_group) directly.
    ///
    /// After subscribing, use `events()` or `into_events()` to
    /// receive events.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Nl80211};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<Nl80211>::new_async().await?;
    /// conn.subscribe()?;
    ///
    /// let mut events = conn.events().await;
    /// while let Some(event) = events.next().await {
    ///     println!("{:?}", event?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn subscribe(&self) -> Result<()> {
        let mut subscribed = false;
        for name in [
            NL80211_MCGRP_SCAN,
            NL80211_MCGRP_MLME,
            NL80211_MCGRP_REGULATORY,
            NL80211_MCGRP_CONFIG,
        ] {
            if let Some(id) = self.state().mcast_groups.get(name).copied() {
                self.socket().add_membership(id)?;
                subscribed = true;
            }
        }

        if !subscribed {
            return Err(Error::invalid_message(
                "no nl80211 multicast groups available",
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Interface Queries
    // =========================================================================

    /// List all wireless interfaces.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::netlink::Nl80211>::new_async().await?;
    /// let ifaces = conn.get_interfaces().await?;
    /// for iface in &ifaces {
    ///     println!("{}: {:?}", iface.name.as_deref().unwrap_or("?"), iface.iftype);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interfaces"))]
    pub async fn get_interfaces(&self) -> Result<Vec<WirelessInterface>> {
        let responses = self.nl80211_dump(NL80211_CMD_GET_INTERFACE).await?;
        let mut interfaces = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            interfaces.push(parse_interface(&payload[GENL_HDRLEN..]));
        }

        Ok(interfaces)
    }

    /// Get a specific wireless interface by name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface"))]
    pub async fn get_interface(&self, name: &str) -> Result<Option<WirelessInterface>> {
        let ifaces = self.get_interfaces().await?;
        Ok(ifaces.into_iter().find(|i| i.name.as_deref() == Some(name)))
    }

    /// Get a specific wireless interface by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_interface_by_index"))]
    pub async fn get_interface_by_index(&self, ifindex: u32) -> Result<Option<WirelessInterface>> {
        let ifaces = self.get_interfaces().await?;
        Ok(ifaces.into_iter().find(|i| i.ifindex == ifindex))
    }

    // =========================================================================
    // Scanning
    // =========================================================================

    /// Trigger a scan on an interface.
    ///
    /// This is asynchronous: the kernel starts the scan and returns
    /// immediately. Poll `get_scan_results()` to get results.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EBUSY` if a scan is already in progress.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "trigger_scan"))]
    pub async fn trigger_scan(&self, iface: &str, request: &ScanRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.trigger_scan_by_index(ifindex, request).await
    }

    /// Trigger a scan by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "trigger_scan_by_index"))]
    pub async fn trigger_scan_by_index(&self, ifindex: u32, request: &ScanRequest) -> Result<()> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_TRIGGER_SCAN, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        if !request.frequencies.is_empty() {
            let nest = builder.nest_start(NL80211_ATTR_SCAN_FREQUENCIES);
            for (i, freq) in request.frequencies.iter().enumerate() {
                builder.append_attr_u32((i + 1) as u16, *freq);
            }
            builder.nest_end(nest);
        }

        if !request.ssids.is_empty() {
            let nest = builder.nest_start(NL80211_ATTR_SCAN_SSIDS);
            for (i, ssid) in request.ssids.iter().enumerate() {
                builder.append_attr((i + 1) as u16, ssid);
            }
            builder.nest_end(nest);
        }

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Wait for ACK
        self.wait_ack(&mut session, seq).await
    }

    /// Get cached scan results for an interface.
    ///
    /// Returns the most recent scan results. Call `trigger_scan()` first
    /// to ensure fresh results.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_scan_results"))]
    pub async fn get_scan_results(&self, iface: &str) -> Result<Vec<ScanResult>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_scan_results_by_index(ifindex).await
    }

    /// Get scan results by interface index (namespace-safe).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_scan_results_by_index")
    )]
    pub async fn get_scan_results_by_index(&self, ifindex: u32) -> Result<Vec<ScanResult>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_SCAN, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(&mut session, seq).await?;
        let mut results = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            // Scan results have NL80211_ATTR_BSS as a nested attribute
            for (attr_type, attr_payload) in AttrIter::new(&payload[GENL_HDRLEN..]) {
                if attr_type == NL80211_ATTR_BSS {
                    results.push(parse_bss(attr_payload));
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Station Info
    // =========================================================================

    /// Get station info for the currently associated AP.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_station"))]
    pub async fn get_station(&self, iface: &str) -> Result<Option<StationInfo>> {
        let stations = self.get_stations(iface).await?;
        Ok(stations.into_iter().next())
    }

    /// Get station info by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_station_by_index"))]
    pub async fn get_station_by_index(&self, ifindex: u32) -> Result<Option<StationInfo>> {
        let stations = self.get_stations_by_index(ifindex).await?;
        Ok(stations.into_iter().next())
    }

    /// List all stations (useful in AP mode).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_stations"))]
    pub async fn get_stations(&self, iface: &str) -> Result<Vec<StationInfo>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_stations_by_index(ifindex).await
    }

    /// List all stations by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_stations_by_index"))]
    pub async fn get_stations_by_index(&self, ifindex: u32) -> Result<Vec<StationInfo>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_STATION, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(&mut session, seq).await?;
        let mut stations = Vec::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            stations.push(parse_station(&payload[GENL_HDRLEN..]));
        }

        Ok(stations)
    }

    /// Channel survey results — per-frequency occupation/noise stats
    /// (`NL80211_CMD_GET_SURVEY`). Useful for channel selection: derive
    /// utilisation from `time_busy_ms / time_ms`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_survey"))]
    pub async fn get_survey(&self, iface: &str) -> Result<Vec<SurveyInfo>> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.get_survey_by_index(ifindex).await
    }

    /// Channel survey results by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_survey_by_index"))]
    pub async fn get_survey_by_index(&self, ifindex: u32) -> Result<Vec<SurveyInfo>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_SURVEY, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(&mut session, seq).await?;
        let mut surveys = Vec::new();
        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            if let Some(s) = parse_survey(&payload[GENL_HDRLEN..]) {
                surveys.push(s);
            }
        }
        Ok(surveys)
    }

    // =========================================================================
    // Physical Device
    // =========================================================================

    /// List all physical wireless devices (what `iw phy` shows: bands,
    /// channels, bitrates, HT/VHT/HE/EHT capabilities, supported
    /// interface types, and cipher suites).
    ///
    /// The dump requests `NL80211_ATTR_SPLIT_WIPHY_DUMP`, so the kernel
    /// emits each wiphy's attributes across multiple messages (sharing
    /// the same `NL80211_ATTR_WIPHY` index) instead of truncating a
    /// rich PHY to a single message. The messages are reassembled by
    /// wiphy index here, merging bands by band index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_phys"))]
    pub async fn get_phys(&self) -> Result<Vec<PhyInfo>> {
        let responses = self.dump_wiphy_split().await?;
        let mut accs: BTreeMap<u32, PhyAcc> = BTreeMap::new();

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            let attrs = &payload[GENL_HDRLEN..];
            // Split-dump frames always carry the wiphy index; without
            // it we can't attribute the frame to a device, so skip.
            let Some(idx) = wiphy_index_of(attrs) else {
                continue;
            };
            accs.entry(idx).or_default().merge_message(attrs);
        }

        Ok(accs.into_values().map(PhyAcc::finalize).collect())
    }

    /// Get capabilities of a specific physical device.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_phy"))]
    pub async fn get_phy(&self, wiphy: u32) -> Result<Option<PhyInfo>> {
        let phys = self.get_phys().await?;
        Ok(phys.into_iter().find(|p| p.index == wiphy))
    }

    /// The physical device named `name` — a `mac80211_hwsim` radio's
    /// wiphy is named after the radio (#530).
    pub async fn get_phy_by_name(&self, name: &str) -> Result<Option<PhyInfo>> {
        let phys = self.get_phys().await?;
        Ok(phys.into_iter().find(|p| p.name == name))
    }

    // =========================================================================
    // Regulatory
    // =========================================================================

    /// Get the current regulatory domain.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_regulatory"))]
    pub async fn get_regulatory(&self) -> Result<RegulatoryDomain> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_REG, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(&mut session, seq).await?;

        let mut domain = RegulatoryDomain {
            country: String::new(),
            rules: Vec::new(),
        };

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            parse_regulatory(&payload[GENL_HDRLEN..], &mut domain);
        }

        Ok(domain)
    }

    /// Request a regulatory-domain change by ISO 3166-1 alpha-2
    /// country code (e.g. `"US"`, `"DE"`, or `"00"` for the world
    /// domain). This is the `iw reg set` path
    /// (`NL80211_CMD_REQ_SET_REG`): a user hint that the kernel's
    /// regulatory core applies, not the full-regdom CRDA upload.
    ///
    /// Requires `CAP_NET_ADMIN`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_regulatory"))]
    pub async fn set_regulatory(&self, alpha2: &str) -> Result<()> {
        let code = normalize_alpha2(alpha2)?;

        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_REQ_SET_REG, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        // alpha2 is a NUL-terminated 2-char string (matches `iw`).
        builder.append_attr_str(NL80211_ATTR_REG_ALPHA2, &code);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(&mut session, seq).await
    }

    // =========================================================================
    // Station Mode (Phase 2)
    // =========================================================================

    /// Connect to a wireless network.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EALREADY` if already connected.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "connect"))]
    pub async fn connect(&self, iface: &str, request: ConnectRequest) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.connect_by_index(ifindex, request).await
    }

    /// Connect by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "connect_by_index"))]
    pub async fn connect_by_index(&self, ifindex: u32, request: ConnectRequest) -> Result<()> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_CONNECT, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr(NL80211_ATTR_SSID, &request.ssid);
        builder.append_attr_u32(NL80211_ATTR_AUTH_TYPE, request.auth_type as u32);

        if let Some(bssid) = request.bssid {
            builder.append_attr(NL80211_ATTR_MAC, &bssid);
        }
        if let Some(freq) = request.frequency {
            builder.append_attr_u32(NL80211_ATTR_WIPHY_FREQ, freq);
        }

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(&mut session, seq).await
    }

    /// Disconnect from the current network.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "disconnect"))]
    pub async fn disconnect(&self, iface: &str) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.disconnect_by_index(ifindex).await
    }

    /// Disconnect by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "disconnect_by_index"))]
    pub async fn disconnect_by_index(&self, ifindex: u32) -> Result<()> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_DISCONNECT, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr_u16(NL80211_ATTR_REASON_CODE, 3); // REASON_DEAUTH_LEAVING

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(&mut session, seq).await
    }

    /// Remove (kick) a station from an AP-mode interface by MAC.
    ///
    /// Sends `NL80211_CMD_DEL_STATION`, deauthenticating the client.
    /// Useful in AP mode to disconnect a specific associated station.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_station"))]
    pub async fn del_station(&self, iface: &str, mac: [u8; 6]) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.del_station_by_index(ifindex, mac).await
    }

    /// Remove a station by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_station_by_index"))]
    pub async fn del_station_by_index(&self, ifindex: u32, mac: [u8; 6]) -> Result<()> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr(NL80211_ATTR_MAC, &mac);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(&mut session, seq).await
    }

    /// Set power save mode.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_power_save"))]
    pub async fn set_power_save(&self, iface: &str, enabled: bool) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_SET_POWER_SAVE, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
        builder.append_attr_u32(
            NL80211_ATTR_PS_STATE,
            if enabled {
                PowerSaveState::Enabled as u32
            } else {
                PowerSaveState::Disabled as u32
            },
        );

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.wait_ack(&mut session, seq).await
    }

    /// Get power save mode.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_power_save"))]
    pub async fn get_power_save(&self, iface: &str) -> Result<PowerSaveState> {
        let ifindex = self.resolve_ifindex(iface).await?;
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_POWER_SAVE, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let responses = self.collect_dump_responses(&mut session, seq).await?;

        for payload in &responses {
            if payload.len() < GENL_HDRLEN {
                continue;
            }
            for (attr_type, attr_payload) in AttrIter::new(&payload[GENL_HDRLEN..]) {
                if attr_type == NL80211_ATTR_PS_STATE && attr_payload.len() >= 4 {
                    let val = u32::from_ne_bytes(attr_payload[..4].try_into().unwrap());
                    return PowerSaveState::try_from(val);
                }
            }
        }

        Ok(PowerSaveState::Disabled)
    }

    // =========================================================================
    // PHY namespace movement
    // =========================================================================

    /// Move a wireless PHY to a different network namespace.
    ///
    /// The PHY is identified by its wiphy index (from `get_phys()`).
    /// The target namespace is specified by file descriptor (from
    /// [`namespace::open()`](crate::netlink::namespace::open) or
    /// [`NamespaceFd`](crate::netlink::namespace::NamespaceFd)).
    ///
    /// After the move, all interfaces on this PHY appear inside the
    /// target namespace. The PHY can only be in one namespace at a time.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Nl80211, namespace};
    ///
    /// let nl = Connection::<Nl80211>::new_async().await?;
    /// let phys = nl.get_phys().await?;
    /// let ns_fd = namespace::open("my-namespace")?;
    ///
    /// // Move phy0 to the namespace
    /// nl.set_wiphy_netns(phys[0].index, &ns_fd).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wiphy_netns"))]
    pub async fn set_wiphy_netns(&self, wiphy: u32, netns_fd: impl std::os::fd::AsFd) -> Result<()> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&netns_fd.as_fd());
        self.move_wiphy(wiphy, WiphyNetns::Fd(fd))
            .await
            .map_err(|e| e.with_context("set_wiphy_netns"))
    }

    /// Move a wireless PHY to the network namespace of a given process.
    ///
    /// This is a convenience variant that uses the process PID instead of
    /// a namespace file descriptor.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wiphy_netns_pid"))]
    pub async fn set_wiphy_netns_pid(&self, wiphy: u32, pid: u32) -> Result<()> {
        self.move_wiphy(wiphy, WiphyNetns::Pid(pid))
            .await
            .map_err(|e| e.with_context("set_wiphy_netns_pid"))
    }

    /// Change interface `ifindex`'s type (`NL80211_CMD_SET_INTERFACE`,
    /// #530): to a mesh point to join a mesh, to an access point, ….
    /// Bring the interface down first: mac80211 changes a running
    /// interface's type only where the driver can (`EBUSY` otherwise, as
    /// on `mac80211_hwsim`). Unverified on a live kernel.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_interface_type_by_index"))]
    pub async fn set_interface_type_by_index(&self, ifindex: u32, iftype: InterfaceType) -> Result<()> {
        let builder = interface_request(self.state().family_id, NL80211_CMD_SET_INTERFACE, Some(ifindex), |b| {
            b.append_attr_u32(NL80211_ATTR_IFTYPE, iftype as u32);
        });
        self.ack(builder).await.map_err(|e| e.with_context("set_interface_type"))
    }

    /// [`set_interface_type_by_index`](Self::set_interface_type_by_index),
    /// by name.
    pub async fn set_interface_type(&self, iface: &str, iftype: InterfaceType) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.set_interface_type_by_index(ifindex, iftype).await
    }

    /// Create an interface `name` of `iftype` on `wiphy`
    /// (`NL80211_CMD_NEW_INTERFACE`, #530), returning its ifindex.
    /// Unverified on a live kernel.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "new_interface"))]
    pub async fn new_interface(&self, wiphy: u32, name: &str, iftype: InterfaceType) -> Result<u32> {
        let mut builder = interface_request(self.state().family_id, NL80211_CMD_NEW_INTERFACE, None, |b| {
            b.append_attr_u32(NL80211_ATTR_WIPHY, wiphy);
            b.append_attr_str(NL80211_ATTR_IFNAME, name);
            b.append_attr_u32(NL80211_ATTR_IFTYPE, iftype as u32);
        });
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());
        self.socket().send(&builder.finish()).await?;
        // The kernel answers with the new interface, then the ACK.
        let mut ifindex = None;
        self.with_timeout(async {
            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                for message in MessageIter::new(&data) {
                    let (header, payload) = message?;
                    if header.nlmsg_seq != seq {
                        continue;
                    }
                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        if !err.is_ack() {
                            return Err(err.to_error(header.nlmsg_flags, payload));
                        }
                        return ifindex.ok_or_else(|| {
                            crate::netlink::Error::invalid_message(
                                "new_interface: the kernel acked without the interface",
                            )
                        });
                    }
                    let attrs = payload.get(crate::netlink::genl::GENL_HDRLEN..).unwrap_or(&[]);
                    ifindex = AttrIter::new(attrs)
                        .find(|(a, _)| a & 0x7FFF == NL80211_ATTR_IFINDEX)
                        .and_then(|(_, v)| crate::netlink::attr::get::u32_ne(v).ok())
                        .or(ifindex);
                }
            }
        })
        .await
    }

    /// Delete interface `ifindex` (`NL80211_CMD_DEL_INTERFACE`, #530).
    /// Unverified on a live kernel.
    pub async fn del_interface_by_index(&self, ifindex: u32) -> Result<()> {
        let builder = interface_request(self.state().family_id, NL80211_CMD_DEL_INTERFACE, Some(ifindex), |_| {});
        self.ack(builder).await.map_err(|e| e.with_context("del_interface"))
    }

    /// [`del_interface_by_index`](Self::del_interface_by_index), by name.
    pub async fn del_interface(&self, iface: &str) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.del_interface_by_index(ifindex).await
    }

    /// Join mesh `mesh_id` (at most 32 bytes) on `freq_mhz`
    /// (`NL80211_CMD_JOIN_MESH`, #530) — `iw dev X mesh join`. The
    /// interface must be a mesh point, and up. Unverified on a live
    /// kernel.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "join_mesh_by_index"))]
    pub async fn join_mesh_by_index(&self, ifindex: u32, mesh_id: &[u8], freq_mhz: u32) -> Result<()> {
        if mesh_id.is_empty() || mesh_id.len() > 32 {
            return Err(crate::netlink::Error::invalid_message(format!(
                "join_mesh: a mesh id is 1 to 32 bytes, not {}",
                mesh_id.len()
            )));
        }
        let builder = interface_request(self.state().family_id, NL80211_CMD_JOIN_MESH, Some(ifindex), |b| {
            b.append_attr(NL80211_ATTR_MESH_ID, mesh_id);
            b.append_attr_u32(NL80211_ATTR_WIPHY_FREQ, freq_mhz);
        });
        self.ack(builder).await.map_err(|e| e.with_context("join_mesh"))
    }

    /// [`join_mesh_by_index`](Self::join_mesh_by_index), by name.
    pub async fn join_mesh(&self, iface: &str, mesh_id: &[u8], freq_mhz: u32) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.join_mesh_by_index(ifindex, mesh_id, freq_mhz).await
    }

    /// Leave the mesh (`NL80211_CMD_LEAVE_MESH`, #530). Unverified on a
    /// live kernel.
    pub async fn leave_mesh_by_index(&self, ifindex: u32) -> Result<()> {
        let builder = interface_request(self.state().family_id, NL80211_CMD_LEAVE_MESH, Some(ifindex), |_| {});
        self.ack(builder).await.map_err(|e| e.with_context("leave_mesh"))
    }

    /// [`leave_mesh_by_index`](Self::leave_mesh_by_index), by name.
    pub async fn leave_mesh(&self, iface: &str) -> Result<()> {
        let ifindex = self.resolve_ifindex(iface).await?;
        self.leave_mesh_by_index(ifindex).await
    }

    /// Send `builder` and wait for its ACK.
    async fn ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());
        self.socket().send(&builder.finish()).await?;
        self.wait_ack(&mut session, seq).await
    }

    async fn move_wiphy(&self, wiphy: u32, to: WiphyNetns) -> Result<()> {
        let mut builder = wiphy_netns_request(self.state().family_id, wiphy, to);
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());
        let msg = builder.finish();
        self.socket().send(&msg).await?;
        self.wait_ack(&mut session, seq).await
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a GENL dump request (no filter).
    async fn nl80211_dump(&self, cmd: u8) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(cmd, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(&mut session, seq).await
    }

    /// Send a `GET_WIPHY` dump with `NL80211_ATTR_SPLIT_WIPHY_DUMP`.
    ///
    /// Without the flag the kernel caps each wiphy's reply to a single
    /// message, silently dropping bands/channels/HE caps that don't
    /// fit. With it, a wiphy's attributes span multiple messages (same
    /// `NL80211_ATTR_WIPHY` index) which `get_phys` reassembles.
    async fn dump_wiphy_split(&self) -> Result<Vec<Vec<u8>>> {
        let family_id = self.state().family_id;

        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_DUMP);
        let genl_hdr = GenlMsgHdr::new(NL80211_CMD_GET_WIPHY, NL80211_GENL_VERSION);
        builder.append(&genl_hdr);
        builder.append_attr_empty(NL80211_ATTR_SPLIT_WIPHY_DUMP);

        let seq = self.socket().next_seq();

        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.collect_dump_responses(&mut session, seq).await
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
                        Classification::Data { payload } => {
                            results.push(payload.to_vec());
                        }
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

    /// Wait for an ACK response.
    async fn wait_ack(
        &self,
        session: &mut crate::netlink::connection::RecvSession,
        seq: u32,
    ) -> Result<()> {
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

    /// Resolve interface name to ifindex via dump.
    async fn resolve_ifindex(&self, name: &str) -> Result<u32> {
        let ifaces = self.get_interfaces().await?;
        ifaces
            .iter()
            .find(|i| i.name.as_deref() == Some(name))
            .map(|i| i.ifindex)
            .ok_or_else(|| Error::invalid_attribute(format!("interface not found: {name}")))
    }
}

// =============================================================================
// Attribute Parsing
// =============================================================================

fn parse_interface(data: &[u8]) -> WirelessInterface {
    let mut iface = WirelessInterface {
        ifindex: 0,
        name: None,
        iftype: InterfaceType::Unspecified,
        wiphy: 0,
        mac: None,
        frequency: None,
        ssid: None,
        signal_dbm: None,
        tx_bitrate: None,
        generation: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_IFINDEX if payload.len() >= 4 => {
                iface.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_IFNAME => {
                iface.name = attr_str(payload);
            }
            NL80211_ATTR_IFTYPE if payload.len() >= 4 => {
                let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                iface.iftype = InterfaceType::try_from(val).unwrap_or(InterfaceType::Unspecified);
            }
            NL80211_ATTR_WIPHY if payload.len() >= 4 => {
                iface.wiphy = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_MAC if payload.len() >= 6 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&payload[..6]);
                iface.mac = Some(mac);
            }
            NL80211_ATTR_WIPHY_FREQ if payload.len() >= 4 => {
                iface.frequency = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_ATTR_SSID => {
                iface.ssid = std::str::from_utf8(payload).ok().map(String::from);
            }
            NL80211_ATTR_GENERATION if payload.len() >= 4 => {
                iface.generation = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }

    iface
}

fn parse_bss(data: &[u8]) -> ScanResult {
    let mut result = ScanResult {
        bssid: [0; 6],
        frequency: 0,
        ..Default::default()
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_BSS_BSSID if payload.len() >= 6 => {
                result.bssid.copy_from_slice(&payload[..6]);
            }
            NL80211_BSS_FREQUENCY if payload.len() >= 4 => {
                result.frequency = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_BSS_TSF if payload.len() >= 8 => {
                result.tsf = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_BSS_BEACON_INTERVAL if payload.len() >= 2 => {
                result.beacon_interval = u16::from_ne_bytes(payload[..2].try_into().unwrap());
            }
            NL80211_BSS_CAPABILITY if payload.len() >= 2 => {
                result.capability = u16::from_ne_bytes(payload[..2].try_into().unwrap());
            }
            NL80211_BSS_INFORMATION_ELEMENTS => {
                result.information_elements = payload.to_vec();
                // Walk the IE chain to find the SSID (element-id 0).
                // Plan 215 M13 — pre-fix assumed SSID is the FIRST IE
                // and returned None for any BSS whose beacon
                // prepended a vendor-specific IE (id=221) before the
                // SSID. Now walks the chain per 802.11 spec.
                result.ssid = parse_ssid_from_ies(payload);
            }
            NL80211_BSS_SIGNAL_MBM if payload.len() >= 4 => {
                result.signal_mbm = i32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_BSS_STATUS if payload.len() >= 4 => {
                let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                result.status = BssStatus::try_from(val).ok();
            }
            NL80211_BSS_SEEN_MS_AGO if payload.len() >= 4 => {
                result.seen_ms_ago = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_BSS_SIGNAL_UNSPEC if !payload.is_empty() => {
                result.signal_unspec = Some(payload[0]);
            }
            NL80211_BSS_BEACON_IES => {
                result.beacon_ies = payload.to_vec();
                // Prefer the SSID from the (probe-response) IEs; fall
                // back to the beacon IEs only if we haven't found one.
                if result.ssid.is_none() {
                    result.ssid = parse_ssid_from_ies(payload);
                }
            }
            NL80211_BSS_LAST_SEEN_BOOTTIME if payload.len() >= 8 => {
                result.last_seen_boottime_ns =
                    Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_BSS_FREQUENCY_OFFSET if payload.len() >= 4 => {
                result.frequency_offset_khz =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }

    result
}

/// Walk the 802.11 information elements (TLV chain) and extract the
/// SSID (element-id 0). The SSID IE may not be the first element —
/// vendor-specific IEs (id=221) are sometimes prepended.
///
/// Plan 215 M13 (0.19). Returns `None` if no SSID IE is found or
/// the chain is malformed. UTF-8 decoding is lossy to match how
/// `wpa_supplicant` and other tools handle non-printable SSIDs.
fn parse_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = ies[offset + 1] as usize;
        if offset + 2 + len > ies.len() {
            // Truncated IE — bail rather than slice-panic.
            return None;
        }
        if id == 0 {
            return Some(String::from_utf8_lossy(&ies[offset + 2..offset + 2 + len]).into_owned());
        }
        offset += 2 + len;
    }
    None
}

fn parse_station(data: &[u8]) -> StationInfo {
    let mut station = StationInfo {
        mac: [0; 6],
        ifindex: 0,
        ..Default::default()
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_MAC if payload.len() >= 6 => {
                station.mac.copy_from_slice(&payload[..6]);
            }
            NL80211_ATTR_IFINDEX if payload.len() >= 4 => {
                station.ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_ATTR_STA_INFO => {
                parse_station_info_nested(payload, &mut station);
            }
            _ => {}
        }
    }

    station
}

fn parse_station_info_nested(data: &[u8], station: &mut StationInfo) {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_STA_INFO_INACTIVE_TIME if payload.len() >= 4 => {
                station.inactive_time_ms =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_RX_BYTES if payload.len() >= 4 && station.rx_bytes.is_none() => {
                station.rx_bytes =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64);
            }
            NL80211_STA_INFO_TX_BYTES if payload.len() >= 4 && station.tx_bytes.is_none() => {
                station.tx_bytes =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()) as u64);
            }
            NL80211_STA_INFO_RX_BYTES64 if payload.len() >= 8 => {
                station.rx_bytes = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_STA_INFO_TX_BYTES64 if payload.len() >= 8 => {
                station.tx_bytes = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_STA_INFO_SIGNAL if !payload.is_empty() => {
                station.signal_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_SIGNAL_AVG if !payload.is_empty() => {
                station.signal_avg_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_TX_BITRATE => {
                station.tx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_RX_BITRATE => {
                station.rx_bitrate = Some(parse_bitrate_info(payload));
            }
            NL80211_STA_INFO_RX_PACKETS if payload.len() >= 4 => {
                station.rx_packets = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_TX_PACKETS if payload.len() >= 4 => {
                station.tx_packets = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_TX_RETRIES if payload.len() >= 4 => {
                station.tx_retries = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_TX_FAILED if payload.len() >= 4 => {
                station.tx_failed = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_BEACON_LOSS if payload.len() >= 4 => {
                station.beacon_loss = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_RX_DROP_MISC if payload.len() >= 8 => {
                station.rx_drop_misc = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_STA_INFO_EXPECTED_THROUGHPUT if payload.len() >= 4 => {
                station.expected_throughput_kbps =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_STA_INFO_BEACON_SIGNAL_AVG if !payload.is_empty() => {
                station.beacon_signal_avg_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_ACK_SIGNAL if !payload.is_empty() => {
                station.ack_signal_dbm = Some(payload[0] as i8);
            }
            NL80211_STA_INFO_CONNECTED_TIME if payload.len() >= 4 => {
                station.connected_time_secs =
                    Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            _ => {}
        }
    }
}

/// Parse a single `NL80211_CMD_GET_SURVEY` dump message into a
/// [`SurveyInfo`]. Returns `None` if the message carries no
/// `NL80211_ATTR_SURVEY_INFO` nest (e.g. a header-only frame).
fn parse_survey(data: &[u8]) -> Option<SurveyInfo> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == NL80211_ATTR_SURVEY_INFO {
            return Some(parse_survey_info_nested(payload));
        }
    }
    None
}

fn parse_survey_info_nested(data: &[u8]) -> SurveyInfo {
    let mut s = SurveyInfo::default();
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_SURVEY_INFO_FREQUENCY if payload.len() >= 4 => {
                s.frequency_mhz = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_SURVEY_INFO_FREQUENCY_OFFSET if payload.len() >= 4 => {
                s.frequency_offset_khz = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_NOISE if !payload.is_empty() => {
                s.noise_dbm = Some(payload[0] as i8);
            }
            NL80211_SURVEY_INFO_IN_USE => {
                s.in_use = true;
            }
            NL80211_SURVEY_INFO_TIME if payload.len() >= 8 => {
                s.time_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_BUSY if payload.len() >= 8 => {
                s.time_busy_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_EXT_BUSY if payload.len() >= 8 => {
                s.time_ext_busy_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_RX if payload.len() >= 8 => {
                s.time_rx_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_TX if payload.len() >= 8 => {
                s.time_tx_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_SCAN if payload.len() >= 8 => {
                s.time_scan_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            NL80211_SURVEY_INFO_TIME_BSS_RX if payload.len() >= 8 => {
                s.time_bss_rx_ms = Some(u64::from_ne_bytes(payload[..8].try_into().unwrap()));
            }
            _ => {}
        }
    }
    s
}

fn parse_bitrate_info(data: &[u8]) -> BitrateInfo {
    let mut info = BitrateInfo {
        bitrate_100kbps: None,
        mcs: None,
        width: None,
        short_gi: false,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_RATE_INFO_BITRATE if payload.len() >= 2 && info.bitrate_100kbps.is_none() => {
                info.bitrate_100kbps =
                    Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()) as u32);
            }
            NL80211_RATE_INFO_BITRATE32 if payload.len() >= 4 => {
                info.bitrate_100kbps = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_RATE_INFO_MCS | NL80211_RATE_INFO_VHT_MCS if !payload.is_empty() => {
                info.mcs = Some(payload[0]);
            }
            NL80211_RATE_INFO_SHORT_GI => {
                info.short_gi = true; // Flag attribute
            }
            NL80211_RATE_INFO_40_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width40);
            }
            NL80211_RATE_INFO_80_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width80);
            }
            NL80211_RATE_INFO_80P80_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width80P80);
            }
            NL80211_RATE_INFO_160_MHZ_WIDTH => {
                info.width = Some(ChannelWidth::Width160);
            }
            _ => {}
        }
    }

    info
}

/// Find the `NL80211_ATTR_WIPHY` index in a `GET_WIPHY` message's
/// attributes, so split-dump frames can be grouped by device.
fn wiphy_index_of(data: &[u8]) -> Option<u32> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == NL80211_ATTR_WIPHY && payload.len() >= 4 {
            return Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
        }
    }
    None
}

/// Accumulates a single wiphy's attributes across the multiple
/// messages of a split `GET_WIPHY` dump. Bands are keyed by band
/// index so a band whose frequency list spans messages is merged
/// rather than duplicated.
#[derive(Default)]
struct PhyAcc {
    index: u32,
    name: String,
    supported_iftypes: Vec<InterfaceType>,
    max_scan_ssids: Option<u8>,
    cipher_suites: Vec<u32>,
    bands: BTreeMap<u16, Band>,
}

impl PhyAcc {
    /// Fold one split-dump message's attributes into the accumulator.
    fn merge_message(&mut self, data: &[u8]) {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                NL80211_ATTR_WIPHY if payload.len() >= 4 => {
                    self.index = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
                NL80211_ATTR_WIPHY_NAME if self.name.is_empty() => {
                    self.name = attr_str(payload).unwrap_or_default();
                }
                NL80211_ATTR_MAX_NUM_SCAN_SSIDS if !payload.is_empty() => {
                    self.max_scan_ssids.get_or_insert(payload[0]);
                }
                NL80211_ATTR_SUPPORTED_IFTYPES => {
                    for (idx, _v) in AttrIter::new(payload) {
                        // The attr index itself is the iftype value.
                        if let Ok(iftype) = InterfaceType::try_from(idx as u32)
                            && !self.supported_iftypes.contains(&iftype)
                        {
                            self.supported_iftypes.push(iftype);
                        }
                    }
                }
                NL80211_ATTR_CIPHER_SUITES => {
                    // Flat array of u32 suite selectors.
                    for chunk in payload.as_chunks::<4>().0 {
                        self.cipher_suites.push(u32::from_ne_bytes(*chunk));
                    }
                }
                NL80211_ATTR_WIPHY_BANDS => {
                    for (band_idx, band_data) in AttrIter::new(payload) {
                        let partial = parse_band(band_data);
                        merge_band(self.bands.entry(band_idx).or_default(), partial);
                    }
                }
                _ => {}
            }
        }
    }

    fn finalize(self) -> PhyInfo {
        PhyInfo {
            index: self.index,
            name: self.name,
            bands: self.bands.into_values().collect(),
            supported_iftypes: self.supported_iftypes,
            max_scan_ssids: self.max_scan_ssids,
            cipher_suites: self.cipher_suites,
        }
    }
}

/// Merge one message's slice of a band into the accumulated band.
/// Lists (freqs/rates/iftype caps) concatenate — the kernel splits
/// arrays at element boundaries without repeating — while scalar
/// capabilities are filled when present.
fn merge_band(dst: &mut Band, src: Band) {
    dst.frequencies.extend(src.frequencies);
    dst.rates.extend(src.rates);
    if src.ht_capa.is_some() {
        dst.ht_capa = src.ht_capa;
    }
    if src.vht_capa.is_some() {
        dst.vht_capa = src.vht_capa;
    }
    if src.ht_mcs_set.is_some() {
        dst.ht_mcs_set = src.ht_mcs_set;
    }
    if src.vht_mcs_set.is_some() {
        dst.vht_mcs_set = src.vht_mcs_set;
    }
    dst.iftype_capa.extend(src.iftype_capa);
}

fn parse_band(data: &[u8]) -> Band {
    let mut band = Band::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_BAND_ATTR_FREQS => {
                for (_idx, freq_data) in AttrIter::new(payload) {
                    band.frequencies.push(parse_frequency(freq_data));
                }
            }
            NL80211_BAND_ATTR_RATES => {
                for (_idx, rate_data) in AttrIter::new(payload) {
                    for (rate_attr, rate_payload) in AttrIter::new(rate_data) {
                        if rate_attr == NL80211_BITRATE_ATTR_RATE && rate_payload.len() >= 4 {
                            band.rates
                                .push(u32::from_ne_bytes(rate_payload[..4].try_into().unwrap()));
                        }
                    }
                }
            }
            NL80211_BAND_ATTR_HT_CAPA if payload.len() >= 2 => {
                band.ht_capa = Some(u16::from_ne_bytes(payload[..2].try_into().unwrap()));
            }
            NL80211_BAND_ATTR_VHT_CAPA if payload.len() >= 4 => {
                band.vht_capa = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            NL80211_BAND_ATTR_HT_MCS_SET if !payload.is_empty() => {
                band.ht_mcs_set = Some(payload.to_vec());
            }
            NL80211_BAND_ATTR_VHT_MCS_SET if !payload.is_empty() => {
                band.vht_mcs_set = Some(payload.to_vec());
            }
            NL80211_BAND_ATTR_IFTYPE_DATA => {
                for (_idx, iftype_data) in AttrIter::new(payload) {
                    band.iftype_capa.push(parse_band_iftype_data(iftype_data));
                }
            }
            _ => {}
        }
    }

    band
}

fn parse_band_iftype_data(data: &[u8]) -> BandIftypeCapa {
    let mut capa = BandIftypeCapa::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_BAND_IFTYPE_ATTR_IFTYPES => {
                for (idx, _v) in AttrIter::new(payload) {
                    if let Ok(iftype) = InterfaceType::try_from(idx as u32) {
                        capa.iftypes.push(iftype);
                    }
                }
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC if !payload.is_empty() => {
                capa.he_cap_mac = Some(payload.to_vec());
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY if !payload.is_empty() => {
                capa.he_cap_phy = Some(payload.to_vec());
            }
            NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET if !payload.is_empty() => {
                capa.he_cap_mcs_set = Some(payload.to_vec());
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC if !payload.is_empty() => {
                capa.eht_cap_mac = Some(payload.to_vec());
            }
            NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY if !payload.is_empty() => {
                capa.eht_cap_phy = Some(payload.to_vec());
            }
            _ => {}
        }
    }

    capa
}

fn parse_frequency(data: &[u8]) -> Frequency {
    let mut freq = Frequency::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_FREQUENCY_ATTR_FREQ if payload.len() >= 4 => {
                freq.freq = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_FREQUENCY_ATTR_DISABLED => {
                freq.disabled = true; // Flag attribute
            }
            NL80211_FREQUENCY_ATTR_NO_IR => {
                freq.no_ir = true;
            }
            NL80211_FREQUENCY_ATTR_RADAR => {
                freq.radar = true;
            }
            NL80211_FREQUENCY_ATTR_MAX_TX_POWER if payload.len() >= 4 => {
                freq.max_power_mbm = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            NL80211_FREQUENCY_ATTR_DFS_STATE if payload.len() >= 4 => {
                let v = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                freq.dfs_state = DfsState::try_from(v).ok();
            }
            NL80211_FREQUENCY_ATTR_NO_HT40_MINUS => {
                freq.no_ht40_minus = true;
            }
            NL80211_FREQUENCY_ATTR_NO_HT40_PLUS => {
                freq.no_ht40_plus = true;
            }
            NL80211_FREQUENCY_ATTR_NO_80MHZ => {
                freq.no_80mhz = true;
            }
            NL80211_FREQUENCY_ATTR_NO_160MHZ => {
                freq.no_160mhz = true;
            }
            NL80211_FREQUENCY_ATTR_OFFSET if payload.len() >= 4 => {
                freq.offset_khz = u32::from_ne_bytes(payload[..4].try_into().unwrap());
            }
            _ => {}
        }
    }

    freq
}

fn parse_regulatory(data: &[u8], domain: &mut RegulatoryDomain) {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            NL80211_ATTR_REG_ALPHA2 => {
                domain.country = attr_str(payload).unwrap_or_default();
            }
            NL80211_ATTR_REG_RULES => {
                for (_idx, rule_data) in AttrIter::new(payload) {
                    domain.rules.push(parse_reg_rule(rule_data));
                }
            }
            _ => {}
        }
    }
}

fn parse_reg_rule(data: &[u8]) -> RegulatoryRule {
    let mut rule = RegulatoryRule {
        start_freq_khz: 0,
        end_freq_khz: 0,
        max_bandwidth_khz: 0,
        max_antenna_gain_mbi: 0,
        max_eirp_mbm: 0,
        flags: 0,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        if payload.len() < 4 {
            continue;
        }
        let val = u32::from_ne_bytes(payload[..4].try_into().unwrap());
        match attr_type {
            NL80211_ATTR_REG_RULE_FLAGS => rule.flags = val,
            NL80211_ATTR_FREQ_RANGE_START => rule.start_freq_khz = val,
            NL80211_ATTR_FREQ_RANGE_END => rule.end_freq_khz = val,
            NL80211_ATTR_FREQ_RANGE_MAX_BW => rule.max_bandwidth_khz = val,
            NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN => rule.max_antenna_gain_mbi = val,
            NL80211_ATTR_POWER_RULE_MAX_EIRP => rule.max_eirp_mbm = val,
            _ => {}
        }
    }

    rule
}

/// Validate + normalize an ISO 3166-1 alpha-2 country code to the
/// uppercase 2-char form the kernel expects. Accepts the special
/// `"00"` world domain. Rejects anything that isn't exactly two
/// ASCII letters (or `00`) — strict, so a typo errors rather than
/// silently requesting a bogus domain.
fn normalize_alpha2(s: &str) -> Result<String> {
    let t = s.trim();
    if t == "00" {
        return Ok("00".to_string());
    }
    if t.len() == 2 && t.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Ok(t.to_ascii_uppercase());
    }
    Err(Error::invalid_message(format!(
        "invalid regulatory country code `{s}` (expected a 2-letter code like `US`, or `00` for the world domain)"
    )))
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
mod alpha2_tests {
    use super::normalize_alpha2;

    #[test]
    fn normalizes_and_validates() {
        assert_eq!(normalize_alpha2("us").unwrap(), "US");
        assert_eq!(normalize_alpha2(" DE ").unwrap(), "DE");
        assert_eq!(normalize_alpha2("00").unwrap(), "00"); // world domain
        // strict — typos and junk error rather than silently apply
        assert!(normalize_alpha2("USA").is_err());
        assert!(normalize_alpha2("U").is_err());
        assert!(normalize_alpha2("U1").is_err());
        assert!(normalize_alpha2("").is_err());
    }
}

#[cfg(test)]
mod ssid_walker_tests {
    use super::parse_ssid_from_ies;

    #[test]
    fn ssid_extracted_from_first_ie() {
        // IE 0: id=0, len=4, "home"
        let ies = [0u8, 4, b'h', b'o', b'm', b'e'];
        assert_eq!(parse_ssid_from_ies(&ies).as_deref(), Some("home"));
    }

    #[test]
    fn ssid_extracted_after_vendor_specific_ie() {
        // Plan 215 M13 regression — vendor IE (id=221) prepended.
        let ies = [
            221, 3, 0xAA, 0xBB, 0xCC, // vendor IE
            0, 4, b'h', b'o', b'm', b'e', // SSID IE
        ];
        assert_eq!(parse_ssid_from_ies(&ies).as_deref(), Some("home"));
    }

    #[test]
    fn ssid_missing_returns_none_not_garbage() {
        let ies = [221u8, 3, 0xAA, 0xBB, 0xCC];
        assert_eq!(parse_ssid_from_ies(&ies), None);
    }

    #[test]
    fn truncated_ie_terminates_without_panic() {
        // IE claims 100 bytes of payload but only 3 follow.
        let ies = [0u8, 100, 1, 2, 3];
        assert_eq!(parse_ssid_from_ies(&ies), None);
    }

    #[test]
    fn ssid_with_non_utf8_decoded_lossily() {
        let ies = [0u8, 3, 0xFF, b'a', 0xFE];
        // Lossy decode produces replacement characters; assert
        // we get Some(_) (not None) and the SSID byte count is
        // preserved.
        let ssid = parse_ssid_from_ies(&ies).expect("lossy ssid");
        assert!(ssid.contains('a'));
    }

    #[test]
    fn empty_ies_returns_none() {
        assert_eq!(parse_ssid_from_ies(&[]), None);
    }
}

#[cfg(test)]
mod station_info_tests {
    use super::*;

    /// Emit a netlink attribute (TLV, 4-byte aligned) into `buf`.
    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    /// Pin every modelled `NL80211_STA_INFO_*` constant against its
    /// position in `enum nl80211_sta_info` (linux/nl80211.h). This is
    /// the regression guard for the pre-0.23 bug where RX_BITRATE was
    /// 12 (actually TX_FAILED) instead of 14.
    #[test]
    fn sta_info_constants_match_kernel_enum() {
        assert_eq!(NL80211_STA_INFO_INACTIVE_TIME, 1);
        assert_eq!(NL80211_STA_INFO_RX_BYTES, 2);
        assert_eq!(NL80211_STA_INFO_TX_BYTES, 3);
        assert_eq!(NL80211_STA_INFO_SIGNAL, 7);
        assert_eq!(NL80211_STA_INFO_TX_BITRATE, 8);
        assert_eq!(NL80211_STA_INFO_RX_PACKETS, 9);
        assert_eq!(NL80211_STA_INFO_TX_PACKETS, 10);
        assert_eq!(NL80211_STA_INFO_TX_RETRIES, 11);
        assert_eq!(NL80211_STA_INFO_TX_FAILED, 12);
        assert_eq!(NL80211_STA_INFO_SIGNAL_AVG, 13);
        assert_eq!(NL80211_STA_INFO_RX_BITRATE, 14); // NOT 12
        assert_eq!(NL80211_STA_INFO_CONNECTED_TIME, 16);
        assert_eq!(NL80211_STA_INFO_STA_FLAGS, 17);
        assert_eq!(NL80211_STA_INFO_BEACON_LOSS, 18);
        assert_eq!(NL80211_STA_INFO_RX_BYTES64, 23);
        assert_eq!(NL80211_STA_INFO_TX_BYTES64, 24);
        assert_eq!(NL80211_STA_INFO_EXPECTED_THROUGHPUT, 27);
        assert_eq!(NL80211_STA_INFO_RX_DROP_MISC, 28);
        assert_eq!(NL80211_STA_INFO_BEACON_RX, 29);
        assert_eq!(NL80211_STA_INFO_BEACON_SIGNAL_AVG, 30);
        assert_eq!(NL80211_STA_INFO_ACK_SIGNAL, 34);
    }

    /// TX_FAILED (12) and RX_BITRATE (14) are distinct attributes;
    /// before the fix, attr 12 was misparsed as rx_bitrate. Build a
    /// station nest carrying both + the new counters and confirm each
    /// lands in the right field.
    #[test]
    fn parse_station_distinguishes_tx_failed_from_rx_bitrate() {
        // Inner STA_INFO nest.
        let mut sta = Vec::new();
        push_attr(&mut sta, NL80211_STA_INFO_TX_FAILED, &7u32.to_ne_bytes());
        push_attr(&mut sta, NL80211_STA_INFO_RX_PACKETS, &100u32.to_ne_bytes());
        push_attr(&mut sta, NL80211_STA_INFO_TX_PACKETS, &200u32.to_ne_bytes());
        push_attr(&mut sta, NL80211_STA_INFO_TX_RETRIES, &3u32.to_ne_bytes());
        push_attr(&mut sta, NL80211_STA_INFO_BEACON_LOSS, &1u32.to_ne_bytes());
        push_attr(&mut sta, NL80211_STA_INFO_RX_DROP_MISC, &9u64.to_ne_bytes());
        push_attr(
            &mut sta,
            NL80211_STA_INFO_EXPECTED_THROUGHPUT,
            &54000u32.to_ne_bytes(),
        );
        push_attr(&mut sta, NL80211_STA_INFO_ACK_SIGNAL, &[0xCE]); // -50 dBm
        // RX_BITRATE is a nest; an empty one parses to a default
        // BitrateInfo, which is enough to prove attr 14 → rx_bitrate.
        push_attr(&mut sta, NL80211_STA_INFO_RX_BITRATE, &[]);

        // Outer station attrs: MAC + STA_INFO.
        let mut outer = Vec::new();
        push_attr(&mut outer, NL80211_ATTR_MAC, &[1, 2, 3, 4, 5, 6]);
        push_attr(&mut outer, NL80211_ATTR_STA_INFO, &sta);

        let s = parse_station(&outer);
        assert_eq!(s.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(s.tx_failed, Some(7)); // attr 12 → tx_failed (not rx_bitrate)
        assert!(s.rx_bitrate.is_some()); // attr 14 → rx_bitrate
        assert_eq!(s.rx_packets, Some(100));
        assert_eq!(s.tx_packets, Some(200));
        assert_eq!(s.tx_retries, Some(3));
        assert_eq!(s.beacon_loss, Some(1));
        assert_eq!(s.rx_drop_misc, Some(9));
        assert_eq!(s.expected_throughput_kbps, Some(54000));
        assert_eq!(s.ack_signal_dbm, Some(-50));
    }
}

#[cfg(test)]
mod bss_tests {
    use super::*;

    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    /// Pin every modelled `NL80211_BSS_*` constant against its position
    /// in `enum nl80211_bss` (linux/nl80211.h) — the same id-drift guard
    /// added for STA_INFO. (BSS constants were already correct; this
    /// locks them.)
    /// Hand-pinned copy of the kernel enum.
    ///
    /// As of #266 this is a *fast local check*, not the guard — the UAPI audit
    /// gate now verifies every `pub const` whose name the kernel also defines,
    /// which covers all of these automatically and cannot go stale the way a
    /// hand-copied table can. `NL80211_BSS_FREQUENCY_OFFSET` was pinned here at
    /// 21 (the kernel's `NL80211_BSS_MLO_LINK_ID`) for exactly that reason: the
    /// table was transcribed from the same wrong source as the constant.
    ///
    /// Note the fixtures below (`parse_bss_reads_new_attributes` and the survey
    /// tests) build frames from these same symbols, so they stay green whatever
    /// the value is. That is fine *now* — the symbol is checked against the
    /// header — but it is why they never caught the drift themselves.
    #[test]
    fn bss_constants_match_kernel_enum() {
        assert_eq!(NL80211_BSS_BSSID, 1);
        assert_eq!(NL80211_BSS_FREQUENCY, 2);
        assert_eq!(NL80211_BSS_TSF, 3);
        assert_eq!(NL80211_BSS_BEACON_INTERVAL, 4);
        assert_eq!(NL80211_BSS_CAPABILITY, 5);
        assert_eq!(NL80211_BSS_INFORMATION_ELEMENTS, 6);
        assert_eq!(NL80211_BSS_SIGNAL_MBM, 7);
        assert_eq!(NL80211_BSS_SIGNAL_UNSPEC, 8);
        assert_eq!(NL80211_BSS_STATUS, 9);
        assert_eq!(NL80211_BSS_SEEN_MS_AGO, 10);
        assert_eq!(NL80211_BSS_BEACON_IES, 11);
        assert_eq!(NL80211_BSS_LAST_SEEN_BOOTTIME, 15);
        assert_eq!(NL80211_BSS_FREQUENCY_OFFSET, 20);
    }

    #[test]
    fn parse_bss_reads_new_attributes() {
        let mut bss = Vec::new();
        push_attr(&mut bss, NL80211_BSS_BSSID, &[0xAA; 6]);
        push_attr(&mut bss, NL80211_BSS_FREQUENCY, &5180u32.to_ne_bytes());
        push_attr(&mut bss, NL80211_BSS_SIGNAL_UNSPEC, &[70]);
        push_attr(
            &mut bss,
            NL80211_BSS_LAST_SEEN_BOOTTIME,
            &123_456_789u64.to_ne_bytes(),
        );
        push_attr(
            &mut bss,
            NL80211_BSS_FREQUENCY_OFFSET,
            &500u32.to_ne_bytes(),
        );
        // Beacon IEs carrying an SSID — picked up when probe-resp IEs
        // are absent.
        let ssid_ie = [0u8, 4, b'h', b'o', b'm', b'e'];
        push_attr(&mut bss, NL80211_BSS_BEACON_IES, &ssid_ie);

        let r = parse_bss(&bss);
        assert_eq!(r.bssid, [0xAA; 6]);
        assert_eq!(r.frequency, 5180);
        assert_eq!(r.signal_unspec, Some(70));
        assert_eq!(r.last_seen_boottime_ns, Some(123_456_789));
        assert_eq!(r.frequency_offset_khz, Some(500));
        assert_eq!(r.beacon_ies, ssid_ie);
        assert_eq!(r.ssid.as_deref(), Some("home"));
    }

    /// Probe-response IEs take precedence over beacon IEs for the SSID.
    #[test]
    fn probe_response_ies_win_over_beacon_for_ssid() {
        let mut bss = Vec::new();
        push_attr(
            &mut bss,
            NL80211_BSS_INFORMATION_ELEMENTS,
            &[0u8, 5, b'r', b'e', b'a', b'l', b'!'],
        );
        push_attr(
            &mut bss,
            NL80211_BSS_BEACON_IES,
            &[0u8, 6, b'h', b'i', b'd', b'd', b'e', b'n'],
        );
        let r = parse_bss(&bss);
        assert_eq!(r.ssid.as_deref(), Some("real!"));
    }
}

#[cfg(test)]
mod survey_tests {
    use super::*;

    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    /// Pin every modelled `NL80211_SURVEY_INFO_*` constant against its
    /// position in `enum nl80211_survey_info` (linux/nl80211.h) — the
    /// same id-drift guard added for STA_INFO and BSS.
    #[test]
    fn survey_info_constants_match_kernel_enum() {
        assert_eq!(NL80211_SURVEY_INFO_FREQUENCY, 1);
        assert_eq!(NL80211_SURVEY_INFO_NOISE, 2);
        assert_eq!(NL80211_SURVEY_INFO_IN_USE, 3);
        assert_eq!(NL80211_SURVEY_INFO_TIME, 4);
        assert_eq!(NL80211_SURVEY_INFO_TIME_BUSY, 5);
        assert_eq!(NL80211_SURVEY_INFO_TIME_EXT_BUSY, 6);
        assert_eq!(NL80211_SURVEY_INFO_TIME_RX, 7);
        assert_eq!(NL80211_SURVEY_INFO_TIME_TX, 8);
        assert_eq!(NL80211_SURVEY_INFO_TIME_SCAN, 9);
        assert_eq!(NL80211_SURVEY_INFO_TIME_BSS_RX, 11);
        assert_eq!(NL80211_SURVEY_INFO_FREQUENCY_OFFSET, 12);
    }

    /// A full survey nest round-trips each attribute into the right
    /// `SurveyInfo` field, including the `IN_USE` flag (zero-length).
    #[test]
    fn parse_survey_round_trips_nest() {
        let mut nest = Vec::new();
        push_attr(
            &mut nest,
            NL80211_SURVEY_INFO_FREQUENCY,
            &5180u32.to_ne_bytes(),
        );
        push_attr(
            &mut nest,
            NL80211_SURVEY_INFO_FREQUENCY_OFFSET,
            &200u32.to_ne_bytes(),
        );
        push_attr(&mut nest, NL80211_SURVEY_INFO_NOISE, &[0xBD]); // -67 dBm
        push_attr(&mut nest, NL80211_SURVEY_INFO_IN_USE, &[]); // flag
        push_attr(&mut nest, NL80211_SURVEY_INFO_TIME, &1000u64.to_ne_bytes());
        push_attr(
            &mut nest,
            NL80211_SURVEY_INFO_TIME_BUSY,
            &250u64.to_ne_bytes(),
        );
        push_attr(
            &mut nest,
            NL80211_SURVEY_INFO_TIME_RX,
            &120u64.to_ne_bytes(),
        );
        push_attr(&mut nest, NL80211_SURVEY_INFO_TIME_TX, &80u64.to_ne_bytes());

        let mut outer = Vec::new();
        push_attr(&mut outer, NL80211_ATTR_SURVEY_INFO, &nest);

        let s = parse_survey(&outer).expect("survey nest present");
        assert_eq!(s.frequency_mhz, 5180);
        assert_eq!(s.frequency_offset_khz, Some(200));
        assert_eq!(s.noise_dbm, Some(-67));
        assert!(s.in_use);
        assert_eq!(s.time_ms, Some(1000));
        assert_eq!(s.time_busy_ms, Some(250));
        assert_eq!(s.time_rx_ms, Some(120));
        assert_eq!(s.time_tx_ms, Some(80));
        assert_eq!(s.time_ext_busy_ms, None);
        assert_eq!(s.time_scan_ms, None);
    }

    /// A frame with no `SURVEY_INFO` nest (header-only) yields `None`,
    /// and truncated attrs are skipped without panicking
    /// (Parser-robustness rule 2).
    #[test]
    fn parse_survey_handles_missing_and_truncated() {
        assert!(parse_survey(&[]).is_none());

        // Outer attr present but inner FREQUENCY truncated to 2 bytes:
        // the guard skips it and frequency stays 0 (default).
        let mut nest = Vec::new();
        push_attr(&mut nest, NL80211_SURVEY_INFO_FREQUENCY, &[1, 2]);
        push_attr(&mut nest, NL80211_SURVEY_INFO_IN_USE, &[]);
        let mut outer = Vec::new();
        push_attr(&mut outer, NL80211_ATTR_SURVEY_INFO, &nest);

        let s = parse_survey(&outer).expect("nest present");
        assert_eq!(s.frequency_mhz, 0);
        assert!(s.in_use);
    }
}

#[cfg(test)]
mod band_tests {
    use super::*;

    /// Emit a netlink attribute (TLV, 4-byte aligned) into `buf`. For
    /// nested arrays, pass the array element's index as `atype`.
    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    /// Build a band nest carrying a single frequency entry at `freq`.
    fn band_with_freq(band_idx: u16, freq: u32) -> Vec<u8> {
        let mut freq_entry = Vec::new();
        push_attr(&mut freq_entry, NL80211_FREQUENCY_ATTR_FREQ, &freq.to_ne_bytes());
        let mut freqs = Vec::new();
        push_attr(&mut freqs, 0, &freq_entry); // freq array index 0
        let mut band = Vec::new();
        push_attr(&mut band, NL80211_BAND_ATTR_FREQS, &freqs);
        let mut bands = Vec::new();
        push_attr(&mut bands, band_idx, &band);
        let mut msg = Vec::new();
        push_attr(&mut msg, NL80211_ATTR_WIPHY_BANDS, &bands);
        msg
    }

    /// Pin every modelled `NL80211_BAND_ATTR_*` / `*_FREQUENCY_ATTR_*` /
    /// `*_BAND_IFTYPE_ATTR_*` constant against its position in the
    /// kernel enums (linux/nl80211.h). Regression guard for the
    /// pre-0.23 bug where VHT_CAPA was 9 (actually IFTYPE_DATA) so
    /// `vht_capa` was parsed off the wrong attribute.
    #[test]
    fn band_attr_constants_match_kernel_enum() {
        assert_eq!(NL80211_BAND_ATTR_FREQS, 1);
        assert_eq!(NL80211_BAND_ATTR_RATES, 2);
        assert_eq!(NL80211_BAND_ATTR_HT_MCS_SET, 3);
        assert_eq!(NL80211_BAND_ATTR_HT_CAPA, 4);
        assert_eq!(NL80211_BAND_ATTR_VHT_MCS_SET, 7);
        assert_eq!(NL80211_BAND_ATTR_VHT_CAPA, 8); // NOT 9
        assert_eq!(NL80211_BAND_ATTR_IFTYPE_DATA, 9);

        assert_eq!(NL80211_FREQUENCY_ATTR_FREQ, 1);
        assert_eq!(NL80211_FREQUENCY_ATTR_DISABLED, 2);
        assert_eq!(NL80211_FREQUENCY_ATTR_NO_IR, 3);
        assert_eq!(NL80211_FREQUENCY_ATTR_RADAR, 5);
        assert_eq!(NL80211_FREQUENCY_ATTR_MAX_TX_POWER, 6);
        assert_eq!(NL80211_FREQUENCY_ATTR_DFS_STATE, 7);
        assert_eq!(NL80211_FREQUENCY_ATTR_NO_HT40_MINUS, 9);
        assert_eq!(NL80211_FREQUENCY_ATTR_NO_HT40_PLUS, 10);
        assert_eq!(NL80211_FREQUENCY_ATTR_NO_80MHZ, 11);
        assert_eq!(NL80211_FREQUENCY_ATTR_NO_160MHZ, 12);
        assert_eq!(NL80211_FREQUENCY_ATTR_OFFSET, 20);

        assert_eq!(NL80211_BAND_IFTYPE_ATTR_IFTYPES, 1);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, 2);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, 3);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, 4);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, 8);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, 9);
        assert_eq!(NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, 10);

        assert_eq!(NL80211_ATTR_CIPHER_SUITES, 57);
        assert_eq!(NL80211_ATTR_SPLIT_WIPHY_DUMP, 174);
    }

    /// VHT_CAPA (attr 8) lands in `vht_capa`, and the adjacent
    /// IFTYPE_DATA (attr 9) is parsed as HE/EHT caps — not confused
    /// with VHT as the pre-0.23 mis-numbering did.
    #[test]
    fn vht_capa_uses_attr_8_and_iftype_data_is_he() {
        // IFTYPE_DATA element advertising HE PHY caps for Station.
        let mut iftypes = Vec::new();
        push_attr(&mut iftypes, InterfaceType::Station as u16, &[]);
        let mut ifd_entry = Vec::new();
        push_attr(&mut ifd_entry, NL80211_BAND_IFTYPE_ATTR_IFTYPES, &iftypes);
        push_attr(&mut ifd_entry, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, &[0xAA; 11]);
        let mut ifd = Vec::new();
        push_attr(&mut ifd, 0, &ifd_entry); // iftype-data array index 0

        let mut band = Vec::new();
        push_attr(&mut band, NL80211_BAND_ATTR_VHT_CAPA, &0xDEAD_BEEFu32.to_ne_bytes());
        push_attr(&mut band, NL80211_BAND_ATTR_IFTYPE_DATA, &ifd);

        let b = parse_band(&band);
        assert_eq!(b.vht_capa, Some(0xDEAD_BEEF));
        assert_eq!(b.iftype_capa.len(), 1);
        assert!(b.he_supported());
        assert!(!b.eht_supported());
        assert_eq!(b.iftype_capa[0].iftypes, vec![InterfaceType::Station]);
        assert_eq!(b.iftype_capa[0].he_cap_phy.as_deref(), Some(&[0xAA; 11][..]));
    }

    /// A split dump delivers one wiphy's band across two messages
    /// (same WIPHY index, same band index, different frequency slice).
    /// Reassembly merges them into one band with both frequencies —
    /// the headline correctness fix.
    #[test]
    fn split_dump_reassembles_band_by_index() {
        let mut msg1 = Vec::new();
        push_attr(&mut msg1, NL80211_ATTR_WIPHY, &0u32.to_ne_bytes());
        push_attr(&mut msg1, NL80211_ATTR_WIPHY_NAME, b"phy0\0");
        msg1.extend_from_slice(&band_with_freq(0, 2412));

        let mut msg2 = Vec::new();
        push_attr(&mut msg2, NL80211_ATTR_WIPHY, &0u32.to_ne_bytes());
        msg2.extend_from_slice(&band_with_freq(0, 2417));

        assert_eq!(wiphy_index_of(&msg1), Some(0));

        let mut acc = PhyAcc::default();
        acc.merge_message(&msg1);
        acc.merge_message(&msg2);
        let phy = acc.finalize();

        assert_eq!(phy.index, 0);
        assert_eq!(phy.name, "phy0");
        assert_eq!(phy.bands.len(), 1, "same band index must merge, not duplicate");
        let freqs: Vec<u32> = phy.bands[0].frequencies.iter().map(|f| f.freq).collect();
        assert_eq!(freqs, vec![2412, 2417]);
    }

    /// DFS state, bandwidth-restriction flags, and the freq offset
    /// parse into their fields.
    #[test]
    fn parse_frequency_reads_dfs_and_bw_flags() {
        let mut f = Vec::new();
        push_attr(&mut f, NL80211_FREQUENCY_ATTR_FREQ, &5260u32.to_ne_bytes());
        push_attr(&mut f, NL80211_FREQUENCY_ATTR_RADAR, &[]);
        push_attr(&mut f, NL80211_FREQUENCY_ATTR_DFS_STATE, &2u32.to_ne_bytes());
        push_attr(&mut f, NL80211_FREQUENCY_ATTR_NO_80MHZ, &[]);
        push_attr(&mut f, NL80211_FREQUENCY_ATTR_OFFSET, &500u32.to_ne_bytes());

        let freq = parse_frequency(&f);
        assert_eq!(freq.freq, 5260);
        assert!(freq.radar);
        assert_eq!(freq.dfs_state, Some(DfsState::Available));
        assert!(freq.no_80mhz);
        assert!(!freq.no_160mhz);
        assert_eq!(freq.offset_khz, 500);
    }
}

/// Where [`Connection::set_wiphy_netns`] and
/// [`Connection::set_wiphy_netns_pid`] move a wiphy.
#[derive(Clone, Copy)]
enum WiphyNetns {
    Fd(i32),
    Pid(u32),
}

/// The request that moves a wiphy. It is `NL80211_CMD_SET_WIPHY_NETNS`, as
/// `iw phy <phy> set netns` sends: `NL80211_CMD_SET_WIPHY` does not read the
/// namespace attributes, so the move it was sent as was acked and did
/// nothing (#604). Unverified on a live kernel: nothing here has a wiphy.
/// An nl80211 request for `cmd`, on `ifindex` if given, with what
/// `attrs` adds.
fn interface_request(
    family_id: u16,
    cmd: u8,
    ifindex: Option<u32>,
    attrs: impl FnOnce(&mut MessageBuilder),
) -> MessageBuilder {
    let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
    builder.append(&GenlMsgHdr::new(cmd, NL80211_GENL_VERSION));
    if let Some(ifindex) = ifindex {
        builder.append_attr_u32(NL80211_ATTR_IFINDEX, ifindex);
    }
    attrs(&mut builder);
    builder
}

fn wiphy_netns_request(family_id: u16, wiphy: u32, to: WiphyNetns) -> MessageBuilder {
    let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST | NLM_F_ACK);
    builder.append(&GenlMsgHdr::new(
        NL80211_CMD_SET_WIPHY_NETNS,
        NL80211_GENL_VERSION,
    ));
    builder.append_attr_u32(NL80211_ATTR_WIPHY, wiphy);
    match to {
        WiphyNetns::Fd(fd) => builder.append_attr_u32(NL80211_ATTR_NETNS_FD, fd as u32),
        WiphyNetns::Pid(pid) => builder.append_attr_u32(NL80211_ATTR_PID, pid),
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #530: each interface and mesh command, its command byte and its
    /// attributes as `iw` sends them.
    #[test]
    fn interface_and_mesh_requests_carry_their_command_and_attrs() {
        let attrs = |msg: Vec<u8>| -> (u8, Vec<(u16, Vec<u8>)>) {
            (msg[16], AttrIter::new(&msg[20..]).map(|(a, v)| (a, v.to_vec())).collect())
        };
        let ne = |v: u32| v.to_ne_bytes().to_vec();
        let set = interface_request(0x1d, NL80211_CMD_SET_INTERFACE, Some(4), |b| {
            b.append_attr_u32(NL80211_ATTR_IFTYPE, InterfaceType::MeshPoint as u32);
        });
        assert_eq!(
            attrs(set.finish()),
            (NL80211_CMD_SET_INTERFACE, vec![(NL80211_ATTR_IFINDEX, ne(4)), (NL80211_ATTR_IFTYPE, ne(7))])
        );
        let join = interface_request(0x1d, NL80211_CMD_JOIN_MESH, Some(4), |b| {
            b.append_attr(NL80211_ATTR_MESH_ID, b"lab");
            b.append_attr_u32(NL80211_ATTR_WIPHY_FREQ, 2412);
        });
        assert_eq!(
            attrs(join.finish()),
            (
                NL80211_CMD_JOIN_MESH,
                vec![
                    (NL80211_ATTR_IFINDEX, ne(4)),
                    (NL80211_ATTR_MESH_ID, b"lab".to_vec()),
                    (NL80211_ATTR_WIPHY_FREQ, ne(2412)),
                ]
            )
        );
        let leave = interface_request(0x1d, NL80211_CMD_LEAVE_MESH, Some(4), |_| {});
        assert_eq!(attrs(leave.finish()), (NL80211_CMD_LEAVE_MESH, vec![(NL80211_ATTR_IFINDEX, ne(4))]));
    }

    /// The command byte after the 16-byte nlmsghdr, and the attributes
    /// after the 4-byte genl header (#604).
    #[test]
    fn moving_a_wiphy_sends_set_wiphy_netns() {
        let attrs = |to| {
            let msg = wiphy_netns_request(0x1d, 3, to).finish();
            assert_eq!(msg[16], NL80211_CMD_SET_WIPHY_NETNS, "the command");
            let mut out = Vec::new();
            let mut rest = &msg[20..];
            while rest.len() >= 8 {
                let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
                let kind = u16::from_ne_bytes([rest[2], rest[3]]);
                let value = u32::from_ne_bytes([rest[4], rest[5], rest[6], rest[7]]);
                out.push((kind, value));
                rest = &rest[len.next_multiple_of(4).min(rest.len())..];
            }
            out
        };
        assert_eq!(NL80211_CMD_SET_WIPHY_NETNS, 49);
        assert_eq!(
            attrs(WiphyNetns::Fd(7)),
            [(NL80211_ATTR_WIPHY, 3), (NL80211_ATTR_NETNS_FD, 7)]
        );
        assert_eq!(
            attrs(WiphyNetns::Pid(4242)),
            [(NL80211_ATTR_WIPHY, 3), (NL80211_ATTR_PID, 4242)]
        );
    }
}
