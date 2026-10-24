//! Ethtool connection implementation for `Connection<Ethtool>`.
//!
//! This module provides methods for querying and configuring network device
//! settings using the ethtool netlink interface.

use super::{
    ETHTOOL_FLAG_OMIT_REPLY, ETHTOOL_GENL_NAME, ETHTOOL_GENL_VERSION, ETHTOOL_MCGRP_MONITOR, EthtoolBitsetAttr,
    EthtoolChannelsAttr, EthtoolCmd, EthtoolCoalesceAttr, EthtoolEeeAttr, EthtoolFeaturesAttr,
    EthtoolFecAttr, EthtoolHeaderAttr, EthtoolLinkinfoAttr, EthtoolLinkmodesAttr,
    EthtoolLinkstateAttr, EthtoolModuleEepromAttr, EthtoolPauseAttr, EthtoolRingsAttr,
    EthtoolRssAttr, EthtoolStatsAttr, EthtoolStatsGrpAttr, EthtoolStringAttr,
    EthtoolPhyAttr, EthtoolStringSet, EthtoolStringsetAttr, EthtoolStrsetAttr, EthtoolTsinfoAttr,
    EthtoolWolAttr,
    WOL_MODE_NAMES,
    bitset::EthtoolBitset,
    stats_group, types::*,
};
use crate::{
    macros::{__rt::resolve_genl_family_with_groups, GenlFamily},
    netlink::{
        attr::{AttrIter, NLA_F_NESTED},
        builder::MessageBuilder,
        connection::Connection,
        dump_frame::{Classification, classify},
        error::{Error, Result},
        genl::{GENL_HDRLEN, GenlMsgHdr},
        interface_ref::InterfaceRef,
        message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMsgError},
        protocol::{AsyncProtocolInit, Ethtool},
        socket::NetlinkSocket,
    },
};

impl AsyncProtocolInit for Ethtool {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        let (family_id, mcast_groups) =
            resolve_genl_family_with_groups(socket, ETHTOOL_GENL_NAME).await?;
        Ok(Self {
            family_id,
            mcast_groups,
        })
    }
}

impl GenlFamily for Ethtool {
    const VERSION: u8 = ETHTOOL_GENL_VERSION;
    const NAME: &'static str = ETHTOOL_GENL_NAME;

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn mcast_group(&self, name: &str) -> Option<u32> {
        self.mcast_groups.get(name).copied()
    }
}

#[nlink_macros::send_futures]
impl Connection<Ethtool> {
    /// Get the ethtool family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Get the monitor multicast group ID (if available).
    pub fn monitor_group_id(&self) -> Option<u32> {
        self.state()
            .mcast_groups
            .get(ETHTOOL_MCGRP_MONITOR)
            .copied()
    }

    /// Resolve an interface reference to a name.
    ///
    /// Ethtool uses interface names in its protocol, so we resolve
    /// indices back to names when needed.
    async fn resolve_interface_name(&self, iface: &InterfaceRef) -> Result<String> {
        match iface {
            InterfaceRef::Name(name) => Ok(name.clone()),
            InterfaceRef::Index(idx) => {
                // In this connection's namespace, not the process's (#497).
                let route_conn = self.route_sibling()?;
                route_conn
                    .get_link_by_index(*idx)
                    .await?
                    .and_then(|l| l.name().map(|s| s.to_string()))
                    .ok_or_else(|| self.interface_not_found(format!("ifindex {idx}")))
            }
        }
    }

    // =========================================================================
    // Link State
    // =========================================================================

    /// Get link state (carrier detection, signal quality).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let state = conn.get_link_state("eth0").await?;
    ///
    /// // By index
    /// let state = conn.get_link_state(5u32).await?;
    ///
    /// println!("Link detected: {:?}", state.link);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_state"))]
    pub async fn get_link_state(&self, iface: impl Into<InterfaceRef>) -> Result<LinkState> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_state_by_name(&ifname).await
    }

    /// Get link state by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_state_by_name"))]
    pub async fn get_link_state_by_name(&self, ifname: &str) -> Result<LinkState> {
        let response = self.ethtool_get(EthtoolCmd::LinkstateGet, ifname).await?;

        let mut state = LinkState::default();

        if response.len() < GENL_HDRLEN {
            return Ok(state);
        }

        self.parse_link_state(&response[GENL_HDRLEN..], &mut state)?;
        Ok(state)
    }

    fn parse_link_state(&self, data: &[u8], state: &mut LinkState) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkstateAttr::Header as u16 => {
                    self.parse_header(payload, &mut state.ifname, &mut state.ifindex)?;
                }
                t if t == EthtoolLinkstateAttr::Link as u16 && !payload.is_empty() => {
                    state.link = Some(payload[0] != 0);
                }
                t if t == EthtoolLinkstateAttr::Sqi as u16 && payload.len() >= 4 => {
                    state.sqi = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolLinkstateAttr::SqiMax as u16 && payload.len() >= 4 => {
                    state.sqi_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolLinkstateAttr::ExtState as u16 && !payload.is_empty() => {
                    state.ext_state = Some(LinkExtState::from_u8(payload[0]));
                }
                t if t == EthtoolLinkstateAttr::ExtSubstate as u16 && !payload.is_empty() => {
                    state.ext_substate = Some(payload[0]);
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Link Info
    // =========================================================================

    /// Get link info (port type, transceiver, MDI-X).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let info = conn.get_link_info("eth0").await?;
    ///
    /// // By index
    /// let info = conn.get_link_info(5u32).await?;
    ///
    /// println!("Port: {:?}", info.port);
    /// println!("Transceiver: {:?}", info.transceiver);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_info"))]
    pub async fn get_link_info(&self, iface: impl Into<InterfaceRef>) -> Result<LinkInfo> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_info_by_name(&ifname).await
    }

    /// Get link info by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_info_by_name"))]
    pub async fn get_link_info_by_name(&self, ifname: &str) -> Result<LinkInfo> {
        let response = self.ethtool_get(EthtoolCmd::LinkinfoGet, ifname).await?;

        let mut info = LinkInfo::default();

        if response.len() < GENL_HDRLEN {
            return Ok(info);
        }

        self.parse_link_info(&response[GENL_HDRLEN..], &mut info)?;
        Ok(info)
    }

    fn parse_link_info(&self, data: &[u8], info: &mut LinkInfo) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkinfoAttr::Header as u16 => {
                    self.parse_header(payload, &mut info.ifname, &mut info.ifindex)?;
                }
                t if t == EthtoolLinkinfoAttr::Port as u16 && !payload.is_empty() => {
                    info.port = Some(Port::from_u8(payload[0]));
                }
                t if t == EthtoolLinkinfoAttr::Phyaddr as u16 && !payload.is_empty() => {
                    info.phyaddr = Some(payload[0]);
                }
                t if t == EthtoolLinkinfoAttr::TpMdiCtrl as u16 && !payload.is_empty() => {
                    info.tp_mdix_ctrl = Some(MdiX::from_u8(payload[0]));
                }
                t if t == EthtoolLinkinfoAttr::TpMdix as u16 && !payload.is_empty() => {
                    info.tp_mdix = Some(MdiX::from_u8(payload[0]));
                }
                t if t == EthtoolLinkinfoAttr::Transceiver as u16 && !payload.is_empty() => {
                    info.transceiver = Some(Transceiver::from_u8(payload[0]));
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Link Modes
    // =========================================================================

    /// Get link modes (speed, duplex, autonegotiation).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let modes = conn.get_link_modes("eth0").await?;
    ///
    /// // By index
    /// let modes = conn.get_link_modes(5u32).await?;
    ///
    /// println!("Speed: {:?} Mb/s", modes.speed);
    /// println!("Duplex: {:?}", modes.duplex);
    /// println!("Autoneg: {}", modes.autoneg);
    /// println!("Supported modes: {:?}", modes.supported_modes());
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_modes"))]
    pub async fn get_link_modes(&self, iface: impl Into<InterfaceRef>) -> Result<LinkModes> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_link_modes_by_name(&ifname).await
    }

    /// Get link modes by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_link_modes_by_name"))]
    pub async fn get_link_modes_by_name(&self, ifname: &str) -> Result<LinkModes> {
        let response = self.ethtool_get(EthtoolCmd::LinkmodesGet, ifname).await?;

        let mut modes = LinkModes::default();

        if response.len() < GENL_HDRLEN {
            return Ok(modes);
        }

        self.parse_link_modes(&response[GENL_HDRLEN..], &mut modes)?;
        Ok(modes)
    }

    /// Set link modes (speed, duplex, autonegotiation).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    /// use nlink::netlink::genl::ethtool::Duplex;
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // Force 1000Mbps full duplex (by name)
    /// conn.set_link_modes("eth0", |m| {
    ///     m.autoneg(false)
    ///      .speed(1000)
    ///      .duplex(Duplex::Full)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_link_modes(5u32, |m| {
    ///     m.autoneg(true)
    ///      .advertise("1000baseT/Full")
    ///      .advertise("100baseT/Full")
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_modes"))]
    pub async fn set_link_modes(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(LinkModesBuilder) -> LinkModesBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_link_modes_by_name(&ifname, configure).await
    }

    /// Set link modes by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_link_modes_by_name"))]
    pub async fn set_link_modes_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(LinkModesBuilder) -> LinkModesBuilder,
    ) -> Result<()> {
        let builder = configure(LinkModesBuilder::new());
        self.apply_link_modes(ifname, &builder).await
    }

    fn parse_link_modes(&self, data: &[u8], modes: &mut LinkModes) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolLinkmodesAttr::Header as u16 => {
                    self.parse_header(payload, &mut modes.ifname, &mut modes.ifindex)?;
                }
                t if t == EthtoolLinkmodesAttr::Autoneg as u16 && !payload.is_empty() => {
                    modes.autoneg = payload[0] != 0;
                }
                t if t == EthtoolLinkmodesAttr::Speed as u16 && payload.len() >= 4 => {
                    let speed = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                    // 0xFFFFFFFF means unknown
                    if speed != 0xFFFFFFFF {
                        modes.speed = Some(speed);
                    }
                }
                t if t == EthtoolLinkmodesAttr::Duplex as u16 && !payload.is_empty() => {
                    modes.duplex = Some(Duplex::from_u8(payload[0]));
                }
                t if t == EthtoolLinkmodesAttr::Lanes as u16 && payload.len() >= 4 => {
                    modes.lanes = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolLinkmodesAttr::MasterSlaveCfg as u16 && !payload.is_empty() => {
                    modes.master_slave_cfg = Some(payload[0]);
                }
                t if t == EthtoolLinkmodesAttr::MasterSlaveState as u16 && !payload.is_empty() => {
                    modes.master_slave_state = Some(payload[0]);
                }
                // ONE kernel attribute, two answers: OURS packs the supported
                // modes into the bitset's mask and the advertised ones into its
                // value. nlink used to model these as two separate attribute
                // ids (Supported = 3, Advertised = 4), which shifted every
                // later id up by one and silently corrupted speed and duplex
                // (#196).
                t if t == EthtoolLinkmodesAttr::Ours as u16 => {
                    let ours = EthtoolBitset::parse(payload)?;
                    modes.supported = ours.all_bits_set();
                    modes.advertised = ours;
                }
                t if t == EthtoolLinkmodesAttr::Peer as u16 => {
                    modes.peer = EthtoolBitset::parse(payload)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_link_modes(&self, ifname: &str, config: &LinkModesBuilder) -> Result<()> {
        // Only the named modes are advertised; a mode present in the
        // bitset with the VALUE flag is "advertise this", which is what
        // `ethtool -s dev advertise` means.
        let mut ours = EthtoolBitset::new();
        for name in &config.advertised {
            ours.set(name, true);
        }

        self.ethtool_set(EthtoolCmd::LinkmodesSet, ifname, move |builder| {
            if let Some(autoneg) = config.autoneg {
                builder.append_attr_u8(EthtoolLinkmodesAttr::Autoneg as u16, autoneg as u8);
            }
            if let Some(speed) = config.speed {
                builder.append_attr_u32(EthtoolLinkmodesAttr::Speed as u16, speed);
            }
            if let Some(duplex) = config.duplex {
                builder.append_attr_u8(EthtoolLinkmodesAttr::Duplex as u16, duplex.to_u8());
            }
            if let Some(lanes) = config.lanes {
                builder.append_attr_u32(EthtoolLinkmodesAttr::Lanes as u16, lanes);
            }
            // Advertised modes go in `ETHTOOL_A_LINKMODES_OURS` as a
            // bit-by-bit bitset — the same encoder `set_features` uses.
            //
            // `advertise()` / `advertise_modes()` had shipped and were
            // stored in `LinkModesBuilder::advertised` with no read site
            // anywhere; the comment here said to wire them up "when a
            // downstream user asks for it", by which time the setter was
            // already public and the rustdoc example already called it.
            // Pinning advertised modes is the whole point of
            // `ethtool -s dev advertise ...`, and a caller combining it
            // with `.autoneg(true)` renegotiated on the *old*
            // advertisement and concluded the NIC had ignored them
            // (#275).
            if !ours.is_empty() {
                ours.write_to(builder, EthtoolLinkmodesAttr::Ours as u16);
            }
        })
        .await
    }

    // =========================================================================
    // Features
    // =========================================================================

    /// Get device features (offloads).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let features = conn.get_features("eth0").await?;
    ///
    /// // By index
    /// let features = conn.get_features(5u32).await?;
    ///
    /// println!("TSO: {}", features.is_active("tx-tcp-segmentation"));
    /// println!("GRO: {}", features.is_active("rx-gro"));
    ///
    /// for (name, enabled) in features.iter() {
    ///     println!("{}: {}", name, if enabled { "on" } else { "off" });
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_features"))]
    pub async fn get_features(&self, iface: impl Into<InterfaceRef>) -> Result<Features> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_features_by_name(&ifname).await
    }

    /// Get device features by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_features_by_name"))]
    pub async fn get_features_by_name(&self, ifname: &str) -> Result<Features> {
        let response = self.ethtool_get(EthtoolCmd::FeaturesGet, ifname).await?;

        let mut features = Features::default();

        if response.len() < GENL_HDRLEN {
            return Ok(features);
        }

        self.parse_features(&response[GENL_HDRLEN..], &mut features)?;
        Ok(features)
    }

    /// Get a device string set (`ETHTOOL_MSG_STRSET_GET`).
    ///
    /// String sets are how the kernel names things it otherwise reports
    /// by index: statistic names, private-flag names, feature names,
    /// link-mode names. `EthtoolStringSet` selects which.
    ///
    /// This did not exist. `EthtoolCmd::StrsetGet`, `EthtoolStringSet`,
    /// the three attribute enums and the `StringSet` result struct were
    /// all defined — and none of the 44 public methods on
    /// `Connection<Ethtool>` issued the command or returned the type, so
    /// `EthtoolStringSet` had zero non-test references. The enum's own
    /// rustdoc describes query behaviour in the present tense while
    /// explaining the #227 id fix, so a reader concluded the API existed
    /// and could not find it (#276).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::netlink::{Connection, Ethtool, genl::ethtool::EthtoolStringSet};
    /// # async fn f() -> nlink::Result<()> {
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// let names = conn.get_string_set("eth0", EthtoolStringSet::Stats).await?;
    /// for (i, name) in names.to_vec().iter().enumerate() {
    ///     println!("{i}: {name}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_string_set"))]
    pub async fn get_string_set(
        &self,
        iface: impl Into<InterfaceRef>,
        set: EthtoolStringSet,
    ) -> Result<StringSet> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_string_set_by_name(&ifname, set).await
    }

    /// Get a device string set by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_string_set_by_name"))]
    pub async fn get_string_set_by_name(
        &self,
        ifname: &str,
        set: EthtoolStringSet,
    ) -> Result<StringSet> {
        let response = self
            .ethtool_get_with(EthtoolCmd::StrsetGet, ifname, |builder| {
                // ETHTOOL_A_STRSET_STRINGSETS -> one ETHTOOL_A_STRINGSETS_STRINGSET
                // -> ETHTOOL_A_STRINGSET_ID. Asking for one set by id;
                // omitting the nest asks for all of them.
                let sets = builder.nest_start(EthtoolStrsetAttr::Stringsets as u16 | NLA_F_NESTED);
                let one = builder.nest_start(1 | NLA_F_NESTED);
                builder.append_attr_u32(EthtoolStringsetAttr::Id as u16, set as u32);
                builder.nest_end(one);
                builder.nest_end(sets);
            })
            .await?;

        let mut out = StringSet {
            id: set as u32,
            ..StringSet::default()
        };
        if response.len() < GENL_HDRLEN {
            return Ok(out);
        }
        self.parse_string_set(&response[GENL_HDRLEN..], &mut out);
        Ok(out)
    }

    /// Walk `ETHTOOL_A_STRSET_STRINGSETS` and collect the strings of the
    /// set whose id matches the one requested.
    fn parse_string_set(&self, data: &[u8], out: &mut StringSet) {
        for (attr_type, payload) in AttrIter::new(data) {
            if attr_type != EthtoolStrsetAttr::Stringsets as u16 {
                continue;
            }
            for (_idx, set_data) in AttrIter::new(payload) {
                let mut id = None;
                let mut strings_blob = None;
                for (t, p) in AttrIter::new(set_data) {
                    if t == EthtoolStringsetAttr::Id as u16 && p.len() >= 4 {
                        id = Some(u32::from_ne_bytes(p[..4].try_into().expect("len >= 4")));
                    } else if t == EthtoolStringsetAttr::Strings as u16 {
                        strings_blob = Some(p);
                    }
                }
                if id != Some(out.id) {
                    continue;
                }
                let Some(blob) = strings_blob else { continue };
                for (_i, string_data) in AttrIter::new(blob) {
                    let mut index = None;
                    let mut value = None;
                    for (t, p) in AttrIter::new(string_data) {
                        if t == EthtoolStringAttr::Index as u16 && p.len() >= 4 {
                            index = Some(u32::from_ne_bytes(p[..4].try_into().expect("len >= 4")));
                        } else if t == EthtoolStringAttr::Value as u16 {
                            let end = p.iter().position(|&b| b == 0).unwrap_or(p.len());
                            value = Some(String::from_utf8_lossy(&p[..end]).into_owned());
                        }
                    }
                    if let (Some(i), Some(v)) = (index, value) {
                        out.strings.insert(i, v);
                    }
                }
            }
        }
    }

    /// Set device features (offloads).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_features("eth0", |f| {
    ///     f.enable("tx-checksumming")
    ///      .disable("rx-gro")
    /// }).await?;
    ///
    /// // By index
    /// conn.set_features(5u32, |f| {
    ///     f.enable("tx-checksumming")
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_features"))]
    pub async fn set_features(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(FeaturesBuilder) -> FeaturesBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_features_by_name(&ifname, configure).await
    }

    /// Set device features by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_features_by_name"))]
    pub async fn set_features_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(FeaturesBuilder) -> FeaturesBuilder,
    ) -> Result<()> {
        let builder = configure(FeaturesBuilder::new());
        self.apply_features(ifname, &builder).await
    }

    fn parse_features(&self, data: &[u8], features: &mut Features) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolFeaturesAttr::Header as u16 => {
                    self.parse_header(payload, &mut features.ifname, &mut features.ifindex)?;
                }
                t if t == EthtoolFeaturesAttr::Hw as u16 => {
                    features.hw = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::Wanted as u16 => {
                    features.wanted = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::Active as u16 => {
                    features.active = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolFeaturesAttr::NoChange as u16 => {
                    features.nochange = EthtoolBitset::parse(payload)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_features(&self, ifname: &str, config: &FeaturesBuilder) -> Result<()> {
        // Build a bitset reflecting the requested changes. Bits
        // present in the encoded message = "I'm changing this";
        // VALUE flag presence = enable; absence = disable.
        let mut wanted = EthtoolBitset::new();
        for name in &config.enable {
            wanted.set(name, true);
        }
        for name in &config.disable {
            wanted.set(name, false);
        }

        self.ethtool_set(EthtoolCmd::FeaturesSet, ifname, move |builder| {
            // Serialise as ETHTOOL_A_FEATURES_WANTED (= 3, see
            // EthtoolFeaturesAttr). The encoder uses the bit-by-bit
            // format and is exercised by the roundtrip unit test
            // in `bitset.rs::tests::write_to_roundtrips_through_parse`.
            wanted.write_to(builder, EthtoolFeaturesAttr::Wanted as u16);
        })
        .await
    }

    // =========================================================================
    // Rings
    // =========================================================================

    /// Get ring buffer sizes.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let rings = conn.get_rings("eth0").await?;
    ///
    /// // By index
    /// let rings = conn.get_rings(5u32).await?;
    ///
    /// println!("RX: {:?} (max {:?})", rings.rx, rings.rx_max);
    /// println!("TX: {:?} (max {:?})", rings.tx, rings.tx_max);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rings"))]
    pub async fn get_rings(&self, iface: impl Into<InterfaceRef>) -> Result<Rings> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_rings_by_name(&ifname).await
    }

    /// Get ring buffer sizes by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rings_by_name"))]
    pub async fn get_rings_by_name(&self, ifname: &str) -> Result<Rings> {
        let response = self.ethtool_get(EthtoolCmd::RingsGet, ifname).await?;

        let mut rings = Rings::default();

        if response.len() < GENL_HDRLEN {
            return Ok(rings);
        }

        self.parse_rings(&response[GENL_HDRLEN..], &mut rings)?;
        Ok(rings)
    }

    /// Set ring buffer sizes.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_rings("eth0", |r| {
    ///     r.rx(4096).tx(4096)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_rings(5u32, |r| {
    ///     r.rx(4096).tx(4096)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_rings"))]
    pub async fn set_rings(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(RingsBuilder) -> RingsBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_rings_by_name(&ifname, configure).await
    }

    /// Set ring buffer sizes by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_rings_by_name"))]
    pub async fn set_rings_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(RingsBuilder) -> RingsBuilder,
    ) -> Result<()> {
        let builder = configure(RingsBuilder::new());
        self.apply_rings(ifname, &builder).await
    }

    /// A device's timestamping capabilities (`ethtool -T`, #166): what
    /// `SO_TIMESTAMPING` can ask of it, its hardware modes and filters, and
    /// its PTP clock. Accepts an interface name or index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_tsinfo"))]
    pub async fn get_tsinfo(&self, iface: impl Into<InterfaceRef>) -> Result<Tsinfo> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        let response = self.ethtool_get(EthtoolCmd::TsinfoGet, &ifname).await?;
        let mut info = Tsinfo::default();
        let Some(data) = response.get(GENL_HDRLEN..) else {
            return Ok(info);
        };
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolTsinfoAttr::Header as u16 => {
                    self.parse_header(payload, &mut info.ifname, &mut info.ifindex)?;
                }
                t if t == EthtoolTsinfoAttr::Timestamping as u16 => {
                    info.timestamping = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolTsinfoAttr::TxTypes as u16 => {
                    info.tx_types = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolTsinfoAttr::RxFilters as u16 => {
                    info.rx_filters = EthtoolBitset::parse(payload)?;
                }
                t if t == EthtoolTsinfoAttr::PhcIndex as u16 && payload.len() >= 4 => {
                    info.phc_index = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(info)
    }

    /// The PHYs on a link (`ethtool --show-phys`, kernel 6.12, #166): the
    /// one on the board, a media converter in front of it, one on an SFP
    /// module. A virtual device has none. Accepts an interface name or
    /// index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_phys"))]
    pub async fn get_phys(&self, iface: impl Into<InterfaceRef>) -> Result<Vec<PhyInfo>> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        let replies = self.ethtool_dump(EthtoolCmd::PhyGet, Some(&ifname)).await?;
        Ok(replies.iter().filter_map(|r| r.get(GENL_HDRLEN..)).map(phy_from_reply).collect())
    }

    /// Every PHY on every link in the connection's namespace (#166).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "dump_phys"))]
    pub async fn dump_phys(&self) -> Result<Vec<PhyInfo>> {
        let replies = self.ethtool_dump(EthtoolCmd::PhyGet, None).await?;
        Ok(replies.iter().filter_map(|r| r.get(GENL_HDRLEN..)).map(phy_from_reply).collect())
    }

    /// An ethtool dump, of one device's objects when `ifname` is given: the
    /// commands with a dump handler of their own (PHY_GET) honour the
    /// device a dump names, unlike the default handler, which answers for
    /// every device (#754, #773). Each reply's payload, GENL header first.
    async fn ethtool_dump(&self, cmd: EthtoolCmd, ifname: Option<&str>) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&GenlMsgHdr::new(cmd as u8, ETHTOOL_GENL_VERSION));
        if let Some(ifname) = ifname {
            let header = builder.nest_start(1 | NLA_F_NESTED); // ETHTOOL_A_*_HEADER = 1
            builder.append_attr_str(EthtoolHeaderAttr::DevName as u16, ifname);
            builder.nest_end(header);
        }
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        // #134 — dual-mode recv (dump). Register/lock before send.
        let mut session = self.recv_session_dump(seq).await?;
        let msg = builder.finish();
        self.socket().send(&msg).await?;

        self.with_timeout(async {
            let mut replies = Vec::new();
            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;
                    match classify(header, payload, seq) {
                        Classification::SkipSeq | Classification::Ack => continue,
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            return Ok(replies);
                        }
                        Classification::Data { payload } => replies.push(payload.to_vec()),
                    }
                }
            }
        })
        .await
    }

    fn parse_rings(&self, data: &[u8], rings: &mut Rings) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolRingsAttr::Header as u16 => {
                    self.parse_header(payload, &mut rings.ifname, &mut rings.ifindex)?;
                }
                t if t == EthtoolRingsAttr::RxMax as u16 && payload.len() >= 4 => {
                    rings.rx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::RxMiniMax as u16 && payload.len() >= 4 => {
                    rings.rx_mini_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::RxJumboMax as u16 && payload.len() >= 4 => {
                    rings.rx_jumbo_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::TxMax as u16 && payload.len() >= 4 => {
                    rings.tx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::Rx as u16 && payload.len() >= 4 => {
                    rings.rx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::RxMini as u16 && payload.len() >= 4 => {
                    rings.rx_mini = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::RxJumbo as u16 && payload.len() >= 4 => {
                    rings.rx_jumbo = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::Tx as u16 && payload.len() >= 4 => {
                    rings.tx = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::RxBufLen as u16 && payload.len() >= 4 => {
                    rings.rx_buf_len = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::CqeSize as u16 && payload.len() >= 4 => {
                    rings.cqe_size = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRingsAttr::TxPush as u16 && !payload.is_empty() => {
                    rings.tx_push = Some(payload[0] != 0);
                }
                t if t == EthtoolRingsAttr::RxPush as u16 && !payload.is_empty() => {
                    rings.rx_push = Some(payload[0] != 0);
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_rings(&self, ifname: &str, config: &RingsBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::RingsSet, ifname, |builder| {
            if let Some(rx) = config.rx {
                builder.append_attr_u32(EthtoolRingsAttr::Rx as u16, rx);
            }
            if let Some(rx_mini) = config.rx_mini {
                builder.append_attr_u32(EthtoolRingsAttr::RxMini as u16, rx_mini);
            }
            if let Some(rx_jumbo) = config.rx_jumbo {
                builder.append_attr_u32(EthtoolRingsAttr::RxJumbo as u16, rx_jumbo);
            }
            if let Some(tx) = config.tx {
                builder.append_attr_u32(EthtoolRingsAttr::Tx as u16, tx);
            }
        })
        .await
    }

    // =========================================================================
    // Channels
    // =========================================================================

    /// Get channel counts (RX/TX queues).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let channels = conn.get_channels("eth0").await?;
    ///
    /// // By index
    /// let channels = conn.get_channels(5u32).await?;
    ///
    /// println!("RX: {:?} (max {:?})", channels.rx_count, channels.rx_max);
    /// println!("TX: {:?} (max {:?})", channels.tx_count, channels.tx_max);
    /// println!("Combined: {:?} (max {:?})", channels.combined_count, channels.combined_max);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_channels"))]
    pub async fn get_channels(&self, iface: impl Into<InterfaceRef>) -> Result<Channels> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_channels_by_name(&ifname).await
    }

    /// Get channel counts by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_channels_by_name"))]
    pub async fn get_channels_by_name(&self, ifname: &str) -> Result<Channels> {
        let response = self.ethtool_get(EthtoolCmd::ChannelsGet, ifname).await?;

        let mut channels = Channels::default();

        if response.len() < GENL_HDRLEN {
            return Ok(channels);
        }

        self.parse_channels(&response[GENL_HDRLEN..], &mut channels)?;
        Ok(channels)
    }

    /// Set channel counts.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_channels("eth0", |c| {
    ///     c.combined(4)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_channels(5u32, |c| {
    ///     c.combined(4)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_channels"))]
    pub async fn set_channels(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(ChannelsBuilder) -> ChannelsBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_channels_by_name(&ifname, configure).await
    }

    /// Set channel counts by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_channels_by_name"))]
    pub async fn set_channels_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(ChannelsBuilder) -> ChannelsBuilder,
    ) -> Result<()> {
        let builder = configure(ChannelsBuilder::new());
        self.apply_channels(ifname, &builder).await
    }

    fn parse_channels(&self, data: &[u8], channels: &mut Channels) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolChannelsAttr::Header as u16 => {
                    self.parse_header(payload, &mut channels.ifname, &mut channels.ifindex)?;
                }
                t if t == EthtoolChannelsAttr::RxMax as u16 && payload.len() >= 4 => {
                    channels.rx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::TxMax as u16 && payload.len() >= 4 => {
                    channels.tx_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::OtherMax as u16 && payload.len() >= 4 => {
                    channels.other_max = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::CombinedMax as u16 && payload.len() >= 4 => {
                    channels.combined_max =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::RxCount as u16 && payload.len() >= 4 => {
                    channels.rx_count = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::TxCount as u16 && payload.len() >= 4 => {
                    channels.tx_count = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::OtherCount as u16 && payload.len() >= 4 => {
                    channels.other_count =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolChannelsAttr::CombinedCount as u16 && payload.len() >= 4 => {
                    channels.combined_count =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_channels(&self, ifname: &str, config: &ChannelsBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::ChannelsSet, ifname, |builder| {
            if let Some(rx) = config.rx {
                builder.append_attr_u32(EthtoolChannelsAttr::RxCount as u16, rx);
            }
            if let Some(tx) = config.tx {
                builder.append_attr_u32(EthtoolChannelsAttr::TxCount as u16, tx);
            }
            if let Some(other) = config.other {
                builder.append_attr_u32(EthtoolChannelsAttr::OtherCount as u16, other);
            }
            if let Some(combined) = config.combined {
                builder.append_attr_u32(EthtoolChannelsAttr::CombinedCount as u16, combined);
            }
        })
        .await
    }

    // =========================================================================
    // Coalesce
    // =========================================================================

    /// Get interrupt coalescing parameters.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let coalesce = conn.get_coalesce("eth0").await?;
    ///
    /// // By index
    /// let coalesce = conn.get_coalesce(5u32).await?;
    ///
    /// println!("RX usecs: {:?}", coalesce.rx_usecs);
    /// println!("TX usecs: {:?}", coalesce.tx_usecs);
    /// println!("Adaptive RX: {:?}", coalesce.use_adaptive_rx);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_coalesce"))]
    pub async fn get_coalesce(&self, iface: impl Into<InterfaceRef>) -> Result<Coalesce> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_coalesce_by_name(&ifname).await
    }

    /// Get interrupt coalescing parameters by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_coalesce_by_name"))]
    pub async fn get_coalesce_by_name(&self, ifname: &str) -> Result<Coalesce> {
        let response = self.ethtool_get(EthtoolCmd::CoalesceGet, ifname).await?;

        let mut coalesce = Coalesce::default();

        if response.len() < GENL_HDRLEN {
            return Ok(coalesce);
        }

        self.parse_coalesce(&response[GENL_HDRLEN..], &mut coalesce)?;
        Ok(coalesce)
    }

    /// Set interrupt coalescing parameters.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_coalesce("eth0", |c| {
    ///     c.rx_usecs(100)
    ///      .tx_usecs(100)
    ///      .use_adaptive_rx(true)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_coalesce(5u32, |c| {
    ///     c.rx_usecs(100)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_coalesce"))]
    pub async fn set_coalesce(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(CoalesceBuilder) -> CoalesceBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_coalesce_by_name(&ifname, configure).await
    }

    /// Set interrupt coalescing parameters by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_coalesce_by_name"))]
    pub async fn set_coalesce_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(CoalesceBuilder) -> CoalesceBuilder,
    ) -> Result<()> {
        let builder = configure(CoalesceBuilder::new());
        self.apply_coalesce(ifname, &builder).await
    }

    fn parse_coalesce(&self, data: &[u8], coalesce: &mut Coalesce) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolCoalesceAttr::Header as u16 => {
                    self.parse_header(payload, &mut coalesce.ifname, &mut coalesce.ifindex)?;
                }
                t if t == EthtoolCoalesceAttr::RxUsecs as u16 && payload.len() >= 4 => {
                    coalesce.rx_usecs = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::RxMaxFrames as u16 && payload.len() >= 4 => {
                    coalesce.rx_max_frames =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::RxUsecsIrq as u16 && payload.len() >= 4 => {
                    coalesce.rx_usecs_irq =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::RxMaxFramesIrq as u16 && payload.len() >= 4 => {
                    coalesce.rx_max_frames_irq =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::TxUsecs as u16 && payload.len() >= 4 => {
                    coalesce.tx_usecs = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::TxMaxFrames as u16 && payload.len() >= 4 => {
                    coalesce.tx_max_frames =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::TxUsecsIrq as u16 && payload.len() >= 4 => {
                    coalesce.tx_usecs_irq =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::TxMaxFramesIrq as u16 && payload.len() >= 4 => {
                    coalesce.tx_max_frames_irq =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::StatsBlockUsecs as u16 && payload.len() >= 4 => {
                    coalesce.stats_block_usecs =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::UseAdaptiveRx as u16 && !payload.is_empty() => {
                    coalesce.use_adaptive_rx = Some(payload[0] != 0);
                }
                t if t == EthtoolCoalesceAttr::UseAdaptiveTx as u16 && !payload.is_empty() => {
                    coalesce.use_adaptive_tx = Some(payload[0] != 0);
                }
                t if t == EthtoolCoalesceAttr::PktRateLow as u16 && payload.len() >= 4 => {
                    coalesce.pkt_rate_low =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::PktRateHigh as u16 && payload.len() >= 4 => {
                    coalesce.pkt_rate_high =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolCoalesceAttr::RateSampleInterval as u16 && payload.len() >= 4 => {
                    coalesce.rate_sample_interval =
                        Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_coalesce(&self, ifname: &str, config: &CoalesceBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::CoalesceSet, ifname, |builder| {
            if let Some(v) = config.rx_usecs {
                builder.append_attr_u32(EthtoolCoalesceAttr::RxUsecs as u16, v);
            }
            if let Some(v) = config.rx_max_frames {
                builder.append_attr_u32(EthtoolCoalesceAttr::RxMaxFrames as u16, v);
            }
            if let Some(v) = config.tx_usecs {
                builder.append_attr_u32(EthtoolCoalesceAttr::TxUsecs as u16, v);
            }
            if let Some(v) = config.tx_max_frames {
                builder.append_attr_u32(EthtoolCoalesceAttr::TxMaxFrames as u16, v);
            }
            if let Some(v) = config.use_adaptive_rx {
                builder.append_attr_u8(EthtoolCoalesceAttr::UseAdaptiveRx as u16, v as u8);
            }
            if let Some(v) = config.use_adaptive_tx {
                builder.append_attr_u8(EthtoolCoalesceAttr::UseAdaptiveTx as u16, v as u8);
            }
        })
        .await
    }

    // =========================================================================
    // Pause
    // =========================================================================

    /// Get pause/flow control settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// let pause = conn.get_pause("eth0").await?;
    ///
    /// // By index
    /// let pause = conn.get_pause(5u32).await?;
    ///
    /// println!("Autoneg: {:?}", pause.autoneg);
    /// println!("RX pause: {:?}", pause.rx);
    /// println!("TX pause: {:?}", pause.tx);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_pause"))]
    pub async fn get_pause(&self, iface: impl Into<InterfaceRef>) -> Result<Pause> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_pause_by_name(&ifname).await
    }

    /// Get pause/flow control settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_pause_by_name"))]
    pub async fn get_pause_by_name(&self, ifname: &str) -> Result<Pause> {
        let response = self.ethtool_get(EthtoolCmd::PauseGet, ifname).await?;

        let mut pause = Pause::default();

        if response.len() < GENL_HDRLEN {
            return Ok(pause);
        }

        self.parse_pause(&response[GENL_HDRLEN..], &mut pause)?;
        Ok(pause)
    }

    /// Set pause/flow control settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    ///
    /// // By name
    /// conn.set_pause("eth0", |p| {
    ///     p.autoneg(true)
    ///      .rx(true)
    ///      .tx(true)
    /// }).await?;
    ///
    /// // By index
    /// conn.set_pause(5u32, |p| {
    ///     p.autoneg(true)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_pause"))]
    pub async fn set_pause(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(PauseBuilder) -> PauseBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_pause_by_name(&ifname, configure).await
    }

    /// Set pause/flow control settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_pause_by_name"))]
    pub async fn set_pause_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(PauseBuilder) -> PauseBuilder,
    ) -> Result<()> {
        let builder = configure(PauseBuilder::new());
        self.apply_pause(ifname, &builder).await
    }

    fn parse_pause(&self, data: &[u8], pause: &mut Pause) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolPauseAttr::Header as u16 => {
                    self.parse_header(payload, &mut pause.ifname, &mut pause.ifindex)?;
                }
                t if t == EthtoolPauseAttr::Autoneg as u16 && !payload.is_empty() => {
                    pause.autoneg = Some(payload[0] != 0);
                }
                t if t == EthtoolPauseAttr::Rx as u16 && !payload.is_empty() => {
                    pause.rx = Some(payload[0] != 0);
                }
                t if t == EthtoolPauseAttr::Tx as u16 && !payload.is_empty() => {
                    pause.tx = Some(payload[0] != 0);
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn apply_pause(&self, ifname: &str, config: &PauseBuilder) -> Result<()> {
        self.ethtool_set(EthtoolCmd::PauseSet, ifname, |builder| {
            if let Some(v) = config.autoneg {
                builder.append_attr_u8(EthtoolPauseAttr::Autoneg as u16, v as u8);
            }
            if let Some(v) = config.rx {
                builder.append_attr_u8(EthtoolPauseAttr::Rx as u16, v as u8);
            }
            if let Some(v) = config.tx {
                builder.append_attr_u8(EthtoolPauseAttr::Tx as u16, v as u8);
            }
        })
        .await
    }

    // =========================================================================
    // Wake-on-LAN (ethtool -w / -W)
    // =========================================================================

    /// Get Wake-on-LAN settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// let wol = conn.get_wol("eth0").await?;
    /// println!("supported: {:?}, active: {:?}", wol.supported, wol.active);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_wol"))]
    pub async fn get_wol(&self, iface: impl Into<InterfaceRef>) -> Result<Wol> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_wol_by_name(&ifname).await
    }

    /// Get Wake-on-LAN settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_wol_by_name"))]
    pub async fn get_wol_by_name(&self, ifname: &str) -> Result<Wol> {
        let response = self.ethtool_get(EthtoolCmd::WolGet, ifname).await?;

        let mut wol = Wol::default();
        if response.len() < GENL_HDRLEN {
            return Ok(wol);
        }
        self.parse_wol(&response[GENL_HDRLEN..], &mut wol)?;
        Ok(wol)
    }

    /// Set Wake-on-LAN settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// // Enable magic-packet wake-up.
    /// conn.set_wol("eth0", |w| w.mode("magic")).await?;
    /// // Disable all WoL.
    /// conn.set_wol("eth0", |w| w).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wol"))]
    pub async fn set_wol(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(WolBuilder) -> WolBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_wol_by_name(&ifname, configure).await
    }

    /// Set Wake-on-LAN settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_wol_by_name"))]
    pub async fn set_wol_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(WolBuilder) -> WolBuilder,
    ) -> Result<()> {
        let config = configure(WolBuilder::new());

        // Validate mode names up front so a typo is a clean error
        // instead of a silent no-op (strict-parse spirit).
        for m in &config.modes {
            if !WOL_MODE_NAMES.contains(&m.as_str()) {
                return Err(Error::invalid_message(format!(
                    "wol: unknown mode `{m}` (expected one of {})",
                    WOL_MODE_NAMES.join(", ")
                )));
            }
        }

        // Build the modes bitset across the full name space: each known
        // mode is present (so the kernel treats it as "being set") with
        // its value = whether it was requested. This mirrors how the
        // kernel expects a full WoL modes bitset.
        let mut modes = EthtoolBitset::new();
        for (idx, name) in WOL_MODE_NAMES.iter().enumerate() {
            modes.add(idx as u32, name, config.modes.iter().any(|m| m == name));
        }

        let sopass = config.sopass;
        self.ethtool_set(EthtoolCmd::WolSet, ifname, move |builder| {
            modes.write_to(builder, EthtoolWolAttr::Modes as u16);
            if let Some(pass) = sopass {
                builder.append_attr(EthtoolWolAttr::Sopass as u16, &pass);
            }
        })
        .await
    }

    fn parse_wol(&self, data: &[u8], wol: &mut Wol) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolWolAttr::Header as u16 => {
                    self.parse_header(payload, &mut wol.ifname, &mut wol.ifindex)?;
                }
                t if t == EthtoolWolAttr::Modes as u16 => {
                    let bitset = EthtoolBitset::parse(payload)?;
                    // `all_names` = supported (present in the mask),
                    // `active_names` = currently enabled (value set).
                    wol.supported = bitset.all_names().into_iter().map(String::from).collect();
                    wol.active = bitset
                        .active_names()
                        .into_iter()
                        .map(String::from)
                        .collect();
                }
                t if t == EthtoolWolAttr::Sopass as u16 && payload.len() >= 6 => {
                    let mut pass = [0u8; 6];
                    pass.copy_from_slice(&payload[..6]);
                    wol.sopass = Some(pass);
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Energy-Efficient Ethernet (ethtool --show-eee / --set-eee)
    // =========================================================================

    /// Get Energy-Efficient Ethernet settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_eee"))]
    pub async fn get_eee(&self, iface: impl Into<InterfaceRef>) -> Result<Eee> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_eee_by_name(&ifname).await
    }

    /// Get Energy-Efficient Ethernet settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_eee_by_name"))]
    pub async fn get_eee_by_name(&self, ifname: &str) -> Result<Eee> {
        let response = self.ethtool_get(EthtoolCmd::EeeGet, ifname).await?;

        let mut eee = Eee::default();
        if response.len() < GENL_HDRLEN {
            return Ok(eee);
        }
        self.parse_eee(&response[GENL_HDRLEN..], &mut eee)?;
        Ok(eee)
    }

    /// Set Energy-Efficient Ethernet settings.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// conn.set_eee("eth0", |e| e.enabled(true).tx_lpi_enabled(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_eee"))]
    pub async fn set_eee(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(EeeBuilder) -> EeeBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_eee_by_name(&ifname, configure).await
    }

    /// Set Energy-Efficient Ethernet settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_eee_by_name"))]
    pub async fn set_eee_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(EeeBuilder) -> EeeBuilder,
    ) -> Result<()> {
        let config = configure(EeeBuilder::new());
        self.ethtool_set(EthtoolCmd::EeeSet, ifname, move |builder| {
            if let Some(v) = config.enabled {
                builder.append_attr_u8(EthtoolEeeAttr::Enabled as u16, v as u8);
            }
            if let Some(v) = config.tx_lpi_enabled {
                builder.append_attr_u8(EthtoolEeeAttr::TxLpiEnabled as u16, v as u8);
            }
            if let Some(v) = config.tx_lpi_timer {
                builder.append_attr_u32(EthtoolEeeAttr::TxLpiTimer as u16, v);
            }
        })
        .await
    }

    fn parse_eee(&self, data: &[u8], eee: &mut Eee) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolEeeAttr::Header as u16 => {
                    self.parse_header(payload, &mut eee.ifname, &mut eee.ifindex)?;
                }
                t if t == EthtoolEeeAttr::ModesOurs as u16 => {
                    let bs = EthtoolBitset::parse(payload)?;
                    eee.advertised = bs.active_names().into_iter().map(String::from).collect();
                }
                t if t == EthtoolEeeAttr::ModesPeer as u16 => {
                    let bs = EthtoolBitset::parse(payload)?;
                    eee.peer = bs.active_names().into_iter().map(String::from).collect();
                }
                t if t == EthtoolEeeAttr::Active as u16 && !payload.is_empty() => {
                    eee.active = Some(payload[0] != 0);
                }
                t if t == EthtoolEeeAttr::Enabled as u16 && !payload.is_empty() => {
                    eee.enabled = Some(payload[0] != 0);
                }
                t if t == EthtoolEeeAttr::TxLpiEnabled as u16 && !payload.is_empty() => {
                    eee.tx_lpi_enabled = Some(payload[0] != 0);
                }
                t if t == EthtoolEeeAttr::TxLpiTimer as u16 && payload.len() >= 4 => {
                    eee.tx_lpi_timer = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Forward Error Correction (ethtool --show-fec)
    // =========================================================================

    /// Get Forward Error Correction settings (read-only).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    /// The configured-modes bitset uses kernel-specific mode bit names;
    /// feed the same names back to [`Connection::set_fec`] to change the
    /// configuration.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_fec"))]
    pub async fn get_fec(&self, iface: impl Into<InterfaceRef>) -> Result<Fec> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_fec_by_name(&ifname).await
    }

    /// Get Forward Error Correction settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_fec_by_name"))]
    pub async fn get_fec_by_name(&self, ifname: &str) -> Result<Fec> {
        let response = self.ethtool_get(EthtoolCmd::FecGet, ifname).await?;

        let mut fec = Fec::default();
        if response.len() < GENL_HDRLEN {
            return Ok(fec);
        }
        self.parse_fec(&response[GENL_HDRLEN..], &mut fec)?;
        Ok(fec)
    }

    fn parse_fec(&self, data: &[u8], fec: &mut Fec) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolFecAttr::Header as u16 => {
                    self.parse_header(payload, &mut fec.ifname, &mut fec.ifindex)?;
                }
                t if t == EthtoolFecAttr::Modes as u16 => {
                    let bs = EthtoolBitset::parse(payload)?;
                    fec.modes = bs.active_names().into_iter().map(String::from).collect();
                }
                t if t == EthtoolFecAttr::Auto as u16 && !payload.is_empty() => {
                    fec.auto = Some(payload[0] != 0);
                }
                t if t == EthtoolFecAttr::Active as u16 && payload.len() >= 4 => {
                    fec.active = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Set Forward Error Correction settings.
    ///
    /// FEC mode names are the kernel-labelled bitset names — pass the
    /// same strings [`Fec::modes`] reports for the device. See
    /// [`FecBuilder`] for the normalisation of common spellings.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Ethtool;
    /// # let conn = nlink::Connection::<nlink::netlink::Ethtool>::new_async().await?;
    /// // Enable RS FEC and turn auto-negotiation off.
    /// conn.set_fec("eth0", |f| f.mode("rs").auto(false)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_fec"))]
    pub async fn set_fec(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(FecBuilder) -> FecBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_fec_by_name(&ifname, configure).await
    }

    /// Set Forward Error Correction settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_fec_by_name"))]
    pub async fn set_fec_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(FecBuilder) -> FecBuilder,
    ) -> Result<()> {
        let config = configure(FecBuilder::new());
        self.ethtool_set(EthtoolCmd::FecSet, ifname, move |builder| {
            if !config.modes.is_empty() {
                // The requested encodings become the active set: present +
                // Value flag = enable; the kernel leaves unlisted bits
                // untouched, so list only what we want enabled.
                let mut bs = EthtoolBitset::new();
                for (idx, name) in config.modes.iter().enumerate() {
                    bs.add(idx as u32, name, true);
                }
                bs.write_to(builder, EthtoolFecAttr::Modes as u16);
            }
            if let Some(auto) = config.auto {
                builder.append_attr_u8(EthtoolFecAttr::Auto as u16, auto as u8);
            }
        })
        .await
    }

    // =========================================================================
    // Module EEPROM (ethtool -m)
    // =========================================================================

    /// Read raw bytes from an SFP/QSFP module's EEPROM (`ethtool -m`).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    /// A single read is bounded to one 128-byte page at one I2C address;
    /// see [`ModuleEepromRequest`] for page/bank/address selection.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_module_eeprom"))]
    pub async fn get_module_eeprom(
        &self,
        iface: impl Into<InterfaceRef>,
        request: ModuleEepromRequest,
    ) -> Result<ModuleEeprom> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_module_eeprom_by_name(&ifname, request).await
    }

    /// Read module EEPROM bytes by interface name.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "get_module_eeprom_by_name")
    )]
    pub async fn get_module_eeprom_by_name(
        &self,
        ifname: &str,
        request: ModuleEepromRequest,
    ) -> Result<ModuleEeprom> {
        if request.length == 0 || request.length > 128 {
            return Err(Error::invalid_message(format!(
                "get_module_eeprom: length {} out of range (1..=128)",
                request.length
            )));
        }
        let response = self
            .ethtool_get_with(EthtoolCmd::ModuleEepromGet, ifname, |builder| {
                builder.append_attr_u32(EthtoolModuleEepromAttr::Offset as u16, request.offset);
                builder.append_attr_u32(EthtoolModuleEepromAttr::Length as u16, request.length);
                builder.append_attr_u8(EthtoolModuleEepromAttr::Page as u16, request.page);
                builder.append_attr_u8(EthtoolModuleEepromAttr::Bank as u16, request.bank);
                builder.append_attr_u8(
                    EthtoolModuleEepromAttr::I2cAddress as u16,
                    request.i2c_address,
                );
            })
            .await?;

        let mut out = ModuleEeprom::default();
        if response.len() < GENL_HDRLEN {
            return Ok(out);
        }
        for (attr_type, payload) in AttrIter::new(&response[GENL_HDRLEN..]) {
            match attr_type {
                t if t == EthtoolModuleEepromAttr::Header as u16 => {
                    self.parse_header(payload, &mut out.ifname, &mut out.ifindex)?;
                }
                t if t == EthtoolModuleEepromAttr::Data as u16 => {
                    out.data = payload.to_vec();
                }
                _ => {}
            }
        }
        Ok(out)
    }

    // =========================================================================
    // Receive Side Scaling (ethtool -x)
    // =========================================================================

    /// Get Receive Side Scaling settings (`ethtool -x`).
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    /// `context` selects an RSS context (`None` = the default context).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rss"))]
    pub async fn get_rss(
        &self,
        iface: impl Into<InterfaceRef>,
        context: Option<u32>,
    ) -> Result<Rss> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_rss_by_name(&ifname, context).await
    }

    /// Get Receive Side Scaling settings by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_rss_by_name"))]
    pub async fn get_rss_by_name(&self, ifname: &str, context: Option<u32>) -> Result<Rss> {
        let response = self
            .ethtool_get_with(EthtoolCmd::RssGet, ifname, |builder| {
                if let Some(ctx) = context {
                    builder.append_attr_u32(EthtoolRssAttr::Context as u16, ctx);
                }
            })
            .await?;

        let mut rss = Rss::default();
        if response.len() < GENL_HDRLEN {
            return Ok(rss);
        }
        for (attr_type, payload) in AttrIter::new(&response[GENL_HDRLEN..]) {
            match attr_type {
                t if t == EthtoolRssAttr::Header as u16 => {
                    self.parse_header(payload, &mut rss.ifname, &mut rss.ifindex)?;
                }
                t if t == EthtoolRssAttr::Context as u16 && payload.len() >= 4 => {
                    rss.context = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRssAttr::Hfunc as u16 && payload.len() >= 4 => {
                    rss.hfunc = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRssAttr::Indir as u16 => {
                    // Binary array of u32 (native endian); accept a
                    // trailing partial word defensively (read whole words).
                    rss.indirection_table = payload
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| u32::from_ne_bytes(*c))
                        .collect();
                }
                t if t == EthtoolRssAttr::Hkey as u16 => {
                    rss.hash_key = payload.to_vec();
                }
                _ => {}
            }
        }
        Ok(rss)
    }

    // =========================================================================
    // Standardized statistics (ethtool -S --groups)
    // =========================================================================

    /// Get standardized device statistics (the IEEE-802.3 / RMON
    /// groups, like `ethtool -S --groups eth-mac eth-phy eth-ctrl
    /// rmon`).
    ///
    /// Accepts an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    /// use nlink::netlink::genl::ethtool::stats_index;
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
    /// let stats = conn.get_eth_stats("eth0").await?;
    /// if let Some(mac) = &stats.eth_mac {
    ///     println!("rx-packets: {:?}", mac.get(stats_index::ETH_MAC_RX_PKT));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_eth_stats"))]
    pub async fn get_eth_stats(&self, iface: impl Into<InterfaceRef>) -> Result<EthtoolStats> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_eth_stats_by_name(&ifname).await
    }

    /// Get standardized device statistics by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_eth_stats_by_name"))]
    pub async fn get_eth_stats_by_name(&self, ifname: &str) -> Result<EthtoolStats> {
        let response = self.ethtool_stats_get(ifname).await?;
        let mut stats = EthtoolStats::default();
        if response.len() < GENL_HDRLEN {
            return Ok(stats);
        }
        self.parse_eth_stats(&response[GENL_HDRLEN..], &mut stats)?;
        Ok(stats)
    }

    /// STATS_GET for one device: its header is attribute 2, not the usual
    /// 1, and a `Groups` bitset selects the standardized groups. A `doit`:
    /// sent as a dump, ethtool answered for every device and the first,
    /// `lo`, was kept, whatever the name (#773).
    async fn ethtool_stats_get(&self, ifname: &str) -> Result<Vec<u8>> {
        self.ethtool_doit(EthtoolCmd::StatsGet, EthtoolStatsAttr::Header as u16, ifname, |builder| {
            // Groups bitset (compact, no-mask): the 4 standardized groups
            // (bits 0..=3 set => 0x0F).
            let groups = builder.nest_start(EthtoolStatsAttr::Groups as u16 | NLA_F_NESTED);
            builder.append_attr(EthtoolBitsetAttr::Nomask as u16, &[]);
            builder.append_attr_u32(EthtoolBitsetAttr::Size as u16, 4);
            builder.append_attr(EthtoolBitsetAttr::Value as u16, &0x0fu32.to_ne_bytes());
            builder.nest_end(groups);
        })
        .await
    }

    fn parse_eth_stats(&self, data: &[u8], stats: &mut EthtoolStats) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolStatsAttr::Header as u16 => {
                    self.parse_header(payload, &mut stats.ifname, &mut stats.ifindex)?;
                }
                t if t == EthtoolStatsAttr::Grp as u16 => {
                    if let Some((group_id, group)) = parse_stats_group(payload) {
                        match group_id {
                            stats_group::ETH_PHY => stats.eth_phy = Some(group),
                            stats_group::ETH_MAC => stats.eth_mac = Some(group),
                            stats_group::ETH_CTRL => stats.eth_ctrl = Some(group),
                            stats_group::RMON => stats.rmon = Some(group),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Parse the common header (interface name and index).
    fn parse_header(
        &self,
        data: &[u8],
        ifname: &mut Option<String>,
        ifindex: &mut Option<u32>,
    ) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolHeaderAttr::DevIndex as u16 && payload.len() >= 4 => {
                    *ifindex = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolHeaderAttr::DevName as u16 => {
                    *ifname = Some(
                        std::str::from_utf8(payload)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Send an ethtool GET for one device and return its reply payload.
    ///
    /// A `doit`. It was a dump (`NLM_F_DUMP`), which ethtool answers for
    /// every device in the namespace — `ethnl_default_start` drops the
    /// device a dump names — and this kept the first message: every getter
    /// built on it (link state, info and modes, features, rings, channels,
    /// coalesce, …) read the namespace's first device, `lo`, whatever it
    /// was asked for.
    async fn ethtool_get(&self, cmd: EthtoolCmd, ifname: &str) -> Result<Vec<u8>> {
        self.ethtool_get_with(cmd, ifname, |_| {}).await
    }

    /// Send a parameterized ethtool GET (`doit`, not a dump): the caller
    /// appends request attributes after the device header, and the
    /// single reply payload is returned. Used by reads that carry input
    /// parameters (e.g. module-EEPROM offset/length/page).
    async fn ethtool_get_with(
        &self,
        cmd: EthtoolCmd,
        ifname: &str,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        // ETHTOOL_A_*_HEADER = 1, for every message but STATS.
        self.ethtool_doit(cmd, 1, ifname, build_attrs).await
    }

    /// An ethtool GET for one device, as a `doit`, with its header in
    /// attribute `header` (STATS keeps it in 2), and the single reply's
    /// payload.
    async fn ethtool_doit(
        &self,
        cmd: EthtoolCmd,
        header: u16,
        ifname: &str,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let family_id = self.state().family_id;

        // NLM_F_REQUEST only (no DUMP) — this is a do-it with parameters.
        let mut builder = MessageBuilder::new(family_id, NLM_F_REQUEST);
        let genl_hdr = GenlMsgHdr::new(cmd as u8, ETHTOOL_GENL_VERSION);
        builder.append(&genl_hdr);

        let header_token = builder.nest_start(header | NLA_F_NESTED);
        builder.append_attr_str(EthtoolHeaderAttr::DevName as u16, ifname);
        builder.nest_end(header_token);

        build_attrs(&mut builder);

        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        // #134 — dual-mode recv (single doit). Register/lock before send.
        let mut session = self.recv_session(seq).await?;
        let msg = builder.finish();
        self.socket().send(&msg).await?;

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
                            continue;
                        }
                        return Err(err.to_error(header.nlmsg_flags, payload));
                    }
                    if header.is_done() {
                        return Err(Error::invalid_message("no response received"));
                    }
                    // The doit reply is a single message — return its payload.
                    return Ok(payload.to_vec());
                }
            }
        })
        .await
    }

    /// Send an ethtool SET request.
    ///
    /// #135 — routes through the canonical [`Connection::send_ack`]
    /// (looped recv + seq filter + 30s timeout), closing the H9
    /// stale-frame bug class (the old single-`recv_msg` could return
    /// `Ok` without consuming its own ACK, desyncing the fd).
    async fn ethtool_set(
        &self,
        cmd: EthtoolCmd,
        ifname: &str,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_ACK);

        // Append GENL header
        builder.append(&GenlMsgHdr::new(cmd as u8, ETHTOOL_GENL_VERSION));

        // Append request header with device name. A set request may
        // answer with a reply message — FEATURES_SET does, with what it
        // changed — before its ACK, unless the header asks it not to; an
        // ACK-only exchange saw that reply as an error, so `set_features`
        // failed on every device.
        let header_token = builder.nest_start(1 | NLA_F_NESTED); // ETHTOOL_A_*_HEADER = 1
        builder.append_attr_str(EthtoolHeaderAttr::DevName as u16, ifname);
        builder.append_attr_u32(EthtoolHeaderAttr::Flags as u16, ETHTOOL_FLAG_OMIT_REPLY);
        builder.nest_end(header_token);

        // Let caller append additional attributes
        build_attrs(&mut builder);

        self.send_ack(builder).await
    }

    // =========================================================================
    // Event Monitoring
    // =========================================================================

    /// Subscribe to ethtool events.
    ///
    /// After subscribing, use `events()` or `into_events()` to receive
    /// notifications about ethtool configuration changes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Ethtool};
    /// use tokio_stream::StreamExt;
    ///
    /// let conn = Connection::<Ethtool>::new_async().await?;
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
        self.subscribe_group(ETHTOOL_MCGRP_MONITOR)
    }
}

/// Parse one `ETHTOOL_A_STATS_GRP` nest into `(group_id, StatGroup)`.
///
/// The nest carries `GRP_ID` (which group) and zero or more `GRP_STAT`
/// sub-nests; each `GRP_STAT` holds a single attribute whose type is
/// the per-group stat index and whose payload is a `u64`.
fn parse_stats_group(data: &[u8]) -> Option<(u32, StatGroup)> {
    let mut group_id = None;
    let mut group = StatGroup::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == EthtoolStatsGrpAttr::Id as u16 && payload.len() >= 4 => {
                group_id = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
            }
            t if t == EthtoolStatsGrpAttr::Stat as u16 => {
                if let Some((index, value)) = parse_one_stat(payload) {
                    group.values.insert(index, value);
                }
            }
            _ => {}
        }
    }

    Some((group_id?, group))
}

/// Parse a single `GRP_STAT` nest: one inner attr `index -> u64`.
/// Reads the first 8 bytes of the value (accept-larger policy).
fn parse_one_stat(data: &[u8]) -> Option<(u32, u64)> {
    for (index, payload) in AttrIter::new(data) {
        if payload.len() >= 8 {
            let value = u64::from_ne_bytes(payload[..8].try_into().unwrap());
            return Some((u32::from(index), value));
        }
    }
    None
}

/// A PHY_GET reply's attributes, after its GENL header, as a [`PhyInfo`].
fn phy_from_reply(data: &[u8]) -> PhyInfo {
    let text = |p: &[u8]| std::str::from_utf8(p).unwrap_or("").trim_end_matches('\0').to_string();
    let u32_of = |p: &[u8]| p.get(..4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    let mut phy = PhyInfo::default();
    let mut upstream_type = None;
    let mut upstream_index = None;
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & !NLA_F_NESTED {
            t if t == EthtoolPhyAttr::Header as u16 => {
                for (t, p) in AttrIter::new(payload) {
                    match t {
                        t if t == EthtoolHeaderAttr::DevIndex as u16 => phy.ifindex = u32_of(p),
                        t if t == EthtoolHeaderAttr::DevName as u16 => phy.ifname = Some(text(p)),
                        _ => {}
                    }
                }
            }
            t if t == EthtoolPhyAttr::Index as u16 => phy.index = u32_of(payload).unwrap_or(0),
            t if t == EthtoolPhyAttr::Drvname as u16 => phy.driver = Some(text(payload)),
            t if t == EthtoolPhyAttr::Name as u16 => phy.name = Some(text(payload)),
            t if t == EthtoolPhyAttr::UpstreamType as u16 => upstream_type = u32_of(payload),
            t if t == EthtoolPhyAttr::UpstreamIndex as u16 => upstream_index = u32_of(payload),
            t if t == EthtoolPhyAttr::UpstreamSfpName as u16 => phy.upstream_sfp = Some(text(payload)),
            t if t == EthtoolPhyAttr::DownstreamSfpName as u16 => {
                phy.downstream_sfp = Some(text(payload))
            }
            _ => {}
        }
    }
    // `PHY_UPSTREAM_MAC`, `PHY_UPSTREAM_PHY`.
    phy.upstream = upstream_type.map(|t| match t {
        0 => PhyUpstream::Mac,
        1 => PhyUpstream::Phy {
            index: upstream_index.unwrap_or(0),
        },
        other => PhyUpstream::Other(other),
    });
    phy
}

#[cfg(test)]
mod phy_tests {
    use super::*;
    use crate::netlink::builder::MessageBuilder;

    /// A media converter's PHY on an SFP module, as the kernel's
    /// `phy_fill_reply` writes it.
    #[test]
    fn a_phy_reply_reads_back() {
        let mut b = MessageBuilder::new(0, 0);
        let header = b.nest_start(EthtoolPhyAttr::Header as u16 | NLA_F_NESTED);
        b.append_attr_u32(EthtoolHeaderAttr::DevIndex as u16, 7);
        b.append_attr_str(EthtoolHeaderAttr::DevName as u16, "eth0");
        b.nest_end(header);
        b.append_attr_u32(EthtoolPhyAttr::Index as u16, 2);
        b.append_attr_str(EthtoolPhyAttr::Drvname as u16, "Marvell 88X3310");
        b.append_attr_str(EthtoolPhyAttr::Name as u16, "sfp-eth0:00");
        b.append_attr_u32(EthtoolPhyAttr::UpstreamType as u16, 1);
        b.append_attr_u32(EthtoolPhyAttr::UpstreamIndex as u16, 1);
        b.append_attr_str(EthtoolPhyAttr::UpstreamSfpName as u16, "sfp-eth0");
        let phy = phy_from_reply(&b.as_bytes()[16..]);
        assert_eq!(
            phy,
            PhyInfo {
                ifname: Some("eth0".into()),
                ifindex: Some(7),
                index: 2,
                driver: Some("Marvell 88X3310".into()),
                name: Some("sfp-eth0:00".into()),
                upstream: Some(PhyUpstream::Phy { index: 1 }),
                upstream_sfp: Some("sfp-eth0".into()),
                downstream_sfp: None,
            }
        );
    }

    /// The PHY on the board, attached to the MAC; an upstream kind newer
    /// than nlink keeps its number.
    #[test]
    fn a_phy_on_the_mac_and_an_unknown_upstream() {
        let mut b = MessageBuilder::new(0, 0);
        b.append_attr_u32(EthtoolPhyAttr::Index as u16, 1);
        b.append_attr_u32(EthtoolPhyAttr::UpstreamType as u16, 0);
        b.append_attr_str(EthtoolPhyAttr::DownstreamSfpName as u16, "sfp-eth1");
        let phy = phy_from_reply(&b.as_bytes()[16..]);
        assert_eq!(phy.upstream, Some(PhyUpstream::Mac));
        assert_eq!(phy.downstream_sfp.as_deref(), Some("sfp-eth1"));
        let mut b = MessageBuilder::new(0, 0);
        b.append_attr_u32(EthtoolPhyAttr::UpstreamType as u16, 9);
        assert_eq!(phy_from_reply(&b.as_bytes()[16..]).upstream, Some(PhyUpstream::Other(9)));
    }
}

#[cfg(test)]
mod fec_builder_tests {
    use super::*;

    #[test]
    fn fec_builder_normalises_common_spellings() {
        let f = FecBuilder::new()
            .mode("rs")
            .mode("Off")
            .mode("baser")
            .mode("FancyVendorName")
            .auto(true);
        assert_eq!(f.modes, vec!["RS", "Off", "BASER", "FancyVendorName"]);
        assert_eq!(f.auto, Some(true));
    }

    #[test]
    fn module_eeprom_request_defaults_and_setters() {
        let r = ModuleEepromRequest::new(4, 64);
        assert_eq!(r.offset, 4);
        assert_eq!(r.length, 64);
        assert_eq!(r.page, 0);
        assert_eq!(r.i2c_address, 0x50);
        let r2 = ModuleEepromRequest::new(0, 128).page(1).i2c_address(0x51);
        assert_eq!(r2.page, 1);
        assert_eq!(r2.i2c_address, 0x51);
    }

    #[test]
    fn rss_parse_collects_indir_table_and_key() {
        use crate::netlink::builder::MessageBuilder;
        let mut b = MessageBuilder::new(0, 0);
        // header skipped; emit hfunc, indir (3 u32 queues), hkey (4 bytes)
        b.append_attr_u32(EthtoolRssAttr::Hfunc as u16, 0x1);
        let mut indir = Vec::new();
        for q in [0u32, 1, 2] {
            indir.extend_from_slice(&q.to_ne_bytes());
        }
        b.append_attr(EthtoolRssAttr::Indir as u16, &indir);
        b.append_attr(EthtoolRssAttr::Hkey as u16, &[0xde, 0xad, 0xbe, 0xef]);

        // Parse the attribute region (skip the 16-byte nl header the
        // builder prepends; no GENL header in this synthetic buffer).
        let conn_attrs = &b.as_bytes()[16..];
        let mut rss = Rss::default();
        for (attr_type, payload) in AttrIter::new(conn_attrs) {
            match attr_type {
                t if t == EthtoolRssAttr::Hfunc as u16 && payload.len() >= 4 => {
                    rss.hfunc = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                }
                t if t == EthtoolRssAttr::Indir as u16 => {
                    rss.indirection_table = payload
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| u32::from_ne_bytes(*c))
                        .collect();
                }
                t if t == EthtoolRssAttr::Hkey as u16 => rss.hash_key = payload.to_vec(),
                _ => {}
            }
        }
        assert_eq!(rss.hfunc, Some(1));
        assert_eq!(rss.indirection_table, vec![0, 1, 2]);
        assert_eq!(rss.hash_key, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn fec_set_request_encodes_modes_bitset() {
        // The bitset write path must round-trip the requested modes.
        let mut bs = EthtoolBitset::new();
        bs.add(0, "RS", true);
        bs.add(1, "Off", false);
        let mut b = MessageBuilder::new(0, 0);
        bs.write_to(&mut b, EthtoolFecAttr::Modes as u16);
        // Re-parse the nested Modes attr and confirm RS is active.
        for (attr_type, payload) in AttrIter::new(&b.as_bytes()[16..]) {
            if attr_type == EthtoolFecAttr::Modes as u16 {
                let parsed = EthtoolBitset::parse(payload).expect("parse modes");
                assert!(parsed.is_set("RS"));
                assert!(!parsed.is_set("Off"));
            }
        }
    }
}

#[cfg(test)]
mod stats_parse_tests {
    use super::*;
    use crate::netlink::{builder::MessageBuilder, genl::ethtool::stats_index};

    fn attrs(build: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        build(&mut b);
        b.as_bytes()[16..].to_vec()
    }

    #[test]
    fn parse_stats_group_collects_indexed_u64s() {
        let data = attrs(|b| {
            b.append_attr_u32(EthtoolStatsGrpAttr::Id as u16, stats_group::ETH_MAC);
            // Two stats: index 3 (rx-pkt) = 100, index 6 (tx-bytes) = 4096.
            let s1 = b.nest_start(EthtoolStatsGrpAttr::Stat as u16 | NLA_F_NESTED);
            b.append_attr(stats_index::ETH_MAC_RX_PKT as u16, &100u64.to_ne_bytes());
            b.nest_end(s1);
            let s2 = b.nest_start(EthtoolStatsGrpAttr::Stat as u16 | NLA_F_NESTED);
            b.append_attr(stats_index::ETH_MAC_TX_BYTES as u16, &4096u64.to_ne_bytes());
            b.nest_end(s2);
        });

        let (gid, group) = parse_stats_group(&data).expect("group");
        assert_eq!(gid, stats_group::ETH_MAC);
        assert_eq!(group.get(stats_index::ETH_MAC_RX_PKT), Some(100));
        assert_eq!(group.get(stats_index::ETH_MAC_TX_BYTES), Some(4096));
        assert_eq!(group.get(99), None);
    }

    #[test]
    fn parse_eth_stats_routes_groups() {
        let conn_data = attrs(|b| {
            // GRP(rmon) with one stat.
            let g = b.nest_start(EthtoolStatsAttr::Grp as u16 | NLA_F_NESTED);
            b.append_attr_u32(EthtoolStatsGrpAttr::Id as u16, stats_group::RMON);
            let s = b.nest_start(EthtoolStatsGrpAttr::Stat as u16 | NLA_F_NESTED);
            b.append_attr(stats_index::RMON_FRAG as u16, &7u64.to_ne_bytes());
            b.nest_end(s);
            b.nest_end(g);
        });

        // Drive the routing logic directly via parse_stats_group +
        // manual dispatch mirror (parse_eth_stats needs &self).
        let mut found = None;
        for (attr_type, payload) in AttrIter::new(&conn_data) {
            if attr_type == EthtoolStatsAttr::Grp as u16 {
                found = parse_stats_group(payload);
            }
        }
        let (gid, group) = found.expect("group");
        assert_eq!(gid, stats_group::RMON);
        assert_eq!(group.get(stats_index::RMON_FRAG), Some(7));
    }
}
