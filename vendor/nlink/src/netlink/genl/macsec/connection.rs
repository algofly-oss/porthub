//! MACsec connection implementation for `Connection<Macsec>`.

use super::{
    MACSEC_GENL_NAME, MACSEC_GENL_VERSION,
    types::{
        MacsecCipherSuite, MacsecDevice, MacsecOffload, MacsecRxSa, MacsecRxSc, MacsecSaBuilder,
        MacsecTxSa, MacsecTxSc, MacsecValidate,
    },
};
use crate::{
    macros::__rt::resolve_genl_family,
    netlink::{
        attr::{AttrIter, NLA_F_NESTED, get},
        builder::MessageBuilder,
        connection::Connection,
        error::Result,
        genl::{GENL_HDRLEN, GenlMsgHdr},
        interface_ref::InterfaceRef,
        message::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN},
        protocol::{AsyncProtocolInit, Macsec},
        socket::NetlinkSocket,
    },
};

impl AsyncProtocolInit for Macsec {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        // #135 — shared canonical resolver (was a per-family copy).
        let family_id = resolve_genl_family(socket, MACSEC_GENL_NAME).await?;
        Ok(Self { family_id })
    }
}
use crate::netlink::types::macsec::{
    macsec_attr, macsec_cmd, macsec_offload_attr, macsec_rxsc_attr, macsec_rxsc_stats_attr,
    macsec_sa_attr, macsec_secy_attr, macsec_txsc_stats_attr,
};

#[nlink_macros::send_futures]
impl Connection<Macsec> {
    /// Get the MACsec family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Resolve an interface reference to an index.
    ///
    /// This creates a temporary Route connection to resolve interface names.
    /// For repeated operations, consider resolving the index once and using
    /// the `*_by_index` methods directly.
    async fn resolve_interface(&self, iface: &InterfaceRef) -> Result<u32> {
        match iface {
            InterfaceRef::Index(idx) => Ok(*idx),
            InterfaceRef::Name(name) => {
                // In this connection's namespace, not the process's (#497).
                let route_conn = self.route_sibling()?;
                route_conn
                    .get_link_by_name(name)
                    .await?
                    .map(|l| l.ifindex())
                    .ok_or_else(|| self.interface_not_found(name.clone()))
            }
        }
    }

    /// Get device information.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Macsec};
    ///
    /// let conn = Connection::<Macsec>::new_async().await?;
    ///
    /// // By name (convenient)
    /// let device = conn.get_device("macsec0").await?;
    ///
    /// // By index (efficient for repeated operations)
    /// let device = conn.get_device(5u32).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device"))]
    pub async fn get_device(&self, iface: impl Into<InterfaceRef>) -> Result<MacsecDevice> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.get_device_by_index(ifindex).await
    }

    /// Get device information by interface index.
    ///
    /// Returns the current configuration and status of the MACsec interface.
    /// This is the preferred method for namespace operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::Route;
    /// # use nlink::netlink::Macsec;
    /// // Get ifindex via Route connection first
    /// let route_conn = Connection::<Route>::new()?;
    /// let link = route_conn.get_link_by_name("macsec0").await?.unwrap();
    ///
    /// let macsec_conn = Connection::<Macsec>::new_async().await?;
    /// let device = macsec_conn.get_device_by_index(link.ifindex()).await?;
    /// println!("SCI: {:016x}", device.sci);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device_by_index"))]
    pub async fn get_device_by_index(&self, ifindex: u32) -> Result<MacsecDevice> {
        let responses = self
            .dump_macsec_command(macsec_cmd::GET_TXSC, |builder| {
                builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);
            })
            .await?;

        if responses.is_empty() {
            return Err(self.interface_not_found(format!("ifindex {ifindex}")));
        }

        // One device per response, and only the one that was asked for.
        //
        // This used to fold *every* response into a single `MacsecDevice`
        // (#260). `MACSEC_CMD_GET_TXSC` is a dump, and a dump message carries
        // its own `MACSEC_ATTR_IFINDEX`, so on a host with more than one
        // MACsec device the result was every device's SAs and RX SCs
        // concatenated — with `ifindex` left holding whichever device came
        // last, since `parse_device_attrs` assigns it from each message.
        //
        // Filtering client-side is correct whether or not the kernel honours
        // the request's ifindex: if it does, this is a no-op; if it does not,
        // this is the only thing that makes the answer right. Same reasoning
        // as `Connection::<Nftables>::list_tables_in`.
        for response in &responses {
            // `send_dump` returns full netlink messages — skip the
            // nlmsghdr and the GENL header to reach the attrs.
            if response.len() < NLMSG_HDRLEN + GENL_HDRLEN {
                continue;
            }
            let attrs_data = &response[NLMSG_HDRLEN + GENL_HDRLEN..];

            let mut device = MacsecDevice::new();
            device.ifindex = ifindex;
            parse_device_attrs(attrs_data, &mut device)?;

            if device.ifindex == ifindex {
                return Ok(device);
            }
        }

        Err(self.interface_not_found(format!("ifindex {ifindex}")))
    }

    /// Add a TX Security Association by interface index.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Macsec;
    /// # use nlink::netlink::genl::macsec::MacsecSaBuilder;
    /// # let conn = nlink::Connection::<nlink::netlink::Macsec>::new_async().await?;
    /// let key = [0u8; 16]; // 128-bit key
    /// // Resolve the index through a route connection in the same netns —
    /// // never through sysfs, which reads the caller's namespace.
    /// let route = nlink::Connection::<nlink::Route>::new()?;
    /// let ifindex = route
    ///     .get_link_by_name("macsec0")
    ///     .await?
    ///     .expect("macsec0 exists")
    ///     .ifindex();
    /// conn.add_tx_sa_by_index(ifindex,
    ///     MacsecSaBuilder::new(0, &key)
    ///         .packet_number(1)
    ///         .active(true)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tx_sa_by_index"))]
    pub async fn add_tx_sa_by_index(&self, ifindex: u32, sa: MacsecSaBuilder) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            builder.append_attr(macsec_sa_attr::KEY, sa.get_key());
            if let Some(pn) = sa.get_pn() {
                // Use u32 for standard PN, u64 for XPN
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            if let Some(key_id) = sa.get_key_id() {
                builder.append_attr(macsec_sa_attr::KEYID, key_id);
            }
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Delete a TX Security Association by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `an` - Association Number (0-3)
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tx_sa_by_index"))]
    pub async fn del_tx_sa_by_index(&self, ifindex: u32, an: u8) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, an);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Update a TX Security Association by interface index.
    ///
    /// This can be used to activate/deactivate an SA or update the packet number.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_tx_sa_by_index"))]
    pub async fn update_tx_sa_by_index(&self, ifindex: u32, sa: MacsecSaBuilder) -> Result<()> {
        self.macsec_command(macsec_cmd::UPD_TXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Add an RX Secure Channel by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `sci` - Secure Channel Identifier (typically peer's MAC + port)
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rx_sc_by_index"))]
    pub async fn add_rx_sc_by_index(&self, ifindex: u32, sci: u64) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_RXSC, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr(macsec_rxsc_attr::SCI, &sci.to_be_bytes());
            builder.append_attr_u8(macsec_rxsc_attr::ACTIVE, 1);
            builder.nest_end(rxsc_config);
        })
        .await?;

        Ok(())
    }

    /// Delete an RX Secure Channel by interface index.
    ///
    /// This also deletes all associated RX SAs.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rx_sc_by_index"))]
    pub async fn del_rx_sc_by_index(&self, ifindex: u32, sci: u64) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_RXSC, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr(macsec_rxsc_attr::SCI, &sci.to_be_bytes());
            builder.nest_end(rxsc_config);
        })
        .await?;

        Ok(())
    }

    /// Add an RX Security Association by interface index.
    ///
    /// # Arguments
    ///
    /// * `ifindex` - Interface index
    /// * `sci` - Secure Channel Identifier
    /// * `sa` - SA configuration
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rx_sa_by_index"))]
    pub async fn add_rx_sa_by_index(
        &self,
        ifindex: u32,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        self.macsec_command(macsec_cmd::ADD_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            // RX SC config with SCI
            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr(macsec_rxsc_attr::SCI, &sci.to_be_bytes());
            builder.nest_end(rxsc_config);

            // SA config
            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            builder.append_attr(macsec_sa_attr::KEY, sa.get_key());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            if let Some(key_id) = sa.get_key_id() {
                builder.append_attr(macsec_sa_attr::KEYID, key_id);
            }
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Delete an RX Security Association by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rx_sa_by_index"))]
    pub async fn del_rx_sa_by_index(&self, ifindex: u32, sci: u64, an: u8) -> Result<()> {
        self.macsec_command(macsec_cmd::DEL_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr(macsec_rxsc_attr::SCI, &sci.to_be_bytes());
            builder.nest_end(rxsc_config);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, an);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    /// Update an RX Security Association by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_rx_sa_by_index"))]
    pub async fn update_rx_sa_by_index(
        &self,
        ifindex: u32,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        self.macsec_command(macsec_cmd::UPD_RXSA, |builder| {
            builder.append_attr_u32(macsec_attr::IFINDEX, ifindex);

            let rxsc_config = builder.nest_start(macsec_attr::RXSC_CONFIG | NLA_F_NESTED);
            builder.append_attr(macsec_rxsc_attr::SCI, &sci.to_be_bytes());
            builder.nest_end(rxsc_config);

            let sa_config = builder.nest_start(macsec_attr::SA_CONFIG | NLA_F_NESTED);
            builder.append_attr_u8(macsec_sa_attr::AN, sa.get_an());
            if let Some(pn) = sa.get_pn() {
                if pn <= u32::MAX as u64 {
                    builder.append_attr_u32(macsec_sa_attr::PN, pn as u32);
                } else {
                    builder.append_attr_u64(macsec_sa_attr::PN, pn);
                }
            }
            builder.append_attr_u8(macsec_sa_attr::ACTIVE, sa.is_active() as u8);
            builder.nest_end(sa_config);
        })
        .await?;

        Ok(())
    }

    // ========================================================================
    // Convenience methods that accept InterfaceRef
    // ========================================================================

    /// Add a TX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Macsec;
    /// # use nlink::netlink::genl::macsec::MacsecSaBuilder;
    /// # let conn = nlink::Connection::<nlink::netlink::Macsec>::new_async().await?;
    /// let key = [0u8; 16];
    /// conn.add_tx_sa("macsec0", MacsecSaBuilder::new(0, &key).active(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_tx_sa"))]
    pub async fn add_tx_sa(
        &self,
        iface: impl Into<InterfaceRef>,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.add_tx_sa_by_index(ifindex, sa).await
    }

    /// Delete a TX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_tx_sa"))]
    pub async fn del_tx_sa(&self, iface: impl Into<InterfaceRef>, an: u8) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.del_tx_sa_by_index(ifindex, an).await
    }

    /// Update a TX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_tx_sa"))]
    pub async fn update_tx_sa(
        &self,
        iface: impl Into<InterfaceRef>,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.update_tx_sa_by_index(ifindex, sa).await
    }

    /// Add an RX Secure Channel.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rx_sc"))]
    pub async fn add_rx_sc(&self, iface: impl Into<InterfaceRef>, sci: u64) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.add_rx_sc_by_index(ifindex, sci).await
    }

    /// Delete an RX Secure Channel.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rx_sc"))]
    pub async fn del_rx_sc(&self, iface: impl Into<InterfaceRef>, sci: u64) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.del_rx_sc_by_index(ifindex, sci).await
    }

    /// Add an RX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rx_sa"))]
    pub async fn add_rx_sa(
        &self,
        iface: impl Into<InterfaceRef>,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.add_rx_sa_by_index(ifindex, sci, sa).await
    }

    /// Delete an RX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rx_sa"))]
    pub async fn del_rx_sa(&self, iface: impl Into<InterfaceRef>, sci: u64, an: u8) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.del_rx_sa_by_index(ifindex, sci, an).await
    }

    /// Update an RX Security Association.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "update_rx_sa"))]
    pub async fn update_rx_sa(
        &self,
        iface: impl Into<InterfaceRef>,
        sci: u64,
        sa: MacsecSaBuilder,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&iface.into()).await?;
        self.update_rx_sa_by_index(ifindex, sci, sa).await
    }

    /// Send a MACsec GENL `SET`-style command and wait for the ACK.
    ///
    /// #135 — routes through the canonical [`Connection::send_ack`]
    /// (looped recv + seq filter + 30s timeout), closing the H9
    /// stale-frame bug class.
    async fn macsec_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_ACK);
        builder.append(&GenlMsgHdr::new(cmd, MACSEC_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_ack(builder).await
    }

    /// Send a MACsec GENL dump command and collect all responses.
    ///
    /// #135 — routes through [`Connection::send_dump`]; each element is
    /// a full netlink message, so callers skip
    /// `NLMSG_HDRLEN + GENL_HDRLEN` to reach the attributes.
    async fn dump_macsec_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&GenlMsgHdr::new(cmd, MACSEC_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_dump(builder).await
    }
}

/// Parse device attributes from a GENL response.
fn parse_device_attrs(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_attr::IFINDEX => {
                device.ifindex = get::u32_ne(payload)?;
            }
            t if t == macsec_attr::SECY => {
                parse_secy_config(payload, device)?;
            }
            t if t == macsec_attr::TXSC_STATS => {
                parse_txsc_stats(payload, device)?;
            }
            t if t == macsec_attr::TXSA_LIST => {
                parse_txsa_list(payload, device)?;
            }
            t if t == macsec_attr::RXSC_LIST => {
                parse_rxsc_list(payload, device)?;
            }
            t if t == macsec_attr::OFFLOAD => {
                parse_offload(payload, device)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse SecY configuration.
fn parse_secy_config(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            // `sci_t` is `__be64`: MAC then port, as `ip macsec` shows it
            // (#516).
            t if t == macsec_secy_attr::SCI => {
                device.sci = get::u64_be(payload)?;
            }
            t if t == macsec_secy_attr::ENCODING_SA => {
                device.encoding_sa = get::u8(payload)?;
            }
            t if t == macsec_secy_attr::WINDOW => {
                device.replay_window = get::u32_ne(payload)?;
            }
            t if t == macsec_secy_attr::CIPHER_SUITE => {
                let cipher_id = get::u64_ne(payload)?;
                device.cipher = MacsecCipherSuite::from_u64(cipher_id).unwrap_or_default();
            }
            t if t == macsec_secy_attr::ICV_LEN => {
                device.icv_len = get::u8(payload)?;
            }
            t if t == macsec_secy_attr::ENCRYPT => {
                device.encrypt = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::PROTECT => {
                device.protect = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::REPLAY => {
                device.replay_protect = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::VALIDATE => {
                device.validate = MacsecValidate::from_u8(get::u8(payload)?);
            }
            t if t == macsec_secy_attr::INC_SCI => {
                device.include_sci = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::ES => {
                device.end_station = get::u8(payload)? != 0;
            }
            t if t == macsec_secy_attr::SCB => {
                device.scb = get::u8(payload)? != 0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse TX SC statistics.
fn parse_txsc_stats(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    let tx_sc = device.tx_sc.get_or_insert_with(MacsecTxSc::default);

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_txsc_stats_attr::OUT_PKTS_PROTECTED => {
                tx_sc.stats_protected_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_PKTS_ENCRYPTED => {
                tx_sc.stats_encrypted_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_OCTETS_PROTECTED => {
                tx_sc.stats_protected_octets = get::u64_ne(payload)?;
            }
            t if t == macsec_txsc_stats_attr::OUT_OCTETS_ENCRYPTED => {
                tx_sc.stats_encrypted_octets = get::u64_ne(payload)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse TX SA list.
fn parse_txsa_list(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    let tx_sc = device.tx_sc.get_or_insert_with(MacsecTxSc::default);
    tx_sc.sci = device.sci;

    for (_idx, sa_data) in AttrIter::new(data) {
        let sa = parse_sa_attrs(sa_data)?;
        tx_sc.sas.push(MacsecTxSa {
            an: sa.0,
            active: sa.1,
            pn: sa.2,
            key_id: sa.3,
        });
    }
    Ok(())
}

/// Parse RX SC list.
fn parse_rxsc_list(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (_idx, rxsc_data) in AttrIter::new(data) {
        let rxsc = parse_rxsc_attrs(rxsc_data)?;
        device.rx_scs.push(rxsc);
    }
    Ok(())
}

/// Parse a single RX SC.
fn parse_rxsc_attrs(data: &[u8]) -> Result<MacsecRxSc> {
    let mut rxsc = MacsecRxSc::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_rxsc_attr::SCI => {
                rxsc.sci = get::u64_be(payload)?;
            }
            t if t == macsec_rxsc_attr::ACTIVE => {
                rxsc.active = get::u8(payload)? != 0;
            }
            t if t == macsec_rxsc_attr::SA_LIST => {
                for (_idx, sa_data) in AttrIter::new(payload) {
                    let sa = parse_sa_attrs(sa_data)?;
                    rxsc.sas.push(MacsecRxSa {
                        an: sa.0,
                        active: sa.1,
                        pn: sa.2,
                        key_id: sa.3,
                    });
                }
            }
            // Stats live in this nest as MACSEC_RXSC_ATTR_STATS. This used
            // to be a second pass looking for the top-level
            // `macsec_attr::RXSC_STATS` — an attribute the kernel has never
            // defined (#260). Its invented value, 3, is `SA_LIST` in this
            // nest, so the old code fed the SA list to the stats parser and
            // read SA attributes as counters.
            t if t == macsec_rxsc_attr::STATS => {
                parse_rxsc_stats_attrs(payload, &mut rxsc)?;
            }
            _ => {}
        }
    }

    Ok(rxsc)
}

/// Parse RX SC statistics.
fn parse_rxsc_stats_attrs(data: &[u8], rxsc: &mut MacsecRxSc) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_rxsc_stats_attr::IN_PKTS_OK => {
                rxsc.stats_ok_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_PKTS_INVALID => {
                rxsc.stats_invalid_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_PKTS_NOT_VALID => {
                rxsc.stats_not_valid_pkts = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_OCTETS_VALIDATED => {
                rxsc.stats_validated_octets = get::u64_ne(payload)?;
            }
            t if t == macsec_rxsc_stats_attr::IN_OCTETS_DECRYPTED => {
                rxsc.stats_decrypted_octets = get::u64_ne(payload)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse SA attributes, returns (an, active, pn, key_id).
fn parse_sa_attrs(data: &[u8]) -> Result<(u8, bool, u64, Option<[u8; 16]>)> {
    let mut an = 0u8;
    let mut active = false;
    let mut pn = 0u64;
    let mut key_id: Option<[u8; 16]> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == macsec_sa_attr::AN => {
                an = get::u8(payload)?;
            }
            t if t == macsec_sa_attr::ACTIVE => {
                active = get::u8(payload)? != 0;
            }
            t if t == macsec_sa_attr::PN => {
                // PN can be u32 or u64 depending on XPN mode
                if payload.len() >= 8 {
                    pn = get::u64_ne(payload)?;
                } else if payload.len() >= 4 {
                    pn = get::u32_ne(payload)? as u64;
                }
            }
            t if t == macsec_sa_attr::KEYID && payload.len() >= 16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(&payload[..16]);
                key_id = Some(id);
            }
            _ => {}
        }
    }

    Ok((an, active, pn, key_id))
}

/// Parse offload configuration.
fn parse_offload(data: &[u8], device: &mut MacsecDevice) -> Result<()> {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type == macsec_offload_attr::TYPE {
            device.offload = MacsecOffload::from_u8(get::u8(payload)?);
        }
    }
    Ok(())
}
