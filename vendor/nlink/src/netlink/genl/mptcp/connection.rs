//! `Connection<Mptcp>` implementation.

use std::net::IpAddr;

use super::{
    MPTCP_PM_GENL_NAME, MPTCP_PM_GENL_VERSION,
    types::{MptcpEndpoint, MptcpEndpointBuilder, MptcpFlags, MptcpLimits},
};
use crate::{
    macros::__rt::resolve_genl_family,
    netlink::{
        attr::{AttrIter, NLA_F_NESTED},
        builder::MessageBuilder,
        connection::Connection,
        error::Result,
        genl::{GENL_HDRLEN, GenlMsgHdr},
        message::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN},
        protocol::{AsyncProtocolInit, Mptcp},
        socket::NetlinkSocket,
    },
};

impl AsyncProtocolInit for Mptcp {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        // #135 — shared canonical resolver (was a per-family copy).
        let family_id = resolve_genl_family(socket, MPTCP_PM_GENL_NAME).await?;
        Ok(Self { family_id })
    }
}
use crate::netlink::types::mptcp::{mptcp_pm_addr_attr, mptcp_pm_attr, mptcp_pm_cmd};

#[nlink_macros::send_futures]
impl Connection<Mptcp> {
    /// Get the MPTCP PM family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Get all configured MPTCP endpoints.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::Mptcp;
    /// let conn = Connection::<Mptcp>::new_async().await?;
    /// for ep in conn.get_endpoints().await? {
    ///     println!("Endpoint {}: {} flags={:?}", ep.id, ep.address, ep.flags);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_endpoints"))]
    pub async fn get_endpoints(&self) -> Result<Vec<MptcpEndpoint>> {
        let responses = self
            .dump_mptcp_command(mptcp_pm_cmd::GET_ADDR, |_builder| {})
            .await?;

        let mut endpoints = Vec::new();
        for response in &responses {
            if let Some(ep) = parse_endpoint_response(response)? {
                endpoints.push(ep);
            }
        }

        Ok(endpoints)
    }

    /// Add an MPTCP endpoint.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let eth1_ifindex: u32 = 3;
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpEndpointBuilder;
    ///
    /// conn.add_endpoint(
    ///     MptcpEndpointBuilder::new("192.168.2.1".parse()?)
    ///         .id(1)
    ///         .ifindex(eth1_ifindex)   // resolve via a Connection<Route> in the same netns
    ///         .subflow()
    ///         .signal()
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_endpoint"))]
    pub async fn add_endpoint(&self, endpoint: MptcpEndpointBuilder) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::ADD_ADDR, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            append_endpoint_attrs(builder, &endpoint);
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    /// Delete an MPTCP endpoint by ID.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// conn.del_endpoint(1).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_endpoint"))]
    pub async fn del_endpoint(&self, id: u8) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::DEL_ADDR, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    /// Flush all MPTCP endpoints.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// conn.flush_endpoints().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_endpoints"))]
    pub async fn flush_endpoints(&self) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::FLUSH_ADDRS, |_builder| {})
            .await?;

        Ok(())
    }

    /// Get MPTCP limits.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// let limits = conn.get_limits().await?;
    /// println!("Max subflows: {:?}", limits.subflows);
    /// println!("Max add_addr_accepted: {:?}", limits.add_addr_accepted);
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_limits"))]
    pub async fn get_limits(&self) -> Result<MptcpLimits> {
        let response = self
            .mptcp_query(mptcp_pm_cmd::GET_LIMITS, |_builder| {})
            .await?;

        if let Some(limits) = parse_limits_response(&response)? {
            return Ok(limits);
        }

        Ok(MptcpLimits::default())
    }

    /// Set MPTCP limits.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpLimits;
    ///
    /// conn.set_limits(
    ///     MptcpLimits::new()
    ///         .subflows(4)
    ///         .add_addr_accepted(4)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_limits"))]
    pub async fn set_limits(&self, limits: MptcpLimits) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::SET_LIMITS, |builder| {
            if let Some(subflows) = limits.subflows {
                builder.append_attr_u32(mptcp_pm_attr::SUBFLOWS, subflows);
            }
            if let Some(add_addr) = limits.add_addr_accepted {
                builder.append_attr_u32(mptcp_pm_attr::RCV_ADD_ADDRS, add_addr);
            }
        })
        .await?;

        Ok(())
    }

    /// Set endpoint flags by ID.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpFlags;
    ///
    /// // Mark endpoint 1 as backup
    /// conn.set_endpoint_flags(1, MptcpFlags { backup: true, ..Default::default() }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_endpoint_flags"))]
    pub async fn set_endpoint_flags(&self, id: u8, flags: MptcpFlags) -> Result<()> {
        self.mptcp_command(mptcp_pm_cmd::SET_FLAGS, |builder| {
            let addr_token = builder.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
            builder.append_attr_u32(mptcp_pm_addr_attr::FLAGS, flags.to_raw());
            builder.nest_end(addr_token);
        })
        .await?;

        Ok(())
    }

    // ========================================================================
    // Per-Connection Operations (Subflow Management)
    // ========================================================================

    /// Create a new subflow on an existing MPTCP connection.
    ///
    /// This allows programmatic creation of subflows between specific
    /// local and remote addresses on an active MPTCP connection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::IpAddr;
    /// # let connection_token: u32 = 0;
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpSubflowBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// // Create a subflow using local address ID 1 to the remote
    /// conn.create_subflow(
    ///     MptcpSubflowBuilder::new(connection_token)
    ///         .local_id(1)
    ///         .remote_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    ///         .remote_port(80)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "create_subflow"))]
    pub async fn create_subflow(&self, subflow: super::types::MptcpSubflowBuilder) -> Result<()> {
        use crate::netlink::types::mptcp::mptcp_attr;

        self.mptcp_command(mptcp_pm_cmd::SUBFLOW_CREATE, |builder| {
            // Token is required
            builder.append_attr_u32(mptcp_attr::TOKEN, subflow.token);

            // Local address ID
            if let Some(id) = subflow.local_id {
                builder.append_attr_u8(mptcp_attr::LOC_ID, id);
            }

            // Remote address ID
            if let Some(id) = subflow.remote_id {
                builder.append_attr_u8(mptcp_attr::REM_ID, id);
            }

            // Local address
            if let Some(ref addr) = subflow.local_addr {
                append_source_addr(builder, addr);
            }

            // Remote address
            if let Some(ref addr) = subflow.remote_addr {
                append_dest_addr(builder, addr);
            }

            // Interface (must be provided as ifindex for namespace safety)
            if let Some(ifindex) = subflow.ifindex {
                builder.append_attr_u32(mptcp_attr::IF_IDX, ifindex);
            }

            // Backup flag
            if subflow.backup {
                builder.append_attr_u8(mptcp_attr::BACKUP, 1);
            }
        })
        .await?;

        Ok(())
    }

    /// Destroy a subflow on an existing MPTCP connection.
    ///
    /// This closes a specific subflow identified by its local and remote addresses.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::IpAddr;
    /// # let connection_token: u32 = 0;
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpSubflowBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// // Destroy the subflow between specific addresses
    /// conn.destroy_subflow(
    ///     MptcpSubflowBuilder::new(connection_token)
    ///         .local_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    ///         .local_port(12345)
    ///         .remote_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    ///         .remote_port(80)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "destroy_subflow"))]
    pub async fn destroy_subflow(&self, subflow: super::types::MptcpSubflowBuilder) -> Result<()> {
        use crate::netlink::types::mptcp::mptcp_attr;

        self.mptcp_command(mptcp_pm_cmd::SUBFLOW_DESTROY, |builder| {
            // Token is required
            builder.append_attr_u32(mptcp_attr::TOKEN, subflow.token);

            // Local address ID
            if let Some(id) = subflow.local_id {
                builder.append_attr_u8(mptcp_attr::LOC_ID, id);
            }

            // Remote address ID
            if let Some(id) = subflow.remote_id {
                builder.append_attr_u8(mptcp_attr::REM_ID, id);
            }

            // Local address
            if let Some(ref addr) = subflow.local_addr {
                append_source_addr(builder, addr);
            }

            // Remote address
            if let Some(ref addr) = subflow.remote_addr {
                append_dest_addr(builder, addr);
            }
        })
        .await?;

        Ok(())
    }

    /// Announce an address to a peer on a specific connection.
    ///
    /// This sends an ADD_ADDR message to the peer on the specified connection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use std::net::IpAddr;
    /// # let connection_token: u32 = 0;
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// use nlink::netlink::genl::mptcp::MptcpAnnounceBuilder;
    /// use std::net::Ipv4Addr;
    ///
    /// // Announce address ID 1 to the peer
    /// conn.announce_addr(
    ///     MptcpAnnounceBuilder::new(connection_token)
    ///         .addr_id(1)
    ///         .address(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "announce_addr"))]
    pub async fn announce_addr(&self, announce: super::types::MptcpAnnounceBuilder) -> Result<()> {
        use crate::netlink::types::mptcp::mptcp_attr;

        self.mptcp_command(mptcp_pm_cmd::ANNOUNCE, |builder| {
            // Token is required
            builder.append_attr_u32(mptcp_attr::TOKEN, announce.token);

            // Address ID
            if let Some(id) = announce.addr_id {
                builder.append_attr_u8(mptcp_attr::LOC_ID, id);
            }

            // Address to announce
            if let Some(ref addr) = announce.address {
                append_source_addr(builder, addr);
            }
        })
        .await?;

        Ok(())
    }

    /// Remove an address announcement from a specific connection.
    ///
    /// This sends a REMOVE_ADDR message to the peer.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let connection_token: u32 = 0;
    /// # use nlink::netlink::Mptcp;
    /// # let conn = nlink::Connection::<nlink::netlink::Mptcp>::new_async().await?;
    /// // Remove address ID 1 from the connection
    /// conn.del_addr(connection_token, 1).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_addr"))]
    pub async fn del_addr(&self, token: u32, addr_id: u8) -> Result<()> {
        use crate::netlink::types::mptcp::mptcp_attr;

        self.mptcp_command(mptcp_pm_cmd::REMOVE, |builder| {
            builder.append_attr_u32(mptcp_attr::TOKEN, token);
            builder.append_attr_u8(mptcp_attr::LOC_ID, addr_id);
        })
        .await?;

        Ok(())
    }

    /// Send an MPTCP PM GENL `SET`-style command and wait for the ACK.
    ///
    /// #135 — routes through the canonical [`Connection::send_ack`]
    /// (looped recv + seq filter + 30s timeout), closing the H9
    /// stale-frame bug class.
    async fn mptcp_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_ACK);
        builder.append(&GenlMsgHdr::new(cmd, MPTCP_PM_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_ack(builder).await
    }

    /// Send an MPTCP PM GENL query command (no ACK requested, single
    /// data reply).
    ///
    /// #135 — routes through the canonical [`Connection::send_request`]
    /// (looped recv + seq filter + 30s timeout). Returns the full
    /// netlink response buffer; callers parse past
    /// `NLMSG_HDRLEN + GENL_HDRLEN`.
    async fn mptcp_query(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<u8>> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST);
        builder.append(&GenlMsgHdr::new(cmd, MPTCP_PM_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_request(builder).await
    }

    /// Send an MPTCP PM GENL dump command and collect all responses.
    ///
    /// #135 — routes through [`Connection::send_dump`]; each element is
    /// a full netlink message, so callers skip
    /// `NLMSG_HDRLEN + GENL_HDRLEN` to reach the attributes.
    async fn dump_mptcp_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&GenlMsgHdr::new(cmd, MPTCP_PM_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_dump(builder).await
    }
}

/// Append endpoint attributes to a message builder.
fn append_endpoint_attrs(builder: &mut MessageBuilder, endpoint: &MptcpEndpointBuilder) {
    // Address family
    let family = match endpoint.address {
        IpAddr::V4(_) => libc::AF_INET as u16,
        IpAddr::V6(_) => libc::AF_INET6 as u16,
    };
    builder.append_attr(mptcp_pm_addr_attr::FAMILY, &family.to_ne_bytes());

    // Address
    match endpoint.address {
        IpAddr::V4(addr) => {
            builder.append_attr(mptcp_pm_addr_attr::ADDR4, &addr.octets());
        }
        IpAddr::V6(addr) => {
            builder.append_attr(mptcp_pm_addr_attr::ADDR6, &addr.octets());
        }
    }

    // Optional ID
    if let Some(id) = endpoint.id {
        builder.append_attr_u8(mptcp_pm_addr_attr::ID, id);
    }

    // Optional port.
    //
    // `MPTCP_PM_ADDR_ATTR_PORT` is host order: the kernel ingests it
    // with `addr->port = htons(nla_get_u16(...))`. nlink wrote it big-
    // endian and read it back big-endian, so it round-tripped through
    // nlink perfectly while the kernel held the swapped value —
    // `.port(8080)` installed an endpoint on **36895**, which is what
    // `ip mptcp endpoint show` reported (#275).
    if let Some(port) = endpoint.port {
        builder.append_attr(mptcp_pm_addr_attr::PORT, &port.to_ne_bytes());
    }

    // Optional interface index (must be provided as ifindex for namespace safety)
    if let Some(ifindex) = endpoint.ifindex {
        builder.append_attr_u32(mptcp_pm_addr_attr::IF_IDX, ifindex);
    }

    // Flags
    let flags = endpoint.flags.to_raw();
    if flags != 0 {
        builder.append_attr_u32(mptcp_pm_addr_attr::FLAGS, flags);
    }
}

/// Parse an endpoint from a full netlink response message.
///
/// The frame comes from `send_dump`, so it begins with the 16-byte
/// `nlmsghdr`; skip that plus the GENL header to reach the attributes.
fn parse_endpoint_response(frame: &[u8]) -> Result<Option<MptcpEndpoint>> {
    if frame.len() < NLMSG_HDRLEN + GENL_HDRLEN {
        return Ok(None);
    }
    let data = &frame[NLMSG_HDRLEN + GENL_HDRLEN..];

    // Look for MPTCP_PM_ATTR_ADDR
    for (attr_type, attr_payload) in AttrIter::new(data) {
        if attr_type == mptcp_pm_attr::ADDR {
            return Ok(Some(parse_endpoint_attrs(attr_payload)?));
        }
    }

    Ok(None)
}

/// Parse endpoint attributes from nested data.
fn parse_endpoint_attrs(data: &[u8]) -> Result<MptcpEndpoint> {
    let mut endpoint = MptcpEndpoint::default();

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == mptcp_pm_addr_attr::ID && !payload.is_empty() => {
                endpoint.id = payload[0];
            }
            t if t == mptcp_pm_addr_attr::ADDR4 && payload.len() >= 4 => {
                let octets: [u8; 4] = payload[..4].try_into().unwrap();
                endpoint.address = IpAddr::V4(octets.into());
            }
            t if t == mptcp_pm_addr_attr::ADDR6 && payload.len() >= 16 => {
                let octets: [u8; 16] = payload[..16].try_into().unwrap();
                endpoint.address = IpAddr::V6(octets.into());
            }
            t if t == mptcp_pm_addr_attr::PORT && payload.len() >= 2 => {
                let port = u16::from_ne_bytes(payload[..2].try_into().unwrap());
                if port != 0 {
                    endpoint.port = Some(port);
                }
            }
            t if t == mptcp_pm_addr_attr::FLAGS && payload.len() >= 4 => {
                let flags = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                endpoint.flags = MptcpFlags::from_raw(flags);
            }
            t if t == mptcp_pm_addr_attr::IF_IDX && payload.len() >= 4 => {
                let ifindex = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                if ifindex != 0 {
                    endpoint.ifindex = Some(ifindex);
                }
            }
            _ => {}
        }
    }

    Ok(endpoint)
}

/// Parse limits from a full netlink response message.
///
/// The frame comes from `send_request`, so it begins with the 16-byte
/// `nlmsghdr`; skip that plus the GENL header to reach the attributes.
fn parse_limits_response(frame: &[u8]) -> Result<Option<MptcpLimits>> {
    if frame.len() < NLMSG_HDRLEN + GENL_HDRLEN {
        return Ok(None);
    }
    let data = &frame[NLMSG_HDRLEN + GENL_HDRLEN..];

    let mut limits = MptcpLimits::default();
    let mut found = false;

    for (attr_type, attr_payload) in AttrIter::new(data) {
        match attr_type {
            t if t == mptcp_pm_attr::SUBFLOWS && attr_payload.len() >= 4 => {
                limits.subflows = Some(u32::from_ne_bytes(attr_payload[..4].try_into().unwrap()));
                found = true;
            }
            t if t == mptcp_pm_attr::RCV_ADD_ADDRS && attr_payload.len() >= 4 => {
                limits.add_addr_accepted =
                    Some(u32::from_ne_bytes(attr_payload[..4].try_into().unwrap()));
                found = true;
            }
            _ => {}
        }
    }

    if found { Ok(Some(limits)) } else { Ok(None) }
}

/// Append source address attributes for subflow operations.
fn append_source_addr(builder: &mut MessageBuilder, addr: &super::types::MptcpAddress) {
    use crate::netlink::types::mptcp::mptcp_attr;

    // Address family
    let family = match addr.addr {
        IpAddr::V4(_) => libc::AF_INET as u16,
        IpAddr::V6(_) => libc::AF_INET6 as u16,
    };
    builder.append_attr(mptcp_attr::FAMILY, &family.to_ne_bytes());

    // Source address
    match addr.addr {
        IpAddr::V4(a) => {
            builder.append_attr(mptcp_attr::SADDR4, &a.octets());
        }
        IpAddr::V6(a) => {
            builder.append_attr(mptcp_attr::SADDR6, &a.octets());
        }
    }

    // Source port — big-endian, and deliberately unlike the endpoint's
    // `MPTCP_PM_ADDR_ATTR_PORT` above, which is host order.
    //
    // These are two different attribute sets. `MPTCP_ATTR_SPORT` is
    // from `enum mptcp_event_attr`, which the kernel emits with
    // `nla_put_be16`; `MPTCP_PM_ADDR_ATTR_PORT` is from
    // `enum mptcp_pm_addr_attr`, ingested with
    // `htons(nla_get_u16(...))`. Do not "fix" one to match the other.
    if let Some(port) = addr.port {
        builder.append_attr(mptcp_attr::SPORT, &port.to_be_bytes());
    }
}

/// Append destination address attributes for subflow operations.
fn append_dest_addr(builder: &mut MessageBuilder, addr: &super::types::MptcpAddress) {
    use crate::netlink::types::mptcp::mptcp_attr;

    // Destination address
    match addr.addr {
        IpAddr::V4(a) => {
            builder.append_attr(mptcp_attr::DADDR4, &a.octets());
        }
        IpAddr::V6(a) => {
            builder.append_attr(mptcp_attr::DADDR6, &a.octets());
        }
    }

    // Destination port — big-endian; see the note on `SPORT` above for
    // why this differs from the endpoint's port.
    if let Some(port) = addr.port {
        builder.append_attr(mptcp_attr::DPORT, &port.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::genl::GENL_ID_CTRL;

    #[test]
    fn test_parse_empty_payload() {
        let result = parse_endpoint_response(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_limits_empty() {
        let result = parse_limits_response(&[]).unwrap();
        assert!(result.is_none());
    }

    /// Build a full netlink frame (16-byte nlmsghdr + GENL header +
    /// attrs), exactly what `send_dump`/`send_request` hand back after
    /// the #135 unification. The parse helpers must skip
    /// `NLMSG_HDRLEN + GENL_HDRLEN` to reach the attributes — this test
    /// pins that offset so a regression to the old GENL-only offset is
    /// caught.
    fn frame_with_attrs(build: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST);
        b.append(&GenlMsgHdr::new(
            mptcp_pm_cmd::GET_LIMITS,
            MPTCP_PM_GENL_VERSION,
        ));
        build(&mut b);
        b.set_seq(7);
        b.finish()
    }

    #[test]
    fn parse_limits_reads_full_frame_at_correct_offset() {
        let frame = frame_with_attrs(|b| {
            b.append_attr_u32(mptcp_pm_attr::SUBFLOWS, 4);
            b.append_attr_u32(mptcp_pm_attr::RCV_ADD_ADDRS, 8);
        });
        let limits = parse_limits_response(&frame)
            .unwrap()
            .expect("limits parsed");
        assert_eq!(limits.subflows, Some(4));
        assert_eq!(limits.add_addr_accepted, Some(8));
    }

    #[test]
    fn parse_endpoint_reads_full_frame_at_correct_offset() {
        let frame = frame_with_attrs(|b| {
            let addr_token = b.nest_start(mptcp_pm_attr::ADDR | NLA_F_NESTED);
            b.append_attr_u8(mptcp_pm_addr_attr::ID, 3);
            b.append_attr(mptcp_pm_addr_attr::ADDR4, &[10, 0, 0, 1]);
            b.nest_end(addr_token);
        });
        let ep = parse_endpoint_response(&frame)
            .unwrap()
            .expect("endpoint parsed");
        assert_eq!(ep.id, 3);
        assert_eq!(ep.address, IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    }

    /// A frame shorter than `nlmsghdr + GENL header` must not panic —
    /// it returns `None` (the length guard).
    #[test]
    fn parse_helpers_reject_short_frame() {
        let too_short = vec![0u8; NLMSG_HDRLEN + GENL_HDRLEN - 1];
        assert!(parse_limits_response(&too_short).unwrap().is_none());
        assert!(parse_endpoint_response(&too_short).unwrap().is_none());
    }
}
