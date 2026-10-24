//! WireGuard connection implementation for `Connection<Wireguard>`.
//!
//! This module provides methods for WireGuard device configuration
//! integrated into the Connection pattern.

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::{
    WG_GENL_NAME, WG_GENL_VERSION, WgAllowedIpAttr, WgCmd, WgDeviceAttr, WgDeviceFlag, WgPeerAttr,
    types::{AllowedIp, WG_KEY_LEN, WgDevice, WgDeviceBuilder, WgPeer, parse_timespec},
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
        protocol::{AsyncProtocolInit, Wireguard},
        socket::NetlinkSocket,
    },
};

impl AsyncProtocolInit for Wireguard {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        // #135 — resolve via the shared canonical resolver instead of
        // a per-family copy (the old `resolve_wireguard_family` was a
        // byte-for-byte duplicate of `resolve_genl_family`).
        let family_id = resolve_genl_family(socket, WG_GENL_NAME).await?;
        Ok(Self {
            family_id,
            ..Default::default()
        })
    }
}

#[nlink_macros::send_futures]
impl Connection<Wireguard> {
    /// Get the WireGuard family ID.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Resolve an interface reference to a name.
    ///
    /// WireGuard uses interface names in its protocol, so we resolve
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

    // ========================================================================
    // Convenience methods that accept InterfaceRef
    // ========================================================================

    /// Get device information.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Wireguard};
    ///
    /// let conn = Connection::<Wireguard>::new_async().await?;
    ///
    /// // By name
    /// let device = conn.get_device("wg0").await?;
    ///
    /// // By index
    /// let device = conn.get_device(5u32).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device"))]
    pub async fn get_device(&self, iface: impl Into<InterfaceRef>) -> Result<WgDevice> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.get_device_by_name(&ifname).await
    }

    /// Set device configuration.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Wireguard>::new_async().await?;
    /// # let my_key = [0u8; 32];
    /// conn.set_device("wg0", |dev| {
    ///     dev.private_key(my_key)
    ///        .listen_port(51820)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_device"))]
    pub async fn set_device(
        &self,
        iface: impl Into<InterfaceRef>,
        configure: impl FnOnce(WgDeviceBuilder) -> WgDeviceBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_device_by_name(&ifname, configure).await
    }

    /// Add or update a peer.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_peer"))]
    pub async fn set_peer(
        &self,
        iface: impl Into<InterfaceRef>,
        public_key: [u8; WG_KEY_LEN],
        configure: impl FnOnce(super::types::WgPeerBuilder) -> super::types::WgPeerBuilder,
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.set_peer_by_name(&ifname, public_key, configure).await
    }

    /// Remove a peer by public key.
    ///
    /// Accepts either an interface name or index via [`InterfaceRef`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_peer"))]
    pub async fn del_peer(
        &self,
        iface: impl Into<InterfaceRef>,
        public_key: [u8; WG_KEY_LEN],
    ) -> Result<()> {
        let ifname = self.resolve_interface_name(&iface.into()).await?;
        self.del_peer_by_name(&ifname, public_key).await
    }

    // ========================================================================
    // Name-based methods (used internally and for efficiency)
    // ========================================================================

    /// Get device information by interface name.
    ///
    /// Returns the current configuration and status of the WireGuard interface.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_device_by_name"))]
    pub async fn get_device_by_name(&self, ifname: &str) -> Result<WgDevice> {
        let responses = self
            .dump_wg_command(WgCmd::GetDevice as u8, |builder| {
                builder.append_attr_str(WgDeviceAttr::Ifname as u16, ifname);
            })
            .await?;

        if responses.is_empty() {
            return Err(self.interface_not_found(ifname));
        }

        // Parse the response(s) - may be split across multiple messages for large peer lists
        let mut device = WgDevice::new();

        for response in &responses {
            // `send_dump` returns full netlink messages — skip the
            // 16-byte nlmsghdr and the GENL header to reach the attrs.
            if response.len() < NLMSG_HDRLEN + GENL_HDRLEN {
                continue;
            }

            let attrs_data = &response[NLMSG_HDRLEN + GENL_HDRLEN..];
            self.parse_device_attrs(attrs_data, &mut device)?;
        }

        Ok(device)
    }

    /// Set device configuration by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_device_by_name"))]
    pub async fn set_device_by_name(
        &self,
        ifname: &str,
        configure: impl FnOnce(WgDeviceBuilder) -> WgDeviceBuilder,
    ) -> Result<()> {
        let builder = configure(WgDeviceBuilder::new());
        self.apply_device_config(ifname, &builder).await
    }

    /// Add or update a peer by interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "set_peer_by_name"))]
    pub async fn set_peer_by_name(
        &self,
        ifname: &str,
        public_key: [u8; WG_KEY_LEN],
        configure: impl FnOnce(super::types::WgPeerBuilder) -> super::types::WgPeerBuilder,
    ) -> Result<()> {
        let peer_builder = configure(super::types::WgPeerBuilder::new(public_key));
        let device_builder = WgDeviceBuilder::new().peer(peer_builder);
        self.apply_device_config(ifname, &device_builder).await
    }

    /// Whether the kernel removes a single allowed-IP prefix
    /// (`WGALLOWEDIP_F_REMOVE_ME`, 6.16+), asked once per connection
    /// (#529).
    ///
    /// The probe is a `SET_DEVICE` that changes nothing on either kind of
    /// kernel: for `peer`, which the device must have, update-only, it
    /// removes `absent`, a prefix the peer does not hold. A kernel without
    /// the flag refuses the message (`EINVAL`: its strict parse of the
    /// allowed-IP nest knows no attribute 4), which is `false`; one with it
    /// accepts — removing nothing — which is `true`. The `true` path is
    /// unverified: this was written on 6.12.
    pub async fn allowed_ip_removal_supported(
        &self,
        ifname: &str,
        peer: [u8; WG_KEY_LEN],
        absent: AllowedIp,
    ) -> Result<bool> {
        if let Some(known) = self.state().allowed_ip_removal.get() {
            return Ok(*known);
        }
        let supported = match self
            .set_peer_by_name(ifname, peer, |b| b.update_only().remove_allowed_ip(absent))
            .await
        {
            Ok(()) => true,
            Err(e) if e.is_invalid_argument() => false,
            Err(e) => return Err(e),
        };
        tracing::debug!(supported, "wireguard: per-prefix allowed-IP removal");
        let _ = self.state().allowed_ip_removal.set(supported);
        Ok(supported)
    }

    /// Remove a peer by public key using interface name.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_peer_by_name"))]
    pub async fn del_peer_by_name(&self, ifname: &str, public_key: [u8; WG_KEY_LEN]) -> Result<()> {
        let peer_builder = super::types::WgPeerBuilder::new(public_key).remove();
        let device_builder = WgDeviceBuilder::new().peer(peer_builder);
        self.apply_device_config(ifname, &device_builder).await
    }

    /// Apply device configuration to the kernel, in as many `SET_DEVICE`
    /// messages as it takes (#500).
    ///
    /// Every peer went into one `WGDEVICE_A_PEERS` nest, whose `nla_len` is
    /// a u16: past about 400 peers, or 1,600 IPv6 allowed-ips on one peer,
    /// that was a debug-build panic and a malformed message in release.
    /// This splits the way `wg(8)` does: the device's own settings, and
    /// `WGDEVICE_F_REPLACE_PEERS`, go in the first message only; a peer
    /// continued in the next one repeats just its public key and the rest
    /// of its allowed-ips, without `WGPEER_F_REPLACE_ALLOWEDIPS`. The
    /// messages are separate kernel operations, as they are for `wg`.
    async fn apply_device_config(&self, ifname: &str, config: &WgDeviceBuilder) -> Result<()> {
        for (i, message) in plan_set_device(config.get_peers()).iter().enumerate() {
            self.wg_command(WgCmd::SetDevice as u8, |builder| {
                builder.append_attr_str(WgDeviceAttr::Ifname as u16, ifname);
                if i == 0 {
                    if config.has_replace_peers() {
                        builder.append_attr_u32(
                            WgDeviceAttr::Flags as u16,
                            WgDeviceFlag::ReplacePeers as u32,
                        );
                    }
                    if let Some(key) = config.get_private_key() {
                        builder.append_attr(WgDeviceAttr::PrivateKey as u16, key);
                    }
                    if let Some(port) = config.get_listen_port() {
                        builder.append_attr_u16(WgDeviceAttr::ListenPort as u16, port);
                    }
                    if let Some(mark) = config.get_fwmark() {
                        builder.append_attr_u32(WgDeviceAttr::Fwmark as u16, mark);
                    }
                }
                if !message.is_empty() {
                    let peers = builder.nest_start(WgDeviceAttr::Peers as u16 | NLA_F_NESTED);
                    for (idx, part) in message.iter().enumerate() {
                        append_peer_part(builder, idx as u16, part);
                    }
                    builder.nest_end(peers);
                }
            })
            .await?;
        }
        Ok(())
    }

    /// Send a WireGuard GENL `SET`-style command and wait for the ACK.
    ///
    /// #135 — routes through the canonical [`Connection::send_ack`]
    /// helper instead of a hand-rolled single-`recv_msg`. That helper
    /// loops with the seq filter + 30s timeout, closing the H9
    /// stale-frame bug class (the old single-recv could return `Ok`
    /// without consuming its own ACK, desyncing the fd).
    async fn wg_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_ACK);
        builder.append(&GenlMsgHdr::new(cmd, WG_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_ack(builder).await
    }

    /// Send a WireGuard GENL dump command and collect all responses.
    ///
    /// #135 — routes through the canonical [`Connection::send_dump`]
    /// helper. Each returned element is a full netlink message
    /// (16-byte `nlmsghdr` + GENL header + attrs); callers skip
    /// `NLMSG_HDRLEN + GENL_HDRLEN` to reach the attribute bytes.
    async fn dump_wg_command(
        &self,
        cmd: u8,
        build_attrs: impl FnOnce(&mut MessageBuilder),
    ) -> Result<Vec<Vec<u8>>> {
        let mut builder = MessageBuilder::new(self.state().family_id, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&GenlMsgHdr::new(cmd, WG_GENL_VERSION));
        build_attrs(&mut builder);
        self.send_dump(builder).await
    }

    /// Parse device attributes from a GENL response.
    fn parse_device_attrs(&self, data: &[u8], device: &mut WgDevice) -> Result<()> {
        for (attr_type, payload) in AttrIter::new(data) {
            if attr_type == WgDeviceAttr::Peers as u16 {
                self.parse_peers_attr(payload, &mut device.peers)?;
            } else {
                parse_device_attr_scalar(attr_type, payload, device)?;
            }
        }
        Ok(())
    }

    /// Parse the peers nested attribute, coalescing continuations.
    ///
    /// `wg_get_device_dump` splits a large peer list across skbs, and a
    /// peer whose `allowed_ips` do not fit is emitted again in the next
    /// chunk: its `WGPEER_A_PUBLIC_KEY` repeats, the remaining allowed
    /// IPs follow, and the scalars — `RX_BYTES`, `TX_BYTES`,
    /// `LAST_HANDSHAKE_TIME`, `PERSISTENT_KEEPALIVE`, `ENDPOINT`,
    /// `PRESHARED_KEY` — appear only in the *first* chunk.
    ///
    /// This pushed unconditionally, so such a peer came back **twice**:
    /// once with stats and a partial `allowed_ips`, once with zeroed
    /// stats, no endpoint, and the rest. `wg(8)` coalesces by public
    /// key; so does this now (#277).
    ///
    /// The knock-on was worse than a duplicate row.
    /// `WireguardConfig::diff_against` keys the current state by public
    /// key, so the second, stats-less entry *overwrote* the full one:
    /// the declared peer was compared against a truncated view,
    /// `endpoint_set` and `allowed_ips_set` both fired, and `apply()`
    /// rewrote that peer on every single run.
    fn parse_peers_attr(&self, data: &[u8], peers: &mut Vec<WgPeer>) -> Result<()> {
        for (_idx, peer_data) in AttrIter::new(data) {
            let peer = self.parse_peer_attrs(peer_data)?;
            match peers.iter_mut().find(|p| p.public_key == peer.public_key) {
                Some(existing) => existing.merge_continuation(peer),
                None => peers.push(peer),
            }
        }
        Ok(())
    }

    /// Parse a single peer's attributes.
    fn parse_peer_attrs(&self, data: &[u8]) -> Result<WgPeer> {
        let mut peer = WgPeer::default();

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == WgPeerAttr::PublicKey as u16 && payload.len() >= WG_KEY_LEN => {
                    peer.public_key.copy_from_slice(&payload[..WG_KEY_LEN]);
                }
                t if t == WgPeerAttr::PresharedKey as u16 && payload.len() >= WG_KEY_LEN => {
                    let mut key = [0u8; WG_KEY_LEN];
                    key.copy_from_slice(&payload[..WG_KEY_LEN]);
                    // Only set if not all zeros (kernel returns zeros if not set)
                    if key.iter().any(|&b| b != 0) {
                        peer.preshared_key = Some(key);
                    }
                }
                t if t == WgPeerAttr::Endpoint as u16 => {
                    peer.endpoint = parse_sockaddr(payload);
                }
                t if t == WgPeerAttr::PersistentKeepalive as u16 => {
                    peer.persistent_keepalive = Some(get::u16_ne(payload)?);
                }
                t if t == WgPeerAttr::LastHandshake as u16 => {
                    peer.last_handshake = parse_timespec(payload);
                }
                t if t == WgPeerAttr::RxBytes as u16 => {
                    peer.rx_bytes = get::u64_ne(payload)?;
                }
                t if t == WgPeerAttr::TxBytes as u16 => {
                    peer.tx_bytes = get::u64_ne(payload)?;
                }
                t if t == WgPeerAttr::AllowedIps as u16 => {
                    self.parse_allowed_ips_attr(payload, &mut peer.allowed_ips)?;
                }
                t if t == WgPeerAttr::ProtocolVersion as u16 => {
                    peer.protocol_version = Some(get::u32_ne(payload)?);
                }
                _ => {}
            }
        }

        Ok(peer)
    }

    /// Parse allowed IPs nested attribute.
    fn parse_allowed_ips_attr(&self, data: &[u8], allowed_ips: &mut Vec<AllowedIp>) -> Result<()> {
        for (_idx, ip_data) in AttrIter::new(data) {
            if let Some(ip) = parse_allowed_ip_attrs(ip_data)? {
                allowed_ips.push(ip);
            }
        }
        Ok(())
    }
}

/// Read a `WG_KEY_LEN` key from the front of `payload`, mapping the kernel's
/// all-zeros sentinel to `None`.
///
/// The kernel returns 32 zero bytes (not an absent attribute) for a key field
/// of a keyless device on a privileged `GET_DEVICE`. All-zeros is not a usable
/// key, so it's reported as `None` — the same normalization the peer
/// `PresharedKey` arm applies. Callers must guard `payload.len() >= WG_KEY_LEN`
/// before calling.
fn parse_key(payload: &[u8]) -> Option<[u8; WG_KEY_LEN]> {
    let mut key = [0u8; WG_KEY_LEN];
    key.copy_from_slice(&payload[..WG_KEY_LEN]);
    key.iter().any(|&b| b != 0).then_some(key)
}

/// Parse scalar (non-nested) device attributes into `device`.
///
/// Split out from `Connection::parse_device_attrs` so the scalar parsing path
/// is testable without a live socket.
fn parse_device_attr_scalar(attr_type: u16, payload: &[u8], device: &mut WgDevice) -> Result<()> {
    match attr_type {
        t if t == WgDeviceAttr::Ifindex as u16 => {
            device.ifindex = Some(get::u32_ne(payload)?);
        }
        t if t == WgDeviceAttr::Ifname as u16 => {
            device.ifname = Some(get::string(payload)?.to_string());
        }
        t if t == WgDeviceAttr::PrivateKey as u16 && payload.len() >= WG_KEY_LEN => {
            device.private_key = parse_key(payload);
        }
        t if t == WgDeviceAttr::PublicKey as u16 && payload.len() >= WG_KEY_LEN => {
            device.public_key = parse_key(payload);
        }
        t if t == WgDeviceAttr::ListenPort as u16 => {
            device.listen_port = Some(get::u16_ne(payload)?);
        }
        t if t == WgDeviceAttr::Fwmark as u16 => {
            device.fwmark = Some(get::u32_ne(payload)?);
        }
        _ => {}
    }
    Ok(())
}

/// Append peer attributes to a message builder.
/// How many attribute bytes one `SET_DEVICE` message carries before
/// [`plan_set_device`] starts the next; well inside the u16 `nla_len` of
/// the peers nest, as `wg(8)`'s own socket-buffer-sized messages are.
const SET_DEVICE_BUDGET: usize = 32 * 1024;

/// Room kept in every message for the GENL header, the device name and,
/// in the first, the device's own settings.
const SET_DEVICE_OVERHEAD: usize = 256;

/// One peer's share of one `SET_DEVICE` message: all of its settings if
/// `first`, and the allowed-ips in `ips`.
struct PeerPart<'a> {
    peer: &'a super::types::WgPeerBuilder,
    first: bool,
    ips: std::ops::Range<usize>,
}

/// The bytes `write` appends to a message.
fn encoded_len(write: impl FnOnce(&mut MessageBuilder)) -> usize {
    let mut builder = MessageBuilder::new(0, 0);
    let start = builder.len();
    write(&mut builder);
    builder.len() - start
}

/// Split `peers` into `SET_DEVICE` messages of at most
/// [`SET_DEVICE_BUDGET`] bytes (#500). Always at least one message, so the
/// device's own settings are sent even with no peers.
fn plan_set_device(peers: &[super::types::WgPeerBuilder]) -> Vec<Vec<PeerPart<'_>>> {
    let mut messages = Vec::new();
    let mut current = Vec::new();
    let mut used = SET_DEVICE_OVERHEAD;
    for peer in peers {
        let ips = peer.allowed_ip_entries();
        let (mut next, mut first) = (0, true);
        loop {
            let head = encoded_len(|b| {
                append_peer_part(
                    b,
                    0,
                    &PeerPart {
                        peer,
                        first,
                        ips: 0..0,
                    },
                );
            }) + 4; // the allowed-ips nest header
            if used + head > SET_DEVICE_BUDGET && !current.is_empty() {
                messages.push(std::mem::take(&mut current));
                used = SET_DEVICE_OVERHEAD;
            }
            used += head;
            let start = next;
            while let Some((ip, remove)) = ips.get(next) {
                let len = encoded_len(|b| append_allowed_ip(b, 0, ip, *remove));
                if used + len > SET_DEVICE_BUDGET {
                    break;
                }
                used += len;
                next += 1;
            }
            current.push(PeerPart {
                peer,
                first,
                ips: start..next,
            });
            if next == ips.len() {
                break;
            }
            messages.push(std::mem::take(&mut current));
            used = SET_DEVICE_OVERHEAD;
            first = false;
        }
    }
    messages.push(current);
    messages
}

/// One allowed-ip entry, nested under index `idx`; a removal carries
/// `WGALLOWEDIP_F_REMOVE_ME` (#529).
fn append_allowed_ip(builder: &mut MessageBuilder, idx: u16, allowed_ip: &AllowedIp, remove: bool) {
    let ip_token = builder.nest_start(idx | NLA_F_NESTED);
    builder.append_attr_u16(WgAllowedIpAttr::Family as u16, allowed_ip.family());
    builder.append_attr(WgAllowedIpAttr::IpAddr as u16, &allowed_ip.addr_bytes());
    builder.append_attr_u8(WgAllowedIpAttr::CidrMask as u16, allowed_ip.cidr);
    if remove {
        builder.append_attr_u32(WgAllowedIpAttr::Flags as u16, super::WGALLOWEDIP_F_REMOVE_ME);
    }
    builder.nest_end(ip_token);
}

/// One peer's part of a `SET_DEVICE` message, nested under index `idx`. A
/// continued peer (`!first`) carries its public key, its flags but
/// `REPLACE_ALLOWEDIPS` — that would drop what the earlier message added —
/// and its remaining allowed-ips.
fn append_peer_part(builder: &mut MessageBuilder, idx: u16, part: &PeerPart<'_>) {
    let peer = part.peer;
    let peer_token = builder.nest_start(idx | NLA_F_NESTED);

    builder.append_attr(WgPeerAttr::PublicKey as u16, peer.get_public_key());

    let mut flags = peer.get_flags();
    if !part.first {
        flags &= !(super::types::WgPeerFlags::ReplaceAllowedIps as u32);
    }
    if flags != 0 {
        builder.append_attr_u32(WgPeerAttr::Flags as u16, flags);
    }

    if part.first {
        if let Some(psk) = peer.get_preshared_key() {
            builder.append_attr(WgPeerAttr::PresharedKey as u16, psk);
        }
        if let Some(endpoint) = peer.get_endpoint() {
            let sockaddr_bytes = sockaddr_to_bytes(endpoint);
            builder.append_attr(WgPeerAttr::Endpoint as u16, &sockaddr_bytes);
        }
        if let Some(interval) = peer.get_persistent_keepalive() {
            builder.append_attr_u16(WgPeerAttr::PersistentKeepalive as u16, interval);
        }
    }

    let entries = peer.allowed_ip_entries();
    let ips = &entries[part.ips.clone()];
    if !ips.is_empty() {
        let ips_token = builder.nest_start(WgPeerAttr::AllowedIps as u16 | NLA_F_NESTED);
        for (ip_idx, (allowed_ip, remove)) in ips.iter().enumerate() {
            append_allowed_ip(builder, ip_idx as u16, allowed_ip, *remove);
        }
        builder.nest_end(ips_token);
    }

    builder.nest_end(peer_token);
}

/// Parse a single allowed IP's attributes.
fn parse_allowed_ip_attrs(data: &[u8]) -> Result<Option<AllowedIp>> {
    let mut family: Option<u16> = None;
    let mut addr_bytes: Option<&[u8]> = None;
    let mut cidr: Option<u8> = None;

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type {
            t if t == WgAllowedIpAttr::Family as u16 => {
                family = Some(get::u16_ne(payload)?);
            }
            t if t == WgAllowedIpAttr::IpAddr as u16 => {
                addr_bytes = Some(payload);
            }
            t if t == WgAllowedIpAttr::CidrMask as u16 => {
                cidr = Some(get::u8(payload)?);
            }
            _ => {}
        }
    }

    let (family, addr_bytes, cidr) = match (family, addr_bytes, cidr) {
        (Some(f), Some(a), Some(c)) => (f, a, c),
        _ => return Ok(None),
    };

    let addr = match family as i32 {
        libc::AF_INET if addr_bytes.len() >= 4 => IpAddr::V4(std::net::Ipv4Addr::new(
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        )),
        libc::AF_INET6 if addr_bytes.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr_bytes[..16]);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Ok(None),
    };

    Ok(Some(AllowedIp { addr, cidr }))
}

/// Convert a SocketAddr to kernel sockaddr bytes.
fn sockaddr_to_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            // struct sockaddr_in: family (2), port (2), addr (4), zero (8)
            let mut buf = vec![0u8; 16];
            buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            buf
        }
        SocketAddr::V6(v6) => {
            // struct sockaddr_in6: family (2), port (2), flowinfo (4), addr (16), scope_id (4)
            let mut buf = vec![0u8; 28];
            buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            buf[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            buf
        }
    }
}

/// Parse kernel sockaddr bytes to a SocketAddr.
fn parse_sockaddr(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }

    let family = u16::from_ne_bytes([data[0], data[1]]);
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family as i32 {
        libc::AF_INET if data.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if data.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            let scope_id = if data.len() >= 28 {
                u32::from_ne_bytes([data[24], data[25], data[26], data[27]])
            } else {
                0
            };
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// #529: a removal carries `WGALLOWEDIP_F_REMOVE_ME`; an addition
    /// carries no flags attribute.
    #[test]
    fn a_removed_allowed_ip_carries_the_remove_flag() {
        use crate::netlink::attr::AttrIter;
        let ip = AllowedIp::v4(std::net::Ipv4Addr::new(10, 1, 0, 0), 24);
        let flags_of = |remove| {
            let mut b = MessageBuilder::new(0, 0);
            append_allowed_ip(&mut b, 0, &ip, remove);
            let bytes = b.finish();
            let (_, nest) = AttrIter::new(&bytes[16..]).next().unwrap();
            AttrIter::new(nest)
                .find(|(t, _)| *t == WgAllowedIpAttr::Flags as u16)
                .map(|(_, v)| u32::from_ne_bytes(v.try_into().unwrap()))
        };
        assert_eq!(flags_of(true), Some(super::super::WGALLOWEDIP_F_REMOVE_ME));
        assert_eq!(flags_of(false), None);
    }

    use super::*;
    use crate::netlink::attr::{NLA_HDRLEN, NlAttr, nla_align};

    /// Build a minimal NLA buffer: [u16 len LE][u16 type LE][payload][pad to 4].
    fn make_attr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
        let hdr = NlAttr::new(attr_type, payload.len());
        let total = NLA_HDRLEN + payload.len();
        let aligned = nla_align(total);
        let mut buf = vec![0u8; aligned];
        buf[..NLA_HDRLEN].copy_from_slice(hdr.as_bytes());
        buf[NLA_HDRLEN..NLA_HDRLEN + payload.len()].copy_from_slice(payload);
        buf
    }

    /// Drive `parse_device_attr_scalar` via `AttrIter` over a single-attr buffer.
    fn parse_buf(buf: &[u8]) -> WgDevice {
        let mut device = WgDevice::default();
        for (attr_type, payload) in AttrIter::new(buf) {
            parse_device_attr_scalar(attr_type, payload, &mut device).unwrap();
        }
        device
    }

    #[test]
    fn parse_private_key_present() {
        let key = [0xCDu8; WG_KEY_LEN];
        let buf = make_attr(WgDeviceAttr::PrivateKey as u16, &key);
        let device = parse_buf(&buf);
        assert_eq!(device.private_key, Some(key));
    }

    #[test]
    fn parse_private_key_all_zero_is_none() {
        // Privileged read of a keyless device: the kernel emits 32 zero bytes.
        // All-zeros is not a usable key, so it normalizes to None (matching the
        // peer PresharedKey arm).
        let buf = make_attr(WgDeviceAttr::PrivateKey as u16, &[0u8; WG_KEY_LEN]);
        let device = parse_buf(&buf);
        assert_eq!(device.private_key, None);
    }

    #[test]
    fn parse_public_key_present_and_all_zero() {
        let key = [0xCDu8; WG_KEY_LEN];
        let buf = make_attr(WgDeviceAttr::PublicKey as u16, &key);
        assert_eq!(parse_buf(&buf).public_key, Some(key));

        // Keyless device: same all-zeros-to-None normalization as private_key.
        let zero = make_attr(WgDeviceAttr::PublicKey as u16, &[0u8; WG_KEY_LEN]);
        assert_eq!(parse_buf(&zero).public_key, None);
    }

    #[test]
    fn parse_private_key_short_payload_ignored() {
        // payload shorter than WG_KEY_LEN — length guard must hold, no panic
        let short = [0xCDu8; WG_KEY_LEN - 1];
        let buf = make_attr(WgDeviceAttr::PrivateKey as u16, &short);
        let device = parse_buf(&buf);
        assert_eq!(device.private_key, None);
    }

    #[test]
    fn parse_private_key_absent() {
        // Buffer with only a ListenPort attr — no PrivateKey attr at all
        let port: u16 = 51820;
        let buf = make_attr(WgDeviceAttr::ListenPort as u16, &port.to_ne_bytes());
        let device = parse_buf(&buf);
        assert_eq!(device.private_key, None);
        assert_eq!(device.listen_port, Some(51820));
    }

    #[test]
    fn parse_private_key_oversize_payload_uses_first_32() {
        // Future kernel that ships a >32-byte key payload (e.g. a TLV
        // tail or an unrelated forward-grow). The length guard accepts
        // anything ≥ WG_KEY_LEN and reads only the first 32 bytes —
        // CLAUDE.md parser-robustness rule 1 (accept-larger-than-expected
        // on fixed-size structs).
        let key = [0xCDu8; WG_KEY_LEN];
        let mut payload = key.to_vec();
        payload.extend_from_slice(&[0xFFu8; 8]); // 8 trailing bytes the parser must ignore
        let buf = make_attr(WgDeviceAttr::PrivateKey as u16, &payload);
        let device = parse_buf(&buf);
        assert_eq!(device.private_key, Some(key));
    }

    #[test]
    fn test_sockaddr_v4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820));
        let bytes = sockaddr_to_bytes(&addr);
        let parsed = parse_sockaddr(&bytes).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_sockaddr_v6_roundtrip() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            51820,
            0,
            0,
        ));
        let bytes = sockaddr_to_bytes(&addr);
        let parsed = parse_sockaddr(&bytes).unwrap();
        assert_eq!(addr, parsed);
    }

    fn peer(
        n: u32,
        ips: impl IntoIterator<Item = AllowedIp>,
    ) -> super::super::types::WgPeerBuilder {
        let mut key = [0u8; WG_KEY_LEN];
        key[..4].copy_from_slice(&n.to_be_bytes());
        super::super::types::WgPeerBuilder::new(key)
            .replace_allowed_ips()
            .allowed_ips(ips)
    }

    /// The peers nest of one planned message, as `apply_device_config`
    /// writes it.
    fn encode(message: &[PeerPart<'_>]) -> MessageBuilder {
        let mut b = MessageBuilder::new(0, 0);
        let peers = b.nest_start(WgDeviceAttr::Peers as u16 | NLA_F_NESTED);
        for (idx, part) in message.iter().enumerate() {
            append_peer_part(&mut b, idx as u16, part);
        }
        b.nest_end(peers);
        b
    }

    /// #500: every peer went into one `WGDEVICE_A_PEERS` nest, which a u16
    /// `nla_len` cannot describe past ~400 peers or ~1,600 IPv6 allowed-ips
    /// on one peer. The plan splits them, every message fits, and every
    /// peer and allowed-ip is sent exactly once.
    #[test]
    fn a_large_peer_set_is_split_across_messages_that_fit() {
        let mut peers: Vec<_> = (0..1000)
            .map(|n| peer(n, [AllowedIp::v4(Ipv4Addr::from(0x0a00_0000 + n), 32)]))
            .collect();
        let v6 = (0..3000u32)
            .map(|n| AllowedIp::v6(Ipv6Addr::from(0xfd00_u128 << 112 | u128::from(n)), 128));
        peers.push(peer(1000, v6));

        let plan = plan_set_device(&peers);
        assert!(plan.len() > 2, "{} messages", plan.len());
        let mut seen = vec![0usize; peers.len()];
        for message in &plan {
            let encoded = encode(message);
            assert_eq!(encoded.oversized_nest(), None);
            assert!(
                encoded.len() <= SET_DEVICE_BUDGET,
                "{} bytes",
                encoded.len()
            );
            for part in message {
                let i = peers
                    .iter()
                    .position(|p| std::ptr::eq(p, part.peer))
                    .unwrap();
                assert_eq!(
                    part.first,
                    part.ips.start == 0,
                    "peer {i}: first is its first part"
                );
                assert_eq!(
                    part.ips.start, seen[i],
                    "peer {i}: contiguous, no gap or repeat"
                );
                seen[i] = part.ips.end;
            }
        }
        for (i, p) in peers.iter().enumerate() {
            assert_eq!(
                seen[i],
                p.get_allowed_ips().len(),
                "peer {i}: every allowed-ip sent"
            );
        }
        // A continued peer does not replace what its first part added.
        let continued = plan
            .iter()
            .flatten()
            .find(|p| !p.first)
            .expect("the big peer continues");
        let encoded = encode(std::slice::from_ref(continued));
        let flags_attr = WgPeerAttr::Flags as u16;
        let peers_payload = &encoded.as_bytes()[16 + 4..];
        let peer_payload = crate::netlink::attr::AttrIter::new(peers_payload)
            .next()
            .unwrap()
            .1;
        let flags =
            crate::netlink::attr::AttrIter::new(peer_payload).find(|(t, _)| *t == flags_attr);
        assert!(
            flags.is_none(),
            "REPLACE_ALLOWEDIPS must not be repeated: {flags:?}"
        );
    }

    /// No peers: still one message, for the device's own settings.
    #[test]
    fn a_device_with_no_peers_is_one_message() {
        let plan = plan_set_device(&[]);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].is_empty());
    }

    /// #500: a nest past `nla_len` is refused before it is sent, in every
    /// build — it was a debug-only panic and a clamped header in release.
    #[tokio::test]
    async fn an_oversized_nest_is_refused() {
        let conn = Connection::<crate::netlink::Route>::new().expect("socket");
        let mut b = MessageBuilder::new(0, 0);
        let nest = b.nest_start(1 | NLA_F_NESTED);
        for _ in 0..2_000 {
            b.append_attr(2, &[0u8; 36]); // 40 bytes each, like a key
        }
        b.nest_end(nest);
        assert!(b.oversized_nest().is_some_and(|len| len > 80_000));
        let err = conn.send_ack(b).await.expect_err("oversized");
        assert!(err.to_string().contains("65535"), "{err}");
    }
}
