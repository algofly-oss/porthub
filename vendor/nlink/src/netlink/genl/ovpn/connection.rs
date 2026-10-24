//! `Connection<Ovpn>` helper methods.
//!
//! Thin wrappers over the generic
//! [`Connection::send_typed`][crate::netlink::Connection::send_typed]
//! / [`dump_typed_stream`][crate::netlink::Connection::dump_typed_stream]
//! dispatch the `#[derive(GenlMessage)]` + `#[genl_family]` machinery
//! provides.
//!
//! # Socket attachment
//!
//! The kernel's `peer-new`/`peer-set` GENL commands take an
//! `OVPN_A_PEER_SOCKET` u32 attribute — the fd of a UDP/TCP socket,
//! resolved by the kernel via `sockfd_lookup` in the **calling
//! process**. Since fds are process-global (not netns-scoped), a
//! controller process that holds the fd can attach it regardless of
//! which netns the socket was created in; for the kernel to interpret
//! the socket's namespace it also accepts `OVPN_A_PEER_SOCKET_NETNSID`.
//! See [`Connection::<Ovpn>::attach_socket`] /
//! [`attach_socket_in_netns`](Connection::<Ovpn>::attach_socket_in_netns).
//!
//! (#136 originally specified an `SCM_RIGHTS` sendmsg path here; that
//! was a misreading of the protocol — netlink genl handlers never
//! consume `SCM_RIGHTS` fds. The general
//! [`NetlinkSocket::send_with_fds`](crate::netlink::NetlinkSocket::send_with_fds)
//! primitive still ships for protocols that do.)

use std::os::fd::{AsFd, AsRawFd, RawFd};

use super::Ovpn;
use crate::{
    macros::GenlTypedDumpStream,
    netlink::{
        Connection,
        error::{Error, Result},
        genl::ovpn::{
            messages::{
                OvpnKeyDelRequest, OvpnKeyGetRequest, OvpnKeyNewRequest, OvpnKeyReply,
                OvpnKeySwapRequest, OvpnKeyconf, OvpnPeer, OvpnPeerDelRequest, OvpnPeerGetRequest,
                OvpnPeerNewRequest, OvpnPeerReply, OvpnPeerSetRequest,
            },
            types::OvpnKeySlot,
        },
    },
};

#[nlink_macros::send_futures]
impl Connection<Ovpn> {
    // ============================================================
    // Peer operations
    // ============================================================

    /// Install a new peer on the ovpn interface.
    ///
    /// `peer.id` must be set and unique among the interface's
    /// peers. The peer's UDP/TCP socket can be specified via
    /// `peer.socket` (a fd in the caller's process) and, for a socket
    /// in another network namespace, `peer.socket_netnsid`. To attach a
    /// socket to a peer after creation, see [`Self::attach_socket`].
    pub async fn peer_new(&self, ifindex: u32, peer: OvpnPeer) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerNewRequest::new(ifindex, peer))
            .await?;
        Ok(())
    }

    /// Modify an existing peer. Only set fields are applied; the
    /// kernel preserves prior values for omitted attributes.
    pub async fn peer_set(&self, ifindex: u32, peer: OvpnPeer) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerSetRequest::new(ifindex, peer))
            .await?;
        Ok(())
    }

    /// Query a single peer by ID. Returns
    /// `Error::is_not_found()` if no peer with that ID exists on
    /// the interface.
    pub async fn peer_get(&self, ifindex: u32, peer_id: u32) -> Result<OvpnPeer> {
        let reply: OvpnPeerReply = self
            .send_typed(OvpnPeerGetRequest::by_id(ifindex, peer_id))
            .await?;
        reply.peer.ok_or_else(|| {
            Error::invalid_message(format!(
                "peer_get(ifindex={ifindex}, peer_id={peer_id}): kernel reply missing OVPN_A_PEER"
            ))
        })
    }

    /// Dump every peer on the ovpn interface. On an interface
    /// with no peers, returns an empty vector.
    pub async fn peer_dump(&self, ifindex: u32) -> Result<Vec<OvpnPeer>> {
        use tokio_stream::StreamExt;
        let mut stream: GenlTypedDumpStream<'_, Ovpn, OvpnPeerReply> = self
            .dump_typed_stream(OvpnPeerGetRequest::dump(ifindex))
            .await?;
        let mut out = Vec::new();
        while let Some(reply) = stream.next().await {
            let reply = reply?;
            if let Some(peer) = reply.peer {
                out.push(peer);
            }
        }
        Ok(out)
    }

    /// Delete a peer. The kernel emits a `peer-del-ntf` on the
    /// `peers` multicast group after the delete completes.
    pub async fn peer_del(&self, ifindex: u32, peer_id: u32) -> Result<()> {
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerDelRequest::new(ifindex, peer_id))
            .await?;
        Ok(())
    }

    // ============================================================
    // Key operations
    // ============================================================

    /// Install a cipher key for `(peer_id, slot)`. The key bytes
    /// in `keyconf.encrypt_dir` / `.decrypt_dir` are write-only
    /// — `key_get` never returns them.
    ///
    /// The `cipher_alg` and `key_id` fields must be set; the
    /// kernel rejects requests missing either.
    pub async fn key_new(&self, ifindex: u32, keyconf: OvpnKeyconf) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeyNewRequest::new(ifindex, keyconf))
            .await?;
        Ok(())
    }

    /// Read non-sensitive metadata about an installed key
    /// (cipher_alg, key_id, slot). Returns `Error::is_not_found()`
    /// if no key is installed at that slot.
    pub async fn key_get(
        &self,
        ifindex: u32,
        peer_id: u32,
        slot: OvpnKeySlot,
    ) -> Result<OvpnKeyconf> {
        let reply: OvpnKeyReply = self
            .send_typed(OvpnKeyGetRequest::new(ifindex, peer_id, slot))
            .await?;
        reply.keyconf.ok_or_else(|| {
            Error::invalid_message(format!(
                "key_get(ifindex={ifindex}, peer_id={peer_id}, slot={slot:?}): \
                 kernel reply missing OVPN_A_KEYCONF"
            ))
        })
    }

    /// Atomically swap the primary and secondary key slots for
    /// `peer_id`. This is the rekey cutover point — OpenVPN 2.7
    /// installs the new key into the secondary slot then calls
    /// `key_swap` to activate it without dropping a single packet.
    pub async fn key_swap(&self, ifindex: u32, peer_id: u32) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeySwapRequest::new(ifindex, peer_id))
            .await?;
        Ok(())
    }

    /// Delete the cipher key at `(peer_id, slot)`. Returns
    /// `Error::is_not_found()` if no key is installed there.
    pub async fn key_del(&self, ifindex: u32, peer_id: u32, slot: OvpnKeySlot) -> Result<()> {
        let _: OvpnKeyReply = self
            .send_typed(OvpnKeyDelRequest::new(ifindex, peer_id, slot))
            .await?;
        Ok(())
    }

    // ============================================================
    // Socket attachment
    // ============================================================

    /// Attach a transport socket to the peer identified by `peer_id`.
    ///
    /// Issues a `peer-set` carrying `OVPN_A_PEER_SOCKET = fd`. The
    /// kernel resolves the fd via `sockfd_lookup` in the **calling
    /// process** (file descriptors are process-global, not netns-scoped),
    /// so this works whenever the current process holds the fd —
    /// including a controller process that created the socket in a
    /// different network namespace than the ovpn interface lives in.
    ///
    /// For a socket whose namespace the kernel must be told about
    /// explicitly, use [`Self::attach_socket_in_netns`].
    ///
    /// # Note — SCM_RIGHTS is *not* the mechanism here
    ///
    /// #136 originally framed this as an `SCM_RIGHTS` sendmsg control
    /// message. That premise was wrong: netlink generic-command handlers
    /// never receive `SCM_RIGHTS` file descriptors, and the upstream
    /// ovpn netlink spec passes the socket as the plain `OVPN_A_PEER_SOCKET`
    /// u32 attribute (+ `OVPN_A_PEER_SOCKET_NETNSID` for cross-netns).
    /// A general [`NetlinkSocket::send_with_fds`](crate::netlink::NetlinkSocket::send_with_fds)
    /// SCM_RIGHTS primitive still ships for protocols that genuinely
    /// consume passed fds.
    pub async fn attach_socket(&self, ifindex: u32, peer_id: u32, fd: impl AsFd) -> Result<()> {
        self.attach_socket_inner(ifindex, peer_id, fd.as_fd().as_raw_fd(), None)
            .await
    }

    /// Attach a transport socket that lives in the network namespace
    /// identified by `netnsid`.
    ///
    /// Issues a `peer-set` carrying `OVPN_A_PEER_SOCKET = fd` plus
    /// `OVPN_A_PEER_SOCKET_NETNSID = netnsid`. `netnsid` is a namespace
    /// id as assigned by `RTM_NEWNSID` / `ip netns set` and is resolved
    /// by the kernel relative to the caller's netns. This is the
    /// kernel-blessed cross-namespace socket-attach path.
    pub async fn attach_socket_in_netns(
        &self,
        ifindex: u32,
        peer_id: u32,
        fd: impl AsFd,
        netnsid: i32,
    ) -> Result<()> {
        self.attach_socket_inner(ifindex, peer_id, fd.as_fd().as_raw_fd(), Some(netnsid))
            .await
    }

    async fn attach_socket_inner(
        &self,
        ifindex: u32,
        peer_id: u32,
        fd: RawFd,
        netnsid: Option<i32>,
    ) -> Result<()> {
        let mut peer = OvpnPeer::identity(peer_id);
        peer.socket = Some(fd as u32);
        peer.socket_netnsid = netnsid;
        let _: OvpnPeerReply = self
            .send_typed(OvpnPeerSetRequest::new(ifindex, peer))
            .await?;
        Ok(())
    }
}
