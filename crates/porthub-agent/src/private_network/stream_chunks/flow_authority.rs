//! Local authoritative half of authenticated flow-open. Remote epoch labels
//! delineate a pinned-TLS context; they never substitute for local authority.
use super::*;
use crate::private_network::sparse;
use porthub_network::{
    policy::pair_acl::{CompiledPortMask, PairAcl},
    tcp_stream,
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Initiator,
    Acceptor,
}
#[derive(Clone)]
pub(crate) struct LocalAuthority {
    workspace: String,
    local: Peer,
    peer: Peer,
    epoch: [u8; 32],
    outgoing: CompiledPortMask,
    incoming: CompiledPortMask,
    permit: SendPermit,
}
fn epoch(raw: &str) -> Result<[u8; 32]> {
    ensure!(
        raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "noncanonical local authority epoch"
    );
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}
fn peer(info: &porthub_network::policy::PeerInfo) -> Peer {
    Peer {
        id: info.id.clone(),
        ip: info.ip,
        fingerprint: info.fingerprint.clone(),
        instance: info.instance.clone(),
    }
}
impl LocalAuthority {
    pub(crate) fn capture(
        handle: &sparse::Handle,
        workspace: &str,
        own: &str,
        remote: &str,
    ) -> Result<Self> {
        let view = handle
            .bound_pair_authority(remote)
            .ok_or_else(|| anyhow::anyhow!("flow pair authority unavailable"))?;
        let lease = view.lease();
        ensure!(
            lease.workspace == workspace
                && lease.self_ == own
                && lease.local.id == own
                && lease.peer.id == remote
                && own != remote,
            "flow authority identity/workspace mismatch"
        );
        let acl = match &lease.acl {
            Some(acl) => acl.clone(),
            None => PairAcl::from_grants(own, remote, &lease.grants)?,
        }
        .compile()?;
        let permit = view.permit();
        ensure!(
            permit.remaining().is_some(),
            "flow authority has no original bounded request"
        );
        Ok(Self {
            workspace: workspace.into(),
            local: peer(&lease.local),
            peer: peer(&lease.peer),
            epoch: epoch(&lease.epoch)?,
            outgoing: acl.tcp(false),
            incoming: acl.tcp(true),
            permit,
        })
    }
    pub(super) fn original(&self) -> SendPermit {
        self.permit.clone()
    }
    pub(super) fn bind_transport(
        &self,
        remote: &Peer,
        local: std::net::Ipv4Addr,
        belongs: bool,
    ) -> Result<()> {
        ensure!(
            *remote == self.peer
                && local == self.local.ip
                && belongs
                && self.permit.remaining().is_some(),
            "flow-open transport identity/factory mismatch"
        );
        Ok(())
    }
    pub(crate) fn local_epoch(&self) -> [u8; 32] {
        self.epoch
    }
}
/// Sealed at the synchronous kernel-packet admission boundary. A caller cannot
/// relabel an opaque permit or another peer's SYN after flow-open has waited.
pub(crate) struct PendingSyn {
    local: LocalAuthority,
    bytes: Bytes,
    flow: tcp_stream::Flow,
    nonce: [u8; 16],
}
impl LocalAuthority {
    pub(crate) fn admit_syn(&self, bytes: Bytes) -> Result<PendingSyn> {
        let flow = tcp_stream::tagged::validate_syn(&bytes)?;
        ensure!(
            *flow.source.ip() == self.local.ip
                && *flow.destination.ip() == self.peer.ip
                && self.outgoing.contains(flow.destination.port())
                && self.permit.remaining().is_some(),
            "native SYN identity/service/original denied"
        );
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("native SYN nonce unavailable"))?;
        ensure!(nonce != [0; 16], "invalid native SYN nonce");
        Ok(PendingSyn {
            local: self.clone(),
            bytes,
            flow,
            nonce,
        })
    }
}
impl PendingSyn {
    pub(super) fn parameters(&self) -> ([u8; 16], u16, u16) {
        (
            self.nonce,
            self.flow.source.port(),
            self.flow.destination.port(),
        )
    }
    pub(super) fn bind_current(&self, current: &LocalAuthority) -> Result<SendPermit> {
        ensure!(
            self.local.workspace == current.workspace
                && self.local.local == current.local
                && self.local.peer == current.peer
                && self.local.epoch == current.epoch
                && current.outgoing.contains(self.flow.destination.port()),
            "native SYN current pair/epoch changed while queued"
        );
        let permit = SendPermit::combine(vec![self.local.original(), current.original()]);
        ensure!(
            permit.remaining().is_some(),
            "native SYN original admission retired"
        );
        Ok(permit)
    }
    pub(super) async fn prepare(
        self,
        context: &Context,
        handle: &tcp_stream::tagged::Handle,
        opening: SendPermit,
    ) -> Result<tcp_stream::tagged::PendingConnection> {
        ensure!(
            context.parameters() == self.parameters()
                && context.source_native_tuple(Side::Initiator) == self.flow.reverse(),
            "native SYN does not own opened context/tuple"
        );
        let original = context.authorize(&self.local, Side::Initiator)?;
        let permit = SendPermit::combine(vec![original, opening]);
        permit
            .during(handle.prepare_syn(self.bytes, permit.clone()))
            .await?
    }
}

#[derive(Clone)]
pub(crate) struct Context {
    workspace: String,
    initiator: Peer,
    acceptor: Peer,
    initiator_epoch: [u8; 32],
    acceptor_epoch: [u8; 32],
    nonce: [u8; 16],
    source_port: u16,
    destination_port: u16,
    digest: [u8; 32],
}
fn hash_text(hash: &mut Sha256, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}
fn hash_peer(hash: &mut Sha256, peer: &Peer) {
    hash_text(hash, &peer.id);
    hash.update(peer.ip.octets());
    hash_text(hash, &peer.fingerprint);
    hash_text(hash, &peer.instance);
}
impl Context {
    pub(crate) fn from_local(
        local: &LocalAuthority,
        side: Side,
        remote_epoch: [u8; 32],
        nonce: [u8; 16],
        source_port: u16,
        destination_port: u16,
    ) -> Result<Self> {
        ensure!(
            nonce != [0; 16]
                && source_port != 0
                && destination_port != 0
                && local.epoch != [0; 32]
                && remote_epoch != [0; 32],
            "invalid flow-open context"
        );
        ensure!(local.permit.valid(), "local flow authority retired");
        let (initiator, acceptor, initiator_epoch, acceptor_epoch) = match side {
            Side::Initiator => (
                local.local.clone(),
                local.peer.clone(),
                local.epoch,
                remote_epoch,
            ),
            Side::Acceptor => (
                local.peer.clone(),
                local.local.clone(),
                remote_epoch,
                local.epoch,
            ),
        };
        let mut hash = Sha256::new();
        hash.update(b"porthub-authenticated-flow-v2\0");
        hash_text(&mut hash, &local.workspace);
        hash_peer(&mut hash, &initiator);
        hash_peer(&mut hash, &acceptor);
        hash.update(initiator_epoch);
        hash.update(acceptor_epoch);
        hash.update(nonce);
        hash.update(source_port.to_be_bytes());
        hash.update(destination_port.to_be_bytes());
        let context = Self {
            workspace: local.workspace.clone(),
            initiator,
            acceptor,
            initiator_epoch,
            acceptor_epoch,
            nonce,
            source_port,
            destination_port,
            digest: hash.finalize().into(),
        };
        context.authorize(local, side)?;
        Ok(context)
    }
    pub(super) fn remote_peer(&self, side: Side) -> Peer {
        match side {
            Side::Initiator => self.acceptor.clone(),
            Side::Acceptor => self.initiator.clone(),
        }
    }
    pub(super) fn parameters(&self) -> ([u8; 16], u16, u16) {
        (self.nonce, self.source_port, self.destination_port)
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn authorize(&self, local: &LocalAuthority, side: Side) -> Result<SendPermit> {
        let (own, remote, expected_epoch, ports) = match side {
            Side::Initiator => (
                &self.initiator,
                &self.acceptor,
                self.initiator_epoch,
                &local.outgoing,
            ),
            Side::Acceptor => (
                &self.acceptor,
                &self.initiator,
                self.acceptor_epoch,
                &local.incoming,
            ),
        };
        ensure!(
            self.workspace == local.workspace
                && *own == local.local
                && *remote == local.peer
                && expected_epoch == local.epoch,
            "flow-open context no longer matches local identity/epoch"
        );
        ensure!(
            ports.contains(self.destination_port) && local.permit.remaining().is_some(),
            "flow-open TCP service denied or expired"
        );
        Ok(local.permit.clone())
    }
    pub(crate) fn data_flow(&self, sender: Side) -> Flow {
        let (local_port, remote_port, direction) = match sender {
            Side::Initiator => (self.source_port, self.destination_port, 0),
            Side::Acceptor => (self.destination_port, self.source_port, 1),
        };
        Flow {
            nonce: self.nonce,
            direction,
            local_port,
            remote_port,
            epoch: self.digest,
        }
    }
    pub(crate) fn source_native_tuple(&self, sender: Side) -> tcp_stream::Flow {
        // A native source reader observes traffic INCOMING to its proxy leg.
        let (source, destination) = match sender {
            Side::Initiator => (
                std::net::SocketAddrV4::new(self.acceptor.ip, self.destination_port),
                std::net::SocketAddrV4::new(self.initiator.ip, self.source_port),
            ),
            Side::Acceptor => (
                std::net::SocketAddrV4::new(self.initiator.ip, self.source_port),
                std::net::SocketAddrV4::new(self.acceptor.ip, self.destination_port),
            ),
        };
        tcp_stream::Flow {
            source,
            destination,
        }
    }
    pub(crate) fn receiver_access(
        &self,
        local: &LocalAuthority,
        side: Side,
    ) -> Result<super::receiver::Access> {
        let permit = self.authorize(local, side)?;
        let ports = match side {
            Side::Initiator => local.outgoing.clone(),
            Side::Acceptor => local.incoming.clone(),
        };
        Ok(super::receiver::Access {
            peer: local.peer.clone(),
            epoch: self.digest,
            ports,
            permit,
        })
    }
    pub(crate) fn bind_source(
        &self,
        local: &LocalAuthority,
        side: Side,
        connection: &BoundedSourceConnection,
        gate: &Gate,
        native: &porthub_network::tcp_stream::tagged::Connection,
    ) -> Result<SendPermit> {
        let authority = self.authorize(local, side)?;
        ensure!(
            connection.peer() == &local.peer
                && connection.local_ip() == local.local.ip
                && connection.belongs_to(&gate.factory)
                && native.flow() == self.source_native_tuple(side),
            "flow source peer/factory/native tuple mismatch"
        );
        Ok(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_network::{
        authority_clock::{RequestWindow, SuspendClock},
        authority_event::Authority,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn capture(
        own: &str,
        remote: &str,
        label: &str,
        clock: Arc<Clock>,
    ) -> (sparse::Handle, LocalAuthority) {
        let descriptor = |id: &str| serde_json::json!({"id":id,"ip":if id=="a"{"10.203.0.2"}else{"10.203.1.2"},"fingerprint":format!("fp-{id}"),"instance":format!("instance-{id}"),"hostname":format!("{id}.phub")} );
        let expiry = chrono::Utc::now() + chrono::Duration::seconds(60);
        let epoch = label.repeat(64);
        let snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":own,"revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":epoch},"peers":[descriptor(own)],"grants":[]})).unwrap();
        let lease=serde_json::from_value(serde_json::json!({"workspace":"w","self":own,"epoch":epoch,"revision":1,"expires_at":expiry,"local":descriptor(own),"peer":descriptor(remote),"grants":[{"source":"a","destination":"b","protocol":"any","ports":[]}]})).unwrap();
        let authority = || {
            Authority::new(
                (),
                Some(RequestWindow::start(clock.clone()).unwrap()),
                expiry,
            )
        };
        let (handle, _) = sparse::channel();
        handle.update_base_authority(&snapshot, authority());
        handle.installed_authority(
            &porthub_network::policy::Lookup {
                kind: "peer".into(),
                value: remote.into(),
            },
            lease,
            authority(),
        );
        let local = LocalAuthority::capture(&handle, "w", own, remote).unwrap();
        (handle, local)
    }
    #[test]
    fn reciprocal_local_epochs_bind_same_context_without_granting_remote_authority() {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let (a_handle, a) = capture("a", "b", "a", clock.clone());
        let (_b_handle, b) = capture("b", "a", "b", clock.clone());
        assert_ne!(a.local_epoch(), b.local_epoch());
        let left =
            Context::from_local(&a, Side::Initiator, b.local_epoch(), [7; 16], 42000, 443).unwrap();
        let right =
            Context::from_local(&b, Side::Acceptor, a.local_epoch(), [7; 16], 42000, 443).unwrap();
        assert_eq!(left.digest(), right.digest());
        assert!(left.authorize(&b, Side::Acceptor).is_ok());
        let wrong = Context::from_local(&a, Side::Initiator, [9; 32], [7; 16], 42000, 443).unwrap();
        assert_ne!(left.digest(), wrong.digest());
        assert!(wrong.authorize(&b, Side::Acceptor).is_err());
        assert!(left.authorize(&a, Side::Acceptor).is_err());
        a_handle.revoke_all();
        assert!(left.authorize(&a, Side::Initiator).is_err());
        clock.0.store(15000, Ordering::SeqCst);
        assert!(right.authorize(&b, Side::Acceptor).is_err());
    }
    #[test]
    fn context_binds_each_identity_port_nonce_and_service_direction() {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let (_a_handle, a) = capture("a", "b", "a", clock.clone());
        let (_b_handle, b) = capture("b", "a", "b", clock);
        let make = |nonce, port| {
            Context::from_local(&a, Side::Initiator, b.local_epoch(), nonce, 42000, port).unwrap()
        };
        let c = make([1; 16], 443);
        assert_ne!(c.digest(), make([2; 16], 443).digest());
        assert_ne!(c.digest(), make([1; 16], 80).digest());
        assert!(
            Context::from_local(&b, Side::Initiator, a.local_epoch(), [1; 16], 42000, 443).is_err(),
            "reply permission cannot authorize reverse initiation"
        );
        assert_eq!(
            c.data_flow(Side::Initiator).epoch,
            c.data_flow(Side::Acceptor).epoch
        );
        assert_ne!(
            c.source_native_tuple(Side::Initiator),
            c.source_native_tuple(Side::Acceptor)
        );
    }
    #[tokio::test]
    async fn actual_native_syn_owns_peer_tuple_and_original_queued_admission() -> Result<()> {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let (_ha, a) = capture("a", "b", "a", clock.clone());
        let (_hb, b) = capture("b", "a", "b", clock.clone());
        let (handle, mut output, runner) = tcp_stream::stack()?;
        let stop = CancellationToken::new();
        let running = tokio::spawn(runner.run(stop.clone()));
        let flow = tcp_stream::Flow {
            source: "10.203.0.2:42000".parse()?,
            destination: "10.203.1.2:443".parse()?,
        };
        let connecting = tokio::spawn(async move { handle.connect(flow).await });
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let result = (|| -> Result<()> {
            let syn = a.admit_syn(bytes.clone())?;
            ensure!(
                syn.flow == flow && syn.parameters().1 == 42000 && syn.parameters().2 == 443,
                "native SYN tuple was relabeled"
            );
            ensure!(
                b.admit_syn(bytes.clone()).is_err(),
                "foreign pair adopted SYN"
            );
            let mut invalid = bytes.to_vec();
            invalid[0] = 0;
            ensure!(
                a.admit_syn(invalid.into()).is_err(),
                "malformed SYN opened authority"
            );
            let mut changed = a.clone();
            changed.peer.instance = "replacement".into();
            ensure!(
                syn.bind_current(&changed).is_err(),
                "peer replacement adopted queued SYN"
            );
            clock.0.store(15000, Ordering::SeqCst);
            let (_fresh_handle, fresh) = capture("a", "b", "a", clock.clone());
            ensure!(
                syn.bind_current(&fresh).is_err(),
                "fresh pair publication renewed queued original SYN"
            );
            Ok(())
        })();
        stop.cancel();
        connecting.abort();
        let _ = connecting.await;
        tokio::time::timeout(std::time::Duration::from_secs(1), running).await???;
        result
    }
}
