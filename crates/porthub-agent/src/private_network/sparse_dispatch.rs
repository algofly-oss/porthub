//! Portable, experimental sparse flow owner. This configures no host interface,
//! resolver, route, listener or service. Callers retain native route ownership.
//! Control installation accepts only envelopes minted by the real controller;
//! it cannot mint a new request-start witness from serialized policy bytes.
use super::{
    controller::Event,
    policy::{Engine, PairLease, PeerInfo, Snapshot},
    sparse,
    stream_chunks::{flow_authority::LocalAuthority, flow_runtime},
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_mesh::Identity;
use std::{future::Future, net::Ipv4Addr, sync::Arc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Node {
    inner: flow_runtime::Runtime,
    handle: sparse::Handle,
    workspace: String,
    own: String,
    fingerprint: String,
    owner: CancellationToken,
}
pub struct Runner(flow_runtime::Background);
/// A route installer may inspect these immutable admitted values. Returning
/// success attests only its OWN route work, not application or native readiness.
/// It must roll back its own partial native operations on failure.
pub enum Routes {
    Base(Snapshot),
    Pair(PairLease),
    Retire(PeerInfo),
}
pub enum Installed {
    Base(Snapshot),
    Pair(PeerInfo),
    Unavailable,
}
impl Node {
    pub fn new(
        workspace: String,
        own: String,
        identity: Identity,
        handle: sparse::Handle,
        events: mpsc::Sender<Event>,
        cancel: CancellationToken,
    ) -> Result<(Self, Runner)> {
        let fingerprint = identity.fingerprint().to_owned();
        let (lookup, space, local) = (handle.clone(), workspace.clone(), own.clone());
        let current = Arc::new(move |peer: &str| {
            LocalAuthority::capture(&lookup, &space, &local, peer)
                .ok()
                .map(Arc::new)
        });
        let lookup = handle.clone();
        let request = Arc::new(move |peer: &str| {
            lookup.request_peer(peer);
        });
        let (inner, runner) =
            flow_runtime::Runtime::new(identity, current, request, events, cancel.clone())?;
        Ok((
            Self {
                inner,
                handle,
                workspace,
                own,
                fingerprint,
                owner: cancel,
            },
            Runner(runner),
        ))
    }
    /// This belongs after the caller's outbound packet-policy check. Existing
    /// owned tuples retain their original choice even if preference changes.
    pub fn kernel_packet(&self, peer: &str, packet: Bytes, prefer_stream: bool) -> bool {
        if self.owner.is_cancelled() {
            return true;
        }
        self.inner.kernel_packet(peer, packet, prefer_stream)
    }
    /// The peer ID and address MUST come from authenticated Session/relay
    /// ingress. PHG2 metadata alone never establishes either identity.
    pub fn receive(&self, peer: &str, source: Ipv4Addr, payload: Bytes) -> Result<bool> {
        if self.owner.is_cancelled() {
            return Ok(false);
        }
        Ok(self.inner.receive(peer, source, payload)?
            == super::stream_chunks::dispatch::Outcome::Delivered)
    }
    pub fn raw_ingress(&self, packet: &[u8]) -> bool {
        !self.owner.is_cancelled() && self.inner.raw_ingress(packet)
    }
    pub fn counts(&self) -> (usize, usize) {
        self.inner.counts()
    }
    /// Serial control-owner boundary. `&mut Engine` prevents that owner's
    /// packet checks from racing route preparation. The Handle publishes pair
    /// authority only AFTER route success and a second immutable-witness check.
    /// Errors fail closed; this is not permission to waive native route audits.
    pub async fn install_control<F, Fut>(
        &self,
        event: Event,
        policy: &mut Engine,
        install_routes: F,
    ) -> Result<Installed>
    where
        F: FnOnce(Routes) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        ensure!(
            !self.owner.is_cancelled() && !self.handle.revoked(),
            "sparse node owner retired"
        );
        match event {
            Event::Snapshot(authority) => {
                authority.check()?;
                ensure!(
                    authority.remaining()?.is_some(),
                    "base request-start bound missing"
                );
                let snapshot = authority.accepted()?.clone();
                ensure!(
                    snapshot.workspace == self.workspace
                        && snapshot.self_ == self.own
                        && snapshot.sparse.is_some(),
                    "sparse node control identity/mode mismatch"
                );
                ensure!(
                    snapshot
                        .peers
                        .iter()
                        .any(|peer| peer.id == self.own && peer.fingerprint == self.fingerprint),
                    "sparse node certificate identity mismatch"
                );
                policy.apply(snapshot.clone())?;
                let result = authority
                    .during(install_routes(Routes::Base(snapshot.clone())))
                    .await
                    .and_then(|()| {
                        authority.check()?;
                        ensure!(
                            !self.owner.is_cancelled() && !self.handle.revoked(),
                            "sparse node owner retired during route install"
                        );
                        Ok(())
                    });
                if let Err(error) = result {
                    policy.revoke();
                    self.handle.revoke_all();
                    return Err(error);
                }
                authority.check()?;
                self.handle
                    .update_base_authority(&snapshot, authority.retained());
                Ok(Installed::Base(snapshot))
            }
            Event::Pair(authority) => {
                authority.check()?;
                ensure!(
                    authority.remaining()?.is_some(),
                    "pair request-start bound missing"
                );
                let response = authority.accepted()?.clone();
                let Some(lease) = response
                    .lease
                    .as_ref()
                    .filter(|_| response.status == "allowed")
                else {
                    if let Some(peer) = sparse::apply_denial(&self.handle, policy, &response) {
                        // Revocation is immediate; native cleanup cannot extend
                        // the old grant even if that cleanup fails or blocks.
                        authority
                            .during(install_routes(Routes::Retire(peer)))
                            .await?;
                    }
                    self.handle.unavailable(&response.query);
                    return Ok(Installed::Unavailable);
                };
                ensure!(
                    lease.workspace == self.workspace
                        && lease.self_ == self.own
                        && lease.local.id == self.own
                        && lease.local.fingerprint == self.fingerprint,
                    "sparse node pair identity mismatch"
                );
                let lease = lease.clone();
                let peer = lease.peer.clone();
                policy.install_pair(lease.clone())?;
                let result = authority
                    .during(install_routes(Routes::Pair(lease.clone())))
                    .await
                    .and_then(|()| {
                        authority.check()?;
                        ensure!(
                            !self.owner.is_cancelled() && !self.handle.revoked(),
                            "sparse node owner retired during route install"
                        );
                        Ok(())
                    });
                if let Err(error) = result {
                    policy.revoke_pair(&peer.id);
                    self.handle.retire(&peer.id);
                    return Err(error);
                }
                authority.check()?;
                self.handle
                    .installed_authority(&response.query, lease, authority.retained());
                Ok(Installed::Pair(peer))
            }
            _ => anyhow::bail!("not a controller authority event"),
        }
    }
}
impl Runner {
    pub async fn run(self) -> Result<()> {
        self.0.run().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_network::{
        authority_clock::{RequestWindow, SuspendClock},
        authority_event::Authority,
    };
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    fn setup() -> Result<(Node, Engine, sparse::Handle, Arc<Clock>, Snapshot)> {
        let identity = Identity::new()?;
        let fingerprint = identity.fingerprint().to_owned();
        let (handle, _) = sparse::channel();
        let (events, _) = mpsc::channel(1);
        let (node, _) = Node::new(
            "w".into(),
            "a".into(),
            identity,
            handle.clone(),
            events,
            CancellationToken::new(),
        )?;
        let snapshot = serde_json::from_value(
            serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":"a".repeat(64)},"peers":[{"id":"a","ip":"10.234.0.1","fingerprint":fingerprint,"instance":"a-instance","hostname":"a.phub"}],"grants":[]}),
        )?;
        Ok((
            node,
            Engine::default(),
            handle,
            Arc::new(Clock(AtomicU64::new(0))),
            snapshot,
        ))
    }
    fn event(snapshot: Snapshot, clock: Arc<Clock>) -> Result<Event> {
        let expiry = snapshot.expires_at;
        Ok(Event::Snapshot(Authority::new(
            snapshot,
            Some(RequestWindow::start(clock)?),
            expiry,
        )))
    }
    #[tokio::test]
    async fn route_completion_cannot_publish_or_keep_policy_after_original_witness_expires_inside_final_poll(
    ) -> Result<()> {
        let (node, mut policy, handle, clock, snapshot) = setup()?;
        let message = event(snapshot, clock.clone())?;
        let result = node
            .install_control(message, &mut policy, |_| async move {
                clock.0.store(15000, Ordering::SeqCst);
                Ok(())
            })
            .await;
        ensure!(
            result.is_err() && !policy.valid_lease() && handle.revoked(),
            "expired route completion retained a policy or published request authority"
        );
        Ok(())
    }
    #[tokio::test]
    async fn foreign_controller_identity_and_unbound_cached_policy_never_call_route_installer(
    ) -> Result<()> {
        let (node, mut policy, handle, clock, mut snapshot) = setup()?;
        snapshot.workspace = "foreign".into();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = called.clone();
        ensure!(node
            .install_control(event(snapshot, clock)?, &mut policy, |_| async move {
                check.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err());
        ensure!(!called.load(Ordering::SeqCst) && !handle.enabled() && !policy.valid_lease());
        let (node, mut policy, handle, _, snapshot) = setup()?;
        let expiry = snapshot.expires_at;
        let check = called.clone();
        ensure!(node
            .install_control(
                Event::Snapshot(Authority::new(snapshot, None, expiry)),
                &mut policy,
                |_| async move {
                    check.store(true, Ordering::SeqCst);
                    Ok(())
                }
            )
            .await
            .is_err());
        ensure!(!called.load(Ordering::SeqCst) && !handle.enabled() && !policy.valid_lease());
        Ok(())
    }
    #[tokio::test]
    async fn profile_owner_cancel_during_route_completion_retires_all_entrypoints_without_raw_fallback(
    ) -> Result<()> {
        let (node, mut policy, handle, clock, snapshot) = setup()?;
        let owner = node.owner.clone();
        ensure!(node
            .install_control(event(snapshot, clock)?, &mut policy, |_| async move {
                owner.cancel();
                Ok(())
            })
            .await
            .is_err());
        ensure!(handle.revoked() && !policy.valid_lease() && node.counts() == (0, 0));
        ensure!(
            node.kernel_packet("b", Bytes::from_static(b"closed-owner"), true),
            "retired profile offered raw fallback"
        );
        ensure!(
            !node.raw_ingress(b"closed-owner")
                && !node.receive(
                    "b",
                    "10.235.0.1".parse()?,
                    Bytes::from_static(b"closed-owner")
                )?
        );
        Ok(())
    }
}
