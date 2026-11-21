//! SSH forwarding for immutable, named service mappings. No session channel is admitted.
mod grant;
mod master;
use anyhow::Result;
pub use async_trait::async_trait;
pub use grant::{Dial, Grant};
pub use master::{credential_from_seed, Master};
use russh::{
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
    Channel, MethodKind, MethodSet,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub fn valid_id(id: &str) -> bool {
    id.len() == 24
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[async_trait]
pub trait Authority: Send + Sync {
    async fn authorize(&self, entry: &str, signed_key: &str) -> Result<Option<Arc<Grant>>>;
}
#[derive(Default, Clone)]
pub struct Registry(Arc<Mutex<Entries>>);
#[derive(Default)]
struct Entries {
    epoch: u64,
    grants: HashMap<String, Weak<Grant>>,
}
impl Registry {
    pub fn get(&self, id: &str) -> Option<Arc<Grant>> {
        self.0
            .lock()
            .unwrap()
            .grants
            .get(id)?
            .upgrade()
            .filter(|g| !g.cancel.is_cancelled())
    }
    pub fn revoke(&self, id: &str) {
        let mut entries = self.0.lock().unwrap();
        entries.epoch = entries.epoch.wrapping_add(1);
        if let Some(old) = entries.grants.remove(id).and_then(|g| g.upgrade()) {
            old.cancel.cancel();
        }
    }
    fn admit(&self, id: &str, epoch: u64, fresh: Arc<Grant>) -> Option<Arc<Grant>> {
        let mut entries = self.0.lock().unwrap();
        if entries.epoch != epoch {
            return None;
        }
        entries.grants.retain(|_, g| g.strong_count() > 0);
        if let Some(existing) = entries.grants.get(id).and_then(Weak::upgrade) {
            return (!existing.cancel.is_cancelled()).then_some(existing);
        }
        entries.grants.insert(id.to_owned(), Arc::downgrade(&fresh));
        Some(fresh)
    }
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    master: &Master,
    registry: Registry,
    authority: Arc<dyn Authority>,
    stop: CancellationToken,
) -> Result<()> {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    let config = Arc::new(server::Config {
        keys: vec![master.host()],
        methods,
        max_auth_attempts: 3,
        auth_rejection_time: Duration::from_millis(250),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    });
    let (authenticated, mut auth) = tokio::sync::oneshot::channel();
    let handler = Handler {
        registry,
        authority,
        forwarding: None,
        authenticated: Some(authenticated),
    };
    let (inner, mut transport) = tokio::io::duplex(65536);
    let mut stream = stream;
    let _pump = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut transport).await;
    }));
    let handshake = async {
        let mut running = server::run_stream(config, inner, handler).await?;
        let grant = tokio::select! {r=&mut running=>{r?;return Ok(None)},v=&mut auth=>v?};
        Ok::<_, anyhow::Error>(Some((running, grant)))
    };
    let Some((mut running, cancel)) = (tokio::select! {biased;_=stop.cancelled()=>return Ok(()),r=tokio::time::timeout(Duration::from_secs(15),handshake)=>r??})
    else {
        return Ok(());
    };
    tokio::select! {biased;_=cancel.cancelled()=>{},_=stop.cancelled()=>{},r=&mut running=>{r?;}}
    Ok(())
}
struct Handler {
    registry: Registry,
    authority: Arc<dyn Authority>,
    forwarding: Option<grant::ForwardSession>,
    authenticated: Option<tokio::sync::oneshot::Sender<CancellationToken>>,
}
impl server::Handler for Handler {
    type Error = anyhow::Error;
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth> {
        Ok(
            if user.strip_prefix("pf-").is_some_and(valid_id)
                && offer.public_key.algorithm() == russh::keys::Algorithm::Ed25519
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth> {
        let Some(id) = user.strip_prefix("pf-").filter(|s| valid_id(s)) else {
            return Ok(Auth::reject());
        };
        if key.public_key.algorithm() != russh::keys::Algorithm::Ed25519
            || self.forwarding.is_some()
        {
            return Ok(Auth::reject());
        }
        let witness = self.registry.0.lock().unwrap().epoch;
        let Some(grant) = self
            .authority
            .authorize(id, &key.public_key.to_openssh()?)
            .await?
            .and_then(|g| self.registry.admit(id, witness, g))
        else {
            return Ok(Auth::reject());
        };
        let token = grant.cancel.clone();
        self.forwarding = Some(grant::ForwardSession::new(grant));
        if let Some(tx) = self.authenticated.take() {
            let _ = tx.send(token);
        }
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if let Some(g) = self.forwarding.as_mut() {
            g.direct(channel, host, port, reply).await;
        } else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        }
        Ok(())
    }
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        s: &mut Session,
    ) -> Result<bool> {
        Ok(self
            .forwarding
            .as_mut()
            .is_some_and(|g| g.listen(address, *port, s)))
    }
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _: &mut Session,
    ) -> Result<bool> {
        Ok(self
            .forwarding
            .as_mut()
            .is_some_and(|g| g.unlisten(address, port)))
    }
}
