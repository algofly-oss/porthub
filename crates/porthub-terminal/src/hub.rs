//! Bounded in-memory terminal routing. Persistent authorization/revocation is
//! checked by the API before registering a host. No terminal transcript is kept.
use crate::protocol::*;
use anyhow::{ensure, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Hub {
    inner: Arc<Mutex<Inner>>,
    admission: Arc<tokio::sync::Semaphore>,
}
impl Default for Hub {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            admission: Arc::new(tokio::sync::Semaphore::new(192)),
        }
    }
}
#[derive(Default)]
struct Inner {
    sessions: HashMap<String, Arc<Shared>>,
    tokens: HashMap<String, (String, bool)>,
}
pub struct Shared {
    pub id: String,
    pub owner: String,
    pub options: Options,
    pub stop: CancellationToken,
    secret_hash: String,
    state: Mutex<State>,
}
struct State {
    host: Option<mpsc::Sender<HostEvent>>,
    generation: u64,
    offline_at: Option<Instant>,
    activity: Instant,
    next_client: u64,
    viewers: HashMap<u64, Viewer>,
    close_event: Option<HostEvent>,
    invitations_revoked: bool,
}
struct Viewer {
    identity: u64,
    history_pending: Option<u32>,
    history_started: Option<Instant>,
    joined_at: i64,
    last_active_at: i64,
    activity_published_at: i64,
    read_only: bool,
    cols: u16,
    rows: u16,
    term: String,
    events: mpsc::Sender<ViewerEvent>,
}
pub struct HostLease {
    pub session: Arc<Shared>,
    pub generation: u64,
    pub events: mpsc::Receiver<HostEvent>,
}
pub struct Attachment {
    pub id: u64,
    pub session: Arc<Shared>,
    pub events: mpsc::Receiver<ViewerEvent>,
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.session.detach(self.id);
    }
}
impl Hub {
    pub fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("terminal gateway capacity reached"))
    }
    pub fn register(&self, owner: &str, hello: &HostHello, now: i64) -> Result<HostLease> {
        self.register_persisted(owner, hello, now, false)
    }
    /// Persisted invitation revocation is installed atomically with admission.
    pub fn register_persisted(
        &self,
        owner: &str,
        hello: &HostHello,
        now: i64,
        invitations_revoked: bool,
    ) -> Result<HostLease> {
        hello.validate(now)?;
        let mut inner = self.inner.lock().expect("terminal hub mutex");
        let session = if let Some(session) = inner.sessions.get(&hello.id) {
            ensure!(
                session.owner == owner
                    && session.secret_hash == digest(&hello.secret)
                    && session.options == hello.options
                    && !session.stop.is_cancelled(),
                "terminal host identity does not match"
            );
            session.clone()
        } else {
            ensure!(
                inner.sessions.len() < 64
                    && inner.sessions.values().filter(|s| s.owner == owner).count() < 8,
                "terminal session capacity reached"
            );
            let write_hash = digest(&hello.write_token);
            let read_hash = digest(&hello.read_token);
            ensure!(
                !inner.tokens.contains_key(&write_hash) && !inner.tokens.contains_key(&read_hash),
                "terminal capability already registered"
            );
            let session = Arc::new(Shared {
                id: hello.id.clone(),
                owner: owner.to_owned(),
                options: hello.options.clone(),
                secret_hash: digest(&hello.secret),
                stop: CancellationToken::new(),
                state: Mutex::new(State {
                    host: None,
                    generation: 0,
                    offline_at: None,
                    activity: Instant::now(),
                    next_client: participant_id(),
                    viewers: HashMap::new(),
                    close_event: None,
                    invitations_revoked,
                }),
            });
            inner
                .tokens
                .insert(write_hash, (hello.id.clone(), hello.options.read_only));
            inner.tokens.insert(read_hash, (hello.id.clone(), true));
            inner.sessions.insert(hello.id.clone(), session.clone());
            session
        };
        let (send, events) = mpsc::channel(128);
        let generation = {
            let mut state = session.state.lock().expect("terminal session mutex");
            state.invitations_revoked |= invitations_revoked;
            // A reconnect replaces the transport, not the shared shell/session.
            if let Some(previous) = state.host.take() {
                let _ = previous.try_send(HostEvent::Reconnect {
                    reason: "host connection replaced".into(),
                });
            }
            state.generation += 1;
            state.offline_at = None;
            for (id, viewer) in &mut state.viewers {
                if let Some(request) = viewer.history_pending.take() {
                    let _ = viewer.events.try_send(ViewerEvent::History {
                        page: HistoryChunk {
                            request,
                            data: String::new(),
                            done: true,
                            total: 0,
                            before: 0,
                            lines: 0,
                            truncated: false,
                            error: Some("Host reconnected; refresh this history page.".into()),
                        },
                    });
                }
                send.try_send(HostEvent::Attach {
                    client: *id,
                    read_only: viewer.read_only,
                    cols: viewer.cols,
                    rows: viewer.rows,
                    term: viewer.term.clone(),
                })?;
            }
            if state.invitations_revoked {
                send.try_send(HostEvent::InvitationsRevoked)?;
            }
            state.host = Some(send);
            presence(&mut state);
            state.generation
        };
        Ok(HostLease {
            session,
            generation,
            events,
        })
    }
    pub fn resolve(&self, capability: &str) -> Result<(Arc<Shared>, bool)> {
        ensure!(
            token(capability, 64),
            "invalid or expired terminal invitation"
        );
        let inner = self.inner.lock().expect("terminal hub mutex");
        let (id, read_only) = inner
            .tokens
            .get(&digest(capability))
            .ok_or_else(|| anyhow::anyhow!("invalid or expired terminal invitation"))?;
        let session = inner
            .sessions
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("invalid or expired terminal invitation"))?
            .clone();
        ensure!(
            session.options.expires_at == 0 || now() < session.options.expires_at,
            "terminal invitation expired"
        );
        ensure!(
            !session.stop.is_cancelled()
                && !session.expired(now())
                && session
                    .state
                    .lock()
                    .expect("terminal session mutex")
                    .host
                    .is_some(),
            "terminal host is reconnecting or unavailable"
        );
        ensure!(
            !session.invitations_revoked(),
            "terminal invitation revoked"
        );
        Ok((session, *read_only))
    }
    pub fn attach(&self, capability: &str, cols: u16, rows: u16, term: &str) -> Result<Attachment> {
        self.attach_invitation(capability, None, cols, rows, term)
    }
    pub fn attach_invitation(
        &self,
        capability: &str,
        identity: Option<u64>,
        cols: u16,
        rows: u16,
        term: &str,
    ) -> Result<Attachment> {
        let (session, read_only) = self.resolve(capability)?;
        self.attach_inner(&session.id, identity, read_only, cols, rows, term, true)
    }
    /// Only the trusted gateway may call this after verifying a durable guest
    /// grant. It intentionally bypasses invitation expiry, never session expiry.
    pub fn attach_authorized(
        &self,
        session_id: &str,
        identity: Option<u64>,
        read_only: bool,
        cols: u16,
        rows: u16,
        term: &str,
    ) -> Result<Attachment> {
        self.attach_inner(session_id, identity, read_only, cols, rows, term, false)
    }
    #[allow(clippy::too_many_arguments)]
    fn attach_inner(
        &self,
        session_id: &str,
        identity: Option<u64>,
        read_only: bool,
        cols: u16,
        rows: u16,
        term: &str,
        invited: bool,
    ) -> Result<Attachment> {
        dimensions(cols, rows)?;
        ensure!(
            !term.is_empty()
                && term.len() <= 64
                && term
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)),
            "invalid terminal type"
        );
        let inner = self.inner.lock().expect("terminal hub mutex");
        let session = inner
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("terminal host unavailable"))?;
        ensure!(
            !session.stop.is_cancelled() && !session.expired(now()),
            "terminal session ended"
        );
        let total: usize = inner
            .sessions
            .values()
            .map(|session| {
                session
                    .state
                    .lock()
                    .expect("terminal session mutex")
                    .viewers
                    .len()
            })
            .sum();
        let mut state = session.state.lock().expect("terminal session mutex");
        if invited {
            ensure!(
                !state.invitations_revoked
                    && (session.options.expires_at == 0 || now() < session.options.expires_at),
                "terminal invitation expired or revoked"
            );
        }
        ensure!(
            total < 128
                || identity.is_some_and(|identity| state
                    .viewers
                    .values()
                    .any(|viewer| viewer.identity == identity)),
            "terminal gateway participant capacity reached"
        );
        if let Some(identity) = identity {
            ensure!(
                identity > 0 && identity < (1u64 << 53),
                "invalid participant identity"
            );
            ensure!(state.host.is_some(), "terminal host reconnecting");
            if let Some(previous) = state
                .viewers
                .iter()
                .find_map(|(&id, viewer)| (viewer.identity == identity).then_some(id))
            {
                if let Some(viewer) = state.viewers.remove(&previous) {
                    let _ = viewer.events.try_send(ViewerEvent::Closed {
                        reason: "participant reconnected elsewhere".into(),
                        retryable: false,
                    });
                }
                if let Some(host) = &state.host {
                    host.try_send(HostEvent::Detach { client: previous })?;
                }
            }
        }
        ensure!(
            state.viewers.len() < usize::from(session.options.max_viewers).min(MAX_VIEWERS),
            "terminal participant limit reached"
        );
        let id = state.next_client;
        state.next_client = state
            .next_client
            .checked_add(1)
            .filter(|id| *id < (1u64 << 53))
            .ok_or_else(|| anyhow::anyhow!("terminal client identity exhausted"))?;
        let (events, receive) = mpsc::channel(64);
        state
            .host
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("terminal host unavailable"))?
            .try_send(HostEvent::Attach {
                client: id,
                read_only,
                cols,
                rows,
                term: term.into(),
            })?;
        events.try_send(ViewerEvent::Welcome {
            name: session.options.name.clone(),
            read_only,
            expires_at: session.options.expires_at,
            participants: state.viewers.len() + 1,
        })?;
        state.viewers.insert(
            id,
            Viewer {
                identity: identity.unwrap_or(id),
                history_pending: None,
                history_started: None,
                joined_at: now(),
                last_active_at: now(),
                activity_published_at: now(),
                read_only,
                cols,
                rows,
                term: term.into(),
                events,
            },
        );
        state.activity = Instant::now();
        presence(&mut state);
        drop(state);
        drop(inner);
        Ok(Attachment {
            id,
            session,
            events: receive,
        })
    }
    pub fn end(&self, id: &str, reason: &str) {
        self.remove(id, reason, true);
    }
    pub fn disconnect(&self, id: &str, reason: &str) {
        self.remove(id, reason, false);
    }
    fn remove(&self, id: &str, reason: &str, revoked: bool) {
        let mut inner = self.inner.lock().expect("terminal hub mutex");
        if let Some(session) = inner.sessions.remove(id) {
            let mut state = session.state.lock().expect("terminal session mutex");
            let event = if revoked {
                HostEvent::Stop {
                    reason: reason.into(),
                }
            } else {
                HostEvent::Reconnect {
                    reason: reason.into(),
                }
            };
            state.close_event = Some(event.clone());
            session.stop.cancel();
            if let Some(host) = state.host.take() {
                let _ = host.try_send(event);
            }
            for (_, viewer) in state.viewers.drain() {
                let _ = viewer.events.try_send(ViewerEvent::Closed {
                    retryable: !revoked,
                    reason: reason.into(),
                });
            }
        }
        inner.tokens.retain(|_, (session, _)| session != id);
    }
    pub fn sessions(&self) -> Vec<Arc<Shared>> {
        self.inner
            .lock()
            .expect("terminal hub mutex")
            .sessions
            .values()
            .cloned()
            .collect()
    }
}
fn presence(state: &mut State) {
    let mut members: Vec<_> = state
        .viewers
        .iter()
        .map(|(_, viewer)| Participant {
            id: viewer.identity,
            read_only: viewer.read_only,
            joined_at: viewer.joined_at,
            last_active_at: viewer.last_active_at,
        })
        .collect();
    members.sort_by_key(|member| member.id);
    if let Some(host) = &state.host {
        let _ = host.try_send(HostEvent::Presence {
            members: members.clone(),
        });
    }
    let event = ViewerEvent::Presence {
        members,
        participants: state.viewers.len(),
    };
    for viewer in state.viewers.values() {
        let _ = viewer.events.try_send(event.clone());
    }
}
fn remove_participant(state: &mut State, identity: u64) {
    let Some(client) = state
        .viewers
        .iter()
        .find_map(|(&id, viewer)| (viewer.identity == identity).then_some(id))
    else {
        return;
    };
    if let Some(viewer) = state.viewers.remove(&client) {
        let _ = viewer.events.try_send(ViewerEvent::Closed {
            reason: "removed by the host".into(),
            retryable: false,
        });
        if let Some(host) = &state.host {
            let _ = host.try_send(HostEvent::Detach { client });
        }
        presence(state);
    }
}
impl Shared {
    pub fn close_event(&self) -> Option<HostEvent> {
        self.state
            .lock()
            .expect("terminal session mutex")
            .close_event
            .clone()
    }
    pub fn recovery_expired(&self) -> bool {
        self.state
            .lock()
            .expect("terminal session mutex")
            .offline_at
            .is_some_and(|offline| {
                offline.elapsed() >= Duration::from_secs(self.options.reconnect_timeout.into())
            })
    }
    pub fn participants(&self) -> usize {
        self.state
            .lock()
            .expect("terminal session mutex")
            .viewers
            .len()
    }

    pub fn invitations_revoked(&self) -> bool {
        self.state
            .lock()
            .expect("terminal session mutex")
            .invitations_revoked
    }
    pub fn revoke_invitations(&self) {
        let mut state = self.state.lock().expect("terminal session mutex");
        state.invitations_revoked = true;
        if let Some(host) = &state.host {
            let _ = host.try_send(HostEvent::InvitationsRevoked);
        }
    }
    pub fn participant_list(&self) -> Vec<Participant> {
        let state = self.state.lock().expect("terminal session mutex");
        let mut members: Vec<_> = state
            .viewers
            .values()
            .map(|viewer| Participant {
                id: viewer.identity,
                read_only: viewer.read_only,
                joined_at: viewer.joined_at,
                last_active_at: viewer.last_active_at,
            })
            .collect();
        members.sort_by_key(|member| member.id);
        members
    }
    /// Called only after gateway-side authorization and durable revocation.
    pub fn kick(&self, identity: u64) -> Result<()> {
        let mut state = self.state.lock().expect("terminal session mutex");
        ensure!(!self.stop.is_cancelled(), "terminal session ended");
        remove_participant(&mut state, identity);
        Ok(())
    }
    pub fn offline(&self, generation: u64) {
        let mut state = self.state.lock().expect("terminal session mutex");
        if generation == state.generation {
            state.host = None;
            state.offline_at = Some(Instant::now());
        }
    }
    pub fn input(&self, client: u64, input: ViewerInput) -> Result<()> {
        ensure!(!self.stop.is_cancelled(), "terminal session ended");
        let mut state = self.state.lock().expect("terminal session mutex");
        let viewer = state
            .viewers
            .get_mut(&client)
            .ok_or_else(|| anyhow::anyhow!("terminal participant detached"))?;
        let mut publish_activity = false;
        let event = match input {
            ViewerInput::History {
                request,
                pane,
                before,
                lines,
            } => {
                history_request(&pane, before, lines)?;
                if viewer.history_started.is_some_and(|started| {
                    started.elapsed() < Duration::from_millis(500)
                        || viewer.history_pending.is_some()
                            && started.elapsed() < Duration::from_secs(3)
                }) {
                    viewer.events.try_send(ViewerEvent::History {
                        page: HistoryChunk {
                            request,
                            data: String::new(),
                            done: true,
                            total: 0,
                            before,
                            lines: 0,
                            truncated: false,
                            error: Some("History is busy; try again shortly.".into()),
                        },
                    })?;
                    return Ok(());
                }
                viewer.history_started = Some(Instant::now());
                viewer.history_pending = Some(request);
                HostEvent::History {
                    client,
                    request,
                    pane,
                    before,
                    lines,
                }
            }

            ViewerInput::Input { data } => {
                ensure!(!viewer.read_only, "this invitation is read-only");
                decode_data(&data)?;
                let timestamp = now();
                publish_activity = timestamp.saturating_sub(viewer.activity_published_at) >= 5;
                viewer.last_active_at = timestamp;
                if publish_activity {
                    viewer.activity_published_at = timestamp;
                }
                HostEvent::Input { client, data }
            }
            ViewerInput::Resize { cols, rows } => {
                dimensions(cols, rows)?;
                viewer.cols = cols;
                viewer.rows = rows;
                HostEvent::Resize { client, cols, rows }
            }
            ViewerInput::Pong => return Ok(()),
        };
        state.activity = Instant::now();
        state
            .host
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("terminal host is reconnecting"))?
            .try_send(event)?;
        if publish_activity {
            presence(&mut state);
        }
        Ok(())
    }
    pub fn output(&self, generation: u64, output: HostOutput) -> Result<()> {
        let mut state = self.state.lock().expect("terminal session mutex");
        ensure!(
            generation == state.generation && !self.stop.is_cancelled(),
            "stale terminal host connection"
        );
        match output {
            HostOutput::RevokeInvitations => {
                anyhow::bail!("invitation revocation must be persisted by the gateway")
            }
            HostOutput::History { client, page } => {
                page.validate()?;
                if let Some(viewer) = state.viewers.get_mut(&client) {
                    if viewer.history_pending == Some(page.request) {
                        if page.done {
                            viewer.history_pending = None;
                        }
                        if viewer
                            .events
                            .try_send(ViewerEvent::History { page })
                            .is_err()
                        {
                            state.viewers.remove(&client);
                            if let Some(host) = &state.host {
                                let _ = host.try_send(HostEvent::Detach { client });
                            }
                            presence(&mut state);
                        }
                    }
                }
            }
            HostOutput::Kick { client } => remove_participant(&mut state, client),
            HostOutput::Output { client, data } => {
                decode_data(&data)?;
                if let Some(viewer) = state.viewers.get(&client) {
                    if viewer
                        .events
                        .try_send(ViewerEvent::Output { data })
                        .is_err()
                    {
                        // A slow participant may reconnect; never stall another
                        // participant or discard bytes silently on that channel.
                        state.viewers.remove(&client);
                        if let Some(host) = &state.host {
                            let _ = host.try_send(HostEvent::Detach { client });
                        }
                        presence(&mut state);
                    }
                }
            }
            HostOutput::Closed { client } => {
                state.viewers.remove(&client);
                presence(&mut state);
            }
            HostOutput::Pong => {}
            HostOutput::Activity => {
                state.activity = Instant::now();
            }
            HostOutput::End => anyhow::bail!("terminal host ended the session"),
        }
        Ok(())
    }
    pub fn detach(&self, client: u64) {
        let mut state = self.state.lock().expect("terminal session mutex");
        if state.viewers.remove(&client).is_some() {
            if let Some(host) = &state.host {
                let _ = host.try_send(HostEvent::Detach { client });
            }
            presence(&mut state);
        }
    }
    pub fn expired(&self, now: i64) -> bool {
        // The host enforces idle limits using actual tmux activity, including
        // locally attached owners. Gateway traffic cannot establish idleness.
        self.options.session_expires_at.is_some_and(|at| now >= at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello() -> HostHello {
        HostHello {
            id: random_token(16),
            secret: random_token(32),
            write_token: random_token(32),
            read_token: random_token(32),
            options: Options {
                name: "Pair debugging".into(),
                expires_at: now() + 100,
                session_expires_at: None,
                idle_timeout: 0,
                reconnect_timeout: 60,
                history_limit: DEFAULT_HISTORY,
                mouse: true,
                read_only: false,
                size_policy: SizePolicy::Smallest,
                access: Access::Both,
                max_viewers: 16,
            },
        }
    }
    #[tokio::test]
    async fn capabilities_are_session_scoped_read_only_enforced_and_revocation_closes_everyone(
    ) -> Result<()> {
        let hub = Hub::default();
        let h = hello();
        let mut host = hub.register("owner", &h, now())?;
        let mut writer = hub.attach(&h.write_token, 80, 24, "xterm-256color")?;
        let reader = hub.attach(&h.read_token, 80, 24, "xterm-256color")?;
        assert!(reader
            .session
            .input(
                reader.id,
                ViewerInput::Input {
                    data: encode_data(b"rm -rf /")
                }
            )
            .is_err());
        writer.session.input(
            writer.id,
            ViewerInput::Input {
                data: encode_data(b"ls\r"),
            },
        )?;
        let mut input = false;
        while let Ok(event) = host.events.try_recv() {
            if matches!(event, HostEvent::Input { .. }) {
                input = true;
            }
        }
        assert!(input);
        let mut other = hello();
        other.id = h.id.clone();
        assert!(hub.register("other", &other, now()).is_err());
        hub.end(&h.id, "owner ended session");
        assert!(hub.resolve(&h.write_token).is_err() && hub.resolve(&h.read_token).is_err());
        assert!(writer.session.stop.is_cancelled());
        while writer.events.recv().await.is_some() {}
        Ok(())
    }
    #[tokio::test]
    async fn invitation_revocation_blocks_new_joins_without_interrupting_guests_or_recovery(
    ) -> Result<()> {
        let hub = Hub::default();
        let mut h = hello();
        h.options.expires_at = 0;
        let host = hub.register("owner", &h, now())?;
        let writer = hub.attach(&h.write_token, 80, 24, "xterm-256color")?;
        let reader = hub.attach(&h.read_token, 80, 24, "xterm-256color")?;
        host.session.revoke_invitations();
        assert!(hub.resolve(&h.write_token).is_err() && hub.resolve(&h.read_token).is_err());
        assert!(hub
            .attach(&h.write_token, 80, 24, "xterm-256color")
            .is_err());
        assert!(hub
            .attach_invitation(&h.read_token, Some(88), 80, 24, "xterm-256color")
            .is_err());
        writer.session.input(
            writer.id,
            ViewerInput::Input {
                data: encode_data(b"echo alive\r"),
            },
        )?;
        reader
            .session
            .input(reader.id, ViewerInput::Resize { cols: 90, rows: 30 })?;
        let recovered = hub.attach_authorized(&h.id, Some(88), true, 80, 24, "xterm-256color")?;
        recovered
            .session
            .input(recovered.id, ViewerInput::Resize { cols: 90, rows: 30 })?;
        assert_eq!(host.session.participants(), 3);
        assert!(!host.session.stop.is_cancelled());
        let replacement = hub.register("owner", &h, now())?;
        assert!(replacement.session.invitations_revoked());
        assert!(hub.resolve(&h.write_token).is_err());
        let restarted = Hub::default();
        let lease = restarted.register_persisted("owner", &h, now(), true)?;
        assert!(lease.session.invitations_revoked());
        assert!(restarted.resolve(&h.read_token).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn read_only_history_is_request_scoped_bounded_and_does_not_authorize_input() -> Result<()>
    {
        let hub = Hub::default();
        let h = hello();
        let mut host = hub.register("owner", &h, now())?;
        let mut reader = hub.attach(&h.read_token, 80, 24, "xterm-256color")?;
        let mut other = hub.attach(&h.read_token, 80, 24, "xterm-256color")?;
        while reader.events.try_recv().is_ok() {}
        while other.events.try_recv().is_ok() {}
        reader.session.input(
            reader.id,
            ViewerInput::History {
                request: 11,
                pane: "%0".into(),
                before: 0,
                lines: 200,
            },
        )?;
        let mut routed = false;
        while let Ok(event) = host.events.try_recv() {
            if matches!(event,HostEvent::History{client,request:11,..} if client==reader.id) {
                routed = true;
            }
        }
        assert!(routed);
        assert!(reader
            .session
            .input(
                reader.id,
                ViewerInput::Input {
                    data: encode_data(b"exit\r")
                }
            )
            .is_err());
        let mut page = HistoryChunk {
            request: 99,
            data: encode_data(b"private scrollback"),
            done: true,
            total: 200,
            before: 0,
            lines: 1,
            truncated: false,
            error: None,
        };
        host.session.output(
            host.generation,
            HostOutput::History {
                client: reader.id,
                page: page.clone(),
            },
        )?;
        assert!(
            reader.events.try_recv().is_err(),
            "unsolicited response must be ignored"
        );
        page.request = 11;
        host.session.output(
            host.generation,
            HostOutput::History {
                client: reader.id,
                page,
            },
        )?;
        assert!(matches!(
            reader.events.try_recv(),
            Ok(ViewerEvent::History { .. })
        ));
        assert!(
            other.events.try_recv().is_err(),
            "history belongs only to requesting guest"
        );
        reader.session.input(
            reader.id,
            ViewerInput::History {
                request: 12,
                pane: "%0".into(),
                before: 0,
                lines: 200,
            },
        )?;
        assert!(
            matches!(reader.events.try_recv(),Ok(ViewerEvent::History{page}) if page.error.is_some()),
            "rapid capture must be rate limited without disconnecting the guest"
        );
        assert_eq!(host.session.participants(), 2);
        assert!(reader
            .session
            .input(
                reader.id,
                ViewerInput::History {
                    request: 13,
                    pane: "%0;bad".into(),
                    before: 0,
                    lines: 200
                }
            )
            .is_err());
        assert!(reader
            .session
            .input(
                reader.id,
                ViewerInput::History {
                    request: 13,
                    pane: "".into(),
                    before: 0,
                    lines: 513
                }
            )
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn durable_guest_recovery_bypasses_invite_expiry_and_fences_old_attachment() -> Result<()>
    {
        let hub = Hub::default();
        let mut h = hello();
        h.options.expires_at = now() - 1;
        let host = hub.register("owner", &h, now())?;
        assert!(hub.attach(&h.read_token, 80, 24, "xterm-256color").is_err());
        let first = hub.attach_authorized(&h.id, Some(42), true, 80, 24, "xterm-256color")?;
        let mut resumed =
            hub.attach_authorized(&h.id, Some(42), true, 100, 30, "xterm-256color")?;
        assert_ne!(first.id, resumed.id);
        assert!(first
            .session
            .input(first.id, ViewerInput::Resize { cols: 80, rows: 24 })
            .is_err());
        host.session
            .output(host.generation, HostOutput::Closed { client: first.id })?;
        drop(first);
        assert_eq!(host.session.participants(), 1);
        assert!(resumed
            .session
            .input(
                resumed.id,
                ViewerInput::Input {
                    data: encode_data(b"exit\r")
                }
            )
            .is_err());
        resumed.session.input(
            resumed.id,
            ViewerInput::Resize {
                cols: 100,
                rows: 30,
            },
        )?;
        let mut found = false;
        while let Ok(event) = resumed.events.try_recv() {
            if let ViewerEvent::Presence { members, .. } = event {
                found = members.len() == 1 && members[0].id == 42 && members[0].read_only;
            }
        }
        assert!(found);
        host.session
            .output(host.generation, HostOutput::Kick { client: 42 })?;
        assert_eq!(host.session.participants(), 0);
        assert!(!host.session.stop.is_cancelled());
        Ok(())
    }

    #[tokio::test]
    async fn host_kick_is_generation_fenced_and_preserves_other_guests() -> Result<()> {
        let hub = Hub::default();
        let h = hello();
        let old = hub.register("owner", &h, now())?;
        let mut writer = hub.attach(&h.write_token, 80, 24, "xterm-256color")?;
        let reader = hub.attach(&h.read_token, 80, 24, "xterm-256color")?;
        let mut members = Vec::new();
        while let Ok(event) = writer.events.try_recv() {
            if let ViewerEvent::Presence {
                members: current, ..
            } = event
            {
                members = current;
            }
        }
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].id, writer.id);
        assert!(!members[0].read_only);
        assert!(members[1].read_only);
        assert!(members.iter().all(|member| member.joined_at > 0));
        let current = hub.register("owner", &h, now())?;
        assert!(old
            .session
            .output(old.generation, HostOutput::Kick { client: writer.id })
            .is_err());
        assert_eq!(current.session.participants(), 2);
        current
            .session
            .output(current.generation, HostOutput::Kick { client: writer.id })?;
        let mut removed = false;
        while let Some(event) = writer.events.recv().await {
            if matches!(event, ViewerEvent::Closed { .. }) {
                removed = true;
            }
        }
        assert!(removed);
        assert_eq!(current.session.participants(), 1);
        assert!(!current.session.stop.is_cancelled());
        assert!(hub.resolve(&h.read_token).is_ok());
        assert!(reader
            .session
            .input(
                reader.id,
                ViewerInput::Resize {
                    cols: 100,
                    rows: 30
                }
            )
            .is_ok());
        assert!(writer
            .session
            .input(
                writer.id,
                ViewerInput::Input {
                    data: encode_data(b"exit\r")
                }
            )
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn invitation_expiry_blocks_new_joins_without_interrupting_existing_viewers() -> Result<()>
    {
        let hub = Hub::default();
        let mut h = hello();
        h.options.expires_at = now() + 100;
        let host = hub.register("owner", &h, now())?;
        let viewer = hub.attach(&h.write_token, 80, 24, "xterm-256color")?;
        // The expiry decision must never be used as workspace termination.
        assert!(!host.session.expired(h.options.expires_at + 1));
        viewer.session.input(
            viewer.id,
            ViewerInput::Input {
                data: encode_data(b"pwd\r"),
            },
        )?;
        host.session.offline(host.generation);
        assert!(!host.session.expired(now() + 86_400));
        assert!(!host.session.stop.is_cancelled());
        drop(viewer);
        assert_eq!(host.session.participants(), 0);
        assert!(!host.session.stop.is_cancelled());

        let mut expired = hello();
        expired.options.expires_at = now() - 1;
        let resumed = hub.register("owner", &expired, now())?;
        assert!(hub
            .attach(&expired.write_token, 80, 24, "xterm-256color")
            .is_err());
        assert!(!resumed.session.expired(now()));
        Ok(())
    }

    #[tokio::test]
    async fn host_reconnect_retains_viewers_but_stale_host_cannot_write() -> Result<()> {
        let hub = Hub::default();
        let h = hello();
        let old = hub.register("owner", &h, now())?;
        let viewer = hub.attach(&h.write_token, 80, 24, "xterm-256color")?;
        old.session.offline(old.generation);
        let mut current = hub.register("owner", &h, now())?;
        assert!(matches!(
            current.events.recv().await,
            Some(HostEvent::Attach { .. })
        ));
        old.session.offline(old.generation);
        assert!(hub.resolve(&h.write_token).is_ok());
        assert!(old
            .session
            .output(
                old.generation,
                HostOutput::Output {
                    client: viewer.id,
                    data: encode_data(b"forged")
                }
            )
            .is_err());
        Ok(())
    }
}
