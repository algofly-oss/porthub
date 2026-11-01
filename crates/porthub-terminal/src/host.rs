//! Remote attachments for one transport generation. Replace this router on
//! reconnect, retaining its Workspace; old PTY events cannot enter the new link.
use crate::{history::{Snapshot, SnapshotCache}, multiplexer::Workspace, protocol::*, pty::Client};
use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::mpsc;

// A participant identity can survive recovery; each local attachment cannot.
// Stamp asynchronous output at admission so late PTY/RTC/history callbacks can
// never close or write into a replacement with the same public identity.
struct Queued {
    scope: Option<(u64, u64)>,
    output: HostOutput,
}
fn participant(output: &HostOutput) -> Option<u64> {
    match output {
        HostOutput::Delivery { client, .. } | HostOutput::DirectAnswer { client, .. }
        | HostOutput::DirectUnavailable { client, .. } | HostOutput::History { client, .. }
        | HostOutput::Kick { client } | HostOutput::Output { client, .. }
        | HostOutput::Closed { client } => Some(*client),
        HostOutput::RotateInvitations { .. } | HostOutput::RevokeInvitations
        | HostOutput::End | HostOutput::Pong | HostOutput::Activity => None,
    }
}

async fn forward_participant(client: u64, generation: u64, mut incoming: mpsc::Receiver<HostOutput>, send: mpsc::Sender<Queued>) {
    while let Some(output) = incoming.recv().await {
        // This worker is allowed to report only its own attachment.
        if participant(&output) != Some(client) && !matches!(output,HostOutput::Activity) {break;}
        let closed = matches!(output, HostOutput::Closed {..});
        if send.send(Queued {scope:Some((client,generation)),output}).await.is_err() {return;}
        if closed {return;}
    }
    // The PTY's best-effort Closed can lose a full-queue race. EOF itself is
    // authoritative; wait for space rather than leaving a dead attachment.
    let _ = send.send(Queued {scope:Some((client,generation)),output:HostOutput::Closed {client}}).await;
}

pub struct Attachments {
    #[cfg(feature="direct")]
    direct: BTreeMap<u64,crate::direct::host::Handle>,
    #[cfg(feature="direct")]
    direct_config: Option<crate::direct::host::Config>,
    #[cfg(feature="direct")]
    direct_enabled: bool,
    workspace: Workspace,
    snapshots: std::sync::Arc<std::sync::Mutex<SnapshotCache>>,
    history_snapshots: bool,
    clients: BTreeMap<u64, Client>,
    send: mpsc::Sender<Queued>,
    receive: mpsc::Receiver<Queued>,
    generations: BTreeMap<u64, u64>,
    generation: u64,
    forwarders: BTreeMap<u64, tokio_util::task::AbortOnDropHandle<()>>,
    max_viewers: usize,
    traffic: crate::traffic::Counters,
    history_send: mpsc::Sender<Queued>,
    history_receive: mpsc::Receiver<Queued>,
    history_jobs: tokio::task::JoinSet<()>,
    history_capacity: std::sync::Arc<tokio::sync::Semaphore>,
    pending_redraw: BTreeSet<u64>,
    redraw_capacity: std::sync::Arc<tokio::sync::Semaphore>,
    live_burst: u8,
}

impl Attachments {
    pub fn traffic(&self) -> crate::traffic::Snapshot {
        self.traffic.snapshot()
    }
    pub fn participant_traffic(&self, client: u64) -> Option<crate::traffic::Snapshot> {
        self.clients.get(&client).map(Client::traffic)
    }
    pub fn new(workspace: Workspace, max_viewers: usize) -> Result<Self> {
        ensure!(
            (1..=MAX_VIEWERS).contains(&max_viewers),
            "invalid terminal participant limit"
        );
        let (send, receive) = mpsc::channel(128);
        let (history_send, history_receive) = mpsc::channel(8);
        Ok(Self {
            #[cfg(feature="direct")]
            direct:BTreeMap::new(),
            #[cfg(feature="direct")]
            direct_config:None,
            #[cfg(feature="direct")]
            direct_enabled:false,
            workspace,
            snapshots: std::sync::Arc::new(std::sync::Mutex::new(SnapshotCache::default())),
            history_snapshots: false,
            clients: BTreeMap::new(),
            generations: BTreeMap::new(),
            generation: 0,
            forwarders: BTreeMap::new(),
            send,
            receive,
            max_viewers,
            traffic:Default::default(),
            history_send,
            history_receive,
            history_jobs: tokio::task::JoinSet::new(),
            history_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            pending_redraw: BTreeSet::new(),
            redraw_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            live_burst: 0,
        })
    }

    #[cfg(feature="direct")]
    pub fn configure_direct(&mut self, config:crate::direct::host::Config)->Result<()> {
        ensure!(self.clients.is_empty(),"configure terminal direct transport before attaching guests");
        config.validate()?;self.direct_config=Some(config);Ok(())
    }

    fn queued(&self, output: HostOutput) -> Result<Queued> {
        let scope = participant(&output).map(|client| {
            self.generations.get(&client).copied()
                .map(|generation| (client, generation))
                .context("terminal participant generation missing")
        }).transpose()?;
        Ok(Queued { scope, output })
    }
    fn emit(&self, output: HostOutput) -> Result<()> {
        self.send.try_send(self.queued(output)?)?;
        Ok(())
    }
    fn admit_generation(&mut self, client: u64) -> Result<u64> {
        self.generation = self.generation.checked_add(1)
            .context("terminal attachment generations exhausted")?;
        self.generations.insert(client, self.generation);
        Ok(self.generation)
    }

    /// A false result ends this transport, while keeping the shared workspace.
    pub fn apply(&mut self, event: HostEvent) -> Result<bool> {
        match event {
            HostEvent::Delivery {client,packet} => {
                #[cfg(feature="direct")]
                if let Some(handle)=self.direct.get(&client) {if handle.relay(packet).is_ok(){return Ok(true);}}
                #[cfg(not(feature="direct"))]
                let _=packet;

                // No configured actor (or a failed control queue): reject only
                // this attachment; shipped CLI capability remains disabled.
                // Unexpected sequenced input must never end another attachment.
                if self.clients.remove(&client).is_some() {
                    self.forwarders.remove(&client);
                    #[cfg(feature="direct")]
                    self.direct.remove(&client);
                    self.pending_redraw.remove(&client);
                    self.snapshots.lock().expect("snapshot cache").detach(client);
                    self.emit(HostOutput::Closed {client})?;
                }
            }
            HostEvent::DirectOffer {client,request,description} => {
                #[cfg(feature="direct")]
                if let Some(handle)=self.direct.get(&client) {if handle.offer(request,description).is_ok(){return Ok(true);}}
                #[cfg(not(feature="direct"))]
                let _=description;

                if self.clients.contains_key(&client) {self.emit(HostOutput::DirectUnavailable {client,request})?;}
            }
            HostEvent::Redraw { client } => {
                if self.clients.contains_key(&client) {
                    self.pending_redraw.insert(client);
                }
            }

            HostEvent::History {
                freeze, snapshot,
                client,
                request,
                pane,
                before,
                lines,
            } => {
                history_request(&pane, before, lines)?;
                if !self.clients.contains_key(&client) {
                    return Ok(true);
                }
                ensure!(snapshot.as_ref().is_none_or(|id| freeze && token(id, 32)), "invalid history snapshot reference");
                let workspace = self.workspace.clone();
                let snapshots = self.snapshots.clone();
                let enabled = self.history_snapshots;
                let send = self.history_send.clone();
                let generation = *self.generations.get(&client).context("terminal participant generation missing")?;
                match self.history_capacity.clone().try_acquire_owned() {
                    Ok(permit) => {
                        self.history_jobs.spawn(async move {
                        let _permit=permit;
                        let result: Result<_> = async {
                            if !freeze { return Ok((crate::history::page_pinned(&workspace,&pane,before,lines).await?, None)); }
                            ensure!(enabled, "history snapshots unsupported; refresh history");
                            let retained = if let Some(identity) = snapshot {
                                snapshots.lock().expect("snapshot cache").get(client,&identity,&pane,std::time::Instant::now())?
                            } else {
                                let reservation = snapshots.lock().expect("snapshot cache").begin(client)?;
                                let retained = Snapshot::capture(&workspace,&pane).await?;
                                snapshots.lock().expect("snapshot cache").install(reservation,retained.clone(),std::time::Instant::now())?;
                                retained
                            };
                            Ok((retained.page(before,lines)?,Some(retained.id().to_owned())))
                        }.await;
                        let (bytes,total,count,truncated,error,resolved_pane,snapshot)=match result {
                            Ok((page,snapshot))=>(page.bytes,page.total,page.lines,page.truncated,None,Some(page.pane),snapshot),
                            Err(error)=>{
                                let detail=error.to_string();
                                let message=if freeze && (detail.starts_with("history snapshot ") || detail.starts_with("history snapshots ")) {
                                    detail.chars().take(200).collect()
                                } else { "History is temporarily unavailable; the pane may have closed.".into() };
                                (Vec::new(),0,0,false,Some(message),None,None)
                            },
                        };
                        let chunks=bytes.len().max(1).div_ceil(MAX_DATA);
                        for index in 0..chunks {
                            let start=(index*MAX_DATA).min(bytes.len());let end=((index+1)*MAX_DATA).min(bytes.len());
                            let page=HistoryChunk {
                                snapshot:snapshot.clone(),request,pane:resolved_pane.clone(),data:encode_data(&bytes[start..end]),done:index+1==chunks,total,before,lines:count,truncated,error:error.clone()};
                            if send.send(Queued {scope:Some((client,generation)),output:HostOutput::History {client,page}}).await.is_err() {break;}
                        }
                    });
                    }
                    Err(_) => {
                        let _ = self.history_send.try_send(self.queued(HostOutput::History {
                            client,
                            page: HistoryChunk {
                                snapshot: None,
                                pane: None,
                                request,
                                data: String::new(),
                                done: true,
                                total: 0,
                                before,
                                lines: 0,
                                truncated: false,
                                error: Some("History is busy; try again shortly.".into()),
                            },
                        })?);
                    }
                }
            }

            HostEvent::Attach {
                client,
                read_only,
                cols,
                rows,
                term,
            } => {
                ensure!(
                    !self.clients.contains_key(&client),
                    "duplicate terminal participant identity"
                );
                let generation = self.admit_generation(client)?;
                if self.clients.len() >= self.max_viewers {
                    self.emit(HostOutput::Closed { client })?;
                    return Ok(true);
                }
                let (output, incoming) = mpsc::channel(8);
                match Client::attach_measured(
                    &self.workspace,
                    client,
                    read_only,
                    cols,
                    rows,
                    &term,
                    output,
                    self.traffic.child(),
                ) {
                    Ok(pty) => {
                        #[allow(unused_mut)]
                        let mut incoming = incoming;
                        #[cfg(feature="direct")]
                        if self.direct_enabled && self.direct_config.is_some() {
                            let (output, receive) = mpsc::channel(8);
                            let handle=crate::direct::host::spawn_measured(client,pty.input_sink(),incoming,output,self.direct_config.clone().unwrap(),pty.traffic_counter());
                            self.direct.insert(client,handle);
                            incoming = receive;
                        }
                        let send = self.send.clone();
                        self.forwarders.insert(client, tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                            forward_participant(client,generation,incoming,send)
                        )));
                        self.snapshots.lock().expect("snapshot cache").attach(client)?;
                        self.clients.insert(client, pty);
                    }
                    Err(_) => {
                        self.emit(HostOutput::Closed { client })?;
                    }
                }
            }
            HostEvent::Input { client, data } => {
                if let Some(pty) = self.clients.get(&client) {
                    if pty.input(&data).is_err() {
                        // Disconnect only the offending or backpressured viewer.
                        self.clients.remove(&client);
                        self.forwarders.remove(&client);
                        #[cfg(feature="direct")]
                        self.direct.remove(&client);
                        self.snapshots.lock().expect("snapshot cache").detach(client);
                        self.emit(HostOutput::Closed { client })?;
                    }
                }
            }
            HostEvent::Resize { client, cols, rows } => {
                if let Some(pty) = self.clients.get(&client) {
                    pty.resize(cols, rows)?;
                }
            }
            HostEvent::Detach { client } => {
                self.generations.remove(&client);
                self.forwarders.remove(&client);
                self.pending_redraw.remove(&client);
                self.clients.remove(&client);
                #[cfg(feature="direct")]
                self.direct.remove(&client);
                self.snapshots.lock().expect("snapshot cache").detach(client);
            }
            HostEvent::Ping => {
                self.emit(HostOutput::Pong)?;
            }
            HostEvent::Stop { .. } | HostEvent::Reconnect { .. } => {
                self.generations.clear();
                self.forwarders.clear();
                self.clients.clear();
                #[cfg(feature="direct")]
                self.direct.clear();
                *self.snapshots.lock().expect("snapshot cache") = SnapshotCache::default();
                return Ok(false);
            }
            HostEvent::Ready { history_snapshots, direct_transport:_direct_transport, .. } => {
                self.history_snapshots = history_snapshots;
                #[cfg(feature="direct")]
                {self.direct_enabled=_direct_transport;}
            },
            HostEvent::Presence { .. }
            | HostEvent::InvitationsRevoked
            | HostEvent::InvitationsRotated { .. } => {}
        }
        Ok(true)
    }

    pub async fn next(&mut self) -> Option<HostOutput> {
        loop {
            let queued = loop {
                // Reap completed background captures even during continuous PTY
                // output, so finished JoinSet entries cannot accumulate forever.
                while self.history_jobs.try_join_next().is_some() {}
                // Prefer interactive output, but guarantee a waiting history chunk
                // a turn after at most eight live messages. A permanently ready
                // PTY must not starve an independent read-only history request.
                if self.live_burst >= 8 {
                    if let Ok(output) = self.history_receive.try_recv() {
                        self.live_burst = 0;
                        break output;
                    }
                }
                while let Some(client) = self.pending_redraw.first().copied() {
                    let Ok(permit) = self.redraw_capacity.clone().try_acquire_owned() else {
                        break;
                    };
                    self.pending_redraw.remove(&client);
                    let Some(pty) = self.clients.get(&client) else {
                        continue;
                    };
                    let Ok(command) = pty.redraw_command(&self.workspace) else {
                        continue;
                    };
                    self.history_jobs.spawn(async move {
                        let _permit = permit;
                        let mut command = tokio::process::Command::from(command);
                        command
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .kill_on_drop(true);
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(1), command.status())
                                .await;
                    });
                }

                tokio::select! {
                    biased;
                    output=self.receive.recv()=>{
                        self.live_burst=self.live_burst.saturating_add(1);
                        break output?;
                    },
                    output=self.history_receive.recv()=>{
                        self.live_burst=0;
                        break output?;
                    },
                    _=self.history_jobs.join_next(), if !self.history_jobs.is_empty()=>{},
                }
            };
            if let Some((client, generation)) = queued.scope {
                if self.generations.get(&client) != Some(&generation) {continue;}
            }
            let output = queued.output;
            if let HostOutput::Closed { client } = &output {
                self.generations.remove(client);
                self.forwarders.remove(client);
                self.clients.remove(client);
                #[cfg(feature="direct")]
                self.direct.remove(client);
                self.snapshots.lock().expect("snapshot cache").detach(*client);
            }
            return Some(output);
        }
    }

    pub fn participants(&self) -> usize {
        self.clients.len()
    }
    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn worker_eof_reports_closed_after_a_full_output_queue_drains() -> Result<()> {
        let (send, mut receive) = mpsc::channel(1);
        send.try_send(Queued {scope:None,output:HostOutput::Pong})?;
        let (source, input) = mpsc::channel(1);
        drop(source);
        let forward = tokio::spawn(forward_participant(7,2,input,send));
        tokio::task::yield_now().await;
        assert!(!forward.is_finished(), "closure must wait for queue space");
        assert!(matches!(receive.recv().await,Some(Queued {output:HostOutput::Pong,..})));
        assert!(matches!(receive.recv().await,Some(Queued {scope:Some((7,2)),output:HostOutput::Closed {client:7}})));
        forward.await?;
        Ok(())
    }

    #[tokio::test]
    async fn worker_activity_keeps_its_attachment_generation_without_closing_it() -> Result<()> {
        let (send, mut receive) = mpsc::channel(2);
        let (source, input) = mpsc::channel(1);
        source.try_send(HostOutput::Activity)?;
        let forward = tokio::spawn(forward_participant(7,2,input,send));
        assert!(matches!(receive.recv().await,Some(Queued {scope:Some((7,2)),output:HostOutput::Activity})));
        assert!(!forward.is_finished());
        drop(source);
        assert!(matches!(receive.recv().await,Some(Queued {scope:Some((7,2)),output:HostOutput::Closed {client:7}})));
        forward.await?;
        Ok(())
    }

    #[tokio::test]
    async fn worker_cannot_route_events_to_an_independent_participant() -> Result<()> {
        let (send, mut receive) = mpsc::channel(2);
        let (source, input) = mpsc::channel(1);
        source.try_send(HostOutput::Closed {client:8})?;
        let forward = tokio::spawn(forward_participant(7,2,input,send));
        assert!(matches!(receive.recv().await,Some(Queued {scope:Some((7,2)),output:HostOutput::Closed {client:7}})));
        forward.await?;
        assert!(receive.recv().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn stale_pty_and_history_callbacks_cannot_cross_attachment_generations() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let workspace = Workspace::open("/unused-runtime".into(), "/unused-terminfo".into(), directory.path().into())?;
        let mut router = Attachments::new(workspace, 2)?;
        let old = router.admit_generation(7)?;
        let fresh = router.admit_generation(7)?;
        let independent = router.admit_generation(8)?;
        router.send.try_send(Queued {scope:Some((7,old)),output:HostOutput::Closed {client:7}})?;
        router.send.try_send(Queued {scope:Some((7,old)),output:HostOutput::Output {client:7,data:encode_data(b"old screen")}})?;
        let history = |request| HostOutput::History {client:7,page:HistoryChunk {
            snapshot:None,pane:None,request,data:String::new(),done:true,total:0,before:0,lines:0,truncated:false,error:None,
        }};
        router.history_send.try_send(Queued {scope:Some((7,old)),output:history(1)})?;
        router.history_send.try_send(Queued {scope:Some((7,fresh)),output:history(2)})?;
        router.emit(HostOutput::Pong)?;
        assert!(matches!(router.next().await,Some(HostOutput::Pong)));
        assert_eq!(router.generations.get(&7),Some(&fresh));
        assert!(matches!(router.next().await,Some(HostOutput::History {client:7,page}) if page.request==2));
        router.emit(HostOutput::Closed {client:7})?;
        assert!(matches!(router.next().await,Some(HostOutput::Closed {client:7})));
        assert!(!router.generations.contains_key(&7));
        assert_eq!(router.generations.get(&8),Some(&independent));
        Ok(())
    }

    #[tokio::test]
    async fn history_is_served_during_continuously_ready_live_output() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let workspace = Workspace::open(
            "/unused-runtime".into(),
            "/unused-terminfo".into(),
            directory.path().into(),
        )?;
        let mut attachments = Attachments::new(workspace, 1)?;
        attachments.admit_generation(7)?;
        // Keep the live queue ready without OS scheduling or a running shell.
        for _ in 0..128 {
            attachments.emit(HostOutput::Pong)?;
        }
        attachments.history_send.try_send(attachments.queued(HostOutput::History {
            client: 7,
            page: HistoryChunk {
                snapshot: None,
                pane: None,
                request: 19,
                data: String::new(),
                done: true,
                total: 0,
                before: 0,
                lines: 0,
                truncated: false,
                error: None,
            },
        })?)?;
        for _ in 0..8 {
            assert!(matches!(attachments.next().await, Some(HostOutput::Pong)));
        }
        assert!(
            matches!(
                attachments.next().await,
                Some(HostOutput::History { client: 7, .. })
            ),
            "history must not starve behind a busy live output queue"
        );
        assert!(matches!(attachments.next().await, Some(HostOutput::Pong)));
        Ok(())
    }
}
