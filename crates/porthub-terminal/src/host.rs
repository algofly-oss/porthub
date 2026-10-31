//! Remote attachments for one transport generation. Replace this router on
//! reconnect, retaining its Workspace; old PTY events cannot enter the new link.
use crate::{multiplexer::Workspace, protocol::*, pty::Client};
use anyhow::{ensure, Result};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::mpsc;

pub struct Attachments {
    workspace: Workspace,
    clients: BTreeMap<u64, Client>,
    send: mpsc::Sender<HostOutput>,
    receive: mpsc::Receiver<HostOutput>,
    max_viewers: usize,
    history_send: mpsc::Sender<HostOutput>,
    history_receive: mpsc::Receiver<HostOutput>,
    history_jobs: tokio::task::JoinSet<()>,
    history_capacity: std::sync::Arc<tokio::sync::Semaphore>,
    pending_redraw: BTreeSet<u64>,
    redraw_capacity: std::sync::Arc<tokio::sync::Semaphore>,
    live_burst: u8,
}

impl Attachments {
    pub fn new(workspace: Workspace, max_viewers: usize) -> Result<Self> {
        ensure!(
            (1..=MAX_VIEWERS).contains(&max_viewers),
            "invalid terminal participant limit"
        );
        let (send, receive) = mpsc::channel(128);
        let (history_send, history_receive) = mpsc::channel(8);
        Ok(Self {
            workspace,
            clients: BTreeMap::new(),
            send,
            receive,
            max_viewers,
            history_send,
            history_receive,
            history_jobs: tokio::task::JoinSet::new(),
            history_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            pending_redraw: BTreeSet::new(),
            redraw_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            live_burst: 0,
        })
    }

    /// A false result ends this transport, while keeping the shared workspace.
    pub fn apply(&mut self, event: HostEvent) -> Result<bool> {
        match event {
            HostEvent::Redraw { client } => {
                if self.clients.contains_key(&client) {
                    self.pending_redraw.insert(client);
                }
            }

            HostEvent::History {
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
                let workspace = self.workspace.clone();
                let send = self.history_send.clone();
                match self.history_capacity.clone().try_acquire_owned() {
                    Ok(permit) => {
                        self.history_jobs.spawn(async move {
                        let _permit=permit;
                        let result=crate::history::page(&workspace,&pane,before,lines).await;
                        let (bytes,total,count,truncated,error)=match result {
                            Ok((bytes,total,count,truncated))=>(bytes,total,count,truncated,None),
                            Err(_)=>(Vec::new(),0,0,false,Some("History is temporarily unavailable; the pane may have closed.".into())),
                        };
                        let chunks=bytes.len().max(1).div_ceil(MAX_DATA);
                        for index in 0..chunks {
                            let start=(index*MAX_DATA).min(bytes.len());let end=((index+1)*MAX_DATA).min(bytes.len());
                            let page=HistoryChunk {request,data:encode_data(&bytes[start..end]),done:index+1==chunks,total,before,lines:count,truncated,error:error.clone()};
                            if send.send(HostOutput::History {client,page}).await.is_err() {break;}
                        }
                    });
                    }
                    Err(_) => {
                        let _ = self.history_send.try_send(HostOutput::History {
                            client,
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
                        });
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
                if self.clients.len() >= self.max_viewers {
                    self.send.try_send(HostOutput::Closed { client })?;
                    return Ok(true);
                }
                match Client::attach(
                    &self.workspace,
                    client,
                    read_only,
                    cols,
                    rows,
                    &term,
                    self.send.clone(),
                ) {
                    Ok(pty) => {
                        self.clients.insert(client, pty);
                    }
                    Err(_) => {
                        self.send.try_send(HostOutput::Closed { client })?;
                    }
                }
            }
            HostEvent::Input { client, data } => {
                if let Some(pty) = self.clients.get(&client) {
                    if pty.input(&data).is_err() {
                        // Disconnect only the offending or backpressured viewer.
                        self.clients.remove(&client);
                        self.send.try_send(HostOutput::Closed { client })?;
                    }
                }
            }
            HostEvent::Resize { client, cols, rows } => {
                if let Some(pty) = self.clients.get(&client) {
                    pty.resize(cols, rows)?;
                }
            }
            HostEvent::Detach { client } => {
                self.pending_redraw.remove(&client);
                self.clients.remove(&client);
            }
            HostEvent::Ping => {
                self.send.try_send(HostOutput::Pong)?;
            }
            HostEvent::Stop { .. } | HostEvent::Reconnect { .. } => {
                self.clients.clear();
                return Ok(false);
            }
            HostEvent::Ready { .. }
            | HostEvent::Presence { .. }
            | HostEvent::InvitationsRevoked
            | HostEvent::InvitationsRotated { .. } => {}
        }
        Ok(true)
    }

    pub async fn next(&mut self) -> Option<HostOutput> {
        let output = loop {
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
        if let HostOutput::Closed { client } = &output {
            self.clients.remove(client);
        }
        Some(output)
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
    async fn history_is_served_during_continuously_ready_live_output() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let workspace = Workspace::open(
            "/unused-runtime".into(),
            "/unused-terminfo".into(),
            directory.path().into(),
        )?;
        let mut attachments = Attachments::new(workspace, 1)?;
        // Keep the live queue ready without OS scheduling or a running shell.
        for _ in 0..128 {
            attachments.send.try_send(HostOutput::Pong)?;
        }
        attachments.history_send.try_send(HostOutput::History {
            client: 7,
            page: HistoryChunk {
                request: 19,
                data: String::new(),
                done: true,
                total: 0,
                before: 0,
                lines: 0,
                truncated: false,
                error: None,
            },
        })?;
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
