//! Persistent sharing supervisor. Core's local broker alone injects gateway credentials.
use crate::workspace::{private, read_private, select, workspace, write_private};
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use porthub_components::protocol::terminal::Broker;
use porthub_terminal::multiplexer::Workspace;
use porthub_terminal::{host::Attachments, protocol::*};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncWriteExt, BufReader};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectPolicy {
    #[serde(rename = "type")]
    kind: String,
    addresses: Vec<std::net::IpAddr>,
    stun_servers: Vec<String>,
}
pub(crate) async fn connect_broker(broker: &Broker) -> Result<tokio::net::UnixStream> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = fs::symlink_metadata(&broker.endpoint)?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == broker.owner,
        "local registration endpoint is not trusted"
    );
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::UnixStream::connect(&broker.endpoint),
    )
    .await??;
    ensure!(
        stream.peer_cred()?.uid() == broker.owner,
        "local registration agent identity mismatch"
    );
    Ok(stream)
}
#[derive(Clone, Serialize, Deserialize)]
struct Ready {
    ssh_host: String,
    ssh_port: u16,
    public_base: String,
}
#[derive(Serialize, Deserialize)]
struct Sharing {
    #[serde(default)]
    broker: Option<Broker>,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    invitations: Option<InvitationUpdate>,
    #[serde(default)]
    pending_invitations: Option<InvitationUpdate>,
    #[serde(default)]
    invitations_revoked: bool,
    hello: HostHello,
    registration: String,
    user: bool,
    ready: Option<Ready>,
    state: String,
}

fn path(root: &Path, id: &str) -> Result<PathBuf> {
    ensure!(token(id, 32), "invalid terminal session identity");
    Ok(root.join(format!("{id}.share")))
}
fn load(root: &Path, id: &str) -> Result<Sharing> {
    let sharing: Sharing = serde_json::from_slice(&read_private(&path(root, id)?)?)?;
    ensure!(sharing.hello.id == id, "terminal sharing identity mismatch");
    sharing.hello.validate(now())?;
    porthub_terminal::connectivity::checked(&sharing.stun_servers)?;
    if let Some(update) = &sharing.invitations {
        update.validate(now())?;
    }
    if let Some(pending) = &sharing.pending_invitations {
        pending.validate(now())?;
        ensure!(
            pending.revision
                == sharing
                    .invitations
                    .as_ref()
                    .map_or(0, |u| u.revision)
                    .saturating_add(1),
            "invalid pending invitation revision"
        );
    }
    Ok(sharing)
}
fn save(root: &Path, sharing: &Sharing, replace: bool) -> Result<()> {
    write_private(
        &path(root, &sharing.hello.id)?,
        &serde_json::to_vec(sharing)?,
        replace,
    )
}
fn worker_lock(root: &Path, id: &str) -> Result<fs::File> {
    ensure!(token(id, 32), "invalid terminal session identity");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(root.join(format!("{id}.share.lock")))?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal supervisor lock owner"
    );
    file.try_lock_exclusive()
        .context("terminal sharing supervisor is already running")?;
    Ok(file)
}
fn enforce_limits(workspace: &Workspace, options: &Options) -> Result<()> {
    if !workspace.is_alive() {
        return Ok(());
    }
    let session_expired = options.session_expires_at.is_some_and(|at| now() >= at);
    let idle = options.idle_timeout != 0
        && now().saturating_sub(workspace.last_activity()?) >= i64::from(options.idle_timeout);
    if session_expired || idle {
        workspace.stop()?;
    }
    Ok(())
}

// Credential-free broker metadata is a compatibility hint, never authority.
// Legacy brokers reject unknown HostHello fields before opening the gateway.
#[cfg(test)]
fn broker_has_history_snapshots(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let parsed: Option<Vec<u32>> = parts
        .iter()
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        })
        .collect();
    parsed.is_some_and(|v| (v[0], v[1], v[2]) >= (1, 10, 0))
}

fn prepare_rotation(root: &Path, sharing: &mut Sharing, seconds: u32) -> Result<InvitationUpdate> {
    ensure!(seconds <= 604800, "invitation lifetime exceeds seven days");
    if let Some(update) = &sharing.pending_invitations {
        return Ok(update.clone());
    }
    let revision = sharing
        .invitations
        .as_ref()
        .map_or(0, |u| u.revision)
        .checked_add(1)
        .context("invitation revision exhausted")?;
    let update = InvitationUpdate {
        revision,
        write_token: random_token(32),
        read_token: random_token(32),
        expires_at: if seconds == 0 {
            0
        } else {
            now() + i64::from(seconds)
        },
    };
    update.validate(now())?;
    sharing.pending_invitations = Some(update.clone());
    if let Err(error) = save(root, sharing, true) {
        sharing.pending_invitations = None;
        return Err(error);
    }
    Ok(update)
}

fn broker_request(
    hello: &HostHello,
    extensions: bool,
    stun_servers: &[String],
) -> serde_json::Value {
    let mut hello = hello.clone();
    if !extensions {
        hello.history_snapshots = false;
        hello.direct_transport = false;
    }
    let mut request = serde_json::json!({"operation":"terminal_host","hello":hello});
    if extensions {
        request["traffic_reporting"] = true.into();
        if !stun_servers.is_empty() {
            request["stun_servers"] = serde_json::json!(stun_servers);
        }
    }
    request
}

async fn report_traffic<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    emitter: &mut Option<crate::sharing_telemetry::Emitter>,
    attachments: &Attachments,
) -> Result<()> {
    let Some(emitter) = emitter else {
        return Ok(());
    };
    let report = emitter.report(attachments.traffic())?;
    let mut bytes = serde_json::to_vec(&report)?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(&bytes)).await??;
    Ok(())
}

pub async fn serve(root: &Path, id: &str) -> Result<()> {
    private(root)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let _guard = loop {
        match worker_lock(root, id) {
            Ok(guard) => break guard,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(error) => return Err(error),
        }
    };
    let job = select(root, id)?;
    let workspace = workspace(&job)?;
    let mut owner = crate::owner::participant_control::Server::start(&job)?;
    let mut sharing = load(root, id)?;
    sharing.hello.direct_transport &= cfg!(feature = "terminal-direct");
    owner.state.lock().expect("owner state").invitations_revoked = sharing.invitations_revoked;
    {
        let mut state = owner.state.lock().expect("owner state");
        state.invitation_revision = sharing.invitations.as_ref().map_or(0, |u| u.revision);
        state.rotation_pending = sharing.pending_invitations.is_some();
    }

    ensure!(sharing.state != "ended", "sharing session has ended");
    let broker = sharing
        .broker
        .clone()
        .context("terminal share requires a core-selected local broker")?;
    let mut delay = 1;
    loop {
        enforce_limits(&workspace, &sharing.hello.options)?;
        {
            let mut state = owner.state.lock().expect("owner state");
            state.connected = false;
            state.members.clear();
        }
        sharing.state = "reconnecting".into();
        save(root, &sharing, true)?;
        let result = tokio::time::timeout(Duration::from_secs(10), connect_broker(&broker)).await;
        if let Ok(Ok(stream)) = result {
            let mut local = BufReader::new(stream);
            let traffic_requested = broker.traffic;
            let mut request = serde_json::to_vec(&broker_request(
                &sharing.hello,
                traffic_requested,
                &sharing.stun_servers,
            ))?;
            request.push(b'\n');
            if local.get_mut().write_all(&request).await.is_ok() {
                let mut attachments = Attachments::new(
                    workspace.clone(),
                    usize::from(sharing.hello.options.max_viewers),
                )?;
                let mut partial = Vec::new();
                let mut traffic = None;
                let mut last_traffic = tokio::time::Instant::now();
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                let mut last_gateway = tokio::time::Instant::now();
                loop {
                    tokio::select! {
                        bytes=crate::owner::frame(&mut local,&mut partial)=> {
                            let Ok(bytes)=bytes else{break;};
                            let Ok(value)=serde_json::from_slice::<serde_json::Value>(&bytes) else {break;};
                            if value.get("type").and_then(serde_json::Value::as_str)==Some("terminal_traffic_policy") {
                                ensure!(traffic_requested && traffic.is_none(),"unsolicited terminal traffic policy");
                                traffic=Some(crate::sharing_telemetry::Emitter::new(serde_json::from_value(value)?)?);
                                continue;
                            }
                            #[cfg(feature="terminal-direct")]
                            if value.get("type").and_then(serde_json::Value::as_str)==Some("terminal_direct_policy") {
                                let policy:DirectPolicy=serde_json::from_value(value)?;
                                attachments.configure_direct(porthub_terminal::direct::host::Config {
                                    addresses:policy.addresses,stun_servers:policy.stun_servers,
                                })?;
                                continue;
                            }
                            let Ok(event)=serde_json::from_value::<HostEvent>(value) else{break;};
                            last_gateway=tokio::time::Instant::now();
                            if matches!(event,HostEvent::Stop{..}) {
                                sharing.state="ended".into();save(root,&sharing,true)?;
                                // Revocation ends sharing. The local owner keeps
                                // the workspace and can explicitly stop it.
                                return Ok(());
                            }
                            if let HostEvent::Presence { members } = &event {
                                let mut state=owner.state.lock().expect("owner state");state.connected=true;state.members=members.clone();
                            }
                            if let HostEvent::InvitationsRotated {revision,expires_at,invitations_revoked}=&event {
                                if sharing.pending_invitations.as_ref().is_some_and(|u| u.revision==*revision && u.expires_at==*expires_at) {
                                    sharing.invitations=sharing.pending_invitations.take();
                                    sharing.invitations_revoked=*invitations_revoked;
                                    save(root,&sharing,true)?;
                                    let mut state=owner.state.lock().expect("owner state");
                                    state.invitation_revision=*revision;state.rotation_pending=false;state.invitations_revoked=*invitations_revoked;
                                }
                            }
                            if let HostEvent::InvitationsRevoked=&event {sharing.invitations_revoked=true;save(root,&sharing,true)?;owner.state.lock().expect("owner state").invitations_revoked=true;}
                            if let HostEvent::Ready{ssh_host,ssh_port,public_base,invitations_revoked,..}=&event {
                                sharing.invitations_revoked|=*invitations_revoked;
                                sharing.ready=Some(Ready{ssh_host:ssh_host.clone(),ssh_port:*ssh_port,public_base:public_base.clone()});
                                sharing.state="connected".into();save(root,&sharing,true)?;owner.state.lock().expect("owner state").invitations_revoked=sharing.invitations_revoked;delay=1;
                                if let Some(update)=sharing.pending_invitations.clone() {
                                    let mut frame=serde_json::to_vec(&HostOutput::RotateInvitations {update})?;frame.push(b'\n');
                                    if !matches!(tokio::time::timeout(Duration::from_secs(2),local.get_mut().write_all(&frame)).await,Ok(Ok(()))) {break;}
                                }

                            }
                            if !attachments.apply(event)?{break;}
                        }
                        request=owner.requests.recv()=> {
                            let Some((action, reply))=request else {break;};
                            let output=match action {
                                crate::owner::participant_control::Action::Kick(client)=>HostOutput::Kick{client},
                                crate::owner::participant_control::Action::RevokeInvitations=>{
                                    if sharing.pending_invitations.is_some() {let _=reply.send(Err("invitation rotation still pending".into()));continue;}
                                    HostOutput::RevokeInvitations
                                },
                                crate::owner::participant_control::Action::RotateInvitations(seconds)=>{
                                    let update=match prepare_rotation(root,&mut sharing,seconds) {
                                        Ok(update)=>update,
                                        Err(error)=>{let _=reply.send(Err(error.to_string()));continue;}
                                    };
                                    owner.state.lock().expect("owner state").rotation_pending=true;
                                    HostOutput::RotateInvitations {update}
                                }
                            };
                            let bytes=serde_json::to_vec(&output)?;
                            let mut frame=bytes;frame.push(b'\n');
                            let result=tokio::time::timeout(Duration::from_secs(2),local.get_mut().write_all(&frame)).await;
                            let ok=matches!(result,Ok(Ok(())));
                            let _=reply.send(if ok {Ok(())} else {Err("gateway connection unavailable".into())});
                            if !ok {break;}
                        }
                        output=attachments.next()=> {
                            let Some(output)=output else{break;};
                            if matches!(output,HostOutput::Closed {..}) {
                                if report_traffic(local.get_mut(),&mut traffic,&attachments).await.is_err() {break;}
                            }
                            let mut bytes=serde_json::to_vec(&output)?;bytes.push(b'\n');
                            if !matches!(tokio::time::timeout(Duration::from_secs(5),local.get_mut().write_all(&bytes)).await,Ok(Ok(()))){break;}
                        }
                        _=tick.tick()=> {
                            enforce_limits(&workspace,&sharing.hello.options)?;
                            let alive=workspace.is_alive();
                            if last_traffic.elapsed()>=Duration::from_secs(5) || !alive {
                                if report_traffic(local.get_mut(),&mut traffic,&attachments).await.is_err() {break;}
                                last_traffic=tokio::time::Instant::now();
                            }
                            if !alive {
                                sharing.state="ended".into();save(root,&sharing,true)?;
                                let _=tokio::time::timeout(Duration::from_secs(2),local.get_mut().write_all(b"{\"type\":\"end\"}\n")).await;
                                return Ok(());
                            }
                            if last_gateway.elapsed()>Duration::from_secs(45){break;}
                        }
                    }
                }
            }
        }
        {
            let mut state = owner.state.lock().expect("owner state");
            state.connected = false;
            state.members.clear();
        }
        while let Ok((_, reply)) = owner.requests.try_recv() {
            let _ = reply.send(Err("gateway reconnecting; refresh participants".into()));
        }
        sharing.state = "reconnecting".into();
        save(root, &sharing, true)?;
        if !workspace.is_alive() {
            sharing.state = "ended".into();
            save(root, &sharing, true)?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = (delay * 2).min(15);
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    #[test]
    fn snapshot_advertisement_requires_a_compatible_broker_version() {
        for version in [
            "",
            "2fb9d6e",
            "1.9.0",
            "1.9.99",
            "1.10",
            "1.10.0.extra",
            "1.10.x",
            "1.10.0-preview",
        ] {
            assert!(!broker_has_history_snapshots(version), "{version}");
        }
        for version in ["1.10.0", "1.11.0", "2.0.0"] {
            assert!(broker_has_history_snapshots(version), "{version}");
        }
    }

    #[test]
    fn older_broker_requests_omit_extensions_without_modifying_the_saved_session() -> Result<()> {
        let hello: HostHello = serde_json::from_value(serde_json::json!({
            "id":random_token(16),"secret":random_token(32),"write_token":random_token(32),"read_token":random_token(32),
            "history_snapshots":true,"direct_transport":true,
            "options":{"name":"quietotter","expires_at":0,"idle_timeout":0,"reconnect_timeout":60,"history_limit":100000,"mouse":true,"read_only":false,"size_policy":"smallest"}}))?;
        let servers = vec!["stun:127.0.0.1:3478".into()];
        let old = broker_request(&hello, false, &servers);
        assert_eq!(old.as_object().unwrap().len(), 2);
        assert!(
            old["hello"].get("history_snapshots").is_none()
                && old["hello"].get("direct_transport").is_none()
        );
        assert!(
            hello.history_snapshots && hello.direct_transport,
            "compatibility negotiation must not downgrade saved capabilities"
        );
        let current = broker_request(&hello, true, &servers);
        assert_eq!(current["stun_servers"], serde_json::json!(servers));
        assert!(current["hello"].get("stun_servers").is_none());
        assert_eq!(current["traffic_reporting"], true);
        assert_eq!(current["hello"]["history_snapshots"], true);
        Ok(())
    }

    #[test]
    fn failed_save_cannot_be_retried_as_unsaved_rotation_and_saved_retry_reuses_links() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let mut sharing: Sharing = serde_json::from_value(serde_json::json!({
            "hello":{"id":random_token(16),"secret":random_token(32),"write_token":random_token(32),"read_token":random_token(32),
                "options":{"name":"quietotter","expires_at":0,"idle_timeout":0,"reconnect_timeout":60,"history_limit":100000,"mouse":true,"read_only":false,"size_policy":"smallest"}},
            "registration":random_token(32),"user":true,"ready":null,"state":"connected"
        }))?;
        let invalid = temp.path().join("file");
        fs::write(&invalid, b"untouched")?;
        assert!(prepare_rotation(&invalid, &mut sharing, 60).is_err());
        assert!(
            sharing.pending_invitations.is_none(),
            "failed save cannot create a sendable in-memory update"
        );
        assert_eq!(fs::read(invalid)?, b"untouched");
        let saved = prepare_rotation(temp.path(), &mut sharing, 60)?;
        let mut restored = load(temp.path(), &sharing.hello.id)?;
        let retry = prepare_rotation(temp.path(), &mut restored, 3600)?;
        assert_eq!(saved.write_token, retry.write_token);
        assert_eq!(saved.read_token, retry.read_token);
        assert_eq!(saved.expires_at, retry.expires_at);
        assert_eq!(retry.revision, 1);
        Ok(())
    }
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    #[tokio::test]
    async fn local_broker_requires_a_socket_and_matching_os_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("broker.sock");
        let owner = unsafe { libc::geteuid() };
        let broker = Broker {
            endpoint: path.clone(),
            owner,
            traffic: false,
        };
        fs::write(&path, b"unchanged")?;
        assert!(connect_broker(&broker).await.is_err());
        assert_eq!(fs::read(&path)?, b"unchanged");
        fs::remove_file(&path)?;
        let listener = tokio::net::UnixListener::bind(&path)?;
        let wrong = Broker {
            owner: owner.wrapping_add(1),
            ..broker.clone()
        };
        assert!(connect_broker(&wrong).await.is_err());
        let (client, server) = tokio::join!(connect_broker(&broker), listener.accept());
        drop(client?);
        drop(server?);
        Ok(())
    }
}
