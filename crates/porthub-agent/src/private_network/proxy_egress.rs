//! A UI-authorized outbound proxy stream. No listener, packet route, system
//! setting, or service is created on the serving peer.
use anyhow::{ensure, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, protocol::WebSocketConfig, Message,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    host: String,
    port: u16,
    allow_lan: bool,
    overlay: Vec<IpAddr>,
}
#[derive(Serialize)]
struct Ready {
    destination_ip: IpAddr,
}
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
async fn connect(
    profile: &crate::private_profile::Profile,
    origins: &[String],
    sources: &[SocketAddr],
    path: &str,
    limit: usize,
) -> Result<Socket> {
    let local: Vec<_> = sources.iter().map(SocketAddr::ip).collect();
    ensure!(!local.is_empty(), "peer proxy underlay is unavailable");
    for origin in origins {
        let Ok(mut url) = url::Url::parse(&format!("{}{path}", origin.trim_end_matches('/')))
        else {
            continue;
        };
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" => "ws",
            _ => continue,
        };
        if url.set_scheme(scheme).is_err() {
            continue;
        }
        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            let stream = porthub_mesh::underlay::connect(&url, &local).await?;
            let _ = stream.set_nodelay(true);
            let mut request = url.as_str().into_client_request()?;
            request
                .headers_mut()
                .insert("x-porthub-peer", profile.peer_id.parse()?);
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {}", profile.token).parse()?,
            );
            let limits = WebSocketConfig::default()
                .read_buffer_size(8192)
                .write_buffer_size(8192)
                .max_message_size(Some(limit))
                .max_frame_size(Some(limit));
            Ok::<_, anyhow::Error>(
                tokio_tungstenite::client_async_tls_with_config(
                    request,
                    stream,
                    Some(limits),
                    None,
                )
                .await?
                .0,
            )
        })
        .await;
        if let Ok(Ok(socket)) = connected {
            return Ok(socket);
        }
    }
    anyhow::bail!("peer proxy gateway unavailable")
}
pub(super) async fn run(
    profile: &crate::private_profile::Profile,
    id: &str,
    origins: &[String],
    sources: &[SocketAddr],
) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid peer proxy session"
    );
    let mut socket = connect(
        profile,
        origins,
        sources,
        &format!("/api/access/proxy-serve/{id}"),
        65536,
    )
    .await?;
    let policy = tokio::time::timeout(Duration::from_secs(5), socket.next()).await?;
    let Some(Ok(Message::Text(policy))) = policy else {
        anyhow::bail!("peer proxy policy was not delivered");
    };
    let policy: Policy = serde_json::from_str(&policy)?;
    ensure!(
        policy.overlay.len() <= 4096,
        "peer proxy policy exceeds limits"
    );
    let destination = porthub_egress::Destination::new(policy.host, policy.port)?;
    let mut remote = tokio::time::timeout(Duration::from_secs(8), async {
        let addresses: Vec<_> =
            tokio::net::lookup_host((destination.host.as_str(), destination.port))
                .await?
                .take(32)
                .collect();
        ensure!(
            !addresses.is_empty()
                && addresses
                    .iter()
                    .all(|address| porthub_egress::destination::permitted(
                        address.ip(),
                        policy.allow_lan,
                        &policy.overlay
                    )),
            "peer proxy target is outside its grant"
        );
        for address in addresses {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(address),
            )
            .await
            {
                return Ok(stream);
            }
        }
        anyhow::bail!("peer proxy destination unavailable")
    })
    .await??;
    let _ = remote.set_nodelay(true);
    socket
        .send(Message::Text(
            serde_json::to_string(&Ready {
                destination_ip: remote.peer_addr()?.ip(),
            })?
            .into(),
        ))
        .await?;
    let mut carrier = porthub_egress::websocket::stream(socket)?;
    tokio::io::copy_bidirectional(&mut carrier, &mut remote).await?;
    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq)]
struct Configuration {
    origins: Vec<String>,
    provider: bool,
}
struct Task {
    cancel: tokio_util::sync::CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}
impl Drop for Task {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}
pub(super) struct Manager {
    configuration: tokio::sync::watch::Sender<Configuration>,
    jobs: tokio::sync::mpsc::Sender<String>,
    _task: Task,
}
impl Manager {
    pub fn start(
        profile: crate::private_profile::Profile,
        interfaces: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        let (configuration, changes) = tokio::sync::watch::channel(Configuration::default());
        let (jobs, receiver) = tokio::sync::mpsc::channel(128);
        let work = cancel.child_token();
        let owner = work.clone();
        let notifications = jobs.clone();
        let handle = tokio::spawn(async move {
            manage(profile, interfaces, changes, notifications, receiver, work).await;
        });
        Self {
            configuration,
            jobs,
            _task: Task {
                cancel: owner,
                handle,
            },
        }
    }
    pub fn update(&self, origins: Vec<String>, provider: bool, jobs: &[String]) {
        let configuration = Configuration { origins, provider };
        if *self.configuration.borrow() != configuration {
            self.configuration.send_replace(configuration);
        }
        for id in jobs {
            let _ = self.jobs.try_send(id.clone());
        }
    }
}
async fn manage(
    profile: crate::private_profile::Profile,
    mut interfaces: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
    mut changes: tokio::sync::watch::Receiver<Configuration>,
    notifications: tokio::sync::mpsc::Sender<String>,
    mut jobs: tokio::sync::mpsc::Receiver<String>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut workers = tokio::task::JoinSet::new();
    let mut active = std::collections::HashMap::<String, tokio::task::Id>::new();
    let mut completed = std::collections::HashMap::new();
    let mut subscription = None::<Task>;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            changed=changes.changed()=>{
                if changed.is_err(){break;}
                subscription.take();
                let config=changes.borrow_and_update().clone();
                if config.provider {
                    let profile=profile.clone();let sources=interfaces.borrow().clone();let notifications=notifications.clone();
                    let work=cancel.child_token();let stop=work.clone();
                    let handle=tokio::spawn(async move {watch_jobs(&profile,&config.origins,&sources,notifications,work).await;});
                    subscription=Some(Task{cancel:stop,handle});
                }
            },
            changed=interfaces.changed()=>{
                if changed.is_err(){break;}
                subscription.take();
                let config=changes.borrow().clone();
                if config.provider {
                    let profile=profile.clone();let sources=interfaces.borrow_and_update().clone();let notifications=notifications.clone();
                    let work=cancel.child_token();let stop=work.clone();
                    let handle=tokio::spawn(async move {watch_jobs(&profile,&config.origins,&sources,notifications,work).await;});
                    subscription=Some(Task{cancel:stop,handle});
                }
            },
            result=workers.join_next(),if !workers.is_empty()=>{
                let finished=match result {
                    Some(Ok(id))=>Some(id),
                    Some(Err(error))=>active.iter().find(|(_,task)|**task==error.id()).map(|(id,_)|id.clone()),
                    None=>None,
                };
                if let Some(id)=finished {
                    active.remove(&id);
                    if completed.len()<4096 {completed.insert(id,std::time::Instant::now()+Duration::from_secs(30));}
                }
            },
            id=jobs.recv()=>{
                let Some(id)=id else {break;};
                completed.retain(|_,expires|*expires>std::time::Instant::now());
                if id.len()!=32 || !id.bytes().all(|byte|byte.is_ascii_hexdigit()) || active.len()>=64 || completed.contains_key(&id) || active.contains_key(&id){continue;}
                let profile=profile.clone();let config=changes.borrow().clone();let sources=interfaces.borrow().clone();
                let identity=id.clone();
                let task=workers.spawn(async move {let _=run(&profile,&id,&config.origins,&sources).await;id});
                active.insert(identity,task.id());
            },
        }
    }
    drop(subscription);
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}
async fn watch_jobs(
    profile: &crate::private_profile::Profile,
    origins: &[String],
    sources: &[SocketAddr],
    jobs: tokio::sync::mpsc::Sender<String>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut backoff = 1;
    loop {
        let result = tokio::select! {_=cancel.cancelled()=>return,result=connect(profile,origins,sources,"/api/access/proxy-jobs",1024)=>result};
        if let Ok(mut socket) = result {
            backoff = 1;
            loop {
                let message = tokio::select! {_=cancel.cancelled()=>return,result=tokio::time::timeout(Duration::from_secs(75),socket.next())=>result};
                match message {
                    Ok(Some(Ok(Message::Text(id))))
                        if id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                    {
                        let _ = jobs.try_send(id.to_string());
                    }
                    Ok(Some(Ok(Message::Ping(_)))) => {
                        if socket.flush().await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Ok(Message::Pong(_)))) => {}
                    _ => break,
                }
            }
        }
        tokio::select! {_=cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(backoff))=>{}}
        backoff = (backoff * 2).min(60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn an_authenticated_policy_cannot_open_loopback_even_with_lan_enabled() -> Result<()> {
        let gateway = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", gateway.local_addr()?);
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = target.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (socket, _) = gateway.accept().await?;
            let mut socket = tokio_tungstenite::accept_async(socket).await?;
            socket.send(Message::Text(serde_json::json!({"host":"127.0.0.1","port":port,"allow_lan":true,"overlay":[]}).to_string().into())).await?;
            assert!(!matches!(socket.next().await, Some(Ok(Message::Text(_)))));
            Ok::<_, anyhow::Error>(())
        });
        let profile = crate::private_profile::Profile {
            server: origin.clone(),
            peer_id: "fixture-peer".into(),
            token: "fixture-private-token-01234567890123456789".into(),
            workspace: "fixture".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: true,
        };
        assert!(run(
            &profile,
            &"a".repeat(32),
            &[origin],
            &["127.0.0.1:0".parse()?]
        )
        .await
        .is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        server.await??;
        Ok(())
    }
    #[tokio::test]
    async fn provider_is_idle_until_enabled_and_deduplicates_push_and_sync_jobs() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let profile = crate::private_profile::Profile {
            server: origin.clone(),
            peer_id: "fixture-peer".into(),
            token: "fixture-private-token-01234567890123456789".into(),
            workspace: "fixture".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: true,
        };
        let (_updates, sources) = tokio::sync::watch::channel(vec!["127.0.0.1:0".parse()?]);
        let manager = Manager::start(profile, sources, tokio_util::sync::CancellationToken::new());
        manager.update(vec![origin.clone()], false, &[]);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        manager.update(vec![origin.clone()], true, &[]);
        let (socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        let mut notifications = tokio_tungstenite::accept_async(socket).await?;
        notifications.send(Message::Ping(vec![1].into())).await?;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), notifications.next()).await?,
            Some(Ok(Message::Pong(_)))
        ));
        let id = "a".repeat(32);
        notifications.send(Message::Text(id.clone().into())).await?;
        let (socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        let mut provider = tokio_tungstenite::accept_async(socket).await?;
        provider
            .send(Message::Text(
                serde_json::json!({"host":"127.0.0.1","port":9,"allow_lan":true,"overlay":[]})
                    .to_string()
                    .into(),
            ))
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(2), provider.next()).await?;
        // The same session can arrive through both the live channel and sync.
        tokio::time::sleep(Duration::from_millis(50)).await;
        notifications.send(Message::Text(id.clone().into())).await?;
        manager.update(vec![origin], true, &[id]);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
        drop(manager);
        let closed = tokio::time::timeout(Duration::from_secs(2), notifications.next()).await?;
        assert!(matches!(
            closed,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
        Ok(())
    }
}
