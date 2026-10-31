//! Ephemeral public terminal invitations. Capability hashes and revocations are
//! persisted; terminal contents are only routed through bounded live channels.
use crate::{
    domain::machine_client,
    error::{ApiError, ApiResult},
    store, App,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use mongodb::bson::{doc, DateTime};
use porthub_terminal::protocol::*;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Settings {
    pub ssh_socket: Option<PathBuf>,
    pub host_key: PathBuf,
    pub ssh_host: String,
    pub ssh_port: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ssh_socket: None,
            host_key: PathBuf::from("/data/terminal/ssh_host_ed25519"),
            ssh_host: String::new(),
            ssh_port: 8347,
        }
    }
}
impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        let mut settings = Self::default();
        settings.ssh_socket = std::env::var_os("PORTHUB_TERMINAL_SSH_SOCKET")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("PORTHUB_API_SOCKET")
                    .map(|path| PathBuf::from(path).with_file_name("terminal-ssh.sock"))
            });
        if let Some(path) = std::env::var_os("PORTHUB_TERMINAL_HOST_KEY") {
            settings.host_key = path.into();
        }
        settings.ssh_host = std::env::var("PORTHUB_TERMINAL_SSH_HOST").unwrap_or_default();
        if let Ok(port) = std::env::var("PORTHUB_TERMINAL_SSH_PORT") {
            settings.ssh_port = port.parse()?;
        }
        anyhow::ensure!(settings.ssh_port > 0, "invalid terminal SSH port");
        anyhow::ensure!(
            settings.ssh_host.is_empty() || valid_host(&settings.ssh_host),
            "invalid terminal SSH hostname"
        );
        anyhow::ensure!(
            settings.host_key.is_absolute()
                && settings.ssh_socket.as_ref().is_none_or(|p| p.is_absolute()),
            "terminal socket/key paths must be absolute"
        );
        Ok(settings)
    }
}
fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
}
fn advertised_host(app: &App) -> String {
    let candidates = [
        Some(app.config.terminal.ssh_host.clone()).filter(|h| !h.is_empty()),
        app.config.gateway_public_ip.clone(),
        app.config.gateway_advertised_url.clone(),
        Some(app.config.rathole_server_address.clone()),
    ];
    for candidate in candidates.into_iter().flatten() {
        let value = if candidate.contains("://") {
            candidate
        } else {
            format!("http://{candidate}")
        };
        if let Ok(url) = url::Url::parse(&value) {
            if let Some(host) = url.host_str() {
                let host = host.trim_matches(['[', ']']);
                if valid_host(host) {
                    return host.into();
                }
            }
        }
    }
    String::new()
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/terminal/host", get(host))
        .route("/api/terminal/join", get(join))
        .route("/api/terminal/info", post(info))
        .route("/api/terminal/{id}/participants", get(management))
        .route("/api/terminal/{id}/kick", post(kick))
}
fn bad(message: &str) -> ApiError {
    ApiError::bad_request(message)
}
async fn host(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let permit = app.terminals.admit().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "terminal gateway capacity reached",
        )
    })?;
    let machine = headers
        .get("x-porthub-machine-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad("machine identity required"))?
        .to_owned();
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.len() <= 256)
        .ok_or_else(|| bad("machine authorization required"))?
        .to_owned();
    machine_client::authenticate(&app, &machine, &token).await?;
    Ok(upgrade
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            host_socket(app, machine, token, socket).await
        }))
}
async fn register(app: &App, machine: &str, hello: &HostHello) -> ApiResult<()> {
    hello
        .validate(now())
        .map_err(|_| bad("invalid terminal session settings"))?;
    let collection = app.collection("terminal_sessions");
    if let Some(previous) = collection.find_one(doc! {"_id":&hello.id}).await? {
        let options: Options = mongodb::bson::from_bson(
            previous
                .get("options")
                .cloned()
                .ok_or_else(|| bad("terminal state unavailable"))?,
        )
        .map_err(|_| bad("terminal state unavailable"))?;
        if store::string(&previous, "machine_id") != machine
            || store::string(&previous, "secret_hash") != digest(&hello.secret)
            || store::string(&previous, "write_hash") != digest(&hello.write_token)
            || store::string(&previous, "read_hash") != digest(&hello.read_token)
            || store::string(&previous, "state") != "active"
            || options != hello.options
        {
            return Err(bad("terminal session expired or revoked"));
        }
    } else {
        if hello.options.expires_at != 0 && hello.options.expires_at <= now() {
            return Err(bad("terminal invitation already expired"));
        }
        let options =
            mongodb::bson::to_bson(&hello.options).map_err(|_| bad("invalid terminal options"))?;
        collection.insert_one(doc!{"_id":&hello.id,"machine_id":machine,"secret_hash":digest(&hello.secret),"write_hash":digest(&hello.write_token),"read_hash":digest(&hello.read_token),"options":options,"state":"active","created_at":DateTime::now()}).await?;
    }
    Ok(())
}
async fn finish(app: &App, id: &str, reason: &str) {
    app.terminals.end(id, reason);
    let _ =
        tokio::time::timeout(Duration::from_secs(3), crate::terminal_grants::end(app, id)).await;
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        app.collection("terminal_sessions").update_one(
            doc! {"_id":id},
            doc! {"$set":{"state":"ended","ended_at":DateTime::now()}},
        ),
    )
    .await;
}
async fn send_host(socket: &mut WebSocket, event: &HostEvent) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            socket.send(Message::Text(serde_json::to_string(event).unwrap().into()))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn host_socket(app: Arc<App>, machine: String, token: String, mut socket: WebSocket) {
    let first = tokio::time::timeout(Duration::from_secs(5), socket.recv()).await;
    let Ok(Some(Ok(Message::Text(first)))) = first else {
        return;
    };
    if first.len() > 8192 {
        return;
    }
    let Ok(hello) = serde_json::from_str::<HostHello>(&first) else {
        return;
    };
    if register(&app, &machine, &hello).await.is_err() {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let Ok(mut host) = app.terminals.register(&machine, &hello, now()) else {
        return;
    };
    let ready = HostEvent::Ready {
        ssh_host: advertised_host(&app),
        ssh_port: app.config.terminal.ssh_port,
        public_base: app.config.public_base_url.trim_end_matches('/').into(),
    };
    if !send_host(&mut socket, &ready).await {
        host.session.offline(host.generation);
        return;
    }
    let lease = host.session.clone();
    let monitor_app = app.clone();
    let monitor_machine = machine.clone();
    let session_id = hello.id.clone();
    let _monitor = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut last_valid = std::time::Instant::now();
        loop {
            tokio::select! {_=lease.stop.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(5))=>{}}
            match tokio::time::timeout(
                Duration::from_secs(3),
                machine_client::authenticate(&monitor_app, &monitor_machine, &token),
            )
            .await
            {
                Ok(Ok(_)) => last_valid = std::time::Instant::now(),
                Ok(Err(error)) if error.status.is_client_error() => {
                    finish(&monitor_app, &session_id, "machine authorization revoked").await;
                    return;
                }
                _ if last_valid.elapsed() >= Duration::from_secs(15) => {
                    monitor_app
                        .terminals
                        .disconnect(&session_id, "authorization lease unavailable");
                    return;
                }
                _ => {}
            }
        }
    }));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut last_host_message = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _=host.session.stop.cancelled()=>{
                if let Some(event)=host.session.close_event(){let _=send_host(&mut socket,&event).await;}
                break;
            },
            _=heartbeat.tick()=>{if last_host_message.elapsed()>=Duration::from_secs(45) || !send_host(&mut socket,&HostEvent::Ping).await {break;}},
            event=host.events.recv()=>{
                let Some(event)=event else {break;};
                if !send_host(&mut socket,&event).await {break;}
            }
            message=socket.recv()=>match message {
                Some(Ok(Message::Text(value)))=>{
                    let Ok(output)=serde_json::from_str::<HostOutput>(&value) else {break;};
                    last_host_message=tokio::time::Instant::now();
                    if host.session.output(host.generation,HostOutput::Pong).is_err() {break;}
                    if let HostOutput::Kick {client} = &output {
                        // Persist revocation before removing the live attachment.
                        // Recovery admission rechecks this record after attaching.
                        if !matches!(tokio::time::timeout(Duration::from_secs(3),crate::terminal_grants::revoke(&app,&hello.id,*client)).await,Ok(Ok(()))) {break;}
                    }
                    if matches!(output,HostOutput::End) {finish(&app,&hello.id,"owner ended session").await;break;}
                    if host.session.output(host.generation,output).is_err() {break;}
                }
                Some(Ok(Message::Ping(_)|Message::Pong(_)))=>{},
                _=>break,
            }
        }
    }
    host.session.offline(host.generation);
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinHello {
    #[serde(default)]
    token: String,
    #[serde(default)]
    resume_token: Option<String>,
    cols: u16,
    rows: u16,
    #[serde(default = "terminal_type")]
    term: String,
}
fn terminal_type() -> String {
    "xterm-256color".into()
}
async fn join(State(app): State<Arc<App>>, upgrade: WebSocketUpgrade) -> Response {
    let Ok(permit) = app.terminals.admit() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .max_message_size(32768)
        .max_frame_size(32768)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            viewer_socket(app, socket).await
        })
        .into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    token: String,
}
async fn info(
    State(app): State<Arc<App>>,
    axum::Json(lookup): axum::Json<Lookup>,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let (session, read_only) = app.terminals.resolve(&lookup.token).map_err(|_| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "invitation expired or host unavailable",
        )
    })?;
    Ok(axum::Json(
        serde_json::json!({"name":session.options.name,"read_only":read_only,"expires_at":session.options.expires_at,"participants":session.participants(),"max_viewers":session.options.max_viewers,"access":session.options.access,"ssh_host":advertised_host(&app),"ssh_port":app.config.terminal.ssh_port}),
    ))
}
async fn managed_session(
    app: &App,
    headers: &HeaderMap,
    id: &str,
) -> ApiResult<Arc<porthub_terminal::hub::Shared>> {
    let user = crate::auth::current_user(app, headers).await?;
    if !token(id, 32) {
        return Err(bad("invalid terminal session"));
    }
    let record = app
        .collection("terminal_sessions")
        .find_one(doc! {"_id":id,"state":"active"})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "terminal session unavailable"))?;
    let machine_id = crate::domain::workspaces::object_id(
        store::string(&record, "machine_id"),
        "invalid terminal machine",
    )?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":machine_id,"deletion_pending":{"$ne":true}})
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "terminal machine unavailable"))?;
    let owner = machine
        .get_object_id("user_id")
        .map_err(|_| bad("terminal machine ownership unavailable"))?;
    crate::domain::workspaces::access(app, &user, &owner.to_hex(), true).await?;
    app.terminals
        .sessions()
        .into_iter()
        .find(|session| session.id == id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "terminal host reconnecting",
            )
        })
}
fn management_origin(headers: &HeaderMap) -> ApiResult<()> {
    // Cookie-authenticated browser management is restricted to this origin.
    // Invitation capabilities never authorize administrative actions.
    if let Some(origin) = headers.get("origin") {
        let origin = origin
            .to_str()
            .ok()
            .and_then(|origin| url::Url::parse(origin).ok())
            .filter(|origin| {
                matches!(origin.scheme(), "http" | "https")
                    && origin.username().is_empty()
                    && origin.password().is_none()
            })
            .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid management origin"))?;
        let host = headers
            .get("host")
            .and_then(|host| host.to_str().ok())
            .ok_or_else(|| bad("management host required"))?;
        let expected = url::Url::parse(&format!("{}://{}", origin.scheme(), host))
            .map_err(|_| bad("invalid management host"))?;
        if origin.origin() != expected.origin() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "cross-origin terminal management denied",
            ));
        }
    }
    Ok(())
}
async fn management(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult<axum::Json<serde_json::Value>> {
    management_origin(&headers)?;
    let session = managed_session(&app, &headers, &id).await?;
    Ok(axum::Json(
        serde_json::json!({"can_manage":true,"members":session.participant_list()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Kick {
    client: u64,
}
async fn kick(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(request): axum::Json<Kick>,
) -> ApiResult<axum::Json<serde_json::Value>> {
    management_origin(&headers)?;
    let session = managed_session(&app, &headers, &id).await?;
    if !session
        .participant_list()
        .iter()
        .any(|member| member.id == request.client)
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "participant already detached",
        ));
    }
    crate::terminal_grants::revoke(&app, &id, request.client).await?;
    session
        .kick(request.client)
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "terminal session changed"))?;
    Ok(axum::Json(
        serde_json::json!({"ok":true,"members":session.participant_list()}),
    ))
}
async fn viewer_socket(app: Arc<App>, mut socket: WebSocket) {
    let Ok(Some(Ok(Message::Text(first)))) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv()).await
    else {
        return;
    };
    if first.len() > 1024 {
        return;
    }
    let Ok(hello) = serde_json::from_str::<JoinHello>(&first) else {
        return;
    };
    let recovered = hello.resume_token.is_some();
    let admission = async {
        let (grant, recovery) = if let Some(raw) = hello.resume_token.as_deref() {
            if !hello.token.is_empty() {
                return Err(bad("choose an invitation or recovery credential"));
            }
            let grant = crate::terminal_grants::resume(&app, raw).await?;
            (grant, raw.to_owned())
        } else {
            let (session, read_only) = app
                .terminals
                .resolve(&hello.token)
                .map_err(|_| bad("invitation expired or host unavailable"))?;
            if session.options.access == Access::Ssh {
                return Err(bad("browser access is disabled"));
            }
            crate::terminal_grants::create(
                &app,
                &session.id,
                read_only,
                session.options.reconnect_timeout,
            )
            .await?
        };
        let viewer = app
            .terminals
            .attach_authorized(
                &grant.session,
                Some(grant.identity),
                grant.read_only,
                hello.cols,
                hello.rows,
                &hello.term,
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "terminal host unavailable or participant limit reached",
                )
            })?;
        // Revocation can race a resume's database lookup. A second conditional
        // lease check closes that window before exposing any terminal frames.
        if crate::terminal_grants::renew(&app, &grant).await.is_err()
            || viewer.session.options.access == Access::Ssh
        {
            drop(viewer);
            return Err(bad("terminal recovery credential revoked"));
        }
        Ok::<_, ApiError>((grant, recovery, viewer))
    };
    let (grant, recovery, mut viewer) =
        match tokio::time::timeout(Duration::from_secs(5), admission).await {
            Ok(Ok(admitted)) => admitted,
            failure => {
                let retryable = match &failure {
                    Ok(Err(error)) => error.status.is_server_error(),
                    Err(_) => true,
                    _ => false,
                };
                let reason = if recovered {
                    "Recovery expired, revoked, or host unavailable"
                } else {
                    "Invitation expired, revoked, or host unavailable"
                };
                let _ = socket
                    .send(Message::Text(
                        serde_json::json!({"type":"closed","reason":reason,"retryable":retryable})
                            .to_string()
                            .into(),
                    ))
                    .await;
                return;
            }
        };
    let recovery = ViewerEvent::Recovery {
        session: grant.session.clone(),
        token: recovery,
        participant: grant.identity,
        reconnect_timeout: grant.grace,
    };
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(3),
            socket.send(Message::Text(
                serde_json::to_string(&recovery).unwrap().into()
            ))
        )
        .await,
        Ok(Ok(()))
    ) {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            crate::terminal_grants::release(&app, &grant),
        )
        .await;
        return;
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut last_viewer_message = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _=heartbeat.tick()=> {
                if last_viewer_message.elapsed()>=Duration::from_secs(45) {break;}
                if !matches!(tokio::time::timeout(Duration::from_secs(3),crate::terminal_grants::renew(&app,&grant)).await,Ok(Ok(()))) {break;}
                if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Text("{\"type\":\"ping\"}".into()))).await,Ok(Ok(()))) {break;}
            },
            _=viewer.session.stop.cancelled()=>{
                let (reason,retryable)=match viewer.session.close_event() {Some(HostEvent::Reconnect{reason})=>(reason,true),Some(HostEvent::Stop{reason})=>(reason,false),_=>("terminal session ended".into(),false)};
                let event=ViewerEvent::Closed{reason,retryable};
                let _=tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Text(serde_json::to_string(&event).unwrap().into()))).await;break;
            },
            event=viewer.events.recv()=>{
                let Some(event)=event else {break;};
                let closed=matches!(event,ViewerEvent::Closed {..});
                if !matches!(tokio::time::timeout(Duration::from_secs(10),socket.send(Message::Text(serde_json::to_string(&event).unwrap().into()))).await,Ok(Ok(()))) || closed {break;}
            },
            message=socket.recv()=>match message {
                Some(Ok(Message::Text(message)))=>{
                    let Ok(input)=serde_json::from_str::<ViewerInput>(&message) else {break;};
                    last_viewer_message=tokio::time::Instant::now();
                    if viewer.session.input(viewer.id,input).is_err() {break;}
                }
                Some(Ok(Message::Ping(_)|Message::Pong(_)))=>{},
                _=>break,
            }
        }
    }
    // Conditional lease identity prevents an old socket from shortening a
    // replacement socket's recovery window.
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        crate::terminal_grants::release(&app, &grant),
    )
    .await;
}
pub async fn maintenance(app: Arc<App>, cancel: CancellationToken) {
    loop {
        tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
        for session in app.terminals.sessions() {
            if session.expired(now()) {
                finish(&app, &session.id, "session expired or idle timeout reached").await;
            } else if session.recovery_expired() {
                app.terminals
                    .disconnect(&session.id, "transport recovery window elapsed");
            }
        }
    }
    for session in app.terminals.sessions() {
        app.terminals.disconnect(&session.id, "gateway restarting");
    }
}
#[cfg(unix)]
pub async fn serve_ssh(app: Arc<App>, cancel: CancellationToken) -> anyhow::Result<()> {
    let Some(path) = &app.config.terminal.ssh_socket else {
        cancel.cancelled().await;
        return Ok(());
    };
    let directory = app
        .config
        .terminal
        .host_key
        .parent()
        .ok_or_else(|| anyhow::anyhow!("terminal key directory missing"))?;
    tokio::fs::create_dir_all(directory).await?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).await?;
    let key = porthub_terminal::ssh::host_key(&app.config.terminal.host_key)?;
    let config = porthub_terminal::ssh::config(key);
    let (listener, _guard) = porthub_runtime::socket::bind(path).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            connection=listener.accept()=>{
                let (socket,_)=connection?;
                let Ok(permit)=semaphore.clone().try_acquire_owned() else {continue;};
                let config=config.clone();let hub=app.terminals.clone();let stop=cancel.child_token();
                tasks.spawn(async move {let _permit=permit;let _=porthub_terminal::ssh::serve(socket,config,hub,stop).await;});
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
