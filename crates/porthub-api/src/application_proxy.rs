//! On-demand streams on the existing API listener. Browser-owned grants are
//! checked independently of agent membership; reachability is not permission.
use crate::{
    domain::workspaces::token_digest,
    error::{ApiError, ApiResult},
    routes::{private_sync, proxy_grants},
    store, App,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::doc;
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

pub struct Capacity {
    global: Arc<tokio::sync::Semaphore>,
    grants: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Weak<tokio::sync::Semaphore>>,
    >,
}
impl Default for Capacity {
    fn default() -> Self {
        Self {
            global: Arc::new(tokio::sync::Semaphore::new(256)),
            grants: Default::default(),
        }
    }
}
impl Capacity {
    pub(crate) fn acquire(
        &self,
        grant: &str,
    ) -> ApiResult<(
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    )> {
        // ObjectId URLs accept either case; aliases share one grant budget.
        let canonical = grant.to_ascii_lowercase();
        let grant = canonical.as_str();
        let busy = || {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Shared proxy capacity is in use",
            )
        };
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let limit = {
            let mut grants = self
                .grants
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            grants.retain(|_, limit| limit.strong_count() > 0);
            if let Some(limit) = grants.get(grant).and_then(std::sync::Weak::upgrade) {
                limit
            } else {
                let limit = Arc::new(tokio::sync::Semaphore::new(64));
                grants.insert(grant.into(), Arc::downgrade(&limit));
                limit
            }
        };
        let local = limit.try_acquire_owned().map_err(|_| busy())?;
        Ok((global, local))
    }
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/proxy-stream/{grant}", get(connect))
        .route(
            "/api/access/proxy-serve/{session}",
            get(crate::peer_proxy::serve),
        )
        .route("/api/access/proxy-jobs", get(crate::peer_proxy::subscribe))
        .route("/api/access/proxy-check/{grant}", get(check))
}
async fn check(
    State(app): State<Arc<App>>,
    Path(grant): Path<String>,
    headers: HeaderMap,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let (peer, token) = credentials(&headers)?;
    let auth = tokio::time::timeout(
        Duration::from_secs(4),
        authorize(&app, &grant, &peer, &token),
    )
    .await
    .map_err(|_| denied())??;
    let ready = auth
        .target_peer
        .as_ref()
        .is_none_or(|binding| app.proxy_pending.ready(binding));
    Ok(axum::Json(serde_json::json!({"ready":ready})))
}
#[derive(Deserialize)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
}
pub(crate) struct Authorization {
    pub allow_lan: bool,
    pub target_machine: Option<String>,
    pub target_peer: Option<crate::peer_proxy::Binding>,
    pub overlay: Vec<IpAddr>,
}
fn denied() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "Shared proxy permission is unavailable or revoked",
    )
}
pub(crate) async fn authorize(
    app: &App,
    grant: &str,
    peer_id: &str,
    token: &str,
) -> ApiResult<Authorization> {
    if peer_id.len() > 60 || !(32..=200).contains(&token.len()) {
        return Err(denied());
    }
    let grant = crate::domain::workspaces::object_id(grant, "Invalid proxy grant")?;
    let peer = app
        .collection("private_peers")
        .find_one(doc! {
            "_id":peer_id,"credential_hash":token_digest(token),"enabled":true
        })
        .await?
        .ok_or_else(denied)?;
    let workspace = peer.get_object_id("workspace_id").map_err(|_| denied())?;
    let (active, _) = private_sync::active(app, workspace).await?;
    let current = active
        .iter()
        .find(|peer| store::string(peer, "_id") == peer_id)
        .ok_or_else(denied)?;
    let machine = current.get_object_id("machine_id").map_err(|_| denied())?;
    let record = app
        .collection(proxy_grants::COLLECTION)
        .find_one(doc! {
            "_id":grant,"workspace_id":workspace,"enabled":true,"client_machine_ids":machine
        })
        .await?
        .ok_or_else(denied)?;
    let target_machine = match record.get_str("target_kind") {
        Ok("gateway") => None,
        Ok("machine") => {
            let target = record
                .get_object_id("target_machine_id")
                .map_err(|_| denied())?;
            if target == machine
                || !active
                    .iter()
                    .any(|peer| peer.get_object_id("machine_id") == Ok(target))
            {
                return Err(denied());
            }
            Some(target.to_hex())
        }
        _ => return Err(denied()),
    };
    if target_machine.is_none() && record.get_bool("allow_lan")==Ok(true)
        && record.get_bool("gateway_lan_authorized")!=Ok(true) {return Err(denied());}
    let target_peer = target_machine
        .as_ref()
        .map(|machine| {
            let peer = active
                .iter()
                .find(|peer| store::id(peer.get("machine_id")) == *machine)
                .ok_or_else(denied)?;
            if peer.get_bool("application_proxy") != Ok(true) {
                return Err(denied());
            }
            let binding = crate::peer_proxy::Binding {
                id: store::string(peer, "_id").into(),
                instance: store::string(peer, "instance").into(),
                fingerprint: store::string(peer, "fingerprint").into(),
            };
            if binding.instance.is_empty() || binding.fingerprint.is_empty() {
                return Err(denied());
            }
            Ok(binding)
        })
        .transpose()?;
    let overlay = active
        .iter()
        .filter_map(|peer| store::string(peer, "ip").parse().ok())
        .collect();
    Ok(Authorization {
        allow_lan: record.get_bool("allow_lan").unwrap_or(false),
        target_machine,
        target_peer,
        overlay,
    })
}
pub(crate) fn credentials(headers: &HeaderMap) -> ApiResult<(String, String)> {
    let peer = headers
        .get("x-porthub-peer")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(denied)?;
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(denied)?;
    if peer.is_empty() || peer.len() > 60 || !(32..=200).contains(&token.len()) {
        return Err(denied());
    }
    Ok((peer.into(), token.into()))
}
async fn open(target: &Target, auth: &Authorization) -> ApiResult<TcpStream> {
    let target = porthub_egress::Destination::new(target.host.clone(), target.port)
        .map_err(|_| ApiError::bad_request("Invalid proxy destination"))?;
    let addresses: Vec<_> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Proxy destination lookup failed"))?
        .take(32)
        .collect();
    if addresses.is_empty()
        || addresses.iter().any(|address| {
            !porthub_egress::destination::permitted(address.ip(), auth.allow_lan, &auth.overlay)
        })
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Proxy destination is outside this grant",
        ));
    }
    for address in addresses {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(address)).await
        {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err(ApiError::new(
        StatusCode::BAD_GATEWAY,
        "Proxy destination is unavailable",
    ))
}
async fn connect(
    State(app): State<Arc<App>>,
    Path(grant): Path<String>,
    Query(target): Query<Target>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let (peer, token) = credentials(&headers)?;
    let auth = tokio::time::timeout(
        Duration::from_secs(4),
        authorize(&app, &grant, &peer, &token),
    )
    .await
    .map_err(|_| denied())??;
    if auth.target_machine.is_some() {
        return crate::peer_proxy::connect(app, grant, peer, token, auth, target, ws).await;
    }
    let permit = app.proxy_capacity.acquire(&grant)?;
    let stream = tokio::time::timeout(Duration::from_secs(10), open(&target, &auth))
        .await
        .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "Proxy destination timed out"))??;
    let destination_ip = stream
        .peer_addr()
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Proxy destination disconnected"))?
        .ip();
    // The grant is rechecked in a separate task. Database latency cannot stall
    // an active stream, and no lease task exists while the proxy is idle.
    Ok(ws
        .max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let cancel = CancellationToken::new();
            let revoked = cancel.clone();
            let guard = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let valid = tokio::time::timeout(
                        Duration::from_secs(4),
                        authorize(&app, &grant, &peer, &token),
                    )
                    .await;
                    match valid {
                        Ok(Ok(next))
                            if next.target_machine.is_none()
                                && porthub_egress::destination::permitted(
                                    destination_ip,
                                    next.allow_lan,
                                    &next.overlay,
                                ) => {}
                        _ => {
                            revoked.cancel();
                            break;
                        }
                    }
                }
            });
            bridge(socket, stream, cancel).await;
            guard.abort();
            let _ = guard.await;
        }))
}
async fn bridge(socket: WebSocket, stream: TcpStream, cancel: CancellationToken) {
    let (mut outgoing, mut incoming) = socket.split();
    let (mut reader, mut writer) = stream.into_split();
    let upload = async {
        loop {
            match incoming.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    writer.write_all(&bytes).await.map_err(|_| ())?
                }
                Some(Ok(Message::Text(text))) if text == "eof" => {
                    writer.shutdown().await.map_err(|_| ())?;
                    return Ok::<_, ()>(());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => return Err(()),
            }
        }
    };
    let download = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let size = reader.read(&mut buffer).await.map_err(|_| ())?;
            if size == 0 {
                outgoing
                    .send(Message::Text("eof".into()))
                    .await
                    .map_err(|_| ())?;
                return Ok::<_, ()>(());
            }
            outgoing
                .send(Message::Binary(buffer[..size].to_vec().into()))
                .await
                .map_err(|_| ())?;
        }
    };
    tokio::select! {
        _=cancel.cancelled()=>{},
        _=async {tokio::try_join!(upload,download)}=>{},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_limits_are_per_grant_global_and_released_with_the_stream() {
        let capacity = Capacity::default();
        let mut held = Vec::new();
        for grant in ["a", "b", "c", "d"] {
            for _ in 0..64 {
                held.push(capacity.acquire(grant).ok().expect("available capacity"));
            }
            assert!(capacity.acquire(grant).is_err());
            assert!(capacity.acquire(&grant.to_ascii_uppercase()).is_err());
        }
        assert!(capacity.acquire("e").is_err());
        held.clear();
        let next = capacity.acquire("e").ok().expect("released capacity");
        assert_eq!(capacity.grants.lock().unwrap().len(), 1);
        drop(next);
        assert_eq!(capacity.global.available_permits(), 256);
    }
    #[test]
    fn browser_cookies_or_query_strings_cannot_replace_agent_authentication() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "porthub_session=browser-session".parse().unwrap());
        assert!(credentials(&headers).is_err());
        headers.insert(
            "authorization",
            "Bearer private-credential-0123456789012345"
                .parse()
                .unwrap(),
        );
        assert!(credentials(&headers).is_err());
        headers.insert("x-porthub-peer", "workspace:machine".parse().unwrap());
        assert!(credentials(&headers).is_ok());
        headers.insert("authorization", "Bearer short".parse().unwrap());
        assert!(credentials(&headers).is_err());
    }
}
