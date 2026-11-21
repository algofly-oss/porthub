//! Reach named agent imports and accept explicitly public exports through the
//! existing filesystem-protected edge control socket.
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, post},
    Router,
};
use hyper_util::rt::TokioIo;
use porthub_tunnel::EmbeddedServer;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{watch, Mutex, RwLock},
};

const PROTOCOL: &str = "porthub-forward-v1";
type Error = StatusCode;
#[derive(Clone)]
struct StateData {
    server: Arc<RwLock<EmbeddedServer>>,
    exports: Arc<Mutex<HashMap<u16, Arc<Export>>>>,
}
struct Export {
    id: String,
    socket: RwLock<Option<TcpListener>>,
    stop: watch::Sender<bool>,
}

fn valid(id: &str) -> bool {
    id.len() == 24
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn upgraded<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut req: Request,
    mut stream: S,
) -> Result<Response, Error> {
    if req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        != Some(PROTOCOL)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(Ok(io)) = tokio::time::timeout(Duration::from_secs(3), upgrade).await {
            let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(io), &mut stream).await;
        }
    });
    Ok((
        StatusCode::SWITCHING_PROTOCOLS,
        [(header::CONNECTION, "upgrade"), (header::UPGRADE, PROTOCOL)],
    )
        .into_response())
}
async fn import(
    State(state): State<StateData>,
    Path((id, index)): Path<(String, u8)>,
    request: Request,
) -> Result<Response, Error> {
    if !valid(&id) || index >= 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let service = format!("porthub_import_{id}_{index}");
    let open = state.server.read().await.open_import(&service);
    let stream = open.await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    upgraded(request, stream)
}
async fn listen(
    State(state): State<StateData>,
    Path((id, port)): Path<(String, u16)>,
) -> Result<StatusCode, Error> {
    if !valid(&id) || port < 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut exports = state.exports.lock().await;
    if let Some(existing) = exports.get(&port) {
        return if existing.id == id {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(StatusCode::CONFLICT)
        };
    }
    if exports.len() >= 4096 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let socket = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let (stop, _) = watch::channel(false);
    exports.insert(
        port,
        Arc::new(Export {
            id,
            socket: RwLock::new(Some(socket)),
            stop,
        }),
    );
    Ok(StatusCode::NO_CONTENT)
}
async fn accept(
    State(state): State<StateData>,
    Path((id, port)): Path<(String, u16)>,
    request: Request,
) -> Result<Response, Error> {
    let export = state
        .exports
        .lock()
        .await
        .get(&port)
        .filter(|e| e.id == id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut stop = export.stop.subscribe();
    let guard = export.socket.read().await;
    let listener = guard.as_ref().ok_or(StatusCode::GONE)?;
    if *stop.borrow() {
        return Err(StatusCode::GONE);
    }
    let (stream, _) = tokio::select! {
        _=stop.changed()=>return Err(StatusCode::GONE),
        value=tokio::time::timeout(Duration::from_secs(12),listener.accept())=>value.map_err(|_|StatusCode::NO_CONTENT)?.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?,
    };
    let _ = stream.set_nodelay(true);
    upgraded(request, stream)
}
async fn remove(
    State(state): State<StateData>,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    if !valid(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut retired = Vec::new();
    state.exports.lock().await.retain(|_, export| {
        if export.id != id {
            return true;
        }
        export.stop.send_replace(true);
        retired.push(export.clone());
        false
    });
    for export in retired {
        export.socket.write().await.take();
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn inventory(State(state): State<StateData>) -> axum::Json<Vec<(String, u16)>> {
    axum::Json(
        state
            .exports
            .lock()
            .await
            .iter()
            .map(|(port, e)| (e.id.clone(), *port))
            .collect(),
    )
}
pub fn router(server: Arc<RwLock<EmbeddedServer>>) -> Router {
    Router::new()
        .route("/forwards/import/{id}/{index}", post(import))
        .route("/forwards/public", axum::routing::get(inventory))
        .route("/forwards/public/{id}/{port}", post(listen))
        .route("/forwards/public/{id}/{port}/accept", post(accept))
        .route("/forwards/public/{id}", delete(remove))
        .with_state(StateData {
            server,
            exports: Default::default(),
        })
}
