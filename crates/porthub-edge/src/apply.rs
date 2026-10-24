//! The control router is served only over a separate role-scoped Unix socket.
//! Public ingress never mounts these routes.
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use porthub_runtime::gateway_apply::{self, Snapshot};
use porthub_tunnel::{gateway_config, EmbeddedServer};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{io::AsyncReadExt, sync::RwLock};
#[derive(Clone)]
struct Apply {
    server: Arc<RwLock<EmbeddedServer>>,
    path: PathBuf,
}

/// Read under the same lock as reload so a queued watcher cannot apply an old
/// file after a newer IPC request has been acknowledged. Cancellation leaves
/// pending socket cleanup owned by EmbeddedServer for the next apply attempt.
pub async fn file(
    server: &RwLock<EmbeddedServer>,
    path: &Path,
    expected: Option<&str>,
) -> Result<String> {
    let mut server = server.write().await;
    let mut content = String::new();
    tokio::fs::File::open(path)
        .await?
        .take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut content)
        .await?;
    anyhow::ensure!(
        content.len() <= 16 * 1024 * 1024,
        "gateway configuration exceeded limit"
    );
    let digest = gateway_apply::digest(content.as_bytes());
    if let Some(expected) = expected {
        anyhow::ensure!(digest == expected, "gateway snapshot changed before apply");
    }
    server
        .reload(gateway_config(&content)?)
        .await
        .context("apply gateway snapshot")?;
    Ok(digest)
}

async fn apply(
    State(state): State<Apply>,
    Json(request): Json<Snapshot>,
) -> Result<Json<Snapshot>, StatusCode> {
    if !gateway_apply::valid_digest(&request.digest) {
        return Err(StatusCode::BAD_REQUEST);
    }
    match file(&state.server, &state.path, Some(&request.digest)).await {
        Ok(digest) => Ok(Json(Snapshot { digest })),
        Err(error) => {
            tracing::warn!(%error,"gateway apply request rejected");
            Err(StatusCode::CONFLICT)
        }
    }
}

pub fn router(server: Arc<RwLock<EmbeddedServer>>, path: PathBuf) -> Router {
    Router::new()
        .route("/apply", post(apply))
        .layer(DefaultBodyLimit::max(256))
        .with_state(Apply { server, path })
}
