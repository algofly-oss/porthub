//! Single-core publication serialization backed by a freshly read durable head.
//! The runner must hold this same guard across the head transition and writes.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};
#[derive(Default)]
pub struct Fences(Mutex<HashMap<String, Weak<Mutex<()>>>>);
impl Fences {
    #[cfg(test)]
    pub(crate) async fn waiting(&self,workspace:&str)->bool {
        self.0.lock().await.get(workspace).is_some_and(|lock|lock.strong_count()>1)
    }
    async fn acquire(&self, workspace: &str) -> ApiResult<OwnedMutexGuard<()>> {
        let lock = {
            let mut locks = self.0.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(workspace).and_then(Weak::upgrade) {
                lock
            } else {
                if locks.len() >= 16384 {
                    return Err(ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Workspace admission is busy",
                    ));
                }
                let lock = Arc::new(Mutex::new(()));
                locks.insert(workspace.into(), Arc::downgrade(&lock));
                lock
            }
        };
        Ok(lock.lock_owned().await)
    }
}
/// Authoritative revocation remains possible while a crashed migration is
/// fenced. It serializes with a live runner but never restores publication.
pub(crate) async fn revocation(app:&App,workspace:ObjectId)->ApiResult<OwnedMutexGuard<()>> {
    app.private_sparse.workspace_fences.acquire(&workspace.to_hex()).await
}
/// No cached head is allowed: a crashed Preparing/Applying job stays fenced
/// after App restart. Missing head is the historical generation zero.
pub(crate) async fn stable(app: &App, workspace: ObjectId) -> ApiResult<OwnedMutexGuard<()>> {
    let key = workspace.to_hex();
    let guard = app.private_sparse.workspace_fences.acquire(&key).await?;
    let row = app
        .collection("private_renumber_heads")
        .find_one(doc! {"_id":&key})
        .await?;
    let (generation, blocked) = match row {
        None => (0, false),
        Some(row) => {
            let Some(generation)=row.get_i64("generation").ok().filter(|g|*g>=0) else {
                app.private_relay.block_workspace(&key);
                return Err(ApiError::new(StatusCode::CONFLICT,"Invalid private migration head; recovery required"));
            };
            let generation=generation as u64;
            (generation, row.get_str("state").ok() != Some("stable"))
        }
    };
    if !app
        .private_relay
        .workspace_generation(&key, generation, blocked)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Private addresses are migrating or require recovery; retry later",
        ));
    }
    Ok(guard)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn same_workspace_waits_but_other_workspace_progresses() {
        let fences = Arc::new(Fences::default());
        let first = fences.acquire("a").await.ok().unwrap();
        let waiting = {
            let f = fences.clone();
            tokio::spawn(async move { f.acquire("a").await.ok().unwrap() })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        let other = fences.acquire("b").await.ok().unwrap();
        drop(other);
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn inactive_workspace_keys_are_reclaimed() {
        let fences = Fences::default();
        for i in 0..20000 {
            drop(fences.acquire(&i.to_string()).await.ok().unwrap());
        }
        assert_eq!(fences.0.lock().await.len(), 1);
    }
}
