//! Shared capture metadata, never packet or membership authority. A cache hit
//! cannot grant a pair; picker/publication still perform their fresh checks.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use porthub_mesh::lan_routes::Network;
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::Mutex as AsyncMutex, time::Instant};
const CAPACITY: usize = 64;
const LIFETIME: Duration = Duration::from_secs(5);
#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    owner: ObjectId,
    route: String,
}
struct Entry {
    generation: AtomicU64,
    flight: AsyncMutex<Option<Cached>>,
}
struct Cached {
    generation: u64,
    deadline: Instant,
    wall_deadline: i64,
    networks: Vec<Network>,
}
struct Slot {
    entry: Arc<Entry>,
    used: Instant,
}
#[derive(Default)]
pub(crate) struct CaptureCache {
    entries: Mutex<HashMap<Key, Slot>>,
}
struct Loaded {
    networks: Vec<Network>,
    earliest_expiry: Option<i64>,
}
fn busy() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "Exit capture metadata changed or is busy; retry sync",
    )
}
impl CaptureCache {
    fn entry(&self, key: &Key) -> ApiResult<Arc<Entry>> {
        // Only map bookkeeping under the global lock; no await or Mongo call.
        let mut entries = self.entries.lock().map_err(|_| busy())?;
        if let Some(slot) = entries.get_mut(key) {
            slot.used = Instant::now();
            return Ok(slot.entry.clone());
        }
        if entries.len() >= CAPACITY {
            let victim = entries
                .iter()
                .filter(|(_, s)| Arc::strong_count(&s.entry) == 1)
                .min_by_key(|(_, s)| s.used)
                .map(|(k, _)| k.clone())
                .ok_or_else(busy)?;
            entries.remove(&victim);
        }
        let entry = Arc::new(Entry {
            generation: AtomicU64::new(0),
            flight: AsyncMutex::new(None),
        });
        entries.insert(
            key.clone(),
            Slot {
                entry: entry.clone(),
                used: Instant::now(),
            },
        );
        Ok(entry)
    }
    /// Does not wait for an in-flight Mongo scan. The reader must discard its
    /// old generation before caching/returning a result after publication.
    pub(crate) fn invalidate(&self, owner: ObjectId, route: &str) {
        if let Ok(entries) = self.entries.lock() {
            if let Some(slot) = entries.get(&Key {
                owner,
                route: route.into(),
            }) {
                slot.entry.generation.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    pub(crate) fn invalidate_owner(&self, owner: ObjectId) {
        if let Ok(entries) = self.entries.lock() {
            for (_, slot) in entries.iter().filter(|(key, _)| key.owner == owner) {
                slot.entry.generation.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    async fn get<F, Fut>(&self, key: Key, mut load: F) -> ApiResult<Vec<Network>>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = ApiResult<Loaded>>,
    {
        let entry = self.entry(&key)?;
        let mut cached = entry.flight.lock().await;
        let generation = entry.generation.load(Ordering::Acquire);
        if let Some(value) = cached.as_ref().filter(|v| {
            v.generation == generation
                && v.deadline > Instant::now()
                && v.wall_deadline > DateTime::now().timestamp_millis()
        }) {
            return Ok(value.networks.clone());
        }
        *cached = None; // Errors never become cached results or stale fallbacks.
        for _ in 0..2 {
            let generation = entry.generation.load(Ordering::Acquire);
            let started = Instant::now();
            let wall_started = DateTime::now().timestamp_millis();
            let value = load().await?;
            if generation != entry.generation.load(Ordering::Acquire) {
                continue;
            }
            let wall_deadline = value
                .earliest_expiry
                .unwrap_or(i64::MAX)
                .min(wall_started.saturating_add(LIFETIME.as_millis() as i64));
            let remaining = wall_deadline - DateTime::now().timestamp_millis();
            if remaining <= 0 || started + LIFETIME <= Instant::now() {
                continue;
            }
            let deadline =
                (started + LIFETIME).min(Instant::now() + Duration::from_millis(remaining as u64));
            let networks = value.networks;
            *cached = Some(Cached {
                generation,
                deadline,
                wall_deadline,
                networks: networks.clone(),
            });
            return Ok(networks);
        }
        Err(busy())
    }
}
pub(crate) async fn networks(app: &App, owner: ObjectId, route: &str) -> ApiResult<Vec<Network>> {
    app.private_sparse
        .exit_capture
        .get(
            Key {
                owner,
                route: route.into(),
            },
            || load(app, owner, route),
        )
        .await
}
async fn load(app: &App, owner: ObjectId, route: &str) -> ApiResult<Loaded> {
    let mut rows = app
        .collection("private_exit_routers")
        .find(doc! {"workspace_id":owner,"route_id":route,"expires_at":{"$gt":DateTime::now()}})
        .projection(doc! {"lan_networks":1,"expires_at":1})
        .batch_size(128)
        .await?;
    let mut networks = Vec::new();
    let mut peers = 0usize;
    let mut earliest: Option<i64> = None;
    let mut compact_at = 4096;
    while let Some(row) = rows.try_next().await? {
        peers += 1;
        let expiry = row
            .get_datetime("expires_at")
            .map_err(|_| ApiError::bad_request("Invalid exit capture row deadline"))?
            .timestamp_millis();
        earliest = Some(earliest.map_or(expiry, |old| old.min(expiry)));
        for value in row
            .get_array("lan_networks")
            .map_err(|_| ApiError::bad_request("Invalid exit capture advertisement list"))?
        {
            let raw = value
                .as_str()
                .ok_or_else(|| ApiError::bad_request("Invalid exit capture advertisement"))?;
            networks.push(
                raw.parse::<Network>()
                    .map_err(|_| ApiError::bad_request("Invalid exit capture advertisement"))?,
            );
        }
        if networks.len() >= compact_at {
            networks = crate::private_exit_picker::exact_union(networks);
            // Geometric work bound even when many prefixes cannot coalesce.
            compact_at = 4096usize.max(networks.len().saturating_mul(2));
        }
    }
    let networks = if peers == 1 {
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            .into_iter()
            .map(|s| s.parse().expect("RFC1918"))
            .collect()
    } else {
        crate::private_exit_picker::exact_union(networks)
    };
    if networks.len() > porthub_network::capture_routes::MAX_CAPTURE_PREFIXES {
        return Err(ApiError::bad_request("Exit LAN capture plan exceeds exact native prefix capacity; no partial plan was published"));
    }
    Ok(Loaded {
        networks,
        earliest_expiry: earliest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;
    fn loaded(raw: &str) -> Loaded {
        Loaded {
            networks: vec![raw.parse().unwrap()],
            earliest_expiry: None,
        }
    }
    #[tokio::test]
    async fn concurrent_same_route_singleflights_but_accounts_are_isolated() {
        let cache = Arc::new(CaptureCache::default());
        let owner = ObjectId::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get(
                        Key {
                            owner,
                            route: "same".into(),
                        },
                        || {
                            let calls = calls.clone();
                            async move {
                                calls.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                Ok(loaded("10.1.0.0/16"))
                            }
                        },
                    )
                    .await
                    .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail))
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), vec!["10.1.0.0/16".parse().unwrap()]);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let other = cache
            .get(
                Key {
                    owner: ObjectId::new(),
                    route: "same".into(),
                },
                || async { Ok(loaded("10.2.0.0/16")) },
            )
            .await
            .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail));
        assert_eq!(other, vec!["10.2.0.0/16".parse().unwrap()]);
    }
    #[tokio::test]
    async fn invalidation_discards_inflight_result_and_errors_are_not_cached() {
        let cache = Arc::new(CaptureCache::default());
        let owner = ObjectId::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let task = {
            let cache = cache.clone();
            let calls = calls.clone();
            let entered = entered.clone();
            let release = release.clone();
            tokio::spawn(async move {
                cache
                    .get(
                        Key {
                            owner,
                            route: "route".into(),
                        },
                        || {
                            let calls = calls.clone();
                            let entered = entered.clone();
                            let release = release.clone();
                            async move {
                                let n = calls.fetch_add(1, Ordering::Relaxed);
                                if n == 0 {
                                    entered.notify_one();
                                    release.notified().await;
                                }
                                Ok(loaded(if n == 0 { "10.1.0.0/16" } else { "10.2.0.0/16" }))
                            }
                        },
                    )
                    .await
                    .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail))
            })
        };
        entered.notified().await;
        cache.invalidate(owner, "route");
        release.notify_one();
        assert_eq!(task.await.unwrap(), vec!["10.2.0.0/16".parse().unwrap()]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let key = Key {
            owner,
            route: "error".into(),
        };
        assert!(cache
            .get(key.clone(), || async {
                Err(ApiError::bad_request("owned fixture error"))
            })
            .await
            .is_err());
        assert!(cache
            .get(key, || async { Ok(loaded("10.3.0.0/16")) })
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn cache_and_inflight_share_capacity_and_cancelled_loaders_can_be_evicted() {
        let cache = Arc::new(CaptureCache::default());
        let owner = ObjectId::new();
        let started = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..CAPACITY {
            let cache = cache.clone();
            let started = started.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .get(
                        Key {
                            owner,
                            route: i.to_string(),
                        },
                        || async {
                            started.fetch_add(1, Ordering::Relaxed);
                            std::future::pending::<ApiResult<Loaded>>().await
                        },
                    )
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::Relaxed) != CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(cache
            .get(
                Key {
                    owner,
                    route: "overflow".into()
                },
                || async {
                    panic!("overflow must not start a loader");
                    #[allow(unreachable_code)]
                    Ok(loaded("10.1.0.0/16"))
                }
            )
            .await
            .is_err());
        assert_eq!(cache.entries.lock().unwrap().len(), CAPACITY);
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        assert!(cache
            .get(
                Key {
                    owner,
                    route: "after-cancel".into()
                },
                || async { Ok(loaded("10.1.0.0/16")) }
            )
            .await
            .is_ok());
        assert_eq!(cache.entries.lock().unwrap().len(), CAPACITY);
    }
    #[tokio::test]
    async fn lifetime_starts_before_load_and_expired_wall_deadline_cannot_hit() {
        let cache = CaptureCache::default();
        let key = Key {
            owner: ObjectId::new(),
            route: "clock".into(),
        };
        let begun = Arc::new(Mutex::new(None));
        cache
            .get(key.clone(), || {
                let begun = begun.clone();
                async move {
                    *begun.lock().unwrap() = Some(Instant::now());
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(loaded("10.1.0.0/16"))
                }
            })
            .await
            .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail));
        let entry = cache
            .entry(&key)
            .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail));
        {
            let mut value = entry.flight.lock().await;
            let value = value.as_mut().unwrap();
            assert!(value.deadline <= begun.lock().unwrap().unwrap() + LIFETIME);
            value.wall_deadline = DateTime::now().timestamp_millis() - 1;
        }
        let result = cache
            .get(key, || async { Ok(loaded("10.2.0.0/16")) })
            .await
            .unwrap_or_else(|error| panic!("cache fixture failed: {}", error.detail));
        assert_eq!(result, vec!["10.2.0.0/16".parse().unwrap()]);
    }
}
