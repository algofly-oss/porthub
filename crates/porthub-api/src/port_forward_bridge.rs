//! TCP service admission for persisted, owner-scoped SSH forwarding entries.
pub(crate) mod private;
use crate::{
    error::{ApiError, ApiResult},
    routes::port_forwards::COLLECTION,
    App,
};
use anyhow::{anyhow, ensure, Context, Result};
use axum::http::{header, StatusCode};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime, Document};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::DuplexStream,
    sync::{watch, Mutex, OnceCell},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(crate) struct Bridge {
    changes: Mutex<()>,
    indexes: OnceCell<()>,
    edge: OnceCell<reqwest::Client>,
    workers: std::sync::Mutex<HashMap<(ObjectId, u16), Worker>>,
}
struct Worker {
    stop: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
}
impl Bridge {
    fn workers(&self) -> std::sync::MutexGuard<'_, HashMap<(ObjectId, u16), Worker>> {
        self.workers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}
const PROTOCOL: &str = "porthub-forward-v1";
const BASE: &str = "http://localhost/forwards";
fn api(err: ApiError) -> anyhow::Error {
    anyhow!("forward service reconciliation failed ({})", err.status)
}
async fn edge(app: &App) -> Result<&reqwest::Client> {
    app.forward_bridge
        .edge
        .get_or_try_init(|| async {
            Ok(reqwest::Client::builder()
                .unix_socket(
                    app.config
                        .edge_socket
                        .clone()
                        .context("edge control socket unavailable")?,
                )
                .no_proxy()
                .connect_timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .build()?)
        })
        .await
}
fn number(mapping: &Document, key: &str) -> Result<u16> {
    let port = u16::try_from(mapping.get_i32(key)?)?;
    ensure!(port != 0, "invalid mapping port");
    Ok(port)
}
fn mappings(row: &Document) -> Result<Vec<&Document>> {
    row.get_array("mappings")?
        .iter()
        .map(|v| v.as_document().context("invalid mapping"))
        .collect()
}
async fn entry(app: &App, owner: ObjectId, id: ObjectId) -> Result<Document> {
    let query = doc! {"_id":id,"workspace_id":owner,"state":"active"};
    let entries = app.collection(COLLECTION);
    let users = app.collection("users");
    let (row, user) = tokio::try_join!(
        entries.find_one(query).into_future(),
        users
            .find_one(doc! {"_id":owner,"account_deletion":{"$exists":false}})
            .projection(doc! {"_id":1})
            .into_future()
    )?;
    ensure!(user.is_some(), "account withdrawn");
    row.context("entry withdrawn")
}
use std::future::IntoFuture;
fn import_service(id: ObjectId, index: usize) -> String {
    format!("porthub_import_{}_{index}", id.to_hex())
}

/// Synthesize both endpoint plans from the same durable mapping. The destination
/// gets its ordinary service configuration; the matching edge service has no listener.
pub(crate) async fn imports(app: &App, machines: &[Document]) -> ApiResult<Vec<Document>> {
    let mut owners = HashMap::new();
    for machine in machines {
        if let (Ok(id), Ok(owner)) = (
            machine.get_object_id("_id"),
            machine.get_object_id("user_id"),
        ) {
            if machine.get_bool("enabled") != Ok(false)
                && machine.get_bool("deletion_pending") != Ok(true)
                && machine.get_str("kind") != Ok("virtual_host")
            {
                owners.insert(id.to_hex(), owner);
            }
        }
    }
    if owners.is_empty() {
        return Ok(vec![]);
    }
    let ids: Vec<_> = owners.keys().cloned().collect();
    let mut rows = app
        .collection(COLLECTION)
        .find(doc! {"state":"active","mappings.machineId":{"$in":ids}})
        .projection(doc! {"_id":1,"workspace_id":1,"mappings":1})
        .await?;
    let mut records = Vec::new();
    while let Some(row) = rows.try_next().await? {
        let (Ok(owner), Ok(entry), Ok(items)) = (
            row.get_object_id("workspace_id"),
            row.get_object_id("_id"),
            mappings(&row),
        ) else {
            continue;
        };
        for (index, m) in items.into_iter().enumerate() {
            let (Ok(id), Ok(port)) = (m.get_str("machineId"), number(m, "servicePort")) else {
                continue;
            };
            if index >= 32
                || m.get_str("direction") != Ok("local")
                || owners.get(id) != Some(&owner)
                || m.get_str("target") != Ok(format!("host-{id}").as_str())
            {
                continue;
            }
            let key = import_service(entry, index);
            records.push(
                doc! {"_id":&key,"machine_id":ObjectId::parse_str(id).expect("inventory id"),
                "forward_import_service":&key,"service_name":"SSH port forward","enabled":true,
                "external_port":0,"internal_ip":"127.0.0.1","internal_port":i32::from(port)},
            );
        }
    }
    records.sort_by(|a, b| a.get_str("_id").ok().cmp(&b.get_str("_id").ok()));
    Ok(records)
}
pub async fn open_import(
    app: &Arc<App>,
    owner: &str,
    id: &str,
    index: &str,
) -> Result<DuplexStream> {
    let (owner, id, index) = (
        ObjectId::parse_str(owner)?,
        ObjectId::parse_str(id)?,
        index.parse::<usize>()?,
    );
    let row = entry(app, owner, id).await?;
    let mappings = mappings(&row)?;
    let m = *mappings.get(index).context("unlisted service")?;
    let machine = m.get_str("machineId")?;
    ensure!(
        index < 32
            && m.get_str("direction")? == "local"
            && m.get_str("target")? == format!("host-{machine}"),
        "invalid registered target"
    );
    number(m, "servicePort")?;
    let actual = app
        .collection("machines")
        .find_one(doc! {"_id":ObjectId::parse_str(machine)?,"user_id":owner,
        "kind":{"$ne":"virtual_host"},"enabled":{"$ne":false},"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1})
        .await?;
    ensure!(actual.is_some(), "registered destination unavailable");
    let mut stream = upgrade(edge(app).await?, format!("{BASE}/import/{id}/{index}"))
        .await?
        .context("destination unavailable")?;
    let grant = app
        .forward_registry
        .get(&id.to_hex())
        .context("grant withdrawn")?;
    let (user, mut pipe) = tokio::io::duplex(32 * 1024);
    tokio::spawn(async move {
        tokio::select! {biased;_=grant.cancel.cancelled()=>{},_=tokio::io::copy_bidirectional(&mut stream,&mut pipe)=>{}}
    });
    Ok(user)
}
async fn upgrade(http: &reqwest::Client, url: String) -> Result<Option<reqwest::Upgraded>> {
    let response = http
        .post(url)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, PROTOCOL)
        .timeout(Duration::from_secs(16))
        .send()
        .await?;
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(None);
    }
    ensure!(
        response.status() == StatusCode::SWITCHING_PROTOCOLS
            && response
                .headers()
                .get(header::UPGRADE)
                .is_some_and(|v| v == PROTOCOL),
        "edge service unavailable"
    );
    Ok(Some(response.upgrade().await?))
}
async fn policy(app: &App, port: u16, public: bool) -> Result<()> {
    if let Some(client) = &app.firewall {
        let path = format!("/ports/{port}/policy");
        if public {
            client
                .request(
                    reqwest::Method::PUT,
                    &path,
                    Some(serde_json::json!({"is_public":true,"allowed_ips":[]})),
                )
                .await
                .map_err(api)?;
        } else {
            client
                .request(reqwest::Method::DELETE, &path, None)
                .await
                .map_err(api)?;
        }
    }
    Ok(())
}
/// Firewall sweeps use ownership of the reservation rather than its disabled
/// flag. Ordinary machine mappings are reconciled by their original code path.
pub(crate) async fn sync_reservation(app: &App, connection: &Document) -> ApiResult<()> {
    let (Ok(id), Ok(owner), Ok(port)) = (
        connection.get_object_id("forward_reservation"),
        connection.get_object_id("forward_owner"),
        number(connection, "external_port"),
    ) else {
        return Ok(());
    };
    let public = app
        .collection(COLLECTION)
        .count_documents(
            doc! {"_id":id,"workspace_id":owner,"state":"active","public":true,
            "mappings":{"$elemMatch":{"direction":"remote","gatewayPort":i32::from(port)}}},
        )
        .await?
        > 0;
    policy(app, port, public).await.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Forward firewall reconciliation failed",
        )
    })
}
async fn public_worker(
    app: Arc<App>,
    owner: ObjectId,
    id: ObjectId,
    port: u16,
    stop: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        while sessions.try_join_next().is_some() {}
        let accept = async {
            let http = edge(&app).await?;
            upgrade(http, format!("{BASE}/public/{id}/{port}/accept")).await
        };
        let result = tokio::select! {biased;_=stop.cancelled()=>break, result=accept=>result};
        ready.store(result.is_ok(), std::sync::atomic::Ordering::Release);
        match result {
            Ok(Some(stream)) if sessions.len() < 32 => {
                if let Some(grant) = app
                    .forward_registry
                    .get(&id.to_hex())
                    .filter(|g| g.is_listening(port))
                {
                    if entry(&app, owner, id)
                        .await
                        .is_ok_and(|r| r.get_bool("public") == Ok(true))
                    {
                        sessions.spawn(async move {
                            let _ = grant.forward(port, stream).await;
                        });
                    }
                }
            }
            Err(_) => {
                tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
            }
            _ => {}
        }
    }
    sessions.shutdown().await;
}
async fn notify(app: &App, row: &Document) {
    let ids: HashSet<_> = mappings(row)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| m.get_str("machineId").ok())
        .collect();
    for id in ids {
        app.notify_config(id).await;
    }
}
pub async fn activate(app: &Arc<App>, owner: ObjectId, id: ObjectId) -> Result<()> {
    let _provision = app.forward_bridge.changes.lock().await;
    let row = entry(app, owner, id).await?;
    let items = mappings(&row)?;
    if items.iter().any(|m| m.get_str("direction") == Ok("local")) {
        ensure!(app.gateway_apply.is_some(), "managed gateway required");
        crate::generated::rebuild(app).await.map_err(api)?;
        notify(app, &row).await;
    }
    if row.get_bool("public") == Ok(true) {
        let http = edge(app).await?;
        for mapping in items
            .iter()
            .filter(|m| m.get_str("direction") == Ok("remote"))
        {
            let port = number(mapping, "gatewayPort")?;
            ensure!(app.collection("connections").count_documents(doc!{"forward_reservation":id,"forward_owner":owner,"external_port":i32::from(port)}).await?==1,"port reservation missing");
            policy(app, port, true).await?;
            http.post(format!("{BASE}/public/{id}/{port}"))
                .timeout(Duration::from_secs(3))
                .send()
                .await?
                .error_for_status()?;
            let mut workers = app.forward_bridge.workers();
            let worker = workers.entry((id, port)).or_insert_with(|| {
                let stop = CancellationToken::new();
                let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
                tokio::spawn(public_worker(
                    app.clone(),
                    owner,
                    id,
                    port,
                    stop.clone(),
                    ready.clone(),
                ));
                Worker { stop, ready }
            });
            worker
                .ready
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
    private::signal(app, owner);
    Ok(())
}
/// Close only audience-facing resources; SSH identity and port reservations survive.
pub(crate) async fn withdraw_audience(app: &App, owner: ObjectId, id: ObjectId, old: &Document) -> Result<()> {
    let _provision = app.forward_bridge.changes.lock().await;
    private::signal(app, owner);
    app.forward_bridge.workers().retain(|(entry, _), worker| {
        if *entry == id { worker.stop.cancel(); false } else { true }
    });
    if old.get_bool("public") == Ok(true) || old.get_bool("audience_cleanup_pending") == Ok(true) {
        edge(app).await?.delete(format!("{BASE}/public/{id}"))
            .timeout(Duration::from_secs(3)).send().await?.error_for_status()?;
        for mapping in mappings(old)? {
            if mapping.get_str("direction") == Ok("remote") {
                policy(app, number(mapping, "gatewayPort")?, false).await?;
            }
        }
    }
    Ok(())
}

pub async fn deactivate(app: &App, owner: ObjectId, id: ObjectId) -> Result<()> {
    let _provision = app.forward_bridge.changes.lock().await;
    let row = app
        .collection(COLLECTION)
        .find_one(doc! {"_id":id,"workspace_id":owner})
        .await?;
    private::signal(app, owner);
    app.forward_bridge.workers().retain(|(entry, _), worker| {
        if *entry == id {
            worker.stop.cancel();
            false
        } else {
            true
        }
    });
    if let Some(row) = row {
        if row.get_bool("public") == Ok(true) || row.get_bool("audience_cleanup_pending") == Ok(true) {
            edge(app)
                .await?
                .delete(format!("{BASE}/public/{id}"))
                .timeout(Duration::from_secs(3))
                .send()
                .await?
                .error_for_status()?;
            for m in mappings(&row).unwrap_or_default() {
                if let Ok(port) = number(m, "gatewayPort") {
                    policy(app, port, false).await?;
                }
            }
        }
        if mappings(&row)
            .unwrap_or_default()
            .iter()
            .any(|m| m.get_str("direction") == Ok("local"))
        {
            crate::generated::rebuild(app).await.map_err(api)?;
            notify(app, &row).await;
        }
    }
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    ready: bool,
    pub private_host: Option<String>,
    pub public_host: Option<String>,
    reason: Option<&'static str>,
}
pub async fn workspace_suffix(app: &App, owner: ObjectId) -> ApiResult<String> {
    private::suffix(app, owner).await
}
pub fn status_from_row(app: &App, row: &Document, suffix: &str) -> Result<BridgeStatus> {
    let id = row.get_object_id("_id")?;
    let public = row.get_bool("public") == Ok(true);
    let ports: Vec<_> = mappings(&row)?
        .into_iter()
        .filter(|m| m.get_str("direction") == Ok("remote"))
        .map(|m| number(m, "gatewayPort"))
        .collect::<Result<_>>()?;
    let grant = app.forward_registry.get(&id.to_hex());
    let attached = grant
        .as_ref()
        .is_some_and(|g| ports.iter().all(|p| g.is_listening(*p)));
    let edge_ready = !public || {
        let workers = app.forward_bridge.workers();
        ports.iter().all(|p| {
            workers
                .get(&(id, *p))
                .is_some_and(|worker| worker.ready.load(std::sync::atomic::Ordering::Acquire))
        })
    };
    let selected = row.get_array("machine_ids").is_ok_and(|v| !v.is_empty())
        || row.get_array("group_ids").is_ok_and(|v| !v.is_empty());
    let unpublished = !ports.is_empty() && !public && !selected;
    let ready = attached && edge_ready && !unpublished;
    let reason = if unpublished {
        Some("Choose an audience to publish this forward")
    } else if !edge_ready {
        Some("Waiting for the public gateway listener")
    } else if !attached {
        Some("Waiting for the saved SSH command to connect")
    } else {
        None
    };
    let private_host = if !public && selected && !ports.is_empty() {
        Some(format!("{id}.forwards.{suffix}"))
    } else {
        None
    };
    Ok(BridgeStatus {
        ready,
        private_host,
        public_host: if public {
            Some(crate::port_forward_auth::endpoint(app)?.0)
        } else {
            None
        },
        reason,
    })
}

async fn ensure_indexes(app: &App) -> Result<()> {
    app.forward_bridge
        .indexes
        .get_or_try_init(|| async {
            use mongodb::IndexModel;
            // Separate compound indexes for the two selector arrays avoid MongoDB's
            // parallel multikey restriction and keep unrelated machine syncs cheap.
            let keys = [
                doc! {"state":1,"mappings.machineId":1},
                doc! {"workspace_id":1,"state":1,"machine_ids":1},
                doc! {"workspace_id":1,"state":1,"group_ids":1},
                doc! {"state":1,"created_at":1},
            ];
            app.collection(COLLECTION)
                .create_indexes(
                    keys.into_iter()
                        .map(|key| IndexModel::builder().keys(key).build()),
                )
                .await?;
            Ok::<(), anyhow::Error>(())
        })
        .await?;
    Ok(())
}
async fn reap(app: &Arc<App>) -> Result<()> {
    let cutoff = DateTime::from_millis(DateTime::now().timestamp_millis() - 600_000);
    let mut stale=app.collection(COLLECTION).find(doc!{"$or":[{"state":"provisioning","created_at":{"$lt":cutoff}},{"state":"deleting"}]})
        .projection(doc!{"workspace_id":1}).limit(256).await?;
    while let Some(row) = stale.try_next().await? {
        let owner = row.get_object_id("workspace_id")?;
        let id = row.get_object_id("_id")?;
        // Lock ordering matches CREATE: a claimed but unfinished reservation
        // must never be reaped while another creator still owns the write lock.
        let _guard = app.connection_lock.lock().await;
        let modified = app
            .collection(COLLECTION)
            .update_one(
                doc! {"_id":id,"workspace_id":owner,
                "$or":[{"state":"deleting"},{"state":"provisioning","created_at":{"$lt":cutoff}}]},
                doc! {"$set":{"state":"deleting"}},
            )
            .await?
            .matched_count;
        if modified == 0 {
            continue;
        }
        crate::routes::port_forwards::retire(app, owner, id)
            .await
            .map_err(api)?;
    }
    let mut orphan=app.collection("connections").aggregate([
        doc!{"$match":{"forward_reservation":{"$exists":true}}},
        doc!{"$lookup":{"from":COLLECTION,"localField":"forward_reservation","foreignField":"_id","as":"entry"}},
        doc!{"$match":{"entry.0":{"$exists":false}}},doc!{"$limit":256},doc!{"$project":{"entry":0}}
    ]).await?;
    while let Some(row) = orphan.try_next().await? {
        let _guard = app.connection_lock.lock().await;
        let id = row.get_object_id("forward_reservation")?;
        if app
            .collection(COLLECTION)
            .count_documents(doc! {"_id":id})
            .await?
            != 0
        {
            continue;
        }
        // This reserved port cannot be reused until the edge confirms its old
        // listener has closed and any previous firewall allowance is gone.
        edge(app)
            .await?
            .delete(format!("{BASE}/public/{id}"))
            .timeout(Duration::from_secs(3))
            .send()
            .await?
            .error_for_status()?;
        policy(app, number(&row, "external_port")?, false).await?;
        app.collection("connections")
            .delete_one(doc! {"_id":row.get_object_id("_id")?,"forward_reservation":id})
            .await?;
    }
    Ok(())
}
async fn recover_public(app: &Arc<App>) -> Result<()> {
    // A failed audience withdrawal remains durable across retries/restarts.
    let pending: Vec<Document> = app.collection(COLLECTION)
        .find(doc!{"state":"active","audience_cleanup_pending":true})
        .limit(256).await?.try_collect().await?;
    for candidate in pending {
        let _connection = app.connection_lock.lock().await;
        let id = candidate.get_object_id("_id")?;
        if let Some(row) = app.collection(COLLECTION)
            .find_one(doc!{"_id":id,"state":"active","audience_cleanup_pending":true}).await? {
            withdraw_audience(app,row.get_object_id("workspace_id")?,id,&row).await?;
            app.collection(COLLECTION).update_one(doc!{"_id":id},
                doc!{"$unset":{"audience_cleanup_pending":""}}).await?;
        }
    }

    let mut rows = app
        .collection(COLLECTION)
        .find(doc! {"state":"active","public":true})
        .projection(doc! {"workspace_id":1,"mappings":1})
        .await?;
    let mut wanted = HashMap::new();
    while let Some(row) = rows.try_next().await? {
        for m in mappings(&row)? {
            if m.get_str("direction") == Ok("remote") {
                wanted.insert(
                    (row.get_object_id("_id")?, number(m, "gatewayPort")?),
                    row.get_object_id("workspace_id")?,
                );
            }
        }
    }
    let http = edge(app).await?;
    let existing: Vec<(String, u16)> = http
        .get(format!("{BASE}/public"))
        .timeout(Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let existing: HashSet<_> = existing
        .into_iter()
        .filter_map(|(id, p)| ObjectId::parse_str(id).ok().map(|id| (id, p)))
        .collect();
    let workers: HashSet<_> = app.forward_bridge.workers().keys().copied().collect();
    let stale: HashSet<_> = existing
        .union(&workers)
        .filter(|key| !wanted.contains_key(key))
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        let _guard = app.forward_bridge.changes.lock().await;
        if app
            .collection(COLLECTION)
            .count_documents(doc! {"_id":id,"state":"active","public":true})
            .await?
            != 0
        {
            continue;
        }
        app.forward_bridge.workers().retain(|(entry, _), worker| {
            if *entry == id {
                worker.stop.cancel();
                false
            } else {
                true
            }
        });
        http.delete(format!("{BASE}/public/{id}"))
            .timeout(Duration::from_secs(3))
            .send()
            .await?
            .error_for_status()?;
    }
    let missing: HashSet<_> = wanted
        .iter()
        .filter(|(k, _)| !existing.contains(k) || !workers.contains(k))
        .map(|((id, _), owner)| (*owner, *id))
        .collect();
    for (owner, id) in missing {
        activate(app, owner, id).await?;
    }
    Ok(())
}
pub async fn run(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {biased;_=stop.changed()=>break,_=interval.tick()=>{
            if let Err(err)=ensure_indexes(&app).await {tracing::warn!(%err,"SSH forward indexes will retry");}
            if let Err(err)=reap(&app).await{tracing::warn!(%err,"SSH forward cleanup will retry");}
            if app.config.edge_socket.is_some(){if let Err(err)=recover_public(&app).await{tracing::warn!(%err,"SSH forward edge recovery will retry");}}
        }}
    }
    for (_, worker) in app.forward_bridge.workers().drain() {
        worker.stop.cancel();
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use tokio::net::{TcpListener, UnixListener};
    #[tokio::test]
    #[ignore = "needs isolated MongoDB"]
    async fn public_edge_rebinds_and_quarantines_incomplete_reservations() -> Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_forward_recovery_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("edge.sock");
        let socket = UnixListener::bind(&path)?;
        let server = porthub_tunnel::EmbeddedServer::new(porthub_tunnel::gateway_config(
            "[server.services]",
        )?)
        .await?;
        let router = porthub_edge::apply::router(
            Arc::new(tokio::sync::RwLock::new(server)),
            temp.path().join("edge.toml"),
        );
        let server = tokio::spawn(async move { axum::serve(socket, router).await });
        let app = Arc::new(App::new(
            crate::config::Config {
                edge_socket: Some(path),
                ..Default::default()
            },
            db.clone(),
        ));
        let result=async{
            ensure_indexes(&app).await?;
            let (id,owner,orphan,stale)=(ObjectId::new(),ObjectId::new(),ObjectId::new(),ObjectId::new());
            let original=TcpListener::bind("127.0.0.1:0").await?;
            let port=original.local_addr()?.port();drop(original);
            app.collection("users").insert_one(doc!{"_id":owner}).await?;
            app.collection(COLLECTION).insert_one(doc!{"_id":id,"workspace_id":owner,"public":true,"state":"active","mappings":[{"direction":"remote","gatewayPort":i32::from(port),"clientPort":22}]}).await?;
            app.collection("connections").insert_one(doc!{"forward_owner":owner,"forward_reservation":id,"external_port":i32::from(port),"enabled":false}).await?;
            let list=||async{edge(&app).await?.get(format!("{BASE}/public")).send().await?.json::<Vec<(String,u16)>>().await.map_err(anyhow::Error::from)};
            recover_public(&app).await?;assert_eq!(list().await?,vec![(id.to_hex(),port)]);
            // A restarted edge has an empty in-memory listener registry. Its
            // live core worker must recreate the listener for exactly this id.
            let http=edge(&app).await?;
            http.delete(format!("{BASE}/public/{id}")).send().await?.error_for_status()?;
            assert!(list().await?.is_empty());
            recover_public(&app).await?;assert_eq!(list().await?,vec![(id.to_hex(),port)]);
            // Audience withdrawal closes the actual public listener while
            // retaining the exact reservation and durable SSH mapping.
            let old = app.collection(COLLECTION).find_one(doc!{"_id":id}).await?.unwrap();
            app.collection(COLLECTION).update_one(doc!{"_id":id},doc!{"$set":{"public":false,"machine_ids":[],"group_ids":[],"audience_cleanup_pending":true}}).await?;
            let _ = old;
            recover_public(&app).await?;
            assert!(app.collection(COLLECTION).find_one(doc!{"_id":id}).await?.unwrap().get("audience_cleanup_pending").is_none());
            assert!(list().await?.is_empty());
            assert!(TcpListener::bind(("0.0.0.0",port)).await.is_ok());
            assert_eq!(app.collection("connections").count_documents(doc!{"forward_reservation":id}).await?,1);
            app.collection(COLLECTION).update_one(doc!{"_id":id},doc!{"$set":{"public":true}}).await?;
            recover_public(&app).await?;
            assert_eq!(list().await?,vec![(id.to_hex(),port)]);
            app.collection(COLLECTION).insert_one(doc!{"_id":stale,"workspace_id":owner,"state":"provisioning","public":false,"created_at":DateTime::from_millis(0)}).await?;
            for (n,entry) in [(31003,orphan),(31004,stale)] {
                app.collection("connections").insert_one(doc!{"forward_owner":owner,"forward_reservation":entry,"external_port":n,"enabled":false}).await?;
            }
            reap(&app).await?;
            assert!(app.collection(COLLECTION).find_one(doc!{"_id":stale}).await?.is_none());
            assert_eq!(app.collection("connections").count_documents(doc!{"forward_owner":owner}).await?,1);
            app.collection(COLLECTION).update_one(doc!{"_id":id},doc!{"$set":{"state":"deleting"}}).await?;
            reap(&app).await?;assert!(list().await?.is_empty());
            assert!(TcpListener::bind(("0.0.0.0",port)).await.is_ok());
            assert!(app.forward_bridge.workers().is_empty());
            assert_eq!(app.collection("connections").count_documents(doc!{"forward_owner":owner}).await?,0);
            Ok::<_,anyhow::Error>(())
        }.await;
        server.abort();
        db.drop().await?;
        result
    }
}
