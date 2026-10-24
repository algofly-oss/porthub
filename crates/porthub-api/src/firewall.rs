//! Dedicated authenticated IPC client; firewall credentials never enter gateway
//! requests or the API's general HTTP client.
use crate::{
    config::Config,
    error::{ApiError, ApiResult},
    input_compat, store, App,
};
use axum::http::StatusCode;
use mongodb::bson::Document;
use reqwest::{Client as HttpClient, Method};
use serde_json::{json, Value};
use std::time::Duration;
pub struct Client {
    http: HttpClient,
    base: String,
    key: String,
}
impl Client {
    pub fn new(config: &Config) -> anyhow::Result<Option<Self>> {
        if config.firewall_api_key.is_empty()
            || (config.firewall_socket.is_none() && config.firewall_base_url.is_empty())
        {
            return Ok(None);
        }
        let mut builder = HttpClient::builder()
            .no_proxy()
            .timeout(config.firewall_timeout)
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none());
        let base = if let Some(socket) = &config.firewall_socket {
            builder = builder.unix_socket(socket.clone());
            "http://localhost/api".into()
        } else {
            config.firewall_base_url.trim_end_matches('/').to_owned()
        };
        Ok(Some(Self {
            http: builder.build()?,
            base,
            key: config.firewall_api_key.clone(),
        }))
    }
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> ApiResult<Value> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header("x-api-key", &self.key);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let run = async {
            let mut response = request.send().await?;
            let status = response.status();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len() + chunk.len() <= 16 * 1024 * 1024,
                    "firewall response exceeded limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            anyhow::ensure!(
                status.is_success(),
                "firewall rejected request with status {status}"
            );
            Ok::<Value, anyhow::Error>(
                serde_json::from_slice::<Value>(&bytes)?
                    .get("data")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
        };
        run.await.map_err(|error| {
            tracing::warn!(%error,"firewall IPC failed");
            ApiError::new(StatusCode::BAD_GATEWAY, "Firewall request failed")
        })
    }
}
pub fn configured(app: &App) -> ApiResult<&Client> {
    app.firewall.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Firewall integration is not configured",
        )
    })
}
pub fn policy(connection: &Document) -> Value {
    let Some(firewall) = connection.get_document("firewall").ok() else {
        return json!({"is_public":true,"allowed_ips":[]});
    };
    let public = firewall
        .get("is_public")
        .map(store::json)
        .map(|v| input_compat::truthy(&v))
        .unwrap_or(true);
    let ips = firewall
        .get_array("allowed_ips")
        .into_iter()
        .flatten()
        .map(store::json)
        .map(|v| input_compat::text(&v))
        .collect::<Vec<_>>();
    json!({"is_public":public,"allowed_ips":ips})
}
pub fn port(connection: &Document) -> Option<i64> {
    match connection.get("external_port") {
        Some(mongodb::bson::Bson::Int32(n)) => Some(*n as i64),
        Some(mongodb::bson::Bson::Int64(n)) => Some(*n),
        _ => None,
    }
}
pub async fn remove(app: &App, connection: &Document) -> ApiResult<()> {
    remove_many(app, std::slice::from_ref(connection)).await
}
pub async fn remove_many(app: &App, connections: &[Document]) -> ApiResult<()> {
    if let Some(client) = &app.firewall {
        // Keep restrictions if edge is unreachable or rejects the snapshot.
        // Rebuild/ack is idempotent and also protects startup reconciliation.
        if app.gateway_apply.is_some() {
            crate::generated::rebuild(app).await?;
        }
        for connection in connections {
            if let Some(port) = port(connection) {
                client
                    .request(Method::DELETE, &format!("/ports/{port}/policy"), None)
                    .await?;
            }
        }
    }
    Ok(())
}
pub async fn prime(app: &App) -> ApiResult<()> {
    use futures_util::TryStreamExt;
    use mongodb::bson::{doc, Bson};
    let Some(client) = &app.firewall else {
        return Ok(());
    };
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"enabled":{"$ne":false},"deletion_pending":{"$ne":true}})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<Bson> = machines
        .iter()
        .filter_map(|m| m.get("_id").cloned())
        .collect();
    let mut connections = app
        .collection("connections")
        .find(doc! {"machine_id":{"$in":ids},"enabled":{"$ne":false}})
        .await?;
    while let Some(connection) = connections.try_next().await? {
        if let Some(port) = port(&connection) {
            client
                .request(
                    Method::PUT,
                    &format!("/ports/{port}/policy"),
                    Some(policy(&connection)),
                )
                .await?;
        }
    }
    Ok(())
}
/// Install every active restriction before an inactive mapping's removal can
/// publish/acknowledge the enabled machine snapshot.
pub async fn sync_machine(app: &App, id: mongodb::bson::oid::ObjectId) -> ApiResult<()> {
    use futures_util::TryStreamExt;
    use mongodb::bson::doc;
    let Some(client) = &app.firewall else {
        return Ok(());
    };
    let machine = app.collection("machines").find_one(doc! {"_id":id}).await?;
    let enabled = machine.as_ref().is_some_and(|machine| {
        machine.get_bool("enabled") != Ok(false) && machine.get_bool("deletion_pending") != Ok(true)
    });
    let records: Vec<Document> = app
        .collection("connections")
        .find(doc! {"machine_id":id})
        .await?
        .try_collect()
        .await?;
    let (active, inactive): (Vec<_>, Vec<_>) = records
        .into_iter()
        .partition(|connection| enabled && connection.get_bool("enabled") != Ok(false));
    for connection in active {
        if let Some(port) = port(&connection) {
            client
                .request(
                    Method::PUT,
                    &format!("/ports/{port}/policy"),
                    Some(policy(&connection)),
                )
                .await?;
        }
    }
    if !inactive.is_empty() {
        remove_many(app, &inactive).await?;
    }
    Ok(())
}
pub async fn sync(app: &App, connection: &Document) -> ApiResult<()> {
    let (Some(client), Some(port)) = (&app.firewall, port(connection)) else {
        return Ok(());
    };
    let machine = match connection.get("machine_id") {
        Some(id) => {
            app.collection("machines")
                .find_one(mongodb::bson::doc! {"_id":id})
                .await?
        }
        None => None,
    };
    if connection.get_bool("enabled") == Ok(false)
        || machine.as_ref().is_none_or(|m| {
            m.get_bool("enabled") == Ok(false) || m.get_bool("deletion_pending") == Ok(true)
        })
    {
        return remove(app, connection).await;
    }
    client
        .request(
            Method::PUT,
            &format!("/ports/{port}/policy"),
            Some(policy(connection)),
        )
        .await?;
    Ok(())
}
pub async fn reconcile(app: &App) -> ApiResult<()> {
    use futures_util::TryStreamExt;
    if app.firewall.is_none() {
        return Ok(());
    }
    if app.gateway_apply.is_some() {
        prime(app).await?;
    }
    let mut connections = app
        .collection("connections")
        .find(mongodb::bson::doc! {})
        .await?;
    let mut desired = std::collections::HashSet::new();
    while let Some(connection) = connections.try_next().await? {
        if let Some(port) = port(&connection) {
            desired.insert(port);
        }
        sync(app, &connection).await?;
    }
    let existing = app
        .firewall
        .as_ref()
        .unwrap()
        .request(Method::GET, "/ports/policies/list", None)
        .await?;
    if app.gateway_apply.is_some() {
        crate::generated::rebuild(app).await?;
    }
    for policy in existing.as_array().into_iter().flatten() {
        if let Some(port) = policy.get("port").and_then(Value::as_i64) {
            if !desired.contains(&port) {
                app.firewall
                    .as_ref()
                    .unwrap()
                    .request(Method::DELETE, &format!("/ports/{port}/policy"), None)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Coalesced reconciliation: retry failures, otherwise sleep until a mutation
/// requests recovery. No periodic scans or per-connection background tasks.
pub async fn run(app: std::sync::Arc<App>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            return;
        }
        let result = {
            let _guard = app.connection_lock.lock().await;
            reconcile(&app).await
        };
        match result {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                tokio::select! {_=app.firewall_changes.notified()=>{},_=stop.changed()=>return}
            }
            Err(error) => {
                tracing::warn!(detail=%error.detail,"firewall reconciliation will retry");
                tokio::select! {_=tokio::time::sleep(backoff)=>{},_=stop.changed()=>return};
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}
