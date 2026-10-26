use super::connections::{machine, owned};
use crate::{
    App, auth,
    domain::{connections, inventory, workspaces::object_id},
    error::{ApiError, ApiResult},
    firewall,
    input::ApiBody,
    input_compat, store,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
};
use futures_util::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/api/connections/firewall/policy/{id}",
            get(policy).delete(delete),
        )
        .route("/api/connections/firewall/policy", put(update))
        .route("/api/connections/firewall/active", get(active))
        .route(
            "/api/connections/firewall/traffic/snapshot",
            axum::routing::post(snapshot),
        )
        .route("/api/connections/firewall/recent-ip-hits/{id}", get(hits))
}
fn reply(message: &str, data: Value) -> Json<Value> {
    Json(json!({"msg":message,"data":data}))
}
async fn owner(app: &App, headers: &HeaderMap) -> ApiResult<Bson> {
    Ok(auth::current_user(app, headers)
        .await?
        .get("_id")
        .cloned()
        .unwrap_or(Bson::Null))
}
async fn answer(
    app: &App,
    connection: &Document,
    message: &str,
    applied: bool,
) -> ApiResult<Json<Value>> {
    let machine = machine(app, connection).await?;
    let mut policy = firewall::policy(connection);
    policy["applied"] = json!(applied);
    Ok(reply(
        message,
        json!({"connection":inventory::connection(app,connection,machine.as_ref()),"firewall":policy}),
    ))
}
async fn policy(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    let connection = owned(&app, &owner, &id, StatusCode::NOT_FOUND).await?;
    let applied = connection
        .get("enabled")
        .map(store::json)
        .map(|v| input_compat::truthy(&v))
        .unwrap_or(true);
    answer(
        &app,
        &connection,
        "Connection firewall policy fetched successfully",
        applied,
    )
    .await
}
async fn set(
    app: Arc<App>,
    owner: Bson,
    id: String,
    policy: Value,
    message: &'static str,
) -> ApiResult<Json<Value>> {
    tokio::spawn(async move {
        let _guard = app.connection_lock.lock().await;
        let previous = owned(&app, &owner, &id, StatusCode::NOT_FOUND).await?;
        if previous.get_bool("temporary") == Ok(true) {
            return Err(ApiError::bad_request(
                "Temporary agent mappings can only be stopped from the PortHub CLI",
            ));
        }
        let mut candidate = previous.clone();
        candidate.insert(
            "firewall",
            mongodb::bson::to_bson(&policy).map_err(|_| ApiError::bad_request("Invalid policy"))?,
        );
        // A configured firewall must accept changes before the API reports success.
        // Unconfigured development retains the stored policy for later reconciliation.
        if let Err(error) = firewall::sync(&app, &candidate).await {
            app.firewall_changes.notify_one();
            return Err(error);
        }
        if let Err(error) = app
            .collection("connections")
            .replace_one(
                doc! {"_id":previous.get("_id"),"user_id":owner},
                candidate.clone(),
            )
            .await
        {
            if let Err(error) = firewall::sync(&app, &previous).await {
                tracing::error!(detail=%error.detail,"firewall policy rollback failed");
                app.firewall_changes.notify_one();
            }
            return Err(error.into());
        }
        let applied = candidate.get_bool("enabled") != Ok(false);
        answer(&app, &candidate, message, applied).await
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))?
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = connections::firewall(raw)?;
    let owner = owner(&app, &headers).await?;
    set(
        app,
        owner,
        input.data_id,
        json!({"is_public":input.is_public,"allowed_ips":input.allowed_ips}),
        "Connection firewall policy updated successfully",
    )
    .await
}
async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    set(
        app,
        owner,
        id,
        json!({"is_public":true,"allowed_ips":[]}),
        "Connection firewall policy deleted successfully",
    )
    .await
}
async fn records(app: &App, owner: Bson, ids: Vec<String>) -> ApiResult<Vec<Document>> {
    let mut filter = doc! {"user_id":owner};
    if !ids.is_empty() {
        let ids = ids
            .iter()
            .map(|id| object_id(id, "Invalid connection id"))
            .collect::<ApiResult<Vec<_>>>()?;
        filter.insert("_id", doc! {"$in":ids});
    }
    Ok(app
        .collection("connections")
        .find(filter)
        .await?
        .try_collect()
        .await?)
}
async fn active(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let client = firewall::configured(&app)?;
    let owner = owner(&app, &headers).await?;
    let records = records(&app, owner, Vec::new()).await?;
    let by_port: HashMap<i64, &Document> = records
        .iter()
        .filter_map(|c| firewall::port(c).map(|p| (p, c)))
        .collect();
    let active = client.request(Method::GET, "/ports/active", None).await?;
    let mut data = Vec::new();
    for item in active.as_array().into_iter().flatten() {
        if let Some(connection) = item
            .get("port")
            .and_then(Value::as_i64)
            .and_then(|p| by_port.get(&p))
        {
            let machine = machine(&app, connection).await?;
            data.push(json!({"port":item["port"],"last_seen":item["last_seen"],"connection":inventory::connection(&app,connection,machine.as_ref())}));
        }
    }
    Ok(reply(
        "Connection firewall activity fetched successfully",
        json!(data),
    ))
}
async fn snapshot(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let body = connections::snapshot(raw)?;
    let ids = body["data_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let client = firewall::configured(&app)?;
    let owner = owner(&app, &headers).await?;
    let records = records(&app, owner, ids).await?;
    let ports: BTreeSet<i64> = records.iter().filter_map(firewall::port).collect();
    let snapshot = client
        .request(
            Method::POST,
            "/ports/traffic/snapshot",
            Some(json!({"ports":ports})),
        )
        .await?;
    let mut data = Vec::new();
    for connection in records {
        let key = firewall::port(&connection).unwrap_or_default().to_string();
        let traffic = snapshot
            .get(&key)
            .filter(|v| input_compat::truthy(v))
            .cloned()
            .unwrap_or(json!([]));
        let machine = machine(&app, &connection).await?;
        data.push(json!({"connection":inventory::connection(&app,&connection,machine.as_ref()),"traffic":traffic}));
    }
    Ok(reply(
        "Connection firewall traffic snapshot fetched successfully",
        json!(data),
    ))
}
async fn hits(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let limit=query.get("limit").map(|v|v.trim().parse::<i64>()).transpose().map_err(|_|ApiError::validation(vec![json!({"loc":["query","limit"],"msg":"value is not a valid integer","type":"type_error.integer"})]))?.unwrap_or(10);
    let client = firewall::configured(&app)?;
    let owner = owner(&app, &headers).await?;
    let connection = owned(&app, &owner, &id, StatusCode::NOT_FOUND).await?;
    let port = firewall::port(&connection).unwrap_or_default();
    let hits = client
        .request(
            Method::GET,
            &format!("/ports/{port}/recent-ip-hits?limit={limit}"),
            None,
        )
        .await?;
    Ok(reply(
        "Connection recent IP hits fetched successfully",
        hits,
    ))
}
