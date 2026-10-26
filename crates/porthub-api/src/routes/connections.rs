use crate::{
    App, auth,
    domain::{
        connections::{self, Input},
        inventory,
        workspaces::object_id,
    },
    error::{ApiError, ApiResult},
    firewall, generated,
    input::{ApiBody, Model},
    input_compat::strip,
    store,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use futures_util::TryStreamExt;
use mongodb::{
    IndexModel,
    bson::{Bson, DateTime, Document, doc, oid::ObjectId},
    options::IndexOptions,
};
use rand::Rng;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/connections/add", post(add))
        .route("/api/connections/update", put(update))
        .route("/api/connections/delete", post(delete))
        .route("/api/connections/list", get(list))
        .route("/api/connections/refresh", post(refresh))
        .route("/api/connections/random", get(random))
        .route(
            "/api/connections/external-port/{port}/availability",
            get(availability),
        )
        .route("/api/connections/command/{id}", get(command))
}
fn reply(message: &str, data: Value) -> Json<Value> {
    Json(json!({"msg":message,"data":data}))
}
fn range_error(app: &App, port: i64) -> Option<String> {
    app.config
        .external_port_range
        .filter(|(a, b)| port < *a as i64 || port > *b as i64)
        .map(|(a, b)| format!("External port must be between {a} and {b}"))
}
pub async fn owned(app: &App, owner: &Bson, id: &str, status: StatusCode) -> ApiResult<Document> {
    let id = object_id(id, "Invalid connection id")?;
    app.collection("connections")
        .find_one(doc! {"_id":id,"user_id":owner})
        .await?
        .ok_or_else(|| ApiError::new(status, "Connection not found"))
}
pub async fn machine(app: &App, connection: &Document) -> ApiResult<Option<Document>> {
    match connection.get("machine_id") {
        Some(id) => Ok(app
            .collection("machines")
            .find_one(doc! {"_id":id,"user_id":connection.get("user_id")})
            .await?),
        None => Ok(None),
    }
}
async fn ensure_index(app: &App) -> ApiResult<()> {
    app.collection("connections")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"external_port":1})
                .options(
                    IndexOptions::builder()
                        .name("porthub_external_port_unique".to_owned())
                        .unique(true)
                        .partial_filter_expression(doc! {"external_port":{"$type":"number"}})
                        .build(),
                )
                .build(),
        )
        .await?;
    Ok(())
}
fn database_error(error: mongodb::error::Error) -> ApiError {
    if store::duplicate(&error) {
        ApiError::bad_request("Port already in use")
    } else {
        error.into()
    }
}
async fn wake(app: &App, connection: &Document) {
    app.notify_config(&store::id(connection.get("machine_id")))
        .await;
}
pub(crate) async fn restore(app: &App, previous: Option<&Document>, candidate: &Document) {
    let result = if let Some(previous) = previous {
        app.collection("connections")
            .replace_one(doc! {"_id":previous.get("_id")}, previous.clone())
            .await
            .map(|_| ())
    } else {
        app.collection("connections")
            .delete_one(doc! {"_id":candidate.get("_id")})
            .await
            .map(|_| ())
    };
    if let Err(error) = result {
        tracing::error!(%error,"connection database rollback failed");
        app.firewall_changes.notify_one();
    }
    if let Some(previous) = previous {
        if let Err(error) = firewall::sync(app, previous).await {
            tracing::error!(detail=%error.detail,"connection firewall rollback failed");
            app.firewall_changes.notify_one();
            return;
        }
    }
    if let Err(error) = generated::rebuild(app).await {
        tracing::error!(detail=%error.detail,"connection configuration rollback failed");
        app.firewall_changes.notify_one();
        return;
    }
    if previous.is_none_or(|previous| firewall::port(previous) != firewall::port(candidate)) {
        if let Err(error) = firewall::remove(app, candidate).await {
            tracing::error!(detail=%error.detail,"connection firewall rollback failed");
            app.firewall_changes.notify_one();
        }
    }
}
async fn save(app: Arc<App>, owner: Bson, input: Input, updating: bool) -> ApiResult<Json<Value>> {
    let _guard = app.connection_lock.lock().await;
    let name = strip(&input.service_name);
    if name.is_empty() {
        return Err(ApiError::bad_request("Service name is required"));
    }
    let machine_id = object_id(&input.machine_id, "Invalid machine id")?;
    let machine = app
        .collection("machines")
        .find_one(doc! {"_id":machine_id,"user_id":&owner,"deletion_pending":{"$ne":true}})
        .await?
        .ok_or_else(|| ApiError::bad_request("Machine not found"))?;
    let previous = if updating {
        Some(
            owned(
                &app,
                &owner,
                input.data_id.as_deref().unwrap_or(""),
                StatusCode::BAD_REQUEST,
            )
            .await?,
        )
    } else {
        None
    };
    if previous
        .as_ref()
        .is_some_and(|connection| connection.get_bool("temporary") == Ok(true))
    {
        return Err(ApiError::bad_request(
            "Temporary agent mappings can only be stopped from the PortHub CLI",
        ));
    }
    if let Some(error) = range_error(&app, input.external_port) {
        return Err(ApiError::bad_request(&error));
    }
    let mut filter = doc! {"external_port":input.external_port};
    if let Some(previous) = &previous {
        filter.insert("_id", doc! {"$ne":previous.get("_id")});
    }
    if app
        .collection("connections")
        .find_one(filter)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Port already in use"));
    }
    ensure_index(&app).await?;
    let now = DateTime::now();
    let enabled = input.enabled.unwrap_or(true);
    let automatic = input.auto_refresh_enabled.unwrap_or(false);
    let minutes = input.auto_refresh_interval_minutes.unwrap_or(60);
    let reset = automatic
        && previous.as_ref().is_none_or(|previous| {
            previous.get_bool("auto_refresh_enabled") != Ok(true)
                || previous
                    .get("auto_refresh_interval_minutes")
                    .and_then(|v| match v {
                        Bson::Int32(n) => Some(*n as i64),
                        Bson::Int64(n) => Some(*n),
                        _ => None,
                    })
                    != Some(minutes)
                || previous
                    .get("auto_refresh_next_at")
                    .is_none_or(|v| v == &Bson::Null)
                || (previous.get_bool("enabled") == Ok(false) && enabled)
        });
    let mut candidate=previous.clone().unwrap_or_else(||doc! {"_id":ObjectId::new(),"user_id":&owner,"created_at":now,"firewall":{"is_public":true,"allowed_ips":[]}});
    candidate.remove("native_refresh");
    candidate.extend(doc! {"machine_id":machine_id,"service_name":name,"service_description":strip(input.service_description.as_deref().unwrap_or("")),
        "internal_ip":input.internal_ip,"internal_port":input.internal_port,"external_port":input.external_port,"enabled":enabled,
        "auto_refresh_enabled":automatic,"auto_refresh_interval_minutes":if automatic {Bson::Int64(minutes)}else{Bson::Null},"updated_at":now});
    if !automatic {
        candidate.insert("auto_refresh_next_at", Bson::Null);
    } else if reset {
        candidate.insert(
            "auto_refresh_next_at",
            DateTime::from_millis(now.timestamp_millis() + minutes * 60_000),
        );
    }
    if previous.is_some() {
        app.collection("connections")
            .replace_one(
                doc! {"_id":candidate.get("_id"),"user_id":owner},
                candidate.clone(),
            )
            .await
            .map_err(database_error)?;
    } else {
        app.collection("connections")
            .insert_one(candidate.clone())
            .await
            .map_err(database_error)?;
    }
    // Apply restrictions before publishing a new listener. Failed policy or
    // publication restores both the old record and the previous gateway snapshot.
    if let Err(error) = async {
        if enabled {
            firewall::sync(&app, &candidate).await?;
            generated::rebuild(&app).await
        } else {
            generated::rebuild(&app).await?;
            firewall::sync(&app, &candidate).await
        }
    }
    .await
    {
        restore(&app, previous.as_ref(), &candidate).await;
        return Err(error);
    }
    wake(&app, &candidate).await;
    if let Some(previous) = &previous {
        wake(&app, previous).await;
        if firewall::port(previous) != firewall::port(&candidate) {
            if let Err(error) = firewall::remove(&app, previous).await {
                tracing::warn!(detail=%error.detail,"stale connection policy cleanup will retry");
                app.firewall_changes.notify_one();
            }
        }
    }
    Ok(reply(
        if updating {
            "Connection updated successfully"
        } else {
            "Connection added successfully"
        },
        inventory::connection(&app, &candidate, Some(&machine)),
    ))
}
async fn operation(
    app: Arc<App>,
    headers: HeaderMap,
    raw: Value,
    updating: bool,
) -> ApiResult<Json<Value>> {
    let input = connections::parse(raw)?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").cloned().unwrap_or(Bson::Null);
    tokio::spawn(save(app, owner, input, updating))
        .await
        .map_err(|error| {
            tracing::error!(%error,"connection operation task failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })?
}
async fn add(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    operation(app, headers, raw, false).await
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    operation(app, headers, raw, true).await
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").cloned().unwrap_or(Bson::Null);
    let connections: Vec<Document> = app
        .collection("connections")
        .find(doc! {"user_id":&owner})
        .await?
        .try_collect()
        .await?;
    let ids: Vec<Bson> = connections
        .iter()
        .filter_map(|c| c.get("machine_id").cloned())
        .collect();
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"_id":{"$in":ids},"user_id":owner})
        .await?
        .try_collect()
        .await?;
    let machines: HashMap<String, Document> = machines
        .into_iter()
        .map(|m| (store::id(m.get("_id")), m))
        .collect();
    Ok(reply(
        "Connections listed successfully",
        json!(
            connections
                .iter()
                .map(|c| inventory::connection(
                    &app,
                    c,
                    machines.get(&store::id(c.get("machine_id")))
                ))
                .collect::<Vec<_>>()
        ),
    ))
}
async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").cloned().unwrap_or(Bson::Null);
    tokio::spawn(async move {
        let _guard = app.connection_lock.lock().await;
        let previous = owned(&app, &owner, &id, StatusCode::BAD_REQUEST).await?;
        if previous.get_bool("temporary") == Ok(true) {
            return Err(ApiError::bad_request(
                "Temporary agent mappings can only be stopped from the PortHub CLI",
            ));
        }
        let machine = machine(&app, &previous).await?;
        app.collection("connections")
            .delete_one(doc! {"_id":previous.get("_id"),"user_id":owner})
            .await?;
        if let Err(error) = generated::rebuild(&app).await {
            if let Err(error) = app
                .collection("connections")
                .insert_one(previous.clone())
                .await
            {
                tracing::error!(%error,"connection deletion rollback failed");
                app.firewall_changes.notify_one();
            }
            return Err(error);
        }
        if let Err(error) = firewall::remove(&app, &previous).await {
            tracing::warn!(detail=%error.detail,"deleted connection policy cleanup will retry");
            app.firewall_changes.notify_one();
        }
        wake(&app, &previous).await;
        Ok(reply(
            "Connection deleted successfully",
            inventory::connection(&app, &previous, machine.as_ref()),
        ))
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))?
}
async fn random(State(app): State<Arc<App>>) -> ApiResult<Json<Value>> {
    // Legacy random-port discovery is unauthenticated; availability remains a hint.
    let (start, end) = app.config.external_port_range.unwrap_or((10000, 65535));
    let used: Vec<Document> = app
        .collection("connections")
        .find(doc! {"external_port":{"$gte":start as i64,"$lte":end as i64}})
        .projection(doc! {"external_port":1})
        .await?
        .try_collect()
        .await?;
    let used: HashSet<i64> = used.iter().filter_map(firewall::port).collect();
    let available: Vec<u16> = (start..=end)
        .filter(|n| !used.contains(&(*n as i64)))
        .collect();
    if available.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "No available external ports in the configured range",
        ));
    }
    Ok(Json(
        json!({"port":available[rand::thread_rng().gen_range(0..available.len())]}),
    ))
}
async fn availability(
    State(app): State<Arc<App>>,
    Path(raw): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let port=crate::input_compat::integer(&Value::String(raw)).ok_or_else(||ApiError::validation(vec![json!({"loc":["path","port"],"msg":"value is not a valid integer","type":"type_error.integer"})]))?;
    auth::current_user(&app, &headers).await?;
    if !(1..=65535).contains(&port) {
        return Err(ApiError::bad_request("Invalid port"));
    }
    if let Some(error) = range_error(&app, port as i64) {
        return Ok(Json(json!({"available":false,"message":error})));
    }
    let mut filter = doc! {"external_port":port as i64};
    if let Some(id) = query.get("data_id").filter(|v| !v.is_empty()) {
        filter.insert("_id", doc! {"$ne":object_id(id,"Invalid connection id")?});
    }
    let available = app
        .collection("connections")
        .find_one(filter)
        .await?
        .is_none();
    Ok(Json(
        json!({"available":available,"message":if available{Value::Null}else{json!("External port is already assigned")} }),
    ))
}
async fn command() -> ApiError {
    ApiError::new(
        StatusCode::GONE,
        "Per-connection client scripts are deprecated. Use the machine bootstrap endpoint instead.",
    )
}

async fn refresh(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").cloned().unwrap_or(Bson::Null);
    tokio::spawn(async move {
        let connection = owned(&app, &owner, &id, StatusCode::BAD_REQUEST).await?;
        if connection.get_bool("enabled") == Ok(false) {
            return Err(ApiError::bad_request(
                "Enable the service before refreshing",
            ));
        }
        let refreshed = crate::connection_refresh::refresh(
            &app,
            connection,
            std::time::Duration::from_secs(5),
            None,
        )
        .await?
        .ok_or_else(|| ApiError::bad_request("Could not refresh connection"))?;
        let machine = machine(&app, &refreshed).await?;
        Ok(reply(
            "Connection refreshed successfully",
            inventory::connection(&app, &refreshed, machine.as_ref()),
        ))
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"))?
}
