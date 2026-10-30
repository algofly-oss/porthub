use crate::{
    auth,
    domain::{
        inventory,
        traffic_routes::{self, Input},
        workspaces::object_id,
    },
    error::{ApiError, ApiResult},
    generated,
    input::{ApiBody, Model},
    input_compat::strip,
    store, App,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/traffic-routes/add", post(add))
        .route("/api/traffic-routes/update", put(update))
        .route("/api/traffic-routes/list", get(list))
        .route("/api/traffic-routes/health", get(health))
        .route(
            "/api/traffic-routes/activity",
            get(crate::web_activity::activity),
        )
        .route("/api/traffic-routes/delete", post(delete))
}

async fn ensure_index(app: &App) -> ApiResult<()> {
    app.collection("traffic_routes")
        .create_index(
            IndexModel::builder()
                .keys(doc! {"hosts":1})
                .options(
                    IndexOptions::builder()
                        .unique(true)
                        .partial_filter_expression(doc! {"hosts":{"$type":"array"}})
                        .build(),
                )
                .build(),
        )
        .await?;
    Ok(())
}
async fn conflicts(app: &App, hosts: &[String], exclude: Option<ObjectId>) -> ApiResult<()> {
    let mut filter = doc! {"hosts":{"$in":hosts}};
    if let Some(id) = exclude {
        filter.insert("_id", doc! {"$ne":id});
    }
    let existing: Vec<Document> = app
        .collection("traffic_routes")
        .find(filter)
        .await?
        .try_collect()
        .await?;
    let conflicts: BTreeSet<String> = existing
        .iter()
        .flat_map(|route| route.get_array("hosts").into_iter().flatten())
        .filter_map(Bson::as_str)
        .filter(|host| hosts.iter().any(|wanted| wanted == host))
        .map(str::to_owned)
        .collect();
    if !conflicts.is_empty() {
        return Err(ApiError::bad_request(&format!(
            "Hosts already in use: {}",
            conflicts.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    Ok(())
}
async fn metadata(app: &App, owner: &Bson, id: &str) -> ApiResult<Bson> {
    if id.is_empty() {
        return Ok(Bson::Null);
    }
    let id = object_id(id, "Invalid connection id")?;
    let connection = app
        .collection("connections")
        .find_one(doc! {"_id":id,"user_id":owner})
        .await?
        .ok_or_else(|| ApiError::bad_request("Mapped port-pair entry not found"))?;
    if connection.get_bool("temporary") == Ok(true) {
        return Err(ApiError::bad_request(
            "Temporary agent mappings can only use their generated proxy address",
        ));
    }
    let machine = match connection.get("machine_id") {
        Some(id) => {
            app.collection("machines")
                .find_one(doc! {"_id":id,"user_id":owner})
                .await?
        }
        None => None,
    };
    let mut result = doc! {"data_id":id.to_hex(),"machine_id":store::id(connection.get("machine_id")),"machine_name":"","machine_hostname":"",
    "service_name":connection.get("service_name").cloned().unwrap_or(Bson::String(String::new())),
    "service_description":connection.get("service_description").cloned().unwrap_or(Bson::String(String::new())),
    "internal_ip":connection.get("internal_ip").or_else(||connection.get("internalIp")).cloned().unwrap_or(Bson::String("0.0.0.0".into())),
    "internal_port":connection.get("internal_port").cloned().unwrap_or(Bson::Null),
    "external_port":connection.get("external_port").cloned().unwrap_or(Bson::Null),
    "enabled":connection.get("enabled").cloned().unwrap_or(Bson::Boolean(true))};
    if let Some(machine) = machine {
        result.insert(
            "machine_name",
            machine
                .get("name")
                .cloned()
                .unwrap_or(Bson::String(String::new())),
        );
        result.insert("machine_hostname", inventory::hostname(&machine));
    }
    Ok(Bson::Document(result))
}

async fn document(app: &App, owner: &Bson, input: Input) -> ApiResult<Document> {
    if strip(&input.name).is_empty() {
        return Err(ApiError::bad_request("Route name is required"));
    }
    let mut binding_records = Vec::new();
    if let Some(bindings) = &input.bindings {
        for binding in bindings {
            let connection = if binding.target_mode == "connection" {
                metadata(
                    app,
                    owner,
                    binding.connection_data_id.as_deref().unwrap_or(""),
                )
                .await?
            } else {
                Bson::Null
            };
            let target = if let Bson::Document(connection) = &connection {
                generated::connection_web_target(connection).map_err(|_| {
                    ApiError::bad_request("Machine port has no valid gateway listener")
                })?
            } else {
                binding
                    .target_url
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_owned()
            };
            binding_records.push(doc!{"id":&binding.id,"label":binding.label.trim(),"target_mode":&binding.target_mode,"target_url":target,
                "priority":binding.priority as i64,"weight":binding.weight as i64,"enabled":binding.enabled,
                "pass_host":binding.pass_host,"health_path":&binding.health_path,"connection":connection});
        }
    }
    let connection = metadata(
        app,
        owner,
        input.connection_data_id.as_deref().map(strip).unwrap_or(""),
    )
    .await?;
    let now = DateTime::now();
    let mut record = doc! {"_id":ObjectId::new(),"user_id":owner,"name":strip(&input.name),"group":strip(&input.group),
    "description":input.description.as_deref().map(strip).unwrap_or(""),"hosts":input.hosts,
    "target_mode":input.target_mode,"target_url":input.target_url.as_deref().map(strip).unwrap_or(""),
    "entry_points":input.entry_points,"enabled":input.enabled.unwrap_or(true),"connection":connection,"created_at":now,"updated_at":now};
    if !binding_records.is_empty() {
        let primary = &binding_records[0];
        record.insert("target_url", primary.get_str("target_url").unwrap());
        record.insert(
            "connection",
            primary.get("connection").cloned().unwrap_or(Bson::Null),
        );
        record.insert("bindings", binding_records);
        record.insert(
            "routing",
            mongodb::bson::to_bson(&input.routing)
                .map_err(|_| ApiError::bad_request("Invalid routing settings"))?,
        );
    }
    // Validate even a disabled route now, so enabling it cannot reserve gateway
    // aliases or poison the next published routing snapshot.
    let mut active = record.clone();
    active.insert("enabled", true);
    let config = generated::render_web(&[active])
        .map_err(|_| ApiError::bad_request("Web route target must be a valid HTTP or HTTPS URL"))?;
    let hosts = std::iter::once(&app.config.public_base_url)
        .chain(std::iter::once(&app.config.tunnel_http_base_url))
        .chain(app.config.tunnel_fallback_base_urls.iter())
        .filter_map(|base| url::Url::parse(base).ok())
        .filter_map(|url| url.host_str().map(str::to_owned));
    porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(hosts)
        .reload(config)
        .map_err(|error| ApiError::bad_request(&error.to_string()))?;
    Ok(record)
}
async fn owned(app: &App, owner: &Bson, id: &str) -> ApiResult<Document> {
    let id = object_id(id, "Invalid traffic route id")?;
    app.collection("traffic_routes")
        .find_one(doc! {"_id":id,"user_id":owner})
        .await?
        .ok_or_else(|| ApiError::bad_request("Traffic route not found"))
}
fn hosts(record: &Document) -> Vec<String> {
    record
        .get_array("hosts")
        .unwrap()
        .iter()
        .filter_map(Bson::as_str)
        .map(str::to_owned)
        .collect()
}
async fn add(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(body): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = traffic_routes::parse(body)?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let candidate = document(&app, owner, input).await?;
    let _guard = app.traffic_route_lock.lock().await;
    conflicts(&app, &hosts(&candidate), None).await?;
    ensure_index(&app).await?;
    let id = candidate.get_object_id("_id").unwrap();
    if let Err(error) = app
        .collection("traffic_routes")
        .insert_one(&candidate)
        .await
    {
        if store::duplicate(&error) {
            return Err(ApiError::bad_request("Hosts already in use"));
        }
        return Err(error.into());
    }
    if let Err(error) = generated::rebuild_web(&app).await {
        app.collection("traffic_routes")
            .delete_one(doc! {"_id":id,"user_id":owner})
            .await?;
        return Err(error);
    }
    Ok(Json(
        json!({"msg":"Traffic route created successfully","data":traffic_routes::serialize(&candidate)}),
    ))
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(body): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = traffic_routes::parse(body)?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let id = input.data_id.clone().unwrap_or_default();
    let _guard = app.traffic_route_lock.lock().await;
    let previous = owned(&app, owner, &id).await?;
    if previous.get_bool("temporary") == Ok(true) {
        return Err(ApiError::bad_request(
            "Temporary agent proxies can only be stopped from the PortHub CLI",
        ));
    }
    let id = previous.get_object_id("_id").unwrap();
    if previous.get_array("bindings").is_ok() && input.bindings.is_none() {
        return Err(ApiError::bad_request(
            "This proxy uses multiple bindings; reload the editor before saving",
        ));
    }
    let patch = document(&app, owner, input).await?;
    let mut candidate = previous.clone();
    for (key, value) in patch {
        if !["_id", "user_id", "created_at"].contains(&key.as_str()) {
            candidate.insert(key, value);
        }
    }
    conflicts(&app, &hosts(&candidate), Some(id)).await?;
    ensure_index(&app).await?;
    if let Err(error) = app
        .collection("traffic_routes")
        .replace_one(doc! {"_id":id,"user_id":owner}, &candidate)
        .await
    {
        if store::duplicate(&error) {
            return Err(ApiError::bad_request("Hosts already in use"));
        }
        return Err(error.into());
    }
    if let Err(error) = generated::rebuild_web(&app).await {
        app.collection("traffic_routes")
            .replace_one(doc! {"_id":id,"user_id":owner}, previous)
            .await?;
        return Err(error);
    }
    Ok(Json(
        json!({"msg":"Traffic route updated successfully","data":traffic_routes::serialize(&candidate)}),
    ))
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let records: Vec<Document> = app
        .collection("traffic_routes")
        .find(doc! {"user_id":user.get("_id")})
        .sort(doc! {"created_at":1,"_id":1})
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"msg":"Traffic routes listed successfully","data":records.iter().map(traffic_routes::serialize).collect::<Vec<_>>()}),
    ))
}
async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ApiBody(body): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let id = model.required_string("data_id");
    model.finish()?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user.get("_id").ok_or_else(ApiError::unauthenticated)?;
    let _guard = app.traffic_route_lock.lock().await;
    let previous = owned(&app, owner, &id).await?;
    if previous.get_bool("temporary") == Ok(true) {
        return Err(ApiError::bad_request(
            "Temporary agent proxies can only be stopped from the PortHub CLI",
        ));
    }
    let id = previous.get_object_id("_id").unwrap();
    app.collection("traffic_routes")
        .delete_one(doc! {"_id":id,"user_id":owner})
        .await?;
    if let Err(error) = generated::rebuild_web(&app).await {
        app.collection("traffic_routes")
            .insert_one(&previous)
            .await?;
        return Err(error);
    }
    Ok(Json(
        json!({"msg":"Traffic route deleted successfully","data":traffic_routes::serialize(&previous)}),
    ))
}

async fn health(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owned: Vec<Document> = app
        .collection("traffic_routes")
        .find(doc! {"user_id":user.get("_id")})
        .projection(doc! {"_id":1,"bindings.id":1})
        .await?
        .try_collect()
        .await?;
    let Some(path) = app
        .config
        .web_activity_log_path
        .as_ref()
        .map(|p| p.with_file_name("web-health.json"))
    else {
        return Ok(Json(json!({"available":false,"data":{}})));
    };
    let snapshot = tokio::task::spawn_blocking(move || -> Option<Value> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 8 * 1024 * 1024 {
            return None;
        }
        serde_json::from_slice(&bytes).ok()
    })
    .await
    .ok()
    .flatten();
    let Some(snapshot) = snapshot else {
        return Ok(Json(json!({"available":false,"data":{}})));
    };
    let stamp = snapshot
        .get("updated_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if !(0..=30000).contains(&(chrono::Utc::now().timestamp_millis() - stamp)) {
        return Ok(Json(json!({"available":false,"data":{}})));
    }
    let mut data = serde_json::Map::new();
    for route in owned {
        let id = store::id(route.get("_id"));
        if let Some(bindings) = snapshot
            .get("routes")
            .and_then(|v| v.get(&id))
            .and_then(Value::as_array)
        {
            let ids: Vec<_> = route
                .get_array("bindings")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Bson::as_document)
                .filter_map(|b| b.get_str("id").ok())
                .collect();
            let valid: Vec<_> = bindings
                .iter()
                .filter(|b| {
                    b.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| ids.contains(&id) || ids.is_empty() && id == "primary")
                })
                .cloned()
                .collect();
            data.insert(id, json!(valid));
        }
    }
    Ok(Json(
        json!({"available":true,"updated_at":stamp,"data":data}),
    ))
}
