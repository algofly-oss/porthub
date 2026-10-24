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
    let connection = metadata(
        app,
        owner,
        input.connection_data_id.as_deref().map(strip).unwrap_or(""),
    )
    .await?;
    let now = DateTime::now();
    let record = doc! {"_id":ObjectId::new(),"user_id":owner,"name":strip(&input.name),"group":strip(&input.group),
    "description":input.description.as_deref().map(strip).unwrap_or(""),"hosts":input.hosts,
    "target_mode":input.target_mode,"target_url":input.target_url.as_deref().map(strip).unwrap_or(""),
    "entry_points":input.entry_points,"enabled":input.enabled.unwrap_or(true),"connection":connection,"created_at":now,"updated_at":now};
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
    let id = previous.get_object_id("_id").unwrap();
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
