//! Agent-owned temporary public mappings for interactive local exposure.
use crate::{
    domain::{machine_client, workspaces::object_id},
    error::{ApiError, ApiResult},
    firewall, generated,
    input::Model,
    store, App,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use rand::Rng;
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

const LEASE_MILLIS: i64 = 90_000;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/expose", post(create))
        .route("/api/machines/client/expose/renew", post(renew))
        .route("/api/machines/client/expose/close", post(close))
}

fn machine_credentials(model: &mut Model) -> (String, String) {
    let id = model.required_string("machine_id");
    model.string_length("machine_id", &id, 1, Some(64));
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    (id, token)
}

fn public_host(app: &App) -> ApiResult<String> {
    // Public mapping URLs use the operator's service domain. The direct origin
    // address is a transport optimization, not the user-facing service name.
    let domain = app.config.service_domain.trim();
    if !domain.is_empty() {
        let value = if domain.contains("://") { domain.to_owned() } else { format!("http://{domain}") };
        if let Some(host) = url::Url::parse(&value).ok().and_then(|url| url.host_str().map(str::to_owned)) {
            return Ok(host);
        }
        return Err(ApiError::bad_request("Gateway service domain is invalid"));
    }
    if let Some(ip) = app.config.gateway_public_ip.as_deref() {
        return Ok(ip.to_owned());
    }
    let source = app
        .config
        .gateway_advertised_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or(&app.config.public_base_url);
    url::Url::parse(source)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Gateway public address is not configured",
            )
        })
}

fn allowed_range(app: &App) -> (u16, u16) {
    app.config.external_port_range.unwrap_or((10_000, 65_535))
}

async fn choose_port(app: &App, requested: Option<i64>) -> ApiResult<u16> {
    let (start, end) = allowed_range(app);
    if let Some(port) = requested {
        if !(start as i64..=end as i64).contains(&port) {
            return Err(ApiError::bad_request(&format!(
                "External port must be between {start} and {end}"
            )));
        }
        if app
            .collection("connections")
            .find_one(doc! {"external_port":port})
            .await?
            .is_some()
        {
            return Err(ApiError::bad_request("External port is already in use"));
        }
        return Ok(port as u16);
    }
    let used: Vec<Document> = app
        .collection("connections")
        .find(doc! {"external_port":{"$gte":start as i64,"$lte":end as i64}})
        .projection(doc! {"external_port":1})
        .await?
        .try_collect()
        .await?;
    let used: HashSet<i64> = used.iter().filter_map(firewall::port).collect();
    let available: Vec<u16> = (start..=end)
        .filter(|port| !used.contains(&(*port as i64)))
        .collect();
    if available.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "No available external ports in the configured range",
        ));
    }
    Ok(available[rand::thread_rng().gen_range(0..available.len())])
}

async fn create(State(app): State<Arc<App>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let (machine_id, token) = machine_credentials(&mut model);
    let request_id = model.optional_string("request_id");
    if let Some(id) = &request_id {
        if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request("Invalid exposure request identity"));
        }
    }
    let internal_port = model.required_integer("local_port", 1, 65535);
    let external_port = model.optional_integer("external_port", 1, 65535);
    let subdomain = model
        .optional_string("subdomain")
        .map(|value| value.trim().to_ascii_lowercase());
    model.finish()?;
    let machine = machine_client::authenticate(&app, &machine_id, &token).await?;
    if machine.get_bool("enabled") == Ok(false) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Machine disabled"));
    }
    let owner = machine
        .get("user_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    if app
        .collection("users")
        .find_one(doc! {"_id":&owner,"account_deletion":{"$exists":false}})
        .await?
        .is_none()
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Registered account is unavailable",
        ));
    }
    let domain = if let Some(label) = &subdomain {
        if !crate::input_compat::hostname(label) || label.contains('.') {
            return Err(ApiError::bad_request(
                "Subdomain must be one DNS label, such as myapp",
            ));
        }
        let suffix = app
            .config
            .proxy_domain_suffix
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Custom proxy domains are not configured",
            ));
        }
        Some(format!("{label}.{suffix}"))
    } else {
        None
    };
    let host = public_host(&app)?;
    let _connection_guard = app.connection_lock.lock().await;
    let _route_guard = app.traffic_route_lock.lock().await;
    if let Some(request_id) = &request_id {
        let machine = object_id(&machine_id, "Invalid machine id")?;
        if let Some(existing) = app.collection("connections").find_one(doc! {"machine_id":machine,"temporary":true,"request_id":request_id}).await? {
            if existing.get_i64("internal_port") != Ok(internal_port)
                || existing.get_i64("requested_external_port").ok() != external_port
                || existing.get_str("requested_subdomain").ok() != subdomain.as_deref()
                || !existing.get_datetime("lease_expires_at").is_ok_and(|expiry| *expiry > DateTime::now()) {
                return Err(ApiError::new(StatusCode::CONFLICT, "Exposure request identity is already used or expired"));
            }
            let port = existing.get_i64("external_port").unwrap_or_default();
            return Ok(Json(json!({"data":{"exposure_id":store::string(&existing,"exposure_id"),"external_port":port,"gateway_host":host,
                "tcp_url":format!("{host}:{port}"),"proxy_url":domain,"local_port":internal_port}})));
        }
    }
    let port = choose_port(&app, external_port).await?;
    let now = DateTime::now();
    let exposure_id = Uuid::new_v4().to_string();
    let machine_id = object_id(&machine_id, "Invalid machine id")?;
    let connection = doc! {
        "_id":ObjectId::new(),"user_id":&owner,"machine_id":machine_id,"service_name":format!("Temporary exposure {port}"),
        "service_description":"Temporary mapping created by the PortHub CLI","internal_ip":"127.0.0.1","internal_port":internal_port,
        "external_port":port as i64,"enabled":true,"firewall":{"is_public":true,"allowed_ips":[]},
        "request_id":request_id,"requested_external_port":external_port,"requested_subdomain":subdomain,
        "created_at":now,"updated_at":now,"temporary":true,"managed_by":"agent","exposure_id":&exposure_id,
        "lease_expires_at":DateTime::from_millis(now.timestamp_millis()+LEASE_MILLIS)
    };
    app.collection("connections")
        .insert_one(&connection)
        .await
        .map_err(|error| {
            if store::duplicate(&error) {
                ApiError::bad_request("External port is already in use")
            } else {
                error.into()
            }
        })?;
    if let Err(error) = async {
        firewall::sync(&app, &connection).await?;
        generated::rebuild(&app).await?;
        if let Some(domain) = &domain {
            create_proxy(&app, &owner, &connection, domain, &exposure_id).await?;
        }
        Ok::<_, ApiError>(())
    }
    .await
    {
        app.collection("connections")
            .delete_one(doc! {"_id":connection.get("_id")})
            .await?;
        let _ = generated::rebuild(&app).await;
        let _ = firewall::remove(&app, &connection).await;
        return Err(error);
    }
    app.notify_config(&machine_id.to_hex()).await;
    app.deletion_changes.notify_one();
    Ok(Json(
        json!({"data":{"exposure_id":exposure_id,"external_port":port,"gateway_host":host,
        "tcp_url":format!("{host}:{port}"),"proxy_url":domain,"local_port":internal_port}}),
    ))
}

async fn create_proxy(
    app: &App,
    owner: &Bson,
    connection: &Document,
    host: &str,
    exposure_id: &str,
) -> ApiResult<()> {
    let connection_id = connection
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let suffix = app
        .config
        .proxy_domain_suffix
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    let route = doc! {"_id":ObjectId::new(),"user_id":owner,"name":format!("Temporary exposure {host}"),"group":"","description":"Temporary proxy created by the PortHub CLI",
    "hosts":[host],"target_mode":"connection","target_url":format!("http://127.0.0.1:{}",connection.get_i64("external_port").unwrap_or_default()),
    "entry_points":["web","websecure"],"enabled":true,"connection":{"data_id":connection_id.to_hex(),"machine_id":store::id(connection.get("machine_id")),
        "service_name":store::string(connection,"service_name"),"internal_ip":"127.0.0.1","internal_port":connection.get("internal_port").cloned().unwrap_or(Bson::Null),
        "external_port":connection.get("external_port").cloned().unwrap_or(Bson::Null)},"created_at":DateTime::now(),"updated_at":DateTime::now(),
    "temporary":true,"managed_by":"agent","exposure_id":exposure_id,"domain_suffix":suffix};
    let conflicts: Vec<Document> = app
        .collection("traffic_routes")
        .find(doc! {"hosts":host})
        .limit(1)
        .await?
        .try_collect()
        .await?;
    if !conflicts.is_empty() {
        return Err(ApiError::bad_request("Custom subdomain is already in use"));
    }
    app.collection("traffic_routes")
        .insert_one(&route)
        .await
        .map_err(|error| {
            if store::duplicate(&error) {
                ApiError::bad_request("Custom subdomain is already in use")
            } else {
                error.into()
            }
        })?;
    if let Err(error) = generated::rebuild_web(app).await {
        app.collection("traffic_routes")
            .delete_one(doc! {"_id":route.get("_id")})
            .await?;
        return Err(error);
    }
    Ok(())
}

async fn renew(State(app): State<Arc<App>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let (machine_id, token) = machine_credentials(&mut model);
    let exposure_id = model.required_string("exposure_id");
    model.finish()?;
    let machine = machine_client::authenticate(&app, &machine_id, &token).await?;
    let id = machine
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    let _connection_guard = app.connection_lock.lock().await;
    let now = DateTime::now();
    let updated = app.collection("connections").update_one(doc! {"machine_id":id,"exposure_id":&exposure_id,"temporary":true,"lease_expires_at":{"$gt":now}}, doc! {"$set":{"lease_expires_at":DateTime::from_millis(now.timestamp_millis()+LEASE_MILLIS)}}).await?;
    if updated.matched_count != 1 {
        return Err(ApiError::new(
            StatusCode::GONE,
            "Temporary exposure has expired",
        ));
    }
    app.deletion_changes.notify_one();
    Ok(Json(json!({"data":{"renewed":true}})))
}

async fn close(State(app): State<Arc<App>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let mut model = Model::new(body)?;
    let (machine_id, token) = machine_credentials(&mut model);
    let exposure_id = model.required_string("exposure_id");
    model.finish()?;
    let machine = machine_client::authenticate(&app, &machine_id, &token).await?;
    let machine_id = machine
        .get("_id")
        .cloned()
        .ok_or_else(ApiError::unauthenticated)?;
    remove(&app, machine_id, &exposure_id, None).await?;
    Ok(Json(json!({"data":{"closed":true}})))
}

async fn remove(app: &App, machine_id: Bson, exposure_id: &str, expired_at: Option<DateTime>) -> ApiResult<()> {
    let _connection_guard = app.connection_lock.lock().await;
    let _route_guard = app.traffic_route_lock.lock().await;
    let mut filter = doc! {"machine_id":&machine_id,"exposure_id":exposure_id,"temporary":true};
    // Recheck under the same lock as renewal: a stale worker scan must not
    // remove a lease that was renewed before the lock was acquired.
    if let Some(now) = expired_at {
        filter.insert("lease_expires_at", doc! {"$lte":now});
    }
    let connection = app
        .collection("connections")
        .find_one(filter)
        .await?;
    let Some(connection) = connection else {
        return Ok(());
    };
    let routes: Vec<Document> = app
        .collection("traffic_routes")
        .find(doc! {"exposure_id":exposure_id,"temporary":true})
        .await?
        .try_collect()
        .await?;
    app.collection("traffic_routes")
        .delete_many(doc! {"exposure_id":exposure_id,"temporary":true})
        .await?;
    app.collection("connections")
        .delete_one(doc! {"_id":connection.get("_id")})
        .await?;
    if let Err(error) = async {
        generated::rebuild_web(app).await?;
        generated::rebuild(app).await
    }
    .await
    {
        app.collection("connections")
            .insert_one(&connection)
            .await?;
        if !routes.is_empty() {
            app.collection("traffic_routes").insert_many(routes).await?;
        }
        let _ = generated::rebuild_web(app).await;
        let _ = generated::rebuild(app).await;
        return Err(error);
    }
    firewall::remove(app, &connection).await?;
    app.notify_config(&store::id(connection.get("machine_id")))
        .await;
    app.deletion_changes.notify_one();
    Ok(())
}

/// Removes expired exposure leases and returns the next expiry for the shared idle worker.
pub async fn recover_due(app: &App) -> ApiResult<Option<DateTime>> {
    let now = DateTime::now();
    let due: Vec<Document> = app
        .collection("connections")
        .find(doc! {"temporary":true,"lease_expires_at":{"$lte":now}})
        .limit(32)
        .await?
        .try_collect()
        .await?;
    for connection in due {
        if let Some(id) = connection.get("machine_id").cloned() {
            let exposure_id = store::string(&connection, "exposure_id");
            remove(app, id, &exposure_id, Some(now)).await?;
        }
    }
    let next = app
        .collection("connections")
        .find_one(doc! {"temporary":true})
        .sort(doc! {"lease_expires_at":1})
        .await?;
    Ok(next.and_then(|record| record.get_datetime("lease_expires_at").ok().copied()))
}
